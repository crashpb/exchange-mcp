using System.Globalization;
using System.Xml.Linq;

namespace Company.ExchangeMcp.Exchange;

public sealed record EwsDiscoveredFolder(
    string Id,
    string Name,
    string FolderClass,
    string? DistinguishedId,
    EwsFolderAccessRights Rights,
    string ChangeKey = "",
    string? ParentId = null);

public sealed record EwsMailboxFolderDiscovery(IReadOnlyList<EwsDiscoveredFolder> Folders, bool Complete);

public sealed partial class EwsClient
{
    private const int MaximumDiscoveredFolders = 512;
    private const int DiscoveryFolderPageSize = 100;
    private const int MaximumRightsFolderBatch = 100;
    private const int MaximumDiscoveryPages = 6;
    private static readonly TimeSpan MaximumFolderDiscoveryDuration = TimeSpan.FromSeconds(30);
    private static readonly (string Id, string DistinguishedId)[] KnownFolderIds =
    [
        ("inbox", "inbox"), ("calendar", "calendar"), ("tasks", "tasks"), ("contacts", "contacts"),
        ("drafts", "drafts"), ("sentitems", "sentitems"), ("deleteditems", "deleteditems"),
        ("msgfolderroot", "msgfolderroot")
    ];

    public Task<EwsMailboxFolderDiscovery> DiscoverMailboxFoldersAsync(
        string mailbox, CancellationToken cancellationToken) =>
        DiscoverMailboxFoldersCoreAsync(mailbox, metadataOwner: null, cancellationToken);

    private Task<EwsMailboxFolderDiscovery> DiscoverMailboxFolderMetadataCoreAsync(
        string mailbox, string metadataOwner, CancellationToken cancellationToken) =>
        DiscoverMailboxFoldersCoreAsync(mailbox, metadataOwner, cancellationToken);

    private async Task<EwsMailboxFolderDiscovery> DiscoverMailboxFoldersCoreAsync(
        string mailbox, string? metadataOwner, CancellationToken cancellationToken)
    {
        var normalizedMailbox = ValidateMailbox(mailbox);
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(MaximumFolderDiscoveryDuration);
        var folders = new Dictionary<string, EwsDiscoveredFolder>(StringComparer.Ordinal);
        var complete = true;
        var rootAvailable = false;
        var batchSucceeded = false;

        var operation = BuildKnownFolderRequest(KnownFolderIds.Select(folder => folder.DistinguishedId));
        try
        {
            var document = await SendAsync(normalizedMailbox, operation, deadline.Token,
                allowPartialResponseErrors: true, metadataOwner: metadataOwner).ConfigureAwait(false);
            batchSucceeded = true;
            var messages = document.Descendants(M + "GetFolderResponseMessage").ToArray();
            if (messages.Length != KnownFolderIds.Length)
                complete = false;

            for (var index = 0; index < Math.Min(messages.Length, KnownFolderIds.Length); index++)
            {
                deadline.Token.ThrowIfCancellationRequested();
                var known = KnownFolderIds[index];
                var responseClass = (string?)messages[index].Attribute("ResponseClass");
                var responseCode = messages[index].Element(M + "ResponseCode")?.Value.Trim();
                if (responseClass == "Success" && responseCode == "NoError")
                {
                    var parsed = ParseResponseFolder(messages[index], known.DistinguishedId, out var valid);
                    if (!valid)
                    {
                        complete = false;
                        continue;
                    }
                    if (known.DistinguishedId == "msgfolderroot")
                        rootAvailable = true;
                    if (parsed is not null)
                        AddFolder(folders, parsed, ref complete);
                    continue;
                }

                if (responseCode is "ErrorFolderNotFound" or "ErrorItemNotFound")
                {
                    if (known.DistinguishedId == "msgfolderroot")
                        complete = false;
                    continue;
                }
                if (responseCode is not null && IsPermissionResponseCode(responseCode))
                {
                    if (known.DistinguishedId == "msgfolderroot")
                        complete = false;
                    continue;
                }
                complete = false;
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (EwsPermissionDeniedException exception) when (exception.ResponseCode is
            "ErrorImpersonationDenied" or "ErrorImpersonateUserDenied")
        {
            return new([], false);
        }
        catch (Exception exception) when (exception is not OutOfMemoryException and not StackOverflowException)
        {
            complete = false;
        }

        if (!batchSucceeded)
        {
            // A SOAP-level denial can hide successful default-folder probes, so retry them separately.
            var fallback = await ProbeKnownFoldersIndividuallyAsync(normalizedMailbox, folders, deadline.Token,
                cancellationToken, metadataOwner).ConfigureAwait(false);
            complete &= fallback.Complete;
            rootAvailable = fallback.RootAvailable;
        }

        if (rootAvailable && !deadline.IsCancellationRequested)
            complete &= await FindAccessibleHierarchyAsync(normalizedMailbox, folders, deadline.Token,
                cancellationToken, metadataOwner).ConfigureAwait(false);
        else if (!rootAvailable)
            complete = false;

        return new(folders.Values.OrderBy(folder => folder.DistinguishedId, StringComparer.Ordinal)
            .ThenBy(folder => folder.Name, StringComparer.OrdinalIgnoreCase).ThenBy(folder => folder.Id, StringComparer.Ordinal)
            .ToArray(), complete && !deadline.IsCancellationRequested);
    }

    public async Task<IReadOnlyList<EwsDiscoveredFolder>> GetMailboxFolderRightsAsync(
        string mailbox, IReadOnlyList<string> folderIds, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(folderIds);
        if (folderIds.Count > MaximumDiscoveredFolders)
            throw new ArgumentOutOfRangeException(nameof(folderIds));
        var normalizedMailbox = ValidateMailbox(mailbox);
        var normalizedIds = folderIds.Select(id => ValidateItemId(id, "folder"))
            .Distinct(StringComparer.Ordinal).ToArray();

        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(MaximumFolderDiscoveryDuration);
        var result = new List<EwsDiscoveredFolder>();
        try
        {
            for (var offset = 0; offset < normalizedIds.Length; offset += MaximumRightsFolderBatch)
            {
                deadline.Token.ThrowIfCancellationRequested();
                var batch = normalizedIds.Skip(offset).Take(MaximumRightsFolderBatch).ToArray();
                var operation = new XElement(M + "GetFolder", DiscoveryFolderShape(),
                    new XElement(M + "FolderIds", batch.Select(id => new XElement(T + "FolderId", new XAttribute("Id", id)))));
                var document = await SendAsync(normalizedMailbox, operation, deadline.Token,
                    allowPartialResponseErrors: true).ConfigureAwait(false);
                var messages = document.Descendants(M + "GetFolderResponseMessage").ToArray();
                if (messages.Length != batch.Length)
                    throw new EwsRequestFailedException(null, "GetFolder");
                for (var index = 0; index < messages.Length; index++)
                {
                    var message = messages[index];
                    var responseClass = (string?)message.Attribute("ResponseClass");
                    var responseCode = message.Element(M + "ResponseCode")?.Value.Trim();
                    if (responseClass == "Success" && responseCode == "NoError")
                    {
                        var discovered = ParseResponseFolder(message, distinguishedId: null, out var valid);
                        if (!valid || (discovered is not null
                            && !string.Equals(discovered.Id, batch[index], StringComparison.Ordinal)))
                            throw new EwsRequestFailedException(null, "GetFolder");
                        if (discovered is not null)
                            result.Add(discovered);
                        continue;
                    }
                    if (responseCode is "ErrorFolderNotFound" or "ErrorItemNotFound"
                        || responseCode is not null && IsPermissionResponseCode(responseCode))
                        continue;
                    throw new EwsRequestFailedException(responseCode, "GetFolder");
                }
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (OperationCanceledException)
        {
            throw new TimeoutException("The Exchange folder-rights lookup exceeded its time limit.");
        }
        return result;
    }

    private async Task<(bool Complete, bool RootAvailable)> ProbeKnownFoldersIndividuallyAsync(
        string mailbox,
        IDictionary<string, EwsDiscoveredFolder> folders,
        CancellationToken deadline,
        CancellationToken callerCancellation,
        string? metadataOwner)
    {
        var complete = true;
        var rootAvailable = false;
        foreach (var known in KnownFolderIds)
        {
            if (deadline.IsCancellationRequested)
                return (false, rootAvailable);
            try
            {
                var document = await SendAsync(mailbox, BuildKnownFolderRequest([known.DistinguishedId]), deadline,
                    metadataOwner: metadataOwner)
                    .ConfigureAwait(false);
                var response = document.Descendants(M + "GetFolderResponseMessage").SingleOrDefault();
                if (response is null)
                {
                    complete = false;
                    continue;
                }
                if (known.DistinguishedId == "msgfolderroot"
                    && (string?)response.Attribute("ResponseClass") == "Success"
                    && response.Element(M + "ResponseCode")?.Value.Trim() == "NoError")
                    rootAvailable = true;
                var parsed = ParseResponseFolder(response, known.DistinguishedId, out var valid);
                if (!valid)
                {
                    complete = false;
                    continue;
                }
                if (parsed is not null)
                    AddFolder(folders, parsed, ref complete);
            }
            catch (OperationCanceledException) when (callerCancellation.IsCancellationRequested)
            {
                throw;
            }
            catch (EwsRequestFailedException exception) when (exception.ResponseCode is "ErrorFolderNotFound" or "ErrorItemNotFound")
            {
                if (known.DistinguishedId == "msgfolderroot")
                    return (false, false);
            }
            catch (EwsPermissionDeniedException)
            {
                if (known.DistinguishedId == "msgfolderroot")
                    return (false, false);
            }
            catch (Exception exception) when (exception is not OutOfMemoryException and not StackOverflowException)
            {
                complete = false;
            }
        }
        return (complete, rootAvailable);
    }

    private async Task<bool> FindAccessibleHierarchyAsync(
        string mailbox,
        IDictionary<string, EwsDiscoveredFolder> folders,
        CancellationToken deadline,
        CancellationToken callerCancellation,
        string? metadataOwner)
    {
        var complete = true;
        var offset = 0;
        var pageCount = 0;
        var scanned = KnownFolderIds.Length;
        while (pageCount++ < MaximumDiscoveryPages && scanned < MaximumDiscoveredFolders)
        {
            if (deadline.IsCancellationRequested)
            {
                return false;
            }
            try
            {
                var operation = new XElement(M + "FindFolder",
                    new XAttribute("Traversal", "Deep"),
                    DiscoveryFolderShape(),
                    new XElement(M + "IndexedPageFolderView",
                        new XAttribute("MaxEntriesReturned", DiscoveryFolderPageSize),
                        new XAttribute("Offset", offset),
                        new XAttribute("BasePoint", "Beginning")),
                    new XElement(M + "ParentFolderIds", FolderReference("msgfolderroot")));
                var document = await SendAsync(mailbox, operation, deadline, metadataOwner: metadataOwner)
                    .ConfigureAwait(false);
                var root = RequiredElement(document, M + "RootFolder");
                var page = root.Element(T + "Folders");
                if (page is null)
                {
                    return false;
                }
                var entries = page.Elements().Where(IsFolderElement).ToArray();
                if (entries.Length > DiscoveryFolderPageSize)
                {
                    return false;
                }
                var remaining = MaximumDiscoveredFolders - scanned;
                foreach (var entry in entries.Take(remaining))
                {
                    var parsed = ParseFolderElement(entry, distinguishedId: null, out var valid);
                    if (!valid)
                    {
                        complete = false;
                        continue;
                    }
                    if (parsed is not null)
                        AddFolder(folders, parsed, ref complete);
                }
                scanned += entries.Length;
                if (entries.Length > remaining)
                {
                    return false;
                }
                if (IncludesLastItem(root))
                    return complete;
                if (!int.TryParse((string?)root.Attribute("IndexedPagingOffset"), NumberStyles.None,
                        CultureInfo.InvariantCulture, out var nextOffset))
                    return false;
                if (nextOffset <= offset)
                {
                    return false;
                }
                offset = nextOffset;
            }
            catch (OperationCanceledException) when (callerCancellation.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception exception) when (exception is not OutOfMemoryException and not StackOverflowException)
            {
                return false;
            }
        }
        return false;
    }

    private static XElement BuildKnownFolderRequest(IEnumerable<string> folderIds) =>
        new(M + "GetFolder", DiscoveryFolderShape(), new XElement(M + "FolderIds",
            folderIds.Select(id => new XElement(T + "DistinguishedFolderId", new XAttribute("Id", id)))));

    private static XElement DiscoveryFolderShape() =>
        new(M + "FolderShape", new XElement(T + "BaseShape", "IdOnly"),
            new XElement(T + "AdditionalProperties", Field("folder:DisplayName"), Field("folder:FolderClass"), Field("folder:ParentFolderId"),
                Field("folder:EffectiveRights")));

    private static EwsDiscoveredFolder? ParseResponseFolder(
        XElement message, string? distinguishedId, out bool valid)
    {
        valid = false;
        if ((string?)message.Attribute("ResponseClass") != "Success"
            || message.Element(M + "ResponseCode")?.Value.Trim() != "NoError")
            return null;
        var folders = message.Element(M + "Folders")?.Elements().Where(IsFolderElement).ToArray();
        if (folders is not { Length: 1 })
            return null;
        return ParseFolderElement(folders[0], distinguishedId, out valid);
    }

    private static bool IsFolderElement(XElement element) => element.Name.Namespace == T
        && element.Element(T + "FolderId") is not null;

    private static EwsDiscoveredFolder? ParseFolderElement(
        XElement folder, string? distinguishedId, out bool valid)
    {
        valid = false;
        try
        {
            var id = folder.Element(T + "FolderId")?.Attribute("Id")?.Value;
            var changeKey = folder.Element(T + "FolderId")?.Attribute("ChangeKey")?.Value ?? string.Empty;
            var rawName = folder.Element(T + "DisplayName")?.Value;
            var folderClass = folder.Element(T + "FolderClass")?.Value ?? string.Empty;
            if (string.IsNullOrWhiteSpace(id) || id.Length > 4_096 || id.Any(char.IsControl)
                || rawName is null || rawName.Length > 255
                || folderClass.Length > 128 || folderClass.Any(char.IsControl))
                return null;
            // Existing Exchange folders can have whitespace/control names; sanitize their label, never their identity.
            var name = string.IsNullOrWhiteSpace(rawName) ? "(unnamed folder)"
                : new string(rawName.Select(character => char.IsControl(character) ? '\uFFFD' : character).ToArray());
            _ = ValidateItemId(id, "folder");
            if (changeKey.Length > 0)
                _ = ValidateChangeKey(changeKey);
            ValidateFolderName(name);
            var effective = ParseEffectiveRights(folder.Element(T + "EffectiveRights"));
            if (effective is null)
                return null;
            var rights = new EwsFolderAccessRights(effective.Read,
                effective.CreateAssociated || effective.CreateContents || effective.CreateHierarchy,
                effective.Modify, effective.Delete);
            var parentId = ParseFolderParentId(folder);
            valid = true;
            return rights.Read == true || rights.Create == true || rights.Modify == true || rights.Delete == true
                ? new(id, name, folderClass, distinguishedId, rights, changeKey, parentId) : null;
        }
        catch (Exception exception) when (exception is ArgumentException or InvalidOperationException or FormatException)
        {
            return null;
        }
    }

    private static string? ParseFolderParentId(XElement folder)
    {
        var id = folder.Element(T + "ParentFolderId")?.Attribute("Id")?.Value;
        return id is null ? null : ValidateItemId(id, "parent folder");
    }

    private static void AddFolder(
        IDictionary<string, EwsDiscoveredFolder> folders, EwsDiscoveredFolder folder, ref bool complete)
    {
        if (!folders.TryGetValue(folder.Id, out var existing))
        {
            folders.Add(folder.Id, folder);
            return;
        }
        if (!string.Equals(existing.Name, folder.Name, StringComparison.Ordinal)
            || !string.Equals(existing.FolderClass, folder.FolderClass, StringComparison.Ordinal)
            || !string.Equals(existing.ParentId, folder.ParentId, StringComparison.Ordinal)
            || existing.Rights != folder.Rights)
        {
            complete = false;
            return;
        }
        if (existing.DistinguishedId is null && folder.DistinguishedId is not null)
            folders[folder.Id] = folder;
    }
}
