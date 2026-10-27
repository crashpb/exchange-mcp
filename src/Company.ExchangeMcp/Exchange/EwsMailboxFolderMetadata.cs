using System.Globalization;
using System.Xml.Linq;
using Company.ExchangeMcp.Security;

namespace Company.ExchangeMcp.Exchange;

public sealed partial class EwsClient
{
    private readonly AsyncLocal<FolderMetadataContext?> folderMetadataContext = new();

    /// <summary>
    /// Reads only folder hierarchy metadata as the validated mailbox owner. Callers must
    /// verify every returned folder ID again under the selected actor before exposing it.
    /// Owner effective rights are deliberately removed from the result.
    /// </summary>
    internal async Task<EwsMailboxFolderDiscovery> DiscoverMailboxFolderMetadataAsync(
        MailboxDirectoryCandidate candidate,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(candidate);
        if (folderMetadataContext.Value is not null)
            throw new InvalidOperationException("Nested Exchange folder metadata discovery is not allowed.");

        var selected = ValidateFolderMetadataCandidate(candidate);
        var previous = folderMetadataContext.Value;
        folderMetadataContext.Value = new(candidate, selected.ActorMailbox!);
        try
        {
            var result = await DiscoverMailboxFolderMetadataCoreAsync(
                candidate.Mailbox, candidate.Mailbox, cancellationToken).ConfigureAwait(false);
            return new(result.Folders.Select(folder => folder with
            {
                Rights = new EwsFolderAccessRights(null, null, null, null)
            }).ToArray(), result.Complete);
        }
        finally
        {
            folderMetadataContext.Value = previous;
        }
    }

    private MailboxIdentity ValidateFolderMetadataCandidate(
        MailboxDirectoryCandidate candidate)
    {
        if (!SupportsFolderMetadataDiscovery(candidate))
            throw new InvalidOperationException("Owner folder metadata is limited to a validated native directory mailbox.");

        var selected = _mailboxAccess?.CurrentSelection;
        if (selected is null
            || !string.Equals(selected.TargetId, candidate.Key, StringComparison.Ordinal)
            || !string.Equals(selected.Mailbox, candidate.Mailbox, StringComparison.OrdinalIgnoreCase)
            || string.IsNullOrWhiteSpace(selected.ActorMailbox)
            || !ServiceOptions.IsMailbox(selected.ActorMailbox))
            throw new InvalidOperationException("Owner folder metadata requires the current actor's matching mailbox selection.");

        return selected;
    }

    internal static bool SupportsFolderMetadataDiscovery(MailboxDirectoryCandidate candidate)
    {
        return Guid.TryParseExact(candidate.Key, "D", out var key) && key != Guid.Empty
            && string.Equals(candidate.Key, key.ToString("D"), StringComparison.Ordinal)
            && candidate.RecipientTypeDetails is 1 or 4 or 16 or 32
            && ServiceOptions.IsMailbox(candidate.Mailbox);
    }

    private void ValidateFolderMetadataRequest(
        string mailbox,
        string metadataOwner,
        XElement operation,
        FolderMetadataContext context,
        bool allowMissingUserConfiguration,
        Action<XDocument, string>? responseValidator,
        bool allowPartialResponseErrors)
    {
        var selected = ValidateFolderMetadataCandidate(context.Candidate);
        if (!string.Equals(selected.ActorMailbox, context.ActorMailbox, StringComparison.OrdinalIgnoreCase)
            || !string.Equals(mailbox, context.Candidate.Mailbox, StringComparison.OrdinalIgnoreCase)
            || !string.Equals(metadataOwner, context.Candidate.Mailbox, StringComparison.OrdinalIgnoreCase)
            || allowMissingUserConfiguration
            || responseValidator is not null)
            throw new InvalidOperationException("Owner folder metadata requests must remain bound to the current validated mailbox selection.");

        if (operation.Name == M + "GetFolder")
        {
            if (!IsMetadataGetFolder(operation))
                throw new InvalidOperationException("Owner metadata access permits only bounded folder metadata reads.");
            return;
        }

        if (operation.Name == M + "FindFolder" && !allowPartialResponseErrors && IsMetadataFindFolder(operation))
            return;

        throw new InvalidOperationException("Owner metadata access permits only bounded folder metadata reads.");
    }

    private static bool IsMetadataGetFolder(XElement operation)
    {
        if (operation.Attributes().Any()
            || !operation.Elements().Select(element => element.Name).SequenceEqual([M + "FolderShape", M + "FolderIds"]))
            return false;

        var shape = operation.Element(M + "FolderShape");
        if (shape is null || !XNode.DeepEquals(shape, DiscoveryFolderShape()))
            return false;

        var folderIds = operation.Element(M + "FolderIds");
        var references = folderIds?.Elements().ToArray();
        if (folderIds is null || folderIds.Attributes().Any() || references is not { Length: > 0 and <= 8 })
            return false;

        var knownIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "inbox", "calendar", "tasks", "contacts", "drafts", "sentitems", "deleteditems", "msgfolderroot"
        };
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var reference in references)
        {
            var id = (string?)reference.Attribute("Id");
            if (reference.Name != T + "DistinguishedFolderId"
                || reference.Attributes().Count() != 1
                || reference.Elements().Any()
                || id is null || !knownIds.Contains(id) || !seen.Add(id))
                return false;
        }
        return true;
    }

    private static bool IsMetadataFindFolder(XElement operation)
    {
        var attributes = operation.Attributes().ToArray();
        if (attributes.Length != 1 || attributes[0].Name != "Traversal" || attributes[0].Value != "Deep"
            || !operation.Elements().Select(element => element.Name).SequenceEqual(
                [M + "FolderShape", M + "IndexedPageFolderView", M + "ParentFolderIds"]))
            return false;

        var shape = operation.Element(M + "FolderShape");
        if (shape is null || !XNode.DeepEquals(shape, DiscoveryFolderShape()))
            return false;

        var view = operation.Element(M + "IndexedPageFolderView");
        if (view is null || view.Elements().Any()
            || view.Attributes().Count() != 3
            || (string?)view.Attribute("MaxEntriesReturned") != "100"
            || !int.TryParse((string?)view.Attribute("Offset"), NumberStyles.None, CultureInfo.InvariantCulture, out var offset)
            || offset is < 0 or >= 512
            || (string?)view.Attribute("BasePoint") != "Beginning")
            return false;

        var parent = operation.Element(M + "ParentFolderIds");
        var reference = parent?.Elements().SingleOrDefault();
        return parent is not null && !parent.Attributes().Any()
            && parent.Elements().Count() == 1
            && reference?.Name == T + "DistinguishedFolderId"
            && reference.Attributes().Count() == 1
            && (string?)reference.Attribute("Id") == "msgfolderroot"
            && !reference.Elements().Any();
    }

    private sealed record FolderMetadataContext(
        MailboxDirectoryCandidate Candidate,
        string ActorMailbox);
}
