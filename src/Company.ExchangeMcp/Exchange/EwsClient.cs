using System.Globalization;
using System.Net.Http;
using System.Net.Mail;
using System.Text;
using System.Xml;
using System.Xml.Linq;
using Company.ExchangeMcp.Security;
using Microsoft.Extensions.Options;

namespace Company.ExchangeMcp.Exchange;

/// <summary>
/// Small, explicit EWS SOAP client. Authentication belongs to the injected HttpClient handler.
/// </summary>
public sealed partial class EwsClient
{
    private const string SoapEnvelopeNamespace = "http://schemas.xmlsoap.org/soap/envelope/";
    private const string MessagesNamespace = "http://schemas.microsoft.com/exchange/services/2006/messages";
    private const string TypesNamespace = "http://schemas.microsoft.com/exchange/services/2006/types";
    private const string TimeoutError = "The Exchange request timed out.";
    private const int MaxMailboxLength = 320;
    private const int MaxItemIdLength = 4_096;
    private const int MaxQueryLength = 256;
    private const int MaxBodyLength = 1_048_576;
    private const int MaxRecipients = 100;
    internal const int MaxAttachmentBytes = 5 * 1024 * 1024;
    internal const int MaxDraftAttachmentBytes = 10 * 1024 * 1024;
    internal const int MaxAttachments = 100;
    private const int MaxAttachmentNameLength = 255;
    private const int MaxFolders = 10_000;
    private const int FolderPageSize = 1_000;

    private static readonly XNamespace Soap = SoapEnvelopeNamespace;
    private static readonly XNamespace M = MessagesNamespace;
    private static readonly XNamespace T = TypesNamespace;
    private static readonly XNamespace Xmlns = XNamespace.Xmlns;
    private static readonly IReadOnlyDictionary<string, string> DistinguishedFolders =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["inbox"] = "inbox",
            ["drafts"] = "drafts",
            ["sentitems"] = "sentitems",
            ["deleteditems"] = "deleteditems",
            ["msgfolderroot"] = "msgfolderroot"
        };

    private readonly HttpClient _httpClient;
    private readonly EwsOptions _options;
    private readonly Uri _endpoint;
    private readonly MailboxAccess? _mailboxAccess;
    private readonly LdapMailboxPermissionReader? _taskDirectory;

    public EwsClient(HttpClient httpClient, IOptions<EwsOptions> options, MailboxAccess? mailboxAccess = null,
        LdapMailboxPermissionReader? taskDirectory = null)
    {
        _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        _options = options?.Value ?? throw new ArgumentNullException(nameof(options));
        _mailboxAccess = mailboxAccess;
        _taskDirectory = taskDirectory;

        if (!Uri.TryCreate(_options.Endpoint, UriKind.Absolute, out var endpoint) ||
            endpoint.Scheme != Uri.UriSchemeHttps ||
            !string.IsNullOrEmpty(endpoint.UserInfo))
        {
            throw new InvalidOperationException("The Exchange endpoint must be an absolute HTTPS URI without user information.");
        }

        if (_options.TimeoutSeconds is < 1 or > 300)
        {
            throw new InvalidOperationException("The Exchange request timeout is outside the supported range.");
        }

        if (_options.MaxResponseBytes is < 1_024 or > 16_777_216)
        {
            throw new InvalidOperationException("The Exchange response size limit is outside the supported range.");
        }

        _endpoint = endpoint;
    }

    public async Task<IReadOnlyList<EwsFolder>> ListFoldersAsync(
        string mailbox,
        CancellationToken cancellationToken)
    {
        var normalizedMailbox = ValidateMailbox(mailbox);
        var folders = new List<EwsFolder>();
        var offset = 0;

        while (true)
        {
            var operation = new XElement(
                M + "FindFolder",
                new XAttribute("Traversal", "Deep"),
                new XElement(M + "FolderShape", new XElement(T + "BaseShape", "AllProperties")),
                new XElement(
                    M + "IndexedPageFolderView",
                    new XAttribute("MaxEntriesReturned", FolderPageSize),
                    new XAttribute("Offset", offset),
                    new XAttribute("BasePoint", "Beginning")),
                new XElement(M + "ParentFolderIds", FolderReference("msgfolderroot")));

            var document = await SendAsync(normalizedMailbox, operation, cancellationToken).ConfigureAwait(false);
            var rootFolder = RequiredElement(document, M + "RootFolder");
            var page = rootFolder.Element(T + "Folders");

            if (page is null)
            {
                throw new InvalidOperationException("Exchange returned a folder page without its folder collection.");
            }

            foreach (var folder in page.Elements().Where(folder =>
                         folder.Name.Namespace == T && folder.Element(T + "FolderId") is not null))
            {
                folders.Add(ParseFolder(folder));
                if (folders.Count > MaxFolders)
                {
                    throw new InvalidOperationException("The Exchange folder result exceeded the supported limit.");
                }
            }

            if (IncludesLastItem(rootFolder))
            {
                return folders;
            }

            var nextOffset = ReadOffset(rootFolder, offset + page.Elements().Count());
            if (nextOffset <= offset || nextOffset > MaxFolders)
            {
                throw new InvalidOperationException("The Exchange folder result could not be paged safely.");
            }

            offset = nextOffset;
        }
    }

    public async Task<EwsFolder> GetFolderAsync(string mailbox, string folderId, CancellationToken cancellationToken)
    {
        var normalizedMailbox = ValidateMailbox(mailbox);
        var normalizedFolder = ValidateItemId(folderId, "folder");
        var operation = new XElement(M + "GetFolder",
            new XElement(M + "FolderShape", new XElement(T + "BaseShape", "AllProperties")),
            new XElement(M + "FolderIds", FolderReference(normalizedFolder)));
        var document = await SendAsync(normalizedMailbox, operation, cancellationToken).ConfigureAwait(false);
        return ParseFolder(RequiredElement(document, T + "Folder"));
    }

    public async Task<EwsPage<EwsMessage>> FindMessagesAsync(
        string mailbox,
        string folderId,
        string? query,
        int offset,
        int limit,
        CancellationToken cancellationToken,
        DateTimeOffset? receivedAfterUtc = null,
        DateTimeOffset? receivedBeforeUtc = null,
        string? sender = null,
        bool? unread = null)
    {
        var normalizedMailbox = ValidateMailbox(mailbox);
        var normalizedFolder = ValidateItemId(folderId, "folder");
        ValidatePage(offset, limit);
        if (query is not null && query.Length > MaxQueryLength)
        {
            throw new ArgumentException("The message search query is too long.", nameof(query));
        }

        if (receivedAfterUtc is not null && receivedBeforeUtc is not null
            && receivedAfterUtc.Value > receivedBeforeUtc.Value)
        {
            throw new ArgumentException("The received date range is invalid.");
        }
        if (sender is not null)
        {
            _ = NormalizeAddress(sender);
        }

        var operation = new XElement(
            M + "FindItem",
            new XAttribute("Traversal", "Shallow"),
            MessageShape(summaryOnly: true),
            new XElement(
                M + "IndexedPageItemView",
                new XAttribute("MaxEntriesReturned", limit),
                new XAttribute("Offset", offset),
                    new XAttribute("BasePoint", "Beginning")));

        var restrictions = new List<XElement>();
        if (!string.IsNullOrWhiteSpace(query)) restrictions.Add(ContainsRestriction(query));
        if (receivedAfterUtc is not null)
            restrictions.Add(DateRestriction("IsGreaterThanOrEqualTo", receivedAfterUtc.Value));
        if (receivedBeforeUtc is not null)
            restrictions.Add(DateRestriction("IsLessThan", receivedBeforeUtc.Value));
        if (sender is not null) restrictions.Add(Equal("message:From", sender));
        if (unread is not null) restrictions.Add(Equal("message:IsRead", (!unread.Value).ToString().ToLowerInvariant()));
        if (restrictions.Count > 0)
            operation.Add(new XElement(M + "Restriction", AndRestrictions(restrictions)));
        operation.Add(new XElement(M + "SortOrder", new XElement(T + "FieldOrder",
            new XAttribute("Order", "Descending"), Field("item:DateTimeReceived"))));
        operation.Add(new XElement(M + "ParentFolderIds", FolderReference(normalizedFolder)));

        var document = await SendAsync(normalizedMailbox, operation, cancellationToken).ConfigureAwait(false);
        var rootFolder = RequiredElement(document, M + "RootFolder");
        var items = rootFolder.Element(T + "Items")?.Elements()
            .Where(item => item.Name.Namespace == T && item.Element(T + "ItemId") is not null)
            .Select(ParseMessage)
            .ToArray() ?? Array.Empty<EwsMessage>();

        return new EwsPage<EwsMessage>(items, GetNextOffset(rootFolder, offset, items.Length));
    }

    public async Task<EwsMessage> GetMessageAsync(
        string mailbox,
        string itemId,
        CancellationToken cancellationToken)
    {
        var normalizedMailbox = ValidateMailbox(mailbox);
        var normalizedItemId = ValidateItemId(itemId, "item");
        var operation = new XElement(
            M + "GetItem",
            MessageShape(),
            new XElement(M + "ItemIds", ItemReference(normalizedItemId)));

        var document = await SendAsync(normalizedMailbox, operation, cancellationToken).ConfigureAwait(false);
        var item = RequiredReturnedItem(document);
        return ParseMessage(item);
    }

    public async Task<EwsItemRef> CreateDraftAsync(
        string mailbox,
        EwsDraftInput input,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(input);
        var normalizedMailbox = ValidateMailbox(mailbox);
        var message = BuildMessage(input.Subject, input.Body, input.To, input.Cc, input.Bcc ?? Array.Empty<string>(), input.BodyType,
            ResolveDraftSender(normalizedMailbox, input.From));
        var operation = new XElement(
            M + "CreateItem",
            new XAttribute("MessageDisposition", "SaveOnly"),
            new XElement(M + "SavedItemFolderId", FolderReference("drafts")),
            new XElement(M + "Items", message));

        var actorStorage = await NeedsActorSavedFolderAsync(normalizedMailbox, "drafts", cancellationToken).ConfigureAwait(false);
        var document = await SendAsync(normalizedMailbox, operation, cancellationToken, saveInActorFolder: actorStorage).ConfigureAwait(false);
        return ParseItemReference(RequiredReturnedItem(document));
    }

    public async Task<EwsItemRef> UpdateDraftAsync(
        string mailbox,
        string itemId,
        string changeKey,
        EwsDraftInput input,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(input);
        var normalizedMailbox = ValidateMailbox(mailbox);
        var normalizedItemId = ValidateItemId(itemId, "item");
        var normalizedChangeKey = ValidateChangeKey(changeKey);
        var sender = ResolveDraftSender(normalizedMailbox, input.From);
        _ = BuildMessage(input.Subject, input.Body, input.To, input.Cc, input.Bcc ?? Array.Empty<string>(), input.BodyType, sender);
        var updates = new XElement(T + "Updates",
            SetField("item:Subject", new XElement(T + "Message", new XElement(T + "Subject", input.Subject))),
            SetField("item:Body", new XElement(T + "Message", BuildBodyElement("Body", input.Body, input.BodyType))),
            SetRecipientsField("message:ToRecipients", "ToRecipients", input.To),
            SetRecipientsField("message:CcRecipients", "CcRecipients", input.Cc),
            SetRecipientsField("message:BccRecipients", "BccRecipients", input.Bcc ?? Array.Empty<string>()),
            sender is null ? null : SetMailboxField("message:From", "From", sender));
        var operation = new XElement(
            M + "UpdateItem",
            new XAttribute("MessageDisposition", "SaveOnly"),
            new XAttribute("ConflictResolution", "NeverOverwrite"),
            new XElement(M + "ItemChanges",
                new XElement(T + "ItemChange", ItemReference(normalizedItemId, normalizedChangeKey), updates)));
        var document = await SendAsync(normalizedMailbox, operation, cancellationToken).ConfigureAwait(false);
        return ParseItemReference(RequiredReturnedItem(document));
    }

    internal async Task<EwsItemRef> UpdateNativeDraftBodyAsync(
        string mailbox, EwsMessage expected, string body, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(expected);
        var normalizedMailbox = ValidateMailbox(mailbox);
        var itemId = ValidateItemId(expected.Id, "item");
        var changeKey = ValidateChangeKey(expected.ChangeKey);
        if (!expected.IsDraft || expected.BodyType != "HTML")
            throw new ArgumentException("The expected native HTML draft is invalid.", nameof(expected));
        var normalizedBody = RichBody.SerializeExchangeHtml(RichBody.ParseExchangeHtml(body));
        var operation = new XElement(M + "UpdateItem", new XAttribute("MessageDisposition", "SaveOnly"),
            new XAttribute("ConflictResolution", "NeverOverwrite"),
            new XElement(M + "ItemChanges", new XElement(T + "ItemChange", ItemReference(itemId, changeKey),
                new XElement(T + "Updates", SetField("item:Body", new XElement(T + "Message",
                    new XElement(T + "Body", new XAttribute("BodyType", "HTML"), normalizedBody)))))));
        var document = await SendAsync(normalizedMailbox, operation, cancellationToken).ConfigureAwait(false);
        var updated = ParseItemReference(RequiredReturnedItem(document));
        if (updated.Id != itemId || string.IsNullOrEmpty(updated.ChangeKey))
            throw new InvalidOperationException("The updated native draft revision could not be verified.");
        return updated;
    }

    public async Task<EwsItemRef> ForwardDraftAsync(
        string mailbox,
        string itemId,
        string changeKey,
        string body,
        IReadOnlyList<string> to,
        IReadOnlyList<string> cc,
        IReadOnlyList<string> bcc,
        CancellationToken cancellationToken,
        string bodyType = "Text",
        EwsReplySource? source = null)
    {
        var normalizedMailbox = ValidateMailbox(mailbox);
        var normalizedItemId = ValidateItemId(itemId, "item");
        var normalizedChangeKey = ValidateChangeKey(changeKey);
        _ = RichBody.Validate(body, bodyType);
        ValidateRecipients(to, nameof(to));
        ValidateRecipients(cc, nameof(cc));
        ValidateRecipients(bcc, nameof(bcc));
        if (to.Count == 0) throw new ArgumentException("At least one recipient is required.", nameof(to));
        if (source is not null && (!string.Equals(ValidateMailbox(source.Mailbox), normalizedMailbox, StringComparison.OrdinalIgnoreCase)
            || source.Message.Id != normalizedItemId || source.Message.ChangeKey != normalizedChangeKey))
            throw new ArgumentException("The forward presentation source does not match the selected mailbox and original message revision.", nameof(source));
        var transportBodyType = RichBody.NormalizeBodyType(bodyType);
        if (source?.Message.BodyType == "HTML" && transportBodyType == "Text")
        {
            // NewBodyContent also selects the native quote format; escape only the authored text.
            body = "<div>" + System.Net.WebUtility.HtmlEncode(body).Replace("\r\n", "\n", StringComparison.Ordinal)
                .Replace('\r', '\n').Replace("\n", "<br />", StringComparison.Ordinal) + "</div>";
            transportBodyType = "HTML";
        }
        var present = source is not null && transportBodyType == "HTML";
        var marker = present ? "company-forward-" + Guid.NewGuid().ToString("N") : null;
        var submittedBody = marker is null ? body : "<div id=\"" + marker + "\">" + body + "</div>";
        var zone = present ? await ReadReplyTimeZoneAsync(normalizedMailbox, cancellationToken).ConfigureAwait(false) : TimeZoneInfo.Utc;
        var forward = new XElement(T + "ForwardItem");
        AddRecipients(forward, "ToRecipients", to);
        AddRecipients(forward, "CcRecipients", cc);
        AddRecipients(forward, "BccRecipients", bcc);
        forward.Add(
            new XElement(T + "ReferenceItemId", new XAttribute("Id", normalizedItemId), new XAttribute("ChangeKey", normalizedChangeKey)),
            BuildBodyElement("NewBodyContent", submittedBody, transportBodyType));
        var operation = new XElement(M + "CreateItem",
            new XAttribute("MessageDisposition", "SaveOnly"),
            new XElement(M + "SavedItemFolderId", FolderReference("drafts")),
            new XElement(M + "Items", forward));
        var actorStorage = await NeedsActorSavedFolderAsync(normalizedMailbox, "drafts", cancellationToken).ConfigureAwait(false);
        var document = await SendAsync(normalizedMailbox, operation, cancellationToken, saveInActorFolder: actorStorage).ConfigureAwait(false);
        var draft = ParseItemReference(RequiredReturnedItem(document));
        draft = await UpdateDraftSenderAsync(normalizedMailbox, draft, ResolveDraftSender(normalizedMailbox, null), cancellationToken)
            .ConfigureAwait(false);
        return present ? await PresentReplyAsync(normalizedMailbox, draft, source!.Message, marker!, body, zone, cancellationToken)
            .ConfigureAwait(false) : draft;
    }

    public async Task<EwsItemRef> ReplyDraftAsync(
        string mailbox,
        string itemId,
        string body,
        bool replyAll,
        CancellationToken cancellationToken)
        => await ReplyDraftAsync(mailbox, itemId, null, body, replyAll, cancellationToken).ConfigureAwait(false);

    public async Task<EwsItemRef> ReplyDraftAsync(
        string mailbox,
        string itemId,
        string? changeKey,
        string body,
        bool replyAll,
        CancellationToken cancellationToken,
        string bodyType = "Text",
        IReadOnlyList<string>? to = null,
        IReadOnlyList<string>? cc = null,
        IReadOnlyList<string>? bcc = null,
        EwsReplySource? source = null)
    {
        var normalizedMailbox = ValidateMailbox(mailbox);
        var normalizedItemId = ValidateItemId(itemId, "item");
        _ = RichBody.Validate(body, bodyType);
        if (to is not null) ValidateRecipients(to, nameof(to));
        if (cc is not null) ValidateRecipients(cc, nameof(cc));
        if (bcc is not null) ValidateRecipients(bcc, nameof(bcc));
        if (source is not null && (!string.Equals(ValidateMailbox(source.Mailbox), normalizedMailbox, StringComparison.OrdinalIgnoreCase)
            || source.Message.Id != normalizedItemId || string.IsNullOrEmpty(changeKey) || source.Message.ChangeKey != changeKey))
            throw new ArgumentException("The reply presentation source does not match the selected mailbox and original message revision.", nameof(source));
        var transportBodyType = RichBody.NormalizeBodyType(bodyType);
        if (source?.Message.BodyType == "HTML" && transportBodyType == "Text")
        {
            // NewBodyContent also selects the native quote format; escape only the authored text.
            body = "<div>" + System.Net.WebUtility.HtmlEncode(body).Replace("\r\n", "\n", StringComparison.Ordinal)
                .Replace('\r', '\n').Replace("\n", "<br />", StringComparison.Ordinal) + "</div>";
            transportBodyType = "HTML";
        }
        var present = source is not null && transportBodyType == "HTML";
        var marker = present ? "company-reply-" + Guid.NewGuid().ToString("N") : null;
        var submittedBody = marker is null ? body : "<div id=\"" + marker + "\">" + body + "</div>";
        var zone = present ? await ReadReplyTimeZoneAsync(normalizedMailbox, cancellationToken).ConfigureAwait(false) : TimeZoneInfo.Utc;
        var operation = new XElement(
            M + "CreateItem",
            new XAttribute("MessageDisposition", "SaveOnly"),
            new XElement(M + "SavedItemFolderId", FolderReference("drafts")),
            new XElement(
                M + "Items",
                new XElement(
                    T + (replyAll ? "ReplyAllToItem" : "ReplyToItem"),
                    to is null ? null : RecipientsElement("ToRecipients", to),
                    cc is null ? null : RecipientsElement("CcRecipients", cc),
                    bcc is null ? null : RecipientsElement("BccRecipients", bcc),
                    BuildReferenceItem(normalizedItemId, changeKey),
                    BuildBodyElement("NewBodyContent", submittedBody, transportBodyType))));

        var actorStorage = await NeedsActorSavedFolderAsync(normalizedMailbox, "drafts", cancellationToken).ConfigureAwait(false);
        var document = await SendAsync(normalizedMailbox, operation, cancellationToken, saveInActorFolder: actorStorage).ConfigureAwait(false);
        var draft = ParseItemReference(RequiredReturnedItem(document));
        draft = await UpdateDraftSenderAsync(normalizedMailbox, draft, ResolveDraftSender(normalizedMailbox, null), cancellationToken)
            .ConfigureAwait(false);
        return present ? await PresentReplyAsync(normalizedMailbox, draft, source!.Message, marker!, body, zone, cancellationToken)
            .ConfigureAwait(false) : draft;
    }

    public async Task<EwsItemRef> MoveMessageAsync(
        string mailbox,
        string itemId,
        string destinationFolderId,
        CancellationToken cancellationToken)
        => await MoveMessageAsync(mailbox, itemId, null, destinationFolderId, cancellationToken).ConfigureAwait(false);

    public async Task<EwsItemRef> MoveMessageAsync(
        string mailbox,
        string itemId,
        string? changeKey,
        string destinationFolderId,
        CancellationToken cancellationToken)
    {
        var normalizedMailbox = ValidateMailbox(mailbox);
        var normalizedItemId = ValidateItemId(itemId, "item");
        var normalizedDestination = ValidateItemId(destinationFolderId, "destination folder");
        var operation = new XElement(
            M + "MoveItem",
            new XElement(M + "ToFolderId", FolderReference(normalizedDestination)),
            new XElement(M + "ItemIds", ItemReference(normalizedItemId, changeKey)));

        var document = await SendAsync(normalizedMailbox, operation, cancellationToken).ConfigureAwait(false);
        return ParseItemReference(RequiredReturnedItem(document));
    }

    public async Task SetReadStateAsync(
        string mailbox,
        string itemId,
        string changeKey,
        bool isRead,
        CancellationToken cancellationToken)
    {
        var normalizedMailbox = ValidateMailbox(mailbox);
        var normalizedItemId = ValidateItemId(itemId, "item");
        var normalizedChangeKey = ValidateChangeKey(changeKey);
        var operation = new XElement(
            M + "UpdateItem",
            new XAttribute("MessageDisposition", "SaveOnly"),
            new XAttribute("ConflictResolution", "NeverOverwrite"),
            new XAttribute("SuppressReadReceipts", "true"),
            new XElement(
                M + "ItemChanges",
                new XElement(
                    T + "ItemChange",
                    ItemReference(normalizedItemId, normalizedChangeKey),
                    new XElement(
                        T + "Updates",
                        new XElement(
                            T + "SetItemField",
                            new XElement(T + "FieldURI", new XAttribute("FieldURI", "message:IsRead")),
                            new XElement(T + "Message", new XElement(T + "IsRead", isRead)))))));

        await SendAsync(normalizedMailbox, operation, cancellationToken).ConfigureAwait(false);
    }

    public async Task SoftDeleteAsync(
        string mailbox,
        string itemId,
        CancellationToken cancellationToken)
        => await SoftDeleteAsync(mailbox, itemId, null, cancellationToken).ConfigureAwait(false);

    public async Task SoftDeleteAsync(
        string mailbox,
        string itemId,
        string? changeKey,
        CancellationToken cancellationToken)
    {
        var normalizedMailbox = ValidateMailbox(mailbox);
        var normalizedItemId = ValidateItemId(itemId, "item");
        var operation = new XElement(
            M + "DeleteItem",
            new XAttribute("DeleteType", "MoveToDeletedItems"),
            new XAttribute("SuppressReadReceipts", "true"),
            new XElement(M + "ItemIds", ItemReference(normalizedItemId, changeKey)));

        await SendAsync(normalizedMailbox, operation, cancellationToken).ConfigureAwait(false);
    }

    public async Task SendDraftAsync(
        string mailbox,
        string itemId,
        string changeKey,
        CancellationToken cancellationToken)
    {
        var normalizedMailbox = ValidateMailbox(mailbox);
        var normalizedItemId = ValidateItemId(itemId, "item");
        var normalizedChangeKey = ValidateChangeKey(changeKey);
        var operation = new XElement(
            M + "SendItem",
            new XAttribute("SaveItemToFolder", "true"),
            new XElement(M + "ItemIds", ItemReference(normalizedItemId, normalizedChangeKey)),
            DelegatedSenderFolder(normalizedMailbox));

        var actorStorage = await NeedsActorSavedFolderAsync(normalizedMailbox, "sentitems", cancellationToken).ConfigureAwait(false);
        await SendAsync(normalizedMailbox, operation, cancellationToken, saveInActorFolder: actorStorage).ConfigureAwait(false);
    }

    private async Task<bool> NeedsActorSavedFolderAsync(string mailbox, string folder, CancellationToken cancellationToken)
    {
        if (_mailboxAccess?.CurrentSelection is not { TargetId: not "own" }) return false;
        try
        {
            var rights = await GetEffectiveRightsAsync(mailbox, folder, cancellationToken).ConfigureAwait(false);
            return rights.Create != true;
        }
        catch (EwsPermissionDeniedException) { return true; }
        catch (EwsRequestFailedException exception) when (exception.ResponseCode == "ErrorFolderNotFound") { return true; }
    }

    private string? ResolveDraftSender(string targetMailbox, string? requestedSender)
    {
        if (requestedSender is not null)
            return ValidateMailbox(requestedSender);

        var selection = _mailboxAccess?.CurrentSelection;
        return selection is { TargetId: not "own" } ? targetMailbox : null;
    }

    private async Task<EwsItemRef> UpdateDraftSenderAsync(
        string mailbox,
        EwsItemRef draft,
        string? sender,
        CancellationToken cancellationToken)
    {
        if (sender is null)
            return draft;

        var operation = new XElement(
            M + "UpdateItem",
            new XAttribute("MessageDisposition", "SaveOnly"),
            new XAttribute("ConflictResolution", "NeverOverwrite"),
            new XElement(M + "ItemChanges",
                new XElement(T + "ItemChange",
                    ItemReference(draft.Id, ValidateChangeKey(draft.ChangeKey)),
                    new XElement(T + "Updates", SetMailboxField("message:From", "From", sender)))));
        var document = await SendAsync(mailbox, operation, cancellationToken).ConfigureAwait(false);
        return ParseItemReference(RequiredReturnedItem(document));
    }

    private XElement? DelegatedSenderFolder(string targetMailbox) =>
        ResolveDraftSender(targetMailbox, null) is null
            ? null
            : new XElement(M + "SavedItemFolderId", FolderReference("sentitems"));

    public async Task<EwsFolder> CreateFolderAsync(
        string mailbox,
        string parentFolderId,
        string name,
        CancellationToken cancellationToken)
    {
        var normalizedMailbox = ValidateMailbox(mailbox);
        var normalizedParent = ValidateItemId(parentFolderId, "parent folder");
        if (string.IsNullOrWhiteSpace(name) || name.Length > 255 || name.IndexOfAny(['\r', '\n']) >= 0)
        {
            throw new ArgumentException("The folder name is invalid.", nameof(name));
        }

        var operation = new XElement(
            M + "CreateFolder",
            new XElement(M + "ParentFolderId", FolderReference(normalizedParent)),
            new XElement(
                M + "Folders",
                new XElement(T + "Folder", new XElement(T + "DisplayName", name))));

        var document = await SendAsync(normalizedMailbox, operation, cancellationToken).ConfigureAwait(false);
        return ParseFolder(RequiredElement(document, T + "Folder"));
    }

    public async Task<EwsFolder> RenameFolderAsync(
        string mailbox,
        string folderId,
        string changeKey,
        string name,
        CancellationToken cancellationToken)
    {
        var normalizedMailbox = ValidateMailbox(mailbox);
        var normalizedFolder = ValidateItemId(folderId, "folder");
        var normalizedChangeKey = ValidateChangeKey(changeKey);
        ValidateFolderName(name);
        var operation = new XElement(M + "UpdateFolder",
            new XElement(M + "FolderChanges",
                new XElement(T + "FolderChange", FolderReference(normalizedFolder, normalizedChangeKey),
                    new XElement(T + "Updates",
                        new XElement(T + "SetFolderField",
                            Field("folder:DisplayName"),
                            new XElement(T + "Folder", new XElement(T + "DisplayName", name)))))));
        var document = await SendAsync(normalizedMailbox, operation, cancellationToken).ConfigureAwait(false);
        return ParseFolder(RequiredElement(document, T + "Folder"));
    }

    public async Task SoftDeleteFolderAsync(
        string mailbox,
        string folderId,
        string changeKey,
        CancellationToken cancellationToken)
    {
        var normalizedMailbox = ValidateMailbox(mailbox);
        var normalizedFolder = ValidateItemId(folderId, "folder");
        var normalizedChangeKey = ValidateChangeKey(changeKey);
        var operation = new XElement(M + "DeleteFolder",
            new XAttribute("DeleteType", "MoveToDeletedItems"),
            new XElement(M + "FolderIds", FolderReference(normalizedFolder, normalizedChangeKey)));
        await SendAsync(normalizedMailbox, operation, cancellationToken).ConfigureAwait(false);
    }

    public async Task<EwsItemRef> UpdateCategoriesAsync(
        string mailbox,
        string itemId,
        string changeKey,
        IReadOnlyList<string> categories,
        CancellationToken cancellationToken)
    {
        var normalizedMailbox = ValidateMailbox(mailbox);
        var normalizedItemId = ValidateItemId(itemId, "item");
        var normalizedChangeKey = ValidateChangeKey(changeKey);
        ValidateCategories(categories);
        var values = new XElement(T + "Categories", categories.Select(category => new XElement(T + "String", category)));
        var operation = new XElement(M + "UpdateItem",
            new XAttribute("MessageDisposition", "SaveOnly"),
            new XAttribute("ConflictResolution", "NeverOverwrite"),
            new XElement(M + "ItemChanges",
                new XElement(T + "ItemChange", ItemReference(normalizedItemId, normalizedChangeKey),
                    new XElement(T + "Updates",
                        new XElement(T + "SetItemField", Field("item:Categories"),
                            new XElement(T + "Message", values))))));
        var document = await SendAsync(normalizedMailbox, operation, cancellationToken).ConfigureAwait(false);
        return ParseItemReference(RequiredReturnedItem(document));
    }

    public async Task<EwsAttachmentResult> CreateFileAttachmentAsync(
        string mailbox,
        string itemId,
        string changeKey,
        string name,
        byte[] content,
        string? contentType,
        CancellationToken cancellationToken,
        bool isInline = false,
        string? contentId = null)
    {
        var normalizedMailbox = ValidateMailbox(mailbox);
        var normalizedItemId = ValidateItemId(itemId, "item");
        var normalizedChangeKey = ValidateChangeKey(changeKey);
        ValidateAttachmentName(name);
        ArgumentNullException.ThrowIfNull(content);
        if (content.Length > MaxAttachmentBytes) throw new ArgumentException("The attachment is too large.", nameof(content));
        if (contentType is not null && (contentType.Length > 255 || contentType.IndexOfAny(['\r', '\n']) >= 0))
            throw new ArgumentException("The attachment content type is invalid.", nameof(contentType));
        if (isInline && (contentType is null || !RichBody.HasImageHeader(content, contentType)))
            throw new ArgumentException("Inline attachments must contain matching PNG, JPEG or GIF image bytes.", nameof(contentType));
        if (isInline) ValidateContentId(contentId);
        else if (!string.IsNullOrWhiteSpace(contentId)) throw new ArgumentException("A content ID is only valid for inline attachments.", nameof(contentId));
        var file = new XElement(T + "FileAttachment",
            new XElement(T + "Name", name),
            string.IsNullOrWhiteSpace(contentType) ? null : new XElement(T + "ContentType", contentType),
            isInline ? new XElement(T + "ContentId", contentId) : null,
            isInline ? new XElement(T + "IsInline", true) : null,
            new XElement(T + "Content", Convert.ToBase64String(content)));
        var operation = new XElement(M + "CreateAttachment",
            new XElement(M + "ParentItemId", new XAttribute("Id", normalizedItemId), new XAttribute("ChangeKey", normalizedChangeKey)),
            new XElement(M + "Attachments", file));
        var document = await SendAsync(normalizedMailbox, operation, cancellationToken).ConfigureAwait(false);
        var responseAttachment = document.Descendants(T + "FileAttachment").FirstOrDefault()
            ?? throw new InvalidOperationException("Exchange returned no attachment.");
        var attachmentReference = responseAttachment.Element(T + "AttachmentId");
        var attachmentId = attachmentReference?.Attribute("Id")?.Value;
        var parentId = attachmentReference?.Attribute("RootItemId")?.Value ?? normalizedItemId;
        var parentChangeKey = attachmentReference?.Attribute("RootItemChangeKey")?.Value ?? string.Empty;
        if (string.IsNullOrWhiteSpace(attachmentId)) throw new InvalidOperationException("Exchange returned no attachment identifier.");
        return new EwsAttachmentResult(
            new EwsItemRef(parentId, parentChangeKey),
            new EwsAttachment(attachmentId, name, content.Length, isInline, contentType, contentId));
    }

    public async Task<EwsAttachmentContent> GetAttachmentAsync(
        string mailbox,
        string attachmentId,
        CancellationToken cancellationToken)
    {
        var normalizedMailbox = ValidateMailbox(mailbox);
        var normalizedAttachment = ValidateItemId(attachmentId, "attachment");
        var operation = new XElement(M + "GetAttachment",
            new XElement(M + "AttachmentShape", new XElement(T + "BodyType", "Text")),
            new XElement(M + "AttachmentIds", new XElement(T + "AttachmentId", new XAttribute("Id", normalizedAttachment))));
        var document = await SendAsync(normalizedMailbox, operation, cancellationToken).ConfigureAwait(false);
        var file = document.Descendants(T + "FileAttachment").FirstOrDefault()
            ?? throw new InvalidOperationException("Exchange returned no file attachment.");
        var contentText = file.Element(T + "Content")?.Value ?? string.Empty;
        byte[] content;
        try { content = Convert.FromBase64String(contentText); }
        catch (FormatException) { throw new InvalidOperationException("Exchange returned an invalid attachment."); }
        if (content.Length > MaxAttachmentBytes) throw new InvalidOperationException("The attachment exceeded the supported size.");
        return new EwsAttachmentContent(
            normalizedAttachment,
            file.Element(T + "Name")?.Value ?? string.Empty,
            file.Element(T + "ContentType")?.Value,
            content,
            ReadBool(file.Element(T + "IsInline")),
            file.Element(T + "ContentId")?.Value);
    }

    public async Task<EwsItemRef> DeleteAttachmentAsync(
        string mailbox,
        string attachmentId,
        CancellationToken cancellationToken)
    {
        var normalizedMailbox = ValidateMailbox(mailbox);
        var normalizedAttachment = ValidateItemId(attachmentId, "attachment");
        var operation = new XElement(M + "DeleteAttachment",
            new XElement(M + "AttachmentIds", new XElement(T + "AttachmentId", new XAttribute("Id", normalizedAttachment))));
        var document = await SendAsync(normalizedMailbox, operation, cancellationToken).ConfigureAwait(false);
        var parentReference = document.Descendants(M + "RootItemId").FirstOrDefault();
        var parentId = parentReference?.Attribute("RootItemId")?.Value
            ?? throw new InvalidOperationException("Exchange returned no parent message.");
        return new EwsItemRef(parentId, parentReference.Attribute("RootItemChangeKey")?.Value ?? string.Empty);
    }

    private async Task<XDocument> SendAsync(
        string mailbox,
        XElement operation,
        CancellationToken cancellationToken,
        bool allowMissingUserConfiguration = false,
        Action<XDocument, string>? responseValidator = null,
        bool allowPartialResponseErrors = false,
        bool saveInActorFolder = false,
        string? metadataOwner = null)
    {
        if (allowPartialResponseErrors && (operation.Name != M + "GetFolder" || responseValidator is not null))
            throw new ArgumentException("Partial Exchange responses are limited to folder discovery.", nameof(allowPartialResponseErrors));
        var normalizedMailbox = ValidateMailbox(mailbox);
        string actorMailbox;
        string targetMailbox;
        var metadataContext = folderMetadataContext.Value;
        if (metadataOwner is null)
        {
            if (metadataContext is not null)
                throw new InvalidOperationException("Owner metadata context requires an explicit validated metadata owner.");
            (actorMailbox, targetMailbox) = ResolveRequestMailboxes(normalizedMailbox);
        }
        else
        {
            if (metadataContext is null)
                throw new InvalidOperationException("Owner folder metadata access is not active.");
            ValidateFolderMetadataRequest(normalizedMailbox, metadataOwner, operation, metadataContext,
                allowMissingUserConfiguration, responseValidator, allowPartialResponseErrors);
            actorMailbox = metadataOwner;
            targetMailbox = metadataOwner;
        }
        var requestOperation = BindTargetFolderReferences(operation, actorMailbox, targetMailbox);
        var isSendItem = requestOperation.Name == M + "SendItem";
        var isMailSubmission = isSendItem || requestOperation.Name == M + "CreateItem"
            && (string?)requestOperation.Attribute("MessageDisposition") == "SendAndSaveCopy"
            && requestOperation.Element(M + "Items")?.Elements(T + "Message")
                .Any(message => (string?)message.Element(T + "ItemClass") == "IPM.Outlook.Recall") == true;
        if (saveInActorFolder)
        {
            var saved = requestOperation.Element(M + "SavedItemFolderId")?.Element(T + "DistinguishedFolderId");
            if (metadataContext is not null || operation.Name != M + "CreateItem" && operation.Name != M + "SendItem"
                || saved is null || (string?)saved.Attribute("Id") is not ("drafts" or "sentitems"))
                throw new InvalidOperationException("Actor-owned storage is limited to draft and sent-item folders.");
            saved.Element(T + "Mailbox")?.Remove();
            saved.Add(new XElement(T + "Mailbox", new XElement(T + "EmailAddress", actorMailbox)));
        }

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(_options.TimeoutSeconds));

        using var request = new HttpRequestMessage(HttpMethod.Post, _endpoint)
        {
            Content = new StringContent(
                BuildEnvelope(actorMailbox, targetMailbox, requestOperation).ToString(SaveOptions.DisableFormatting),
                Encoding.UTF8,
                "text/xml")
        };
        // Exchange uses this header to route the request to the mailbox being
        // impersonated.  A delegated target is bound separately on each
        // DistinguishedFolderId, so anchoring to the target would contradict
        // ConnectingSID and can route the request outside the actor context.
        if (!request.Headers.TryAddWithoutValidation("X-AnchorMailbox", actorMailbox))
        {
            throw new InvalidOperationException("The Exchange anchor mailbox header could not be added.");
        }
        request.Headers.TryAddWithoutValidation("SOAPAction", $"\"{MessagesNamespace}/{requestOperation.Name.LocalName}\"");
        var tracking = OperationTracking.Current;
        if (tracking is not null
            && (!request.Headers.TryAddWithoutValidation("client-request-id", Guid.ParseExact(tracking.Id, "N").ToString("D"))
                || !request.Headers.TryAddWithoutValidation("return-client-request-id", "true")))
        {
            throw new InvalidOperationException("The Exchange tracking headers could not be added.");
        }

        HttpResponseMessage response;
        try
        {
            if (isMailSubmission) tracking?.SetExchangeSendDispatched();
            response = await _httpClient.SendAsync(
                request,
                HttpCompletionOption.ResponseHeadersRead,
                timeout.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new TimeoutException(TimeoutError);
        }
        catch (HttpRequestException)
        {
            throw new InvalidOperationException("The Exchange request failed.");
        }

        using (response)
        {
            byte[] payload;
            try
            {
                payload = await ReadBoundedAsync(response, timeout.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                throw new TimeoutException(TimeoutError);
            }
            catch (HttpRequestException)
            {
                throw new InvalidOperationException("The Exchange response could not be read.");
            }

            XDocument document;
            try
            {
                using var stream = new MemoryStream(payload, writable: false);
                using var reader = XmlReader.Create(
                    stream,
                    new XmlReaderSettings
                    {
                        DtdProcessing = DtdProcessing.Prohibit,
                        XmlResolver = null,
                        MaxCharactersInDocument = _options.MaxResponseBytes
                    });
                document = XDocument.Load(reader, LoadOptions.None);
            }
            catch (XmlException)
            {
                if (!response.IsSuccessStatusCode)
                    throw new EwsRequestFailedException(null, requestOperation.Name.LocalName, rejected: true);
                throw new InvalidOperationException("Exchange returned an invalid response.");
            }

            try
            {
                if (!response.IsSuccessStatusCode)
                {
                    ThrowPermissionDeniedIfPresent(document, requestOperation.Name.LocalName);
                    throw new EwsRequestFailedException(FirstErrorResponseCode(document), requestOperation.Name.LocalName,
                        rejected: true, errorField: FirstErrorField(document));
                }

                if (responseValidator is null && allowPartialResponseErrors)
                    ValidatePartialResponse(document, requestOperation.Name.LocalName);
                else if (responseValidator is null) ValidateResponse(document, requestOperation.Name.LocalName, allowMissingUserConfiguration);
                else
                {
                    ThrowPermissionDeniedIfPresent(document, requestOperation.Name.LocalName);
                    responseValidator(document, requestOperation.Name.LocalName);
                }
            }
            catch (EwsRequestFailedException exception) when (isMailSubmission)
            {
                // Only a parsed Exchange error code proves the operation was rejected.
                // HTTP gateway errors, malformed responses and timeouts remain unknown.
                if (exception.ResponseCode is not null) tracking?.SetExchangeSendRejected();
                throw;
            }
            catch (EwsPermissionDeniedException) when (isMailSubmission)
            {
                tracking?.SetExchangeSendRejected();
                throw;
            }
            if (isMailSubmission) tracking?.SetExchangeSendAcknowledged();
            return document;
        }
    }

    private async Task<byte[]> ReadBoundedAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        await using var source = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        await using var destination = new MemoryStream();
        var buffer = new byte[16 * 1024];
        long total = 0;
        int read;
        while ((read = await source.ReadAsync(buffer.AsMemory(), cancellationToken).ConfigureAwait(false)) > 0)
        {
            total += read;
            if (total > _options.MaxResponseBytes)
            {
                throw new InvalidOperationException("The Exchange response exceeded the configured size limit.");
            }

            await destination.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
        }

        return destination.ToArray();
    }

    private (string ActorMailbox, string TargetMailbox) ResolveRequestMailboxes(string targetMailbox)
    {
        var selected = _mailboxAccess?.CurrentSelection;
        if (_mailboxAccess is not null && selected is null)
            throw new InvalidOperationException("Exchange mailbox operation has no authenticated actor context.");
        if (selected is null)
            return (targetMailbox, targetMailbox);

        if (!string.Equals(selected.Mailbox, targetMailbox, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Exchange mailbox selection does not match the requested target.");

        var actorMailbox = ValidateMailbox(selected.ActorMailbox ?? selected.Mailbox);
        return (actorMailbox, targetMailbox);
    }

    private static XDocument BuildEnvelope(string actorMailbox, string targetMailbox, XElement operation)
    {
        return new XDocument(
            new XElement(
                Soap + "Envelope",
                new XAttribute(Xmlns + "soap", SoapEnvelopeNamespace),
                new XAttribute(Xmlns + "m", MessagesNamespace),
                new XAttribute(Xmlns + "t", TypesNamespace),
                new XElement(
                    Soap + "Header",
                    new XElement(
                        T + "RequestServerVersion",
                        new XAttribute("Version", "Exchange2016")),
                    new XElement(
                        T + "ExchangeImpersonation",
                        new XElement(
                            T + "ConnectingSID",
                             new XElement(T + "PrimarySmtpAddress", actorMailbox)))),
                new XElement(Soap + "Body", operation)));
    }

    private static XElement BindTargetFolderReferences(XElement operation, string actorMailbox, string targetMailbox)
    {
        var clone = new XElement(operation);
        if (string.Equals(actorMailbox, targetMailbox, StringComparison.OrdinalIgnoreCase))
            return clone;

        foreach (var folder in clone.Descendants(T + "DistinguishedFolderId"))
        {
            var mailbox = folder.Element(T + "Mailbox");
            if (mailbox is null)
            {
                folder.Add(new XElement(T + "Mailbox", new XElement(T + "EmailAddress", targetMailbox)));
                continue;
            }

            var address = mailbox.Element(T + "EmailAddress");
            if (address is null)
                mailbox.Add(new XElement(T + "EmailAddress", targetMailbox));
            else
                address.Value = targetMailbox;
        }

        return clone;
    }

    private static XElement MessageShape(bool summaryOnly = false)
    {
        var shape = new XElement(
            M + "ItemShape",
            new XElement(T + "BaseShape", "IdOnly"),
            new XElement(T + "BodyType", "Best"),
            new XElement(T + "AdditionalProperties",
                Field("item:Subject"),
                Field("message:From"),
                Field("message:Sender"),
                Field("item:DateTimeReceived"),
                Field("item:DateTimeSent"),
                Field("item:Importance"),
                Field("message:IsRead"),
                Field("item:IsDraft"),
                Field("item:Categories")));
        if (!summaryOnly)
            shape.Element(T + "AdditionalProperties")!.Add(Field("message:ToRecipients"),
                Field("message:CcRecipients"), Field("message:BccRecipients"), Field("item:Body"), Field("item:Attachments"));
        return shape;
    }

    private static XElement Field(string fieldUri) =>
        new(T + "FieldURI", new XAttribute("FieldURI", fieldUri));

    private static XElement ContainsRestriction(string query)
    {
        return new XElement(
            T + "Or",
            Contains("item:Subject", query),
            Contains("item:Body", query));
    }

    private static XElement Contains(string fieldUri, string value)
    {
        return new XElement(
            T + "Contains",
            new XAttribute("ContainmentMode", "Substring"),
            new XAttribute("ContainmentComparison", "IgnoreCase"),
            Field(fieldUri),
            new XElement(T + "Constant", new XAttribute("Value", value)));
    }

    private static XElement Equal(string fieldUri, string value) =>
        new(T + "IsEqualTo", Field(fieldUri),
            new XElement(T + "FieldURIOrConstant", new XElement(T + "Constant", new XAttribute("Value", value))));

    private static XElement DateRestriction(string comparison, DateTimeOffset value) =>
        new(T + comparison, Field("item:DateTimeReceived"),
            new XElement(T + "FieldURIOrConstant", new XElement(T + "Constant",
                new XAttribute("Value", value.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ", CultureInfo.InvariantCulture)))));

    private static XElement AndRestrictions(IReadOnlyList<XElement> restrictions)
    {
        if (restrictions.Count == 1) return restrictions[0];
        var current = new XElement(T + "And", restrictions[0], restrictions[1]);
        for (var index = 2; index < restrictions.Count; index++)
            current = new XElement(T + "And", current, restrictions[index]);
        return current;
    }

    private static XElement BuildMessage(
        string subject,
        string body,
        IReadOnlyList<string> to,
        IReadOnlyList<string> cc,
        IReadOnlyList<string> bcc,
        string bodyType = "Text",
        string? from = null)
    {
        if (subject is null || subject.Length > 998 || subject.IndexOfAny(['\r', '\n']) >= 0)
        {
            throw new ArgumentException("The draft subject is invalid.", nameof(subject));
        }

        var normalizedBody = RichBody.Validate(body, bodyType);
        ValidateRecipients(to, nameof(to));
        ValidateRecipients(cc, nameof(cc));
        ValidateRecipients(bcc, nameof(bcc));
        if (to.Count + cc.Count + bcc.Count > MaxRecipients)
            throw new ArgumentException("The combined recipient list is too long.");
        var message = new XElement(
            T + "Message",
            new XElement(T + "Subject", subject),
            BuildBodyElement("Body", normalizedBody, bodyType));
        AddRecipients(message, "ToRecipients", to);
        AddRecipients(message, "CcRecipients", cc);
        AddRecipients(message, "BccRecipients", bcc);
        if (from is not null)
        {
            message.Add(new XElement(T + "From", MailboxElement(from)));
        }
        return message;
    }

    private static XElement SetField(string fieldUri, XElement messageValue) =>
        new(T + "SetItemField", Field(fieldUri), messageValue);

    private static XElement SetRecipientsField(string fieldUri, string elementName, IReadOnlyList<string> recipients)
    {
        var value = new XElement(T + "Message");
        if (recipients.Count == 0) value.Add(new XElement(T + elementName));
        else AddRecipients(value, elementName, recipients);
        return SetField(fieldUri, value);
    }

    private static XElement SetMailboxField(string fieldUri, string elementName, string mailbox) =>
        SetField(fieldUri, new XElement(T + "Message", new XElement(T + elementName, MailboxElement(mailbox))));

    private static XElement MailboxElement(string mailbox) =>
        new XElement(T + "Mailbox", new XElement(T + "EmailAddress", NormalizeAddress(mailbox)));

    private static XElement RecipientsElement(string elementName, IReadOnlyList<string> recipients) =>
        new(T + elementName, recipients.Select(address => new XElement(T + "Mailbox",
            new XElement(T + "EmailAddress", NormalizeAddress(address)))));

    private static XElement BuildBodyElement(string elementName, string body, string bodyType)
    {
        var normalizedType = RichBody.NormalizeBodyType(bodyType);
        var normalizedBody = RichBody.Validate(body, normalizedType);
        return new XElement(T + elementName, new XAttribute("BodyType", normalizedType), normalizedBody);
    }

    private static void AddRecipients(XElement message, string elementName, IReadOnlyList<string> recipients)
    {
        if (recipients.Count == 0)
        {
            return;
        }

        message.Add(
            new XElement(
                T + elementName,
                recipients.Select(
                    address => new XElement(
                        T + "Mailbox",
                        new XElement(T + "EmailAddress", NormalizeAddress(address))))));
    }

    private static void ValidateRecipients(IReadOnlyList<string> recipients, string parameterName)
    {
        ArgumentNullException.ThrowIfNull(recipients);
        if (recipients.Count > MaxRecipients)
        {
            throw new ArgumentException("The recipient list is too long.", parameterName);
        }

        foreach (var recipient in recipients)
        {
            _ = NormalizeAddress(recipient);
        }
    }

    private static string NormalizeAddress(string address)
    {
        if (string.IsNullOrWhiteSpace(address) || address.IndexOfAny(['\r', '\n']) >= 0 || address.Length > MaxMailboxLength)
        {
            throw new ArgumentException("The email address is invalid.");
        }

        try
        {
            var parsed = new MailAddress(address);
            if (!string.Equals(parsed.Address, address, StringComparison.OrdinalIgnoreCase))
            {
                throw new FormatException();
            }

            return parsed.Address;
        }
        catch (FormatException)
        {
            throw new ArgumentException("The email address is invalid.");
        }
    }

    private static string ValidateMailbox(string mailbox) => NormalizeAddress(mailbox);

    private static string ValidateItemId(string value, string name)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > MaxItemIdLength || value.IndexOfAny(['\r', '\n']) >= 0)
        {
            throw new ArgumentException("The Exchange identifier is invalid.", name);
        }

        return value;
    }

    private static string ValidateChangeKey(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > MaxItemIdLength || value.IndexOfAny(['\r', '\n']) >= 0)
        {
            throw new ArgumentException("The Exchange change key is invalid.", nameof(value));
        }

        return value;
    }

    private static void ValidateFolderName(string name)
    {
        if (string.IsNullOrWhiteSpace(name) || name.Length > 255 || name.IndexOfAny(['\r', '\n']) >= 0 || name.Any(char.IsControl))
            throw new ArgumentException("The folder name is invalid.", nameof(name));
    }

    private static void ValidateAttachmentName(string name)
    {
        if (string.IsNullOrWhiteSpace(name) || name.Length > MaxAttachmentNameLength
            || name.IndexOfAny(['\r', '\n']) >= 0 || name.Any(char.IsControl))
            throw new ArgumentException("The attachment name is invalid.", nameof(name));
    }

    private static void ValidateContentId(string? contentId)
    {
        if (string.IsNullOrWhiteSpace(contentId) || contentId.Length > 255 || contentId.Any(char.IsControl)
            || contentId.Any(character => !(char.IsLetterOrDigit(character) || character is '.' or '-' or '_' or '+' or '@' or '%' or ':' or '/')))
            throw new ArgumentException("The inline attachment content ID is invalid.", nameof(contentId));
    }

    private static void ValidateCategories(IReadOnlyList<string> categories)
    {
        ArgumentNullException.ThrowIfNull(categories);
        if (categories.Count > 100) throw new ArgumentException("Too many categories.", nameof(categories));
        if (categories.Any(category => string.IsNullOrWhiteSpace(category) || category.Length > 255
            || category.IndexOfAny(['\r', '\n']) >= 0 || category.Any(char.IsControl)))
            throw new ArgumentException("A category is invalid.", nameof(categories));
    }

    private static void ValidateBody(string body)
    {
        if (body is null || body.Length > MaxBodyLength)
        {
            throw new ArgumentException("The message body is invalid.", nameof(body));
        }
    }

    private static void ValidatePage(int offset, int limit)
    {
        if (offset is < 0 or > 1_000_000 || limit is < 1 or > 100)
        {
            throw new ArgumentOutOfRangeException(offset < 0 || offset > 1_000_000 ? nameof(offset) : nameof(limit));
        }
    }

    private static XElement FolderReference(string value)
    {
        if (DistinguishedFolders.TryGetValue(value, out var distinguishedId))
        {
            return new XElement(T + "DistinguishedFolderId", new XAttribute("Id", distinguishedId));
        }

        return new XElement(T + "FolderId", new XAttribute("Id", value));
    }

    private static XElement FolderReference(string value, string changeKey)
    {
        var reference = FolderReference(value);
        if (!reference.Name.LocalName.Equals("DistinguishedFolderId", StringComparison.Ordinal))
            reference.Add(new XAttribute("ChangeKey", changeKey));
        return reference;
    }

    private static XElement ItemReference(string id, string? changeKey = null)
    {
        var item = new XElement(T + "ItemId", new XAttribute("Id", id));
        if (!string.IsNullOrEmpty(changeKey))
        {
            item.Add(new XAttribute("ChangeKey", changeKey));
        }

        return item;
    }

    private static XElement BuildReferenceItem(string id, string? changeKey) =>
        new XElement(T + "ReferenceItemId", new XAttribute("Id", id),
            string.IsNullOrEmpty(changeKey) ? null : new XAttribute("ChangeKey", ValidateChangeKey(changeKey)));

    private static XElement RequiredElement(XDocument document, XName name) =>
        document.Descendants(name).FirstOrDefault()
        ?? throw new InvalidOperationException("Exchange returned an incomplete response.");

    private static XElement RequiredReturnedItem(XDocument document) =>
        document.Descendants()
            .FirstOrDefault(item => item.Name.Namespace == T && item.Element(T + "ItemId") is not null)
        ?? throw new InvalidOperationException("Exchange returned no item.");

    private static EwsItemRef ParseItemReference(XElement item)
    {
        var id = item.Element(T + "ItemId") ?? item.Descendants(T + "ItemId").FirstOrDefault();
        if (id is null || string.IsNullOrEmpty((string?)id.Attribute("Id")))
        {
            throw new InvalidOperationException("Exchange returned no item identifier.");
        }

        return new EwsItemRef(
            (string)id.Attribute("Id")!,
            (string?)id.Attribute("ChangeKey") ?? string.Empty);
    }

    private static EwsFolder ParseFolder(XElement folder)
    {
        var id = folder.Element(T + "FolderId");
        if (id is null || string.IsNullOrEmpty((string?)id.Attribute("Id")))
        {
            throw new InvalidOperationException("Exchange returned a folder without an identifier.");
        }

        return new EwsFolder(
            (string)id.Attribute("Id")!,
            (string?)id.Attribute("ChangeKey") ?? string.Empty,
            folder.Element(T + "DisplayName")?.Value ?? string.Empty,
            ReadInt(folder.Element(T + "TotalCount")),
            ReadInt(folder.Element(T + "UnreadCount")),
            ParseFolderParentId(folder));
    }

    private static EwsMessage ParseMessage(XElement message)
    {
        var id = message.Element(T + "ItemId");
        if (id is null || string.IsNullOrEmpty((string?)id.Attribute("Id")))
        {
            throw new InvalidOperationException("Exchange returned a message without an identifier.");
        }

        var fromMailbox = message.Element(T + "From")?.Element(T + "Mailbox");
        var from = fromMailbox?.Element(T + "EmailAddress")?.Value ?? fromMailbox?.Element(T + "Name")?.Value;
        var senderMailbox = message.Element(T + "Sender")?.Element(T + "Mailbox");
        var sender = senderMailbox?.Element(T + "EmailAddress")?.Value ?? senderMailbox?.Element(T + "Name")?.Value;
        var attachmentNames = ParseAttachmentNames(message.Element(T + "Attachments"));
        var attachments = ParseAttachments(message.Element(T + "Attachments"));
        var attachmentCount = message.Element(T + "Attachments")?.Elements().Count() ?? 0;
        if (attachmentCount > MaxAttachments || attachmentNames.Count > MaxAttachments || attachments.Count > MaxAttachments)
            throw new InvalidOperationException("Exchange returned more attachments than the supported limit.");
        var body = message.Element(T + "Body");
        var bodyType = RichBody.NormalizeBodyType((string?)body?.Attribute("BodyType"));
        return new EwsMessage(
            (string)id.Attribute("Id")!,
            (string?)id.Attribute("ChangeKey") ?? string.Empty,
            message.Element(T + "Subject")?.Value ?? string.Empty,
            string.IsNullOrWhiteSpace(from) ? null : from,
            ParseRecipients(message.Element(T + "ToRecipients")),
            ParseRecipients(message.Element(T + "CcRecipients")),
            ParseRecipients(message.Element(T + "BccRecipients")),
            attachmentNames,
            ParseReceivedUtc(message.Element(T + "DateTimeReceived")?.Value),
            ReadBool(message.Element(T + "IsRead")),
            ReadBool(message.Element(T + "IsDraft")),
            body?.Value,
            message.Element(T + "Categories")?.Elements(T + "String").Select(x => x.Value).ToArray()
                ?? Array.Empty<string>(),
            bodyType)
        {
            Sender = string.IsNullOrWhiteSpace(sender) ? null : sender,
            FromIdentity = ParseMailboxIdentity(fromMailbox),
            SenderIdentity = ParseMailboxIdentity(senderMailbox),
            ToIdentities = message.Element(T + "ToRecipients")?.Elements(T + "Mailbox").Select(mailbox => ParseMailboxIdentity(mailbox)!).ToArray() ?? [],
            CcIdentities = message.Element(T + "CcRecipients")?.Elements(T + "Mailbox").Select(mailbox => ParseMailboxIdentity(mailbox)!).ToArray() ?? [],
            SentUtc = ParseReceivedUtc(message.Element(T + "DateTimeSent")?.Value),
            Importance = message.Element(T + "Importance")?.Value,
            Attachments = attachments,
            AttachmentCount = attachmentCount,
            TotalAttachmentBytes = message.Element(T + "Attachments")?.Elements()
                .Sum(x => (long)ReadInt(x.Element(T + "Size"))) ?? 0
        };
    }

    private static IReadOnlyList<string> ParseRecipients(XElement? recipients) =>
        recipients?.Elements(T + "Mailbox")
            .Select(x =>
            {
                var address = x.Element(T + "EmailAddress")?.Value;
                var routing = x.Element(T + "RoutingType")?.Value;
                // Preserve an invalid marker instead of silently dropping an unreviewable recipient.
                return string.IsNullOrWhiteSpace(address) ? "[unresolved recipient]"
                    : routing is not null && !string.Equals(routing, "SMTP", StringComparison.OrdinalIgnoreCase)
                        ? "[unsupported recipient routing]" : address;
            })
            .ToArray() ?? Array.Empty<string>();

    private static EwsMailboxIdentity? ParseMailboxIdentity(XElement? mailbox) => mailbox is null ? null : new(
        mailbox.Element(T + "Name")?.Value, mailbox.Element(T + "EmailAddress")?.Value, mailbox.Element(T + "RoutingType")?.Value);

    private static IReadOnlyList<string> ParseAttachmentNames(XElement? attachments) =>
        attachments?.Elements()
            .Select(x => x.Element(T + "Name")?.Value)
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Select(x => x!)
            .ToArray() ?? Array.Empty<string>();

    private static IReadOnlyList<EwsAttachment> ParseAttachments(XElement? attachments) =>
        attachments?.Elements(T + "FileAttachment")
            .Select(x =>
            {
                var id = x.Element(T + "AttachmentId")?.Attribute("Id")?.Value;
                var name = x.Element(T + "Name")?.Value;
                var size = ReadInt(x.Element(T + "Size"));
                return string.IsNullOrWhiteSpace(id) || string.IsNullOrWhiteSpace(name)
                    ? null
                    : new EwsAttachment(id, name, size, ReadBool(x.Element(T + "IsInline")), x.Element(T + "ContentType")?.Value,
                        x.Element(T + "ContentId")?.Value);
            })
            .Where(x => x is not null)
            .Cast<EwsAttachment>()
            .ToArray() ?? Array.Empty<EwsAttachment>();

    private static string? ParseReceivedUtc(string? value)
    {
        if (string.IsNullOrWhiteSpace(value) ||
            !DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var parsed))
        {
            return null;
        }

        return parsed.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture);
    }

    private static int ReadInt(XElement? element) =>
        element is not null && int.TryParse(element.Value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var value)
            ? Math.Max(0, value)
            : 0;

    private static bool ReadBool(XElement? element)
    {
        if (element is null) return false;
        try { return XmlConvert.ToBoolean(element.Value.Trim()); }
        catch (FormatException) { throw new InvalidOperationException("Exchange returned a malformed XML boolean."); }
    }

    private static bool IncludesLastItem(XElement rootFolder)
    {
        var value = (string?)rootFolder.Attribute("IncludesLastItemInRange");
        if (value is null)
            throw new InvalidOperationException("Exchange returned a page without its completeness flag.");
        try { return XmlConvert.ToBoolean(value.Trim()); }
        catch (FormatException) { throw new InvalidOperationException("Exchange returned a malformed page completeness flag."); }
    }

    private static int ReadOffset(XElement rootFolder, int fallback) =>
        int.TryParse((string?)rootFolder.Attribute("IndexedPagingOffset"), NumberStyles.Integer, CultureInfo.InvariantCulture, out var next)
            ? next
            : fallback;

    private static int? GetNextOffset(XElement rootFolder, int offset, int count)
    {
        if (IncludesLastItem(rootFolder))
        {
            return null;
        }

        var next = ReadOffset(rootFolder, offset + count);
        if (next <= offset)
        {
            throw new InvalidOperationException("The Exchange message result could not be paged safely.");
        }

        return next;
    }

    private static void ValidateResponse(XDocument document, string operation, bool allowMissingUserConfiguration = false)
    {
        var body = document.Root?.Name == Soap + "Envelope" ? document.Root.Element(Soap + "Body") : null;
        var response = body?.Element(M + (operation + "Response"));
        var messages = response?.Element(M + "ResponseMessages")?.Elements().ToArray();
        ThrowPermissionDeniedIfPresent(document, operation);

        if (body?.Element(Soap + "Fault") is null && body?.Elements().Count() == 1
            && allowMissingUserConfiguration && string.Equals(operation, "GetUserConfiguration", StringComparison.Ordinal)
            && messages is { Length: 1 }
            && messages[0].Name == M + "GetUserConfigurationResponseMessage"
            && messages[0].Element(M + "ResponseCode")?.Value == "ErrorItemNotFound"
            && (string?)messages[0].Attribute("ResponseClass") == "Error")
            return;
        if (body?.Elements().Count() != 1 || body?.Element(Soap + "Fault") is not null
            || response is null || messages is null || messages.Length == 0
            || messages.Any(message => message.Name != M + (operation + "ResponseMessage")
                || message.Element(M + "ResponseCode")?.Value != "NoError"
                || (string?)message.Attribute("ResponseClass") != "Success"))
        {
            throw new EwsRequestFailedException(FirstErrorResponseCode(document), operation, errorField: FirstErrorField(document));
        }
    }

    private static void ValidatePartialResponse(XDocument document, string operation)
    {
        var body = document.Root?.Name == Soap + "Envelope" ? document.Root.Element(Soap + "Body") : null;
        var response = body?.Element(M + (operation + "Response"));
        var messages = response?.Element(M + "ResponseMessages")?.Elements().ToArray();
        if (operation != "GetFolder" || body?.Elements().Count() != 1 || body.Element(Soap + "Fault") is not null
            || response is null || messages is not { Length: > 0 and <= 100 }
            || messages.Any(message => message.Name != M + "GetFolderResponseMessage"
                || (string?)message.Attribute("ResponseClass") is not ("Success" or "Error" or "Warning")
                || message.Elements(M + "ResponseCode").Count() != 1
                || string.IsNullOrWhiteSpace(message.Element(M + "ResponseCode")?.Value)))
        {
            throw new EwsRequestFailedException(FirstErrorResponseCode(document), operation,
                errorField: FirstErrorField(document));
        }
    }

    private static string? FirstErrorResponseCode(XDocument document)
    {
        var body = document.Root?.Name == Soap + "Envelope" ? document.Root.Element(Soap + "Body") : null;
        return body?.Descendants()
            .Where(element => element.Name == M + "ResponseCode"
                || element.Ancestors(Soap + "Fault").Any()
                    && element.Name.LocalName is "ResponseCode" or "ErrorCode")
            .Select(element => element.Value)
            .FirstOrDefault(value => value.StartsWith("Error", StringComparison.Ordinal));
    }

    private static XElement? FirstErrorField(XDocument document)
    {
        var body = document.Root?.Name == Soap + "Envelope" ? document.Root.Element(Soap + "Body") : null;
        var failedMessage = body?.Descendants(M + "ResponseCode")
            .FirstOrDefault(element => element.Value.StartsWith("Error", StringComparison.Ordinal))?.Parent;
        var messageXml = failedMessage?.Element(M + "MessageXml")
            ?? body?.Element(Soap + "Fault")?.Descendants(M + "MessageXml").FirstOrDefault();
        return messageXml?.Descendants().FirstOrDefault(element => element.Name == T + "FieldURI"
            || element.Name == T + "ExtendedFieldURI");
    }

    private static bool IsPermissionResponseCode(string? code) => code is
        "ErrorAccessDenied" or "ErrorSendAsDenied" or "ErrorImpersonationDenied"
        or "ErrorImpersonateUserDenied" or "ErrorUnauthorized";

    private static void ThrowPermissionDeniedIfPresent(XDocument document, string operation)
    {
        var body = document.Root?.Name == Soap + "Envelope" ? document.Root.Element(Soap + "Body") : null;
        var permissionCode = body?.Descendants(M + "ResponseCode")
            .Select(element => element.Value.Trim())
            .FirstOrDefault(IsPermissionResponseCode);
        if (permissionCode is null && body?.Element(Soap + "Fault") is { } fault)
        {
            permissionCode = fault.Descendants()
                .Where(element => element.Name.LocalName is "ResponseCode" or "ErrorCode" or "faultcode")
                .Select(element => element.Name.LocalName == "faultcode"
                    ? element.Value.Trim().Split(':').Last() : element.Value.Trim())
                .FirstOrDefault(IsPermissionResponseCode);
        }

        if (permissionCode is not null)
            throw new EwsPermissionDeniedException(permissionCode, operation);
    }
}
