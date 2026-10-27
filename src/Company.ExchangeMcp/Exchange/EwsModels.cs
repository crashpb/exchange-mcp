using System.Globalization;
using System.Text.Json.Serialization;
using System.Xml.Linq;

namespace Company.ExchangeMcp.Exchange;

public sealed record EwsFolder(
    string Id,
    string ChangeKey,
    string Name,
    int TotalCount,
    int UnreadCount,
    string? ParentId = null);

public sealed record EwsFolderAccessRights(
    bool? Read,
    bool? Create,
    bool? Modify,
    bool? Delete);

/// <summary>Safe Exchange permission failure retaining only the exact response code and operation.</summary>
public sealed class EwsPermissionDeniedException : InvalidOperationException
{
    public EwsPermissionDeniedException(string responseCode, string operation)
        : base(CreateMessage(responseCode, operation))
    {
        ResponseCode = responseCode;
        Operation = operation;
    }

    public string ResponseCode { get; }
    public string Operation { get; }

    private static string CreateMessage(string responseCode, string operation) => responseCode switch
    {
        "ErrorSendAsDenied" => "Exchange denied SendAs for this delegated send.",
        "ErrorImpersonationDenied" or "ErrorImpersonateUserDenied" => "Exchange denied the service impersonation required for this mailbox.",
        "ErrorUnauthorized" => "Exchange rejected the authenticated mailbox request.",
        _ when operation.Equals("SendItem", StringComparison.Ordinal)
            => "Exchange denied sending this message. The server did not identify whether SendAs or SendOnBehalf is required.",
        _ => "Exchange denied access to the selected mailbox, folder or item."
    };
}

/// <summary>Native failure metadata without server messages, XML or mailbox data.</summary>
public sealed class EwsRequestFailedException : InvalidOperationException
{
    public EwsRequestFailedException(string? responseCode, string operation, bool rejected = false, XElement? errorField = null)
        : base(rejected ? "Exchange rejected the request." : "Exchange returned an unsuccessful response.")
    {
        ResponseCode = responseCode is { Length: > 5 and <= 128 }
            && responseCode.StartsWith("Error", StringComparison.Ordinal)
            && responseCode.All(value => value is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9')
                ? responseCode : null;
        Operation = operation is "FindFolder" or "GetFolder" or "CreateFolder" or "UpdateFolder" or "DeleteFolder"
            or "FindItem" or "GetItem" or "CreateItem" or "UpdateItem" or "DeleteItem" or "MoveItem" or "CopyItem" or "SendItem"
            or "GetAttachment" or "CreateAttachment" or "DeleteAttachment"
            or "GetUserConfiguration" or "CreateUserConfiguration" or "UpdateUserConfiguration" or "DeleteUserConfiguration"
            or "GetUserAvailabilityRequest" or "GetRoomLists" or "GetRooms" or "ResolveNames"
            or "SyncFolderHierarchy" or "SyncFolderItems" or "Subscribe" or "GetStreamingEvents" or "Unsubscribe"
            or "GetDelegate" or "AddDelegate" or "UpdateDelegate" or "RemoveDelegate"
            or "GetUserOofSettingsRequest" or "SetUserOofSettingsRequest" or "GetInboxRules" or "UpdateInboxRules"
                ? operation : "Unknown";
        ErrorField = SanitizeErrorField(errorField);
    }

    public string? ResponseCode { get; }
    public string Operation { get; }
    public string? ErrorField { get; }

    private static string? SanitizeErrorField(XElement? field)
    {
        XNamespace types = "http://schemas.microsoft.com/exchange/services/2006/types";
        if (field?.Name == types + "FieldURI")
            return (string?)field.Attribute("FieldURI") is
                "item:Subject" or "item:Body" or "item:ItemClass" or "item:Attachments"
                or "task:StartDate" or "task:DueDate" or "task:CompleteDate" or "task:PercentComplete" or "task:Status"
                or "task:Owner" or "task:DelegationState" or "task:Delegator" or "task:AssignedTime" or "task:ChangeCount"
                or "task:IsAssignmentEditable" or "task:IsComplete" or "task:IsRecurring" or "task:IsTeamTask"
                or "message:From" or "message:Sender" or "message:ToRecipients" or "message:CcRecipients"
                    ? "FieldURI=" + (string)field.Attribute("FieldURI")! : null;
        if (field?.Name != types + "ExtendedFieldURI" || field.Attribute("PropertyName") is not null)
            return null;
        if (field.Attribute("PropertyTag") is { } tag)
            return field.Attribute("PropertyId") is null && field.Attribute("PropertySetId") is null
                && (tag.Value.Equals("0x1080", StringComparison.OrdinalIgnoreCase)
                    || tag.Value.Equals("0x7D01", StringComparison.OrdinalIgnoreCase))
                    ? "PropertyTag=" + tag.Value.ToUpperInvariant().Replace("0X", "0x", StringComparison.Ordinal) : null;
        var set = (string?)field.Attribute("PropertySetId");
        var id = (string?)field.Attribute("PropertyId");
        if (!Guid.TryParseExact(set, "D", out var setId) || id is not { Length: > 0 and <= 5 }
            || !id.All(value => value is >= '0' and <= '9')
            || !int.TryParse(id, NumberStyles.None, CultureInfo.InvariantCulture, out var propertyId))
            return null;
        var canonicalSet = setId.ToString("D");
        var knownProperty = canonicalSet == "00062003-0000-0000-c000-000000000046"
            ? propertyId is 0x8108 or 0x8112 or 0x8113 or 0x8115 or 0x8117 or 0x8119 or 0x811A or 0x811B
                or 0x811F or 0x8121 or 0x8122 or 0x8125 or 0x8129 or 0x812A
            : canonicalSet == "00062008-0000-0000-c000-000000000046" && propertyId is 0x8518 or 0x8519;
        return knownProperty ? "PropertySetId=" + canonicalSet + ";PropertyId=" + propertyId.ToString(CultureInfo.InvariantCulture) : null;
    }
}

public sealed record EwsMessage(
    string Id,
    string ChangeKey,
    string Subject,
    string? From,
    IReadOnlyList<string> To,
    IReadOnlyList<string> Cc,
    IReadOnlyList<string> Bcc,
    IReadOnlyList<string> AttachmentNames,
    string? ReceivedUtc,
    bool IsRead,
    bool IsDraft,
    string? Body,
    IReadOnlyList<string> Categories,
    string BodyType = "Text")
{
    public string? Sender { get; init; }
    [JsonIgnore] public EwsMailboxIdentity? FromIdentity { get; init; }
    [JsonIgnore] public EwsMailboxIdentity? SenderIdentity { get; init; }
    [JsonIgnore] public IReadOnlyList<EwsMailboxIdentity> ToIdentities { get; init; } = [];
    [JsonIgnore] public IReadOnlyList<EwsMailboxIdentity> CcIdentities { get; init; } = [];
    [JsonIgnore] public string? SentUtc { get; init; }
    [JsonIgnore] public string? Importance { get; init; }
    public string? EventSearchKey { get; init; }
    public IReadOnlyList<EwsAttachment> Attachments { get; init; } = Array.Empty<EwsAttachment>();
    public int AttachmentCount { get; init; }
    public long TotalAttachmentBytes { get; init; }
}

public sealed record EwsPage<T>(IReadOnlyList<T> Items, int? NextOffset);

public sealed record EwsMailboxIdentity(string? Name, string? Address, string? RoutingType);
public sealed record EwsReplySource(string Mailbox, EwsMessage Message);
public sealed record EwsItemRef(string Id, string ChangeKey)
{
    [JsonIgnore] public string? PresentationWarning { get; init; }
}

public sealed record EwsAttachment(
    string Id,
    string Name,
    int Size,
    bool IsInline,
    string? ContentType,
    string? ContentId = null);

public sealed record EwsAttachmentContent(
    string Id,
    string Name,
    string? ContentType,
    byte[] Content,
    bool IsInline = false,
    string? ContentId = null);

public sealed record EwsAttachmentResult(
    EwsItemRef Parent,
    EwsAttachment Attachment);

public sealed record EwsDraftInput(
    string Subject,
    string Body,
    IReadOnlyList<string> To,
    IReadOnlyList<string> Cc,
    IReadOnlyList<string>? Bcc = null,
    string BodyType = "Text",
    string? From = null);
