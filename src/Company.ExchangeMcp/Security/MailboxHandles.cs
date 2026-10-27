using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using ModelContextProtocol;

namespace Company.ExchangeMcp.Security;

public sealed record MailboxHandle(string Subject, string Mailbox, string Kind, string Id, string ChangeKey,
    string ClientId = "", string? SessionId = null, string? EventSearchKey = null);

public sealed class MailboxHandles(IDataProtectionProvider protection)
{
    private readonly ITimeLimitedDataProtector protector = protection.CreateProtector(
        "Company.ExchangeMcp.MailboxHandles.v1").ToTimeLimitedDataProtector();

    public string Issue(MailboxIdentity identity, string kind, string id, string changeKey) =>
        protector.Protect(JsonSerializer.Serialize(new MailboxHandle(identity.Subject, identity.Mailbox,
            kind, id, changeKey, identity.ClientId, identity.SessionId)), kind == "recall" ? TimeSpan.FromHours(48) : TimeSpan.FromMinutes(15));

    public string IssueEventMessage(MailboxIdentity identity, string id, string changeKey,
        DateTimeOffset observedAt, string? searchKey) =>
        protector.Protect(JsonSerializer.Serialize(new MailboxHandle(identity.Subject, identity.Mailbox,
            "event-message", id, changeKey, identity.ClientId, identity.SessionId, searchKey)), observedAt.AddHours(48));

    public static string TargetBinding(MailboxIdentity identity, string? targetMailbox = null) =>
        identity.ClientId + "\0" + (identity.SessionId ?? "") + "\0"
        + (targetMailbox ?? identity.Mailbox);

    public MailboxHandle Resolve(MailboxIdentity identity, string kind, string value) =>
        Resolve(identity, kind, value, allowEventMessage: false);

    public MailboxHandle ResolveMessageForRead(MailboxIdentity identity, string value) =>
        Resolve(identity, "message", value, allowEventMessage: true);

    private MailboxHandle Resolve(MailboxIdentity identity, string kind, string value, bool allowEventMessage)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > 16384)
            throw InvalidHandle();
        try
        {
            var handle = JsonSerializer.Deserialize<MailboxHandle>(protector.Unprotect(value));
            if (handle is null || handle.Subject != identity.Subject || handle.Mailbox != identity.Mailbox
                || handle.ClientId != identity.ClientId || handle.SessionId != identity.SessionId
                || (handle.Kind != kind && (!allowEventMessage || handle.Kind != "event-message"))
                || (handle.Kind == "event-message" && (identity.TargetId != "own"
                    || !string.Equals(identity.ActorMailbox ?? identity.Mailbox, identity.Mailbox, StringComparison.OrdinalIgnoreCase)))
                || string.IsNullOrWhiteSpace(handle.Id))
                throw InvalidHandle();
            return handle;
        }
        catch (Exception ex) when (ex is CryptographicException or JsonException or FormatException)
        {
            throw InvalidHandle();
        }
    }

    public string ResolveFolder(MailboxIdentity identity, string folder) => folder switch
    {
        "inbox" or "drafts" or "sentitems" or "deleteditems" or "msgfolderroot" => folder,
        _ => Resolve(identity, "folder", folder).Id
    };

    private static McpException InvalidHandle() => new(
        "Invalid or expired mailbox handle. Refresh the folder or message list for this account.");
}
