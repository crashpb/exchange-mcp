using System.ComponentModel;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Company.ExchangeMcp.Exchange;
using Company.ExchangeMcp.Security;
using Microsoft.AspNetCore.DataProtection;
using ModelContextProtocol;
using ModelContextProtocol.Server;

namespace Company.ExchangeMcp;

[McpServerToolType]
public sealed class MailboxSyncTools(EwsClient exchange, MailboxAccess access, MailboxHandles handles,
    AuditLog audit, IDataProtectionProvider protection)
{
    private readonly ITimeLimitedDataProtector protector = protection.CreateProtector(
        "Company.ExchangeMcp.SyncCursor.v1").ToTimeLimitedDataProtector();
    private sealed record Cursor(string Subject, string Mailbox, string Kind, string Folder, string State);

    [McpServerTool(Name = "mail_sync_folders", ReadOnly = true, Destructive = false, Idempotent = true, OpenWorld = false)]
    [Description("Read one page of mailbox folder changes. Omit cursor for an initial baseline, then carry the returned opaque cursor until hasMore=false and use it for subsequent changes. Cursors belong to this employee, expire after 30 days and reset on a server restart; expired/rejected cursors require a new baseline. No workstation application or background polling is needed.")]
    public Task<object> Folders(ClaimsPrincipal user, CancellationToken cancellationToken, string? cursor = null) =>
        Run(user, "mail_sync_folders", async (identity, ct) =>
        {
            var state = ReadCursor(identity, "hierarchy", "msgfolderroot", cursor);
            var page = await exchange.SyncFoldersAsync(identity.Mailbox, state, ct);
            return Result(identity, "hierarchy", "msgfolderroot", page);
        }, cancellationToken);

    [McpServerTool(Name = "mail_sync_items", ReadOnly = true, Destructive = false, Idempotent = true, OpenWorld = false)]
    [Description("Read one bounded page of normal item changes in a mail/calendar/contact/task folder. Pass the same folder and returned opaque cursor; omit cursor for an initial baseline. Changes contain stable object keys and short-lived typed handles, without message bodies. Deleted keys are tombstones. Calendar changes identify an item; read it to determine whether it is a series and use bounded calendar views to expand occurrences. Search-folder changes have no usable handle; associated configuration items are excluded. Cursors reset on server restart.")]
    public Task<object> Items(ClaimsPrincipal user, CancellationToken cancellationToken, string folder = "inbox",
        string? cursor = null, int maxChanges = 100) => Run(user, "mail_sync_items", async (identity, ct) =>
        {
            var folderId = ResolveFolder(identity, folder);
            var state = ReadCursor(identity, "items", folderId, cursor);
            var page = await exchange.SyncItemsAsync(identity.Mailbox, folderId, state, maxChanges, ct);
            return Result(identity, "items", folderId, page);
        }, cancellationToken);

    private string ResolveFolder(MailboxIdentity identity, string folder)
    {
        if (folder is "calendar" or "contacts" or "tasks") return folder;
        if (folder is "inbox" or "drafts" or "sentitems" or "deleteditems" or "msgfolderroot") return folder;
        foreach (var kind in new[] { "folder", "calendar-folder", "contactfolder", "taskfolder" })
        {
            try { return handles.Resolve(identity, kind, folder).Id; }
            catch (McpException) { }
        }
        throw new McpException("Invalid or expired folder handle. Refresh the folder list for this account.");
    }

    private string? ReadCursor(MailboxIdentity identity, string kind, string folder, string? value)
    {
        if (value is null) return null;
        if (string.IsNullOrWhiteSpace(value) || value.Length > 131_072) throw InvalidCursor();
        try
        {
            var cursor = JsonSerializer.Deserialize<Cursor>(protector.Unprotect(value));
            if (cursor is null || cursor.Subject != identity.Subject || cursor.Mailbox != identity.Mailbox
                || cursor.Kind != kind || cursor.Folder != folder || string.IsNullOrWhiteSpace(cursor.State)
                || cursor.State.Length > 65_536) throw InvalidCursor();
            return cursor.State;
        }
        catch (Exception ex) when (ex is CryptographicException or JsonException or FormatException)
        { throw InvalidCursor(); }
    }

    private object Result(MailboxIdentity identity, string kind, string folder, EwsSyncPage page) => new
    {
        cursor = protector.Protect(JsonSerializer.Serialize(new Cursor(identity.Subject, identity.Mailbox,
            kind, folder, page.State)), TimeSpan.FromDays(30)),
        hasMore = !page.IncludesLastChange,
        changes = page.Changes.Select(change => new
        {
            change = change.Change,
            kind = change.Kind,
            objectKey = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(
                identity.Subject + "\0" + identity.Mailbox + "\0" + change.Id))),
            handle = change.Change is "Delete" or "ReadFlagChange" || change.Kind is "unsupported-item" or "search-folder"
                || string.IsNullOrWhiteSpace(change.ChangeKey)
                ? null : handles.Issue(identity, change.Kind, change.Id, change.ChangeKey),
            isRead = change.IsRead
        }).ToArray()
    };

    private static McpException InvalidCursor() => new("Invalid or expired synchronization cursor. Start a new baseline for this account and folder.");

    private async Task<object> Run(ClaimsPrincipal user, string operation,
        Func<MailboxIdentity, CancellationToken, Task<object>> action, CancellationToken cancellationToken)
    {
        var identity = access.Require(user, MailboxAccess.Read);
        var id = Guid.NewGuid().ToString("N");
        await audit.RecordAsync(identity, operation, "started", id, cancellationToken);
        try
        {
            var result = await action(identity, cancellationToken);
            await audit.RecordAsync(identity, operation, "completed", id, CancellationToken.None);
            return result;
        }
        catch (EwsPermissionDeniedException ex)
        {
            await audit.RecordAsync(identity, operation, "failed", id, CancellationToken.None);
            throw new McpException(ex.Message);
        }
        catch
        {
            await audit.RecordAsync(identity, operation, "failed", id, CancellationToken.None);
            throw;
        }
    }
}
