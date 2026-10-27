using System.ComponentModel;
using System.Security.Claims;
using System.Text;
using Company.ExchangeMcp.Exchange;
using Company.ExchangeMcp.Security;
using ModelContextProtocol;
using ModelContextProtocol.Server;

namespace Company.ExchangeMcp;

[McpServerToolType]
public sealed class GroupwareAttachmentTools(EwsClient exchange, MailboxAccess access, MailboxHandles handles, AuditLog audit)
{
    [McpServerTool(Name = "groupware_list_attachments", ReadOnly = true, Destructive = false, Idempotent = true, OpenWorld = false)]
    [Description("List file attachments on an owned calendar event, personal contact or task. Use its typed item handle and kind calendar/contact/task. Returns account-bound attachment handles; embedded item contents are unavailable.")]
    public Task<object> List(ClaimsPrincipal user, string kind, string itemHandle, CancellationToken cancellationToken) =>
        Run(user, MailboxAccess.Read, "groupware_attachments_list", async (identity, ct) =>
        {
            var reference = handles.Resolve(identity, HandleKind(kind), itemHandle);
            var item = await exchange.GetGroupwareAttachmentsAsync(identity.Mailbox, reference.Id, kind, ct);
            RequireCurrent(reference.ChangeKey, item.ChangeKey);
            return (object)new
            {
                items = item.Files.Select(file => new
                {
                    handle = handles.Issue(identity, "groupware-attachment", Encode(kind, item.Id, file.Id), item.ChangeKey),
                    file.Name,
                    file.Size,
                    file.ContentType,
                    file.IsInline,
                    file.ContentId
                }).ToArray(),
                item.Count,
                item.Bytes
            };
        }, cancellationToken);

    [McpServerTool(Name = "groupware_read_attachment", ReadOnly = true, Destructive = false, Idempotent = true, OpenWorld = false)]
    [Description("Read a current calendar/contact/task file attachment as bounded base64 bytes. Uses only an attachment handle issued to the signed-in mailbox.")]
    public Task<object> Read(ClaimsPrincipal user, string attachmentHandle, CancellationToken cancellationToken) =>
        Run(user, MailboxAccess.Read, "groupware_attachment_read", async (identity, ct) =>
        {
            var reference = handles.Resolve(identity, "groupware-attachment", attachmentHandle);
            var ids = Decode(reference.Id);
            var item = await exchange.GetGroupwareAttachmentsAsync(identity.Mailbox, ids.Item, ids.Kind, ct);
            RequireCurrent(reference.ChangeKey, item.ChangeKey);
            var metadata = item.Files.SingleOrDefault(f => f.Id == ids.Attachment)
                ?? throw new McpException("The attachment no longer belongs to this item.");
            if (metadata.Size > EwsClient.MaxAttachmentBytes) throw new McpException("The file exceeds 5 MiB.");
            var file = await exchange.GetAttachmentAsync(identity.Mailbox, ids.Attachment, ct);
            return (object)new
            {
                file.Name,
                file.ContentType,
                file.IsInline,
                file.ContentId,
                contentBase64 = Convert.ToBase64String(file.Content)
            };
        }, cancellationToken);

    [McpServerTool(Name = "groupware_create_attachment", ReadOnly = false, Destructive = false, Idempotent = false, OpenWorld = false)]
    [Description("Attach selected file bytes to an owned calendar event, contact or task, maximum 5 MiB per file and 10 MiB/100 attachments per item. Saves only; does not send meeting updates. For organizer meetings use calendar_update_event afterward to notify attendees. Cannot edit attendee meeting attachments. Never fetch server-local paths or remote URLs.")]
    public Task<object> Create(ClaimsPrincipal user, string kind, string itemHandle, string name, string contentBase64,
        CancellationToken cancellationToken, string? contentType = null, bool isInline = false, string? contentId = null) =>
        Run(user, MailboxAccess.Write, "groupware_attachment_create", async (identity, ct) =>
        {
            if (contentBase64 is null || contentBase64.Length > ((EwsClient.MaxAttachmentBytes + 2) / 3) * 4)
                throw new McpException("The file exceeds 5 MiB.");
            byte[] bytes;
            try { bytes = Convert.FromBase64String(contentBase64); }
            catch (FormatException) { throw new McpException("Invalid base64 file data."); }
            if (bytes.Length > EwsClient.MaxAttachmentBytes) throw new McpException("The file exceeds 5 MiB.");
            var reference = handles.Resolve(identity, HandleKind(kind), itemHandle);
            var item = await exchange.GetGroupwareAttachmentsAsync(identity.Mailbox, reference.Id, kind, ct);
            RequireCurrent(reference.ChangeKey, item.ChangeKey);
            RequireWritable(item);
            if (item.Count >= EwsClient.MaxAttachments || item.Bytes + bytes.Length > EwsClient.MaxDraftAttachmentBytes)
                throw new McpException("The item exceeds 10 MiB or 100 attachments.");
            if (isInline && item.Files.Any(f => f.ContentId == contentId))
                throw new McpException("The ContentId already exists on this item.");
            var created = await exchange.CreateFileAttachmentAsync(identity.Mailbox, item.Id, item.ChangeKey,
                name, bytes, contentType, ct, isInline, contentId);
            var updated = await exchange.GetGroupwareAttachmentsAsync(identity.Mailbox, created.Parent.Id, kind, ct);
            return (object)new
            {
                status = "attachment_saved",
                meetingUpdateSent = false,
                handle = handles.Issue(identity, HandleKind(kind), updated.Id, updated.ChangeKey),
                attachmentHandle = handles.Issue(identity, "groupware-attachment", Encode(kind, updated.Id, created.Attachment.Id), updated.ChangeKey)
            };
        }, cancellationToken);

    [McpServerTool(Name = "groupware_delete_attachment", ReadOnly = false, Destructive = true, Idempotent = false, OpenWorld = false)]
    [Description("Remove one owned calendar/contact/task file attachment after the user requests it. Saves only; does not send a meeting update. Cannot edit attendee meetings. Refresh the item handle after success; never retry an uncertain removal.")]
    public Task<object> Delete(ClaimsPrincipal user, string attachmentHandle, CancellationToken cancellationToken) =>
        Run(user, MailboxAccess.Manage, "groupware_attachment_delete", async (identity, ct) =>
        {
            var reference = handles.Resolve(identity, "groupware-attachment", attachmentHandle);
            var ids = Decode(reference.Id);
            var item = await exchange.GetGroupwareAttachmentsAsync(identity.Mailbox, ids.Item, ids.Kind, ct);
            RequireCurrent(reference.ChangeKey, item.ChangeKey);
            RequireWritable(item);
            if (item.Files.All(f => f.Id != ids.Attachment)) throw new McpException("The attachment no longer belongs to this item.");
            await exchange.DeleteAttachmentAsync(identity.Mailbox, ids.Attachment, ct);
            var updated = await exchange.GetGroupwareAttachmentsAsync(identity.Mailbox, ids.Item, ids.Kind, ct);
            return (object)new
            {
                status = "attachment_removed",
                meetingUpdateSent = false,
                handle = handles.Issue(identity, HandleKind(ids.Kind), updated.Id, updated.ChangeKey)
            };
        }, cancellationToken);

    private static string HandleKind(string kind) => kind switch
    {
        "calendar" => "calendar-event",
        "contact" => "contact",
        "task" => "task",
        _ => throw new McpException("Item kind must be calendar, contact or task.")
    };
    private static void RequireCurrent(string expected, string actual)
    {
        if (string.IsNullOrEmpty(actual) || !string.Equals(expected, actual, StringComparison.Ordinal))
            throw new McpException("This item handle is stale. Read the item again.");
    }
    private static void RequireWritable(EwsGroupwareAttachments item)
    {
        if (item.IsMeeting && !item.IsOrganizer) throw new McpException("Attendee meeting attachments cannot be edited.");
        if (item.Kind == "task" && item.IsAssignedTask)
            throw new McpException("Assigned task attachments are fixed for this assignment. Edit attachments before assigning a task.");
    }
    private static string Encode(string kind, string item, string attachment) =>
        Convert.ToBase64String(Encoding.UTF8.GetBytes(kind + "\0" + item + "\0" + attachment));
    private static (string Kind, string Item, string Attachment) Decode(string value)
    {
        try
        {
            var parts = Encoding.UTF8.GetString(Convert.FromBase64String(value)).Split('\0');
            if (parts.Length != 3 || parts.Any(string.IsNullOrEmpty)) throw new FormatException();
            _ = HandleKind(parts[0]);
            return (parts[0], parts[1], parts[2]);
        }
        catch (FormatException) { throw new McpException("Invalid attachment handle."); }
    }
    private async Task<object> Run(ClaimsPrincipal user, string scope, string operation,
        Func<MailboxIdentity, CancellationToken, Task<object>> action, CancellationToken cancellationToken)
    {
        var identity = access.Require(user, scope);
        var operationId = Guid.NewGuid().ToString("N");
        await audit.RecordAsync(identity, operation, "started", operationId, cancellationToken);
        object result;
        try { result = await action(identity, cancellationToken); }
        catch (EwsPermissionDeniedException ex)
        {
            await audit.RecordAsync(identity, operation, "failed_or_uncertain", operationId, CancellationToken.None);
            throw new McpException(ex.Message);
        }
        catch { await audit.RecordAsync(identity, operation, "failed_or_uncertain", operationId, CancellationToken.None); throw; }
        try { await audit.RecordAsync(identity, operation, "completed", operationId, CancellationToken.None); }
        catch { throw new McpException("The operation completed but audit recording failed. Do not repeat it; contact the administrator."); }
        return result;
    }
}
