using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Net;
using Company.ExchangeMcp.Exchange;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Options;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;

namespace Company.ExchangeMcp.Security;

public sealed record SendApproval(string Subject, string Mailbox, string Id, string ChangeKey,
    string Digest, string Nonce, string ClientId, string? SessionId, DateTimeOffset ExpiresAt = default);

public sealed class SendGuard(IDataProtectionProvider protection, MailboxActionApprovalStore store,
    IOptions<ServiceOptions>? options = null) : IDisposable
{
    private readonly IDataProtector protector = protection.CreateProtector("Company.ExchangeMcp.SendApproval.v2");
    private readonly ServiceOptions service = options?.Value ?? new();

    public static bool UsesOAuthSendGrant(MailboxIdentity identity) =>
        identity.ClientId == "https://chatgpt.com/oauth/client.json";

    public void ConsumeOAuthSendGrant(MailboxIdentity identity, EwsMessage current)
    {
        if (!UsesOAuthSendGrant(identity) || !current.IsDraft || string.IsNullOrEmpty(current.ChangeKey))
            throw new McpException("This client or draft cannot use OAuth-authorized sending.");
        ReserveAttempt(identity.Mailbox, current.Id, null, Digest(current));
    }

    public bool UsesConfiguredSendGrant(MailboxIdentity identity, EwsMessage current) =>
        UsesConfiguredGrant(identity, current.To.Concat(current.Cc).Concat(current.Bcc));

    public bool UsesConfiguredRecallGrant(MailboxIdentity identity, EwsRecallRequest current) =>
        UsesConfiguredGrant(identity, current.To.Concat(current.Cc).Concat(current.Bcc));

    private bool UsesConfiguredGrant(MailboxIdentity identity, IEnumerable<string> recipients) =>
        service.AutoEnrollmentEnabled && !string.IsNullOrEmpty(service.SendWithoutNativeConfirmationActor)
        && string.Equals(identity.ActorMailbox, service.SendWithoutNativeConfirmationActor, StringComparison.OrdinalIgnoreCase)
        && (identity.TargetId != "own" || string.Equals(identity.Mailbox, identity.ActorMailbox, StringComparison.OrdinalIgnoreCase))
        && service.SendWithoutNativeConfirmationMailboxes.Contains(identity.Mailbox, StringComparer.OrdinalIgnoreCase)
        && service.SendWithoutNativeConfirmationClientIds.Contains(identity.ClientId, StringComparer.Ordinal)
        && service.AllowedClientIds.Contains(identity.ClientId, StringComparer.Ordinal)
        && recipients.Any()
        && recipients.All(recipient =>
            ServiceOptions.IsMailbox(recipient)
            && service.SendWithoutNativeConfirmationMailboxes.Contains(recipient, StringComparer.OrdinalIgnoreCase));

    public void ConsumeConfiguredSendGrant(MailboxIdentity identity, EwsMessage current)
    {
        if (!UsesConfiguredSendGrant(identity, current) || !current.IsDraft || string.IsNullOrEmpty(current.ChangeKey))
            throw new McpException("This account or draft cannot use configured sending approval.");
        ReserveAttempt(identity.Mailbox, current.Id, null, Digest(current));
    }

    public void ConsumeConfiguredRecallGrant(MailboxIdentity identity, EwsRecallRequest current)
    {
        if (!UsesConfiguredRecallGrant(identity, current) || string.IsNullOrEmpty(current.Id) || string.IsNullOrEmpty(current.ChangeKey))
            throw new McpException("This account or sent message cannot use configured recall approval.");
        var digest = Digest(current);
        // Share native recall's replay key so switching approval paths cannot repeat an attempt.
        var key = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(
            identity.Mailbox + "\0recall\0" + current.Id + "\0" + digest)));
        store.Reserve(key, null, digest, identity.Mailbox, "recall", current.Id);
    }

    public static void RequireConfirmationSupport(McpServer server,
        RequestContext<CallToolRequestParams> context)
    {
        var capabilities = context.JsonRpcRequest.Context?.ClientCapabilities ?? server.ClientCapabilities;
        if ((!server.IsMrtrSupported && string.IsNullOrWhiteSpace(server.SessionId))
            || capabilities?.Elicitation?.Form is null)
            throw new MissingRequiredClientCapabilityException(new ClientCapabilities
            {
                Elicitation = new ElicitationCapability { Form = new FormElicitationCapability() }
            }, "Sending requires native form confirmation on an MRTR or stateful MCP session.");
    }

    public void RequestApproval(MailboxIdentity identity, EwsMessage draft, McpServer server,
        RequestContext<CallToolRequestParams> context)
    {
        RequireConfirmationSupport(server, context);
        var nonce = Guid.NewGuid().ToString("N");
        var approval = new SendApproval(identity.Subject, identity.Mailbox, draft.Id, draft.ChangeKey,
            Digest(draft), nonce, identity.ClientId, identity.SessionId, store.ExpiresAt());
        var state = protector.Protect(JsonSerializer.Serialize(approval));
        if (state.Length > 32768) throw new MailboxActionApprovalException("The send approval is too large.", "capacity");
        store.Stage(nonce, MailboxActionApprovalStore.Fingerprint(approval), approval.ExpiresAt);
        var preview = RichBody.Preview(draft.Body ?? string.Empty, draft.BodyType);
        var bodyForConfirmation = draft.BodyType.Equals("HTML", StringComparison.OrdinalIgnoreCase)
            ? $"Preview:\n{preview}\nExact HTML (escaped):\n{WebUtility.HtmlEncode(draft.Body ?? string.Empty)}"
            : preview;
        var senderForConfirmation = draft.Sender ?? "(not supplied by Exchange)";
        var attachmentSummary = draft.Attachments.Count == 0
            ? "(none)"
            : string.Join(", ", draft.Attachments.Select(attachment =>
                $"{attachment.Name} [{attachment.ContentType ?? "unknown"}, {attachment.Size} bytes"
                + (attachment.IsInline ? $", inline {attachment.ContentId ?? "without CID"}" : string.Empty) + "]"));
        var mailboxPrefix = identity.TargetId == "own" ? string.Empty : $"Acting mailbox: {identity.Mailbox}\n";
        throw new InputRequiredException(new Dictionary<string, InputRequest>
        {
            ["send_confirmation"] = InputRequest.ForElicitation(new ElicitRequestParams
            {
                Mode = "form",
                Message = mailboxPrefix + $"Send this draft?\nTo: {string.Join(", ", draft.To)}\nCc: {string.Join(", ", draft.Cc)}"
                    + $"\nBcc: {string.Join(", ", draft.Bcc)}\nFrom: {draft.From ?? "(not supplied by Exchange)"}"
                    + $"\nSender: {senderForConfirmation}\nSubject: {draft.Subject}"
                    + $"\nBody type: {draft.BodyType}\nAttachments: {attachmentSummary}\nBody:\n{bodyForConfirmation}",
                RequestedSchema = new ElicitRequestParams.RequestSchema
                {
                    Properties = new Dictionary<string, ElicitRequestParams.PrimitiveSchemaDefinition>
                    { ["confirm"] = new ElicitRequestParams.BooleanSchema { Description = "Approve sending this exact draft." } },
                    Required = ["confirm"]
                }
            })
        }, state);
    }

    public SendApproval ReadApproval(MailboxIdentity identity, string draftId,
        RequestContext<CallToolRequestParams> context) => ReadApproval(identity, draftId, context.Params?.RequestState);

    public SendApproval ReadApproval(MailboxIdentity identity, string draftId, string? state)
    {
        if (string.IsNullOrWhiteSpace(state) || state.Length > 32768)
            throw new MailboxActionApprovalException("A valid send approval is required.", "tampered");
        try
        {
            var approval = JsonSerializer.Deserialize<SendApproval>(protector.Unprotect(state));
            if (approval is null || approval.Subject != identity.Subject || approval.Mailbox != identity.Mailbox
                || approval.ClientId != identity.ClientId || approval.SessionId != identity.SessionId
                || approval.Id != draftId)
                throw new MailboxActionApprovalException("The send approval does not match this account, connection or draft.", "binding_mismatch");
            store.RequirePending(approval.Nonce, MailboxActionApprovalStore.Fingerprint(approval), approval.ExpiresAt);
            return approval;
        }
        catch (Exception ex) when (ex is CryptographicException or JsonException or FormatException)
        { throw new MailboxActionApprovalException("The send approval is invalid or expired.", "tampered"); }
    }

    public static bool Accepted(RequestContext<CallToolRequestParams> context)
    {
        if (context.Params?.InputResponses?.Count != 1
            || !context.Params.InputResponses.TryGetValue("send_confirmation", out var response))
            throw new MailboxActionApprovalException("The human confirmation response is missing.", "confirmation_missing");
        try
        {
            var result = response.Deserialize(InputResponse.ElicitResultJsonTypeInfo);
            return result?.Action == "accept" && result.Content?.TryGetValue("confirm", out var answer) == true
                && answer.ValueKind == JsonValueKind.True;
        }
        catch (JsonException) { throw new MailboxActionApprovalException("The human confirmation response is invalid.", "confirmation_missing"); }
    }

    public void Consume(SendApproval approval, EwsMessage current)
    {
        if (!current.IsDraft || current.Id != approval.Id || current.ChangeKey != approval.ChangeKey || Digest(current) != approval.Digest)
            throw new MailboxActionApprovalException("The draft changed after approval. Review it and request approval again.", "content_changed");
        var fingerprint = MailboxActionApprovalStore.Fingerprint(approval);
        store.RequirePending(approval.Nonce, fingerprint, approval.ExpiresAt);
        ReserveAttempt(approval.Mailbox, approval.Id, approval.Nonce, fingerprint);
    }

    private void ReserveAttempt(string mailbox, string draftId, string? approvalNonce, string fingerprint)
    {
        var draftKey = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(mailbox + "\0" + draftId)));
        store.Reserve(draftKey, approvalNonce, fingerprint, mailbox, "send", draftId);
    }

    public void Cancel(SendApproval approval) => store.Cancel(approval.Nonce, MailboxActionApprovalStore.Fingerprint(approval));
    public static string Digest(EwsMessage draft) => Convert.ToHexString(SHA256.HashData(
        JsonSerializer.SerializeToUtf8Bytes(draft)));
    public static string Digest(EwsRecallRequest request) => Convert.ToHexString(SHA256.HashData(
        JsonSerializer.SerializeToUtf8Bytes(request)));
    public void Dispose() { }
}
