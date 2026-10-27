using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Company.ExchangeMcp.Exchange;
using Microsoft.AspNetCore.DataProtection;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;

namespace Company.ExchangeMcp.Security;

public sealed record CalendarActionApproval(
    string Subject,
    string Mailbox,
    string Action,
    string ItemId,
    string ChangeKey,
    string Digest,
    string Nonce,
    string ClientId,
    string? SessionId,
    DateTimeOffset? ActionTimeUtc = null,
    DateTimeOffset ExpiresAt = default);

public sealed class CalendarActionApprovalGuard(IDataProtectionProvider protection, MailboxActionApprovalStore store) : IDisposable
{
    private readonly IDataProtector protector = protection.CreateProtector("Company.ExchangeMcp.CalendarActionApproval.v2");

    public void RequestApproval(MailboxIdentity identity, string action, string itemId, string changeKey,
        string digest, string preview, McpServer server, RequestContext<CallToolRequestParams> context,
        string confirmationName = "calendar_confirmation", DateTimeOffset? actionTimeUtc = null)
    {
        SendGuard.RequireConfirmationSupport(server, context);
        var nonce = Guid.NewGuid().ToString("N");
        var approval = new CalendarActionApproval(identity.Subject, identity.Mailbox, action, itemId, changeKey,
            digest, nonce, identity.ClientId, identity.SessionId, actionTimeUtc, store.ExpiresAt());
        var state = protector.Protect(JsonSerializer.Serialize(approval));
        if (state.Length > 32768) throw new MailboxActionApprovalException("The mailbox action approval is too large.", "capacity");
        store.Stage(nonce, MailboxActionApprovalStore.Fingerprint(approval), approval.ExpiresAt);
        throw new InputRequiredException(new Dictionary<string, InputRequest>
        {
            [confirmationName] = InputRequest.ForElicitation(new ElicitRequestParams
            {
                Mode = "form",
                Message = identity.TargetId == "own" ? preview : $"Acting mailbox: {identity.Mailbox}\n{preview}",
                RequestedSchema = new ElicitRequestParams.RequestSchema
                {
                    Properties = new Dictionary<string, ElicitRequestParams.PrimitiveSchemaDefinition>
                    {
                        ["confirm"] = new ElicitRequestParams.BooleanSchema
                        { Description = "Approve this exact mailbox action and any stated transmission or access change." }
                    },
                    Required = ["confirm"]
                }
            })
        }, state);
    }

    public CalendarActionApproval ReadApproval(MailboxIdentity identity, string action, string itemId,
        RequestContext<CallToolRequestParams> context) => ReadApproval(identity, action, itemId, context.Params?.RequestState);

    public CalendarActionApproval ReadApproval(MailboxIdentity identity, string action, string itemId, string? state)
    {
        if (string.IsNullOrWhiteSpace(state) || state.Length > 32768)
            throw new MailboxActionApprovalException("A valid mailbox action approval is required.", "tampered");
        try
        {
            var approval = JsonSerializer.Deserialize<CalendarActionApproval>(protector.Unprotect(state));
            if (approval is null || approval.Subject != identity.Subject || approval.Mailbox != identity.Mailbox
                || approval.ClientId != identity.ClientId || approval.SessionId != identity.SessionId
                || approval.Action != action || approval.ItemId != itemId)
                throw new MailboxActionApprovalException("The mailbox action approval does not match this account, connection or action.", "binding_mismatch");
            store.RequirePending(approval.Nonce, MailboxActionApprovalStore.Fingerprint(approval), approval.ExpiresAt);
            return approval;
        }
        catch (Exception ex) when (ex is CryptographicException or JsonException or FormatException)
        { throw new MailboxActionApprovalException("The mailbox action approval is invalid or expired.", "tampered"); }
    }

    public static bool Accepted(RequestContext<CallToolRequestParams> context, string confirmationName = "calendar_confirmation")
    {
        if (context.Params?.InputResponses?.Count != 1
            || !context.Params.InputResponses.TryGetValue(confirmationName, out var response))
            throw new MailboxActionApprovalException("The calendar confirmation response is missing.", "confirmation_missing");
        try
        {
            var result = response.Deserialize(InputResponse.ElicitResultJsonTypeInfo);
            return result?.Action == "accept" && result.Content?.TryGetValue("confirm", out var answer) == true
                && answer.ValueKind == JsonValueKind.True;
        }
        catch (JsonException) { throw new MailboxActionApprovalException("The calendar confirmation response is invalid.", "confirmation_missing"); }
    }

    public void Consume(CalendarActionApproval approval, string itemId, string changeKey, string digest)
    {
        if (!string.Equals(approval.ItemId, itemId, StringComparison.Ordinal)
            || !string.Equals(approval.ChangeKey, changeKey, StringComparison.Ordinal)
            || !string.Equals(approval.Digest, digest, StringComparison.Ordinal))
            throw new MailboxActionApprovalException("The mailbox item changed after approval. Review it and request approval again.", "content_changed");
        var fingerprint = MailboxActionApprovalStore.Fingerprint(approval);
        store.RequirePending(approval.Nonce, fingerprint, approval.ExpiresAt);
        store.Reserve(ReplayKey(approval), approval.Nonce, fingerprint, approval.Mailbox, approval.Action, approval.ItemId);
    }

    public void CompleteVerified(CalendarActionApproval approval)
    {
        if (approval.Action is not ("delegate_add" or "delegate_update" or "delegate_remove"))
            throw new InvalidOperationException("Only a verified delegate action can be completed.");
        try
        {
            store.CompleteVerified(ReplayKey(approval), approval.Nonce, approval.Mailbox, approval.ItemId,
                approval.Action == "delegate_remove");
        }
        catch (MailboxActionApprovalException)
        {
            // Exchange was already verified; do not mislabel a failed hold release as not dispatched.
            throw new McpException("Exchange verified the delegate change, but its durable replay hold could not be released. Verify the mailbox before another change; contact the administrator.");
        }
    }

    public void Cancel(CalendarActionApproval approval) => store.Cancel(approval.Nonce, MailboxActionApprovalStore.Fingerprint(approval));

    private static string ReplayKey(CalendarActionApproval approval) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(
            approval.Mailbox + "\0" + approval.Action + "\0" + approval.ItemId + "\0" + approval.Digest)));

    public void Dispose() { }
}
