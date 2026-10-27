using System.ComponentModel;
using System.Security.Claims;
using System.Text.Json;
using Company.ExchangeMcp.Exchange;
using Company.ExchangeMcp.Security;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;

namespace Company.ExchangeMcp;

[McpServerToolType]
public sealed class RecallTools(EwsClient exchange, MailboxAccess access, MailboxHandles handles,
    AuditLog audit, CalendarActionApprovalGuard approval, SendGuard send)
{
    [McpServerTool(Name = "mail_recall_message", ReadOnly = false, Destructive = true, Idempotent = false, OpenWorld = true)]
    [Description("Request native Classic Outlook recall of the selected mailbox's unchanged Sent Items message, deleting eligible unread recipient copies and requesting reports. Requires mail.send and mail.manage plus native human confirmation except for server-verified standing approval for the configured actor, client and mailbox pair. Recall notices use the original To/Cc/Bcc recipients. Submission is not proof of recall; use the returned recall handle for reports. Never retry an uncertain submission automatically.")]
    public Task<object> Recall(ClaimsPrincipal user, string messageHandle, McpServer server,
        RequestContext<CallToolRequestParams> context, CancellationToken cancellationToken) =>
        Run(user, MailboxAccess.Send, "recall_message", async (identity, ct) =>
        {
            _ = access.Require(user, MailboxAccess.Manage);
            var reference = handles.Resolve(identity, "message", messageHandle);
            var request = await exchange.PrepareRecallAsync(identity.Mailbox, reference.Id, ct);
            if (!string.Equals(reference.ChangeKey, request.ChangeKey, StringComparison.Ordinal))
                throw new McpException("This message handle is stale. Refresh Sent Items before requesting recall.");
            access.ValidateRecipients(request.To.Concat(request.Cc).Concat(request.Bcc));
            var digest = SendGuard.Digest(request);
            var configuredRecall = send.UsesConfiguredRecallGrant(identity, request);
            CalendarActionApproval? state = null;
            if (configuredRecall)
            {
                if (context.Params?.RequestState is not null || context.Params?.InputResponses is not null)
                    throw new McpException("This recall uses prior authorization. Start a fresh recall request without a confirmation continuation.");
            }
            else
            {
                SendGuard.RequireConfirmationSupport(server, context);
                if (context.Params?.RequestState is null)
                {
                    if (context.Params?.InputResponses is not null) throw new McpException("A valid recall approval state is required.");
                    var preview = $"Request recall of the sent message: {request.Subject}\n"
                        + $"To: {string.Join(", ", request.To)}\nCc: {string.Join(", ", request.Cc)}\nBcc: {string.Join(", ", request.Bcc)}\n"
                        + "Send one recall notice to these recipients, requesting deletion of eligible unread copies and success/failure reports. "
                        + "Classic Outlook recall depends on recipient processing and is not guaranteed.";
                    approval.RequestApproval(identity, "recall", request.Id, request.ChangeKey, digest,
                        preview, server, context, "recall_confirmation");
                }
                state = approval.ReadApproval(identity, "recall", request.Id, context);
                if (!CalendarActionApprovalGuard.Accepted(context, "recall_confirmation"))
                {
                    approval.Cancel(state);
                    return (object)new { status = "cancelled", submitted = false };
                }
            }
            var tracking = new EwsRecallTracking(request.ReportTag, request.SearchKey, request.Subject,
                request.To.Count + request.Cc.Count + request.Bcc.Count);
            var recallHandle = handles.Issue(identity, "recall", JsonSerializer.Serialize(tracking), string.Empty);
            if (configuredRecall)
            {
                if (!await access.VerifyCurrentActorAsync(identity, ct).ConfigureAwait(false))
                    throw new McpException("The current directory identity could not be verified for configured recall approval.");
                send.ConsumeConfiguredRecallGrant(identity, request);
            }
            else approval.Consume(state!, request.Id, request.ChangeKey, digest);
            try { await exchange.SubmitRecallAsync(identity.Mailbox, request, ct); }
            catch (EwsPermissionDeniedException)
            {
                return (object)new
                {
                    status = "permission_denied",
                    recallHandle,
                    doNotRetryAutomatically = true,
                    message = "Exchange denied access required to submit this recall. No recall was submitted. Check mailbox permissions before trying again."
                };
            }
            catch
            {
                return (object)new
                {
                    status = "submission_unverified",
                    recallHandle,
                    doNotRetryAutomatically = true,
                    message = "Exchange did not return a verified submission result. Check recall status and Sent Items before any further action."
                };
            }
            return (object)new { status = "recall_requested", recallHandle, reportingRequested = true, statusHandleHours = 48 };
        }, cancellationToken);

    [McpServerTool(Name = "mail_recall_status", ReadOnly = true, Destructive = false, Idempotent = true, OpenWorld = false)]
    [Description("Read exact correlated native recall reports. Supply either the returned recallHandle, valid for 48 hours, or a fresh messageHandle to the selected mailbox's existing submitted native recall notice to recover tracking and return a new recallHandle. Recovery is read-only and also works when the notice was moved to Deleted Items. A missing report means pending or unreported; reports do not prove that every recipient copy was removed.")]
    public Task<object> Status(ClaimsPrincipal user, CancellationToken cancellationToken,
        string? recallHandle = null, string? messageHandle = null) =>
        Run(user, MailboxAccess.Read, "recall_status", async (identity, ct) =>
        {
            if ((recallHandle is null) == (messageHandle is null))
                throw new McpException("Supply exactly one recallHandle or messageHandle to a submitted recall notice.");
            EwsRecallTracking tracking;
            if (messageHandle is not null)
            {
                var notice = handles.Resolve(identity, "message", messageHandle);
                tracking = await exchange.GetRecallTrackingAsync(identity.Mailbox, notice.Id, notice.ChangeKey, ct);
                recallHandle = handles.Issue(identity, "recall", JsonSerializer.Serialize(tracking), string.Empty);
            }
            else
            {
                MailboxHandle reference;
                try { reference = handles.Resolve(identity, "recall", recallHandle!); }
                catch (McpException)
                {
                    throw new McpException("Invalid or expired recall handle. Search for the existing submitted recall notice and use its fresh messageHandle to recover status without sending another recall.");
                }
                try
                {
                    tracking = JsonSerializer.Deserialize<EwsRecallTracking>(reference.Id)
                        ?? throw new FormatException();
                }
                catch (Exception ex) when (ex is JsonException or FormatException)
                { throw new McpException("Invalid recall status handle. Use the handle returned by the recall request."); }
            }
            try
            {
                if (tracking.RecipientCount is < 1 or > 100 || tracking.Subject is null || tracking.Subject.Length > 998
                    || tracking.Subject.IndexOfAny(['\r', '\n', '\0']) >= 0)
                    throw new FormatException();
                EwsClient.ValidateRecallTag(tracking.ReportTag, tracking.SearchKey);
            }
            catch (Exception ex) when (ex is JsonException or FormatException or ArgumentException)
            { throw new McpException("Invalid recall status handle. Use the handle returned by the recall request."); }
            var reports = await exchange.GetRecallReportsAsync(identity.Mailbox, tracking.ReportTag, ct);
            return (object)new
            {
                status = reports.Count == 0 ? "pending_or_unreported" : "reports_received",
                recallHandle,
                originalSubject = tracking.Subject,
                originalRecipientCount = tracking.RecipientCount,
                successReports = reports.Count(report => report.Outcome == "success"),
                failureReports = reports.Count(report => report.Outcome == "failure"),
                reports,
                allRecipientCopiesVerified = false,
                contentTrust = "untrusted_email_content"
            };
        }, cancellationToken);

    private async Task<T> Run<T>(ClaimsPrincipal user, string scope, string operation,
        Func<MailboxIdentity, CancellationToken, Task<T>> action, CancellationToken cancellationToken)
    {
        var identity = access.Require(user, scope);
        var operationId = Guid.NewGuid().ToString("N");
        await audit.RecordAsync(identity, operation, "started", operationId, cancellationToken);
        T result;
        try { result = await action(identity, cancellationToken); }
        catch (InputRequiredException)
        {
            await audit.RecordAsync(identity, operation, "approval_required", operationId, CancellationToken.None);
            throw;
        }
        catch (RecallPreparationException exception)
        {
            OperationTracking.Current?.SetRecallPreparationFailure(exception.Phase, exception.Reason);
            await audit.RecordAsync(identity, operation, "failed", operationId, CancellationToken.None);
            throw;
        }
        catch
        {
            await audit.RecordAsync(identity, operation, "failed_or_uncertain", operationId, CancellationToken.None);
            throw;
        }
        var outcome = OperationTracking.Current is { ExchangeSendAttempted: true } current ? current.SendOutcome : "completed";
        try { await audit.RecordAsync(identity, operation, outcome, operationId, CancellationToken.None); }
        catch { throw new McpException("The operation completed but audit recording failed. Do not repeat it; contact the administrator."); }
        return result;
    }
}
