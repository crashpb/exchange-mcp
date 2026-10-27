using System.Text.Json;
using System.Text.Json.Nodes;
using Company.ExchangeMcp.Exchange;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;

namespace Company.ExchangeMcp.Security;

/// <summary>Correlates MCP tool calls and resource reads with HTTP requests and any Exchange send.</summary>
public sealed class OperationTracking
{
    private const string RequestIdItem = "Company.ExchangeMcp.RequestId";
    private static readonly AsyncLocal<OperationState?> CurrentState = new();

    internal static OperationState? Current => CurrentState.Value;

    /// <summary>Set this in HTTP middleware before authentication to cover rejected requests too.</summary>
    public static string EnsureRequestId(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        var id = context.Items.TryGetValue(RequestIdItem, out var item) && item is string stored
            && IsOperationId(stored) ? stored
            : Guid.NewGuid().ToString("N");
        context.Items[RequestIdItem] = id;
        context.TraceIdentifier = id;
        if (!context.Response.HasStarted) context.Response.Headers["X-Request-ID"] = id;
        return id;
    }

    public static McpRequestFilter<CallToolRequestParams, CallToolResult> WrapCallTool =>
        next => async (context, cancellationToken) =>
        {
            var http = context.Services?.GetService<IHttpContextAccessor>()?.HttpContext;
            var id = http is null ? Guid.NewGuid().ToString("N") : EnsureRequestId(http);
            var tool = SafeToolName(context.Params?.Name);
            using var scope = Begin(id, tool);
            var state = CurrentState.Value!;
            var audit = context.Services?.GetService<AuditLog>();
            CallToolResult result;

            try
            {
                using var admission = context.Services is { } services
                    ? await services.GetRequiredService<RequestAdmission>().AcquireOperationAsync(context.User!, cancellationToken)
                    : null;
                if (admission is { IsAcquired: false })
                {
                    state.SetAdmissionFailure(admission.Reason, admission.RetrySeconds);
                    result = Error("Exchange MCP is busy. Retry after the indicated delay; this invocation did not dispatch mailbox work.");
                }
                else result = await next(context, cancellationToken).ConfigureAwait(false);
            }
            catch (InputRequiredException)
            {
                state.SetApprovalRequired();
                await RecordSafely(audit, state, cancellationToken).ConfigureAwait(false);
                throw;
            }
            catch (OperationCanceledException)
            {
                state.SetCancelled();
                await RecordSafely(audit, state, CancellationToken.None).ConfigureAwait(false);
                throw;
            }
            catch (MailboxActionApprovalException exception)
            {
                state.SetApprovalFailure(exception.Reason);
                result = Error(exception.Message);
            }
            catch (RecallPreparationException exception)
            {
                state.SetRecallPreparationFailure(exception.Phase, exception.Reason);
                result = Error(exception.Message);
                result.StructuredContent = JsonSerializer.SerializeToElement(new
                {
                    status = "recall_preparation_failed",
                    submitted = false,
                    phase = exception.Phase,
                    reason = exception.Reason
                });
            }
            catch (McpException exception)
            {
                state.SetFailure();
                result = Error(exception.Message);
            }
            catch (Exception exception) when (IsSafeToHandle(exception))
            {
                state.SetFailure();
                result = Error("The request failed inside Exchange MCP. Use the tracking ID to ask the administrator to inspect the server log.");
            }

            state.CompleteApprovalReservations(result);
            state.SetResult(result.IsError == true);
            var tracked = AddTracking(result, state);
            await RecordSafely(audit, state, CancellationToken.None).ConfigureAwait(false);
            return tracked;
        };

    public static McpRequestFilter<ReadResourceRequestParams, ReadResourceResult> WrapReadResource =>
        next => async (context, cancellationToken) =>
        {
            var http = context.Services?.GetService<IHttpContextAccessor>()?.HttpContext;
            var id = http is null ? Guid.NewGuid().ToString("N") : EnsureRequestId(http);
            var audit = context.Services?.GetService<AuditLog>();
            var uri = context.Params?.Uri;
            var status = "failed";
            ReadResourceResult? result = null;
            try
            {
                result = await next(context, cancellationToken).ConfigureAwait(false);
                status = "completed";
                return result;
            }
            catch (OperationCanceledException)
            {
                status = "cancelled";
                throw;
            }
            finally
            {
                if (audit is not null)
                {
                    try { await audit.RecordResourceAsync(id, uri, status, result, CancellationToken.None).ConfigureAwait(false); }
                    catch (Exception exception) when (IsSafeToHandle(exception)) { }
                }
            }
        };

    internal static IDisposable Begin(string id, string tool)
    {
        var previous = CurrentState.Value;
        var state = new OperationState(id, tool);
        CurrentState.Value = state;
        return new Scope(previous, state);
    }

    internal static bool IsOperationId(string? value) => value is { Length: 32 }
        && value.All(character => character is >= '0' and <= '9' or >= 'a' and <= 'f' or >= 'A' and <= 'F');

    private static bool IsSafeToHandle(Exception exception) =>
        exception is not (OutOfMemoryException or StackOverflowException or AccessViolationException);

    private static string SafeToolName(string? value) => value is { Length: > 0 and <= 80 }
        && value.All(character => char.IsAsciiLetterOrDigit(character) || character is '_' or '-')
            ? value : "unknown_tool";

    private static CallToolResult Error(string message) => new()
    {
        IsError = true,
        Content = [new TextContentBlock { Text = message }]
    };

    private static CallToolResult AddTracking(CallToolResult result, OperationState state)
    {
        var outcome = state.AdmissionReason is not null || state.ApprovalFailureReason is not null ? "not_dispatched"
            : state.Tool == "mail_send_draft" || state.ExchangeSendAttempted
            ? state.SendOutcome : result.IsError == true ? "failed" : "completed";
        var tracking = new JsonObject
        {
            ["id"] = state.Id,
            ["outcome"] = outcome,
            ["stage"] = state.Stage
        };
        if (state.Tool is "mail_send_draft" or "mail_recall_message" || state.ExchangeSendAttempted)
            tracking["sendStatus"] = state.SendOutcome;
        if (state.RecallPreparationPhase is { } phase)
        {
            tracking["phase"] = phase;
            tracking["reason"] = state.RecallPreparationReason;
        }
        if (state.ApprovalFailureReason is { } reason)
        {
            tracking["reason"] = reason;
            tracking["dispatchStatus"] = "not_dispatched";
        }
        if (state.ApprovalCompletionFailed) tracking["approvalPersistence"] = "hold_retained";
        if (state.AdmissionReason is { } admissionReason)
        {
            tracking["reason"] = admissionReason;
            tracking["retrySeconds"] = state.RetrySeconds;
            tracking["dispatchStatus"] = "not_dispatched";
        }

        var structured = result.StructuredContent;
        // Some SDK tools serialize their payload only in the first text block.
        if (structured is null && result.Content?.FirstOrDefault() is TextContentBlock { Text: { } text })
        {
            try
            {
                using var payload = JsonDocument.Parse(text);
                structured = payload.RootElement.Clone();
            }
            catch (JsonException) { }
        }
        var root = structured is { ValueKind: JsonValueKind.Object }
            ? JsonNode.Parse(structured.Value.GetRawText()) as JsonObject ?? new JsonObject()
            : new JsonObject();
        if (root.ContainsKey("tracking"))
        {
            root = new JsonObject { ["data"] = root };
        }
        root["tracking"] = tracking;
        if (state.AdmissionReason is { } rejected)
        {
            root["reason"] = rejected;
            root["retrySeconds"] = state.RetrySeconds;
            root["dispatchStatus"] = "not_dispatched";
        }
        // Keep array/scalar response contracts intact for existing callers.
        if (structured is null or { ValueKind: JsonValueKind.Object })
        {
            using var document = JsonDocument.Parse(root.ToJsonString());
            result.StructuredContent = document.RootElement.Clone();
        }
        result.Meta ??= new JsonObject();
        result.Meta["tracking"] = tracking.DeepClone();

        var note = state.ApprovalFailureReason is not null
            ? $"Tracking ID: {state.Id}. This invocation did not dispatch the mailbox write. Approval status: {state.ApprovalFailureReason}. A replay rejection does not establish the outcome of an earlier invocation."
            : state.Tool == "mail_send_draft" ? SendNote(state)
            : state.ExchangeSendAttempted ? ExchangeSendNote(state)
            : $"Tracking ID: {state.Id}.";
        var content = result.Content?.ToList() ?? [];
        content.Add(new TextContentBlock { Text = note });
        if (state.ApprovalCompletionFailed)
            content.Add(new TextContentBlock { Text = "The mailbox action completed, but durable approval completion could not be saved. Its replay hold remains; do not repeat the action. Ask the administrator to inspect approval storage." });
        result.Content = content;
        return result;
    }

    private static string SendNote(OperationState state) => state.SendOutcome switch
    {
        "acknowledged" => $"Tracking ID: {state.Id}. Exchange acknowledged the send request; this does not confirm delivery.",
        "rejected" => $"Tracking ID: {state.Id}. Send status: rejected by Exchange. No successful send acknowledgement was received.",
        "unknown" => $"Tracking ID: {state.Id}. Send status: unknown because the Exchange request attempt started. Check Sent Items before retrying; do not retry until its status is confirmed.",
        _ => $"Tracking ID: {state.Id}. Send status: not_dispatched; the SendItem request was not sent to Exchange."
    };

    private static string ExchangeSendNote(OperationState state) => state.SendOutcome switch
    {
        "acknowledged" => $"Tracking ID: {state.Id}. Exchange acknowledged the outbound request; this does not confirm delivery.",
        "rejected" => $"Tracking ID: {state.Id}. Exchange rejected the outbound request; no successful acknowledgement was received.",
        _ => $"Tracking ID: {state.Id}. The outbound Exchange outcome is unknown. Confirm the item status before repeating this operation."
    };

    private static async Task RecordSafely(AuditLog? audit, OperationState state, CancellationToken cancellationToken)
    {
        if (audit is null) return;
        var sendStatus = state.Tool is "mail_send_draft" or "mail_recall_message" || state.ExchangeSendAttempted ? state.SendOutcome : null;
        try { await audit.RecordTrackingAsync(state.Id, state.Tool, state.Outcome, state.Stage, sendStatus, cancellationToken).ConfigureAwait(false); }
        catch (Exception exception) when (IsSafeToHandle(exception)) { }
    }

    internal sealed class OperationState(string id, string tool)
    {
        private readonly List<(string Action, Action Complete)> approvalCompletions = [];
        public bool ApprovalCompletionFailed { get; private set; }
        public string? ApprovalFailureReason { get; private set; }
        public string? AdmissionReason { get; private set; }
        public string? RecallPreparationPhase { get; private set; }
        public string? RecallPreparationReason { get; private set; }
        public int RetrySeconds { get; private set; }
        public string Id { get; } = id;
        public string Tool { get; } = tool;
        public string Stage { get; private set; } = "started";
        public string Outcome { get; private set; } = "in_progress";
        public string SendOutcome { get; private set; } = "not_dispatched";
        public bool ExchangeSendAttempted { get; private set; }

        public void RegisterApprovalCompletion(string action, Action complete) => approvalCompletions.Add((action, complete));

        public void CompleteApprovalReservations(CallToolResult result)
        {
            if (result.IsError == true || ApprovalFailureReason is not null
                || (ExchangeSendAttempted && SendOutcome != "acknowledged")) return;
            JsonElement? payload = result.StructuredContent;
            if (payload is null && result.Content?.FirstOrDefault() is TextContentBlock { Text: { } text })
            {
                try { using var document = JsonDocument.Parse(text); payload = document.RootElement.Clone(); }
                catch (JsonException) { return; }
            }
            var status = payload is { ValueKind: JsonValueKind.Object } value
                && value.TryGetProperty("status", out var statusValue) && statusValue.ValueKind == JsonValueKind.String
                ? statusValue.GetString() : null;
            foreach (var (action, complete) in approvalCompletions)
            {
                var acknowledged = action switch
                {
                    "send" => SendOutcome == "acknowledged",
                    "create_invitation" => status == "event_created",
                    "update_invitation" => status == "event_updated",
                    "cancel_invitation" => status is "occurrence_removed_from_series" or "meeting_cancelled" or "event_moved_to_deleted_items",
                    "respond" => status is "response_sent" or "response_saved",
                    "recall" => status == "recall_requested",
                    "sharing_set_folder_permission" or "sharing_remove_folder_permission" => status == "folder_permissions_updated",
                    "delegate_add" => status == "delegate_added",
                    "delegate_update" => status == "delegate_updated",
                    "delegate_remove" => status == "delegate_removed",
                    "oof_activate" or "inbox_rule_delete" => payload is { ValueKind: JsonValueKind.Object },
                    "task_delete_copy" => status == "task_moved_to_deleted_items",
                    // Plans return non-error partial results too; only complete execution releases their hold.
                    var task when task.StartsWith("task_", StringComparison.Ordinal) => status == "completed",
                    _ => false
                };
                if (!acknowledged) continue;
                try { complete(); }
                catch (Exception exception) when (IsSafeToHandle(exception))
                {
                    // This runs after a verified write; preserve its result and the conservative replay hold.
                    ApprovalCompletionFailed = true;
                }
            }
        }

        public void SetExchangeSendDispatched()
        {
            ExchangeSendAttempted = true;
            Stage = "exchange_send_dispatched";
            SendOutcome = "unknown";
        }

        public void SetExchangeSendAcknowledged()
        {
            Stage = "exchange_send_acknowledged";
            SendOutcome = "acknowledged";
        }

        public void SetExchangeSendRejected()
        {
            Stage = "exchange_send_rejected";
            SendOutcome = "rejected";
        }

        public void SetApprovalRequired() { Stage = "approval_required"; Outcome = "approval_required"; }
        public void SetRecallPreparationFailure(string phase, string reason)
        {
            RecallPreparationPhase = phase;
            RecallPreparationReason = reason;
            Stage = "recall_preparation_" + phase;
            Outcome = "failed";
        }
        public void SetAdmissionFailure(string reason, int retrySeconds)
        {
            AdmissionReason = reason; RetrySeconds = retrySeconds;
            Stage = "admission_" + reason; Outcome = "not_dispatched";
        }
        public void SetApprovalFailure(string reason)
        {
            ApprovalFailureReason = reason;
            Stage = "approval_" + reason;
            Outcome = "not_dispatched";
        }
        public void SetCancelled()
        {
            if (Tool == "mail_send_draft" && SendOutcome == "unknown") Outcome = "unknown";
            else { Stage = "cancelled"; Outcome = Tool == "mail_send_draft" ? SendOutcome : "cancelled"; }
        }

        public void SetFailure()
        {
            if (ExchangeSendAttempted)
            {
                Outcome = SendOutcome;
                return;
            }
            Stage = "failed";
            Outcome = Tool == "mail_send_draft" ? SendOutcome : "failed";
        }

        public void SetResult(bool isError)
        {
            if (AdmissionReason is not null || ApprovalFailureReason is not null) return;
            if (ExchangeSendAttempted)
            {
                Outcome = SendOutcome;
                return;
            }
            if (Tool != "mail_send_draft")
            {
                if (isError && Stage == "started") Stage = "failed";
                Outcome = isError ? "failed" : "completed";
                return;
            }

            if (isError && SendOutcome == "not_dispatched") Stage = "failed";
            Outcome = SendOutcome;
        }
    }

    private sealed class Scope(OperationState? previous, OperationState state) : IDisposable
    {
        public OperationState State { get; } = state;
        public void Dispose() => CurrentState.Value = previous;
    }
}
