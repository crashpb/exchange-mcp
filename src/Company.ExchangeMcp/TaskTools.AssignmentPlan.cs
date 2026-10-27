using System.Collections.Concurrent;
using System.ComponentModel;
using System.Globalization;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Company.ExchangeMcp.Exchange;
using Company.ExchangeMcp.Security;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;

namespace Company.ExchangeMcp;

internal sealed record TaskAssignmentPlanRow(
    string Assignee,
    DateOnly? OccurrenceDate,
    DateTimeOffset? StartDateUtc,
    DateTimeOffset? DueDateUtc,
    DateTimeOffset? ReminderDueByUtc,
    string GlobalTaskId);

internal sealed record TaskAssignmentPlan(
    string Id,
    string Binding,
    string TemplateId,
    string TemplateChangeKey,
    string TemplateDigest,
    string Digest,
    string Subject,
    DateTimeOffset ActionTimeUtc,
    bool KeepUpdated,
    bool CompletionReport,
    IReadOnlyList<TaskAssignmentPlanRow> Rows,
    DateTimeOffset ExpiresUtc,
    int SizeBytes);

/// <summary>Short-lived, process-local storage for explicit task plans. Plans are one-shot and actor/session bound.</summary>
public sealed class TaskAssignmentPlanStore
{
    private const int MaxPlanBytes = 1024 * 1024;
    private const int MaxStoreBytes = 16 * 1024 * 1024;
    private const int MaxPlans = 128;
    private static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(5);
    private readonly object gate = new();
    private readonly Dictionary<string, TaskAssignmentPlan> plans = new(StringComparer.Ordinal);
    private int storedBytes;

    internal TaskAssignmentPlan Add(MailboxIdentity identity, string templateId, string changeKey,
        string templateDigest, string subject, DateTimeOffset actionTimeUtc, bool keepUpdated,
        bool completionReport, IReadOnlyList<TaskAssignmentPlanRow> rows)
    {
        var binding = Binding(identity);
        var payload = JsonSerializer.SerializeToUtf8Bytes(new
        {
            templateId,
            changeKey,
            templateDigest,
            subject,
            actionTimeUtc,
            keepUpdated,
            completionReport,
            rows
        });
        if (payload.Length > MaxPlanBytes) throw new McpException("The assignment plan exceeds the 1 MiB limit.");
        var digest = Convert.ToHexString(SHA256.HashData(payload));
        var now = DateTimeOffset.UtcNow;
        lock (gate)
        {
            RemoveExpired(now);
            if (plans.Count >= MaxPlans || storedBytes + payload.Length > MaxStoreBytes)
                throw new McpException("The short-lived assignment plan store is full. Wait for an existing plan to expire.");
            var id = Convert.ToHexString(RandomNumberGenerator.GetBytes(24));
            var plan = new TaskAssignmentPlan(id, binding, templateId, changeKey, templateDigest, digest,
                subject, actionTimeUtc, keepUpdated, completionReport, rows.ToArray(), now + Lifetime, payload.Length);
            plans.Add(id, plan);
            storedBytes += payload.Length;
            return plan;
        }
    }

    internal TaskAssignmentPlan Get(string id, MailboxIdentity identity)
    {
        lock (gate)
        {
            RemoveExpired(DateTimeOffset.UtcNow);
            if (!plans.TryGetValue(id, out var plan) || !string.Equals(plan.Binding, Binding(identity), StringComparison.Ordinal))
                throw new McpException("The assignment plan is invalid or expired. Create a new plan.");
            return plan;
        }
    }

    internal TaskAssignmentPlan Take(string id, MailboxIdentity identity)
    {
        lock (gate)
        {
            RemoveExpired(DateTimeOffset.UtcNow);
            if (!plans.TryGetValue(id, out var plan) || !string.Equals(plan.Binding, Binding(identity), StringComparison.Ordinal))
                throw new McpException("The assignment plan is invalid or expired. Create a new plan.");
            plans.Remove(id);
            storedBytes -= plan.SizeBytes;
            return plan;
        }
    }

    internal void Remove(string id, MailboxIdentity identity)
    {
        lock (gate)
        {
            if (plans.TryGetValue(id, out var plan) && string.Equals(plan.Binding, Binding(identity), StringComparison.Ordinal))
            {
                plans.Remove(id);
                storedBytes -= plan.SizeBytes;
            }
        }
    }

    private void RemoveExpired(DateTimeOffset now)
    {
        foreach (var pair in plans.Where(pair => pair.Value.ExpiresUtc <= now).ToArray())
        {
            plans.Remove(pair.Key);
            storedBytes -= pair.Value.SizeBytes;
        }
    }

    private static string Binding(MailboxIdentity identity) =>
        identity.Subject + "\0" + MailboxHandles.TargetBinding(identity, identity.Mailbox)
        + "\0" + identity.TargetId + "\0" + (identity.ActorMailbox ?? identity.Mailbox);
}

public sealed partial class TaskTools
{
    private const int MaxAssignmentPlanRecipients = 8;
    private const int MaxAssignmentPlanRows = 32;

    [McpServerTool(Name = "task_plan_assignments", ReadOnly = true, Destructive = false, Idempotent = true, OpenWorld = false)]
    [Description("Prepare a read-only, five-minute plan to assign one task to up to eight people. Recurring tasks require an inclusive throughDate (YYYY-MM-DD); all finite child assignments are shown and require one separate exact native approval before any task copy or request is created.")]
    public Task<object> PlanAssignments(ClaimsPrincipal user, string taskHandle, string[] assignees,
        CancellationToken cancellationToken, string? throughDate = null, bool keepUpdated = true,
        bool completionReport = true) => Run(user, MailboxAccess.Read, "task_plan_assignments", async (identity, ct) =>
        {
            if (assignmentPlans is null) throw new McpException("Assignment plans are unavailable in this server configuration.");
            if (assignees is null || assignees.Length is < 1 or > MaxAssignmentPlanRecipients)
                throw new McpException($"Provide one to {MaxAssignmentPlanRecipients} assignees.");
            access.ValidateRecipients(assignees);
            var normalizedAssignees = assignees.Select(EwsClient.NormalizeTaskAssignmentPlanRecipient)
                .Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
            if (normalizedAssignees.Length != assignees.Length)
                throw new McpException("Each assignee must be unique.");
            var reference = handles.Resolve(identity, "task", taskHandle);
            var template = await exchange.ReadTaskAssignmentPlanTemplateAsync(identity.Mailbox, reference.Id, ct).ConfigureAwait(false);
            RequireCurrent(reference, template.ChangeKey);
            var templateBytes = JsonSerializer.SerializeToUtf8Bytes(template).Length;
            if (templateBytes > 1024 * 1024) throw new McpException("The task template exceeds the 1 MiB assignment-plan limit.");

            DateOnly? through = null;
            IReadOnlyList<DateOnly> dates;
            if (template.IsRecurring)
            {
                if (string.IsNullOrWhiteSpace(throughDate)
                    || !DateOnly.TryParseExact(throughDate, "yyyy-MM-dd", CultureInfo.InvariantCulture,
                        DateTimeStyles.None, out var parsedThrough))
                    throw new McpException("Recurring tasks require throughDate in YYYY-MM-DD format.");
                through = parsedThrough;
                dates = EwsClient.ExpandTaskAssignmentPlanOccurrences(template, through.Value,
                    MaxAssignmentPlanRows / normalizedAssignees.Length);
                if (dates.Count == 0) throw new McpException("The recurrence has no occurrences within the requested horizon.");
            }
            else
            {
                if (throughDate is not null) throw new McpException("throughDate is only valid for a recurring task.");
                dates = [DateOnly.FromDateTime((template.StartDateUtc ?? template.DueDateUtc)?.UtcDateTime ?? DateTime.MinValue)];
            }

            var rows = new List<TaskAssignmentPlanRow>();
            foreach (var date in dates)
                foreach (var assignee in normalizedAssignees)
                {
                    var shift = template.IsRecurring
                        ? date.DayNumber - DateOnly.FromDateTime((template.Recurrence!.StartDateUtc ?? template.StartDateUtc)!.Value.UtcDateTime).DayNumber
                        : 0;
                    DateTimeOffset? Shift(DateTimeOffset? value) => value?.AddDays(shift);
                    rows.Add(new TaskAssignmentPlanRow(assignee, template.IsRecurring ? date : null,
                        Shift(template.StartDateUtc), Shift(template.DueDateUtc), Shift(template.ReminderDueByUtc),
                        Convert.ToBase64String(RandomNumberGenerator.GetBytes(16))));
                }
            if (rows.Count is < 1 or > MaxAssignmentPlanRows) throw new McpException("The plan exceeds 32 individual assignments.");
            var templateDigest = EwsClient.TaskAssignmentPlanTemplateDigest(template);
            var plan = assignmentPlans.Add(identity, template.Id, template.ChangeKey, templateDigest,
                template.Subject, DateTimeOffset.UtcNow, keepUpdated, completionReport, rows);
            return (object)new
            {
                status = "awaiting_exact_native_approval",
                planHandle = handles.Issue(identity, "taskplan", plan.Id, plan.Digest),
                templateHandle = taskHandle,
                templateSubject = template.Subject,
                templateChangeKey = template.ChangeKey,
                throughDate = through?.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture),
                assignmentCount = rows.Count,
                recipients = normalizedAssignees,
                expiresInSeconds = 300,
                items = rows.Select((row, index) => new
                {
                    index = index + 1,
                    row.Assignee,
                    occurrenceDate = row.OccurrenceDate?.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture),
                    startDateUtc = row.StartDateUtc?.ToString("O", CultureInfo.InvariantCulture),
                    dueDateUtc = row.DueDateUtc?.ToString("O", CultureInfo.InvariantCulture),
                    reminderDueByUtc = row.ReminderDueByUtc?.ToString("O", CultureInfo.InvariantCulture),
                    globalTaskId = row.GlobalTaskId,
                    resultingSubject = template.Subject
                }).ToArray()
            };
        }, cancellationToken);

    [McpServerTool(Name = "task_execute_assignment_plan", ReadOnly = false, Destructive = false, Idempotent = false, OpenWorld = true)]
    [Description("Execute every child assignment in a live task plan after one exact native approval of all recipients, dates and resulting copies. Creates independent nonrecurring sender-side copies; stops on the first failed or uncertain step and never retries automatically.")]
    public Task<object> ExecuteAssignmentPlan(ClaimsPrincipal user, string planHandle, McpServer server,
        RequestContext<CallToolRequestParams> context, CancellationToken cancellationToken) =>
        Run(user, MailboxAccess.Send, "task_execute_assignment_plan", async (identity, ct) =>
        {
            if (assignmentPlans is null) throw new McpException("Assignment plans are unavailable in this server configuration.");
            _ = access.Require(user, MailboxAccess.Write);
            SendGuard.RequireConfirmationSupport(server, context);
            var handle = handles.Resolve(identity, "taskplan", planHandle);
            var plan = assignmentPlans.Get(handle.Id, identity);
            if (!string.Equals(handle.ChangeKey, plan.Digest, StringComparison.Ordinal))
                throw new McpException("The assignment-plan handle does not match its stored contents.");
            var templateHandle = handles.Issue(identity, "task", plan.TemplateId, plan.TemplateChangeKey);
            var templateReference = handles.Resolve(identity, "task", templateHandle);
            var template = await exchange.ReadTaskAssignmentPlanTemplateAsync(identity.Mailbox, templateReference.Id, ct).ConfigureAwait(false);
            RequireCurrent(templateReference, template.ChangeKey);
            RequirePlanTemplate(plan, template);
            foreach (var row in plan.Rows)
                EwsClient.PreflightTaskAssignmentPlanCopy(template, row.StartDateUtc, row.DueDateUtc,
                    row.ReminderDueByUtc, row.GlobalTaskId);
            var actions = plan.Rows.Select(row => exchange.PrepareTaskAssignmentPlanPreview(template, identity.Mailbox,
                row.Assignee, row.StartDateUtc, row.DueDateUtc, row.ReminderDueByUtc, row.GlobalTaskId,
                plan.KeepUpdated, plan.CompletionReport, plan.ActionTimeUtc)).ToArray();
            if (actions.Any(action => string.IsNullOrWhiteSpace(action.PayloadXml)
                || Encoding.UTF8.GetByteCount(action.PayloadXml) > 512 * 1024))
                throw new McpException("A native task request exceeds the 512 KiB per-assignment payload limit.");
            var (_, firstPreview) = TaskActionPreview(actions[0]);
            var preview = firstPreview + "\n\nComplete assignment plan (each row creates one independent, nonrecurring sender copy and sends one native request):\n"
                + string.Join("\n", plan.Rows.Select((row, index) =>
                    $"{index + 1}. To: {row.Assignee}; occurrence: {row.OccurrenceDate?.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture) ?? "single task"}; subject: {template.Subject}; start: {row.StartDateUtc?.ToString("O", CultureInfo.InvariantCulture) ?? "not set"}; due: {row.DueDateUtc?.ToString("O", CultureInfo.InvariantCulture) ?? "not set"}; reminder enabled: {template.ReminderIsSet}; reminder: {row.ReminderDueByUtc?.ToString("O", CultureInfo.InvariantCulture) ?? "not set"}; GlobalTaskId: {row.GlobalTaskId}"))
                + "\nThe source template remains unchanged. Approving sends all listed requests sequentially; execution stops after the first failed or uncertain result.";
            if (Encoding.UTF8.GetByteCount(preview) > 1024 * 1024)
                throw new McpException("The exact native confirmation exceeds the 1 MiB assignment-plan limit.");
            if (context.Params?.RequestState is null)
            {
                if (context.Params?.InputResponses is not null) throw new McpException("A valid task assignment-plan confirmation state is required.");
                approval.RequestApproval(identity, "task_execute_assignment_plan", plan.TemplateId,
                    plan.TemplateChangeKey, plan.Digest, preview, server, context,
                    "task_assignment_plan_confirmation", plan.ActionTimeUtc);
            }
            var state = approval.ReadApproval(identity, "task_execute_assignment_plan", plan.TemplateId, context);
            if (!CalendarActionApprovalGuard.Accepted(context, "task_assignment_plan_confirmation"))
            {
                approval.Cancel(state);
                assignmentPlans.Remove(plan.Id, identity);
                return (object)new { status = "cancelled", sent = false, applied = false };
            }
            var fresh = await exchange.ReadTaskAssignmentPlanTemplateAsync(identity.Mailbox, plan.TemplateId, ct).ConfigureAwait(false);
            RequirePlanTemplate(plan, fresh);
            approval.Consume(state, plan.TemplateId, fresh.ChangeKey, plan.Digest);
            plan = assignmentPlans.Take(plan.Id, identity);
            return await ExecuteAssignmentPlanRows(user, identity, plan, ct).ConfigureAwait(false);
        }, cancellationToken);

    private static void RequirePlanTemplate(TaskAssignmentPlan plan, EwsTask template)
    {
        if (!string.Equals(plan.TemplateChangeKey, template.ChangeKey, StringComparison.Ordinal)
            || !string.Equals(plan.TemplateDigest, EwsClient.TaskAssignmentPlanTemplateDigest(template), StringComparison.Ordinal))
            throw new McpException("The task template changed after planning. Create a fresh assignment plan.");
    }

    private async Task<object> ExecuteAssignmentPlanRows(ClaimsPrincipal user, MailboxIdentity identity,
        TaskAssignmentPlan plan, CancellationToken cancellationToken)
    {
        var results = new List<object>();
        var stop = false;
        foreach (var row in plan.Rows)
        {
            if (stop)
            {
                results.Add(new
                {
                    status = "unsent",
                    sent = false,
                    recipient = row.Assignee,
                    occurrenceDate = row.OccurrenceDate?.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture),
                    taskHandle = (string?)null,
                    reason = "Stopped after an earlier failed or uncertain assignment."
                });
                continue;
            }

            EwsItemRef? copy = null;
            try
            {
                _ = access.Require(user, MailboxAccess.Write);
                _ = access.Require(user, MailboxAccess.Send);
                access.ValidateRecipients([row.Assignee]);
                copy = await exchange.CreateTaskAssignmentPlanCopyAsync(identity.Mailbox, plan.TemplateId,
                    plan.TemplateChangeKey, plan.TemplateDigest, row.StartDateUtc, row.DueDateUtc,
                    row.ReminderDueByUtc, row.GlobalTaskId, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception exception)
            {
                var reconciled = await FindPlannedCopy(row.GlobalTaskId, identity.Mailbox, cancellationToken).ConfigureAwait(false);
                var copyHandle = reconciled is null ? null : handles.Issue(identity, "task", reconciled.Id, reconciled.ChangeKey);
                results.Add(new
                {
                    status = "uncertain",
                    sent = (bool?)null,
                    recipient = row.Assignee,
                    occurrenceDate = row.OccurrenceDate?.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture),
                    taskHandle = copyHandle,
                    failureKind = FailureKind(exception),
                    message = "The sender-side task copy could not be verified. Do not retry this plan; reconcile the task by its planned GlobalTaskId."
                });
                stop = true;
                continue;
            }

            var childHandle = handles.Issue(identity, "task", copy.Id, copy.ChangeKey);
            EwsTaskAction action;
            try
            {
                action = await exchange.PrepareTaskAssignmentAsync(identity.Mailbox, copy.Id, row.Assignee,
                    plan.KeepUpdated, plan.CompletionReport, false, cancellationToken, plan.ActionTimeUtc).ConfigureAwait(false);
            }
            catch (Exception exception)
            {
                results.Add(new
                {
                    status = "unsent",
                    sent = false,
                    recipient = row.Assignee,
                    occurrenceDate = row.OccurrenceDate?.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture),
                    taskHandle = childHandle,
                    failureKind = FailureKind(exception),
                    message = "The sender-side task copy exists, but its native request was not prepared. Do not rerun this plan."
                });
                stop = true;
                continue;
            }

            try
            {
                var result = await exchange.ExecuteTaskActionAsync(identity.Mailbox, action, cancellationToken).ConfigureAwait(false);
                results.Add(new
                {
                    status = result.Sent ? "sent" : "uncertain",
                    sent = (bool?)result.Sent,
                    recipient = row.Assignee,
                    occurrenceDate = row.OccurrenceDate?.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture),
                    taskHandle = result.ResultItemId is not null && !string.IsNullOrWhiteSpace(result.ResultChangeKey)
                        ? handles.Issue(identity, "task", result.ResultItemId, result.ResultChangeKey) : childHandle,
                    executionStatus = result.Status,
                    detail = result.Detail,
                    doNotRetryAutomatically = !result.Sent
                });
                stop = !result.Sent;
            }
            catch (Exception exception)
            {
                results.Add(new
                {
                    status = "uncertain",
                    sent = (bool?)null,
                    recipient = row.Assignee,
                    occurrenceDate = row.OccurrenceDate?.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture),
                    taskHandle = childHandle,
                    failureKind = FailureKind(exception),
                    message = "The native request did not return verified success. A notice may have been sent; reconcile this copy and its matching notice before any further action."
                });
                stop = true;
            }
        }
        return new { status = stop ? "partial_or_uncertain" : "completed", doNotRetryPlan = true, assignments = results };
    }

    private async Task<EwsItemRef?> FindPlannedCopy(string globalTaskId, string mailbox, CancellationToken cancellationToken)
    {
        try { return await exchange.FindTaskAssignmentPlanCopyAsync(mailbox, globalTaskId, cancellationToken).ConfigureAwait(false); }
        catch { return null; }
    }

    private static string FailureKind(Exception exception) => exception switch
    {
        EwsPermissionDeniedException => "permission_denied",
        EwsRequestFailedException failure => failure.ResponseCode ?? failure.Operation ?? "ews_request_failed",
        TimeoutException => "timeout",
        OperationCanceledException => "cancelled_or_timed_out",
        ArgumentException => "invalid_input",
        InvalidOperationException => "exchange_state_changed_or_invalid",
        _ => "unexpected_error"
    };
}
