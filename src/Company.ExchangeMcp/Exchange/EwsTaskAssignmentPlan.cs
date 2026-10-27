using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Xml.Linq;

namespace Company.ExchangeMcp.Exchange;

public sealed partial class EwsClient
{
    internal static IReadOnlyList<DateOnly> ExpandTaskAssignmentPlanOccurrences(
        EwsTask task,
        DateOnly throughDate,
        int maximumOccurrences)
    {
        var recurrence = task.Recurrence
            ?? throw new ArgumentException("A recurring task needs recurrence details.", nameof(task));
        if (recurrence.Pattern is "dailyRegeneration" or "weeklyRegeneration" or "monthlyRegeneration" or "yearlyRegeneration")
            throw new InvalidOperationException("Completion-based task recurrence cannot be expanded into fixed dates.");
        if (recurrence.Pattern is not ("daily" or "weekly" or "monthly" or "yearly" or "relativeMonthly" or "relativeYearly"))
            throw new InvalidOperationException("The task recurrence pattern is not supported for assignment planning.");
        if (maximumOccurrences is < 1 or > 32) throw new ArgumentOutOfRangeException(nameof(maximumOccurrences));
        ValidateRecurrence(recurrence);
        var start = DateOnly.FromDateTime((recurrence.StartDateUtc ?? task.StartDateUtc
            ?? throw new InvalidOperationException("The recurring task has no recurrence start date.")).UtcDateTime);
        if (throughDate < start) throw new ArgumentException("throughDate must be on or after the recurrence start date.", nameof(throughDate));
        DateOnly maximumThroughDate;
        try { maximumThroughDate = start.AddYears(32); }
        catch (ArgumentOutOfRangeException) { maximumThroughDate = DateOnly.MaxValue; }
        if (throughDate > maximumThroughDate)
            throw new ArgumentException("The requested horizon cannot exceed 32 years.", nameof(throughDate));
        var end = recurrence.Range == "EndDate" && recurrence.EndDateUtc is { } endDate
            ? DateOnly.FromDateTime(endDate.UtcDateTime) : DateOnly.MaxValue;
        var limit = recurrence.Range == "Numbered" ? recurrence.NumberOfOccurrences : null;
        var results = new List<DateOnly>();

        void Add(DateOnly date)
        {
            if (date < start || date > end || date > throughDate || limit is { } count && results.Count >= count) return;
            results.Add(date);
            if (results.Count > maximumOccurrences)
                throw new InvalidOperationException($"The requested horizon expands to more than {maximumOccurrences} occurrences per recipient.");
        }

        switch (recurrence.Pattern)
        {
            case "daily":
                for (var index = 0; ; index++)
                {
                    DateOnly date;
                    try { date = start.AddDays(checked((int)((long)index * recurrence.Interval))); }
                    catch (ArgumentOutOfRangeException) { break; }
                    if (date > throughDate || date > end || limit is { } dailyLimit && results.Count >= dailyLimit) break;
                    Add(date);
                }
                break;
            case "weekly":
                {
                    var firstDay = ParseTaskRecurrenceDay(recurrence.FirstDayOfWeek ?? "Sunday");
                    var anchorWeekDayNumber = (long)start.DayNumber - ((7 + (int)start.DayOfWeek - (int)firstDay) % 7);
                    var days = RecurrenceDays(recurrence.DaysOfWeek!);
                    for (var date = start; date <= throughDate && date <= end;)
                    {
                        var week = (date.DayNumber - anchorWeekDayNumber) / 7;
                        if (week % recurrence.Interval == 0 && days.Contains(date.DayOfWeek))
                        {
                            Add(date);
                            if (limit is { } weeklyLimit && results.Count >= weeklyLimit) break;
                        }
                        if (date == throughDate || date == end || date == DateOnly.MaxValue) break;
                        date = date.AddDays(1);
                    }
                    break;
                }
            case "monthly":
                for (var index = 0; ; index++)
                {
                    DateOnly month;
                    try { month = new DateOnly(start.Year, start.Month, 1).AddMonths(index * recurrence.Interval); }
                    catch (ArgumentOutOfRangeException) { break; }
                    if (month > throughDate || month > end) break;
                    var day = Math.Min(recurrence.DayOfMonth!.Value, DateTime.DaysInMonth(month.Year, month.Month));
                    Add(new DateOnly(month.Year, month.Month, day));
                    if (limit is { } monthlyLimit && results.Count >= monthlyLimit) break;
                }
                break;
            case "yearly":
                for (var year = start.Year; year <= throughDate.Year && year <= end.Year; year++)
                {
                    var month = recurrence.Month!.Value;
                    var day = Math.Min(recurrence.DayOfMonth!.Value, DateTime.DaysInMonth(year, month));
                    if (year >= start.Year) Add(new DateOnly(year, month, day));
                    if (limit is { } yearlyLimit && results.Count >= yearlyLimit) break;
                }
                break;
            case "relativeMonthly":
                for (var index = 0; ; index++)
                {
                    DateOnly month;
                    try { month = new DateOnly(start.Year, start.Month, 1).AddMonths(index * recurrence.Interval); }
                    catch (ArgumentOutOfRangeException) { break; }
                    if (month > throughDate || month > end) break;
                    Add(SelectRelativeDate(month.Year, month.Month, recurrence.DaysOfWeek![0], recurrence.DayOfWeekIndex!));
                    if (limit is { } relativeMonthlyLimit && results.Count >= relativeMonthlyLimit) break;
                }
                break;
            case "relativeYearly":
                for (var year = start.Year; year <= throughDate.Year && year <= end.Year; year++)
                {
                    Add(SelectRelativeDate(year, recurrence.Month!.Value, recurrence.DaysOfWeek![0], recurrence.DayOfWeekIndex!));
                    if (limit is { } relativeYearlyLimit && results.Count >= relativeYearlyLimit) break;
                }
                break;
        }
        return results;
    }

    private static DateOnly SelectRelativeDate(int year, int month, string dayName, string index)
    {
        var days = Enumerable.Range(1, DateTime.DaysInMonth(year, month))
            .Select(day => new DateOnly(year, month, day))
            .Where(date => MatchesRecurrenceDay(date.DayOfWeek, dayName)).ToArray();
        if (days.Length == 0) throw new InvalidOperationException("The relative recurrence has no matching date.");
        return index == "Last" ? days[^1] : days[index switch { "First" => 0, "Second" => 1, "Third" => 2, "Fourth" => 3, _ => throw new InvalidOperationException("The recurrence index is not supported.") }];
    }

    private static HashSet<DayOfWeek> RecurrenceDays(IReadOnlyList<string> dayNames) =>
        dayNames.SelectMany(name => name switch
        {
            "Day" => Enum.GetValues<DayOfWeek>(),
            "Weekday" => new[] { DayOfWeek.Monday, DayOfWeek.Tuesday, DayOfWeek.Wednesday, DayOfWeek.Thursday, DayOfWeek.Friday },
            "WeekendDay" => new[] { DayOfWeek.Saturday, DayOfWeek.Sunday },
            _ => new[] { ParseTaskRecurrenceDay(name) }
        }).ToHashSet();

    private static bool MatchesRecurrenceDay(DayOfWeek day, string name) => name switch
    {
        "Day" => true,
        "Weekday" => day is not (DayOfWeek.Saturday or DayOfWeek.Sunday),
        "WeekendDay" => day is DayOfWeek.Saturday or DayOfWeek.Sunday,
        _ => ParseTaskRecurrenceDay(name) == day
    };

    private static DayOfWeek ParseTaskRecurrenceDay(string name) => name switch
    {
        "Sunday" => DayOfWeek.Sunday,
        "Monday" => DayOfWeek.Monday,
        "Tuesday" => DayOfWeek.Tuesday,
        "Wednesday" => DayOfWeek.Wednesday,
        "Thursday" => DayOfWeek.Thursday,
        "Friday" => DayOfWeek.Friday,
        "Saturday" => DayOfWeek.Saturday,
        _ => throw new InvalidOperationException("The recurrence day is not supported.")
    };

    internal async Task<EwsTask> ReadTaskAssignmentPlanTemplateAsync(
        string mailbox,
        string taskId,
        CancellationToken cancellationToken)
    {
        var normalizedMailbox = ValidateMailbox(mailbox);
        var task = await GetTaskAsync(normalizedMailbox, ValidateItemId(taskId, "task"), cancellationToken)
            .ConfigureAwait(false);
        task = await HydrateTaskAttachmentsAsync(normalizedMailbox, task, cancellationToken).ConfigureAwait(false);
        ValidateTaskAssignmentPlanTemplate(task);
        return task;
    }

    internal static string TaskAssignmentPlanTemplateDigest(EwsTask task) =>
        Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(task)));

    internal static string NormalizeTaskAssignmentPlanRecipient(string value) => NormalizeAddress(value);

    internal EwsTaskAction PrepareTaskAssignmentPlanPreview(
        EwsTask template,
        string mailbox,
        string assignee,
        DateTimeOffset? startDateUtc,
        DateTimeOffset? dueDateUtc,
        DateTimeOffset? reminderDueByUtc,
        string globalTaskId,
        bool keepUpdated,
        bool completionReport,
        DateTimeOffset actionTimeUtc)
    {
        ValidateTaskAssignmentPlanTemplate(template);
        var normalizedMailbox = ValidateMailbox(mailbox);
        var normalizedAssignee = NormalizeAddress(assignee);
        var copy = BuildTaskAssignmentPlanCopy(template, startDateUtc, dueDateUtc, reminderDueByUtc, globalTaskId);
        ValidateAssignableTask(copy);
        var assignment = copy.Assignment!;
        var prepared = copy with
        {
            Assignment = assignment with
            {
                AssignerAddress = normalizedMailbox,
                AssigneeAddress = normalizedAssignee,
                OwnerAddress = normalizedAssignee,
                Version = Math.Max(1, assignment.Version ?? 1) + 1,
                State = 3,
                Ownership = 1,
                AcceptanceState = 1,
                LastUpdateUtc = actionTimeUtc.ToUniversalTime(),
                LastUserName = normalizedMailbox,
                LastDelegateName = normalizedMailbox,
                Accepted = false,
                UpdatesEnabled = keepUpdated,
                CompletionReportEnabled = completionReport
            }
        };
        var payload = BuildTaskSendOperation(prepared, normalizedAssignee, normalizedMailbox,
            "IPM.TaskRequest", keepUpdated, completionReport);
        return CreateTaskAction("assign", normalizedMailbox, prepared, normalizedAssignee,
            template.Id, payload, false, sourceChangeKey: template.ChangeKey,
            previewTask: prepared, actionTimeUtc: actionTimeUtc);
    }

    internal static void PreflightTaskAssignmentPlanCopy(
        EwsTask template,
        DateTimeOffset? startDateUtc,
        DateTimeOffset? dueDateUtc,
        DateTimeOffset? reminderDueByUtc,
        string globalTaskId)
    {
        ValidateTaskAssignmentPlanTemplate(template);
        var normalizedGlobalId = ValidateGlobalTaskId(globalTaskId)
            ?? throw new ArgumentException("A planned assignment needs a fresh native task identifier.", nameof(globalTaskId));
        if (string.Equals(template.Assignment?.GlobalTaskId, normalizedGlobalId, StringComparison.Ordinal))
            throw new InvalidOperationException("A planned task copy cannot reuse its template's GlobalTaskId.");
        var copy = BuildTaskAssignmentPlanCopy(template, startDateUtc, dueDateUtc, reminderDueByUtc, normalizedGlobalId);
        ValidateAssignableTask(copy);
        _ = BuildTaskAssignmentPlanCopyCreateOperation(copy);
    }

    internal async Task<EwsItemRef> CreateTaskAssignmentPlanCopyAsync(
        string mailbox,
        string templateId,
        string templateChangeKey,
        string templateDigest,
        DateTimeOffset? startDateUtc,
        DateTimeOffset? dueDateUtc,
        DateTimeOffset? reminderDueByUtc,
        string globalTaskId,
        CancellationToken cancellationToken)
    {
        var normalizedMailbox = ValidateMailbox(mailbox);
        var template = await ReadTaskAssignmentPlanTemplateAsync(normalizedMailbox, templateId, cancellationToken)
            .ConfigureAwait(false);
        if (!string.Equals(template.ChangeKey, templateChangeKey, StringComparison.Ordinal)
            || !string.Equals(TaskAssignmentPlanTemplateDigest(template), templateDigest, StringComparison.Ordinal))
            throw new InvalidOperationException("The task template changed after the assignment plan was approved.");

        var normalizedGlobalId = ValidateGlobalTaskId(globalTaskId)
            ?? throw new ArgumentException("A planned assignment needs a fresh native task identifier.", nameof(globalTaskId));
        if (string.Equals(template.Assignment?.GlobalTaskId, normalizedGlobalId, StringComparison.Ordinal))
            throw new InvalidOperationException("A planned task copy cannot reuse its template's GlobalTaskId.");
        await EnsureNoDuplicateTaskGlobalIdAsync(normalizedMailbox, normalizedGlobalId, cancellationToken)
            .ConfigureAwait(false);

        var copy = BuildTaskAssignmentPlanCopy(template, startDateUtc, dueDateUtc, reminderDueByUtc, normalizedGlobalId);
        ValidateAssignableTask(copy);
        var create = BuildTaskAssignmentPlanCopyCreateOperation(copy);
        var document = await SendAsync(normalizedMailbox, create, cancellationToken).ConfigureAwait(false);
        return ParseItemReference(RequiredReturnedItem(document));
    }

    private static XElement BuildTaskAssignmentPlanCopyCreateOperation(EwsTask copy)
    {
        var create = new XElement(M + "CreateItem",
            new XElement(M + "SavedItemFolderId", PeopleTasksFolderReference("tasks")),
            new XElement(M + "Items", BuildDetachedTask(copy)));
        if (Encoding.UTF8.GetByteCount(create.ToString(SaveOptions.DisableFormatting)) > 512 * 1024)
            throw new InvalidOperationException("The planned sender-side task copy exceeds the 512 KiB native payload limit.");
        return create;
    }

    internal async Task<EwsItemRef?> FindTaskAssignmentPlanCopyAsync(
        string mailbox,
        string globalTaskId,
        CancellationToken cancellationToken)
    {
        var found = await FindTaskByGlobalIdAsync(ValidateMailbox(mailbox),
            ValidateGlobalTaskId(globalTaskId) ?? throw new ArgumentException("A planned GlobalTaskId is required.", nameof(globalTaskId)),
            cancellationToken).ConfigureAwait(false);
        return found?.Reference;
    }

    private static void ValidateTaskAssignmentPlanTemplate(EwsTask task)
    {
        if (EwsClient.IsAssignedTaskCopy(task))
            throw new InvalidOperationException("Assignment plans require an unassigned task template.");
        if (string.IsNullOrWhiteSpace(task.Subject))
            throw new InvalidOperationException("A task without a subject cannot be used as an assignment template.");
        if (task.IsRecurring != (task.Recurrence is not null))
            throw new InvalidOperationException("Exchange returned an incomplete task recurrence; refresh the task before planning assignments.");
        ValidateTaskAttachmentMetadata(task, task.Attachments ?? Array.Empty<EwsAttachment>());
        ValidateTaskAttachmentSnapshot(task);
    }

    private static EwsTask BuildTaskAssignmentPlanCopy(
        EwsTask template,
        DateTimeOffset? startDateUtc,
        DateTimeOffset? dueDateUtc,
        DateTimeOffset? reminderDueByUtc,
        string globalTaskId)
    {
        var assignment = new EwsTaskAssignmentInfo(null, null, globalTaskId, null, null, null,
            null, null, false, false);
        return template with
        {
            StartDateUtc = startDateUtc,
            DueDateUtc = dueDateUtc,
            ReminderDueByUtc = reminderDueByUtc,
            Recurrence = null,
            IsRecurring = false,
            Assignment = assignment
        };
    }
}
