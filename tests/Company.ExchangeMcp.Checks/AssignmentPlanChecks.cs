using System.Globalization;
using System.Reflection;
using System.Text;
using System.Xml.Linq;
using Company.ExchangeMcp.Exchange;
using Company.ExchangeMcp.Security;
using Microsoft.Extensions.DependencyInjection;

internal sealed partial class Checks
{
    private async Task AssignmentPlanChecksAsync()
    {
        await TaskPlanRecurrenceChecksAsync();

        var exchange = new AssignmentPlanRecordingHandler
        { UnassignedTask = true, IncludeTaskFileAttachment = true, IncludeTaskReminder = true };
        await using var host = await StartHostAsync(exchange, writesEnabled: true, sendEnabled: true,
            classicStateful: true);
        const string session = "task-plan-checks";
        var form = new NativeFormResponder(accept: false);
        var token = Token("user-a", "mail.read mail.write mail.send", sessionId: session);
        await using var client = await CreateNativeClientAsync(host, token, form);
        var identity = new MailboxIdentity("user-a", "alice@example.test", "chatgpt-test", session);
        var handle = host.App.Services.GetRequiredService<MailboxHandles>()
            .Issue(identity, "task", "task-1", exchange.TaskChangeKey);
        var planArguments = new Dictionary<string, object?>
        {
            ["taskHandle"] = handle,
            ["assignees"] = new[] { "bob@example.test", "carol@example.test" },
            ["throughDate"] = "2026-01-22"
        };
        var preview = await client.Client.CallToolAsync("task_plan_assignments", planArguments);
        var previewData = NativeData(preview);
        var plannedGlobalIds = previewData.GetProperty("items").EnumerateArray()
            .Select(item => item.GetProperty("globalTaskId").GetString()!).ToArray();
        Expect(preview.IsError != true && previewData.GetProperty("assignmentCount").GetInt32() == 4
            && plannedGlobalIds.Distinct(StringComparer.Ordinal).Count() == plannedGlobalIds.Length
            && plannedGlobalIds.All(value => Convert.FromBase64String(value).Length == 16)
            && exchange.CreateItemCount == 0 && exchange.UpdateItemCount == 0,
            "A recurring multiassignee plan did not expand to four read-only children with unique native GlobalTaskIds.");
        var planHandle = previewData.GetProperty("planHandle").GetString()!;
        var declined = await client.Client.CallToolAsync("task_execute_assignment_plan",
            new Dictionary<string, object?> { ["planHandle"] = planHandle });
        Expect(declined.IsError != true && NativeData(declined).GetProperty("status").GetString() == "cancelled"
            && form.Calls == 1 && exchange.CreateItemCount == 0 && exchange.UpdateItemCount == 0,
            "Declining a whole assignment plan created or sent a task copy.");
        var declinedPrompt = form.LastRequest?.Message ?? string.Empty;
        Expect(declinedPrompt.Contains("bob@example.test", StringComparison.OrdinalIgnoreCase)
            && declinedPrompt.Contains("carol@example.test", StringComparison.OrdinalIgnoreCase)
            && declinedPrompt.Contains("2026-01-12", StringComparison.Ordinal)
            && declinedPrompt.Contains("2026-01-14", StringComparison.Ordinal)
            && declinedPrompt.Contains("Disposable task", StringComparison.Ordinal)
            && declinedPrompt.Contains("evidence.bin", StringComparison.Ordinal)
            && declinedPrompt.Contains("reminder enabled: True; reminder: 2026-01-12T08:45:00.0000000+00:00", StringComparison.Ordinal)
            && declinedPrompt.Contains("reminder enabled: True; reminder: 2026-01-14T08:45:00.0000000+00:00", StringComparison.Ordinal),
            "The exact plan confirmation omitted recipients, occurrence dates, body, attachment or shifted reminder details.");

        form.Accept = true;
        exchange.FailOnCopyNumber = 2;
        var secondPlan = await client.Client.CallToolAsync("task_plan_assignments", planArguments);
        var secondPlanHandle = NativeData(secondPlan).GetProperty("planHandle").GetString()!;
        var executed = await client.Client.CallToolAsync("task_execute_assignment_plan",
            new Dictionary<string, object?> { ["planHandle"] = secondPlanHandle });
        var executedData = NativeData(executed);
        var rows = executedData.GetProperty("assignments").EnumerateArray().ToArray();
        Expect(executed.IsError != true && executedData.GetProperty("status").GetString() == "partial_or_uncertain"
            && rows.Length == 4 && rows[0].GetProperty("status").GetString() == "sent"
            && rows[1].GetProperty("status").GetString() == "uncertain"
            && rows.Skip(2).All(row => row.GetProperty("status").GetString() == "unsent"),
            "Plan execution did not stop after its first uncertain row or report every row.");
        var copyCreates = exchange.Calls.Count(call => call.Operation == "CreateItem"
            && call.Body.Contains("<m:SavedItemFolderId>", StringComparison.Ordinal)
            && call.Body.Contains("<m:Items><t:Task", StringComparison.Ordinal));
        var nativeRequests = exchange.Calls.Count(call => call.Operation == "CreateItem"
            && call.Body.Contains("IPM.TaskRequest", StringComparison.Ordinal));
        Expect(copyCreates == 2 && nativeRequests == 1 && exchange.UpdateItemCount == 1,
            "Execution created or sent later assignment rows after an uncertain copy creation.");
        var firstCopy = exchange.Calls.First(call => call.Operation == "CreateItem"
            && call.Body.Contains("<m:SavedItemFolderId>", StringComparison.Ordinal)
            && call.Body.Contains("<m:Items><t:Task", StringComparison.Ordinal)).Body;
        Expect(firstCopy.Contains("evidence.bin", StringComparison.Ordinal)
            && firstCopy.Contains("<t:Content>YWJj</t:Content>", StringComparison.Ordinal)
            && firstCopy.Contains("Disposable task", StringComparison.Ordinal),
            "The detached sender copy did not preserve the task body and file attachment content.");
        var updateIds = exchange.Calls.Where(call => call.Operation == "UpdateItem")
            .Select(call => XDocument.Parse(call.Body).Descendants().FirstOrDefault(element => element.Name.LocalName == "ItemId")?.Attribute("Id")?.Value)
            .ToArray();
        Expect(updateIds.All(id => id == "result-1"),
            "Plan execution updated the source task instead of only the detached child copy.");
        var replay = await client.Client.CallToolAsync("task_execute_assignment_plan",
            new Dictionary<string, object?> { ["planHandle"] = secondPlanHandle });
        Expect(replay.IsError == true && copyCreates == exchange.Calls.Count(call => call.Operation == "CreateItem"
            && call.Body.Contains("<m:SavedItemFolderId>", StringComparison.Ordinal)),
            "A consumed task assignment plan was replayed.");

        await TaskAssignmentPlanBindingChecksAsync();
    }

    private async Task TaskPlanRecurrenceChecksAsync()
    {
        var weekly = TaskRecurrence("weekly", new DateTimeOffset(2026, 1, 4, 9, 0, 0, TimeSpan.Zero),
            interval: 2, days: ["Monday", "Wednesday"], firstDay: "Monday");
        var mondayFirst = ExpandTaskPlanDates(weekly, new DateOnly(2026, 1, 22));
        Expect(mondayFirst.SequenceEqual([new DateOnly(2026, 1, 12), new DateOnly(2026, 1, 14)]),
            "Weekly assignment expansion ignored FirstDayOfWeek at an alternating-week boundary.");

        var monthly = TaskRecurrence("monthly", new DateTimeOffset(2026, 1, 31, 9, 0, 0, TimeSpan.Zero), dayOfMonth: 31);
        Expect(ExpandTaskPlanDates(monthly, new DateOnly(2026, 4, 30))
                .SequenceEqual([new DateOnly(2026, 1, 31), new DateOnly(2026, 2, 28), new DateOnly(2026, 3, 31), new DateOnly(2026, 4, 30)]),
            "Monthly day-31 recurrence did not clamp to short months as Exchange does.");

        var relative = TaskRecurrence("relativeMonthly", new DateTimeOffset(2026, 1, 1, 9, 0, 0, TimeSpan.Zero),
            days: ["Weekday"], dayOfWeekIndex: "Last");
        Expect(ExpandTaskPlanDates(relative, new DateOnly(2026, 3, 31))
                .SequenceEqual([new DateOnly(2026, 1, 30), new DateOnly(2026, 2, 27), new DateOnly(2026, 3, 31)]),
            "Relative monthly recurrence did not calculate each month's last weekday.");

        var leap = TaskRecurrence("yearly", new DateTimeOffset(2024, 1, 1, 9, 0, 0, TimeSpan.Zero), dayOfMonth: 29, month: 2);
        Expect(ExpandTaskPlanDates(leap, new DateOnly(2028, 12, 31))
                .SequenceEqual([new DateOnly(2024, 2, 29), new DateOnly(2025, 2, 28), new DateOnly(2026, 2, 28),
                    new DateOnly(2027, 2, 28), new DateOnly(2028, 2, 29)]),
            "Yearly February 29 recurrence did not clamp in non-leap years as Exchange does.");

        var horizon = TaskRecurrence("yearly", new DateTimeOffset(2020, 1, 1, 9, 0, 0, TimeSpan.Zero),
            dayOfMonth: 1, month: 1, range: "Numbered", numberOfOccurrences: 32);
        Expect(ExpandTaskPlanDates(horizon, new DateOnly(2052, 1, 1)).Count == 32,
            "A recurrence with 32 occurrences within the 32-calendar-year horizon was rejected.");
        ExpectPlanThrows<ArgumentException>(() => ExpandTaskPlanDates(horizon, new DateOnly(2052, 1, 2)),
            "A recurrence horizon beyond 32 calendar years was accepted.");

        var numbered = TaskRecurrence("daily", new DateTimeOffset(2026, 1, 1, 9, 0, 0, TimeSpan.Zero),
            range: "Numbered", numberOfOccurrences: 3);
        Expect(ExpandTaskPlanDates(numbered, new DateOnly(2026, 1, 10))
                .SequenceEqual([new DateOnly(2026, 1, 1), new DateOnly(2026, 1, 2), new DateOnly(2026, 1, 3)]),
            "Numbered recurrence exceeded its native occurrence limit.");
        var regeneration = TaskRecurrence("dailyRegeneration", new DateTimeOffset(2026, 1, 1, 9, 0, 0, TimeSpan.Zero));
        ExpectPlanThrows<InvalidOperationException>(() => ExpandTaskPlanDates(regeneration, new DateOnly(2026, 1, 10)),
            "Completion-based regeneration was treated as a fixed-date recurrence.");

        var handler = new TaskAssignmentRecordingHandler { UnassignedTask = true };
        var create = new EwsTaskInput("Weekly", Recurrence: new EwsTaskRecurrence("weekly", 2,
            ["Monday"], StartDateUtc: new DateTimeOffset(2026, 1, 4, 0, 0, 0, TimeSpan.Zero),
            FirstDayOfWeek: "Monday"));
        _ = await NewEwsClient(handler).CreateTaskAsync("alice@example.test", "tasks", create, CancellationToken.None);
        var createBody = handler.Calls.Single(call => call.Operation == "CreateItem").Body;
        Expect(createBody.Contains("<t:FirstDayOfWeek>Monday</t:FirstDayOfWeek>", StringComparison.Ordinal),
            "Weekly FirstDayOfWeek was not emitted in the native recurrence XML.");

        ValidateTaskRecurrence(new EwsTaskRecurrence("weekly", 99, ["Sunday", "Monday"]));
        ExpectPlanThrows<ArgumentOutOfRangeException>(
            () => ValidateTaskRecurrence(new EwsTaskRecurrence("weekly", 100, ["Monday"])),
            "A weekly recurrence interval above Exchange's limit of 99 was accepted.");
        foreach (var group in new[] { "Day", "Weekday", "WeekendDay" })
            ExpectPlanThrows<ArgumentException>(
                () => ValidateTaskRecurrence(new EwsTaskRecurrence("weekly", 1, [group])),
                $"The {group} recurrence group was accepted by a weekly pattern.");
        foreach (var group in new[] { "Day", "Weekday", "WeekendDay" })
        {
            ValidateTaskRecurrence(new EwsTaskRecurrence("relativeMonthly", 1, [group], DayOfWeekIndex: "Last"));
            ValidateTaskRecurrence(new EwsTaskRecurrence("relativeYearly", 1, [group], Month: 1, DayOfWeekIndex: "Last"));
        }

        var largeContent = new byte[350_000];
        var largeAttachment = new EwsAttachment("attachment-1", "large.bin", largeContent.Length,
            false, "application/octet-stream");
        var oversized = new EwsTask("task-1", "change-1", "Large task", new string('x', 80_000), "Text",
            null, null, null, 0, "NotStarted", 1, false, null, [], null, false, false, null,
            true, [largeAttachment], [new EwsAttachmentContent("attachment-1", "large.bin",
                "application/octet-stream", largeContent)]);
        ExpectPlanThrows<InvalidOperationException>(() => PreflightTaskPlanCopy(oversized),
            "An oversized detached-copy packet passed preflight.");
    }

    private static IReadOnlyList<DateOnly> ExpandTaskPlanDates(EwsTask task, DateOnly throughDate, int maximumOccurrences = 32)
    {
        var method = typeof(EwsClient).GetMethod("ExpandTaskAssignmentPlanOccurrences",
            BindingFlags.NonPublic | BindingFlags.Static) ?? throw new InvalidOperationException("Plan recurrence helper was not found.");
        try { return (IReadOnlyList<DateOnly>)method.Invoke(null, [task, throughDate, maximumOccurrences])!; }
        catch (TargetInvocationException exception) when (exception.InnerException is not null)
        {
            System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(exception.InnerException).Throw();
            throw;
        }
    }

    private static void PreflightTaskPlanCopy(EwsTask task)
    {
        var method = typeof(EwsClient).GetMethod("PreflightTaskAssignmentPlanCopy",
            BindingFlags.NonPublic | BindingFlags.Static) ?? throw new InvalidOperationException("Plan copy preflight helper was not found.");
        try
        {
            method.Invoke(null, [task, null, null, null, Convert.ToBase64String(new byte[16])]);
        }
        catch (TargetInvocationException exception) when (exception.InnerException is not null)
        {
            System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(exception.InnerException).Throw();
            throw;
        }
    }

    private static void ValidateTaskRecurrence(EwsTaskRecurrence recurrence)
    {
        var method = typeof(EwsClient).GetMethod("ValidateRecurrence",
            BindingFlags.NonPublic | BindingFlags.Static) ?? throw new InvalidOperationException("Task recurrence validator was not found.");
        try { method.Invoke(null, [recurrence]); }
        catch (TargetInvocationException exception) when (exception.InnerException is not null)
        {
            System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(exception.InnerException).Throw();
            throw;
        }
    }

    private async Task TaskAssignmentPlanBindingChecksAsync()
    {
        const string session = "task-plan-binding-a";
        var exchange = new AssignmentPlanRecordingHandler { UnassignedTask = true };
        await using var host = await StartHostAsync(exchange, writesEnabled: true, sendEnabled: true,
            classicStateful: true);
        var acceptedForm = new NativeFormResponder(accept: true);
        await using var owner = await CreateNativeClientAsync(host,
            Token("user-a", "mail.read mail.write mail.send", sessionId: session), acceptedForm);
        var identity = new MailboxIdentity("user-a", "alice@example.test", "chatgpt-test", session);
        var taskHandle = host.App.Services.GetRequiredService<MailboxHandles>()
            .Issue(identity, "task", "task-1", exchange.TaskChangeKey);
        var planResult = await owner.Client.CallToolAsync("task_plan_assignments", new Dictionary<string, object?>
        {
            ["taskHandle"] = taskHandle,
            ["assignees"] = new[] { "bob@example.test" },
            ["throughDate"] = "2026-01-12"
        });
        Expect(planResult.IsError != true, "A valid assignment plan could not be created for the binding checks.");
        var planHandle = NativeData(planResult).GetProperty("planHandle").GetString()!;
        var arguments = new Dictionary<string, object?> { ["planHandle"] = planHandle };

        await using var otherUser = await CreateNativeClientAsync(host,
            Token("user-b", "mail.read mail.write mail.send", sessionId: "task-plan-binding-b"),
            new NativeFormResponder(accept: true));
        var crossUser = await otherUser.Client.CallToolAsync("task_execute_assignment_plan", arguments);
        Expect(crossUser.IsError == true && acceptedForm.Calls == 0
            && exchange.CreateItemCount == 0 && exchange.UpdateItemCount == 0,
            "A different mailbox read or consumed the owner’s assignment plan.");

        await using var otherSession = await CreateNativeClientAsync(host,
            Token("user-a", "mail.read mail.write mail.send", sessionId: "task-plan-binding-other"),
            new NativeFormResponder(accept: true));
        var crossSession = await otherSession.Client.CallToolAsync("task_execute_assignment_plan", arguments);
        Expect(crossSession.IsError == true && acceptedForm.Calls == 0
            && exchange.CreateItemCount == 0 && exchange.UpdateItemCount == 0,
            "A different authentication session read or consumed the owner’s assignment plan.");

        var ownerExecution = await owner.Client.CallToolAsync("task_execute_assignment_plan", arguments);
        Expect(ownerExecution.IsError != true && NativeData(ownerExecution).GetProperty("status").GetString() == "completed"
            && acceptedForm.Calls == 1 && exchange.CreateItemCount == 2 && exchange.UpdateItemCount == 1,
            "Cross-user or cross-session attempts consumed the valid plan before its owner executed it.");
    }

    private static EwsTask TaskRecurrence(string pattern, DateTimeOffset start, int interval = 1,
        IReadOnlyList<string>? days = null, int? dayOfMonth = null, int? month = null,
        string range = "NoEnd", int? numberOfOccurrences = null, string? dayOfWeekIndex = null,
        string? firstDay = null)
    {
        var recurrence = new EwsTaskRecurrence(pattern, interval, days, dayOfMonth, month, start, range,
            NumberOfOccurrences: numberOfOccurrences, DayOfWeekIndex: dayOfWeekIndex, FirstDayOfWeek: firstDay);
        return new EwsTask("task-1", "change-1", "Verify assignment", "Plan body", "Text", start, null,
            null, 0, "NotStarted", 1, false, null, [], recurrence, false, true);
    }

    private static void ExpectPlanThrows<TException>(Action action, string message) where TException : Exception
    {
        try { action(); }
        catch (TException) { return; }
        throw new InvalidOperationException(message);
    }

    private sealed class AssignmentPlanRecordingHandler : TaskAssignmentRecordingHandler
    {
        private static readonly XNamespace Soap = "http://schemas.xmlsoap.org/soap/envelope/";
        private static readonly XNamespace M = "http://schemas.microsoft.com/exchange/services/2006/messages";
        private static readonly XNamespace T = "http://schemas.microsoft.com/exchange/services/2006/types";
        private const string FixtureGlobalId = "AAECAwQFBgcICQoLDA0ODw==";
        private const string Recurrence = "<t:Recurrence><t:WeeklyRecurrence><t:Interval>2</t:Interval><t:DaysOfWeek>Monday Wednesday</t:DaysOfWeek><t:FirstDayOfWeek>Monday</t:FirstDayOfWeek></t:WeeklyRecurrence><t:NoEndRecurrence><t:StartDate>2026-01-04</t:StartDate></t:NoEndRecurrence></t:Recurrence>";
        private int copyCount;
        private string? currentGlobalId;

        public int FailOnCopyNumber { get; set; }
        public bool IncludeTaskReminder { get; set; }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var body = await request.Content!.ReadAsStringAsync(cancellationToken);
            var document = XDocument.Parse(body);
            var operation = document.Root!.Element(Soap + "Body")!.Elements().Single();
            if (operation.Name == M + "CreateItem" && operation.Element(M + "SavedItemFolderId") is not null
                && operation.Element(M + "Items")?.Elements(T + "Task").Any() == true)
            {
                copyCount++;
                currentGlobalId = operation.Descendants(T + "ExtendedProperty")
                    .Where(property => property.Element(T + "ExtendedFieldURI")?.Attribute("PropertyId")?.Value == "0x8519")
                    .Select(property => property.Element(T + "Value")?.Value).FirstOrDefault(value => value is not null);
                if (copyCount == FailOnCopyNumber) EmptyItemsOnCreate = true;
            }
            var requestedId = operation.Descendants(T + "ItemId").Select(item => item.Attribute("Id")?.Value).FirstOrDefault();
            var response = await base.SendAsync(request, cancellationToken);
            var responseBody = await response.Content!.ReadAsStringAsync(cancellationToken);
            if (operation.Name == M + "GetItem" && requestedId == "task-1")
                responseBody = responseBody.Replace("<t:IsRecurring>false</t:IsRecurring>",
                    $"<t:IsRecurring>true</t:IsRecurring>{Recurrence}", StringComparison.Ordinal);
            if (IncludeTaskReminder)
                responseBody = responseBody.Replace("<t:ReminderIsSet>false</t:ReminderIsSet>",
                    "<t:ReminderIsSet>true</t:ReminderIsSet><t:ReminderDueBy>2026-01-04T08:45:00Z</t:ReminderDueBy>",
                    StringComparison.Ordinal);
            else if (operation.Name == M + "GetItem" && currentGlobalId is not null)
                responseBody = responseBody.Replace(FixtureGlobalId, currentGlobalId, StringComparison.Ordinal);
            if (operation.Name == M + "GetItem" && requestedId is not null && requestedId != "task-1")
                responseBody = responseBody.Replace("Id='task-1' ChangeKey='",
                    $"Id='{requestedId}' ChangeKey='", StringComparison.Ordinal);
            response.Content.Dispose();
            response.Content = new StringContent(responseBody, Encoding.UTF8, "text/xml");
            return response;
        }
    }
}
