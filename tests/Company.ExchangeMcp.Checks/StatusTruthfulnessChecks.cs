using System.Text.Json;
using Company.ExchangeMcp.Exchange;
using Company.ExchangeMcp.Security;
using Microsoft.Extensions.DependencyInjection;

internal sealed partial class Checks
{
    private async Task StatusTruthfulnessChecksAsync()
    {
        var calendarExchange = new CalendarCompletenessRecordingHandler();
        await using (var host = await StartHostAsync(calendarExchange, writesEnabled: false,
            sendEnabled: false, classicStateful: true))
        {
            await using var native = await CreateNativeClientAsync(host,
                Token("user-a", "mail.read", sessionId: "calendar-status"), new NativeFormResponder(accept: false));
            var listed = await native.Client.CallToolAsync("calendar_list_events", new Dictionary<string, object?>
            {
                ["start"] = "2026-10-10T00:00:00Z",
                ["end"] = "2026-10-11T00:00:00Z"
            });
            Expect(listed.IsError != true, "Calendar status fixture could not list events.");
            var summary = NativeData(listed).GetProperty("items")[0];
            Expect(!summary.GetProperty("detailsComplete").GetBoolean()
                && summary.GetProperty("detailTool").GetString() == "calendar_read_event"
                && Unloaded(summary, "body")
                && Unloaded(summary, "requiredAttendees")
                && Unloaded(summary, "optionalAttendees")
                && Unloaded(summary, "resources")
                && Unloaded(summary, "attachmentNames"),
                "FindItem summary invented empty body, attendee or attachment details.");
            var read = await native.Client.CallToolAsync("calendar_read_event", new Dictionary<string, object?>
            {
                ["eventHandle"] = summary.GetProperty("handle").GetString()
            });
            Expect(read.IsError != true, "Calendar status fixture could not read the listed event.");
            var full = NativeData(read);
            Expect(full.GetProperty("detailsComplete").GetBoolean()
                && full.GetProperty("body").ValueKind == JsonValueKind.String
                && full.GetProperty("requiredAttendees").ValueKind == JsonValueKind.Array,
                "GetItem details were labelled as unloaded or replaced by summary values.");
            var searched = await native.Client.CallToolAsync("calendar_search", new Dictionary<string, object?>
            { ["query"] = "planning" });
            Expect(searched.IsError != true
                && !NativeData(searched).GetProperty("items")[0].GetProperty("detailsComplete").GetBoolean(),
                "Calendar search falsely advertised complete GetItem details.");
        }

        var taskExchange = new TaskAssignmentRecordingHandler { AcceptanceWireOverride = TaskAcceptanceWire("1") };
        await using (var host = await StartHostAsync(taskExchange, writesEnabled: false,
            sendEnabled: false, classicStateful: true))
        {
            var identity = new MailboxIdentity("user-a", "alice@example.test", "chatgpt-test", "task-status");
            var handle = host.App.Services.GetRequiredService<MailboxHandles>()
                .Issue(identity, "task", "task-1", taskExchange.TaskChangeKey);
            await using var native = await CreateNativeClientAsync(host,
                Token("user-a", "mail.read", sessionId: "task-status"), new NativeFormResponder(accept: false));
            var result = await native.Client.CallToolAsync("task_assignment_status", new Dictionary<string, object?>
            { ["taskHandle"] = handle });
            Expect(result.IsError != true, "Task status fixture could not read its assignment.");
            var status = NativeData(result);
            Expect(Unloaded(status, "isProcessed")
                && status.GetProperty("processingStatus").GetString() == "not_applicable_to_task_item"
                && status.GetProperty("acceptanceStatus").GetString() == "unknown"
                && status.GetProperty("percentComplete").GetInt32() == 25,
                "Task progress or unsupported processing flag was confused with assignment acceptance.");
        }

        Expect(EwsTaskAssignmentInfo.DescribeAcceptance(2, 2, 0, true) == "accepted"
            && EwsTaskAssignmentInfo.DescribeAcceptance(3, 1, 1, true) == "unknown"
            && EwsTaskAssignmentInfo.DescribeAcceptance(4, 2, 3, true) == "declined"
            && EwsTaskAssignmentInfo.DescribeAcceptance(1, 0, 0, null) == "not_assigned"
            && EwsTaskAssignmentInfo.DescribeAcceptance(null, null, null, null) == "unknown",
            "Readable acceptance status lost the verified Outlook acceptance tuple or invented a response.");

        static bool Unloaded(JsonElement item, string name) =>
            !item.TryGetProperty(name, out var value) || value.ValueKind == JsonValueKind.Null;
    }
}
