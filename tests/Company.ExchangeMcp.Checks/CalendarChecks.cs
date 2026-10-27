using System.Net;
using System.Text;
using System.Xml.Schema;
using System.Xml.Linq;
using Company.ExchangeMcp;
using Company.ExchangeMcp.Exchange;
using Company.ExchangeMcp.Security;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using ModelContextProtocol.AspNetCore;

internal sealed partial class Checks
{
    // Called by the runner when calendar tools are registered. It stays transport-free so it can run
    // against the Exchange 2019 wire fixture before a live mailbox qualification is authorized.
    private async Task CalendarChecksAsync()
    {
        var handler = new CalendarRecordingHandler();
        var client = NewEwsClient(handler);
        var folders = await client.ListCalendarFoldersAsync("alice@example.test", CancellationToken.None);
        Expect(folders.Count == 1 && folders[0].FolderClass == "IPF.Appointment"
            && folders[0].IsDefault && folders[0].Id == "real-calendar-id",
            "Calendar folder discovery did not resolve the distinguished default folder to its real Exchange id.");

        var page = await client.FindCalendarEventsAsync("alice@example.test", "calendar",
            new DateTimeOffset(2026, 10, 10, 0, 0, 0, TimeSpan.Zero),
            new DateTimeOffset(2026, 10, 11, 0, 0, 0, TimeSpan.Zero), 50, CancellationToken.None);
        Expect(page.Items.Count == 1 && page.Items[0].IsMeeting && page.Items[0].RequiredAttendees.Count == 1,
            "CalendarView did not parse the expanded event and attendees.");
        var view = XDocument.Parse(handler.LastBody).Root!.Element(XName.Get("Body", CalendarRecordingHandler.Soap))!.Elements().Single();
        Expect(view.Elements().Select(x => x.Name.LocalName).SequenceEqual(["ItemShape", "CalendarView", "ParentFolderIds"]),
            "CalendarView request element order was not Exchange-safe.");

        handler.ReturnTruncatedCalendarView = true;
        await AssertThrowsAsync<InvalidOperationException>(() => client.FindCalendarEventsAsync("alice@example.test", "calendar",
            new DateTimeOffset(2026, 10, 10, 0, 0, 0, TimeSpan.Zero),
            new DateTimeOffset(2026, 10, 11, 0, 0, 0, TimeSpan.Zero), 50, CancellationToken.None));
        handler.ReturnTruncatedCalendarView = false;

        foreach (var (wire, expectedPattern) in new[]
        {
            ("<t:DailyRecurrence><t:Interval>2</t:Interval></t:DailyRecurrence>", "daily"),
            ("<t:WeeklyRecurrence><t:Interval>1</t:Interval><t:DaysOfWeek>Monday Wednesday</t:DaysOfWeek><t:FirstDayOfWeek>Monday</t:FirstDayOfWeek></t:WeeklyRecurrence>", "weekly"),
            ("<t:RelativeMonthlyRecurrence><t:Interval>1</t:Interval><t:DaysOfWeek>Monday</t:DaysOfWeek><t:DayOfWeekIndex>Last</t:DayOfWeekIndex></t:RelativeMonthlyRecurrence>", "monthly"),
            ("<t:RelativeYearlyRecurrence><t:DaysOfWeek>Friday</t:DaysOfWeek><t:DayOfWeekIndex>First</t:DayOfWeekIndex><t:Month>October</t:Month></t:RelativeYearlyRecurrence>", "yearly")
        })
        {
            handler.RecurrenceWire = wire;
            var parsed = await client.GetCalendarEventAsync("alice@example.test", "event-1", CancellationToken.None);
            Expect(parsed.Recurrence?.Pattern == expectedPattern,
                $"Exchange {expectedPattern} recurrence was not normalized by the public calendar model.");
        }
        handler.RecurrenceWire = "<t:RelativeMonthlyRecurrence><t:Interval>1</t:Interval><t:DaysOfWeek>Monday Tuesday</t:DaysOfWeek><t:DayOfWeekIndex>First</t:DayOfWeekIndex></t:RelativeMonthlyRecurrence>";
        await AssertThrowsAsync<InvalidOperationException>(() => client.GetCalendarEventAsync("alice@example.test", "event-1", CancellationToken.None));
        handler.RecurrenceWire = "<t:RelativeYearlyRecurrence><t:DaysOfWeek>Friday</t:DaysOfWeek><t:DayOfWeekIndex>First</t:DayOfWeekIndex><t:Month>Smarch</t:Month></t:RelativeYearlyRecurrence>";
        await AssertThrowsAsync<InvalidOperationException>(() => client.GetCalendarEventAsync("alice@example.test", "event-1", CancellationToken.None));
        handler.RecurrenceWire = null;

        var input = new EwsCalendarEventInput("Recurring test", "<b>Body</b>", "HTML",
            new DateTimeOffset(2026, 10, 10, 9, 0, 0, TimeSpan.FromHours(3.5)),
            new DateTimeOffset(2026, 10, 10, 10, 0, 0, TimeSpan.FromHours(3.5)),
            "Iran Standard Time", false, "Room 1", ["to@example.test"], ["cc@example.test"], ["room@example.test"],
            new EwsCalendarRecurrence("weekly", 1, ["Saturday"], "Saturday", NoEnd: true), 15, ["work"], "Normal", "Busy");
        await client.CreateCalendarEventAsync("alice@example.test", "calendar", input, true, CancellationToken.None);
        var create = XDocument.Parse(handler.LastBody).Root!.Element(XName.Get("Body", CalendarRecordingHandler.Soap))!.Elements().Single();
        Expect((string?)create.Attribute("SendMeetingInvitations") == "SendToAllAndSaveCopy"
            && create.Descendants(XName.Get("WeeklyRecurrence", CalendarRecordingHandler.Types)).Any()
            && create.Descendants(XName.Get("RequiredAttendees", CalendarRecordingHandler.Types)).Any(),
            "Calendar meeting creation omitted recurrence, attendees or invitation transmission intent.");
        await AssertThrowsAsync<ArgumentException>(() => client.CreateCalendarEventAsync("alice@example.test", "calendar",
            input with { Recurrence = new EwsCalendarRecurrence("yearly", 2, NoEnd: true) }, false, CancellationToken.None));
        await AssertThrowsAsync<ArgumentException>(() => client.CreateCalendarEventAsync("alice@example.test", "calendar",
            input with
            {
                Recurrence = new EwsCalendarRecurrence("monthly", 1, ["Monday", "Tuesday"],
                    DayOfWeekIndex: "First", NoEnd: true)
            }, false, CancellationToken.None));
        await AssertThrowsAsync<ArgumentException>(() => client.CreateCalendarEventAsync("alice@example.test", "calendar",
            input with
            {
                Recurrence = new EwsCalendarRecurrence("yearly", 1, ["Monday"],
                    Month: "Smarch", DayOfWeekIndex: "First", NoEnd: true)
            }, false, CancellationToken.None));
        await AssertThrowsAsync<ArgumentException>(() => client.CreateCalendarEventAsync("alice@example.test", "calendar",
            input with
            {
                Recurrence = new EwsCalendarRecurrence("weekly", 1, ["saturday"],
                    FirstDayOfWeek: "Saturday", NoEnd: true)
            }, false, CancellationToken.None));
        await AssertThrowsAsync<ArgumentException>(() => client.CreateCalendarEventAsync("alice@example.test", "calendar",
            input with
            {
                Recurrence = new EwsCalendarRecurrence("yearly", 1, ["Saturday"],
                    Month: "october", DayOfWeekIndex: "First", NoEnd: true)
            }, false, CancellationToken.None));
        var daylightSavingAllDay = input with
        {
            Body = "All-day body",
            Recurrence = null,
            IsAllDay = true,
            Start = new DateTimeOffset(2026, 3, 8, 0, 0, 0, TimeSpan.FromHours(-8)),
            End = new DateTimeOffset(2026, 3, 9, 0, 0, 0, TimeSpan.FromHours(-7)),
            TimeZone = "Pacific Standard Time"
        };
        await client.CreateCalendarEventAsync("alice@example.test", "calendar", daylightSavingAllDay, false, CancellationToken.None);
        var allDayCreate = XDocument.Parse(handler.LastBody).Root!.Element(XName.Get("Body", CalendarRecordingHandler.Soap))!.Elements().Single();
        Expect(allDayCreate.Descendants(XName.Get("IsAllDayEvent", CalendarRecordingHandler.Types)).Any(x => x.Value == "true"),
            "An all-day event crossing a daylight-saving offset change was rejected or not marked all-day.");

        await client.UpdateCalendarEventAsync("alice@example.test", "event-1", "event-change", input, false, CancellationToken.None);
        var update = XDocument.Parse(handler.LastBody).Root!.Element(XName.Get("Body", CalendarRecordingHandler.Soap))!.Elements().Single();
        Expect((string?)update.Attribute("ConflictResolution") == "NeverOverwrite"
            && (string?)update.Attribute("SendMeetingInvitationsOrCancellations") == "SendToNone",
            "Calendar update did not use stale-change-key protection or explicit no-send behavior.");
        var ordinaryUpdate = input with { Recurrence = null };
        await client.UpdateCalendarEventAsync("alice@example.test", "event-1", "event-change", ordinaryUpdate, false, CancellationToken.None);
        var ordinaryWire = XDocument.Parse(handler.LastBody).Root!.Element(XName.Get("Body", CalendarRecordingHandler.Soap))!.Elements().Single();
        Expect(!ordinaryWire.Descendants(XName.Get("DeleteItemField", CalendarRecordingHandler.Types)).Any(),
            "An ordinary calendar update cleared recurrence without explicit clearRecurrence intent.");
        await client.UpdateCalendarEventAsync("alice@example.test", "event-1", "event-change", ordinaryUpdate with { ClearRecurrence = true }, false, CancellationToken.None);
        var clearWire = XDocument.Parse(handler.LastBody).Root!.Element(XName.Get("Body", CalendarRecordingHandler.Soap))!.Elements().Single();
        Expect(clearWire.Descendants(XName.Get("DeleteItemField", CalendarRecordingHandler.Types)).Any(),
            "An explicit recurrence clear did not delete the recurrence field.");
        var clearAttendees = input with
        {
            RequiredAttendees = [],
            OptionalAttendees = [],
            Resources = []
        };
        await client.UpdateCalendarEventAsync("alice@example.test", "event-1", "event-change", clearAttendees, false, CancellationToken.None);
        var clearAttendeeWire = XDocument.Parse(handler.LastBody).Root!.Element(XName.Get("Body", CalendarRecordingHandler.Soap))!.Elements().Single();
        var clearedAttendeeUris = clearAttendeeWire.Descendants(XName.Get("DeleteItemField", CalendarRecordingHandler.Types))
            .Select(x => (string?)x.Element(XName.Get("FieldURI", CalendarRecordingHandler.Types))?.Attribute("FieldURI"))
            .ToHashSet(StringComparer.Ordinal);
        Expect(clearedAttendeeUris.SetEquals(["calendar:RequiredAttendees", "calendar:OptionalAttendees", "calendar:Resources"])
            && !clearAttendeeWire.Descendants(XName.Get("RequiredAttendees", CalendarRecordingHandler.Types)).Any()
            && !clearAttendeeWire.Descendants(XName.Get("OptionalAttendees", CalendarRecordingHandler.Types)).Any()
            && !clearAttendeeWire.Descendants(XName.Get("Resources", CalendarRecordingHandler.Types)).Any(),
            "An empty attendee update emitted schema-invalid empty attendee containers instead of clearing the fields.");
        await client.DeleteCalendarEventAsync("alice@example.test", "event-1", "event-change", false, CancellationToken.None);
        var delete = XDocument.Parse(handler.LastBody).Root!.Element(XName.Get("Body", CalendarRecordingHandler.Soap))!.Elements().Single();
        Expect((string?)delete.Attribute("DeleteType") == "MoveToDeletedItems"
            && (string?)delete.Attribute("SendMeetingCancellations") == "SendToNone",
            "Calendar deletion was not recoverable or did not make cancellation intent explicit.");

        var freeBusy = await client.GetFreeBusyAsync("alice@example.test", ["to@example.test"],
            new DateTimeOffset(2026, 10, 10, 0, 0, 0, TimeSpan.Zero),
            new DateTimeOffset(2026, 10, 11, 0, 0, 0, TimeSpan.Zero), 30, CancellationToken.None);
        Expect(freeBusy.Count == 1 && freeBusy[0].Events.Count == 1 && freeBusy[0].Events[0].BusyType == "Busy",
            "GetUserAvailability did not parse the free/busy response.");
        handler.OmitAvailabilityStatus = true;
        await AssertThrowsAsync<InvalidOperationException>(() => client.GetFreeBusyAsync("alice@example.test", ["to@example.test"],
            new DateTimeOffset(2026, 10, 10, 0, 0, 0, TimeSpan.Zero),
            new DateTimeOffset(2026, 10, 11, 0, 0, 0, TimeSpan.Zero), 30, CancellationToken.None));
        handler.OmitAvailabilityStatus = false;
        handler.OmitAvailabilityViewType = true;
        await AssertThrowsAsync<InvalidOperationException>(() => client.GetFreeBusyAsync("alice@example.test", ["to@example.test"],
            new DateTimeOffset(2026, 10, 10, 0, 0, 0, TimeSpan.Zero),
            new DateTimeOffset(2026, 10, 11, 0, 0, 0, TimeSpan.Zero), 30, CancellationToken.None));
        handler.OmitAvailabilityViewType = false;
        handler.OmitAvailabilityEventStart = true;
        await AssertThrowsAsync<InvalidOperationException>(() => client.GetFreeBusyAsync("alice@example.test", ["to@example.test"],
            new DateTimeOffset(2026, 10, 10, 0, 0, 0, TimeSpan.Zero),
            new DateTimeOffset(2026, 10, 11, 0, 0, 0, TimeSpan.Zero), 30, CancellationToken.None));
        handler.OmitAvailabilityEventStart = false;
        handler.InvalidAvailabilityViewType = true;
        await AssertThrowsAsync<InvalidOperationException>(() => client.GetFreeBusyAsync("alice@example.test", ["to@example.test"],
            new DateTimeOffset(2026, 10, 10, 0, 0, 0, TimeSpan.Zero),
            new DateTimeOffset(2026, 10, 11, 0, 0, 0, TimeSpan.Zero), 30, CancellationToken.None));
        handler.InvalidAvailabilityViewType = false;
        handler.InvalidAvailabilityBusyType = true;
        await AssertThrowsAsync<InvalidOperationException>(() => client.GetFreeBusyAsync("alice@example.test", ["to@example.test"],
            new DateTimeOffset(2026, 10, 10, 0, 0, 0, TimeSpan.Zero),
            new DateTimeOffset(2026, 10, 11, 0, 0, 0, TimeSpan.Zero), 30, CancellationToken.None));
        handler.InvalidAvailabilityBusyType = false;
        ValidateCalendarSchema(handler);
    }

    // The wire checks above deliberately use a small EWS fixture. This second gate exercises
    // the real MCP approval path, including native classic elicitation and July MRTR state.
    // The runner invokes this after CalendarChecksAsync once CalendarTools is registered.
    private async Task CalendarPolicyChecksAsync()
    {
        await AssertCalendarNoSendScopeAsync();
        await AssertCalendarApprovalCancellationAsync();
        await AssertCalendarApprovalBindingAsync();
        await AssertCalendarChangedItemAsync(changeKeyChanged: true);
        await AssertCalendarChangedItemAsync(changeKeyChanged: false);
        await AssertCalendarUncertainWriteReplayAsync();
        await AssertCalendarOccurrenceAndSeriesGuardsAsync();
        await AssertCalendarResponsePreviewAsync();
        await AssertCalendarResponseOrganizerPolicyAsync();
        await AssertCalendarUpdatePreservesOmittedFieldsAsync();
    }

    private static void ValidateCalendarSchema(CalendarRecordingHandler handler)
    {
        var schemas = LoadOptionalExchangeSchemas();
        Expect(handler.Bodies.Count > 0, "Calendar fixture did not capture an EWS operation for schema validation.");
        foreach (var bodyText in handler.Bodies)
        {
            var document = XDocument.Parse(bodyText, LoadOptions.PreserveWhitespace);
            var operation = document.Root?.Element(XName.Get("Body", CalendarRecordingHandler.Soap))?.Elements().Single()
                ?? throw new InvalidOperationException("Calendar SOAP operation was not captured.");
            if (schemas is not null)
                new XDocument(new XElement(operation)).Validate(schemas, (_, error) => throw new InvalidOperationException(
                    $"Exchange 2019 schema rejected calendar operation: {error.Message}"));
        }
    }

    private async Task AssertCalendarNoSendScopeAsync()
    {
        var exchange = new CalendarPolicyRecordingHandler();
        await using var host = await StartCalendarHostAsync(exchange, writesEnabled: true, sendEnabled: true,
            classicStateful: true);
        var form = new NativeFormResponder(accept: true);
        await using var client = await CreateNativeClientAsync(host,
            Token("user-a", "mail.read mail.write", sessionId: "calendar-no-send"), form);

        var result = await client.Client.CallToolAsync("calendar_create_event", CalendarCreateArguments(sendInvitations: true));
        Expect(result.IsError == true && exchange.CalendarWriteCount == 0 && form.Calls == 0,
            "A calendar invitation without mail.send reached Exchange or opened approval.");
    }

    private async Task AssertCalendarApprovalCancellationAsync()
    {
        var exchange = new CalendarPolicyRecordingHandler();
        await using var host = await StartCalendarHostAsync(exchange, writesEnabled: true, sendEnabled: true,
            classicStateful: true);
        var form = new NativeFormResponder(accept: false);
        await using var client = await CreateNativeClientAsync(host,
            Token("user-a", "mail.read mail.write mail.manage mail.send", sessionId: "calendar-cancel"), form);

        var result = await client.Client.CallToolAsync("calendar_create_event", CalendarCreateArguments(
            sendInvitations: true, body: "<p>Agenda &amp; decisions</p>", bodyType: "HTML"));
        Expect(result.IsError != true && NativeData(result).GetProperty("status").GetString() == "cancelled"
            && form.Calls == 1 && exchange.CalendarWriteCount == 0
            && form.LastRequest?.Message.Contains("Body type: HTML", StringComparison.Ordinal) == true
            && form.LastRequest.Message.Contains("Exact HTML (escaped):", StringComparison.Ordinal)
            && form.LastRequest.Message.Contains("&lt;p&gt;Agenda &amp;amp; decisions&lt;/p&gt;", StringComparison.Ordinal)
            && form.LastRequest.Message.Contains("Time zone: Iran Standard Time", StringComparison.Ordinal)
            && form.LastRequest.Message.Contains("All day: False", StringComparison.Ordinal)
            && form.LastRequest.Message.Contains("Resources: (none)", StringComparison.Ordinal),
            "A declined calendar invitation was not cancelled before EWS.");
    }

    private async Task AssertCalendarApprovalBindingAsync()
    {
        var exchange = new CalendarPolicyRecordingHandler();
        await using var host = await StartCalendarHostAsync(exchange, writesEnabled: true, sendEnabled: true,
            classicStateful: false);
        var token = Token("user-a", "mail.read mail.write mail.manage mail.send", sessionId: "calendar-bind");
        await InitializeAsync(host.Client, token, elicitation: true);
        var handle = await CalendarEventHandleAsync(host.Client, token);
        var updateArgs = CalendarUpdateArguments(handle, sendUpdates: true);
        var approval = await ToolRequestAsync(host.Client, token, "tools/call", new
        {
            name = "calendar_update_event",
            arguments = updateArgs
        }, JulyProtocolVersion, elicitation: true);
        var state = InputRequiredState(approval.Body);

        var alternate = Token("user-a", "mail.read mail.write mail.manage mail.send",
            azp: "chatgpt-alt", sessionId: "calendar-bind");
        var before = exchange.CalendarWriteCount;
        var alternateRetry = await CalendarApprovalResumeAsync(host.Client, alternate, state, handle, updateArgs);
        Expect(IsToolError(alternateRetry.Body) && exchange.CalendarWriteCount == before,
            "A calendar approval was reusable by a different OAuth client.");

        var changedSession = Token("user-a", "mail.read mail.write mail.manage mail.send", sessionId: "calendar-other");
        var changedRetry = await CalendarApprovalResumeAsync(host.Client, changedSession, state, handle, updateArgs);
        Expect(IsToolError(changedRetry.Body) && exchange.CalendarWriteCount == before,
            "A calendar approval was reusable from a different OAuth session.");

        var accepted = await CalendarApprovalResumeAsync(host.Client, token, state, handle, updateArgs);
        var acceptedData = !IsToolError(accepted.Body) ? ToolStructuredData(accepted.Body) : default;
        var approvedWire = XDocument.Parse(exchange.LastBody);
        var approvedUris = approvedWire.Descendants(XName.Get("SetItemField", CalendarPolicyRecordingHandler.Types))
            .Select(x => (string?)x.Element(XName.Get("FieldURI", CalendarPolicyRecordingHandler.Types))?.Attribute("FieldURI"))
            .Where(x => x is not null)
            .Select(x => x!)
            .ToHashSet(StringComparer.Ordinal);
        Expect(!IsToolError(accepted.Body)
            && acceptedData.GetProperty("status").GetString() == "event_updated"
            && acceptedData.GetProperty("invitationsSent").GetBoolean()
            && exchange.CalendarWriteCount == before + 1
            && (string?)approvedWire.Root!.Element(XName.Get("Body", CalendarPolicyRecordingHandler.Soap))!
                .Elements().Single().Attribute("SendMeetingInvitationsOrCancellations") == "SendToAllAndSaveCopy"
            && approvedUris.SetEquals(["item:Subject", "item:Body", "calendar:Start", "calendar:End", "calendar:StartTimeZone"]),
            "An accepted calendar approval did not produce one verified meeting update with the expected partial wire fields.");
    }

    private async Task AssertCalendarChangedItemAsync(bool changeKeyChanged)
    {
        var exchange = new CalendarPolicyRecordingHandler();
        await using var host = await StartCalendarHostAsync(exchange, writesEnabled: true, sendEnabled: true,
            classicStateful: true);
        var token = Token("user-a", "mail.read mail.write mail.manage mail.send",
            sessionId: changeKeyChanged ? "calendar-change-key" : "calendar-change-payload");
        var responder = new NativeFormResponder(accept: true)
        {
            BeforeResponse = () =>
            {
                if (changeKeyChanged) exchange.ChangeKey = "changed-after-approval";
                else exchange.Subject = "Changed after approval";
            }
        };
        await using var client = await CreateNativeClientAsync(host, token, responder);
        var handle = await CalendarEventHandleAsync(client.Client);
        var updateArgs = CalendarUpdateArguments(handle, sendUpdates: true);
        var rejected = await NativeRejectedAsync(client.Client, "calendar_update_event", updateArgs);
        Expect(rejected && exchange.CalendarWriteCount == 0,
            changeKeyChanged
                ? "A calendar event with a changed item key was updated after approval."
                : "A calendar event with a changed payload was updated after approval.");
        Expect(responder.LastRequest?.Message.Contains("Body preview:", StringComparison.Ordinal) == true
            && responder.LastRequest.Message.Contains("Time zone: Iran Standard Time", StringComparison.Ordinal)
            && responder.LastRequest.Message.Contains("Resources: room@example.test", StringComparison.Ordinal)
            && responder.LastRequest.Message.Contains("Attachments retained: agenda.pdf", StringComparison.Ordinal),
            "The calendar update confirmation did not show the complete submitted payload.");
    }

    private async Task AssertCalendarUncertainWriteReplayAsync()
    {
        var exchange = new CalendarPolicyRecordingHandler { ThrowNextCalendarWrite = true };
        await using var host = await StartCalendarHostAsync(exchange, writesEnabled: true, sendEnabled: true,
            classicStateful: true);
        var form = new NativeFormResponder(accept: true);
        await using var client = await CreateNativeClientAsync(host,
            Token("user-a", "mail.read mail.write mail.manage mail.send", sessionId: "calendar-uncertain"), form);
        var first = await client.Client.CallToolAsync("calendar_create_event", CalendarCreateArguments(sendInvitations: true));
        Expect(first.IsError == true && exchange.CalendarWriteCount == 1,
            "An uncertain calendar transmission was not surfaced after one EWS attempt.");

        var second = await NativeRejectedAsync(client.Client, "calendar_create_event",
            CalendarCreateArguments(sendInvitations: true));
        Expect(second && exchange.CalendarWriteCount == 1,
            "An uncertain calendar transmission was retried against Exchange.");
    }

    private async Task AssertCalendarOccurrenceAndSeriesGuardsAsync()
    {
        var exchange = new CalendarPolicyRecordingHandler();
        await using var host = await StartCalendarHostAsync(exchange, writesEnabled: true, sendEnabled: false);
        var token = Token("user-a", "mail.read mail.write mail.manage", sessionId: "calendar-scope");
        await InitializeAsync(host.Client, token);
        var handle = await CalendarEventHandleAsync(host.Client, token);
        var before = exchange.CalendarWriteCount;
        var series = await ToolRequestAsync(host.Client, token, "tools/call", new
        {
            name = "calendar_update_event",
            arguments = CalendarUpdateArguments(handle, sendUpdates: false, scope: "series")
        });
        var occurrence = await ToolRequestAsync(host.Client, token, "tools/call", new
        {
            name = "calendar_update_event",
            arguments = CalendarUpdateArguments(handle, sendUpdates: false, scope: "occurrence")
        });
        Expect(IsToolError(series.Body) && IsToolError(occurrence.Body) && exchange.CalendarWriteCount == before,
            "Calendar occurrence/series scope safeguards allowed a single event handle to be written.");
    }

    private async Task AssertCalendarResponsePreviewAsync()
    {
        var exchange = new CalendarPolicyRecordingHandler
        {
            IsOrganizer = false,
            Organizer = "organizer@example.test"
        };
        await using var host = await StartCalendarHostAsync(exchange, writesEnabled: true, sendEnabled: true,
            classicStateful: true);
        var token = Token("user-a", "mail.read mail.write mail.manage mail.send", sessionId: "calendar-response-preview");
        var form = new NativeFormResponder(accept: false);
        await using var client = await CreateNativeClientAsync(host, token, form);
        var handle = await CalendarEventHandleAsync(client.Client);
        var result = await client.Client.CallToolAsync("calendar_respond", new Dictionary<string, object?>
        {
            ["eventHandle"] = handle,
            ["response"] = "tentative",
            ["body"] = "I can join after lunch."
        });
        Expect(result.IsError != true && form.Calls == 1 && exchange.CalendarWriteCount == 0
            && form.LastRequest?.Message.Contains("Organizer: organizer@example.test", StringComparison.Ordinal) == true
            && form.LastRequest.Message.Contains("Resources: room@example.test", StringComparison.Ordinal)
            && form.LastRequest.Message.Contains("I can join after lunch.", StringComparison.Ordinal),
            "The meeting response confirmation did not show the organizer and response body.");
    }

    private async Task AssertCalendarUpdatePreservesOmittedFieldsAsync()
    {
        var exchange = new CalendarPolicyRecordingHandler
        {
            IsAllDay = true,
            ReminderMinutes = 15,
            Sensitivity = "Private",
            ReturnRichBody = true
        };
        await using var host = await StartCalendarHostAsync(exchange, writesEnabled: true, sendEnabled: false);
        var token = Token("user-a", "mail.read mail.write mail.manage", sessionId: "calendar-preserve-omitted");
        await InitializeAsync(host.Client, token);
        var handle = await CalendarEventHandleAsync(host.Client, token);
        var update = new
        {
            eventHandle = handle,
            subject = "Changed subject",
            body = "<p>Changed <em>rich</em> body</p>",
            bodyType = "HTML",
            start = "2026-10-10T00:00:00+03:30",
            end = "2026-10-11T00:00:00+03:30",
            timeZone = "Iran Standard Time",
            sendUpdates = false,
            scope = "event"
        };
        var result = await ToolRequestAsync(host.Client, token, "tools/call", new
        {
            name = "calendar_update_event",
            arguments = update
        });
        Expect(!IsToolError(result.Body) && exchange.CalendarWriteCount == 1,
            "An ordinary calendar update with omitted optional fields did not complete.");
        var wire = XDocument.Parse(exchange.LastBody);
        var updateUris = wire.Descendants(XName.Get("SetItemField", CalendarPolicyRecordingHandler.Types))
            .Select(x => (string?)x.Element(XName.Get("FieldURI", CalendarPolicyRecordingHandler.Types))?.Attribute("FieldURI"))
            .Where(x => x is not null)
            .Select(x => x!)
            .ToHashSet(StringComparer.Ordinal);
        Expect(updateUris.SetEquals([
                "item:Subject", "item:Body", "calendar:Start", "calendar:End", "calendar:StartTimeZone"])
            && wire.Descendants(XName.Get("SetItemField", CalendarPolicyRecordingHandler.Types)).Count() == 5
            && !wire.Descendants(XName.Get("DeleteItemField", CalendarPolicyRecordingHandler.Types)).Any()
            && wire.Descendants(XName.Get("Body", CalendarPolicyRecordingHandler.Types))
                .Any(x => (string?)x.Attribute("BodyType") == "HTML" && x.Value.Contains("<em>rich</em>", StringComparison.Ordinal))
            && !wire.Descendants(XName.Get("RequiredAttendees", CalendarPolicyRecordingHandler.Types)).Any()
            && !wire.Descendants(XName.Get("Sensitivity", CalendarPolicyRecordingHandler.Types)).Any()
            && !wire.Descendants(XName.Get("IsAllDayEvent", CalendarPolicyRecordingHandler.Types)).Any()
            && !wire.Descendants(XName.Get("ReminderMinutesBeforeStart", CalendarPolicyRecordingHandler.Types)).Any()
            && !wire.Descendants(XName.Get("Categories", CalendarPolicyRecordingHandler.Types)).Any(),
            "An ordinary calendar update rewrote omitted fields instead of sending only the explicitly supplied fields.");

        var omittedBodyUpdate = new
        {
            eventHandle = handle,
            subject = "Body retained",
            start = "2026-10-10T00:00:00+03:30",
            end = "2026-10-11T00:00:00+03:30",
            timeZone = "Iran Standard Time",
            sendUpdates = false,
            scope = "event"
        };
        var omittedBodyResult = await ToolRequestAsync(host.Client, token, "tools/call", new
        {
            name = "calendar_update_event",
            arguments = omittedBodyUpdate
        });
        Expect(!IsToolError(omittedBodyResult.Body) && exchange.CalendarWriteCount == 2,
            "An update that omitted an existing rich HTML body was rejected.");
        var omittedBodyWire = XDocument.Parse(exchange.LastBody);
        var omittedBodyUris = omittedBodyWire.Descendants(XName.Get("SetItemField", CalendarPolicyRecordingHandler.Types))
            .Select(x => (string?)x.Element(XName.Get("FieldURI", CalendarPolicyRecordingHandler.Types))?.Attribute("FieldURI"))
            .Where(x => x is not null)
            .Select(x => x!)
            .ToHashSet(StringComparer.Ordinal);
        Expect(omittedBodyUris.SetEquals([
                "item:Subject", "calendar:Start", "calendar:End", "calendar:StartTimeZone"])
            && omittedBodyWire.Descendants(XName.Get("SetItemField", CalendarPolicyRecordingHandler.Types)).Count() == 4
            && !omittedBodyWire.Descendants(XName.Get("Body", CalendarPolicyRecordingHandler.Types)).Any(),
            "An omitted rich HTML body was rewritten instead of being left to Exchange unchanged.");
    }

    private async Task AssertCalendarResponseOrganizerPolicyAsync()
    {
        var exchange = new CalendarPolicyRecordingHandler
        {
            IsOrganizer = false,
            Organizer = "organizer@external.example"
        };
        await using var host = await StartCalendarHostAsync(exchange, writesEnabled: true, sendEnabled: true,
            classicStateful: true);
        var token = Token("user-a", "mail.read mail.write mail.manage mail.send", sessionId: "calendar-response-domain");
        var form = new NativeFormResponder(accept: true);
        await using var client = await CreateNativeClientAsync(host, token, form);
        var handle = await CalendarEventHandleAsync(client.Client);
        var result = await client.Client.CallToolAsync("calendar_respond", new Dictionary<string, object?>
        {
            ["eventHandle"] = handle,
            ["response"] = "tentative",
            ["body"] = "I can join after lunch."
        });
        Expect(result.IsError == true && form.Calls == 0 && exchange.CalendarWriteCount == 0,
            "A meeting response to an organizer outside the configured recipient policy reached approval or Exchange.");
    }

    private async Task<string> CalendarEventHandleAsync(HttpClient client, string token)
    {
        var result = await ToolRequestAsync(client, token, "tools/call", new
        {
            name = "calendar_list_events",
            arguments = new { start = "2026-10-10T00:00:00Z", end = "2026-10-11T00:00:00Z" }
        });
        Expect(!IsToolError(result.Body), "The calendar policy fixture could not list its event.");
        var items = ToolStructuredData(result.Body).GetProperty("items");
        Expect(items.GetArrayLength() == 1, "The calendar policy fixture did not return one event.");
        return items[0].GetProperty("handle").GetString()!;
    }

    private async Task<string> CalendarEventHandleAsync(ModelContextProtocol.Client.McpClient client)
    {
        var result = await client.CallToolAsync("calendar_list_events", new Dictionary<string, object?>
        {
            ["start"] = "2026-10-10T00:00:00Z",
            ["end"] = "2026-10-11T00:00:00Z"
        });
        Expect(result.IsError != true, "The calendar policy fixture could not list its event.");
        var items = NativeData(result).GetProperty("items");
        Expect(items.GetArrayLength() == 1, "The calendar policy fixture did not return one event.");
        return items[0].GetProperty("handle").GetString()!;
    }

    private static Dictionary<string, object?> CalendarCreateArguments(bool sendInvitations,
        string body = "Agenda", string bodyType = "Text") => new()
        {
            ["subject"] = "Planning",
            ["body"] = body,
            ["bodyType"] = bodyType,
            ["start"] = "2026-10-10T09:00:00+03:30",
            ["end"] = "2026-10-10T10:00:00+03:30",
            ["timeZone"] = "Iran Standard Time",
            ["requiredAttendees"] = new[] { "to@example.test" },
            ["sendInvitations"] = sendInvitations
        };

    private static Dictionary<string, object?> CalendarUpdateArguments(string handle, bool sendUpdates,
        string scope = "event") => new()
        {
            ["eventHandle"] = handle,
            ["subject"] = "Planning",
            ["body"] = "Agenda",
            ["start"] = "2026-10-10T09:00:00+03:30",
            ["end"] = "2026-10-10T10:00:00+03:30",
            ["timeZone"] = "Iran Standard Time",
            ["sendUpdates"] = sendUpdates,
            ["scope"] = scope
        };

    private static Task<(HttpStatusCode StatusCode, string Body)> CalendarApprovalResumeAsync(
        HttpClient client, string token, string state, string handle, IReadOnlyDictionary<string, object?> arguments) =>
        ToolRequestAsync(client, token, "tools/call", new
        {
            name = "calendar_update_event",
            requestState = state,
            inputResponses = new Dictionary<string, object?>
            {
                ["calendar_confirmation"] = new { action = "accept", content = new { confirm = true } }
            },
            arguments
        }, JulyProtocolVersion, elicitation: true);

    private async Task<TestHostContext> StartCalendarHostAsync(CalendarPolicyRecordingHandler exchange,
        bool writesEnabled, bool sendEnabled, bool classicStateful = false)
    {
        var passwordPath = Path.Combine(runDirectory, $"calendar-password-{Guid.NewGuid():N}.txt");
        var introspectionSecretPath = Path.Combine(runDirectory, $"calendar-introspection-{Guid.NewGuid():N}.txt");
        var auditPath = Path.Combine(runDirectory, $"calendar-audit-{Guid.NewGuid():N}.jsonl");
        await File.WriteAllTextAsync(passwordPath, "synthetic-password");
        await File.WriteAllTextAsync(introspectionSecretPath, "synthetic-introspection-secret");
        var app = AppHost.Create([], builder =>
        {
            builder.WebHost.UseTestServer();
            if (!classicStateful)
                builder.Services.PostConfigure<HttpServerTransportOptions>(options =>
                    options.SessionMode = HttpServerSessionMode.Stateless);
            builder.Configuration.AddInMemoryCollection(ConfigurationValues(passwordPath, introspectionSecretPath,
                auditPath, writesEnabled, sendEnabled));
            builder.Services.PostConfigure<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme, options =>
            {
                var configuration = new OpenIdConnectConfiguration { Issuer = Authority };
                configuration.SigningKeys.Add(signingKey);
                options.Configuration = configuration;
                options.ConfigurationManager = new StaticConfigurationManager<OpenIdConnectConfiguration>(configuration);
            });
            builder.Services.AddHttpClient<EwsClient>()
                .ConfigurePrimaryHttpMessageHandler(() => exchange);
            builder.Services.AddHttpClient<KeycloakTokenStatus>()
                .ConfigurePrimaryHttpMessageHandler(() => new IntrospectionHandler());
        });
        await app.StartAsync();
        var client = app.GetTestClient();
        client.BaseAddress = new Uri("https://mail.example.test/");
        return new TestHostContext(app, client);
    }
}

internal sealed class CalendarRecordingHandler : HttpMessageHandler
{
    public const string Soap = "http://schemas.xmlsoap.org/soap/envelope/";
    public const string Messages = "http://schemas.microsoft.com/exchange/services/2006/messages";
    public const string Types = "http://schemas.microsoft.com/exchange/services/2006/types";
    public string LastBody { get; private set; } = string.Empty;
    public List<string> Bodies { get; } = [];
    public bool ReturnTruncatedCalendarView { get; set; }
    public string? RecurrenceWire { get; set; }
    public bool OmitAvailabilityStatus { get; set; }
    public bool OmitAvailabilityViewType { get; set; }
    public bool OmitAvailabilityEventStart { get; set; }
    public bool InvalidAvailabilityViewType { get; set; }
    public bool InvalidAvailabilityBusyType { get; set; }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        LastBody = await request.Content!.ReadAsStringAsync(cancellationToken);
        Bodies.Add(LastBody);
        var document = XDocument.Parse(LastBody);
        var operation = document.Root!.Element(XName.Get("Body", Soap))!.Elements().Single().Name.LocalName;
        var payload = operation switch
        {
            "FindFolder" => "<m:RootFolder IncludesLastItemInRange='true'><t:Folders><t:CalendarFolder><t:FolderId Id='real-calendar-id' ChangeKey='calendar-change'/><t:FolderClass>IPF.Appointment</t:FolderClass><t:DisplayName>Calendar</t:DisplayName><t:TotalCount>1</t:TotalCount><t:UnreadCount>0</t:UnreadCount><t:ChildFolderCount>0</t:ChildFolderCount></t:CalendarFolder></t:Folders></m:RootFolder>",
            "GetFolder" => "<t:CalendarFolder><t:FolderId Id='real-calendar-id' ChangeKey='calendar-change'/><t:FolderClass>IPF.Appointment</t:FolderClass><t:DisplayName>Calendar</t:DisplayName><t:TotalCount>1</t:TotalCount><t:UnreadCount>0</t:UnreadCount><t:ChildFolderCount>0</t:ChildFolderCount></t:CalendarFolder>",
            "FindItem" => Event("event-1", "event-change", ReturnTruncatedCalendarView),
            "GetItem" => $"<m:Items>{EventItem("event-1", "event-change", false, RecurrenceWire)}</m:Items>",
            "CreateItem" or "UpdateItem" => "<m:Items><t:CalendarItem><t:ItemId Id='event-1' ChangeKey='event-change'/></t:CalendarItem></m:Items>",
            "GetUserAvailabilityRequest" => "<m:FreeBusyResponseArray><m:FreeBusyResponse><m:ResponseMessage ResponseClass='Success'><m:ResponseCode>NoError</m:ResponseCode></m:ResponseMessage><m:FreeBusyView><t:FreeBusyViewType>DetailedMerged</t:FreeBusyViewType><t:MergedFreeBusy>2</t:MergedFreeBusy><t:CalendarEventArray><t:CalendarEvent><t:StartTime>2026-10-10T05:30:00Z</t:StartTime><t:EndTime>2026-10-10T06:30:00Z</t:EndTime><t:BusyType>Busy</t:BusyType><t:CalendarEventDetails><t:Subject>Planning</t:Subject><t:Location>Room 1</t:Location></t:CalendarEventDetails></t:CalendarEvent></t:CalendarEventArray></m:FreeBusyView></m:FreeBusyResponse></m:FreeBusyResponseArray>",
            _ => string.Empty
        };
        var responseMessages = operation == "GetUserAvailabilityRequest" ? string.Empty
            : $"<m:ResponseMessages><m:{operation}ResponseMessage ResponseClass='Success'><m:ResponseCode>NoError</m:ResponseCode>{payload}</m:{operation}ResponseMessage></m:ResponseMessages>";
        var responseName = operation == "GetUserAvailabilityRequest" ? "GetUserAvailability" : operation;
        var responseBody = operation == "GetUserAvailabilityRequest" ? payload : responseMessages;
        var xml = $"<s:Envelope xmlns:s='{Soap}' xmlns:m='{Messages}' xmlns:t='{Types}'><s:Body><m:{responseName}Response>{responseBody}</m:{responseName}Response></s:Body></s:Envelope>";
        if (OmitAvailabilityStatus)
        {
            var malformed = XDocument.Parse(xml);
            malformed.Descendants(XName.Get("ResponseMessage", Messages)).Remove();
            xml = malformed.ToString();
        }
        if (OmitAvailabilityViewType || OmitAvailabilityEventStart || InvalidAvailabilityViewType || InvalidAvailabilityBusyType)
        {
            var malformed = XDocument.Parse(xml);
            if (OmitAvailabilityViewType)
                malformed.Descendants(XName.Get("FreeBusyViewType", Types)).Remove();
            if (OmitAvailabilityEventStart)
                malformed.Descendants(XName.Get("StartTime", Types)).Remove();
            if (InvalidAvailabilityViewType)
                malformed.Descendants(XName.Get("FreeBusyViewType", Types)).FirstOrDefault()!.Value = "detailedmerged";
            if (InvalidAvailabilityBusyType)
                malformed.Descendants(XName.Get("BusyType", Types)).FirstOrDefault()!.Value = "Occupied";
            xml = malformed.ToString();
        }
        return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(xml, Encoding.UTF8, "text/xml") };
    }

    private static string Event(string id, string changeKey, bool truncated = false, string? recurrence = null) =>
        $"<m:RootFolder IncludesLastItemInRange='{(!truncated).ToString().ToLowerInvariant()}'><t:Items><t:CalendarItem><t:ItemId Id='{id}' ChangeKey='{changeKey}'/><t:Subject>Planning</t:Subject><t:Body BodyType='Text'>Agenda</t:Body><t:Start>2026-10-10T05:30:00Z</t:Start><t:End>2026-10-10T06:30:00Z</t:End><t:StartTimeZone Id='Iran Standard Time'/><t:EndTimeZone Id='Iran Standard Time'/><t:IsAllDayEvent>false</t:IsAllDayEvent><t:Location>Room 1</t:Location><t:IsMeeting>true</t:IsMeeting><t:IsOrganizer>true</t:IsOrganizer><t:IsOutOfDate>false</t:IsOutOfDate><t:IsRecurring>{(recurrence is not null).ToString().ToLowerInvariant()}</t:IsRecurring><t:IsCancelled>false</t:IsCancelled><t:CalendarItemType>{(recurrence is null ? "Single" : "RecurringMaster")}</t:CalendarItemType><t:RequiredAttendees><t:Attendee><t:Mailbox><t:EmailAddress>to@example.test</t:EmailAddress></t:Mailbox><t:ResponseType>NoResponseReceived</t:ResponseType></t:Attendee></t:RequiredAttendees><t:Categories><t:String>work</t:String></t:Categories><t:Sensitivity>Normal</t:Sensitivity><t:LegacyFreeBusyStatus>Busy</t:LegacyFreeBusyStatus>{(recurrence is null ? string.Empty : $"<t:Recurrence>{recurrence}<t:NoEndRecurrence><t:StartDate>2026-10-10</t:StartDate></t:NoEndRecurrence></t:Recurrence>")}</t:CalendarItem></t:Items></m:RootFolder>";

    private static string EventItem(string id, string changeKey, bool truncated = false, string? recurrence = null) =>
        Event(id, changeKey, truncated, recurrence)
            .Replace($"<m:RootFolder IncludesLastItemInRange='{(!truncated).ToString().ToLowerInvariant()}'><t:Items>", string.Empty, StringComparison.Ordinal)
            .Replace("</t:Items></m:RootFolder>", string.Empty, StringComparison.Ordinal);
}

internal sealed partial class CalendarPolicyRecordingHandler : HttpMessageHandler
{
    public const string Soap = CalendarRecordingHandler.Soap;
    public const string Messages = CalendarRecordingHandler.Messages;
    public const string Types = CalendarRecordingHandler.Types;
    public string LastBody { get; private set; } = string.Empty;
    public string ChangeKey { get; set; } = "event-change";
    public string Subject { get; set; } = "Planning";
    public bool IsOrganizer { get; set; } = true;
    public string Organizer { get; set; } = "organizer@example.test";
    public bool IsAllDay { get; set; }
    public int? ReminderMinutes { get; set; }
    public string Sensitivity { get; set; } = "Normal";
    public bool ThrowNextCalendarWrite { get; set; }
    public bool ReturnMeetingRequest { get; set; }
    public bool ReturnPersonalAppointment { get; set; }
    public bool ReturnRichBody { get; set; }
    public int CalendarWriteCount { get; private set; }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        LastBody = await request.Content!.ReadAsStringAsync(cancellationToken);
        var document = XDocument.Parse(LastBody);
        var operation = document.Root!.Element(XName.Get("Body", Soap))!.Elements().Single().Name.LocalName;
        var requestedFolderId = operation == "GetFolder"
            ? document.Descendants(XName.Get("FolderId", Types)).Select(x => (string?)x.Attribute("Id")).FirstOrDefault()
                ?? "calendar"
            : "calendar";
        RequestCount++;
        Bodies.Add(LastBody);
        if (RecurringSeriesMode && operation is not ("FindFolder" or "GetFolder"))
        {
            var recurringResponse = BuildRecurringSeriesResponse(operation, document);
            Responses.Add(recurringResponse);
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(recurringResponse, Encoding.UTF8, "text/xml")
            };
        }
        if (operation is "CreateItem" or "UpdateItem" or "DeleteItem" or "MoveItem" or "CopyItem")
        {
            CalendarWriteCount++;
            if (ThrowNextCalendarWrite)
            {
                ThrowNextCalendarWrite = false;
                throw new HttpRequestException("synthetic transport uncertainty");
            }
        }

        var payload = operation switch
        {
            "FindFolder" => "<m:RootFolder IncludesLastItemInRange='true'><t:Folders><t:CalendarFolder><t:FolderId Id='calendar' ChangeKey='calendar-change'/><t:FolderClass>IPF.Appointment</t:FolderClass><t:DisplayName>Calendar</t:DisplayName><t:TotalCount>1</t:TotalCount><t:UnreadCount>0</t:UnreadCount><t:ChildFolderCount>0</t:ChildFolderCount></t:CalendarFolder></t:Folders></m:RootFolder>",
            "GetFolder" => $"<t:CalendarFolder><t:FolderId Id='{requestedFolderId}' ChangeKey='calendar-change'/><t:FolderClass>IPF.Appointment</t:FolderClass><t:DisplayName>Calendar</t:DisplayName><t:TotalCount>1</t:TotalCount><t:UnreadCount>0</t:UnreadCount><t:ChildFolderCount>0</t:ChildFolderCount></t:CalendarFolder>",
            "FindItem" => ReturnPersonalAppointment ? PersonalEvent("event-1", ChangeKey, Subject)
                : Event("event-1", ChangeKey, Subject, IsOrganizer, Organizer,
                    IsAllDay, ReminderMinutes, Sensitivity, ReturnRichBody),
            "GetItem" => ReturnMeetingRequest
                ? MeetingRequestMessage()
                : ReturnPersonalAppointment ? $"<m:Items>{PersonalEventItem("event-1", ChangeKey, Subject)}</m:Items>"
                : $"<m:Items>{EventItem("event-1", ChangeKey, Subject, IsOrganizer, Organizer,
                    IsAllDay, ReminderMinutes, Sensitivity, ReturnRichBody)}</m:Items>",
            "CreateItem" => "<m:Items><t:CalendarItem><t:ItemId Id='event-created' ChangeKey='event-created-change'/></t:CalendarItem></m:Items>",
            "UpdateItem" => "<m:Items><t:CalendarItem><t:ItemId Id='event-1' ChangeKey='event-updated-change'/></t:CalendarItem></m:Items>",
            "MoveItem" => "<m:Items><t:CalendarItem><t:ItemId Id='moved-event' ChangeKey='moved-change'/></t:CalendarItem></m:Items>",
            "CopyItem" => "<m:Items><t:CalendarItem><t:ItemId Id='copied-event' ChangeKey='copied-change'/></t:CalendarItem></m:Items>",
            _ => string.Empty
        };
        var responseMessages = $"<m:ResponseMessages><m:{operation}ResponseMessage ResponseClass='Success'><m:ResponseCode>NoError</m:ResponseCode>{payload}</m:{operation}ResponseMessage></m:ResponseMessages>";
        var xml = $"<s:Envelope xmlns:s='{Soap}' xmlns:m='{Messages}' xmlns:t='{Types}'><s:Body><m:{operation}Response>{responseMessages}</m:{operation}Response></s:Body></s:Envelope>";
        return new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(xml, Encoding.UTF8, "text/xml")
        };
    }

    private static string Event(string id, string changeKey, string subject, bool isOrganizer = true, string? organizer = null,
        bool isAllDay = false, int? reminderMinutes = null, string sensitivity = "Normal", bool richBody = false) =>
        $"<m:RootFolder IncludesLastItemInRange='true'><t:Items><t:CalendarItem><t:ItemId Id='{id}' ChangeKey='{changeKey}'/><t:Subject>{System.Security.SecurityElement.Escape(subject)}</t:Subject>{(richBody ? "<t:Body BodyType='HTML'>&lt;p&gt;Existing &lt;strong&gt;rich&lt;/strong&gt; body&lt;/p&gt;</t:Body>" : "<t:Body BodyType='Text'>Agenda</t:Body>")}<t:Start>2026-10-10T05:30:00Z</t:Start><t:End>2026-10-10T06:30:00Z</t:End><t:StartTimeZone Id='Iran Standard Time'/><t:EndTimeZone Id='Iran Standard Time'/><t:IsAllDayEvent>{isAllDay.ToString().ToLowerInvariant()}</t:IsAllDayEvent><t:Location>Room 1</t:Location><t:IsMeeting>true</t:IsMeeting><t:IsOrganizer>{isOrganizer.ToString().ToLowerInvariant()}</t:IsOrganizer><t:IsOutOfDate>false</t:IsOutOfDate><t:IsRecurring>false</t:IsRecurring><t:IsCancelled>false</t:IsCancelled><t:CalendarItemType>Single</t:CalendarItemType>{(string.IsNullOrWhiteSpace(organizer) ? string.Empty : $"<t:Organizer><t:Mailbox><t:EmailAddress>{System.Security.SecurityElement.Escape(organizer)}</t:EmailAddress></t:Mailbox></t:Organizer>")}<t:RequiredAttendees><t:Attendee><t:Mailbox><t:EmailAddress>to@example.test</t:EmailAddress></t:Mailbox><t:ResponseType>NoResponseReceived</t:ResponseType></t:Attendee></t:RequiredAttendees><t:Resources><t:Attendee><t:Mailbox><t:EmailAddress>room@example.test</t:EmailAddress></t:Mailbox><t:ResponseType>NoResponseReceived</t:ResponseType></t:Attendee></t:Resources><t:Attachments><t:FileAttachment><t:AttachmentId Id='calendar-att-1'/><t:Name>agenda.pdf</t:Name><t:Size>4</t:Size><t:ContentType>application/pdf</t:ContentType></t:FileAttachment></t:Attachments><t:Categories><t:String>work</t:String></t:Categories><t:Sensitivity>{System.Security.SecurityElement.Escape(sensitivity)}</t:Sensitivity><t:LegacyFreeBusyStatus>Busy</t:LegacyFreeBusyStatus>{(reminderMinutes is null ? "<t:ReminderIsSet>false</t:ReminderIsSet>" : $"<t:ReminderIsSet>true</t:ReminderIsSet><t:ReminderMinutesBeforeStart>{reminderMinutes.Value}</t:ReminderMinutesBeforeStart>")}<t:ResponseObjects><t:AcceptItem/><t:TentativelyAcceptItem/><t:DeclineItem/></t:ResponseObjects></t:CalendarItem></t:Items></m:RootFolder>";

    private static string EventItem(string id, string changeKey, string subject, bool isOrganizer = true, string? organizer = null,
        bool isAllDay = false, int? reminderMinutes = null, string sensitivity = "Normal", bool richBody = false) =>
        Event(id, changeKey, subject, isOrganizer, organizer, isAllDay, reminderMinutes, sensitivity, richBody)
            .Replace("<m:RootFolder IncludesLastItemInRange='true'><t:Items>", string.Empty, StringComparison.Ordinal)
            .Replace("</t:Items></m:RootFolder>", string.Empty, StringComparison.Ordinal);

    private static string PersonalEvent(string id, string changeKey, string subject) =>
        $"<m:RootFolder IncludesLastItemInRange='true'><t:Items><t:CalendarItem><t:ItemId Id='{id}' ChangeKey='{changeKey}'/><t:ParentFolderId Id='calendar' ChangeKey='calendar-change'/><t:Subject>{System.Security.SecurityElement.Escape(subject)}</t:Subject><t:Body BodyType='Text'>Agenda</t:Body><t:Start>2026-10-10T05:30:00Z</t:Start><t:End>2026-10-10T06:30:00Z</t:End><t:StartTimeZone Id='Iran Standard Time'/><t:EndTimeZone Id='Iran Standard Time'/><t:IsAllDayEvent>false</t:IsAllDayEvent><t:Location>Room 1</t:Location><t:IsMeeting>false</t:IsMeeting><t:IsOrganizer>false</t:IsOrganizer><t:IsRecurring>false</t:IsRecurring><t:IsCancelled>false</t:IsCancelled><t:CalendarItemType>Single</t:CalendarItemType></t:CalendarItem></t:Items></m:RootFolder>";

    private static string PersonalEventItem(string id, string changeKey, string subject) =>
        PersonalEvent(id, changeKey, subject)
            .Replace("<m:RootFolder IncludesLastItemInRange='true'><t:Items>", string.Empty, StringComparison.Ordinal)
            .Replace("</t:Items></m:RootFolder>", string.Empty, StringComparison.Ordinal);
}
