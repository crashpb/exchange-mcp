using System.Net;
using System.Text;
using System.Xml.Linq;
using System.Xml.Schema;
using Company.ExchangeMcp.Exchange;
using Company.ExchangeMcp.Security;
using Microsoft.Extensions.DependencyInjection;

internal sealed partial class Checks
{
    private async Task CalendarCompletenessChecksAsync()
    {
        var handler = new CalendarCompletenessRecordingHandler();
        var client = NewEwsClient(handler);

        var item = await client.GetCalendarEventAsync("alice@example.test", "event-1", CancellationToken.None);
        Expect(item.EndTimeZone == "Pacific Standard Time"
            && item.ReminderIsSet == false
            && item.ReminderMinutesBeforeStart is null
            && item.Importance == "High"
            && item.IsResponseRequested == true
            && item.AllowNewTimeProposal == false
            && item.MeetingRequestWasSent == true
            && item.ResponseObjects.SequenceEqual(["AcceptItem", "DeclineItem"])
            && item.ParentFolderId == "calendar"
            && item.AppointmentReplyTime == new DateTimeOffset(2026, 10, 9, 12, 0, 0, TimeSpan.Zero)
            && item.AppointmentSequenceNumber == 7
            && item.AppointmentState == 3
            && item.FirstOccurrence?.Id == "occ-first"
            && item.LastOccurrence?.Id == "occ-last"
            && item.ModifiedOccurrences.Count == 1
            && item.DeletedOccurrences.Count == 1
            && item.Recurrence?.StartDate == new DateOnly(2026, 10, 1),
            "Calendar read omitted end time zone, disabled reminder, response capabilities, occurrence metadata or the recurrence local start date.");

        handler.UseEndDateRecurrence = true;
        foreach (var (start, end) in new[]
        {
            ("2026-10-01", "2026-10-03"),
            ("2026-10-01Z", "2026-10-03Z"),
            ("2026-10-01+03:30", "2026-10-03-03:30"),
            ("2026-10-01-14:00", "2026-10-03+14:00")
        })
        {
            handler.RecurrenceStartDate = start;
            handler.RecurrenceEndDate = end;
            var parsed = await client.GetCalendarEventAsync("alice@example.test", "event-1", CancellationToken.None);
            Expect(parsed.Recurrence?.StartDate == new DateOnly(2026, 10, 1)
                && parsed.Recurrence.EndDate == new DateOnly(2026, 10, 3),
                $"Calendar recurrence date variant was not parsed without changing its lexical day: {start}/{end}.");
        }

        foreach (var (start, end) in new[]
        {
            ("2026-10-01+14:01", "2026-10-03"),
            ("2026-10-01trailing", "2026-10-03"),
            ("2026-02-30", "2026-03-03"),
            ("2026-10-01T00:00:00Z", "2026-10-03"),
            (null, "2026-10-03"),
            ("2026-10-01", null)
        })
        {
            handler.RecurrenceStartDate = start;
            handler.RecurrenceEndDate = end;
            await AssertThrowsAsync<InvalidOperationException>(() => client.GetCalendarEventAsync(
                "alice@example.test", "event-1", CancellationToken.None));
        }
        handler.UseEndDateRecurrence = false;
        handler.RecurrenceStartDate = "2026-10-01";
        handler.RecurrenceEndDate = null;

        var readShape = XDocument.Parse(handler.LastBody);
        var readFields = readShape.Descendants(XName.Get("FieldURI", CalendarCompletenessRecordingHandler.Types))
            .Select(x => (string?)x.Attribute("FieldURI"))
            .Where(x => x is not null)
            .Select(x => x!)
            .ToHashSet(StringComparer.Ordinal);
        Expect(readFields.IsSupersetOf([
            "calendar:EndTimeZone", "item:ReminderIsSet", "item:Importance", "calendar:IsResponseRequested",
            "calendar:AllowNewTimeProposal", "calendar:MeetingRequestWasSent", "item:ResponseObjects",
            "item:ParentFolderId", "calendar:AppointmentReplyTime", "calendar:AppointmentSequenceNumber",
            "calendar:AppointmentState", "calendar:FirstOccurrence", "calendar:LastOccurrence",
            "calendar:ModifiedOccurrences", "calendar:DeletedOccurrences"]),
            "Calendar ItemShape did not request the fields needed to preserve calendar metadata.");

        handler.AddDecoyCalendarReadItem = true;
        await AssertThrowsAsync<InvalidOperationException>(() => client.GetCalendarEventAsync(
            "alice@example.test", "event-1", CancellationToken.None));
        handler.AddDecoyCalendarReadItem = false;
        handler.ReturnWrongCalendarReadItemType = true;
        await AssertThrowsAsync<InvalidOperationException>(() => client.GetCalendarEventAsync(
            "alice@example.test", "event-1", CancellationToken.None));
        handler.ReturnWrongCalendarReadItemType = false;
        handler.OmitCalendarIsMeeting = true;
        await AssertThrowsAsync<InvalidOperationException>(() => client.GetCalendarEventAsync(
            "alice@example.test", "event-1", CancellationToken.None));
        handler.OmitCalendarIsMeeting = false;
        handler.OmitCalendarIsOrganizer = true;
        await AssertThrowsAsync<InvalidOperationException>(() => client.GetCalendarEventAsync(
            "alice@example.test", "event-1", CancellationToken.None));
        handler.OmitCalendarIsOrganizer = false;
        handler.OmitMeetingRequestIsOrganizer = true;
        await AssertThrowsAsync<InvalidOperationException>(() => client.GetCalendarMeetingMessageAsync(
            "alice@example.test", "meeting-request-1", CancellationToken.None));
        handler.OmitMeetingRequestIsOrganizer = false;
        handler.ReturnLongStoredRange = true;
        var longStored = await client.GetCalendarEventAsync(
            "alice@example.test", "event-long", CancellationToken.None);
        Expect(longStored.Id == "event-long"
            && longStored.Start == new DateTimeOffset(2025, 1, 1, 0, 0, 0, TimeSpan.Zero)
            && longStored.End == new DateTimeOffset(2027, 1, 1, 0, 0, 0, TimeSpan.Zero),
            "A valid stored calendar event spanning more than 366 days was rejected or truncated on read.");
        handler.ReturnLongStoredRange = false;

        var partialFields = new HashSet<string>([
            "Subject", "Body", "EndTimeZone", "ReminderIsSet", "Importance", "IsResponseRequested", "AllowNewTimeProposal"],
            StringComparer.Ordinal);
        var partialInput = new EwsCalendarEventInput(
            "Updated subject", "<p>Updated <b>body</b>.</p>", "HTML",
            new DateTimeOffset(2026, 10, 10, 9, 0, 0, TimeSpan.FromHours(3.5)),
            new DateTimeOffset(2026, 10, 10, 10, 0, 0, TimeSpan.FromHours(3.5)),
            "Iran Standard Time", false, "Updated room", ["ignored@example.test"], [], [], null, null, [], "Normal", "Busy")
        {
            EndTimeZone = "Pacific Standard Time",
            Importance = "High",
            IsResponseRequested = false,
            AllowNewTimeProposal = false,
            TimeZone = "Not A Windows Time Zone",
            Location = "\u0001",
            RequiredAttendees = ["not-a-mailbox"],
            Categories = [string.Empty],
            Sensitivity = "NotARealSensitivity",
            LegacyFreeBusyStatus = "NotARealFreeBusyStatus",
            ClearReminder = true,
            UpdatedFields = partialFields
        };
        await client.UpdateCalendarEventAsync("alice@example.test", "event-1", "event-change", partialInput,
            sendUpdates: false, CancellationToken.None);
        var partialWire = XDocument.Parse(handler.LastBody);
        var updateFields = partialWire.Descendants(XName.Get("SetItemField", CalendarCompletenessRecordingHandler.Types))
            .Select(x => (string?)x.Element(XName.Get("FieldURI", CalendarCompletenessRecordingHandler.Types))?.Attribute("FieldURI"))
            .Where(x => x is not null)
            .Concat(partialWire.Descendants(XName.Get("DeleteItemField", CalendarCompletenessRecordingHandler.Types))
                .Select(x => (string?)x.Element(XName.Get("FieldURI", CalendarCompletenessRecordingHandler.Types))?.Attribute("FieldURI")))
            .Where(x => x is not null)
            .Select(x => x!)
            .ToHashSet(StringComparer.Ordinal);
        Expect(updateFields.SetEquals([
            "item:Subject", "item:Body", "calendar:EndTimeZone", "item:ReminderIsSet",
            "item:Importance", "calendar:IsResponseRequested", "calendar:AllowNewTimeProposal"]),
            "Calendar partial update emitted omitted fields or used the wrong EWS field names.");
        Expect(partialWire.Descendants(XName.Get("Body", CalendarCompletenessRecordingHandler.Types))
            .Any(x => (string?)x.Attribute("BodyType") == "HTML" && x.Value.Contains("<b>body</b>", StringComparison.Ordinal))
            && partialWire.Descendants(XName.Get("DeleteItemField", CalendarCompletenessRecordingHandler.Types)).Count() == 0
            && partialWire.Descendants(XName.Get("ReminderIsSet", CalendarCompletenessRecordingHandler.Types)).Any(x => x.Value == "false")
            && !partialWire.Descendants(XName.Get("ReminderMinutesBeforeStart", CalendarCompletenessRecordingHandler.Types)).Any(),
            "Calendar partial update did not preserve the submitted rich body or disable the reminder while preserving minutes.");

        var createInput = partialInput with
        {
            Subject = "Created",
            Body = "Created body",
            BodyType = "Text",
            TimeZone = "Iran Standard Time",
            Location = "Created room",
            RequiredAttendees = [],
            Categories = [],
            Sensitivity = "Normal",
            LegacyFreeBusyStatus = "Busy",
            ReminderMinutesBeforeStart = 10,
            ClearReminder = false,
            UpdatedFields = null,
            Recurrence = new EwsCalendarRecurrence("weekly", 1, ["Saturday"], "Saturday", NoEnd: true)
            {
                StartDate = new DateOnly(2026, 10, 1)
            }
        };
        await client.CreateCalendarEventAsync("alice@example.test", "calendar", createInput, sendInvitations: false,
            CancellationToken.None);
        var createWire = XDocument.Parse(handler.LastBody);
        Expect(createWire.Descendants(XName.Get("EndTimeZone", CalendarCompletenessRecordingHandler.Types))
                   .Any(x => (string?)x.Attribute("Id") == "Pacific Standard Time")
            && createWire.Descendants(XName.Get("Start", CalendarCompletenessRecordingHandler.Types))
                .Any(x => x.Value == "2026-10-10T05:30:00.000Z")
            && createWire.Descendants(XName.Get("End", CalendarCompletenessRecordingHandler.Types))
                .Any(x => x.Value == "2026-10-10T06:30:00.000Z")
            && createWire.Descendants(XName.Get("Importance", CalendarCompletenessRecordingHandler.Types)).Any(x => x.Value == "High")
            && createWire.Descendants(XName.Get("IsResponseRequested", CalendarCompletenessRecordingHandler.Types)).Any(x => x.Value == "false")
            && createWire.Descendants(XName.Get("AllowNewTimeProposal", CalendarCompletenessRecordingHandler.Types)).Any(x => x.Value == "false")
            && createWire.Descendants(XName.Get("StartDate", CalendarCompletenessRecordingHandler.Types)).Any(x => x.Value == "2026-10-01"),
            "Calendar creation did not emit end time zone, response controls or the recurrence's explicit local start date.");

        var search = await client.SearchCalendarEventsAsync("alice@example.test", "calendar", "planning", 25, 0, CancellationToken.None);
        Expect(search.Items.Count == 1 && search.NextOffset == 25,
            "Calendar search did not return the bounded page continuation offset.");
        var searchWire = XDocument.Parse(handler.LastBody);
        var page = searchWire.Descendants(XName.Get("IndexedPageItemView", CalendarCompletenessRecordingHandler.Messages)).Single();
        Expect((string?)page.Attribute("MaxEntriesReturned") == "25"
            && (string?)page.Attribute("Offset") == "0"
            && searchWire.Descendants(XName.Get("QueryString", CalendarCompletenessRecordingHandler.Messages))
                .Any(x => x.Value == "planning")
            && searchWire.Descendants(XName.Get("ParentFolderIds", CalendarCompletenessRecordingHandler.Messages)).Single()
                .ElementsAfterSelf().FirstOrDefault()?.Name == XName.Get("QueryString", CalendarCompletenessRecordingHandler.Messages),
            "Calendar search did not send the bounded offset, limit and query string after the folder restriction.");
        await client.SearchCalendarEventsAsync("alice@example.test", "calendar", null, 100, 10_000, CancellationToken.None);
        var boundarySearchWire = XDocument.Parse(handler.LastBody);
        var boundaryPage = boundarySearchWire.Descendants(XName.Get("IndexedPageItemView", CalendarCompletenessRecordingHandler.Messages)).Single();
        Expect((string?)boundaryPage.Attribute("MaxEntriesReturned") == "100"
            && (string?)boundaryPage.Attribute("Offset") == "10000"
            && !boundarySearchWire.Descendants(XName.Get("QueryString", CalendarCompletenessRecordingHandler.Messages)).Any(),
            "Calendar search did not accept the documented maximum page size and offset without inventing a query.");
        await AssertThrowsAsync<ArgumentOutOfRangeException>(() => client.SearchCalendarEventsAsync(
            "alice@example.test", "calendar", null, 25, 10_001, CancellationToken.None));
        await AssertThrowsAsync<ArgumentException>(() => client.SearchCalendarEventsAsync(
            "alice@example.test", "calendar", "bad\u0001query", 25, 0, CancellationToken.None));

        var moved = await client.MoveCalendarEventAsync("alice@example.test", "event-1", "event-change", "calendar-2", CancellationToken.None);
        Expect(moved.Id == "moved-event" && handler.LastOperation == "MoveItem"
            && XDocument.Parse(handler.LastBody).Descendants(XName.Get("FolderId", CalendarCompletenessRecordingHandler.Types))
                .Any(x => (string?)x.Attribute("Id") == "calendar-2"),
            "Calendar move did not preserve the change key or target the requested calendar folder.");
        var copied = await client.CopyCalendarEventAsync("alice@example.test", "event-1", "event-change", "calendar-2", CancellationToken.None);
        Expect(copied.Id == "copied-event" && handler.LastOperation == "CopyItem",
            "Calendar copy did not return the new Exchange item reference.");

        await client.CancelCalendarEventAsync("alice@example.test", "event-1", "event-change",
            "<p>Cancelled</p>", "HTML", CancellationToken.None);
        var cancelWire = XDocument.Parse(handler.LastBody);
        Expect(handler.LastOperation == "CreateItem"
            && (string?)cancelWire.Descendants(XName.Get("CreateItem", CalendarCompletenessRecordingHandler.Messages)).Single().Attribute("MessageDisposition") == "SendAndSaveCopy"
            && cancelWire.Descendants(XName.Get("CancelCalendarItem", CalendarCompletenessRecordingHandler.Types)).Any()
            && cancelWire.Descendants(XName.Get("NewBodyContent", CalendarCompletenessRecordingHandler.Types))
                .Any(x => (string?)x.Attribute("BodyType") == "HTML" && x.Value.Contains("<p>Cancelled</p>", StringComparison.Ordinal)),
            "Calendar cancellation did not use the native CancelCalendarItem body shape.");

        var proposalStart = new DateTimeOffset(2026, 10, 12, 9, 0, 0, TimeSpan.Zero);
        var proposalEnd = new DateTimeOffset(2026, 10, 12, 10, 0, 0, TimeSpan.Zero);
        var response = await client.RespondToMeetingAsync("alice@example.test", "event-1", "event-change", "tentative",
            "<p>Proposing another time</p>", CancellationToken.None, bodyType: "HTML", sendResponse: true,
            proposedStart: proposalStart, proposedEnd: proposalEnd);
        var responseWire = XDocument.Parse(handler.LastBody);
        Expect(response?.Id == "response-copy" && responseWire.Descendants(XName.Get("TentativelyAcceptItem", CalendarCompletenessRecordingHandler.Types)).Any()
            && (string?)responseWire.Descendants(XName.Get("CreateItem", CalendarCompletenessRecordingHandler.Messages)).Single().Attribute("MessageDisposition") == "SendAndSaveCopy"
            && responseWire.Descendants(XName.Get("ProposedStart", CalendarCompletenessRecordingHandler.Types)).Any(x => x.Value == "2026-10-12T09:00:00.000Z")
            && responseWire.Descendants(XName.Get("ProposedEnd", CalendarCompletenessRecordingHandler.Types)).Any(x => x.Value == "2026-10-12T10:00:00.000Z")
            && responseWire.Descendants(XName.Get("Body", CalendarCompletenessRecordingHandler.Types))
                .Any(x => (string?)x.Attribute("BodyType") == "HTML"),
            "Calendar response did not send the rich proposal with native proposed start/end fields.");

        await client.RespondToMeetingAsync("alice@example.test", "event-1", "event-change", "accept", null,
            CancellationToken.None, sendResponse: false);
        var silentWire = XDocument.Parse(handler.LastBody);
        Expect((string?)silentWire.Descendants(XName.Get("CreateItem", CalendarCompletenessRecordingHandler.Messages)).Single().Attribute("MessageDisposition") == "SaveOnly",
            "A silent calendar response was transmitted instead of being saved only.");
        var invalidHandler = new CalendarCompletenessRecordingHandler();
        var invalidClient = NewEwsClient(invalidHandler);
        await AssertThrowsAsync<ArgumentException>(() => invalidClient.RespondToMeetingAsync(
            "alice@example.test", "event-1", "event-change", "accept", null, CancellationToken.None,
            proposedStart: proposalStart));
        Expect(invalidHandler.Calls == 0, "Invalid calendar response proposal reached EWS.");

        var request = await client.GetCalendarMeetingMessageAsync("alice@example.test", "meeting-request-1", CancellationToken.None);
        Expect(XDocument.Parse(handler.LastBody).Descendants(XName.Get("FieldURI", CalendarCompletenessRecordingHandler.Types))
            .Any(field => (string?)field.Attribute("FieldURI") == "meeting:IsOutOfDate"),
            "Meeting-message ItemShape did not request current-request metadata.");
        Expect(request.ItemType == "MeetingRequest"
            && request.Meeting.IsMeeting && !request.Meeting.IsOrganizer
            && request.AssociatedCalendarItem is { Id: "event-1", ChangeKey: "event-change" }
            && request.ProposedStart == proposalStart
            && request.ProposedEnd == proposalEnd
            && request.ResponseType == "Accept"
            && request.From == "organizer@example.test"
            && request.IsOutOfDate == false,
            "Inbound meeting request did not expose its typed meeting, associated calendar item, proposal or response metadata.");

        ValidateCalendarCompletenessSchema(handler);
    }

    private async Task CalendarMeetingMessageChecksAsync()
    {
        var exchange = new CalendarPolicyRecordingHandler
        {
            ReturnMeetingRequest = true,
            MeetingRequestChangeKey = "latest-request-change"
        };
        await using var host = await StartCalendarHostAsync(exchange, writesEnabled: true, sendEnabled: true,
            classicStateful: true);
        var token = Token("user-a", "mail.read mail.write mail.manage mail.send", sessionId: "calendar-meeting-message");

        var identity = new MailboxIdentity("user-a", "alice@example.test", "chatgpt-test", "calendar-meeting-message");
        var handles = host.App.Services.GetRequiredService<MailboxHandles>();
        var messageHandle = handles.Issue(identity, "message", "meeting-request-1", "meeting-request-change");
        var form = new NativeFormResponder(accept: true);
        await using var native = await CreateNativeClientAsync(host, token, form);
        var read = await native.Client.CallToolAsync("calendar_read_meeting_message", new Dictionary<string, object?>
        {
            ["messageHandle"] = messageHandle
        });
        Expect(read.IsError != true, "A typed owned mail handle could not read an inbound calendar meeting request.");
        var data = NativeData(read);
        Expect(data.GetProperty("itemType").GetString() == "MeetingRequest"
            && data.GetProperty("requestHandle").GetString() is { Length: > 0 }
            && data.GetProperty("associatedEventHandle").GetString() is { Length: > 0 }
            && data.GetProperty("contentTrust").GetString() == "untrusted_calendar_content"
            && data.GetProperty("proposedStart").GetString()?.StartsWith("2026-10-12T09:00:00", StringComparison.Ordinal) == true
            && data.GetProperty("proposedEnd").GetString()?.StartsWith("2026-10-12T10:00:00", StringComparison.Ordinal) == true
            && data.GetProperty("responseType").GetString() == "Accept"
            && data.GetProperty("from").GetString() == "organizer@example.test"
            && data.GetProperty("isOutOfDate").GetBoolean() == false,
            "The inbound meeting request omitted its typed request handle, associated event handle, proposed times, response metadata or content trust marker.");

        var requestHandle = data.GetProperty("requestHandle").GetString()!;
        var staleRequestHandle = handles.Issue(identity, "calendar-meeting-request", "meeting-request-1", "meeting-request-change");
        var staleResponse = await native.Client.CallToolAsync("calendar_respond", new Dictionary<string, object?>
        {
            ["eventHandle"] = staleRequestHandle,
            ["response"] = "tentative",
            ["source"] = "request"
        });
        Expect(staleResponse.IsError == true && form.Calls == 0 && exchange.CalendarWriteCount == 0,
            "A stale meeting-request response handle reached approval or Exchange write.");

        var response = await native.Client.CallToolAsync("calendar_respond", new Dictionary<string, object?>
        {
            ["eventHandle"] = requestHandle,
            ["response"] = "tentative",
            ["source"] = "request",
            ["body"] = "I can join after lunch."
        });
        var responseWire = XDocument.Parse(exchange.LastBody);
        Expect(response.IsError != true && form.Calls == 1 && exchange.CalendarWriteCount == 1
            && responseWire.Descendants(XName.Get("ReferenceItemId", CalendarPolicyRecordingHandler.Types))
                .Any(x => (string?)x.Attribute("Id") == "meeting-request-1"
                    && (string?)x.Attribute("ChangeKey") == "latest-request-change"),
            "A stale message read did not issue a current request handle for the request-source response.");

        var before = exchange.RequestCount;
        var raw = await native.Client.CallToolAsync("calendar_read_meeting_message", new Dictionary<string, object?>
        {
            ["messageHandle"] = "meeting-request-1"
        });
        Expect(raw.IsError == true && exchange.RequestCount == before,
            "A raw Exchange mailbox item id was accepted without a signed message handle.");
        var wrongType = await native.Client.CallToolAsync("calendar_read_meeting_message", new Dictionary<string, object?>
        {
            ["messageHandle"] = handles.Issue(identity, "calendar-event", "meeting-request-1", "meeting-request-change")
        });
        Expect(wrongType.IsError == true && exchange.RequestCount == before,
            "A calendar-event handle was accepted where a typed mail message handle was required.");
    }

    private async Task CalendarTransferChecksAsync()
    {
        var personalExchange = new CalendarPolicyRecordingHandler { ReturnPersonalAppointment = true };
        await using (var host = await StartCalendarHostAsync(personalExchange, writesEnabled: true, sendEnabled: false))
        {
            var token = Token("user-a", "mail.read mail.write mail.manage", sessionId: "calendar-transfer-personal");
            await InitializeAsync(host.Client, token);
            var listed = await ToolRequestAsync(host.Client, token, "tools/call", new
            {
                name = "calendar_list_events",
                arguments = new { start = "2026-10-10T00:00:00Z", end = "2026-10-11T00:00:00Z" }
            });
            Expect(!IsToolError(listed.Body), "The personal appointment fixture could not be listed.");
            var eventHandle = ToolStructuredData(listed.Body).GetProperty("items")[0].GetProperty("handle").GetString()!;
            var identity = new MailboxIdentity("user-a", "alice@example.test", "chatgpt-test", "calendar-transfer-personal");
            var destinationHandle = host.App.Services.GetRequiredService<MailboxHandles>()
                .Issue(identity, "calendar-folder", "calendar-2", "calendar-change");

            var copied = await ToolRequestAsync(host.Client, token, "tools/call", new
            {
                name = "calendar_copy_event",
                arguments = new { eventHandle, destinationFolder = destinationHandle, scope = "event" }
            });
            Expect(!IsToolError(copied.Body) && personalExchange.CalendarWriteCount == 1
                && XDocument.Parse(personalExchange.LastBody).Descendants(XName.Get("CopyItem", CalendarPolicyRecordingHandler.Messages)).Any()
                && XDocument.Parse(personalExchange.LastBody).Descendants(XName.Get("FolderId", CalendarPolicyRecordingHandler.Types))
                    .Any(x => (string?)x.Attribute("Id") == "calendar-2"),
                "A personal appointment could not be copied to an owned destination calendar.");

            var moved = await ToolRequestAsync(host.Client, token, "tools/call", new
            {
                name = "calendar_move_event",
                arguments = new { eventHandle, destinationFolder = destinationHandle, scope = "event" }
            });
            Expect(!IsToolError(moved.Body) && personalExchange.CalendarWriteCount == 2
                && XDocument.Parse(personalExchange.LastBody).Descendants(XName.Get("MoveItem", CalendarPolicyRecordingHandler.Messages)).Any(),
                "A personal appointment could not be moved to an owned destination calendar.");
        }

        var meetingExchange = new CalendarPolicyRecordingHandler();
        await using var meetingHost = await StartCalendarHostAsync(meetingExchange, writesEnabled: true, sendEnabled: false);
        var meetingToken = Token("user-a", "mail.read mail.write mail.manage", sessionId: "calendar-transfer-meeting");
        await InitializeAsync(meetingHost.Client, meetingToken);
        var meetingList = await ToolRequestAsync(meetingHost.Client, meetingToken, "tools/call", new
        {
            name = "calendar_list_events",
            arguments = new { start = "2026-10-10T00:00:00Z", end = "2026-10-11T00:00:00Z" }
        });
        var meetingHandle = ToolStructuredData(meetingList.Body).GetProperty("items")[0].GetProperty("handle").GetString()!;
        var before = meetingExchange.CalendarWriteCount;
        var refusedCopy = await ToolRequestAsync(meetingHost.Client, meetingToken, "tools/call", new
        {
            name = "calendar_copy_event",
            arguments = new { eventHandle = meetingHandle, destinationFolder = "calendar-2", scope = "event" }
        });
        var refusedMove = await ToolRequestAsync(meetingHost.Client, meetingToken, "tools/call", new
        {
            name = "calendar_move_event",
            arguments = new { eventHandle = meetingHandle, destinationFolder = "calendar-2", scope = "event" }
        });
        Expect(IsToolError(refusedCopy.Body) && IsToolError(refusedMove.Body)
            && meetingExchange.CalendarWriteCount == before,
            "A meeting or attendee-bearing calendar item was moved or copied as if it were a personal appointment.");
    }

    private static void ValidateCalendarCompletenessSchema(CalendarCompletenessRecordingHandler handler)
    {
        var schemas = LoadOptionalExchangeSchemas();
        Expect(handler.Bodies.Count > 0, "Calendar completeness fixture captured no EWS requests.");
        foreach (var body in handler.Bodies)
        {
            var operation = XDocument.Parse(body).Root?.Element(XName.Get("Body", CalendarCompletenessRecordingHandler.Soap))?.Elements().Single()
                ?? throw new InvalidOperationException("Calendar completeness SOAP operation was not captured.");
            if (schemas is not null)
                new XDocument(new XElement(operation)).Validate(schemas, (_, error) => throw new InvalidOperationException(
                    $"Exchange 2019 schema rejected calendar completeness operation: {error.Message}"));
        }
    }
}

internal sealed class CalendarCompletenessRecordingHandler : HttpMessageHandler
{
    public const string Soap = "http://schemas.xmlsoap.org/soap/envelope/";
    public const string Messages = "http://schemas.microsoft.com/exchange/services/2006/messages";
    public const string Types = "http://schemas.microsoft.com/exchange/services/2006/types";
    public List<string> Bodies { get; } = [];
    public int Calls { get; private set; }
    public string LastBody { get; private set; } = string.Empty;
    public string LastOperation { get; private set; } = string.Empty;
    public bool AddDecoyCalendarReadItem { get; set; }
    public bool ReturnWrongCalendarReadItemType { get; set; }
    public bool OmitCalendarIsMeeting { get; set; }
    public bool OmitCalendarIsOrganizer { get; set; }
    public bool OmitMeetingRequestIsOrganizer { get; set; }
    public bool ReturnLongStoredRange { get; set; }
    public bool UseEndDateRecurrence { get; set; }
    public string? RecurrenceStartDate { get; set; } = "2026-10-01";
    public string? RecurrenceEndDate { get; set; }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        LastBody = await request.Content!.ReadAsStringAsync(cancellationToken);
        Bodies.Add(LastBody);
        Calls++;
        var document = XDocument.Parse(LastBody);
        var operation = document.Root!.Element(XName.Get("Body", Soap))!.Elements().Single();
        LastOperation = operation.Name.LocalName;
        var itemId = operation.Descendants(XName.Get("ItemId", Types)).FirstOrDefault()?.Attribute("Id")?.Value;
        var requestedSearchOffset = int.TryParse(
            (string?)operation.Element(XName.Get("IndexedPageItemView", Messages))?.Attribute("Offset"), out var parsedSearchOffset)
            ? parsedSearchOffset : 0;
        string payload;
        if (LastOperation == "GetItem" && itemId == "meeting-request-1")
            payload = $"<m:Items>{MeetingRequest()}</m:Items>";
        else if (LastOperation == "GetItem")
        {
            var readId = itemId == "event-long" ? "event-long" : "event-1";
            var readChangeKey = itemId == "event-long" ? "event-long-change" : "event-change";
            if (ReturnWrongCalendarReadItemType)
                payload = "<m:Items><t:Message><t:ItemId Id='wrong-item' ChangeKey='wrong-change'/></t:Message></m:Items>";
            else
                payload = $"<m:Items>{CalendarItem(readId, readChangeKey, ReturnLongStoredRange && itemId == "event-long")}{(AddDecoyCalendarReadItem ? CalendarItem("decoy-item", "decoy-change") : string.Empty)}</m:Items>";
        }
        else if (LastOperation == "FindItem")
        {
            var isSearch = operation.Element(XName.Get("IndexedPageItemView", Messages)) is not null;
            payload = isSearch
                ? $"<m:RootFolder IncludesLastItemInRange='{(requestedSearchOffset >= 10_000).ToString().ToLowerInvariant()}' IndexedPagingOffset='{(requestedSearchOffset >= 10_000 ? requestedSearchOffset : requestedSearchOffset + 25)}'><t:Items>{CalendarItem("search-event", "search-change")}</t:Items></m:RootFolder>"
                : $"<m:{(LastOperation == "GetItem" ? "Items" : "RootFolder")}" + (LastOperation == "FindItem" ? " IncludesLastItemInRange='true'" : string.Empty) + ">"
                    + (LastOperation == "FindItem" ? "<t:Items>" : string.Empty) + CalendarItem("event-1", "event-change")
                    + (LastOperation == "FindItem" ? "</t:Items>" : string.Empty) + $"</m:{(LastOperation == "GetItem" ? "Items" : "RootFolder")}>";
        }
        else if (LastOperation == "CreateItem" && operation.Descendants().Any(x => x.Name.LocalName is "AcceptItem" or "TentativelyAcceptItem" or "DeclineItem"))
            payload = "<m:Items><t:CalendarItem><t:ItemId Id='response-copy' ChangeKey='response-change'/></t:CalendarItem></m:Items>";
        else if (LastOperation is "CreateItem" or "UpdateItem")
            payload = "<m:Items><t:CalendarItem><t:ItemId Id='updated-event' ChangeKey='updated-change'/></t:CalendarItem></m:Items>";
        else if (LastOperation == "MoveItem")
            payload = "<m:Items><t:CalendarItem><t:ItemId Id='moved-event' ChangeKey='moved-change'/></t:CalendarItem></m:Items>";
        else if (LastOperation == "CopyItem")
            payload = "<m:Items><t:CalendarItem><t:ItemId Id='copied-event' ChangeKey='copied-change'/></t:CalendarItem></m:Items>";
        else
            payload = string.Empty;
        var response = SoapResponse(LastOperation, payload);
        if (LastOperation == "GetItem")
        {
            var malformed = XDocument.Parse(response);
            var calendar = malformed.Descendants(XName.Get("CalendarItem", Types)).FirstOrDefault();
            if (itemId != "meeting-request-1" && calendar is not null)
            {
                if (OmitCalendarIsMeeting) calendar.Element(XName.Get("IsMeeting", Types))?.Remove();
                if (OmitCalendarIsOrganizer) calendar.Element(XName.Get("IsOrganizer", Types))?.Remove();
            }
            if (itemId == "meeting-request-1" && OmitMeetingRequestIsOrganizer)
                malformed.Descendants(XName.Get("MeetingRequest", Types)).Elements(XName.Get("IsOrganizer", Types)).Remove();
            response = malformed.ToString(SaveOptions.DisableFormatting);
        }
        return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(response, Encoding.UTF8, "text/xml") };
    }

    private static string SoapResponse(string operation, string payload) =>
        $"<s:Envelope xmlns:s='{Soap}' xmlns:m='{Messages}' xmlns:t='{Types}'><s:Body><m:{operation}Response>"
        + $"<m:ResponseMessages><m:{operation}ResponseMessage ResponseClass='Success'><m:ResponseCode>NoError</m:ResponseCode>{payload}</m:{operation}ResponseMessage></m:ResponseMessages>"
        + $"</m:{operation}Response></s:Body></s:Envelope>";

    private string CalendarItem(string id, string changeKey, bool longStoredRange = false) =>
        $"<t:CalendarItem><t:ItemId Id='{id}' ChangeKey='{changeKey}'/><t:Subject>Planning</t:Subject>"
        + $"<t:Body BodyType='HTML'>&lt;p&gt;Agenda&lt;/p&gt;</t:Body><t:Start>{(longStoredRange ? "2025-01-01T00:00:00Z" : "2026-10-10T05:30:00Z")}</t:Start><t:End>{(longStoredRange ? "2027-01-01T00:00:00Z" : "2026-10-10T06:30:00Z")}</t:End>"
        + "<t:StartTimeZone Id='Iran Standard Time'/><t:EndTimeZone Id='Pacific Standard Time'/><t:IsAllDayEvent>false</t:IsAllDayEvent>"
        + "<t:Location>Room 1</t:Location><t:IsMeeting>true</t:IsMeeting><t:IsOrganizer>false</t:IsOrganizer><t:IsOutOfDate>false</t:IsOutOfDate><t:IsRecurring>true</t:IsRecurring><t:IsCancelled>false</t:IsCancelled>"
        + "<t:MeetingRequestWasSent>true</t:MeetingRequestWasSent><t:IsResponseRequested>true</t:IsResponseRequested><t:AllowNewTimeProposal>false</t:AllowNewTimeProposal>"
        + "<t:CalendarItemType>RecurringMaster</t:CalendarItemType><t:UID>uid-1</t:UID><t:RecurrenceId>2026-10-10T05:30:00Z</t:RecurrenceId><t:MyResponseType>Accept</t:MyResponseType>"
        + "<t:Organizer><t:Mailbox><t:EmailAddress>organizer@example.test</t:EmailAddress></t:Mailbox></t:Organizer>"
        + "<t:RequiredAttendees><t:Attendee><t:Mailbox><t:EmailAddress>to@example.test</t:EmailAddress></t:Mailbox><t:ResponseType>Accept</t:ResponseType><t:LastResponseTime>2026-10-09T10:00:00Z</t:LastResponseTime></t:Attendee></t:RequiredAttendees>"
        + "<t:ReminderIsSet>false</t:ReminderIsSet><t:Importance>High</t:Importance><t:Categories><t:String>work</t:String></t:Categories><t:Sensitivity>Normal</t:Sensitivity><t:LegacyFreeBusyStatus>Busy</t:LegacyFreeBusyStatus>"
        + "<t:ParentFolderId Id='calendar' ChangeKey='folder-change'/><t:AppointmentReplyTime>2026-10-09T12:00:00Z</t:AppointmentReplyTime><t:AppointmentSequenceNumber>7</t:AppointmentSequenceNumber><t:AppointmentState>3</t:AppointmentState>"
        + $"<t:Recurrence><t:WeeklyRecurrence><t:Interval>1</t:Interval><t:DaysOfWeek>Saturday</t:DaysOfWeek><t:FirstDayOfWeek>Saturday</t:FirstDayOfWeek></t:WeeklyRecurrence>{(UseEndDateRecurrence ? $"<t:EndDateRecurrence><t:StartDate>{RecurrenceStartDate}</t:StartDate><t:EndDate>{RecurrenceEndDate}</t:EndDate></t:EndDateRecurrence>" : $"<t:NumberedRecurrence><t:StartDate>{RecurrenceStartDate}</t:StartDate><t:NumberOfOccurrences>3</t:NumberOfOccurrences></t:NumberedRecurrence>")}</t:Recurrence>"
        + "<t:FirstOccurrence><t:ItemId Id='occ-first' ChangeKey='occ-first-change'/><t:Start>2026-10-10T05:30:00Z</t:Start><t:End>2026-10-10T06:30:00Z</t:End><t:OriginalStart>2026-10-10T05:30:00Z</t:OriginalStart></t:FirstOccurrence>"
        + "<t:LastOccurrence><t:ItemId Id='occ-last' ChangeKey='occ-last-change'/><t:Start>2026-10-12T05:30:00Z</t:Start><t:End>2026-10-12T06:30:00Z</t:End><t:OriginalStart>2026-10-12T05:30:00Z</t:OriginalStart></t:LastOccurrence>"
        + "<t:ModifiedOccurrences><t:Occurrence><t:ItemId Id='occ-mod' ChangeKey='occ-mod-change'/><t:Start>2026-10-11T05:30:00Z</t:Start><t:End>2026-10-11T06:30:00Z</t:End><t:OriginalStart>2026-10-11T05:30:00Z</t:OriginalStart></t:Occurrence></t:ModifiedOccurrences>"
        + "<t:DeletedOccurrences><t:DeletedOccurrence><t:Start>2026-10-13T05:30:00Z</t:Start></t:DeletedOccurrence></t:DeletedOccurrences>"
        + "<t:ResponseObjects><t:AcceptItem/><t:DeclineItem/></t:ResponseObjects></t:CalendarItem>";

    private string MeetingRequest() => CalendarItem("meeting-request-1", "meeting-request-change")
        .Replace("<t:CalendarItem>", "<t:MeetingRequest>", StringComparison.Ordinal)
        .Replace("</t:CalendarItem>", "</t:MeetingRequest>", StringComparison.Ordinal)
        .Replace("<t:ItemId Id='meeting-request-1' ChangeKey='meeting-request-change'/>",
            "<t:ItemId Id='meeting-request-1' ChangeKey='meeting-request-change'/><t:AssociatedCalendarItemId Id='event-1' ChangeKey='event-change'/><t:ResponseType>Accept</t:ResponseType><t:From><t:Mailbox><t:EmailAddress>organizer@example.test</t:EmailAddress></t:Mailbox></t:From><t:IsOutOfDate>false</t:IsOutOfDate><t:ProposedStart>2026-10-12T09:00:00Z</t:ProposedStart><t:ProposedEnd>2026-10-12T10:00:00Z</t:ProposedEnd>", StringComparison.Ordinal);
}

internal sealed partial class CalendarPolicyRecordingHandler
{
    public string MeetingRequestChangeKey { get; set; } = "meeting-request-change";

    private string MeetingRequestMessage() =>
        $"<m:Items><t:MeetingRequest><t:ItemId Id='meeting-request-1' ChangeKey='{MeetingRequestChangeKey}'/>"
        + "<t:Subject>Planning request</t:Subject><t:Body BodyType='Text'>Please join.</t:Body>"
        + "<t:Start>2026-10-10T05:30:00Z</t:Start><t:End>2026-10-10T06:30:00Z</t:End>"
        + "<t:StartTimeZone Id='Iran Standard Time'/><t:EndTimeZone Id='Pacific Standard Time'/><t:IsAllDayEvent>false</t:IsAllDayEvent>"
        + "<t:Location>Room 1</t:Location><t:IsMeeting>true</t:IsMeeting><t:IsOrganizer>false</t:IsOrganizer>"
        + "<t:IsRecurring>false</t:IsRecurring><t:IsCancelled>false</t:IsCancelled><t:CalendarItemType>Single</t:CalendarItemType>"
        + "<t:Organizer><t:Mailbox><t:EmailAddress>organizer@example.test</t:EmailAddress></t:Mailbox></t:Organizer>"
        + "<t:ResponseType>Accept</t:ResponseType><t:From><t:Mailbox><t:EmailAddress>organizer@example.test</t:EmailAddress></t:Mailbox></t:From><t:IsOutOfDate>false</t:IsOutOfDate>"
        + "<t:ResponseObjects><t:AcceptItem/><t:TentativelyAcceptItem/><t:DeclineItem/></t:ResponseObjects>"
        + "<t:AssociatedCalendarItemId Id='event-1' ChangeKey='event-change'/>"
        + "<t:ProposedStart>2026-10-12T09:00:00Z</t:ProposedStart><t:ProposedEnd>2026-10-12T10:00:00Z</t:ProposedEnd>"
        + "</t:MeetingRequest></m:Items>";
}
