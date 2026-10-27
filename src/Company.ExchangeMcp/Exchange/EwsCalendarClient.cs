using System.Globalization;
using System.Net.Mail;
using System.Text;
using System.Xml;
using System.Xml.Linq;

namespace Company.ExchangeMcp.Exchange;

public sealed partial class EwsClient
{
    private const int MaxCalendarEvents = 100;
    private const int MaxCalendarFolders = 10_000;
    private const int MaxCalendarSearchOffset = 10_000;
    private const int MaxCalendarQueryLength = 1_024;
    private const int MaxAttendeeCount = 100;
    private static readonly HashSet<string> ValidMonthNames = new(StringComparer.Ordinal)
    {
        "January", "February", "March", "April", "May", "June",
        "July", "August", "September", "October", "November", "December"
    };
    private static readonly HashSet<string> ValidDayNames = new(StringComparer.Ordinal)
    {
        "Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday",
        "Day", "Weekday", "WeekendDay"
    };
    private static readonly HashSet<string> ValidDayOfWeekIndexes = new(StringComparer.Ordinal)
    {
        "First", "Second", "Third", "Fourth", "Last"
    };
    private static readonly HashSet<string> ValidFreeBusyViewTypes = new(StringComparer.Ordinal)
    {
        "None", "MergedOnly", "FreeBusy", "FreeBusyMerged", "Detailed", "DetailedMerged"
    };
    private static readonly HashSet<string> ValidBusyTypes = new(StringComparer.Ordinal)
    {
        "Free", "Tentative", "Busy", "OOF", "WorkingElsewhere", "NoData"
    };
    private static readonly HashSet<string> CalendarUpdateFields = new(StringComparer.Ordinal)
    {
        "Subject", "Body", "Start", "End", "StartTimeZone", "EndTimeZone", "IsAllDayEvent", "Location",
        "Sensitivity", "LegacyFreeBusyStatus", "ReminderIsSet", "ReminderMinutesBeforeStart", "RequiredAttendees",
        "OptionalAttendees", "Resources", "Categories", "Recurrence", "Importance", "IsResponseRequested",
        "AllowNewTimeProposal"
    };
    private static readonly string[] CalendarUpdateFieldOrder =
    [
        "Subject", "Body", "Start", "End", "StartTimeZone", "EndTimeZone", "IsAllDayEvent", "Location",
        "Sensitivity", "LegacyFreeBusyStatus", "ReminderIsSet", "ReminderMinutesBeforeStart", "RequiredAttendees",
        "OptionalAttendees", "Resources", "Categories", "Recurrence", "Importance", "IsResponseRequested",
        "AllowNewTimeProposal"
    ];
    private static readonly HashSet<string> Weekdays = new(StringComparer.Ordinal)
    {
        "Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"
    };

    public async Task<IReadOnlyList<EwsCalendarFolder>> ListCalendarFoldersAsync(
        string mailbox, CancellationToken cancellationToken)
    {
        var normalizedMailbox = ValidateMailbox(mailbox);
        var defaultFolder = await GetCalendarFolderAsync(normalizedMailbox, "calendar", cancellationToken)
            .ConfigureAwait(false);
        defaultFolder = defaultFolder with { IsDefault = true };
        var folders = new List<EwsCalendarFolder>();
        var offset = 0;
        var scannedFolders = 0;
        while (true)
        {
            var operation = new XElement(
                M + "FindFolder",
                new XAttribute("Traversal", "Deep"),
                new XElement(M + "FolderShape",
                    new XElement(T + "BaseShape", "AllProperties"),
                    new XElement(T + "AdditionalProperties", Field("folder:FolderClass"))),
                new XElement(M + "IndexedPageFolderView",
                    new XAttribute("MaxEntriesReturned", 1000),
                    new XAttribute("Offset", offset),
                    new XAttribute("BasePoint", "Beginning")),
                new XElement(M + "ParentFolderIds", FolderReference("msgfolderroot")));
            var document = await SendAsync(normalizedMailbox, operation, cancellationToken).ConfigureAwait(false);
            var root = RequiredElement(document, M + "RootFolder");
            var folderElements = root.Element(T + "Folders")?.Elements()
                .Where(x => x.Name.Namespace == T && x.Element(T + "FolderId") is not null)
                .ToArray() ?? Array.Empty<XElement>();
            scannedFolders += folderElements.Length;
            if (scannedFolders > MaxCalendarFolders)
                throw new InvalidOperationException("The Exchange calendar folder result exceeded the supported limit.");
            var page = folderElements
                .Select(ParseCalendarFolder)
                .Where(x => x.FolderClass.StartsWith("IPF.Appointment", StringComparison.OrdinalIgnoreCase))
                .ToArray();
            folders.AddRange(page);
            if (IncludesLastItem(root)) break;
            var nextOffset = ReadCalendarOffset(root, offset + folderElements.Length);
            if (nextOffset <= offset)
                throw new InvalidOperationException("The Exchange calendar folder result could not be paged safely.");
            offset = nextOffset;
        }

        var listedDefault = folders.FirstOrDefault(x => x.Id.Equals(defaultFolder.Id, StringComparison.Ordinal));
        folders.RemoveAll(x => x.Id.Equals(defaultFolder.Id, StringComparison.Ordinal));
        folders.Insert(0, (listedDefault ?? defaultFolder) with { IsDefault = true });
        return folders;
    }

    public async Task<EwsCalendarFolder> GetCalendarFolderAsync(
        string mailbox, string folderId, CancellationToken cancellationToken)
    {
        var normalizedMailbox = ValidateMailbox(mailbox);
        var operation = new XElement(M + "GetFolder",
            new XElement(M + "FolderShape",
                new XElement(T + "BaseShape", "AllProperties"),
                new XElement(T + "AdditionalProperties", Field("folder:FolderClass"))),
            new XElement(M + "FolderIds", CalendarFolderReference(folderId)));
        var document = await SendAsync(normalizedMailbox, operation, cancellationToken).ConfigureAwait(false);
        return ParseCalendarFolder(RequiredElement(document, T + "CalendarFolder")) with
        {
            IsDefault = folderId.Equals("calendar", StringComparison.OrdinalIgnoreCase)
        };
    }

    public async Task<EwsCalendarFolder> CreateCalendarFolderAsync(
        string mailbox, string parentFolderId, string name, CancellationToken cancellationToken)
    {
        ValidateFolderName(name);
        var operation = new XElement(M + "CreateFolder",
            new XElement(M + "ParentFolderId", CalendarFolderReference(parentFolderId)),
            new XElement(M + "Folders", new XElement(T + "CalendarFolder",
                new XElement(T + "DisplayName", name))));
        var document = await SendAsync(ValidateMailbox(mailbox), operation, cancellationToken).ConfigureAwait(false);
        var folder = RequiredElement(document, T + "CalendarFolder");
        return ParseCalendarFolder(folder);
    }

    public async Task<EwsPage<EwsCalendarEvent>> FindCalendarEventsAsync(
        string mailbox, string folderId, DateTimeOffset startUtc, DateTimeOffset endUtc,
        int limit, CancellationToken cancellationToken)
    {
        if (limit is < 1 or > MaxCalendarEvents) throw new ArgumentOutOfRangeException(nameof(limit));
        if (startUtc >= endUtc) throw new ArgumentException("The calendar date range is invalid.");
        if (endUtc - startUtc > TimeSpan.FromDays(366))
            throw new ArgumentException("A calendar view may cover at most 366 days.");
        var operation = new XElement(M + "FindItem", new XAttribute("Traversal", "Shallow"),
            CalendarShape(),
            new XElement(M + "CalendarView",
                new XAttribute("StartDate", CalendarFormatUtc(startUtc)),
                new XAttribute("EndDate", CalendarFormatUtc(endUtc)),
                new XAttribute("MaxEntriesReturned", limit)),
            new XElement(M + "ParentFolderIds", CalendarFolderReference(folderId)));
        var document = await SendAsync(ValidateMailbox(mailbox), operation, cancellationToken).ConfigureAwait(false);
        var root = RequiredElement(document, M + "RootFolder");
        var items = root.Element(T + "Items")?.Elements()
            .Where(x => x.Name == T + "CalendarItem" && x.Element(T + "ItemId") is not null)
            .Select(ParseCalendarEvent).ToArray() ?? Array.Empty<EwsCalendarEvent>();
        if (!IncludesLastItem(root))
            throw new InvalidOperationException("The Exchange calendar view was truncated. Narrow the date range or raise the limit up to 100 and retry.");
        return new EwsPage<EwsCalendarEvent>(items, null);
    }

    public async Task<EwsPage<EwsCalendarEvent>> SearchCalendarEventsAsync(
        string mailbox, string folderId, string? query, int limit, int offset,
        CancellationToken cancellationToken)
    {
        if (limit is < 1 or > MaxCalendarEvents) throw new ArgumentOutOfRangeException(nameof(limit));
        if (offset is < 0 or > MaxCalendarSearchOffset) throw new ArgumentOutOfRangeException(nameof(offset));
        if (query is not null && (query.Length > MaxCalendarQueryLength || query.Any(char.IsControl)))
            throw new ArgumentException("The calendar search query is invalid.", nameof(query));

        var operation = new XElement(M + "FindItem", new XAttribute("Traversal", "Shallow"),
            CalendarShape(),
            new XElement(M + "IndexedPageItemView",
                new XAttribute("MaxEntriesReturned", limit),
                new XAttribute("Offset", offset),
                new XAttribute("BasePoint", "Beginning")),
            new XElement(M + "ParentFolderIds", CalendarFolderReference(folderId)));
        if (!string.IsNullOrWhiteSpace(query)) operation.Add(new XElement(M + "QueryString", query));

        var document = await SendAsync(ValidateMailbox(mailbox), operation, cancellationToken).ConfigureAwait(false);
        var root = RequiredElement(document, M + "RootFolder");
        var items = root.Element(T + "Items")?.Elements()
            .Where(x => x.Name == T + "CalendarItem" && x.Element(T + "ItemId") is not null)
            .Select(ParseCalendarEvent).ToArray() ?? Array.Empty<EwsCalendarEvent>();
        return new EwsPage<EwsCalendarEvent>(items, GetNextCalendarOffset(root, offset, items.Length));
    }

    public async Task<EwsCalendarEvent> GetCalendarEventAsync(
        string mailbox, string itemId, CancellationToken cancellationToken)
    {
        var operation = new XElement(M + "GetItem", CalendarShape(),
            new XElement(M + "ItemIds", ItemReference(ValidateItemId(itemId, "event"))));
        var document = await SendAsync(ValidateMailbox(mailbox), operation, cancellationToken).ConfigureAwait(false);
        return ParseCalendarEvent(RequiredCalendarReadItem(document, "CalendarItem"));
    }

    public async Task<EwsCalendarEvent> GetRecurringMasterFromOccurrenceAsync(
        string mailbox, string occurrenceId, string occurrenceChangeKey,
        CancellationToken cancellationToken)
    {
        var normalizedOccurrenceId = ValidateItemId(occurrenceId, "calendar occurrence");
        var normalizedChangeKey = ValidateChangeKey(occurrenceChangeKey);
        var operation = new XElement(M + "GetItem", CalendarShape(),
            new XElement(M + "ItemIds",
                new XElement(T + "RecurringMasterItemId",
                    new XAttribute("OccurrenceId", normalizedOccurrenceId),
                    new XAttribute("ChangeKey", normalizedChangeKey))));
        var document = await SendAsync(ValidateMailbox(mailbox), operation, cancellationToken).ConfigureAwait(false);
        var master = ParseCalendarEvent(RequiredCalendarReadItem(document, "CalendarItem"));
        if (!master.CalendarItemType.Equals("RecurringMaster", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Exchange did not return a recurring calendar master.");
        return master;
    }

    public async Task<EwsCalendarMeetingMessage> GetCalendarMeetingMessageAsync(
        string mailbox, string messageId, CancellationToken cancellationToken)
    {
        var normalizedMailbox = ValidateMailbox(mailbox);
        var normalizedMessageId = ValidateItemId(messageId, "meeting message");
        var operation = new XElement(M + "GetItem", MeetingMessageShape(),
            new XElement(M + "ItemIds", ItemReference(normalizedMessageId)));
        var document = await SendAsync(normalizedMailbox, operation, cancellationToken).ConfigureAwait(false);
        var item = RequiredCalendarReadItem(document, "MeetingRequest", "MeetingResponse", "MeetingCancellation");
        var itemType = item.Name.LocalName;
        if (itemType is not ("MeetingRequest" or "MeetingResponse" or "MeetingCancellation"))
            throw new InvalidOperationException("Exchange returned an unsupported calendar meeting message.");

        var meeting = ParseCalendarEvent(item) with { IsMeeting = true };
        var associated = ParseOptionalItemReference(item.Element(T + "AssociatedCalendarItemId"));
        var proposedStart = ParseCalendarDate(item.Element(T + "ProposedStart")?.Value);
        var proposedEnd = ParseCalendarDate(item.Element(T + "ProposedEnd")?.Value);
        ValidateReturnedRange(proposedStart, proposedEnd, "meeting proposal");
        return new EwsCalendarMeetingMessage(
            meeting.Id, meeting.ChangeKey, itemType, meeting, associated,
            proposedStart, proposedEnd)
        {
            ResponseType = item.Element(T + "ResponseType")?.Value,
            From = item.Element(T + "From")?.Element(T + "Mailbox")?.Element(T + "EmailAddress")?.Value,
            IsOutOfDate = ReadNullableBool(item.Element(T + "IsOutOfDate"))
        };
    }

    public async Task<EwsItemRef> CreateCalendarEventAsync(
        string mailbox, string folderId, EwsCalendarEventInput input, bool sendInvitations,
        CancellationToken cancellationToken)
    {
        var calendar = BuildCalendarItem(input);
        var operation = new XElement(M + "CreateItem",
            new XAttribute("MessageDisposition", "SaveOnly"),
            new XAttribute("SendMeetingInvitations", sendInvitations ? "SendToAllAndSaveCopy" : "SendToNone"),
            new XElement(M + "SavedItemFolderId", CalendarFolderReference(folderId)),
            new XElement(M + "Items", calendar));
        var document = await SendAsync(ValidateMailbox(mailbox), operation, cancellationToken).ConfigureAwait(false);
        return ParseCalendarItemReference(document);
    }

    public async Task<EwsItemRef> UpdateCalendarEventAsync(
        string mailbox, string itemId, string changeKey, EwsCalendarEventInput input,
        bool sendUpdates, CancellationToken cancellationToken)
    {
        var normalizedItemId = ValidateItemId(itemId, "event");
        var normalizedChangeKey = ValidateChangeKey(changeKey);
        var updates = CalendarUpdates(input);
        var operation = new XElement(M + "UpdateItem",
            new XAttribute("MessageDisposition", "SaveOnly"),
            new XAttribute("SendMeetingInvitationsOrCancellations",
                sendUpdates ? "SendToAllAndSaveCopy" : "SendToNone"),
            new XAttribute("ConflictResolution", "NeverOverwrite"),
            new XElement(M + "ItemChanges",
                new XElement(T + "ItemChange", ItemReference(normalizedItemId, normalizedChangeKey), updates)));
        var document = await SendAsync(ValidateMailbox(mailbox), operation, cancellationToken).ConfigureAwait(false);
        return ParseCalendarItemReference(document);
    }

    public async Task CancelCalendarEventAsync(
        string mailbox, string itemId, string changeKey, string body, string bodyType,
        CancellationToken cancellationToken)
    {
        var normalizedMailbox = ValidateMailbox(mailbox);
        var response = new XElement(T + "CancelCalendarItem",
            new XElement(T + "ReferenceItemId",
                new XAttribute("Id", ValidateItemId(itemId, "event")),
                new XAttribute("ChangeKey", ValidateChangeKey(changeKey))),
            BuildBodyElement("NewBodyContent", body, bodyType));
        var operation = new XElement(M + "CreateItem",
            new XAttribute("MessageDisposition", "SendAndSaveCopy"),
            new XElement(M + "Items", response));
        await SendAsync(normalizedMailbox, operation, cancellationToken).ConfigureAwait(false);
    }

    public async Task<EwsItemRef> MoveCalendarEventAsync(
        string mailbox, string itemId, string changeKey, string destinationFolderId,
        CancellationToken cancellationToken)
    {
        var normalizedDestination = ValidateItemId(destinationFolderId, "destination folder");
        var operation = new XElement(M + "MoveItem",
            new XElement(M + "ToFolderId", CalendarFolderReference(normalizedDestination)),
            new XElement(M + "ItemIds", ItemReference(ValidateItemId(itemId, "event"), ValidateChangeKey(changeKey))));
        var document = await SendAsync(ValidateMailbox(mailbox), operation, cancellationToken).ConfigureAwait(false);
        return ParseCalendarItemReference(document);
    }

    public async Task<EwsItemRef> CopyCalendarEventAsync(
        string mailbox, string itemId, string changeKey, string destinationFolderId,
        CancellationToken cancellationToken)
    {
        var normalizedDestination = ValidateItemId(destinationFolderId, "destination folder");
        var operation = new XElement(M + "CopyItem",
            new XElement(M + "ToFolderId", CalendarFolderReference(normalizedDestination)),
            new XElement(M + "ItemIds", ItemReference(ValidateItemId(itemId, "event"), ValidateChangeKey(changeKey))));
        var document = await SendAsync(ValidateMailbox(mailbox), operation, cancellationToken).ConfigureAwait(false);
        return ParseCalendarItemReference(document);
    }

    public async Task DeleteCalendarEventAsync(
        string mailbox, string itemId, string changeKey, bool sendCancellations,
        CancellationToken cancellationToken)
    {
        var operation = new XElement(M + "DeleteItem",
            new XAttribute("DeleteType", "MoveToDeletedItems"),
            new XAttribute("SendMeetingCancellations",
                sendCancellations ? "SendToAllAndSaveCopy" : "SendToNone"),
            new XElement(M + "ItemIds", ItemReference(ValidateItemId(itemId, "event"), ValidateChangeKey(changeKey))));
        await SendAsync(ValidateMailbox(mailbox), operation, cancellationToken).ConfigureAwait(false);
    }

    public async Task<EwsItemRef?> RespondToMeetingAsync(
        string mailbox, string itemId, string changeKey, string response, string? body,
        CancellationToken cancellationToken, string bodyType = "Text", bool sendResponse = true,
        DateTimeOffset? proposedStart = null, DateTimeOffset? proposedEnd = null)
    {
        var elementName = response.ToLowerInvariant() switch
        {
            "accept" => "AcceptItem",
            "tentative" => "TentativelyAcceptItem",
            "decline" => "DeclineItem",
            _ => throw new ArgumentException("Response must be accept, tentative or decline.", nameof(response))
        };
        var normalizedBodyType = RichBody.NormalizeBodyType(bodyType);
        if (body is not null) _ = RichBody.Validate(body, normalizedBodyType);
        if (proposedStart is not null || proposedEnd is not null)
        {
            if (!sendResponse || proposedStart is null || proposedEnd is null
                || proposedStart >= proposedEnd || proposedEnd - proposedStart > TimeSpan.FromDays(366))
                throw new ArgumentException("A sent meeting proposal requires a positive range of at most 366 days.");
        }
        var responseItem = new XElement(T + elementName);
        if (!string.IsNullOrEmpty(body))
            responseItem.Add(BuildBodyElement("Body", body, normalizedBodyType));
        responseItem.Add(new XElement(T + "ReferenceItemId",
            new XAttribute("Id", ValidateItemId(itemId, "event")),
            new XAttribute("ChangeKey", ValidateChangeKey(changeKey))));
        if (proposedStart is not null)
        {
            responseItem.Add(new XElement(T + "ProposedStart", CalendarFormatUtc(proposedStart.Value)),
                new XElement(T + "ProposedEnd", CalendarFormatUtc(proposedEnd!.Value)));
        }
        var operation = new XElement(M + "CreateItem",
            new XAttribute("MessageDisposition", sendResponse ? "SendAndSaveCopy" : "SaveOnly"),
            new XElement(M + "Items", responseItem));
        var document = await SendAsync(ValidateMailbox(mailbox), operation, cancellationToken).ConfigureAwait(false);
        var returned = ReturnedCalendarItems(document).ToArray();
        if (returned.Length > 1) throw new InvalidOperationException("Exchange returned multiple attendee calendar items.");
        return returned.Length == 0 ? null : ParseReturnedIdentifier(
            returned[0].Element(T + "ItemId") ?? throw new InvalidOperationException("Exchange returned a calendar item without an identifier."), "response item");
    }

    public async Task<IReadOnlyList<EwsFreeBusyResult>> GetFreeBusyAsync(
        string mailbox, IReadOnlyList<string> participants, DateTimeOffset startUtc,
        DateTimeOffset endUtc, int intervalMinutes, CancellationToken cancellationToken)
    {
        if (participants.Count is < 1 or > 100 || participants.Any(x => !IsPlainMailbox(x)))
            throw new ArgumentException("Free/busy participants must be plain email addresses and at most 100.", nameof(participants));
        if (startUtc >= endUtc || endUtc - startUtc > TimeSpan.FromDays(31))
            throw new ArgumentException("The free/busy range must be positive and at most 31 days.");
        if (intervalMinutes is < 5 or > 1440) throw new ArgumentOutOfRangeException(nameof(intervalMinutes));
        var operation = new XElement(M + "GetUserAvailabilityRequest",
            AvailabilityTimeZone(),
            new XElement(M + "MailboxDataArray", participants.Select(address => new XElement(T + "MailboxData",
                new XElement(T + "Email", new XElement(T + "Address", address)),
                new XElement(T + "AttendeeType", "Required"),
                new XElement(T + "ExcludeConflicts", false)))),
            new XElement(T + "FreeBusyViewOptions",
                new XElement(T + "TimeWindow", new XElement(T + "StartTime", CalendarFormatUtc(startUtc)), new XElement(T + "EndTime", CalendarFormatUtc(endUtc))),
                new XElement(T + "MergedFreeBusyIntervalInMinutes", intervalMinutes),
                new XElement(T + "RequestedView", "DetailedMerged")));
        var document = await SendAvailabilityAsync(ValidateMailbox(mailbox), operation, participants.Count, cancellationToken).ConfigureAwait(false);
        var responses = document.Descendants(M + "FreeBusyResponse").ToArray();
        return responses.Select((response, index) =>
        {
            var view = response.Element(M + "FreeBusyView")
                ?? throw new InvalidOperationException("Exchange returned an incomplete free/busy response.");
            var viewType = view.Element(T + "FreeBusyViewType")?.Value;
            if (string.IsNullOrWhiteSpace(viewType) || !IsValidFreeBusyViewType(viewType))
                throw new InvalidOperationException("Exchange returned an incomplete free/busy view.");
            var events = view.Element(T + "CalendarEventArray")?.Elements(T + "CalendarEvent").Select(item =>
            {
                var start = ParseCalendarDate(item.Element(T + "StartTime")?.Value)
                    ?? throw new InvalidOperationException("Exchange returned a free/busy event without a start time.");
                var end = ParseCalendarDate(item.Element(T + "EndTime")?.Value)
                    ?? throw new InvalidOperationException("Exchange returned a free/busy event without an end time.");
                if (start >= end) throw new InvalidOperationException("Exchange returned an invalid free/busy event range.");
                var busyType = item.Element(T + "BusyType")?.Value;
                if (string.IsNullOrWhiteSpace(busyType) || !ValidBusyTypes.Contains(busyType))
                    throw new InvalidOperationException("Exchange returned a free/busy event without a busy type.");
                var details = item.Element(T + "CalendarEventDetails");
                return new EwsFreeBusyEvent(
                    start,
                    end,
                    busyType,
                    details?.Element(T + "Subject")?.Value,
                    details?.Element(T + "Location")?.Value);
            }).ToArray() ?? Array.Empty<EwsFreeBusyEvent>();
            return new EwsFreeBusyResult(participants[Math.Min(index, participants.Count - 1)],
                viewType, view.Element(T + "MergedFreeBusy")?.Value, events)
            { HasEventArray = view.Element(T + "CalendarEventArray") is not null };
        }).ToArray();
    }

    private static XElement CalendarShape() => new XElement(M + "ItemShape",
        new XElement(T + "BaseShape", "AllProperties"),
        new XElement(T + "BodyType", "Best"),
        new XElement(T + "AdditionalProperties",
            Field("item:Subject"), Field("item:Body"), Field("item:DateTimeReceived"),
            Field("item:Categories"), Field("item:Sensitivity"), Field("item:Importance"),
            Field("item:ParentFolderId"), Field("item:ResponseObjects"), Field("item:ReminderIsSet"),
            Field("item:ReminderMinutesBeforeStart"), Field("calendar:Start"), Field("calendar:End"),
            Field("calendar:OriginalStart"), Field("calendar:TimeZone"),
            Field("calendar:StartTimeZone"), Field("calendar:EndTimeZone"), Field("calendar:IsAllDayEvent"),
            Field("calendar:Location"), Field("calendar:IsMeeting"), Field("calendar:IsOrganizer"),
            Field("calendar:IsRecurring"), Field("calendar:IsCancelled"), Field("calendar:MeetingRequestWasSent"),
            Field("calendar:IsResponseRequested"), Field("calendar:AllowNewTimeProposal"),
            Field("calendar:CalendarItemType"),
            Field("calendar:UID"), Field("calendar:RecurrenceId"), Field("calendar:MyResponseType"),
            Field("calendar:Organizer"), Field("item:Attachments"),
            Field("calendar:RequiredAttendees"), Field("calendar:OptionalAttendees"),
            Field("calendar:Resources"), Field("calendar:Recurrence"), Field("calendar:LegacyFreeBusyStatus"),
            Field("calendar:AppointmentReplyTime"), Field("calendar:AppointmentSequenceNumber"),
            Field("calendar:AppointmentState"), Field("calendar:FirstOccurrence"), Field("calendar:LastOccurrence"),
            Field("calendar:ModifiedOccurrences"), Field("calendar:DeletedOccurrences")));

    private static XElement MeetingMessageShape() => new XElement(M + "ItemShape",
        new XElement(T + "BaseShape", "AllProperties"),
        new XElement(T + "BodyType", "Best"),
        new XElement(T + "AdditionalProperties",
            Field("item:Body"), Field("item:ResponseObjects"), Field("meeting:AssociatedCalendarItemId"),
            Field("meeting:ResponseType"), Field("meeting:IsOutOfDate")));

    private Task<XDocument> SendAvailabilityAsync(string mailbox, XElement operation,
        int expectedResponseCount, CancellationToken cancellationToken) =>
        SendAsync(mailbox, operation, cancellationToken, responseValidator: (document, _) =>
        {
            var soapBody = document.Root?.Name == Soap + "Envelope" ? document.Root.Element(Soap + "Body") : null;
            var responseArray = soapBody?.Element(M + "GetUserAvailabilityResponse")?.Element(M + "FreeBusyResponseArray");
            var responses = responseArray?.Elements(M + "FreeBusyResponse").ToArray() ?? [];
            if (soapBody?.Elements().Count() != 1 || document.Descendants(Soap + "Fault").Any()
                || responseArray is null || responses.Length != expectedResponseCount)
                throw new InvalidOperationException("Exchange returned an unsuccessful free/busy response.");
            foreach (var response in responses)
            {
                var message = response.Element(M + "ResponseMessage");
                if (message is null || !string.Equals(message.Attribute("ResponseClass")?.Value, "Success", StringComparison.Ordinal)
                    || !string.Equals(message.Element(M + "ResponseCode")?.Value, "NoError", StringComparison.Ordinal))
                    throw new InvalidOperationException("Exchange returned an unsuccessful free/busy response.");
                var viewType = response.Element(M + "FreeBusyView")?.Element(T + "FreeBusyViewType")?.Value;
                if (string.IsNullOrWhiteSpace(viewType) || !IsValidFreeBusyViewType(viewType))
                    throw new InvalidOperationException("Exchange returned an incomplete free/busy response.");
            }
        });

    public static void ValidateCalendarEventInput(EwsCalendarEventInput input)
    {
        _ = input.UpdatedFields is null ? BuildCalendarItem(input) : CalendarUpdates(input);
    }

    private static XElement BuildCalendarItem(EwsCalendarEventInput input)
    {
        ValidateCalendarInput(input);
        var startZone = ResolveTimeZone(input.TimeZone);
        var endZone = ResolveTimeZone(input.EndTimeZone ?? input.TimeZone);
        var calendar = new XElement(T + "CalendarItem",
            new XElement(T + "Subject", input.Subject),
            new XElement(T + "Sensitivity", input.Sensitivity),
            new XElement(T + "Body", new XAttribute("BodyType", input.BodyType), input.Body),
            new XElement(T + "Categories", input.Categories.Select(x => new XElement(T + "String", x))),
            new XElement(T + "Importance", input.Importance),
            new XElement(T + "ReminderIsSet", input.ReminderMinutesBeforeStart is not null),
            input.ReminderMinutesBeforeStart is null ? null : new XElement(T + "ReminderMinutesBeforeStart", input.ReminderMinutesBeforeStart.Value),
            new XElement(T + "Start", CalendarFormatUtc(input.Start)),
            new XElement(T + "End", CalendarFormatUtc(input.End)),
            new XElement(T + "IsAllDayEvent", input.IsAllDay),
            new XElement(T + "LegacyFreeBusyStatus", input.LegacyFreeBusyStatus),
            new XElement(T + "Location", input.Location ?? string.Empty),
            new XElement(T + "IsResponseRequested", input.IsResponseRequested));
        AddAttendees(calendar, "RequiredAttendees", input.RequiredAttendees);
        AddAttendees(calendar, "OptionalAttendees", input.OptionalAttendees);
        AddAttendees(calendar, "Resources", input.Resources);
        if (input.Recurrence is not null) calendar.Add(BuildRecurrence(input.Recurrence, input.Start, startZone));
        calendar.Add(new XElement(T + "StartTimeZone", new XAttribute("Id", startZone.Id)),
            new XElement(T + "EndTimeZone", new XAttribute("Id", endZone.Id)),
            new XElement(T + "AllowNewTimeProposal", input.AllowNewTimeProposal));
        return calendar;
    }

    private static XElement CalendarUpdates(EwsCalendarEventInput input)
    {
        if (input.ClearRecurrence && input.Recurrence is not null)
            throw new ArgumentException("A recurrence cannot be supplied while clearing recurrence.", nameof(input));
        if (input.ClearReminder && input.ReminderMinutesBeforeStart is not null)
            throw new ArgumentException("Reminder minutes cannot be supplied while clearing the reminder.", nameof(input));
        if (input.UpdatedFields is null)
        {
            var calendar = BuildCalendarItem(input);
            return FullCalendarUpdates(input, calendar);
        }

        foreach (var field in input.UpdatedFields)
            if (!CalendarUpdateFields.Contains(field))
                throw new ArgumentException($"Unsupported calendar update field: {field}.", nameof(input));
        var fields = input.UpdatedFields.Count == 0 ? new[] { "Subject" } : input.UpdatedFields.ToArray();
        ValidateFilteredCalendarInput(input, fields);
        var updates = new XElement(T + "Updates");
        foreach (var field in fields)
        {
            if (field == "Recurrence" && input.Recurrence is null)
            {
                if (input.ClearRecurrence)
                    updates.Add(new XElement(T + "DeleteItemField", Field("calendar:Recurrence")));
                continue;
            }
            if (field == "ReminderIsSet" && input.ClearReminder)
            {
                updates.Add(new XElement(T + "SetItemField", Field("item:ReminderIsSet"),
                    new XElement(T + "CalendarItem", new XElement(T + "ReminderIsSet", false))));
                continue;
            }
            if (field == "ReminderMinutesBeforeStart" && input.ClearReminder)
                continue;
            var uri = CalendarFieldUri(field);
            var value = CalendarUpdateValue(input, field);
            if (value is null && field is ("RequiredAttendees" or "OptionalAttendees" or "Resources"))
            {
                updates.Add(new XElement(T + "DeleteItemField", Field(uri)));
                continue;
            }
            value ??= new XElement(T + field);
            updates.Add(new XElement(T + "SetItemField", Field(uri), new XElement(T + "CalendarItem", value)));
        }
        return updates;
    }

    private static XElement FullCalendarUpdates(EwsCalendarEventInput input, XElement calendar)
    {
        var updates = new XElement(T + "Updates");
        foreach (var field in CalendarUpdateFieldOrder)
        {
            if (field == "Recurrence" && input.Recurrence is null)
            {
                if (input.ClearRecurrence) updates.Add(new XElement(T + "DeleteItemField", Field("calendar:Recurrence")));
                continue;
            }
            if (field == "ReminderIsSet" && input.ClearReminder)
            {
                updates.Add(new XElement(T + "SetItemField", Field("item:ReminderIsSet"),
                    new XElement(T + "CalendarItem", new XElement(T + "ReminderIsSet", false))));
                continue;
            }
            if (field == "ReminderMinutesBeforeStart" && (input.ReminderMinutesBeforeStart is null || input.ClearReminder)) continue;
            var uri = CalendarFieldUri(field);
            var value = calendar.Element(T + field);
            if (value is null && field is ("RequiredAttendees" or "OptionalAttendees" or "Resources"))
            {
                updates.Add(new XElement(T + "DeleteItemField", Field(uri)));
                continue;
            }
            value ??= new XElement(T + field);
            updates.Add(new XElement(T + "SetItemField", Field(uri), new XElement(T + "CalendarItem", value)));
        }
        return updates;
    }

    private static string CalendarFieldUri(string field) => field switch
    {
        "Subject" => "item:Subject",
        "Body" => "item:Body",
        "Start" => "calendar:Start",
        "End" => "calendar:End",
        "StartTimeZone" => "calendar:StartTimeZone",
        "EndTimeZone" => "calendar:EndTimeZone",
        "IsAllDayEvent" => "calendar:IsAllDayEvent",
        "Location" => "calendar:Location",
        "Sensitivity" => "item:Sensitivity",
        "LegacyFreeBusyStatus" => "calendar:LegacyFreeBusyStatus",
        "ReminderIsSet" => "item:ReminderIsSet",
        "ReminderMinutesBeforeStart" => "item:ReminderMinutesBeforeStart",
        "RequiredAttendees" => "calendar:RequiredAttendees",
        "OptionalAttendees" => "calendar:OptionalAttendees",
        "Resources" => "calendar:Resources",
        "Categories" => "item:Categories",
        "Recurrence" => "calendar:Recurrence",
        "Importance" => "item:Importance",
        "IsResponseRequested" => "calendar:IsResponseRequested",
        "AllowNewTimeProposal" => "calendar:AllowNewTimeProposal",
        _ => throw new InvalidOperationException()
    };

    private static XElement? CalendarUpdateValue(EwsCalendarEventInput input, string field)
    {
        return field switch
        {
            "Subject" => new XElement(T + "Subject", input.Subject),
            "Body" => new XElement(T + "Body", new XAttribute("BodyType", input.BodyType), input.Body),
            "Start" => new XElement(T + "Start", CalendarFormatUtc(input.Start)),
            "End" => new XElement(T + "End", CalendarFormatUtc(input.End)),
            "StartTimeZone" => new XElement(T + "StartTimeZone", new XAttribute("Id", ResolveTimeZone(input.TimeZone).Id)),
            "EndTimeZone" => new XElement(T + "EndTimeZone", new XAttribute("Id", ResolveTimeZone(input.EndTimeZone ?? input.TimeZone).Id)),
            "IsAllDayEvent" => new XElement(T + "IsAllDayEvent", input.IsAllDay),
            "Location" => new XElement(T + "Location", input.Location ?? string.Empty),
            "Sensitivity" => new XElement(T + "Sensitivity", input.Sensitivity),
            "LegacyFreeBusyStatus" => new XElement(T + "LegacyFreeBusyStatus", input.LegacyFreeBusyStatus),
            "ReminderIsSet" => new XElement(T + "ReminderIsSet", input.ReminderMinutesBeforeStart is not null),
            "ReminderMinutesBeforeStart" => input.ReminderMinutesBeforeStart is null ? null : new XElement(T + "ReminderMinutesBeforeStart", input.ReminderMinutesBeforeStart),
            "RequiredAttendees" => AttendeesValue("RequiredAttendees", input.RequiredAttendees),
            "OptionalAttendees" => AttendeesValue("OptionalAttendees", input.OptionalAttendees),
            "Resources" => AttendeesValue("Resources", input.Resources),
            "Categories" => new XElement(T + "Categories", input.Categories.Select(x => new XElement(T + "String", x))),
            "Recurrence" => input.Recurrence is null ? null : BuildRecurrence(input.Recurrence, input.Start, ResolveTimeZone(input.TimeZone)),
            "Importance" => new XElement(T + "Importance", input.Importance),
            "IsResponseRequested" => new XElement(T + "IsResponseRequested", input.IsResponseRequested),
            "AllowNewTimeProposal" => new XElement(T + "AllowNewTimeProposal", input.AllowNewTimeProposal),
            _ => throw new InvalidOperationException()
        };
    }

    private static XElement? AttendeesValue(string name, IReadOnlyList<string> attendees) =>
        attendees.Count == 0 ? null : new XElement(T + name, attendees.Select(address =>
            new XElement(T + "Attendee", new XElement(T + "Mailbox", new XElement(T + "EmailAddress", address)))));

    private static XElement BuildRecurrence(EwsCalendarRecurrence recurrence, DateTimeOffset start, TimeZoneInfo startZone)
    {
        if (string.IsNullOrWhiteSpace(recurrence.Pattern)) throw new ArgumentException("A recurrence pattern is required.");
        var patternName = recurrence.Pattern.ToLowerInvariant();
        var localStart = TimeZoneInfo.ConvertTime(start, startZone);
        var startDate = recurrence.StartDate ?? DateOnly.FromDateTime(localStart.DateTime);
        if (recurrence.Interval is < 1 or > 999) throw new ArgumentException("Recurrence interval must be 1–999.");
        if (recurrence.NoEnd && (recurrence.EndDate is not null || recurrence.NumberOfOccurrences is not null)
            || recurrence.EndDate is not null && recurrence.NumberOfOccurrences is not null
            || !recurrence.NoEnd && recurrence.EndDate is null && recurrence.NumberOfOccurrences is null)
            throw new ArgumentException("Specify exactly one recurrence range: no end, end date, or occurrence count.");
        if (recurrence.EndDate is { } recurrenceEnd && recurrenceEnd < startDate)
            throw new ArgumentException("The recurrence end date precedes its start date.");
        if (recurrence.DaysOfWeek is not null && (recurrence.DaysOfWeek.Count == 0 || recurrence.DaysOfWeek.Any(x => !ValidDayNames.Contains(x))))
            throw new ArgumentException("The recurrence days of week are invalid.");
        if (recurrence.DayOfMonth is < 1 or > 31) throw new ArgumentException("The recurrence day of month is invalid.");
        if (recurrence.NumberOfOccurrences is <= 0 or > 10000) throw new ArgumentException("The recurrence occurrence count is invalid.");
        if (recurrence.DayOfWeekIndex is not null && !ValidDayOfWeekIndexes.Contains(recurrence.DayOfWeekIndex))
            throw new ArgumentException("The recurrence day-of-week index is invalid.");
        if (recurrence.FirstDayOfWeek is not null && !Weekdays.Contains(recurrence.FirstDayOfWeek))
            throw new ArgumentException("The recurrence first day of week is invalid.");
        if ((patternName is "yearly" or "absoluteyearly" or "relativeyearly") && recurrence.Interval != 1)
            throw new ArgumentException("Exchange yearly recurrence supports only interval 1.");
        var relativeMonthly = patternName == "relativemonthly" || patternName == "monthly" && recurrence.DayOfWeekIndex is not null;
        var absoluteMonthly = patternName == "absolutemonthly" || patternName == "monthly" && recurrence.DayOfWeekIndex is null;
        var relativeYearly = patternName == "relativeyearly" || patternName == "yearly" && recurrence.DayOfWeekIndex is not null;
        var absoluteYearly = patternName == "absoluteyearly" || patternName == "yearly" && recurrence.DayOfWeekIndex is null;
        if (patternName is "daily" or "weekly" && recurrence.DayOfWeekIndex is not null)
            throw new ArgumentException("Daily and weekly recurrence cannot have a day-of-week index.");
        if ((patternName == "daily" || absoluteMonthly || absoluteYearly) && recurrence.DaysOfWeek is not null)
            throw new ArgumentException("This recurrence pattern cannot have days of week.");
        if (relativeMonthly && recurrence.DayOfWeekIndex is null
            || relativeMonthly && (recurrence.DaysOfWeek is null || recurrence.DaysOfWeek.Count != 1))
            throw new ArgumentException("Relative monthly recurrence requires exactly one day of week.");
        if (absoluteMonthly && recurrence.DayOfWeekIndex is not null)
            throw new ArgumentException("Absolute monthly recurrence cannot have a day-of-week index.");
        if (relativeYearly && recurrence.DayOfWeekIndex is null
            || relativeYearly && (recurrence.DaysOfWeek is null || recurrence.DaysOfWeek.Count != 1))
            throw new ArgumentException("Relative yearly recurrence requires exactly one day of week.");
        if (absoluteYearly && recurrence.DayOfWeekIndex is not null)
            throw new ArgumentException("Absolute yearly recurrence cannot have a day-of-week index.");
        if ((absoluteYearly || relativeYearly)
            && (recurrence.Month is null || !ValidMonthNames.Contains(recurrence.Month)))
            throw new ArgumentException("The yearly recurrence month is invalid.");
        var pattern = patternName switch
        {
            "daily" => new XElement(T + "DailyRecurrence", new XElement(T + "Interval", recurrence.Interval)),
            "weekly" => new XElement(T + "WeeklyRecurrence",
                new XElement(T + "Interval", recurrence.Interval),
                new XElement(T + "DaysOfWeek", string.Join(' ', recurrence.DaysOfWeek ?? throw new ArgumentException("Weekly recurrence requires days of week."))),
                recurrence.FirstDayOfWeek is null ? null : new XElement(T + "FirstDayOfWeek", recurrence.FirstDayOfWeek)),
            "monthly" or "absolutemonthly" or "relativemonthly" => recurrence.DayOfWeekIndex is null
                ? new XElement(T + "AbsoluteMonthlyRecurrence", new XElement(T + "Interval", recurrence.Interval), new XElement(T + "DayOfMonth", recurrence.DayOfMonth ?? localStart.Day))
                : new XElement(T + "RelativeMonthlyRecurrence", new XElement(T + "Interval", recurrence.Interval),
                    new XElement(T + "DaysOfWeek", string.Join(' ', recurrence.DaysOfWeek ?? throw new ArgumentException("Relative monthly recurrence requires days of week."))),
                    new XElement(T + "DayOfWeekIndex", recurrence.DayOfWeekIndex)),
            "yearly" or "absoluteyearly" or "relativeyearly" => recurrence.DayOfWeekIndex is null
                ? new XElement(T + "AbsoluteYearlyRecurrence", new XElement(T + "DayOfMonth", recurrence.DayOfMonth ?? localStart.Day), new XElement(T + "Month", recurrence.Month ?? CultureInfo.InvariantCulture.DateTimeFormat.GetMonthName(localStart.Month)))
                : new XElement(T + "RelativeYearlyRecurrence", new XElement(T + "DaysOfWeek", string.Join(' ', recurrence.DaysOfWeek ?? throw new ArgumentException("Relative yearly recurrence requires days of week."))),
                    new XElement(T + "DayOfWeekIndex", recurrence.DayOfWeekIndex), new XElement(T + "Month", recurrence.Month ?? CultureInfo.InvariantCulture.DateTimeFormat.GetMonthName(localStart.Month))),
            _ => throw new ArgumentException("Recurrence pattern must be daily, weekly, monthly or yearly.")
        };
        XElement range;
        if (recurrence.NoEnd) range = new XElement(T + "NoEndRecurrence", new XElement(T + "StartDate", startDate.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture)));
        else if (recurrence.NumberOfOccurrences is > 0 and <= 10000)
            range = new XElement(T + "NumberedRecurrence", new XElement(T + "StartDate", startDate.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture)), new XElement(T + "NumberOfOccurrences", recurrence.NumberOfOccurrences.Value));
        else if (recurrence.EndDate is { } end)
            range = new XElement(T + "EndDateRecurrence", new XElement(T + "StartDate", startDate.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture)), new XElement(T + "EndDate", end.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture)));
        else throw new ArgumentException("Recurrence requires noEnd, a positive numberOfOccurrences, or endDate.");
        return new XElement(T + "Recurrence", pattern, range);
    }

    private static void ValidateCalendarInput(EwsCalendarEventInput input)
    {
        ArgumentNullException.ThrowIfNull(input);
        if (input.Subject is null || input.Subject.Length > 998 || input.Subject.IndexOfAny(['\r', '\n']) >= 0)
            throw new ArgumentException("The calendar subject is invalid.", nameof(input));
        if (input.Start >= input.End || input.End - input.Start > TimeSpan.FromDays(366))
            throw new ArgumentException("The calendar event duration is invalid.", nameof(input));
        var timeZone = ResolveTimeZone(input.TimeZone);
        var endTimeZone = ResolveTimeZone(input.EndTimeZone ?? input.TimeZone);
        ArgumentNullException.ThrowIfNull(input.RequiredAttendees);
        ArgumentNullException.ThrowIfNull(input.OptionalAttendees);
        ArgumentNullException.ThrowIfNull(input.Resources);
        ArgumentNullException.ThrowIfNull(input.Categories);
        if (input.IsAllDay)
        {
            var localStart = TimeZoneInfo.ConvertTime(input.Start, timeZone);
            var localEnd = TimeZoneInfo.ConvertTime(input.End, endTimeZone);
            if (localStart.TimeOfDay != TimeSpan.Zero || localEnd.TimeOfDay != TimeSpan.Zero || localEnd.Date <= localStart.Date)
                throw new ArgumentException("All-day events must begin and end at local midnight on consecutive calendar dates.", nameof(input));
        }
        _ = RichBody.Validate(input.Body, input.BodyType);
        if (input.Location?.Length > 255 || input.Location?.Any(char.IsControl) == true)
            throw new ArgumentException("The event location is invalid.", nameof(input));
        if (input.Sensitivity is not ("Normal" or "Personal" or "Private" or "Confidential"))
            throw new ArgumentException("The sensitivity is invalid.", nameof(input));
        if (input.LegacyFreeBusyStatus is not ("Free" or "Tentative" or "Busy" or "OOF" or "WorkingElsewhere" or "NoData"))
            throw new ArgumentException("The free/busy status is invalid.", nameof(input));
        if (input.Importance is not ("Low" or "Normal" or "High"))
            throw new ArgumentException("The importance is invalid.", nameof(input));
        if (input.ReminderMinutesBeforeStart is < 0 or > 2_629_800)
            throw new ArgumentException("The reminder is outside the supported range.", nameof(input));
        var attendees = input.RequiredAttendees.Concat(input.OptionalAttendees).Concat(input.Resources).ToArray();
        if (attendees.Length > MaxAttendeeCount || attendees.Any(x => !IsPlainMailbox(x))
            || attendees.Length != attendees.Distinct(StringComparer.OrdinalIgnoreCase).Count())
            throw new ArgumentException("Attendees must be plain email addresses and at most 100 total.", nameof(input));
        if (input.Categories.Count > 100 || input.Categories.Any(x => string.IsNullOrWhiteSpace(x) || x.Length > 255 || x.Any(char.IsControl)))
            throw new ArgumentException("Categories are invalid.", nameof(input));
        if (input.ClearRecurrence && input.Recurrence is not null)
            throw new ArgumentException("A recurrence cannot be supplied while clearing recurrence.", nameof(input));
        if (input.ClearReminder && input.ReminderMinutesBeforeStart is not null)
            throw new ArgumentException("Reminder minutes cannot be supplied while clearing the reminder.", nameof(input));
        if (input.Recurrence is not null) _ = BuildRecurrence(input.Recurrence, input.Start, timeZone);
    }

    private static void ValidateFilteredCalendarInput(EwsCalendarEventInput input, IReadOnlyCollection<string> fields)
    {
        if (fields.Contains("Subject"))
            if (input.Subject is null || input.Subject.Length > 998 || input.Subject.IndexOfAny(['\r', '\n']) >= 0)
                throw new ArgumentException("The calendar subject is invalid.", nameof(input));
        if (fields.Contains("Body")) _ = RichBody.Validate(input.Body, input.BodyType);
        if (fields.Contains("Sensitivity") && input.Sensitivity is not ("Normal" or "Personal" or "Private" or "Confidential"))
            throw new ArgumentException("The sensitivity is invalid.", nameof(input));
        if (fields.Contains("LegacyFreeBusyStatus") && input.LegacyFreeBusyStatus is not ("Free" or "Tentative" or "Busy" or "OOF" or "WorkingElsewhere" or "NoData"))
            throw new ArgumentException("The free/busy status is invalid.", nameof(input));
        if (fields.Contains("Importance") && input.Importance is not ("Low" or "Normal" or "High"))
            throw new ArgumentException("The importance is invalid.", nameof(input));
        if (fields.Contains("Location") && (input.Location?.Length > 255 || input.Location?.Any(char.IsControl) == true))
            throw new ArgumentException("The event location is invalid.", nameof(input));
        if (fields.Contains("ReminderIsSet") || fields.Contains("ReminderMinutesBeforeStart"))
        {
            if (input.ReminderMinutesBeforeStart is < 0 or > 2_629_800)
                throw new ArgumentException("The reminder is outside the supported range.", nameof(input));
            if (fields.Contains("ReminderMinutesBeforeStart") && input.ReminderMinutesBeforeStart is null && !input.ClearReminder)
                throw new ArgumentException("Reminder minutes are required when that field is selected.", nameof(input));
        }
        if (fields.Contains("Categories"))
        {
            ArgumentNullException.ThrowIfNull(input.Categories);
            if (input.Categories.Count > 100 || input.Categories.Any(x => string.IsNullOrWhiteSpace(x) || x.Length > 255 || x.Any(char.IsControl)))
                throw new ArgumentException("Categories are invalid.", nameof(input));
        }
        var attendeeFields = new[] { "RequiredAttendees", "OptionalAttendees", "Resources" }.Where(fields.Contains).ToArray();
        if (attendeeFields.Length > 0)
        {
            if (fields.Contains("RequiredAttendees")) ArgumentNullException.ThrowIfNull(input.RequiredAttendees);
            if (fields.Contains("OptionalAttendees")) ArgumentNullException.ThrowIfNull(input.OptionalAttendees);
            if (fields.Contains("Resources")) ArgumentNullException.ThrowIfNull(input.Resources);
            var lists = attendeeFields.Select(field => field switch
            {
                "RequiredAttendees" => input.RequiredAttendees,
                "OptionalAttendees" => input.OptionalAttendees,
                _ => input.Resources
            }).ToArray();
            var recipients = lists.SelectMany(x => x).ToArray();
            var allRecipients = input.RequiredAttendees.Concat(input.OptionalAttendees).Concat(input.Resources).ToArray();
            if (allRecipients.Length > MaxAttendeeCount || recipients.Any(x => !IsPlainMailbox(x))
                || allRecipients.Length != allRecipients.Distinct(StringComparer.OrdinalIgnoreCase).Count())
                throw new ArgumentException("Attendees must be plain email addresses and at most 100 total.", nameof(input));
        }
        if (fields.Contains("Start") || fields.Contains("End"))
        {
            if (input.Start >= input.End || input.End - input.Start > TimeSpan.FromDays(366))
                throw new ArgumentException("The calendar event duration is invalid.", nameof(input));
            _ = ResolveTimeZone(input.TimeZone);
            _ = ResolveTimeZone(input.EndTimeZone ?? input.TimeZone);
        }
        if (fields.Contains("StartTimeZone")) _ = ResolveTimeZone(input.TimeZone);
        if (fields.Contains("EndTimeZone")) _ = ResolveTimeZone(input.EndTimeZone ?? input.TimeZone);
        if (input.IsAllDay && fields.Any(field => field is "IsAllDayEvent" or "Start" or "End" or "StartTimeZone" or "EndTimeZone"))
        {
            var startZone = ResolveTimeZone(input.TimeZone);
            var endZone = ResolveTimeZone(input.EndTimeZone ?? input.TimeZone);
            var localStart = TimeZoneInfo.ConvertTime(input.Start, startZone);
            var localEnd = TimeZoneInfo.ConvertTime(input.End, endZone);
            if (localStart.TimeOfDay != TimeSpan.Zero || localEnd.TimeOfDay != TimeSpan.Zero || localEnd.Date <= localStart.Date)
                throw new ArgumentException("All-day events must begin and end at local midnight on consecutive calendar dates.", nameof(input));
        }
        if (fields.Contains("Recurrence") && input.Recurrence is not null)
            _ = BuildRecurrence(input.Recurrence, input.Start, ResolveTimeZone(input.TimeZone));
    }

    private static TimeZoneInfo ResolveTimeZone(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > 128 || value.Any(char.IsControl))
            throw new ArgumentException("A named time zone is required.");
        var normalized = value;
        if (TimeZoneInfo.TryConvertIanaIdToWindowsId(value, out var windowsId)) normalized = windowsId;
        try { return TimeZoneInfo.FindSystemTimeZoneById(normalized); }
        catch (TimeZoneNotFoundException) { throw new ArgumentException("The named time zone is not recognized."); }
        catch (InvalidTimeZoneException) { throw new ArgumentException("The named time zone is invalid."); }
    }

    private static void AddAttendees(XElement calendar, string name, IReadOnlyList<string> attendees)
    {
        if (attendees.Count == 0) return;
        calendar.Add(new XElement(T + name, attendees.Select(address =>
            new XElement(T + "Attendee", new XElement(T + "Mailbox", new XElement(T + "EmailAddress", address))))));
    }

    private static EwsCalendarFolder ParseCalendarFolder(XElement folder)
    {
        var parsed = ParseFolder(folder);
        return new EwsCalendarFolder(parsed.Id, parsed.ChangeKey, parsed.Name,
            folder.Element(T + "FolderClass")?.Value ?? string.Empty, parsed.TotalCount, parsed.UnreadCount,
            ReadInt(folder.Element(T + "ChildFolderCount")));
    }

    private static EwsCalendarEvent ParseCalendarEvent(XElement item)
    {
        var id = item.Element(T + "ItemId") ?? throw new InvalidOperationException("Exchange returned an event without an identifier.");
        var eventId = ParseReturnedIdentifier(id, "event");
        var start = ParseCalendarDate(item.Element(T + "Start")?.Value);
        var end = ParseCalendarDate(item.Element(T + "End")?.Value);
        ValidateReturnedRange(start, end, "calendar event");
        var recurrence = ParseCalendarRecurrence(item.Element(T + "Recurrence"), start);
        var calendarItemType = item.Element(T + "CalendarItemType")?.Value ?? "Single";
        var reminderMinutes = ReadNullableIntStrict(item.Element(T + "ReminderMinutesBeforeStart"), "reminder minutes");
        if (reminderMinutes is < 0 or > 2_629_800)
            throw new InvalidOperationException("Exchange returned invalid reminder minutes.");
        var isRecurring = ReadBool(item.Element(T + "IsRecurring"))
            || calendarItemType.Equals("RecurringMaster", StringComparison.OrdinalIgnoreCase)
            || calendarItemType.Equals("Occurrence", StringComparison.OrdinalIgnoreCase)
            || calendarItemType.Equals("Exception", StringComparison.OrdinalIgnoreCase)
            || recurrence is not null;
        var parsed = new EwsCalendarEvent(
            eventId.Id,
            (string?)id.Attribute("ChangeKey") ?? string.Empty,
            item.Element(T + "Subject")?.Value ?? string.Empty,
            item.Element(T + "Body")?.Value ?? string.Empty,
            (string?)item.Element(T + "Body")?.Attribute("BodyType") ?? "Text",
            start, end,
            item.Element(T + "StartTimeZone")?.Attribute("Id")?.Value ?? item.Element(T + "TimeZone")?.Value,
            ReadBool(item.Element(T + "IsAllDayEvent")), item.Element(T + "Location")?.Value,
            item.Name == T + "CalendarItem" ? ReadRequiredCalendarBool(item, "IsMeeting") : true,
            item.Name == T + "CalendarItem" || item.Name == T + "MeetingRequest"
                ? ReadRequiredCalendarBool(item, "IsOrganizer") : ReadBool(item.Element(T + "IsOrganizer")),
            isRecurring, ReadBool(item.Element(T + "IsCancelled")),
            calendarItemType, item.Element(T + "UID")?.Value,
            ParseCalendarDate(item.Element(T + "RecurrenceId")?.Value), item.Element(T + "MyResponseType")?.Value,
            ParseAttendees(item.Element(T + "RequiredAttendees")), ParseAttendees(item.Element(T + "OptionalAttendees")),
            ParseAttendees(item.Element(T + "Resources")), recurrence,
            reminderMinutes,
            item.Element(T + "Categories")?.Elements(T + "String").Select(x => x.Value).ToArray() ?? Array.Empty<string>(),
            item.Element(T + "Sensitivity")?.Value ?? "Normal", item.Element(T + "LegacyFreeBusyStatus")?.Value ?? "Busy");
        var organizer = item.Element(T + "Organizer")?.Element(T + "Mailbox")?.Element(T + "EmailAddress")?.Value;
        var firstOccurrence = ParseOccurrence(item.Element(T + "FirstOccurrence"));
        var lastOccurrence = ParseOccurrence(item.Element(T + "LastOccurrence"));
        var modifiedOccurrences = ParseOccurrences(item.Element(T + "ModifiedOccurrences"));
        var deletedOccurrences = ParseDeletedOccurrences(item.Element(T + "DeletedOccurrences"));
        if (modifiedOccurrences.Count + deletedOccurrences.Count
            + (firstOccurrence is null ? 0 : 1) + (lastOccurrence is null ? 0 : 1) > 10_000)
            throw new InvalidOperationException("Exchange returned too many occurrence metadata entries.");
        return parsed with
        {
            EndTimeZone = item.Element(T + "EndTimeZone")?.Attribute("Id")?.Value,
            ReminderIsSet = ReadNullableBool(item.Element(T + "ReminderIsSet")),
            Importance = item.Element(T + "Importance")?.Value,
            IsResponseRequested = ReadNullableBool(item.Element(T + "IsResponseRequested")),
            AllowNewTimeProposal = ReadNullableBool(item.Element(T + "AllowNewTimeProposal")),
            MeetingRequestWasSent = ReadNullableBool(item.Element(T + "MeetingRequestWasSent")),
            ResponseObjects = ParseResponseObjects(item.Element(T + "ResponseObjects")),
            OriginalStart = ParseCalendarDate(item.Element(T + "OriginalStart")?.Value),
            ParentFolderId = ParseOptionalItemReference(item.Element(T + "ParentFolderId"))?.Id,
            AppointmentReplyTime = ParseCalendarDate(item.Element(T + "AppointmentReplyTime")?.Value),
            AppointmentSequenceNumber = ReadNullableIntStrict(item.Element(T + "AppointmentSequenceNumber"), "appointment sequence number"),
            AppointmentState = ReadNullableIntStrict(item.Element(T + "AppointmentState"), "appointment state"),
            FirstOccurrence = firstOccurrence,
            LastOccurrence = lastOccurrence,
            ModifiedOccurrences = modifiedOccurrences,
            DeletedOccurrences = deletedOccurrences,
            Organizer = string.IsNullOrWhiteSpace(organizer) ? null : organizer,
            Attachments = ParseAttachments(item.Element(T + "Attachments")),
            AttachmentNames = ParseAttachmentNames(item.Element(T + "Attachments"))
        };
    }

    private static EwsCalendarRecurrence? ParseCalendarRecurrence(XElement? element, DateTimeOffset? eventStart)
    {
        if (element is null) return null;
        var patterns = element.Elements().Where(x => x.Name.LocalName.EndsWith("Recurrence", StringComparison.Ordinal)
            && x.Name.LocalName is not "NoEndRecurrence" and not "EndDateRecurrence" and not "NumberedRecurrence").ToArray();
        if (patterns.Length != 1) throw new InvalidOperationException("Exchange returned an invalid calendar recurrence pattern.");
        var pattern = patterns[0];
        var kind = pattern.Name.LocalName switch
        {
            "DailyRecurrence" => "daily",
            "WeeklyRecurrence" => "weekly",
            "AbsoluteMonthlyRecurrence" or "RelativeMonthlyRecurrence" => "monthly",
            "AbsoluteYearlyRecurrence" or "RelativeYearlyRecurrence" => "yearly",
            _ => throw new InvalidOperationException("Exchange returned an unsupported calendar recurrence pattern.")
        };
        var days = pattern.Element(T + "DaysOfWeek")?.Value.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (days is not null && (days.Length == 0 || days.Any(day => !ValidDayNames.Contains(day))))
            throw new InvalidOperationException("Exchange returned a recurrence with an invalid day of week.");
        if (pattern.Name.LocalName is "RelativeMonthlyRecurrence" or "RelativeYearlyRecurrence"
            && (days is null || days.Length != 1))
            throw new InvalidOperationException("Exchange returned a relative recurrence with an invalid day-of-week set.");
        if (pattern.Name.LocalName is "WeeklyRecurrence" && (days is null || days.Length == 0))
            throw new InvalidOperationException("Exchange returned a weekly recurrence without days of week.");
        var firstDayOfWeek = pattern.Element(T + "FirstDayOfWeek")?.Value;
        if (firstDayOfWeek is not null && !Weekdays.Contains(firstDayOfWeek))
            throw new InvalidOperationException("Exchange returned a recurrence with an invalid first day of week.");
        var dayOfWeekIndex = pattern.Element(T + "DayOfWeekIndex")?.Value;
        if (dayOfWeekIndex is not null && !ValidDayOfWeekIndexes.Contains(dayOfWeekIndex))
            throw new InvalidOperationException("Exchange returned a recurrence with an invalid day-of-week index.");
        if (pattern.Name.LocalName is "DailyRecurrence" or "WeeklyRecurrence" && dayOfWeekIndex is not null)
            throw new InvalidOperationException("Exchange returned a recurrence with an invalid day-of-week index.");
        if (pattern.Name.LocalName is "AbsoluteMonthlyRecurrence" or "AbsoluteYearlyRecurrence" && dayOfWeekIndex is not null)
            throw new InvalidOperationException("Exchange returned an absolute recurrence with a day-of-week index.");
        if (pattern.Name.LocalName is "AbsoluteMonthlyRecurrence" or "AbsoluteYearlyRecurrence" && days is not null)
            throw new InvalidOperationException("Exchange returned an absolute recurrence with days of week.");
        if (pattern.Name.LocalName is "RelativeMonthlyRecurrence" or "RelativeYearlyRecurrence" && dayOfWeekIndex is null)
            throw new InvalidOperationException("Exchange returned a relative recurrence without a day-of-week index.");
        if (pattern.Name.LocalName is "DailyRecurrence" && days is not null
            || pattern.Name.LocalName is "WeeklyRecurrence" && days is null)
            throw new InvalidOperationException("Exchange returned an invalid recurrence day set.");
        var month = pattern.Element(T + "Month")?.Value;
        if (kind == "yearly" && (month is null || !ValidMonthNames.Contains(month)))
            throw new InvalidOperationException("Exchange returned a yearly recurrence with an invalid month.");
        var interval = kind == "yearly" ? 1 : ReadRequiredInt(pattern.Element(T + "Interval"), 1, 999, "recurrence interval");
        if (kind == "yearly" && interval != 1) throw new InvalidOperationException("Exchange returned an invalid yearly recurrence interval.");
        var dayOfMonth = ReadNullableIntStrict(pattern.Element(T + "DayOfMonth"), "recurrence day of month");
        if (dayOfMonth is < 1 or > 31) throw new InvalidOperationException("Exchange returned an invalid recurrence day of month.");
        if (pattern.Name.LocalName is "AbsoluteMonthlyRecurrence" or "AbsoluteYearlyRecurrence"
            && dayOfMonth is null)
            throw new InvalidOperationException("Exchange returned an absolute recurrence without a day of month.");
        var range = element.Elements().FirstOrDefault(x => x.Name.LocalName is "NoEndRecurrence" or "EndDateRecurrence" or "NumberedRecurrence");
        if (range is null || element.Elements().Count(x => x.Name.LocalName is "NoEndRecurrence" or "EndDateRecurrence" or "NumberedRecurrence") != 1)
            throw new InvalidOperationException("Exchange returned an invalid recurrence range.");
        var startDate = ParseDateOnly(range.Element(T + "StartDate")?.Value, "recurrence start date");
        DateOnly? endDate = range.Name.LocalName == "EndDateRecurrence" ? ParseDateOnly(range.Element(T + "EndDate")?.Value, "recurrence end date") : null;
        if (endDate is not null && endDate < startDate)
            throw new InvalidOperationException("Exchange returned a recurrence range that ends before it starts.");
        int? occurrences = range.Name.LocalName == "NumberedRecurrence"
            ? ReadRequiredInt(range.Element(T + "NumberOfOccurrences"), 1, 10_000, "recurrence occurrence count") : null;
        if (range.Name.LocalName == "NoEndRecurrence" && (endDate is not null || occurrences is not null)
            || range.Name.LocalName == "EndDateRecurrence" && (endDate is null || occurrences is not null)
            || range.Name.LocalName == "NumberedRecurrence" && (endDate is not null || occurrences is null))
            throw new InvalidOperationException("Exchange returned an inconsistent recurrence range.");
        return new EwsCalendarRecurrence(kind,
            interval, days, firstDayOfWeek,
            dayOfMonth, month,
            dayOfWeekIndex,
            endDate, occurrences, range.Name.LocalName == "NoEndRecurrence")
        { StartDate = startDate };
    }

    private static IReadOnlyList<EwsCalendarAttendee> ParseAttendees(XElement? element) =>
        element?.Elements(T + "Attendee").Select(attendee =>
        {
            var mailbox = attendee.Element(T + "Mailbox");
            return new EwsCalendarAttendee(mailbox?.Element(T + "EmailAddress")?.Value ?? "[unresolved recipient]",
                mailbox?.Element(T + "Name")?.Value, attendee.Element(T + "ResponseType")?.Value)
            {
                LastResponseTime = ParseCalendarDate(attendee.Element(T + "LastResponseTime")?.Value)
            };
        }).ToArray() ?? Array.Empty<EwsCalendarAttendee>();

    private static DateTimeOffset? ParseCalendarDate(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        if (value.Length >= 6 && (value.EndsWith('Z') || value[^6] is '+' or '-')
            && DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var parsed)) return parsed;
        throw new InvalidOperationException("Exchange returned a malformed calendar date.");
    }

    private static bool? ReadNullableBool(XElement? element)
    {
        if (element is null) return null;
        try { return XmlConvert.ToBoolean(element.Value.Trim()); }
        catch (FormatException) { throw new InvalidOperationException("Exchange returned a malformed calendar boolean."); }
    }

    private static bool ReadRequiredCalendarBool(XElement item, string field) =>
        ReadNullableBool(item.Element(T + field))
            ?? throw new InvalidOperationException($"Exchange did not return required calendar metadata: {field}.");

    private static IReadOnlyList<string> ParseResponseObjects(XElement? element) =>
        element?.Elements().Select(x => x.Name.LocalName).Where(x => !string.IsNullOrWhiteSpace(x)).ToArray()
        ?? Array.Empty<string>();

    private static EwsItemRef ParseReturnedIdentifier(XElement element, string kind)
    {
        var id = (string?)element.Attribute("Id");
        if (string.IsNullOrWhiteSpace(id) || id.Length > 4_096 || id.Any(char.IsControl))
            throw new InvalidOperationException($"Exchange returned a malformed {kind} identifier.");
        var changeKey = (string?)element.Attribute("ChangeKey") ?? string.Empty;
        if (changeKey.Length > 4_096 || changeKey.Any(char.IsControl))
            throw new InvalidOperationException($"Exchange returned a malformed {kind} change key.");
        return new EwsItemRef(id, changeKey);
    }

    private static EwsItemRef ParseCalendarItemReference(XDocument document)
    {
        var items = ReturnedCalendarItems(document).ToArray();
        if (items.Length != 1) throw new InvalidOperationException("Exchange did not return exactly one calendar item.");
        var item = items[0].Element(T + "ItemId")
            ?? throw new InvalidOperationException("Exchange returned no calendar item identifier.");
        return ParseReturnedIdentifier(item, "calendar item");
    }

    private static XElement RequiredCalendarReadItem(XDocument document, params string[] itemTypes)
    {
        var items = document.Descendants(M + "ResponseMessages").Elements(M + "GetItemResponseMessage")
            .Elements(M + "Items").Elements().ToArray();
        if (items.Length != 1 || !itemTypes.Any(type => items[0].Name == T + type))
            throw new InvalidOperationException("Exchange did not return exactly one item of the expected calendar type.");
        return items[0];
    }

    private static IEnumerable<XElement> ReturnedCalendarItems(XDocument document) => document.Descendants(M + "ResponseMessages")
        .Elements().Elements(M + "Items").Elements().Where(item => item.Name == T + "CalendarItem" || item.Name == T + "Item");

    private static EwsItemRef? ParseOptionalItemReference(XElement? element)
    {
        if (element is null) return null;
        var id = element.Name == T + "ItemId" || element.Attribute("Id") is not null
            ? element : element.Element(T + "ItemId") ?? element.Element(T + "FolderId");
        return id is null ? throw new InvalidOperationException("Exchange returned a malformed item reference.")
            : ParseReturnedIdentifier(id, "item");
    }

    private static EwsCalendarOccurrence? ParseOccurrence(XElement? element)
    {
        if (element is null) return null;
        var id = element.Element(T + "ItemId") ?? throw new InvalidOperationException("Exchange returned an occurrence without an identifier.");
        var reference = ParseReturnedIdentifier(id, "occurrence");
        var start = ParseRequiredCalendarDate(element.Element(T + "Start")?.Value, "occurrence start");
        var end = ParseRequiredCalendarDate(element.Element(T + "End")?.Value, "occurrence end");
        var originalStart = ParseRequiredCalendarDate(element.Element(T + "OriginalStart")?.Value, "occurrence original start");
        ValidateReturnedRange(start, end, "occurrence");
        return new EwsCalendarOccurrence(reference.Id, reference.ChangeKey, start, end, originalStart);
    }

    private static IReadOnlyList<EwsCalendarOccurrence> ParseOccurrences(XElement? element)
    {
        var values = element?.Elements(T + "Occurrence").ToArray() ?? Array.Empty<XElement>();
        if (values.Length > 10_000) throw new InvalidOperationException("Exchange returned too many modified occurrences.");
        return values.Select(ParseOccurrence).Where(x => x is not null).Cast<EwsCalendarOccurrence>().ToArray();
    }

    private static IReadOnlyList<DateTimeOffset> ParseDeletedOccurrences(XElement? element)
    {
        var values = element?.Elements(T + "DeletedOccurrence").ToArray() ?? Array.Empty<XElement>();
        if (values.Length > 10_000) throw new InvalidOperationException("Exchange returned too many deleted occurrences.");
        return values.Select(x => ParseRequiredCalendarDate(x.Element(T + "Start")?.Value, "deleted occurrence start")).ToArray();
    }

    private static DateTimeOffset ParseRequiredCalendarDate(string? value, string name) =>
        ParseCalendarDate(value) ?? throw new InvalidOperationException($"Exchange returned no {name}.");

    private static void ValidateReturnedRange(DateTimeOffset? start, DateTimeOffset? end, string name)
    {
        if (start is null || end is null) return;
        if (start >= end)
            throw new InvalidOperationException($"Exchange returned an invalid {name} range.");
    }

    private static DateOnly ParseDateOnly(string? value, string name)
    {
        // xs:date keeps the calendar date lexical value even when a timezone is present.
        if (value is null || value.Length < 10 || value[4] != '-' || value[7] != '-'
            || !value[..4].All(char.IsAsciiDigit) || !value[5..7].All(char.IsAsciiDigit)
            || !value[8..10].All(char.IsAsciiDigit)
            || value.Length is not (10 or 11 or 16))
            throw new InvalidOperationException($"Exchange returned a malformed {name}.");

        var suffix = value[10..];
        if (suffix.Length == 1 && suffix != "Z"
            || suffix.Length == 6 && (suffix[0] is not ('+' or '-') || suffix[3] != ':'
                || !suffix[1..3].All(char.IsAsciiDigit) || !suffix[4..6].All(char.IsAsciiDigit)))
            throw new InvalidOperationException($"Exchange returned a malformed {name}.");
        if (suffix.Length == 6
            && (int.Parse(suffix[1..3], CultureInfo.InvariantCulture) > 14
                || int.Parse(suffix[4..6], CultureInfo.InvariantCulture) > 59
                || int.Parse(suffix[1..3], CultureInfo.InvariantCulture) == 14
                    && int.Parse(suffix[4..6], CultureInfo.InvariantCulture) != 0))
            throw new InvalidOperationException($"Exchange returned a malformed {name}.");

        try
        {
            _ = XmlConvert.ToDateTime(value, XmlDateTimeSerializationMode.RoundtripKind);
            return DateOnly.FromDateTime(XmlConvert.ToDateTime(value[..10], XmlDateTimeSerializationMode.Unspecified));
        }
        catch (FormatException)
        {
            throw new InvalidOperationException($"Exchange returned a malformed {name}.");
        }
    }

    private static int ReadRequiredInt(XElement? element, int min, int max, string name)
    {
        var value = ReadNullableIntStrict(element, name);
        if (value is null || value < min || value > max)
            throw new InvalidOperationException($"Exchange returned an invalid {name}.");
        return value.Value;
    }

    private static int? ReadNullableIntStrict(XElement? element, string name)
    {
        if (element is null) return null;
        if (int.TryParse(element.Value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var value)) return value;
        throw new InvalidOperationException($"Exchange returned a malformed {name}.");
    }

    private static int ReadInt(XElement? element, int fallback) =>
        element is not null && int.TryParse(element.Value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var value)
            ? value : fallback;

    private static int? ReadIntNullable(XElement? element) =>
        element is not null && int.TryParse(element.Value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var value)
            ? value : null;

    private static int ReadCalendarOffset(XElement root, int fallback) =>
        int.TryParse((string?)root.Attribute("IndexedPagingOffset"), NumberStyles.Integer,
            CultureInfo.InvariantCulture, out var value) && value > fallback ? value : fallback;

    private static int? GetNextCalendarOffset(XElement root, int offset, int count)
    {
        if (IncludesLastItem(root)) return null;
        var next = ReadCalendarOffset(root, offset + count);
        if (next <= offset || next > MaxCalendarSearchOffset)
            throw new InvalidOperationException("The Exchange calendar search result could not be paged safely.");
        return next;
    }

    private static string CalendarFormatUtc(DateTimeOffset value) => value.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ", CultureInfo.InvariantCulture);

    private static bool IsValidFreeBusyViewType(string value) =>
        value.Split(' ', StringSplitOptions.RemoveEmptyEntries).Length > 0
        && value.Split(' ', StringSplitOptions.RemoveEmptyEntries).All(ValidFreeBusyViewTypes.Contains);

    private static bool IsPlainMailbox(string address)
    {
        if (string.IsNullOrWhiteSpace(address) || address.Length > MaxMailboxLength || address.IndexOfAny(['\r', '\n']) >= 0) return false;
        try { return new MailAddress(address).Address.Equals(address, StringComparison.OrdinalIgnoreCase); }
        catch (FormatException) { return false; }
    }

    private static XElement CalendarFolderReference(string value) =>
        value.Equals("calendar", StringComparison.OrdinalIgnoreCase)
            ? new XElement(T + "DistinguishedFolderId", new XAttribute("Id", "calendar"))
            : FolderReference(value);

    private static XElement AvailabilityTimeZone() => new XElement(T + "TimeZone",
        new XElement(T + "Bias", 0),
        new XElement(T + "StandardTime",
            new XElement(T + "Bias", 0), new XElement(T + "Time", "00:00:00"),
            new XElement(T + "DayOrder", 5), new XElement(T + "Month", 10),
            new XElement(T + "DayOfWeek", "Sunday")),
        new XElement(T + "DaylightTime",
            new XElement(T + "Bias", 0), new XElement(T + "Time", "00:00:00"),
            new XElement(T + "DayOrder", 5), new XElement(T + "Month", 3),
            new XElement(T + "DayOfWeek", "Sunday")));
}
