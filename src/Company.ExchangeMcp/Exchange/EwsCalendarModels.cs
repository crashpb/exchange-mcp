namespace Company.ExchangeMcp.Exchange;

public sealed record EwsCalendarFolder(
    string Id,
    string ChangeKey,
    string Name,
    string FolderClass,
    int TotalCount,
    int UnreadCount,
    int ChildFolderCount = 0,
    bool IsDefault = false);

public sealed record EwsCalendarAttendee(
    string Address,
    string? Name,
    string? ResponseType)
{
    public DateTimeOffset? LastResponseTime { get; init; }
}

public sealed record EwsCalendarRecurrence(
    string Pattern,
    int Interval = 1,
    IReadOnlyList<string>? DaysOfWeek = null,
    string? FirstDayOfWeek = null,
    int? DayOfMonth = null,
    string? Month = null,
    string? DayOfWeekIndex = null,
    DateOnly? EndDate = null,
    int? NumberOfOccurrences = null,
    bool NoEnd = false)
{
    public DateOnly? StartDate { get; init; }
}

public sealed record EwsCalendarEventInput(
    string Subject,
    string Body,
    string BodyType,
    DateTimeOffset Start,
    DateTimeOffset End,
    string TimeZone,
    bool IsAllDay,
    string? Location,
    IReadOnlyList<string> RequiredAttendees,
    IReadOnlyList<string> OptionalAttendees,
    IReadOnlyList<string> Resources,
    EwsCalendarRecurrence? Recurrence,
    int? ReminderMinutesBeforeStart,
    IReadOnlyList<string> Categories,
    string Sensitivity,
    string LegacyFreeBusyStatus,
    bool ClearRecurrence = false,
    bool ClearReminder = false)
{
    public string? EndTimeZone { get; init; }
    public string Importance { get; init; } = "Normal";
    public bool IsResponseRequested { get; init; } = true;
    public bool AllowNewTimeProposal { get; init; } = true;
    public IReadOnlySet<string>? UpdatedFields { get; init; }
}

public sealed record EwsCalendarEvent(
    string Id,
    string ChangeKey,
    string Subject,
    string Body,
    string BodyType,
    DateTimeOffset? Start,
    DateTimeOffset? End,
    string? TimeZone,
    bool IsAllDay,
    string? Location,
    bool IsMeeting,
    bool IsOrganizer,
    bool IsRecurring,
    bool IsCancelled,
    string CalendarItemType,
    string? Uid,
    DateTimeOffset? RecurrenceId,
    string? MyResponseType,
    IReadOnlyList<EwsCalendarAttendee> RequiredAttendees,
    IReadOnlyList<EwsCalendarAttendee> OptionalAttendees,
    IReadOnlyList<EwsCalendarAttendee> Resources,
    EwsCalendarRecurrence? Recurrence,
    int? ReminderMinutesBeforeStart,
    IReadOnlyList<string> Categories,
    string Sensitivity,
    string LegacyFreeBusyStatus)
{
    public string? EndTimeZone { get; init; }
    public bool? ReminderIsSet { get; init; }
    public string? Importance { get; init; }
    public bool? IsResponseRequested { get; init; }
    public bool? AllowNewTimeProposal { get; init; }
    public bool? MeetingRequestWasSent { get; init; }
    public IReadOnlyList<string> ResponseObjects { get; init; } = Array.Empty<string>();
    public DateTimeOffset? OriginalStart { get; init; }
    public string? ParentFolderId { get; init; }
    public DateTimeOffset? AppointmentReplyTime { get; init; }
    public int? AppointmentSequenceNumber { get; init; }
    public int? AppointmentState { get; init; }
    public EwsCalendarOccurrence? FirstOccurrence { get; init; }
    public EwsCalendarOccurrence? LastOccurrence { get; init; }
    public IReadOnlyList<EwsCalendarOccurrence> ModifiedOccurrences { get; init; } = Array.Empty<EwsCalendarOccurrence>();
    public IReadOnlyList<DateTimeOffset> DeletedOccurrences { get; init; } = Array.Empty<DateTimeOffset>();
    public string? Organizer { get; init; }
    public IReadOnlyList<EwsAttachment> Attachments { get; init; } = Array.Empty<EwsAttachment>();
    public IReadOnlyList<string> AttachmentNames { get; init; } = Array.Empty<string>();
}

public sealed record EwsCalendarOccurrence(
    string Id,
    string ChangeKey,
    DateTimeOffset Start,
    DateTimeOffset End,
    DateTimeOffset OriginalStart);

public sealed record EwsCalendarMeetingMessage(
    string Id,
    string ChangeKey,
    string ItemType,
    EwsCalendarEvent Meeting,
    EwsItemRef? AssociatedCalendarItem,
    DateTimeOffset? ProposedStart,
    DateTimeOffset? ProposedEnd)
{
    public string? ResponseType { get; init; }
    public string? From { get; init; }
    public bool? IsOutOfDate { get; init; }
}

public sealed record EwsFreeBusyEvent(
    DateTimeOffset Start,
    DateTimeOffset End,
    string BusyType,
    string? Subject,
    string? Location);

public sealed record EwsFreeBusyResult(
    string Mailbox,
    string ViewType,
    string? MergedFreeBusy,
    IReadOnlyList<EwsFreeBusyEvent> Events)
{
    public bool HasEventArray { get; init; } = true;
}
