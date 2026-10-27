namespace Company.ExchangeMcp.Exchange;

public sealed record EwsContactEmail(string Key, string Address);

public sealed record EwsContactPhone(string Key, string Number);

public sealed record EwsContactAddress(
    string Key,
    string? Street,
    string? City,
    string? State,
    string? Country,
    string? PostalCode);

public sealed record EwsContact(
    string Id,
    string ChangeKey,
    string DisplayName,
    string? FileAs,
    string? GivenName,
    string? MiddleName,
    string? Surname,
    string? CompanyName,
    string? JobTitle,
    string? Department,
    IReadOnlyList<EwsContactEmail> EmailAddresses,
    IReadOnlyList<EwsContactPhone> PhoneNumbers,
    IReadOnlyList<EwsContactAddress> PhysicalAddresses,
    DateTimeOffset? BirthdayUtc,
    string? Notes,
    IReadOnlyList<string> Categories);

public sealed record EwsContactInput(
    string DisplayName,
    string? FileAs = null,
    string? GivenName = null,
    string? MiddleName = null,
    string? Surname = null,
    string? CompanyName = null,
    string? JobTitle = null,
    string? Department = null,
    IReadOnlyList<EwsContactEmail>? EmailAddresses = null,
    IReadOnlyList<EwsContactPhone>? PhoneNumbers = null,
    IReadOnlyList<EwsContactAddress>? PhysicalAddresses = null,
    DateTimeOffset? BirthdayUtc = null,
    string? Notes = null,
    IReadOnlyList<string>? Categories = null);

public sealed record EwsContactGroupMember(
    string? Name,
    string EmailAddress,
    string? RoutingType,
    string? MailboxType,
    string? ItemId,
    string? ServerMemberKey = null);

public sealed record EwsContactGroup(
    string Id,
    string ChangeKey,
    string DisplayName,
    IReadOnlyList<EwsContactGroupMember> Members)
{
    public bool MembersTruncated { get; init; }
}

public sealed record EwsContactGroupInput(
    string DisplayName,
    IReadOnlyList<string> Members);

public sealed record EwsDirectoryPerson(
    string? DisplayName,
    string? EmailAddress,
    string? RoutingType,
    string? CompanyName,
    string? JobTitle,
    string? Department,
    string? PhoneNumber);

public sealed record EwsTaskFolder(
    string Id,
    string ChangeKey,
    string Name,
    string FolderClass,
    int TotalCount,
    int ChildFolderCount,
    bool IsDefault = false);

public sealed record EwsContactFolder(
    string Id,
    string ChangeKey,
    string Name,
    string FolderClass,
    int TotalCount,
    int ChildFolderCount,
    bool IsDefault = false);

public sealed record EwsTaskRecurrence(
    string Pattern,
    int Interval = 1,
    IReadOnlyList<string>? DaysOfWeek = null,
    int? DayOfMonth = null,
    int? Month = null,
    DateTimeOffset? StartDateUtc = null,
    string Range = "NoEnd",
    DateTimeOffset? EndDateUtc = null,
    int? NumberOfOccurrences = null,
    string? DayOfWeekIndex = null,
    string? FirstDayOfWeek = null);

public sealed record EwsTask(
    string Id,
    string ChangeKey,
    string Subject,
    string? Body,
    string BodyType,
    DateTimeOffset? StartDateUtc,
    DateTimeOffset? DueDateUtc,
    DateTimeOffset? CompleteDateUtc,
    double PercentComplete,
    string Status,
    int Priority,
    bool ReminderIsSet,
    DateTimeOffset? ReminderDueByUtc,
    IReadOnlyList<string> Categories,
    EwsTaskRecurrence? Recurrence,
    bool IsComplete,
    bool IsRecurring,
    EwsTaskAssignmentInfo? Assignment = null,
    bool HasAttachments = false,
    IReadOnlyList<EwsAttachment>? Attachments = null,
    IReadOnlyList<EwsAttachmentContent>? AttachmentContents = null);

public sealed record EwsTaskInput(
    string Subject,
    string? Body = null,
    string BodyType = "Text",
    DateTimeOffset? StartDateUtc = null,
    DateTimeOffset? DueDateUtc = null,
    DateTimeOffset? CompleteDateUtc = null,
    double PercentComplete = 0,
    string Status = "NotStarted",
    int Priority = 0,
    bool ReminderIsSet = false,
    DateTimeOffset? ReminderDueByUtc = null,
    IReadOnlyList<string>? Categories = null,
    EwsTaskRecurrence? Recurrence = null);
