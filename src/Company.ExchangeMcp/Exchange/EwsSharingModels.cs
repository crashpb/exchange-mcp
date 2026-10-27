namespace Company.ExchangeMcp.Exchange;

public sealed record EwsSharingUserId(
    string? PrimarySmtpAddress,
    string? DisplayName,
    string? DistinguishedUser,
    string? ExternalUserIdentity,
    string? Sid)
{
    public string Principal => !string.IsNullOrWhiteSpace(PrimarySmtpAddress)
        ? PrimarySmtpAddress
        : !string.IsNullOrWhiteSpace(DistinguishedUser)
            ? DistinguishedUser
            : !string.IsNullOrWhiteSpace(ExternalUserIdentity)
                ? ExternalUserIdentity
                : Sid ?? string.Empty;
}

public sealed record EwsFolderPermission(
    EwsSharingUserId User,
    bool CanCreateItems,
    bool CanCreateSubFolders,
    bool IsFolderOwner,
    bool IsFolderVisible,
    bool IsFolderContact,
    string? EditItems,
    string? DeleteItems,
    string? ReadItems,
    string? PermissionLevel,
    string? CalendarPermissionLevel);

public sealed record EwsEffectiveRights(
    bool CreateAssociated,
    bool CreateContents,
    bool CreateHierarchy,
    bool Delete,
    bool Modify,
    bool Read,
    bool? ViewPrivateItems);

public sealed record EwsFolderPermissions(
    string Id,
    string ChangeKey,
    string FolderClass,
    bool IsCalendar,
    IReadOnlyList<EwsFolderPermission> Permissions,
    IReadOnlyList<string> UnknownEntries,
    EwsEffectiveRights? EffectiveRights);

public sealed record EwsDelegate(
    EwsSharingUserId User,
    string? CalendarFolderPermissionLevel,
    string? TasksFolderPermissionLevel,
    string? InboxFolderPermissionLevel,
    string? ContactsFolderPermissionLevel,
    string? NotesFolderPermissionLevel,
    string? JournalFolderPermissionLevel,
    bool? ReceiveCopiesOfMeetingMessages,
    bool? ViewPrivateItems);

public sealed record EwsDelegates(
    string? DeliverMeetingRequests,
    IReadOnlyList<EwsDelegate> Items);

public sealed record EwsDelegateInput(
    EwsSharingUserId User,
    string? CalendarFolderPermissionLevel,
    string? TasksFolderPermissionLevel,
    string? InboxFolderPermissionLevel,
    string? ContactsFolderPermissionLevel,
    string? NotesFolderPermissionLevel,
    string? JournalFolderPermissionLevel,
    bool? ReceiveCopiesOfMeetingMessages,
    bool? ViewPrivateItems);
