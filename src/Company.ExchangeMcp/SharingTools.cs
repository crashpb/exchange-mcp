using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using System.ComponentModel;
using System.Net.Http;
using Company.ExchangeMcp.Exchange;
using Company.ExchangeMcp.Security;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;

namespace Company.ExchangeMcp;

[McpServerToolType]
public sealed class SharingTools(EwsClient exchange, MailboxAccess access, MailboxHandles handles,
    AuditLog audit, CalendarActionApprovalGuard approval)
{
    [McpServerTool(Name = "sharing_get_folder_permissions", ReadOnly = true, Destructive = false, Idempotent = true, OpenWorld = false)]
    [Description("Read the selected mailbox's folder permissions and effective rights. The folder must be a distinguished folder name or a current mailbox-folder handle; Exchange identifiers are never returned.")]
    public Task<object> GetFolderPermissions(ClaimsPrincipal user, string folder, CancellationToken cancellationToken) =>
        Run(user, MailboxAccess.Read, "sharing_get_folder_permissions", async (identity, ct) =>
        {
            var current = await exchange.GetFolderPermissionsAsync(identity.Mailbox, ResolveFolder(identity, folder), ct);
            return (object)FolderView(identity, current);
        }, cancellationToken);

    [McpServerTool(Name = "sharing_set_folder_permission", ReadOnly = false, Destructive = false, Idempotent = false, OpenWorld = false)]
    [Description("Set or replace one principal's permission on a folder while preserving every other existing ACL entry. The exact current ACL and requested change require native human confirmation.")]
    public Task<object> SetFolderPermission(ClaimsPrincipal user, string folder, string principal,
        CancellationToken cancellationToken, McpServer server, RequestContext<CallToolRequestParams> context,
        string permissionLevel = "", string calendarPermissionLevel = "", string readItems = "",
        string calendarReadItems = "", bool? canCreateItems = null, bool? canCreateSubFolders = null,
        bool? isFolderVisible = null, string editItems = "", string deleteItems = "") =>
        Run(user, MailboxAccess.Manage, "sharing_set_folder_permission", async (identity, ct) =>
        {
            ValidatePermissionLevel(permissionLevel, calendarPermissionLevel, readItems, calendarReadItems,
                editItems, deleteItems);
            var customFields = HasCustomPermissionFields(readItems, calendarReadItems, canCreateItems,
                canCreateSubFolders, isFolderVisible, editItems, deleteItems);
            if (customFields && (IsNamedPermissionLevel(permissionLevel)
                || IsNamedPermissionLevel(calendarPermissionLevel)))
                throw new McpException("Choose a named permission level or individual permission fields, not both.");
            ValidatePrincipal(principal);
            var folderId = ResolveFolder(identity, folder);
            var current = await exchange.GetFolderPermissionsAsync(identity.Mailbox, folderId, ct);
            if (current.IsCalendar
                    ? !string.IsNullOrWhiteSpace(permissionLevel) || !string.IsNullOrWhiteSpace(readItems)
                    : !string.IsNullOrWhiteSpace(calendarPermissionLevel) || !string.IsNullOrWhiteSpace(calendarReadItems))
                throw new McpException("The supplied permission fields do not match the folder type.");
            var updated = ApplyPermission(current, principal, permissionLevel, calendarPermissionLevel,
                readItems, calendarReadItems, canCreateItems, canCreateSubFolders, isFolderVisible,
                editItems, deleteItems, customFields);
            var digest = Digest(current, new
            {
                action = "set",
                principal,
                permissionLevel,
                calendarPermissionLevel,
                readItems,
                calendarReadItems,
                canCreateItems,
                canCreateSubFolders,
                isFolderVisible,
                editItems,
                deleteItems
            });
            var snapshotFingerprint = SnapshotDigest(current);
            var effectivePermission = updated.Permissions.FirstOrDefault(x => PrincipalEquals(x.User.Principal, principal));
            if (effectivePermission is null)
                throw new McpException("The requested permission could not be represented in the resulting ACL.");
            var result = await ConfirmFolderChangeAsync(identity, current, updated, "sharing_set_folder_permission",
                snapshotFingerprint, digest, $"Change folder permissions for {principal}?\nFolder type: {current.FolderClass}\n"
                + $"Effective permission: {(current.IsCalendar ? effectivePermission.CalendarPermissionLevel : effectivePermission.PermissionLevel) ?? "(none)"}\n"
                + $"Read access: {effectivePermission.ReadItems ?? "(none)"}\n"
                + $"Create items: {effectivePermission.CanCreateItems}; create subfolders: {effectivePermission.CanCreateSubFolders}\n"
                + $"Folder owner: {effectivePermission.IsFolderOwner}; folder contact: {effectivePermission.IsFolderContact}\n"
                + $"Visible: {effectivePermission.IsFolderVisible}; edit: {effectivePermission.EditItems ?? "(none)"}; delete: {effectivePermission.DeleteItems ?? "(none)"}",
                server, context, ct);
            return result;
        }, cancellationToken);

    [McpServerTool(Name = "sharing_remove_folder_permission", ReadOnly = false, Destructive = true, Idempotent = false, OpenWorld = false)]
    [Description("Remove one principal from a folder ACL while preserving every other existing entry. The exact current ACL requires native human confirmation.")]
    public Task<object> RemoveFolderPermission(ClaimsPrincipal user, string folder, string principal,
        McpServer server, RequestContext<CallToolRequestParams> context, CancellationToken cancellationToken) =>
        Run(user, MailboxAccess.Manage, "sharing_remove_folder_permission", async (identity, ct) =>
        {
            ValidatePrincipal(principal);
            var folderId = ResolveFolder(identity, folder);
            var current = await exchange.GetFolderPermissionsAsync(identity.Mailbox, folderId, ct);
            var existing = current.Permissions.FirstOrDefault(x => PrincipalEquals(x.User.Principal, principal));
            if (existing is null) throw new McpException("That principal has no explicit permission on this folder.");
            if (existing.IsFolderOwner) throw new McpException("The folder owner cannot be removed.");
            var updated = current with
            {
                Permissions = current.Permissions.Where(x => !PrincipalEquals(x.User.Principal, principal)).ToArray()
            };
            var snapshotFingerprint = SnapshotDigest(current);
            var digest = Digest(current, new { action = "remove", principal });
            return await ConfirmFolderChangeAsync(identity, current, updated, "sharing_remove_folder_permission",
                snapshotFingerprint, digest, $"Remove {principal} from the {current.FolderClass} folder ACL?", server, context, ct);
        }, cancellationToken);

    [McpServerTool(Name = "delegate_list", ReadOnly = true, Destructive = false, Idempotent = true, OpenWorld = false)]
    [Description("List delegates and the meeting-request delivery setting for the selected mailbox.")]
    public Task<object> ListDelegates(ClaimsPrincipal user, CancellationToken cancellationToken) =>
        Run(user, MailboxAccess.Read, "delegate_list", async (identity, ct) =>
        {
            var delegates = await ReadDelegatesAsync(identity.Mailbox, ct);
            return (object)new
            {
                deliverMeetingRequests = delegates.DeliverMeetingRequests,
                items = delegates.Items.Select(DelegateView).ToArray()
            };
        }, cancellationToken);

    [McpServerTool(Name = "delegate_add", ReadOnly = false, Destructive = false, Idempotent = false, OpenWorld = false)]
    [Description("Add one mailbox delegate with optional folder permissions. This also grants Send on Behalf access; viewPrivateItems applies across all mailbox folders. The exact current list and grant require native human confirmation.")]
    public Task<object> AddDelegate(ClaimsPrincipal user, string principal, CancellationToken cancellationToken,
        McpServer server, RequestContext<CallToolRequestParams> context,
        string? calendarPermissionLevel = null, string? tasksPermissionLevel = null,
        string? inboxPermissionLevel = null, string? contactsPermissionLevel = null,
        string? notesPermissionLevel = null, string? journalPermissionLevel = null,
        bool? receiveCopiesOfMeetingMessages = null, bool? viewPrivateItems = null,
        string? deliverMeetingRequests = null) =>
        Run(user, MailboxAccess.Manage, "delegate_add", async (identity, ct) =>
        {
            ValidateDelegatePrincipal(principal);
            var requestedDelivery = NormalizeOptional(deliverMeetingRequests);
            ValidateDelegateLevels(calendarPermissionLevel, tasksPermissionLevel, inboxPermissionLevel,
                contactsPermissionLevel, notesPermissionLevel, journalPermissionLevel, requestedDelivery);
            var current = await ReadDelegatesAsync(identity.Mailbox, ct);
            EnsureUniqueDelegates(current.Items);
            if (FindDelegate(current.Items, principal) is not null)
                throw new McpException("That mailbox delegate already exists; use delegate_update.");
            var input = NewDelegateInput(principal, calendarPermissionLevel, tasksPermissionLevel,
                inboxPermissionLevel, contactsPermissionLevel, notesPermissionLevel, journalPermissionLevel,
                receiveCopiesOfMeetingMessages, viewPrivateItems);
            input = WithSafeDelegateDefaults(input);
            var effectiveDelivery = ResolveDelivery(requestedDelivery, current.DeliverMeetingRequests);
            ValidatePreservedDelivery(effectiveDelivery);
            var digest = Digest(current, new
            {
                action = "add",
                input,
                requestedDelivery,
                effectiveDelivery
            });
            var expected = AddExpectedDelegate(current, input, effectiveDelivery);
            var snapshotFingerprint = SnapshotDigest(current);
            var state = await ConfirmDelegateAsync(identity, current, principal, "delegate_add", digest,
                snapshotFingerprint,
                $"Add {principal} as an Exchange delegate. This also grants Send on Behalf access.\n"
                + DelegatePermissionPreview(input)
                + "Other delegate entries are preserved.\n"
                + $"Meeting request delivery: {DeliveryPreview(requestedDelivery, effectiveDelivery, current.DeliverMeetingRequests)}",
                server, context, ct);
            if (state is null) return new { status = "cancelled", changed = false };
            var result = await ApplyDelegateMutationAsync(
                () => exchange.AddDelegateAsync(identity.Mailbox, input, effectiveDelivery, ct), "add", principal);
            var added = VerifyDelegateMutation(expected, result, "add", principal)
                ?? throw DelegateVerificationFailed("add", principal, "readback state mismatch");
            approval.CompleteVerified(state);
            return (object)new { status = "delegate_added", delegateItem = DelegateView(added), deliverMeetingRequests = result.DeliverMeetingRequests };
        }, cancellationToken);

    [McpServerTool(Name = "delegate_update", ReadOnly = false, Destructive = false, Idempotent = false, OpenWorld = false)]
    [Description("Update one existing mailbox delegate. Omitted values preserve current state; viewPrivateItems applies across all mailbox folders, and Send on Behalf access remains. The exact current list and change require native human confirmation.")]
    public Task<object> UpdateDelegate(ClaimsPrincipal user, string principal, CancellationToken cancellationToken,
        McpServer server, RequestContext<CallToolRequestParams> context,
        string? calendarPermissionLevel = null, string? tasksPermissionLevel = null,
        string? inboxPermissionLevel = null, string? contactsPermissionLevel = null,
        string? notesPermissionLevel = null, string? journalPermissionLevel = null,
        bool? receiveCopiesOfMeetingMessages = null, bool? viewPrivateItems = null,
        string? deliverMeetingRequests = null) =>
        Run(user, MailboxAccess.Manage, "delegate_update", async (identity, ct) =>
        {
            ValidateDelegatePrincipal(principal);
            var requestedDelivery = NormalizeOptional(deliverMeetingRequests);
            ValidateDelegateLevels(calendarPermissionLevel, tasksPermissionLevel, inboxPermissionLevel,
                contactsPermissionLevel, notesPermissionLevel, journalPermissionLevel, requestedDelivery);
            var current = await ReadDelegatesAsync(identity.Mailbox, ct);
            EnsureUniqueDelegates(current.Items);
            var existing = FindDelegate(current.Items, principal);
            if (existing is null) throw new McpException("That mailbox delegate does not exist; use delegate_add.");
            var input = MergeDelegate(existing, calendarPermissionLevel, tasksPermissionLevel,
                inboxPermissionLevel, contactsPermissionLevel, notesPermissionLevel, journalPermissionLevel,
                receiveCopiesOfMeetingMessages, viewPrivateItems);
            var effectiveDelivery = ResolveDelivery(requestedDelivery, current.DeliverMeetingRequests);
            ValidatePreservedDelivery(effectiveDelivery);
            var digest = Digest(current, new
            {
                action = "update",
                input,
                requestedDelivery,
                effectiveDelivery
            });
            var expected = ReplaceExpectedDelegate(current, input, effectiveDelivery);
            var state = await ConfirmDelegateAsync(identity, current, principal, "delegate_update", digest,
                SnapshotDigest(current),
                $"Update the existing Exchange delegate {principal}; its Send on Behalf access remains.\n"
                + DelegatePermissionPreview(input)
                + "Other delegate entries are preserved.\n"
                + $"Meeting request delivery: {DeliveryPreview(requestedDelivery, effectiveDelivery, current.DeliverMeetingRequests)}",
                server, context, ct);
            if (state is null) return new { status = "cancelled", changed = false };
            var result = await ApplyDelegateMutationAsync(
                () => exchange.UpdateDelegateAsync(identity.Mailbox, input, effectiveDelivery, ct), "update", principal);
            var updated = VerifyDelegateMutation(expected, result, "update", principal)
                ?? throw DelegateVerificationFailed("update", principal, "readback state mismatch");
            approval.CompleteVerified(state);
            return (object)new { status = "delegate_updated", delegateItem = DelegateView(updated), deliverMeetingRequests = result.DeliverMeetingRequests };
        }, cancellationToken);

    [McpServerTool(Name = "delegate_remove", ReadOnly = false, Destructive = true, Idempotent = false, OpenWorld = false)]
    [Description("Remove one mailbox delegate and its associated Send on Behalf access. The exact current delegate list requires native human confirmation.")]
    public Task<object> RemoveDelegate(ClaimsPrincipal user, string principal, CancellationToken cancellationToken,
        McpServer server, RequestContext<CallToolRequestParams> context) =>
        Run(user, MailboxAccess.Manage, "delegate_remove", async (identity, ct) =>
        {
            ValidateDelegatePrincipal(principal);
            var current = await ReadDelegatesAsync(identity.Mailbox, ct);
            EnsureUniqueDelegates(current.Items);
            var existing = FindDelegate(current.Items, principal);
            if (existing is null)
                throw new McpException("That mailbox delegate does not exist.");
            var digest = Digest(current, new { action = "remove", principal });
            var expected = RemoveExpectedDelegate(current, principal);
            var state = await ConfirmDelegateAsync(identity, current, principal, "delegate_remove", digest,
                SnapshotDigest(current),
                $"Remove {principal}'s Exchange delegate entry and its associated Send on Behalf access.\n"
                + DelegatePermissionPreview(DelegateInput(existing))
                + $"Meeting request delivery: {current.DeliverMeetingRequests ?? "(Exchange returned no setting)"} (preserved)\n"
                + "Other delegate entries are preserved.",
                server, context, ct);
            if (state is null) return new { status = "cancelled", changed = false };
            var result = await ApplyDelegateMutationAsync(
                () => exchange.RemoveDelegateAsync(identity.Mailbox, principal, ct), "remove", principal);
            _ = VerifyDelegateMutation(expected, result, "remove", principal);
            approval.CompleteVerified(state);
            return (object)new { status = "delegate_removed", principal, deliverMeetingRequests = result.DeliverMeetingRequests };
        }, cancellationToken);

    private async Task<object> ConfirmFolderChangeAsync(MailboxIdentity identity, EwsFolderPermissions current,
        EwsFolderPermissions updated, string action, string snapshotFingerprint, string digest, string preview, McpServer server,
        RequestContext<CallToolRequestParams> context, CancellationToken cancellationToken)
    {
        CalendarActionApproval state;
        if (context.Params?.RequestState is null)
        {
            if (context.Params?.InputResponses is not null) throw new McpException("A valid sharing approval state is required.");
            approval.RequestApproval(identity, action, current.Id, current.ChangeKey, digest, preview, server, context, "sharing_confirmation");
        }
        state = approval.ReadApproval(identity, action, current.Id, context);
        var latest = await exchange.GetFolderPermissionsAsync(identity.Mailbox, current.Id, cancellationToken);
        if (!string.Equals(state.ChangeKey, latest.ChangeKey, StringComparison.Ordinal)
            || !string.Equals(SnapshotDigest(latest), snapshotFingerprint, StringComparison.Ordinal)
            || !string.Equals(state.Digest, digest, StringComparison.Ordinal))
            throw new McpException("The folder ACL changed after approval. Refresh it and try again.");
        if (!CalendarActionApprovalGuard.Accepted(context, "sharing_confirmation"))
        {
            approval.Cancel(state);
            return new { status = "cancelled", changed = false };
        }
        approval.Consume(state, latest.Id, latest.ChangeKey, digest);
        var result = await exchange.UpdateFolderPermissionsAsync(identity.Mailbox, latest.Id, latest.ChangeKey,
            updated, cancellationToken);
        return new
        {
            status = "folder_permissions_updated",
            folder = handles.Issue(identity, "folder", result.Id, result.ChangeKey),
            permissions = result.Permissions.Select(PermissionView).ToArray()
        };
    }

    private async Task<CalendarActionApproval?> ConfirmDelegateAsync(MailboxIdentity identity, EwsDelegates current,
        string principal, string action, string digest, string snapshotFingerprint, string preview, McpServer server,
        RequestContext<CallToolRequestParams> context, CancellationToken cancellationToken)
    {
        CalendarActionApproval state;
        var target = principal.Trim();
        if (context.Params?.RequestState is null)
        {
            if (context.Params?.InputResponses is not null) throw new McpException("A valid sharing approval state is required.");
            approval.RequestApproval(identity, action, target, string.Empty, digest, preview, server, context, "sharing_confirmation");
        }
        state = approval.ReadApproval(identity, action, target, context);
        var latest = await ReadDelegatesAsync(identity.Mailbox, cancellationToken);
        if (!string.Equals(SnapshotDigest(latest), snapshotFingerprint, StringComparison.Ordinal)
            || !string.Equals(state.Digest, digest, StringComparison.Ordinal))
            throw new McpException("The delegate list changed after approval. Refresh it and try again.");
        if (!CalendarActionApprovalGuard.Accepted(context, "sharing_confirmation"))
        {
            approval.Cancel(state);
            return null;
        }
        approval.Consume(state, target, string.Empty, digest);
        return state;
    }

    private async Task<EwsDelegates> ReadDelegatesAsync(string mailbox, CancellationToken cancellationToken)
    {
        try
        {
            return await exchange.GetDelegatesAsync(mailbox, cancellationToken).ConfigureAwait(false);
        }
        catch (EwsPermissionDeniedException exception) when (exception.Operation == "GetDelegate")
        {
            throw new McpException($"{exception.Message} No delegate change was attempted.");
        }
        catch (EwsRequestFailedException exception) when (exception.Operation == "GetDelegate"
            && exception.ResponseCode is not null)
        {
            throw new McpException($"Exchange refused the delegate-list read ({exception.ResponseCode}). No delegate change was attempted.");
        }
    }

    private static EwsFolderPermissions ApplyPermission(EwsFolderPermissions current, string principal,
        string permissionLevel, string calendarPermissionLevel, string readItems, string calendarReadItems,
        bool? canCreateItems, bool? canCreateSubFolders, bool? isFolderVisible, string editItems, string deleteItems,
        bool customFields)
    {
        var requestedLevel = NullIfEmpty(current.IsCalendar ? calendarPermissionLevel : permissionLevel);
        var existing = current.Permissions.FirstOrDefault(x => PrincipalEquals(x.User.Principal, principal));
        if (existing is null)
        {
            if (requestedLevel is null)
                throw new McpException("A permission level is required when adding a new principal.");
            var user = PrincipalUser(principal);
            var added = new EwsFolderPermission(user, canCreateItems ?? false, canCreateSubFolders ?? false,
                false, isFolderVisible ?? true, false, NullIfEmpty(editItems), NullIfEmpty(deleteItems),
                current.IsCalendar ? NullIfEmpty(calendarReadItems) : NullIfEmpty(readItems),
                current.IsCalendar ? null : requestedLevel,
                current.IsCalendar ? requestedLevel : null);
            if (requestedLevel != "Custom") added = WithNamedPermissionDefaults(added, current.IsCalendar, requestedLevel);
            return current with { Permissions = current.Permissions.Append(added).ToArray() };
        }
        if (existing.IsFolderOwner && requestedLevel is not null
            && requestedLevel is not "Owner" and not "Custom")
            throw new McpException("The folder owner permission cannot be downgraded.");
        var currentLevel = current.IsCalendar ? existing.CalendarPermissionLevel : existing.PermissionLevel;
        var replacementLevel = requestedLevel ?? (customFields ? "Custom" : currentLevel);
        var replacement = existing with
        {
            CanCreateItems = canCreateItems ?? existing.CanCreateItems,
            CanCreateSubFolders = canCreateSubFolders ?? existing.CanCreateSubFolders,
            IsFolderVisible = isFolderVisible ?? existing.IsFolderVisible,
            EditItems = string.IsNullOrWhiteSpace(editItems) ? existing.EditItems : editItems,
            DeleteItems = string.IsNullOrWhiteSpace(deleteItems) ? existing.DeleteItems : deleteItems,
            ReadItems = current.IsCalendar
                ? (string.IsNullOrWhiteSpace(calendarReadItems) ? existing.ReadItems : calendarReadItems)
                : (string.IsNullOrWhiteSpace(readItems) ? existing.ReadItems : readItems),
            PermissionLevel = current.IsCalendar ? existing.PermissionLevel : replacementLevel,
            CalendarPermissionLevel = current.IsCalendar ? replacementLevel : existing.CalendarPermissionLevel
        };
        if (requestedLevel is not null && requestedLevel != "Custom")
            replacement = WithNamedPermissionDefaults(replacement, current.IsCalendar, requestedLevel);
        if (replacement == existing) return current;
        return current with { Permissions = current.Permissions.Select(x => ReferenceEquals(x, existing) ? replacement : x).ToArray() };
    }

    private static EwsFolderPermission WithNamedPermissionDefaults(EwsFolderPermission permission, bool isCalendar,
        string level)
    {
        (bool CreateItems, bool CreateSubFolders, bool FolderOwner, bool FolderVisible, bool FolderContact,
            string EditItems, string DeleteItems, string ReadItems) defaults = level switch
            {
                "None" => (false, false, false, false, false, "None", "None", "None"),
                "Owner" => (true, true, true, true, true, "All", "All", "FullDetails"),
                "PublishingEditor" => (true, true, false, true, false, "All", "All", "FullDetails"),
                "Editor" => (true, false, false, true, false, "All", "All", "FullDetails"),
                "PublishingAuthor" => (true, true, false, true, false, "Owned", "Owned", "FullDetails"),
                "Author" => (true, false, false, true, false, "Owned", "Owned", "FullDetails"),
                "NoneditingAuthor" => (true, false, false, true, false, "None", "Owned", "FullDetails"),
                "Reviewer" => (false, false, false, true, false, "None", "None", "FullDetails"),
                "Contributor" => (true, false, false, true, false, "None", "None", "None"),
                "FreeBusyTimeOnly" => (false, false, false, false, false, "None", "None", "TimeOnly"),
                "FreeBusyTimeAndSubjectAndLocation" =>
                    (false, false, false, false, false, "None", "None", "TimeAndSubjectAndLocation"),
                _ => throw new InvalidOperationException("The folder permission level is not supported.")
            };
        return permission with
        {
            CanCreateItems = defaults.CreateItems,
            CanCreateSubFolders = defaults.CreateSubFolders,
            IsFolderOwner = defaults.FolderOwner,
            IsFolderVisible = defaults.FolderVisible,
            IsFolderContact = defaults.FolderContact,
            EditItems = defaults.EditItems,
            DeleteItems = defaults.DeleteItems,
            ReadItems = defaults.ReadItems,
            PermissionLevel = isCalendar ? permission.PermissionLevel : level,
            CalendarPermissionLevel = isCalendar ? level : permission.CalendarPermissionLevel
        };
    }

    private static EwsDelegateInput NewDelegateInput(string principal, string? calendar, string? tasks, string? inbox,
        string? contacts, string? notes, string? journal, bool? copies, bool? privateItems) =>
        new(PrincipalUser(principal), NormalizeOptional(calendar), NormalizeOptional(tasks), NormalizeOptional(inbox),
            NormalizeOptional(contacts), NormalizeOptional(notes), NormalizeOptional(journal), copies, privateItems);

    private static EwsDelegateInput WithSafeDelegateDefaults(EwsDelegateInput input) =>
        input with
        {
            CalendarFolderPermissionLevel = input.CalendarFolderPermissionLevel ?? "None",
            TasksFolderPermissionLevel = input.TasksFolderPermissionLevel ?? "None",
            InboxFolderPermissionLevel = input.InboxFolderPermissionLevel ?? "None",
            ContactsFolderPermissionLevel = input.ContactsFolderPermissionLevel ?? "None",
            NotesFolderPermissionLevel = input.NotesFolderPermissionLevel ?? "None",
            JournalFolderPermissionLevel = input.JournalFolderPermissionLevel ?? "None",
            ReceiveCopiesOfMeetingMessages = input.ReceiveCopiesOfMeetingMessages ?? false,
            ViewPrivateItems = input.ViewPrivateItems ?? false
        };

    private static string DelegatePermissionPreview(EwsDelegateInput input) =>
        $"Calendar: {input.CalendarFolderPermissionLevel ?? "None"}; tasks: {input.TasksFolderPermissionLevel ?? "None"}; inbox: {input.InboxFolderPermissionLevel ?? "None"}\n"
        + $"Contacts: {input.ContactsFolderPermissionLevel ?? "None"}; notes: {input.NotesFolderPermissionLevel ?? "None"}; journal: {input.JournalFolderPermissionLevel ?? "None"}\n"
        + $"Receive meeting copies: {input.ReceiveCopiesOfMeetingMessages?.ToString() ?? "preserve current"}\n"
        + $"View private items: {input.ViewPrivateItems?.ToString() ?? "preserve current"} (applies across all mailbox folders)\n";

    private static string DeliveryPreview(string? requested, string? effective, string? current) =>
        requested is null
            ? $"{effective ?? "(Exchange returned no setting)"} (preserved)"
            : string.Equals(effective, current, StringComparison.Ordinal)
                ? $"{effective} (unchanged)"
                : $"{effective} (changed)";

    private static void ValidatePreservedDelivery(string? value)
    {
        if (value is not null && value is not ("DelegatesOnly" or "DelegatesAndMe"
            or "DelegatesAndSendInformationToMe" or "NoForward"))
            throw new McpException("Exchange returned an unsupported meeting delivery setting; refusing to change it.");
    }

    private static string ResolveDelivery(string? requested, string? current)
    {
        if (requested is not null) return requested;
        if (current is null)
            throw new McpException("Exchange did not report the current meeting-request delivery setting. Supply deliverMeetingRequests before adding or updating a delegate.");
        return current;
    }

    private static void EnsureUniqueDelegates(IReadOnlyList<EwsDelegate> items)
    {
        var principals = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (items.Any(item => string.IsNullOrWhiteSpace(item.User.Principal)
            || !principals.Add(item.User.Principal)))
            throw new McpException("Exchange returned an ambiguous delegate list; refresh it before changing access.");
    }

    private static EwsDelegate? FindDelegate(IReadOnlyList<EwsDelegate> items, string principal) =>
        items.SingleOrDefault(item => PrincipalEquals(item.User.Principal, principal));

    private static EwsDelegates AddExpectedDelegate(EwsDelegates current, EwsDelegateInput input, string? delivery) =>
        current with
        {
            DeliverMeetingRequests = delivery,
            Items = current.Items.Append(DelegateState(input)).ToArray()
        };

    private static EwsDelegates ReplaceExpectedDelegate(EwsDelegates current, EwsDelegateInput input, string? delivery) =>
        current with
        {
            DeliverMeetingRequests = delivery,
            Items = current.Items.Select(item => PrincipalEquals(item.User.Principal, input.User.Principal)
                ? DelegateState(input) : item).ToArray()
        };

    private static EwsDelegates RemoveExpectedDelegate(EwsDelegates current, string principal) =>
        current with { Items = current.Items.Where(item => !PrincipalEquals(item.User.Principal, principal)).ToArray() };

    private static EwsDelegate DelegateState(EwsDelegateInput input) =>
        new(input.User, input.CalendarFolderPermissionLevel, input.TasksFolderPermissionLevel,
            input.InboxFolderPermissionLevel, input.ContactsFolderPermissionLevel, input.NotesFolderPermissionLevel,
            input.JournalFolderPermissionLevel, input.ReceiveCopiesOfMeetingMessages, input.ViewPrivateItems);

    private static EwsDelegateInput DelegateInput(EwsDelegate item) =>
        new(item.User, item.CalendarFolderPermissionLevel, item.TasksFolderPermissionLevel,
            item.InboxFolderPermissionLevel, item.ContactsFolderPermissionLevel, item.NotesFolderPermissionLevel,
            item.JournalFolderPermissionLevel, item.ReceiveCopiesOfMeetingMessages, item.ViewPrivateItems);

    private static EwsDelegate? VerifyDelegateMutation(EwsDelegates expected, EwsDelegates actual,
        string action, string principal)
    {
        if (expected.DeliverMeetingRequests != actual.DeliverMeetingRequests
            || expected.Items.Count != actual.Items.Count)
            throw DelegateVerificationFailed(action, principal, "readback state mismatch");

        var actualPrincipals = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var item in actual.Items)
        {
            if (string.IsNullOrWhiteSpace(item.User.Principal) || !actualPrincipals.Add(item.User.Principal))
                throw DelegateVerificationFailed(action, principal, "readback state mismatch");
        }

        foreach (var wanted in expected.Items)
        {
            var observed = FindDelegate(actual.Items, wanted.User.Principal);
            if (observed is null || !DelegateSettingsEqual(wanted, observed))
                throw DelegateVerificationFailed(action, principal, "readback state mismatch");
        }

        return FindDelegate(actual.Items, principal);
    }

    private static bool DelegateSettingsEqual(EwsDelegate expected, EwsDelegate actual) =>
        EffectivePermission(expected.CalendarFolderPermissionLevel) == EffectivePermission(actual.CalendarFolderPermissionLevel)
        && EffectivePermission(expected.TasksFolderPermissionLevel) == EffectivePermission(actual.TasksFolderPermissionLevel)
        && EffectivePermission(expected.InboxFolderPermissionLevel) == EffectivePermission(actual.InboxFolderPermissionLevel)
        && EffectivePermission(expected.ContactsFolderPermissionLevel) == EffectivePermission(actual.ContactsFolderPermissionLevel)
        && EffectivePermission(expected.NotesFolderPermissionLevel) == EffectivePermission(actual.NotesFolderPermissionLevel)
        && EffectivePermission(expected.JournalFolderPermissionLevel) == EffectivePermission(actual.JournalFolderPermissionLevel)
        && (expected.ReceiveCopiesOfMeetingMessages ?? false) == (actual.ReceiveCopiesOfMeetingMessages ?? false)
        && (expected.ViewPrivateItems ?? false) == (actual.ViewPrivateItems ?? false);

    private static string EffectivePermission(string? permission) => permission ?? "None";

    private static McpException DelegateVerificationFailed(string action, string principal, string evidence) =>
        new($"Exchange did not confirm the complete reviewed delegate state after {action} for {principal} ({evidence}). The change may have been applied. Call delegate_list to reconcile before retrying.");

    private static async Task<EwsDelegates> ApplyDelegateMutationAsync(Func<Task<EwsDelegates>> mutation,
        string action, string principal)
    {
        try
        {
            return await mutation().ConfigureAwait(false);
        }
        catch (EwsPermissionDeniedException exception) when (exception.Operation != "GetDelegate")
        {
            throw;
        }
        catch (EwsRequestFailedException exception) when (exception.Operation != "GetDelegate")
        {
            throw new McpException(exception.Message);
        }
        catch (EwsPermissionDeniedException exception) when (exception.Operation == "GetDelegate")
        {
            throw DelegateVerificationFailed(action, principal, $"GetDelegate denied ({exception.ResponseCode})");
        }
        catch (EwsRequestFailedException exception) when (exception.Operation == "GetDelegate")
        {
            var evidence = exception.ResponseCode is { } responseCode
                ? $"GetDelegate failed ({responseCode})"
                : "GetDelegate response was invalid or unavailable";
            throw DelegateVerificationFailed(action, principal, evidence);
        }
        catch (HttpRequestException)
        {
            throw DelegateVerificationFailed(action, principal, "Exchange response was unavailable");
        }
        catch (Exception exception) when (exception is not OutOfMemoryException and not StackOverflowException)
        {
            throw DelegateVerificationFailed(action, principal, "Exchange response was invalid or unavailable");
        }
    }

    private static EwsDelegateInput MergeDelegate(EwsDelegate existing, string? calendar, string? tasks, string? inbox,
        string? contacts, string? notes, string? journal, bool? copies, bool? privateItems) =>
        new(existing.User, NormalizeOptional(calendar) ?? existing.CalendarFolderPermissionLevel,
            NormalizeOptional(tasks) ?? existing.TasksFolderPermissionLevel,
            NormalizeOptional(inbox) ?? existing.InboxFolderPermissionLevel,
            NormalizeOptional(contacts) ?? existing.ContactsFolderPermissionLevel,
            NormalizeOptional(notes) ?? existing.NotesFolderPermissionLevel,
            NormalizeOptional(journal) ?? existing.JournalFolderPermissionLevel,
            copies ?? existing.ReceiveCopiesOfMeetingMessages, privateItems ?? existing.ViewPrivateItems);

    private static string? NormalizeOptional(string? value) =>
        string.IsNullOrWhiteSpace(value) ? null : value;

    private object FolderView(MailboxIdentity identity, EwsFolderPermissions folder) => new
    {
        folderHandle = handles.Issue(identity, "folder", folder.Id, folder.ChangeKey),
        folderClass = folder.FolderClass,
        isCalendar = folder.IsCalendar,
        permissions = folder.Permissions.Select(PermissionView).ToArray(),
        effectiveRights = folder.EffectiveRights,
        unknownEntryCount = folder.UnknownEntries.Count
    };

    private static object PermissionView(EwsFolderPermission permission) => new
    {
        principal = permission.User.Principal,
        displayName = permission.User.DisplayName,
        canCreateItems = permission.CanCreateItems,
        canCreateSubFolders = permission.CanCreateSubFolders,
        isFolderOwner = permission.IsFolderOwner,
        isFolderVisible = permission.IsFolderVisible,
        isFolderContact = permission.IsFolderContact,
        editItems = permission.EditItems,
        deleteItems = permission.DeleteItems,
        readItems = permission.ReadItems,
        permissionLevel = permission.PermissionLevel,
        calendarPermissionLevel = permission.CalendarPermissionLevel
    };

    private static object DelegateView(EwsDelegate item) => new
    {
        principal = item.User.Principal,
        displayName = item.User.DisplayName,
        calendarPermissionLevel = item.CalendarFolderPermissionLevel,
        tasksPermissionLevel = item.TasksFolderPermissionLevel,
        inboxPermissionLevel = item.InboxFolderPermissionLevel,
        contactsPermissionLevel = item.ContactsFolderPermissionLevel,
        notesPermissionLevel = item.NotesFolderPermissionLevel,
        journalPermissionLevel = item.JournalFolderPermissionLevel,
        receiveCopiesOfMeetingMessages = item.ReceiveCopiesOfMeetingMessages,
        viewPrivateItems = item.ViewPrivateItems
    };

    private string ResolveFolder(MailboxIdentity identity, string folder) => folder.ToLowerInvariant() switch
    {
        "calendar" or "contacts" or "tasks" or "inbox" or "drafts" or "sentitems" or "deleteditems" or "msgfolderroot" => folder.ToLowerInvariant(),
        _ => ResolveFolderHandle(identity, folder)
    };

    private string ResolveFolderHandle(MailboxIdentity identity, string value)
    {
        foreach (var kind in new[] { "folder", "calendar-folder", "contactfolder", "taskfolder" })
        {
            try { return handles.Resolve(identity, kind, value).Id; }
            catch (McpException) { }
        }
        throw new McpException("Invalid or expired folder handle. Refresh the folder and try again.");
    }

    private void ValidatePrincipal(string principal)
    {
        if (string.Equals(principal, "Default", StringComparison.OrdinalIgnoreCase)
            || string.Equals(principal, "Anonymous", StringComparison.OrdinalIgnoreCase)) return;
        access.ValidateRecipients([principal]);
    }

    private void ValidateDelegatePrincipal(string principal)
    {
        if (string.Equals(principal, "Default", StringComparison.OrdinalIgnoreCase)
            || string.Equals(principal, "Anonymous", StringComparison.OrdinalIgnoreCase))
            throw new McpException("Default and Anonymous cannot be mailbox delegate addresses.");
        access.ValidateRecipients([principal]);
    }

    private static EwsSharingUserId PrincipalUser(string principal) =>
        string.Equals(principal, "Default", StringComparison.OrdinalIgnoreCase)
            ? new EwsSharingUserId(null, null, "Default", null, null)
            : string.Equals(principal, "Anonymous", StringComparison.OrdinalIgnoreCase)
                ? new EwsSharingUserId(null, null, "Anonymous", null, null)
                : new EwsSharingUserId(principal, null, null, null, null);

    private static bool PrincipalEquals(string left, string right) =>
        string.Equals(left, right, StringComparison.OrdinalIgnoreCase);

    private static string? NullIfEmpty(string value) => string.IsNullOrWhiteSpace(value) ? null : value;

    private static bool HasCustomPermissionFields(string readItems, string calendarReadItems,
        bool? canCreateItems, bool? canCreateSubFolders, bool? isFolderVisible, string editItems, string deleteItems) =>
        !string.IsNullOrWhiteSpace(readItems) || !string.IsNullOrWhiteSpace(calendarReadItems)
        || canCreateItems.HasValue || canCreateSubFolders.HasValue || isFolderVisible.HasValue
        || !string.IsNullOrWhiteSpace(editItems) || !string.IsNullOrWhiteSpace(deleteItems);

    private static bool IsNamedPermissionLevel(string level) =>
        !string.IsNullOrWhiteSpace(level) && level != "Custom";

    private static void ValidatePermissionLevel(string permissionLevel, string calendarPermissionLevel,
        string readItems, string calendarReadItems, string editItems, string deleteItems)
    {
        ValidateValue(permissionLevel, ["None", "Owner", "PublishingEditor", "Editor", "PublishingAuthor", "Author", "NoneditingAuthor", "Reviewer", "Contributor", "Custom"]);
        ValidateValue(calendarPermissionLevel, ["None", "Owner", "PublishingEditor", "Editor", "PublishingAuthor", "Author", "NoneditingAuthor", "Reviewer", "Contributor", "FreeBusyTimeOnly", "FreeBusyTimeAndSubjectAndLocation", "Custom"]);
        ValidateValue(readItems, ["None", "FullDetails"]);
        ValidateValue(calendarReadItems, ["None", "TimeOnly", "TimeAndSubjectAndLocation", "FullDetails"]);
        ValidateValue(editItems, ["None", "Owned", "All"]);
        ValidateValue(deleteItems, ["None", "Owned", "All"]);
    }

    private static void ValidateDelegateLevels(string? calendar, string? tasks, string? inbox, string? contacts,
        string? notes, string? journal, string? deliver)
    {
        foreach (var value in new[] { calendar, tasks, inbox, contacts, notes, journal })
            ValidateValue(value, ["None", "Editor", "Reviewer", "Author", "Custom"]);
        ValidateValue(deliver, ["DelegatesOnly", "DelegatesAndMe", "DelegatesAndSendInformationToMe", "NoForward"]);
    }

    private static void ValidateValue(string? value, IEnumerable<string> allowed)
    {
        if (!string.IsNullOrWhiteSpace(value) && !allowed.Contains(value, StringComparer.Ordinal))
            throw new McpException("A supplied sharing permission value is not supported by Exchange.");
    }

    private static string Digest(object snapshot, object request) => Convert.ToHexString(SHA256.HashData(
        JsonSerializer.SerializeToUtf8Bytes(new { snapshot, request })));

    private static string SnapshotDigest(object snapshot) => Convert.ToHexString(SHA256.HashData(
        JsonSerializer.SerializeToUtf8Bytes(snapshot)));

    private async Task<T> Run<T>(ClaimsPrincipal user, string scope, string operation,
        Func<MailboxIdentity, CancellationToken, Task<T>> action, CancellationToken cancellationToken)
    {
        var identity = access.Require(user, scope);
        var operationId = Guid.NewGuid().ToString("N");
        await audit.RecordAsync(identity, operation, "started", operationId, cancellationToken);
        T result;
        try { result = await action(identity, cancellationToken); }
        catch (InputRequiredException)
        {
            await audit.RecordAsync(identity, operation, "approval_required", operationId, CancellationToken.None);
            throw;
        }
        catch
        {
            await audit.RecordAsync(identity, operation, "failed_or_uncertain", operationId, CancellationToken.None);
            throw;
        }
        try { await audit.RecordAsync(identity, operation, "completed", operationId, CancellationToken.None); }
        catch { throw new McpException("The operation completed but audit recording failed. Do not repeat it; contact the administrator."); }
        return result;
    }
}
