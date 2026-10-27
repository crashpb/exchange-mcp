using System.Globalization;
using System.Net.Mail;
using System.Xml.Linq;

namespace Company.ExchangeMcp.Exchange;

public sealed partial class EwsClient
{
    public async Task<EwsFolderPermissions> GetFolderPermissionsAsync(
        string mailbox, string folderId, CancellationToken cancellationToken)
    {
        var normalizedMailbox = ValidateMailbox(mailbox);
        var normalizedFolder = ValidateSharingFolderId(folderId);
        var operation = new XElement(M + "GetFolder",
            new XElement(M + "FolderShape",
                new XElement(T + "BaseShape", "Default"),
                new XElement(T + "AdditionalProperties",
                    Field("folder:PermissionSet"), Field("folder:EffectiveRights"), Field("folder:FolderClass"))),
            new XElement(M + "FolderIds", SharingFolderReference(normalizedFolder)));
        var document = await SendAsync(normalizedMailbox, operation, cancellationToken).ConfigureAwait(false);
        return ParseFolderPermissions(RequiredSharingFolder(document));
    }

    public async Task<EwsFolderPermissions> UpdateFolderPermissionsAsync(
        string mailbox, string folderId, string changeKey, EwsFolderPermissions permissions,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(permissions);
        var normalizedMailbox = ValidateMailbox(mailbox);
        var normalizedFolder = ValidateSharingFolderId(folderId);
        var normalizedChangeKey = ValidateChangeKey(changeKey);
        if (!string.Equals(permissions.Id, normalizedFolder, StringComparison.Ordinal)
            || !string.Equals(permissions.ChangeKey, normalizedChangeKey, StringComparison.Ordinal))
            throw new ArgumentException("The folder permission snapshot is stale.", nameof(permissions));
        EnsureUniquePermissionPrincipals(permissions.Permissions);
        var folder = new XElement(T + (permissions.IsCalendar ? "CalendarFolder" : "Folder"),
            BuildPermissionSet(permissions));
        var operation = new XElement(M + "UpdateFolder",
            new XElement(M + "FolderChanges",
                new XElement(T + "FolderChange",
                    new XElement(T + "FolderId", new XAttribute("Id", normalizedFolder),
                        new XAttribute("ChangeKey", normalizedChangeKey)),
                    new XElement(T + "Updates",
                        new XElement(T + "SetFolderField", Field("folder:PermissionSet"), folder)))));
        // Re-read because Exchange 2019 may return only Id and ChangeKey here.
        _ = await SendAsync(normalizedMailbox, operation, cancellationToken).ConfigureAwait(false);
        return await GetFolderPermissionsAsync(normalizedMailbox, normalizedFolder, cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task<EwsDelegates> GetDelegatesAsync(string mailbox, CancellationToken cancellationToken)
    {
        var normalizedMailbox = ValidateMailbox(mailbox);
        var operation = new XElement(M + "GetDelegate",
            new XAttribute("IncludePermissions", "true"),
            new XElement(M + "Mailbox", new XElement(T + "EmailAddress", normalizedMailbox)));
        var document = await SendAsync(normalizedMailbox, operation, cancellationToken,
            responseValidator: ValidateDelegateChildResponses).ConfigureAwait(false);
        var deliver = document.Descendants(M + "DeliverMeetingRequests").FirstOrDefault()?.Value;
        var responseMessages = document.Root?.Element(Soap + "Body")?.Element(M + "GetDelegateResponse")
            ?.Element(M + "ResponseMessages")?.Elements(M + "DelegateUserResponseMessageType")
            ?? Enumerable.Empty<XElement>();
        var delegates = responseMessages
            .Select(message => message.Element(M + "DelegateUser")
                ?? throw new InvalidOperationException("Exchange returned a delegate response without a delegate user."))
            .Select(ParseDelegate)
            .ToArray();
        return new EwsDelegates(deliver, delegates);
    }

    public async Task<EwsDelegates> AddDelegateAsync(
        string mailbox, EwsDelegateInput input, string? deliverMeetingRequests,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(input);
        var normalizedMailbox = ValidateMailbox(mailbox);
        var operation = new XElement(M + "AddDelegate",
            new XElement(M + "Mailbox", new XElement(T + "EmailAddress", normalizedMailbox)),
            new XElement(M + "DelegateUsers", BuildDelegateUser(input)),
            BuildDeliverMeetingRequests(deliverMeetingRequests));
        var document = await SendAsync(normalizedMailbox, operation, cancellationToken,
            responseValidator: ValidateDelegateChildResponses).ConfigureAwait(false);
        return await GetDelegatesAfterMutationAsync(normalizedMailbox, cancellationToken).ConfigureAwait(false);
    }

    public async Task<EwsDelegates> UpdateDelegateAsync(
        string mailbox, EwsDelegateInput input, string? deliverMeetingRequests,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(input);
        var normalizedMailbox = ValidateMailbox(mailbox);
        var operation = new XElement(M + "UpdateDelegate",
            new XElement(M + "Mailbox", new XElement(T + "EmailAddress", normalizedMailbox)),
            new XElement(M + "DelegateUsers", BuildDelegateUser(input)),
            BuildDeliverMeetingRequests(deliverMeetingRequests));
        var document = await SendAsync(normalizedMailbox, operation, cancellationToken,
            responseValidator: ValidateDelegateChildResponses).ConfigureAwait(false);
        return await GetDelegatesAfterMutationAsync(normalizedMailbox, cancellationToken).ConfigureAwait(false);
    }

    public async Task<EwsDelegates> RemoveDelegateAsync(
        string mailbox, string principal, CancellationToken cancellationToken)
    {
        var normalizedMailbox = ValidateMailbox(mailbox);
        var user = BuildSharingUserId(principal);
        var operation = new XElement(M + "RemoveDelegate",
            new XElement(M + "Mailbox", new XElement(T + "EmailAddress", normalizedMailbox)),
            new XElement(M + "UserIds", BuildUserId(user)));
        var document = await SendAsync(normalizedMailbox, operation, cancellationToken,
            responseValidator: ValidateDelegateChildResponses).ConfigureAwait(false);
        return await GetDelegatesAfterMutationAsync(normalizedMailbox, cancellationToken).ConfigureAwait(false);
    }

    private async Task<EwsDelegates> GetDelegatesAfterMutationAsync(string mailbox, CancellationToken cancellationToken)
    {
        try
        {
            return await GetDelegatesAsync(mailbox, cancellationToken).ConfigureAwait(false);
        }
        catch (EwsRequestFailedException exception) when (exception.Operation == "GetDelegate"
            && exception.ResponseCode is "ErrorInternalServerTransientError" or "ErrorDelegateMissingConfiguration")
        {
            var retryDelay = exception.ResponseCode == "ErrorDelegateMissingConfiguration"
                ? TimeSpan.FromSeconds(5)
                : TimeSpan.FromMilliseconds(250);
            await Task.Delay(retryDelay, cancellationToken).ConfigureAwait(false);
            return await GetDelegatesAsync(mailbox, cancellationToken).ConfigureAwait(false);
        }
    }

    private static EwsFolderPermissions ParseFolderPermissions(XElement folder)
    {
        ValidateFolderElement(folder);
        var id = RequireSingleElement(folder, T + "FolderId", "folder identifier");
        var folderId = (string?)id.Attribute("Id");
        if (string.IsNullOrWhiteSpace(folderId))
            throw new InvalidOperationException("Exchange returned a folder without an identifier.");
        var changeKey = (string?)id.Attribute("ChangeKey") ?? string.Empty;
        if (string.IsNullOrWhiteSpace(changeKey))
            throw new InvalidOperationException("Exchange returned a folder without a change key.");
        EnsureFolderIdAttributes(id);
        var permissionSet = RequireSingleElement(folder, T + "PermissionSet", "permission set");
        ValidatePermissionSet(permissionSet, folder.Name == T + "CalendarFolder");
        var permissions = permissionSet.Element(T + "Permissions");
        var calendarPermissions = permissionSet.Element(T + "CalendarPermissions");
        var isCalendar = folder.Name == T + "CalendarFolder";
        var entries = (isCalendar ? calendarPermissions!.Elements(T + "CalendarPermission")
                                  : permissions!.Elements(T + "Permission"))
            .Select(entry => ParseFolderPermission(entry, isCalendar))
            .ToArray();
        var unknown = permissionSet.Element(T + "UnknownEntries")?.Elements(T + "UnknownEntry")
            .Select(x => x.Value)
            .ToArray() ?? Array.Empty<string>();
        var rights = ParseEffectiveRights(folder.Element(T + "EffectiveRights"));
        return new EwsFolderPermissions(folderId, changeKey, folder.Element(T + "FolderClass")?.Value ?? string.Empty,
            isCalendar, entries, unknown, rights);
    }

    private static EwsFolderPermission ParseFolderPermission(XElement element, bool isCalendar)
    {
        var levelName = T + (isCalendar ? "CalendarPermissionLevel" : "PermissionLevel");
        var allowed = new[]
        {
            T + "UserId", T + "CanCreateItems", T + "CanCreateSubFolders", T + "IsFolderOwner",
            T + "IsFolderVisible", T + "IsFolderContact", T + "EditItems", T + "DeleteItems", T + "ReadItems", levelName
        };
        EnsureAllowedChildren(element, allowed, "folder permission");
        EnsureNoDuplicateScalars(element, allowed);
        var userId = RequireSingleElement(element, T + "UserId", "permission user");
        var level = RequireSingleElement(element, levelName, "permission level").Value;
        if (string.IsNullOrWhiteSpace(level))
            throw new InvalidOperationException("Exchange returned a folder permission with an empty permission level.");
        var otherLevelName = T + (isCalendar ? "PermissionLevel" : "CalendarPermissionLevel");
        if (element.Element(otherLevelName) is not null)
            throw new InvalidOperationException("Exchange returned mixed calendar and ordinary folder permission fields.");
        var user = ParseSharingUserId(element.Element(T + "UserId"));
        return new EwsFolderPermission(user,
            ReadSharingBool(element.Element(T + "CanCreateItems")),
            ReadSharingBool(element.Element(T + "CanCreateSubFolders")),
            ReadSharingBool(element.Element(T + "IsFolderOwner")),
            ReadSharingBool(element.Element(T + "IsFolderVisible")),
            ReadSharingBool(element.Element(T + "IsFolderContact")),
            element.Element(T + "EditItems")?.Value,
            element.Element(T + "DeleteItems")?.Value,
            element.Element(T + "ReadItems")?.Value,
            isCalendar ? null : level,
            isCalendar ? level : null);
    }

    private static EwsEffectiveRights? ParseEffectiveRights(XElement? element)
    {
        if (element is null) return null;
        var allowed = new[]
        {
            T + "CreateAssociated", T + "CreateContents", T + "CreateHierarchy", T + "Delete",
            T + "Modify", T + "Read", T + "ViewPrivateItems"
        };
        EnsureAllowedChildren(element, allowed, "effective rights");
        EnsureNoDuplicateScalars(element, allowed);
        return new EwsEffectiveRights(
            ReadSharingBool(RequireSingleElement(element, T + "CreateAssociated", "effective right CreateAssociated")),
            ReadSharingBool(RequireSingleElement(element, T + "CreateContents", "effective right CreateContents")),
            ReadSharingBool(RequireSingleElement(element, T + "CreateHierarchy", "effective right CreateHierarchy")),
            ReadSharingBool(RequireSingleElement(element, T + "Delete", "effective right Delete")),
            ReadSharingBool(RequireSingleElement(element, T + "Modify", "effective right Modify")),
            ReadSharingBool(RequireSingleElement(element, T + "Read", "effective right Read")),
            ReadNullableSharingBool(element.Element(T + "ViewPrivateItems")));
    }

    private static XElement RequiredSharingFolder(XDocument document) =>
        document.Descendants().FirstOrDefault(x => x.Name == T + "Folder" || x.Name == T + "CalendarFolder"
                                                   || x.Name == T + "ContactsFolder" || x.Name == T + "TasksFolder")
        ?? throw new InvalidOperationException("Exchange returned no folder permission snapshot.");

    private static XElement BuildPermissionSet(EwsFolderPermissions permissions)
    {
        var isCalendar = permissions.IsCalendar;
        var entryName = isCalendar ? "CalendarPermission" : "Permission";
        var setName = isCalendar ? "CalendarPermissions" : "Permissions";
        var entries = permissions.Permissions.Select(permission =>
        {
            var level = isCalendar ? permission.CalendarPermissionLevel : permission.PermissionLevel;
            if (string.IsNullOrWhiteSpace(level))
                throw new InvalidOperationException("The folder permission snapshot is missing a required permission level.");
            var element = new XElement(T + entryName, BuildUserId(permission.User));
            if (level == "Custom")
            {
                element.Add(
                    new XElement(T + "CanCreateItems", permission.CanCreateItems),
                    new XElement(T + "CanCreateSubFolders", permission.CanCreateSubFolders),
                    new XElement(T + "IsFolderOwner", permission.IsFolderOwner),
                    new XElement(T + "IsFolderVisible", permission.IsFolderVisible),
                    new XElement(T + "IsFolderContact", permission.IsFolderContact));
                if (permission.EditItems is not null) element.Add(new XElement(T + "EditItems", permission.EditItems));
                if (permission.DeleteItems is not null) element.Add(new XElement(T + "DeleteItems", permission.DeleteItems));
                if (permission.ReadItems is not null) element.Add(new XElement(T + "ReadItems", permission.ReadItems));
            }
            element.Add(new XElement(T + (isCalendar ? "CalendarPermissionLevel" : "PermissionLevel"),
                level));
            return element;
        }).ToArray();
        var set = new XElement(T + "PermissionSet", new XElement(T + setName, entries));
        if (permissions.UnknownEntries.Count > 0)
            set.Add(new XElement(T + "UnknownEntries", permissions.UnknownEntries.Select(x => new XElement(T + "UnknownEntry", x))));
        return set;
    }

    private static EwsDelegate ParseDelegate(XElement element)
    {
        var user = ParseSharingUserId(element.Element(T + "UserId"));
        var permissions = element.Element(T + "DelegatePermissions");
        return new EwsDelegate(user,
            permissions?.Element(T + "CalendarFolderPermissionLevel")?.Value,
            permissions?.Element(T + "TasksFolderPermissionLevel")?.Value,
            permissions?.Element(T + "InboxFolderPermissionLevel")?.Value,
            permissions?.Element(T + "ContactsFolderPermissionLevel")?.Value,
            permissions?.Element(T + "NotesFolderPermissionLevel")?.Value,
            permissions?.Element(T + "JournalFolderPermissionLevel")?.Value,
            ReadNullableSharingBool(element.Element(T + "ReceiveCopiesOfMeetingMessages")),
            ReadNullableSharingBool(element.Element(T + "ViewPrivateItems")));
    }

    private static XElement BuildDelegateUser(EwsDelegateInput input)
    {
        var permissions = new XElement(T + "DelegatePermissions");
        AddOptional(permissions, "CalendarFolderPermissionLevel", input.CalendarFolderPermissionLevel);
        AddOptional(permissions, "TasksFolderPermissionLevel", input.TasksFolderPermissionLevel);
        AddOptional(permissions, "InboxFolderPermissionLevel", input.InboxFolderPermissionLevel);
        AddOptional(permissions, "ContactsFolderPermissionLevel", input.ContactsFolderPermissionLevel);
        AddOptional(permissions, "NotesFolderPermissionLevel", input.NotesFolderPermissionLevel);
        AddOptional(permissions, "JournalFolderPermissionLevel", input.JournalFolderPermissionLevel);
        return new XElement(T + "DelegateUser", BuildUserId(input.User),
            permissions.HasElements ? permissions : null,
            input.ReceiveCopiesOfMeetingMessages is { } copies
                ? new XElement(T + "ReceiveCopiesOfMeetingMessages", copies) : null,
            input.ViewPrivateItems is { } privateItems
                ? new XElement(T + "ViewPrivateItems", privateItems) : null);
    }

    private static XElement? BuildDeliverMeetingRequests(string? value) =>
        string.IsNullOrWhiteSpace(value) ? null : new XElement(M + "DeliverMeetingRequests", value);

    private static EwsSharingUserId ParseSharingUserId(XElement? element)
    {
        if (element is null) throw new InvalidOperationException("Exchange returned a permission without a user.");
        var allowed = new[]
        {
            T + "SID", T + "PrimarySmtpAddress", T + "DisplayName", T + "DistinguishedUser",
            T + "ExternalUserIdentity"
        };
        EnsureAllowedChildren(element, allowed, "permission user");
        EnsureNoDuplicateScalars(element, allowed);
        var sid = element.Element(T + "SID")?.Value;
        var smtp = element.Element(T + "PrimarySmtpAddress")?.Value;
        var distinguished = element.Element(T + "DistinguishedUser")?.Value;
        var external = element.Element(T + "ExternalUserIdentity")?.Value;
        var hasInternalIdentity = sid is not null || smtp is not null;
        if ((!hasInternalIdentity && distinguished is null && external is null)
            || (hasInternalIdentity && (distinguished is not null || external is not null))
            || (distinguished is not null && external is not null)
            || new[] { sid, smtp, distinguished, external }.Any(x => x is not null && string.IsNullOrWhiteSpace(x)))
            throw new InvalidOperationException("Exchange returned a permission user with an ambiguous identity.");
        var user = new EwsSharingUserId(smtp,
            element.Element(T + "DisplayName")?.Value, distinguished, external, sid);
        if (string.IsNullOrWhiteSpace(user.Principal))
            throw new InvalidOperationException("Exchange returned a permission without a usable user.");
        if (user.DistinguishedUser is not null
            && user.DistinguishedUser is not ("Default" or "Anonymous"))
            throw new InvalidOperationException("Exchange returned an unsupported distinguished user.");
        return user;
    }

    private static EwsSharingUserId BuildSharingUserId(string principal)
    {
        if (string.Equals(principal, "Default", StringComparison.OrdinalIgnoreCase))
            return new EwsSharingUserId(null, null, "Default", null, null);
        if (string.Equals(principal, "Anonymous", StringComparison.OrdinalIgnoreCase))
            return new EwsSharingUserId(null, null, "Anonymous", null, null);
        if (string.IsNullOrWhiteSpace(principal) || principal.Length > 320 ||
            principal.IndexOfAny(['\r', '\n']) >= 0)
            throw new ArgumentException("The sharing principal is invalid.", nameof(principal));
        try
        {
            var address = new MailAddress(principal);
            if (!string.Equals(address.Address, principal, StringComparison.OrdinalIgnoreCase)) throw new FormatException();
            return new EwsSharingUserId(address.Address, null, null, null, null);
        }
        catch (FormatException)
        { throw new ArgumentException("The sharing principal must be a plain email address, Default or Anonymous.", nameof(principal)); }
    }

    private static XElement BuildUserId(EwsSharingUserId user)
    {
        if (!string.IsNullOrWhiteSpace(user.PrimarySmtpAddress))
            return new XElement(T + "UserId", new XElement(T + "PrimarySmtpAddress", user.PrimarySmtpAddress));
        if (!string.IsNullOrWhiteSpace(user.DistinguishedUser))
            return new XElement(T + "UserId", new XElement(T + "DistinguishedUser", user.DistinguishedUser));
        if (!string.IsNullOrWhiteSpace(user.ExternalUserIdentity))
            return new XElement(T + "UserId", new XElement(T + "ExternalUserIdentity", user.ExternalUserIdentity));
        if (!string.IsNullOrWhiteSpace(user.Sid))
            return new XElement(T + "UserId", new XElement(T + "SID", user.Sid));
        throw new ArgumentException("The sharing principal is invalid.", nameof(user));
    }

    private static void EnsureUniquePermissionPrincipals(IReadOnlyList<EwsFolderPermission> permissions)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (permissions.Any(x => !seen.Add(x.User.Principal)))
            throw new InvalidOperationException("Exchange returned duplicate folder permission principals; refusing to replace the ACL.");
    }

    private static void ValidateDelegateChildResponses(XDocument document, string operation)
    {
        var body = document.Root?.Name == Soap + "Envelope" ? document.Root.Element(Soap + "Body") : null;
        var response = body?.Element(M + (operation + "Response"));
        if (response is not null)
            ThrowIfDefinitiveDelegateRejection(response, operation);
        if (body?.Element(Soap + "Fault") is not null || body?.Elements().Count() != 1 || response is null
            || !HasSuccessfulDelegateResponse(response))
            throw new InvalidOperationException("Exchange returned an unsuccessful delegate response.");

        var allowedResponseChildren = operation == "GetDelegate"
            ? new[] { M + "MessageText", M + "ResponseCode", M + "DescriptiveLinkKey", M + "MessageXml",
                M + "ResponseMessages", M + "DeliverMeetingRequests" }
            : new[] { M + "MessageText", M + "ResponseCode", M + "DescriptiveLinkKey", M + "MessageXml",
                M + "ResponseMessages" };
        EnsureAllowedChildren(response, allowedResponseChildren, "delegate response");
        EnsureNoDuplicateScalars(response, allowedResponseChildren);
        var responseMessages = response.Element(M + "ResponseMessages");
        if (responseMessages is null) return;
        var children = responseMessages.Elements().ToArray();
        if (children.Length == 0)
            throw new InvalidOperationException("Exchange returned an empty delegate response collection.");
        if (children.Length > 1024)
            throw new InvalidOperationException("Exchange returned too many delegate response entries.");
        foreach (var message in children)
        {
            if (message.Name != M + "DelegateUserResponseMessageType")
                throw new InvalidOperationException("Exchange returned an unsuccessful delegate response.");
            ThrowIfDefinitiveDelegateRejection(message, operation);
            if (!HasSuccessfulDelegateResponse(message))
                throw new InvalidOperationException("Exchange returned an unsuccessful delegate response.");
            var allowedMessageChildren = new[]
            {
                M + "MessageText", M + "ResponseCode", M + "DescriptiveLinkKey", M + "MessageXml", M + "DelegateUser"
            };
            EnsureAllowedChildren(message, allowedMessageChildren, "delegate response entry");
            EnsureNoDuplicateScalars(message, allowedMessageChildren);
            if (operation == "GetDelegate" && message.Element(M + "DelegateUser") is null)
                throw new InvalidOperationException("Exchange returned a successful delegate response without a delegate user.");
        }
    }

    private static bool HasSuccessfulDelegateResponse(XElement response)
    {
        if (response.Attribute("ResponseClass")?.Value != "Success") return false;
        var codes = response.Elements(M + "ResponseCode").ToArray();
        return codes.Length == 0 || codes.Length == 1 && codes[0].Value == "NoError";
    }

    private static void ThrowIfDefinitiveDelegateRejection(XElement response, string operation)
    {
        if (response.Attribute("ResponseClass")?.Value != "Error") return;
        var codes = response.Elements(M + "ResponseCode").ToArray();
        if (codes.Length != 1) return;
        var code = codes[0].Value.Trim();
        if (operation == "GetDelegate")
        {
            var failure = new EwsRequestFailedException(code, operation, rejected: true);
            if (failure.ResponseCode is not null) throw failure;
        }
        if (operation == "AddDelegate" && code == "ErrorDelegateAlreadyExists")
            throw new EwsRequestFailedException(code, operation, rejected: true);
    }

    private static bool ReadSharingBool(XElement? element)
    {
        if (element is null) return false;
        if (!bool.TryParse(element.Value, out var value))
            throw new InvalidOperationException("Exchange returned a malformed Boolean sharing field.");
        return value;
    }

    private static bool? ReadNullableSharingBool(XElement? element)
    {
        if (element is null) return null;
        if (!bool.TryParse(element.Value, out var value))
            throw new InvalidOperationException("Exchange returned a malformed Boolean sharing field.");
        return value;
    }

    private static void ValidateFolderElement(XElement folder)
    {
        var baseChildren = new[]
        {
            T + "FolderId", T + "ParentFolderId", T + "FolderClass", T + "DisplayName", T + "TotalCount",
            T + "ChildFolderCount", T + "ExtendedProperty", T + "ManagedFolderInformation", T + "EffectiveRights",
            T + "DistinguishedFolderId", T + "PolicyTag", T + "ArchiveTag", T + "ReplicaList"
        };
        var allowed = folder.Name switch
        {
            var name when name == T + "CalendarFolder" => baseChildren.Append(T + "SharingEffectiveRights").Append(T + "PermissionSet").ToArray(),
            var name when name == T + "ContactsFolder" => baseChildren.Append(T + "SharingEffectiveRights").Append(T + "PermissionSet")
                .Append(T + "SourceId").Append(T + "AccountName").ToArray(),
            var name when name == T + "Folder" || name == T + "TasksFolder" => baseChildren.Append(T + "PermissionSet").Append(T + "UnreadCount").ToArray(),
            _ => throw new InvalidOperationException("Exchange returned an unsupported folder type for permissions.")
        };
        EnsureAllowedChildren(folder, allowed, "folder");
        EnsureNoDuplicateScalars(folder, allowed.Where(x => x != T + "ExtendedProperty" && x != T + "ReplicaList").ToArray());
    }

    private static void ValidatePermissionSet(XElement permissionSet, bool isCalendar)
    {
        var allowed = new[] { T + "Permissions", T + "CalendarPermissions", T + "UnknownEntries" };
        EnsureAllowedChildren(permissionSet, allowed, "permission set");
        EnsureNoDuplicateScalars(permissionSet, allowed);
        var ordinary = permissionSet.Elements(T + "Permissions").ToArray();
        var calendar = permissionSet.Elements(T + "CalendarPermissions").ToArray();
        if (ordinary.Length + calendar.Length != 1 || (isCalendar != (calendar.Length == 1)))
            throw new InvalidOperationException("Exchange returned a missing or mixed folder permission collection.");
        var collection = isCalendar ? calendar[0] : ordinary[0];
        var expected = isCalendar ? T + "CalendarPermission" : T + "Permission";
        if (collection.Elements().Any(x => x.Name != expected))
            throw new InvalidOperationException("Exchange returned an invalid folder permission collection.");
        var unknown = permissionSet.Elements(T + "UnknownEntries").ToArray();
        if (unknown.Length == 1 && unknown[0].Elements().Any(x => x.Name != T + "UnknownEntry"))
            throw new InvalidOperationException("Exchange returned an invalid unknown folder permission collection.");
    }

    private static void EnsureFolderIdAttributes(XElement element)
    {
        if (element.Attributes().Any(attribute => attribute.Name.LocalName is not ("Id" or "ChangeKey")))
            throw new InvalidOperationException("Exchange returned unknown folder identifier attributes.");
    }

    private static XElement RequireSingleElement(XElement parent, XName name, string description)
    {
        var elements = parent.Elements(name).ToArray();
        if (elements.Length != 1)
            throw new InvalidOperationException($"Exchange returned an invalid {description}.");
        return elements[0];
    }

    private static void EnsureAllowedChildren(XElement parent, IReadOnlyCollection<XName> allowed, string description)
    {
        if (parent.Elements().Any(child => !allowed.Contains(child.Name)))
            throw new InvalidOperationException($"Exchange returned an unknown field in the {description}.");
    }

    private static void EnsureNoDuplicateScalars(XElement parent, IReadOnlyCollection<XName> scalarNames)
    {
        if (scalarNames.Any(name => parent.Elements(name).Skip(1).Any()))
            throw new InvalidOperationException("Exchange returned duplicate scalar sharing fields.");
    }

    private static void AddOptional(XElement parent, string name, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value)) parent.Add(new XElement(T + name, value));
    }

    private static string ValidateSharingFolderId(string value)
    {
        if (string.IsNullOrWhiteSpace(value)) throw new ArgumentException("The folder is required.", nameof(value));
        return value.ToLowerInvariant() switch
        {
            "calendar" => "calendar",
            "contacts" => "contacts",
            "tasks" => "tasks",
            "inbox" => "inbox",
            "drafts" => "drafts",
            "sentitems" => "sentitems",
            "deleteditems" => "deleteditems",
            "msgfolderroot" => "msgfolderroot",
            _ => ValidateItemId(value, "folder")
        };
    }

    private static XElement SharingFolderReference(string value) =>
        value switch
        {
            "calendar" or "contacts" or "tasks" =>
                new XElement(T + "DistinguishedFolderId", new XAttribute("Id", value)),
            _ => FolderReference(value)
        };
}
