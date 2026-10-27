using System.Globalization;
using System.Xml.Linq;

namespace Company.ExchangeMcp.Exchange;

public sealed partial class EwsClient
{
    private const int PeopleTasksMaxTextLength = 80_000;
    private const int PeopleTasksMaxQueryLength = 256;
    private const int PeopleTasksMaxCategories = 100;
    private const int PeopleTasksMaxEmails = 3;
    private const int PeopleTasksMaxPhones = 23;
    private const int PeopleTasksMaxAddresses = 3;
    private const int PeopleTasksMaxGroupMembers = 500;

    private static readonly string[] ContactPhoneKeys =
    [
        "AssistantPhone", "BusinessFax", "BusinessPhone", "BusinessPhone2",
        "Callback", "CarPhone", "CompanyMainPhone", "HomeFax", "HomePhone", "HomePhone2",
        "Isdn", "MobilePhone", "OtherFax", "OtherTelephone", "Pager", "PrimaryPhone",
        "RadioPhone", "Telex", "TtyTddPhone", "BusinessMobile", "IPPhone", "Mms", "Msn"
    ];

    private static readonly string[] ContactAddressKeys = ["Home", "Business", "Other"];
    private static readonly string[] ContactAddressFields =
        ["Street", "City", "State", "CountryOrRegion", "PostalCode"];

    private static XElement PeopleTasksFolderReference(string value)
    {
        if (value.Equals("contacts", StringComparison.OrdinalIgnoreCase)
            || value.Equals("tasks", StringComparison.OrdinalIgnoreCase))
            return new XElement(T + "DistinguishedFolderId", new XAttribute("Id", value.ToLowerInvariant()));
        if (DistinguishedFolders.TryGetValue(value, out var distinguishedId))
            return new XElement(T + "DistinguishedFolderId", new XAttribute("Id", distinguishedId));
        return new XElement(T + "FolderId", new XAttribute("Id", ValidateItemId(value, "folder")));
    }

    public async Task<EwsPage<EwsContact>> FindContactsAsync(
        string mailbox,
        string folderId,
        string? query,
        int offset,
        int limit,
        CancellationToken cancellationToken)
    {
        var normalizedMailbox = ValidateMailbox(mailbox);
        var normalizedFolder = ValidateItemId(folderId, "contact folder");
        ValidatePage(offset, limit);
        if (query is not null && query.Length > PeopleTasksMaxQueryLength)
            throw new ArgumentException("The contact search query is too long.", nameof(query));

        var operation = new XElement(
            M + "FindItem",
            new XAttribute("Traversal", "Shallow"),
            ContactShape(),
            new XElement(M + "IndexedPageItemView",
                new XAttribute("MaxEntriesReturned", limit),
                new XAttribute("Offset", offset),
                new XAttribute("BasePoint", "Beginning")),
            string.IsNullOrWhiteSpace(query)
                ? null
                : new XElement(M + "Restriction", new XElement(T + "Or",
                    Contains("contacts:DisplayName", query),
                    Contains("contacts:CompanyName", query),
                    ContainsIndexed("contacts:EmailAddress", "EmailAddress1", query))),
            new XElement(M + "SortOrder", new XElement(T + "FieldOrder",
                new XAttribute("Order", "Ascending"), Field("contacts:DisplayName"))),
            new XElement(M + "ParentFolderIds", PeopleTasksFolderReference(normalizedFolder)));

        var document = await SendAsync(normalizedMailbox, operation, cancellationToken).ConfigureAwait(false);
        var root = RequiredElement(document, M + "RootFolder");
        var contacts = root.Element(T + "Items")?.Elements()
            .Where(item => item.Name == T + "Contact" && item.Element(T + "ItemId") is not null)
            .Select(ParseContact)
            .ToArray() ?? Array.Empty<EwsContact>();
        return new EwsPage<EwsContact>(contacts, GetNextOffset(root, offset, contacts.Length));
    }

    public async Task<EwsContact> GetContactAsync(string mailbox, string itemId, CancellationToken cancellationToken)
    {
        var normalizedMailbox = ValidateMailbox(mailbox);
        var normalizedItemId = ValidateItemId(itemId, "contact");
        var operation = new XElement(M + "GetItem", ContactShape(),
            new XElement(M + "ItemIds", ItemReference(normalizedItemId)));
        var document = await SendAsync(normalizedMailbox, operation, cancellationToken).ConfigureAwait(false);
        var item = RequiredReturnedItem(document);
        return ParseContact(item);
    }

    public async Task<EwsPage<EwsContactGroup>> FindContactGroupsAsync(
        string mailbox,
        string folderId,
        string? query,
        int offset,
        int limit,
        CancellationToken cancellationToken)
    {
        var normalizedMailbox = ValidateMailbox(mailbox);
        var normalizedFolder = ValidateItemId(folderId, "contact folder");
        ValidatePage(offset, limit);
        if (query is not null && query.Length > PeopleTasksMaxQueryLength)
            throw new ArgumentException("The contact group search query is too long.", nameof(query));

        var operation = new XElement(
            M + "FindItem",
            new XAttribute("Traversal", "Shallow"),
            ContactGroupShape(),
            new XElement(M + "IndexedPageItemView",
                new XAttribute("MaxEntriesReturned", limit),
                new XAttribute("Offset", offset),
                new XAttribute("BasePoint", "Beginning")),
            string.IsNullOrWhiteSpace(query)
                ? null
                : new XElement(M + "Restriction", Contains("contacts:DisplayName", query)),
            new XElement(M + "SortOrder", new XElement(T + "FieldOrder",
                new XAttribute("Order", "Ascending"), Field("contacts:DisplayName"))),
            new XElement(M + "ParentFolderIds", PeopleTasksFolderReference(normalizedFolder)));

        var document = await SendAsync(normalizedMailbox, operation, cancellationToken).ConfigureAwait(false);
        var root = RequiredElement(document, M + "RootFolder");
        var groups = root.Element(T + "Items")?.Elements()
            .Where(item => item.Name == T + "DistributionList" && item.Element(T + "ItemId") is not null)
            .Select(ParseContactGroup)
            .ToArray() ?? Array.Empty<EwsContactGroup>();
        return new EwsPage<EwsContactGroup>(groups, GetNextOffset(root, offset, groups.Length));
    }

    public async Task<EwsContactGroup> GetContactGroupAsync(string mailbox, string itemId, CancellationToken cancellationToken)
    {
        var normalizedMailbox = ValidateMailbox(mailbox);
        var normalizedItemId = ValidateItemId(itemId, "contact group");
        var operation = new XElement(M + "GetItem", ContactGroupShape(),
            new XElement(M + "ItemIds", ItemReference(normalizedItemId)));
        var document = await SendAsync(normalizedMailbox, operation, cancellationToken).ConfigureAwait(false);
        return ParseContactGroup(RequiredReturnedItem(document));
    }

    public async Task<EwsItemRef> CreateContactGroupAsync(
        string mailbox,
        string folderId,
        EwsContactGroupInput input,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(input);
        var normalizedMailbox = ValidateMailbox(mailbox);
        var normalizedFolder = ValidateItemId(folderId, "contact folder");
        ValidateContactGroupInput(input);
        var operation = new XElement(M + "CreateItem",
            new XElement(M + "SavedItemFolderId", PeopleTasksFolderReference(normalizedFolder)),
            new XElement(M + "Items", BuildContactGroup(input)));
        var document = await SendAsync(normalizedMailbox, operation, cancellationToken).ConfigureAwait(false);
        return ParseItemReference(RequiredReturnedItem(document));
    }

    public async Task<EwsItemRef> UpdateContactGroupAsync(
        string mailbox,
        string itemId,
        string changeKey,
        string displayName,
        CancellationToken cancellationToken)
    {
        var normalizedMailbox = ValidateMailbox(mailbox);
        var normalizedItemId = ValidateItemId(itemId, "contact group");
        var normalizedChangeKey = ValidateChangeKey(changeKey);
        ValidatePeopleTasksName(displayName, "contact group name");
        var operation = new XElement(M + "UpdateItem",
            new XAttribute("ConflictResolution", "NeverOverwrite"),
            new XElement(M + "ItemChanges",
                new XElement(T + "ItemChange", ItemReference(normalizedItemId, normalizedChangeKey),
                    new XElement(T + "Updates",
                        SetField("contacts:DisplayName", new XElement(T + "DistributionList",
                            new XElement(T + "DisplayName", displayName)))))));
        var document = await SendAsync(normalizedMailbox, operation, cancellationToken).ConfigureAwait(false);
        return ParseItemReference(RequiredReturnedItem(document));
    }

    public async Task<EwsItemRef> UpdateContactGroupMembersAsync(
        string mailbox,
        EwsContactGroup current,
        string? displayName,
        IReadOnlyList<string>? addMemberEmails,
        IReadOnlyList<string>? removeMemberKeys,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(current);
        var normalizedMailbox = ValidateMailbox(mailbox);
        var normalizedItemId = ValidateItemId(current.Id, "contact group");
        var normalizedChangeKey = ValidateChangeKey(current.ChangeKey);
        if (displayName is null && addMemberEmails is not { Count: > 0 }
            && removeMemberKeys is not { Count: > 0 })
            throw new ArgumentException("At least one contact group update is required.");
        if (displayName is not null)
            ValidatePeopleTasksName(displayName, "contact group name");
        if (current.MembersTruncated || current.Members.Count > PeopleTasksMaxGroupMembers)
            throw new ArgumentException("Contact group membership exceeds the supported bound.", nameof(current));
        if (addMemberEmails is { Count: > PeopleTasksMaxGroupMembers })
            throw new ArgumentException($"At most {PeopleTasksMaxGroupMembers} contact group members can be added at once.", nameof(addMemberEmails));
        if (removeMemberKeys is { Count: > PeopleTasksMaxGroupMembers })
            throw new ArgumentException($"At most {PeopleTasksMaxGroupMembers} contact group members can be removed at once.", nameof(removeMemberKeys));

        var currentKeys = new HashSet<string>(StringComparer.Ordinal);
        foreach (var member in current.Members)
        {
            if (string.IsNullOrWhiteSpace(member.ServerMemberKey)) continue;
            var key = ValidateContactGroupMemberKey(member.ServerMemberKey);
            if (!currentKeys.Add(key))
                throw new InvalidOperationException("Exchange returned duplicate contact group member keys.");
        }

        var removals = removeMemberKeys?.Select(ValidateContactGroupMemberKey).ToArray()
            ?? Array.Empty<string>();
        var removalSet = new HashSet<string>(StringComparer.Ordinal);
        foreach (var key in removals)
        {
            if (!removalSet.Add(key))
                throw new ArgumentException("A contact group member was selected more than once.", nameof(removeMemberKeys));
            if (!currentKeys.Contains(key))
                throw new ArgumentException("A selected contact group member is no longer present.", nameof(removeMemberKeys));
        }

        var additions = addMemberEmails?.Select(NormalizeAddress).ToArray() ?? Array.Empty<string>();
        if (additions.Distinct(StringComparer.OrdinalIgnoreCase).Count() != additions.Length)
            throw new ArgumentException("Contact group additions cannot contain duplicate email addresses.", nameof(addMemberEmails));
        var retainedSmtpAddresses = current.Members
            .Where(member => !removalSet.Contains(member.ServerMemberKey ?? string.Empty)
                && string.Equals(member.RoutingType, "SMTP", StringComparison.OrdinalIgnoreCase))
            .Select(member => member.EmailAddress)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        if (additions.Any(retainedSmtpAddresses.Contains))
            throw new ArgumentException("A contact group member with that email address already exists.", nameof(addMemberEmails));
        if (current.Members.Count - removals.Length + additions.Length > PeopleTasksMaxGroupMembers)
            throw new ArgumentException($"A contact group cannot exceed {PeopleTasksMaxGroupMembers} members.", nameof(addMemberEmails));

        var updates = new XElement(T + "Updates");
        if (displayName is not null)
            updates.Add(SetField("contacts:DisplayName", new XElement(T + "DistributionList",
                new XElement(T + "DisplayName", displayName))));
        foreach (var key in removals)
            updates.Add(new XElement(T + "DeleteItemField", IndexedField("distributionlist:Members:Member", key)));
        if (additions.Length > 0)
            updates.Add(new XElement(T + "AppendToItemField", Field("distributionlist:Members"),
                new XElement(T + "DistributionList", new XElement(T + "Members", additions.Select(address =>
                    new XElement(T + "Member", new XElement(T + "Mailbox", new XElement(T + "EmailAddress", address))))))));

        var operation = new XElement(M + "UpdateItem",
            new XAttribute("ConflictResolution", "NeverOverwrite"),
            new XElement(M + "ItemChanges",
                new XElement(T + "ItemChange", ItemReference(normalizedItemId, normalizedChangeKey), updates)));
        var document = await SendAsync(normalizedMailbox, operation, cancellationToken).ConfigureAwait(false);
        return ParseItemReference(RequiredReturnedItem(document));
    }

    public Task DeleteContactGroupAsync(string mailbox, string itemId, string? changeKey, CancellationToken cancellationToken) =>
        SoftDeleteAsync(mailbox, ValidateItemId(itemId, "contact group"), changeKey, cancellationToken);

    public async Task<IReadOnlyList<EwsContactFolder>> ListContactFoldersAsync(
        string mailbox,
        CancellationToken cancellationToken)
    {
        var normalizedMailbox = ValidateMailbox(mailbox);
        var defaultFolder = await GetContactFolderAsync(normalizedMailbox, "contacts", cancellationToken).ConfigureAwait(false);
        var operation = new XElement(M + "FindFolder",
            new XAttribute("Traversal", "Deep"),
            new XElement(M + "FolderShape", new XElement(T + "BaseShape", "AllProperties")),
            new XElement(M + "IndexedPageFolderView",
                new XAttribute("MaxEntriesReturned", 1_000),
                new XAttribute("Offset", 0),
                new XAttribute("BasePoint", "Beginning")),
            new XElement(M + "ParentFolderIds", PeopleTasksFolderReference("msgfolderroot")));
        var document = await SendAsync(normalizedMailbox, operation, cancellationToken).ConfigureAwait(false);
        return document.Descendants(M + "RootFolder").Elements(T + "Folders").Elements()
            .Select(folder => ParseContactFolder(folder))
            .Where(folder => folder.FolderClass.StartsWith("IPF.Contact", StringComparison.OrdinalIgnoreCase))
            .Select(folder => folder with { IsDefault = folder.Id == defaultFolder.Id })
            .ToArray();
    }

    public async Task<EwsContactFolder> GetContactFolderAsync(string mailbox, string folderId, CancellationToken cancellationToken)
    {
        var normalizedMailbox = ValidateMailbox(mailbox);
        var normalizedFolder = ValidateItemId(folderId, "contact folder");
        var operation = new XElement(M + "GetFolder",
            new XElement(M + "FolderShape", new XElement(T + "BaseShape", "AllProperties")),
            new XElement(M + "FolderIds", PeopleTasksFolderReference(normalizedFolder)));
        var document = await SendAsync(normalizedMailbox, operation, cancellationToken).ConfigureAwait(false);
        var folder = document.Descendants().FirstOrDefault(value =>
                value.Name == T + "ContactsFolder" || value.Name == T + "Folder")
            ?? throw new InvalidOperationException("Exchange returned no contact folder.");
        return ParseContactFolder(folder, normalizedFolder.Equals("contacts", StringComparison.OrdinalIgnoreCase)) with
        { IsDefault = normalizedFolder.Equals("contacts", StringComparison.OrdinalIgnoreCase) };
    }

    public async Task<EwsContactFolder> CreateContactFolderAsync(
        string mailbox,
        string parentFolderId,
        string name,
        CancellationToken cancellationToken)
    {
        var normalizedMailbox = ValidateMailbox(mailbox);
        var normalizedParent = ValidateItemId(parentFolderId, "parent contact folder");
        ValidatePeopleTasksName(name, "contact folder");
        var operation = new XElement(M + "CreateFolder",
            new XElement(M + "ParentFolderId", PeopleTasksFolderReference(normalizedParent)),
            new XElement(M + "Folders", new XElement(T + "ContactsFolder",
                new XElement(T + "DisplayName", name))));
        var document = await SendAsync(normalizedMailbox, operation, cancellationToken).ConfigureAwait(false);
        var folder = document.Descendants().FirstOrDefault(value =>
                value.Name == T + "ContactsFolder" || value.Name == T + "Folder")
            ?? throw new InvalidOperationException("Exchange returned no contact folder.");
        return ParseContactFolder(folder, assumeContact: true);
    }

    public async Task<EwsContactFolder> RenameContactFolderAsync(
        string mailbox,
        string folderId,
        string changeKey,
        string name,
        CancellationToken cancellationToken)
    {
        var folder = await RenameFolderAsync(mailbox, folderId, changeKey, name, cancellationToken).ConfigureAwait(false);
        return await GetContactFolderAsync(mailbox, folder.Id, cancellationToken).ConfigureAwait(false);
    }

    public Task DeleteContactFolderAsync(string mailbox, string folderId, string changeKey, CancellationToken cancellationToken) =>
        SoftDeleteFolderAsync(mailbox, ValidateItemId(folderId, "contact folder"), ValidateChangeKey(changeKey), cancellationToken);

    public async Task<EwsItemRef> CreateContactAsync(
        string mailbox,
        string folderId,
        EwsContactInput input,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(input);
        var normalizedMailbox = ValidateMailbox(mailbox);
        var normalizedFolder = ValidateItemId(folderId, "contact folder");
        var operation = new XElement(M + "CreateItem",
            new XElement(M + "SavedItemFolderId", PeopleTasksFolderReference(normalizedFolder)),
            new XElement(M + "Items", BuildContact(input)));
        var document = await SendAsync(normalizedMailbox, operation, cancellationToken).ConfigureAwait(false);
        return ParseItemReference(RequiredReturnedItem(document));
    }

    public async Task<EwsItemRef> UpdateContactAsync(
        string mailbox,
        string itemId,
        string changeKey,
        EwsContactInput input,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(input);
        ValidateContactInput(input);
        var normalizedMailbox = ValidateMailbox(mailbox);
        var normalizedItemId = ValidateItemId(itemId, "contact");
        var normalizedChangeKey = ValidateChangeKey(changeKey);
        var current = await GetContactAsync(normalizedMailbox, normalizedItemId, cancellationToken).ConfigureAwait(false);
        if (!string.Equals(current.ChangeKey, normalizedChangeKey, StringComparison.Ordinal))
            throw new ArgumentException("The contact change key is stale.", nameof(changeKey));
        var updates = new XElement(T + "Updates");
        AddContactUpdate(updates, "contacts:DisplayName", input.DisplayName, "DisplayName");
        AddContactUpdate(updates, "contacts:FileAs", input.FileAs, "FileAs");
        AddContactUpdate(updates, "contacts:GivenName", input.GivenName, "GivenName");
        AddContactUpdate(updates, "contacts:MiddleName", input.MiddleName, "MiddleName");
        AddContactUpdate(updates, "contacts:Surname", input.Surname, "Surname");
        AddContactUpdate(updates, "contacts:CompanyName", input.CompanyName, "CompanyName");
        AddContactUpdate(updates, "contacts:JobTitle", input.JobTitle, "JobTitle");
        AddContactUpdate(updates, "contacts:Department", input.Department, "Department");
        AddContactEmailUpdate(updates, input.EmailAddresses, current.EmailAddresses);
        AddContactPhoneUpdate(updates, input.PhoneNumbers, current.PhoneNumbers);
        AddContactPhysicalAddressUpdate(updates, input.PhysicalAddresses, current.PhysicalAddresses);
        AddContactUpdate(updates, "contacts:Birthday", input.BirthdayUtc, "Birthday");
        AddContactUpdate(updates, "item:Body", input.Notes, "Body", "Item");
        AddCategoriesUpdate(updates, input.Categories);
        var operation = new XElement(M + "UpdateItem",
            new XAttribute("ConflictResolution", "NeverOverwrite"),
            new XElement(M + "ItemChanges",
                new XElement(T + "ItemChange", ItemReference(normalizedItemId, normalizedChangeKey), updates)));
        var document = await SendAsync(normalizedMailbox, operation, cancellationToken).ConfigureAwait(false);
        return ParseItemReference(RequiredReturnedItem(document));
    }

    public Task DeleteContactAsync(string mailbox, string itemId, string? changeKey, CancellationToken cancellationToken) =>
        SoftDeleteAsync(mailbox, ValidateItemId(itemId, "contact"), changeKey, cancellationToken);

    public async Task<IReadOnlyList<EwsDirectoryPerson>> ResolveDirectoryAsync(
        string mailbox,
        string query,
        int limit,
        CancellationToken cancellationToken)
    {
        var normalizedMailbox = ValidateMailbox(mailbox);
        if (string.IsNullOrWhiteSpace(query) || query.Length > PeopleTasksMaxQueryLength)
            throw new ArgumentException("The directory query must contain 1–256 characters.", nameof(query));
        if (limit is < 1 or > 100) throw new ArgumentOutOfRangeException(nameof(limit));

        var operation = new XElement(M + "ResolveNames",
            new XAttribute("ReturnFullContactData", "true"),
            new XAttribute("SearchScope", "ActiveDirectory"),
            new XAttribute("ContactDataShape", "AllProperties"),
            new XElement(M + "UnresolvedEntry", query));
        var document = await SendAsync(normalizedMailbox, operation, cancellationToken).ConfigureAwait(false);
        return document.Descendants(M + "ResolutionSet").Elements(T + "Resolution")
            .Take(limit)
            .Select(ParseDirectoryPerson)
            .ToArray();
    }

    public async Task<IReadOnlyList<EwsTaskFolder>> ListTaskFoldersAsync(
        string mailbox,
        CancellationToken cancellationToken)
    {
        var normalizedMailbox = ValidateMailbox(mailbox);
        var defaultFolder = await GetTaskFolderAsync(normalizedMailbox, "tasks", cancellationToken).ConfigureAwait(false);
        var operation = new XElement(M + "FindFolder",
            new XAttribute("Traversal", "Deep"),
            new XElement(M + "FolderShape", new XElement(T + "BaseShape", "AllProperties")),
            new XElement(M + "IndexedPageFolderView",
                new XAttribute("MaxEntriesReturned", 1_000),
                new XAttribute("Offset", 0),
                new XAttribute("BasePoint", "Beginning")),
            new XElement(M + "ParentFolderIds", PeopleTasksFolderReference("msgfolderroot")));
        var document = await SendAsync(normalizedMailbox, operation, cancellationToken).ConfigureAwait(false);
        return document.Descendants(M + "RootFolder").Elements(T + "Folders").Elements()
            .Select(ParseTaskFolder)
            .Where(folder => folder.FolderClass.Equals("IPF.Task", StringComparison.OrdinalIgnoreCase))
            .Select(folder => folder with { IsDefault = folder.Id == defaultFolder.Id })
            .ToArray();
    }

    public async Task<EwsTaskFolder> GetTaskFolderAsync(string mailbox, string folderId, CancellationToken cancellationToken)
    {
        var normalizedMailbox = ValidateMailbox(mailbox);
        var normalizedFolder = ValidateItemId(folderId, "task folder");
        var operation = new XElement(M + "GetFolder",
            new XElement(M + "FolderShape", new XElement(T + "BaseShape", "AllProperties")),
            new XElement(M + "FolderIds", PeopleTasksFolderReference(normalizedFolder)));
        var document = await SendAsync(normalizedMailbox, operation, cancellationToken).ConfigureAwait(false);
        var folder = document.Descendants().FirstOrDefault(value => value.Name == T + "TasksFolder" || value.Name == T + "Folder")
            ?? throw new InvalidOperationException("Exchange returned no task folder.");
        var isDefault = normalizedFolder.Equals("tasks", StringComparison.OrdinalIgnoreCase);
        if (!isDefault)
        {
            var defaultFolder = await GetTaskFolderAsync(normalizedMailbox, "tasks", cancellationToken).ConfigureAwait(false);
            isDefault = string.Equals(defaultFolder.Id, (string?)folder.Element(T + "FolderId")?.Attribute("Id"), StringComparison.Ordinal);
        }
        return ParseTaskFolder(folder) with { IsDefault = isDefault };
    }

    public async Task<EwsTaskFolder> CreateTaskFolderAsync(
        string mailbox,
        string parentFolderId,
        string name,
        CancellationToken cancellationToken)
    {
        var normalizedMailbox = ValidateMailbox(mailbox);
        var normalizedParent = ValidateItemId(parentFolderId, "parent task folder");
        ValidatePeopleTasksName(name, "task folder");
        var operation = new XElement(M + "CreateFolder",
            new XElement(M + "ParentFolderId", PeopleTasksFolderReference(normalizedParent)),
            new XElement(M + "Folders", new XElement(T + "TasksFolder",
                new XElement(T + "FolderClass", "IPF.Task"),
                new XElement(T + "DisplayName", name))));
        var document = await SendAsync(normalizedMailbox, operation, cancellationToken).ConfigureAwait(false);
        var folder = document.Descendants().FirstOrDefault(value => value.Name == T + "TasksFolder" || value.Name == T + "Folder")
            ?? throw new InvalidOperationException("Exchange returned no task folder.");
        return ParseTaskFolder(folder);
    }

    public async Task<EwsTaskFolder> RenameTaskFolderAsync(
        string mailbox,
        string folderId,
        string changeKey,
        string name,
        CancellationToken cancellationToken)
    {
        var folder = await RenameFolderAsync(mailbox, folderId, changeKey, name, cancellationToken).ConfigureAwait(false);
        return new EwsTaskFolder(folder.Id, folder.ChangeKey, folder.Name, "IPF.Task", folder.TotalCount, 0);
    }

    public Task DeleteTaskFolderAsync(string mailbox, string folderId, string changeKey, CancellationToken cancellationToken) =>
        SoftDeleteFolderAsync(mailbox, ValidateItemId(folderId, "task folder"), ValidateChangeKey(changeKey), cancellationToken);

    public async Task<EwsPage<EwsTask>> FindTasksAsync(
        string mailbox,
        string folderId,
        string? query,
        int offset,
        int limit,
        CancellationToken cancellationToken)
    {
        var normalizedMailbox = ValidateMailbox(mailbox);
        var normalizedFolder = ValidateItemId(folderId, "task folder");
        ValidatePage(offset, limit);
        if (query is not null && query.Length > PeopleTasksMaxQueryLength)
            throw new ArgumentException("The task search query is too long.", nameof(query));

        var operation = new XElement(M + "FindItem",
            new XAttribute("Traversal", "Shallow"),
            TaskShape(),
            new XElement(M + "IndexedPageItemView",
                new XAttribute("MaxEntriesReturned", limit),
                new XAttribute("Offset", offset),
                new XAttribute("BasePoint", "Beginning")),
            string.IsNullOrWhiteSpace(query)
                ? null
                : new XElement(M + "Restriction", Contains("item:Subject", query)),
            new XElement(M + "SortOrder", new XElement(T + "FieldOrder",
                new XAttribute("Order", "Ascending"), Field("task:DueDate"))),
            new XElement(M + "ParentFolderIds", PeopleTasksFolderReference(normalizedFolder)));
        var document = await SendAsync(normalizedMailbox, operation, cancellationToken).ConfigureAwait(false);
        var root = RequiredElement(document, M + "RootFolder");
        var tasks = root.Element(T + "Items")?.Elements()
            .Where(item => item.Name == T + "Task" && item.Element(T + "ItemId") is not null)
            .Select(ParseTask)
            .ToArray() ?? Array.Empty<EwsTask>();
        return new EwsPage<EwsTask>(tasks, GetNextOffset(root, offset, tasks.Length));
    }

    public async Task<EwsTask> GetTaskAsync(string mailbox, string itemId, CancellationToken cancellationToken)
    {
        var normalizedMailbox = ValidateMailbox(mailbox);
        var normalizedItemId = ValidateItemId(itemId, "task");
        var operation = new XElement(M + "GetItem", TaskShape(),
            new XElement(M + "ItemIds", ItemReference(normalizedItemId)));
        var document = await SendAsync(normalizedMailbox, operation, cancellationToken).ConfigureAwait(false);
        return ParseTask(RequiredReturnedItem(document));
    }

    public async Task<EwsItemRef> CreateTaskAsync(
        string mailbox,
        string folderId,
        EwsTaskInput input,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(input);
        var normalizedMailbox = ValidateMailbox(mailbox);
        var normalizedFolder = ValidateItemId(folderId, "task folder");
        ValidateTaskInput(input);
        var operation = new XElement(M + "CreateItem",
            new XElement(M + "SavedItemFolderId", PeopleTasksFolderReference(normalizedFolder)),
            new XElement(M + "Items", BuildTask(input)));
        var document = await SendAsync(normalizedMailbox, operation, cancellationToken).ConfigureAwait(false);
        return ParseItemReference(RequiredReturnedItem(document));
    }

    public async Task<EwsItemRef> UpdateTaskAsync(
        string mailbox,
        string itemId,
        string changeKey,
        EwsTaskInput input,
        CancellationToken cancellationToken,
        bool clearRecurrence = false)
    {
        ArgumentNullException.ThrowIfNull(input);
        var normalizedMailbox = ValidateMailbox(mailbox);
        var normalizedItemId = ValidateItemId(itemId, "task");
        var normalizedChangeKey = ValidateChangeKey(changeKey);
        var currentTask = await GetTaskAsync(normalizedMailbox, normalizedItemId, cancellationToken).ConfigureAwait(false);
        EnsureOrdinaryTaskMutationAllowed(currentTask);
        ValidateTaskInput(input);
        if (clearRecurrence && input.Recurrence is not null)
            throw new ArgumentException("Set recurrence or clearRecurrence, not both.", nameof(clearRecurrence));
        var updates = new XElement(T + "Updates");
        AddTaskField(updates, "item:Subject", input.Subject, "Subject");
        AddTaskField(updates, "item:Body", input.Body, "Body", "Item", input.BodyType);
        AddTaskField(updates, "task:StartDate", input.StartDateUtc, "StartDate");
        AddTaskField(updates, "task:DueDate", input.DueDateUtc, "DueDate");
        AddTaskField(updates, "task:CompleteDate", input.CompleteDateUtc, "CompleteDate");
        AddTaskField(updates, "task:PercentComplete", input.PercentComplete, "PercentComplete");
        AddTaskField(updates, "task:Status", input.Status, "Status");
        AddTaskField(updates, "item:Importance", TaskPriorityToImportance(input.Priority), "Importance", "Item");
        AddTaskField(updates, "item:ReminderIsSet", input.ReminderIsSet, "ReminderIsSet", "Item");
        AddTaskField(updates, "item:ReminderDueBy", input.ReminderDueByUtc, "ReminderDueBy", "Item");
        AddTaskCategoriesUpdate(updates, input.Categories);
        AddTaskRecurrenceUpdate(updates, input.Recurrence, clearRecurrence);
        var operation = new XElement(M + "UpdateItem",
            new XAttribute("ConflictResolution", "NeverOverwrite"),
            new XElement(M + "ItemChanges",
                new XElement(T + "ItemChange", ItemReference(normalizedItemId, normalizedChangeKey), updates)));
        var document = await SendAsync(normalizedMailbox, operation, cancellationToken).ConfigureAwait(false);
        return ParseItemReference(RequiredReturnedItem(document));
    }

    public Task<EwsItemRef> CompleteTaskAsync(string mailbox, string itemId, string changeKey, CancellationToken cancellationToken) =>
        UpdateTaskStateAsync(mailbox, itemId, changeKey, true, cancellationToken);

    public Task<EwsItemRef> ReopenTaskAsync(string mailbox, string itemId, string changeKey, CancellationToken cancellationToken) =>
        UpdateTaskStateAsync(mailbox, itemId, changeKey, false, cancellationToken);

    private async Task<EwsItemRef> UpdateTaskStateAsync(
        string mailbox,
        string itemId,
        string changeKey,
        bool complete,
        CancellationToken cancellationToken)
    {
        var normalizedMailbox = ValidateMailbox(mailbox);
        var normalizedItemId = ValidateItemId(itemId, "task");
        var normalizedChangeKey = ValidateChangeKey(changeKey);
        var currentTask = await GetTaskAsync(normalizedMailbox, normalizedItemId, cancellationToken).ConfigureAwait(false);
        EnsureOrdinaryTaskMutationAllowed(currentTask);
        var updates = new XElement(T + "Updates",
            TaskField("task:Status", complete ? "Completed" : "NotStarted", "Status"),
            TaskField("task:PercentComplete", complete ? 100d : 0d, "PercentComplete"));
        if (complete)
            updates.Add(TaskField("task:CompleteDate", DateTimeOffset.UtcNow, "CompleteDate"));
        else
            updates.Add(new XElement(T + "DeleteItemField", Field("task:CompleteDate")));
        var operation = new XElement(M + "UpdateItem",
            new XAttribute("ConflictResolution", "NeverOverwrite"),
            new XElement(M + "ItemChanges",
                new XElement(T + "ItemChange", ItemReference(normalizedItemId, normalizedChangeKey), updates)));
        var document = await SendAsync(normalizedMailbox, operation, cancellationToken).ConfigureAwait(false);
        return ParseItemReference(RequiredReturnedItem(document));
    }

    public async Task DeleteTaskAsync(
        string mailbox,
        string itemId,
        string changeKey,
        string recurrenceScope,
        CancellationToken cancellationToken,
        bool allowAssignedCopy = false)
    {
        var normalizedMailbox = ValidateMailbox(mailbox);
        var normalizedItemId = ValidateItemId(itemId, "task");
        var normalizedChangeKey = ValidateChangeKey(changeKey);
        var currentTask = await GetTaskAsync(normalizedMailbox, normalizedItemId, cancellationToken).ConfigureAwait(false);
        if (!allowAssignedCopy) EnsureOrdinaryTaskMutationAllowed(currentTask);
        else if (!IsAssignedTaskCopy(currentTask) || recurrenceScope != "series" || currentTask.ChangeKey != normalizedChangeKey)
            throw new InvalidOperationException("The task-copy deletion requires the current complete-copy approval.");
        var normalizedScope = recurrenceScope?.Trim().ToLowerInvariant();
        var affectedOccurrences = normalizedScope switch
        {
            "single" => "SpecifiedOccurrenceOnly",
            "series" => "AllOccurrences",
            _ => throw new ArgumentException("Task deletion scope must be single or series.", nameof(recurrenceScope))
        };
        var operation = new XElement(M + "DeleteItem",
            new XAttribute("DeleteType", "MoveToDeletedItems"),
            new XAttribute("AffectedTaskOccurrences", affectedOccurrences),
            new XElement(M + "ItemIds", ItemReference(normalizedItemId, normalizedChangeKey)));
        await SendAsync(normalizedMailbox, operation, cancellationToken).ConfigureAwait(false);
    }

    private static XElement ContactShape() => new XElement(M + "ItemShape",
        new XElement(T + "BaseShape", "IdOnly"),
        new XElement(T + "AdditionalProperties",
            Field("item:Categories"), Field("contacts:FileAs"), Field("contacts:DisplayName"),
            Field("contacts:GivenName"), Field("contacts:MiddleName"), Field("contacts:Surname"),
            Field("contacts:CompanyName"), Field("contacts:JobTitle"), Field("contacts:Department"),
            IndexedField("contacts:EmailAddress", "EmailAddress1"),
            IndexedField("contacts:EmailAddress", "EmailAddress2"),
            IndexedField("contacts:EmailAddress", "EmailAddress3"),
            ContactPhoneKeys.Select(key => IndexedField("contacts:PhoneNumber", key)),
            ContactAddressKeys.SelectMany(key => ContactAddressFields.Select(field =>
                IndexedField($"contacts:PhysicalAddress:{field}", key))),
            Field("contacts:Birthday"), Field("item:Body")));

    private static XElement ContainsIndexed(string fieldUri, string fieldIndex, string value) =>
        new XElement(T + "Contains",
            new XAttribute("ContainmentMode", "Substring"),
            new XAttribute("ContainmentComparison", "IgnoreCase"),
            IndexedField(fieldUri, fieldIndex),
            new XElement(T + "Constant", new XAttribute("Value", value)));

    private static XElement IndexedField(string fieldUri, string fieldIndex) =>
        new(T + "IndexedFieldURI",
            new XAttribute("FieldURI", fieldUri),
            new XAttribute("FieldIndex", fieldIndex));

    private static XElement ContactGroupShape() => new XElement(M + "ItemShape",
        new XElement(T + "BaseShape", "IdOnly"),
        new XElement(T + "AdditionalProperties",
            Field("contacts:DisplayName"), Field("distributionlist:Members")));

    private static XElement TaskShape() => new XElement(M + "ItemShape",
        new XElement(T + "BaseShape", "IdOnly"),
        new XElement(T + "BodyType", "Best"),
        new XElement(T + "AdditionalProperties",
            Field("item:ItemClass"), Field("item:Subject"), Field("item:Body"), Field("item:HasAttachments"), Field("item:Categories"), Field("item:Importance"),
             Field("task:StartDate"), Field("task:DueDate"), Field("task:CompleteDate"),
             Field("task:PercentComplete"), Field("task:Status"), Field("task:IsComplete"),
             Field("task:IsRecurring"), Field("task:Recurrence"), Field("item:ReminderIsSet"),
             Field("item:ReminderDueBy"), Field("item:Attachments"), TaskAssignmentFields()));

    internal async Task<EwsTask> HydrateTaskAttachmentsAsync(
        string mailbox,
        EwsTask task,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(task);
        var attachments = task.Attachments ?? Array.Empty<EwsAttachment>();
        ValidateTaskAttachmentMetadata(task, attachments);
        if (attachments.Count == 0)
            return task with { Attachments = Array.Empty<EwsAttachment>(), AttachmentContents = Array.Empty<EwsAttachmentContent>() };

        var contents = new List<EwsAttachmentContent>(attachments.Count);
        var normalizedAttachments = new List<EwsAttachment>(attachments.Count);
        foreach (var attachment in attachments)
        {
            var content = await GetAttachmentAsync(mailbox, attachment.Id, cancellationToken).ConfigureAwait(false);
            if (!string.Equals(content.Id, attachment.Id, StringComparison.Ordinal)
                || !string.Equals(content.Name, attachment.Name, StringComparison.Ordinal)
                || !string.Equals(content.ContentType, attachment.ContentType, StringComparison.Ordinal)
                || content.Content.Length > attachment.Size
                || content.IsInline != attachment.IsInline
                || !string.Equals(content.ContentId, attachment.ContentId, StringComparison.Ordinal))
                throw new InvalidOperationException("Exchange returned attachment data that does not match the task snapshot.");
            contents.Add(content);
            normalizedAttachments.Add(new EwsAttachment(content.Id, content.Name, content.Content.Length,
                content.IsInline, content.ContentType, content.ContentId));
        }
        var hydratedTask = task with { Attachments = normalizedAttachments, AttachmentContents = contents };
        ValidateTaskAttachmentSnapshot(hydratedTask);
        return hydratedTask;
    }

    private static void EnsureOrdinaryTaskMutationAllowed(EwsTask task)
    {
        if (IsAssignedTaskCopy(task))
            throw new InvalidOperationException(
                "Assigned task copies require the native task assignment workflow so the other mailbox receives the change.");
    }

    internal static bool IsAssignedTaskCopy(EwsTask task) => task.Assignment is { } assignment
        && (assignment.State is 2 or 3 or 4 || assignment.Ownership is 1 or 2
            || !string.IsNullOrWhiteSpace(assignment.AssignerAddress)
            || !string.IsNullOrWhiteSpace(assignment.AssigneeAddress)
            || !string.IsNullOrWhiteSpace(assignment.OwnerAddress));

    private static XElement BuildContact(EwsContactInput input)
    {
        ValidateContactInput(input);
        var contact = new XElement(T + "Contact");
        // Contact extends ItemType. Keep the base Item fields before the
        // ContactItemType fields so Exchange 2019 accepts the request.
        if (!string.IsNullOrEmpty(input.Notes)) contact.Add(new XElement(T + "Body",
            new XAttribute("BodyType", "Text"), input.Notes));
        if (input.Categories is { Count: > 0 }) contact.Add(BuildCategories(input.Categories));
        AddOptional(contact, "FileAs", input.FileAs);
        AddOptional(contact, "DisplayName", input.DisplayName);
        AddOptional(contact, "GivenName", input.GivenName);
        AddOptional(contact, "MiddleName", input.MiddleName);
        AddOptional(contact, "CompanyName", input.CompanyName);
        if (input.EmailAddresses is { Count: > 0 }) contact.Add(BuildEmailAddresses(input.EmailAddresses));
        if (input.PhysicalAddresses is { Count: > 0 }) contact.Add(BuildPhysicalAddresses(input.PhysicalAddresses));
        if (input.PhoneNumbers is { Count: > 0 }) contact.Add(BuildPhoneNumbers(input.PhoneNumbers));
        if (input.BirthdayUtc is not null) contact.Add(new XElement(T + "Birthday", FormatUtc(input.BirthdayUtc.Value)));
        AddOptional(contact, "Department", input.Department);
        AddOptional(contact, "JobTitle", input.JobTitle);
        AddOptional(contact, "Surname", input.Surname);
        return contact;
    }

    private static XElement BuildContactGroup(EwsContactGroupInput input)
    {
        ValidateContactGroupInput(input);
        return new XElement(T + "DistributionList",
            new XElement(T + "DisplayName", input.DisplayName),
            new XElement(T + "Members", input.Members.Select(address =>
                new XElement(T + "Member", new XElement(T + "Mailbox",
                    new XElement(T + "EmailAddress", NormalizeAddress(address)))))));
    }

    private static void AddContactUpdate(XElement updates, string fieldUri, object? value, string elementName,
        string parentName = "Contact", string bodyType = "Text")
    {
        if (value is null)
        {
            updates.Add(new XElement(T + "DeleteItemField", Field(fieldUri)));
            return;
        }
        XElement element = value switch
        {
            DateTimeOffset date => new XElement(T + elementName, FormatUtc(date)),
            _ when elementName == "Body" => new XElement(T + elementName,
                new XAttribute("BodyType", bodyType), value.ToString()),
            _ => new XElement(T + elementName, value)
        };
        updates.Add(SetField(fieldUri, new XElement(T + parentName, element)));
    }

    private static void AddContactPhoneUpdate(XElement updates, IReadOnlyList<EwsContactPhone>? values,
        IReadOnlyList<EwsContactPhone> current)
    {
        foreach (var key in ContactPhoneKeys)
        {
            var value = values?.FirstOrDefault(phone => phone.Key == key);
            var field = IndexedField("contacts:PhoneNumber", key);
            if (value is null)
            {
                if (current.Any(phone => phone.Key == key))
                    updates.Add(new XElement(T + "DeleteItemField", field));
                continue;
            }
            updates.Add(new XElement(T + "SetItemField", field,
                new XElement(T + "Contact",
                    new XElement(T + "PhoneNumbers",
                        new XElement(T + "Entry", new XAttribute("Key", key), value.Number)))));
        }
    }

    private static void AddContactPhysicalAddressUpdate(XElement updates, IReadOnlyList<EwsContactAddress>? values,
        IReadOnlyList<EwsContactAddress> current)
    {
        foreach (var key in ContactAddressKeys)
        {
            var address = values?.FirstOrDefault(value => value.Key == key);
            foreach (var fieldName in ContactAddressFields)
            {
                var field = IndexedField($"contacts:PhysicalAddress:{fieldName}", key);
                var fieldValue = address is null ? null : ContactAddressFieldValue(address, fieldName);
                if (string.IsNullOrEmpty(fieldValue))
                {
                    var currentAddress = current.FirstOrDefault(value => value.Key == key);
                    if (currentAddress is not null
                        && !string.IsNullOrEmpty(ContactAddressFieldValue(currentAddress, fieldName)))
                        updates.Add(new XElement(T + "DeleteItemField", field));
                    continue;
                }
                updates.Add(new XElement(T + "SetItemField", field,
                    new XElement(T + "Contact",
                        new XElement(T + "PhysicalAddresses",
                            new XElement(T + "Entry", new XAttribute("Key", key),
                                new XElement(T + fieldName, fieldValue))))));
            }
        }
    }

    private static string? ContactAddressFieldValue(EwsContactAddress address, string fieldName) => fieldName switch
    {
        "Street" => address.Street,
        "City" => address.City,
        "State" => address.State,
        "CountryOrRegion" => address.Country,
        "PostalCode" => address.PostalCode,
        _ => throw new ArgumentOutOfRangeException(nameof(fieldName))
    };

    private static void AddContactEmailUpdate(XElement updates, IReadOnlyList<EwsContactEmail>? values,
        IReadOnlyList<EwsContactEmail> current)
    {
        for (var index = 1; index <= PeopleTasksMaxEmails; index++)
        {
            var key = $"EmailAddress{index}";
            var value = values?.FirstOrDefault(email => email.Key == key);
            var field = IndexedField("contacts:EmailAddress", key);
            if (value is null)
            {
                if (current.Any(email => email.Key == key))
                    updates.Add(new XElement(T + "DeleteItemField", field));
                continue;
            }
            updates.Add(new XElement(T + "SetItemField", field,
                new XElement(T + "Contact", BuildEmailAddresses([value]))));
        }
    }

    private static void AddCategoriesUpdate(XElement updates, IReadOnlyList<string>? categories)
    {
        if (categories is null)
        {
            updates.Add(new XElement(T + "DeleteItemField", Field("item:Categories")));
            return;
        }
        ValidateCategoriesForPeopleTasks(categories);
        updates.Add(SetField("item:Categories", new XElement(T + "Item", BuildCategories(categories))));
    }

    private static XElement BuildEmailAddresses(IReadOnlyList<EwsContactEmail> values) =>
        new XElement(T + "EmailAddresses", values.Select(value =>
            new XElement(T + "Entry", new XAttribute("Key", value.Key),
                value.Address)));

    private static XElement BuildPhoneNumbers(IReadOnlyList<EwsContactPhone> values) =>
        new XElement(T + "PhoneNumbers", values.Select(value =>
            new XElement(T + "Entry", new XAttribute("Key", value.Key),
                value.Number)));

    private static XElement BuildPhysicalAddresses(IReadOnlyList<EwsContactAddress> values) =>
        new XElement(T + "PhysicalAddresses", values.Select(value =>
            new XElement(T + "Entry", new XAttribute("Key", value.Key),
                OptionalElement("Street", value.Street), OptionalElement("City", value.City),
                OptionalElement("State", value.State), OptionalElement("CountryOrRegion", value.Country),
                OptionalElement("PostalCode", value.PostalCode))));

    private static XElement BuildCategories(IReadOnlyList<string> values) =>
        new XElement(T + "Categories", values.Select(value => new XElement(T + "String", value)));

    private static XElement BuildTask(EwsTaskInput input)
    {
        ValidateTaskInput(input);
        var task = new XElement(T + "Task", new XElement(T + "Subject", input.Subject));
        if (input.Body is not null) task.Add(new XElement(T + "Body",
            new XAttribute("BodyType", input.BodyType), input.Body));
        if (input.Categories is { Count: > 0 }) task.Add(BuildCategories(input.Categories));
        task.Add(new XElement(T + "Importance", TaskPriorityToImportance(input.Priority)));
        AddOptional(task, "ReminderDueBy", input.ReminderDueByUtc);
        task.Add(new XElement(T + "ReminderIsSet", input.ReminderIsSet));
        AddOptional(task, "CompleteDate", input.CompleteDateUtc);
        AddOptional(task, "DueDate", input.DueDateUtc);
        task.Add(new XElement(T + "PercentComplete", input.PercentComplete.ToString(CultureInfo.InvariantCulture)));
        if (input.Recurrence is not null) task.Add(BuildRecurrence(input.Recurrence));
        AddOptional(task, "StartDate", input.StartDateUtc);
        task.Add(new XElement(T + "Status", input.Status));
        return task;
    }

    private static void AddTaskField(XElement updates, string fieldUri, object? value, string elementName,
        string parentName = "Task", string bodyType = "Text")
    {
        if (value is null)
        {
            updates.Add(new XElement(T + "DeleteItemField", Field(fieldUri)));
            return;
        }
        updates.Add(TaskField(fieldUri, value, elementName, parentName, bodyType));
    }

    private static XElement TaskField(string fieldUri, object value, string elementName,
        string parentName = "Task", string bodyType = "Text")
    {
        XElement element = value switch
        {
            DateTimeOffset date => new XElement(T + elementName, FormatUtc(date)),
            double number => new XElement(T + elementName, number.ToString(CultureInfo.InvariantCulture)),
            bool boolean => new XElement(T + elementName, boolean),
            _ when elementName == "Body" => new XElement(T + elementName,
                new XAttribute("BodyType", bodyType), value.ToString()),
            _ => new XElement(T + elementName, value)
        };
        return SetField(fieldUri, new XElement(T + parentName, element));
    }

    private static void AddTaskCategoriesUpdate(XElement updates, IReadOnlyList<string>? categories)
    {
        if (categories is null)
        {
            updates.Add(new XElement(T + "DeleteItemField", Field("item:Categories")));
            return;
        }
        ValidateCategoriesForPeopleTasks(categories);
        updates.Add(SetField("item:Categories", new XElement(T + "Task", BuildCategories(categories))));
    }

    private static void AddTaskRecurrenceUpdate(XElement updates, EwsTaskRecurrence? recurrence, bool clearRecurrence)
    {
        if (recurrence is null && !clearRecurrence)
            return;
        if (recurrence is null)
        {
            updates.Add(new XElement(T + "DeleteItemField", Field("task:Recurrence")));
            return;
        }
        updates.Add(SetField("task:Recurrence", new XElement(T + "Task", BuildRecurrence(recurrence))));
    }

    private static XElement BuildRecurrence(EwsTaskRecurrence recurrence)
    {
        ValidateRecurrence(recurrence);
        var recurrenceElement = new XElement(T + "Recurrence");
        var pattern = recurrence.Pattern.Trim();
        var patternName = pattern switch
        {
            "daily" => "DailyRecurrence",
            "weekly" => "WeeklyRecurrence",
            "monthly" => "AbsoluteMonthlyRecurrence",
            "yearly" => "AbsoluteYearlyRecurrence",
            "relativeMonthly" => "RelativeMonthlyRecurrence",
            "relativeYearly" => "RelativeYearlyRecurrence",
            "dailyRegeneration" => "DailyRegeneration",
            "weeklyRegeneration" => "WeeklyRegeneration",
            "monthlyRegeneration" => "MonthlyRegeneration",
            "yearlyRegeneration" => "YearlyRegeneration",
            _ => throw new ArgumentException("Unsupported task recurrence pattern.", nameof(recurrence))
        };
        var patternElement = new XElement(T + patternName);
        if (patternName is "DailyRecurrence" or "WeeklyRecurrence" or "AbsoluteMonthlyRecurrence"
            or "RelativeMonthlyRecurrence"
            or "DailyRegeneration" or "WeeklyRegeneration" or "MonthlyRegeneration" or "YearlyRegeneration")
            patternElement.Add(new XElement(T + "Interval", recurrence.Interval));
        if (patternName == "WeeklyRecurrence" && recurrence.DaysOfWeek is { Count: > 0 })
            patternElement.Add(new XElement(T + "DaysOfWeek", string.Join(' ', recurrence.DaysOfWeek)));
        if (patternName == "WeeklyRecurrence")
            patternElement.Add(new XElement(T + "FirstDayOfWeek", recurrence.FirstDayOfWeek ?? "Sunday"));
        if (patternName is "RelativeMonthlyRecurrence" or "RelativeYearlyRecurrence")
        {
            patternElement.Add(new XElement(T + "DaysOfWeek", recurrence.DaysOfWeek![0]));
            patternElement.Add(new XElement(T + "DayOfWeekIndex", recurrence.DayOfWeekIndex));
        }
        if (patternName == "AbsoluteMonthlyRecurrence")
            patternElement.Add(new XElement(T + "DayOfMonth", recurrence.DayOfMonth));
        if (patternName is "AbsoluteYearlyRecurrence" or "RelativeYearlyRecurrence")
        {
            if (patternName == "AbsoluteYearlyRecurrence")
                patternElement.Add(new XElement(T + "DayOfMonth", recurrence.DayOfMonth));
            patternElement.Add(new XElement(T + "Month", RecurrenceMonthName(recurrence.Month!.Value)));
        }
        recurrenceElement.Add(patternElement);
        var start = (recurrence.StartDateUtc ?? DateTimeOffset.UtcNow).UtcDateTime.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
        recurrenceElement.Add(recurrence.Range.Trim() switch
        {
            "NoEnd" => new XElement(T + "NoEndRecurrence", new XElement(T + "StartDate", start)),
            "EndDate" => new XElement(T + "EndDateRecurrence", new XElement(T + "StartDate", start),
                new XElement(T + "EndDate", recurrence.EndDateUtc!.Value.UtcDateTime.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture))),
            "Numbered" => new XElement(T + "NumberedRecurrence", new XElement(T + "StartDate", start),
                new XElement(T + "NumberOfOccurrences", recurrence.NumberOfOccurrences)),
            _ => throw new ArgumentException("Unsupported task recurrence range.", nameof(recurrence))
        });
        return recurrenceElement;
    }

    private static EwsContact ParseContact(XElement item)
    {
        if (item.Name != T + "Contact") throw new InvalidOperationException("Exchange returned a non-contact item.");
        var id = item.Element(T + "ItemId");
        if (id is null || string.IsNullOrWhiteSpace((string?)id.Attribute("Id")))
            throw new InvalidOperationException("Exchange returned a contact without an identifier.");
        var body = item.Element(T + "Body")?.Value;
        return new EwsContact(
            (string)id.Attribute("Id")!, (string?)id.Attribute("ChangeKey") ?? string.Empty,
            item.Element(T + "DisplayName")?.Value ?? string.Empty,
            Value(item, "FileAs"), Value(item, "GivenName"), Value(item, "MiddleName"), Value(item, "Surname"),
            Value(item, "CompanyName"), Value(item, "JobTitle"), Value(item, "Department"),
            ParseContactEmails(item.Element(T + "EmailAddresses")),
            ParseContactPhones(item.Element(T + "PhoneNumbers")),
            ParseContactAddresses(item.Element(T + "PhysicalAddresses")),
            ParseDate(item.Element(T + "Birthday")?.Value), body,
            item.Element(T + "Categories")?.Elements(T + "String").Select(x => x.Value).ToArray() ?? Array.Empty<string>());
    }

    private static EwsContactGroup ParseContactGroup(XElement item)
    {
        if (item.Name != T + "DistributionList")
            throw new InvalidOperationException("Exchange returned a non-contact-group item.");
        var id = item.Element(T + "ItemId");
        if (id is null || string.IsNullOrWhiteSpace((string?)id.Attribute("Id")))
            throw new InvalidOperationException("Exchange returned a contact group without an identifier.");
        var memberElements = item.Element(T + "Members")?.Elements(T + "Member")
            .Take(PeopleTasksMaxGroupMembers + 1).ToArray() ?? Array.Empty<XElement>();
        var members = memberElements.Take(PeopleTasksMaxGroupMembers)
            .Select(ParseContactGroupMember).ToArray();
        return new EwsContactGroup(
            (string)id.Attribute("Id")!, (string?)id.Attribute("ChangeKey") ?? string.Empty,
            item.Element(T + "DisplayName")?.Value ?? string.Empty, members)
        {
            MembersTruncated = memberElements.Length > PeopleTasksMaxGroupMembers
        };
    }

    private static EwsContactGroupMember ParseContactGroupMember(XElement member)
    {
        var mailbox = member.Element(T + "Mailbox");
        var itemId = mailbox?.Element(T + "ItemId");
        return new EwsContactGroupMember(
            mailbox?.Element(T + "Name")?.Value,
            mailbox?.Element(T + "EmailAddress")?.Value ?? string.Empty,
            mailbox?.Element(T + "RoutingType")?.Value,
            mailbox?.Element(T + "MailboxType")?.Value,
            (string?)itemId?.Attribute("Id"),
            (string?)member.Attribute("Key"));
    }

    private static string ValidateContactGroupMemberKey(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > 4_096 || value.Any(char.IsControl))
            throw new ArgumentException("The contact group member key is invalid.", nameof(value));
        return value;
    }

    private static EwsDirectoryPerson ParseDirectoryPerson(XElement resolution)
    {
        var mailbox = resolution.Element(T + "Mailbox");
        var contact = resolution.Element(T + "Contact");
        return new EwsDirectoryPerson(
            contact?.Element(T + "DisplayName")?.Value ?? mailbox?.Element(T + "Name")?.Value,
            mailbox?.Element(T + "EmailAddress")?.Value,
            mailbox?.Element(T + "RoutingType")?.Value,
            contact?.Element(T + "CompanyName")?.Value,
            contact?.Element(T + "JobTitle")?.Value,
            contact?.Element(T + "Department")?.Value,
            contact?.Element(T + "PhoneNumbers")?.Elements(T + "Entry")
                .Select(entry => entry.Value)
                .FirstOrDefault(value => !string.IsNullOrWhiteSpace(value)));
    }

    private static EwsTaskFolder ParseTaskFolder(XElement folder)
    {
        var id = folder.Element(T + "FolderId")
            ?? throw new InvalidOperationException("Exchange returned a folder without an identifier.");
        if (string.IsNullOrWhiteSpace((string?)id.Attribute("Id")))
            throw new InvalidOperationException("Exchange returned a folder without an identifier.");
        return new EwsTaskFolder(
            (string)id.Attribute("Id")!, (string?)id.Attribute("ChangeKey") ?? string.Empty,
            folder.Element(T + "DisplayName")?.Value ?? string.Empty,
            folder.Element(T + "FolderClass")?.Value
                ?? (folder.Name.LocalName == "TasksFolder" ? "IPF.Task" : string.Empty),
            ReadInt(folder.Element(T + "TotalCount")), ReadInt(folder.Element(T + "ChildFolderCount")));
    }

    private static EwsContactFolder ParseContactFolder(XElement folder, bool assumeContact = false)
    {
        var id = folder.Element(T + "FolderId")
            ?? throw new InvalidOperationException("Exchange returned a contact folder without an identifier.");
        if (string.IsNullOrWhiteSpace((string?)id.Attribute("Id")))
            throw new InvalidOperationException("Exchange returned a contact folder without an identifier.");
        var folderClass = folder.Element(T + "FolderClass")?.Value
            ?? (folder.Name.LocalName == "ContactsFolder" || assumeContact ? "IPF.Contact" : string.Empty);
        if (!folderClass.StartsWith("IPF.Contact", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Exchange returned a non-contact folder.");
        return new EwsContactFolder(
            (string)id.Attribute("Id")!, (string?)id.Attribute("ChangeKey") ?? string.Empty,
            folder.Element(T + "DisplayName")?.Value ?? string.Empty, folderClass,
            ReadInt(folder.Element(T + "TotalCount")), ReadInt(folder.Element(T + "ChildFolderCount")));
    }

    private static EwsTask ParseTask(XElement item)
    {
        if (item.Name != T + "Task") throw new InvalidOperationException("Exchange returned a non-task item.");
        var id = item.Element(T + "ItemId");
        if (id is null || string.IsNullOrWhiteSpace((string?)id.Attribute("Id")))
            throw new InvalidOperationException("Exchange returned a task without an identifier.");
        var percent = double.TryParse(item.Element(T + "PercentComplete")?.Value,
            NumberStyles.Float, CultureInfo.InvariantCulture, out var parsedPercent) ? parsedPercent : 0d;
        var importance = item.Element(T + "Importance")?.Value;
        var attachments = ParseTaskAttachments(item.Element(T + "Attachments"));
        return new EwsTask(
            (string)id.Attribute("Id")!, (string?)id.Attribute("ChangeKey") ?? string.Empty,
            item.Element(T + "Subject")?.Value ?? string.Empty,
            item.Element(T + "Body")?.Value, item.Element(T + "Body")?.Attribute("BodyType")?.Value ?? "Text",
            ParseDate(item.Element(T + "StartDate")?.Value), ParseDate(item.Element(T + "DueDate")?.Value),
            ParseDate(item.Element(T + "CompleteDate")?.Value), Math.Clamp(parsedPercent, 0d, 100d),
            item.Element(T + "Status")?.Value ?? "NotStarted", importance switch
            {
                "High" => 2,
                "Low" => 0,
                _ => 1
            }, ReadBool(item.Element(T + "ReminderIsSet")), ParseDate(item.Element(T + "ReminderDueBy")?.Value),
            item.Element(T + "Categories")?.Elements(T + "String").Select(x => x.Value).ToArray() ?? Array.Empty<string>(),
            ParseRecurrence(item.Element(T + "Recurrence")), ReadBool(item.Element(T + "IsComplete")),
            ReadBool(item.Element(T + "IsRecurring")), ParseTaskAssignment(item),
            ReadBool(item.Element(T + "HasAttachments")) || attachments.Count != 0,
            attachments);
    }

    private static IReadOnlyList<EwsAttachment> ParseTaskAttachments(XElement? attachments)
    {
        if (attachments is null) return Array.Empty<EwsAttachment>();
        var result = new List<EwsAttachment>();
        foreach (var element in attachments.Elements())
        {
            if (element.Name != T + "FileAttachment" && element.Name != T + "ItemAttachment")
                throw new InvalidOperationException("Exchange returned an unsupported task attachment type.");
            var id = element.Element(T + "AttachmentId")?.Attribute("Id")?.Value;
            var name = element.Element(T + "Name")?.Value;
            if (string.IsNullOrWhiteSpace(id) || string.IsNullOrWhiteSpace(name))
                throw new InvalidOperationException("Exchange returned a task attachment without an identifier or name.");
            if (element.Name == T + "ItemAttachment")
                throw new InvalidOperationException("Embedded item attachments cannot be assigned safely.");
            var sizeElement = element.Element(T + "Size");
            if (sizeElement is null
                || !int.TryParse(sizeElement.Value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var size)
                || size < 0)
                throw new InvalidOperationException("Exchange returned a task attachment without a valid size.");
            result.Add(new EwsAttachment(id, name, size,
                ReadBool(element.Element(T + "IsInline")), element.Element(T + "ContentType")?.Value,
                element.Element(T + "ContentId")?.Value));
        }
        return result;
    }

    private static IReadOnlyList<EwsContactEmail> ParseContactEmails(XElement? parent) =>
        parent?.Elements(T + "Entry").Select(entry => new EwsContactEmail(
            (string?)entry.Attribute("Key") ?? string.Empty, entry.Value))
        .Where(value => !string.IsNullOrWhiteSpace(value.Key) && !string.IsNullOrWhiteSpace(value.Address)).Take(PeopleTasksMaxEmails).ToArray()
        ?? Array.Empty<EwsContactEmail>();

    private static IReadOnlyList<EwsContactPhone> ParseContactPhones(XElement? parent) =>
        parent?.Elements(T + "Entry").Select(entry => new EwsContactPhone(
            (string?)entry.Attribute("Key") ?? string.Empty, entry.Value))
        .Where(value => !string.IsNullOrWhiteSpace(value.Key) && !string.IsNullOrWhiteSpace(value.Number)).Take(PeopleTasksMaxPhones).ToArray()
        ?? Array.Empty<EwsContactPhone>();

    private static IReadOnlyList<EwsContactAddress> ParseContactAddresses(XElement? parent) =>
        parent?.Elements(T + "Entry").Select(entry => new EwsContactAddress(
            (string?)entry.Attribute("Key") ?? string.Empty, Value(entry, "Street"), Value(entry, "City"),
            Value(entry, "State"), Value(entry, "CountryOrRegion"), Value(entry, "PostalCode")))
        .Where(value => !string.IsNullOrWhiteSpace(value.Key)).Take(PeopleTasksMaxAddresses).ToArray()
        ?? Array.Empty<EwsContactAddress>();

    private static EwsTaskRecurrence? ParseRecurrence(XElement? recurrence)
    {
        if (recurrence is null) return null;
        var pattern = recurrence.Elements().FirstOrDefault(x => x.Name.LocalName is
            "DailyRecurrence" or "WeeklyRecurrence" or "AbsoluteMonthlyRecurrence" or "AbsoluteYearlyRecurrence"
            or "RelativeMonthlyRecurrence" or "RelativeYearlyRecurrence"
            or "DailyRegeneration" or "WeeklyRegeneration" or "MonthlyRegeneration" or "YearlyRegeneration");
        if (pattern is null)
            throw new InvalidOperationException("Exchange returned an unsupported task recurrence pattern.");
        var name = pattern.Name.LocalName;
        var patternName = name switch
        {
            "DailyRecurrence" => "daily",
            "WeeklyRecurrence" => "weekly",
            "AbsoluteMonthlyRecurrence" => "monthly",
            "AbsoluteYearlyRecurrence" => "yearly",
            "RelativeMonthlyRecurrence" => "relativeMonthly",
            "RelativeYearlyRecurrence" => "relativeYearly",
            "DailyRegeneration" => "dailyRegeneration",
            "WeeklyRegeneration" => "weeklyRegeneration",
            "MonthlyRegeneration" => "monthlyRegeneration",
            "YearlyRegeneration" => "yearlyRegeneration",
            _ => name
        };
        _ = int.TryParse(pattern.Element(T + "Interval")?.Value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var interval);
        _ = int.TryParse(pattern.Element(T + "DayOfMonth")?.Value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var day);
        var month = ParseRecurrenceMonth(pattern.Element(T + "Month")?.Value);
        var range = recurrence.Elements().FirstOrDefault(x => x.Name.LocalName.EndsWith("Recurrence", StringComparison.Ordinal)
            && (x.Name.LocalName is "NoEndRecurrence" or "EndDateRecurrence" or "NumberedRecurrence"));
        var rangeName = range?.Name.LocalName switch { "EndDateRecurrence" => "EndDate", "NumberedRecurrence" => "Numbered", _ => "NoEnd" };
        _ = int.TryParse(range?.Element(T + "NumberOfOccurrences")?.Value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var occurrences);
        return new EwsTaskRecurrence(patternName, Math.Max(1, interval),
            pattern.Element(T + "DaysOfWeek")?.Value.Split(' ', StringSplitOptions.RemoveEmptyEntries),
            day == 0 ? null : day, month == 0 ? null : month, ParseDate(range?.Element(T + "StartDate")?.Value), rangeName,
            ParseDate(range?.Element(T + "EndDate")?.Value), occurrences == 0 ? null : occurrences,
            pattern.Element(T + "DayOfWeekIndex")?.Value,
            patternName == "weekly" ? pattern.Element(T + "FirstDayOfWeek")?.Value ?? "Sunday" : null);
    }

    private static string? Value(XElement parent, string name) => parent.Element(T + name)?.Value;

    private static string RecurrenceMonthName(int month) => month switch
    {
        1 => "January",
        2 => "February",
        3 => "March",
        4 => "April",
        5 => "May",
        6 => "June",
        7 => "July",
        8 => "August",
        9 => "September",
        10 => "October",
        11 => "November",
        12 => "December",
        _ => throw new ArgumentOutOfRangeException(nameof(month), "Recurrence month must be 1–12.")
    };

    private static int ParseRecurrenceMonth(string? value)
    {
        if (int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var numeric))
            return numeric;
        return value switch
        {
            "January" => 1,
            "February" => 2,
            "March" => 3,
            "April" => 4,
            "May" => 5,
            "June" => 6,
            "July" => 7,
            "August" => 8,
            "September" => 9,
            "October" => 10,
            "November" => 11,
            "December" => 12,
            _ => 0
        };
    }

    private static XElement? OptionalElement(string name, string? value) =>
        string.IsNullOrEmpty(value) ? null : new XElement(T + name, value);

    private static void AddOptional(XElement parent, string name, object? value)
    {
        if (value is null) return;
        parent.Add(value is DateTimeOffset date
            ? new XElement(T + name, FormatUtc(date))
            : new XElement(T + name, value));
    }

    private static DateTimeOffset? ParseDate(string? value) =>
        DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var result) ? result : null;

    private static string FormatUtc(DateTimeOffset value) =>
        value.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ", CultureInfo.InvariantCulture);

    private static string TaskPriorityToImportance(int priority) => priority switch
    {
        0 => "Low",
        1 => "Normal",
        2 => "High",
        _ => throw new ArgumentOutOfRangeException(nameof(priority))
    };

    private static void ValidateContactInput(EwsContactInput input)
    {
        ValidatePeopleTasksText(input.DisplayName, "display name", required: true);
        foreach (var value in new[] { input.FileAs, input.GivenName, input.MiddleName, input.Surname,
            input.CompanyName, input.JobTitle, input.Department, input.Notes })
            if (value is not null) ValidatePeopleTasksText(value, "contact field");
        if (input.EmailAddresses is { Count: > PeopleTasksMaxEmails }) throw new ArgumentException("At most three contact email addresses are supported.");
        if (input.PhoneNumbers is { Count: > PeopleTasksMaxPhones }) throw new ArgumentException("Too many contact phone numbers.");
        if (input.PhysicalAddresses is { Count: > PeopleTasksMaxAddresses }) throw new ArgumentException("Too many contact addresses.");
        if (input.EmailAddresses is not null)
            foreach (var value in input.EmailAddresses)
            {
                ValidatePeopleTasksText(value.Key, "email key", true, 32);
                if (value.Key is not ("EmailAddress1" or "EmailAddress2" or "EmailAddress3"))
                    throw new ArgumentException($"Unsupported contact email key '{value.Key}'.");
                ValidatePeopleTasksText(value.Address, "email address", true, 320);
            }
        if (input.PhoneNumbers is not null)
            foreach (var value in input.PhoneNumbers) { ValidatePeopleTasksText(value.Key, "phone key", true, 64); ValidatePeopleTasksText(value.Number, "phone number", true, 128); }
        if (input.PhysicalAddresses is not null)
            foreach (var value in input.PhysicalAddresses) { ValidatePeopleTasksText(value.Key, "address key", true, 64); foreach (var field in new[] { value.Street, value.City, value.State, value.Country, value.PostalCode }) if (field is not null) ValidatePeopleTasksText(field, "address field", false, 255); }
        if (input.PhoneNumbers is not null)
            foreach (var value in input.PhoneNumbers)
                if (!ContactPhoneKeys.Contains(value.Key, StringComparer.Ordinal))
                    throw new ArgumentException($"Unsupported contact phone key '{value.Key}'.");
        if (input.PhysicalAddresses is not null)
            foreach (var value in input.PhysicalAddresses)
                if (!ContactAddressKeys.Contains(value.Key, StringComparer.Ordinal))
                    throw new ArgumentException($"Unsupported contact address key '{value.Key}'.");
        if (input.BirthdayUtc is not null && input.BirthdayUtc.Value.Year is < 1601 or > 9999) throw new ArgumentException("The contact birthday is invalid.");
        if (input.Categories is not null) ValidateCategoriesForPeopleTasks(input.Categories);
    }

    private static void ValidateContactGroupInput(EwsContactGroupInput input)
    {
        ValidatePeopleTasksText(input.DisplayName, "contact group name", required: true, max: 255);
        if (input.Members is null || input.Members.Count > PeopleTasksMaxGroupMembers)
            throw new ArgumentException($"A contact group must contain 1–{PeopleTasksMaxGroupMembers} members.");
        if (input.Members.Count == 0)
            throw new ArgumentException("A contact group must contain at least one member.");
        foreach (var member in input.Members)
        {
            ValidatePeopleTasksText(member, "contact group member", required: true, 320);
            _ = NormalizeAddress(member);
        }
    }

    private static void ValidateTaskInput(EwsTaskInput input)
    {
        ValidatePeopleTasksText(input.Subject, "task subject", true, 998);
        if (input.Body is { } body && (body.Length > PeopleTasksMaxTextLength
            || body.Any(value => char.IsControl(value) && value is not ('\r' or '\n' or '\t'))))
            throw new ArgumentException("The task body is invalid.", "task body");
        if (!string.Equals(input.BodyType, "Text", StringComparison.OrdinalIgnoreCase) && !string.Equals(input.BodyType, "HTML", StringComparison.OrdinalIgnoreCase)) throw new ArgumentException("Task body type must be Text or HTML.");
        if (input.PercentComplete is < 0 or > 100 || double.IsNaN(input.PercentComplete) || double.IsInfinity(input.PercentComplete)) throw new ArgumentOutOfRangeException(nameof(input.PercentComplete));
        if (input.Status is null or not ("NotStarted" or "InProgress" or "Completed" or "WaitingOnOthers" or "Deferred")) throw new ArgumentException("Unsupported task status.");
        _ = TaskPriorityToImportance(input.Priority);
        if (input.Categories is not null) ValidateCategoriesForPeopleTasks(input.Categories);
        if (input.Recurrence is not null) ValidateRecurrence(input.Recurrence);
    }

    private static void ValidateRecurrence(EwsTaskRecurrence recurrence)
    {
        if (recurrence.Interval is < 1 or > 999) throw new ArgumentOutOfRangeException(nameof(recurrence.Interval));
        if (recurrence.Pattern is null or not ("daily" or "weekly" or "monthly" or "yearly" or "relativeMonthly" or "relativeYearly" or "dailyRegeneration" or "weeklyRegeneration" or "monthlyRegeneration" or "yearlyRegeneration")) throw new ArgumentException("Unsupported task recurrence pattern.");
        if ((recurrence.Pattern is "yearly" or "relativeYearly") && recurrence.Interval != 1)
            throw new ArgumentException("Exchange yearly task recurrence supports only interval 1.");
        if (recurrence.Pattern is "relativeMonthly" or "relativeYearly")
        {
            var relativeDays = recurrence.DaysOfWeek;
            if (relativeDays is not { Count: 1 }
                || relativeDays[0] is not ("Sunday" or "Monday" or "Tuesday" or "Wednesday"
                    or "Thursday" or "Friday" or "Saturday" or "Day" or "Weekday" or "WeekendDay"))
                throw new ArgumentException("Relative recurrence needs exactly one valid day.");
            if (recurrence.DayOfWeekIndex is not ("First" or "Second" or "Third" or "Fourth" or "Last"))
                throw new ArgumentException("Relative recurrence needs a valid day-of-week index.");
        }
        if (recurrence.Pattern == "weekly")
        {
            if (recurrence.Interval > 99)
                throw new ArgumentOutOfRangeException(nameof(recurrence.Interval), "Weekly recurrence interval must be between 1 and 99.");
            if (recurrence.DaysOfWeek is null || recurrence.DaysOfWeek.Count is < 1 or > 7
                || recurrence.DaysOfWeek.Any(day => day is not ("Sunday" or "Monday" or "Tuesday" or "Wednesday"
                    or "Thursday" or "Friday" or "Saturday")))
                throw new ArgumentException("Weekly recurrence needs one to seven weekdays.");
            if (recurrence.FirstDayOfWeek is not null and not ("Sunday" or "Monday" or "Tuesday" or "Wednesday"
                or "Thursday" or "Friday" or "Saturday"))
                throw new ArgumentException("Weekly recurrence needs a valid first day of week.");
        }
        else if (recurrence.FirstDayOfWeek is not null)
            throw new ArgumentException("FirstDayOfWeek is only supported for weekly recurrence.");
        else if (recurrence.Pattern is not ("relativeMonthly" or "relativeYearly")
            && recurrence.DaysOfWeek is { Count: > 0 })
            throw new ArgumentException("DaysOfWeek is only supported for weekly recurrence.");
        if (recurrence.Pattern == "monthly" && recurrence.DayOfMonth is not >= 1 and <= 31) throw new ArgumentException("Monthly recurrence needs a day of month.");
        if (recurrence.Pattern == "yearly" && (recurrence.DayOfMonth is not >= 1 and <= 31 || recurrence.Month is not >= 1 and <= 12)) throw new ArgumentException("Yearly recurrence needs a valid month and day.");
        if (recurrence.Pattern == "relativeYearly" && recurrence.Month is not >= 1 and <= 12)
            throw new ArgumentException("Relative yearly recurrence needs a valid month.");
        if (recurrence.Pattern is not ("monthly" or "yearly") && recurrence.DayOfMonth is not null)
            throw new ArgumentException("DayOfMonth is only supported for monthly or yearly recurrence.");
        if (recurrence.Pattern is not ("yearly" or "relativeYearly") && recurrence.Month is not null)
            throw new ArgumentException("Month is only supported for yearly recurrence.");
        if (recurrence.Pattern is not ("relativeMonthly" or "relativeYearly") && recurrence.DayOfWeekIndex is not null)
            throw new ArgumentException("DayOfWeekIndex is only supported for relative recurrence.");
        if (recurrence.Range == "EndDate" && recurrence.EndDateUtc is null) throw new ArgumentException("EndDate recurrence needs an end date.");
        if (recurrence.Range == "Numbered" && recurrence.NumberOfOccurrences is not >= 1 and <= 9999) throw new ArgumentException("Numbered recurrence needs one to 9999 occurrences.");
        if (recurrence.Range is null or not ("NoEnd" or "EndDate" or "Numbered")) throw new ArgumentException("Unsupported task recurrence range.");
    }

    private static void ValidateCategoriesForPeopleTasks(IReadOnlyList<string> categories)
    {
        if (categories.Count > PeopleTasksMaxCategories || categories.Any(value => string.IsNullOrWhiteSpace(value) || value.Length > 255 || value.Any(char.IsControl))) throw new ArgumentException("Categories must contain at most 100 labels of 1–255 characters.");
    }

    private static void ValidatePeopleTasksText(string? value, string name, bool required = false, int max = PeopleTasksMaxTextLength)
    {
        if ((required && string.IsNullOrWhiteSpace(value)) || value is not null && (value.Length > max || value.Any(char.IsControl))) throw new ArgumentException($"The {name} is invalid.", name);
    }

    private static void ValidatePeopleTasksName(string value, string name) => ValidatePeopleTasksText(value, name, true, 255);
}
