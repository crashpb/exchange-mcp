using System.Xml.Linq;

namespace Company.ExchangeMcp.Exchange;

public sealed record EwsSyncChange(string Change, string Kind, string Id, string ChangeKey, bool? IsRead);
public sealed record EwsSyncPage(string State, bool IncludesLastChange, IReadOnlyList<EwsSyncChange> Changes);

public sealed partial class EwsClient
{
    public async Task<EwsSyncPage> SyncFoldersAsync(string mailbox, string? state, CancellationToken cancellationToken)
    {
        ValidateSyncState(state);
        var operation = new XElement(M + "SyncFolderHierarchy",
            new XElement(M + "FolderShape", new XElement(T + "BaseShape", "IdOnly")),
            new XElement(M + "SyncFolderId", FolderReference("msgfolderroot")));
        if (state is not null) operation.Add(new XElement(M + "SyncState", state));
        var document = await SendAsync(ValidateMailbox(mailbox), operation, cancellationToken).ConfigureAwait(false);
        return ParseSyncPage(document, "SyncFolderHierarchy", "IncludesLastFolderInRange", true, MaxFolders);
    }

    public async Task<EwsSyncPage> SyncItemsAsync(string mailbox, string folderId, string? state,
        int maxChanges, CancellationToken cancellationToken)
    {
        ValidateSyncState(state);
        if (maxChanges is < 1 or > 512) throw new ArgumentException("Request between 1 and 512 changes.", nameof(maxChanges));
        var folder = folderId == "calendar" ? CalendarFolderReference(folderId)
            : folderId is "contacts" or "tasks" ? PeopleTasksFolderReference(folderId) : FolderReference(ValidateItemId(folderId, "folder"));
        var operation = new XElement(M + "SyncFolderItems",
            new XElement(M + "ItemShape", new XElement(T + "BaseShape", "IdOnly")),
            new XElement(M + "SyncFolderId", folder));
        if (state is not null) operation.Add(new XElement(M + "SyncState", state));
        operation.Add(new XElement(M + "MaxChangesReturned", maxChanges), new XElement(M + "SyncScope", "NormalItems"));
        var document = await SendAsync(ValidateMailbox(mailbox), operation, cancellationToken).ConfigureAwait(false);
        return ParseSyncPage(document, "SyncFolderItems", "IncludesLastItemInRange", false, maxChanges);
    }

    private static void ValidateSyncState(string? state)
    {
        if (state is not null && (string.IsNullOrWhiteSpace(state) || state.Length > 65_536))
            throw new ArgumentException("The synchronization state is invalid. Start a new synchronization.", nameof(state));
    }

    private static EwsSyncPage ParseSyncPage(XDocument document, string operation, string lastElement,
        bool folders, int limit)
    {
        var response = document.Root?.Element(Soap + "Body")?.Element(M + (operation + "Response"))
            ?.Element(M + "ResponseMessages")?.Elements(M + (operation + "ResponseMessage")).SingleOrDefault()
            ?? throw new InvalidOperationException("Exchange returned an invalid synchronization response.");
        var state = response.Element(M + "SyncState")?.Value;
        ValidateSyncState(state);
        if (state is null || !bool.TryParse(response.Element(M + lastElement)?.Value, out var last))
            throw new InvalidOperationException("Exchange omitted the synchronization continuation state.");
        var changes = new List<EwsSyncChange>();
        var changeElements = response.Element(M + "Changes")?.Elements() ?? [];
        foreach (var change in changeElements)
        {
            if (change.Name.Namespace != T || change.Name.LocalName is not ("Create" or "Update" or "Delete" or "ReadFlagChange")
                || (folders && change.Name.LocalName == "ReadFlagChange")
                || change.Elements().Count() != (change.Name.LocalName == "ReadFlagChange" ? 2 : 1))
                throw new InvalidOperationException("Exchange returned an unsupported synchronization change.");
            var value = change.Elements().First();
            if (value.Name.Namespace != T)
                throw new InvalidOperationException("Exchange returned an invalid synchronized object namespace.");
            var tombstone = change.Name.LocalName is "Delete" or "ReadFlagChange";
            var id = tombstone ? value : value.Element(T + (folders ? "FolderId" : "ItemId"));
            if (id?.Name != T + (folders ? "FolderId" : "ItemId"))
                throw new InvalidOperationException("Exchange omitted the synchronized object identifier.");
            var identifier = ValidateItemId(id.Attribute("Id")?.Value ?? "", "synchronized object");
            var key = id.Attribute("ChangeKey")?.Value ?? "";
            var kind = tombstone ? (folders ? "folder" : change.Name.LocalName == "ReadFlagChange" ? "read-state" : "deleted-item") : value.Name.LocalName switch
            {
                "Folder" => "folder",
                "SearchFolder" => "search-folder",
                "CalendarFolder" => "calendar-folder",
                "ContactsFolder" => "contactfolder",
                "TasksFolder" => "taskfolder",
                "Message" => "message",
                "CalendarItem" => "calendar-event",
                "Contact" => "contact",
                "DistributionList" => "contact-group",
                "Task" => "task",
                _ => "unsupported-item"
            };
            bool? read = null;
            if (change.Name.LocalName == "ReadFlagChange")
            {
                if (!bool.TryParse(change.Element(T + "IsRead")?.Value, out var parsed))
                    throw new InvalidOperationException("Exchange omitted the synchronized read state.");
                read = parsed;
            }
            changes.Add(new(change.Name.LocalName, kind, identifier, key, read));
            if (changes.Count > limit) throw new InvalidOperationException("Exchange exceeded the synchronization page limit.");
        }
        return new(state, last, changes);
    }
}
