using System.Xml.Linq;

namespace Company.ExchangeMcp.Exchange;

public sealed record EwsGroupwareAttachments(string Id, string ChangeKey, string Kind, bool IsMeeting,
    bool IsOrganizer, IReadOnlyList<EwsAttachment> Files, int Count, long Bytes,
    bool IsAssignedTask = false);

public sealed partial class EwsClient
{
    public async Task<EwsGroupwareAttachments> GetGroupwareAttachmentsAsync(string mailbox, string itemId,
        string kind, CancellationToken cancellationToken)
    {
        var itemName = kind switch
        {
            "calendar" => "CalendarItem",
            "contact" => "Contact",
            "task" => "Task",
            _ => throw new ArgumentException("Item kind must be calendar, contact or task.", nameof(kind))
        };
        var properties = new XElement(T + "AdditionalProperties", Field("item:Attachments"));
        if (kind == "task") properties.Add(TaskAssignmentFields());
        if (kind == "calendar") properties.Add(Field("calendar:IsMeeting"), Field("calendar:IsOrganizer"));
        var operation = new XElement(M + "GetItem", new XElement(M + "ItemShape",
            new XElement(T + "BaseShape", "IdOnly"), properties),
            new XElement(M + "ItemIds", ItemReference(ValidateItemId(itemId, "item"))));
        var document = await SendAsync(ValidateMailbox(mailbox), operation, cancellationToken).ConfigureAwait(false);
        var item = RequiredReturnedItem(document);
        if (item.Name != T + itemName) throw new InvalidOperationException("Exchange returned a different item kind.");
        var reference = ParseItemReference(item);
        var attachments = item.Element(T + "Attachments");
        var assignment = kind == "task" ? ParseTaskAssignment(item) : null;
        var assignedTask = kind == "task" && assignment is not null &&
            (assignment.State is 2 or 3 or 4 || assignment.Ownership is 1 or 2
                || !string.IsNullOrWhiteSpace(assignment.AssignerAddress)
                || !string.IsNullOrWhiteSpace(assignment.AssigneeAddress)
                || !string.IsNullOrWhiteSpace(assignment.OwnerAddress));
        return new(reference.Id, reference.ChangeKey, kind, ReadBool(item.Element(T + "IsMeeting")),
            ReadBool(item.Element(T + "IsOrganizer")), ParseAttachments(attachments), attachments?.Elements().Count() ?? 0,
            attachments?.Elements().Sum(a => (long)ReadInt(a.Element(T + "Size"))) ?? 0, assignedTask);
    }
}
