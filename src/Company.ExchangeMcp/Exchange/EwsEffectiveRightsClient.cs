using System.Xml;
using System.Xml.Linq;

namespace Company.ExchangeMcp.Exchange;

public sealed partial class EwsClient
{
    /// <summary>
    /// Reads Exchange's folder EffectiveRights field for the selected mailbox.
    /// This does not query or infer FullAccess, SendAs, or SendOnBehalf rights.
    /// </summary>
    public async Task<EwsFolderAccessRights> GetEffectiveRightsAsync(
        string mailbox,
        string folderId,
        CancellationToken cancellationToken)
    {
        var normalizedMailbox = ValidateMailbox(mailbox);
        var normalizedFolder = ValidateItemId(folderId, "folder");
        var operation = new XElement(
            M + "GetFolder",
            new XElement(
                M + "FolderShape",
                new XElement(T + "BaseShape", "IdOnly"),
                new XElement(T + "AdditionalProperties", Field("folder:EffectiveRights"))),
            new XElement(M + "FolderIds", EffectiveRightsFolderReference(normalizedFolder)));

        var document = await SendAsync(normalizedMailbox, operation, cancellationToken).ConfigureAwait(false);
        var responseMessages = document.Descendants(M + "GetFolderResponseMessage").ToArray();
        if (responseMessages.Length != 1)
            throw new InvalidOperationException("Exchange returned an invalid folder-rights response.");
        var folderContainers = responseMessages[0].Elements(M + "Folders").ToArray();
        if (folderContainers.Length != 1)
            throw new InvalidOperationException("Exchange returned an invalid folder-rights response.");
        var folders = folderContainers[0].Elements().ToArray();
        if (folders.Length != 1 || !IsSupportedFolder(folders[0]))
            throw new InvalidOperationException("Exchange returned an invalid folder-rights response.");
        var folder = folders[0];
        var rights = folder.Element(T + "EffectiveRights");
        if (rights is null)
        {
            return new EwsFolderAccessRights(null, null, null, null);
        }

        return new EwsFolderAccessRights(
            ReadRequiredBool(rights, "Read"),
            ReadRequiredBool(rights, "CreateContents"),
            ReadRequiredBool(rights, "Modify"),
            ReadRequiredBool(rights, "Delete"));
    }

    private static bool IsSupportedFolder(XElement folder) =>
        folder.Name.Namespace == T
        && folder.Name.LocalName is "Folder" or "CalendarFolder" or "SearchFolder" or "ContactsFolder" or "TasksFolder";

    private static XElement EffectiveRightsFolderReference(string value) =>
        value.Equals("calendar", StringComparison.OrdinalIgnoreCase)
            ? new XElement(T + "DistinguishedFolderId", new XAttribute("Id", "calendar"))
            : value.Equals("tasks", StringComparison.OrdinalIgnoreCase)
                ? new XElement(T + "DistinguishedFolderId", new XAttribute("Id", "tasks"))
            : FolderReference(value);

    private static bool ReadRequiredBool(XElement parent, string name)
    {
        var elements = parent.Elements(T + name).ToArray();
        if (elements.Length != 1)
            throw new InvalidOperationException($"Exchange returned incomplete folder-rights metadata: {name}.");

        try { return XmlConvert.ToBoolean(elements[0].Value.Trim()); }
        catch (FormatException) { throw new InvalidOperationException("Exchange returned malformed folder-rights metadata."); }
    }
}
