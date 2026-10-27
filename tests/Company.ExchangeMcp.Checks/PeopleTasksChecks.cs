using System.Net;
using System.Text;
using System.Xml.Linq;
using System.Xml.Schema;
using Company.ExchangeMcp.Exchange;
using Company.ExchangeMcp.Security;
using Microsoft.Extensions.DependencyInjection;

internal sealed partial class Checks
{
    private async Task PeopleTasksChecksAsync()
    {
        var calls = new List<CapturedEwsRequest>();
        var client = NewEwsClient(new DelegateHandler(async (request, cancellationToken) =>
        {
            var body = await request.Content!.ReadAsStringAsync(cancellationToken);
            var document = XDocument.Parse(body);
            var operation = document.Root!.Element(XName.Get("Body", SoapNamespace))!.Elements().Single();
            calls.Add(new CapturedEwsRequest(operation.Name.LocalName, body, request.Headers,
                document.Descendants(XName.Get("PrimarySmtpAddress", TypesNamespace)).SingleOrDefault()?.Value));
            var isGroup = body.Contains("distributionlist:Members", StringComparison.Ordinal)
                || body.Contains("<t:DistributionList", StringComparison.Ordinal);
            var isTask = body.Contains("<t:Task", StringComparison.Ordinal)
                || body.Contains("task:DueDate", StringComparison.Ordinal)
                || body.Contains("AffectedTaskOccurrences", StringComparison.Ordinal);
            var isFolder = operation.Name.LocalName is "FindFolder" or "GetFolder" or "CreateFolder"
                or "UpdateFolder" or "DeleteFolder";
            var taskFolder = HasDistinguishedFolder(document, "tasks")
                || (operation.Name.LocalName == "FindFolder"
                    && calls.LastOrDefault(call => call.Operation == "GetFolder") is { } previousFolder
                    && HasDistinguishedFolder(XDocument.Parse(previousFolder.Body), "tasks"));
            return Response(PeopleTasksResponse(operation.Name.LocalName, isTask, isGroup, isFolder,
                body.Contains("Value=\"Yearly\"", StringComparison.Ordinal),
                body.Contains("Value=\"RelativeYearly\"", StringComparison.Ordinal),
                body.Contains("Value=\"RelativeMonthly\"", StringComparison.Ordinal),
                taskFolder));
        }));

        var contactInput = new EwsContactInput(
            "Ada Lovelace", GivenName: "Ada", Surname: "Lovelace", CompanyName: "Analytical Engines",
            JobTitle: "Mathematician", EmailAddresses: [new("EmailAddress1", "ada@example.test")],
            PhoneNumbers: [new("MobilePhone", "+1 555 0100")],
            PhysicalAddresses: [new("Business", "1 Engine Street", "London", null, "GB", "N1")],
            Notes: "contact note", Categories: ["research"]);
        var createdContact = await client.CreateContactAsync("alice@example.test", "contacts", contactInput, CancellationToken.None);
        Expect(createdContact.Id == "contact-1", "Contact creation did not parse the returned item reference.");
        var contactXml = XDocument.Parse(calls[^1].Body);
        Expect(Operation(contactXml).Descendants(XName.Get("Contact", TypesNamespace)).Any()
            && calls[^1].Body.Contains("contacts:EmailAddress1", StringComparison.Ordinal) == false
            && calls[^1].Body.Contains("EmailAddress1", StringComparison.Ordinal),
            "Contact creation did not emit the bounded typed contact fields.");

        var contacts = await client.FindContactsAsync("alice@example.test", "contacts", "Ada", 0, 20, CancellationToken.None);
        Expect(contacts.Items.Count == 1 && contacts.Items[0].EmailAddresses.Single().Address == "ada@example.test",
            "Contact listing did not parse the typed response.");
        Expect(calls[^1].Body.Contains("<t:IndexedFieldURI FieldURI=\"contacts:EmailAddress\" FieldIndex=\"EmailAddress1\"", StringComparison.Ordinal)
            && !calls[^1].Body.Contains("<t:IndexedFieldURI FieldURI=\"contacts:EmailAddresses\"", StringComparison.Ordinal),
            "Contact email search did not use the Exchange contact email dictionary field.");
        var contact = await client.GetContactAsync("alice@example.test", "contact-1", CancellationToken.None);
        Expect(contact.CompanyName == "Analytical Engines" && contact.Categories.SequenceEqual(["research"]),
            "Contact read did not preserve company or categories.");
        var readBody = calls[^1].Body;
        var readDocument = XDocument.Parse(readBody);
        var readIndexedFields = readDocument.Descendants(XName.Get("IndexedFieldURI", TypesNamespace)).ToArray();
        Expect(readIndexedFields.Count(field => field.Attribute("FieldURI")?.Value == "contacts:EmailAddress") == 3
            && readIndexedFields.Count(field => field.Attribute("FieldURI")?.Value == "contacts:PhoneNumber") == 23
            && readIndexedFields.Count(field => field.Attribute("FieldURI")?.Value?.StartsWith("contacts:PhysicalAddress:", StringComparison.Ordinal) == true) == 15
            && !readDocument.Descendants(XName.Get("FieldURI", TypesNamespace)).Any(field =>
                field.Attribute("FieldURI")?.Value is "contacts:EmailAddresses" or "contacts:PhoneNumbers" or "contacts:PhysicalAddresses"),
            "Contact read did not request every supported phone/address slot through indexed fields.");
        await client.UpdateContactAsync("alice@example.test", "contact-1", "contact-change",
            contactInput with { DisplayName = "Ada Updated", EmailAddresses = [new("EmailAddress2", "ada2@example.test")] },
            CancellationToken.None);
        var replacementBody = calls[^1].Body;
        var replacementDocument = XDocument.Parse(replacementBody);
        Expect(HasIndexedOperation(replacementDocument, "SetItemField", "contacts:EmailAddress", "EmailAddress2")
            && replacementBody.Contains("<t:Entry Key=\"EmailAddress2\">ada2@example.test</t:Entry>", StringComparison.Ordinal)
            && HasIndexedOperation(replacementDocument, "DeleteItemField", "contacts:EmailAddress", "EmailAddress1")
            && !HasIndexedOperation(replacementDocument, "DeleteItemField", "contacts:EmailAddress", "EmailAddress3")
            && HasIndexedOperation(replacementDocument, "SetItemField", "contacts:PhoneNumber", "MobilePhone")
            && HasIndexedOperation(replacementDocument, "DeleteItemField", "contacts:PhoneNumber", "BusinessPhone")
            && !HasIndexedOperation(replacementDocument, "DeleteItemField", "contacts:PhoneNumber", "BusinessMobile")
            && HasIndexedOperation(replacementDocument, "SetItemField", "contacts:PhysicalAddress:Street", "Business")
            && HasIndexedOperation(replacementDocument, "DeleteItemField", "contacts:PhysicalAddress:State", "Business")
            && HasIndexedOperation(replacementDocument, "SetItemField", "contacts:PhysicalAddress:CountryOrRegion", "Business")
            && replacementBody.Contains("<t:CountryOrRegion>GB</t:CountryOrRegion>", StringComparison.Ordinal)
            && HasIndexedOperation(replacementDocument, "DeleteItemField", "contacts:PhysicalAddress:Street", "Home")
            && !HasIndexedOperation(replacementDocument, "DeleteItemField", "contacts:PhysicalAddress:Street", "Other")
            && !replacementDocument.Descendants(XName.Get("FieldURI", TypesNamespace)).Any(field =>
                field.Attribute("FieldURI")?.Value is "contacts:EmailAddresses" or "contacts:PhoneNumbers" or "contacts:PhysicalAddresses"),
            "Contact update did not replace stored dictionary members without deleting absent slots.");
        await client.UpdateContactAsync("alice@example.test", "contact-1", "contact-change",
            contactInput with { EmailAddresses = null }, CancellationToken.None);
        var clearDocument = XDocument.Parse(calls[^1].Body);
        Expect(HasIndexedOperation(clearDocument, "DeleteItemField", "contacts:EmailAddress", "EmailAddress1")
            && !HasIndexedOperation(clearDocument, "DeleteItemField", "contacts:EmailAddress", "EmailAddress2")
            && !HasIndexedOperation(clearDocument, "DeleteItemField", "contacts:EmailAddress", "EmailAddress3")
            && !clearDocument.Descendants(XName.Get("FieldURI", TypesNamespace)).Any(field =>
                field.Attribute("FieldURI")?.Value == "contacts:EmailAddresses"),
            "Contact email clear did not delete only the stored indexed email slot.");
        await client.UpdateContactAsync("alice@example.test", "contact-1", "contact-change",
            contactInput with { EmailAddresses = null, PhoneNumbers = null, PhysicalAddresses = null }, CancellationToken.None);
        var dictionaryClearDocument = XDocument.Parse(calls[^1].Body);
        Expect(HasIndexedOperation(dictionaryClearDocument, "DeleteItemField", "contacts:PhoneNumber", "MobilePhone")
            && HasIndexedOperation(dictionaryClearDocument, "DeleteItemField", "contacts:PhoneNumber", "BusinessPhone")
            && !HasIndexedOperation(dictionaryClearDocument, "DeleteItemField", "contacts:PhoneNumber", "BusinessMobile")
            && HasIndexedOperation(dictionaryClearDocument, "DeleteItemField", "contacts:PhysicalAddress:PostalCode", "Business")
            && HasIndexedOperation(dictionaryClearDocument, "DeleteItemField", "contacts:PhysicalAddress:Street", "Home")
            && !HasIndexedOperation(dictionaryClearDocument, "DeleteItemField", "contacts:PhysicalAddress:Street", "Other")
            && !dictionaryClearDocument.Descendants(XName.Get("FieldURI", TypesNamespace)).Any(field =>
                field.Attribute("FieldURI")?.Value is "contacts:PhoneNumbers" or "contacts:PhysicalAddresses"),
            "Contact phone and address clear did not delete only stored indexed dictionary members.");
        await AssertThrowsAsync<ArgumentException>(() => client.CreateContactAsync("alice@example.test", "contacts",
            contactInput with { PhoneNumbers = [new("OtherTelephone1", "+1 555 0101")] }, CancellationToken.None));
        await AssertThrowsAsync<ArgumentException>(() => client.CreateContactAsync("alice@example.test", "contacts",
            contactInput with { PhysicalAddresses = [new("OtherAddress", "1 Engine Street", null, null, null, null)] }, CancellationToken.None));
        await AssertThrowsAsync<ArgumentException>(() => client.UpdateContactAsync("alice@example.test", "contact-1", "contact-change",
            contactInput with { PhoneNumbers = [new("OtherTelephone1", "+1 555 0101")] }, CancellationToken.None));
        await AssertThrowsAsync<ArgumentException>(() => client.UpdateContactAsync("alice@example.test", "contact-1", "stale-change",
            contactInput, CancellationToken.None));

        var directory = await client.ResolveDirectoryAsync("alice@example.test", "Ada", 20, CancellationToken.None);
        Expect(directory.Count == 1 && directory[0].PhoneNumber == "+1 555 0100",
            "Directory resolution did not parse the PhoneNumbers dictionary.");

        var groups = await client.FindContactGroupsAsync("alice@example.test", "contacts", null, 0, 20, CancellationToken.None);
        Expect(groups.Items.Count == 1 && groups.Items[0].DisplayName == "Engineering",
            "Contact group listing did not parse the private distribution list.");
        var group = await client.GetContactGroupAsync("alice@example.test", "group-1", CancellationToken.None);
        Expect(group.Members.Count == 2 && group.Members[0].EmailAddress == "ada@example.test",
            "Contact group read did not parse bounded DistributionList members.");
        Expect(calls[^1].Body.Contains("FieldURI=\"distributionlist:Members\"", StringComparison.Ordinal)
            && !calls[^1].Body.Contains("<m:ExpandDL", StringComparison.Ordinal),
            "Contact group read did not request direct DistributionList members.");
        var createdGroup = await client.CreateContactGroupAsync("alice@example.test", "contacts",
            new EwsContactGroupInput("Research", ["ada@example.test", "grace@example.test"]), CancellationToken.None);
        Expect(createdGroup.Id == "group-1" && calls[^1].Body.Contains("<t:DistributionList>", StringComparison.Ordinal)
            && calls[^1].Body.Contains("<t:EmailAddress>ada@example.test</t:EmailAddress>", StringComparison.Ordinal),
            "Contact group creation did not emit the bounded DistributionList shape.");
        var updatedGroup = await client.UpdateContactGroupAsync("alice@example.test", "group-1", "group-change", "Research Team", CancellationToken.None);
        Expect(updatedGroup.Id == "group-1" && calls[^1].Body.Contains("contacts:DisplayName", StringComparison.Ordinal),
            "Contact group update did not use the current change key and display-name field.");

        var contactFolders = await client.ListContactFoldersAsync("alice@example.test", CancellationToken.None);
        Expect(contactFolders.Count == 1 && contactFolders[0].IsDefault,
            "Contact folder listing did not identify the protected default Contacts folder.");
        var createdContactFolder = await client.CreateContactFolderAsync("alice@example.test", "contacts", "Vendors", CancellationToken.None);
        Expect(createdContactFolder.Id == "folder-1" && calls[^1].Body.Contains("<t:ContactsFolder>", StringComparison.Ordinal)
            && !calls[^1].Body.Contains("<t:FolderClass>", StringComparison.Ordinal),
            "Contact folder creation did not emit the typed ContactsFolder shape.");
        var renamedContactFolder = await client.RenameContactFolderAsync("alice@example.test", "folder-1", "folder-change", "Vendors", CancellationToken.None);
        Expect(renamedContactFolder.Id == "folder-1" && calls[^2].Body.Contains("folder:DisplayName", StringComparison.Ordinal),
            "Contact folder rename did not use the current change key and folder display-name field.");
        await client.DeleteContactFolderAsync("alice@example.test", "folder-1", "folder-change", CancellationToken.None);
        Expect(calls[^1].Body.Contains("DeleteType=\"MoveToDeletedItems\"", StringComparison.Ordinal),
            "Contact folder deletion was not recoverable.");
        var defaultTaskFolder = await client.GetTaskFolderAsync("alice@example.test", "tasks", CancellationToken.None);
        Expect(defaultTaskFolder.IsDefault && defaultTaskFolder.FolderClass == "IPF.Task",
            "The distinguished Tasks folder was not marked as protected.");
        var taskFolders = await client.ListTaskFoldersAsync("alice@example.test", CancellationToken.None);
        Expect(taskFolders.Count == 1 && taskFolders[0].IsDefault,
            "Task folder listing did not identify the protected default Tasks folder.");

        var taskInput = new EwsTaskInput(
            "Review design", "<b>Review</b>", "HTML", DateTimeOffset.Parse("2026-10-10T09:00:00Z"),
            DateTimeOffset.Parse("2026-10-12T17:00:00Z"), PercentComplete: 25, Status: "InProgress", Priority: 2,
            ReminderIsSet: true, ReminderDueByUtc: DateTimeOffset.Parse("2026-10-11T09:00:00Z"),
            Categories: ["work"], Recurrence: new EwsTaskRecurrence("weekly", 1, ["Monday"], StartDateUtc: DateTimeOffset.Parse("2026-10-12Z")));
        var createdTask = await client.CreateTaskAsync("alice@example.test", "tasks", taskInput, CancellationToken.None);
        Expect(createdTask.Id == "task-1", "Task creation did not parse the returned item reference.");
        Expect(calls[^1].Body.Contains("<t:WeeklyRecurrence>", StringComparison.Ordinal)
            && calls[^1].Body.Contains("<t:DaysOfWeek>Monday</t:DaysOfWeek>", StringComparison.Ordinal)
            && calls[^1].Body.Contains("<t:Body BodyType=\"HTML\">&lt;b&gt;Review&lt;/b&gt;</t:Body>", StringComparison.Ordinal),
            "Task creation did not emit HTML body or recurrence safely.");
        foreach (var bodyType in new[] { "Text", "HTML" })
        {
            var body = bodyType == "HTML" ? MultilineTaskHtml : "Disposable task\r\n\tSecond line\nLast line\rFinal line";
            // XML parsing normalizes literal line endings; tabs and body text stay unchanged.
            var wireBody = body.Replace("\r\n", "\n", StringComparison.Ordinal).Replace('\r', '\n');
            await client.CreateTaskAsync("alice@example.test", "tasks",
                taskInput with { Body = body, BodyType = bodyType }, CancellationToken.None);
            var createdBody = XDocument.Parse(calls[^1].Body)
                .Descendants(XName.Get("Body", TypesNamespace)).Single();
            Expect(createdBody.Value == wireBody && createdBody.Attribute("BodyType")?.Value == bodyType,
                $"Creating a multiline {bodyType} task changed its text, tabs or type beyond XML line-ending normalization.");
            await client.UpdateTaskAsync("alice@example.test", "task-1", "task-change",
                taskInput with { Body = body, BodyType = bodyType }, CancellationToken.None);
            var updatedBody = XDocument.Parse(calls[^1].Body)
                .Descendants(XName.Get("Body", TypesNamespace)).Single();
            Expect(updatedBody.Value == wireBody && updatedBody.Attribute("BodyType")?.Value == bodyType,
                $"Updating a multiline {bodyType} task changed its text, tabs or type beyond XML line-ending normalization.");
        }
        await client.CreateTaskAsync("alice@example.test", "tasks",
            taskInput with { Body = new string('x', 80_000) }, CancellationToken.None);
        var callsBeforeInvalidText = calls.Count;
        foreach (var invalidBody in new[] { "task\0body", "task\vbody", "task\u007fbody", "task\u0085body", new string('x', 80_001) })
            await AssertThrowsAsync<ArgumentException>(() => client.CreateTaskAsync("alice@example.test", "tasks",
                taskInput with { Body = invalidBody }, CancellationToken.None));
        foreach (var control in new[] { '\r', '\n', '\t' })
        {
            await AssertThrowsAsync<ArgumentException>(() => client.CreateTaskAsync("alice@example.test", "tasks",
                taskInput with { Subject = $"task{control}subject" }, CancellationToken.None));
            await AssertThrowsAsync<ArgumentException>(() => client.CreateTaskAsync("alice@example.test", "tasks",
                taskInput with { Categories = [$"category{control}label"] }, CancellationToken.None));
            await AssertThrowsAsync<ArgumentException>(() => client.CreateContactAsync("alice@example.test", "contacts",
                contactInput with { DisplayName = $"contact{control}name" }, CancellationToken.None));
        }
        Expect(calls.Count == callsBeforeInvalidText,
            "Invalid task body, subject, category or contact text reached Exchange.");
        await client.CreateTaskAsync("alice@example.test", "tasks", taskInput with
        {
            Recurrence = new EwsTaskRecurrence("yearly", 1, DayOfMonth: 10, Month: 10,
                StartDateUtc: DateTimeOffset.Parse("2026-10-12Z"))
        }, CancellationToken.None);
        Expect(calls[^1].Body.Contains("<t:AbsoluteYearlyRecurrence>", StringComparison.Ordinal)
            && calls[^1].Body.Contains("<t:Month>October</t:Month>", StringComparison.Ordinal),
            "Yearly task recurrence did not emit the Exchange month enumeration.");
        await client.CreateTaskAsync("alice@example.test", "tasks", taskInput with
        {
            Recurrence = new EwsTaskRecurrence("monthlyRegeneration", 2,
                StartDateUtc: DateTimeOffset.Parse("2026-10-12Z"))
        }, CancellationToken.None);
        await client.CreateTaskAsync("alice@example.test", "tasks", taskInput with
        {
            Recurrence = new EwsTaskRecurrence("yearlyRegeneration", 2,
                StartDateUtc: DateTimeOffset.Parse("2026-10-12Z"))
        }, CancellationToken.None);
        await client.CreateTaskAsync("alice@example.test", "tasks", taskInput with
        {
            Recurrence = new EwsTaskRecurrence("relativeMonthly", 1, ["Monday"],
                DayOfWeekIndex: "Last", StartDateUtc: DateTimeOffset.Parse("2026-10-12Z"))
        }, CancellationToken.None);
        Expect(calls[^1].Body.Contains("<t:RelativeMonthlyRecurrence>", StringComparison.Ordinal)
            && calls[^1].Body.Contains("<t:DayOfWeekIndex>Last</t:DayOfWeekIndex>", StringComparison.Ordinal),
            "Relative monthly recurrence did not emit its day index.");
        await client.CreateTaskAsync("alice@example.test", "tasks", taskInput with
        {
            Recurrence = new EwsTaskRecurrence("relativeYearly", DaysOfWeek: ["Monday"],
                Month: 10, DayOfWeekIndex: "Last", StartDateUtc: DateTimeOffset.Parse("2026-10-12Z"))
        }, CancellationToken.None);
        Expect(calls[^1].Body.Contains("<t:RelativeYearlyRecurrence>", StringComparison.Ordinal)
            && calls[^1].Body.Contains("<t:Month>October</t:Month>", StringComparison.Ordinal),
            "Relative yearly recurrence did not emit the Exchange month name.");
        var tasks = await client.FindTasksAsync("alice@example.test", "tasks", "Review", 0, 20, CancellationToken.None);
        Expect(tasks.Items.Count == 1 && tasks.Items[0].Priority == 2 && tasks.Items[0].BodyType == "HTML"
            && tasks.Items[0].Recurrence?.Pattern == "dailyRegeneration",
            "Task listing did not parse priority, body type or regeneration recurrence.");
        var yearlyTasks = await client.FindTasksAsync("alice@example.test", "tasks", "Yearly", 0, 20, CancellationToken.None);
        var yearlyRecurrence = yearlyTasks.Items.Single().Recurrence;
        Expect(yearlyRecurrence is { Pattern: "yearly", Month: 10 },
            "Task recurrence parsing did not convert the Exchange month name.");
        var relativeYearlyTasks = await client.FindTasksAsync("alice@example.test", "tasks", "RelativeYearly", 0, 20, CancellationToken.None);
        var relativeYearly = relativeYearlyTasks.Items.Single().Recurrence;
        Expect(relativeYearly is { Pattern: "relativeYearly", Month: 10, DayOfWeekIndex: "Last" },
            "Relative yearly recurrence parsing did not preserve month and day index.");
        var relativeMonthlyTasks = await client.FindTasksAsync("alice@example.test", "tasks", "RelativeMonthly", 0, 20, CancellationToken.None);
        var relativeMonthly = relativeMonthlyTasks.Items.Single().Recurrence;
        Expect(relativeMonthly is { Pattern: "relativeMonthly", Interval: 1, DayOfWeekIndex: "Last" }
            && relativeMonthly.DaysOfWeek is ["Monday"],
            "Relative monthly recurrence parsing did not preserve interval, day and day index.");
        var completed = await client.CompleteTaskAsync("alice@example.test", "task-1", "task-change", CancellationToken.None);
        Expect(completed.Id == "task-1" && calls[^1].Body.Contains("<t:Status>Completed</t:Status>", StringComparison.Ordinal)
            && !calls[^1].Body.Contains("task:IsComplete", StringComparison.Ordinal),
            "Task completion did not emit the completed state.");
        await AssertThrowsAsync<ArgumentException>(() => client.UpdateTaskAsync("alice@example.test", "task-1", "task-change",
            taskInput, CancellationToken.None, clearRecurrence: true));
        await client.UpdateTaskAsync("alice@example.test", "task-1", "task-change",
            taskInput with { Recurrence = null }, CancellationToken.None);
        Expect(!calls[^1].Body.Contains("FieldURI=\"task:Recurrence\"", StringComparison.Ordinal),
            "A task update with no recurrence did not preserve the existing recurrence.");
        await client.UpdateTaskAsync("alice@example.test", "task-1", "task-change",
            taskInput with { Recurrence = null }, CancellationToken.None, clearRecurrence: true);
        Expect(calls[^1].Body.Contains("FieldURI=\"task:Recurrence\"", StringComparison.Ordinal),
            "An explicit recurrence clear did not emit the recurrence delete field.");

        var rejected = false;
        try
        {
            await client.CreateTaskAsync("alice@example.test", "tasks",
                taskInput with { Recurrence = new EwsTaskRecurrence("weekly", 1, []) }, CancellationToken.None);
        }
        catch (ArgumentException) { rejected = true; }
        Expect(rejected, "An invalid recurrence was accepted.");
        await AssertThrowsAsync<ArgumentException>(() => client.CreateTaskAsync("alice@example.test", "tasks",
            taskInput with { Recurrence = new EwsTaskRecurrence("relativeYearly", 2, ["Monday"], Month: 10, DayOfWeekIndex: "Last") }, CancellationToken.None));

        await client.DeleteTaskAsync("alice@example.test", "task-1", "task-change", "series", CancellationToken.None);
        Expect(calls[^1].Body.Contains("AffectedTaskOccurrences=\"AllOccurrences\"", StringComparison.Ordinal),
            "Recurring task series deletion did not emit the explicit all-occurrences scope.");
        await client.DeleteTaskAsync("alice@example.test", "task-1", "task-change", "single", CancellationToken.None);
        Expect(calls[^1].Body.Contains("AffectedTaskOccurrences=\"SpecifiedOccurrenceOnly\"", StringComparison.Ordinal),
            "Recurring task occurrence deletion did not emit the explicit single-occurrence scope.");

        // A mailbox folder handle is deliberately a different opaque kind
        // from a contact-folder handle. It must be rejected before EWS so an
        // Inbox handle can never be used to list or create personal contacts.
        var genericFolderExchange = new RecordingEwsHandler();
        await using (var host = await StartHostAsync(genericFolderExchange, writesEnabled: true, sendEnabled: false))
        {
            var token = Token("user-a", "mail.read mail.write mail.manage");
            await InitializeAsync(host.Client, token);
            var handles = host.App.Services.GetRequiredService<MailboxHandles>();
            var identity = new MailboxIdentity("user-a", "alice@example.test", "chatgpt-test");
            var inboxHandle = handles.Issue(identity, "folder", "inbox", "inbox-change");
            var response = await ToolRequestAsync(host.Client, token, "tools/call", new
            {
                name = "people_list_contacts",
                arguments = new { folder = inboxHandle, offset = 0, limit = 20 }
            });
            var groupResponse = await ToolRequestAsync(host.Client, token, "tools/call", new
            {
                name = "people_create_contact_group",
                arguments = new
                {
                    displayName = "Should not be created",
                    memberEmails = new[] { "ada@example.test" },
                    folder = inboxHandle
                }
            });
            Expect(IsToolError(response.Body) && IsToolError(groupResponse.Body)
                && genericFolderExchange.Calls.Count == 0,
                "A generic mail-folder handle was accepted for contacts or reached EWS.");
        }

        ValidatePeopleTasksSchema(calls);
    }

    private static bool HasDistinguishedFolder(XDocument document, string id) =>
        document.Descendants(XName.Get("DistinguishedFolderId", TypesNamespace))
            .Attributes("Id")
            .Any(attribute => string.Equals(attribute.Value, id, StringComparison.OrdinalIgnoreCase));

    private static bool HasIndexedOperation(XDocument document, string operation, string fieldUri, string fieldIndex) =>
        document.Descendants(XName.Get(operation, TypesNamespace))
            .Elements(XName.Get("IndexedFieldURI", TypesNamespace))
            .Any(field => field.Attribute("FieldURI")?.Value == fieldUri
                && field.Attribute("FieldIndex")?.Value == fieldIndex);

    private static string PeopleTasksResponse(string operation, bool isTask, bool isGroup, bool isFolder,
        bool yearlyRecurrence = false, bool relativeYearlyRecurrence = false, bool relativeMonthlyRecurrence = false,
        bool taskFolder = false)
    {
        if (isFolder)
        {
            var folder = taskFolder
                ? "<t:TasksFolder><t:FolderId Id='task-folder-1' ChangeKey='task-folder-change'/><t:FolderClass>IPF.Task</t:FolderClass><t:DisplayName>Tasks</t:DisplayName><t:TotalCount>0</t:TotalCount><t:ChildFolderCount>0</t:ChildFolderCount></t:TasksFolder>"
                : operation == "UpdateFolder"
                ? "<t:Folder><t:FolderId Id='folder-1' ChangeKey='folder-change'/><t:FolderClass>IPF.Contact</t:FolderClass><t:DisplayName>Vendors</t:DisplayName><t:TotalCount>0</t:TotalCount><t:ChildFolderCount>0</t:ChildFolderCount></t:Folder>"
                : "<t:ContactsFolder><t:FolderId Id='folder-1' ChangeKey='folder-change'/><t:FolderClass>IPF.Contact</t:FolderClass><t:DisplayName>Contacts</t:DisplayName><t:TotalCount>0</t:TotalCount><t:ChildFolderCount>0</t:ChildFolderCount></t:ContactsFolder>";
            var folders = folder;
            return $"<s:Envelope xmlns:s='{SoapNamespace}' xmlns:m='{MessagesNamespace}' xmlns:t='{TypesNamespace}'><s:Body><m:{operation}Response><m:ResponseMessages><m:{operation}ResponseMessage ResponseClass='Success'><m:ResponseCode>NoError</m:ResponseCode></m:{operation}ResponseMessage></m:ResponseMessages>{(operation == "FindFolder" ? $"<m:RootFolder IncludesLastItemInRange='true'><t:Folders>{folders}</t:Folders></m:RootFolder>" : $"<m:Folders>{folders}</m:Folders>")}</m:{operation}Response></s:Body></s:Envelope>";
        }
        var itemName = isTask ? "Task" : "Contact";
        if (operation == "ResolveNames")
            return $"<s:Envelope xmlns:s='{SoapNamespace}' xmlns:m='{MessagesNamespace}' xmlns:t='{TypesNamespace}'><s:Body><m:ResolveNamesResponse><m:ResponseMessages><m:ResolveNamesResponseMessage ResponseClass='Success'><m:ResponseCode>NoError</m:ResponseCode><m:ResolutionSet TotalItemsInView='1' IncludesLastItemInRange='true'><t:Resolution><t:Mailbox><t:Name>Ada Lovelace</t:Name><t:EmailAddress>ada@example.test</t:EmailAddress><t:RoutingType>SMTP</t:RoutingType><t:MailboxType>Mailbox</t:MailboxType></t:Mailbox><t:Contact><t:DisplayName>Ada Lovelace</t:DisplayName><t:CompanyName>Analytical Engines</t:CompanyName><t:PhoneNumbers><t:Entry Key='BusinessPhone'>+1 555 0100</t:Entry></t:PhoneNumbers></t:Contact></t:Resolution></m:ResolutionSet></m:ResolveNamesResponseMessage></m:ResponseMessages></m:ResolveNamesResponse></s:Body></s:Envelope>";
        var taskRecurrence = relativeMonthlyRecurrence
            ? "<t:RelativeMonthlyRecurrence><t:Interval>1</t:Interval><t:DaysOfWeek>Monday</t:DaysOfWeek><t:DayOfWeekIndex>Last</t:DayOfWeekIndex></t:RelativeMonthlyRecurrence>"
            : relativeYearlyRecurrence
            ? "<t:RelativeYearlyRecurrence><t:DaysOfWeek>Monday</t:DaysOfWeek><t:DayOfWeekIndex>Last</t:DayOfWeekIndex><t:Month>October</t:Month></t:RelativeYearlyRecurrence>"
            : yearlyRecurrence
            ? "<t:AbsoluteYearlyRecurrence><t:DayOfMonth>10</t:DayOfMonth><t:Month>October</t:Month></t:AbsoluteYearlyRecurrence>"
            : "<t:DailyRegeneration><t:Interval>2</t:Interval></t:DailyRegeneration>";
        var item = isGroup
            ? "<t:DistributionList><t:ItemId Id='group-1' ChangeKey='group-change'/><t:DisplayName>Engineering</t:DisplayName><t:Members><t:Member><t:Mailbox><t:Name>Ada Lovelace</t:Name><t:EmailAddress>ada@example.test</t:EmailAddress><t:RoutingType>SMTP</t:RoutingType><t:MailboxType>Mailbox</t:MailboxType></t:Mailbox></t:Member><t:Member><t:Mailbox><t:Name>Grace Hopper</t:Name><t:EmailAddress>grace@example.test</t:EmailAddress><t:RoutingType>SMTP</t:RoutingType><t:MailboxType>Mailbox</t:MailboxType></t:Mailbox></t:Member></t:Members></t:DistributionList>"
            : isTask
            ? $"<t:Task><t:ItemId Id='task-1' ChangeKey='task-change'/><t:Subject>Review design</t:Subject><t:Body BodyType='HTML'>&lt;b&gt;Review&lt;/b&gt;</t:Body><t:StartDate>2026-10-10T09:00:00Z</t:StartDate><t:DueDate>2026-10-12T17:00:00Z</t:DueDate><t:PercentComplete>25</t:PercentComplete><t:Status>InProgress</t:Status><t:IsComplete>false</t:IsComplete><t:IsRecurring>true</t:IsRecurring><t:Importance>High</t:Importance><t:ReminderIsSet>true</t:ReminderIsSet><t:ReminderDueBy>2026-10-11T09:00:00Z</t:ReminderDueBy><t:Categories><t:String>work</t:String></t:Categories><t:Recurrence>{taskRecurrence}<t:NoEndRecurrence><t:StartDate>2026-10-10</t:StartDate></t:NoEndRecurrence></t:Recurrence></t:Task>"
             : "<t:Contact><t:ItemId Id='contact-1' ChangeKey='contact-change'/><t:DisplayName>Ada Lovelace</t:DisplayName><t:GivenName>Ada</t:GivenName><t:Surname>Lovelace</t:Surname><t:CompanyName>Analytical Engines</t:CompanyName><t:JobTitle>Mathematician</t:JobTitle><t:EmailAddresses><t:Entry Key='EmailAddress1'>ada@example.test</t:Entry></t:EmailAddresses><t:PhoneNumbers><t:Entry Key='BusinessPhone'>+1 555 0199</t:Entry><t:Entry Key='MobilePhone'>+1 555 0100</t:Entry></t:PhoneNumbers><t:PhysicalAddresses><t:Entry Key='Business'><t:Street>1 Engine Street</t:Street><t:City>London</t:City><t:State>England</t:State><t:CountryOrRegion>GB</t:CountryOrRegion><t:PostalCode>N1</t:PostalCode></t:Entry><t:Entry Key='Home'><t:Street>2 Home Street</t:Street><t:City>London</t:City><t:State>England</t:State><t:CountryOrRegion>GB</t:CountryOrRegion><t:PostalCode>N2</t:PostalCode></t:Entry></t:PhysicalAddresses><t:Categories><t:String>research</t:String></t:Categories><t:Body BodyType='Text'>contact note</t:Body></t:Contact>";
        var result = operation switch
        {
            "FindItem" => $"<m:RootFolder IncludesLastItemInRange='true'><t:Items>{item}</t:Items></m:RootFolder>",
            "GetItem" => $"<m:Items>{item}</m:Items>",
            _ => $"<m:Items><t:{(isGroup ? "DistributionList" : itemName)}><t:ItemId Id='{(isGroup ? "group-1" : isTask ? "task-1" : "contact-1")}' ChangeKey='{(isGroup ? "group-change" : isTask ? "task-change" : "contact-change")}'/></t:{(isGroup ? "DistributionList" : itemName)}></m:Items>"
        };
        return $"<s:Envelope xmlns:s='{SoapNamespace}' xmlns:m='{MessagesNamespace}' xmlns:t='{TypesNamespace}'><s:Body><m:{operation}Response><m:ResponseMessages><m:{operation}ResponseMessage ResponseClass='Success'><m:ResponseCode>NoError</m:ResponseCode></m:{operation}ResponseMessage></m:ResponseMessages>{result}</m:{operation}Response></s:Body></s:Envelope>";
    }

    private static void ValidatePeopleTasksSchema(IReadOnlyList<CapturedEwsRequest> calls)
    {
        var schemas = LoadOptionalExchangeSchemas();
        var relevant = calls.Where(call => call.Operation is "CreateItem" or "UpdateItem" or "FindItem" or "GetItem"
            or "CreateFolder" or "UpdateFolder" or "FindFolder" or "GetFolder" or "DeleteFolder" or "DeleteItem").ToArray();
        Expect(relevant.Length > 0, "People/tasks fixture did not capture any EWS operation for schema validation.");
        foreach (var call in relevant)
        {
            var document = XDocument.Parse(call.Body, LoadOptions.PreserveWhitespace);
            var operation = document.Root?.Element(XName.Get("Body", SoapNamespace))?.Elements().Single()
                ?? throw new InvalidOperationException($"SOAP operation {call.Operation} was not captured.");
            if (schemas is not null)
                new XDocument(new XElement(operation)).Validate(schemas, (_, error) => throw new InvalidOperationException(
                    $"Exchange 2019 schema rejected people/tasks {call.Operation}: {error.Message}"));
        }
    }
}
