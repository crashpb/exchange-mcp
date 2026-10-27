using System.Net;
using System.Buffers.Binary;
using System.DirectoryServices.Protocols;
using System.Globalization;
using System.Text;
using System.Xml.Linq;
using Company.ExchangeMcp.Exchange;
using Company.ExchangeMcp.Security;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

internal sealed partial class Checks
{
    private const string TaskGlobalId = "AAECAwQFBgcICQoLDA0ODw==";
    private const string MultilineTaskHtml = "<html>\r\n<body>\r\n\t<p>Disposable task</p>\r\n\t<table><tr><td>Task evidence</td></tr></table>\r\n\t<img src=\"cid:cid-task-evidence\">\r\n</body>\r\n</html>";

    private async Task TaskAssignmentChecksAsync()
    {
        AssertCanonicalAndLegacyTaskAssignerStacks();
        var exchange = new TaskAssignmentRecordingHandler { UnassignedTask = true };
        var client = NewEwsClient(exchange, taskDirectory: NewTaskAssignerDirectory());

        var initialNullExchange = new TaskAssignmentRecordingHandler
        {
            UnassignedTask = true,
            OmitAssignerStack = true,
            TaskVersion = 1
        };
        var initialNullClient = NewEwsClient(initialNullExchange);
        var initialNullAssignment = await initialNullClient.PrepareTaskAssignmentAsync(
            "alice@example.test", "task-1", "bob@example.test", keepUpdated: false,
            completionReport: false, reassign: false, CancellationToken.None,
            actionTimeUtc: DateTimeOffset.Parse("2026-10-12T10:00:00.123Z", CultureInfo.InvariantCulture));
        AssertTaskSend(initialNullAssignment, "IPM.TaskRequest", "bob@example.test", TaskGlobalId,
            expectedVersion: "2", requireAssignerStack: false);
        var initialNullResult = await initialNullClient.ExecuteTaskActionAsync(
            "alice@example.test", initialNullAssignment, CancellationToken.None);
        var initialNullUpdate = XDocument.Parse(initialNullExchange.Calls
            .Last(call => call.Operation == "UpdateItem").Body);
        Expect(initialNullResult.Sent && initialNullResult.Applied
            && TaskUpdateValue(initialNullUpdate, "0x8117") is null
            && TaskDeleteField(initialNullUpdate, "0x8121"),
            "An initial task assignment did not delete the native PidLidTaskAssigner from the source copy.");

        foreach (var (wire, numeric) in new[]
        {
            ("NoMatch", 0), ("OwnNew", 1), ("Owned", 2), ("Accepted", 3)
        })
        {
            var freshChangeKey = $"acceptance-{numeric}-change";
            var aliasExchange = new TaskAssignmentRecordingHandler
            {
                AcceptanceWireOverride = wire,
                TaskChangeKey = freshChangeKey
            };
            var aliasClient = NewEwsClient(aliasExchange);
            var aliasTask = await aliasClient.GetTaskAsync(
                "alice@example.test", "task-1", CancellationToken.None);
            Expect(aliasTask.Assignment?.AcceptanceState == numeric
                && aliasTask.ChangeKey == freshChangeKey
                && aliasTask.Subject == "Verify assignment"
                && aliasTask.Body == "Disposable task"
                && aliasExchange.CreateItemCount == 0,
                $"Native task acceptance wire alias {wire} did not round-trip to {numeric} with the unchanged personal task shape.");
        }
        var numericExchange = new TaskAssignmentRecordingHandler { AcceptanceWireOverride = "2" };
        var numericTask = await NewEwsClient(numericExchange).GetTaskAsync(
            "alice@example.test", "task-1", CancellationToken.None);
        Expect(numericTask.Assignment?.AcceptanceState == 2,
            "Numeric native task acceptance values lost compatibility.");
        var invalidExchange = new TaskAssignmentRecordingHandler { AcceptanceWireOverride = "Declined" };
        await AssertThrowsAsync<InvalidOperationException>(() => NewEwsClient(invalidExchange).GetTaskAsync(
            "alice@example.test", "task-1", CancellationToken.None));

        var assignmentBefore = DateTimeOffset.UtcNow.AddSeconds(-1);
        var preciseTime = DateTimeOffset.UtcNow.ToOffset(TimeSpan.FromMinutes(210));
        preciseTime = preciseTime.AddTicks(4567 - preciseTime.Ticks % TimeSpan.TicksPerMillisecond);
        var assignment = await client.PrepareTaskAssignmentAsync(
            "alice@example.test", "task-1", "bob@example.test", keepUpdated: true,
            completionReport: true, reassign: false, CancellationToken.None, actionTimeUtc: preciseTime);
        var assignmentAfter = DateTimeOffset.UtcNow.AddSeconds(1);
        AssertTaskSend(assignment, "IPM.TaskRequest", "bob@example.test", TaskGlobalId,
            expectedVersion: "3");
        Expect(assignment.SourceChangeKey == "task-change" && assignment.TaskGlobalId == TaskGlobalId
            && assignment.Digest.Length == 64 && !string.IsNullOrWhiteSpace(assignment.StableCorrelation)
            && assignment.ActionTimeUtc >= assignmentBefore && assignment.ActionTimeUtc <= assignmentAfter,
            "Task assignment did not retain its Exchange version, global identifier, and approval digest.");
        Expect(assignment.ActionTimeUtc == preciseTime.ToUniversalTime()
            && assignment.ActionTimeUtc.Ticks % TimeSpan.TicksPerMillisecond == 4567,
            "Task property wire formatting truncated the native approval timestamp.");

        var assignmentRepeat = await client.PrepareTaskAssignmentAsync(
            "alice@example.test", "task-1", "bob@example.test", keepUpdated: true,
            completionReport: true, reassign: false, CancellationToken.None,
            actionTimeUtc: assignment.ActionTimeUtc);
        Expect(assignment.PayloadXml == assignmentRepeat.PayloadXml && assignment.Digest == assignmentRepeat.Digest
            && assignment.StableCorrelation == assignmentRepeat.StableCorrelation,
            "Repeated task assignment preparation was not deterministic.");

        exchange.UnassignedTask = false;
        var reassignment = await client.PrepareTaskAssignmentAsync(
            "alice@example.test", "task-1", "carol@example.test", keepUpdated: false,
            completionReport: false, reassign: true, CancellationToken.None);
        // Outlook sends a reassignment as the same native TaskRequest class;
        // the mode/global-id/assigner chain distinguishes it from a new task.
        AssertTaskSend(reassignment, "IPM.TaskRequest", "carol@example.test", TaskGlobalId,
            expectedVersion: "3");
        Expect(reassignment.IsReassignment && reassignment.TaskGlobalId == assignment.TaskGlobalId
            && reassignment.AssigneeAddress == "carol@example.test"
            && reassignment.SourceId == assignment.SourceId,
            "Task reassignment did not preserve the native GlobalID/source task while changing the recipient chain.");

        var reassignmentRepeat = await client.PrepareTaskAssignmentAsync(
            "alice@example.test", "task-1", "carol@example.test", keepUpdated: false,
            completionReport: false, reassign: true, CancellationToken.None,
            actionTimeUtc: reassignment.ActionTimeUtc);
        Expect(reassignment.PayloadXml == reassignmentRepeat.PayloadXml && reassignment.Digest == reassignmentRepeat.Digest,
            "Repeated task reassignment preparation was not deterministic.");

        var progress = await client.PrepareTaskProgressAsync(
            "alice@example.test", "task-1", 50, "InProgress", CancellationToken.None);
        AssertTaskSend(progress, "IPM.TaskRequest.Update", "bob@example.test", TaskGlobalId,
            expectedVersion: "3");
        Expect(progress.PercentComplete == 50 && progress.Status == "InProgress",
            "Task progress did not preserve the bounded percentage and status.");
        var progressRepeat = await client.PrepareTaskProgressAsync(
            "alice@example.test", "task-1", 50, "InProgress", CancellationToken.None,
            actionTimeUtc: progress.ActionTimeUtc);
        Expect(progress.PayloadXml == progressRepeat.PayloadXml && progress.Digest == progressRepeat.Digest,
            "Repeated task progress preparation was not deterministic.");
        await AssertThrowsAsync<ArgumentException>(() => client.PrepareTaskProgressAsync(
            "alice@example.test", "task-1", 50, "NotStarted", CancellationToken.None));
        await AssertThrowsAsync<ArgumentException>(() => client.PrepareTaskProgressAsync(
            "alice@example.test", "task-1", 100, "InProgress", CancellationToken.None));
        await AssertThrowsAsync<ArgumentException>(() => client.PrepareTaskProgressAsync(
            "alice@example.test", "task-1", 100, "WaitingOnOthers", CancellationToken.None));
        await AssertThrowsAsync<ArgumentException>(() => client.PrepareTaskProgressAsync(
            "alice@example.test", "task-1", 100, "Deferred", CancellationToken.None));
        var notStarted = await client.PrepareTaskProgressAsync(
            "alice@example.test", "task-1", 0, "NotStarted", CancellationToken.None);
        var completed = await client.PrepareTaskProgressAsync(
            "alice@example.test", "task-1", 100, "Completed", CancellationToken.None);
        Expect(notStarted.PercentComplete == 0 && notStarted.Status == "NotStarted"
            && completed.PercentComplete == 100 && completed.Status == "Completed",
            "Valid task progress boundary states were rejected or changed.");

        var accepted = await client.PrepareTaskResponseAsync(
            "alice@example.test", "request-1", responseAccept: true, CancellationToken.None);
        AssertTaskSend(accepted, "IPM.TaskRequest.Accept", "bob@example.test", TaskGlobalId,
            expectedState: "2", expectedOwnership: "2", expectedAcceptance: "2", expectedVersion: "3");
        var declined = await client.PrepareTaskResponseAsync(
            "alice@example.test", "request-1", responseAccept: false, CancellationToken.None);
        AssertTaskSend(declined, "IPM.TaskRequest.Decline", "bob@example.test", TaskGlobalId,
            expectedState: "4", expectedOwnership: "2", expectedAcceptance: "3", expectedVersion: "3");

        var request = await client.ReadTaskAssignmentMessageAsync(
            "alice@example.test", "request-1", CancellationToken.None);
        Expect(request.ItemClass == "IPM.TaskRequest" && request.Task?.Assignment is { } requestAssignment
            && requestAssignment.GlobalTaskId == TaskGlobalId
            && requestAssignment.Version == 2 && requestAssignment.State == 3
            && requestAssignment.Ownership == 1 && requestAssignment.AcceptanceState == 1
            && request.Mode == 1 && request.EmbeddedTaskClass == "IPM.Task"
            && request.EmbeddedTaskIsInline == true
            && request.ToRecipients.SequenceEqual(["alice@example.test"])
            && request.From == "bob@example.test" && !request.IsProcessed,
            "Native task request parsing did not preserve class, target, sender, global ID, and assignment state.");
        var legacyWireExchange = new TaskAssignmentRecordingHandler
        {
            TaskVersion = 1,
            OmitTaskAttachmentInline = true
        };
        var legacyRequest = await NewEwsClient(legacyWireExchange).ReadTaskAssignmentMessageAsync(
            "alice@example.test", "request-1", CancellationToken.None);
        Expect(legacyRequest.Task?.Assignment?.Version == 1
            && legacyRequest.EmbeddedTaskIsInline is null,
            "Legacy version-1 task requests or native omitted ItemAttachment IsInline did not remain readable.");
        var assignmentShape = XDocument.Parse(exchange.Calls.Last(call =>
            call.Operation == "GetItem" && call.Body.Contains("item:Attachments", StringComparison.Ordinal)).Body);
        var shapeUris = assignmentShape.Descendants(XName.Get("ExtendedFieldURI", TypesNamespace))
            .Where(value => value.Attribute("PropertySetId") is not null && value.Attribute("PropertyId") is not null)
            .ToArray();
        var invalidShapePropertyIds = shapeUris
            .Where(value => !int.TryParse(value.Attribute("PropertyId")!.Value, NumberStyles.Integer,
                CultureInfo.InvariantCulture, out _))
            .Select(value => value.Attribute("PropertyId")!.Value)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        var shapeFields = shapeUris
            .Select(value => NamedPropertyKey(value.Attribute("PropertySetId")!.Value,
                value.Attribute("PropertyId")!.Value))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var commonSet = "00062008-0000-0000-C000-000000000046";
        var taskSet = "00062003-0000-0000-C000-000000000046";
        var requiredFields = new[]
        {
            NamedPropertyKey(commonSet, "0x8519"), NamedPropertyKey(commonSet, "0x8518"), NamedPropertyKey(taskSet, "0x8113"),
            NamedPropertyKey(taskSet, "0x8129"), NamedPropertyKey(taskSet, "0x812A"), NamedPropertyKey(taskSet, "0x8112"),
            NamedPropertyKey(taskSet, "0x8108"), NamedPropertyKey(taskSet, "0x811A"), NamedPropertyKey(taskSet, "0x811B"),
            NamedPropertyKey(taskSet, "0x8119"), NamedPropertyKey(taskSet, "0x8121"), NamedPropertyKey(taskSet, "0x811F"),
            NamedPropertyKey(taskSet, "0x8122"), NamedPropertyKey(taskSet, "0x8125"), NamedPropertyKey(taskSet, "0x8115"),
            NamedPropertyKey(taskSet, "0x8117")
        };
        var missingFields = requiredFields.Where(field => !shapeFields.Contains(field)).ToArray();
        Expect(missingFields.Length == 0 && !shapeFields.Contains(NamedPropertyKey(commonSet, "0x23")),
            $"Task assignment reads did not request the complete canonical Outlook named-property set. Missing: {string.Join(", ", missingFields)}; invalid PropertyId values: {string.Join(", ", invalidShapePropertyIds)}.");
        var attachmentCall = exchange.Calls.Last(call => call.Operation == "GetAttachment");
        var attachmentDocument = XDocument.Parse(attachmentCall.Body);
        var attachmentShape = attachmentDocument.Descendants(XName.Get("AttachmentShape", MessagesNamespace)).Single();
        Expect(!attachmentShape.Elements(XName.Get("BaseShape", TypesNamespace)).Any(),
            "Exchange 2019 GetAttachment used BaseShape under AttachmentResponseShapeType, which is not valid EWS schema.");
        var attachmentFields = attachmentShape.Element(XName.Get("AdditionalProperties", TypesNamespace))?
            .Elements(XName.Get("ExtendedFieldURI", TypesNamespace))
            .Where(value => value.Attribute("PropertySetId") is not null
                && value.Attribute("PropertyId") is not null)
            .Select(value => NamedPropertyKey(value.Attribute("PropertySetId")!.Value,
                value.Attribute("PropertyId")!.Value))
            .ToHashSet(StringComparer.OrdinalIgnoreCase)
            ?? new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        Expect(requiredFields.All(attachmentFields.Contains),
            "GetAttachment did not request the complete canonical Outlook named-property set.");

        var messages = await client.ListTaskAssignmentMessagesAsync(
            "alice@example.test", 0, 20, CancellationToken.None);
        Expect(messages.Items.Count == 1 && messages.Items[0].GlobalTaskId == TaskGlobalId,
            "Task assignment message listing did not return its native correlation identifier.");
        var status = await client.GetTaskAssignmentStatusAsync(
            "alice@example.test", "task-1", CancellationToken.None);
        Expect(status.GlobalTaskId == TaskGlobalId && status.Version == 2 && status.State == 2
            && status.Ownership == 2 && status.AssignerName == "bob@example.test"
            && status.OwnerName == "alice@example.test"
            && status.Status == "InProgress" && status.PercentComplete == 25,
            "Task assignment status did not expose the EWS task status/progress alongside the native version, state, ownership, assigner, and owner.");

        var executed = await client.ExecuteTaskActionAsync("alice@example.test", assignment, CancellationToken.None);
        Expect(executed.Sent && executed.Applied && exchange.CreateItemCount == 1,
            "Approved task assignment did not send exactly one native task request.");
        Expect(exchange.Calls.Single(call => call.Operation == "CreateItem").Body.Contains(
            "MessageDisposition=\"SendAndSaveCopy\"", StringComparison.Ordinal),
            "Task assignment did not use a send-and-save native EWS disposition.");

        var acceptedResult = await client.ExecuteTaskActionAsync("alice@example.test", accepted, CancellationToken.None);
        var acceptedCreates = exchange.Calls.Where(call => call.Operation == "CreateItem").ToArray();
        var acceptedLocalDocument = XDocument.Parse(acceptedCreates[^2].Body);
        var acceptedLocalTask = acceptedLocalDocument.Descendants(XName.Get("Task", TypesNamespace)).Single();
        var acceptedLocalProperties = ReadNamedProperties(
            acceptedLocalTask.Elements(XName.Get("ExtendedProperty", TypesNamespace)));
        var acceptedLocalSummary = $"creates={acceptedCreates.Length}; saved={acceptedCreates[^2].Body.Contains("<m:SavedItemFolderId>", StringComparison.Ordinal)}; "
            + string.Join(", ", acceptedLocalProperties.Select(value => $"{value.Key}={value.Value}"));
        Expect(acceptedResult.Sent && acceptedResult.Applied && acceptedCreates.Length == 3
            && acceptedCreates[^2].Body.Contains("<m:SavedItemFolderId>", StringComparison.Ordinal)
            && acceptedLocalProperties[NamedPropertyKey("00062008-0000-0000-C000-000000000046", "0x8519")] == TaskGlobalId
            && acceptedLocalProperties[NamedPropertyKey("00062008-0000-0000-C000-000000000046", "0x8518")] == "0"
            && acceptedLocalProperties[NamedPropertyKey("00062003-0000-0000-C000-000000000046", "0x8129")] == "2"
            // The saved local task is the recipient's accepted copy. Exchange
            // records the response in the communication and leaves the local
            // copy's acceptance state at None (0); the response version is the
            // source version incremented while accepting (fixture version 2 -> 3).
            && acceptedLocalProperties[NamedPropertyKey("00062003-0000-0000-C000-000000000046", "0x812A")] == TaskAcceptanceWire("0")
            && acceptedLocalProperties[NamedPropertyKey("00062003-0000-0000-C000-000000000046", "0x8113")] == "2"
            && acceptedLocalProperties[NamedPropertyKey("00062003-0000-0000-C000-000000000046", "0x8112")] == "3",
            $"Accepted task processing did not create the local Task with native ownership, acceptance, state, GlobalID, and version metadata. Actual: {acceptedLocalSummary}");

        var declinedResult = await client.ExecuteTaskActionAsync(
            "alice@example.test", declined, CancellationToken.None);
        Expect(declinedResult.Sent && declinedResult.Applied
            && exchange.Calls.Count(call => call.Operation == "CreateItem") == 4,
            "Approved task decline did not send exactly one native decline notice.");
        var delegatedAccess = new MailboxAccess(Options.Create(new ServiceOptions
        {
            Mailboxes = new Dictionary<string, string> { ["user-a"] = "alice@example.test" },
            AllowedClientIds = ["check-client"]
        }));
        var delegatedClient = new EwsClient(new HttpClient(exchange),
            Options.Create(new EwsOptions
            {
                Endpoint = "https://mail.example.test/EWS/Exchange.asmx",
                TimeoutSeconds = 10,
                MaxResponseBytes = 2_097_152
            }), delegatedAccess);
        using (delegatedAccess.SelectTarget(new MailboxIdentity(
                   "user-a", "it@example.test", "check-client", TargetId: DiscoveryMailboxKey,
                   ActorMailbox: "alice@example.test")))
        {
            await delegatedClient.ListTaskAssignmentMessagesAsync(
                "it@example.test", 0, 20, CancellationToken.None);
        }
        var delegatedWire = exchange.Calls.Last(call => call.Operation == "FindItem");
        var delegatedDocument = XDocument.Parse(delegatedWire.Body);
        var delegatedTargetAddresses = delegatedDocument
            .Descendants(XName.Get("DistinguishedFolderId", TypesNamespace))
            .SelectMany(folder => folder.Elements(XName.Get("Mailbox", TypesNamespace)))
            .SelectMany(mailbox => mailbox.Elements(XName.Get("EmailAddress", TypesNamespace)))
            .Select(value => value.Value)
            .ToArray();
        var anchors = delegatedWire.Headers.TryGetValues("X-AnchorMailbox", out var headerValues)
            ? headerValues.ToArray()
            : Array.Empty<string>();
        Expect(delegatedWire.PrimarySmtpAddress == "alice@example.test"
            && anchors.SequenceEqual(["alice@example.test"])
            && delegatedTargetAddresses.SequenceEqual(["it@example.test"]),
            $"Delegated task requests did not keep the actor ConnectingSID/anchor while binding target folders. Anchors: {string.Join(",", anchors)}; target folders: {string.Join(",", delegatedTargetAddresses)}.");

        var reassignmentResult = await client.ExecuteTaskActionAsync(
            "alice@example.test", reassignment, CancellationToken.None);
        var reassignmentUpdate = XDocument.Parse(exchange.Calls
            .Last(call => call.Operation == "UpdateItem").Body);
        var reassignmentTask = XDocument.Parse(reassignment.PayloadXml!)
            .Descendants(XName.Get("Task", TypesNamespace)).Single();
        var reassignmentProperties = ReadNamedProperties(
            reassignmentTask.Elements(XName.Get("ExtendedProperty", TypesNamespace)));
        var plannedStack = reassignmentProperties.TryGetValue(
            NamedPropertyKey("00062003-0000-0000-C000-000000000046", "0x8117"), out var stack)
            ? stack : null;
        var appliedStack = TaskUpdateValue(reassignmentUpdate, "0x8117");
        Expect(reassignmentResult.Sent && reassignmentResult.Applied
            && plannedStack is not null && appliedStack == plannedStack
            && IsValidTaskAssignerStack(appliedStack)
            && TaskDeleteField(reassignmentUpdate, "0x8121")
            && TaskUpdateValue(reassignmentUpdate, "0x8121") is null
            && TaskUpdateNameValue(reassignmentUpdate, "Company.Exchange.Mcp.TaskAssignerAddress") == "alice@example.test",
            "Task reassignment did not preserve its private assigner correlation while deleting native PidLidTaskAssigner from the tracker copy.");
        var createCountAfterReassignment = exchange.CreateItemCount;
        exchange.TaskChangeKey = "task-change-new";
        await AssertThrowsAsync<InvalidOperationException>(() => client.ExecuteTaskActionAsync(
            "alice@example.test", reassignment, CancellationToken.None));
        Expect(exchange.CreateItemCount == createCountAfterReassignment,
            "A stale task assignment action reached EWS after the source change key changed.");

        exchange.TaskChangeKey = "task-change";
        exchange.ProcessMessage = true;
        exchange.ReturnLocalTaskForFind = true;
        exchange.TaskVersion = 3;
        var process = await client.PrepareTaskProcessAsync(
            "alice@example.test", "request-1", CancellationToken.None);
        var processDocument = XDocument.Parse(process.PayloadXml!);
        Expect(process.Operation == "process"
            && processDocument.Root?.Name == XName.Get("UpdateItem", MessagesNamespace)
            && processDocument.Descendants(XName.Get("ItemChange", TypesNamespace))
                .Any(value => (string?)value.Element(XName.Get("ItemId", TypesNamespace))?.Attribute("Id") == "local-task-1")
            && processDocument.Descendants(XName.Get("ExtendedFieldURI", TypesNamespace))
                .Any(value => PropertyIdMatches(value, "0x812A"))
            && TaskUpdateValue(processDocument, "0x8129") == "1"
            && TaskUpdateValue(processDocument, "0x812A") == TaskAcceptanceWire("2")
            && TaskUpdateValue(processDocument, "0x8113") == "3"
            && TaskUpdateValue(processDocument, "0x8112") == "3"
            && TaskUpdateValue(processDocument, "0x8108") == "true"
            && TaskDeleteField(processDocument, "0x8121")
            && TaskUpdateValue(processDocument, "0x8121") is null
            && TaskUpdateNameValue(processDocument, "Company.Exchange.Mcp.TaskAssignerAddress") == "bob@example.test",
            "Processing a task response did not build the local tracker update with native PidLidTaskAssigner removed and private correlation retained.");
        exchange.TaskVersion = 2;
        await AssertThrowsAsync<InvalidOperationException>(() => client.ExecuteTaskActionAsync(
            "alice@example.test", process, CancellationToken.None));
        exchange.TaskVersion = 3;
        var processed = await client.ExecuteTaskActionAsync(
            "alice@example.test", process, CancellationToken.None);
        var processedMessageUpdates = exchange.Calls
            .Where(call => call.Operation == "UpdateItem"
                && call.Body.Contains("PropertyTag=\"0x7D01\"", StringComparison.Ordinal))
            .ToArray();
        Expect(!processed.Sent && processed.Applied && exchange.UpdateItemCount >= 3
            && processedMessageUpdates.Length == 3
            && processedMessageUpdates.All(call =>
                call.Body.Contains("MessageDisposition=\"SaveOnly\"", StringComparison.Ordinal)
                && call.Body.Contains("ConflictResolution=\"NeverOverwrite\"", StringComparison.Ordinal)),
            "A fresh task response was not applied to the original task and marked processed.");

        var nativeAcceptedExchange = new TaskAssignmentRecordingHandler
        {
            ProcessMessage = true,
            ReturnLocalTaskForFind = true,
            NativeAcceptedResponse = true,
            TaskVersion = 4,
            LocalTaskVersion = 2
        };
        var nativeAcceptedClient = NewEwsClient(nativeAcceptedExchange,
            taskDirectory: NewTaskAssignerDirectory());
        var nativeAcceptedProcess = await nativeAcceptedClient.PrepareTaskProcessAsync(
            "alice@example.test", "request-1", CancellationToken.None);
        Expect(nativeAcceptedProcess.Operation == "process"
            && TaskUpdateValue(XDocument.Parse(nativeAcceptedProcess.PayloadXml!), "0x812A") == TaskAcceptanceWire("2")
            && TaskUpdateValue(XDocument.Parse(nativeAcceptedProcess.PayloadXml!), "0x8113") == "3"
            && nativeAcceptedExchange.CreateItemCount == 0,
            "The verified Outlook Accept tuple (State 2, Ownership 2, NoMatch, Accepted=true) was not projected to the MCP accepted tracker state.");

        var nativeAcceptedNoOuterVersionExchange = new TaskAssignmentRecordingHandler
        {
            ProcessMessage = true,
            ReturnLocalTaskForFind = true,
            NativeAcceptedResponse = true,
            OmitTaskRequestVersion = true,
            TaskVersion = 4,
            LocalTaskVersion = 2
        };
        var nativeAcceptedNoOuterVersionClient = NewEwsClient(nativeAcceptedNoOuterVersionExchange,
            taskDirectory: NewTaskAssignerDirectory());
        var nativeAcceptedNoOuterVersionMessage = await nativeAcceptedNoOuterVersionClient.ReadTaskAssignmentMessageAsync(
            "alice@example.test", "request-1", CancellationToken.None);
        var nativeAcceptedNoOuterVersionProcess = await nativeAcceptedNoOuterVersionClient.PrepareTaskProcessAsync(
            "alice@example.test", "request-1", CancellationToken.None);
        Expect(nativeAcceptedNoOuterVersionMessage.ItemClass == "IPM.TaskRequest.Accept"
            && nativeAcceptedNoOuterVersionMessage.Mode == 2
            && nativeAcceptedNoOuterVersionMessage.Version == 4
            && nativeAcceptedNoOuterVersionMessage.Task?.Assignment is
            {
                Version: 4, State: 2, Ownership: 2,
                AcceptanceState: 0, Accepted: true
            }
            && nativeAcceptedNoOuterVersionProcess.Operation == "process"
            && nativeAcceptedNoOuterVersionExchange.CreateItemCount == 0,
            "The verified Outlook Accept tuple did not inherit its missing outer version from the correlated embedded task.");

        foreach (var (version, statusValue, percent, isComplete) in new[]
        {
            (5, "InProgress", 50d, false),
            (6, "Completed", 100d, true)
        })
        {
            var nativeUpdatedExchange = new TaskAssignmentRecordingHandler
            {
                ProcessMessage = true,
                ReturnLocalTaskForFind = true,
                NativeUpdatedResponse = true,
                OmitTaskRequestVersion = true,
                TaskVersion = version,
                LocalTaskVersion = 2,
                NativeTaskStatus = statusValue,
                NativeTaskPercentComplete = percent,
                NativeTaskIsComplete = isComplete,
                NativeTaskCompleteDateUtc = isComplete
                    ? DateTimeOffset.Parse("2026-10-13T13:42:00Z", CultureInfo.InvariantCulture)
                    : null
            };
            var nativeUpdatedClient = NewEwsClient(nativeUpdatedExchange,
                taskDirectory: NewTaskAssignerDirectory());
            var nativeUpdatedMessage = await nativeUpdatedClient.ReadTaskAssignmentMessageAsync(
                "alice@example.test", "request-1", CancellationToken.None);
            var nativeUpdatedProcess = await nativeUpdatedClient.PrepareTaskProcessAsync(
                "alice@example.test", "request-1", CancellationToken.None);
            Expect(nativeUpdatedMessage.ItemClass == "IPM.TaskRequest.Update"
                && nativeUpdatedMessage.Mode == 4
                && nativeUpdatedMessage.Version == version
                && nativeUpdatedMessage.Task?.Status == statusValue
                && nativeUpdatedMessage.Task.PercentComplete == percent
                && nativeUpdatedMessage.Task.IsComplete == isComplete
                && nativeUpdatedMessage.Task.Assignment is
                {
                    Mode: 0, Version: var embeddedVersion,
                    State: 2, Ownership: 2, AcceptanceState: 0,
                    Accepted: true
                }
                && embeddedVersion == version
                && nativeUpdatedProcess.Operation == "process"
                && nativeUpdatedExchange.CreateItemCount == 0,
                $"The native Outlook Update v{version} tuple did not preserve its inner mode, version, and progress fields.");
        }

        var nativeUpdatedMissingTrackerRolesExchange = new TaskAssignmentRecordingHandler
        {
            ProcessMessage = true,
            ReturnLocalTaskForFind = true,
            NativeUpdatedResponse = true,
            NativeReassignmentWatcherLocal = true,
            OmitLocalTaskPrivateRoles = true,
            NativeResponseSender = "bob@example.test",
            OmitTaskRequestVersion = true,
            AcceptedFlagOverride = true,
            TaskVersion = 5,
            LocalTaskVersion = 2,
            NativeTaskOwnerName = "bob@example.test",
            EnableDirectoryResolution = true,
            DirectoryExpectedQuery = string.Empty,
            DirectoryDisplayName = "bob@example.test",
            DirectoryEmailAddress = "bob@example.test"
        };
        var nativeUpdatedMissingTrackerRoles = await NewEwsClient(
            nativeUpdatedMissingTrackerRolesExchange,
            taskDirectory: NewTaskAssignerDirectory()).PrepareTaskProcessAsync(
                "alice@example.test", "request-1", CancellationToken.None);
        Expect(nativeUpdatedMissingTrackerRoles.Operation == "process"
            && nativeUpdatedMissingTrackerRoles.PreviewTask?.Assignment is
            {
                AssignerAddress: "alice@example.test",
                AssigneeAddress: "bob@example.test", OwnerAddress: "bob@example.test"
            }
            && nativeUpdatedMissingTrackerRolesExchange.CreateItemCount == 0
            && nativeUpdatedMissingTrackerRolesExchange.UpdateItemCount == 0,
            "A native progress Update did not hydrate a missing tracker owner before sender validation.");

        var nativeReassignmentRequestExchange = new TaskAssignmentRecordingHandler
        {
            NativeReassignmentRequestResponse = true,
            OmitTaskRequestVersion = true,
            AcceptedFlagOverride = true,
            TaskVersion = 5,
            EnableDirectoryResolution = true,
            DirectoryExpectedQuery = string.Empty,
            DirectoryDisplayName = "mb@example.test",
            DirectoryEmailAddress = "mb@example.test",
            DirectoryStackDisplayName = "IT",
            DirectoryStackEmailAddress = "it@example.test",
            NativeTaskOwnerName = "mb@example.test"
        };
        var nativeReassignmentRequestClient = NewEwsClient(
            nativeReassignmentRequestExchange, taskDirectory: NewTaskAssignerDirectory());
        var nativeReassignmentRequest = await nativeReassignmentRequestClient.ReadTaskAssignmentMessageAsync(
            "mb@example.test", "request-1", CancellationToken.None);
        var nativeReassignmentResponse = await nativeReassignmentRequestClient.PrepareTaskResponseAsync(
            "mb@example.test", "request-1", responseAccept: true, CancellationToken.None);
        var nativeReassignmentPayload = XDocument.Parse(nativeReassignmentResponse.PayloadXml!);
        var nativeReassignmentCc = nativeReassignmentPayload.Descendants(XName.Get("CcRecipients", TypesNamespace))
            .Descendants(XName.Get("EmailAddress", TypesNamespace)).Select(value => value.Value).ToArray();
        Expect(nativeReassignmentRequest.Version == 5
            && nativeReassignmentRequest.Mode == 1
            && nativeReassignmentRequest.Task?.Assignment is
            {
                Mode: 1, Version: 5, State: 3, Ownership: 1,
                AcceptanceState: 1, Accepted: true,
                AssigneeAddress: null
            }
            && nativeReassignmentResponse.Operation == "respond_accept"
            && nativeReassignmentResponse.AssigneeAddress == "own@example.test"
            && nativeReassignmentResponse.PreviewTask?.Assignment?.OwnerAddress == "mb@example.test"
            && nativeReassignmentCc.SequenceEqual(["it@example.test"])
            && nativeReassignmentRequestExchange.CreateItemCount == 0,
            "Native Outlook reassignment acceptance did not inherit the strict request tuple or resolve its prior assigner into Cc.");
        var nativeReassignmentResponseTask = XDocument.Parse(nativeReassignmentResponse.PayloadXml!)
            .Descendants(XName.Get("Task", TypesNamespace)).Single();
        var nativeReassignmentResponseProperties = ReadNamedProperties(
            nativeReassignmentResponseTask.Elements(XName.Get("ExtendedProperty", TypesNamespace)));
        var nativeReassignmentResponseStack = TaskAssignerStack.Parse(
            nativeReassignmentResponseProperties[NamedPropertyKey(
                "00062003-0000-0000-C000-000000000046", "0x8117")]);
        var nativeReassignmentResult = await nativeReassignmentRequestClient.ExecuteTaskActionAsync(
            "mb@example.test", nativeReassignmentResponse, CancellationToken.None);
        Expect(nativeReassignmentResponseStack.Count == 2
            && nativeReassignmentResponseStack[0].DisplayName == "IT"
            && nativeReassignmentResponseStack[1].DisplayName == "own"
            && nativeReassignmentResult.Sent && nativeReassignmentResult.Applied
            && nativeReassignmentRequestExchange.CreateItemCount == 2
            && nativeReassignmentRequestExchange.UpdateItemCount > 0,
            "Native Outlook reassignment acceptance did not rehydrate its [watcher, owner] chain during fresh execution.");

        var nativeReassignmentDriftExchange = new TaskAssignmentRecordingHandler
        {
            NativeReassignmentRequestResponse = true,
            OmitTaskRequestVersion = true,
            AcceptedFlagOverride = true,
            TaskVersion = 5,
            EnableDirectoryResolution = true,
            DirectoryExpectedQuery = string.Empty,
            DirectoryDisplayName = "mb@example.test",
            DirectoryEmailAddress = "mb@example.test",
            DirectoryStackDisplayName = "IT",
            DirectoryStackEmailAddress = "it@example.test",
            NativeTaskOwnerName = "mb@example.test"
        };
        var nativeReassignmentDriftClient = NewEwsClient(
            nativeReassignmentDriftExchange, taskDirectory: NewTaskAssignerDirectory());
        var nativeReassignmentDrift = await nativeReassignmentDriftClient.PrepareTaskResponseAsync(
            "mb@example.test", "request-1", responseAccept: true, CancellationToken.None);
        nativeReassignmentDriftExchange.DirectoryEmailAddress = "other@example.test";
        await AssertThrowsAsync<InvalidOperationException>(() => nativeReassignmentDriftClient.ExecuteTaskActionAsync(
            "mb@example.test", nativeReassignmentDrift, CancellationToken.None));
        Expect(nativeReassignmentDriftExchange.CreateItemCount == 0
            && nativeReassignmentDriftExchange.UpdateItemCount == 0,
            "A native reassignment acceptance with fresh directory drift reached the write path.");
        nativeReassignmentDriftExchange.DirectoryEmailAddress = "mb@example.test";
        nativeReassignmentDriftExchange.TaskRequestRecipient = "attacker@example.test";
        await AssertThrowsAsync<InvalidOperationException>(() => nativeReassignmentDriftClient.ExecuteTaskActionAsync(
            "mb@example.test", nativeReassignmentDrift, CancellationToken.None));
        Expect(nativeReassignmentDriftExchange.CreateItemCount == 0
            && nativeReassignmentDriftExchange.UpdateItemCount == 0,
            "A native reassignment acceptance with fresh recipient drift reached the write path.");
        nativeReassignmentDriftExchange.TaskRequestRecipient = null;
        nativeReassignmentDriftExchange.TaskRequestCcRecipients = ["attacker@example.test"];
        await AssertThrowsAsync<InvalidOperationException>(() => nativeReassignmentDriftClient.ExecuteTaskActionAsync(
            "mb@example.test", nativeReassignmentDrift, CancellationToken.None));
        Expect(nativeReassignmentDriftExchange.CreateItemCount == 0
            && nativeReassignmentDriftExchange.UpdateItemCount == 0,
            "A native reassignment acceptance with fresh watcher-chain drift reached the write path.");

        var conflictingNativeRoleExchange = new TaskAssignmentRecordingHandler
        {
            NativeReassignmentRequestResponse = true,
            OmitTaskRequestVersion = true,
            AcceptedFlagOverride = true,
            TaskVersion = 5,
            NativeTaskOwnerName = "mb@example.test",
            NativeTaskAssigneeAddress = "attacker@example.test",
            EnableDirectoryResolution = true,
            DirectoryDisplayName = "mb@example.test",
            DirectoryEmailAddress = "mb@example.test"
        };
        await AssertThrowsAsync<InvalidOperationException>(() => NewEwsClient(
            conflictingNativeRoleExchange, taskDirectory: NewTaskAssignerDirectory()).PrepareTaskResponseAsync(
            "mb@example.test", "request-1", responseAccept: true, CancellationToken.None));
        Expect(conflictingNativeRoleExchange.CreateItemCount == 0,
            "A native reassignment request with conflicting private assignee metadata reached the send path.");

        var conflictingNativeOwnerExchange = new TaskAssignmentRecordingHandler
        {
            NativeReassignmentRequestResponse = true,
            OmitTaskRequestVersion = true,
            AcceptedFlagOverride = true,
            TaskVersion = 5,
            NativeTaskOwnerName = "mb@example.test",
            NativeTaskOwnerAddress = "attacker@example.test",
            EnableDirectoryResolution = true,
            DirectoryDisplayName = "mb@example.test",
            DirectoryEmailAddress = "mb@example.test"
        };
        await AssertThrowsAsync<InvalidOperationException>(() => NewEwsClient(
            conflictingNativeOwnerExchange, taskDirectory: NewTaskAssignerDirectory()).PrepareTaskResponseAsync(
            "mb@example.test", "request-1", responseAccept: true, CancellationToken.None));
        Expect(conflictingNativeOwnerExchange.CreateItemCount == 0,
            "A native reassignment request with conflicting private owner metadata reached the send path.");

        var conflictingNativeCcExchange = new TaskAssignmentRecordingHandler
        {
            NativeReassignmentRequestResponse = true,
            OmitTaskRequestVersion = true,
            AcceptedFlagOverride = true,
            TaskVersion = 5,
            TaskRequestCcRecipients = ["attacker@example.test"],
            NativeTaskOwnerName = "mb@example.test",
            EnableDirectoryResolution = true,
            DirectoryDisplayName = "mb@example.test",
            DirectoryEmailAddress = "mb@example.test",
            DirectoryStackDisplayName = "IT",
            DirectoryStackEmailAddress = "it@example.test"
        };
        await AssertThrowsAsync<InvalidOperationException>(() => NewEwsClient(
            conflictingNativeCcExchange, taskDirectory: NewTaskAssignerDirectory()).PrepareTaskResponseAsync(
            "mb@example.test", "request-1", responseAccept: true, CancellationToken.None));
        Expect(conflictingNativeCcExchange.CreateItemCount == 0,
            "A native reassignment request with an unverified Cc watcher reached the send path.");

        var duplicateNativeStackExchange = new TaskAssignmentRecordingHandler
        {
            NativeReassignmentRequestResponse = true,
            OmitTaskRequestVersion = true,
            AcceptedFlagOverride = true,
            TaskVersion = 5,
            NativeTaskOwnerName = "mb@example.test",
            NativeAssignerStackOverride = TaskAssignmentRecordingHandler.DuplicateNativeReassignmentAssignerStack,
            EnableDirectoryResolution = true,
            DirectoryDisplayName = "mb@example.test",
            DirectoryEmailAddress = "mb@example.test",
            DirectoryStackDisplayName = "IT",
            DirectoryStackEmailAddress = "it@example.test"
        };
        await AssertThrowsAsync<InvalidOperationException>(() => NewEwsClient(
            duplicateNativeStackExchange, taskDirectory: NewTaskAssignerDirectory()).PrepareTaskResponseAsync(
            "mb@example.test", "request-1", responseAccept: true, CancellationToken.None));
        Expect(duplicateNativeStackExchange.CreateItemCount == 0,
            "A native reassignment request with duplicate serialized stack identities reached the send path.");

        var cyclicNativeStackExchange = new TaskAssignmentRecordingHandler
        {
            NativeReassignmentRequestResponse = true,
            OmitTaskRequestVersion = true,
            AcceptedFlagOverride = true,
            TaskVersion = 5,
            NativeTaskOwnerName = "mb@example.test",
            NativeAssignerStackOverride = TaskAssignerStack.Encode([
                new TaskAssignerEntry(
                    "/o=Example/ou=Exchange Administrative Group/cn=Recipients/cn=mb", "MB")]),
            EnableDirectoryResolution = true,
            DirectoryDisplayName = "mb@example.test",
            DirectoryEmailAddress = "mb@example.test",
            DirectoryStackDisplayName = "MB",
            DirectoryStackEmailAddress = "mb@example.test"
        };
        await AssertThrowsAsync<InvalidOperationException>(() => NewEwsClient(
            cyclicNativeStackExchange, taskDirectory: NewTaskAssignerDirectory()).PrepareTaskResponseAsync(
            "mb@example.test", "request-1", responseAccept: true, CancellationToken.None));
        Expect(cyclicNativeStackExchange.CreateItemCount == 0,
            "A native reassignment request whose stack contains the target owner reached the send path.");

        var nativeInitialRequestExchange = new TaskAssignmentRecordingHandler
        {
            NativeInitialRequestResponse = true,
            OmitTaskRequestVersion = true,
            OmitAcceptedFlag = true,
            OmitAssignerStack = true,
            TaskVersion = 2,
            NativeTaskAssignerName = string.Empty,
            NativeTaskOwnerName = "it@example.test",
            NativeTaskLastUserName = string.Empty,
            NativeTaskLastDelegateName = string.Empty,
            EnableDirectoryResolution = true,
            DirectoryExpectedQuery = string.Empty,
            DirectoryDisplayName = "it@example.test",
            DirectoryEmailAddress = "it@example.test"
        };
        var nativeInitialRequestClient = NewEwsClient(
            nativeInitialRequestExchange, taskDirectory: NewTaskAssignerDirectory());
        var nativeInitialRequest = await nativeInitialRequestClient.ReadTaskAssignmentMessageAsync(
            "it@example.test", "request-1", CancellationToken.None);
        var nativeInitialResponse = await nativeInitialRequestClient.PrepareTaskResponseAsync(
            "it@example.test", "request-1", responseAccept: true, CancellationToken.None);
        Expect(nativeInitialRequest.Version == 2
            && nativeInitialRequest.Mode == 1
            && nativeInitialRequest.Task?.Assignment is
            {
                Mode: 1, Version: 2, State: 3, Ownership: 1,
                AcceptanceState: 1, Accepted: null,
                OwnerName: "it@example.test", AssigneeAddress: null
            }
            && nativeInitialResponse.Operation == "respond_accept"
            && nativeInitialResponse.PreviewTask?.Assignment is
            {
                OwnerAddress: "it@example.test", AssigneeAddress: "it@example.test"
            }
            && nativeInitialRequestExchange.CreateItemCount == 0,
            "Native Outlook initial assignment did not inherit its missing outer version or resolve the sole recipient owner.");
        var nativeInitialResult = await nativeInitialRequestClient.ExecuteTaskActionAsync(
            "it@example.test", nativeInitialResponse, CancellationToken.None);
        Expect(nativeInitialResult.Sent && nativeInitialResult.Applied
            && nativeInitialRequestExchange.CreateItemCount == 2
            && nativeInitialRequestExchange.UpdateItemCount > 0,
            "Native Outlook initial assignment acceptance did not hydrate before fresh execution.");

        var ambiguousNativeReassignmentExchange = new TaskAssignmentRecordingHandler
        {
            NativeReassignmentRequestResponse = true,
            OmitTaskRequestVersion = true,
            AcceptedFlagOverride = true,
            TaskVersion = 5,
            EnableDirectoryResolution = true,
            DirectoryDisplayName = "mb@example.test",
            DirectoryEmailAddress = "mb@example.test",
            DirectoryResolutionCount = 2,
            NativeTaskOwnerName = "mb@example.test"
        };
        await AssertThrowsAsync<InvalidOperationException>(() => NewEwsClient(
            ambiguousNativeReassignmentExchange, taskDirectory: NewTaskAssignerDirectory()).PrepareTaskResponseAsync(
            "mb@example.test", "request-1", responseAccept: true, CancellationToken.None));
        Expect(ambiguousNativeReassignmentExchange.CreateItemCount == 0,
            "An ambiguous native reassignment owner directory result reached the send path.");
        var nonSmtpNativeReassignmentExchange = new TaskAssignmentRecordingHandler
        {
            NativeReassignmentRequestResponse = true,
            OmitTaskRequestVersion = true,
            AcceptedFlagOverride = true,
            TaskVersion = 5,
            EnableDirectoryResolution = true,
            DirectoryDisplayName = "mb@example.test",
            DirectoryEmailAddress = "mb@example.test",
            DirectoryRoutingType = "EX",
            NativeTaskOwnerName = "mb@example.test"
        };
        await AssertThrowsAsync<InvalidOperationException>(() => NewEwsClient(
            nonSmtpNativeReassignmentExchange, taskDirectory: NewTaskAssignerDirectory()).PrepareTaskResponseAsync(
            "mb@example.test", "request-1", responseAccept: true, CancellationToken.None));
        Expect(nonSmtpNativeReassignmentExchange.CreateItemCount == 0,
            "A non-SMTP native reassignment directory result reached the send path.");

        var nativeReassignmentUpdateExchange = new TaskAssignmentRecordingHandler
        {
            ProcessMessage = true,
            ReturnLocalTaskForFind = true,
            NativeReassignmentUpdateResponse = true,
            NativeReassignmentWatcherLocal = true,
            OmitTaskRequestVersion = true,
            AcceptedFlagOverride = true,
            TaskVersion = 3,
            LocalTaskVersion = 2,
            NativeTaskOwnerName = "bob.example",
            NativeTaskAssignerName = "own@example.test",
            NativeTaskLastUserName = "own@example.test",
            NativeTaskLastDelegateName = "own@example.test",
            EnableDirectoryResolution = true,
            DirectoryExpectedQuery = string.Empty,
            DirectoryDisplayName = "bob.example",
            DirectoryEmailAddress = "mb@example.test"
            ,
            DirectoryStackDisplayName = "IT",
            DirectoryStackEmailAddress = "it@example.test"
        };
        var nativeReassignmentUpdateClient = NewEwsClient(
            nativeReassignmentUpdateExchange, taskDirectory: NewTaskAssignerDirectory());
        var nativeReassignmentUpdate = await nativeReassignmentUpdateClient.PrepareTaskProcessAsync(
            "it@example.test", "request-1", CancellationToken.None);
        var nativeReassignmentUpdatePayload = XDocument.Parse(nativeReassignmentUpdate.PayloadXml!);
        Expect(nativeReassignmentUpdate.Operation == "process"
            && nativeReassignmentUpdate.AssigneeAddress == "mb@example.test"
            && nativeReassignmentUpdate.PreviewTask?.Assignment is
            {
                State: 3, Ownership: 1, AcceptanceState: 1,
                AssignerAddress: "own@example.test",
                AssigneeAddress: "mb@example.test", OwnerAddress: "mb@example.test"
            }
            && nativeReassignmentUpdatePayload.Descendants(XName.Get("Value", TypesNamespace))
                .Any(value => value.Value == "mb@example.test")
            && nativeReassignmentUpdateExchange.CreateItemCount == 0
            && nativeReassignmentUpdateExchange.UpdateItemCount == 0,
            "Native Outlook reassignment Update did not resolve the new owner or prepare a tracker projection without writing.");
        nativeReassignmentUpdateExchange.DirectoryEmailAddress = "other@example.test";
        await AssertThrowsAsync<InvalidOperationException>(() => nativeReassignmentUpdateClient.ExecuteTaskActionAsync(
            "it@example.test", nativeReassignmentUpdate, CancellationToken.None));
        Expect(nativeReassignmentUpdateExchange.CreateItemCount == 0
            && nativeReassignmentUpdateExchange.UpdateItemCount == 0,
            "A native reassignment owner change after approval reached the EWS write path.");

        var nativeAcceptedTrackerExchange = new TaskAssignmentRecordingHandler
        {
            ProcessMessage = true,
            ReturnLocalTaskForFind = true,
            NativeAcceptedResponse = true,
            NativeReassignmentWatcherLocal = true,
            OmitLocalTaskPrivateRoles = true,
            NativeResponseSender = "mb@example.test",
            TaskVersion = 4,
            LocalTaskVersion = 2,
            NativeTaskOwnerName = "bob.example",
            EnableDirectoryResolution = true,
            DirectoryExpectedQuery = string.Empty,
            DirectoryDisplayName = "bob.example",
            DirectoryEmailAddress = "mb@example.test"
        };
        var nativeAcceptedTrackerClient = NewEwsClient(
            nativeAcceptedTrackerExchange, taskDirectory: NewTaskAssignerDirectory());
        var nativeAcceptedTracker = await nativeAcceptedTrackerClient.PrepareTaskProcessAsync(
            "alice@example.test", "request-1", CancellationToken.None);
        Expect(nativeAcceptedTracker.AssigneeAddress == "mb@example.test"
            && nativeAcceptedTracker.PreviewTask?.Assignment is
            {
                AssignerAddress: "alice@example.test",
                AssigneeAddress: "mb@example.test", OwnerAddress: "mb@example.test"
            }
            && nativeAcceptedTrackerExchange.CreateItemCount == 0
            && nativeAcceptedTrackerExchange.UpdateItemCount == 0,
            "A native accepted response did not hydrate the reassignment tracker owner before sender validation.");

        var acceptedOriginalTrackerMissingRolesExchange = new TaskAssignmentRecordingHandler
        {
            ProcessMessage = true,
            ReturnLocalTaskForFind = true,
            NativeReassignmentWatcherLocal = true,
            OmitLocalTaskPrivateRoles = true,
            NativeResponseSender = "bob@example.test",
            LocalTaskVersion = 2,
            TaskVersion = 3,
            NativeTaskOwnerName = "bob@example.test",
            EnableDirectoryResolution = true,
            DirectoryExpectedQuery = string.Empty,
            DirectoryDisplayName = "bob@example.test",
            DirectoryEmailAddress = "bob@example.test"
        };
        var acceptedOriginalTrackerMissingRoles = await NewEwsClient(
            acceptedOriginalTrackerMissingRolesExchange,
            taskDirectory: NewTaskAssignerDirectory()).PrepareTaskProcessAsync(
                "alice@example.test", "request-1", CancellationToken.None);
        Expect(acceptedOriginalTrackerMissingRoles.Operation == "process"
            && acceptedOriginalTrackerMissingRoles.PreviewTask?.Assignment is
            {
                AssignerAddress: "alice@example.test",
                AssigneeAddress: "bob@example.test", OwnerAddress: "bob@example.test"
            }
            && acceptedOriginalTrackerMissingRolesExchange.CreateItemCount == 0
            && acceptedOriginalTrackerMissingRolesExchange.UpdateItemCount == 0,
            "An ordinary MCP Accept did not hydrate an original native tracker missing private roles.");

        var ordinaryMcpDirectOwnerExchange = new TaskAssignmentRecordingHandler
        {
            ProcessMessage = true,
            ReturnLocalTaskForFind = true,
            NativeAcceptedResponse = true,
            NativeReassignmentWatcherLocal = true,
            NativeLocalTaskAssigneeAddress = "bob@example.test",
            NativeLocalTaskOwnerAddress = "bob@example.test",
            NativeLocalTaskAssignerAddress = "alice@example.test",
            NativeLocalAcceptanceWireOverride = "1",
            NativeResponseSender = "bob@example.test",
            NativeResponseTaskAssigneeAddress = "bob@example.test",
            NativeResponseTaskOwnerAddress = "bob@example.test",
            TaskVersion = 3,
            LocalTaskVersion = 2,
            NativeTaskOwnerName = "bob@example.test"
        };
        var ordinaryMcpDirectOwner = await NewEwsClient(
            ordinaryMcpDirectOwnerExchange, taskDirectory: NewTaskAssignerDirectory()).PrepareTaskProcessAsync(
                "alice@example.test", "request-1", CancellationToken.None);
        Expect(ordinaryMcpDirectOwner.Operation == "process"
            && ordinaryMcpDirectOwner.PreviewTask?.Assignment is
            {
                AssignerAddress: "alice@example.test",
                AssigneeAddress: "bob@example.test", OwnerAddress: "bob@example.test"
            }
            && !ordinaryMcpDirectOwnerExchange.Calls.Any(call => call.Operation == "ResolveNames")
            && ordinaryMcpDirectOwnerExchange.CreateItemCount == 0
            && ordinaryMcpDirectOwnerExchange.UpdateItemCount == 0,
            "An ordinary MCP tracker with a matching private owner performed an unnecessary directory lookup or failed to prepare.");

        var nativeHandoffStaleRolesExchange = new TaskAssignmentRecordingHandler
        {
            ProcessMessage = true,
            ReturnLocalTaskForFind = true,
            NativeAcceptedResponse = true,
            NativeReassignmentWatcherLocal = true,
            NativeResponseSender = "mb@example.test",
            NativeResponseTaskAssigneeAddress = "mb@example.test",
            NativeResponseTaskOwnerAddress = "mb@example.test",
            NativeLocalTaskAssigneeAddress = "own@example.test",
            NativeLocalTaskOwnerAddress = "own@example.test",
            NativeLocalTaskAssignerAddress = "it@example.test",
            NativeLocalAcceptanceWireOverride = "1",
            NativeResponseAssignerStackOverride = TaskAssignerStack.Encode([
                new TaskAssignerEntry(
                    "/o=Example/ou=Exchange Administrative Group/cn=Recipients/cn=it", "IT"),
                new TaskAssignerEntry(
                    "/o=Example/ou=Exchange Administrative Group/cn=Recipients/cn=own", "Own")]),
            NativeResponseAssignerChainOverride = "it@example.test\nown@example.test",
            TaskRequestRecipient = "own@example.test",
            TaskRequestCcRecipients = ["it@example.test"],
            TaskVersion = 6,
            LocalTaskVersion = 5,
            NativeTaskOwnerName = "bob.example",
            NativeTaskAssignerName = string.Empty,
            NativeTaskLastUserName = "own@example.test",
            NativeTaskLastDelegateName = string.Empty,
            OmitAssignerStack = true,
            EnableDirectoryResolution = true,
            DirectoryExpectedQuery = string.Empty,
            DirectoryDisplayName = "bob.example",
            DirectoryEmailAddress = "mb@example.test",
            DirectoryOwnDisplayName = "own@example.test",
            DirectoryOwnEmailAddress = "own@example.test",
            DirectoryStackDisplayName = "IT",
            DirectoryStackEmailAddress = "it@example.test"
        };
        var nativeHandoffStaleRoles = await NewEwsClient(
            nativeHandoffStaleRolesExchange,
            taskDirectory: NewTaskAssignerDirectory()).PrepareTaskProcessAsync(
                "it@example.test", "request-1", CancellationToken.None);
        Expect(nativeHandoffStaleRoles.Operation == "process"
            && nativeHandoffStaleRoles.PreviewTask?.Assignment is
            {
                AssignerAddress: "own@example.test",
                AssigneeAddress: "mb@example.test", OwnerAddress: "mb@example.test"
            }
            && nativeHandoffStaleRolesExchange.CreateItemCount == 0
            && nativeHandoffStaleRolesExchange.UpdateItemCount == 0,
            "A native MB response did not reconcile the stale Outlook tracker owner and current assigner.");

        var acceptedConflictExchange = NewStaleHandoffFixture();
        acceptedConflictExchange.AcceptedFlagOverride = true;
        await AssertThrowsAsync<InvalidOperationException>(() => NewEwsClient(
            acceptedConflictExchange, taskDirectory: NewTaskAssignerDirectory()).PrepareTaskProcessAsync(
            "it@example.test", "request-1", CancellationToken.None));
        Expect(acceptedConflictExchange.CreateItemCount == 0
            && acceptedConflictExchange.UpdateItemCount == 0,
            "A native tracker with an accepted pending owner conflict reached the write path.");

        TaskAssignmentRecordingHandler NewStaleHandoffFixture() => new()
        {
            ProcessMessage = true,
            ReturnLocalTaskForFind = true,
            NativeAcceptedResponse = true,
            NativeReassignmentWatcherLocal = true,
            NativeResponseSender = "mb@example.test",
            NativeResponseTaskAssigneeAddress = "mb@example.test",
            NativeResponseTaskOwnerAddress = "mb@example.test",
            NativeLocalTaskAssigneeAddress = "own@example.test",
            NativeLocalTaskOwnerAddress = "own@example.test",
            NativeLocalTaskAssignerAddress = "it@example.test",
            NativeLocalAcceptanceWireOverride = "1",
            NativeResponseAssignerStackOverride = TaskAssignerStack.Encode([
                new TaskAssignerEntry(
                    "/o=Example/ou=Exchange Administrative Group/cn=Recipients/cn=it", "IT"),
                new TaskAssignerEntry(
                    "/o=Example/ou=Exchange Administrative Group/cn=Recipients/cn=own", "Own")]),
            NativeResponseAssignerChainOverride = "it@example.test\nown@example.test",
            TaskRequestRecipient = "own@example.test",
            TaskRequestCcRecipients = ["it@example.test"],
            TaskVersion = 6,
            LocalTaskVersion = 5,
            NativeTaskOwnerName = "bob.example",
            NativeTaskAssignerName = string.Empty,
            NativeTaskLastUserName = "own@example.test",
            NativeTaskLastDelegateName = string.Empty,
            OmitAssignerStack = true,
            EnableDirectoryResolution = true,
            DirectoryExpectedQuery = string.Empty,
            DirectoryDisplayName = "bob.example",
            DirectoryEmailAddress = "mb@example.test",
            DirectoryOwnDisplayName = "own@example.test",
            DirectoryOwnEmailAddress = "own@example.test",
            DirectoryStackDisplayName = "IT",
            DirectoryStackEmailAddress = "it@example.test"
        };

        var missingLastUserExchange = NewStaleHandoffFixture();
        missingLastUserExchange.NativeTaskLastUserName = string.Empty;
        await AssertThrowsAsync<InvalidOperationException>(() => NewEwsClient(
            missingLastUserExchange, taskDirectory: NewTaskAssignerDirectory()).PrepareTaskProcessAsync(
            "it@example.test", "request-1", CancellationToken.None));
        Expect(missingLastUserExchange.CreateItemCount == 0
            && missingLastUserExchange.UpdateItemCount == 0,
            "A stale native tracker without LastUserName reached the write path.");

        var ambiguousLastUserExchange = NewStaleHandoffFixture();
        ambiguousLastUserExchange.DirectoryAmbiguousQuery = "own@example.test";
        await AssertThrowsAsync<InvalidOperationException>(() => NewEwsClient(
            ambiguousLastUserExchange, taskDirectory: NewTaskAssignerDirectory()).PrepareTaskProcessAsync(
            "it@example.test", "request-1", CancellationToken.None));
        Expect(ambiguousLastUserExchange.CreateItemCount == 0
            && ambiguousLastUserExchange.UpdateItemCount == 0,
            "An ambiguous native tracker LastUserName lookup reached the write path.");

        var mismatchedLastUserExchange = NewStaleHandoffFixture();
        mismatchedLastUserExchange.NativeTaskLastUserName = "other@example.test";
        await AssertThrowsAsync<InvalidOperationException>(() => NewEwsClient(
            mismatchedLastUserExchange, taskDirectory: NewTaskAssignerDirectory()).PrepareTaskProcessAsync(
            "it@example.test", "request-1", CancellationToken.None));
        Expect(mismatchedLastUserExchange.CreateItemCount == 0
            && mismatchedLastUserExchange.UpdateItemCount == 0,
            "A stale native tracker with a mismatched LastUserName reached the write path.");

        var mismatchedAssignerExchange = NewStaleHandoffFixture();
        mismatchedAssignerExchange.NativeLocalTaskAssignerAddress = "other@example.test";
        await AssertThrowsAsync<InvalidOperationException>(() => NewEwsClient(
            mismatchedAssignerExchange, taskDirectory: NewTaskAssignerDirectory()).PrepareTaskProcessAsync(
            "it@example.test", "request-1", CancellationToken.None));
        Expect(mismatchedAssignerExchange.CreateItemCount == 0
            && mismatchedAssignerExchange.UpdateItemCount == 0,
            "A stale native tracker with a mismatched current assigner reached the write path.");

        var missingChainExchange = NewStaleHandoffFixture();
        missingChainExchange.NativeResponseAssignerStackOverride = null;
        await AssertThrowsAsync<InvalidOperationException>(() => NewEwsClient(
            missingChainExchange, taskDirectory: NewTaskAssignerDirectory()).PrepareTaskProcessAsync(
            "it@example.test", "request-1", CancellationToken.None));
        Expect(missingChainExchange.CreateItemCount == 0
            && missingChainExchange.UpdateItemCount == 0,
            "A stale native tracker without a verified watcher chain reached the write path.");

        var directoryDriftExchange = NewStaleHandoffFixture();
        var directoryDriftClient = NewEwsClient(
            directoryDriftExchange, taskDirectory: NewTaskAssignerDirectory());
        var directoryDriftAction = await directoryDriftClient.PrepareTaskProcessAsync(
            "it@example.test", "request-1", CancellationToken.None);
        directoryDriftExchange.DirectoryEmailAddress = "other@example.test";
        await AssertThrowsAsync<InvalidOperationException>(() => directoryDriftClient.ExecuteTaskActionAsync(
            "it@example.test", directoryDriftAction, CancellationToken.None));
        Expect(directoryDriftExchange.CreateItemCount == 0
            && directoryDriftExchange.UpdateItemCount == 0,
            "Native tracker directory drift after approval reached the write path.");

        var staleReassignmentAcceptExchange = new TaskAssignmentRecordingHandler
        {
            ProcessMessage = true,
            ReturnLocalTaskForFind = true,
            NativeAcceptedResponse = true,
            NativeReassignmentWatcherLocal = true,
            TaskVersion = 4,
            LocalTaskVersion = 2
        };
        await AssertThrowsAsync<InvalidOperationException>(() => NewEwsClient(
            staleReassignmentAcceptExchange, taskDirectory: NewTaskAssignerDirectory()).PrepareTaskProcessAsync(
            "alice@example.test", "request-1", CancellationToken.None));
        Expect(staleReassignmentAcceptExchange.CreateItemCount == 0
            && staleReassignmentAcceptExchange.UpdateItemCount == 0,
            "A stale native Accept from the previous assigner was accepted after reassignment.");

        var nativeUpdatedExplicitVersionExchange = new TaskAssignmentRecordingHandler
        {
            ProcessMessage = true,
            ReturnLocalTaskForFind = true,
            NativeUpdatedResponse = true,
            TaskVersion = 5,
            LocalTaskVersion = 2,
            NativeTaskPercentComplete = 50
        };
        await AssertThrowsAsync<InvalidOperationException>(() =>
            NewEwsClient(nativeUpdatedExplicitVersionExchange,
                taskDirectory: NewTaskAssignerDirectory()).ReadTaskAssignmentMessageAsync(
                "alice@example.test", "request-1", CancellationToken.None));

        var nativeUpdatedNoAcceptedFlagExchange = new TaskAssignmentRecordingHandler
        {
            ProcessMessage = true,
            ReturnLocalTaskForFind = true,
            NativeUpdatedResponse = true,
            OmitTaskRequestVersion = true,
            AcceptedFlagOverride = false,
            TaskVersion = 5,
            LocalTaskVersion = 2,
            NativeTaskPercentComplete = 50
        };
        await AssertThrowsAsync<InvalidOperationException>(() =>
            NewEwsClient(nativeUpdatedNoAcceptedFlagExchange,
                taskDirectory: NewTaskAssignerDirectory()).PrepareTaskProcessAsync(
                "alice@example.test", "request-1", CancellationToken.None));
        Expect(nativeUpdatedNoAcceptedFlagExchange.CreateItemCount == 0
            && nativeUpdatedNoAcceptedFlagExchange.UpdateItemCount == 0,
            "A native Update without Outlook's accepted flag reached a write path.");

        var nativeUpdatedMismatchedGlobalExchange = new TaskAssignmentRecordingHandler
        {
            ProcessMessage = true,
            ReturnLocalTaskForFind = true,
            NativeUpdatedResponse = true,
            OmitTaskRequestVersion = true,
            TaskAttachmentGlobalId = TaskAssignmentRecordingHandler.WrongGlobalIdValue,
            TaskVersion = 5,
            LocalTaskVersion = 2,
            NativeTaskPercentComplete = 50
        };
        await AssertThrowsAsync<InvalidOperationException>(() =>
            NewEwsClient(nativeUpdatedMismatchedGlobalExchange,
                taskDirectory: NewTaskAssignerDirectory()).PrepareTaskProcessAsync(
                "alice@example.test", "request-1", CancellationToken.None));
        Expect(nativeUpdatedMismatchedGlobalExchange.CreateItemCount == 0
            && nativeUpdatedMismatchedGlobalExchange.UpdateItemCount == 0,
            "A native Update with mismatched outer and embedded GlobalIds reached a write path.");

        var nativeDeclinedExchange = new TaskAssignmentRecordingHandler
        {
            ProcessMessage = true,
            ReturnLocalTaskForFind = true,
            NativeDeclinedResponse = true,
            OmitTaskRequestVersion = true,
            AcceptedFlagOverride = true,
            TaskVersion = 3,
            LocalTaskVersion = 2
        };
        var nativeDeclinedClient = NewEwsClient(nativeDeclinedExchange,
            taskDirectory: NewTaskAssignerDirectory());
        var nativeDeclinedMessage = await nativeDeclinedClient.ReadTaskAssignmentMessageAsync(
            "alice@example.test", "request-1", CancellationToken.None);
        var nativeDeclinedProcess = await nativeDeclinedClient.PrepareTaskProcessAsync(
            "alice@example.test", "request-1", CancellationToken.None);
        Expect(nativeDeclinedMessage.ItemClass == "IPM.TaskRequest.Decline"
            && nativeDeclinedMessage.Mode == 3
            && nativeDeclinedMessage.Version == 3
            && nativeDeclinedMessage.Task?.Assignment is
            {
                Version: 3, Mode: 3, State: 3, Ownership: 1,
                AcceptanceState: 1, Accepted: true, AssignerStackBase64: "AAAAAA=="
            }
            && nativeDeclinedProcess.Operation == "process"
            && nativeDeclinedExchange.CreateItemCount == 0
            && nativeDeclinedExchange.UpdateItemCount == 0,
            "The verified Outlook Decline tuple did not inherit its missing outer version or discard only the retained native stack tail.");

        var nativeDeclinedMissingTrackerRolesExchange = new TaskAssignmentRecordingHandler
        {
            ProcessMessage = true,
            ReturnLocalTaskForFind = true,
            NativeDeclinedResponse = true,
            NativeReassignmentWatcherLocal = true,
            OmitLocalTaskPrivateRoles = true,
            NativeResponseSender = "bob@example.test",
            OmitTaskRequestVersion = true,
            AcceptedFlagOverride = true,
            TaskVersion = 3,
            LocalTaskVersion = 2,
            NativeTaskOwnerName = "bob@example.test",
            EnableDirectoryResolution = true,
            DirectoryExpectedQuery = string.Empty,
            DirectoryDisplayName = "bob@example.test",
            DirectoryEmailAddress = "bob@example.test"
        };
        var nativeDeclinedMissingTrackerRoles = await NewEwsClient(
            nativeDeclinedMissingTrackerRolesExchange,
            taskDirectory: NewTaskAssignerDirectory()).PrepareTaskProcessAsync(
                "alice@example.test", "request-1", CancellationToken.None);
        Expect(nativeDeclinedMissingTrackerRoles.Operation == "process"
            && nativeDeclinedMissingTrackerRoles.PreviewTask?.Assignment is
            {
                AssignerAddress: "alice@example.test",
                AssigneeAddress: "bob@example.test", OwnerAddress: "bob@example.test"
            }
            && nativeDeclinedMissingTrackerRolesExchange.CreateItemCount == 0
            && nativeDeclinedMissingTrackerRolesExchange.UpdateItemCount == 0,
            "A native Decline did not hydrate a missing tracker owner before sender validation.");

        var nativeDeclinedExistingRolesExchange = new TaskAssignmentRecordingHandler
        {
            ProcessMessage = true,
            ReturnLocalTaskForFind = true,
            NativeDeclinedResponse = true,
            NativeReassignmentWatcherLocal = true,
            NativeResponseSender = "own@example.test",
            OmitTaskRequestVersion = true,
            AcceptedFlagOverride = true,
            TaskVersion = 3,
            LocalTaskVersion = 2
        };
        var nativeDeclinedExistingRolesClient = NewEwsClient(
            nativeDeclinedExistingRolesExchange,
            taskDirectory: NewTaskAssignerDirectory());
        var nativeDeclinedExistingRoles = await nativeDeclinedExistingRolesClient.PrepareTaskProcessAsync(
            "alice@example.test", "request-1", CancellationToken.None);
        var nativeDeclinedExistingRolesResult = await nativeDeclinedExistingRolesClient.ExecuteTaskActionAsync(
            "alice@example.test", nativeDeclinedExistingRoles, CancellationToken.None);
        Expect(!nativeDeclinedExistingRolesResult.Sent
            && nativeDeclinedExistingRolesResult.Applied
            && nativeDeclinedExistingRolesExchange.CreateItemCount == 0
            && nativeDeclinedExistingRolesExchange.UpdateItemCount > 0,
            "A native Decline with an existing private tracker owner did not prepare and apply safely.");

        var nativeDeclinedNoAcceptedFlagExchange = new TaskAssignmentRecordingHandler
        {
            ProcessMessage = true,
            ReturnLocalTaskForFind = true,
            NativeDeclinedResponse = true,
            OmitTaskRequestVersion = true,
            AcceptedFlagOverride = false,
            TaskVersion = 3,
            LocalTaskVersion = 2
        };
        await AssertThrowsAsync<InvalidOperationException>(() =>
            NewEwsClient(nativeDeclinedNoAcceptedFlagExchange,
                taskDirectory: NewTaskAssignerDirectory()).PrepareTaskProcessAsync(
                "alice@example.test", "request-1", CancellationToken.None));
        Expect(nativeDeclinedNoAcceptedFlagExchange.CreateItemCount == 0
            && nativeDeclinedNoAcceptedFlagExchange.UpdateItemCount == 0,
            "A native Decline without Outlook's accepted flag reached a write path.");

        var nativeDeclinedMissingInnerVersionExchange = new TaskAssignmentRecordingHandler
        {
            ProcessMessage = true,
            ReturnLocalTaskForFind = true,
            NativeDeclinedResponse = true,
            OmitTaskRequestVersion = true,
            OmitEmbeddedTaskVersion = true,
            AcceptedFlagOverride = true,
            TaskVersion = 3,
            LocalTaskVersion = 2
        };
        await AssertThrowsAsync<InvalidOperationException>(() =>
            NewEwsClient(nativeDeclinedMissingInnerVersionExchange,
                taskDirectory: NewTaskAssignerDirectory()).PrepareTaskProcessAsync(
                "alice@example.test", "request-1", CancellationToken.None));
        Expect(nativeDeclinedMissingInnerVersionExchange.CreateItemCount == 0
            && nativeDeclinedMissingInnerVersionExchange.UpdateItemCount == 0,
            "A native Decline without an embedded task version reached a write path.");

        var nativeDeclinedMismatchedGlobalExchange = new TaskAssignmentRecordingHandler
        {
            ProcessMessage = true,
            ReturnLocalTaskForFind = true,
            NativeDeclinedResponse = true,
            OmitTaskRequestVersion = true,
            AcceptedFlagOverride = true,
            TaskAttachmentGlobalId = TaskAssignmentRecordingHandler.WrongGlobalIdValue,
            TaskVersion = 3,
            LocalTaskVersion = 2
        };
        await AssertThrowsAsync<InvalidOperationException>(() =>
            NewEwsClient(nativeDeclinedMismatchedGlobalExchange,
                taskDirectory: NewTaskAssignerDirectory()).PrepareTaskProcessAsync(
                "alice@example.test", "request-1", CancellationToken.None));
        Expect(nativeDeclinedMismatchedGlobalExchange.CreateItemCount == 0
            && nativeDeclinedMismatchedGlobalExchange.UpdateItemCount == 0,
            "A native Decline with mismatched outer and embedded GlobalIds reached a write path.");

        var nativeDeclinedZeroOuterVersionExchange = new TaskAssignmentRecordingHandler
        {
            ProcessMessage = true,
            ReturnLocalTaskForFind = true,
            NativeDeclinedResponse = true,
            TaskRequestVersion = 0,
            AcceptedFlagOverride = true,
            TaskVersion = 3,
            LocalTaskVersion = 2
        };
        await AssertThrowsAsync<InvalidOperationException>(() =>
            NewEwsClient(nativeDeclinedZeroOuterVersionExchange,
                taskDirectory: NewTaskAssignerDirectory()).PrepareTaskProcessAsync(
                "alice@example.test", "request-1", CancellationToken.None));
        Expect(nativeDeclinedZeroOuterVersionExchange.CreateItemCount == 0
            && nativeDeclinedZeroOuterVersionExchange.UpdateItemCount == 0,
            "A native Decline with an explicit zero outer version reached a write path.");

        var nativeDeclinedMismatchedVersionExchange = new TaskAssignmentRecordingHandler
        {
            ProcessMessage = true,
            ReturnLocalTaskForFind = true,
            NativeDeclinedResponse = true,
            TaskRequestVersion = 2,
            AcceptedFlagOverride = true,
            TaskVersion = 3,
            LocalTaskVersion = 2
        };
        await AssertThrowsAsync<InvalidOperationException>(() =>
            NewEwsClient(nativeDeclinedMismatchedVersionExchange,
                taskDirectory: NewTaskAssignerDirectory()).PrepareTaskProcessAsync(
                "alice@example.test", "request-1", CancellationToken.None));
        Expect(nativeDeclinedMismatchedVersionExchange.CreateItemCount == 0
            && nativeDeclinedMismatchedVersionExchange.UpdateItemCount == 0,
            "A native Decline with mismatched outer and embedded versions reached a write path.");

        var noAcceptedFlagExchange = new TaskAssignmentRecordingHandler
        {
            ProcessMessage = true,
            ReturnLocalTaskForFind = true,
            NativeAcceptedResponse = true,
            OmitTaskRequestVersion = true,
            OmitAcceptedFlag = true,
            TaskVersion = 4,
            LocalTaskVersion = 2
        };
        await AssertThrowsAsync<InvalidOperationException>(() => NewEwsClient(noAcceptedFlagExchange,
            taskDirectory: NewTaskAssignerDirectory()).PrepareTaskProcessAsync(
                "alice@example.test", "request-1", CancellationToken.None));
        Expect(noAcceptedFlagExchange.CreateItemCount == 0 && noAcceptedFlagExchange.UpdateItemCount == 0,
            "A native Accept without Outlook's accepted flag reached a write path.");

        var missingInnerVersionExchange = new TaskAssignmentRecordingHandler
        {
            ProcessMessage = true,
            ReturnLocalTaskForFind = true,
            NativeAcceptedResponse = true,
            OmitTaskRequestVersion = true,
            OmitEmbeddedTaskVersion = true,
            TaskVersion = 4,
            LocalTaskVersion = 2
        };
        await AssertThrowsAsync<InvalidOperationException>(() => NewEwsClient(missingInnerVersionExchange,
            taskDirectory: NewTaskAssignerDirectory()).PrepareTaskProcessAsync(
                "alice@example.test", "request-1", CancellationToken.None));
        Expect(missingInnerVersionExchange.CreateItemCount == 0 && missingInnerVersionExchange.UpdateItemCount == 0,
            "A native Accept without an embedded task version reached a write path.");

        var mismatchedGlobalExchange = new TaskAssignmentRecordingHandler
        {
            ProcessMessage = true,
            ReturnLocalTaskForFind = true,
            NativeAcceptedResponse = true,
            OmitTaskRequestVersion = true,
            TaskAttachmentGlobalId = TaskAssignmentRecordingHandler.WrongGlobalIdValue,
            TaskVersion = 4,
            LocalTaskVersion = 2
        };
        await AssertThrowsAsync<InvalidOperationException>(() => NewEwsClient(mismatchedGlobalExchange,
            taskDirectory: NewTaskAssignerDirectory()).PrepareTaskProcessAsync(
                "alice@example.test", "request-1", CancellationToken.None));
        Expect(mismatchedGlobalExchange.CreateItemCount == 0 && mismatchedGlobalExchange.UpdateItemCount == 0,
            "A native Accept with mismatched outer and embedded GlobalIds reached a write path.");

        var zeroOuterVersionExchange = new TaskAssignmentRecordingHandler
        {
            ProcessMessage = true,
            ReturnLocalTaskForFind = true,
            NativeAcceptedResponse = true,
            TaskRequestVersion = 0,
            TaskVersion = 4,
            LocalTaskVersion = 2
        };
        await AssertThrowsAsync<InvalidOperationException>(() => NewEwsClient(zeroOuterVersionExchange,
            taskDirectory: NewTaskAssignerDirectory()).PrepareTaskProcessAsync(
                "alice@example.test", "request-1", CancellationToken.None));
        Expect(zeroOuterVersionExchange.CreateItemCount == 0 && zeroOuterVersionExchange.UpdateItemCount == 0,
            "A native Accept with an invalid outer version reached a write path.");

        var missingOuterGlobalExchange = new TaskAssignmentRecordingHandler
        {
            ProcessMessage = true,
            ReturnLocalTaskForFind = true,
            NativeAcceptedResponse = true,
            OmitTaskRequestVersion = true,
            OmitTaskRequestGlobalId = true,
            TaskVersion = 4,
            LocalTaskVersion = 2
        };
        await AssertThrowsAsync<InvalidOperationException>(() => NewEwsClient(missingOuterGlobalExchange,
            taskDirectory: NewTaskAssignerDirectory()).PrepareTaskProcessAsync(
                "alice@example.test", "request-1", CancellationToken.None));
        Expect(missingOuterGlobalExchange.CreateItemCount == 0 && missingOuterGlobalExchange.UpdateItemCount == 0,
            "A native Accept without an outer GlobalId reached a write path.");

        var spoofedAcceptedExchange = new TaskAssignmentRecordingHandler
        {
            ProcessMessage = true,
            ReturnLocalTaskForFind = true,
            NativeAcceptedResponse = true,
            AcceptedFlagOverride = false,
            TaskVersion = 4,
            LocalTaskVersion = 2
        };
        await AssertThrowsAsync<InvalidOperationException>(() => NewEwsClient(spoofedAcceptedExchange,
            taskDirectory: NewTaskAssignerDirectory()).PrepareTaskProcessAsync(
                "alice@example.test", "request-1", CancellationToken.None));
        Expect(spoofedAcceptedExchange.CreateItemCount == 0 && spoofedAcceptedExchange.UpdateItemCount == 0,
            "A NoMatch task response without Outlook's accepted flag reached a write path.");

        var crossCopyExchange = new TaskAssignmentRecordingHandler
        {
            ProcessMessage = true,
            ReturnLocalTaskForFind = true,
            OmitLocalTaskAttachmentMetadata = true,
            IncludeTaskFileAttachment = true,
            TaskAttachmentId = "incoming-file-attachment-1",
            LocalTaskAttachmentId = "local-file-attachment-1",
            TaskAttachmentName = "cm-task-note.txt",
            TaskAttachmentContentType = "text/plain",
            TaskAttachmentContentId = "cid-task-note",
            TaskAttachmentSize = 245,
            TaskAttachmentContentSize = 46,
            TaskBody = MultilineTaskHtml,
            TaskBodyType = "HTML",
            TaskVersion = 3,
            LocalTaskVersion = 2
        };
        var crossCopyClient = NewEwsClient(crossCopyExchange, taskDirectory: NewTaskAssignerDirectory());
        var crossCopyProcess = await crossCopyClient.PrepareTaskProcessAsync(
            "alice@example.test", "request-1", CancellationToken.None);
        var crossCopyResult = await crossCopyClient.ExecuteTaskActionAsync(
            "alice@example.test", crossCopyProcess, CancellationToken.None);
        Expect(crossCopyProcess.PreviewTask?.AttachmentContents is [{ Content.Length: 46 }]
            && crossCopyProcess.PreviewTask.Body == MultilineTaskHtml
            && crossCopyProcess.PreviewTask.BodyType == "HTML"
            && crossCopyResult.Applied && !crossCopyResult.Sent,
            "Processing changed a multiline HTML task body or rejected an unchanged file with different local and incoming Exchange attachment IDs.");

        var changedCorrelationExchange = new TaskAssignmentRecordingHandler
        {
            ProcessMessage = true,
            ReturnLocalTaskForFind = true,
            IncludeTaskFileAttachment = true,
            LocalTaskGlobalId = TaskGlobalId,
            TaskRequestGlobalId = TaskGlobalId,
            TaskGlobalId = TaskAssignmentRecordingHandler.WrongGlobalIdValue
        };
        var changedCorrelationClient = NewEwsClient(changedCorrelationExchange,
            taskDirectory: NewTaskAssignerDirectory());
        await AssertThrowsAsync<InvalidOperationException>(() => changedCorrelationClient.PrepareTaskProcessAsync(
            "alice@example.test", "request-1", CancellationToken.None));
        Expect(changedCorrelationExchange.Calls.Any(call => call.Operation == "FindItem")
            && changedCorrelationExchange.Calls.Count(call => call.Operation == "GetItem") >= 2
            && changedCorrelationExchange.CreateItemCount == 0
            && changedCorrelationExchange.UpdateItemCount == 0,
            "A fresh task GlobalID mismatch did not reach FindItem and the full GetItem recheck before a write or native send.");

        var tampered = assignment with { PayloadXml = assignment.PayloadXml!.Replace("Task Request", "Tampered", StringComparison.Ordinal) };
        await AssertThrowsAsync<InvalidOperationException>(() => client.ExecuteTaskActionAsync(
            "alice@example.test", tampered, CancellationToken.None));
        await AssertThrowsAsync<InvalidOperationException>(() => client.ExecuteTaskActionAsync(
            "other@example.test", assignment, CancellationToken.None));

        exchange.Mode = TaskAssignmentFixtureMode.MissingAttachment;
        await AssertThrowsAsync<InvalidOperationException>(() => client.PrepareTaskResponseAsync(
            "alice@example.test", "request-1", true, CancellationToken.None));
        exchange.Mode = TaskAssignmentFixtureMode.WrongRecipient;
        await AssertThrowsAsync<InvalidOperationException>(() => client.PrepareTaskResponseAsync(
            "alice@example.test", "request-1", true, CancellationToken.None));
        exchange.Mode = TaskAssignmentFixtureMode.Processed;
        await AssertThrowsAsync<InvalidOperationException>(() => client.PrepareTaskResponseAsync(
            "alice@example.test", "request-1", true, CancellationToken.None));
        foreach (var untrustedHeaderMode in new[]
        {
            TaskAssignmentFixtureMode.LegacyHeaderAttribute,
            TaskAssignmentFixtureMode.AnonymousHeader,
            TaskAssignmentFixtureMode.MissingAuthHeader
        })
        {
            var untrustedExchange = new TaskAssignmentRecordingHandler { Mode = untrustedHeaderMode };
            var untrustedClient = NewEwsClient(untrustedExchange, taskDirectory: NewTaskAssignerDirectory());
            await AssertThrowsWithMessageAsync<InvalidOperationException>(() => untrustedClient.PrepareTaskResponseAsync(
                "alice@example.test", "request-1", true, CancellationToken.None),
                "The native task message has no Exchange-internal authentication provenance.");
        }
        exchange.Mode = TaskAssignmentFixtureMode.Duplicate;
        exchange.ReturnLocalTaskForFind = false;
        await AssertThrowsAsync<InvalidOperationException>(() => client.ListTaskAssignmentMessagesAsync(
            "alice@example.test", 0, 20, CancellationToken.None));

        var wrongClassExchange = new TaskAssignmentRecordingHandler { Mode = TaskAssignmentFixtureMode.WrongClass };
        var wrongClassClient = NewEwsClient(wrongClassExchange, taskDirectory: NewTaskAssignerDirectory());
        await AssertThrowsAsync<InvalidOperationException>(() => wrongClassClient.PrepareTaskResponseAsync(
            "alice@example.test", "request-1", true, CancellationToken.None));

        var wrongSenderExchange = new TaskAssignmentRecordingHandler
        {
            Mode = TaskAssignmentFixtureMode.WrongSender,
            ProcessMessage = true,
            ReturnLocalTaskForFind = true,
            TaskVersion = 3,
            LocalTaskVersion = 2
        };
        var wrongSenderClient = NewEwsClient(wrongSenderExchange, taskDirectory: NewTaskAssignerDirectory());
        await AssertThrowsAsync<InvalidOperationException>(() => wrongSenderClient.PrepareTaskProcessAsync(
            "alice@example.test", "request-1", CancellationToken.None));

        var wrongGlobalExchange = new TaskAssignmentRecordingHandler { Mode = TaskAssignmentFixtureMode.WrongGlobalId };
        var wrongGlobalClient = NewEwsClient(wrongGlobalExchange);
        await AssertThrowsAsync<InvalidOperationException>(() => wrongGlobalClient.ReadTaskAssignmentMessageAsync(
            "alice@example.test", "request-1", CancellationToken.None));

        foreach (var staleVersion in new[] { 1, 2 })
        {
            var staleResponseExchange = new TaskAssignmentRecordingHandler
            {
                ProcessMessage = true,
                ReturnLocalTaskForFind = true,
                TaskVersion = staleVersion,
                LocalTaskVersion = 2
            };
            var staleResponseClient = NewEwsClient(staleResponseExchange, taskDirectory: NewTaskAssignerDirectory());
            await AssertThrowsAsync<InvalidOperationException>(() => staleResponseClient.PrepareTaskProcessAsync(
                "alice@example.test", "request-1", CancellationToken.None));
        }

        var emptyResponseExchange = new TaskAssignmentRecordingHandler
        {
            EmptyItemsOnCreate = true,
            UnassignedTask = true
        };
        var emptyResponseClient = NewEwsClient(emptyResponseExchange);
        var emptyResponseAction = await emptyResponseClient.PrepareTaskAssignmentAsync(
            "alice@example.test", "task-1", "bob@example.test", keepUpdated: true,
            completionReport: true, reassign: false, CancellationToken.None,
            actionTimeUtc: assignment.ActionTimeUtc);
        var emptyResponseResult = await emptyResponseClient.ExecuteTaskActionAsync(
            "alice@example.test", emptyResponseAction, CancellationToken.None);
        Expect(emptyResponseResult.Sent && emptyResponseResult.Applied,
            "A successful SendAndSaveCopy response with an empty Items element was treated as a failed task send.");

        var fileExchange = new TaskAssignmentRecordingHandler
        {
            UnassignedTask = true,
            IncludeTaskFileAttachment = true,
            TaskBody = MultilineTaskHtml,
            TaskBodyType = "HTML"
        };
        var fileClient = NewEwsClient(fileExchange, taskDirectory: NewTaskAssignerDirectory());
        var multilineTask = await fileClient.GetTaskAsync("alice@example.test", "task-1", CancellationToken.None);
        Expect(multilineTask.Body == MultilineTaskHtml && multilineTask.BodyType == "HTML",
            "Reading an Exchange-normalized task changed its exact CRLF, tabs or HTML body.");
        var fileAssignment = await fileClient.PrepareTaskAssignmentAsync(
            "alice@example.test", "task-1", "bob@example.test", keepUpdated: true,
            completionReport: true, reassign: false, CancellationToken.None,
            actionTimeUtc: DateTimeOffset.Parse("2026-10-12T11:00:00Z", CultureInfo.InvariantCulture));
        var fileTask = fileAssignment.PreviewTask!;
        var fileContent = fileTask.AttachmentContents!.Single();
        Expect(fileTask.Attachments!.Count == 1 && fileContent.Name == "evidence.bin"
            && fileContent.Content.SequenceEqual(Encoding.UTF8.GetBytes("abc"))
            && fileContent.ContentType == "application/octet-stream"
            && fileContent.IsInline && fileContent.ContentId == "cid-task-evidence"
            && fileAssignment.PayloadXml!.Contains("evidence.bin", StringComparison.Ordinal)
            && fileAssignment.PayloadXml.Contains("YWJj", StringComparison.Ordinal),
            "Task assignment did not preserve the file name, type, inline ContentId and exact bytes.");
        var assignmentCallStart = fileExchange.Calls.Count;
        var fileAssignmentResult = await fileClient.ExecuteTaskActionAsync(
            "alice@example.test", fileAssignment, CancellationToken.None);
        var assignmentCalls = fileExchange.Calls.Skip(assignmentCallStart).ToArray();
        var assignmentUpdateIndex = Array.FindIndex(assignmentCalls,
            call => call.Operation == "UpdateItem");
        var assignmentSendIndex = Array.FindIndex(assignmentCalls,
            call => call.Operation == "CreateItem"
                && call.Body.Contains("IPM.TaskRequest", StringComparison.Ordinal));
        Expect(fileAssignmentResult.Sent && fileAssignmentResult.Applied
            && assignmentUpdateIndex >= 0
            && assignmentSendIndex > assignmentUpdateIndex,
            "Executing a file-backed task assignment did not update the source before sending the native request.");
        AssertExecutedTaskFile(assignmentCalls[assignmentSendIndex], fileContent, expectedMode: "1",
            "file-backed task assignment");
        var overheadExchange = new TaskAssignmentRecordingHandler
        {
            UnassignedTask = true,
            IncludeTaskFileAttachment = true,
            TaskAttachmentName = "cm-task-note.txt",
            TaskAttachmentContentType = "text/plain",
            TaskAttachmentContentId = "cid-task-note",
            TaskAttachmentSize = 245,
            TaskAttachmentContentSize = 46
        };
        var overheadClient = NewEwsClient(overheadExchange, taskDirectory: NewTaskAssignerDirectory());
        var overheadAction = await overheadClient.PrepareTaskAssignmentAsync(
            "alice@example.test", "task-1", "bob@example.test", true, true, false, CancellationToken.None,
            actionTimeUtc: DateTimeOffset.Parse("2026-10-12T11:00:30Z", CultureInfo.InvariantCulture));
        var overheadTask = overheadAction.PreviewTask!;
        var overheadAttachment = overheadTask.Attachments!.Single();
        var overheadContent = overheadTask.AttachmentContents!.Single();
        var overheadPayloadAttachment = XDocument.Parse(overheadAction.PayloadXml!)
            .Descendants(XName.Get("FileAttachment", TypesNamespace)).Single();
        Expect(overheadAttachment.Id == "file-attachment-1"
            && overheadAttachment.Name == "cm-task-note.txt"
            && overheadAttachment.ContentType == "text/plain"
            && overheadAttachment.IsInline
            && overheadAttachment.ContentId == "cid-task-note"
            && overheadAttachment.Size == 46
            && overheadContent.Id == overheadAttachment.Id
            && overheadContent.Content.Length == 46
            && overheadContent.Content.SequenceEqual(Enumerable.Repeat((byte)'a', 46))
            && overheadPayloadAttachment.Element(XName.Get("Size", TypesNamespace))?.Value == "46",
            "Exchange attachment overhead was not normalized to the fetched byte length in the snapshot and payload.");
        var overheadResponseAction = await overheadClient.PrepareTaskResponseAsync(
            "alice@example.test", "request-1", responseAccept: true, CancellationToken.None,
            actionTimeUtc: DateTimeOffset.Parse("2026-10-12T11:00:31Z", CultureInfo.InvariantCulture));
        var overheadResult = await overheadClient.ExecuteTaskActionAsync(
            "alice@example.test", overheadResponseAction, CancellationToken.None);
        Expect(overheadResult.Sent && overheadResult.Applied,
            "An attachment whose Exchange metadata size included overhead failed approval revalidation.");
        var noBodyExchange = new TaskAssignmentRecordingHandler
        {
            UnassignedTask = true,
            IncludeTaskFileAttachment = true,
            TaskBody = null
        };
        var noBodyAction = await NewEwsClient(noBodyExchange, taskDirectory: NewTaskAssignerDirectory())
            .PrepareTaskAssignmentAsync("alice@example.test", "task-1", "bob@example.test", true, true, false,
                CancellationToken.None);
        var noBodyTask = XDocument.Parse(noBodyAction.PayloadXml!).Descendants(XName.Get("Task", TypesNamespace)).Single();
        var noBodyChildren = noBodyTask.Elements().Select(element => element.Name.LocalName).ToArray();
        Expect(!noBodyChildren.Contains("Body")
            && Array.IndexOf(noBodyChildren, "Attachments") > Array.IndexOf(noBodyChildren, "Subject")
            && noBodyTask.Descendants(XName.Get("Content", TypesNamespace)).Single().Value == "YWJj",
            "A file attachment without a task body was serialized before the native Subject or lost its exact content.");
        var fileAccepted = await fileClient.PrepareTaskResponseAsync(
            "alice@example.test", "request-1", responseAccept: true, CancellationToken.None,
            actionTimeUtc: DateTimeOffset.Parse("2026-10-12T11:01:00Z", CultureInfo.InvariantCulture));
        Expect(fileAccepted.PreviewTask!.AttachmentContents!.Single().Content.SequenceEqual(fileContent.Content),
            "Task acceptance did not retain the immutable attachment snapshot.");
        var fileAcceptedResult = await fileClient.ExecuteTaskActionAsync(
            "alice@example.test", fileAccepted, CancellationToken.None);
        var localAcceptedCall = fileExchange.Calls.Last(call => call.Operation == "CreateItem"
            && call.Body.Contains("<m:SavedItemFolderId>", StringComparison.Ordinal));
        var localAcceptedTask = XDocument.Parse(localAcceptedCall.Body)
            .Descendants(XName.Get("Task", TypesNamespace)).Single();
        var localAcceptedFile = localAcceptedTask.Descendants(XName.Get("FileAttachment", TypesNamespace)).Single();
        var localAcceptedProperties = ReadNamedProperties(
            localAcceptedTask.Elements(XName.Get("ExtendedProperty", TypesNamespace)));
        Expect(fileAcceptedResult.Sent && fileAcceptedResult.Applied,
            "Executing file-backed task acceptance did not complete the native action.");
        Expect(localAcceptedFile.Element(XName.Get("Name", TypesNamespace))?.Value == fileContent.Name,
            "Executing file-backed task acceptance changed the attachment name.");
        Expect(localAcceptedFile.Element(XName.Get("Size", TypesNamespace))?.Value
                == fileContent.Content.Length.ToString(CultureInfo.InvariantCulture),
            "Executing file-backed task acceptance changed the attachment size.");
        Expect(localAcceptedFile.Element(XName.Get("ContentType", TypesNamespace))?.Value == fileContent.ContentType,
            "Executing file-backed task acceptance changed the attachment type.");
        Expect(localAcceptedFile.Element(XName.Get("IsInline", TypesNamespace))?.Value == "true",
            "Executing file-backed task acceptance changed the attachment inline flag.");
        Expect(localAcceptedFile.Element(XName.Get("ContentId", TypesNamespace))?.Value == fileContent.ContentId,
            "Executing file-backed task acceptance changed the attachment ContentId.");
        Expect(Convert.FromBase64String(localAcceptedFile.Element(XName.Get("Content", TypesNamespace))!.Value)
                .SequenceEqual(fileContent.Content),
            "Executing file-backed task acceptance changed the attachment bytes.");
        Expect(localAcceptedProperties[NamedPropertyKey("00062008-0000-0000-C000-000000000046", "0x8518")] == "0",
            "Executing file-backed task acceptance did not create a local mode-0 copy.");
        Expect(localAcceptedTask.Element(XName.Get("Body", TypesNamespace))?.Value
                == MultilineTaskHtml.Replace("\r\n", "\n", StringComparison.Ordinal)
            && localAcceptedTask.Element(XName.Get("Body", TypesNamespace))?.Attribute("BodyType")?.Value == "HTML",
            "Accepting a file-backed task changed its multiline HTML body beyond XML line-ending normalization.");
        fileExchange.UnassignedTask = false;
        var fileReassignment = await fileClient.PrepareTaskAssignmentAsync(
            "alice@example.test", "task-1", "carol@example.test", keepUpdated: true,
            completionReport: true, reassign: true, CancellationToken.None,
            actionTimeUtc: DateTimeOffset.Parse("2026-10-12T11:02:00Z", CultureInfo.InvariantCulture));
        var fileProgress = await fileClient.PrepareTaskProgressAsync(
            "alice@example.test", "task-1", 50, "InProgress", CancellationToken.None,
            actionTimeUtc: DateTimeOffset.Parse("2026-10-12T11:03:00Z", CultureInfo.InvariantCulture));
        Expect(fileReassignment.PreviewTask!.AttachmentContents!.Single().Content.SequenceEqual(fileContent.Content)
            && fileProgress.PreviewTask!.AttachmentContents!.Single().Content.SequenceEqual(fileContent.Content)
            && fileProgress.PayloadXml!.Contains("cid-task-evidence", StringComparison.Ordinal),
            "Task reassignment or progress dropped the immutable attachment snapshot.");
        var reassignmentCallStart = fileExchange.Calls.Count;
        var fileReassignmentResult = await fileClient.ExecuteTaskActionAsync(
            "alice@example.test", fileReassignment, CancellationToken.None);
        var reassignmentCalls = fileExchange.Calls.Skip(reassignmentCallStart).ToArray();
        var reassignmentUpdateIndex = Array.FindIndex(reassignmentCalls,
            call => call.Operation == "UpdateItem");
        var reassignmentSendIndex = Array.FindIndex(reassignmentCalls,
            call => call.Operation == "CreateItem"
                && call.Body.Contains("IPM.TaskRequest", StringComparison.Ordinal));
        Expect(fileReassignmentResult.Sent && fileReassignmentResult.Applied
            && reassignmentUpdateIndex >= 0
            && reassignmentSendIndex > reassignmentUpdateIndex,
            "Executing a file-backed task reassignment did not update the source before sending the native request.");
        AssertExecutedTaskFile(reassignmentCalls[reassignmentSendIndex], fileContent, expectedMode: "1",
            "file-backed task reassignment");
        var progressCallStart = fileExchange.Calls.Count;
        var fileProgressResult = await fileClient.ExecuteTaskActionAsync(
            "alice@example.test", fileProgress, CancellationToken.None);
        var progressCalls = fileExchange.Calls.Skip(progressCallStart).ToArray();
        var progressUpdateIndex = Array.FindIndex(progressCalls,
            call => call.Operation == "UpdateItem");
        var progressSendIndex = Array.FindIndex(progressCalls,
            call => call.Operation == "CreateItem"
                && call.Body.Contains("IPM.TaskRequest.Update", StringComparison.Ordinal));
        var progressUpdate = progressUpdateIndex >= 0
            ? XDocument.Parse(progressCalls[progressUpdateIndex].Body)
            : null;
        Expect(fileProgressResult.Sent && fileProgressResult.Applied
            && progressUpdateIndex >= 0
            && progressSendIndex > progressUpdateIndex,
            "Executing a file-backed task progress update did not update the source before sending the native request.");
        Expect(progressUpdate is not null
            && TaskUpdateValue(progressUpdate, "0x8121") == "bob@example.test"
            && !TaskDeleteField(progressUpdate, "0x8121"),
            "Task progress did not retain native PidLidTaskAssigner on the recipient-owned source copy.");
        AssertExecutedTaskFile(progressCalls[progressSendIndex], fileContent, expectedMode: "4",
            "file-backed task progress");
        var plannedAttachmentActions = new[] { fileAssignment, fileAccepted, fileReassignment, fileProgress, noBodyAction };
        foreach (var action in plannedAttachmentActions.Take(4))
        {
            var taskBody = XDocument.Parse(action.PayloadXml!)
                .Descendants(XName.Get("Task", TypesNamespace)).Single()
                .Element(XName.Get("Body", TypesNamespace));
            Expect(action.PreviewTask?.Body == MultilineTaskHtml && action.PreviewTask.BodyType == "HTML"
                && taskBody?.Value == MultilineTaskHtml.Replace("\r\n", "\n", StringComparison.Ordinal)
                && taskBody.Attribute("BodyType")?.Value == "HTML",
                $"Native task action {action.Operation} changed the exact body snapshot or its wire text, tabs or HTML type.");
        }
        ValidatePeopleTasksSchema(plannedAttachmentActions.Select(action => new CapturedEwsRequest(
            "CreateItem", PlannedTaskPayloadEnvelope(action.PayloadXml!), fileExchange.Calls[0].Headers,
            "alice@example.test")).ToArray());

        foreach (var invalidBody in new[] { "task\u007fbody", new string('x', 80_001) })
        {
            var invalidBodyExchange = new TaskAssignmentRecordingHandler
            {
                UnassignedTask = true,
                TaskBody = invalidBody
            };
            await AssertThrowsAsync<ArgumentException>(() => NewEwsClient(invalidBodyExchange)
                .PrepareTaskAssignmentAsync("alice@example.test", "task-1", "bob@example.test", true, true, false,
                    CancellationToken.None));
            Expect(invalidBodyExchange.CreateItemCount == 0,
                "An invalid control or overlength task body reached a native task send.");
        }

        var tamperedExchange = new TaskAssignmentRecordingHandler
        {
            UnassignedTask = true,
            IncludeTaskFileAttachment = true
        };
        var tamperedClient = NewEwsClient(tamperedExchange);
        var tamperedAction = await tamperedClient.PrepareTaskAssignmentAsync(
            "alice@example.test", "task-1", "bob@example.test", true, true, false, CancellationToken.None,
            actionTimeUtc: DateTimeOffset.Parse("2026-10-12T11:04:00Z", CultureInfo.InvariantCulture));
        tamperedExchange.TamperTaskAttachment = true;
        await AssertThrowsAsync<InvalidOperationException>(() => tamperedClient.ExecuteTaskActionAsync(
            "alice@example.test", tamperedAction, CancellationToken.None));

        var embeddedExchange = new TaskAssignmentRecordingHandler
        {
            UnassignedTask = true,
            IncludeEmbeddedTaskAttachment = true
        };
        await AssertThrowsAsync<InvalidOperationException>(() => NewEwsClient(embeddedExchange)
            .PrepareTaskAssignmentAsync("alice@example.test", "task-1", "bob@example.test", true, true, false,
                CancellationToken.None));
        var oversizedExchange = new TaskAssignmentRecordingHandler
        {
            UnassignedTask = true,
            IncludeTaskFileAttachment = true,
            TaskAttachmentSize = 5 * 1024 * 1024 + 1
        };
        await AssertThrowsAsync<InvalidOperationException>(() => NewEwsClient(oversizedExchange)
            .PrepareTaskAssignmentAsync("alice@example.test", "task-1", "bob@example.test", true, true, false,
                CancellationToken.None));
        var mismatchedExchange = new TaskAssignmentRecordingHandler
        {
            UnassignedTask = true,
            IncludeTaskFileAttachment = true,
            TaskAttachmentSize = 2,
            TaskAttachmentContentSize = 3
        };
        await AssertThrowsAsync<InvalidOperationException>(() => NewEwsClient(mismatchedExchange)
            .PrepareTaskAssignmentAsync("alice@example.test", "task-1", "bob@example.test", true, true, false,
                CancellationToken.None));
        var budgetExchange = new TaskAssignmentRecordingHandler
        {
            UnassignedTask = true,
            IncludeTaskFileAttachment = true,
            TaskAttachmentSize = 400_000
        };
        await AssertThrowsAsync<InvalidOperationException>(() => NewEwsClient(budgetExchange)
            .PrepareTaskAssignmentAsync("alice@example.test", "task-1", "bob@example.test", true, true, false,
                CancellationToken.None));
        var utf8BudgetExchange = new TaskAssignmentRecordingHandler
        {
            UnassignedTask = true,
            IncludeTaskFileAttachment = true,
            TaskAttachmentSize = 270_000,
            TaskAttachmentContentSize = 270_000,
            TaskBody = string.Concat(Enumerable.Repeat("😀", 40_000))
        };
        await AssertThrowsAsync<InvalidOperationException>(() => NewEwsClient(utf8BudgetExchange)
            .PrepareTaskAssignmentAsync("alice@example.test", "task-1", "bob@example.test", true, true, false,
                CancellationToken.None));

        foreach (var malformedMetadata in new[]
        {
            (Name: "evidence&#xD;&#xA;.bin", ContentType: "application/octet-stream", ContentId: "cid-task-evidence"),
            (Name: "evidence.bin", ContentType: "application&#xD;&#xA;/octet-stream", ContentId: "cid-task-evidence"),
            (Name: "evidence.bin", ContentType: "application/octet-stream", ContentId: "cid&#xD;&#xA;-task-evidence")
        })
        {
            var malformedExchange = new TaskAssignmentRecordingHandler
            {
                UnassignedTask = true,
                IncludeTaskFileAttachment = true,
                TaskAttachmentName = malformedMetadata.Name,
                TaskAttachmentContentType = malformedMetadata.ContentType,
                TaskAttachmentContentId = malformedMetadata.ContentId
            };
            await AssertThrowsAsync<ArgumentException>(() => NewEwsClient(malformedExchange)
                .PrepareTaskAssignmentAsync("alice@example.test", "task-1", "bob@example.test", true, true, false,
                    CancellationToken.None));
            Expect(!malformedExchange.Calls.Any(call => call.Operation is "CreateItem" or "UpdateItem"),
                "Malformed imported task attachment metadata was accepted before mutation.");
        }

        ValidatePeopleTasksSchema(exchange.Calls);
        foreach (var call in exchange.Calls)
        {
            var values = XDocument.Parse(call.Body).Descendants(XName.Get("ExtendedProperty", TypesNamespace))
                .Where(property => (string?)property.Element(XName.Get("ExtendedFieldURI", TypesNamespace))
                    ?.Attribute("PropertyType") == "SystemTime")
                .Select(property => property.Element(XName.Get("Value", TypesNamespace))?.Value);
            foreach (var value in values)
                Expect(value is not null && DateTimeOffset.TryParseExact(value,
                    "yyyy-MM-ddTHH:mm:ss.fffZ", CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out _),
                    "A native task SystemTime writer did not use the EWS UTC millisecond format.");
        }

        static string? TaskUpdateValue(XDocument document, string propertyId) =>
            document.Descendants(XName.Get("SetItemField", TypesNamespace))
                .SelectMany(value => value.Descendants(XName.Get("ExtendedProperty", TypesNamespace)))
                .Where(value => PropertyIdMatches(
                    value.Element(XName.Get("ExtendedFieldURI", TypesNamespace)), propertyId))
                .Select(value => value.Element(XName.Get("Value", TypesNamespace))?.Value)
                .SingleOrDefault();

        static string? TaskUpdateNameValue(XDocument document, string propertyName) =>
            document.Descendants(XName.Get("SetItemField", TypesNamespace))
                .Where(value => value.Descendants(XName.Get("ExtendedFieldURI", TypesNamespace))
                    .Any(field => (string?)field.Attribute("PropertyName") == propertyName))
                .SelectMany(value => value.Descendants(XName.Get("ExtendedProperty", TypesNamespace)))
                .Select(value => value.Element(XName.Get("Value", TypesNamespace))?.Value)
                .SingleOrDefault();

        static bool TaskDeleteField(XDocument document, string propertyId) =>
            document.Descendants(XName.Get("DeleteItemField", TypesNamespace))
                .Any(value => PropertyIdMatches(
                    value.Element(XName.Get("ExtendedFieldURI", TypesNamespace)), propertyId));
    }

    private static string PlannedTaskPayloadEnvelope(string payload) =>
        $"<s:Envelope xmlns:s='{SoapNamespace}' xmlns:m='{MessagesNamespace}' xmlns:t='{TypesNamespace}'><s:Body>{payload}</s:Body></s:Envelope>";

    private static LdapMailboxPermissionReader NewTaskAssignerDirectory()
    {
        var options = Options.Create(new DirectoryPermissionOptions
        {
            Host = "ldap.example.test",
            Port = 636,
            BaseDn = "DC=example,DC=test",
            TimeoutSeconds = 8
        });
        return new LdapMailboxPermissionReader(options,
            new TaskAssignmentDirectoryFactory(),
            NullLogger<LdapMailboxPermissionReader>.Instance);
    }

    private static string NamedPropertyKey(string propertySet, string propertyId)
    {
        var canonical = propertyId.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
            && int.TryParse(propertyId[2..], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var hex)
            ? hex.ToString(CultureInfo.InvariantCulture)
            : propertyId;
        return $"{propertySet}:{canonical}";
    }

    private static bool PropertyIdMatches(XElement? field, string expected)
    {
        if (field is null) return false;
        return NamedPropertyKey((string?)field.Attribute("PropertySetId") ?? string.Empty,
                (string?)field.Attribute("PropertyId") ?? string.Empty)
            .Equals(NamedPropertyKey((string?)field.Attribute("PropertySetId") ?? string.Empty, expected),
                StringComparison.OrdinalIgnoreCase);
    }

    private static async Task AssertThrowsWithMessageAsync<TException>(Func<Task> action, string expectedMessage)
        where TException : Exception
    {
        try
        {
            await action();
        }
        catch (TException exception) when (exception.Message == expectedMessage)
        {
            return;
        }
        throw new InvalidOperationException($"Expected {typeof(TException).Name} with the exact provenance rejection.");
    }

    private static void AssertTaskSend(EwsTaskAction action, string itemClass, string recipient, string globalId,
        string? expectedState = null, string? expectedOwnership = null, string? expectedAcceptance = null,
        string? expectedVersion = null, bool requireAssignerStack = true)
    {
        var document = XDocument.Parse(action.PayloadXml!);
        var operation = document.Root!;
        Expect(operation.Name == XName.Get("CreateItem", MessagesNamespace)
            && (string?)operation.Attribute("MessageDisposition") == "SendAndSaveCopy",
            $"{action.Operation} did not produce a native send-and-save CreateItem.");
        var message = operation.Descendants(XName.Get("Message", TypesNamespace)).Single();
        Expect(message.Element(XName.Get("ItemClass", TypesNamespace))?.Value == itemClass
            && message.Descendants(XName.Get("EmailAddress", TypesNamespace)).Any(value => value.Value == recipient),
            $"{action.Operation} did not target the expected task recipient and item class.");
        Expect(message.Descendants(XName.Get("ItemAttachment", TypesNamespace)).Any()
            && message.Descendants(XName.Get("Task", TypesNamespace)).Any(),
            $"{action.Operation} did not carry an embedded native Task item.");
        var taskElement = message.Descendants(XName.Get("Task", TypesNamespace)).Single();
        Expect(taskElement.Element(XName.Get("ItemClass", TypesNamespace))?.Value == "IPM.Task",
            "The embedded task lost its native IPM.Task identity.");
        var messageProperties = ReadNamedProperties(message.Elements(XName.Get("ExtendedProperty", TypesNamespace)));
        var taskProperties = ReadNamedProperties(taskElement.Elements(XName.Get("ExtendedProperty", TypesNamespace)));
        var taskTaggedProperties = ReadTaggedProperties(taskElement.Elements(XName.Get("ExtendedProperty", TypesNamespace)));
        var common = "00062008-0000-0000-C000-000000000046";
        var task = "00062003-0000-0000-C000-000000000046";
        var nativeAssignerKey = NamedPropertyKey(task, "0x8121");
        var expectNativeAssigner = !itemClass.Equals("IPM.TaskRequest", StringComparison.OrdinalIgnoreCase);
        var hasValidAssignerStack = taskProperties.TryGetValue(
            NamedPropertyKey(task, "0x8117"), out var assignerStack)
            && IsValidTaskAssignerStack(assignerStack);
        var expectedMode = itemClass switch
        {
            "IPM.TaskRequest" => "1",
            "IPM.TaskRequest.Accept" => "2",
            "IPM.TaskRequest.Decline" => "3",
            "IPM.TaskRequest.Update" => "4",
            _ => throw new InvalidOperationException($"Unexpected task request class {itemClass}.")
        };
        var taskLastUpdateMatches = taskProperties.TryGetValue(NamedPropertyKey(task, "0x8115"), out var taskLastUpdateText)
            && taskLastUpdateText == action.ActionTimeUtc.ToUniversalTime()
                .ToString("yyyy-MM-ddTHH:mm:ss.fffZ", CultureInfo.InvariantCulture);
        var itemAttachment = message.Descendants(XName.Get("ItemAttachment", TypesNamespace)).Single();
        Expect(messageProperties.TryGetValue(NamedPropertyKey(common, "0x8518"), out var messageMode)
            && messageMode == expectedMode
            && messageProperties.TryGetValue(NamedPropertyKey(common, "0x8519"), out var messageGlobalId)
            && messageGlobalId == globalId
            && taskProperties.TryGetValue(NamedPropertyKey(common, "0x8518"), out var embeddedMode)
            && embeddedMode == expectedMode
            && taskProperties.TryGetValue(NamedPropertyKey(common, "0x8519"), out var taskGlobalId)
            && taskGlobalId == globalId
            && taskProperties.TryGetValue(NamedPropertyKey(task, "0x8129"), out var taskOwnership)
            && taskProperties.TryGetValue(NamedPropertyKey(task, "0x812A"), out var taskAcceptance)
            && taskProperties.TryGetValue(NamedPropertyKey(task, "0x8113"), out var taskState)
            && taskProperties.ContainsKey(NamedPropertyKey(task, "0x8112"))
            && (expectedVersion is null || taskProperties[NamedPropertyKey(task, "0x8112")] == expectedVersion)
            && taskProperties.ContainsKey(NamedPropertyKey(task, "0x811A"))
            && taskLastUpdateMatches
            && taskProperties.ContainsKey(NamedPropertyKey(task, "0x8108"))
            && taskProperties.ContainsKey(nativeAssignerKey) == expectNativeAssigner
            && (expectedState is null || taskState == expectedState)
            && (expectedOwnership is null || taskOwnership == expectedOwnership)
            && (expectedAcceptance is null || taskAcceptance == TaskAcceptanceWire(expectedAcceptance))
            && (!requireAssignerStack || hasValidAssignerStack)
            && taskTaggedProperties.TryGetValue("0x0E07", out var messageFlags)
            && messageFlags == "1"
            && taskTaggedProperties.TryGetValue("0x1080", out var iconIndex)
            && iconIndex == "1283"
            && !taskTaggedProperties.ContainsKey("0x0E1F")
            && itemAttachment.Element(XName.Get("IsInline", TypesNamespace)) is null
            && !messageProperties.ContainsKey(NamedPropertyKey(common, "0x23"))
            && !taskProperties.ContainsKey(NamedPropertyKey(common, "0x23")),
            $"{action.Operation} did not carry the Outlook task GlobalID, mode, state, ownership, acceptance, version, history, or safe property set.");
        Expect(!message.Descendants(XName.Get("Item", TypesNamespace)).Any(),
            $"{action.Operation} used a generic Item wrapper instead of a native Task attachment.");
        Expect(!message.Descendants().Any(value => value.Name.LocalName is "IsAssigned" or "IsAccepted" or "IsDelegated"),
            $"{action.Operation} used a synthetic task-assignment flag instead of native Outlook properties.");
    }

    private static void AssertExecutedTaskFile(
        CapturedEwsRequest call,
        EwsAttachmentContent expected,
        string expectedMode,
        string operation)
    {
        var task = XDocument.Parse(call.Body).Descendants(XName.Get("Task", TypesNamespace)).Single();
        var attachment = task.Descendants(XName.Get("FileAttachment", TypesNamespace)).Single();
        var properties = ReadNamedProperties(task.Elements(XName.Get("ExtendedProperty", TypesNamespace)));
        var content = Convert.FromBase64String(attachment.Element(XName.Get("Content", TypesNamespace))!.Value);
        Expect(attachment.Element(XName.Get("AttachmentId", TypesNamespace)) is null
            && attachment.Element(XName.Get("Name", TypesNamespace))?.Value == expected.Name
            && attachment.Element(XName.Get("ContentType", TypesNamespace))?.Value == expected.ContentType
            && attachment.Element(XName.Get("ContentId", TypesNamespace))?.Value == expected.ContentId
            && attachment.Element(XName.Get("IsInline", TypesNamespace))?.Value == "true"
            && attachment.Element(XName.Get("Size", TypesNamespace))?.Value
                == expected.Content.Length.ToString(CultureInfo.InvariantCulture)
            && content.SequenceEqual(expected.Content)
            && properties[NamedPropertyKey("00062008-0000-0000-C000-000000000046", "0x8518")] == expectedMode
            && task.Element(XName.Get("Body", TypesNamespace))?.Value
                == MultilineTaskHtml.Replace("\r\n", "\n", StringComparison.Ordinal)
            && task.Element(XName.Get("Body", TypesNamespace))?.Attribute("BodyType")?.Value == "HTML",
            $"Executing {operation} changed its attachment metadata, content, body or native mode.");
    }

    private static string TaskAcceptanceWire(string numeric) => numeric switch
    {
        "0" => "NoMatch",
        "1" => "OwnNew",
        "2" => "Owned",
        "3" => "Accepted",
        _ => throw new InvalidOperationException("The task acceptance fixture used an unsupported state.")
    };

    private static void AssertCanonicalAndLegacyTaskAssignerStacks()
    {
        const string nativeDn = "/o=Example/ou=Exchange Administrative Group/cn=Recipients/cn=information-technology";
        var canonical = TaskAssignerStack.Encode([
            new TaskAssignerEntry(nativeDn, "Information Technology")]);
        var canonicalBytes = Convert.FromBase64String(canonical);
        var outerLength = BinaryPrimitives.ReadInt32LittleEndian(canonicalBytes.AsSpan(4));
        var entryIdLength = BinaryPrimitives.ReadInt32LittleEndian(canonicalBytes.AsSpan(8));
        Expect(entryIdLength == 28 + Encoding.ASCII.GetByteCount(nativeDn) + 1
            && outerLength == 4 + entryIdLength
                + Encoding.ASCII.GetByteCount("Information Technology") + 1
                + Encoding.Unicode.GetByteCount("Information Technology") + 2,
            "The native task assigner encoder did not write the bounded inner EntryID prefix and canonical size.");
        var parsedCanonical = TaskAssignerStack.Parse(canonical);
        Expect(parsedCanonical.Count == 1 && parsedCanonical[0].LegacyExchangeDn == nativeDn
            && parsedCanonical[0].DisplayName == "Information Technology",
            "The canonical length-prefixed native task assigner entry did not parse.");

        var legacy = BuildLegacyTaskAssignerStack(
            "/o=Example/ou=Exchange Administrative Group/cn=Recipients/cn=legacy", "Legacy User");
        var parsedLegacy = TaskAssignerStack.Parse(legacy);
        Expect(parsedLegacy.Count == 1 && parsedLegacy[0].DisplayName == "Legacy User",
            "The validated legacy unprefixed task assigner entry was not retained for existing MCP tasks.");
    }

    private static string BuildLegacyTaskAssignerStack(string dn, string displayName)
    {
        var provider = Convert.FromHexString("DCA740C8C042101AB4B908002B2FE182");
        using var item = new MemoryStream();
        using (var writer = new BinaryWriter(item, Encoding.ASCII, leaveOpen: true))
        {
            writer.Write(0);
            writer.Write(provider);
            writer.Write(1);
            writer.Write(0);
            writer.Write(Encoding.ASCII.GetBytes(dn));
            writer.Write((byte)0);
            writer.Write(Encoding.ASCII.GetBytes(displayName));
            writer.Write((byte)0);
            writer.Write(Encoding.Unicode.GetBytes(displayName));
            writer.Write((ushort)0);
        }
        using var stack = new MemoryStream();
        using (var writer = new BinaryWriter(stack, Encoding.ASCII, leaveOpen: true))
        {
            writer.Write(1);
            writer.Write(checked((int)item.Length));
            writer.Write(item.ToArray());
        }
        return Convert.ToBase64String(stack.ToArray());
    }

    private static Dictionary<string, string?> ReadNamedProperties(IEnumerable<XElement> fields)
    {
        return fields
            .Select(value => (Field: value.Element(XName.Get("ExtendedFieldURI", TypesNamespace)),
                Value: value.Element(XName.Get("Value", TypesNamespace))?.Value))
            .Where(value => value.Field is not null
                && value.Field.Attribute("PropertySetId") is not null
                && value.Field.Attribute("PropertyId") is not null)
            .GroupBy(value => NamedPropertyKey(value.Field!.Attribute("PropertySetId")!.Value,
                    value.Field.Attribute("PropertyId")!.Value),
                StringComparer.OrdinalIgnoreCase)
            .ToDictionary(group => group.Key, group =>
            {
                var values = group.Select(value => value.Value).Distinct(StringComparer.Ordinal).ToArray();
                if (values.Length != 1)
                    throw new InvalidOperationException($"Native task property {group.Key} had conflicting values: {string.Join(", ", values)}.");
                return values[0];
            }, StringComparer.OrdinalIgnoreCase);
    }

    private static Dictionary<string, string?> ReadTaggedProperties(IEnumerable<XElement> fields)
    {
        return fields
            .Select(value => (Field: value.Element(XName.Get("ExtendedFieldURI", TypesNamespace)),
                Value: value.Element(XName.Get("Value", TypesNamespace))?.Value))
            .Where(value => value.Field?.Attribute("PropertyTag") is not null)
            .GroupBy(value => value.Field!.Attribute("PropertyTag")!.Value,
                StringComparer.OrdinalIgnoreCase)
            .ToDictionary(group => group.Key, group =>
            {
                var values = group.Select(value => value.Value).Distinct(StringComparer.Ordinal).ToArray();
                if (values.Length != 1)
                    throw new InvalidOperationException($"Native task property tag {group.Key} had conflicting values: {string.Join(", ", values)}.");
                return values[0];
            }, StringComparer.OrdinalIgnoreCase);
    }

    private static bool IsValidTaskAssignerStack(string? base64)
    {
        if (string.IsNullOrWhiteSpace(base64)) return false;
        try
        {
            var entries = TaskAssignerStack.Parse(base64);
            return entries.Count == 0 || entries.Count is 1 or 2
                && entries.Select((entry, index) =>
                    entry.LegacyExchangeDn == $"/o=Example/ou=Exchange Administrative Group/cn=Recipients/cn={(index == 0 ? "bob" : "alice")}"
                    && entry.DisplayName == (index == 0 ? "Bob" : "Alice"))
                    .All(value => value);
        }
        catch (InvalidOperationException)
        {
            return false;
        }
    }
}

internal enum TaskAssignmentFixtureMode
{
    Normal,
    MissingAttachment,
    WrongRecipient,
    Processed,
    Duplicate,
    WrongClass,
    WrongSender,
    WrongGlobalId,
    LegacyHeaderAttribute,
    AnonymousHeader,
    MissingAuthHeader
}

// Keep the task tests honest about which directory identity is being resolved:
// reassignment resolves the current mailbox (Alice), while an acceptance resolves
// the original assigner (Bob). Returning one fixed row makes a valid stack look
// cyclic and would hide a real directory-to-native-stack regression.
internal sealed class TaskAssignmentDirectoryFactory : ILdapSearchFacadeFactory
{
    public ILdapSearchFacade Create() => new Facade();

    private sealed class Facade : ILdapSearchFacade
    {
        public IReadOnlyList<LdapSearchEntry> Search(
            string baseDn,
            string filter,
            SearchScope scope,
            IReadOnlyList<string> attributes,
            bool requestDaclOnly,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            const string marker = "(mail=";
            var start = filter.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
            var end = start < 0 ? -1 : filter.IndexOf(')', start + marker.Length);
            var mailbox = start >= 0 && end > start
                ? filter[(start + marker.Length)..end]
                : string.Empty;
            var localPart = mailbox.Split('@', 2)[0];
            var displayName = localPart.Equals("alice", StringComparison.OrdinalIgnoreCase)
                ? "Alice"
                : localPart.Equals("bob", StringComparison.OrdinalIgnoreCase)
                    ? "Bob"
                    : localPart.Equals("it", StringComparison.OrdinalIgnoreCase)
                        ? "IT"
                    : localPart;
            var legacyDn = $"/o=Example/ou=Exchange Administrative Group/cn=Recipients/cn={localPart}";
            return [new LdapSearchEntry($"CN={displayName},DC=example,DC=test",
                new Dictionary<string, IReadOnlyList<string>>(StringComparer.OrdinalIgnoreCase)
                {
                    ["legacyExchangeDN"] = [legacyDn],
                    ["displayName"] = [displayName]
                },
                new Dictionary<string, IReadOnlyList<byte[]>>(StringComparer.OrdinalIgnoreCase))];
        }

        public void Dispose() { }
    }
}

internal class TaskAssignmentRecordingHandler : HttpMessageHandler
{
    private static readonly XNamespace Soap = "http://schemas.xmlsoap.org/soap/envelope/";
    private static readonly XNamespace M = "http://schemas.microsoft.com/exchange/services/2006/messages";
    private static readonly XNamespace T = "http://schemas.microsoft.com/exchange/services/2006/types";
    private const string GlobalId = "AAECAwQFBgcICQoLDA0ODw==";
    public const string GlobalIdForChecks = GlobalId;
    public const string WrongGlobalIdValue = "EBESExQVFhcYGRobHB0eHw==";
    private const string McpTaskPropertySet = "D6D5DCE4-8E0E-4EA5-9C4C-A7C2AD20A9A8";
    private const string EmptyAssignerStack = "AAAAAA==";
    private static readonly string AssignerStack = TaskAssignerStack.Encode([
        new TaskAssignerEntry(
            "/o=Example/ou=Exchange Administrative Group/cn=Recipients/cn=bob", "Bob")]);
    private static readonly string NativeReassignmentAssignerStack = TaskAssignerStack.Encode([
        new TaskAssignerEntry(
            "/o=Example/ou=Exchange Administrative Group/cn=Recipients/cn=it", "IT")]);
    internal static string DuplicateNativeReassignmentAssignerStack
    {
        get
        {
            var single = Convert.FromBase64String(NativeReassignmentAssignerStack);
            var duplicate = new byte[single.Length + single.Length - 4];
            single.CopyTo(duplicate, 0);
            single.AsSpan(4).CopyTo(duplicate.AsSpan(single.Length));
            BinaryPrimitives.WriteInt32LittleEndian(duplicate.AsSpan(), 2);
            return Convert.ToBase64String(duplicate);
        }
    }
    private static string NativeDeclineAssignerStack
    {
        get
        {
            var bytes = Convert.FromBase64String(AssignerStack);
            BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(), 0);
            return Convert.ToBase64String(bytes);
        }
    }

    public List<CapturedEwsRequest> Calls { get; } = [];
    public TaskAssignmentFixtureMode Mode { get; set; }
    public string TaskChangeKey { get; set; } = "task-change";
    public int TaskVersion { get; set; } = 2;
    public int? TaskRequestVersion { get; set; }
    public int LocalTaskVersion { get; set; } = 2;
    public bool ProcessMessage { get; set; }
    public bool ReturnLocalTaskForFind { get; set; }
    public bool EmptyItemsOnCreate { get; set; }
    public bool UnassignedTask { get; set; }
    public bool OmitAssignerStack { get; set; }
    public bool OmitTaskRequestVersion { get; set; }
    public bool OmitTaskRequestGlobalId { get; set; }
    public bool OmitEmbeddedTaskVersion { get; set; }
    public bool OmitAcceptedFlag { get; set; }
    public bool IncludeTaskFileAttachment { get; set; }
    public bool IncludeEmbeddedTaskAttachment { get; set; }
    public bool OmitTaskAttachmentInline { get; set; }
    public bool OmitLocalTaskAttachmentMetadata { get; set; }
    public bool TamperTaskAttachment { get; set; }
    public string LocalTaskGlobalId { get; set; } = GlobalId;
    public string TaskRequestGlobalId { get; set; } = GlobalId;
    public string TaskGlobalId { get; set; } = GlobalId;
    public string? TaskAttachmentGlobalId { get; set; }
    public string TaskAttachmentId { get; set; } = "file-attachment-1";
    public string? LocalTaskAttachmentId { get; set; }
    public int TaskAttachmentSize { get; set; } = 3;
    public int TaskAttachmentContentSize { get; set; } = 3;
    public string TaskAttachmentName { get; set; } = "evidence.bin";
    public string TaskAttachmentContentType { get; set; } = "application/octet-stream";
    public string TaskAttachmentContentId { get; set; } = "cid-task-evidence";
    public string? TaskBody { get; set; } = "Disposable task";
    public string TaskBodyType { get; set; } = "Text";
    public string TaskNoticeItemClass { get; set; } = "IPM.TaskRequest";
    public string TaskRequestId { get; set; } = "request-1";
    public string[] TaskRequestCcRecipients { get; set; } = [];
    public string? AcceptanceWireOverride { get; set; }
    public string? NativeLocalAcceptanceWireOverride { get; set; }
    public bool NativeAcceptedResponse { get; set; }
    public bool NativeDeclinedResponse { get; set; }
    public bool NativeUpdatedResponse { get; set; }
    public bool NativeReassignmentRequestResponse { get; set; }
    public bool NativeInitialRequestResponse { get; set; }
    public bool NativeReassignmentUpdateResponse { get; set; }
    public bool NativeReassignmentWatcherLocal { get; set; }
    public bool OmitLocalTaskPrivateRoles { get; set; }
    public string? NativeResponseSender { get; set; }
    public bool EnableDirectoryResolution { get; set; }
    public string DirectoryExpectedQuery { get; set; } = string.Empty;
    public string DirectoryDisplayName { get; set; } = string.Empty;
    public string DirectoryEmailAddress { get; set; } = string.Empty;
    public string? DirectoryOwnDisplayName { get; set; }
    public string? DirectoryOwnEmailAddress { get; set; }
    public string? DirectoryAmbiguousQuery { get; set; }
    public int DirectoryAmbiguousResolutionCount { get; set; } = 2;
    public string DirectoryRoutingType { get; set; } = "SMTP";
    public string DirectoryStackDisplayName { get; set; } = string.Empty;
    public string DirectoryStackEmailAddress { get; set; } = string.Empty;
    public int DirectoryResolutionCount { get; set; } = 1;
    public string NativeTaskAssignerName { get; set; } = "bob@example.test";
    public string NativeTaskOwnerName { get; set; } = "alice@example.test";
    public string NativeTaskLastUserName { get; set; } = "bob@example.test";
    public string NativeTaskLastDelegateName { get; set; } = "bob@example.test";
    public string? NativeTaskAssigneeAddress { get; set; }
    public string? NativeTaskOwnerAddress { get; set; }
    public string? NativeLocalTaskAssigneeAddress { get; set; }
    public string? NativeLocalTaskOwnerAddress { get; set; }
    public string? NativeLocalTaskAssignerAddress { get; set; }
    public string? NativeResponseTaskAssigneeAddress { get; set; }
    public string? NativeResponseTaskOwnerAddress { get; set; }
    public string? NativeResponseTaskAssignerAddress { get; set; }
    public string? NativeAssignerStackOverride { get; set; }
    public string? NativeResponseAssignerStackOverride { get; set; }
    public string? NativeResponseAssignerChainOverride { get; set; }
    public string? TaskRequestRecipient { get; set; }
    public double NativeTaskPercentComplete { get; set; } = 25;
    public string NativeTaskStatus { get; set; } = "InProgress";
    public bool NativeTaskIsComplete { get; set; }
    public DateTimeOffset? NativeTaskCompleteDateUtc { get; set; }
    public bool? AcceptedFlagOverride { get; set; }
    public int CreateItemCount { get; private set; }
    public int UpdateItemCount { get; private set; }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var body = await request.Content!.ReadAsStringAsync(cancellationToken);
        var document = XDocument.Parse(body);
        var operation = document.Root!.Element(Soap + "Body")!.Elements().Single();
        Calls.Add(new CapturedEwsRequest(operation.Name.LocalName, body, request.Headers,
            document.Descendants(T + "PrimarySmtpAddress").SingleOrDefault()?.Value));
        if (operation.Name.LocalName == "CreateItem") CreateItemCount++;
        if (operation.Name.LocalName == "UpdateItem") UpdateItemCount++;
        var response = operation.Name.LocalName switch
        {
            "ResolveNames" when EnableDirectoryResolution => DirectoryResolutionResponse(body),
            "GetItem" when body.Contains("FieldURI=\"item:Attachments\"", StringComparison.Ordinal)
                && body.Contains("FieldURI=\"message:From\"", StringComparison.Ordinal)
                => TaskRequestResponse(),
            "GetAttachment" when IncludeTaskFileAttachment
                && body.Contains($"Id=\"{TaskAttachmentId}\"", StringComparison.Ordinal)
                || IncludeTaskFileAttachment
                && LocalTaskAttachmentId is not null
                && body.Contains($"Id=\"{LocalTaskAttachmentId}\"", StringComparison.Ordinal)
                => TaskFileContentResponse(ReadRequestedAttachmentId(body)),
            "GetAttachment" => TaskAttachmentResponse(),
            "GetItem" when ReturnLocalTaskForFind => TaskResponse("local-task-1", "local-change",
                includeAssignment: true,
                state: NativeReassignmentWatcherLocal ? 3 : 2,
                ownership: 1,
                version: LocalTaskVersion,
                assigneeAddress: NativeReassignmentWatcherLocal && !OmitLocalTaskPrivateRoles
                    ? "own@example.test" : null),
            "GetItem" => TaskResponse("task-1", TaskChangeKey, includeAssignment: true,
                state: UnassignedTask ? 1 : 2, ownership: UnassignedTask ? 0 : 2),
            "FindItem" when ReturnLocalTaskForFind && FindItemFolderId(body) == "inbox" => TaskMessagesResponse(duplicate: false),
            "FindItem" when ReturnLocalTaskForFind => LocalTaskResponse(),
            "FindItem" => Mode == TaskAssignmentFixtureMode.Duplicate
                ? TaskMessagesResponse(duplicate: true)
                : TaskMessagesResponse(duplicate: false),
            "CreateItem" => EmptyItemsOnCreate ? EmptyItemsResponse("CreateItem")
                : body.Contains("<m:SavedItemFolderId>", StringComparison.Ordinal)
                    ? TaskReferenceResponse("CreateItem", "result-1", "result-change")
                    : ItemReferenceResponse("CreateItem", "result-1", "result-change"),
            "UpdateItem" when body.Contains("<Task", StringComparison.Ordinal)
                => TaskProcessedResponse(),
            "UpdateItem" => ItemReferenceResponse("UpdateItem", "result-1", "result-change"),
            _ => ItemReferenceResponse(operation.Name.LocalName, "result-1", "result-change")
        };
        return new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(response, Encoding.UTF8, "text/xml")
        };
    }

    private string TaskRequestResponse()
    {
        var recipient = TaskRequestRecipient ?? (Mode == TaskAssignmentFixtureMode.WrongRecipient ? "carol@example.test"
            : NativeInitialRequestResponse ? "it@example.test"
            : NativeReassignmentRequestResponse ? "mb@example.test"
            : NativeReassignmentUpdateResponse ? "it@example.test"
            : "alice@example.test");
        var processed = Mode == TaskAssignmentFixtureMode.Processed;
        var itemClass = NativeDeclinedResponse ? "IPM.TaskRequest.Decline"
            : NativeUpdatedResponse ? "IPM.TaskRequest.Update"
            : NativeReassignmentUpdateResponse ? "IPM.TaskRequest.Update"
            : ProcessMessage ? "IPM.TaskRequest.Accept"
            : Mode == TaskAssignmentFixtureMode.WrongClass ? "IPM.Note" : "IPM.TaskRequest";
        var sender = Mode == TaskAssignmentFixtureMode.WrongSender ? "mallory@example.test"
            : NativeInitialRequestResponse || NativeReassignmentRequestResponse || NativeReassignmentUpdateResponse ? "own@example.test"
            : NativeResponseSender ?? (NativeAcceptedResponse && NativeReassignmentWatcherLocal
                ? "it@example.test" : "bob@example.test");
        var messageGlobalId = Mode == TaskAssignmentFixtureMode.WrongGlobalId
            ? WrongGlobalIdValue
            : TaskRequestGlobalId;
        var messageMode = itemClass switch
        {
            "IPM.TaskRequest" => 1,
            "IPM.TaskRequest.Accept" => 2,
            "IPM.TaskRequest.Decline" => 3,
            "IPM.TaskRequest.Update" => 4,
            _ => 1
        };
        var authHeaderAttribute = Mode == TaskAssignmentFixtureMode.LegacyHeaderAttribute ? "Name" : "HeaderName";
        var authHeaderValue = Mode == TaskAssignmentFixtureMode.AnonymousHeader ? "Anonymous" : "Internal";
        var authHeader = Mode == TaskAssignmentFixtureMode.MissingAuthHeader
            ? string.Empty
            : $"<t:InternetMessageHeader {authHeaderAttribute}='X-MS-Exchange-Organization-AuthAs'>{authHeaderValue}</t:InternetMessageHeader>";
        var processedProperty = processed
            ? "<t:ExtendedProperty><t:ExtendedFieldURI PropertyTag='0x7D01' PropertyType='Boolean'/><t:Value>true</t:Value></t:ExtendedProperty>"
            : "<t:ExtendedProperty><t:ExtendedFieldURI PropertyTag='0x7D01' PropertyType='Boolean'/><t:Value>false</t:Value></t:ExtendedProperty>";
        var globalProperty = OmitTaskRequestGlobalId
            ? string.Empty
            : $"<t:ExtendedProperty><t:ExtendedFieldURI PropertySetId='00062008-0000-0000-C000-000000000046' PropertyId='0x8519' PropertyType='Binary'/><t:Value>{messageGlobalId}</t:Value></t:ExtendedProperty>";
        var versionProperty = OmitTaskRequestVersion
            ? string.Empty
            : $"<t:ExtendedProperty><t:ExtendedFieldURI PropertySetId='00062003-0000-0000-C000-000000000046' PropertyId='0x8112' PropertyType='Integer'/><t:Value>{TaskRequestVersion ?? TaskVersion}</t:Value></t:ExtendedProperty>";
        var ccRecipients = string.Concat(TaskRequestCcRecipients.Select(address =>
            $"<t:Mailbox><t:EmailAddress>{System.Security.SecurityElement.Escape(address)}</t:EmailAddress></t:Mailbox>"));
        var ccMarkup = TaskRequestCcRecipients.Length == 0 ? string.Empty : $"<t:CcRecipients>{ccRecipients}</t:CcRecipients>";
        var message = $"<t:Message><t:ItemId Id='{TaskRequestId}' ChangeKey='request-change'/><t:ItemClass>{itemClass}</t:ItemClass><t:Subject>Task Request: Verify</t:Subject><t:From><t:Mailbox><t:EmailAddress>{sender}</t:EmailAddress></t:Mailbox></t:From><t:Sender><t:Mailbox><t:EmailAddress>{sender}</t:EmailAddress></t:Mailbox></t:Sender><t:InternetMessageHeaders>{authHeader}</t:InternetMessageHeaders><t:ToRecipients><t:Mailbox><t:EmailAddress>{recipient}</t:EmailAddress></t:Mailbox></t:ToRecipients>{ccMarkup}<t:IsRead>false</t:IsRead>{(Mode == TaskAssignmentFixtureMode.MissingAttachment ? "" : "<t:Attachments><t:ItemAttachment><t:AttachmentId Id='task-attachment-1'/></t:ItemAttachment></t:Attachments>")}{globalProperty}<t:ExtendedProperty><t:ExtendedFieldURI PropertySetId='00062008-0000-0000-C000-000000000046' PropertyId='0x8518' PropertyType='Integer'/><t:Value>{messageMode}</t:Value></t:ExtendedProperty>{versionProperty}{processedProperty}</t:Message>";
        return EnvelopeInResponseMessage("GetItem", $"<m:Items>{message}</m:Items>");
    }

    private string DirectoryResolutionResponse(string body)
    {
        var query = XDocument.Parse(body).Descendants(M + "UnresolvedEntry").SingleOrDefault()?.Value ?? string.Empty;
        var matches = EnableDirectoryResolution
            && (string.IsNullOrWhiteSpace(DirectoryExpectedQuery)
                || string.Equals(query, DirectoryExpectedQuery, StringComparison.OrdinalIgnoreCase))
            ? string.Equals(query, DirectoryAmbiguousQuery, StringComparison.OrdinalIgnoreCase)
                ? DirectoryAmbiguousResolutionCount : DirectoryResolutionCount
            : 0;
        var isStackQuery = query.StartsWith("/o=", StringComparison.OrdinalIgnoreCase);
        var isOwnStackQuery = isStackQuery
            && query.EndsWith("/cn=own", StringComparison.OrdinalIgnoreCase);
        var isOwnQuery = !isStackQuery
            && !string.IsNullOrWhiteSpace(DirectoryOwnEmailAddress)
            && string.Equals(query, DirectoryOwnEmailAddress, StringComparison.OrdinalIgnoreCase);
        var displayName = isOwnStackQuery && !string.IsNullOrWhiteSpace(DirectoryOwnDisplayName)
            ? DirectoryOwnDisplayName
            : isStackQuery && !string.IsNullOrWhiteSpace(DirectoryStackDisplayName)
            ? DirectoryStackDisplayName
            : isOwnQuery && !string.IsNullOrWhiteSpace(DirectoryOwnDisplayName)
                ? DirectoryOwnDisplayName : DirectoryDisplayName;
        var emailAddress = isOwnStackQuery && !string.IsNullOrWhiteSpace(DirectoryOwnEmailAddress)
            ? DirectoryOwnEmailAddress
            : isStackQuery && !string.IsNullOrWhiteSpace(DirectoryStackEmailAddress)
            ? DirectoryStackEmailAddress
            : isOwnQuery && !string.IsNullOrWhiteSpace(DirectoryOwnEmailAddress)
                ? DirectoryOwnEmailAddress : DirectoryEmailAddress;
        var resolutions = string.Concat(Enumerable.Range(0, matches).Select(_ =>
            $"<t:Resolution><t:Mailbox><t:Name>{System.Security.SecurityElement.Escape(displayName)}</t:Name><t:EmailAddress>{System.Security.SecurityElement.Escape(emailAddress)}</t:EmailAddress><t:RoutingType>{System.Security.SecurityElement.Escape(DirectoryRoutingType)}</t:RoutingType></t:Mailbox></t:Resolution>"));
        return Envelope("ResolveNames",
            $"<m:ResolutionSet TotalItemsInView='{matches}' IncludesLastItemInRange='true'>{resolutions}</m:ResolutionSet>");
    }

    private string TaskAttachmentResponse()
    {
        var isResponse = ProcessMessage;
        var isNativeDecline = NativeDeclinedResponse && isResponse;
        var isNativeUpdate = NativeUpdatedResponse && isResponse;
        var isNativeInitialRequest = NativeInitialRequestResponse && !isResponse;
        var isNativeReassignmentRequest = NativeReassignmentRequestResponse && !isResponse;
        var isNativeReassignmentUpdate = NativeReassignmentUpdateResponse && isResponse;
        var inline = OmitTaskAttachmentInline ? string.Empty : "<t:IsInline>true</t:IsInline>";
        var acceptance = isNativeDecline || isNativeInitialRequest || isNativeReassignmentRequest || isNativeReassignmentUpdate
            ? 1 : isNativeUpdate || NativeAcceptedResponse && isResponse ? 0 : isResponse ? 2 : 1;
        var task = TaskMarkup("task-1", TaskChangeKey, includeAssignment: true,
            state: isNativeDecline || isNativeInitialRequest || isNativeReassignmentRequest || isNativeReassignmentUpdate ? 3 : isResponse ? 2 : 3,
            ownership: isNativeDecline || isNativeInitialRequest || isNativeReassignmentRequest || isNativeReassignmentUpdate ? 1 : isResponse ? 2 : 1,
            acceptance: acceptance,
            assignerStack: isNativeDecline ? NativeDeclineAssignerStack
                : isNativeReassignmentRequest || isNativeReassignmentUpdate
                    ? NativeAssignerStackOverride ?? NativeReassignmentAssignerStack
                : isNativeUpdate ? AssignerStack
                : NativeResponseAssignerStackOverride ?? EmptyAssignerStack,
            nativeDecline: isNativeDecline,
            nativeUpdate: isNativeUpdate,
            nativeInitialRequest: isNativeInitialRequest,
            nativeReassignmentRequest: isNativeReassignmentRequest,
            nativeReassignmentUpdate: isNativeReassignmentUpdate,
            assigneeAddress: isNativeInitialRequest || isNativeReassignmentRequest ? null
                : isResponse ? null : "alice@example.test",
            localTask: false);
        if (TaskAttachmentGlobalId is not null)
            task = task.Replace($"<t:Value>{GlobalId}</t:Value>",
                $"<t:Value>{TaskAttachmentGlobalId}</t:Value>", StringComparison.Ordinal);
        return EnvelopeInResponseMessage("GetAttachment", $"<m:Attachments><t:ItemAttachment><t:AttachmentId Id='task-attachment-1'/>{inline}<t:Item>{task}</t:Item></t:ItemAttachment></m:Attachments>");
    }

    private string TaskResponse(string id, string changeKey, bool includeAssignment, int state, int ownership,
        int? version = null, string? assigneeAddress = null)
    {
        var markup = TaskMarkup(id, changeKey, includeAssignment, state, ownership,
            version: version, attachmentId: LocalTaskAttachmentId ?? TaskAttachmentId,
            assigneeAddress: assigneeAddress, localTask: true);
        if (!string.Equals(TaskGlobalId, GlobalId, StringComparison.Ordinal))
            markup = markup.Replace($"<t:Value>{GlobalId}</t:Value>",
                $"<t:Value>{TaskGlobalId}</t:Value>", StringComparison.Ordinal);
        return Envelope("GetItem", $"<m:Items>{markup}</m:Items>");
    }

    private string TaskMessagesResponse(bool duplicate)
    {
        var first = TaskRequestMessage("request-1", "request-change", GlobalId, TaskNoticeItemClass, TaskVersion);
        var second = duplicate ? TaskRequestMessage("request-1", "request-change-2", GlobalId, TaskNoticeItemClass, TaskVersion) : string.Empty;
        return Envelope("FindItem", $"<m:RootFolder IncludesLastItemInRange='true'><t:Items>{first}{second}</t:Items></m:RootFolder>");
    }

    private string LocalTaskResponse()
    {
        var markup = TaskMarkup("local-task-1", "local-change", includeAssignment: true,
            state: NativeReassignmentWatcherLocal ? 3 : 2, ownership: 1, version: LocalTaskVersion,
            attachmentId: LocalTaskAttachmentId ?? TaskAttachmentId,
            assigneeAddress: NativeReassignmentWatcherLocal && !OmitLocalTaskPrivateRoles
                ? "own@example.test" : null,
            localTask: true);
        if (!OmitLocalTaskAttachmentMetadata)
            return Envelope("FindItem",
                $"<m:RootFolder IncludesLastItemInRange='true'><t:Items>{markup}</t:Items></m:RootFolder>");
        var task = ParseTaskMarkup(markup);
        SetTaskGlobalId(task, LocalTaskGlobalId);
        task.Element(T + "Attachments")?.Remove();
        task.Element(T + "Body")?.SetValue("truncated");
        task.Add(new XElement(T + "HasAttachments", "true"));
        return Envelope("FindItem",
            $"<m:RootFolder IncludesLastItemInRange='true'><t:Items>{task}</t:Items></m:RootFolder>");
    }

    private static void SetTaskGlobalId(XElement task, string value)
    {
        var property = task.Elements(T + "ExtendedProperty").Single(element =>
        {
            var field = element.Element(T + "ExtendedFieldURI");
            return (string?)field?.Attribute("PropertyId") == "0x8519";
        });
        property.Element(T + "Value")!.Value = value;
    }

    private static XElement ParseTaskMarkup(string markup) =>
        XDocument.Parse($"<root xmlns:t='{T.NamespaceName}'>{markup}</root>")
            .Root!.Element(T + "Task")!;

    private static string TaskRequestMessage(string id, string changeKey, string globalId,
        string itemClass = "IPM.TaskRequest", int version = 2)
    {
        var mode = itemClass switch
        {
            "IPM.TaskRequest.Accept" => 2,
            "IPM.TaskRequest.Decline" => 3,
            "IPM.TaskRequest.Update" => 4,
            _ => 1
        };
        return $"<t:Message><t:ItemId Id='{id}' ChangeKey='{changeKey}'/><t:ItemClass>{itemClass}</t:ItemClass><t:Subject>Task Request: Verify</t:Subject><t:From><t:Mailbox><t:EmailAddress>bob@example.test</t:EmailAddress></t:Mailbox></t:From><t:Sender><t:Mailbox><t:EmailAddress>bob@example.test</t:EmailAddress></t:Mailbox></t:Sender><t:InternetMessageHeaders><t:InternetMessageHeader HeaderName='X-MS-Exchange-Organization-AuthAs'>Internal</t:InternetMessageHeader></t:InternetMessageHeaders><t:ToRecipients><t:Mailbox><t:EmailAddress>alice@example.test</t:EmailAddress></t:Mailbox></t:ToRecipients><t:IsRead>false</t:IsRead><t:ExtendedProperty><t:ExtendedFieldURI PropertySetId='00062008-0000-0000-C000-000000000046' PropertyId='0x8519' PropertyType='Binary'/><t:Value>{globalId}</t:Value></t:ExtendedProperty><t:ExtendedProperty><t:ExtendedFieldURI PropertySetId='00062008-0000-0000-C000-000000000046' PropertyId='0x8518' PropertyType='Integer'/><t:Value>{mode}</t:Value></t:ExtendedProperty><t:ExtendedProperty><t:ExtendedFieldURI PropertySetId='00062003-0000-0000-C000-000000000046' PropertyId='0x8112' PropertyType='Integer'/><t:Value>{version}</t:Value></t:ExtendedProperty></t:Message>";
    }

    private static string? FindItemFolderId(string body) => XDocument.Parse(body)
        .Descendants(T + "DistinguishedFolderId").SingleOrDefault()?.Attribute("Id")?.Value;

    private string AcceptedFlagMarkup(int state, int ownership) =>
        OmitAcceptedFlag
            ? string.Empty
            : $"<t:ExtendedProperty><t:ExtendedFieldURI PropertySetId='00062003-0000-0000-C000-000000000046' PropertyId='0x8108' PropertyType='Boolean'/><t:Value>{(AcceptedFlagOverride ?? (state == 2 && ownership == 2) ? "true" : "false")}</t:Value></t:ExtendedProperty>";

    private string EmbeddedTaskVersionMarkup(int? version) =>
        OmitEmbeddedTaskVersion
            ? string.Empty
            : $"<t:ExtendedProperty><t:ExtendedFieldURI PropertySetId='00062003-0000-0000-C000-000000000046' PropertyId='0x8112' PropertyType='Integer'/><t:Value>{version ?? TaskVersion}</t:Value></t:ExtendedProperty>";

    private string TaskMarkup(string id, string changeKey, bool includeAssignment, int state, int ownership,
        int? version = null, int acceptance = 0, string? assignerStack = null, string? assigneeAddress = null,
        string? attachmentId = null, bool nativeDecline = false, bool nativeUpdate = false,
        bool nativeInitialRequest = false, bool nativeReassignmentRequest = false, bool nativeReassignmentUpdate = false,
        bool localTask = false)
    {
        var percent = nativeUpdate ? NativeTaskPercentComplete : 25;
        var status = nativeUpdate ? NativeTaskStatus : "InProgress";
        var isComplete = nativeUpdate ? NativeTaskIsComplete : false;
        var completeDate = nativeUpdate && NativeTaskCompleteDateUtc is { } value
            ? $"<t:CompleteDate>{value.ToUniversalTime():yyyy-MM-ddTHH:mm:ss.fffZ}</t:CompleteDate>"
            : string.Empty;
        var history = nativeDecline ? 2 : nativeUpdate || nativeReassignmentUpdate ? 3 : 5;
        var mode = nativeDecline ? 3 : nativeInitialRequest || nativeReassignmentRequest ? 1 : 0;
        var privateAssigneeAddress = (localTask ? NativeLocalTaskAssigneeAddress : NativeResponseTaskAssigneeAddress)
            ?? NativeTaskAssigneeAddress ?? assigneeAddress;
        var privateOwnerAddress = (localTask ? NativeLocalTaskOwnerAddress : NativeResponseTaskOwnerAddress)
            ?? NativeTaskOwnerAddress;
        var privateAssignerAddress = (localTask ? NativeLocalTaskAssignerAddress : NativeResponseTaskAssignerAddress);
        var privateRoleMarkup = string.Concat(
            privateAssigneeAddress is null ? string.Empty
                : $"<t:ExtendedProperty><t:ExtendedFieldURI PropertySetId='{McpTaskPropertySet}' PropertyName='Company.Exchange.Mcp.TaskAssigneeAddress' PropertyType='String'/><t:Value>{privateAssigneeAddress}</t:Value></t:ExtendedProperty>",
            privateOwnerAddress is null ? string.Empty
                : $"<t:ExtendedProperty><t:ExtendedFieldURI PropertySetId='{McpTaskPropertySet}' PropertyName='Company.Exchange.Mcp.TaskOwnerAddress' PropertyType='String'/><t:Value>{privateOwnerAddress}</t:Value></t:ExtendedProperty>",
            privateAssignerAddress is null ? string.Empty
                : $"<t:ExtendedProperty><t:ExtendedFieldURI PropertySetId='{McpTaskPropertySet}' PropertyName='Company.Exchange.Mcp.TaskAssignerAddress' PropertyType='String'/><t:Value>{privateAssignerAddress}</t:Value></t:ExtendedProperty>");
        var assignerChainMarkup = NativeResponseAssignerChainOverride is null
            ? string.Empty
            : $"<t:ExtendedProperty><t:ExtendedFieldURI PropertySetId='{McpTaskPropertySet}' PropertyName='Company.Exchange.Mcp.TaskAssignerAddresses' PropertyType='String'/><t:Value>{System.Security.SecurityElement.Escape(NativeResponseAssignerChainOverride)}</t:Value></t:ExtendedProperty>";
        var acceptanceWire = localTask && NativeLocalAcceptanceWireOverride is not null
            ? NativeLocalAcceptanceWireOverride
            : AcceptanceWireOverride ?? acceptance.ToString(CultureInfo.InvariantCulture);
        var omitStack = OmitAssignerStack
            && (localTask || NativeResponseAssignerStackOverride is null);
        var stackValue = omitStack
            ? string.Empty : assignerStack ?? AssignerStack;
        var assignmentMarkup = includeAssignment
            ? $"<t:ExtendedProperty><t:ExtendedFieldURI PropertySetId='00062008-0000-0000-C000-000000000046' PropertyId='0x8519' PropertyType='Binary'/><t:Value>{GlobalId}</t:Value></t:ExtendedProperty><t:ExtendedProperty><t:ExtendedFieldURI PropertySetId='00062008-0000-0000-C000-000000000046' PropertyId='0x8518' PropertyType='Integer'/><t:Value>{mode}</t:Value></t:ExtendedProperty><t:ExtendedProperty><t:ExtendedFieldURI PropertySetId='00062003-0000-0000-C000-000000000046' PropertyId='0x8129' PropertyType='Integer'/><t:Value>{ownership}</t:Value></t:ExtendedProperty><t:ExtendedProperty><t:ExtendedFieldURI PropertySetId='00062003-0000-0000-C000-000000000046' PropertyId='0x812A' PropertyType='Integer'/><t:Value>{acceptanceWire}</t:Value></t:ExtendedProperty>{AcceptedFlagMarkup(state, ownership)}<t:ExtendedProperty><t:ExtendedFieldURI PropertySetId='00062003-0000-0000-C000-000000000046' PropertyId='0x8113' PropertyType='Integer'/><t:Value>{state}</t:Value></t:ExtendedProperty>{EmbeddedTaskVersionMarkup(version)}<t:ExtendedProperty><t:ExtendedFieldURI PropertySetId='00062003-0000-0000-C000-000000000046' PropertyId='0x811A' PropertyType='Integer'/><t:Value>{history}</t:Value></t:ExtendedProperty><t:ExtendedProperty><t:ExtendedFieldURI PropertySetId='00062003-0000-0000-C000-000000000046' PropertyId='0x8121' PropertyType='String'/><t:Value>{NativeTaskAssignerName}</t:Value></t:ExtendedProperty><t:ExtendedProperty><t:ExtendedFieldURI PropertySetId='00062003-0000-0000-C000-000000000046' PropertyId='0x811F' PropertyType='String'/><t:Value>{NativeTaskOwnerName}</t:Value></t:ExtendedProperty><t:ExtendedProperty><t:ExtendedFieldURI PropertySetId='00062003-0000-0000-C000-000000000046' PropertyId='0x8122' PropertyType='String'/><t:Value>{NativeTaskLastUserName}</t:Value></t:ExtendedProperty><t:ExtendedProperty><t:ExtendedFieldURI PropertySetId='00062003-0000-0000-C000-000000000046' PropertyId='0x8125' PropertyType='String'/><t:Value>{NativeTaskLastDelegateName}</t:Value></t:ExtendedProperty><t:ExtendedProperty><t:ExtendedFieldURI PropertySetId='00062003-0000-0000-C000-000000000046' PropertyId='0x8115' PropertyType='SystemTime'/><t:Value>2026-10-12T10:00:00Z</t:Value></t:ExtendedProperty><t:ExtendedProperty><t:ExtendedFieldURI PropertySetId='00062003-0000-0000-C000-000000000046' PropertyId='0x8117' PropertyType='Binary'/><t:Value>{stackValue}</t:Value></t:ExtendedProperty><t:ExtendedProperty><t:ExtendedFieldURI PropertySetId='00062003-0000-0000-C000-000000000046' PropertyId='0x811B' PropertyType='Boolean'/><t:Value>true</t:Value></t:ExtendedProperty><t:ExtendedProperty><t:ExtendedFieldURI PropertySetId='00062003-0000-0000-C000-000000000046' PropertyId='0x8119' PropertyType='Boolean'/><t:Value>true</t:Value></t:ExtendedProperty>{privateRoleMarkup}{assignerChainMarkup}"
            : string.Empty;
        return $"<t:Task><t:ItemId Id='{id}' ChangeKey='{changeKey}'/><t:ItemClass>IPM.Task</t:ItemClass><t:Subject>Verify assignment</t:Subject>{(TaskBody is null ? "" : $"<t:Body BodyType='{TaskBodyType}'>{System.Security.SecurityElement.Escape(TaskBody).Replace("\r", "&#xD;", StringComparison.Ordinal)}</t:Body>")}<t:PercentComplete>{percent.ToString(CultureInfo.InvariantCulture)}</t:PercentComplete><t:Status>{status}</t:Status><t:IsComplete>{(isComplete ? "true" : "false")}</t:IsComplete>{completeDate}<t:IsRecurring>false</t:IsRecurring><t:Importance>Normal</t:Importance><t:ReminderIsSet>false</t:ReminderIsSet>{TaskAttachmentMarkup(attachmentId)}{assignmentMarkup}</t:Task>";
    }
    private string TaskAttachmentMarkup(string? attachmentId = null) => IncludeTaskFileAttachment
        ? $"<t:Attachments><t:FileAttachment><t:AttachmentId Id='{attachmentId ?? TaskAttachmentId}'/><t:Name>{TaskAttachmentName}</t:Name><t:Size>{TaskAttachmentSize}</t:Size><t:ContentType>{TaskAttachmentContentType}</t:ContentType><t:IsInline>true</t:IsInline><t:ContentId>{TaskAttachmentContentId}</t:ContentId></t:FileAttachment></t:Attachments>"
        : IncludeEmbeddedTaskAttachment
            ? "<t:Attachments><t:ItemAttachment><t:AttachmentId Id='embedded-attachment-1'/><t:Name>embedded.msg</t:Name><t:Size>1</t:Size></t:ItemAttachment></t:Attachments>"
            : string.Empty;

    private string TaskFileContentResponse(string attachmentId)
    {
        var contentBytes = TamperTaskAttachment
            ? Encoding.UTF8.GetBytes("XYZ")
            : TaskAttachmentContentSize == 3
                ? Encoding.UTF8.GetBytes("abc")
                : Enumerable.Repeat((byte)'a', TaskAttachmentContentSize).ToArray();
        var content = Convert.ToBase64String(contentBytes);
        return EnvelopeInResponseMessage("GetAttachment",
            $"<m:Attachments><t:FileAttachment><t:AttachmentId Id='{attachmentId}'/><t:Name>{TaskAttachmentName}</t:Name><t:Size>{TaskAttachmentSize}</t:Size><t:ContentType>{TaskAttachmentContentType}</t:ContentType><t:IsInline>true</t:IsInline><t:ContentId>{TaskAttachmentContentId}</t:ContentId><t:Content>{content}</t:Content></t:FileAttachment></m:Attachments>");
    }

    private static string ReadRequestedAttachmentId(string body) =>
        XDocument.Parse(body).Descendants(T + "AttachmentId").Single().Attribute("Id")?.Value
        ?? throw new InvalidOperationException("The fixture attachment request has no identifier.");

    private static string ItemReferenceResponse(string operation, string id, string changeKey) => Envelope(operation, $"<m:Items><t:Message><t:ItemId Id='{id}' ChangeKey='{changeKey}'/></t:Message></m:Items>");

    private static string TaskReferenceResponse(string operation, string id, string changeKey) => Envelope(operation,
        $"<m:Items><t:Task><t:ItemId Id='{id}' ChangeKey='{changeKey}'/></t:Task></m:Items>");

    private static string TaskProcessedResponse() => EnvelopeInResponseMessage("UpdateItem",
        "<m:Items><t:Task><t:ItemId Id='local-task-1' ChangeKey='local-change'/></t:Task></m:Items>");

    private static string EmptyItemsResponse(string operation) => Envelope(operation, string.Empty);

    private static string Envelope(string operation, string result) =>
        $"<s:Envelope xmlns:s='{Soap.NamespaceName}' xmlns:m='{M.NamespaceName}' xmlns:t='{T.NamespaceName}'><s:Body><m:{operation}Response><m:ResponseMessages><m:{operation}ResponseMessage ResponseClass='Success'><m:ResponseCode>NoError</m:ResponseCode></m:{operation}ResponseMessage></m:ResponseMessages>{result}</m:{operation}Response></s:Body></s:Envelope>";

    private static string EnvelopeInResponseMessage(string operation, string result) =>
        $"<s:Envelope xmlns:s='{Soap.NamespaceName}' xmlns:m='{M.NamespaceName}' xmlns:t='{T.NamespaceName}'><s:Body><m:{operation}Response><m:ResponseMessages><m:{operation}ResponseMessage ResponseClass='Success'><m:ResponseCode>NoError</m:ResponseCode>{result}</m:{operation}ResponseMessage></m:ResponseMessages></m:{operation}Response></s:Body></s:Envelope>";
}
