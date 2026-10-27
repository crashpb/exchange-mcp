using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Xml;
using System.Xml.Linq;

namespace Company.ExchangeMcp.Exchange;

public sealed partial class EwsClient
{
    // These are the documented Outlook task named properties.  The MCP never
    // persists or exposes an Exchange-mapped property number in their place.
    private const string TaskPropertySet = "00062003-0000-0000-C000-000000000046";
    private const string CommonPropertySet = "00062008-0000-0000-C000-000000000046";
    private const string McpTaskPropertySet = "D6D5DCE4-8E0E-4EA5-9C4C-A7C2AD20A9A8";
    private const string AssignerAddressesPropertyName = "Company.Exchange.Mcp.TaskAssignerAddresses";
    private const string AssignerAddressPropertyName = "Company.Exchange.Mcp.TaskAssignerAddress";
    private const string AssigneeAddressPropertyName = "Company.Exchange.Mcp.TaskAssigneeAddress";
    private const string OwnerAddressPropertyName = "Company.Exchange.Mcp.TaskOwnerAddress";
    private const int TaskAssignmentMaxPayload = 512 * 1024;
    private const int MaxAssignerAddresses = 8;

    private static XElement[] TaskAssignmentFields() =>
    [
        NamedField(CommonPropertySet, "0x8519", "Binary"), // PidLidTaskGlobalId
        NamedField(CommonPropertySet, "0x8518", "Integer"), // PidLidTaskMode
        NamedField(TaskPropertySet, "0x8129", "Integer"), // PidLidTaskOwnership
        NamedField(TaskPropertySet, "0x812A", "Integer"), // PidLidTaskAcceptanceState
        NamedField(TaskPropertySet, "0x8108", "Boolean"), // PidLidTaskAccepted
        NamedField(TaskPropertySet, "0x8113", "Integer"), // PidLidTaskState
        NamedField(TaskPropertySet, "0x8112", "Integer"), // PidLidTaskVersion
        NamedField(TaskPropertySet, "0x811A", "Integer"), // PidLidTaskHistory
        NamedField(TaskPropertySet, "0x8121", "String"), // PidLidTaskAssigner
        NamedField(TaskPropertySet, "0x811F", "String"), // PidLidTaskOwner
        NamedField(TaskPropertySet, "0x8122", "String"), // PidLidTaskLastUser
        NamedField(TaskPropertySet, "0x8125", "String"), // PidLidTaskLastDelegate
        NamedField(TaskPropertySet, "0x8115", "SystemTime"), // PidLidTaskLastUpdate
        NamedField(TaskPropertySet, "0x8117", "Binary"), // PidLidTaskAssigners
        NamedField(TaskPropertySet, "0x811B", "Boolean"), // PidLidTaskUpdates
        NamedField(TaskPropertySet, "0x8119", "Boolean"), // PidLidTaskStatusOnComplete
        NamedNameField(McpTaskPropertySet, AssignerAddressesPropertyName, "String"),
        NamedNameField(McpTaskPropertySet, AssignerAddressPropertyName, "String"),
        NamedNameField(McpTaskPropertySet, AssigneeAddressPropertyName, "String"),
        NamedNameField(McpTaskPropertySet, OwnerAddressPropertyName, "String")
    ];

    public async Task<EwsTaskAction> PrepareTaskAssignmentAsync(
        string mailbox,
        string taskId,
        string assignee,
        bool keepUpdated,
        bool completionReport,
        bool reassign,
        CancellationToken cancellationToken,
        DateTimeOffset? actionTimeUtc = null,
        TaskAssignerEntry? assignerEntry = null)
    {
        var planTime = ResolveActionTime(actionTimeUtc);
        var normalizedMailbox = ValidateMailbox(mailbox);
        var normalizedTaskId = ValidateItemId(taskId, "task");
        var normalizedAssignee = NormalizeAddress(assignee);
        var task = await GetTaskAsync(normalizedMailbox, normalizedTaskId, cancellationToken).ConfigureAwait(false);
        task = await HydrateTaskAttachmentsAsync(normalizedMailbox, task, cancellationToken).ConfigureAwait(false);
        ValidateAssignableTask(task);
        var existing = task.Assignment;
        if (reassign)
        {
            if (existing is null || existing.State is not 2 || existing.Ownership is not 2
                || existing.AcceptanceState is not (0 or 2)
                || !IsAddress(existing.OwnerAddress ?? existing.OwnerName, normalizedMailbox)
                    && !IsAddress(existing.AssigneeAddress ?? existing.OwnerName, normalizedMailbox))
                throw new InvalidOperationException("Reassignment requires the selected mailbox to own an accepted native task copy.");
            if (IsAddress(normalizedAssignee, normalizedMailbox)
                || existing.AssignerChainAddresses?.Any(value => IsAddress(value, normalizedAssignee)) == true)
                throw new InvalidOperationException("The reassignment target would create a native task delegation cycle.");
            if (assignerEntry is null)
            {
                if (_taskDirectory is null)
                    throw new InvalidOperationException("The task assigner directory is unavailable; native reassignment cannot build a verified assigner stack.");
                assignerEntry = await _taskDirectory.ResolveTaskAssignerAsync(normalizedMailbox, cancellationToken)
                    .ConfigureAwait(false);
            }
        }
        else if (HasAssignedRole(existing)
            && !(existing?.State is 4 && existing.Ownership is 2
                && (IsAddress(existing.OwnerAddress ?? existing.OwnerName, normalizedMailbox)
                    || IsAddress(existing.AssigneeAddress ?? existing.OwnerName, normalizedMailbox))))
        {
            throw new InvalidOperationException(
                "This task is already assigned; use the native task reassignment workflow.");
        }
        if (IsAddress(normalizedAssignee, normalizedMailbox))
        {
            throw new InvalidOperationException("A task cannot be assigned to its current mailbox.");
        }
        task = EnsureTaskGlobalId(task, normalizedMailbox);
        var currentAssignment = task.Assignment!;
        var assignerStack = currentAssignment.AssignerStackBase64;
        // The initial request preserves the task's existing stack.  Outlook
        // appends the sender when the recipient accepts; a reassignment
        // appends the current owner before the next recipient receives it.
        if (assignerEntry is not null && reassign)
            // A prepared/replayed reassignment may already contain the
            // current owner as its final stack entry.  Preserve that verified
            // entry; append only when the current owner is genuinely new.
            assignerStack = AppendAssignerStackIfNeeded(assignerStack, assignerEntry);
        task = task with
        {
            Assignment = currentAssignment with
            {
                AssignerAddress = normalizedMailbox,
                AssigneeAddress = normalizedAssignee,
                OwnerAddress = normalizedAssignee,
                // PidLidTaskVersion is incremented when the native request is
                // emitted.  This makes a version-1 source copy produce the
                // Outlook-compatible initial request at version 2 and keeps
                // reassignment on the same monotonic path.
                Version = Math.Max(1, currentAssignment.Version ?? 1) + 1,
                State = 3,
                Ownership = 1,
                AcceptanceState = 1,
                LastUpdateUtc = planTime,
                LastUserName = normalizedMailbox,
                LastDelegateName = normalizedMailbox,
                Accepted = false,
                AssignerStackBase64 = assignerStack,
                UpdatesEnabled = keepUpdated,
                CompletionReportEnabled = completionReport
            }
        };
        var payload = BuildTaskSendOperation(
            task,
            normalizedAssignee,
            normalizedMailbox,
            "IPM.TaskRequest",
            keepUpdated,
            completionReport);
        return CreateTaskAction(
            reassign ? "reassign" : "assign", normalizedMailbox, task, normalizedAssignee,
            task.Id, payload, reassign, sourceChangeKey: task.ChangeKey, actionTimeUtc: planTime);
    }

    public async Task<EwsTaskAction> PrepareTaskResponseAsync(
        string mailbox,
        string requestId,
        bool responseAccept,
        CancellationToken cancellationToken,
        DateTimeOffset? actionTimeUtc = null,
        TaskAssignerEntry? trustedAssignerEntry = null)
    {
        var planTime = ResolveActionTime(actionTimeUtc);
        var normalizedMailbox = ValidateMailbox(mailbox);
        var request = await ReadTaskAssignmentMessageAsync(normalizedMailbox, requestId, cancellationToken)
            .ConfigureAwait(false);
        if (IsNativeOutlookReassignmentRequest(request)
            || IsNativeOutlookInitialRequest(request))
            request = await HydrateNativeReassignmentRequestAsync(normalizedMailbox, request, cancellationToken)
                .ConfigureAwait(false);
        if (request.ItemClass != "IPM.TaskRequest")
            throw new InvalidOperationException("Only an assignment request can be accepted or declined; process responses and progress reports instead.");
        ValidateTaskRequest(request, normalizedMailbox);
        var task = request.Task ?? throw new InvalidOperationException("The task request has no embedded task.");
        var assigner = request.Sender;
        if (string.IsNullOrWhiteSpace(assigner))
            throw new InvalidOperationException("The task request has no assigner address.");
        var assignerStack = task.Assignment?.AssignerStackBase64;
        var chainAddresses = task.Assignment?.AssignerChainAddresses is { Count: > 0 } existingChain
            ? existingChain
            : request.CcRecipients ?? Array.Empty<string>();
        if (responseAccept && chainAddresses.Count == 0 && !string.IsNullOrWhiteSpace(assignerStack))
            chainAddresses = await ResolveNativeAssignerStackAddressesAsync(
                normalizedMailbox, assignerStack, null, cancellationToken).ConfigureAwait(false);
        if (responseAccept)
        {
            var resolvedEntry = trustedAssignerEntry;
            if (resolvedEntry is null)
            {
                if (_taskDirectory is null)
                    throw new InvalidOperationException("The task assigner directory is unavailable; native acceptance cannot build a verified assigner stack.");
                resolvedEntry = await _taskDirectory.ResolveTaskAssignerAsync(assigner, cancellationToken)
                    .ConfigureAwait(false);
            }
            assignerStack = AppendAssignerStackIfNeeded(assignerStack, resolvedEntry);
            chainAddresses = AppendAssignerAddress(chainAddresses, assigner);
        }
        task = task with
        {
            Assignment = (task.Assignment ?? new EwsTaskAssignmentInfo(
                request.Id, request.ChangeKey, request.GlobalTaskId, NormalizeAddress(assigner),
                normalizedMailbox, null, task.Status, (int)Math.Round(task.PercentComplete), false,
                request.IsReassignment)) with
            {
                RequestId = request.Id,
                RequestChangeKey = request.ChangeKey,
                Version = Math.Max(1, task.Assignment?.Version ?? 1) + 1,
                AcceptanceState = responseAccept ? 2 : 3,
                State = responseAccept ? 2 : 4,
                Ownership = 2,
                LastUpdateUtc = planTime,
                LastUserName = normalizedMailbox,
                LastDelegateName = normalizedMailbox,
                // PidLidTaskAccepted indicates that the response was handled;
                // the decline result is carried by acceptance state 3.
                Accepted = true,
                AssignerStackBase64 = assignerStack,
                AssignerChainAddresses = chainAddresses
            }
        };
        var payload = BuildTaskSendOperation(
            task,
            NormalizeAddress(assigner),
            normalizedMailbox,
            responseAccept ? "IPM.TaskRequest.Accept" : "IPM.TaskRequest.Decline",
            keepUpdated: task.Assignment?.UpdatesEnabled ?? false,
            completionReport: task.Assignment?.CompletionReportEnabled ?? false);
        return CreateTaskAction(
            responseAccept ? "respond_accept" : "respond_decline", normalizedMailbox, task,
            NormalizeAddress(assigner), request.Id, payload, isReassignment: false,
            sourceChangeKey: request.ChangeKey, actionTimeUtc: planTime);
    }

    public async Task<EwsTaskAction> PrepareTaskProgressAsync(
        string mailbox,
        string taskId,
        double percentComplete,
        string status,
        CancellationToken cancellationToken,
        DateTimeOffset? actionTimeUtc = null)
    {
        var planTime = ResolveActionTime(actionTimeUtc);
        var normalizedMailbox = ValidateMailbox(mailbox);
        var task = await GetTaskAsync(normalizedMailbox, ValidateItemId(taskId, "task"), cancellationToken)
            .ConfigureAwait(false);
        task = await HydrateTaskAttachmentsAsync(normalizedMailbox, task, cancellationToken).ConfigureAwait(false);
        ValidateAssignableTask(task);
        var existingAssignment = task.Assignment
            ?? throw new InvalidOperationException("Only an accepted native task can send assignment progress.");
        if (existingAssignment.State is not 2 || existingAssignment.Ownership is not 2
            || existingAssignment.AcceptanceState is not (0 or 2)
            || !IsAddress(existingAssignment.OwnerAddress ?? existingAssignment.OwnerName, normalizedMailbox)
                && !IsAddress(existingAssignment.AssigneeAddress ?? existingAssignment.OwnerName, normalizedMailbox))
            throw new InvalidOperationException("The selected task is not the assignee's accepted native copy.");
        ValidateTaskProgress(percentComplete, status);
        var assigner = task.Assignment?.AssignerAddress;
        if (string.IsNullOrWhiteSpace(assigner) && task.Assignment?.GlobalTaskId is { Length: > 0 } globalTaskId)
            assigner = await FindTaskAssignerAsync(normalizedMailbox, globalTaskId, cancellationToken).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(assigner))
            throw new InvalidOperationException("The task has no verified assigner; progress cannot be reported safely.");
        var updated = task with
        {
            PercentComplete = percentComplete,
            Status = status,
            IsComplete = string.Equals(status, "Completed", StringComparison.Ordinal)
                || percentComplete >= 100d,
            CompleteDateUtc = string.Equals(status, "Completed", StringComparison.Ordinal)
                ? task.CompleteDateUtc ?? planTime
                : task.CompleteDateUtc
        };
        updated = updated with
        {
            Assignment = updated.Assignment! with
            {
                Version = Math.Max(1, updated.Assignment!.Version ?? 1) + 1,
                Ownership = 2,
                AcceptanceState = 0,
                State = 2,
                LastUpdateUtc = planTime,
                LastUserName = normalizedMailbox,
                LastDelegateName = normalizedMailbox,
                Accepted = true
            }
        };
        var payload = BuildTaskSendOperation(
            updated,
            NormalizeAddress(assigner),
            normalizedMailbox,
            "IPM.TaskRequest.Update",
            keepUpdated: task.Assignment?.UpdatesEnabled ?? true,
            completionReport: task.Assignment?.CompletionReportEnabled ?? updated.IsComplete);
        return CreateTaskAction(
            "progress", normalizedMailbox, task, NormalizeAddress(assigner), task.Id,
            payload, isReassignment: false, percentComplete, status, task.ChangeKey, updated, planTime);
    }

    public async Task<EwsTaskAction> PrepareTaskProcessAsync(
        string mailbox,
        string requestId,
        CancellationToken cancellationToken,
        DateTimeOffset? actionTimeUtc = null) =>
        await PrepareTaskProcessCoreAsync(mailbox, requestId, cancellationToken, actionTimeUtc, skipOrdinaryRequest: false)
            .ConfigureAwait(false)
            ?? throw new InvalidOperationException("The task notice is not eligible for automatic processing.");

    public Task<EwsTaskAction?> PrepareTaskProcessAsync(
        string mailbox,
        string requestId,
        CancellationToken cancellationToken,
        bool skipOrdinaryRequest,
        DateTimeOffset? actionTimeUtc = null) =>
        PrepareTaskProcessCoreAsync(mailbox, requestId, cancellationToken, actionTimeUtc, skipOrdinaryRequest);

    private async Task<EwsTaskAction?> PrepareTaskProcessCoreAsync(
        string mailbox,
        string requestId,
        CancellationToken cancellationToken,
        DateTimeOffset? actionTimeUtc,
        bool skipOrdinaryRequest)
    {
        var planTime = ResolveActionTime(actionTimeUtc);
        var normalizedMailbox = ValidateMailbox(mailbox);
        var request = await ReadTaskAssignmentMessageAsync(normalizedMailbox, requestId, cancellationToken)
            .ConfigureAwait(false);
        if (IsNativeOutlookReassignmentUpdate(request))
            request = await HydrateNativeReassignmentUpdateAsync(normalizedMailbox, request, cancellationToken)
                .ConfigureAwait(false);
        var watcherRequest = IsWatcherReassignmentRequest(request, normalizedMailbox);
        if (skipOrdinaryRequest
            && request.ItemClass.Equals("IPM.TaskRequest", StringComparison.OrdinalIgnoreCase)
            && !watcherRequest)
            return null;
        if (watcherRequest)
            ValidateWatcherReassignmentRequest(request, normalizedMailbox);
        else
            ValidateTaskRequest(request, normalizedMailbox);
        var task = request.Task ?? throw new InvalidOperationException("The task request has no embedded task.");
        ValidateAssignableTask(task);
        if (request.ItemClass.Equals("IPM.TaskRequest", StringComparison.OrdinalIgnoreCase) && !watcherRequest)
            throw new InvalidOperationException("A task request must be accepted or declined before it can be processed.");
        var globalTaskId = task.Assignment?.GlobalTaskId
            ?? throw new InvalidOperationException("The native task request is missing PidLidTaskGlobalId.");
        var local = await FindTaskByGlobalIdAsync(normalizedMailbox, globalTaskId, cancellationToken)
            .ConfigureAwait(false)
            ?? throw new InvalidOperationException("No matching local task exists for this native task response.");
        var hydratedLocal = await HydrateTaskAttachmentsAsync(normalizedMailbox, local.Task, cancellationToken)
            .ConfigureAwait(false);
        hydratedLocal = await HydrateNativeReassignmentTrackerAsync(
            normalizedMailbox, hydratedLocal, request, task, cancellationToken).ConfigureAwait(false);
        ValidateIncomingTaskProcess(hydratedLocal, request, task, normalizedMailbox, watcherRequest);
        var preview = BuildTaskProcessPreview(hydratedLocal, request, task, normalizedMailbox, watcherRequest, planTime);
        var payload = BuildTaskProcessUpdateOperation(hydratedLocal, preview, request.ItemClass, planTime);
        var actionAssignee = IsNativeOutlookReassignmentUpdate(request)
            ? preview.Assignment?.AssigneeAddress ?? request.Sender
            : request.Sender;
        return CreateTaskAction(
            "process", normalizedMailbox, hydratedLocal, request.Sender, request.Id,
            payload, isReassignment: false, sourceChangeKey: request.ChangeKey,
            assigneeOverride: actionAssignee,
            previewTask: preview, actionTimeUtc: planTime);
    }

    public async Task<EwsTaskActionResult> ExecuteTaskActionAsync(
        string mailbox,
        EwsTaskAction action,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(action);
        var normalizedMailbox = ValidateMailbox(mailbox);
        if (!string.Equals(normalizedMailbox, ValidateMailbox(action.Mailbox), StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("The task action is bound to a different mailbox.");
        ValidateTaskAction(action);
        var fresh = await ValidateFreshTaskActionAsync(action, cancellationToken).ConfigureAwait(false);
        var operation = ParseTaskActionPayload(action.PayloadXml!);
        EwsItemRef? localTaskReference = null;
        if (action.Operation == "process" && operation.Name == M + "CreateItem")
        {
            var globalTaskId = fresh?.Assignment?.GlobalTaskId ?? action.TaskGlobalId
                ?? throw new InvalidOperationException("The native task request is missing PidLidTaskGlobalId.");
            await EnsureNoDuplicateTaskGlobalIdAsync(normalizedMailbox, globalTaskId, cancellationToken)
                .ConfigureAwait(false);
        }
        if (action.Operation is "assign" or "reassign" or "progress")
            localTaskReference = await ApplySourceTaskUpdateAsync(normalizedMailbox, fresh!, action, operation, cancellationToken)
                .ConfigureAwait(false);
        else if (action.Operation == "respond_accept")
        {
            var acceptedTask = action.PreviewTask ?? fresh
                ?? throw new InvalidOperationException("The task response has no embedded task.");
            var globalTaskId = acceptedTask.Assignment?.GlobalTaskId
                ?? throw new InvalidOperationException("The native task response is missing PidLidTaskGlobalId.");
            await EnsureNoDuplicateTaskGlobalIdAsync(normalizedMailbox, globalTaskId, cancellationToken)
                .ConfigureAwait(false);
            var createLocal = new XElement(
                M + "CreateItem", new XElement(M + "SavedItemFolderId", PeopleTasksFolderReference("tasks")),
                new XElement(M + "Items", BuildLocallyAcceptedTask(acceptedTask)));
            var localDocument = await SendAsync(normalizedMailbox, createLocal, cancellationToken).ConfigureAwait(false);
            localTaskReference = ParseItemReference(RequiredReturnedItem(localDocument));
        }
        var document = await SendAsync(normalizedMailbox, operation, cancellationToken).ConfigureAwait(false);
        var sent = action.Operation is "assign" or "reassign" or "respond_accept" or "respond_decline" or "progress";
        if (action.Operation == "process")
            localTaskReference = ParseProcessedTaskReference(document);
        if (action.Operation is "process" or "respond_accept" or "respond_decline")
            await MarkTaskCommunicationProcessedAsync(normalizedMailbox, action.SourceId,
                action.SourceChangeKey, cancellationToken).ConfigureAwait(false);
        var resultReference = localTaskReference;
        return new EwsTaskActionResult(action.Operation, action.SourceId, resultReference?.Id, resultReference?.ChangeKey,
            sent, action.Operation == "respond_decline" ? sent : resultReference is not null,
            "completed", sent ? "Exchange accepted the native task action." : "Task was added to the selected Tasks folder.");
    }

    private static EwsItemRef ParseProcessedTaskReference(XDocument document)
    {
        // An UpdateItem response for the process operation must be bound to
        // the response message and its returned Task.  Searching every
        // descendant ItemId can accidentally select the request or an
        // unrelated item, and SendAndSaveCopy responses are allowed to have
        // no Items element at all.
        var responseMessages = document.Descendants(M + "UpdateItemResponseMessage").ToArray();
        if (responseMessages.Length != 1)
            throw new InvalidOperationException("Exchange returned an ambiguous processed-task response.");
        var items = responseMessages[0].Element(M + "Items")?.Elements(T + "Task").ToArray()
            ?? Array.Empty<XElement>();
        if (items.Length != 1)
            throw new InvalidOperationException("Exchange did not return exactly one processed task.");
        return ParseItemReference(items[0]);
    }

    public async Task<EwsTaskAssignmentMessage> ReadTaskAssignmentMessageAsync(
        string mailbox,
        string requestId,
        CancellationToken cancellationToken)
    {
        var normalizedMailbox = ValidateMailbox(mailbox);
        var normalizedRequestId = ValidateItemId(requestId, "task request");
        var operation = new XElement(
            M + "GetItem",
            AssignmentMessageShape(),
            new XElement(M + "ItemIds", ItemReference(normalizedRequestId)));
        var document = await SendAsync(normalizedMailbox, operation, cancellationToken).ConfigureAwait(false);
        var responseMessages = document.Descendants(M + "GetItemResponseMessage").ToArray();
        if (responseMessages.Length > 1)
            throw new InvalidOperationException("Exchange returned an ambiguous task request response.");
        var response = responseMessages.Length == 1
            && responseMessages[0].Element(M + "Items") is not null
            ? responseMessages[0]
            : document.Descendants(M + "GetItemResponse").ToArray() is [var responseRoot]
                ? responseRoot
                : throw new InvalidOperationException("Exchange returned an ambiguous task request response.");
        var messages = response.Element(M + "Items")?.Elements(T + "Message").ToArray()
            ?? Array.Empty<XElement>();
        if (messages.Length != 1)
            throw new InvalidOperationException("Exchange returned an ambiguous task request message shape.");
        var message = messages[0];
        var parsed = ParseTaskAssignmentMessage(message);
        var attachments = message.Element(T + "Attachments")?.Elements(T + "ItemAttachment").ToArray()
            ?? Array.Empty<XElement>();
        if (attachments.Length != 1)
            throw new InvalidOperationException("The task request has no native item attachment.");
        var attachment = attachments[0];
        var attachmentId = attachment.Element(T + "AttachmentId")?.Attribute("Id")?.Value;
        if (string.IsNullOrWhiteSpace(attachmentId))
            throw new InvalidOperationException("The task request attachment has no identifier.");
        var attachmentDocument = await SendAsync(normalizedMailbox, new XElement(
            M + "GetAttachment",
            new XElement(M + "AttachmentShape",
                new XElement(T + "BodyType", "Best"),
                new XElement(T + "AdditionalProperties",
                    TaskShape().Element(T + "AdditionalProperties")?.Elements()
                        .Select(element => new XElement(element)))),
            new XElement(M + "AttachmentIds", new XElement(T + "AttachmentId", new XAttribute("Id", attachmentId)))),
            cancellationToken).ConfigureAwait(false);
        var attachmentResponses = attachmentDocument.Descendants(M + "GetAttachmentResponseMessage").ToArray();
        if (attachmentResponses.Length > 1)
            throw new InvalidOperationException("Exchange returned an ambiguous task attachment response.");
        var attachmentResponse = attachmentResponses.Length == 1
            && attachmentResponses[0].Element(M + "Attachments") is not null
            ? attachmentResponses[0]
            : attachmentDocument.Descendants(M + "GetAttachmentResponse").ToArray() is [var attachmentRoot]
                ? attachmentRoot
                : throw new InvalidOperationException("Exchange returned an ambiguous task attachment response.");
        var nativeAttachments = attachmentResponse.Element(M + "Attachments")?
            .Elements(T + "ItemAttachment").ToArray() ?? Array.Empty<XElement>();
        if (nativeAttachments.Length != 1)
            throw new InvalidOperationException("Exchange returned an ambiguous task attachment shape.");
        var attachmentItem = nativeAttachments[0].Element(T + "Item");
        var directTasks = nativeAttachments[0].Elements(T + "Task").ToArray();
        var nestedTasks = attachmentItem?.Elements(T + "Task").ToArray() ?? Array.Empty<XElement>();
        var taskElements = directTasks.Length > 0 ? directTasks : nestedTasks;
        if (taskElements.Length != 1)
            throw new InvalidOperationException("The task request attachment does not contain exactly one native Task item.");
        var taskElement = taskElements[0];
        var nativeReassignmentRequest = IsNativeOutlookReassignmentRequest(parsed, taskElement);
        var nativeInitialRequest = IsNativeOutlookInitialRequest(parsed, taskElement);
        var nativeReassignmentUpdate = IsNativeOutlookReassignmentUpdate(parsed, taskElement);
        var nativeDecline = IsNativeOutlookDecline(parsed, taskElement);
        var nativeUpdate = IsNativeOutlookUpdate(parsed, taskElement);
        if (nativeDecline)
            NormalizeNativeDeclineAssignerStack(taskElement);
        var task = ParseDetachedTask(taskElement, parsed.Id, parsed.ChangeKey);
        task = await HydrateTaskAttachmentsAsync(normalizedMailbox, task, cancellationToken).ConfigureAwait(false);
        var nativeAccepted = parsed.ItemClass.Equals("IPM.TaskRequest.Accept", StringComparison.OrdinalIgnoreCase)
            && task.Assignment is { } acceptedAssignment
            && IsNativeOutlookAccepted(acceptedAssignment);
        var assignment = task.Assignment ?? new EwsTaskAssignmentInfo(
            parsed.Id, parsed.ChangeKey, parsed.GlobalTaskId, parsed.From ?? parsed.Sender,
            normalizedMailbox, null, task.Status, (int)Math.Round(task.PercentComplete),
            parsed.IsProcessed, parsed.IsReassignment);
        assignment = assignment with
        {
            RequestId = parsed.Id,
            RequestChangeKey = parsed.ChangeKey,
            AssignerAddress = parsed.ItemClass.Equals("IPM.TaskRequest", StringComparison.OrdinalIgnoreCase)
                ? parsed.Sender
                : assignment.AssignerAddress,
            AssigneeAddress = nativeReassignmentUpdate
                || nativeReassignmentRequest
                || nativeInitialRequest
                || nativeDecline
                || nativeUpdate
                || nativeAccepted
                || parsed.ItemClass.Equals("IPM.TaskRequest.Accept", StringComparison.OrdinalIgnoreCase)
                || parsed.ItemClass.Equals("IPM.TaskRequest.Decline", StringComparison.OrdinalIgnoreCase)
                || parsed.ItemClass.Equals("IPM.TaskRequest.Update", StringComparison.OrdinalIgnoreCase)
                ? assignment.AssigneeAddress
                : assignment.AssigneeAddress ?? normalizedMailbox,
            IsProcessed = parsed.IsProcessed,
            IsReassignment = parsed.IsReassignment,
            AssignerChainAddresses = MergeAssignerAddresses(
                assignment.AssignerChainAddresses, parsed.CcRecipients)
        };
        if (parsed.ItemClass.Equals("IPM.TaskRequest.Update", StringComparison.OrdinalIgnoreCase)
            && assignment.Mode is not 4
            && !nativeUpdate
            && !nativeReassignmentUpdate)
            throw new InvalidOperationException("The native task update has an unverified embedded communication mode.");
        if (parsed.GlobalTaskId is not null && assignment.GlobalTaskId is not null
            && !string.Equals(parsed.GlobalTaskId, assignment.GlobalTaskId, StringComparison.Ordinal))
            throw new InvalidOperationException("The task communication and embedded task have different GlobalIds.");
        if (parsed.Version is not null && assignment.Version is not null && parsed.Version != assignment.Version)
            throw new InvalidOperationException("The task communication and embedded task have different versions.");
        if (parsed.Version is null
            && ((parsed.ItemClass.Equals("IPM.TaskRequest.Accept", StringComparison.OrdinalIgnoreCase)
                    && parsed.Mode == 2
                    && IsNativeOutlookAccepted(assignment))
                || (parsed.ItemClass.Equals("IPM.TaskRequest.Decline", StringComparison.OrdinalIgnoreCase)
                    && parsed.Mode == 3
                    && nativeDecline)
                || (parsed.ItemClass.Equals("IPM.TaskRequest.Update", StringComparison.OrdinalIgnoreCase)
                    && parsed.Mode == 4
                    && (nativeUpdate || nativeReassignmentUpdate))
                || (parsed.ItemClass.Equals("IPM.TaskRequest", StringComparison.OrdinalIgnoreCase)
                    && parsed.Mode == 1
                    && (nativeReassignmentRequest || nativeInitialRequest)))
            && parsed.GlobalTaskId is not null
            && assignment.GlobalTaskId is not null
            && string.Equals(parsed.GlobalTaskId, assignment.GlobalTaskId, StringComparison.Ordinal)
            && assignment.Version is > 0)
        {
            // Outlook's native Accept sample omits the outer PidLidTaskVersion;
            // the embedded Task still carries the authoritative version. Keep
            // this fallback limited to the fully correlated native tuple.
            parsed = parsed with { Version = assignment.Version };
        }
        task = task with { Assignment = assignment };
        return parsed with
        {
            Task = task,
            GlobalTaskId = task.Assignment?.GlobalTaskId ?? parsed.GlobalTaskId,
            IsProcessed = task.Assignment?.IsProcessed ?? parsed.IsProcessed,
            EmbeddedTaskClass = taskElement.Element(T + "ItemClass")?.Value,
            EmbeddedTaskIsInline = ReadOptionalBoolean(nativeAttachments[0].Element(T + "IsInline"), "IsInline")
        };
    }

    public async Task<EwsPage<EwsTaskAssignmentMessage>> ListTaskAssignmentMessagesAsync(
        string mailbox,
        int offset,
        int limit,
        CancellationToken cancellationToken) =>
        await ListTaskAssignmentMessagesAsync(mailbox, offset, limit, unprocessedOnly: false, cancellationToken)
            .ConfigureAwait(false);

    public async Task<EwsPage<EwsTaskAssignmentMessage>> ListUnprocessedTaskAssignmentMessagesAsync(
        string mailbox,
        int offset,
        int limit,
        CancellationToken cancellationToken) =>
        await ListTaskAssignmentMessagesAsync(mailbox, offset, limit, unprocessedOnly: true, cancellationToken)
            .ConfigureAwait(false);

    private async Task<EwsPage<EwsTaskAssignmentMessage>> ListTaskAssignmentMessagesAsync(
        string mailbox,
        int offset,
        int limit,
        bool unprocessedOnly,
        CancellationToken cancellationToken)
    {
        var normalizedMailbox = ValidateMailbox(mailbox);
        ValidatePage(offset, limit);
        var operation = new XElement(
            M + "FindItem",
            new XAttribute("Traversal", "Shallow"),
            AssignmentMessageShape(),
            new XElement(M + "IndexedPageItemView", new XAttribute("MaxEntriesReturned", limit),
                new XAttribute("Offset", offset), new XAttribute("BasePoint", "Beginning")),
            new XElement(M + "Restriction", unprocessedOnly
                ? new XElement(T + "And", TaskAssignmentClassRestriction(), new XElement(T + "Or",
                    new XElement(T + "Not", new XElement(T + "Exists", ProcessedField())),
                    new XElement(T + "IsEqualTo", ProcessedField(),
                        new XElement(T + "FieldURIOrConstant", new XElement(T + "Constant", new XAttribute("Value", "false"))))))
                : TaskAssignmentClassRestriction()),
            new XElement(M + "SortOrder", new XElement(T + "FieldOrder",
                new XAttribute("Order", "Ascending"), Field("item:DateTimeReceived"))),
            new XElement(M + "ParentFolderIds", PeopleTasksFolderReference("inbox")));
        var document = await SendAsync(normalizedMailbox, operation, cancellationToken).ConfigureAwait(false);
        var root = RequiredElement(document, M + "RootFolder");
        var items = root.Element(T + "Items")?.Elements(T + "Message")
            .Select(message => unprocessedOnly ? ParseAutomaticTaskAssignmentMessage(message) : ParseTaskAssignmentMessage(message))
            .Where(message => message is not null).Cast<EwsTaskAssignmentMessage>().ToArray()
            ?? Array.Empty<EwsTaskAssignmentMessage>();
        var ids = new HashSet<string>(StringComparer.Ordinal);
        foreach (var item in items)
            if (!ids.Add(item.Id))
                throw new InvalidOperationException("Exchange returned duplicate task-assignment identifiers.");
        return new EwsPage<EwsTaskAssignmentMessage>(items, GetNextOffset(root, offset, items.Length));
    }

    private async Task<string?> FindTaskAssignerAsync(
        string mailbox,
        string globalTaskId,
        CancellationToken cancellationToken)
    {
        // The native task property stores the assigner's display name, not an
        // SMTP address.  Resolve the address from the still-associated request
        // while it is available, with a bounded scan and no mailbox mutation.
        var page = await ListTaskAssignmentMessagesAsync(mailbox, 0, 100, cancellationToken).ConfigureAwait(false);
        var matches = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var message in page.Items)
        {
            if (!string.Equals(message.GlobalTaskId, globalTaskId, StringComparison.Ordinal)) continue;
            var sender = message.From ?? message.Sender;
            if (!string.IsNullOrWhiteSpace(sender)) matches.Add(NormalizeAddress(sender));
        }
        if (matches.Count > 1)
            throw new InvalidOperationException("The task has conflicting native assigner identities; progress is refused.");
        return matches.SingleOrDefault();
    }

    private async Task EnsureNoDuplicateTaskGlobalIdAsync(
        string mailbox,
        string globalTaskId,
        CancellationToken cancellationToken)
    {
        var operation = new XElement(
            M + "FindItem", new XAttribute("Traversal", "Shallow"), TaskShape(),
            new XElement(M + "IndexedPageItemView", new XAttribute("MaxEntriesReturned", 1),
                new XAttribute("Offset", 0), new XAttribute("BasePoint", "Beginning")),
            new XElement(M + "Restriction", new XElement(T + "IsEqualTo",
                NamedField(CommonPropertySet, "0x8519", "Binary"),
                new XElement(T + "FieldURIOrConstant",
                    new XElement(T + "Constant", new XAttribute("Value", globalTaskId))))),
            new XElement(M + "ParentFolderIds", PeopleTasksFolderReference("tasks")));
        var document = await SendAsync(mailbox, operation, cancellationToken).ConfigureAwait(false);
        if (document.Descendants(T + "Task").Any())
            throw new InvalidOperationException("A task with the same native GlobalTaskId already exists in the selected mailbox.");
    }

    private async Task<(EwsTask Task, EwsItemRef Reference)?> FindTaskByGlobalIdAsync(
        string mailbox,
        string globalTaskId,
        CancellationToken cancellationToken)
    {
        var operation = new XElement(
            M + "FindItem", new XAttribute("Traversal", "Shallow"), TaskShape(),
            new XElement(M + "IndexedPageItemView", new XAttribute("MaxEntriesReturned", 2),
                new XAttribute("Offset", 0), new XAttribute("BasePoint", "Beginning")),
            new XElement(M + "Restriction", new XElement(T + "IsEqualTo",
                NamedField(CommonPropertySet, "0x8519", "Binary"),
                new XElement(T + "FieldURIOrConstant",
                    new XElement(T + "Constant", new XAttribute("Value", globalTaskId))))),
            new XElement(M + "ParentFolderIds", PeopleTasksFolderReference("tasks")));
        var document = await SendAsync(mailbox, operation, cancellationToken).ConfigureAwait(false);
        var tasks = document.Descendants(T + "Task")
            .Where(item => item.Element(T + "ItemId") is not null)
            .Select(ParseTask).ToArray();
        if (tasks.Length > 1)
            throw new InvalidOperationException("Multiple local tasks share the same native GlobalTaskId.");
        if (tasks.Length == 0) return null;
        var fresh = await GetTaskAsync(mailbox, tasks[0].Id, cancellationToken).ConfigureAwait(false);
        if (!string.Equals(fresh.Assignment?.GlobalTaskId, globalTaskId, StringComparison.Ordinal))
            throw new InvalidOperationException("The matching local task changed after lookup; prepare a new action.");
        return (fresh, new EwsItemRef(fresh.Id, fresh.ChangeKey));
    }

    private static bool IsWatcherReassignmentRequest(EwsTaskAssignmentMessage message, string mailbox) =>
        message.ItemClass.StartsWith("IPM.TaskRequest", StringComparison.OrdinalIgnoreCase)
        && message.ToRecipients.Count == 1
        && !message.ToRecipients.Any(value => string.Equals(value, mailbox, StringComparison.OrdinalIgnoreCase))
        && message.CcRecipients?.Any(value => string.Equals(value, mailbox, StringComparison.OrdinalIgnoreCase)) == true;

    private static void ValidateWatcherReassignmentRequest(
        EwsTaskAssignmentMessage request,
        string mailbox)
    {
        if (!request.ItemClass.StartsWith("IPM.TaskRequest", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("The message is not a native Outlook task communication.");
        if (request.IsProcessed || request.ToRecipients.Count != 1
            || request.CcRecipients?.Any(value => string.Equals(value, mailbox, StringComparison.OrdinalIgnoreCase)) != true)
            throw new InvalidOperationException("The reassignment watcher copy is not addressed to the selected mailbox.");
        if (request.CcRecipients is { Count: > MaxAssignerAddresses })
            throw new InvalidOperationException("The native task watcher chain exceeds the supported bound.");
        if (request.BccRecipients is { Count: > 0 })
            throw new InvalidOperationException("Native task assignment messages cannot use Bcc recipients.");
        ValidateNativeSender(request, expected: null,
            "The native reassignment request has no trustworthy sender identity.");
        var task = request.Task ?? throw new InvalidOperationException("The native reassignment request has no embedded task.");
        var assignment = task.Assignment
            ?? throw new InvalidOperationException("The native reassignment request has no task-assignment metadata.");
        if (string.IsNullOrWhiteSpace(assignment.GlobalTaskId) || assignment.Version is not > 0)
            throw new InvalidOperationException("The native task communication has no valid correlation or version.");

        var expectedMode = request.ItemClass switch
        {
            "IPM.TaskRequest" => 1,
            "IPM.TaskRequest.Accept" => 2,
            "IPM.TaskRequest.Decline" => 3,
            "IPM.TaskRequest.Update" => 4,
            _ => 0
        };
        if (expectedMode == 0)
            throw new InvalidOperationException("The message is not a supported native Outlook task communication.");
        if (request.Version is not > 0 || request.Mode != expectedMode || request.Version != assignment.Version)
            throw new InvalidOperationException("The native task communication has mismatched version metadata.");

        if (request.ItemClass.Equals("IPM.TaskRequest", StringComparison.OrdinalIgnoreCase))
        {
            if (assignment.State is not 3 || assignment.Ownership is not 1
                || assignment.AcceptanceState is not 1)
                throw new InvalidOperationException("The native reassignment request has invalid ownership or state.");
            if (assignment.AssigneeAddress is null
                || !string.Equals(NormalizeAddress(assignment.AssigneeAddress),
                    NormalizeAddress(request.ToRecipients[0]), StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("The reassignment request target does not match its native recipient.");
        }
        else if (request.ItemClass.Equals("IPM.TaskRequest.Accept", StringComparison.OrdinalIgnoreCase)
            && (assignment.State is not 2 || assignment.Ownership is not 2
                || assignment.AcceptanceState is not 2 && !IsNativeOutlookAccepted(assignment)))
        {
            throw new InvalidOperationException("The native task acceptance has invalid ownership or state.");
        }
        else if (request.ItemClass.Equals("IPM.TaskRequest.Decline", StringComparison.OrdinalIgnoreCase)
            && !((assignment.State is 4 && assignment.Ownership is 2 && assignment.AcceptanceState is 3)
                || IsNativeOutlookDeclined(assignment)))
        {
            throw new InvalidOperationException("The native task decline has invalid ownership or state.");
        }
        else if (request.ItemClass.Equals("IPM.TaskRequest.Update", StringComparison.OrdinalIgnoreCase)
            && (assignment.State is not 2 || assignment.Ownership is not 2
                || assignment.AcceptanceState is not (0 or 2)))
        {
            throw new InvalidOperationException("The native task update has invalid ownership or state.");
        }
    }

    private static void ValidateIncomingTaskProcess(
        EwsTask local,
        EwsTaskAssignmentMessage message,
        EwsTask incoming,
        string mailbox,
        bool watcherRequest)
    {
        var localInfo = local.Assignment
            ?? throw new InvalidOperationException("The matching local task has no native assignment state.");
        var incomingInfo = incoming.Assignment
            ?? throw new InvalidOperationException("The native task response has no assignment state.");
        ValidateTaskAttachmentSnapshots(local, incoming);
        if (!string.Equals(localInfo.GlobalTaskId, incomingInfo.GlobalTaskId, StringComparison.Ordinal))
            throw new InvalidOperationException("The native task response does not match the local task correlation.");
        if (incomingInfo.Version is not > 0 || localInfo.Version is not > 0
            || incomingInfo.Version <= localInfo.Version)
            throw new InvalidOperationException("The native task response is stale or has no valid version.");
        // The private SMTP role fields are authoritative for MCP-created
        // copies.  For older native tasks, fall back to the native assigner
        // display field so a response cannot be accepted from an unrelated
        // internally-authenticated sender.
        var expectedSender = localInfo.AssigneeAddress ?? localInfo.OwnerAddress
            ?? localInfo.AssignerAddress ?? localInfo.AssignerName ?? localInfo.OwnerName;
        ValidateNativeSender(message, expectedSender,
            "The native task response sender does not match the assigned recipient.");
        if (watcherRequest)
        {
            if (localInfo.State is not 3 || localInfo.Ownership is not 1)
                throw new InvalidOperationException("The reassignment watcher copy is not an assigner tracking copy.");
            if (!IsAddress(localInfo.AssignerAddress, mailbox)
                && localInfo.AssignerChainAddresses?.Any(value => IsAddress(value, mailbox)) != true)
                throw new InvalidOperationException("The selected mailbox is not in the local native task watcher chain.");
            if (!message.CcRecipients!.Any(value => string.Equals(value, mailbox, StringComparison.OrdinalIgnoreCase)))
                throw new InvalidOperationException("The selected mailbox is not a verified reassignment watcher.");
            if (message.ItemClass.Equals("IPM.TaskRequest", StringComparison.OrdinalIgnoreCase))
            {
                if (incomingInfo.AssigneeAddress is null
                    || !string.Equals(NormalizeAddress(incomingInfo.AssigneeAddress),
                        NormalizeAddress(message.ToRecipients[0]), StringComparison.OrdinalIgnoreCase))
                    throw new InvalidOperationException("The reassignment target does not match the native task payload.");
            }
            else
            {
                // A response/update is addressed to the current assigner and
                // copied to this watcher.  Bind that recipient to the stored
                // current assigner (LastUserName is retained for older copies
                // created before AssignerAddress was advanced on a watcher).
                // New watcher copies advance AssignerAddress to the mailbox
                // that owns the current assignment.  Older copies retained
                // the watcher itself there, so use their recorded sender as
                // the current assigner only in that legacy shape.
                var expectedAssigner = IsAddress(localInfo.AssignerAddress, mailbox)
                    ? localInfo.LastUserName ?? localInfo.LastDelegateName ?? localInfo.AssignerAddress
                    : localInfo.AssignerAddress ?? localInfo.LastUserName
                        ?? localInfo.LastDelegateName ?? localInfo.AssignerName;
                if (expectedAssigner is null
                    || !IsAddress(message.ToRecipients[0], NormalizeAddress(expectedAssigner)))
                    throw new InvalidOperationException("The native watcher response is not addressed to the current task assigner.");
                var currentOwner = localInfo.OwnerAddress ?? localInfo.AssigneeAddress;
                var incomingOwner = incomingInfo.OwnerAddress ?? incomingInfo.AssigneeAddress;
                if (currentOwner is null || incomingOwner is null || !IsAddress(incomingOwner, NormalizeAddress(currentOwner)))
                    throw new InvalidOperationException("The native watcher response owner does not match the local task.");
            }
            return;
        }
        if (message.ItemClass.Equals("IPM.TaskRequest.Update", StringComparison.OrdinalIgnoreCase)
            && !IsNativeOutlookReassignmentUpdate(message)
            && incomingInfo.AcceptanceState is not (0 or 2))
            throw new InvalidOperationException("The native task update is not an accepted assignment update.");
        if (IsNativeOutlookReassignmentUpdate(message))
        {
            if (localInfo.State is not 3 || localInfo.Ownership is not 1
                || !IsAddress(localInfo.AssigneeAddress, NormalizeAddress(message.Sender ?? string.Empty)))
                throw new InvalidOperationException("The native reassignment update sender is not the current task assignee.");
            if (incomingInfo.State is not 3 || incomingInfo.Ownership is not 1
                || incomingInfo.AcceptanceState is not 1 || incomingInfo.Accepted != true
                || incomingInfo.AssigneeAddress is null
                || !IsAddress(incomingInfo.AssigneeAddress, incomingInfo.OwnerAddress ?? string.Empty))
                throw new InvalidOperationException("The native reassignment update has invalid ownership metadata.");
        }
        if (message.ItemClass.Equals("IPM.TaskRequest.Accept", StringComparison.OrdinalIgnoreCase)
            && incomingInfo.AcceptanceState is not 2 && !IsNativeOutlookAccepted(incomingInfo))
            throw new InvalidOperationException("The native task acceptance has an invalid acceptance state.");
        if (message.ItemClass.Equals("IPM.TaskRequest.Decline", StringComparison.OrdinalIgnoreCase)
            && incomingInfo.AcceptanceState is not 3
            && !IsNativeOutlookDeclined(incomingInfo))
            throw new InvalidOperationException("The native task decline has an invalid acceptance state.");
    }

    private static bool IsNativeOutlookAccepted(EwsTaskAssignmentInfo assignment) =>
        assignment.State == 2
        && assignment.Ownership == 2
        && assignment.AcceptanceState == 0
        && assignment.Accepted == true;

    private static bool IsSupportedTaskTrackerResponse(
        EwsTaskAssignmentMessage message,
        EwsTaskAssignmentInfo assignment)
    {
        if (message.ItemClass.Equals("IPM.TaskRequest.Accept", StringComparison.OrdinalIgnoreCase))
            return assignment.State == 2 && assignment.Ownership == 2
                && (assignment.AcceptanceState == 2 || IsNativeOutlookAccepted(assignment));
        if (message.ItemClass.Equals("IPM.TaskRequest.Decline", StringComparison.OrdinalIgnoreCase))
            return (assignment.State == 4 && assignment.Ownership == 2 && assignment.AcceptanceState == 3)
                || IsNativeOutlookDeclined(assignment);
        if (message.ItemClass.Equals("IPM.TaskRequest.Update", StringComparison.OrdinalIgnoreCase))
            return (assignment.State == 2 && assignment.Ownership == 2
                    && assignment.AcceptanceState is 0 or 2)
                || IsNativeOutlookReassignmentUpdate(message)
                || IsNativeOutlookProgressUpdate(message, assignment);
        return false;
    }

    private static bool IsNativeOutlookProgressUpdate(
        EwsTaskAssignmentMessage message,
        EwsTaskAssignmentInfo assignment) =>
        message.ItemClass.Equals("IPM.TaskRequest.Update", StringComparison.OrdinalIgnoreCase)
        && message.Mode == 4
        && message.Version is > 0
        && assignment.Mode == 0
        && assignment.State == 2
        && assignment.Ownership == 2
        && assignment.AcceptanceState == 0
        && assignment.Accepted == true
        && assignment.Version == message.Version;

    private static bool IsNativeOutlookDeclined(EwsTaskAssignmentInfo assignment) =>
        assignment.Mode == 3
        && assignment.State == 3
        && assignment.Ownership == 1
        && assignment.AcceptanceState == 1
        && assignment.Accepted == true;

    private static bool IsNativeOutlookDecline(
        EwsTaskAssignmentMessage message,
        XElement taskElement)
    {
        if (!message.ItemClass.Equals("IPM.TaskRequest.Decline", StringComparison.OrdinalIgnoreCase)
            || message.Mode != 3
            || message.Version is not null
            || !message.InternalAuthenticated
            || string.IsNullOrWhiteSpace(message.Sender)
            || !string.Equals(message.From, message.Sender, StringComparison.OrdinalIgnoreCase)
            || string.IsNullOrWhiteSpace(message.GlobalTaskId))
            return false;

        var embeddedGlobal = ReadExtendedValue(taskElement, CommonPropertySet, "0x8519", "Binary");
        if (!string.Equals(message.GlobalTaskId, embeddedGlobal, StringComparison.Ordinal))
            return false;
        return ReadTaskInteger(taskElement, CommonPropertySet, "0x8518") == 3
            && ReadTaskInteger(taskElement, TaskPropertySet, "0x8113") == 3
            && ReadTaskInteger(taskElement, TaskPropertySet, "0x8129") == 1
            && ReadTaskInteger(taskElement, TaskPropertySet, "0x812A") == 1
            && ReadExtendedBool(taskElement, TaskPropertySet, "0x8108") == true
            && ReadTaskInteger(taskElement, TaskPropertySet, "0x811A") == 2
            && ReadTaskInteger(taskElement, TaskPropertySet, "0x8112") is > 0;
    }

    private static bool IsNativeOutlookUpdate(
        EwsTaskAssignmentMessage message,
        XElement taskElement)
    {
        if (!message.ItemClass.Equals("IPM.TaskRequest.Update", StringComparison.OrdinalIgnoreCase)
            || message.Mode != 4
            || message.Version is not null
            || !message.InternalAuthenticated
            || string.IsNullOrWhiteSpace(message.Sender)
            || !string.Equals(message.From, message.Sender, StringComparison.OrdinalIgnoreCase)
            || string.IsNullOrWhiteSpace(message.GlobalTaskId))
            return false;

        var embeddedGlobal = ReadExtendedValue(taskElement, CommonPropertySet, "0x8519", "Binary");
        if (!string.Equals(message.GlobalTaskId, embeddedGlobal, StringComparison.Ordinal))
            return false;
        return ReadTaskInteger(taskElement, CommonPropertySet, "0x8518") == 0
            && ReadTaskInteger(taskElement, TaskPropertySet, "0x8113") == 2
            && ReadTaskInteger(taskElement, TaskPropertySet, "0x8129") == 2
            && ReadTaskInteger(taskElement, TaskPropertySet, "0x812A") == 0
            && ReadExtendedBool(taskElement, TaskPropertySet, "0x8108") == true
            && ReadTaskInteger(taskElement, TaskPropertySet, "0x811A") == 3
            && ReadTaskInteger(taskElement, TaskPropertySet, "0x8112") is > 0;
    }

    private static bool IsNativeOutlookReassignmentRequest(
        EwsTaskAssignmentMessage message,
        XElement taskElement)
    {
        if (!message.ItemClass.Equals("IPM.TaskRequest", StringComparison.OrdinalIgnoreCase)
            || message.Mode != 1
            || message.Version is not null
            || !message.InternalAuthenticated
            || string.IsNullOrWhiteSpace(message.Sender)
            || !string.Equals(message.From, message.Sender, StringComparison.OrdinalIgnoreCase)
            || string.IsNullOrWhiteSpace(message.GlobalTaskId))
            return false;

        var embeddedGlobal = ReadExtendedValue(taskElement, CommonPropertySet, "0x8519", "Binary");
        return string.Equals(message.GlobalTaskId, embeddedGlobal, StringComparison.Ordinal)
            && ReadTaskInteger(taskElement, CommonPropertySet, "0x8518") == 1
            && ReadTaskInteger(taskElement, TaskPropertySet, "0x8113") == 3
            && ReadTaskInteger(taskElement, TaskPropertySet, "0x8129") == 1
            && ReadTaskInteger(taskElement, TaskPropertySet, "0x812A") == 1
            && ReadExtendedBool(taskElement, TaskPropertySet, "0x8108") == true
            && ReadTaskInteger(taskElement, TaskPropertySet, "0x811A") == 5
            && ReadTaskInteger(taskElement, TaskPropertySet, "0x8112") is > 0;
    }

    private static bool IsNativeOutlookInitialRequest(
        EwsTaskAssignmentMessage message,
        XElement taskElement)
    {
        if (!message.ItemClass.Equals("IPM.TaskRequest", StringComparison.OrdinalIgnoreCase)
            || message.Mode != 1
            || message.Version is not null
            || !message.InternalAuthenticated
            || string.IsNullOrWhiteSpace(message.Sender)
            || !string.Equals(message.From, message.Sender, StringComparison.OrdinalIgnoreCase)
            || string.IsNullOrWhiteSpace(message.GlobalTaskId)
            || ReadExtendedBool(taskElement, TaskPropertySet, "0x8108") is not null
            || !string.IsNullOrWhiteSpace(ReadExtendedValue(taskElement, TaskPropertySet, "0x8117", "Binary"))
            || !string.IsNullOrWhiteSpace(ReadExtendedValue(taskElement, TaskPropertySet, "0x8121", "String")))
            return false;

        var embeddedGlobal = ReadExtendedValue(taskElement, CommonPropertySet, "0x8519", "Binary");
        return string.Equals(message.GlobalTaskId, embeddedGlobal, StringComparison.Ordinal)
            && ReadTaskInteger(taskElement, CommonPropertySet, "0x8518") == 1
            && ReadTaskInteger(taskElement, TaskPropertySet, "0x8113") == 3
            && ReadTaskInteger(taskElement, TaskPropertySet, "0x8129") == 1
            && ReadTaskInteger(taskElement, TaskPropertySet, "0x812A") == 1
            && ReadTaskInteger(taskElement, TaskPropertySet, "0x811A") == 5
            && ReadTaskInteger(taskElement, TaskPropertySet, "0x8112") is > 0
            && !string.IsNullOrWhiteSpace(ReadExtendedValue(taskElement, TaskPropertySet, "0x811F", "String"));
    }

    private static bool IsNativeOutlookReassignmentUpdate(
        EwsTaskAssignmentMessage message,
        XElement taskElement)
    {
        if (!message.ItemClass.Equals("IPM.TaskRequest.Update", StringComparison.OrdinalIgnoreCase)
            || message.Mode != 4
            || message.Version is not null
            || !message.InternalAuthenticated
            || string.IsNullOrWhiteSpace(message.Sender)
            || !string.Equals(message.From, message.Sender, StringComparison.OrdinalIgnoreCase)
            || string.IsNullOrWhiteSpace(message.GlobalTaskId))
            return false;

        var embeddedGlobal = ReadExtendedValue(taskElement, CommonPropertySet, "0x8519", "Binary");
        return string.Equals(message.GlobalTaskId, embeddedGlobal, StringComparison.Ordinal)
            && ReadTaskInteger(taskElement, CommonPropertySet, "0x8518") == 0
            && ReadTaskInteger(taskElement, TaskPropertySet, "0x8113") == 3
            && ReadTaskInteger(taskElement, TaskPropertySet, "0x8129") == 1
            && ReadTaskInteger(taskElement, TaskPropertySet, "0x812A") == 1
            && ReadExtendedBool(taskElement, TaskPropertySet, "0x8108") == true
            && ReadTaskInteger(taskElement, TaskPropertySet, "0x811A") == 3
            && ReadTaskInteger(taskElement, TaskPropertySet, "0x8112") is > 0;
    }

    private static bool IsNativeOutlookReassignmentUpdate(EwsTaskAssignmentMessage message)
    {
        var assignment = message.Task?.Assignment;
        return message.ItemClass.Equals("IPM.TaskRequest.Update", StringComparison.OrdinalIgnoreCase)
            && message.Mode == 4
            && message.Version is > 0
            && assignment is not null
            && assignment.Mode == 0
            && assignment.State == 3
            && assignment.Ownership == 1
            && assignment.AcceptanceState == 1
            && assignment.Accepted == true;
    }

    private static bool IsNativeOutlookReassignmentRequest(EwsTaskAssignmentMessage message)
    {
        var assignment = message.Task?.Assignment;
        return message.ItemClass.Equals("IPM.TaskRequest", StringComparison.OrdinalIgnoreCase)
            && message.Mode == 1
            && message.Version is > 0
            && assignment is not null
            && assignment.Mode == 1
            && assignment.State == 3
            && assignment.Ownership == 1
            && assignment.AcceptanceState == 1
            && assignment.Accepted == true;
    }

    private static bool IsNativeOutlookInitialRequest(EwsTaskAssignmentMessage message)
    {
        var assignment = message.Task?.Assignment;
        return message.ItemClass.Equals("IPM.TaskRequest", StringComparison.OrdinalIgnoreCase)
            && message.Mode == 1
            && message.Version is > 0
            && assignment is not null
            && assignment.Mode == 1
            && assignment.State == 3
            && assignment.Ownership == 1
            && assignment.AcceptanceState == 1
            && assignment.Accepted is null
            && string.IsNullOrWhiteSpace(assignment.AssignerStackBase64)
            && string.IsNullOrWhiteSpace(assignment.AssignerName);
    }

    private async Task<EwsTask> HydrateNativeReassignmentTrackerAsync(
        string mailbox,
        EwsTask local,
        EwsTaskAssignmentMessage request,
        EwsTask incoming,
        CancellationToken cancellationToken)
    {
        var localInfo = local.Assignment;
        var incomingInfo = incoming.Assignment;
        var supportedTrackerResponse = localInfo is not null && incomingInfo is not null
            && IsSupportedTaskTrackerResponse(request, incomingInfo);
        if (!supportedTrackerResponse
            || localInfo is null || incomingInfo is null
            || string.IsNullOrWhiteSpace(incomingInfo.GlobalTaskId)
            || incomingInfo.Version is not > 0
            || localInfo.State is not 3 || localInfo.Ownership is not 1)
            return local;
        if (localInfo.AssigneeAddress is not null && localInfo.OwnerAddress is not null
            && !IsAddress(localInfo.AssigneeAddress, localInfo.OwnerAddress))
            throw new InvalidOperationException("The native tracker has conflicting private owner roles.");
        var ownerName = localInfo.OwnerName ?? incomingInfo.OwnerName;
        var owner = localInfo.AssigneeAddress ?? localInfo.OwnerAddress;
        string? nativeOwner = null;
        var nativeOwnerNeedsResolution = owner is null
            || localInfo.AcceptanceState == 1
                && !string.IsNullOrWhiteSpace(ownerName)
                && (!ownerName.Contains('@', StringComparison.Ordinal)
                    || !IsAddress(ownerName, owner));
        if (nativeOwnerNeedsResolution && !string.IsNullOrWhiteSpace(ownerName))
        {
            nativeOwner = await ResolveUniqueNativeMailboxAsync(mailbox, ownerName, cancellationToken)
                .ConfigureAwait(false);
            owner ??= nativeOwner;
        }
        string? currentAssigner = localInfo.AssignerAddress;
        IReadOnlyList<string>? verifiedChain = null;
        if (owner is null)
            throw new InvalidOperationException("The reassignment tracker has no unique native owner identity.");

        // A pending Outlook handoff tracker carries AcceptanceState=1.  Keep
        // the reconciliation branch limited to that native pending shape;
        // ordinary accepted/process trackers can retain their existing MCP
        // private owner roles and must continue through the normal guards.
        if (nativeOwner is not null && !IsAddress(owner, nativeOwner)
            && localInfo.AcceptanceState == 1 && localInfo.Accepted != false)
            throw new InvalidOperationException("The native tracker has an unsupported accepted owner transition.");
        if (nativeOwner is not null && !IsAddress(owner, nativeOwner)
            && localInfo.AcceptanceState == 1 && localInfo.Accepted == false)
        {
            (currentAssigner, owner, verifiedChain) = await ReconcileNativeTrackerRolesAsync(
                mailbox, localInfo, incomingInfo, request, nativeOwner, cancellationToken)
                .ConfigureAwait(false);
        }
        // ReadTaskAssignmentMessageAsync supplies the selected mailbox as a
        // compatibility assignee for ordinary responses.  That value is not
        // a native owner role; only a private owner address is authoritative
        // here.
        var incomingOwner = incomingInfo.OwnerAddress
            ?? (request.ItemClass.Equals("IPM.TaskRequest.Accept", StringComparison.OrdinalIgnoreCase)
                ? null : incomingInfo.AssigneeAddress);
        if (!request.ItemClass.Equals("IPM.TaskRequest.Update", StringComparison.OrdinalIgnoreCase)
            && incomingOwner is not null && !IsAddress(incomingOwner, owner))
            throw new InvalidOperationException("The native accepted response owner conflicts with the reassignment tracker.");
        var hydrated = localInfo with
        {
            AssignerAddress = currentAssigner ?? NormalizeAddress(mailbox),
            AssigneeAddress = owner,
            OwnerAddress = owner,
            AssignerChainAddresses = verifiedChain ?? localInfo.AssignerChainAddresses
        };
        return local with { Assignment = hydrated };
    }

    private async Task<(string CurrentAssigner, string Owner, IReadOnlyList<string> VerifiedChain)> ReconcileNativeTrackerRolesAsync(
        string mailbox,
        EwsTaskAssignmentInfo localInfo,
        EwsTaskAssignmentInfo incomingInfo,
        EwsTaskAssignmentMessage request,
        string nativeOwner,
        CancellationToken cancellationToken)
    {
        var privateOwner = localInfo.OwnerAddress;
        var privateAssignee = localInfo.AssigneeAddress;
        if (string.IsNullOrWhiteSpace(privateOwner)
            || string.IsNullOrWhiteSpace(privateAssignee)
            || !IsAddress(privateAssignee, privateOwner))
            throw new InvalidOperationException("The native tracker has conflicting or incomplete private owner roles.");

        var selectedMailbox = NormalizeAddress(mailbox);
        if (!IsAddress(localInfo.AssignerAddress, selectedMailbox))
            throw new InvalidOperationException("The native tracker private assigner is not the selected watcher mailbox.");

        var previousOwner = NormalizeAddress(privateOwner);
        if (IsAddress(nativeOwner, previousOwner))
            return (previousOwner, nativeOwner, Array.Empty<string>());

        if (string.IsNullOrWhiteSpace(localInfo.LastUserName))
            throw new InvalidOperationException("The native tracker has no last-user identity for its owner transition.");
        var lastUser = await ResolveUniqueNativeMailboxAsync(
            mailbox, localInfo.LastUserName, cancellationToken).ConfigureAwait(false);
        if (!IsAddress(lastUser, previousOwner))
            throw new InvalidOperationException("The native tracker last-user identity does not match its private owner.");

        if (request.Sender is null || !IsAddress(request.Sender, nativeOwner)
            || request.From is not null && !IsAddress(request.From, nativeOwner))
            throw new InvalidOperationException("The native tracker response sender does not match its native owner.");
        if (request.ToRecipients.Count != 1 || !IsAddress(request.ToRecipients[0], previousOwner))
            throw new InvalidOperationException("The native tracker response is not addressed to its previous owner.");

        var ccRecipients = request.CcRecipients ?? Array.Empty<string>();
        if (ccRecipients.Count == 0
            || ccRecipients.Count > MaxAssignerAddresses)
            throw new InvalidOperationException("The native tracker response has no verified watcher recipient.");

        if (string.IsNullOrWhiteSpace(incomingInfo.AssignerStackBase64))
            throw new InvalidOperationException("The native tracker response has no serialized watcher chain.");
        var verifiedStack = await ResolveNativeAssignerStackAddressesAsync(
            mailbox, incomingInfo.AssignerStackBase64, nativeOwner, cancellationToken)
            .ConfigureAwait(false);
        if (verifiedStack.Count < 2
            || !IsAddress(verifiedStack[^1], previousOwner))
            throw new InvalidOperationException("The native tracker response watcher chain does not end at its previous owner.");
        var watcherPrefix = verifiedStack.Take(verifiedStack.Count - 1).ToArray();
        if (!watcherPrefix.Any(address => IsAddress(address, selectedMailbox))
            || !AddressesMatch(ccRecipients, watcherPrefix))
            throw new InvalidOperationException("The native tracker response watcher chain is not the verified native chain.");
        if (incomingInfo.AssignerChainAddresses is not { Count: > 0 } incomingChain
            || !AddressesMatch(incomingChain, verifiedStack))
            throw new InvalidOperationException("The native tracker response has an unverified watcher chain.");

        var incomingOwner = incomingInfo.OwnerAddress ?? incomingInfo.AssigneeAddress;
        if (incomingOwner is not null && !IsAddress(incomingOwner, nativeOwner))
            throw new InvalidOperationException("The native tracker response owner conflicts with its native owner identity.");

        return (previousOwner, nativeOwner, verifiedStack);
    }

    private async Task<EwsTaskAssignmentMessage> HydrateNativeReassignmentRequestAsync(
        string mailbox,
        EwsTaskAssignmentMessage request,
        CancellationToken cancellationToken)
    {
        var task = request.Task ?? throw new InvalidOperationException("The native reassignment request has no embedded task.");
        var assignment = task.Assignment
            ?? throw new InvalidOperationException("The native reassignment request has no assignment metadata.");
        var ownerName = assignment.OwnerName;
        if (string.IsNullOrWhiteSpace(ownerName) || request.ToRecipients.Count != 1)
            throw new InvalidOperationException("The native reassignment request has no unique target identity.");
        var owner = await ResolveUniqueNativeMailboxAsync(mailbox, ownerName, cancellationToken)
            .ConfigureAwait(false);
        if (!IsAddress(owner, request.ToRecipients[0]))
            throw new InvalidOperationException("The native reassignment request owner does not match its recipient.");
        if (assignment.AssigneeAddress is not null && !IsAddress(assignment.AssigneeAddress, owner)
            || assignment.OwnerAddress is not null && !IsAddress(assignment.OwnerAddress, owner))
            throw new InvalidOperationException("The native reassignment request has conflicting private role metadata.");
        var verifiedStack = await ResolveNativeAssignerStackAddressesAsync(
            mailbox, assignment.AssignerStackBase64, owner, cancellationToken).ConfigureAwait(false);
        if (assignment.AssignerChainAddresses is { Count: > 0 } suppliedChain
            && !AddressesMatch(suppliedChain, verifiedStack))
            throw new InvalidOperationException("The native reassignment request watcher chain conflicts with its serialized assigner stack.");
        if (verifiedStack.Any(address => IsAddress(address, owner)))
            throw new InvalidOperationException("The native reassignment request assigner stack contains its target owner.");
        var hydratedAssignment = assignment with
        {
            AssigneeAddress = owner,
            OwnerAddress = owner,
            AssignerChainAddresses = verifiedStack
        };
        return request with { Task = task with { Assignment = hydratedAssignment } };
    }

    private async Task<EwsTaskAssignmentMessage> HydrateNativeReassignmentUpdateAsync(
        string mailbox,
        EwsTaskAssignmentMessage request,
        CancellationToken cancellationToken)
    {
        var task = request.Task ?? throw new InvalidOperationException("The native reassignment update has no embedded task.");
        var assignment = task.Assignment
            ?? throw new InvalidOperationException("The native reassignment update has no assignment metadata.");
        var sender = NormalizeAddress(request.Sender
            ?? throw new InvalidOperationException("The native reassignment update has no sender address."));
        if (assignment.AssignerAddress is not null && !IsAddress(assignment.AssignerAddress, sender))
            throw new InvalidOperationException("The native reassignment update has conflicting private role metadata.");
        var ownerName = assignment.OwnerName;
        if (string.IsNullOrWhiteSpace(ownerName))
            throw new InvalidOperationException("The native reassignment update has no native owner identity.");
        var owner = await ResolveUniqueNativeMailboxAsync(mailbox, ownerName, cancellationToken)
            .ConfigureAwait(false);
        if (assignment.AssigneeAddress is not null && !IsAddress(assignment.AssigneeAddress, owner)
            || assignment.OwnerAddress is not null && !IsAddress(assignment.OwnerAddress, owner))
            throw new InvalidOperationException("The native reassignment update has conflicting private role metadata.");
        var stackAddresses = await ResolveNativeAssignerStackAddressesAsync(
            mailbox, assignment.AssignerStackBase64, owner, cancellationToken).ConfigureAwait(false);
        if (assignment.AssignerChainAddresses is { Count: > 0 } suppliedChain
            && !AddressesMatch(suppliedChain, stackAddresses))
            throw new InvalidOperationException("The native reassignment update watcher chain conflicts with its serialized assigner stack.");
        var hydratedAssignment = assignment with
        {
            AssignerAddress = sender,
            AssigneeAddress = owner,
            OwnerAddress = owner,
            AssignerChainAddresses = stackAddresses
        };
        return request with { Task = task with { Assignment = hydratedAssignment } };
    }

    private async Task<IReadOnlyList<string>> ResolveNativeAssignerStackAddressesAsync(
        string mailbox,
        string? encodedStack,
        string? forbiddenAddress,
        CancellationToken cancellationToken)
    {
        var entries = TaskAssignerStack.Parse(encodedStack);
        if (entries.Count == 0)
            return Array.Empty<string>();
        if (_taskDirectory is null)
            throw new InvalidOperationException("The task assigner directory is unavailable; the native assigner stack cannot be verified.");
        var addresses = new List<string>(entries.Count);
        var seenAddresses = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var normalizedForbiddenAddress = string.IsNullOrWhiteSpace(forbiddenAddress)
            ? null : NormalizeAddress(forbiddenAddress);
        foreach (var entry in entries)
        {
            var resolutions = await ResolveDirectoryAsync(mailbox, entry.LegacyExchangeDn, 2, cancellationToken)
                .ConfigureAwait(false);
            if (resolutions.Count != 1)
                throw new InvalidOperationException("The native task assigner stack directory lookup was ambiguous.");
            var smtp = resolutions
                .Where(value => string.Equals(value.RoutingType, "SMTP", StringComparison.OrdinalIgnoreCase))
                .Select(value => value.EmailAddress)
                .Where(value => !string.IsNullOrWhiteSpace(value))
                .Select(value => NormalizeAddress(value!))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();
            if (smtp.Length != 1)
                throw new InvalidOperationException("The native task assigner stack does not resolve to one SMTP mailbox.");
            if (!seenAddresses.Add(smtp[0]))
                throw new InvalidOperationException("The native task assigner stack contains a duplicate mailbox identity.");
            if (normalizedForbiddenAddress is not null
                && string.Equals(smtp[0], normalizedForbiddenAddress, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("The native task assigner stack contains its target owner.");
            var directoryEntry = await _taskDirectory.ResolveTaskAssignerAsync(smtp[0], cancellationToken)
                .ConfigureAwait(false);
            if (!string.Equals(directoryEntry.LegacyExchangeDn, entry.LegacyExchangeDn,
                    StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("The native task assigner stack has a conflicting Exchange directory identity.");
            addresses.Add(smtp[0]);
        }
        return addresses;
    }

    private static bool AddressesMatch(IReadOnlyList<string> actual, IReadOnlyList<string> expected) =>
        actual.Count == expected.Count
        && actual.Zip(expected)
            .All(pair => string.Equals(NormalizeAddress(pair.First), NormalizeAddress(pair.Second),
                StringComparison.OrdinalIgnoreCase));

    private async Task<string> ResolveUniqueNativeMailboxAsync(
        string mailbox,
        string query,
        CancellationToken cancellationToken)
    {
        var resolutions = await ResolveDirectoryAsync(mailbox, query, 2, cancellationToken)
            .ConfigureAwait(false);
        if (resolutions.Count != 1)
            throw new InvalidOperationException("The native task owner directory lookup was ambiguous.");
        var matches = resolutions
            .Where(value => string.Equals(value.RoutingType, "SMTP", StringComparison.OrdinalIgnoreCase)
                && !string.IsNullOrWhiteSpace(value.EmailAddress)
                && (string.Equals(value.DisplayName, query, StringComparison.OrdinalIgnoreCase)
                    || string.Equals(value.EmailAddress, query, StringComparison.OrdinalIgnoreCase)
                    || string.Equals(value.EmailAddress?.Split('@')[0], query, StringComparison.OrdinalIgnoreCase)))
            .Select(value => NormalizeAddress(value.EmailAddress!))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        if (matches.Length != 1)
            throw new InvalidOperationException("The native task owner does not resolve to one exact SMTP mailbox.");
        return matches[0];
    }

    private static void NormalizeNativeDeclineAssignerStack(XElement taskElement)
    {
        var property = taskElement.Elements(T + "ExtendedProperty").FirstOrDefault(value =>
        {
            var uri = value.Element(T + "ExtendedFieldURI");
            return uri is not null
                && string.Equals((string?)uri.Attribute("PropertySetId"), TaskPropertySet, StringComparison.OrdinalIgnoreCase)
                && PropertyIdEquals((string?)uri.Attribute("PropertyId"), "0x8117")
                && string.Equals((string?)uri.Attribute("PropertyType"), "Binary", StringComparison.OrdinalIgnoreCase);
        });
        var stack = property?.Element(T + "Value")?.Value;
        if (string.IsNullOrWhiteSpace(stack)) return;
        try
        {
            _ = TaskAssignerStack.Parse(stack);
        }
        catch (InvalidOperationException)
        {
            // The native decline shape is already bound to the authenticated
            // message and matching GlobalId.  Validate exactly one complete
            // trailing entry, then retain the declared bytes unchanged.
            property!.Element(T + "Value")!.Value =
                TaskAssignerStack.TrimSingleTrailingEntry(stack);
        }
    }

    private static EwsTask BuildTaskProcessPreview(
        EwsTask local,
        EwsTaskAssignmentMessage request,
        EwsTask incoming,
        string mailbox,
        bool watcherRequest,
        DateTimeOffset actionTimeUtc)
    {
        var localInfo = local.Assignment
            ?? throw new InvalidOperationException("The matching local task has no native assignment state.");
        var incomingInfo = incoming.Assignment
            ?? throw new InvalidOperationException("The native task response has no assignment state.");
        var isBaseWatcherRequest = watcherRequest
            && request.ItemClass.Equals("IPM.TaskRequest", StringComparison.OrdinalIgnoreCase);
        var isDecline = request.ItemClass.Equals("IPM.TaskRequest.Decline", StringComparison.OrdinalIgnoreCase);
        var isNativeHandoff = IsNativeOutlookReassignmentUpdate(request);
        var owner = isBaseWatcherRequest ? NormalizeAddress(request.ToRecipients[0])
            : isNativeHandoff ? incomingInfo.OwnerAddress ?? incomingInfo.AssigneeAddress
            : localInfo.OwnerAddress ?? localInfo.AssigneeAddress;
        var assignee = isBaseWatcherRequest ? NormalizeAddress(request.ToRecipients[0])
            : isNativeHandoff ? incomingInfo.AssigneeAddress ?? incomingInfo.OwnerAddress
            : localInfo.AssigneeAddress;
        var assigner = isBaseWatcherRequest || isNativeHandoff ? request.Sender
            : localInfo.AssignerAddress ?? request.Sender;
        var assignment = incomingInfo with
        {
            RequestId = localInfo.RequestId ?? request.Id,
            RequestChangeKey = localInfo.RequestChangeKey ?? request.ChangeKey,
            GlobalTaskId = localInfo.GlobalTaskId ?? incomingInfo.GlobalTaskId,
            AssignerAddress = assigner,
            AssigneeAddress = assignee,
            OwnerAddress = owner,
            State = isDecline ? 4 : 3,
            Ownership = 1,
            AcceptanceState = isDecline ? 3 : isBaseWatcherRequest || isNativeHandoff ? 1 : 2,
            Accepted = true,
            UpdatesEnabled = localInfo.UpdatesEnabled ?? incomingInfo.UpdatesEnabled,
            CompletionReportEnabled = localInfo.CompletionReportEnabled ?? incomingInfo.CompletionReportEnabled,
            AssignerChainAddresses = MergeAssignerAddresses(
                localInfo.AssignerChainAddresses,
                isBaseWatcherRequest && localInfo.AssignerAddress is not null
                    ? new[] { localInfo.AssignerAddress } : null,
                incomingInfo.AssignerChainAddresses,
                request.CcRecipients),
            LastUserName = request.Sender ?? localInfo.LastUserName ?? mailbox,
            LastDelegateName = request.Sender ?? localInfo.LastDelegateName ?? mailbox,
            LastUpdateUtc = incomingInfo.LastUpdateUtc ?? actionTimeUtc
        };
        return incoming with
        {
            Id = local.Id,
            ChangeKey = local.ChangeKey,
            Assignment = assignment
        };
    }

    private static XElement BuildTaskProcessUpdateOperation(
        EwsTask local,
        EwsTask desired,
        string itemClass,
        DateTimeOffset actionTimeUtc)
    {
        var desiredInfo = desired.Assignment
            ?? throw new InvalidOperationException("The native task response has no assignment state.");
        var updates = new XElement(T + "Updates");
        AddTaskField(updates, "item:Subject", desired.Subject, "Subject");
        AddTaskField(updates, "item:Body", desired.Body, "Body", "Item", desired.BodyType);
        AddTaskField(updates, "task:StartDate", desired.StartDateUtc, "StartDate");
        AddTaskField(updates, "task:DueDate", desired.DueDateUtc, "DueDate");
        AddTaskField(updates, "task:CompleteDate", desired.CompleteDateUtc, "CompleteDate");
        AddTaskField(updates, "task:PercentComplete", desired.PercentComplete, "PercentComplete");
        AddTaskField(updates, "task:Status", desired.Status, "Status");
        updates.Add(SetTaskNamedValue(CommonPropertySet, "0x8518", "Integer", "0"));
        updates.Add(SetTaskNamedValue(TaskPropertySet, "0x8129", "Integer",
            (desiredInfo.Ownership ?? 1).ToString(CultureInfo.InvariantCulture)));
        updates.Add(SetTaskNamedValue(TaskPropertySet, "0x812A", "Integer",
            (desiredInfo.AcceptanceState ?? 2).ToString(CultureInfo.InvariantCulture)));
        updates.Add(SetTaskNamedValue(TaskPropertySet, "0x8113", "Integer",
            (desiredInfo.State ?? 3).ToString(CultureInfo.InvariantCulture)));
        updates.Add(SetTaskNamedValue(TaskPropertySet, "0x811A", "Integer",
            itemClass.Equals("IPM.TaskRequest.Decline", StringComparison.OrdinalIgnoreCase) ? "2" : "3"));
        updates.Add(SetTaskNamedValue(TaskPropertySet, "0x8112", "Integer",
            desiredInfo.Version!.Value.ToString(CultureInfo.InvariantCulture)));
        updates.Add(SetTaskNamedValue(TaskPropertySet, "0x8108", "Boolean", "true"));
        var lastUpdate = desiredInfo.LastUpdateUtc ?? actionTimeUtc;
        updates.Add(SetTaskNamedValue(TaskPropertySet, "0x8115", "SystemTime",
            FormatTaskSystemTime(lastUpdate)));
        // Response processing targets the sender tracker copy; clear receiver-only PidLidTaskAssigner.
        updates.Add(new XElement(T + "DeleteItemField",
            NamedField(TaskPropertySet, "0x8121", "String")));
        var owner = desiredInfo.OwnerAddress ?? desiredInfo.AssigneeAddress ?? desiredInfo.OwnerName;
        if (owner is { Length: > 0 })
            updates.Add(SetTaskNamedValue(TaskPropertySet, "0x811F", "String", owner));
        if (desiredInfo.AssignerStackBase64 is { Length: > 0 } stack)
            updates.Add(SetTaskNamedValue(TaskPropertySet, "0x8117", "Binary", stack));
        var incomingAddresses = SerializeAssignerAddresses(
            MergeAssignerAddresses(desiredInfo.AssignerChainAddresses));
        if (incomingAddresses is not null)
            updates.Add(SetTaskNamedNameValue(McpTaskPropertySet, AssignerAddressesPropertyName, "String", incomingAddresses));
        AddAddressUpdate(updates, AssignerAddressPropertyName, desiredInfo.AssignerAddress);
        AddAddressUpdate(updates, AssigneeAddressPropertyName, desiredInfo.AssigneeAddress);
        AddAddressUpdate(updates, OwnerAddressPropertyName, desiredInfo.OwnerAddress);
        if (desiredInfo.LastUserName is { Length: > 0 } lastUser)
            updates.Add(SetTaskNamedValue(TaskPropertySet, "0x8122", "String", lastUser));
        if (desiredInfo.LastDelegateName is { Length: > 0 } lastDelegate)
            updates.Add(SetTaskNamedValue(TaskPropertySet, "0x8125", "String", lastDelegate));
        updates.Add(SetTaskNamedValue(TaskPropertySet, "0x811B", "Boolean",
            (desiredInfo.UpdatesEnabled ?? false) ? "true" : "false"));
        updates.Add(SetTaskNamedValue(TaskPropertySet, "0x8119", "Boolean",
            (desiredInfo.CompletionReportEnabled ?? false) ? "true" : "false"));
        return new XElement(
            M + "UpdateItem", new XAttribute("ConflictResolution", "NeverOverwrite"),
            new XElement(M + "ItemChanges",
                new XElement(T + "ItemChange", ItemReference(local.Id, local.ChangeKey), updates)));
    }

    public async Task<EwsTaskAssignmentStatus> GetTaskAssignmentStatusAsync(
        string mailbox,
        string taskId,
        CancellationToken cancellationToken)
    {
        var task = await GetTaskAsync(ValidateMailbox(mailbox), ValidateItemId(taskId, "task"), cancellationToken)
            .ConfigureAwait(false);
        var info = task.Assignment;
        return new EwsTaskAssignmentStatus(info?.RequestId, info?.GlobalTaskId,
            info?.AssignerAddress, info?.AssigneeAddress, info?.OwnerAddress,
            task.Status, (int)Math.Round(task.PercentComplete),
            null,
            info is null ? "This is a personal task without native assignment metadata."
                : "Task items have no assignment-message processing status. Check the corresponding request or response message; progress is separate from acceptance.",
            info?.Version, info?.State, info?.Ownership, info?.AcceptanceState,
            info?.AssignerName, info?.OwnerName, info?.UpdatesEnabled, info?.CompletionReportEnabled,
            info?.Accepted);
    }

    private static XElement AssignmentMessageShape() => new XElement(
        M + "ItemShape",
        new XElement(T + "BaseShape", "IdOnly"),
        new XElement(T + "BodyType", "Best"),
        new XElement(T + "AdditionalProperties",
            Field("item:ItemClass"), Field("item:Subject"), Field("item:Attachments"),
            Field("message:From"), Field("message:Sender"), Field("message:ToRecipients"),
            Field("message:CcRecipients"), Field("message:BccRecipients"),
            Field("item:InternetMessageHeaders"),
            Field("message:IsRead"), ProcessedField(),
            TaskAssignmentFields()));

    private static XElement ProcessedField() => new(T + "ExtendedFieldURI",
        new XAttribute("PropertyTag", "0x7D01"), new XAttribute("PropertyType", "Boolean"));

    private static bool ReadProcessed(XElement item)
    {
        var value = item.Elements(T + "ExtendedProperty").FirstOrDefault(property =>
        {
            var uri = property.Element(T + "ExtendedFieldURI");
            return string.Equals((string?)uri?.Attribute("PropertyTag"), "0x7D01", StringComparison.OrdinalIgnoreCase)
                && string.Equals((string?)uri?.Attribute("PropertyType"), "Boolean", StringComparison.OrdinalIgnoreCase);
        })?.Element(T + "Value");
        return ReadBool(value);
    }

    public static bool IsSupportedTaskAssignmentMessageClass(string itemClass) => itemClass is not null
        && (itemClass.Equals("IPM.TaskRequest", StringComparison.OrdinalIgnoreCase)
            || itemClass.Equals("IPM.TaskRequest.Update", StringComparison.OrdinalIgnoreCase)
            || itemClass.Equals("IPM.TaskRequest.Accept", StringComparison.OrdinalIgnoreCase)
            || itemClass.Equals("IPM.TaskRequest.Decline", StringComparison.OrdinalIgnoreCase));

    private static EwsTaskAssignmentMessage? ParseAutomaticTaskAssignmentMessage(XElement message)
    {
        var itemClass = message.Element(T + "ItemClass")?.Value ?? string.Empty;
        if (!IsSupportedTaskAssignmentMessageClass(itemClass)) return null;
        try { return ParseTaskAssignmentMessage(message); }
        catch (Exception exception) when (exception is InvalidOperationException or ArgumentException or FormatException)
        {
            var itemId = message.Element(T + "ItemId");
            var id = (string?)itemId?.Attribute("Id");
            if (string.IsNullOrWhiteSpace(id) || id.Length > 4096) return null;
            return new EwsTaskAssignmentMessage(id, (string?)itemId?.Attribute("ChangeKey") ?? string.Empty,
                itemClass, string.Empty, null, null, [], false, null, null, false, false);
        }
    }

    private static XElement TaskAssignmentClassRestriction() => new XElement(T + "Or",
        Equal("item:ItemClass", "IPM.TaskRequest"),
        Equal("item:ItemClass", "IPM.TaskRequest.Update"),
        Equal("item:ItemClass", "IPM.TaskRequest.Accept"),
        Equal("item:ItemClass", "IPM.TaskRequest.Decline"));

    private static XElement BuildTaskSendOperation(
        EwsTask task,
        string recipient,
        string sender,
        string itemClass,
        bool keepUpdated,
        bool completionReport)
    {
        var globalTaskId = ValidateGlobalTaskId(task.Assignment?.GlobalTaskId)
            ?? throw new InvalidOperationException(
                "Native task communication requires a verified PidLidTaskGlobalId.");
        var ccRecipients = task.Assignment?.AssignerChainAddresses?
            .Where(address => !string.Equals(address, recipient, StringComparison.OrdinalIgnoreCase)
                && !string.Equals(address, sender, StringComparison.OrdinalIgnoreCase))
            .Distinct(StringComparer.OrdinalIgnoreCase).ToArray()
            ?? Array.Empty<string>();
        var subjectPrefix = itemClass switch
        {
            "IPM.TaskRequest" => "Task Request: ",
            "IPM.TaskRequest.Accept" => "Task Accepted: ",
            "IPM.TaskRequest.Decline" => "Task Declined: ",
            _ => "Task Update: "
        };
        var message = new XElement(
            T + "Message",
            new XElement(T + "ItemClass", itemClass),
            new XElement(T + "Subject", subjectPrefix + task.Subject),
            new XElement(T + "Body", new XAttribute("BodyType", "Text"),
                completionReport ? "Task completion report." : keepUpdated ? "Task update." : "Task assignment."),
            // ItemType places Attachments before the extended-property bag.
            // Exchange 2019 rejects the otherwise tempting property-first
            // order when an embedded task is present.
            new XElement(T + "Attachments", BuildTaskAttachment(task, itemClass, keepUpdated, completionReport)),
            new XElement(T + "ExtendedProperty",
                new XElement(T + "ExtendedFieldURI", new XAttribute("PropertyTag", "0x1080"),
                    new XAttribute("PropertyType", "Integer")),
                new XElement(T + "Value", "-1")),
            new XElement(T + "ExtendedProperty",
                NamedField(CommonPropertySet, "0x8518", "Integer"),
                new XElement(T + "Value", TaskCommunicationMode(itemClass).ToString(CultureInfo.InvariantCulture))),
            new XElement(T + "ExtendedProperty",
                NamedField(CommonPropertySet, "0x8519", "Binary"),
                new XElement(T + "Value", globalTaskId)),
            new XElement(T + "ExtendedProperty",
                NamedField(TaskPropertySet, "0x8112", "Integer"),
                new XElement(T + "Value", Math.Max(1, task.Assignment?.Version ?? 1)
                    .ToString(CultureInfo.InvariantCulture))),
            new XElement(T + "ExtendedProperty",
                NamedField(TaskPropertySet, "0x811B", "Boolean"),
                new XElement(T + "Value", keepUpdated ? "true" : "false")),
            new XElement(T + "ExtendedProperty",
                NamedField(TaskPropertySet, "0x8119", "Boolean"),
                new XElement(T + "Value", completionReport ? "true" : "false")),
            new XElement(T + "ExtendedProperty",
                new XElement(T + "ExtendedFieldURI", new XAttribute("PropertyTag", "0x7D01"),
                    new XAttribute("PropertyType", "Boolean")),
                new XElement(T + "Value", "false")),
            new XElement(T + "ToRecipients", MailboxElement(recipient)),
            ccRecipients.Length == 0 ? null : RecipientsElement("CcRecipients", ccRecipients),
            new XElement(T + "From", MailboxElement(sender)));
        return new XElement(M + "CreateItem", new XAttribute("MessageDisposition", "SendAndSaveCopy"),
            new XElement(M + "SavedItemFolderId", PeopleTasksFolderReference("sentitems")),
            new XElement(M + "Items", message));
    }

    private static int TaskCommunicationMode(string itemClass) => itemClass switch
    {
        "IPM.TaskRequest" => 1,
        "IPM.TaskRequest.Accept" => 2,
        "IPM.TaskRequest.Decline" => 3,
        "IPM.TaskRequest.Update" => 4,
        _ => throw new ArgumentException("Unsupported native task communication class.", nameof(itemClass))
    };

    private static XElement BuildTaskAttachment(EwsTask task, string itemClass, bool keepUpdated, bool completionReport) => new XElement(
        T + "ItemAttachment",
        new XElement(T + "Name", task.Subject),
        // EWS accepts the strongly typed Task child directly.  The generic
        // Item wrapper is a response shape and is rejected by some 2019 builds.
        BuildDetachedTask(task, itemClass, keepUpdated, completionReport));

    private static XElement BuildDetachedTask(
        EwsTask task,
        string? itemClass = null,
        bool keepUpdated = false,
        bool completionReport = false)
    {
        var input = new EwsTaskInput(task.Subject, task.Body, task.BodyType, task.StartDateUtc,
            task.DueDateUtc, task.CompleteDateUtc, task.PercentComplete, task.Status, task.Priority,
            task.ReminderIsSet, task.ReminderDueByUtc, task.Categories, task.Recurrence);
        var detached = BuildTask(input);
        detached.AddFirst(new XElement(T + "ItemClass", "IPM.Task"));
        AddTaskAttachmentElements(detached, task);
        var extendedProperties = new List<XElement>();
        if (task.Assignment?.GlobalTaskId is { Length: > 0 } globalId)
            extendedProperties.Add(NamedValue(CommonPropertySet, "0x8519", "Binary", globalId));
        if (task.Assignment?.AssignerStackBase64 is { Length: > 0 } assignerStack)
            extendedProperties.Add(NamedValue(TaskPropertySet, "0x8117", "Binary", assignerStack));
        var assignerAddresses = SerializeAssignerAddresses(task.Assignment?.AssignerChainAddresses);
        if (assignerAddresses is not null)
            extendedProperties.Add(NamedNameValue(McpTaskPropertySet, AssignerAddressesPropertyName, "String", assignerAddresses));
        AddAddressProperty(extendedProperties, AssignerAddressPropertyName, task.Assignment?.AssignerAddress);
        AddAddressProperty(extendedProperties, AssigneeAddressPropertyName, task.Assignment?.AssigneeAddress);
        AddAddressProperty(extendedProperties, OwnerAddressPropertyName, task.Assignment?.OwnerAddress);
        var assigner = task.Assignment?.AssignerAddress ?? task.Assignment?.AssignerName;
        if ((itemClass is null
                || !itemClass.Equals("IPM.TaskRequest", StringComparison.OrdinalIgnoreCase))
            && assigner is { Length: > 0 })
            extendedProperties.Add(NamedValue(TaskPropertySet, "0x8121", "String", assigner));
        var owner = task.Assignment?.OwnerAddress ?? task.Assignment?.AssigneeAddress ?? task.Assignment?.OwnerName;
        if (owner is { Length: > 0 })
            extendedProperties.Add(NamedValue(TaskPropertySet, "0x811F", "String", owner));
        if (task.Assignment?.LastUserName is { Length: > 0 } lastUser)
            extendedProperties.Add(NamedValue(TaskPropertySet, "0x8122", "String", lastUser));
        if (task.Assignment?.LastDelegateName is { Length: > 0 } lastDelegate)
            extendedProperties.Add(NamedValue(TaskPropertySet, "0x8125", "String", lastDelegate));
        if (itemClass is not null && itemClass.StartsWith("IPM.TaskRequest", StringComparison.OrdinalIgnoreCase))
        {
            var isRequest = itemClass.Equals("IPM.TaskRequest", StringComparison.OrdinalIgnoreCase);
            var isAccept = itemClass.Equals("IPM.TaskRequest.Accept", StringComparison.OrdinalIgnoreCase);
            var isDecline = itemClass.Equals("IPM.TaskRequest.Decline", StringComparison.OrdinalIgnoreCase);
            // Outlook carries the communication mode on both the outer
            // message and its embedded Task item.  The locally accepted copy
            // uses mode zero below; native request/response payloads retain
            // their communication class mode for Outlook UI interoperability.
            extendedProperties.Add(NamedValue(CommonPropertySet, "0x8518", "Integer",
                TaskCommunicationMode(itemClass).ToString(CultureInfo.InvariantCulture)));
            var ownership = isRequest ? 1 : 2;
            var acceptance = isRequest ? 1 : isDecline ? 3 : isAccept ? 2 : 0;
            var state = isRequest ? 3 : isDecline ? 4 : 2;
            var history = isRequest ? 5 : isDecline ? 2 : isAccept ? 1 : 3;
            // Native Outlook task messages clear the unsent flag and carry
            // the task icon on the detached communication item.  IsDraft is
            // a read-only EWS property and must not be written here.
            extendedProperties.Add(TaggedValue("0x0E07", "Integer", "1"));
            extendedProperties.Add(TaggedValue("0x1080", "Integer", "1283"));
            extendedProperties.Add(NamedValue(TaskPropertySet, "0x8129", "Integer", ownership.ToString(CultureInfo.InvariantCulture)));
            extendedProperties.Add(NamedValue(TaskPropertySet, "0x812A", "Integer", acceptance.ToString(CultureInfo.InvariantCulture)));
            extendedProperties.Add(NamedValue(TaskPropertySet, "0x8113", "Integer", state.ToString(CultureInfo.InvariantCulture)));
            extendedProperties.Add(NamedValue(TaskPropertySet, "0x811A", "Integer", history.ToString(CultureInfo.InvariantCulture)));
            extendedProperties.Add(NamedValue(TaskPropertySet, "0x8112", "Integer",
                Math.Max(1, task.Assignment?.Version ?? 1).ToString(CultureInfo.InvariantCulture)));
            extendedProperties.Add(NamedValue(TaskPropertySet, "0x8108", "Boolean", isRequest ? "false" : "true"));
            // The embedded task is the durable copy.  Responses and updates
            // must carry the original request's reporting preferences instead
            // of silently resetting them while the outer communication uses
            // its own delivery flags.
            var updatesEnabled = task.Assignment?.UpdatesEnabled ?? (isRequest && keepUpdated);
            var statusOnComplete = task.Assignment?.CompletionReportEnabled ?? (isRequest && completionReport);
            extendedProperties.Add(NamedValue(TaskPropertySet, "0x811B", "Boolean", updatesEnabled ? "true" : "false"));
            extendedProperties.Add(NamedValue(TaskPropertySet, "0x8119", "Boolean", statusOnComplete ? "true" : "false"));
            var lastUpdate = task.Assignment?.LastUpdateUtc ?? DateTimeOffset.UtcNow;
            extendedProperties.Add(NamedValue(TaskPropertySet, "0x8115", "SystemTime",
                FormatTaskSystemTime(lastUpdate)));
        }
        InsertTaskExtendedProperties(detached, extendedProperties);
        return detached;
    }

    private static void AddTaskAttachmentElements(XElement taskElement, EwsTask task)
    {
        var contents = task.AttachmentContents ?? Array.Empty<EwsAttachmentContent>();
        if (contents.Count == 0) return;
        ValidateTaskAttachmentSnapshot(task);
        var body = taskElement.Element(T + "Body");
        var attachments = new XElement(T + "Attachments", contents.Select(content =>
            new XElement(T + "FileAttachment",
                new XElement(T + "Name", content.Name),
                content.ContentType is null ? null : new XElement(T + "ContentType", content.ContentType),
                content.ContentId is null ? null : new XElement(T + "ContentId", content.ContentId),
                new XElement(T + "Size", content.Content.Length.ToString(CultureInfo.InvariantCulture)),
                new XElement(T + "IsInline", content.IsInline),
                new XElement(T + "Content", Convert.ToBase64String(content.Content)))));
        if (body is not null)
        {
            body.AddAfterSelf(attachments);
            return;
        }

        var subject = taskElement.Element(T + "Subject");
        if (subject is not null) subject.AddAfterSelf(attachments);
        else taskElement.Add(attachments);
    }

    private static XElement BuildLocallyAcceptedTask(EwsTask task)
    {
        var detached = BuildDetachedTask(task);
        InsertTaskExtendedProperties(detached,
        [
            NamedValue(CommonPropertySet, "0x8518", "Integer", "0"),
            NamedValue(TaskPropertySet, "0x8129", "Integer", "2"),
            NamedValue(TaskPropertySet, "0x812A", "Integer", "0"),
            NamedValue(TaskPropertySet, "0x8113", "Integer", "2"),
            NamedValue(TaskPropertySet, "0x811A", "Integer", "1"),
            NamedValue(TaskPropertySet, "0x8112", "Integer",
                Math.Max(1, task.Assignment?.Version ?? 1).ToString(CultureInfo.InvariantCulture)),
            NamedValue(TaskPropertySet, "0x8108", "Boolean", "true"),
            NamedValue(TaskPropertySet, "0x811B", "Boolean",
                (task.Assignment?.UpdatesEnabled ?? false) ? "true" : "false"),
            NamedValue(TaskPropertySet, "0x8119", "Boolean",
                (task.Assignment?.CompletionReportEnabled ?? false) ? "true" : "false"),
        ]);
        var lastUpdate = task.Assignment?.LastUpdateUtc ?? DateTimeOffset.UtcNow;
        InsertTaskExtendedProperties(detached,
        [NamedValue(TaskPropertySet, "0x8115", "SystemTime",
            FormatTaskSystemTime(lastUpdate))]);
        return detached;
    }

    private static void InsertTaskExtendedProperties(XElement task, IEnumerable<XElement> properties)
    {
        var insertionPoint = task.Elements().FirstOrDefault(element =>
            element.Name == T + "CompleteDate" || element.Name == T + "DueDate"
            || element.Name == T + "PercentComplete" || element.Name == T + "Recurrence"
            || element.Name == T + "StartDate" || element.Name == T + "Status");
        foreach (var property in properties)
        {
            if (insertionPoint is null) task.Add(property);
            else insertionPoint.AddBeforeSelf(property);
        }
    }

    private static EwsTaskAction CreateTaskAction(
        string operation,
        string mailbox,
        EwsTask task,
        string? assignee,
        string sourceId,
        XElement payload,
        bool isReassignment,
        double? percentComplete = null,
        string? status = null,
        string? sourceChangeKey = null,
        EwsTask? previewTask = null,
        DateTimeOffset? actionTimeUtc = null,
        string? assigneeOverride = null)
    {
        var planTime = ResolveActionTime(actionTimeUtc);
        var actionAssignee = assigneeOverride ?? assignee;
        var stable = StableTaskCorrelation(mailbox, sourceId, task.Assignment?.GlobalTaskId, operation);
        var payloadText = payload.ToString(SaveOptions.DisableFormatting);
        if (Encoding.UTF8.GetByteCount(payloadText) > TaskAssignmentMaxPayload)
            throw new InvalidOperationException("The native task action payload is too large.");
        var digest = DigestTaskAction(operation, mailbox, sourceId, sourceChangeKey ?? task.ChangeKey,
            stable, task.Subject, task.Assignment?.AssignerAddress, actionAssignee, payloadText,
            task.Assignment?.GlobalTaskId, percentComplete, status, isReassignment, planTime);
        return new EwsTaskAction(operation, mailbox, sourceId, sourceChangeKey ?? task.ChangeKey, stable,
            task.Subject, task.Assignment?.AssignerAddress, actionAssignee, payloadText, digest, true,
            task.Assignment?.GlobalTaskId, percentComplete, status, isReassignment, planTime, previewTask ?? task);
    }

    private static string DigestTaskAction(
        string operation, string mailbox, string sourceId, string sourceChangeKey, string stable,
        string? subject, string? assigner, string? assignee, string payload, string? globalId,
        double? percentComplete, string? status, bool isReassignment, DateTimeOffset actionTimeUtc)
    {
        var canonical = string.Join("\n", operation, mailbox, sourceId, sourceChangeKey, stable,
            subject ?? string.Empty, assigner ?? string.Empty, assignee ?? string.Empty, payload,
            globalId ?? string.Empty, percentComplete?.ToString("R", CultureInfo.InvariantCulture) ?? string.Empty,
            status ?? string.Empty, isReassignment ? "1" : "0",
            actionTimeUtc.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture));
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical))).ToLowerInvariant();
    }

    private static DateTimeOffset ResolveActionTime(DateTimeOffset? actionTimeUtc) =>
        (actionTimeUtc ?? DateTimeOffset.UtcNow).ToUniversalTime();

    // Match the EWS Managed API's UTC millisecond format for native task SystemTime values.
    private static string FormatTaskSystemTime(DateTimeOffset value) =>
        value.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ", CultureInfo.InvariantCulture);

    private static string StableTaskCorrelation(string mailbox, string sourceId, string? globalId, string operation) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(
            string.Join("\n", mailbox, sourceId, globalId ?? string.Empty, operation)))).ToLowerInvariant();


    private static EwsTaskAssignmentMessage ParseTaskAssignmentMessage(XElement message)
    {
        var id = message.Element(T + "ItemId")
            ?? throw new InvalidOperationException("Exchange returned a task request without an identifier.");
        var itemId = (string?)id.Attribute("Id");
        if (string.IsNullOrWhiteSpace(itemId)) throw new InvalidOperationException("Exchange returned a task request without an identifier.");
        var from = ParseSingleRecipient(message.Element(T + "From"));
        var sender = ParseSingleRecipient(message.Element(T + "Sender"));
        var recipients = ParseTaskRecipients(message.Element(T + "ToRecipients"));
        var ccRecipients = ParseTaskRecipients(message.Element(T + "CcRecipients"));
        var bccRecipients = ParseTaskRecipients(message.Element(T + "BccRecipients"));
        var internalAuthenticated = HasInternalExchangeAuth(message);
        var global = ReadExtendedValue(message, CommonPropertySet, "0x8519", "Binary");
        global = ValidateGlobalTaskId(global);
        var version = ReadTaskInteger(message, TaskPropertySet, "0x8112");
        var mode = ReadTaskInteger(message, CommonPropertySet, "0x8518");
        ValidateTaskMetadata(version, mode, null, null, null);
        var itemClass = message.Element(T + "ItemClass")?.Value ?? string.Empty;
        return new EwsTaskAssignmentMessage(itemId, (string?)id.Attribute("ChangeKey") ?? string.Empty,
            itemClass, message.Element(T + "Subject")?.Value ?? string.Empty, from, sender, recipients,
            ReadBool(message.Element(T + "IsRead")), global, null,
            ReadProcessed(message),
            itemClass.EndsWith(".Update", StringComparison.OrdinalIgnoreCase), version, mode,
            ccRecipients, bccRecipients, internalAuthenticated);
    }

    private static EwsTask ParseDetachedTask(XElement taskElement, string fallbackId, string fallbackChangeKey)
    {
        var clone = new XElement(taskElement);
        var itemId = clone.Element(T + "ItemId");
        if (itemId is null)
            clone.AddFirst(new XElement(T + "ItemId", new XAttribute("Id", fallbackId), new XAttribute("ChangeKey", fallbackChangeKey)));
        return ParseTask(clone);
    }

    private static EwsTaskAssignmentInfo? ParseTaskAssignment(XElement item)
    {
        var global = ReadExtendedValue(item, CommonPropertySet, "0x8519", "Binary");
        var mode = ReadTaskInteger(item, CommonPropertySet, "0x8518");
        var state = ReadTaskInteger(item, TaskPropertySet, "0x8113");
        var ownership = ReadTaskInteger(item, TaskPropertySet, "0x8129");
        var accepted = ReadTaskInteger(item, TaskPropertySet, "0x812A");
        var acceptedFlag = ReadExtendedBool(item, TaskPropertySet, "0x8108");
        var history = ReadTaskInteger(item, TaskPropertySet, "0x811A");
        var version = ReadTaskInteger(item, TaskPropertySet, "0x8112");
        var assignerName = ReadExtendedValue(item, TaskPropertySet, "0x8121", "String");
        var ownerName = ReadExtendedValue(item, TaskPropertySet, "0x811F", "String");
        var lastUserName = ReadExtendedValue(item, TaskPropertySet, "0x8122", "String");
        var lastDelegateName = ReadExtendedValue(item, TaskPropertySet, "0x8125", "String");
        var updates = ReadExtendedBool(item, TaskPropertySet, "0x811B");
        var completionReport = ReadExtendedBool(item, TaskPropertySet, "0x8119");
        var assignerStack = ReadExtendedValue(item, TaskPropertySet, "0x8117", "Binary");
        if (assignerStack is not null)
            _ = TaskAssignerStack.Parse(assignerStack);
        var assignerAddresses = ParseAssignerAddresses(
            ReadNamedValue(item, McpTaskPropertySet, AssignerAddressesPropertyName, "String"));
        var assignerAddress = ParseOptionalAddress(
            ReadNamedValue(item, McpTaskPropertySet, AssignerAddressPropertyName, "String"));
        var assigneeAddress = ParseOptionalAddress(
            ReadNamedValue(item, McpTaskPropertySet, AssigneeAddressPropertyName, "String"));
        var ownerAddress = ParseOptionalAddress(
            ReadNamedValue(item, McpTaskPropertySet, OwnerAddressPropertyName, "String"));
        var lastUpdateText = ReadExtendedValue(item, TaskPropertySet, "0x8115", "SystemTime");
        DateTimeOffset? lastUpdate = null;
        if (lastUpdateText is not null)
        {
            if (!DateTimeOffset.TryParse(lastUpdateText, CultureInfo.InvariantCulture,
                    DateTimeStyles.RoundtripKind, out var parsedLastUpdate))
                throw new InvalidOperationException("Exchange returned a malformed task last-update time.");
            lastUpdate = parsedLastUpdate.ToUniversalTime();
        }
        global = ValidateGlobalTaskId(global);
        ValidateTaskMetadata(version, mode, state, ownership, accepted);
        if (global is null && mode is null && state is null && ownership is null && accepted is null && history is null
            && assignerAddresses.Count == 0)
            return null;
        return new EwsTaskAssignmentInfo(null, null, global, assignerAddress, assigneeAddress, ownerAddress,
            item.Element(T + "Status")?.Value, null, null, false,
            version, state, ownership, accepted, assignerName, ownerName, updates, completionReport,
            assignerStack, lastUpdate, assignerAddresses, lastUserName, lastDelegateName, acceptedFlag, mode);
    }

    private static string? ReadExtendedValue(XElement item, string propertySet, string propertyId, string propertyType)
    {
        var property = item.Elements(T + "ExtendedProperty").FirstOrDefault(value =>
        {
            var uri = value.Element(T + "ExtendedFieldURI");
            return uri is not null && string.Equals((string?)uri.Attribute("PropertySetId"), propertySet, StringComparison.OrdinalIgnoreCase)
                && PropertyIdEquals((string?)uri.Attribute("PropertyId"), propertyId)
                && string.Equals((string?)uri.Attribute("PropertyType"), propertyType, StringComparison.OrdinalIgnoreCase);
        });
        var text = property?.Element(T + "Value")?.Value;
        if (string.IsNullOrWhiteSpace(text)) return null;
        if (propertyType == "Binary")
        {
            try { return Convert.ToBase64String(Convert.FromBase64String(text)); }
            catch (FormatException) { throw new InvalidOperationException("Exchange returned an invalid task identifier."); }
        }
        return text;
    }

    private static string? ReadNamedValue(XElement item, string propertySet, string propertyName, string propertyType)
    {
        var property = item.Elements(T + "ExtendedProperty").FirstOrDefault(value =>
        {
            var uri = value.Element(T + "ExtendedFieldURI");
            return uri is not null && string.Equals((string?)uri.Attribute("PropertySetId"), propertySet, StringComparison.OrdinalIgnoreCase)
                && string.Equals((string?)uri.Attribute("PropertyName"), propertyName, StringComparison.Ordinal)
                && string.Equals((string?)uri.Attribute("PropertyType"), propertyType, StringComparison.OrdinalIgnoreCase);
        });
        var text = property?.Element(T + "Value")?.Value;
        return string.IsNullOrWhiteSpace(text) ? null : text;
    }

    private static int? ReadTaskInteger(XElement item, string propertySet, string propertyId)
    {
        var text = ReadExtendedValue(item, propertySet, propertyId, "Integer");
        if (text is null) return null;
        if (string.Equals(propertySet, TaskPropertySet, StringComparison.OrdinalIgnoreCase)
            && PropertyIdEquals(propertyId, "0x812A"))
        {
            return text switch
            {
                "NoMatch" => 0,
                "OwnNew" => 1,
                "Owned" => 2,
                "Accepted" => 3,
                _ when int.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out var numeric)
                    && numeric is >= 0 and <= 3 => numeric,
                _ => throw new InvalidOperationException(
                    "Exchange returned an invalid native task acceptance state.")
            };
        }
        if (!int.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out var value))
            throw new InvalidOperationException("Exchange returned a malformed native task integer.");
        return value;
    }

    private static string? ValidateGlobalTaskId(string? value)
    {
        if (value is null) return null;
        try
        {
            if (Convert.FromBase64String(value).Length != 16)
                throw new InvalidOperationException("Native task GlobalId must be exactly 16 bytes.");
        }
        catch (FormatException)
        {
            throw new InvalidOperationException("Exchange returned a malformed native task GlobalId.");
        }
        return value;
    }

    private static void ValidateTaskMetadata(int? version, int? mode, int? state, int? ownership, int? acceptance)
    {
        if (version is <= 0) throw new InvalidOperationException("Exchange returned an invalid native task version.");
        if (mode is < 0 or > 5) throw new InvalidOperationException("Exchange returned an invalid native task mode.");
        if (state is < 0 or > 4) throw new InvalidOperationException("Exchange returned an invalid native task state.");
        if (ownership is < 0 or > 2)
            throw new InvalidOperationException("Exchange returned an invalid native task ownership.");
        if (acceptance is < 0 or > 3)
            throw new InvalidOperationException("Exchange returned an invalid native task acceptance state.");
    }

    private static bool PropertyIdEquals(string? actual, string expected)
    {
        if (string.Equals(actual, expected, StringComparison.OrdinalIgnoreCase)) return true;
        if (actual is null || !expected.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
            || !int.TryParse(expected[2..], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var expectedNumber)
            || !int.TryParse(actual, NumberStyles.Integer, CultureInfo.InvariantCulture, out var actualNumber))
            return false;
        return actualNumber == expectedNumber;
    }

    private static bool? ReadExtendedBool(XElement item, string propertySet, string propertyId)
    {
        var text = ReadExtendedValue(item, propertySet, propertyId, "Boolean");
        if (text is null) return null;
        try { return XmlConvert.ToBoolean(text); }
        catch (FormatException) { throw new InvalidOperationException("Exchange returned a malformed task boolean."); }
    }

    private static XElement NamedField(string propertySet, string propertyId, string propertyType)
    {
        // EWS declares PropertyId as xs:int when PropertySetId is present.
        // Keep the source constants in canonical hexadecimal form for
        // readability, but emit the wire value as the required decimal int.
        var wireId = propertyId.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
            && int.TryParse(propertyId[2..], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var numericId)
            ? numericId.ToString(CultureInfo.InvariantCulture)
            : propertyId;
        return new XElement(T + "ExtendedFieldURI", new XAttribute("PropertySetId", propertySet),
            new XAttribute("PropertyId", wireId), new XAttribute("PropertyType", propertyType));
    }

    private static XElement NamedNameField(string propertySet, string propertyName, string propertyType) =>
        new(T + "ExtendedFieldURI", new XAttribute("PropertySetId", propertySet),
            new XAttribute("PropertyName", propertyName), new XAttribute("PropertyType", propertyType));

    private static XElement NamedValue(string propertySet, string propertyId, string propertyType, string value)
    {
        var wireValue = string.Equals(propertySet, TaskPropertySet, StringComparison.OrdinalIgnoreCase)
            && PropertyIdEquals(propertyId, "0x812A")
            && string.Equals(propertyType, "Integer", StringComparison.OrdinalIgnoreCase)
            ? SerializeTaskAcceptanceState(value)
            : value;
        return new XElement(T + "ExtendedProperty", NamedField(propertySet, propertyId, propertyType),
            new XElement(T + "Value", wireValue));
    }

    private static XElement TaggedValue(string propertyTag, string propertyType, string value) =>
        new(T + "ExtendedProperty",
            new XElement(T + "ExtendedFieldURI", new XAttribute("PropertyTag", propertyTag),
                new XAttribute("PropertyType", propertyType)),
            new XElement(T + "Value", value));

    private static string SerializeTaskAcceptanceState(string value)
    {
        if (!int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var numeric)
            || numeric is < 0 or > 3)
            throw new InvalidOperationException("Native task acceptance state must be an integer from 0 through 3.");
        return numeric switch
        {
            0 => "NoMatch",
            1 => "OwnNew",
            2 => "Owned",
            3 => "Accepted",
            _ => throw new InvalidOperationException("Native task acceptance state was outside the supported range.")
        };
    }

    private static XElement NamedNameValue(string propertySet, string propertyName, string propertyType, string value) =>
        new(T + "ExtendedProperty", NamedNameField(propertySet, propertyName, propertyType), new XElement(T + "Value", value));

    private static string? ParseSingleRecipient(XElement? parent) =>
        parent?.Element(T + "Mailbox")?.Element(T + "EmailAddress")?.Value;

    private static IReadOnlyList<string> ParseTaskRecipients(XElement? parent) =>
        parent?.Elements(T + "Mailbox").Select(value => value.Element(T + "EmailAddress")?.Value)
            .Where(value => !string.IsNullOrWhiteSpace(value)).Select(value => value!).ToArray()
        ?? Array.Empty<string>();

    private static IReadOnlyList<string> AppendAssignerAddress(
        IReadOnlyList<string> existing,
        string address)
    {
        var normalized = NormalizeAddress(address);
        var result = existing
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Select(NormalizeAddress)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
        if (!result.Contains(normalized, StringComparer.OrdinalIgnoreCase))
            result.Add(normalized);
        if (result.Count > MaxAssignerAddresses)
            throw new InvalidOperationException("The native task assigner watcher chain exceeds the supported bound.");
        return result;
    }

    private static IReadOnlyList<string> MergeAssignerAddresses(
        params IReadOnlyList<string>?[] lists)
    {
        IReadOnlyList<string> result = Array.Empty<string>();
        foreach (var list in lists)
            foreach (var address in list ?? Array.Empty<string>())
                result = AppendAssignerAddress(result, address);
        return result;
    }

    private static void AddAddressUpdate(XElement updates, string propertyName, string? address)
    {
        if (!string.IsNullOrWhiteSpace(address))
            updates.Add(SetTaskNamedNameValue(McpTaskPropertySet, propertyName, "String", NormalizeAddress(address)));
    }

    private static string? AppendAssignerStackIfNeeded(string? existing, TaskAssignerEntry entry)
    {
        var entries = TaskAssignerStack.Parse(existing);
        if (entries.Count > 0 && entries[^1].LegacyExchangeDn.Equals(
                entry.LegacyExchangeDn, StringComparison.OrdinalIgnoreCase))
            return existing;
        return TaskAssignerStack.Append(existing, entry);
    }

    private static IReadOnlyList<string> ParseAssignerAddresses(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return Array.Empty<string>();
        var values = value.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (values.Length > MaxAssignerAddresses)
            throw new InvalidOperationException("Exchange returned too many task assigner watcher addresses.");
        return values.Select(NormalizeAddress).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
    }

    private static string? ParseOptionalAddress(string? value) =>
        string.IsNullOrWhiteSpace(value) ? null : NormalizeAddress(value);

    private static string? SerializeAssignerAddresses(IReadOnlyList<string>? values)
    {
        if (values is null || values.Count == 0) return null;
        var normalized = values.Where(value => !string.IsNullOrWhiteSpace(value))
            .Select(NormalizeAddress).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        if (normalized.Length > MaxAssignerAddresses)
            throw new InvalidOperationException("The native task assigner watcher chain exceeds the supported bound.");
        return normalized.Length == 0 ? null : string.Join('\n', normalized);
    }

    private static void AddAddressProperty(List<XElement> properties, string propertyName, string? address)
    {
        if (!string.IsNullOrWhiteSpace(address))
            properties.Add(NamedNameValue(McpTaskPropertySet, propertyName, "String", NormalizeAddress(address)));
    }

    private static bool HasInternalExchangeAuth(XElement message)
    {
        var headers = message.Element(T + "InternetMessageHeaders")?
            .Elements(T + "InternetMessageHeader") ?? Enumerable.Empty<XElement>();
        return headers.Any(header =>
            string.Equals((string?)header.Attribute("HeaderName"),
                "X-MS-Exchange-Organization-AuthAs", StringComparison.OrdinalIgnoreCase)
            && string.Equals(header.Value.Trim(), "Internal", StringComparison.OrdinalIgnoreCase));
    }

    private static void ValidateAssignableTask(EwsTask task)
    {
        if (task.IsRecurring || task.Recurrence is not null)
            throw new InvalidOperationException("Recurring task assignment is not supported safely; assign a single task instance.");
        ValidateTaskAttachmentMetadata(task, task.Attachments ?? Array.Empty<EwsAttachment>());
        ValidateTaskAttachmentSnapshot(task);
        if (string.IsNullOrWhiteSpace(task.Subject))
            throw new InvalidOperationException("A task without a subject cannot be assigned.");
    }

    private static void ValidateTaskAttachmentMetadata(EwsTask task, IReadOnlyList<EwsAttachment> attachments)
    {
        if (task.HasAttachments && attachments.Count == 0)
            throw new InvalidOperationException("The task reports attachments but Exchange returned no attachment metadata.");
        if (attachments.Count > MaxAttachments)
            throw new InvalidOperationException("A task may contain at most 100 file attachments.");
        long totalBytes = 0;
        long estimatedPayloadBytes = 0;
        var ids = new HashSet<string>(StringComparer.Ordinal);
        foreach (var attachment in attachments)
        {
            if (string.IsNullOrWhiteSpace(attachment.Id) || string.IsNullOrWhiteSpace(attachment.Name))
                throw new InvalidOperationException("A task attachment is missing its identifier or name.");
            ValidateAttachmentName(attachment.Name);
            ValidateTaskAttachmentMetadataValue(attachment.ContentType, "content type");
            ValidateTaskAttachmentMetadataValue(attachment.ContentId, "content ID");
            if (!ids.Add(attachment.Id))
                throw new InvalidOperationException("The task contains duplicate attachment identifiers.");
            if (attachment.Size < 0 || attachment.Size > MaxAttachmentBytes)
                throw new InvalidOperationException("A task attachment exceeds the 5 MiB per-file limit.");
            totalBytes += attachment.Size;
            estimatedPayloadBytes += 512L + attachment.Name.Length * 4L
                + (attachment.ContentType?.Length ?? 0) * 4L
                + (attachment.ContentId?.Length ?? 0) * 4L
                + ((attachment.Size + 2L) / 3L) * 4L;
            if (totalBytes > MaxDraftAttachmentBytes || estimatedPayloadBytes > TaskAssignmentMaxPayload)
                throw new InvalidOperationException("Task attachments exceed the native 512 KiB action budget.");
        }
    }

    private static void ValidateTaskAttachmentSnapshot(EwsTask task)
    {
        var attachments = task.Attachments ?? Array.Empty<EwsAttachment>();
        var contents = task.AttachmentContents ?? Array.Empty<EwsAttachmentContent>();
        if (attachments.Count != contents.Count)
            throw new InvalidOperationException("The task attachment snapshot is incomplete.");
        for (var index = 0; index < attachments.Count; index++)
        {
            var metadata = attachments[index];
            var content = contents[index];
            if (!string.Equals(metadata.Id, content.Id, StringComparison.Ordinal)
                || !string.Equals(metadata.Name, content.Name, StringComparison.Ordinal)
                || !string.Equals(metadata.ContentType, content.ContentType, StringComparison.Ordinal)
                || metadata.Size != content.Content.Length
                || metadata.IsInline != content.IsInline
                || !string.Equals(metadata.ContentId, content.ContentId, StringComparison.Ordinal))
                throw new InvalidOperationException("The task attachment snapshot does not match Exchange metadata.");
        }
        if (contents.Sum(content => (long)content.Content.Length) > MaxDraftAttachmentBytes)
            throw new InvalidOperationException("Task attachments exceed the 10 MiB aggregate limit.");
    }

    private static void ValidateTaskAttachmentSnapshots(EwsTask? expected, EwsTask actual)
    {
        if (expected is null)
            throw new InvalidOperationException("The approved task attachment snapshot is missing.");
        ValidateTaskAttachmentSnapshot(expected);
        ValidateTaskAttachmentSnapshot(actual);
        var expectedFiles = expected.AttachmentContents!.Select(TaskAttachmentComparisonKey)
            .OrderBy(value => value, StringComparer.Ordinal).ToArray();
        var actualFiles = actual.AttachmentContents!.Select(TaskAttachmentComparisonKey)
            .OrderBy(value => value, StringComparer.Ordinal).ToArray();
        if (!expectedFiles.SequenceEqual(actualFiles, StringComparer.Ordinal))
            throw new InvalidOperationException("The task attachments changed after approval or do not match the received task.");
    }

    private static string TaskAttachmentComparisonKey(EwsAttachmentContent attachment) => string.Concat(
        AttachmentKeyPart(attachment.Name), AttachmentKeyPart(attachment.ContentType), attachment.IsInline ? "1" : "0",
        AttachmentKeyPart(attachment.ContentId),
        AttachmentKeyPart(Convert.ToHexString(SHA256.HashData(attachment.Content))));

    private static string AttachmentKeyPart(string? value) => $"{value?.Length ?? -1}:{value}";

    private static void ValidateTaskAttachmentMetadataValue(string? value, string label)
    {
        if (value is not null && (value.Length > 255 || value.Any(char.IsControl)))
            throw new ArgumentException($"The task attachment {label} is invalid.", nameof(value));
    }

    private static EwsTask EnsureTaskGlobalId(EwsTask task, string mailbox)
    {
        if (!string.IsNullOrWhiteSpace(task.Assignment?.GlobalTaskId)) return task;
        // Assigned tasks require a 16-byte PidLidTaskGlobalId.  Derive it from
        // stable mailbox/item inputs so approval replay never creates a new ID.
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(mailbox + "\n" + task.Id))[..16];
        var globalId = Convert.ToBase64String(bytes);
        var current = task.Assignment;
        return task with
        {
            Assignment = new EwsTaskAssignmentInfo(current?.RequestId, current?.RequestChangeKey,
                globalId, current?.AssignerAddress, current?.AssigneeAddress, current?.OwnerAddress,
                current?.Status, current?.PercentComplete, current?.IsProcessed,
                current?.IsReassignment ?? false, current?.Version, current?.State,
                current?.Ownership, current?.AcceptanceState, current?.AssignerName,
                current?.OwnerName, current?.UpdatesEnabled, current?.CompletionReportEnabled,
                current?.AssignerStackBase64, current?.LastUpdateUtc,
                current?.AssignerChainAddresses, current?.LastUserName, current?.LastDelegateName,
                current?.Accepted)
        };
    }

    private static void ValidateTaskProgress(double percentComplete, string status)
    {
        if (double.IsNaN(percentComplete) || double.IsInfinity(percentComplete) || percentComplete is < 0 or > 100)
            throw new ArgumentOutOfRangeException(nameof(percentComplete));
        if (status is not ("NotStarted" or "InProgress" or "Completed" or "WaitingOnOthers" or "Deferred"))
            throw new ArgumentException("Unsupported task status.", nameof(status));
        if (status == "NotStarted" && percentComplete != 0)
            throw new ArgumentException("A not-started task must report 0 percent.", nameof(percentComplete));
        if (status == "Completed" && percentComplete != 100)
            throw new ArgumentException("A completed task must report 100 percent.", nameof(percentComplete));
        if (status != "Completed" && percentComplete >= 100)
            throw new ArgumentException("Only a completed task may report 100 percent.", nameof(percentComplete));
    }

    private static bool IsAddress(string? value, string expected) =>
        !string.IsNullOrWhiteSpace(value)
        && string.Equals(NormalizeAddress(value), expected, StringComparison.OrdinalIgnoreCase);

    private static bool HasAssignedRole(EwsTaskAssignmentInfo? assignment) =>
        assignment is not null
        && (assignment.State is 2 or 3 or 4
            || assignment.Ownership is 1 or 2
            || !string.IsNullOrWhiteSpace(assignment.AssignerAddress)
            || !string.IsNullOrWhiteSpace(assignment.AssigneeAddress)
            || !string.IsNullOrWhiteSpace(assignment.OwnerAddress));

    private static void ValidateTaskRequest(EwsTaskAssignmentMessage request, string mailbox)
    {
        if (request.ItemClass is not ("IPM.TaskRequest" or "IPM.TaskRequest.Accept"
            or "IPM.TaskRequest.Decline" or "IPM.TaskRequest.Update"))
            throw new InvalidOperationException("The item is not a native Outlook task request.");
        if (request.IsProcessed)
            throw new InvalidOperationException("The native task request was already processed.");
        if (!request.ToRecipients.Any(value => string.Equals(value, mailbox, StringComparison.OrdinalIgnoreCase)))
            throw new InvalidOperationException("The task request is not addressed to the selected mailbox.");
        if (request.ToRecipients.Count != 1)
            throw new InvalidOperationException("Only a single native task assignee is supported safely.");
        if (request.CcRecipients is { Count: > MaxAssignerAddresses })
            throw new InvalidOperationException("The native task watcher chain exceeds the supported bound.");
        if (request.BccRecipients is { Count: > 0 })
            throw new InvalidOperationException("Native task assignment messages cannot use Bcc recipients.");
        ValidateNativeSender(request, expected: null,
            "The native task request has no trustworthy sender identity.");
        var task = request.Task;
        if (task is null)
            throw new InvalidOperationException("The task request has no embedded task.");
        var assignment = task.Assignment
            ?? throw new InvalidOperationException("The native task request has no task-assignment metadata.");
        if (string.IsNullOrWhiteSpace(assignment.GlobalTaskId))
            throw new InvalidOperationException("The native task request is missing PidLidTaskGlobalId.");
        if (assignment.Version is not > 0)
            throw new InvalidOperationException("The native task request is missing a valid PidLidTaskVersion.");
        if (request.ItemClass.Equals("IPM.TaskRequest", StringComparison.OrdinalIgnoreCase)
            && (assignment.State is not 3 || assignment.Ownership is not 1 || assignment.AcceptanceState is not 1
                || !IsAddress(assignment.AssigneeAddress, NormalizeAddress(request.ToRecipients[0]))))
            throw new InvalidOperationException("The native task request has invalid ownership, acceptance or recipient metadata.");
        if (request.ItemClass.Equals("IPM.TaskRequest.Accept", StringComparison.OrdinalIgnoreCase)
            && (assignment.State is not 2 || assignment.Ownership is not 2
                || assignment.AcceptanceState is not 2 && !IsNativeOutlookAccepted(assignment)))
            throw new InvalidOperationException("The native task acceptance has invalid native ownership or state.");
        if (request.ItemClass.Equals("IPM.TaskRequest.Decline", StringComparison.OrdinalIgnoreCase)
            && !((assignment.State is 4 && assignment.Ownership is 2 && assignment.AcceptanceState is 3)
                || IsNativeOutlookDeclined(assignment)))
            throw new InvalidOperationException("The native task decline has invalid native ownership or state.");
        if (request.ItemClass.Equals("IPM.TaskRequest.Update", StringComparison.OrdinalIgnoreCase)
            && !((assignment.State is 2 && assignment.Ownership is 2
                    && assignment.AcceptanceState is (0 or 2))
                || IsNativeOutlookReassignmentUpdate(request)))
            throw new InvalidOperationException("The native task update has invalid native ownership or state.");
        var expectedMode = request.ItemClass switch
        {
            "IPM.TaskRequest" => 1,
            "IPM.TaskRequest.Accept" => 2,
            "IPM.TaskRequest.Decline" => 3,
            "IPM.TaskRequest.Update" => 4,
            _ => 0
        };
        if (request.Version is not > 0)
            throw new InvalidOperationException("The native task communication is missing a valid PidLidTaskVersion.");
        if (request.Mode != expectedMode)
            throw new InvalidOperationException("The native task request has an invalid PidLidTaskMode.");
        if (request.Version != assignment.Version)
            throw new InvalidOperationException("The native task request has mismatched version metadata.");
    }

    private static void ValidateNativeSender(
        EwsTaskAssignmentMessage message,
        string? expected,
        string error)
    {
        // EWS exposes both From (the claimed author) and Sender (the actual
        // submitting mailbox).  A task response must not be accepted from a
        // From-only value, and an on-behalf mismatch is rejected until the
        // permission reader can prove that delegation for this actor.
        if (string.IsNullOrWhiteSpace(message.Sender)
            || (message.From is not null
                && !string.Equals(NormalizeAddress(message.From), NormalizeAddress(message.Sender),
                    StringComparison.OrdinalIgnoreCase)))
            throw new InvalidOperationException(error);
        if (!message.InternalAuthenticated)
            throw new InvalidOperationException("The native task message has no Exchange-internal authentication provenance.");
        if (expected is not null
            && !string.Equals(NormalizeAddress(message.Sender), NormalizeAddress(expected),
                StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException(error);
    }

    private static void ValidateTaskAction(EwsTaskAction action)
    {
        if (action.Operation is not ("assign" or "reassign" or "respond_accept" or "respond_decline" or "progress" or "process"))
            throw new ArgumentException("Unsupported task action.", nameof(action));
        if (string.IsNullOrWhiteSpace(action.PayloadXml)
            || Encoding.UTF8.GetByteCount(action.PayloadXml) > TaskAssignmentMaxPayload)
            throw new ArgumentException("The task action payload is invalid.", nameof(action));
        _ = ValidateItemId(action.SourceId, "task source");
        _ = ValidateChangeKey(action.SourceChangeKey);
        _ = NormalizeAddress(action.Mailbox);
        if (string.IsNullOrWhiteSpace(action.StableCorrelation) || action.StableCorrelation.Length > 128
            || action.StableCorrelation.Any(value => !Uri.IsHexDigit(value)))
            throw new ArgumentException("The task action correlation is invalid.", nameof(action));
        var expectedCorrelation = StableTaskCorrelation(action.Mailbox, action.SourceId,
            action.TaskGlobalId, action.Operation);
        if (!string.Equals(expectedCorrelation, action.StableCorrelation, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("The task action correlation does not match its source.");
        if (string.IsNullOrWhiteSpace(action.Digest)
            || action.Digest.Length != 64 || action.Digest.Any(value => !Uri.IsHexDigit(value)))
            throw new ArgumentException("The task action digest is invalid.", nameof(action));
        if (action.ActionTimeUtc == default)
            throw new ArgumentException("The task action timestamp is required.", nameof(action));
        var digest = DigestTaskAction(action.Operation, action.Mailbox, action.SourceId, action.SourceChangeKey,
            action.StableCorrelation, action.OriginalTaskSubject, action.AssignerAddress, action.AssigneeAddress,
            action.PayloadXml, action.TaskGlobalId, action.PercentComplete, action.Status, action.IsReassignment,
            action.ActionTimeUtc);
        if (!CryptographicOperations.FixedTimeEquals(
                Encoding.ASCII.GetBytes(digest), Encoding.ASCII.GetBytes(action.Digest.ToLowerInvariant())))
            throw new InvalidOperationException("The task action changed after native approval.");
        _ = XDocument.Parse(action.PayloadXml, LoadOptions.PreserveWhitespace);
    }

    private async Task<EwsTask?> ValidateFreshTaskActionAsync(EwsTaskAction action, CancellationToken cancellationToken)
    {
        if (action.Operation is "assign" or "reassign" or "progress")
        {
            var current = await GetTaskAsync(action.Mailbox, action.SourceId, cancellationToken).ConfigureAwait(false);
            current = await HydrateTaskAttachmentsAsync(action.Mailbox, current, cancellationToken).ConfigureAwait(false);
            if (!string.Equals(current.ChangeKey, action.SourceChangeKey, StringComparison.Ordinal)
                || !string.Equals(current.Subject, action.OriginalTaskSubject, StringComparison.Ordinal))
                throw new InvalidOperationException("The task changed after approval; prepare a new action.");
            ValidateTaskAttachmentSnapshots(action.PreviewTask, current);
            return current;
        }
        var request = await ReadTaskAssignmentMessageAsync(action.Mailbox, action.SourceId, cancellationToken).ConfigureAwait(false);
        if (!string.Equals(request.ChangeKey, action.SourceChangeKey, StringComparison.Ordinal))
            throw new InvalidOperationException("The task request changed after approval; prepare a new action.");
        if (IsNativeOutlookReassignmentRequest(request)
            || IsNativeOutlookInitialRequest(request))
            request = await HydrateNativeReassignmentRequestAsync(
                action.Mailbox, request, cancellationToken).ConfigureAwait(false);
        if (action.Operation == "process")
        {
            if (IsNativeOutlookReassignmentUpdate(request))
                request = await HydrateNativeReassignmentUpdateAsync(
                    action.Mailbox, request, cancellationToken).ConfigureAwait(false);
            var watcherRequest = IsWatcherReassignmentRequest(request, action.Mailbox);
            if (watcherRequest)
                ValidateWatcherReassignmentRequest(request, action.Mailbox);
            else
                ValidateTaskRequest(request, action.Mailbox);
            var requestTask = request.Task
                ?? throw new InvalidOperationException("The task request has no embedded task.");
            var globalTaskId = requestTask.Assignment?.GlobalTaskId
                ?? throw new InvalidOperationException("The native task request is missing PidLidTaskGlobalId.");
            var local = await FindTaskByGlobalIdAsync(action.Mailbox, globalTaskId, cancellationToken)
                .ConfigureAwait(false)
                ?? throw new InvalidOperationException("No matching local task exists for this native task response.");
            var hydratedLocal = await HydrateTaskAttachmentsAsync(action.Mailbox, local.Task, cancellationToken)
                .ConfigureAwait(false);
            hydratedLocal = await HydrateNativeReassignmentTrackerAsync(
                action.Mailbox, hydratedLocal, request, requestTask, cancellationToken).ConfigureAwait(false);
            if (action.PreviewTask is null
                || !string.Equals(action.PreviewTask.Id, hydratedLocal.Id, StringComparison.Ordinal)
                || !string.Equals(action.PreviewTask.ChangeKey, hydratedLocal.ChangeKey, StringComparison.Ordinal))
                throw new InvalidOperationException("The local task changed after approval; prepare a new action.");
            ValidateIncomingTaskProcess(hydratedLocal, request, requestTask, action.Mailbox, watcherRequest);
            var freshPreview = BuildTaskProcessPreview(
                hydratedLocal, request, requestTask, action.Mailbox, watcherRequest, action.ActionTimeUtc);
            var freshPayload = BuildTaskProcessUpdateOperation(
                hydratedLocal, freshPreview, request.ItemClass, action.ActionTimeUtc)
                .ToString(SaveOptions.DisableFormatting);
            if (!string.Equals(freshPayload, action.PayloadXml, StringComparison.Ordinal))
                throw new InvalidOperationException("The native task roles or chain changed after approval; prepare a new action.");
            return hydratedLocal;
        }
        if (request.ItemClass != "IPM.TaskRequest")
            throw new InvalidOperationException("Only an assignment request can be accepted or declined.");
        ValidateTaskRequest(request, action.Mailbox);
        if (action.PreviewTask is not null && request.Task is not null)
            ValidateTaskAttachmentSnapshots(action.PreviewTask, request.Task);
        if (action.Operation is "respond_accept" or "respond_decline")
        {
            var freshResponse = await PrepareTaskResponseAsync(
                action.Mailbox, action.SourceId, action.Operation == "respond_accept",
                cancellationToken, action.ActionTimeUtc).ConfigureAwait(false);
            if (!string.Equals(freshResponse.PayloadXml, action.PayloadXml, StringComparison.Ordinal))
                throw new InvalidOperationException("The native recipient or assigner chain changed after approval; prepare a new action.");
        }
        return request.Task;
    }

    private async Task<EwsItemRef> ApplySourceTaskUpdateAsync(
        string mailbox,
        EwsTask current,
        EwsTaskAction action,
        XElement sendOperation,
        CancellationToken cancellationToken)
    {
        var embedded = sendOperation.Descendants(T + "Task").FirstOrDefault()
            ?? throw new InvalidOperationException("The native task action has no embedded task.");
        // New outgoing files have no Exchange IDs; project source fields without parsing attachments.
        var sourceProjection = new XElement(embedded);
        sourceProjection.Element(T + "Attachments")?.Remove();
        var desired = ParseDetachedTask(sourceProjection, current.Id, current.ChangeKey);
        var updates = new XElement(T + "Updates");
        if (action.Operation == "progress")
        {
            AddTaskField(updates, "task:PercentComplete", desired.PercentComplete, "PercentComplete");
            AddTaskField(updates, "task:Status", desired.Status, "Status");
            AddTaskField(updates, "task:CompleteDate", desired.CompleteDateUtc, "CompleteDate");
        }
        var globalId = action.TaskGlobalId ?? current.Assignment?.GlobalTaskId;
        if (!string.IsNullOrWhiteSpace(globalId))
            updates.Add(SetTaskNamedValue(CommonPropertySet, "0x8519", "Binary", globalId));
        if (desired.Assignment?.AssignerStackBase64 is { Length: > 0 } assignerStack)
            updates.Add(SetTaskNamedValue(TaskPropertySet, "0x8117", "Binary", assignerStack));
        if (action.Operation is "assign" or "reassign")
        {
            updates.Add(SetTaskNamedValue(CommonPropertySet, "0x8518", "Integer", "0"));
            updates.Add(SetTaskNamedValue(TaskPropertySet, "0x8129", "Integer", "1"));
            updates.Add(SetTaskNamedValue(TaskPropertySet, "0x812A", "Integer", "1"));
            updates.Add(SetTaskNamedValue(TaskPropertySet, "0x8113", "Integer", "3"));
            updates.Add(SetTaskNamedValue(TaskPropertySet, "0x811A", "Integer", "5"));
            updates.Add(SetTaskNamedValue(TaskPropertySet, "0x8112", "Integer",
                Math.Max(1, desired.Assignment?.Version ?? current.Assignment?.Version ?? 1)
                    .ToString(CultureInfo.InvariantCulture)));
        }
        else if (action.Operation == "progress")
        {
            updates.Add(SetTaskNamedValue(CommonPropertySet, "0x8518", "Integer", "0"));
            // A progress update changes the assignee's owned copy.  State 2 /
            // ownership 2 is distinct from the assigner's tracking copy
            // (state 3 / ownership 1).
            updates.Add(SetTaskNamedValue(TaskPropertySet, "0x8129", "Integer", "2"));
            updates.Add(SetTaskNamedValue(TaskPropertySet, "0x812A", "Integer", "0"));
            updates.Add(SetTaskNamedValue(TaskPropertySet, "0x8113", "Integer", "2"));
            updates.Add(SetTaskNamedValue(TaskPropertySet, "0x811A", "Integer", "3"));
            updates.Add(SetTaskNamedValue(TaskPropertySet, "0x8112", "Integer",
                Math.Max(1, desired.Assignment?.Version ?? current.Assignment?.Version ?? 1)
                    .ToString(CultureInfo.InvariantCulture)));
        }
        var assigner = desired.Assignment?.AssignerAddress ?? desired.Assignment?.AssignerName;
        if (action.Operation is "assign" or "reassign")
        {
            // Assignment and reassignment update the sender tracker; clear receiver-only PidLidTaskAssigner.
            updates.Add(new XElement(T + "DeleteItemField",
                NamedField(TaskPropertySet, "0x8121", "String")));
        }
        else if (assigner is { Length: > 0 })
            updates.Add(SetTaskNamedValue(TaskPropertySet, "0x8121", "String", assigner));
        var owner = desired.Assignment?.OwnerAddress ?? desired.Assignment?.AssigneeAddress
            ?? desired.Assignment?.OwnerName;
        if (owner is { Length: > 0 })
            updates.Add(SetTaskNamedValue(TaskPropertySet, "0x811F", "String", owner));
        var desiredAddresses = SerializeAssignerAddresses(desired.Assignment?.AssignerChainAddresses);
        if (desiredAddresses is not null)
            updates.Add(SetTaskNamedNameValue(McpTaskPropertySet, AssignerAddressesPropertyName, "String", desiredAddresses));
        AddAddressUpdate(updates, AssignerAddressPropertyName, desired.Assignment?.AssignerAddress);
        AddAddressUpdate(updates, AssigneeAddressPropertyName, desired.Assignment?.AssigneeAddress);
        AddAddressUpdate(updates, OwnerAddressPropertyName, desired.Assignment?.OwnerAddress);
        var lastUser = action.Operation == "progress"
            ? action.Mailbox
            : desired.Assignment?.LastUserName ?? action.Mailbox;
        updates.Add(SetTaskNamedValue(TaskPropertySet, "0x8122", "String", lastUser));
        updates.Add(SetTaskNamedValue(TaskPropertySet, "0x8125", "String",
            desired.Assignment?.LastDelegateName ?? lastUser));
        var lastUpdate = desired.Assignment?.LastUpdateUtc ?? action.ActionTimeUtc;
        updates.Add(SetTaskNamedValue(TaskPropertySet, "0x8115", "SystemTime",
            FormatTaskSystemTime(lastUpdate)));
        updates.Add(SetTaskNamedValue(TaskPropertySet, "0x811B", "Boolean",
            (desired.Assignment?.UpdatesEnabled ?? false) ? "true" : "false"));
        updates.Add(SetTaskNamedValue(TaskPropertySet, "0x8119", "Boolean",
            (desired.Assignment?.CompletionReportEnabled ?? false) ? "true" : "false"));
        var updateOperation = new XElement(
            M + "UpdateItem", new XAttribute("ConflictResolution", "NeverOverwrite"),
            new XElement(M + "ItemChanges",
                new XElement(T + "ItemChange", ItemReference(current.Id, current.ChangeKey), updates)));
        var document = await SendAsync(mailbox, updateOperation, cancellationToken).ConfigureAwait(false);
        return ParseItemReference(RequiredReturnedItem(document));
    }

    private async Task MarkTaskCommunicationProcessedAsync(
        string mailbox,
        string messageId,
        string changeKey,
        CancellationToken cancellationToken)
    {
        var operation = new XElement(
            M + "UpdateItem", new XAttribute("MessageDisposition", "SaveOnly"),
            new XAttribute("ConflictResolution", "NeverOverwrite"),
            new XElement(M + "ItemChanges",
                new XElement(T + "ItemChange", ItemReference(messageId, changeKey),
                    new XElement(T + "Updates", SetMessageNamedValue("0x7D01", "Boolean", "true")))));
        _ = await SendAsync(mailbox, operation, cancellationToken).ConfigureAwait(false);
    }

    private static XElement SetTaskNamedValue(string propertySet, string propertyId, string propertyType, string value) =>
        new XElement(T + "SetItemField", NamedField(propertySet, propertyId, propertyType),
            new XElement(T + "Task", NamedValue(propertySet, propertyId, propertyType, value)));

    private static XElement SetTaskNamedNameValue(string propertySet, string propertyName, string propertyType, string value) =>
        new XElement(T + "SetItemField", NamedNameField(propertySet, propertyName, propertyType),
            new XElement(T + "Task", NamedNameValue(propertySet, propertyName, propertyType, value)));

    private static XElement SetMessageNamedValue(string propertyTag, string propertyType, string value) =>
        new XElement(T + "SetItemField",
            new XElement(T + "ExtendedFieldURI", new XAttribute("PropertyTag", propertyTag),
                new XAttribute("PropertyType", propertyType)),
            new XElement(T + "Message", new XElement(T + "ExtendedProperty",
                new XElement(T + "ExtendedFieldURI", new XAttribute("PropertyTag", propertyTag),
                    new XAttribute("PropertyType", propertyType)), new XElement(T + "Value", value))));

    private static XElement ParseTaskActionPayload(string payload)
    {
        var document = XDocument.Parse(payload, LoadOptions.PreserveWhitespace);
        var operation = document.Root;
        if (operation is null || (operation.Name != M + "CreateItem" && operation.Name != M + "UpdateItem"))
            throw new InvalidOperationException("The task action is not a native CreateItem request.");
        if (operation.Descendants(T + "Message").Any(message =>
                message.Element(T + "ItemClass")?.Value.StartsWith("IPM.TaskRequest", StringComparison.OrdinalIgnoreCase) == true))
            return operation;
        if (operation.Element(M + "SavedItemFolderId") is not null
            && operation.Descendants(T + "Task").Any())
            return operation;
        if (operation.Element(M + "ItemChanges") is not null
            && operation.Descendants(T + "ItemChange").Any())
            return operation;
        throw new InvalidOperationException("The task action payload is not a supported native task request.");
    }
}
