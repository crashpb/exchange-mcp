using Company.ExchangeMcp.Security;
using Company.ExchangeMcp.Exchange;
using Microsoft.Extensions.DependencyInjection;

internal sealed partial class Checks
{
    private async Task TaskAssignmentNativeChecksAsync()
    {
        var exchange = new TaskAssignmentRecordingHandler { UnassignedTask = true };
        await using var host = await StartHostAsync(exchange, writesEnabled: true, sendEnabled: true,
            classicStateful: true);
        const string session = "task-native";
        var form = new NativeFormResponder(accept: false);
        await using var client = await CreateNativeClientAsync(host,
            Token("user-a", "mail.read mail.write mail.send", sessionId: session), form);
        var identity = new MailboxIdentity("user-a", "alice@example.test", "chatgpt-test", session);
        var handle = host.App.Services.GetRequiredService<MailboxHandles>()
            .Issue(identity, "task", "task-1", exchange.TaskChangeKey);
        var arguments = new Dictionary<string, object?>
        {
            ["taskHandle"] = handle,
            ["assignee"] = "bob@example.test",
            ["keepUpdated"] = true,
            ["completionReport"] = true
        };
        var declined = await client.Client.CallToolAsync("task_assign", arguments);
        Expect(declined.IsError != true && NativeData(declined).GetProperty("status").GetString() == "cancelled"
            && form.Calls == 1 && exchange.CreateItemCount == 0 && exchange.UpdateItemCount == 0,
            "Declining task confirmation performed a task change or transmission.");
        Expect(form.LastRequest?.Message.Contains("bob@example.test", StringComparison.Ordinal) == true
            && form.LastRequest.Message.Contains("IPM.TaskRequest", StringComparison.Ordinal)
            && form.LastRequest.Message.Contains("Disposable task", StringComparison.Ordinal),
            "Native task confirmation omitted the assignee, notice class or task body.");

        form.Accept = true;
        var accepted = await client.Client.CallToolAsync("task_assign", arguments);
        var acceptedData = NativeData(accepted);
        Expect(accepted.IsError != true && acceptedData.TryGetProperty("sent", out var sent) && sent.ValueKind == System.Text.Json.JsonValueKind.True,
            "Native task confirmation did not return a verified send: " + acceptedData.GetRawText());
        Expect(acceptedData.GetProperty("sent").GetBoolean()
            && NativeData(accepted).GetProperty("applied").GetBoolean()
            && exchange.CreateItemCount == 1 && exchange.UpdateItemCount == 1,
            "The native confirmation continuation did not preserve the real action timestamp and exact plan.");

        var changed = new TaskAssignmentRecordingHandler { UnassignedTask = true };
        await using var changedHost = await StartHostAsync(changed, writesEnabled: true, sendEnabled: true,
            classicStateful: true);
        var changedForm = new NativeFormResponder(accept: true)
        { BeforeResponse = () => changed.TaskChangeKey = "changed-after-confirmation" };
        await using var changedClient = await CreateNativeClientAsync(changedHost,
            Token("user-a", "mail.read mail.write mail.send", sessionId: session), changedForm);
        var changedHandle = changedHost.App.Services.GetRequiredService<MailboxHandles>()
            .Issue(identity, "task", "task-1", "task-change");
        var changedArguments = new Dictionary<string, object?>(arguments) { ["taskHandle"] = changedHandle };
        Expect(await NativeRejectedAsync(changedClient.Client, "task_assign", changedArguments)
            && changed.CreateItemCount == 0 && changed.UpdateItemCount == 0,
            "An accepted task confirmation used a stale task snapshot.");

        var binding = new TaskAssignmentRecordingHandler { UnassignedTask = true };
        await using var bindingHost = await StartHostAsync(binding, writesEnabled: true, sendEnabled: true);
        var token = Token("user-a", "mail.read mail.write mail.send", sessionId: session);
        await InitializeAsync(bindingHost.Client, token, elicitation: true);
        var bindingHandle = bindingHost.App.Services.GetRequiredService<MailboxHandles>()
            .Issue(identity, "task", "task-1", "task-change");
        var bindingArguments = new Dictionary<string, object?>(arguments) { ["taskHandle"] = bindingHandle };
        var pending = await ToolRequestAsync(bindingHost.Client, token, "tools/call", new
        { name = "task_assign", arguments = bindingArguments }, JulyProtocolVersion, elicitation: true);
        var state = InputRequiredState(pending.Body);
        var alternate = Token("user-a", "mail.read mail.write mail.send", azp: "chatgpt-alt", sessionId: session);
        var wrongClient = await ResumeTaskAsync(alternate, bindingArguments);
        Expect(IsToolError(wrongClient.Body) && binding.CreateItemCount == 0 && binding.UpdateItemCount == 0,
            "Task confirmation crossed OAuth clients.");
        var tamperedArguments = new Dictionary<string, object?>(bindingArguments) { ["assignee"] = "carol@example.test" };
        var tampered = await ResumeTaskAsync(token, tamperedArguments);
        Expect(IsToolError(tampered.Body) && binding.CreateItemCount == 0 && binding.UpdateItemCount == 0,
            "Task confirmation accepted a different assignee.");
        var exact = await ResumeTaskAsync(token, bindingArguments);
        Expect(!IsToolError(exact.Body) && ToolStructuredData(exact.Body).GetProperty("sent").GetBoolean()
            && binding.CreateItemCount == 1, "The exact task confirmation was not accepted.");
        var replay = await ResumeTaskAsync(token, bindingArguments);
        Expect(IsToolError(replay.Body) && binding.CreateItemCount == 1,
            "A consumed task confirmation transmitted a second request.");

        var noSend = new TaskAssignmentRecordingHandler { UnassignedTask = true };
        await using var noSendHost = await StartHostAsync(noSend, writesEnabled: true, sendEnabled: true,
            classicStateful: true);
        var noSendForm = new NativeFormResponder(accept: true);
        await using var noSendClient = await CreateNativeClientAsync(noSendHost,
            Token("user-a", "mail.read mail.write", sessionId: session), noSendForm);
        var noSendHandle = noSendHost.App.Services.GetRequiredService<MailboxHandles>()
            .Issue(identity, "task", "task-1", "task-change");
        Expect(await NativeRejectedAsync(noSendClient.Client, "task_assign",
                new Dictionary<string, object?>(arguments) { ["taskHandle"] = noSendHandle })
            && noSendForm.Calls == 0 && noSend.CreateItemCount == 0 && noSend.UpdateItemCount == 0,
            "Task assignment without mail.send opened confirmation or reached an Exchange mutation.");

        foreach (var sendAsState in new[] { "denied", "unknown" })
        {
            var delegatedExchange = new TaskAssignmentRecordingHandler { UnassignedTask = true };
            var delegatedPermissions = new SyntheticPermissionReader(new MailboxPermissionReport(
                new PermissionDecision("allowed", "synthetic FullAccess"),
                new PermissionDecision(sendAsState, "synthetic SendAs"),
                new PermissionDecision("allowed", "synthetic SendOnBehalf"),
                DateTimeOffset.UtcNow, "task-send-grant"));
            await using var delegatedHost = await StartDelegatedHostAsync(delegatedExchange,
                Path.Combine(runDirectory, "task-behalf-" + sendAsState + ".jsonl"),
                classicStateful: true, permissions: delegatedPermissions);
            var delegatedForm = new NativeFormResponder(accept: true);
            await using var delegatedClient = await CreateNativeClientAsync(delegatedHost,
                Token("user-a", "mail.read mail.write mail.send", sessionId: session), delegatedForm);
            var mailboxes = NativeData(await delegatedClient.Client.CallToolAsync("mail_list_mailboxes",
                new Dictionary<string, object?>()));
            var targetHandle = StringProperty(mailboxes.GetProperty("items").EnumerateArray()
                .Single(item => item.GetProperty("kind").GetString() == "delegated"), "mailboxHandle");
            Expect(await NativeRejectedAsync(delegatedClient.Client, "task_assign",
                    new Dictionary<string, object?>(arguments)
                    { ["mailboxHandle"] = targetHandle, ["taskHandle"] = "no-item-lookup" })
                && delegatedExchange.Calls.Count == 0 && delegatedForm.Calls == 0,
                "SendOnBehalf-only task assignment reached Exchange or confirmation.");
        }

        const string rawFailure = "synthetic-sensitive-server-message";
        foreach (var failure in new[] { "native", "malicious", "native-field", "malicious-field", "permission", "missing-item", "missing-items", "unexpected" })
        {
            var failureExchange = new TaskAssignmentRecordingHandler { UnassignedTask = true };
            using var invoker = new System.Net.Http.HttpMessageInvoker(failureExchange, disposeHandler: false);
            var failureHandler = new DelegateHandler(async (request, ct) =>
            {
                var operation = Operation(System.Xml.Linq.XDocument.Parse(await request.Content!.ReadAsStringAsync(ct))).Name.LocalName;
                if (operation == "UpdateItem" && failure is "native-field" or "malicious-field")
                    return Response(SoapResponse("UpdateItem", "ErrorInvalidPropertySet", rawFailure, "Error")
                        .Replace("</m:UpdateItemResponseMessage>", "<m:MessageXml><t:ExtendedFieldURI"
                            + " PropertySetId='00062003-0000-0000-C000-000000000046' PropertyId='33043'"
                            + (failure == "malicious-field" ? " PropertyName='" + rawFailure + "'" : "")
                            + "/><t:Value>" + rawFailure + "</t:Value></m:MessageXml></m:UpdateItemResponseMessage>", StringComparison.Ordinal));
                if (operation == "UpdateItem" && failure is "missing-item" or "missing-items")
                {
                    var body = SoapResponse("UpdateItem", "NoError", "");
                    if (failure == "missing-item")
                        body = body.Replace("</m:UpdateItemResponseMessage>", "<m:Items/></m:UpdateItemResponseMessage>", StringComparison.Ordinal);
                    return Response(body);
                }
                if (operation == "CreateItem")
                {
                    if (failure == "unexpected") throw new InvalidOperationException(rawFailure);
                    var code = failure == "permission" ? "ErrorSendAsDenied"
                        : failure == "malicious" ? "ErrorInvalidOperation\n" + rawFailure : "ErrorInvalidOperation";
                    return Response(SoapResponse("CreateItem", code, rawFailure, "Error"));
                }
                return await invoker.SendAsync(request, ct);
            });
            await using var failureHost = await StartHostAsync(failureHandler, writesEnabled: true, sendEnabled: true,
                classicStateful: true);
            await using var failureClient = await CreateNativeClientAsync(failureHost,
                Token("user-a", "mail.read mail.write mail.send", sessionId: session), new NativeFormResponder(accept: true));
            var failureHandle = failureHost.App.Services.GetRequiredService<MailboxHandles>()
                .Issue(identity, "task", "task-1", failureExchange.TaskChangeKey);
            var result = await failureClient.Client.CallToolAsync("task_assign",
                new Dictionary<string, object?>(arguments) { ["taskHandle"] = failureHandle });
            var data = NativeData(result);
            Expect(result.IsError != true && data.GetProperty("status").GetString() == "task_action_unverified"
                && (!data.TryGetProperty("sent", out var failureSent) || failureSent.ValueKind == System.Text.Json.JsonValueKind.Null)
                && (!data.TryGetProperty("applied", out var failureApplied) || failureApplied.ValueKind == System.Text.Json.JsonValueKind.Null)
                && data.GetProperty("doNotRetryAutomatically").GetBoolean(),
                "Native task failure fidelity changed the uncertain-send contract.");
            Expect(!data.GetRawText().Contains(rawFailure, StringComparison.Ordinal),
                "Native task failure output exposed raw Exchange or unexpected exception data.");
            if (failure is "native" or "malicious" or "native-field" or "malicious-field")
            {
                var fieldFailure = failure is "native-field" or "malicious-field";
                Expect(data.GetProperty("operation").GetString() == (fieldFailure ? "UpdateItem" : "CreateItem")
                    && (data.TryGetProperty("failureCode", out var failureCode) ? failureCode.GetString() : null)
                        == (fieldFailure ? "ErrorInvalidPropertySet" : failure == "native" ? "ErrorInvalidOperation" : null)
                    && (data.TryGetProperty("failureField", out var failureField) ? failureField.GetString() : null)
                        == (failure == "native-field" ? "PropertySetId=00062003-0000-0000-c000-000000000046;PropertyId=33043" : null),
                    "Native task failure did not expose only a sanitized response code and operation.");
            }
            else if (failure == "permission")
                Expect(!data.TryGetProperty("failureCode", out _)
                    && data.GetProperty("message").GetString()!.StartsWith("Exchange denied SendAs", StringComparison.Ordinal),
                    "Native task failure changed the existing permission response.");
            else
                Expect(data.GetProperty("failureKind").GetString() == (failure is "missing-item" or "missing-items"
                    ? "item_reference_missing" : "InvalidOperationException"),
                    "Native task failure did not classify missing references or unexpected failures safely.");
        }

        await AssignedTaskCopyDeletionChecksAsync();

        Task<(System.Net.HttpStatusCode StatusCode, string Body)> ResumeTaskAsync(string auth,
            IReadOnlyDictionary<string, object?> args) => ToolRequestAsync(bindingHost.Client, auth, "tools/call", new
            {
                name = "task_assign",
                requestState = state,
                inputResponses = new { task_confirmation = new { action = "accept", content = new { confirm = true } } },
                arguments = args
            }, JulyProtocolVersion, elicitation: true);
    }

    private async Task AssignedTaskCopyDeletionChecksAsync()
    {
        const string session = "task-copy-delete";
        var identity = new MailboxIdentity("user-a", "alice@example.test", "chatgpt-test", session);
        var token = Token("user-a", "mail.read mail.write mail.manage", sessionId: session);
        var exchange = new TaskAssignmentRecordingHandler();
        await AssertThrowsAsync<InvalidOperationException>(() => NewEwsClient(exchange)
            .DeleteTaskAsync(identity.Mailbox, "task-1", exchange.TaskChangeKey, "series", CancellationToken.None));
        Expect(!exchange.Calls.Any(call => call.Operation == "DeleteItem"),
            "The default task client allowed deleting an assigned copy without approved workflow.");

        await using var host = await StartHostAsync(exchange, writesEnabled: true, sendEnabled: false,
            classicStateful: true);
        var form = new NativeFormResponder(accept: false);
        await using var client = await CreateNativeClientAsync(host, token, form);
        var handle = host.App.Services.GetRequiredService<MailboxHandles>()
            .Issue(identity, "task", "task-1", exchange.TaskChangeKey);
        var arguments = new Dictionary<string, object?> { ["taskHandle"] = handle, ["scope"] = "series" };
        var declined = await client.Client.CallToolAsync("task_delete", arguments);
        var declinedData = NativeData(declined);
        Expect(declined.IsError != true && declinedData.GetProperty("status").GetString() == "cancelled"
            && !declinedData.GetProperty("applied").GetBoolean()
            && !declinedData.GetProperty("sent").GetBoolean()
            && declinedData.GetProperty("noticesSent").GetInt32() == 0
            && !exchange.Calls.Any(call => call.Operation == "DeleteItem"),
            "Declining assigned-copy cleanup performed a move or sent a notice.");
        var preview = form.LastRequest?.Message;
        Expect(preview?.Contains("Selected mailbox: alice@example.test", StringComparison.Ordinal) == true
            && preview.Contains("Subject: Verify assignment", StringComparison.Ordinal)
            && preview.Contains("Scope: series (complete selected mailbox copy)", StringComparison.Ordinal)
            && preview.Contains("Disposable task", StringComparison.Ordinal)
            && preview.Contains("recoverable from Deleted Items", StringComparison.Ordinal)
            && preview.Contains("Other mailboxes keep their task copies", StringComparison.Ordinal)
            && preview.Contains("does not cancel or decline", StringComparison.Ordinal)
            && preview.Contains("No assignment notices will be sent (0 sends)", StringComparison.Ordinal),
            "Assigned-copy confirmation omitted the exact local-copy deletion boundary.");

        form.Accept = true;
        var accepted = await client.Client.CallToolAsync("task_delete", arguments);
        var acceptedData = NativeData(accepted);
        Expect(accepted.IsError != true && acceptedData.GetProperty("status").GetString() == "task_moved_to_deleted_items"
            && acceptedData.GetProperty("applied").GetBoolean() && acceptedData.GetProperty("recoverable").GetBoolean()
            && !acceptedData.GetProperty("sent").GetBoolean()
            && acceptedData.GetProperty("noticesSent").GetInt32() == 0,
            "Accepted assigned-copy cleanup did not return verified recoverable zero-send success.");
        var deletion = exchange.Calls.Single(call => call.Operation == "DeleteItem");
        var deleteOperation = Operation(System.Xml.Linq.XDocument.Parse(deletion.Body));
        var item = deleteOperation.Descendants(System.Xml.Linq.XName.Get("ItemId", TypesNamespace)).Single();
        Expect(deleteOperation.Attribute("DeleteType")?.Value == "MoveToDeletedItems"
            && deleteOperation.Attribute("AffectedTaskOccurrences")?.Value == "AllOccurrences"
            && item.Attribute("Id")?.Value == "task-1" && item.Attribute("ChangeKey")?.Value == exchange.TaskChangeKey
            && deletion.PrimarySmtpAddress == identity.Mailbox
            && !exchange.Calls.Any(call => call.Operation is "CreateItem" or "UpdateItem" or "SendItem"),
            "Assigned-copy cleanup changed another scope, used a stale reference or sent a notice.");

        var changed = new TaskAssignmentRecordingHandler();
        await using var changedHost = await StartHostAsync(changed, writesEnabled: true, sendEnabled: false,
            classicStateful: true);
        var changedForm = new NativeFormResponder(accept: true)
        { BeforeResponse = () => changed.TaskChangeKey = "changed-after-confirmation" };
        await using var changedClient = await CreateNativeClientAsync(changedHost, token, changedForm);
        var changedHandle = changedHost.App.Services.GetRequiredService<MailboxHandles>()
            .Issue(identity, "task", "task-1", "task-change");
        Expect(await NativeRejectedAsync(changedClient.Client, "task_delete",
                new Dictionary<string, object?>(arguments) { ["taskHandle"] = changedHandle })
            && !changed.Calls.Any(call => call.Operation == "DeleteItem"),
            "Assigned-copy cleanup accepted a stale change key after confirmation.");

        var binding = new TaskAssignmentRecordingHandler();
        var alterSnapshot = false;
        using var bindingInvoker = new System.Net.Http.HttpMessageInvoker(binding, disposeHandler: false);
        var bindingHandler = new DelegateHandler(async (request, ct) =>
        {
            var response = await bindingInvoker.SendAsync(request, ct);
            if (alterSnapshot)
            {
                var body = await response.Content!.ReadAsStringAsync(ct);
                response.Content = new System.Net.Http.StringContent(body.Replace("<t:Subject>Verify assignment</t:Subject>",
                    "<t:Subject>Changed reviewed task</t:Subject>", StringComparison.Ordinal));
            }
            return response;
        });
        await using var bindingHost = await StartHostAsync(bindingHandler, writesEnabled: true, sendEnabled: false);
        await InitializeAsync(bindingHost.Client, token, elicitation: true);
        var bindingHandle = bindingHost.App.Services.GetRequiredService<MailboxHandles>()
            .Issue(identity, "task", "task-1", binding.TaskChangeKey);
        var bindingArguments = new Dictionary<string, object?>(arguments) { ["taskHandle"] = bindingHandle };
        var noConfirmation = await ToolRequestAsync(bindingHost.Client, token, "tools/call", new
        { name = "task_delete", arguments = bindingArguments }, JulyProtocolVersion, elicitation: false);
        Expect(IsToolError(noConfirmation.Body) && !binding.Calls.Any(call => call.Operation == "DeleteItem"),
            "Assigned-copy cleanup bypassed native confirmation capability.");
        var injected = await ToolRequestAsync(bindingHost.Client, token, "tools/call", new
        {
            name = "task_delete",
            arguments = bindingArguments,
            inputResponses = new { task_delete_confirmation = new { action = "accept", content = new { confirm = true } } }
        }, JulyProtocolVersion, elicitation: true);
        Expect(IsToolError(injected.Body), "Assigned-copy cleanup accepted an approval without protected request state.");
        var pending = await ToolRequestAsync(bindingHost.Client, token, "tools/call", new
        { name = "task_delete", arguments = bindingArguments }, JulyProtocolVersion, elicitation: true);
        var state = InputRequiredState(pending.Body);
        var alternate = Token("user-a", "mail.read mail.write mail.manage", azp: "chatgpt-alt", sessionId: session);
        Expect(IsToolError((await ResumeDeleteAsync(alternate, bindingArguments)).Body),
            "Assigned-copy cleanup crossed OAuth clients.");
        var otherSession = Token("user-a", "mail.read mail.write mail.manage", sessionId: "other-session");
        var otherHandle = bindingHost.App.Services.GetRequiredService<MailboxHandles>()
            .Issue(identity with { SessionId = "other-session" }, "task", "task-1", binding.TaskChangeKey);
        Expect(IsToolError((await ResumeDeleteAsync(otherSession,
                new Dictionary<string, object?>(bindingArguments) { ["taskHandle"] = otherHandle })).Body),
            "Assigned-copy cleanup crossed authentication sessions.");
        Expect(IsToolError((await ResumeDeleteAsync(token,
                new Dictionary<string, object?>(bindingArguments) { ["scope"] = "single" })).Body),
            "Assigned-copy cleanup changed the approved complete-copy scope.");
        alterSnapshot = true;
        Expect(IsToolError((await ResumeDeleteAsync(token, bindingArguments)).Body)
            && !binding.Calls.Any(call => call.Operation == "DeleteItem"),
            "Assigned-copy cleanup accepted a changed task snapshot with the same change key.");
        alterSnapshot = false;
        var exact = await ResumeDeleteAsync(token, bindingArguments);
        Expect(!IsToolError(exact.Body) && ToolStructuredData(exact.Body).GetProperty("applied").GetBoolean()
            && binding.Calls.Count(call => call.Operation == "DeleteItem") == 1,
            "The exact assigned-copy cleanup continuation was not accepted once.");
        var replay = await ResumeDeleteAsync(token, bindingArguments);
        Expect(IsToolError(replay.Body) && binding.Calls.Count(call => call.Operation == "DeleteItem") == 1
            && !binding.Calls.Any(call => call.Operation is "CreateItem" or "UpdateItem" or "SendItem"),
            "A replay repeated assigned-copy deletion or sent a notice.");

        var ordinary = new TaskAssignmentRecordingHandler { UnassignedTask = true };
        await using var ordinaryHost = await StartHostAsync(ordinary, writesEnabled: true, sendEnabled: false);
        await InitializeAsync(ordinaryHost.Client, token, elicitation: false);
        var ordinaryHandle = ordinaryHost.App.Services.GetRequiredService<MailboxHandles>()
            .Issue(identity, "task", "task-1", ordinary.TaskChangeKey);
        var ordinaryResult = await ToolRequestAsync(ordinaryHost.Client, token, "tools/call", new
        { name = "task_delete", arguments = new { taskHandle = ordinaryHandle, scope = "series" } });
        Expect(!IsToolError(ordinaryResult.Body) && ordinary.Calls.Count(call => call.Operation == "DeleteItem") == 1,
            "Unassigned task deletion unexpectedly required assigned-copy confirmation.");

        const string rawFailure = "synthetic-sensitive-delete-message";
        var uncertain = new TaskAssignmentRecordingHandler();
        var deleteAttempts = 0;
        using var uncertainInvoker = new System.Net.Http.HttpMessageInvoker(uncertain, disposeHandler: false);
        var uncertainHandler = new DelegateHandler(async (request, ct) =>
        {
            var operation = Operation(System.Xml.Linq.XDocument.Parse(await request.Content!.ReadAsStringAsync(ct)));
            if (operation.Name.LocalName != "DeleteItem") return await uncertainInvoker.SendAsync(request, ct);
            deleteAttempts++;
            return Response(SoapResponse("DeleteItem", "ErrorInvalidOperation", rawFailure, "Error"));
        });
        await using var uncertainHost = await StartHostAsync(uncertainHandler, writesEnabled: true, sendEnabled: false,
            classicStateful: true);
        await using var uncertainClient = await CreateNativeClientAsync(uncertainHost, token, new NativeFormResponder(accept: true));
        var uncertainHandle = uncertainHost.App.Services.GetRequiredService<MailboxHandles>()
            .Issue(identity, "task", "task-1", uncertain.TaskChangeKey);
        var uncertainArguments = new Dictionary<string, object?>(arguments) { ["taskHandle"] = uncertainHandle };
        var uncertainResult = await uncertainClient.Client.CallToolAsync("task_delete", uncertainArguments);
        var uncertainData = NativeData(uncertainResult);
        Expect(uncertainResult.IsError != true && uncertainData.GetProperty("status").GetString() == "task_delete_unverified"
            && (!uncertainData.TryGetProperty("applied", out var applied) || applied.ValueKind == System.Text.Json.JsonValueKind.Null)
            && !uncertainData.GetProperty("sent").GetBoolean() && uncertainData.GetProperty("noticesSent").GetInt32() == 0
            && uncertainData.GetProperty("doNotRetryAutomatically").GetBoolean()
            && uncertainData.GetProperty("failureCode").GetString() == "ErrorInvalidOperation"
            && uncertainData.GetProperty("operation").GetString() == "DeleteItem"
            && !uncertainData.GetRawText().Contains(rawFailure, StringComparison.Ordinal),
            "Unverified assigned-copy deletion lost its safe failure code or exposed raw Exchange data.");
        Expect(await NativeRejectedAsync(uncertainClient.Client, "task_delete", uncertainArguments) && deleteAttempts == 1
            && !uncertain.Calls.Any(call => call.Operation is "CreateItem" or "UpdateItem" or "SendItem"),
            "An uncertain assigned-copy deletion was retried or sent a notice.");

        Task<(System.Net.HttpStatusCode StatusCode, string Body)> ResumeDeleteAsync(string auth,
            IReadOnlyDictionary<string, object?> args) => ToolRequestAsync(bindingHost.Client, auth, "tools/call", new
            {
                name = "task_delete",
                requestState = state,
                arguments = args,
                inputResponses = new { task_delete_confirmation = new { action = "accept", content = new { confirm = true } } }
            }, JulyProtocolVersion, elicitation: true);
    }
}
