using System.Net;
using System.Net.Http;
using System.Reflection;
using System.Text;
using System.Xml.Linq;
using Company.ExchangeMcp.Exchange;
using Company.ExchangeMcp.Security;
using Microsoft.AspNetCore.DataProtection;
using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol;

internal sealed partial class Checks
{
    private async Task DelegateNativeChecksAsync()
    {
        await AssertDelegateAddNativeAsync();
        await AssertDelegateUpdateNativeAsync();
        await AssertDelegateRemoveNativeAsync();
        await AssertDelegateCancellationNativeAsync();
        await AssertDelegateStaleNativeAsync();
        await AssertDelegateReadbackMismatchNativeAsync();
        await AssertDelegateUpdateReadbackMismatchNativeAsync();
        await AssertDelegateNativeRejectionsAsync();
        await AssertDelegateReadbackFailureAfterWriteNativeAsync();
        await AssertDelegatePostAckReadRetryNativeAsync();
        await AssertDelegateMissingConfigurationPostAckReadRetryNativeAsync();
        await AssertDelegatePostAckReadTransportFailureNativeAsync();
        await AssertDelegateAmbiguousListNativeAsync();
        await AssertDelegateMissingDeliveryNativeAsync();
        await AssertDelegateVerifiedReplayLifecycleAsync();
        await AssertDelegateUncertainReplayHoldAsync();
        await AssertDelegateVerifiedRemoveResolvesUncertainHoldNativeAsync();
        AssertDelegateVerifiedRemoveClearsOnlyMatchingHolds();
        await AssertDelegateReadRefusalNativeAsync();
    }

    private async Task AssertDelegateAddNativeAsync()
    {
        var unrelated = Delegate("other@example.test", "Reviewer", "Editor", "None", "Author", "None", "Reviewer", false, false);
        var exchange = new DelegateMcpRecordingHandler([unrelated], "NoForward");
        await using var host = await StartSharingHostAsync(exchange, writesEnabled: true, sendEnabled: true,
            classicStateful: true);
        var responder = new NativeFormResponder(accept: true);
        await using var client = await CreateNativeClientAsync(host,
            Token("user-a", "mail.read mail.manage", sessionId: "delegate-add"), responder);
        var result = await client.Client.CallToolAsync("delegate_add", new Dictionary<string, object?>
        {
            ["principal"] = "new@example.test",
            ["calendarPermissionLevel"] = "Reviewer",
            ["inboxPermissionLevel"] = "Editor",
            ["receiveCopiesOfMeetingMessages"] = true
        });

        var prompt = responder.LastRequest?.Message ?? string.Empty;
        var added = exchange.Items.SingleOrDefault(item => item.User.Principal == "new@example.test");
        var request = XDocument.Parse(exchange.LastMutationBody!);
        var addedWire = request.Descendants(XName.Get("DelegateUser", DelegateMcpRecordingHandler.TypesNamespace)).Single();
        var permissions = addedWire.Element(XName.Get("DelegatePermissions", DelegateMcpRecordingHandler.TypesNamespace))!;
        Expect(result.IsError != true && NativeData(result).GetProperty("status").GetString() == "delegate_added"
            && responder.Calls == 1 && exchange.MutationCount == 1 && added is not null
            && added.CalendarFolderPermissionLevel == "Reviewer" && added.TasksFolderPermissionLevel == "None"
            && added.InboxFolderPermissionLevel == "Editor" && added.ContactsFolderPermissionLevel == "None"
            && added.NotesFolderPermissionLevel == "None" && added.JournalFolderPermissionLevel == "None"
            && added.ReceiveCopiesOfMeetingMessages == true && added.ViewPrivateItems == false
            && SameDelegateSettings(unrelated, exchange.Items.Single(item => item.User.Principal == "other@example.test"))
            && exchange.Delivery == "NoForward"
            && prompt.Contains("Send on Behalf", StringComparison.Ordinal)
            && prompt.Contains("View private items: False (applies across all mailbox folders)", StringComparison.Ordinal)
            && prompt.Contains("NoForward (preserved)", StringComparison.Ordinal)
            && permissions.Elements().Select(element => element.Name.LocalName).SequenceEqual([
                "CalendarFolderPermissionLevel", "TasksFolderPermissionLevel", "InboxFolderPermissionLevel",
                "ContactsFolderPermissionLevel", "NotesFolderPermissionLevel", "JournalFolderPermissionLevel"])
            && permissions.Elements().Select(element => element.Value).SequenceEqual([
                "Reviewer", "None", "Editor", "None", "None", "None"])
            && addedWire.Element(XName.Get("ReceiveCopiesOfMeetingMessages", DelegateMcpRecordingHandler.TypesNamespace))?.Value == "true"
            && addedWire.Element(XName.Get("ViewPrivateItems", DelegateMcpRecordingHandler.TypesNamespace))?.Value == "false"
            && request.Descendants(XName.Get("DeliverMeetingRequests", DelegateMcpRecordingHandler.MessagesNamespace)).Single().Value == "NoForward",
            "Delegate add did not show its Send on Behalf/private-item effects or verify exact permissions, defaults, delivery and unrelated entries.");
    }

    private async Task AssertDelegateUpdateNativeAsync()
    {
        var target = Delegate("target@example.test", "Reviewer", "Editor", "Reviewer", "Author", "None", "Editor", true, false,
            "S-1-5-21-111-222-333-444", "Original Target Name");
        var unrelated = Delegate("other@example.test", "Editor", "Reviewer", "Author", "None", "Reviewer", "None", false, false);
        var exchange = new DelegateMcpRecordingHandler([target, unrelated], "DelegatesAndMe");
        await using var host = await StartSharingHostAsync(exchange, writesEnabled: true, sendEnabled: true,
            classicStateful: true);
        var responder = new NativeFormResponder(accept: true);
        await using var client = await CreateNativeClientAsync(host,
            Token("user-a", "mail.read mail.manage", sessionId: "delegate-update"), responder);
        var result = await client.Client.CallToolAsync("delegate_update", new Dictionary<string, object?>
        {
            ["principal"] = "TARGET@example.test",
            ["calendarPermissionLevel"] = "Editor"
        });

        var prompt = responder.LastRequest?.Message ?? string.Empty;
        var updated = exchange.Items.Single(item => item.User.Principal == "target@example.test");
        var request = XDocument.Parse(exchange.LastMutationBody!);
        var userId = request.Descendants(XName.Get("UserId", DelegateMcpRecordingHandler.TypesNamespace)).Single();
        var permissions = request.Descendants(XName.Get("DelegatePermissions", DelegateMcpRecordingHandler.TypesNamespace)).Single();
        Expect(result.IsError != true && NativeData(result).GetProperty("status").GetString() == "delegate_updated"
            && responder.Calls == 1 && exchange.MutationCount == 1
            && updated.CalendarFolderPermissionLevel == "Editor" && updated.TasksFolderPermissionLevel == "Editor"
            && updated.InboxFolderPermissionLevel == "Reviewer" && updated.ContactsFolderPermissionLevel == "Author"
            && updated.NotesFolderPermissionLevel == "None" && updated.JournalFolderPermissionLevel == "Editor"
            && updated.ReceiveCopiesOfMeetingMessages == true && updated.ViewPrivateItems == false
            && SameDelegateSettings(unrelated, exchange.Items.Single(item => item.User.Principal == "other@example.test"))
            && exchange.Delivery == "DelegatesAndMe"
            && prompt.Contains("Send on Behalf access remains", StringComparison.Ordinal)
            && prompt.Contains("View private items: False (applies across all mailbox folders)", StringComparison.Ordinal)
            && prompt.Contains("DelegatesAndMe (preserved)", StringComparison.Ordinal)
            && userId.Element(XName.Get("PrimarySmtpAddress", DelegateMcpRecordingHandler.TypesNamespace))?.Value == "target@example.test"
            && userId.Elements().Select(element => element.Name.LocalName).SequenceEqual(["PrimarySmtpAddress"])
            && !exchange.LastMutationBody!.Contains("S-1-5-21-111-222-333-444", StringComparison.Ordinal)
            && !exchange.LastMutationBody.Contains("Original Target Name", StringComparison.Ordinal)
            && permissions.Elements().Select(element => element.Value).SequenceEqual([
                "Editor", "Editor", "Reviewer", "Author", "None", "Editor"]),
            "Delegate update did not preserve omitted fields, the same principal, delivery or unrelated delegate entries.");
    }

    private async Task AssertDelegateRemoveNativeAsync()
    {
        var target = Delegate("target@example.test", "Editor", "Reviewer", "Author", "None", "Reviewer", "None", true, true);
        var unrelated = Delegate("other@example.test", "Reviewer", "None", "Editor", "Author", "None", "Reviewer", false, false);
        var exchange = new DelegateMcpRecordingHandler([target, unrelated], "DelegatesAndSendInformationToMe");
        await using var host = await StartSharingHostAsync(exchange, writesEnabled: true, sendEnabled: true,
            classicStateful: true);
        var responder = new NativeFormResponder(accept: true);
        await using var client = await CreateNativeClientAsync(host,
            Token("user-a", "mail.read mail.manage", sessionId: "delegate-remove"), responder);
        var result = await client.Client.CallToolAsync("delegate_remove", new Dictionary<string, object?>
        {
            ["principal"] = "target@example.test"
        });

        var prompt = responder.LastRequest?.Message ?? string.Empty;
        Expect(result.IsError != true && NativeData(result).GetProperty("status").GetString() == "delegate_removed"
            && responder.Calls == 1 && exchange.MutationCount == 1
            && exchange.Items.Count == 1 && exchange.Items[0].User.Principal == "other@example.test"
            && SameDelegateSettings(unrelated, exchange.Items[0])
            && exchange.Delivery == "DelegatesAndSendInformationToMe"
            && prompt.Contains("associated Send on Behalf access", StringComparison.Ordinal)
            && prompt.Contains("View private items: True (applies across all mailbox folders)", StringComparison.Ordinal)
            && prompt.Contains("DelegatesAndSendInformationToMe (preserved)", StringComparison.Ordinal)
            && prompt.Contains("Other delegate entries are preserved", StringComparison.Ordinal),
            "Delegate removal did not remove only the selected entry or clearly preserve global delivery and unrelated delegates.");
    }

    private async Task AssertDelegateCancellationNativeAsync()
    {
        var exchange = new DelegateMcpRecordingHandler(
            [Delegate("other@example.test", "Reviewer", "Editor", "None", "Author", "None", "Reviewer", false, false)],
            "DelegatesOnly");
        await using var host = await StartSharingHostAsync(exchange, writesEnabled: true, sendEnabled: true,
            classicStateful: true);
        var responder = new NativeFormResponder(accept: false);
        await using var client = await CreateNativeClientAsync(host,
            Token("user-a", "mail.read mail.manage", sessionId: "delegate-cancel"), responder);
        var result = await client.Client.CallToolAsync("delegate_add", new Dictionary<string, object?>
        {
            ["principal"] = "new@example.test"
        });

        Expect(result.IsError != true && NativeData(result).GetProperty("status").GetString() == "cancelled"
            && responder.Calls == 1 && exchange.MutationCount == 0
            && exchange.Items.All(item => item.User.Principal != "new@example.test")
            && (responder.LastRequest?.Message ?? string.Empty).Contains("Send on Behalf", StringComparison.Ordinal),
            "Declining native delegate confirmation changed the mailbox or omitted the access side effect.");
    }

    private async Task AssertDelegateStaleNativeAsync()
    {
        var target = Delegate("target@example.test", "Reviewer", "Editor", "Reviewer", "Author", "None", "Editor", true, false);
        var exchange = new DelegateMcpRecordingHandler([target], "DelegatesAndMe");
        await using var host = await StartSharingHostAsync(exchange, writesEnabled: true, sendEnabled: true,
            classicStateful: true);
        var responder = new NativeFormResponder(accept: true)
        {
            BeforeResponse = () => exchange.Items[0] = exchange.Items[0] with
            {
                CalendarFolderPermissionLevel = "Editor"
            }
        };
        await using var client = await CreateNativeClientAsync(host,
            Token("user-a", "mail.read mail.manage", sessionId: "delegate-stale"), responder);
        var rejected = await NativeRejectedAsync(client.Client, "delegate_update", new Dictionary<string, object?>
        {
            ["principal"] = "target@example.test",
            ["tasksPermissionLevel"] = "Reviewer"
        });

        Expect(rejected && responder.Calls == 1 && exchange.MutationCount == 0
            && exchange.Items[0].CalendarFolderPermissionLevel == "Editor",
            "A delegate list changed while approval was open and the stale update still reached Exchange.");
    }

    private async Task AssertDelegateReadbackMismatchNativeAsync()
    {
        var exchange = new DelegateMcpRecordingHandler(
            [Delegate("other@example.test", "Reviewer", "Editor", "None", "Author", "None", "Reviewer", false, false)],
            "DelegatesAndMe");
        exchange.AfterMutation = operation =>
        {
            if (operation != "AddDelegate") return;
            var index = exchange.Items.FindIndex(item => item.User.Principal == "new@example.test");
            exchange.Items[index] = exchange.Items[index] with { CalendarFolderPermissionLevel = "Editor" };
        };
        await AssertDelegateReadbackReconciliationAsync(exchange, "delegate-readback-principal",
            "Wrong settings for the added principal",
            () => exchange.Items.Single(item => item.User.Principal == "new@example.test")
                .CalendarFolderPermissionLevel == "Editor");

        var unrelated = Delegate("other@example.test", "Reviewer", "Editor", "None", "Author", "None", "Reviewer", false, false);
        var preservationExchange = new DelegateMcpRecordingHandler([unrelated], "DelegatesAndMe");
        preservationExchange.AfterMutation = operation =>
        {
            if (operation == "AddDelegate")
                preservationExchange.Items[0] = preservationExchange.Items[0] with
                {
                    JournalFolderPermissionLevel = "Editor"
                };
        };
        await AssertDelegateReadbackReconciliationAsync(preservationExchange, "delegate-readback-unrelated",
            "Changed unrelated delegate settings",
            () => preservationExchange.Items.Single(item => item.User.Principal == "other@example.test")
                .JournalFolderPermissionLevel == "Editor");
    }

    private async Task AssertDelegateUpdateReadbackMismatchNativeAsync()
    {
        var target = Delegate("target@example.test", "Reviewer", "Reviewer", "Reviewer", "Author", "None", "Editor", true, false);
        var exchange = new DelegateMcpRecordingHandler([target], "DelegatesAndMe");
        exchange.AfterMutation = operation =>
        {
            if (operation == "UpdateDelegate")
                exchange.Items[0] = exchange.Items[0] with { TasksFolderPermissionLevel = "Reviewer" };
        };
        await using var host = await StartSharingHostAsync(exchange, writesEnabled: true, sendEnabled: true,
            classicStateful: true);
        var responder = new NativeFormResponder(accept: true);
        await using var client = await CreateNativeClientAsync(host,
            Token("user-a", "mail.read mail.manage", sessionId: "delegate-update-readback"), responder);
        var isError = false;
        var error = string.Empty;
        try
        {
            var result = await client.Client.CallToolAsync("delegate_update", new Dictionary<string, object?>
            {
                ["principal"] = "target@example.test",
                ["tasksPermissionLevel"] = "Editor"
            });
            isError = result.IsError == true;
            error = string.Join(" ", result.Content.OfType<TextContentBlock>().Select(block => block.Text));
        }
        catch (Exception exception)
        {
            isError = true;
            error = exception.Message;
        }

        Expect(isError && responder.Calls == 1 && exchange.MutationCount == 1
            && exchange.Items.Count == 1 && exchange.Items[0].User.Principal == "target@example.test"
            && exchange.Items[0].TasksFolderPermissionLevel == "Reviewer"
            && error.Contains("delegate_list", StringComparison.Ordinal)
            && error.Contains("reconcile before retrying", StringComparison.OrdinalIgnoreCase),
            "Delegate update accepted a same-principal readback whose requested permission was not applied.");
    }

    private async Task AssertDelegateNativeRejectionsAsync()
    {
        foreach (var (code, expectedMessage) in new[]
        {
            ("ErrorDelegateAlreadyExists", "Exchange rejected the request."),
            ("ErrorAccessDenied", "Exchange denied access to the selected mailbox, folder or item.")
        })
        {
            var exchange = new DelegateMcpRecordingHandler(
                [Delegate("other@example.test", "Reviewer", "Editor", "None", "Author", "None", "Reviewer", false, false)],
                "DelegatesAndMe")
            {
                NativeMutationErrorCode = code
            };
            await using var host = await StartSharingHostAsync(exchange, writesEnabled: true, sendEnabled: true,
                classicStateful: true);
            var responder = new NativeFormResponder(accept: true);
            await using var client = await CreateNativeClientAsync(host,
                Token("user-a", "mail.read mail.manage", sessionId: "delegate-native-reject-" + code), responder);
            var isError = false;
            var error = string.Empty;
            try
            {
                var result = await client.Client.CallToolAsync("delegate_add", new Dictionary<string, object?>
                {
                    ["principal"] = "new@example.test"
                });
                isError = result.IsError == true;
                error = string.Join(" ", result.Content.OfType<TextContentBlock>().Select(block => block.Text));
            }
            catch (Exception exception)
            {
                isError = true;
                error = exception.Message;
            }

            Expect(isError && responder.Calls == 1 && exchange.MutationCount == 1
                && exchange.Items.All(item => item.User.Principal != "new@example.test")
                && error.Contains(expectedMessage, StringComparison.Ordinal)
                && !error.Contains("delegate_list", StringComparison.Ordinal)
                && !error.Contains("reconcile before retrying", StringComparison.OrdinalIgnoreCase)
                && !error.Contains("SYNTHETIC_NATIVE_SECRET", StringComparison.Ordinal),
                $"Definitive native delegate rejection {code} was treated as an uncertain write or exposed response details.");
        }
    }

    private async Task AssertDelegateReadbackFailureAfterWriteNativeAsync()
    {
        var exchange = new DelegateMcpRecordingHandler([], "DelegatesAndMe")
        {
            NativeGetErrorForRead = readNumber => readNumber is 4 or 5 ? "ErrorServerBusy" : null
        };
        await using var host = await StartSharingHostAsync(exchange, writesEnabled: true, sendEnabled: true,
            classicStateful: true);
        var responder = new NativeFormResponder(accept: true);
        await using var client = await CreateNativeClientAsync(host,
            Token("user-a", "mail.read mail.manage", sessionId: "delegate-readback-failure"), responder);
        var isError = false;
        var error = string.Empty;
        try
        {
            var result = await client.Client.CallToolAsync("delegate_add", new Dictionary<string, object?>
            {
                ["principal"] = "new@example.test",
                ["calendarPermissionLevel"] = "Reviewer"
            });
            isError = result.IsError == true;
            error = string.Join(" ", result.Content.OfType<TextContentBlock>().Select(block => block.Text));
        }
        catch (Exception exception)
        {
            isError = true;
            error = exception.Message;
        }

        Expect(isError && responder.Calls == 1 && exchange.MutationCount == 1 && exchange.GetDelegateReadCount == 4
            && exchange.Items.SingleOrDefault(item => item.User.Principal == "new@example.test") is not null
            && error.Contains("delegate_list", StringComparison.Ordinal)
            && error.Contains("reconcile before retrying", StringComparison.OrdinalIgnoreCase)
            && error.Contains("GetDelegate failed (ErrorServerBusy)", StringComparison.Ordinal)
            && !error.Contains("SYNTHETIC_NATIVE_SECRET", StringComparison.Ordinal),
            "A post-write delegate readback failure did not remain explicitly uncertain and reconciliation-required.");
    }

    private async Task AssertDelegatePostAckReadRetryNativeAsync()
    {
        var exchange = new DelegateMcpRecordingHandler([], "DelegatesAndMe")
        {
            NativeGetErrorForRead = readNumber => readNumber == 4 ? "ErrorInternalServerTransientError" : null
        };
        await using var host = await StartSharingHostAsync(exchange, writesEnabled: true, sendEnabled: true,
            classicStateful: true);
        var responder = new NativeFormResponder(accept: true);
        await using var client = await CreateNativeClientAsync(host,
            Token("user-a", "mail.read mail.manage", sessionId: "delegate-post-ack-read-retry"), responder);
        var result = await client.Client.CallToolAsync("delegate_add", new Dictionary<string, object?>
        {
            ["principal"] = "new@example.test",
            ["calendarPermissionLevel"] = "Reviewer"
        });

        Expect(result.IsError != true && NativeData(result).GetProperty("status").GetString() == "delegate_added"
            && responder.Calls == 1 && exchange.MutationCount == 1
            && exchange.GetDelegateReadCount == 5
            && exchange.Items.SingleOrDefault(item => item.User.Principal == "new@example.test")?.CalendarFolderPermissionLevel == "Reviewer"
            && exchange.Delivery == "DelegatesAndMe",
            "A transient post-ACK GetDelegate failure was not retried exactly once without repeating the write.");
    }

    private async Task AssertDelegatePostAckReadTransportFailureNativeAsync()
    {
        var exchange = new DelegateMcpRecordingHandler([], "DelegatesAndMe")
        {
            ThrowOnGetDelegateRead = readNumber => readNumber == 4
        };
        await using var host = await StartSharingHostAsync(exchange, writesEnabled: true, sendEnabled: true,
            classicStateful: true);
        var responder = new NativeFormResponder(accept: true);
        await using var client = await CreateNativeClientAsync(host,
            Token("user-a", "mail.read mail.manage", sessionId: "delegate-post-ack-transport-failure"), responder);
        var result = await client.Client.CallToolAsync("delegate_add", new Dictionary<string, object?>
        {
            ["principal"] = "new@example.test",
            ["calendarPermissionLevel"] = "Reviewer"
        });
        var error = string.Join(" ", result.Content.OfType<TextContentBlock>().Select(block => block.Text));

        Expect(result.IsError == true && responder.Calls == 1 && exchange.MutationCount == 1
            && exchange.GetDelegateReadCount == 4
            && exchange.Items.SingleOrDefault(item => item.User.Principal == "new@example.test") is not null
            && error.Contains("delegate_list", StringComparison.Ordinal)
            && error.Contains("reconcile before retrying", StringComparison.OrdinalIgnoreCase)
            && !error.Contains("SYNTHETIC_NATIVE_SECRET", StringComparison.Ordinal),
            "A transport failure after delegate mutation was not reported as sanitized uncertain state without a second read or write.");
    }

    private async Task AssertDelegateMissingConfigurationPostAckReadRetryNativeAsync()
    {
        var exchange = new DelegateMcpRecordingHandler([], "DelegatesAndMe")
        {
            NativeGetErrorForRead = readNumber => readNumber == 4 ? "ErrorDelegateMissingConfiguration" : null
        };
        await using var host = await StartSharingHostAsync(exchange, writesEnabled: true, sendEnabled: true,
            classicStateful: true);
        var responder = new NativeFormResponder(accept: true);
        await using var client = await CreateNativeClientAsync(host,
            Token("user-a", "mail.read mail.manage", sessionId: "delegate-missing-configuration-retry"), responder);
        var result = await client.Client.CallToolAsync("delegate_add", new Dictionary<string, object?>
        {
            ["principal"] = "new@example.test",
            ["calendarPermissionLevel"] = "Reviewer"
        });

        Expect(result.IsError != true && NativeData(result).GetProperty("status").GetString() == "delegate_added"
            && responder.Calls == 1 && exchange.MutationCount == 1
            && exchange.GetDelegateReadCount == 5
            && exchange.Items.SingleOrDefault(item => item.User.Principal == "new@example.test")?.CalendarFolderPermissionLevel == "Reviewer"
            && exchange.Delivery == "DelegatesAndMe",
            "A post-ACK ErrorDelegateMissingConfiguration did not receive exactly one delayed read retry and full verification without repeating the write.");
    }

    private async Task AssertDelegateReadbackReconciliationAsync(DelegateMcpRecordingHandler exchange,
        string sessionId, string failure, Func<bool> mismatchWasInjected)
    {
        await using var host = await StartSharingHostAsync(exchange, writesEnabled: true, sendEnabled: true,
            classicStateful: true);
        var responder = new NativeFormResponder(accept: true);
        await using var client = await CreateNativeClientAsync(host,
            Token("user-a", "mail.read mail.manage", sessionId: sessionId), responder);
        var error = string.Empty;
        try
        {
            var result = await client.Client.CallToolAsync("delegate_add", new Dictionary<string, object?>
            {
                ["principal"] = "new@example.test",
                ["calendarPermissionLevel"] = "Reviewer"
            });
            error = string.Join(" ", result.Content.OfType<TextContentBlock>().Select(block => block.Text));
        }
        catch (Exception exception)
        {
            error = exception.Message;
        }

        var added = exchange.Items.SingleOrDefault(item => item.User.Principal == "new@example.test");
        Expect(exchange.MutationCount == 1 && responder.Calls == 1 && added is not null
            && mismatchWasInjected()
            && error.Contains("delegate_list", StringComparison.Ordinal)
            && error.Contains("reconcile before retrying", StringComparison.OrdinalIgnoreCase),
            $"{failure}: MCP did not reject the mismatch after one write with a clear reconciliation instruction.");
    }

    private async Task AssertDelegateAmbiguousListNativeAsync()
    {
        var exchange = new DelegateMcpRecordingHandler([
            Delegate("target@example.test", "Reviewer", "None", "None", "None", "None", "None", false, false),
            Delegate("TARGET@example.test", "Editor", "None", "None", "None", "None", "None", false, false)
        ], "DelegatesAndMe");
        await using var host = await StartSharingHostAsync(exchange, writesEnabled: true, sendEnabled: true,
            classicStateful: true);
        var responder = new NativeFormResponder(accept: true);
        await using var client = await CreateNativeClientAsync(host,
            Token("user-a", "mail.read mail.manage", sessionId: "delegate-ambiguous"), responder);
        var rejected = await NativeRejectedAsync(client.Client, "delegate_remove", new Dictionary<string, object?>
        {
            ["principal"] = "target@example.test"
        });

        Expect(rejected && responder.Calls == 0 && exchange.MutationCount == 0,
            "An ambiguous duplicate delegate principal reached native approval or Exchange.");
    }

    private async Task AssertDelegateMissingDeliveryNativeAsync()
    {
        var exchange = new DelegateMcpRecordingHandler(
            [Delegate("other@example.test", "Reviewer", "Editor", "None", "Author", "None", "Reviewer", false, false)],
            delivery: null);
        await using var host = await StartSharingHostAsync(exchange, writesEnabled: true, sendEnabled: true,
            classicStateful: true);
        var responder = new NativeFormResponder(accept: true);
        await using var client = await CreateNativeClientAsync(host,
            Token("user-a", "mail.read mail.manage", sessionId: "delegate-delivery-unknown"), responder);
        var rejected = await NativeRejectedAsync(client.Client, "delegate_add", new Dictionary<string, object?>
        {
            ["principal"] = "new@example.test"
        });

        Expect(rejected && responder.Calls == 0 && exchange.MutationCount == 0,
            "Delegate addition proceeded when Exchange did not report the global meeting delivery setting to preserve.");
    }

    private async Task AssertDelegateVerifiedReplayLifecycleAsync()
    {
        var exchange = new DelegateMcpRecordingHandler([], "DelegatesAndMe");
        await using var host = await StartSharingHostAsync(exchange, writesEnabled: true, sendEnabled: true);
        var token = Token("user-a", "mail.read mail.manage", sessionId: "delegates-lifecycle");
        await InitializeAsync(host.Client, token, elicitation: true);
        var reviewerAdd = new Dictionary<string, object?>
        {
            ["principal"] = "delegate@example.test",
            ["calendarPermissionLevel"] = "Reviewer"
        };
        var firstAdd = await DelegateApprovedActionAsync(host.Client, token, "delegate_add", reviewerAdd);
        var oldApprovalReplay = await DelegateApprovalResumeAsync(host.Client, token, "delegate_add",
            firstAdd.State, reviewerAdd);
        var editorUpdate = await DelegateApprovedActionAsync(host.Client, token, "delegate_update",
            new Dictionary<string, object?>
            {
                ["principal"] = "delegate@example.test",
                ["calendarPermissionLevel"] = "Editor"
            });
        var removeAfterUpdate = await DelegateApprovedActionAsync(host.Client, token, "delegate_remove",
            new Dictionary<string, object?> { ["principal"] = "delegate@example.test" });
        var secondAdd = await DelegateApprovedActionAsync(host.Client, token, "delegate_add", reviewerAdd);
        var finalRemove = await DelegateApprovedActionAsync(host.Client, token, "delegate_remove",
            new Dictionary<string, object?> { ["principal"] = "delegate@example.test" });

        Expect(!IsToolError(firstAdd.Result.Body) && IsToolError(oldApprovalReplay.Body)
            && !IsToolError(editorUpdate.Result.Body) && !IsToolError(removeAfterUpdate.Result.Body)
            && !IsToolError(secondAdd.Result.Body) && !IsToolError(finalRemove.Result.Body)
            && exchange.MutationCount == 5 && exchange.Items.Count == 0
            && exchange.Delivery == "DelegatesAndMe",
            "A verified delegate attempt did not release the exact replay key for a later fresh approval, or an old approval was replayed.");
    }

    private async Task AssertDelegateUncertainReplayHoldAsync()
    {
        var cases = new (string Name, DelegateMcpRecordingHandler Exchange, string ToolName,
            Dictionary<string, object?> Arguments, bool MutationApplied)[]
        {
            ("native-write-error",
                new DelegateMcpRecordingHandler([], "DelegatesAndMe")
                {
                    NativeMutationErrorCode = "ErrorInternalServerError"
                },
                "delegate_add",
                new Dictionary<string, object?>
                {
                    ["principal"] = "delegate@example.test",
                    ["calendarPermissionLevel"] = "Reviewer"
                },
                false),
            ("post-write-readback-error",
                new DelegateMcpRecordingHandler([
                    Delegate("delegate@example.test", "Reviewer", "None", "None", "None", "None", "None", false, false)
                ], "DelegatesAndMe")
                {
                    NativeGetErrorForRead = readNumber => readNumber == 4
                        ? "ErrorInsufficientResources" : null
                },
                "delegate_update",
                new Dictionary<string, object?>
                {
                    ["principal"] = "delegate@example.test",
                    ["calendarPermissionLevel"] = "Reviewer"
                },
                true),
            ("persistent-post-write-missing-configuration",
                new DelegateMcpRecordingHandler([
                    Delegate("delegate@example.test", "Reviewer", "None", "None", "None", "None", "None", false, false)
                ], "DelegatesAndMe")
                {
                    NativeGetErrorForRead = readNumber => readNumber is 4 or 5
                        ? "ErrorDelegateMissingConfiguration" : null
                },
                "delegate_update",
                new Dictionary<string, object?>
                {
                    ["principal"] = "delegate@example.test",
                    ["calendarPermissionLevel"] = "Reviewer"
                },
                true)
        };
        foreach (var (name, exchange, toolName, arguments, mutationApplied) in cases)
        {
            await using var host = await StartSharingHostAsync(exchange, writesEnabled: true, sendEnabled: true);
            var token = Token("user-a", "mail.read mail.manage", sessionId: "delegates-uncertain-replay-" + name);
            await InitializeAsync(host.Client, token, elicitation: true);
            var first = await DelegateApprovedActionAsync(host.Client, token, toolName, arguments);
            var retry = await DelegateApprovedActionAsync(host.Client, token, toolName, arguments);
            var expectedDelegate = mutationApplied
                ? exchange.Items.SingleOrDefault(item => item.User.Principal == "delegate@example.test")
                : null;

            Expect(IsToolError(first.Result.Body)
                && first.Result.Body.Contains("reconcile before retrying", StringComparison.OrdinalIgnoreCase)
                && IsToolError(retry.Result.Body)
                && retry.Result.Body.Contains("already had an attempt", StringComparison.OrdinalIgnoreCase)
                && exchange.MutationCount == 1
                && (mutationApplied ? expectedDelegate?.CalendarFolderPermissionLevel == "Reviewer" : exchange.Items.Count == 0),
                $"The {name} delegate uncertainty did not retain its replay hold under a fresh approval.");
        }
    }

    private async Task AssertDelegateVerifiedRemoveResolvesUncertainHoldNativeAsync()
    {
        var exchange = new DelegateMcpRecordingHandler([], "DelegatesAndMe")
        {
            NativeGetErrorForRead = readNumber => readNumber == 4 ? "ErrorServerBusy" : null
        };
        await using var host = await StartSharingHostAsync(exchange, writesEnabled: true, sendEnabled: true);
        var token = Token("user-a", "mail.read mail.manage", sessionId: "delegate-verified-remove-resolves-hold");
        await InitializeAsync(host.Client, token, elicitation: true);
        var addArguments = new Dictionary<string, object?>
        {
            ["principal"] = "delegate@example.test",
            ["calendarPermissionLevel"] = "Reviewer"
        };
        var uncertainAdd = await DelegateApprovedActionAsync(host.Client, token, "delegate_add", addArguments);
        var list = await ToolRequestAsync(host.Client, token, "tools/call", new
        {
            name = "delegate_list",
            arguments = new { }
        }, JulyProtocolVersion);
        var remove = await DelegateApprovedActionAsync(host.Client, token, "delegate_remove",
            new Dictionary<string, object?> { ["principal"] = "delegate@example.test" });
        var oldApprovalReplay = await DelegateApprovalResumeAsync(host.Client, token, "delegate_add",
            uncertainAdd.State, addArguments);
        var freshAdd = await DelegateApprovedActionAsync(host.Client, token, "delegate_add", addArguments);
        var cleanup = await DelegateApprovedActionAsync(host.Client, token, "delegate_remove",
            new Dictionary<string, object?> { ["principal"] = "delegate@example.test" });

        Expect(IsToolError(uncertainAdd.Result.Body)
            && uncertainAdd.Result.Body.Contains("reconcile before retrying", StringComparison.OrdinalIgnoreCase)
            && list.Body.Contains("delegate@example.test", StringComparison.OrdinalIgnoreCase)
            && !IsToolError(remove.Result.Body)
            && IsToolError(oldApprovalReplay.Body)
            && oldApprovalReplay.Body.Contains("invalid, expired or already used", StringComparison.OrdinalIgnoreCase)
            && !IsToolError(freshAdd.Result.Body)
            && !IsToolError(cleanup.Result.Body)
            && exchange.MutationCount == 4 && exchange.Items.Count == 0
            && exchange.Delivery == "DelegatesAndMe",
            "A verified removal did not resolve only the matching uncertain delegate hold while keeping the consumed approval unusable.");
    }

    private void AssertDelegateVerifiedRemoveClearsOnlyMatchingHolds()
    {
        var path = Path.Combine(runDirectory, "delegate-reconciliation", "audit.jsonl");
        using var protection = new DurableDataProtectionProvider(path);
        var store = new MailboxActionApprovalStore(protection, path);
        using var guard = new CalendarActionApprovalGuard(protection, store);
        var removal = Approval("mailbox@example.test", "delegate_remove", "target@example.test", "remove");
        var matchingAdd = Approval("mailbox@example.test", "delegate_add", "target@example.test", "add");
        var matchingUpdate = Approval("mailbox@example.test", "delegate_update", "TARGET@example.test", "update");
        var otherPrincipal = Approval("mailbox@example.test", "delegate_add", "other@example.test", "other-principal");
        var otherMailbox = Approval("other@example.test", "delegate_add", "target@example.test", "other-mailbox");
        var nonDelegate = Approval("mailbox@example.test", "calendar_update", "target@example.test", "calendar");
        var otherDelegateAction = Approval("mailbox@example.test", "delegate_remove", "target@example.test", "remove-other");
        foreach (var held in new[] { removal, matchingAdd, matchingUpdate, otherPrincipal, otherMailbox, nonDelegate, otherDelegateAction })
        {
            store.Stage(held.Nonce, MailboxActionApprovalStore.Fingerprint(held), held.ExpiresAt);
            guard.Consume(held, held.ItemId, held.ChangeKey, held.Digest);
        }

        guard.CompleteVerified(removal);

        using var restartedGuard = new CalendarActionApprovalGuard(protection, new(protection, path));
        foreach (var cleared in new[] { removal, matchingAdd, matchingUpdate })
        {
            var fresh = cleared with { Nonce = Guid.NewGuid().ToString("N") };
            store.Stage(fresh.Nonce, MailboxActionApprovalStore.Fingerprint(fresh), fresh.ExpiresAt);
            restartedGuard.Consume(fresh, fresh.ItemId, fresh.ChangeKey, fresh.Digest);
        }
        foreach (var held in new[] { otherPrincipal, otherMailbox, nonDelegate, otherDelegateAction })
        {
            var fresh = held with { Nonce = Guid.NewGuid().ToString("N") };
            store.Stage(fresh.Nonce, MailboxActionApprovalStore.Fingerprint(fresh), fresh.ExpiresAt);
            ApprovalFailure(() => restartedGuard.Consume(fresh, fresh.ItemId, fresh.ChangeKey, fresh.Digest), "replay");
        }

        var consumedNonceRemainsDead = false;
        try { guard.Consume(matchingAdd, matchingAdd.ItemId, matchingAdd.ChangeKey, matchingAdd.Digest); }
        catch (ModelContextProtocol.McpException) { consumedNonceRemainsDead = true; }
        Expect(consumedNonceRemainsDead,
            "Verified reconciliation made the original consumed approval nonce usable again.");
    }

    private static CalendarActionApproval Approval(string mailbox, string action, string principal, string digest) =>
        new("subject", mailbox, action, principal, string.Empty, digest, Guid.NewGuid().ToString("N"), "client", null,
            ExpiresAt: DateTimeOffset.UtcNow + TimeSpan.FromMinutes(14));

    private async Task AssertDelegateReadRefusalNativeAsync()
    {
        foreach (var code in new[] { "ErrorInvalidOperation", "ErrorAccessDenied" })
        {
            var exchange = new DelegateMcpRecordingHandler([], "DelegatesAndMe")
            {
                NativeGetErrorCode = code
            };
            await using var host = await StartSharingHostAsync(exchange, writesEnabled: true, sendEnabled: true);
            var token = Token("user-a", "mail.read mail.manage", sessionId: "delegate-read-refusal-" + code);
            await InitializeAsync(host.Client, token, elicitation: true);
            var result = await ToolRequestAsync(host.Client, token, "tools/call", new
            {
                name = "delegate_add",
                arguments = new { principal = "delegate@example.test" }
            }, JulyProtocolVersion, elicitation: true);
            var refusal = code == "ErrorAccessDenied"
                ? "Exchange denied access to the selected mailbox"
                : $"Exchange refused the delegate-list read ({code})";

            Expect(IsToolError(result.Body)
                && result.Body.Contains(refusal, StringComparison.Ordinal)
                && result.Body.Contains("No delegate change was attempted", StringComparison.Ordinal)
                && !result.Body.Contains("SYNTHETIC_NATIVE_SECRET", StringComparison.Ordinal)
                && exchange.MutationCount == 0,
                $"The native GetDelegate refusal {code} did not provide a safe pre-write explanation through the MCP.");
        }
    }

    private async Task<(string State, (HttpStatusCode StatusCode, string Body) Result)> DelegateApprovedActionAsync(
        HttpClient client, string token, string toolName, IReadOnlyDictionary<string, object?> arguments)
    {
        var pending = await ToolRequestAsync(client, token, "tools/call", new
        {
            name = toolName,
            arguments
        }, JulyProtocolVersion, elicitation: true);
        var state = InputRequiredState(pending.Body);
        var result = await DelegateApprovalResumeAsync(client, token, toolName, state, arguments);
        return (state, result);
    }

    private static Task<(HttpStatusCode StatusCode, string Body)> DelegateApprovalResumeAsync(
        HttpClient client, string token, string toolName, string state,
        IReadOnlyDictionary<string, object?> arguments) =>
        ToolRequestAsync(client, token, "tools/call", new
        {
            name = toolName,
            requestState = state,
            inputResponses = new Dictionary<string, object?>
            {
                ["sharing_confirmation"] = new { action = "accept", content = new { confirm = true } }
            },
            arguments
        }, JulyProtocolVersion, elicitation: true);

    private static EwsDelegate Delegate(string principal, string? calendar, string? tasks, string? inbox,
        string? contacts, string? notes, string? journal, bool? copies, bool? viewPrivate,
        string? sid = null, string? displayName = null) =>
        new(new EwsSharingUserId(principal, displayName, null, null, sid),
            calendar, tasks, inbox, contacts, notes, journal, copies, viewPrivate);

    private static bool SameDelegateSettings(EwsDelegate expected, EwsDelegate actual) =>
        string.Equals(expected.User.Principal, actual.User.Principal, StringComparison.OrdinalIgnoreCase)
        && expected.CalendarFolderPermissionLevel == actual.CalendarFolderPermissionLevel
        && expected.TasksFolderPermissionLevel == actual.TasksFolderPermissionLevel
        && expected.InboxFolderPermissionLevel == actual.InboxFolderPermissionLevel
        && expected.ContactsFolderPermissionLevel == actual.ContactsFolderPermissionLevel
        && expected.NotesFolderPermissionLevel == actual.NotesFolderPermissionLevel
        && expected.JournalFolderPermissionLevel == actual.JournalFolderPermissionLevel
        && expected.ReceiveCopiesOfMeetingMessages == actual.ReceiveCopiesOfMeetingMessages
        && expected.ViewPrivateItems == actual.ViewPrivateItems;
}

internal sealed class DelegateMcpRecordingHandler(IEnumerable<EwsDelegate> items, string? delivery) : HttpMessageHandler
{
    public const string MessagesNamespace = "http://schemas.microsoft.com/exchange/services/2006/messages";
    public const string TypesNamespace = "http://schemas.microsoft.com/exchange/services/2006/types";
    private static readonly XNamespace Soap = "http://schemas.xmlsoap.org/soap/envelope/";
    private static readonly XNamespace Messages = MessagesNamespace;
    private static readonly XNamespace Types = TypesNamespace;

    public List<EwsDelegate> Items { get; } = items.ToList();
    public string? Delivery { get; private set; } = delivery;
    public int MutationCount { get; private set; }
    public string? LastMutationBody { get; private set; }
    public Action<string>? AfterMutation { get; set; }
    public string? NativeMutationErrorCode { get; init; }
    public string? NativeGetErrorCode { get; init; }
    public string? NativeGetErrorCodeAfterMutation { get; init; }
    public Func<int, string?>? NativeGetErrorForRead { get; init; }
    public Func<int, bool>? ThrowOnGetDelegateRead { get; init; }
    public int GetDelegateReadCount { get; private set; }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        var body = await request.Content!.ReadAsStringAsync(cancellationToken);
        var document = XDocument.Parse(body);
        var operation = document.Root!.Element(Soap + "Body")!.Elements().Single().Name.LocalName;
        var getDelegateReadNumber = operation == "GetDelegate" ? ++GetDelegateReadCount : 0;
        if (operation == "GetDelegate" && ThrowOnGetDelegateRead?.Invoke(getDelegateReadNumber) == true)
            throw new HttpRequestException("SYNTHETIC_NATIVE_SECRET");
        if (operation is "AddDelegate" or "UpdateDelegate" or "RemoveDelegate")
        {
            MutationCount++;
            LastMutationBody = body;
            if (NativeMutationErrorCode is null)
            {
                ApplyMutation(operation, document);
                AfterMutation?.Invoke(operation);
            }
        }

        var isMutation = operation is "AddDelegate" or "UpdateDelegate" or "RemoveDelegate";
        var scriptedReadError = operation == "GetDelegate" ? NativeGetErrorForRead?.Invoke(getDelegateReadNumber) : null;
        var response = operation == "GetDelegate" && scriptedReadError is { } scriptedError
            ? MutationResponse(operation, scriptedError)
            : operation == "GetDelegate" && MutationCount == 0 && NativeGetErrorCode is { } getError
            ? MutationResponse(operation, getError)
            : operation == "GetDelegate" && MutationCount > 0 && NativeGetErrorCodeAfterMutation is { } readbackError
            ? MutationResponse(operation, readbackError)
            : isMutation && NativeMutationErrorCode is { } mutationError
                ? MutationResponse(operation, mutationError)
                : operation == "GetDelegate" ? GetDelegatesResponse() : MutationResponse(operation);
        return new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(response.ToString(SaveOptions.DisableFormatting), Encoding.UTF8, "text/xml")
        };
    }

    private void ApplyMutation(string operation, XDocument request)
    {
        if (operation == "RemoveDelegate")
        {
            var user = request.Descendants(Types + "UserId").Single();
            var principal = user.Element(Types + "PrimarySmtpAddress")?.Value ?? string.Empty;
            Items.RemoveAll(item => string.Equals(item.User.Principal, principal, StringComparison.OrdinalIgnoreCase));
            return;
        }

        var requested = ParseDelegateUser(request.Descendants(Types + "DelegateUser").Single());
        var currentIndex = Items.FindIndex(item =>
            string.Equals(item.User.Principal, requested.User.Principal, StringComparison.OrdinalIgnoreCase));
        if (operation == "AddDelegate")
        {
            if (currentIndex < 0) Items.Add(requested);
        }
        else if (currentIndex >= 0)
        {
            Items[currentIndex] = requested with { User = Items[currentIndex].User };
        }

        var requestedDelivery = request.Descendants(Messages + "DeliverMeetingRequests").SingleOrDefault()?.Value;
        if (requestedDelivery is not null) Delivery = requestedDelivery;
    }

    private static EwsDelegate ParseDelegateUser(XElement element)
    {
        var user = element.Element(Types + "UserId")!;
        var identity = new EwsSharingUserId(
            user.Element(Types + "PrimarySmtpAddress")?.Value,
            user.Element(Types + "DisplayName")?.Value,
            user.Element(Types + "DistinguishedUser")?.Value,
            user.Element(Types + "ExternalUserIdentity")?.Value,
            user.Element(Types + "SID")?.Value);
        var permissions = element.Element(Types + "DelegatePermissions");
        return new EwsDelegate(identity,
            permissions?.Element(Types + "CalendarFolderPermissionLevel")?.Value,
            permissions?.Element(Types + "TasksFolderPermissionLevel")?.Value,
            permissions?.Element(Types + "InboxFolderPermissionLevel")?.Value,
            permissions?.Element(Types + "ContactsFolderPermissionLevel")?.Value,
            permissions?.Element(Types + "NotesFolderPermissionLevel")?.Value,
            permissions?.Element(Types + "JournalFolderPermissionLevel")?.Value,
            ReadNullableBoolean(element.Element(Types + "ReceiveCopiesOfMeetingMessages")),
            ReadNullableBoolean(element.Element(Types + "ViewPrivateItems")));
    }

    private XDocument GetDelegatesResponse()
    {
        var response = new XElement(Messages + "GetDelegateResponse",
            new XAttribute("ResponseClass", "Success"),
            new XElement(Messages + "ResponseCode", "NoError"),
            Items.Count == 0 ? null : new XElement(Messages + "ResponseMessages",
                Items.Select(item => new XElement(Messages + "DelegateUserResponseMessageType",
                    new XAttribute("ResponseClass", "Success"),
                    new XElement(Messages + "ResponseCode", "NoError"),
                    BuildDelegateUser(item)))));
        if (Delivery is not null) response.Add(new XElement(Messages + "DeliverMeetingRequests", Delivery));
        return Envelope(response);
    }

    private static XElement BuildDelegateUser(EwsDelegate item)
    {
        var user = new XElement(Types + "UserId");
        if (item.User.Sid is not null) user.Add(new XElement(Types + "SID", item.User.Sid));
        if (item.User.PrimarySmtpAddress is not null) user.Add(new XElement(Types + "PrimarySmtpAddress", item.User.PrimarySmtpAddress));
        if (item.User.DisplayName is not null) user.Add(new XElement(Types + "DisplayName", item.User.DisplayName));
        if (item.User.DistinguishedUser is not null) user.Add(new XElement(Types + "DistinguishedUser", item.User.DistinguishedUser));
        if (item.User.ExternalUserIdentity is not null) user.Add(new XElement(Types + "ExternalUserIdentity", item.User.ExternalUserIdentity));
        var permissions = new XElement(Types + "DelegatePermissions");
        AddOptional(permissions, "CalendarFolderPermissionLevel", item.CalendarFolderPermissionLevel);
        AddOptional(permissions, "TasksFolderPermissionLevel", item.TasksFolderPermissionLevel);
        AddOptional(permissions, "InboxFolderPermissionLevel", item.InboxFolderPermissionLevel);
        AddOptional(permissions, "ContactsFolderPermissionLevel", item.ContactsFolderPermissionLevel);
        AddOptional(permissions, "NotesFolderPermissionLevel", item.NotesFolderPermissionLevel);
        AddOptional(permissions, "JournalFolderPermissionLevel", item.JournalFolderPermissionLevel);
        return new XElement(Messages + "DelegateUser", user, permissions,
            item.ReceiveCopiesOfMeetingMessages is { } copies
                ? new XElement(Types + "ReceiveCopiesOfMeetingMessages", copies) : null,
            item.ViewPrivateItems is { } viewPrivate
                ? new XElement(Types + "ViewPrivateItems", viewPrivate) : null);
    }

    private static XDocument MutationResponse(string operation, string? errorCode = null) =>
        Envelope(new XElement(Messages + (operation + "Response"),
            new XAttribute("ResponseClass", "Success"),
            new XElement(Messages + "ResponseCode", "NoError"),
            new XElement(Messages + "ResponseMessages",
                new XElement(Messages + "DelegateUserResponseMessageType",
                    new XAttribute("ResponseClass", errorCode is null ? "Success" : "Error"),
                    new XElement(Messages + "ResponseCode", errorCode ?? "NoError"),
                    errorCode is null ? null : new XElement(Messages + "MessageText", "SYNTHETIC_NATIVE_SECRET")))));

    private static XDocument Envelope(XElement response) =>
        new(new XElement(Soap + "Envelope",
            new XAttribute(XNamespace.Xmlns + "s", Soap.NamespaceName),
            new XAttribute(XNamespace.Xmlns + "m", Messages.NamespaceName),
            new XAttribute(XNamespace.Xmlns + "t", Types.NamespaceName),
            new XElement(Soap + "Body", response)));

    private static bool? ReadNullableBoolean(XElement? element) =>
        element is null ? null : bool.Parse(element.Value);

    private static void AddOptional(XElement parent, string name, string? value)
    {
        if (value is not null) parent.Add(new XElement(Types + name, value));
    }
}
