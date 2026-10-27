using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Xml.Linq;
using Company.ExchangeMcp;
using Company.ExchangeMcp.Exchange;
using Company.ExchangeMcp.Security;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;

internal sealed partial class Checks
{
    private async Task DeferredMailboxChecksAsync()
    {
        var exchange = new DelegatedMailboxEwsHandler();
        var auditPath = Path.Combine(runDirectory, "delegated-audit.jsonl");
        await using var host = await StartDelegatedHostAsync(exchange, auditPath);
        var token = Token("user-a", "mail.read mail.write mail.manage mail.send", sessionId: "delegated-a");

        var sessionlessListing = await ToolRequestAsync(host.Client,
            Token("user-a", "mail.read"), "tools/call", new
            {
                name = "mail_list_mailboxes",
                arguments = new { }
            });
        Expect(!IsToolError(sessionlessListing.Body)
            && JsonArrayProperty(ToolStructuredData(sessionlessListing.Body), "items").Length == 1,
            "A sessionless actor was offered delegated mailbox selectors.");

        var tools = await ToolRequestAsync(host.Client, token, "tools/list", new { });
        Expect(tools.StatusCode == HttpStatusCode.OK, "Delegated tools/list failed.");
        using (var document = ParseJson(tools.Body))
        {
            var schemas = document.RootElement.GetProperty("result").GetProperty("tools");
            foreach (var tool in schemas.EnumerateArray())
            {
                var toolName = tool.GetProperty("name").GetString();
                var inputSchema = tool.GetProperty("inputSchema");
                var properties = inputSchema.GetProperty("properties");
                if (toolName is "mail_review_email" or "mail_review_signature" or "mail_preview_saved_signature")
                    Expect(inputSchema.GetProperty("type").GetString() == "object"
                        && !properties.EnumerateObject().Any()
                        && (!inputSchema.TryGetProperty("required", out var required) || required.GetArrayLength() == 0),
                        $"Native entrypoint {toolName} requires arguments or exposed a mailbox selector.");
                else if (toolName is "mail_list_mailboxes" or ConnectionTools.ContinuationTool)
                    Expect(!properties.TryGetProperty("mailboxHandle", out _),
                        $"Own-only tool {toolName} unexpectedly exposed a mailbox selector.");
                else
                    Expect(properties.TryGetProperty("mailboxHandle", out var selector)
                        && selector.ValueKind == JsonValueKind.Object
                        && selector.GetProperty("type").GetString() == "string",
                        $"Tool {toolName} omitted the mailbox selector schema.");
            }
        }

        foreach (var name in new[] { "mail_review_email", "mail_review_signature", "mail_preview_saved_signature" })
        {
            var emptyReview = await ToolRequestAsync(host.Client, token, "tools/call", new { name, arguments = new { } });
            Expect(emptyReview.StatusCode == HttpStatusCode.OK && !IsToolError(emptyReview.Body)
                && ToolStructuredData(emptyReview.Body).GetProperty("status").GetString() == "review_empty",
                $"Native entrypoint {name} rejected its argument-free own-connection invocation.");
        }

        var listed = await ToolRequestAsync(host.Client, token, "tools/call", new
        {
            name = "mail_list_mailboxes",
            arguments = new { }
        });
        Expect(!IsToolError(listed.Body), "mail_list_mailboxes failed for the enrolled actor.");
        var mailboxes = JsonArrayProperty(ToolStructuredData(listed.Body), "items", "mailboxes");
        Expect(mailboxes.Length == 2, "Mailbox discovery returned an unexpected target count.");
        var own = mailboxes.Single(item => item.GetProperty("mailbox").GetString() == "alice@example.test");
        var target = mailboxes.Single(item => item.GetProperty("mailbox").GetString() == "it@example.test");
        Expect(!HasStringProperty(own, "handle", "mailboxHandle"),
            "The actor's own mailbox unexpectedly received a selector handle.");
        var targetHandle = StringProperty(target, "handle", "mailboxHandle");
        Expect(!string.IsNullOrWhiteSpace(targetHandle) && targetHandle != "it@example.test",
            "The delegated mailbox selector was not opaque.");
        Expect(target.TryGetProperty("kind", out var delegated) && delegated.GetString() == "delegated",
            "The delegated mailbox was not marked as a delegated target.");
        Expect(!mailboxes.Any(item => item.GetProperty("mailbox").GetString() == "stale@example.test"),
            "A legacy static mailbox target bypassed the live discovery provider.");

        var discovery = (TestMailboxDiscovery)host.App.Services.GetRequiredService<IMailboxDiscovery>();
        var beforeIncompleteList = exchange.Calls.Count;
        discovery.SetFolderDiscoveryComplete(DiscoveryMailboxKey, complete: false);
        var incompleteFolders = await ToolRequestAsync(host.Client, token, "tools/call", new
        {
            name = "mail_list_folders",
            arguments = new { mailboxHandle = targetHandle }
        });
        Expect(IsToolError(incompleteFolders.Body) && exchange.Calls.Count == beforeIncompleteList,
            "A delegated mailbox returned a partial folder list as if it were complete.");
        discovery.SetFolderDiscoveryComplete(DiscoveryMailboxKey, complete: true);

        var profile = await ToolRequestAsync(host.Client, token, "tools/call", new
        {
            name = "mail_profile",
            arguments = new { mailboxHandle = targetHandle }
        });
        Expect(!IsToolError(profile.Body), "mail_profile could not select the approved target.");
        var profileData = ToolStructuredData(profile.Body);
        Expect(profileData.GetProperty("actorMailbox").GetString() == "alice@example.test"
            && profileData.GetProperty("mailbox").GetString() == "it@example.test"
            && profileData.GetProperty("delegated").GetBoolean(),
            "mail_profile did not distinguish actor and selected mailbox.");
        var capabilities = profileData.GetProperty("capabilities");
        Expect(capabilities.GetProperty("tasks").GetBoolean()
            && capabilities.GetProperty("contacts").GetBoolean()
            && capabilities.GetProperty("signatures").GetString() == "mailbox_profiles_for_mcp_composed_mail"
            && capabilities.GetProperty("recall").GetString() == "native_classic_outlook_request_with_reports",
            "Delegated mail_profile did not expose the reviewed contact, signature and recall capabilities.");

        var selectedSearch = await ToolRequestAsync(host.Client, token, "tools/call", new
        {
            name = "mail_search",
            arguments = new { folder = "inbox", offset = 0, limit = 1, mailboxHandle = targetHandle }
        });
        Expect(!IsToolError(selectedSearch.Body), "A selected mailbox search failed.");
        var selectedMessage = ToolStructuredData(selectedSearch.Body).GetProperty("items")[0]
            .GetProperty("handle").GetString()!;
        var selectedCall = exchange.Calls.Last(call => call.Operation == "FindItem");
        Expect(selectedCall.Anchor == "alice@example.test" && selectedCall.PrimarySmtpAddress == "alice@example.test"
            && DistinguishedFolderMailboxes(selectedCall).Length > 0
            && DistinguishedFolderMailboxes(selectedCall).All(owner => owner == "it@example.test"),
            $"A delegated EWS request did not preserve the actor identity while explicitly targeting the selected mailbox folder (anchor={selectedCall.Anchor ?? "(none)"}, primary={selectedCall.PrimarySmtpAddress ?? "(none)"}, folderOwner={DistinguishedFolderMailbox(selectedCall) ?? "(none)"}).");

        var ownSearch = await ToolRequestAsync(host.Client, token, "tools/call", new
        {
            name = "mail_search",
            arguments = new { folder = "inbox", offset = 0, limit = 1 }
        });
        Expect(!IsToolError(ownSearch.Body), "The actor's own mailbox search failed after delegation.");
        var ownMessage = ToolStructuredData(ownSearch.Body).GetProperty("items")[0]
            .GetProperty("handle").GetString()!;
        var ownCall = exchange.Calls.Last(call => call.Operation == "FindItem");
        Expect(ownCall.Anchor == "alice@example.test" && ownCall.PrimarySmtpAddress == "alice@example.test"
            && DistinguishedFolderMailboxes(ownCall).All(owner => owner is null),
            $"An omitted selector did not return to the actor's own mailbox (anchor={ownCall.Anchor}, primary={ownCall.PrimarySmtpAddress}, folderOwner={DistinguishedFolderMailbox(ownCall) ?? "(none)"}).");

        var selectedOwnItem = await ToolRequestAsync(host.Client, token, "tools/call", new
        {
            name = "mail_read",
            arguments = new { messageHandle = ownMessage, mailboxHandle = targetHandle }
        });
        Expect(IsToolError(selectedOwnItem.Body), "An own-mailbox item handle was accepted in the delegated mailbox.");
        var ownSelectedItem = await ToolRequestAsync(host.Client, token, "tools/call", new
        {
            name = "mail_read",
            arguments = new { messageHandle = selectedMessage }
        });
        Expect(IsToolError(ownSelectedItem.Body), "A delegated item handle was accepted in the actor mailbox.");

        var beforeIsolation = exchange.Calls.Count;
        var concurrentTarget = ToolRequestAsync(host.Client, token, "tools/call", new
        {
            name = "mail_search",
            arguments = new { folder = "inbox", offset = 0, limit = 1, mailboxHandle = targetHandle }
        });
        var concurrentOwn = ToolRequestAsync(host.Client, token, "tools/call", new
        {
            name = "mail_search",
            arguments = new { folder = "inbox", offset = 0, limit = 1 }
        });
        var concurrentResults = await Task.WhenAll(concurrentTarget, concurrentOwn);
        Expect(concurrentResults.All(result => result.StatusCode == HttpStatusCode.OK && !IsToolError(result.Body)),
            "Concurrent delegated and own mailbox calls did not both complete.");
        var concurrentCalls = exchange.Calls.Skip(beforeIsolation).Where(call => call.Operation == "FindItem").ToArray();
        Expect(concurrentCalls.Length == 2
            && concurrentCalls.All(call => call.Anchor == "alice@example.test"
                && call.PrimarySmtpAddress == "alice@example.test")
            && concurrentCalls.Count(call => DistinguishedFolderMailbox(call) == "it@example.test") == 1
            && concurrentCalls.Count(call => DistinguishedFolderMailbox(call) is null) == 1,
            "Concurrent calls leaked actor or selected-folder state across request scopes.");

        var bobRejected = await ToolRequestAsync(host.Client,
            Token("user-b", "mail.read", sessionId: "delegated-b"), "tools/call", new
            {
                name = "mail_profile",
                arguments = new { mailboxHandle = targetHandle }
            });
        Expect(IsToolError(bobRejected.Body), "A different actor replayed the delegated selector.");
        var clientRejected = await ToolRequestAsync(host.Client,
            Token("user-a", "mail.read", azp: "chatgpt-alt", sessionId: "delegated-a"), "tools/call", new
            {
                name = "mail_profile",
                arguments = new { mailboxHandle = targetHandle }
            });
        Expect(IsToolError(clientRejected.Body), "A different OAuth client replayed the delegated selector.");
        var sessionRejected = await ToolRequestAsync(host.Client,
            Token("user-a", "mail.read", sessionId: "delegated-other"), "tools/call", new
            {
                name = "mail_profile",
                arguments = new { mailboxHandle = targetHandle }
            });
        Expect(IsToolError(sessionRejected.Body), "A different OAuth session replayed the delegated selector.");

        foreach (var invalidSelector in new object?[] { "", "it@example.test", 42 })
        {
            var rejected = await ToolRequestAsync(host.Client, token, "tools/call", new
            {
                name = "mail_profile",
                arguments = new { mailboxHandle = invalidSelector }
            });
            Expect(IsToolError(rejected.Body), "An invalid mailbox selector reached a mailbox tool.");
        }
        var discoveryWithSelector = await ToolRequestAsync(host.Client, token, "tools/call", new
        {
            name = "mail_list_mailboxes",
            arguments = new { mailboxHandle = targetHandle }
        });
        Expect(IsToolError(discoveryWithSelector.Body),
            "Mailbox discovery accepted a selector instead of listing approved choices.");

        discovery.Rebind(DiscoveryMailboxKey, "reassigned@example.test");
        var reassigned = await ToolRequestAsync(host.Client, token, "tools/call", new
        {
            name = "mail_profile",
            arguments = new { mailboxHandle = targetHandle }
        });
        Expect(IsToolError(reassigned.Body), "A selector remained usable after its target address was reassigned.");
        discovery.Revoke(DiscoveryMailboxKey);
        var revoked = await ToolRequestAsync(host.Client, token, "tools/call", new
        {
            name = "mail_profile",
            arguments = new { mailboxHandle = targetHandle }
        });
        Expect(IsToolError(revoked.Body), "A revoked target selector remained usable.");
        var afterError = await ToolRequestAsync(host.Client, token, "tools/call", new
        {
            name = "mail_search",
            arguments = new { folder = "inbox", offset = 0, limit = 1 }
        });
        Expect(!IsToolError(afterError.Body)
            && exchange.Calls.Last(call => call.Operation == "FindItem").PrimarySmtpAddress == "alice@example.test",
            "A failed delegated selection left sticky request state behind.");

        await host.DisposeAsync();
        var audit = await File.ReadAllTextAsync(auditPath);
        Expect(audit.Contains("target", StringComparison.OrdinalIgnoreCase)
            && !audit.Contains("it@example.test", StringComparison.Ordinal),
            "Delegated audit entries did not identify the safe target without logging its address.");

        await AssertMailboxDiscoveryWithEmptyLegacyTargetsAsync();
        await AssertNativeApprovalTargetBindingAsync();
        await DelegatedCalendarTaskFolderDiscoveryChecksAsync();
    }

    private async Task AssertMailboxDiscoveryWithEmptyLegacyTargetsAsync()
    {
        var exchange = new DelegatedMailboxEwsHandler();
        await using var host = await StartDelegatedHostAsync(exchange,
            Path.Combine(runDirectory, "delegated-empty-legacy-targets-audit.jsonl"),
            includeLegacyTargetConfig: false);
        var settings = host.App.Services.GetRequiredService<IOptions<ServiceOptions>>().Value;
        Expect(settings.MailboxTargets.Count == 0,
            "The automatic discovery test unexpectedly used a legacy mailbox-target mapping.");
        var listed = await ToolRequestAsync(host.Client,
            Token("user-a", "mail.read", sessionId: "delegated-empty-targets"), "tools/call", new
            {
                name = "mail_list_mailboxes",
                arguments = new { }
            });
        var mailboxes = JsonArrayProperty(ToolStructuredData(listed.Body), "items", "mailboxes");
        Expect(!IsToolError(listed.Body) && mailboxes.Any(item => item.GetProperty("mailbox").GetString() == "it@example.test"),
            "Automatic mailbox discovery did not return the authorized delegated mailbox when the static mapping was empty.");
    }

    private async Task DelegatedActorContextChecksAsync()
    {
        var exchange = new DelegatedMailboxEwsHandler();
        var auditPath = Path.Combine(runDirectory, "delegated-actor-context-audit.jsonl");
        await using var host = await StartDelegatedHostAsync(exchange, auditPath);
        var token = Token("user-a", "mail.read mail.write mail.manage mail.send", sessionId: "delegated-actor-context");

        var listing = await ToolRequestAsync(host.Client, token, "tools/call", new
        {
            name = "mail_list_mailboxes",
            arguments = new { }
        });
        var targetHandle = StringProperty(JsonArrayProperty(ToolStructuredData(listing.Body), "items")
            .Single(item => item.GetProperty("kind").GetString() == "delegated"), "mailboxHandle");

        var selectedSearch = await ToolRequestAsync(host.Client, token, "tools/call", new
        {
            name = "mail_search",
            arguments = new { folder = "inbox", offset = 0, limit = 1, mailboxHandle = targetHandle }
        });
        Expect(!IsToolError(selectedSearch.Body), "The delegated actor-context search fixture did not complete.");
        var selectedCall = exchange.Calls.Last(call => call.Operation == "FindItem");
        Expect(selectedCall.Anchor == "alice@example.test"
            && selectedCall.PrimarySmtpAddress == "alice@example.test"
            && DistinguishedFolderMailboxes(selectedCall).Length > 0
            && DistinguishedFolderMailboxes(selectedCall).All(owner => owner == "it@example.test"),
            $"Delegated mail did not send the actor identity in EWS headers and the target mailbox in the folder reference (anchor={selectedCall.Anchor ?? "(none)"}, primary={selectedCall.PrimarySmtpAddress ?? "(none)"}, folderOwner={DistinguishedFolderMailbox(selectedCall) ?? "(none)"}).");

        var ownSearch = await ToolRequestAsync(host.Client, token, "tools/call", new
        {
            name = "mail_search",
            arguments = new { folder = "inbox", offset = 0, limit = 1 }
        });
        Expect(!IsToolError(ownSearch.Body), "The actor-context own search fixture did not complete.");
        var ownCall = exchange.Calls.Last(call => call.Operation == "FindItem");
        Expect(ownCall.Anchor == "alice@example.test"
            && ownCall.PrimarySmtpAddress == "alice@example.test"
            && DistinguishedFolderMailboxes(ownCall).All(owner => owner is null),
            "An omitted target leaked a foreign mailbox owner into an actor-owned EWS request.");

        var calendarBefore = exchange.Calls.Count;
        var calendarListing = await ToolRequestAsync(host.Client, token, "tools/call", new
        {
            name = "calendar_list_folders",
            arguments = new { mailboxHandle = targetHandle }
        });
        var calendarFolders = ToolStructuredData(calendarListing.Body);
        Expect(!IsToolError(calendarListing.Body) && calendarFolders.ValueKind == JsonValueKind.Array
                && calendarFolders.EnumerateArray().Any(folder => folder.GetProperty("folderClass").GetString() == "IPF.Appointment")
                && exchange.Calls.Count == calendarBefore,
            $"Delegated calendar listing did not use the actor-verified folder snapshot (error={IsToolError(calendarListing.Body)}, response={calendarListing.Body}, extra EWS calls={exchange.Calls.Count - calendarBefore}).");

        var blocked = new (string Name, object Arguments)[]
        {
            ("mail_oof", new { mailboxHandle = targetHandle })
        };
        var beforeBlocked = exchange.Calls.Count;
        foreach (var item in blocked)
        {
            var rejected = await ToolRequestAsync(host.Client, token, "tools/call", new
            {
                name = item.Name,
                arguments = item.Arguments
            });
            Expect(IsToolError(rejected.Body), $"Delegated tool {item.Name} was accepted although it remains intentionally own-mailbox only.");
        }
        Expect(exchange.Calls.Count == beforeBlocked,
            "An intentionally own-mailbox-only settings request reached EWS.");

        // Exchange folder ACL levels are read metadata. A viewer/editor ACL never adds the
        // actor's separate mail.send scope, so a delegated draft cannot be transmitted by
        // a read/write token even when the selected target is otherwise usable.
        // Target handles are bound to the actor, OAuth client and session that
        // issued them. Keep this reduced-scope token in the same session so the
        // probe tests the missing mail.send grant rather than stale-handle rejection.
        var readWriteToken = Token("user-a", "mail.read mail.write", sessionId: "delegated-actor-context");
        var draft = await ToolRequestAsync(host.Client, readWriteToken, "tools/call", new
        {
            name = "mail_create_draft",
            arguments = new
            {
                subject = "synthetic delegated permission probe",
                body = "synthetic body",
                to = new[] { "it@example.test" },
                mailboxHandle = targetHandle
            }
        });
        Expect(!IsToolError(draft.Body), "A read/write delegated actor could not create a synthetic draft for the send-scope check.");
        var draftHandle = ToolStructuredData(draft.Body).GetProperty("handle").GetString()!;
        var send = await ToolRequestAsync(host.Client, readWriteToken, "tools/call", new
        {
            name = "mail_send_draft",
            arguments = new { draftHandle, mailboxHandle = targetHandle }
        });
        Expect(IsToolError(send.Body) && exchange.SendCount == 0,
            "A delegated folder viewer/editor permission was treated as a mail.send grant.");
    }

    private async Task DelegatedCalendarTaskFolderDiscoveryChecksAsync()
    {
        var discovery = new TestMailboxDiscovery("user-a");
        discovery.SetFolderDiscovery(DiscoveryMailboxKey,
        [
            new("calendar-id", "Calendar", "IPF.Appointment", "calendar", new(true, true, false, false), "calendar-change"),
            new("calendar-custom-id", "Project Calendar", "IPF.Appointment", null, new(true, false, false, false), "custom-calendar-change"),
            new("tasks-id", "Tasks", "IPF.Task", "tasks", new(true, true, true, false), "tasks-change"),
            new("task-custom-id", "Project Tasks", "IPF.Task", null, new(true, false, false, false), "custom-task-change"),
            new("notes-id", "Notes", "IPF.Note", null, new(true, false, false, false), "notes-change")
        ], complete: true);
        var exchange = new DelegatedMailboxEwsHandler { EmptyCalendarAndTaskFindItems = true };
        var auditPath = Path.Combine(runDirectory, "delegated-calendar-task-folders-audit.jsonl");
        await using var host = await StartDelegatedHostAsync(exchange, auditPath, mailboxDiscovery: discovery);
        var token = Token("user-a", "mail.read", sessionId: "delegated-calendar-task-folders");
        var listing = await ToolRequestAsync(host.Client, token, "tools/call", new
        {
            name = "mail_list_mailboxes",
            arguments = new { }
        });
        var targetHandle = StringProperty(JsonArrayProperty(ToolStructuredData(listing.Body), "items")
            .Single(item => item.GetProperty("kind").GetString() == "delegated"), "mailboxHandle");

        var beforeFolderLists = exchange.Calls.Count;
        var calendarsResponse = await ToolRequestAsync(host.Client, token, "tools/call", new
        {
            name = "calendar_list_folders",
            arguments = new { mailboxHandle = targetHandle }
        });
        var calendars = ToolStructuredData(calendarsResponse.Body);
        Expect(!IsToolError(calendarsResponse.Body) && calendars.ValueKind == JsonValueKind.Array
            && calendars.EnumerateArray().Select(folder => folder.GetProperty("name").GetString())
                .Order(StringComparer.Ordinal).SequenceEqual(["Calendar", "Project Calendar"])
            && calendars.EnumerateArray().All(folder => folder.GetProperty("folderClass").GetString() == "IPF.Appointment")
            && exchange.Calls.Count == beforeFolderLists,
            $"Delegated calendar listing did not return only verified calendar-class folders from discovery (error={IsToolError(calendarsResponse.Body)}, response={calendarsResponse.Body}).");
        var calendarHandle = calendars.EnumerateArray().Single(folder => folder.GetProperty("name").GetString() == "Project Calendar")
            .GetProperty("handle").GetString()!;

        var tasksResponse = await ToolRequestAsync(host.Client, token, "tools/call", new
        {
            name = "task_list_folders",
            arguments = new { mailboxHandle = targetHandle }
        });
        var tasks = JsonArrayProperty(ToolStructuredData(tasksResponse.Body), "items");
        Expect(!IsToolError(tasksResponse.Body)
            && tasks.Select(folder => folder.GetProperty("name").GetString())
                .Order(StringComparer.Ordinal).SequenceEqual(["Project Tasks", "Tasks"])
            && tasks.All(folder => folder.GetProperty("folderClass").GetString() == "IPF.Task")
            && exchange.Calls.Count == beforeFolderLists,
            $"Delegated task listing did not return only verified task-class folders from discovery (error={IsToolError(tasksResponse.Body)}, response={tasksResponse.Body}).");
        var taskHandle = tasks.Single(folder => folder.GetProperty("name").GetString() == "Project Tasks")
            .GetProperty("handle").GetString()!;

        var beforeWrongType = exchange.Calls.Count;
        var taskWithCalendarHandle = await ToolRequestAsync(host.Client, token, "tools/call", new
        {
            name = "task_list",
            arguments = new { folder = calendarHandle, offset = 0, limit = 10, mailboxHandle = targetHandle }
        });
        var calendarWithTaskHandle = await ToolRequestAsync(host.Client, token, "tools/call", new
        {
            name = "calendar_list_events",
            arguments = new
            {
                folder = taskHandle,
                start = "2026-10-12T00:00:00Z",
                end = "2026-10-13T00:00:00Z",
                mailboxHandle = targetHandle
            }
        });
        Expect(IsToolError(taskWithCalendarHandle.Body) && IsToolError(calendarWithTaskHandle.Body)
            && exchange.Calls.Count == beforeWrongType,
            "A calendar-folder handle was accepted by a task tool or a task-folder handle by a calendar tool.");

        var calendarRead = await ToolRequestAsync(host.Client, token, "tools/call", new
        {
            name = "calendar_list_events",
            arguments = new
            {
                folder = calendarHandle,
                start = "2026-10-12T00:00:00Z",
                end = "2026-10-13T00:00:00Z",
                mailboxHandle = targetHandle
            }
        });
        var calendarReadCall = exchange.Calls.Last(call => call.Operation == "FindItem");
        Expect(!IsToolError(calendarRead.Body) && FolderIds(calendarReadCall).Contains("calendar-custom-id")
            && calendarReadCall.Anchor == "alice@example.test" && calendarReadCall.PrimarySmtpAddress == "alice@example.test",
            $"The delegated calendar handle did not bind its exact folder ID under the actor's EWS identity (error={IsToolError(calendarRead.Body)}, call={calendarReadCall.Body}).");

        var taskRead = await ToolRequestAsync(host.Client, token, "tools/call", new
        {
            name = "task_list",
            arguments = new { folder = taskHandle, offset = 0, limit = 10, mailboxHandle = targetHandle }
        });
        var taskReadCall = exchange.Calls.Last(call => call.Operation == "FindItem");
        Expect(!IsToolError(taskRead.Body) && FolderIds(taskReadCall).Contains("task-custom-id")
            && taskReadCall.Anchor == "alice@example.test" && taskReadCall.PrimarySmtpAddress == "alice@example.test",
            $"The delegated task handle did not bind its exact folder ID under the actor's EWS identity (error={IsToolError(taskRead.Body)}, call={taskReadCall.Body}).");

        discovery.SetFolderDiscoveryComplete(DiscoveryMailboxKey, complete: false);
        var beforeIncomplete = exchange.Calls.Count;
        var incompleteCalendars = await ToolRequestAsync(host.Client, token, "tools/call", new
        {
            name = "calendar_list_folders",
            arguments = new { mailboxHandle = targetHandle }
        });
        var incompleteTasks = await ToolRequestAsync(host.Client, token, "tools/call", new
        {
            name = "task_list_folders",
            arguments = new { mailboxHandle = targetHandle }
        });
        Expect(IsToolError(incompleteCalendars.Body) && IsToolError(incompleteTasks.Body)
            && exchange.Calls.Count == beforeIncomplete,
            "A partial delegated folder snapshot was presented as a complete calendar or task list.");

        discovery.SetFolderDiscoveryComplete(DiscoveryMailboxKey, complete: true);
        var beforeOwnCalendars = exchange.Calls.Count;
        var ownCalendars = await ToolRequestAsync(host.Client, token, "tools/call", new
        {
            name = "calendar_list_folders",
            arguments = new { }
        });
        var ownCalendarCalls = exchange.Calls.Skip(beforeOwnCalendars).Where(call => call.Operation is "GetFolder" or "FindFolder").ToArray();
        Expect(!IsToolError(ownCalendars.Body) && ownCalendarCalls.Length > 0
            && ownCalendarCalls.All(call => call.Anchor == "alice@example.test"
                && call.PrimarySmtpAddress == "alice@example.test" && DistinguishedFolderMailboxes(call).All(owner => owner is null)),
            "The actor's own calendar folder path no longer uses its unchanged native EWS request.");

        var beforeOwnTasks = exchange.Calls.Count;
        var ownTasks = await ToolRequestAsync(host.Client, token, "tools/call", new
        {
            name = "task_list_folders",
            arguments = new { }
        });
        var ownTaskCalls = exchange.Calls.Skip(beforeOwnTasks).Where(call => call.Operation is "GetFolder" or "FindFolder").ToArray();
        Expect(!IsToolError(ownTasks.Body) && ownTaskCalls.Length > 0
            && ownTaskCalls.All(call => call.Anchor == "alice@example.test"
                && call.PrimarySmtpAddress == "alice@example.test" && DistinguishedFolderMailboxes(call).All(owner => owner is null)),
            "The actor's own task folder path no longer uses its unchanged native EWS request.");
    }

    private async Task DelegatedMailboxAccessAndCalendarProbeChecksAsync()
    {
        var exchange = new DelegatedMailboxEwsHandler();
        var auditPath = Path.Combine(runDirectory, "delegated-access-audit.jsonl");
        await using var host = await StartDelegatedHostAsync(exchange, auditPath, classicStateful: true);
        var token = Token("user-a", "mail.read", sessionId: "delegated-access");
        await using var native = await CreateNativeClientAsync(host, token, new NativeFormResponder(accept: true));

        var listing = await native.Client.CallToolAsync("mail_list_mailboxes", new Dictionary<string, object?>());
        Expect(listing.IsError != true, "The actual MCP mailbox discovery call failed.");
        var targetHandle = StringProperty(NativeData(listing).GetProperty("items")
            .EnumerateArray().Single(item => item.GetProperty("kind").GetString() == "delegated"), "mailboxHandle");

        var access = await native.Client.CallToolAsync("mail_get_mailbox_access", new Dictionary<string, object?>
        {
            ["folder"] = "inbox",
            ["mailboxHandle"] = targetHandle
        });
        var accessError = string.Join(" | ", access.Content.OfType<TextContentBlock>().Select(item => item.Text));
        Expect(access.IsError != true, $"The actual MCP mail_get_mailbox_access call could not use the approved IT selector: {accessError} response={exchange.LastResponse} request={exchange.Calls.LastOrDefault(call => call.Operation == "GetFolder")?.Body}");
        var accessData = NativeData(access);
        Expect(accessData.GetProperty("actorMailbox").GetString() == "alice@example.test"
            && accessData.GetProperty("mailbox").GetString() == "it@example.test"
            && accessData.GetProperty("folder").GetProperty("read").GetString() == "true"
            && accessData.GetProperty("folder").GetProperty("create").GetString() == "false"
            && accessData.GetProperty("folder").GetProperty("modify").GetString() == "true"
            && accessData.GetProperty("folder").GetProperty("delete").GetString() == "false",
            "The mailbox access result did not distinguish the actor, selected mailbox, or effective rights.");
        var accessCall = exchange.Calls.Last(call => call.Operation == "GetFolder");
        Expect(accessCall.Anchor == "alice@example.test"
            && accessCall.PrimarySmtpAddress == "alice@example.test"
            && DistinguishedFolderMailboxes(accessCall).SequenceEqual(["it@example.test"]),
            "The actual MCP mailbox access request did not bind the actor headers and selected mailbox folder.");

        var validRights = NewEwsClient(new EffectiveRightsProbeHandler("1", "0", "1", "0"));
        var rights = await validRights.GetEffectiveRightsAsync("alice@example.test", "inbox", CancellationToken.None);
        Expect(rights.Read == true && rights.Create == false && rights.Modify == true && rights.Delete == false,
            "Exchange XML boolean 1/0 values were not interpreted as effective-rights booleans.");

        var missingRights = NewEwsClient(new EffectiveRightsProbeHandler(
            null, null, null, null, includeRights: false));
        var unknown = await missingRights.GetEffectiveRightsAsync(
            "alice@example.test", "inbox", CancellationToken.None);
        Expect(unknown.Read is null && unknown.Create is null
            && unknown.Modify is null && unknown.Delete is null,
            "A folder response without EffectiveRights metadata was treated as granted access.");
        var unknownRights = NewEwsClient(new EffectiveRightsProbeHandler("1", "maybe", "1", "0"));
        await AssertThrowsAsync<InvalidOperationException>(() => unknownRights.GetEffectiveRightsAsync(
            "alice@example.test", "inbox", CancellationToken.None));

        var folderProbe = new CalendarProbeHandler { FolderMode = CalendarFolderResponseMode.DecoyAndOne };
        var calendar = NewEwsClient(folderProbe);
        var folder = await calendar.GetCalendarFolderAsync("alice@example.test", "calendar", CancellationToken.None);
        Expect(folder.Id == "calendar-real" && folder.FolderClass == "IPF.Appointment"
            && folderProbe.LastBody.Contains("DistinguishedFolderId", StringComparison.Ordinal)
            && folderProbe.LastBody.Contains("Id=\"calendar\"", StringComparison.Ordinal),
            "The calendar probe did not request the distinguished Calendar folder or select the CalendarFolder result.");

        var multiple = NewEwsClient(new CalendarProbeHandler { FolderMode = CalendarFolderResponseMode.Multiple });
        var firstCalendar = await multiple.GetCalendarFolderAsync(
            "alice@example.test", "calendar", CancellationToken.None);
        Expect(firstCalendar.Id == "calendar-one",
            "Calendar folder parsing did not preserve the first Exchange CalendarFolder result.");
        await AssertThrowsAsync<InvalidOperationException>(() => NewEwsClient(
            new CalendarProbeHandler { FolderMode = CalendarFolderResponseMode.WrongType }).GetCalendarFolderAsync(
                "alice@example.test", "calendar", CancellationToken.None));

        var lexical = NewEwsClient(new CalendarProbeHandler { BooleanMode = CalendarBooleanResponseMode.OneZero });
        var eventData = await lexical.GetCalendarEventAsync("alice@example.test", "event-1", CancellationToken.None);
        Expect(eventData.IsMeeting && !eventData.IsOrganizer && eventData.IsAllDay
            && !eventData.IsRecurring && !eventData.IsCancelled,
            "Calendar XML boolean 1/0 values did not preserve the event's true and false meanings.");
        await AssertThrowsAsync<InvalidOperationException>(() => NewEwsClient(
            new CalendarProbeHandler { BooleanMode = CalendarBooleanResponseMode.MissingRequired }).GetCalendarEventAsync(
                "alice@example.test", "event-1", CancellationToken.None));
        await AssertThrowsAsync<InvalidOperationException>(() => NewEwsClient(
            new CalendarProbeHandler { BooleanMode = CalendarBooleanResponseMode.Unknown }).GetCalendarEventAsync(
                "alice@example.test", "event-1", CancellationToken.None));
    }

    private async Task DelegatedGroupwareAttachmentAndSyncChecksAsync()
    {
        var exchange = new DelegatedGroupwareEwsHandler();
        var auditPath = Path.Combine(runDirectory, "delegated-groupware-sync-audit.jsonl");
        await using var host = await StartDelegatedHostAsync(exchange, auditPath, classicStateful: true);
        var token = Token("user-a", "mail.read mail.write mail.manage mail.send", sessionId: "delegated-groupware");
        await using var alice = await CreateNativeClientAsync(host, token, new NativeFormResponder(accept: true));

        var listing = await alice.Client.CallToolAsync("mail_list_mailboxes", new Dictionary<string, object?>());
        Expect(listing.IsError != true, "The delegated groupware fixture could not list approved mailboxes.");
        var targetHandle = StringProperty(NativeData(listing).GetProperty("items")
            .EnumerateArray().Single(item => item.GetProperty("kind").GetString() == "delegated"), "mailboxHandle");

        var events = await alice.Client.CallToolAsync("calendar_list_events", new Dictionary<string, object?>
        {
            ["start"] = "2026-10-12T00:00:00Z",
            ["end"] = "2026-10-13T00:00:00Z",
            ["mailboxHandle"] = targetHandle
        });
        Expect(events.IsError != true, $"The delegated calendar event fixture failed: {ResultText(events)}");
        var eventHandle = NativeData(events).GetProperty("items")[0].GetProperty("handle").GetString()!;
        var calendarCall = exchange.Calls.Last(call => call.Operation == "FindItem");
        Expect(calendarCall.Anchor == "alice@example.test"
            && calendarCall.PrimarySmtpAddress == "alice@example.test"
            && DistinguishedFolderMailboxes(calendarCall).SequenceEqual(["it@example.test"]),
            "The delegated calendar list did not preserve actor headers and the selected IT calendar folder.");

        var attachments = await alice.Client.CallToolAsync("groupware_list_attachments", new Dictionary<string, object?>
        {
            ["kind"] = "calendar",
            ["itemHandle"] = eventHandle,
            ["mailboxHandle"] = targetHandle
        });
        Expect(attachments.IsError != true, $"The delegated calendar attachment list failed: {ResultText(attachments)}");
        var attachmentHandle = NativeData(attachments).GetProperty("items")[0].GetProperty("handle").GetString()!;
        var attachmentListCall = exchange.Calls.Last(call => call.Operation == "GetItem");
        Expect(attachmentListCall.Anchor == "alice@example.test"
            && attachmentListCall.PrimarySmtpAddress == "alice@example.test",
            "The delegated attachment metadata request did not use the actor EWS identity.");

        var attachment = await alice.Client.CallToolAsync("groupware_read_attachment", new Dictionary<string, object?>
        {
            ["attachmentHandle"] = attachmentHandle,
            ["mailboxHandle"] = targetHandle
        });
        Expect(attachment.IsError != true
            && NativeData(attachment).GetProperty("contentBase64").GetString() == "bm90ZQ==",
            $"The delegated attachment could not be read through the selected mailbox: {ResultText(attachment)}");
        var attachmentCall = exchange.Calls.Last(call => call.Operation == "GetAttachment");
        Expect(attachmentCall.Anchor == "alice@example.test"
            && attachmentCall.PrimarySmtpAddress == "alice@example.test",
            "The delegated attachment content request did not use the actor EWS identity.");

        var beforeOwnReplay = exchange.Calls.Count;
        var ownReplay = await alice.Client.CallToolAsync("groupware_read_attachment", new Dictionary<string, object?>
        {
            ["attachmentHandle"] = attachmentHandle
        });
        Expect(ownReplay.IsError == true && exchange.Calls.Count == beforeOwnReplay,
            "A delegated attachment handle was accepted by the actor's own mailbox.");

        await using var bob = await CreateNativeClientAsync(host,
            Token("user-b", "mail.read", sessionId: "delegated-groupware-b"), new NativeFormResponder(accept: true));
        var beforeBob = exchange.Calls.Count;
        var bobReplay = await bob.Client.CallToolAsync("groupware_read_attachment", new Dictionary<string, object?>
        {
            ["attachmentHandle"] = attachmentHandle,
            ["mailboxHandle"] = targetHandle
        });
        Expect(bobReplay.IsError == true && exchange.Calls.Count == beforeBob,
            "A different actor replayed a delegated attachment handle.");

        await using var alternateClient = await CreateNativeClientAsync(host,
            Token("user-a", "mail.read", azp: "chatgpt-alt", sessionId: "delegated-groupware-alt"),
            new NativeFormResponder(accept: true));
        var beforeAlternate = exchange.Calls.Count;
        var alternateReplay = await alternateClient.Client.CallToolAsync("groupware_read_attachment",
            new Dictionary<string, object?> { ["attachmentHandle"] = attachmentHandle, ["mailboxHandle"] = targetHandle });
        Expect(alternateReplay.IsError == true && exchange.Calls.Count == beforeAlternate,
            "A delegated attachment handle crossed OAuth client boundaries.");

        await using var changedSession = await CreateNativeClientAsync(host,
            Token("user-a", "mail.read", sessionId: "delegated-groupware-other"), new NativeFormResponder(accept: true));
        var beforeSession = exchange.Calls.Count;
        var sessionReplay = await changedSession.Client.CallToolAsync("groupware_read_attachment",
            new Dictionary<string, object?> { ["attachmentHandle"] = attachmentHandle, ["mailboxHandle"] = targetHandle });
        Expect(sessionReplay.IsError == true && exchange.Calls.Count == beforeSession,
            "A delegated attachment handle crossed OAuth session boundaries.");

        var folders = await alice.Client.CallToolAsync("mail_sync_folders", new Dictionary<string, object?>
        {
            ["mailboxHandle"] = targetHandle
        });
        Expect(folders.IsError != true, $"The delegated folder synchronization baseline failed: {ResultText(folders)}");
        var folderCursor = NativeData(folders).GetProperty("cursor").GetString();
        Expect(!string.IsNullOrWhiteSpace(folderCursor), "The delegated folder synchronization response omitted its opaque cursor.");
        var syncFolderCall = exchange.Calls.Last(call => call.Operation == "SyncFolderHierarchy");
        Expect(syncFolderCall.Anchor == "alice@example.test"
            && syncFolderCall.PrimarySmtpAddress == "alice@example.test"
            && DistinguishedFolderMailboxes(syncFolderCall).SequenceEqual(["it@example.test"]),
            "Delegated folder synchronization did not bind actor headers and the selected target folder.");

        var beforeOwnCursor = exchange.Calls.Count;
        var ownCursor = await alice.Client.CallToolAsync("mail_sync_folders", new Dictionary<string, object?>
        {
            ["cursor"] = folderCursor
        });
        Expect(ownCursor.IsError == true && exchange.Calls.Count == beforeOwnCursor,
            "A delegated synchronization cursor was accepted by the actor's own mailbox.");
        var beforeBobCursor = exchange.Calls.Count;
        var bobCursor = await bob.Client.CallToolAsync("mail_sync_folders", new Dictionary<string, object?>
        {
            ["cursor"] = folderCursor
        });
        Expect(bobCursor.IsError == true && exchange.Calls.Count == beforeBobCursor,
            "A delegated synchronization cursor crossed actor boundaries.");

        var items = await alice.Client.CallToolAsync("mail_sync_items", new Dictionary<string, object?>
        {
            ["folder"] = "calendar",
            ["maxChanges"] = 10,
            ["mailboxHandle"] = targetHandle
        });
        Expect(items.IsError != true, $"The delegated item synchronization baseline failed: {ResultText(items)}");
        var itemCursor = NativeData(items).GetProperty("cursor").GetString();
        Expect(!string.IsNullOrWhiteSpace(itemCursor), "The delegated item synchronization response omitted its opaque cursor.");
        var syncItemsCall = exchange.Calls.Last(call => call.Operation == "SyncFolderItems");
        Expect(syncItemsCall.Anchor == "alice@example.test"
            && syncItemsCall.PrimarySmtpAddress == "alice@example.test"
            && DistinguishedFolderMailboxes(syncItemsCall).SequenceEqual(["it@example.test"]),
            "Delegated item synchronization did not bind actor headers and the selected target calendar.");
        var beforeOwnItemsCursor = exchange.Calls.Count;
        var ownItemsCursor = await alice.Client.CallToolAsync("mail_sync_items", new Dictionary<string, object?>
        {
            ["folder"] = "calendar",
            ["cursor"] = itemCursor
        });
        Expect(ownItemsCursor.IsError == true && exchange.Calls.Count == beforeOwnItemsCursor,
            "A delegated item synchronization cursor was accepted by the actor's own calendar.");
    }

    private async Task PermissionErrorsThroughActualMcpChecksAsync()
    {
        var sendExchange = new PermissionErrorEwsHandler
        {
            ErrorOperation = "SendItem",
            ErrorCode = "ErrorSendAsDenied"
        };
        await using var sendHost = await StartHostAsync(sendExchange, writesEnabled: true, sendEnabled: true,
            classicStateful: true);
        var sendToken = Token("user-a", "mail.read mail.write mail.manage mail.send", sessionId: "permission-send");
        await using var sendClient = await CreateNativeClientAsync(sendHost, sendToken,
            new NativeFormResponder(accept: true));
        var draft = await sendClient.Client.CallToolAsync("mail_create_draft", new Dictionary<string, object?>
        {
            ["subject"] = "synthetic permission send",
            ["body"] = "synthetic body",
            ["to"] = new[] { "to@example.test" }
        });
        Expect(draft.IsError != true, "The permission fixture could not create a synthetic draft.");
        var draftHandle = NativeData(draft).GetProperty("handle").GetString()!;
        var sendFailure = await sendClient.Client.CallToolAsync("mail_send_draft", new Dictionary<string, object?>
        {
            ["draftHandle"] = draftHandle
        });
        var sendText = ResultText(sendFailure);
        Expect(sendFailure.IsError == true
            && !sendText.Contains("synthetic-secret", StringComparison.Ordinal)
            && (sendText.Contains("ErrorSendAsDenied", StringComparison.Ordinal)
                || sendText.Contains("SendAs", StringComparison.OrdinalIgnoreCase)
                || sendText.Contains("SendOnBehalf", StringComparison.OrdinalIgnoreCase)),
            $"A SendAs permission error was not returned as a safe, specific MCP error: {sendText}");

        var responseExchange = new PermissionErrorEwsHandler
        {
            ErrorOperation = "RespondToMeeting",
            ErrorCode = "ErrorAccessDenied",
            IsOrganizer = false
        };
        EwsCalendarEvent responseProbe;
        try
        {
            responseProbe = await NewEwsClient(responseExchange).GetCalendarEventAsync(
                "alice@example.test", "event-1", CancellationToken.None);
        }
        catch (Exception exception)
        {
            throw new InvalidOperationException(
                $"The meeting-response permission fixture did not parse: {exception.Message}; request={responseExchange.LastRequestBody}", exception);
        }
        Expect(!responseProbe.IsOrganizer && responseProbe.IsMeeting
            && responseProbe.ResponseObjects.Contains("AcceptItem", StringComparer.Ordinal),
            "The meeting-response permission fixture did not produce a parseable attendee event.");
        await using var responseHost = await StartHostAsync(responseExchange, writesEnabled: true, sendEnabled: true,
            classicStateful: true);
        var responseToken = Token("user-a", "mail.read mail.write mail.manage mail.send", sessionId: "permission-response");
        await using var responseClient = await CreateNativeClientAsync(responseHost, responseToken,
            new NativeFormResponder(accept: true));
        var responseHandle = await CalendarEventHandleAsync(responseClient.Client);
        var responseFailure = await responseClient.Client.CallToolAsync("calendar_respond", new Dictionary<string, object?>
        {
            ["eventHandle"] = responseHandle,
            ["response"] = "accept",
            ["source"] = "calendar",
            ["scope"] = "event"
        });
        var responseText = ResultText(responseFailure);
        Expect(responseFailure.IsError == true
            && !responseText.Contains("synthetic-secret", StringComparison.Ordinal)
            && responseText.Contains("Exchange denied", StringComparison.OrdinalIgnoreCase),
            $"A meeting-response permission error was not safely mapped through the actual MCP: {responseText}; EWS operations={string.Join(",", responseExchange.Operations)}");

        var cancelExchange = new PermissionErrorEwsHandler
        {
            ErrorOperation = "CancelCalendarItem",
            ErrorCode = "ErrorAccessDenied",
            IsOrganizer = true
        };
        await using var cancelHost = await StartHostAsync(cancelExchange, writesEnabled: true, sendEnabled: true,
            classicStateful: true);
        var cancelToken = Token("user-a", "mail.read mail.write mail.manage mail.send", sessionId: "permission-cancel");
        await using var cancelClient = await CreateNativeClientAsync(cancelHost, cancelToken,
            new NativeFormResponder(accept: true));
        var cancelHandle = await CalendarEventHandleAsync(cancelClient.Client);
        var cancelFailure = await cancelClient.Client.CallToolAsync("calendar_delete_event", new Dictionary<string, object?>
        {
            ["eventHandle"] = cancelHandle,
            ["sendCancellations"] = true,
            ["scope"] = "event"
        });
        var cancelText = ResultText(cancelFailure);
        Expect(cancelFailure.IsError == true
            && !cancelText.Contains("synthetic-secret", StringComparison.Ordinal)
            && cancelText.Contains("Exchange denied", StringComparison.OrdinalIgnoreCase),
            $"A meeting-cancellation permission error was not safely mapped through the actual MCP: {cancelText}");

        var unknownExchange = new PermissionErrorEwsHandler
        {
            ErrorOperation = "SendItem",
            ErrorCode = "ErrorInternalFailure"
        };
        await using var unknownHost = await StartHostAsync(unknownExchange, writesEnabled: true, sendEnabled: true,
            classicStateful: true);
        await using var unknownClient = await CreateNativeClientAsync(unknownHost, sendToken,
            new NativeFormResponder(accept: true));
        var unknownDraft = await unknownClient.Client.CallToolAsync("mail_create_draft", new Dictionary<string, object?>
        {
            ["subject"] = "synthetic unknown error",
            ["body"] = "synthetic body",
            ["to"] = new[] { "to@example.test" }
        });
        var unknownHandle = NativeData(unknownDraft).GetProperty("handle").GetString()!;
        var unknownFailure = await unknownClient.Client.CallToolAsync("mail_send_draft", new Dictionary<string, object?>
        {
            ["draftHandle"] = unknownHandle
        });
        var unknownText = ResultText(unknownFailure);
        Expect(unknownFailure.IsError == true
            && !unknownText.Contains("synthetic-secret", StringComparison.Ordinal)
            && unknownText.Contains("verified success", StringComparison.OrdinalIgnoreCase),
            $"An unknown Exchange fault was not reduced to the generic safe MCP error: {unknownText}");
    }

    private static string ResultText(CallToolResult result) =>
        string.Join(" | ", result.Content.OfType<TextContentBlock>().Select(item => item.Text));

    private static async Task AssertListToolsFilterIsolationAsync()
    {
        using var schemaDocument = JsonDocument.Parse("{\"type\":\"object\",\"properties\":{\"folder\":{\"type\":\"string\"}}}");
        using var outputSchemaDocument = JsonDocument.Parse("{\"type\":\"object\",\"properties\":{\"items\":{\"type\":\"array\"}}}");
        var originalSchema = schemaDocument.RootElement.Clone();
        var originalTool = new ModelContextProtocol.Protocol.Tool
        {
            Name = "mail_search",
            Title = "Search mailbox",
            Description = "Original tool metadata",
            InputSchema = originalSchema,
            OutputSchema = outputSchemaDocument.RootElement.Clone(),
            Annotations = new ModelContextProtocol.Protocol.ToolAnnotations
            {
                Title = "Search safely",
                ReadOnlyHint = true,
                DestructiveHint = false,
                IdempotentHint = true,
                OpenWorldHint = false
            },
            Icons = [new ModelContextProtocol.Protocol.Icon
            {
                Source = "https://example.test/icon.svg",
                MimeType = "image/svg+xml",
                Sizes = ["16x16"],
                Theme = "light"
            }],
            Meta = new JsonObject { ["origin"] = "synthetic" }
        };
        var originalResult = new ModelContextProtocol.Protocol.ListToolsResult
        {
            Tools = [originalTool],
            NextCursor = "synthetic-cursor"
        };
        ModelContextProtocol.Server.McpRequestHandler<ModelContextProtocol.Protocol.ListToolsRequestParams,
            ModelContextProtocol.Protocol.ListToolsResult> downstream = (_, _) => new(originalResult);
        var wrapped = MailboxTargetFilters.WrapListTools(downstream);

        async Task<ModelContextProtocol.Protocol.ListToolsResult> InvokeAsync() =>
            await wrapped(null!, CancellationToken.None);
        var results = await Task.WhenAll(InvokeAsync(), InvokeAsync());

        Expect(results[0] is not null && results[1] is not null
            && !ReferenceEquals(results[0], originalResult)
            && !ReferenceEquals(results[1], originalResult)
            && !ReferenceEquals(results[0], results[1]),
            "tools/list filter reused or mutated the downstream result instance.");
        Expect(!originalTool.InputSchema.GetRawText().Contains("mailboxHandle", StringComparison.Ordinal),
            "tools/list filter mutated the cached downstream input schema.");
        foreach (var result in results)
        {
            var tool = result.Tools.Single();
            Expect(result.NextCursor == "synthetic-cursor"
                && tool.Name == "mail_search"
                && tool.Title == "Search mailbox"
                && tool.Description == "Original tool metadata"
                && tool.Annotations?.Title == "Search safely"
                && tool.Annotations.ReadOnlyHint == true
                && tool.Annotations.DestructiveHint == false
                && tool.Annotations.IdempotentHint == true
                && tool.Annotations.OpenWorldHint == false
                && tool.OutputSchema?.GetProperty("type").GetString() == "object"
                && tool.Meta?["origin"]?.GetValue<string>() == "synthetic"
                && tool.Icons?.Single().Source == "https://example.test/icon.svg"
                && tool.Icons.Single().MimeType == "image/svg+xml"
                && tool.Icons.Single().Sizes?.Single() == "16x16"
                && tool.Icons.Single().Theme == "light",
                "tools/list filter dropped tool or pagination metadata.");
            var properties = tool.InputSchema.GetProperty("properties");
            Expect(properties.TryGetProperty("mailboxHandle", out var selector)
                && selector.GetProperty("type").GetString() == "string",
                "tools/list filter did not add the opaque mailbox selector to the cloned schema.");
        }

        using var malformedSchemaDocument = JsonDocument.Parse("{\"type\":\"object\",\"properties\":\"invalid\"}");
        var malformedResult = new ModelContextProtocol.Protocol.ListToolsResult
        {
            Tools =
            [
                new ModelContextProtocol.Protocol.Tool
                {
                    Name = "mail_search",
                    InputSchema = malformedSchemaDocument.RootElement.Clone()
                }
            ]
        };
        ModelContextProtocol.Server.McpRequestHandler<ModelContextProtocol.Protocol.ListToolsRequestParams,
            ModelContextProtocol.Protocol.ListToolsResult> malformedDownstream = (_, _) => new(malformedResult);
        var malformedWrapped = MailboxTargetFilters.WrapListTools(malformedDownstream);
        var rejected = false;
        try
        {
            await malformedWrapped(null!, CancellationToken.None);
        }
        catch (McpException)
        {
            rejected = true;
        }
        Expect(rejected, "tools/list filter accepted a malformed tool schema instead of failing closed.");
    }

    private async Task AssertNativeApprovalTargetBindingAsync()
    {
        var exchange = new DelegatedMailboxEwsHandler();
        var auditPath = Path.Combine(runDirectory, "delegated-native-audit.jsonl");
        var permissions = new SyntheticPermissionReader(new MailboxPermissionReport(
            PermissionDecision.Unknown("synthetic full access"),
            new PermissionDecision("allowed", "synthetic SendAs", Direct: true),
            PermissionDecision.Unknown("synthetic Send on Behalf"),
            DateTimeOffset.UtcNow,
            "synthetic-delegated-send"));
        await using var host = await StartDelegatedHostAsync(exchange, auditPath,
            classicStateful: true, permissions: permissions);
        var token = Token("user-a", "mail.read mail.write mail.manage mail.send", sessionId: "delegated-native-a");
        var responder = new NativeFormResponder(accept: true);
        await using var alice = await CreateNativeClientAsync(host, token, responder);
        var listing = await alice.Client.CallToolAsync("mail_list_mailboxes", new Dictionary<string, object?>());
        Expect(!listing.IsError.GetValueOrDefault(), "The native approval host could not list delegated mailboxes.");
        var targetHandle = StringProperty(NativeData(listing).GetProperty("items")
            .EnumerateArray()
            .Single(item => item.GetProperty("kind").GetString() == "delegated"), "mailboxHandle");
        var draft = await alice.Client.CallToolAsync("mail_create_draft", new Dictionary<string, object?>
        {
            ["subject"] = "Delegated approval subject",
            ["body"] = "Delegated approval body",
            ["to"] = new[] { "it@example.test" },
            ["mailboxHandle"] = targetHandle
        });
        Expect(!draft.IsError.GetValueOrDefault(), "The delegated native draft could not be created.");
        var draftHandle = NativeData(draft).GetProperty("handle").GetString()!;
        var sent = await alice.Client.CallToolAsync("mail_send_draft", new Dictionary<string, object?>
        {
            ["draftHandle"] = draftHandle,
            ["mailboxHandle"] = targetHandle
        });
        var sentData = sent.IsError.GetValueOrDefault() ? default : NativeData(sent);
        var sentStatus = sentData.ValueKind == JsonValueKind.Object
            && sentData.TryGetProperty("status", out var sentStatusProperty)
            ? sentStatusProperty.GetString() : null;
        var sentPreview = responder.LastRequest?.Message ?? "(none)";
        var sentDiagnostic = string.Join(" | ", sent.Content.OfType<TextContentBlock>().Select(item => item.Text));
        Expect(!sent.IsError.GetValueOrDefault()
            && sentStatus == "sent"
            && sentPreview.Contains("Acting mailbox: it@example.test", StringComparison.Ordinal)
            && exchange.SendCount == 1,
            $"The delegated native approval did not show and send as the selected mailbox (status={sentStatus ?? "(none)"}, error={sentDiagnostic}, preview={sentPreview}, sends={exchange.SendCount}, operations={string.Join(',', exchange.Calls.Select(call => call.Operation))}).");
        var delegatedCreate = exchange.Calls.Last(call => call.Operation == "CreateItem");
        var delegatedSend = exchange.Calls.Last(call => call.Operation == "SendItem");
        Expect(delegatedCreate.Body.Contains("<t:From>", StringComparison.Ordinal)
            && delegatedCreate.Body.Contains("it@example.test", StringComparison.Ordinal)
            && delegatedSend.Body.Contains("SavedItemFolderId", StringComparison.Ordinal)
            && DistinguishedFolderMailboxes(delegatedCreate).SequenceEqual(["alice@example.test"])
            && DistinguishedFolderMailboxes(delegatedSend).SequenceEqual(["alice@example.test"]),
            "The delegated approval fixture did not preserve selected From while saving Drafts and Sent Items in the actor mailbox when target folders denied CreateContents.");

        var sameTargetReplay = await NativeRejectedAsync(alice.Client, "mail_send_draft", new Dictionary<string, object?>
        {
            ["draftHandle"] = draftHandle,
            ["mailboxHandle"] = targetHandle
        });
        var ownReplay = await NativeRejectedAsync(alice.Client, "mail_send_draft", new Dictionary<string, object?>
        {
            ["draftHandle"] = draftHandle
        });
        Expect(sameTargetReplay && ownReplay && exchange.SendCount == 1,
            "A delegated approval or item handle replay reached SendItem.");

        await using var bob = await CreateNativeClientAsync(host,
            Token("user-b", "mail.read mail.write mail.manage mail.send", sessionId: "delegated-native-b"),
            new NativeFormResponder(accept: true));
        var otherActorReplay = await NativeRejectedAsync(bob.Client, "mail_send_draft", new Dictionary<string, object?>
        {
            ["draftHandle"] = draftHandle,
            ["mailboxHandle"] = targetHandle
        });
        Expect(otherActorReplay && exchange.SendCount == 1,
            "A different actor replayed a delegated approval or item handle.");

        await using var alternateClient = await ResumeNativeClientAsync(host, alice.Client,
            Token("user-a", "mail.read mail.write mail.manage mail.send", azp: "chatgpt-alt",
                sessionId: "delegated-native-a"), new NativeFormResponder(accept: true));
        var alternateClientReplay = await NativeRejectedAsync(alternateClient.Client, "mail_send_draft",
            new Dictionary<string, object?> { ["draftHandle"] = draftHandle, ["mailboxHandle"] = targetHandle });
        await using var changedSession = await ResumeNativeClientAsync(host, alice.Client,
            Token("user-a", "mail.read mail.write mail.manage mail.send", sessionId: "delegated-native-other"),
            new NativeFormResponder(accept: true));
        var changedSessionReplay = await NativeRejectedAsync(changedSession.Client, "mail_send_draft",
            new Dictionary<string, object?> { ["draftHandle"] = draftHandle, ["mailboxHandle"] = targetHandle });
        Expect(alternateClientReplay && changedSessionReplay && exchange.SendCount == 1,
            "A delegated send approval or target handle was reusable by another OAuth client or session.");

        responder.Accept = false;
        var ownDraft = await alice.Client.CallToolAsync("mail_create_draft", new Dictionary<string, object?>
        {
            ["subject"] = "Own approval subject",
            ["body"] = "Own approval body",
            ["to"] = new[] { "it@example.test" }
        });
        var ownDraftHandle = NativeData(ownDraft).GetProperty("handle").GetString()!;
        var declined = await alice.Client.CallToolAsync("mail_send_draft", new Dictionary<string, object?>
        {
            ["draftHandle"] = ownDraftHandle
        });
        var declinedPreview = responder.LastRequest?.Message ?? "(none)";
        var declinedDiagnostic = string.Join(" | ", declined.Content.OfType<TextContentBlock>().Select(item => item.Text));
        Expect(!declined.IsError.GetValueOrDefault()
            && NativeData(declined).GetProperty("status").GetString() == "cancelled"
            && !declinedPreview.Contains("Acting mailbox:", StringComparison.Ordinal),
            $"The own-mailbox approval preview was incorrectly labeled delegated (error={declinedDiagnostic}, preview={declinedPreview}, sends={exchange.SendCount}, operations={string.Join(',', exchange.Calls.Select(call => call.Operation))}).");
    }

    private async Task<TestHostContext> StartDelegatedHostAsync(
        HttpMessageHandler exchange, string auditPath, bool classicStateful = false,
        IMailboxPermissionReader? permissions = null, bool includeLegacyTargetConfig = true,
        TestMailboxDiscovery? mailboxDiscovery = null)
    {
        var passwordPath = Path.Combine(runDirectory, "delegated-exchange-password.txt");
        var introspectionSecretPath = Path.Combine(runDirectory, "delegated-introspection-secret.txt");
        await File.WriteAllTextAsync(passwordPath, "synthetic-password");
        await File.WriteAllTextAsync(introspectionSecretPath, "synthetic-introspection-secret");
        var values = ConfigurationValues(passwordPath, introspectionSecretPath, auditPath,
            writesEnabled: true, sendEnabled: true);
        if (includeLegacyTargetConfig)
            values["Service:MailboxTargets:user-a:stale"] = "stale@example.test";
        var app = AppHost.Create([], builder =>
        {
            builder.WebHost.UseTestServer();
            if (!classicStateful)
                builder.Services.PostConfigure<ModelContextProtocol.AspNetCore.HttpServerTransportOptions>(options =>
                    options.SessionMode = ModelContextProtocol.AspNetCore.HttpServerSessionMode.Stateless);
            builder.Configuration.AddInMemoryCollection(values);
            builder.Services.PostConfigure<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme, options =>
            {
                var configuration = new OpenIdConnectConfiguration { Issuer = Authority };
                configuration.SigningKeys.Add(signingKey);
                options.Configuration = configuration;
                options.ConfigurationManager = new StaticConfigurationManager<OpenIdConnectConfiguration>(configuration);
            });
            builder.Services.AddHttpClient<Company.ExchangeMcp.Exchange.EwsClient>()
                .ConfigurePrimaryHttpMessageHandler(() => exchange);
            builder.Services.AddHttpClient<KeycloakTokenStatus>()
                .ConfigurePrimaryHttpMessageHandler(() => new IntrospectionHandler());
            builder.Services.AddSingleton<IMailboxPermissionReader>(permissions ?? new SyntheticPermissionReader(
                new MailboxPermissionReport(
                    PermissionDecision.Unknown("synthetic directory unavailable"),
                    PermissionDecision.Unknown("synthetic directory unavailable"),
                    PermissionDecision.Unknown("synthetic directory unavailable"),
                    DateTimeOffset.UtcNow,
                    "synthetic-delegated-directory")));
            var discovery = mailboxDiscovery ?? new TestMailboxDiscovery("user-a");
            builder.Services.AddSingleton<IMailboxDiscovery>(discovery);
            builder.Services.AddSingleton<IMailboxDirectory>(discovery);
        });
        await app.StartAsync();
        var client = app.GetTestClient();
        client.BaseAddress = new Uri("https://mail.example.test/");
        return new TestHostContext(app, client);
    }

    private static JsonElement[] JsonArrayProperty(JsonElement value, params string[] names)
    {
        foreach (var name in names)
            if (value.TryGetProperty(name, out var property) && property.ValueKind == JsonValueKind.Array)
                return property.EnumerateArray().Select(item => item.Clone()).ToArray();
        throw new InvalidOperationException("The mailbox list omitted its item array.");
    }

    private static string StringProperty(JsonElement value, params string[] names)
    {
        foreach (var name in names)
            if (value.TryGetProperty(name, out var property) && property.ValueKind == JsonValueKind.String)
                return property.GetString()!;
        throw new InvalidOperationException("The mailbox list omitted its selector handle.");
    }

    private static bool HasStringProperty(JsonElement value, params string[] names) =>
        names.Any(name => value.TryGetProperty(name, out var property)
            && property.ValueKind == JsonValueKind.String && !string.IsNullOrWhiteSpace(property.GetString()));

    private static string? DistinguishedFolderMailbox(DelegatedMailboxCall call)
    {
        return DistinguishedFolderMailboxes(call).FirstOrDefault();
    }

    private static string?[] DistinguishedFolderMailboxes(DelegatedMailboxCall call)
    {
        if (string.IsNullOrWhiteSpace(call.Body)) return [];
        var document = XDocument.Parse(call.Body);
        return document.Descendants(XName.Get("DistinguishedFolderId", DelegatedMailboxEwsHandler.TypesNamespace))
            .Select(folder => folder.Element(XName.Get("Mailbox", DelegatedMailboxEwsHandler.TypesNamespace))
                ?.Element(XName.Get("EmailAddress", DelegatedMailboxEwsHandler.TypesNamespace))?.Value)
            .ToArray();
    }

    private static string[] FolderIds(DelegatedMailboxCall call) => string.IsNullOrWhiteSpace(call.Body)
        ? []
        : XDocument.Parse(call.Body).Descendants(XName.Get("FolderId", DelegatedMailboxEwsHandler.TypesNamespace))
            .Select(folder => (string?)folder.Attribute("Id"))
            .Where(id => !string.IsNullOrWhiteSpace(id)).Cast<string>().ToArray();
}

internal sealed record DelegatedMailboxCall(string Operation, string? Anchor, string? PrimarySmtpAddress, string Body);

internal sealed class DelegatedMailboxEwsHandler : HttpMessageHandler
{
    internal const string SoapNamespace = "http://schemas.xmlsoap.org/soap/envelope/";
    internal const string MessagesNamespace = "http://schemas.microsoft.com/exchange/services/2006/messages";
    internal const string TypesNamespace = "http://schemas.microsoft.com/exchange/services/2006/types";
    private static readonly XNamespace Soap = SoapNamespace;
    private static readonly XNamespace Messages = MessagesNamespace;
    private static readonly XNamespace Types = TypesNamespace;
    public ConcurrentQueue<DelegatedMailboxCall> Calls { get; } = [];
    public int SendCount { get; private set; }
    public bool EmptyCalendarAndTaskFindItems { get; init; }
    public string LastResponse { get; private set; } = string.Empty;
    private readonly ConcurrentDictionary<string, string> draftMailboxes = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, string> draftSenders = new(StringComparer.Ordinal);

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        var body = await request.Content!.ReadAsStringAsync(cancellationToken);
        var document = XDocument.Parse(body);
        var operation = document.Root!.Element(Soap + "Body")!.Elements().Single();
        var anchor = request.Headers.TryGetValues("X-AnchorMailbox", out var values)
            ? values.SingleOrDefault() : null;
        var primary = document.Descendants(Types + "PrimarySmtpAddress").SingleOrDefault()?.Value;
        var requestedItem = document.Descendants(Types + "ItemId").FirstOrDefault();
        var itemId = requestedItem?.Attribute("Id")?.Value ?? "synthetic-message";
        var itemChangeKey = requestedItem?.Attribute("ChangeKey")?.Value ?? "synthetic-change";
        var requestedFolderId = document.Descendants(Types + "FolderId")
            .Select(folder => (string?)folder.Attribute("Id")).FirstOrDefault(id => !string.IsNullOrWhiteSpace(id))
            ?? document.Descendants(Types + "DistinguishedFolderId")
                .Select(folder => (string?)folder.Attribute("Id")).FirstOrDefault(id => !string.IsNullOrWhiteSpace(id))
            ?? "inbox-id";
        var folderMailbox = document.Descendants(Types + "DistinguishedFolderId")
            .Select(folder => folder.Element(Types + "Mailbox")?.Element(Types + "EmailAddress")?.Value)
            .FirstOrDefault(value => !string.IsNullOrWhiteSpace(value));
        if (operation.Name.LocalName == "CreateItem")
        {
            draftMailboxes["synthetic-draft"] = folderMailbox ?? primary ?? anchor ?? "alice@example.test";
            var requestedSender = document.Descendants(Types + "From").Elements(Types + "Mailbox")
                .Elements(Types + "EmailAddress").Select(element => element.Value).FirstOrDefault();
            if (!string.IsNullOrWhiteSpace(requestedSender))
                draftSenders["synthetic-draft"] = requestedSender;
            else
                draftSenders.TryRemove("synthetic-draft", out _);
        }
        Calls.Enqueue(new DelegatedMailboxCall(operation.Name.LocalName, anchor, primary, body));
        if (operation.Name.LocalName == "SendItem") SendCount++;
        await Task.Delay(25, cancellationToken);
        var mailbox = operation.Name.LocalName == "GetItem"
            && draftMailboxes.TryGetValue(itemId, out var draftMailbox)
            ? draftMailbox
            : primary ?? anchor ?? "alice@example.test";
        var sender = operation.Name.LocalName == "GetItem"
            && draftSenders.TryGetValue(itemId, out var draftSender)
            ? draftSender
            : mailbox;
        var isCalendarFind = operation.Name.LocalName == "FindItem"
            && document.Descendants(Types + "FieldURI").Any(field => (string?)field.Attribute("FieldURI") == "calendar:Start");
        var isTaskFind = operation.Name.LocalName == "FindItem"
            && document.Descendants(Types + "FieldURI").Any(field => (string?)field.Attribute("FieldURI") == "task:DueDate");
        var distinguishedFolder = document.Descendants(Types + "DistinguishedFolderId")
            .Select(folder => (string?)folder.Attribute("Id")).FirstOrDefault();
        var result = operation.Name.LocalName switch
        {
            "FindItem" when EmptyCalendarAndTaskFindItems && (isCalendarFind || isTaskFind) =>
                "<m:RootFolder IncludesLastItemInRange='true'><t:Items/></m:RootFolder>",
            "FindItem" => "<m:RootFolder IncludesLastItemInRange='true'><t:Items><t:Message>"
                + "<t:ItemId Id='synthetic-message' ChangeKey='synthetic-change'/>"
                + "<t:Subject>synthetic delegated item</t:Subject>"
                + "<t:DateTimeReceived>2026-10-12T10:00:00Z</t:DateTimeReceived>"
                + "<t:IsRead>false</t:IsRead><t:IsDraft>false</t:IsDraft>"
                + "</t:Message></t:Items></m:RootFolder>",
            "GetItem" => $"<m:Items><t:Message><t:ItemId Id='{itemId}' ChangeKey='{itemChangeKey}'/>"
                + $"<t:Subject>synthetic delegated item</t:Subject><t:From><t:Mailbox><t:EmailAddress>{sender}</t:EmailAddress></t:Mailbox></t:From>"
                + $"<t:Sender><t:Mailbox><t:EmailAddress>{primary ?? anchor ?? mailbox}</t:EmailAddress></t:Mailbox></t:Sender>"
                + "<t:ToRecipients><t:Mailbox><t:EmailAddress>it@example.test</t:EmailAddress></t:Mailbox></t:ToRecipients>"
                + "<t:CcRecipients/><t:BccRecipients/><t:Body BodyType='Text'>synthetic body</t:Body>"
                + "<t:IsRead>true</t:IsRead><t:IsDraft>true</t:IsDraft><t:Attachments/>"
                + "</t:Message></m:Items>",
            "CreateItem" => "<m:Items><t:Message><t:ItemId Id='synthetic-draft' ChangeKey='synthetic-draft-change'/></t:Message></m:Items>",
            "GetFolder" when document.Descendants(Types + "FieldURI")
                .Any(field => (string?)field.Attribute("FieldURI") == "folder:EffectiveRights") =>
                $"<m:Folders><t:Folder><t:FolderId Id='{requestedFolderId}' ChangeKey='inbox-change'/><t:DisplayName>Calendar</t:DisplayName><t:FolderClass>IPF.Appointment</t:FolderClass>"
                + "<t:EffectiveRights><t:Read>1</t:Read><t:CreateContents>0</t:CreateContents>"
                + "<t:Modify>1</t:Modify><t:Delete>0</t:Delete></t:EffectiveRights></t:Folder></m:Folders>",
            "GetFolder" when string.Equals(distinguishedFolder, "tasks", StringComparison.OrdinalIgnoreCase) =>
                "<m:Folders><t:TasksFolder><t:FolderId Id='tasks-id' ChangeKey='tasks-change'/>"
                + "<t:FolderClass>IPF.Task</t:FolderClass><t:DisplayName>Tasks</t:DisplayName>"
                + "<t:TotalCount>0</t:TotalCount><t:UnreadCount>0</t:UnreadCount><t:ChildFolderCount>0</t:ChildFolderCount>"
                + "</t:TasksFolder></m:Folders>",
            "GetFolder" => "<m:Folders><t:CalendarFolder><t:FolderId Id='calendar' ChangeKey='calendar-change'/>"
                + "<t:FolderClass>IPF.Appointment</t:FolderClass><t:DisplayName>Calendar</t:DisplayName>"
                + "<t:TotalCount>0</t:TotalCount><t:UnreadCount>0</t:UnreadCount><t:ChildFolderCount>0</t:ChildFolderCount>"
                + "</t:CalendarFolder></m:Folders>",
            "FindFolder" => "<m:RootFolder IncludesLastItemInRange='true'><t:Folders>"
                + "<t:CalendarFolder><t:FolderId Id='calendar-id' ChangeKey='calendar-change'/>"
                + "<t:FolderClass>IPF.Appointment</t:FolderClass><t:DisplayName>Calendar</t:DisplayName>"
                + "<t:TotalCount>0</t:TotalCount><t:UnreadCount>0</t:UnreadCount><t:ChildFolderCount>0</t:ChildFolderCount></t:CalendarFolder>"
                + "<t:TasksFolder><t:FolderId Id='tasks-id' ChangeKey='tasks-change'/>"
                + "<t:FolderClass>IPF.Task</t:FolderClass><t:DisplayName>Tasks</t:DisplayName>"
                + "<t:TotalCount>0</t:TotalCount><t:UnreadCount>0</t:UnreadCount><t:ChildFolderCount>0</t:ChildFolderCount></t:TasksFolder>"
                + "</t:Folders></m:RootFolder>",
            _ => string.Empty
        };
        var isRightsRequest = operation.Name.LocalName == "GetFolder"
            && document.Descendants(Types + "FieldURI")
                .Any(field => (string?)field.Attribute("FieldURI") == "folder:EffectiveRights");
        var response = operation.Name.LocalName == "GetUserConfiguration"
            ? $"<s:Envelope xmlns:s='{Soap.NamespaceName}' xmlns:m='{Messages.NamespaceName}'><s:Body><m:GetUserConfigurationResponse>"
                + "<m:ResponseMessages><m:GetUserConfigurationResponseMessage ResponseClass='Error'><m:ResponseCode>ErrorItemNotFound</m:ResponseCode>"
                + "</m:GetUserConfigurationResponseMessage></m:ResponseMessages></m:GetUserConfigurationResponse></s:Body></s:Envelope>"
            : isRightsRequest
            ? $"<s:Envelope xmlns:s='{Soap.NamespaceName}' xmlns:m='{Messages.NamespaceName}' xmlns:t='{Types.NamespaceName}'><s:Body>"
                + $"<m:{operation.Name.LocalName}Response><m:ResponseMessages><m:{operation.Name.LocalName}ResponseMessage ResponseClass='Success'>"
                + $"<m:ResponseCode>NoError</m:ResponseCode>{result}</m:{operation.Name.LocalName}ResponseMessage></m:ResponseMessages>"
                + $"</m:{operation.Name.LocalName}Response></s:Body></s:Envelope>"
            : $"<s:Envelope xmlns:s='{Soap.NamespaceName}' xmlns:m='{Messages.NamespaceName}' xmlns:t='{Types.NamespaceName}'><s:Body>"
                + $"<m:{operation.Name.LocalName}Response><m:ResponseMessages><m:{operation.Name.LocalName}ResponseMessage ResponseClass='Success'>"
                + $"<m:ResponseCode>NoError</m:ResponseCode></m:{operation.Name.LocalName}ResponseMessage></m:ResponseMessages>{result}"
                + $"</m:{operation.Name.LocalName}Response></s:Body></s:Envelope>";
        LastResponse = response;
        return new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(response, Encoding.UTF8, "text/xml")
        };
    }
}

/// <summary>Private Exchange 2019-shaped fixture for delegated groupware and sync calls.</summary>
internal sealed class DelegatedGroupwareEwsHandler : HttpMessageHandler
{
    private const string SoapNamespace = "http://schemas.xmlsoap.org/soap/envelope/";
    private const string MessagesNamespace = "http://schemas.microsoft.com/exchange/services/2006/messages";
    private const string TypesNamespace = "http://schemas.microsoft.com/exchange/services/2006/types";
    private static readonly XNamespace Soap = SoapNamespace;
    private static readonly XNamespace Messages = MessagesNamespace;
    private static readonly XNamespace Types = TypesNamespace;

    public ConcurrentQueue<DelegatedMailboxCall> Calls { get; } = [];

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        var body = await request.Content!.ReadAsStringAsync(cancellationToken);
        var document = XDocument.Parse(body);
        var operation = document.Root!.Element(Soap + "Body")!.Elements().Single().Name.LocalName;
        var anchor = request.Headers.TryGetValues("X-AnchorMailbox", out var values)
            ? values.SingleOrDefault() : null;
        var primary = document.Descendants(Types + "PrimarySmtpAddress").SingleOrDefault()?.Value;
        Calls.Enqueue(new DelegatedMailboxCall(operation, anchor, primary, body));

        var payload = operation switch
        {
            "FindItem" => $"<m:RootFolder IncludesLastItemInRange='true'><t:Items>{CalendarItem()}</t:Items></m:RootFolder>",
            "GetItem" => $"<m:Items>{CalendarItem()}</m:Items>",
            "GetAttachment" => $"<m:Attachments>{FileAttachment(includeContent: true)}</m:Attachments>",
            "SyncFolderHierarchy" => "<m:SyncState>delegated-folder-state</m:SyncState><m:IncludesLastFolderInRange>true</m:IncludesLastFolderInRange><m:Changes/>",
            "SyncFolderItems" => "<m:SyncState>delegated-item-state</m:SyncState><m:IncludesLastItemInRange>true</m:IncludesLastItemInRange><m:Changes/>",
            _ => string.Empty
        };
        var response = $"<s:Envelope xmlns:s='{Soap.NamespaceName}' xmlns:m='{Messages.NamespaceName}' xmlns:t='{Types.NamespaceName}'><s:Body>"
            + $"<m:{operation}Response><m:ResponseMessages><m:{operation}ResponseMessage ResponseClass='Success'>"
            + "<m:ResponseCode>NoError</m:ResponseCode>" + payload
            + $"</m:{operation}ResponseMessage></m:ResponseMessages></m:{operation}Response></s:Body></s:Envelope>";
        return new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(response, Encoding.UTF8, "text/xml")
        };
    }

    private static string CalendarItem() =>
        "<t:CalendarItem><t:ItemId Id='event-1' ChangeKey='event-change'/>"
        + "<t:Subject>Delegated attachment event</t:Subject><t:Body BodyType='Text'>Synthetic event</t:Body>"
        + "<t:Start>2026-10-12T09:00:00Z</t:Start><t:End>2026-10-12T10:00:00Z</t:End>"
        + "<t:IsAllDayEvent>false</t:IsAllDayEvent><t:IsMeeting>false</t:IsMeeting><t:IsOrganizer>true</t:IsOrganizer>"
        + "<t:IsRecurring>false</t:IsRecurring><t:IsCancelled>false</t:IsCancelled><t:CalendarItemType>Single</t:CalendarItemType>"
        + "<t:Organizer><t:Mailbox><t:EmailAddress>it@example.test</t:EmailAddress></t:Mailbox></t:Organizer>"
        + $"<t:Attachments>{FileAttachment(includeContent: false)}</t:Attachments></t:CalendarItem>";

    private static string FileAttachment(bool includeContent) =>
        "<t:FileAttachment><t:AttachmentId Id='attachment-1'/><t:Name>delegated-note.txt</t:Name>"
        + "<t:Size>4</t:Size><t:ContentType>text/plain</t:ContentType><t:IsInline>false</t:IsInline>"
        + (includeContent ? "<t:Content>bm90ZQ==</t:Content>" : string.Empty)
        + "</t:FileAttachment>";
}

internal enum CalendarFolderResponseMode
{
    DecoyAndOne,
    Multiple,
    WrongType
}

internal enum CalendarBooleanResponseMode
{
    OneZero,
    MissingRequired,
    Unknown
}

internal sealed class EffectiveRightsProbeHandler(
    string? read, string? create, string? modify, string? delete, bool includeRights = true) : HttpMessageHandler
{
    private const string SoapNamespace = "http://schemas.xmlsoap.org/soap/envelope/";
    private const string MessagesNamespace = "http://schemas.microsoft.com/exchange/services/2006/messages";
    private const string TypesNamespace = "http://schemas.microsoft.com/exchange/services/2006/types";

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        _ = await request.Content!.ReadAsStringAsync(cancellationToken);
        var rights = includeRights
            ? "<t:EffectiveRights>"
                + Optional("Read", read) + Optional("CreateContents", create)
                + Optional("Modify", modify) + Optional("Delete", delete)
                + "</t:EffectiveRights>"
            : string.Empty;
        var body = $"<m:Folders><t:Folder><t:FolderId Id='inbox-id' ChangeKey='inbox-change'/>{rights}</t:Folder></m:Folders>";
        return Response("GetFolder", body);
    }

    private static string Optional(string name, string? value) =>
        value is null ? string.Empty : $"<t:{name}>{System.Security.SecurityElement.Escape(value)}</t:{name}>";

    private static HttpResponseMessage Response(string operation, string payload) => new(HttpStatusCode.OK)
    {
        Content = new StringContent(
            $"<s:Envelope xmlns:s='{SoapNamespace}' xmlns:m='{MessagesNamespace}' xmlns:t='{TypesNamespace}'><s:Body>"
            + $"<m:{operation}Response><m:ResponseMessages><m:{operation}ResponseMessage ResponseClass='Success'>"
            + "<m:ResponseCode>NoError</m:ResponseCode>" + payload
            + $"</m:{operation}ResponseMessage></m:ResponseMessages></m:{operation}Response></s:Body></s:Envelope>", Encoding.UTF8, "text/xml")
    };
}

internal sealed class CalendarProbeHandler : HttpMessageHandler
{
    private const string SoapNamespace = "http://schemas.xmlsoap.org/soap/envelope/";
    private const string MessagesNamespace = "http://schemas.microsoft.com/exchange/services/2006/messages";
    private const string TypesNamespace = "http://schemas.microsoft.com/exchange/services/2006/types";
    private static readonly XNamespace Soap = SoapNamespace;
    private static readonly XNamespace Messages = MessagesNamespace;
    private static readonly XNamespace Types = TypesNamespace;

    public CalendarFolderResponseMode FolderMode { get; init; } = CalendarFolderResponseMode.DecoyAndOne;
    public CalendarBooleanResponseMode BooleanMode { get; init; } = CalendarBooleanResponseMode.OneZero;
    public string LastBody { get; private set; } = string.Empty;

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        LastBody = await request.Content!.ReadAsStringAsync(cancellationToken);
        var document = XDocument.Parse(LastBody);
        var operation = document.Root!.Element(Soap + "Body")!.Elements().Single().Name.LocalName;
        var payload = operation switch
        {
            "GetFolder" => FolderPayload(),
            "GetItem" => $"<m:Items>{CalendarItemPayload()}</m:Items>",
            _ => string.Empty
        };
        var response = $"<s:Envelope xmlns:s='{Soap.NamespaceName}' xmlns:m='{Messages.NamespaceName}' xmlns:t='{Types.NamespaceName}'><s:Body>"
            + $"<m:{operation}Response><m:ResponseMessages><m:{operation}ResponseMessage ResponseClass='Success'>"
            + "<m:ResponseCode>NoError</m:ResponseCode>" + payload
            + "</m:" + operation + "ResponseMessage></m:ResponseMessages>"
            + $"</m:{operation}Response></s:Body></s:Envelope>";
        return new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(response, Encoding.UTF8, "text/xml")
        };
    }

    private string FolderPayload() => FolderMode switch
    {
        CalendarFolderResponseMode.DecoyAndOne =>
            "<m:Folders><t:Folder><t:FolderId Id='decoy-folder' ChangeKey='decoy-change'/>"
            + "<t:DisplayName>Decoy</t:DisplayName><t:TotalCount>99</t:TotalCount><t:UnreadCount>99</t:UnreadCount></t:Folder>"
            + "<t:CalendarFolder><t:FolderId Id='calendar-real' ChangeKey='calendar-change'/>"
            + "<t:FolderClass>IPF.Appointment</t:FolderClass><t:DisplayName>Calendar</t:DisplayName>"
            + "<t:TotalCount>4</t:TotalCount><t:UnreadCount>1</t:UnreadCount><t:ChildFolderCount>0</t:ChildFolderCount></t:CalendarFolder></m:Folders>",
        CalendarFolderResponseMode.Multiple =>
            "<m:Folders><t:CalendarFolder><t:FolderId Id='calendar-one' ChangeKey='one'/>"
            + "<t:FolderClass>IPF.Appointment</t:FolderClass><t:DisplayName>One</t:DisplayName>"
            + "<t:TotalCount>0</t:TotalCount><t:UnreadCount>0</t:UnreadCount></t:CalendarFolder>"
            + "<t:CalendarFolder><t:FolderId Id='calendar-two' ChangeKey='two'/>"
            + "<t:FolderClass>IPF.Appointment</t:FolderClass><t:DisplayName>Two</t:DisplayName>"
            + "<t:TotalCount>0</t:TotalCount><t:UnreadCount>0</t:UnreadCount></t:CalendarFolder></m:Folders>",
        _ => "<m:Folders><t:Folder><t:FolderId Id='wrong-folder' ChangeKey='wrong'/>"
            + "<t:DisplayName>Wrong type</t:DisplayName><t:TotalCount>0</t:TotalCount><t:UnreadCount>0</t:UnreadCount></t:Folder></m:Folders>"
    };

    private string CalendarItemPayload()
    {
        var meeting = BooleanMode == CalendarBooleanResponseMode.Unknown ? "maybe"
            : BooleanMode == CalendarBooleanResponseMode.OneZero ? "1" : null;
        var organizer = BooleanMode == CalendarBooleanResponseMode.Unknown ? "0"
            : BooleanMode == CalendarBooleanResponseMode.MissingRequired ? null : "0";
        var allDay = BooleanMode == CalendarBooleanResponseMode.OneZero ? "1" : "false";
        var recurring = BooleanMode == CalendarBooleanResponseMode.OneZero ? "0" : "false";
        var cancelled = BooleanMode == CalendarBooleanResponseMode.OneZero ? "0" : "false";
        return "<t:CalendarItem><t:ItemId Id='event-1' ChangeKey='event-change'/>"
            + "<t:Subject>Probe</t:Subject><t:Start>2026-10-12T09:00:00Z</t:Start><t:End>2026-10-12T10:00:00Z</t:End>"
            + $"<t:IsAllDayEvent>{allDay}</t:IsAllDayEvent>"
            + Optional("IsMeeting", meeting) + Optional("IsOrganizer", organizer)
            + $"<t:IsRecurring>{recurring}</t:IsRecurring><t:IsCancelled>{cancelled}</t:IsCancelled>"
            + "<t:CalendarItemType>Single</t:CalendarItemType><t:Organizer><t:Mailbox><t:EmailAddress>organizer@example.test</t:EmailAddress></t:Mailbox></t:Organizer>"
            + "</t:CalendarItem>";
    }

    private static string Optional(string name, string? value) =>
        value is null ? string.Empty : $"<t:{name}>{value}</t:{name}>";
}

internal sealed class PermissionErrorEwsHandler : HttpMessageHandler
{
    private const string SoapNamespace = "http://schemas.xmlsoap.org/soap/envelope/";
    private const string MessagesNamespace = "http://schemas.microsoft.com/exchange/services/2006/messages";
    private const string TypesNamespace = "http://schemas.microsoft.com/exchange/services/2006/types";
    private static readonly XNamespace Soap = SoapNamespace;
    private static readonly XNamespace Messages = MessagesNamespace;
    private static readonly XNamespace Types = TypesNamespace;

    public string ErrorOperation { get; init; } = "SendItem";
    public string ErrorCode { get; init; } = "ErrorAccessDenied";
    public bool IsOrganizer { get; init; } = true;
    public ConcurrentQueue<string> Operations { get; } = [];
    public string? LastRequestBody { get; private set; }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        var body = await request.Content!.ReadAsStringAsync(cancellationToken);
        LastRequestBody = body;
        var document = XDocument.Parse(body);
        var operation = document.Root!.Element(Soap + "Body")!.Elements().Single().Name.LocalName;
        Operations.Enqueue(operation);
        var isCalendarRequest = document.Descendants(Types + "FieldURI")
            .Select(field => (string?)field.Attribute("FieldURI"))
            .Any(field => field?.StartsWith("calendar:", StringComparison.Ordinal) == true);
        var isResponse = operation == "CreateItem"
            && document.Descendants().Any(element => element.Name.LocalName is "AcceptItem" or "TentativelyAcceptItem" or "DeclineItem");
        var isCancellation = (operation == "CreateItem"
                && document.Descendants().Any(element => element.Name.LocalName == "CancelCalendarItem"))
            || (operation == "DeleteItem"
                && document.Root?.Descendants(Soap + "Body").Elements(Messages + "DeleteItem")
                    .Any(element => string.Equals((string?)element.Attribute("SendMeetingCancellations"),
                        "SendToAllAndSaveCopy", StringComparison.Ordinal)) == true);
        var shouldError = ErrorOperation switch
        {
            "SendItem" => operation == "SendItem",
            "RespondToMeeting" => isResponse,
            "CancelCalendarItem" => isCancellation,
            _ => false
        };
        if (shouldError)
            return ErrorResponse(operation);

        var payload = operation switch
        {
            "GetFolder" => "<m:Folders><t:CalendarFolder><t:FolderId Id='calendar' ChangeKey='calendar-change'/>"
                + "<t:FolderClass>IPF.Appointment</t:FolderClass><t:DisplayName>Calendar</t:DisplayName>"
                + "<t:TotalCount>1</t:TotalCount><t:UnreadCount>0</t:UnreadCount><t:ChildFolderCount>0</t:ChildFolderCount></t:CalendarFolder></m:Folders>",
            "FindItem" when isCalendarRequest => $"<m:RootFolder IncludesLastItemInRange='true'><t:Items>{CalendarEvent()}</t:Items></m:RootFolder>",
            "GetItem" when isCalendarRequest => $"<m:Items>{CalendarEvent()}</m:Items>",
            "GetItem" => "<m:Items><t:Message><t:ItemId Id='draft-1' ChangeKey='draft-change'/>"
                + "<t:Subject>synthetic permission draft</t:Subject><t:From><t:Mailbox><t:EmailAddress>alice@example.test</t:EmailAddress></t:Mailbox></t:From>"
                + "<t:ToRecipients><t:Mailbox><t:EmailAddress>to@example.test</t:EmailAddress></t:Mailbox></t:ToRecipients>"
                + "<t:CcRecipients/><t:BccRecipients/><t:Body BodyType='Text'>synthetic body</t:Body>"
                + "<t:IsRead>true</t:IsRead><t:IsDraft>true</t:IsDraft><t:Attachments/></t:Message></m:Items>",
            "FindItem" => "<m:RootFolder IncludesLastItemInRange='true'><t:Items/></m:RootFolder>",
            "CreateItem" => "<m:Items><t:Message><t:ItemId Id='draft-1' ChangeKey='draft-change'/></t:Message></m:Items>",
            _ => string.Empty
        };
        return SuccessResponse(operation, payload);
    }

    private string CalendarEvent() =>
        "<t:CalendarItem><t:ItemId Id='event-1' ChangeKey='event-change'/><t:Subject>Permission probe</t:Subject>"
        + "<t:Body BodyType='Text'>Agenda</t:Body><t:Start>2026-10-12T09:00:00Z</t:Start><t:End>2026-10-12T10:00:00Z</t:End>"
        + "<t:IsAllDayEvent>false</t:IsAllDayEvent><t:IsMeeting>true</t:IsMeeting>"
        + $"<t:IsOrganizer>{IsOrganizer.ToString().ToLowerInvariant()}</t:IsOrganizer>"
        + "<t:IsRecurring>false</t:IsRecurring><t:IsCancelled>false</t:IsCancelled><t:CalendarItemType>Single</t:CalendarItemType>"
        + "<t:Organizer><t:Mailbox><t:EmailAddress>organizer@example.test</t:EmailAddress></t:Mailbox></t:Organizer>"
        + "<t:RequiredAttendees><t:Attendee><t:Mailbox><t:EmailAddress>to@example.test</t:EmailAddress></t:Mailbox><t:ResponseType>NoResponseReceived</t:ResponseType></t:Attendee></t:RequiredAttendees>"
        + "<t:ResponseObjects><t:AcceptItem/><t:TentativelyAcceptItem/><t:DeclineItem/></t:ResponseObjects></t:CalendarItem>";

    private HttpResponseMessage ErrorResponse(string operation) => new(HttpStatusCode.OK)
    {
        Content = new StringContent(
            $"<s:Envelope xmlns:s='{Soap.NamespaceName}' xmlns:m='{Messages.NamespaceName}' xmlns:t='{Types.NamespaceName}'><s:Body>"
            + $"<m:{operation}Response><m:ResponseMessages><m:{operation}ResponseMessage ResponseClass='Error'>"
            + $"<m:ResponseCode>{System.Security.SecurityElement.Escape(ErrorCode)}</m:ResponseCode>"
            + "<m:MessageText>synthetic-secret</m:MessageText></m:"
            + $"{operation}ResponseMessage></m:ResponseMessages></m:{operation}Response></s:Body></s:Envelope>",
            Encoding.UTF8, "text/xml")
    };

    private static HttpResponseMessage SuccessResponse(string operation, string payload) => new(HttpStatusCode.OK)
    {
        Content = new StringContent(
            $"<s:Envelope xmlns:s='{Soap.NamespaceName}' xmlns:m='{Messages.NamespaceName}' xmlns:t='{Types.NamespaceName}'><s:Body>"
            + $"<m:{operation}Response><m:ResponseMessages><m:{operation}ResponseMessage ResponseClass='Success'>"
            + "<m:ResponseCode>NoError</m:ResponseCode>"
            + payload + "</m:"
            + $"{operation}ResponseMessage></m:ResponseMessages></m:{operation}Response></s:Body></s:Envelope>",
            Encoding.UTF8, "text/xml")
    };
}
