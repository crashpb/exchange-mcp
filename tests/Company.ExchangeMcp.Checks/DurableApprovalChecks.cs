using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Net;
using System.Xml.Linq;
using Company.ExchangeMcp.Exchange;
using Company.ExchangeMcp.Security;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;

internal sealed partial class Checks
{
    private async Task DurableApprovalChecksAsync()
    {
        var path = Path.Combine(runDirectory, "durable-approval", "audit.jsonl");
        var clock = new ApprovalClock(new DateTimeOffset(2026, 10, 18, 12, 0, 0, TimeSpan.Zero));
        var actor = new MailboxIdentity("actor", "alice@example.test", "client", "session");
        string taskHandle, recallHandle, state, sendState;
        CalendarActionApproval approved;
        SendApproval sendApproved;
        var draft = new EwsMessage("draft", "revision", "subject", "alice@example.test", ["bob@example.test"],
            [], [], [], null, false, true, "body", []);
        using (var protection = new DurableDataProtectionProvider(path))
        {
            var store = new MailboxActionApprovalStore(protection, path, clock);
            taskHandle = new MailboxHandles(protection).Issue(actor, "task", "task-id", "revision");
            recallHandle = new MailboxHandles(protection).Issue(actor, "recall", "message-id", "revision");
            approved = new(actor.Subject, actor.Mailbox, "task_assign", "task-id", "revision", "digest",
                Guid.NewGuid().ToString("N"), actor.ClientId, actor.SessionId, ExpiresAt: store.ExpiresAt());
            state = protection.CreateProtector("Company.ExchangeMcp.CalendarActionApproval.v2")
                .Protect(JsonSerializer.Serialize(approved));
            store.Stage(approved.Nonce, MailboxActionApprovalStore.Fingerprint(approved), approved.ExpiresAt);
            sendApproved = new(actor.Subject, actor.Mailbox, draft.Id, draft.ChangeKey, SendGuard.Digest(draft),
                Guid.NewGuid().ToString("N"), actor.ClientId, actor.SessionId, store.ExpiresAt());
            sendState = protection.CreateProtector("Company.ExchangeMcp.SendApproval.v2")
                .Protect(JsonSerializer.Serialize(sendApproved));
            store.Stage(sendApproved.Nonce, MailboxActionApprovalStore.Fingerprint(sendApproved), sendApproved.ExpiresAt);
            Expect(!Encoding.UTF8.GetString(File.ReadAllBytes(Path.Combine(protection.StateDirectory, "approvals.enc")))
                .Contains("alice@example.test", StringComparison.Ordinal), "Approval state exposed a mailbox in plaintext.");
        }

        using (var protection = new DurableDataProtectionProvider(path))
        {
            var store = new MailboxActionApprovalStore(protection, path, clock);
            using var guard = new CalendarActionApprovalGuard(protection, store);
            using var send = new SendGuard(protection, store);
            var handles = new MailboxHandles(protection);
            Expect(handles.Resolve(actor, "task", taskHandle).Id == "task-id"
                && handles.Resolve(actor, "recall", recallHandle).Id == "message-id",
                "Protected task/recall handles did not survive a new protection provider.");
            Expect(guard.ReadApproval(actor, "task_assign", "task-id", state) == approved
                && send.ReadApproval(actor, draft.Id, sendState) == sendApproved,
                "Pending human approvals did not survive a registry/provider restart.");
            foreach (var wrong in new[] { actor with { Subject = "other" }, actor with { Mailbox = "other@example.test" },
                actor with { ClientId = "other" }, actor with { SessionId = "other" } })
            {
                ApprovalFailure(() => guard.ReadApproval(wrong, "task_assign", "task-id", state), "binding_mismatch");
                ApprovalFailure(() => send.ReadApproval(wrong, draft.Id, sendState), "binding_mismatch");
                var refused = false;
                try { handles.Resolve(wrong, "task", taskHandle); } catch (McpException) { refused = true; }
                Expect(refused, "A mailbox handle crossed an actor, mailbox, client or session binding.");
            }
            ApprovalFailure(() => guard.ReadApproval(actor, "task_delete", "task-id", state), "binding_mismatch");
            ApprovalFailure(() => guard.ReadApproval(actor, "task_assign", "other-id", state), "binding_mismatch");
            ApprovalFailure(() => guard.ReadApproval(actor, "task_assign", "task-id", "invalid"), "tampered");
            ApprovalFailure(() => send.ReadApproval(actor, draft.Id, "invalid"), "tampered");
            ApprovalFailure(() => guard.Consume(approved, approved.ItemId, "changed", approved.Digest), "content_changed");
            ApprovalFailure(() => guard.Consume(approved, approved.ItemId, approved.ChangeKey, "changed"), "content_changed");
            ApprovalFailure(() => send.Consume(sendApproved, draft with { Body = "changed" }), "content_changed");
            ApprovalFailure(() => send.Consume(sendApproved, draft with { ChangeKey = "changed" }), "content_changed");
            guard.Consume(approved, approved.ItemId, approved.ChangeKey, approved.Digest);
            send.Consume(sendApproved, draft);
        }

        using (var protection = new DurableDataProtectionProvider(path))
        {
            var store = new MailboxActionApprovalStore(protection, path, clock);
            using var guard = new CalendarActionApprovalGuard(protection, store);
            using var send = new SendGuard(protection, store);
            ApprovalFailure(() => guard.ReadApproval(actor, "task_assign", "task-id", state), "replay");
            ApprovalFailure(() => send.ReadApproval(actor, draft.Id, sendState), "replay");
            var replacement = approved with { Nonce = Guid.NewGuid().ToString("N") };
            store.Stage(replacement.Nonce, MailboxActionApprovalStore.Fingerprint(replacement), replacement.ExpiresAt);
            ApprovalFailure(() => guard.Consume(replacement, replacement.ItemId, replacement.ChangeKey, replacement.Digest), "replay");
            var expired = approved with { Nonce = Guid.NewGuid().ToString("N"), ItemId = "later-task" };
            var expiredState = protection.CreateProtector("Company.ExchangeMcp.CalendarActionApproval.v2").Protect(JsonSerializer.Serialize(expired));
            store.Stage(expired.Nonce, MailboxActionApprovalStore.Fingerprint(expired), expired.ExpiresAt);
            clock.Now += TimeSpan.FromMinutes(16);
            ApprovalFailure(() => guard.ReadApproval(actor, expired.Action, expired.ItemId, expiredState), "expired");
            ApprovalFailure(() => guard.Consume(expired, expired.ItemId, expired.ChangeKey, expired.Digest), "expired");
            var fresh = expired with { Nonce = Guid.NewGuid().ToString("N"), ExpiresAt = store.ExpiresAt() };
            store.Stage(fresh.Nonce, MailboxActionApprovalStore.Fingerprint(fresh), fresh.ExpiresAt);
            guard.Cancel(fresh);
            ApprovalFailure(() => guard.Consume(fresh, fresh.ItemId, fresh.ChangeKey, fresh.Digest), "replay");
            var oauth = actor with { ClientId = "https://chatgpt.com/oauth/client.json" };
            send.ConsumeOAuthSendGrant(oauth, draft with { Id = "oauth-draft" });
        }
        using (var protection = new DurableDataProtectionProvider(path))
        {
            var store = new MailboxActionApprovalStore(protection, path, clock);
            using var send = new SendGuard(protection, store);
            ApprovalFailure(() => send.ConsumeOAuthSendGrant(actor with { ClientId = "https://chatgpt.com/oauth/client.json" },
                draft with { Id = "oauth-draft" }), "replay");
            var registry = Path.Combine(protection.StateDirectory, "approvals.enc");
            var original = File.ReadAllBytes(registry);
            var corrupted = original.ToArray(); corrupted[^1] ^= 1;
            File.WriteAllBytes(registry, corrupted);
            ApprovalFailure(() => store.RequirePending(approved.Nonce, MailboxActionApprovalStore.Fingerprint(approved), approved.ExpiresAt), "storage_unavailable");
            ApprovalFailure(() => new MailboxActionApprovalStore(protection, path, clock), "storage_unavailable");
            File.WriteAllBytes(registry, original);
            using (var oversized = new FileStream(registry, FileMode.Open, FileAccess.Write))
                oversized.SetLength(MailboxActionApprovalStore.MaxStateBytes + 33L);
            ApprovalFailure(() => store.Reserve(new string('A', 64), null, new string('B', 64), actor.Mailbox, "send", "new-draft"), "storage_unavailable");
            File.WriteAllBytes(registry, original);
            File.Delete(registry);
            ApprovalFailure(() => new MailboxActionApprovalStore(protection, path, clock), "storage_unavailable");
            File.WriteAllBytes(registry, original);
        }

        AssertApprovalCapacity(clock, actor);
        AssertApprovalCompletionLifecycle(actor);
        await DurableApprovalProtocolChecksAsync();
        await DurableApprovalPostWriteFaultChecksAsync();
    }

    private async Task DurableApprovalProtocolChecksAsync()
    {
        var path = Path.Combine(runDirectory, "approval-protocol", "audit.jsonl");
        var clock = new ApprovalClock(DateTimeOffset.UtcNow);
        var exchange = new RecordingEwsHandler { DraftMode = true };
        var token = Token("user-a", "mail.read mail.write mail.manage mail.send", sessionId: "durable-approval");
        void Configure(Microsoft.AspNetCore.Builder.WebApplicationBuilder builder)
        {
            builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?> { ["Service:AuditPath"] = path });
            builder.Services.AddSingleton(sp => new MailboxActionApprovalStore(sp.GetRequiredService<IDataProtectionProvider>(),
                sp.GetRequiredService<IOptions<ServiceOptions>>().Value.AuditPath, clock));
        }
        string draftHandle, freshState;
        await using (var host = await StartHostAsync(exchange, writesEnabled: true, sendEnabled: true, configure: Configure))
        {
            await InitializeAsync(host.Client, token, elicitation: true);
            var created = await ToolRequestAsync(host.Client, token, "tools/call", new
            { name = "mail_create_draft", arguments = new { subject = "durable approval", body = "body", to = new[] { "to@example.test" } } });
            draftHandle = ToolStructuredData(created.Body).GetProperty("handle").GetString()!;
            var requested = await ToolRequestAsync(host.Client, token, "tools/call", new
            { name = "mail_send_draft", arguments = new { draftHandle } }, JulyProtocolVersion, elicitation: true);
            var pending = InputRequiredState(requested.Body);
            var position = pending.Length / 2;
            var tampered = pending[..position] + (pending[position] == 'A' ? 'B' : 'A') + pending[(position + 1)..];
            await AssertBlockedAsync(host, tampered, "tampered");
            clock.Now += TimeSpan.FromMinutes(16);
            await AssertBlockedAsync(host, pending, "expired");
            var fresh = await ToolRequestAsync(host.Client, token, "tools/call", new
            { name = "mail_send_draft", arguments = new { draftHandle } }, JulyProtocolVersion, elicitation: true);
            freshState = InputRequiredState(fresh.Body);
        }
        await using (var restarted = await StartHostAsync(exchange, writesEnabled: true, sendEnabled: true, configure: Configure))
        {
            await InitializeAsync(restarted.Client, token, elicitation: true);
            var accepted = await ResumeAsync(restarted, freshState);
            Expect(!IsToolError(accepted) && exchange.SendCount == 1,
                "A real MCP continuation failed after a new host/provider/store instance or sent more than once.");
            await AssertBlockedAsync(restarted, freshState, "replay", 1);
        }
        clock.Now += MailboxActionApprovalStore.AcknowledgedRetention + TimeSpan.FromMinutes(1);
        using (var protection = new DurableDataProtectionProvider(path))
        {
            var store = new MailboxActionApprovalStore(protection, path, clock);
            using var guard = new SendGuard(protection, store);
            // The synthetic EWS fixture keeps a sent draft readable; this checks the matured successful tombstone.
            guard.ConsumeOAuthSendGrant(new("user-a", "alice@example.test", "https://chatgpt.com/oauth/client.json"),
                new("draft-1", "draft-change", "synthetic", null, [], [], [], [], null, false, true, "body", []));
        }

        async Task<string> ResumeAsync(TestHostContext host, string approvalState)
        {
            var response = await ToolRequestAsync(host.Client, token, "tools/call", new
            {
                name = "mail_send_draft",
                requestState = approvalState,
                inputResponses = new Dictionary<string, object?>
                { ["send_confirmation"] = new { action = "accept", content = new { confirm = true } } },
                arguments = new { draftHandle }
            }, JulyProtocolVersion, elicitation: true);
            return response.Body;
        }
        async Task AssertBlockedAsync(TestHostContext host, string approvalState, string reason, int sends = 0)
        {
            var body = await ResumeAsync(host, approvalState);
            var tracking = ToolStructuredData(body).GetProperty("tracking");
            Expect(IsToolError(body) && exchange.SendCount == sends
                && tracking.GetProperty("stage").GetString() == "approval_" + reason
                && tracking.GetProperty("outcome").GetString() == "not_dispatched"
                && tracking.GetProperty("dispatchStatus").GetString() == "not_dispatched",
                "A rejected MCP continuation did not expose its safe approval reason and not_dispatched status: " + reason);
        }
    }

    private async Task DurableApprovalPostWriteFaultChecksAsync()
    {
        var path = Path.Combine(runDirectory, "approval-postwrite", "audit.jsonl");
        var clock = new ApprovalClock(DateTimeOffset.UtcNow);
        var exchange = new RecordingEwsHandler { DraftMode = true };
        using var handler = new ApprovalCompletionLockHandler(exchange, path + ".mcp-state");
        await using var host = await StartHostAsync(handler, writesEnabled: true, sendEnabled: true, configure: builder =>
        {
            builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?> { ["Service:AuditPath"] = path });
            builder.Services.AddSingleton(sp => new MailboxActionApprovalStore(sp.GetRequiredService<IDataProtectionProvider>(), path, clock));
        });
        var token = Token("user-a", "mail.read mail.write mail.manage mail.send", sessionId: "postwrite-fault");
        await InitializeAsync(host.Client, token, elicitation: true);
        var created = await ToolRequestAsync(host.Client, token, "tools/call", new
        { name = "mail_create_draft", arguments = new { subject = "completion fault", body = "body", to = new[] { "to@example.test" } } });
        var draftHandle = ToolStructuredData(created.Body).GetProperty("handle").GetString()!;
        var first = await RequestApprovalAsync();
        var accepted = await ResumeAsync(first);
        var tracking = ToolStructuredData(accepted).GetProperty("tracking");
        Expect(!IsToolError(accepted) && exchange.SendCount == 1
            && tracking.GetProperty("outcome").GetString() == "acknowledged"
            && tracking.GetProperty("approvalPersistence").GetString() == "hold_retained"
            && !tracking.TryGetProperty("dispatchStatus", out _)
            && ModelText(accepted).Contains("do not repeat the action", StringComparison.Ordinal),
            "A post-write approval persistence fault hid the Exchange acknowledgement, invited retry or claimed not_dispatched.");
        handler.ReleaseLock();
        clock.Now += MailboxActionApprovalStore.AcknowledgedRetention + TimeSpan.FromMinutes(1);
        var fresh = await RequestApprovalAsync();
        var blocked = await ResumeAsync(fresh);
        Expect(IsToolError(blocked) && exchange.SendCount == 1
            && ToolStructuredData(blocked).GetProperty("tracking").GetProperty("reason").GetString() == "replay",
            "A failed completion save allowed an uncertain hold to expire or repeat the send.");

        async Task<string> RequestApprovalAsync()
        {
            var result = await ToolRequestAsync(host.Client, token, "tools/call", new
            { name = "mail_send_draft", arguments = new { draftHandle } }, JulyProtocolVersion, elicitation: true);
            return InputRequiredState(result.Body);
        }
        async Task<string> ResumeAsync(string requestState)
        {
            var result = await ToolRequestAsync(host.Client, token, "tools/call", new
            {
                name = "mail_send_draft",
                requestState,
                inputResponses = new Dictionary<string, object?>
                { ["send_confirmation"] = new { action = "accept", content = new { confirm = true } } },
                arguments = new { draftHandle }
            }, JulyProtocolVersion, elicitation: true);
            return result.Body;
        }
    }

    private void AssertApprovalCapacity(ApprovalClock clock, MailboxIdentity actor)
    {
        var path = Path.Combine(runDirectory, "approval-capacity", "audit.jsonl");
        using var protection = new DurableDataProtectionProvider(path);
        var store = new MailboxActionApprovalStore(protection, path, clock);
        var held = Enumerable.Range(0, MailboxActionApprovalStore.MaxEntries).ToDictionary(
            index => index.ToString("X64"), index => new
            {
                Nonce = (string?)null,
                Fingerprint = new string('F', 64),
                Mailbox = actor.Mailbox,
                Action = "send",
                ItemId = "uncertain-draft-" + index
            });
        var state = new { Version = 1, Pending = new Dictionary<string, object>(), Attempts = held };
        File.WriteAllBytes(Path.Combine(protection.StateDirectory, "approvals.enc"),
            protection.CreateProtector("Company.ExchangeMcp.ActionRegistry.v1").Protect(JsonSerializer.SerializeToUtf8Bytes(state)));
        ApprovalFailure(() => store.Reserve(new string('A', 64), null, new string('F', 64), actor.Mailbox, "send", "new-draft"), "capacity");
        store.Acknowledge(0.ToString("X64"), new string('F', 64));
        clock.Now += TimeSpan.FromMinutes(59);
        ApprovalFailure(() => store.Reserve(new string('A', 64), null, new string('F', 64), actor.Mailbox, "send", "new-draft"), "capacity");
        clock.Now += TimeSpan.FromMinutes(2);
        var restarted = new MailboxActionApprovalStore(protection, path, clock);
        restarted.Reserve(new string('A', 64), null, new string('F', 64), actor.Mailbox, "send", "new-draft");
        clock.Now += TimeSpan.FromDays(3);
        ApprovalFailure(() => restarted.Reserve(1.ToString("X64"), null, new string('F', 64), actor.Mailbox, "send", "uncertain-draft-1"), "replay");
        ApprovalFailure(() => restarted.Reserve(new string('B', 64), null, new string('F', 64), actor.Mailbox, "send", "another-draft"), "capacity");
        Expect(held.Count == MailboxActionApprovalStore.MaxEntries, "The capacity fixture was incomplete.");
    }

    private void AssertApprovalCompletionLifecycle(MailboxIdentity actor)
    {
        var path = Path.Combine(runDirectory, "approval-completion", "audit.jsonl");
        var clock = new ApprovalClock(DateTimeOffset.UtcNow);
        using (var protection = new DurableDataProtectionProvider(path))
        {
            var store = new MailboxActionApprovalStore(protection, path, clock);
            Complete("A", "task_assign", "completed");
            Complete("B", "task_execute_assignment_plan", "partial_or_uncertain");
            Complete("C", "task_assign", "task_action_unverified");
            Complete("D", "task_execute_assignment_plan", "completed", unknown: true);
            Complete("E", "task_execute_assignment_plan", "completed");
            Complete("F", "recall", "submission_unverified");
            Complete("1", "task_assign", "completed", rejected: true);
            void Complete(string prefix, string action, string status, bool unknown = false, bool rejected = false)
            {
                using var scope = OperationTracking.Begin(Guid.NewGuid().ToString("N"), action);
                store.Reserve(string.Concat(Enumerable.Repeat(prefix, 64)), null, new string('F', 64), actor.Mailbox, action, "item-" + prefix);
                if (unknown || rejected) OperationTracking.Current!.SetExchangeSendDispatched();
                if (rejected) OperationTracking.Current!.SetExchangeSendRejected();
                OperationTracking.Current!.CompleteApprovalReservations(new CallToolResult
                { StructuredContent = JsonSerializer.SerializeToElement(new { status }), Content = [] });
            }
        }
        clock.Now += MailboxActionApprovalStore.AcknowledgedRetention + TimeSpan.FromMinutes(1);
        using (var protection = new DurableDataProtectionProvider(path))
        {
            var restarted = new MailboxActionApprovalStore(protection, path, clock);
            foreach (var prefix in new[] { 'A', 'E' })
                restarted.Reserve(new string(prefix, 64), null, new string('F', 64), actor.Mailbox, "task_assign", "fresh");
            foreach (var prefix in new[] { 'B', 'C', 'D', 'F', '1' })
                ApprovalFailure(() => restarted.Reserve(new string(prefix, 64), null, new string('F', 64), actor.Mailbox,
                    "task_assign", "still-uncertain"), "replay");
        }
    }

    private static void ApprovalFailure(Action action, string reason)
    {
        try { action(); }
        catch (MailboxActionApprovalException exception) when (exception.Reason == reason) { return; }
        throw new InvalidOperationException("Expected a mailbox action approval failure: " + reason);
    }

    private sealed class ApprovalClock(DateTimeOffset now) : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = now;
        public override DateTimeOffset GetUtcNow() => Now;
    }

    private sealed class ApprovalCompletionLockHandler(HttpMessageHandler inner, string directory) : HttpMessageHandler
    {
        private readonly HttpMessageInvoker invoker = new(inner, disposeHandler: false);
        private FileStream? completionLock;
        public void ReleaseLock() { completionLock?.Dispose(); completionLock = null; }
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var body = await request.Content!.ReadAsStringAsync(cancellationToken);
            var response = await invoker.SendAsync(request, cancellationToken);
            if (XDocument.Parse(body).Descendants().Any(element => element.Name.LocalName == "SendItem"))
                completionLock = new FileStream(Path.Combine(directory, "approvals.lock"), FileMode.Open, FileAccess.ReadWrite, FileShare.None);
            return response;
        }
        protected override void Dispose(bool disposing)
        {
            if (disposing) { ReleaseLock(); invoker.Dispose(); }
            base.Dispose(disposing);
        }
    }
}
