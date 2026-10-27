using System.Net;
using System.Globalization;
using System.Text.Json;
using System.Security.Cryptography;
using System.Text;
using System.Xml.Linq;
using Microsoft.AspNetCore.DataProtection;
using Company.ExchangeMcp;
using Company.ExchangeMcp.Exchange;
using Company.ExchangeMcp.Security;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Logging;

internal sealed partial class Checks
{
    private async Task MailEventChecksAsync()
    {
        await MailStreamingChecksAsync();
        var currentKey = RandomNumberGenerator.GetBytes(32);
        var previousKey = RandomNumberGenerator.GetBytes(32);
        var currentSecret = "whsec_" + Convert.ToBase64String(currentKey);
        var previousSecret = "whsec_" + Convert.ToBase64String(previousKey);
        var body = Encoding.UTF8.GetBytes("{\"eventId\":\"evt_test\"}");
        const string eventId = "evt_test";
        const string timestamp = "1792320000";
        var signature = MailEventWebhook.Sign(currentSecret, eventId, timestamp, body);
        var expectedDigest = HMACSHA256.HashData(currentKey,
            Encoding.UTF8.GetBytes(eventId + "." + timestamp + ".").Concat(body).ToArray());
        Expect(signature == "v1," + Convert.ToBase64String(expectedDigest),
            "Webhook signing did not cover the exact event ID, timestamp and body bytes.");
        var rotated = MailEventWebhook.Sign(currentSecret, previousSecret, eventId, timestamp, body);
        Expect(rotated == signature + " " + MailEventWebhook.Sign(previousSecret, eventId, timestamp, body),
            "Secret rotation did not emit both Standard Webhooks signatures separated by a space.");
        CryptographicOperations.ZeroMemory(currentKey);
        CryptographicOperations.ZeroMemory(previousKey);
        CryptographicOperations.ZeroMemory(expectedDigest);

        Expect(MailEventWebhook.ValidateCallbackUrl("https://8.8.8.8/events").Scheme == Uri.UriSchemeHttps,
            "A public HTTPS callback was rejected.");
        foreach (var url in new[]
        {
            "http://8.8.8.8/events", "https://localhost/events", "https://127.0.0.1/events",
            "https://10.0.0.1/events", "https://user:pass@8.8.8.8/events", "https://8.8.8.8/events#fragment"
        })
            await AssertThrowsAsync<MailEventException>(() =>
            {
                _ = MailEventWebhook.ValidateCallbackUrl(url);
                return Task.CompletedTask;
            });
        foreach (var address in new[] { "0.0.0.0", "10.1.2.3", "100.64.0.1", "127.0.0.1", "169.254.1.1",
                     "192.0.2.1",
                     "172.16.0.1", "192.168.1.1", "198.18.0.1", "224.0.0.1", "::", "::1", "fc00::1", "fe80::1" })
            Expect(!MailEventWebhook.IsPublicAddress(IPAddress.Parse(address)), $"Non-public callback IP {address} was accepted.");
        Expect(MailEventWebhook.IsPublicAddress(IPAddress.Parse("2001:4860:4860::8888")),
            "A public IPv6 callback address was rejected.");
        Expect(!MailEventWebhook.IsPublicAddress(IPAddress.Parse("2002:0808:0808::1")),
            "A 6to4 address was treated as a direct public callback destination.");
        Expect(!MailEventWebhook.IsPublicAddress(IPAddress.Parse("3fff::1")),
            "An IPv6 documentation address was treated as a public callback destination.");
        await AssertThrowsAsync<MailEventException>(() =>
        {
            _ = MailEventWebhook.DecodeSecret("whsec_" + Convert.ToBase64String(new byte[23]));
            return Task.CompletedTask;
        });

        var ewsHandler = new RecordingEwsHandler();
        var summary = await NewEwsClient(ewsHandler).GetMessageSummaryAsync("alice@example.test", "message-1", CancellationToken.None);
        Expect(MailEventProcessor.RecipientRole(summary, "ALICE@example.test") == "to"
            && MailEventProcessor.RecipientRole(summary with { To = [], Cc = ["alice@example.test"] }, "alice@example.test") == "cc"
            && MailEventProcessor.RecipientRole(summary with { To = [], Cc = [] }, "alice@example.test") == "unknown",
            "Inbox recipient role did not distinguish To, CC, and unresolved/alias delivery.");
        var summaryOperation = Operation(XDocument.Parse(ewsHandler.LastRequest.Body));
        var requestedFields = summaryOperation.Descendants(XName.Get("FieldURI", TypesNamespace))
            .Select(field => (string?)field.Attribute("FieldURI")).Where(value => value is not null).ToArray();
        Expect(summary.Subject == "Report" && requestedFields.Contains("item:Subject")
            && requestedFields.Contains("message:From") && requestedFields.Contains("item:DateTimeReceived")
            && requestedFields.Contains("message:ToRecipients") && requestedFields.Contains("message:CcRecipients")
            && summaryOperation.Element(XName.Get("ItemShape", MessagesNamespace))?.Element(
                XName.Get("AdditionalProperties", TypesNamespace))?.Elements(XName.Get("ExtendedFieldURI", TypesNamespace)).Any(field =>
                    (string?)field.Attribute("PropertyTag") == "0x300B" && (string?)field.Attribute("PropertyType") == "Binary") == true
            && !requestedFields.Contains("item:Body") && !requestedFields.Contains("item:Attachments"),
            "Inbox event summary did not request only sender/subject/time metadata.");

        var auditPath = Path.Combine(runDirectory, "mail-event-state", "audit.jsonl");
        var options = Options.Create(new ServiceOptions { AuditPath = auditPath });
        var actor = new MailboxIdentity("subject-a", "alice@example.test", "codex", "session-a", "own", "alice@example.test");
        var otherActor = actor with { Subject = "subject-b", Mailbox = "bob@example.test", ActorMailbox = "bob@example.test" };
        var now = DateTimeOffset.UtcNow;
        var id = "sub_durable-test";
        var cursorKey = MailEventStateStore.CursorKey(actor);
        var callback = "https://events.example.test/receive";
        var subscription = new MailEventSubscription(id, actor.Subject, actor.Mailbox, actor.ClientId,
            actor.SessionId!, MailEventService.InboxEventName, callback, currentSecret, now, now.AddHours(1),
            [], false, null, null, null);
        var stateDirectory = auditPath + ".mail-events";
        var statePath = Path.Combine(stateDirectory, "state.enc");
        var keyPath = Path.Combine(stateDirectory, "state.key");
        using (var store = new MailEventStateStore(options))
        {
            Expect(store.IsAvailable, "The durable encrypted event store did not initialize.");
            await store.SetBaselineIfMissingAsync(actor, "sync-state-0", now, CancellationToken.None);
            await store.AddOrRefreshAsync(subscription, CancellationToken.None);
            await store.CommitPageAsync(cursorKey, "sync-state-1",
                [new MailEventCapturedMessage("message-1", "change-1", "sender@example.test", "New message", now,
                    EventSearchKey: EventMessageReadHandler.SearchKey)],
                now, CancellationToken.None);
            Expect((await store.StatusAsync(actor, CancellationToken.None)).Single().Pending == 1,
                "A new Inbox item was not durably queued.");
            await AssertThrowsAsync<MailEventException>(() => store.CommitPageAsync(cursorKey, "sync-state-2",
                Enumerable.Range(0, 32).Select(index => new MailEventCapturedMessage($"message-{index + 2}", "change",
                    "sender@example.test", "Overflow", now)).ToArray(), now, CancellationToken.None));
            Expect((await store.StatusAsync(actor, CancellationToken.None)).Single().Pending == 1,
                "Queue overflow changed the saved cursor or pending queue.");
            await store.AddOrRefreshAsync(subscription with
            {
                CreatedAt = now.AddMinutes(1),
                ExpiresAt = now.AddHours(2),
                Secret = previousSecret
            }, CancellationToken.None);
        }
        Expect(File.Exists(statePath) && File.ReadAllBytes(keyPath).Length == 32,
            "The event state/key files were not created in the dedicated directory.");
        var persistedBytes = File.ReadAllBytes(statePath);
        Expect(persistedBytes.AsSpan(0, 4).SequenceEqual(Encoding.ASCII.GetBytes("CME1"))
            && !Encoding.UTF8.GetString(persistedBytes).Contains("alice@example.test", StringComparison.Ordinal)
            && !Encoding.UTF8.GetString(persistedBytes).Contains(currentSecret, StringComparison.Ordinal),
            "The persisted event registry was not encrypted.");
        using (var restored = new MailEventStateStore(options))
        {
            var restoredStatus = await restored.StatusAsync(actor, CancellationToken.None);
            Expect(restored.IsAvailable && restoredStatus.Single().Pending == 1
                && (await restored.StatusAsync(otherActor, CancellationToken.None)).Count == 0
                && (await restored.NextDueAsync(id, now, CancellationToken.None))!.EventSearchKey == EventMessageReadHandler.SearchKey,
                "Restart did not preserve the owner's pending event or isolate other mailbox users.");
            var beforeReplay = (await restored.NextDueAsync(id, now, CancellationToken.None))!.EventId;
            await restored.CommitPageAsync(cursorKey, "reconnect-state",
                [new MailEventCapturedMessage("message-1", "changed-key", "sender@example.test", "New message", now)], now,
                CancellationToken.None);
            Expect((await restored.StatusAsync(actor, CancellationToken.None)).Single().Pending == 1
                && (await restored.NextDueAsync(id, now, CancellationToken.None))!.EventId == beforeReplay,
                "Replayed streaming/reconnect changes duplicated a durable event or changed its delivery ID.");
            var restoredSub = (await restored.SubscriptionsAsync(
                (await restored.ActiveCursorsAsync(DateTimeOffset.UtcNow, CancellationToken.None)).Single(),
                DateTimeOffset.UtcNow, CancellationToken.None)).Single();
            Expect(restoredSub.Secret == previousSecret && restoredSub.PreviousSecret == currentSecret
                && restoredSub.PreviousSecretUntil == now.AddMinutes(6),
                "Restart did not preserve the rotated key and its bounded overlap window.");
        }
        persistedBytes[^1] ^= 0x80;
        File.WriteAllBytes(statePath, persistedBytes);
        using (var corrupt = new MailEventStateStore(options))
            Expect(!corrupt.IsAvailable, "Corrupt encrypted event state did not fail closed.");

        var missingAuditPath = Path.Combine(runDirectory, "mail-event-missing-state", "audit.jsonl");
        var missingOptions = Options.Create(new ServiceOptions { AuditPath = missingAuditPath });
        var missingStatePath = missingAuditPath + ".mail-events";
        using (var initialized = new MailEventStateStore(missingOptions))
            Expect(initialized.IsAvailable, "A new event-state registry did not initialize.");
        File.Delete(Path.Combine(missingStatePath, "state.enc"));
        using (var lostState = new MailEventStateStore(missingOptions))
            Expect(!lostState.IsAvailable, "A missing encrypted registry was silently replaced with empty state.");

        await AssertDroppedEventRangesPersistAsync();
        await MailEventProcessorChecksAsync();
        await EventMessageReadChecksAsync();
    }

    private async Task AssertDroppedEventRangesPersistAsync()
    {
        var auditPath = Path.Combine(runDirectory, "mail-event-gap", "audit.jsonl");
        var options = Options.Create(new ServiceOptions { AuditPath = auditPath });
        var actor = new MailboxIdentity("gap-subject", "gap@example.test", "codex", "gap-session", "own", "gap@example.test");
        var now = DateTimeOffset.UtcNow;
        var secret = "whsec_" + Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        var id = "sub_gap-test";
        var subscription = new MailEventSubscription(id, actor.Subject, actor.Mailbox, actor.ClientId,
            actor.SessionId!, MailEventService.InboxEventName, "https://8.8.8.8/events", secret,
            now, now.AddHours(1), [], false, null, null, null);
        using var store = new MailEventStateStore(options);
        await store.SetBaselineIfMissingAsync(actor, "gap-state", now, CancellationToken.None);
        await store.AddOrRefreshAsync(subscription, CancellationToken.None);
        await store.CommitPageAsync(MailEventStateStore.CursorKey(actor), "gap-state-2",
            [new MailEventCapturedMessage("item-1", "key-1", "sender@example.test", "Important", now.AddMinutes(-2))],
            now, CancellationToken.None);
        await store.StopAsync(id, "callback_gone", CancellationToken.None);
        var stopped = (await store.StatusAsync(actor, CancellationToken.None)).Single();
        Expect(stopped.Truncated && stopped.Pending == 0 && stopped.MissedFromUtc is not null
            && stopped.MissedToUtc is not null && stopped.StoppedReason == "callback_gone",
            "Stopping a callback with queued events did not expose the discarded range.");

        await store.SetBaselineIfMissingAsync(actor, "gap-state-3", now.AddMinutes(1), CancellationToken.None);
        await store.AddOrRefreshAsync(subscription with
        {
            CreatedAt = now.AddMinutes(1),
            ExpiresAt = now.AddHours(2)
        }, CancellationToken.None);
        var refreshed = (await store.StatusAsync(actor, CancellationToken.None)).Single();
        Expect(refreshed.Truncated && refreshed.MissedFromUtc == stopped.MissedFromUtc
            && refreshed.MissedToUtc == stopped.MissedToUtc && refreshed.StoppedReason is null,
            "Reactivating a subscription hid its previously discarded event range.");
    }

    private async Task MailEventProcessorChecksAsync()
    {
        var auditPath = Path.Combine(runDirectory, "mail-event-processor", "audit.jsonl");
        var appOptions = new ServiceOptions
        {
            AllowedClientIds = ["codex"],
            Mailboxes = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["subject-a"] = "alice@example.test",
                ["subject-b"] = "bob@example.test"
            },
            AuditPath = auditPath
        };
        var options = Options.Create(appOptions);
        var access = new MailboxAccess(options);
        var handler = new MailEventProcessorEwsHandler();
        using var http = new HttpClient(handler);
        var exchange = new EwsClient(http, Options.Create(new EwsOptions
        {
            Endpoint = "https://mail.example.test/EWS/Exchange.asmx",
            TimeoutSeconds = 10,
            MaxResponseBytes = 2_097_152
        }), access);
        var webhook = new RecordingMailEventWebhook { FirstDeliveryStatus = HttpStatusCode.ServiceUnavailable };
        var timingLogger = new MailEventTimingLogger();
        webhook.OnDelivery = notification => Expect(timingLogger.Entries.Any(entry =>
            entry.GetValueOrDefault("EventId") as string == notification.EventId
            && entry.ContainsKey("AttemptUtc")), "Delivery began before its attempt timing checkpoint.");
        using var store = new MailEventStateStore(options);
        var handles = new MailboxHandles(new EphemeralDataProtectionProvider());
        var service = new MailEventService(exchange, access, store, webhook, options);
        var alice = new MailboxIdentity("subject-a", "alice@example.test", "codex", null, "own", "alice@example.test");
        var bob = new MailboxIdentity("subject-b", "bob@example.test", "codex", "session-b", "own", "bob@example.test");
        var secret = "whsec_" + Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        var emptyArguments = JsonDocument.Parse("{}").RootElement.Clone();
        const string callback = "https://8.8.8.8/events";

        var removedClient = alice with { ClientId = "removed-client" };
        var removedAt = DateTimeOffset.UtcNow;
        string removedBaseline;
        using (access.SelectTarget(alice))
            removedBaseline = await service.ReadCompleteBaselineAsync(alice.Mailbox, CancellationToken.None);
        await store.SetBaselineIfMissingAsync(alice, removedBaseline, removedAt, CancellationToken.None);
        await store.AddOrRefreshAsync(new MailEventSubscription("sub_removed-client", removedClient.Subject,
            removedClient.Mailbox, removedClient.ClientId, "", MailEventService.InboxEventName, callback, secret,
            removedAt, removedAt.AddHours(1), [], false, null, null, null), CancellationToken.None);

        await service.SubscribeAsync(alice, MailEventService.InboxEventName, emptyArguments, callback, secret,
            10 * 60 * 1000, CancellationToken.None);
        await service.SubscribeAsync(bob, MailEventService.InboxEventName, emptyArguments, callback, secret,
            10 * 60 * 1000, CancellationToken.None);
        Expect((await store.StatusAsync(alice, CancellationToken.None)).Single().Pending == 0
            && (await store.StatusAsync(bob, CancellationToken.None)).Single().Pending == 0
            && webhook.Deliveries.Count == 0
            && handler.SummaryReads == 0,
            "Subscription baseline replayed an old Inbox item or fetched its body metadata.");

        var expired = new MailboxIdentity("subject-expired", "expired@example.test", "codex", "session-expired", "own", "expired@example.test");
        var expiredAt = DateTimeOffset.UtcNow.AddMinutes(-2);
        var expiredSub = new MailEventSubscription("sub_expired", expired.Subject, expired.Mailbox,
            expired.ClientId, expired.SessionId!, MailEventService.InboxEventName, callback, secret,
            expiredAt.AddMinutes(-1), expiredAt, [new MailEventPending("evt_expired", expiredAt.AddMinutes(-1),
                "expired-item", "key", "sender@example.test", "Expired", expiredAt.AddMinutes(-1), 0, expiredAt)],
            false, null, null, null);
        await store.SetBaselineIfMissingAsync(expired, "expired-state", expiredAt, CancellationToken.None);
        await store.AddOrRefreshAsync(expiredSub, CancellationToken.None);

        await store.CommitPageAsync(MailEventStateStore.CursorKey(bob), "bob-pending-state",
            [new MailEventCapturedMessage("bob-item", "bob-key", "sender@example.test", "Should not notify", DateTimeOffset.UtcNow)],
            DateTimeOffset.UtcNow, CancellationToken.None);
        handler.ReadAllowedByMailbox["bob@example.test"] = false;
        using (var processor = new MailEventProcessor(exchange, access, handles, store, webhook, options,
            timingLogger))
            await processor.RunOnceAsync(CancellationToken.None);

        var deliveriesAfterFailure = webhook.Deliveries.ToArray();
        Expect(deliveriesAfterFailure.Length == 1
            && deliveriesAfterFailure[0].Notification.Data.Sender == "new.sender@example.test"
            && deliveriesAfterFailure[0].Notification.Data.Subject == "New message"
            && deliveriesAfterFailure[0].Notification.Data.ReceivedUtc == DateTimeOffset.Parse("2026-10-18T10:00:00Z", CultureInfo.InvariantCulture)
            && handler.SummaryReads == 1 && !handler.SummaryRequestedBody && !handler.SummaryRequestedAttachments,
            "The processor did not deliver one body-free header event for a post-baseline Inbox item.");
        var eventId = deliveriesAfterFailure[0].Notification.EventId;
        var deliveredHandle = deliveriesAfterFailure[0].Notification.Data.MessageHandle;
        Expect(handles.ResolveMessageForRead(alice, deliveredHandle).Id == "new-item"
            && handles.ResolveMessageForRead(alice, deliveredHandle).Kind == "event-message"
            && handles.ResolveMessageForRead(alice, deliveredHandle).EventSearchKey == EventMessageReadHandler.SearchKey,
            "A delivered event handle could not be resolved by its valid client without an OAuth sid claim.");
        await AssertThrowsAsync<ModelContextProtocol.McpException>(() =>
        {
            handles.ResolveMessageForRead(alice with { SessionId = "different-session" }, deliveredHandle);
            return Task.CompletedTask;
        });
        Expect((await store.StatusAsync(alice, CancellationToken.None)).Single().Pending == 1,
            "A transient callback failure lost its queued event.");
        Expect((await store.StatusAsync(bob, CancellationToken.None)).Count == 0
            && (await store.StatusAsync(expired, CancellationToken.None)).Count == 0,
            "Revoked or expired subscriptions remained available for event delivery.");
        Expect((await store.StatusAsync(removedClient, CancellationToken.None)).Single().StoppedReason == "client_access_revoked"
            && (await store.StatusAsync(alice, CancellationToken.None)).Single().StoppedReason is null,
            "Removing the first subscription's client revoked the other authorized client for the same mailbox.");

        var aliceSub = (await store.SubscriptionsAsync(
            (await store.ActiveCursorsAsync(DateTimeOffset.UtcNow, CancellationToken.None)).Single(),
            DateTimeOffset.UtcNow, CancellationToken.None)).Single();
        await store.RetryAsync(aliceSub.Id, eventId, DateTimeOffset.UtcNow.AddMinutes(-1), "test_retry", CancellationToken.None);
        timingLogger.ThrowOnLog = true;
        using (var processor = new MailEventProcessor(exchange, access, handles, store, webhook, options,
            timingLogger))
            await processor.RunOnceAsync(CancellationToken.None);
        using (var processor = new MailEventProcessor(exchange, access, handles, store, webhook, options,
            timingLogger))
            await processor.RunOnceAsync(CancellationToken.None);

        var deliveries = webhook.Deliveries.ToArray();
        Expect(deliveries.Length == 2 && deliveries.All(delivery => delivery.Notification.EventId == eventId)
            && (await store.StatusAsync(alice, CancellationToken.None)).Single().Pending == 0,
            "The callback retry changed the stable event ID, duplicated delivery, or left an acknowledged event queued.");
        Expect(handles.ResolveMessageForRead(alice, deliveredHandle).EventSearchKey == EventMessageReadHandler.SearchKey,
            "Callback acknowledgement invalidated the notification read reference.");
        Expect(handler.SyncStates.Contains("baseline-alice") && handler.SyncStates.Contains("poll-alice")
            && handler.SyncStates.Contains("poll-2-alice") && handler.SummaryReads == 1,
            "Mailbox synchronization did not advance from the post-subscription baseline without replaying old items.");

        var entries = timingLogger.Entries.Where(entry => entry.GetValueOrDefault("EventId") as string == eventId).ToArray();
        var queued = entries.Single(entry => entry.ContainsKey("QueuedUtc"));
        var attempts = entries.Where(entry => entry.ContainsKey("AttemptUtc")).ToArray();
        var responses = entries.Where(entry => entry.ContainsKey("ResponseUtc")).ToArray();
        var acknowledged = entries.Single(entry => entry.ContainsKey("AcknowledgedUtc"));
        Expect(queued["RecipientRole"] as string == "cc"
            && (DateTimeOffset)queued["ExchangeReceivedUtc"]! == deliveries[0].Notification.Data.ReceivedUtc
            && deliveries[0].Notification.Timestamp <= (DateTimeOffset)queued["QueuedUtc"]!
            && (DateTimeOffset)queued["QueuedUtc"]! <= (DateTimeOffset)attempts[0]["AttemptUtc"]!
            && attempts.Length == 2 && (int)attempts[0]["AttemptNumber"]! == 1
            && (int)attempts[1]["AttemptNumber"]! > 1
            && responses.Length == 2 && (int)responses[0]["HttpStatus"]! == 503
            && (int)responses[1]["HttpStatus"]! == 200 && timingLogger.FailedWrites >= 3,
            "Timing logs lost the CC role, actual queue checkpoint, retry number, HTTP result, or failed sink isolation.");
        for (var index = 0; index < attempts.Length; index++)
            Expect((DateTimeOffset)attempts[index]["AttemptUtc"]! <= webhook.Timings[index].EnteredUtc
                && webhook.Timings[index].ReturnedUtc <= (DateTimeOffset)responses[index]["ResponseUtc"]!
                && (double)responses[index]["ElapsedMilliseconds"]! >= 0,
                "Attempt/response timing does not bracket the actual callback call.");
        Expect((DateTimeOffset)responses[1]["ResponseUtc"]! <= (DateTimeOffset)acknowledged["AcknowledgedUtc"]!,
            "Acknowledgement was logged before callback success.");

        timingLogger.ThrowOnLog = false;
        webhook.OnDelivery = null;
        const string hostileEventId = "evt_\r\nsecret-injected-line";
        var hostileAt = DateTimeOffset.UtcNow;
        await store.AddOrRefreshAsync(aliceSub with
        {
            Id = "sub_hostile-timing",
            Pending = [new MailEventPending(hostileEventId, hostileAt, "hostile-item", "hostile-key",
                "private-sender@example.test", "Private subject", hostileAt, 0, hostileAt)]
        }, CancellationToken.None);
        using (var processor = new MailEventProcessor(exchange, access, handles, store, webhook, options, timingLogger))
            await processor.RunOnceAsync(CancellationToken.None);
        Expect(timingLogger.Entries.Count(entry => entry.GetValueOrDefault("EventId") as string == "invalid") == 3
            && (await store.StatusAsync(alice, CancellationToken.None)).All(status => status.Pending == 0),
            "Untrusted event correlation was logged verbatim or changed acknowledgement.");
        var traceText = string.Join("\n", timingLogger.Messages);
        foreach (var excluded in new[] { callback, secret, "new.sender@example.test", "alice@example.test",
            "New message", deliveredHandle, "new-item", "new-key", hostileEventId, "secret-injected-line",
            "private-sender@example.test", "Private subject", "hostile-item", "hostile-key", "whsec_", "webhook-signature",
            EventMessageReadHandler.SearchKey })
            Expect(!traceText.Contains(excluded, StringComparison.Ordinal), "Timing diagnostics exposed private callback or message data.");

        var beforeAged = webhook.Deliveries.Count;
        var agedAt = DateTimeOffset.UtcNow.AddHours(-49);
        await store.AddOrRefreshAsync(aliceSub with
        {
            Id = "sub_aged-reference",
            CreatedAt = DateTimeOffset.UtcNow,
            ExpiresAt = DateTimeOffset.UtcNow.AddHours(1),
            Pending = [new MailEventPending("evt_aged", agedAt, "aged-item", "key", "sender@example.test", "Aged",
                agedAt, 0, agedAt, EventSearchKey: EventMessageReadHandler.SearchKey)]
        }, CancellationToken.None);
        using (var processor = new MailEventProcessor(exchange, access, handles, store, webhook, options, timingLogger))
            await processor.RunOnceAsync(CancellationToken.None);
        using (var processor = new MailEventProcessor(exchange, access, handles, store, webhook, options, timingLogger))
            await processor.RunOnceAsync(CancellationToken.None);
        var aged = (await store.StatusAsync(alice, CancellationToken.None)).Single(status => status.Id == "sub_aged-reference");
        Expect(webhook.Deliveries.Count == beforeAged && aged.Pending == 0 && aged.Truncated
            && aged.StoppedReason == "message_reference_expired" && aged.MissedFromUtc is not null,
            "An event older than its read-reference deadline retried delivery or silently lost the missed range.");
    }
}

internal sealed class RecordingMailEventWebhook : IMailEventWebhook
{
    public List<(string SubscriptionId, MailEventNotification Notification)> Deliveries { get; } = [];
    public HttpStatusCode FirstDeliveryStatus { get; init; } = HttpStatusCode.OK;
    public Action<MailEventNotification>? OnDelivery { get; set; }
    public List<(DateTimeOffset EnteredUtc, DateTimeOffset ReturnedUtc)> Timings { get; } = [];

    public Task VerifyAsync(string callbackUrl, string subscriptionId, string secret, CancellationToken cancellationToken) =>
        Task.CompletedTask;

    public Task<HttpStatusCode> DeliverAsync(string callbackUrl, string subscriptionId, string secret,
        string? previousSecret, MailEventNotification notification, CancellationToken cancellationToken)
    {
        var enteredUtc = DateTimeOffset.UtcNow;
        OnDelivery?.Invoke(notification);
        Deliveries.Add((subscriptionId, notification));
        Timings.Add((enteredUtc, DateTimeOffset.UtcNow));
        return Task.FromResult(Deliveries.Count == 1 ? FirstDeliveryStatus : HttpStatusCode.OK);
    }
}

internal sealed class MailEventTimingLogger : ILogger<MailEventProcessor>
{
    public List<Dictionary<string, object?>> Entries { get; } = [];
    public List<string> Messages { get; } = [];
    public bool ThrowOnLog { get; set; }
    public int FailedWrites { get; private set; }
    public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
    public bool IsEnabled(LogLevel logLevel) => true;
    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
        Func<TState, Exception?, string> formatter)
    {
        Entries.Add(((IEnumerable<KeyValuePair<string, object?>>)(object)state!).ToDictionary(pair => pair.Key, pair => pair.Value));
        Messages.Add(formatter(state, exception));
        if (ThrowOnLog)
        {
            FailedWrites++;
            throw new InvalidOperationException("Synthetic timing sink failure.");
        }
    }
}

internal sealed class MailEventProcessorEwsHandler : HttpMessageHandler
{
    private const string Soap = "http://schemas.xmlsoap.org/soap/envelope/";
    private const string Messages = "http://schemas.microsoft.com/exchange/services/2006/messages";
    private const string Types = "http://schemas.microsoft.com/exchange/services/2006/types";
    public Dictionary<string, bool> ReadAllowedByMailbox { get; } = new(StringComparer.OrdinalIgnoreCase);
    public List<string> SyncStates { get; } = [];
    public int SummaryReads { get; private set; }
    public bool SummaryRequestedBody { get; private set; }
    public bool SummaryRequestedAttachments { get; private set; }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var body = await request.Content!.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        var document = XDocument.Parse(body);
        var operation = document.Root!.Element(XName.Get("Body", Soap))!.Elements().Single();
        var name = operation.Name.LocalName;
        var mailbox = request.Headers.GetValues("X-AnchorMailbox").Single();
        string result;
        if (name == "GetFolder")
        {
            var canRead = !ReadAllowedByMailbox.TryGetValue(mailbox, out var read) || read;
            result = $"<m:Folders><t:Folder><t:FolderId Id='inbox-{(mailbox.StartsWith("alice", StringComparison.OrdinalIgnoreCase) ? "alice" : "bob")}'/><t:EffectiveRights><t:Read>{canRead.ToString().ToLowerInvariant()}</t:Read><t:CreateContents>false</t:CreateContents><t:Modify>false</t:Modify><t:Delete>false</t:Delete></t:EffectiveRights></t:Folder></m:Folders>";
        }
        else if (name == "SyncFolderItems")
        {
            var state = operation.Element(XName.Get("SyncState", Messages))?.Value;
            SyncStates.Add(state ?? "<baseline>");
            var owner = mailbox.StartsWith("alice", StringComparison.OrdinalIgnoreCase) ? "alice" : "bob";
            var nextState = state is null ? $"baseline-{owner}"
                : state == $"baseline-{owner}" ? $"poll-{owner}" : $"poll-2-{owner}";
            var changes = state is null
                ? "<t:Create><t:Message><t:ItemId Id='old-item' ChangeKey='old-key'/></t:Message></t:Create>"
                : owner == "alice" && state == "baseline-alice"
                    ? "<t:Create><t:Message><t:ItemId Id='new-item' ChangeKey='new-key'/></t:Message></t:Create>"
                    : "";
            result = $"<m:SyncState>{nextState}</m:SyncState><m:IncludesLastItemInRange>true</m:IncludesLastItemInRange><m:Changes>{changes}</m:Changes>";
        }
        else if (name == "GetItem")
        {
            SummaryReads++;
            var fields = operation.Descendants(XName.Get("FieldURI", Types)).Select(field => (string?)field.Attribute("FieldURI"));
            SummaryRequestedBody |= fields.Contains("item:Body");
            SummaryRequestedAttachments |= fields.Contains("item:Attachments");
            result = $"<m:Items><t:Message><t:ItemId Id='new-item' ChangeKey='new-key'/><t:Subject>New message</t:Subject><t:From><t:Mailbox><t:EmailAddress>new.sender@example.test</t:EmailAddress></t:Mailbox></t:From><t:Sender><t:Mailbox><t:EmailAddress>new.sender@example.test</t:EmailAddress></t:Mailbox></t:Sender><t:CcRecipients><t:Mailbox><t:EmailAddress>alice@example.test</t:EmailAddress></t:Mailbox></t:CcRecipients><t:DateTimeReceived>2026-10-18T10:00:00Z</t:DateTimeReceived><t:ExtendedProperty><t:ExtendedFieldURI PropertyTag='0x300B' PropertyType='Binary'/><t:Value>{EventMessageReadHandler.SearchKey}</t:Value></t:ExtendedProperty></t:Message></m:Items>";
        }
        else throw new InvalidOperationException($"Unexpected mail-event EWS operation: {name}.");

        var xml = $"<s:Envelope xmlns:s='{Soap}' xmlns:m='{Messages}' xmlns:t='{Types}'><s:Body><m:{name}Response><m:ResponseMessages><m:{name}ResponseMessage ResponseClass='Success'><m:ResponseCode>NoError</m:ResponseCode>{result}</m:{name}ResponseMessage></m:ResponseMessages></m:{name}Response></s:Body></s:Envelope>";
        return new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(xml, Encoding.UTF8, "text/xml")
        };
    }
}
