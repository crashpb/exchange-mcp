using System.Collections.Concurrent;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Channels;
using System.Xml.Linq;
using Company.ExchangeMcp;
using Company.ExchangeMcp.Exchange;
using Company.ExchangeMcp.Security;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

internal sealed partial class Checks
{
    private async Task MailStreamingChecksAsync()
    {
        var changed = 0;
        var frames = StreamingCheckHandler.Frame("<t:StatusEvent/>") + "\r\n"
            + StreamingCheckHandler.Frame("<t:CreatedEvent><t:TimeStamp><![CDATA[</s:Envelope>]]></t:TimeStamp><t:ItemId Id='one'/></t:CreatedEvent><t:NewMailEvent><t:ItemId Id='one'/></t:NewMailEvent>")
            + StreamingCheckHandler.Frame("", closed: true);
        await using (var fragmented = new StreamingChunkStream())
        {
            fragmented.Write(frames);
            await EwsClient.ReadStreamingEnvelopesAsync(fragmented, "stream-test", 64 * 1024,
                _ => { changed++; return Task.CompletedTask; }, CancellationToken.None);
        }
        Expect(changed == 1, "Streaming envelopes were not framed independently or duplicate event types caused multiple reconciliations.");
        foreach (var invalid in new[]
        {
            "<!DOCTYPE s:Envelope [<!ENTITY x SYSTEM 'file:///etc/passwd'>]>" + StreamingCheckHandler.Frame("", closed: true),
            StreamingCheckHandler.Frame("<t:NewMailEvent/>").Replace("stream-test", "wrong-subscription", StringComparison.Ordinal),
            StreamingCheckHandler.Frame("", closed: true).Replace("NoError", "ErrorInvalidSubscription", StringComparison.Ordinal),
            "<s:Envelope xmlns:s='http://schemas.xmlsoap.org/soap/envelope/'><s:Body>"
        })
        {
            await AssertThrowsAsync<InvalidOperationException>(async () =>
            {
                using var source = new MemoryStream(Encoding.UTF8.GetBytes(invalid));
                await EwsClient.ReadStreamingEnvelopesAsync(source, "stream-test", 64 * 1024,
                    _ => Task.CompletedTask, CancellationToken.None);
            });
        }
        await AssertThrowsAsync<InvalidOperationException>(async () =>
        {
            using var source = new MemoryStream(Encoding.UTF8.GetBytes(StreamingCheckHandler.Frame(new string('x', 2048))));
            await EwsClient.ReadStreamingEnvelopesAsync(source, "stream-test", 1024,
                _ => Task.CompletedTask, CancellationToken.None);
        });

        var options = Options.Create(new ServiceOptions
        {
            AuditPath = Path.Combine(runDirectory, "streaming-lifecycle", "audit.jsonl"),
            AllowedClientIds = ["codex"],
            Mailboxes = new(StringComparer.Ordinal) { ["subject-a"] = "alice@example.test" }
        });
        var access = new MailboxAccess(options);
        using var handler = new StreamingCheckHandler();
        using var http = new HttpClient(handler, disposeHandler: false);
        var exchange = new EwsClient(http, Options.Create(new EwsOptions
        {
            Endpoint = "https://mail.example.test/EWS/Exchange.asmx",
            TimeoutSeconds = 5,
            MaxResponseBytes = 2_097_152
        }), access);
        using var store = new MailEventStateStore(options);
        var webhook = new RecordingMailEventWebhook();
        var actor = new MailboxIdentity("subject-a", "alice@example.test", "codex", "session-a", "own", "alice@example.test");
        using (access.SelectTarget(actor with { Mailbox = "bob@example.test", TargetId = "delegated-bob" }))
        {
            await AssertThrowsAsync<InvalidOperationException>(() => exchange.SubscribeInboxStreamingAsync("bob@example.test", CancellationToken.None));
            await AssertThrowsAsync<InvalidOperationException>(() => exchange.UnsubscribeStreamingAsync("bob@example.test", "stream-test", CancellationToken.None));
            await AssertThrowsAsync<InvalidOperationException>(() => exchange.ReadInboxStreamingAsync("bob@example.test", "stream-test", http,
                _ => Task.CompletedTask, CancellationToken.None));
        }
        var service = new MailEventService(exchange, access, store, webhook, options);
        using var processor = new MailEventProcessor(exchange, access, new MailboxHandles(new EphemeralDataProtectionProvider()),
            store, webhook, options, NullLogger<MailEventProcessor>.Instance, new StreamingCheckClientFactory(handler));
        await processor.StartAsync(CancellationToken.None);
        try
        {
            await Task.Delay(1100);
            Expect(handler.Subscriptions == 0 && handler.Backend.SyncStates.Count == 0,
                "A mailbox watcher or Exchange polling ran with no active subscription.");
            var removedClient = actor with { ClientId = "removed-client" };
            var createdAt = DateTimeOffset.UtcNow;
            string removedBaseline;
            using (access.SelectTarget(actor))
                removedBaseline = await service.ReadCompleteBaselineAsync(actor.Mailbox, CancellationToken.None);
            await store.SetBaselineIfMissingAsync(actor, removedBaseline, createdAt, CancellationToken.None);
            await store.AddOrRefreshAsync(new MailEventSubscription("sub_stream-removed-client", actor.Subject,
                actor.Mailbox, removedClient.ClientId, actor.SessionId!, MailEventService.InboxEventName,
                "https://8.8.8.8/removed", "whsec_" + Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),
                createdAt, createdAt.AddHours(1), [], false, null, null, null), CancellationToken.None);
            await service.SubscribeAsync(actor, MailEventService.InboxEventName, JsonDocument.Parse("{}").RootElement,
                "https://8.8.8.8/events", "whsec_" + Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),
                10 * 60 * 1000, CancellationToken.None);
            await WaitForStreamingAsync(() => handler.Streams.Count == 1 && handler.Backend.SyncStates.Count >= 2);
            Expect((await store.StatusAsync(removedClient, CancellationToken.None)).Single().StoppedReason == "client_access_revoked"
                && (await store.StatusAsync(actor, CancellationToken.None)).Single().StoppedReason is null,
                "Streaming startup revoked an authorized client because an earlier subscription's client was removed.");
            var syncs = handler.Backend.SyncStates.Count;
            await Task.Delay(1100);
            Expect(handler.Backend.SyncStates.Count == syncs, "Idle event supervision performed periodic Inbox synchronization.");
            handler.Streams.TryPeek(out var stream);
            stream!.Write(StreamingCheckHandler.Frame("<t:StatusEvent/>"));
            await Task.Delay(1100);
            Expect(handler.Backend.SyncStates.Count == syncs, "An EWS StatusEvent triggered mailbox polling.");
            stream.Write(StreamingCheckHandler.Frame("<t:NewMailEvent><t:ItemId Id='new-item'/></t:NewMailEvent>"));
            await WaitForStreamingAsync(() => handler.Backend.SyncStates.Count == syncs + 1);
            Expect(webhook.Deliveries.Count == 1 && webhook.Deliveries[0].Notification.Data.RecipientRole == "cc",
                "Streaming reconciliation lost the metadata-only CC role or duplicated an already captured message.");
            stream.Write(StreamingCheckHandler.Frame("", closed: true));
            await WaitForStreamingAsync(() => handler.Streams.Count == 2);
            Expect(handler.Subscriptions == 1 && handler.Backend.SyncStates.Count == syncs + 1,
                "Normal stream renewal resubscribed or performed periodic Inbox synchronization.");
            handler.Streams.Last().Complete();
            await WaitForStreamingAsync(() => handler.Streams.Count >= 3 && handler.Subscriptions >= 2);
            Expect(handler.Backend.SyncStates.Count >= syncs + 2,
                "A dropped streaming connection did not resubscribe and reconcile its saved cursor.");
            await service.UnsubscribeAsync(actor, MailEventService.InboxEventName, JsonDocument.Parse("{}").RootElement,
                "https://8.8.8.8/events", CancellationToken.None);
            await WaitForStreamingAsync(() => handler.Unsubscriptions >= 2);
            Expect(handler.ValidSubscribeShape && handler.ValidAnchor,
                "Streaming Subscribe/GetStreamingEvents/Unsubscribe did not preserve the EWS schema and actor anchor.");
        }
        finally
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(8));
            await processor.StopAsync(deadline.Token);
        }
    }

    private static async Task WaitForStreamingAsync(Func<bool> predicate)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(12));
        while (!predicate()) await Task.Delay(30, deadline.Token);
    }
}

internal sealed class StreamingCheckClientFactory(StreamingCheckHandler handler) : IHttpClientFactory
{
    public HttpClient CreateClient(string name) => name == "EwsStreaming"
        ? new HttpClient(handler, disposeHandler: false) { Timeout = Timeout.InfiniteTimeSpan }
        : throw new InvalidOperationException("Unexpected streaming client name.");
}

internal sealed class StreamingCheckHandler : HttpMessageHandler
{
    private static readonly XNamespace Soap = "http://schemas.xmlsoap.org/soap/envelope/";
    private static readonly XNamespace M = "http://schemas.microsoft.com/exchange/services/2006/messages";
    private static readonly XNamespace T = "http://schemas.microsoft.com/exchange/services/2006/types";
    public MailEventProcessorEwsHandler Backend { get; } = new();
    private readonly HttpMessageInvoker backend;
    private int subscriptions;
    private int unsubscriptions;
    public int Subscriptions => Volatile.Read(ref subscriptions);
    public int Unsubscriptions => Volatile.Read(ref unsubscriptions);
    public ConcurrentQueue<StreamingChunkStream> Streams { get; } = new();
    public bool ValidSubscribeShape { get; private set; }
    public bool ValidAnchor { get; private set; } = true;

    public StreamingCheckHandler() => backend = new HttpMessageInvoker(Backend);

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var xml = XDocument.Parse(await request.Content!.ReadAsStringAsync(cancellationToken));
        var operation = xml.Root!.Element(Soap + "Body")!.Elements().Single();
        ValidAnchor &= request.Headers.GetValues("X-AnchorMailbox").Single() == "alice@example.test"
            && xml.Descendants(T + "ConnectingSID").Single().Element(T + "PrimarySmtpAddress")!.Value == "alice@example.test";
        var name = operation.Name.LocalName;
        if (name == "GetStreamingEvents")
        {
            if (operation.Element(M + "SubscriptionIds")?.Element(T + "SubscriptionId")?.Value != "stream-test"
                || operation.Element(M + "ConnectionTimeout")?.Value != "1")
                throw new InvalidOperationException("Invalid GetStreamingEvents schema.");
            var source = new StreamingChunkStream();
            Streams.Enqueue(source);
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StreamContent(source) };
        }
        if (name == "Subscribe")
        {
            var subscription = operation.Element(M + "StreamingSubscriptionRequest");
            ValidSubscribeShape = subscription?.Element(T + "FolderIds")?.Element(T + "DistinguishedFolderId")?.Attribute("Id")?.Value == "inbox"
                && subscription?.Element(T + "EventTypes")?.Elements(T + "EventType").Select(element => element.Value)
                    .SequenceEqual(["NewMailEvent", "CreatedEvent", "MovedEvent"]) == true;
            Interlocked.Increment(ref subscriptions);
        }
        else if (name == "Unsubscribe")
        {
            if (operation.Element(M + "SubscriptionId")?.Value != "stream-test")
                throw new InvalidOperationException("Invalid Unsubscribe schema.");
            Interlocked.Increment(ref unsubscriptions);
        }
        else return await backend.SendAsync(request, cancellationToken);
        var result = name == "Subscribe" ? "<m:SubscriptionId>stream-test</m:SubscriptionId>" : "";
        return new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent($"<s:Envelope xmlns:s='{Soap}' xmlns:m='{M}' xmlns:t='{T}'><s:Body><m:{name}Response><m:ResponseMessages><m:{name}ResponseMessage ResponseClass='Success'><m:ResponseCode>NoError</m:ResponseCode>{result}</m:{name}ResponseMessage></m:ResponseMessages></m:{name}Response></s:Body></s:Envelope>", Encoding.UTF8, "text/xml")
        };
    }

    internal static string Frame(string events, bool closed = false) =>
        $"<?xml version='1.0' encoding='utf-8'?><s:Envelope xmlns:s='{Soap}' xmlns:m='{M}' xmlns:t='{T}'><!-- stream --><s:Body><m:GetStreamingEventsResponse><m:ResponseMessages><m:GetStreamingEventsResponseMessage ResponseClass='Success'><m:ResponseCode>NoError</m:ResponseCode><m:Notifications><m:Notification><t:SubscriptionId>stream-test</t:SubscriptionId>{events}</m:Notification></m:Notifications><m:ConnectionStatus>{(closed ? "Closed" : "OK")}</m:ConnectionStatus></m:GetStreamingEventsResponseMessage></m:ResponseMessages></m:GetStreamingEventsResponse></s:Body></s:Envelope>";

    protected override void Dispose(bool disposing)
    {
        if (disposing) backend.Dispose();
        base.Dispose(disposing);
    }
}

internal sealed class StreamingChunkStream : Stream
{
    private readonly Channel<byte[]> chunks = Channel.CreateUnbounded<byte[]>();
    private byte[]? current;
    private int offset;
    public void Write(string value) => chunks.Writer.TryWrite(Encoding.UTF8.GetBytes(value));
    public void Complete() => chunks.Writer.TryComplete();
    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        while (current is null || offset == current.Length)
        {
            if (!await chunks.Reader.WaitToReadAsync(cancellationToken)) return 0;
            if (!chunks.Reader.TryRead(out current)) continue;
            offset = 0;
        }
        var count = Math.Min(Math.Min(buffer.Length, 7), current.Length - offset);
        current.AsMemory(offset, count).CopyTo(buffer);
        offset += count;
        return count;
    }
    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
    public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    public override void Flush() => throw new NotSupportedException();
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}
