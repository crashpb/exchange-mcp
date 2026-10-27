using System.Net;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using System.Text.Json.Nodes;
using Company.ExchangeMcp.Security;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

internal sealed partial class Checks
{
    private async Task PayloadAdmissionChecksAsync()
    {
        using (var admission = new RequestAdmission(Options.Create(new ServiceOptions())))
        {
            static ClaimsPrincipal User(int index) => new(new ClaimsIdentity([new Claim("sub", $"payload-{index}")], "test"));
            var held = new List<RequestAdmission.AdmissionLease>();
            try
            {
                for (var index = 0; index < 8; index++)
                    held.Add(await admission.AcquireTransportAsync(User(index / 2), false, true, CancellationToken.None));
                Expect(held.All(lease => lease.IsAcquired), "Eight payload slots were not available across four users.");
                using var userCancel = new CancellationTokenSource();
                var userWaiting = admission.AcquireTransportAsync(User(0), false, true, userCancel.Token).AsTask();
                using var globalCancel = new CancellationTokenSource();
                var globalWaiting = admission.AcquireTransportAsync(User(4), false, true, globalCancel.Token).AsTask();
                Expect(!userWaiting.IsCompleted && !globalWaiting.IsCompleted,
                    "Payload admission exceeded the per-user two or global eight ceiling.");
                using var small = await admission.AcquireTransportAsync(User(5), false, false, CancellationToken.None);
                Expect(small.IsAcquired, "Payload waiters occupied all normal transport capacity.");
                userCancel.Cancel();
                globalCancel.Cancel();
                await AssertThrowsAsync<OperationCanceledException>(async () => await userWaiting);
                await AssertThrowsAsync<OperationCanceledException>(async () => await globalWaiting);
                held[0].Dispose();
                using var recovered = await admission.AcquireTransportAsync(User(0), false, true, CancellationToken.None);
                Expect(recovered.IsAcquired, "Canceled payload waiters leaked a per-user or global slot.");
            }
            finally { foreach (var lease in held) lease.Dispose(); }
        }

        var gate = new PayloadReadGate();
        await using var host = await StartHostAsync(new AdmissionEwsHandler(), false, false, configure: builder =>
        {
            builder.Services.AddSingleton<IStartupFilter>(new PayloadReadStartupFilter(gate));
            builder.Configuration.AddInMemoryCollection(Enumerable.Range(0, 10).ToDictionary(
                index => $"Service:Mailboxes:payload-{index}", index => (string?)$"payload{index}@example.test"));
        });
        var requests = new List<Task<AdmissionResponse>>();
        try
        {
            for (var index = 0; index < 8; index++)
                requests.Add(PayloadPingAsync(host.Client, Token($"payload-{index}", "mail.read"),
                    knownLength: index % 2 == 0, bytes: index % 2 == 0 ? 65537 : 256));
            await gate.WaitForReadsAsync(8);
            foreach (var known in new[] { true, false })
            {
                using var cancellation = new CancellationTokenSource();
                var excess = PayloadPingAsync(host.Client, Token("payload-8", "mail.read"), known,
                    known ? 65537 : 256, cancellation.Token);
                await Task.Delay(100);
                Expect(!excess.IsCompleted && gate.Reads == 8,
                    "A ninth large or unknown-length request entered JSON body deserialization.");
                cancellation.Cancel();
                await AssertThrowsAsync<OperationCanceledException>(async () => await excess);
            }
            var boundary = await PayloadPingAsync(host.Client, Token("payload-9", "mail.read"), true, 65536)
                .WaitAsync(TimeSpan.FromSeconds(1));
            using var boundaryJson = ParseJson(boundary.Body);
            Expect(boundary.Status == HttpStatusCode.OK && gate.Reads == 8
                && boundaryJson.RootElement.TryGetProperty("result", out _),
                "Known-size protocol traffic at the 64 KiB boundary waited behind payload readers.");
            var timedOut = await PayloadPingAsync(host.Client, Token("payload-8", "mail.read"), true, 65537);
            AssertHttpRejection(timedOut, "payload_queue_timeout");
            Expect(gate.Reads == 8, "A rejected payload was read before its admission decision.");
            Expect(gate.KnownReads == 4 && gate.UnknownReads == 4 && gate.Maximum == 8,
                "The wire fixture did not exercise both Content-Length and unknown/chunked framing.");
        }
        finally { gate.Release(); }
        var completed = await Task.WhenAll(requests).WaitAsync(TimeSpan.FromSeconds(5));
        Expect(completed.All(response =>
        {
            using var json = ParseJson(response.Body);
            return response.Status == HttpStatusCode.OK && json.RootElement.TryGetProperty("result", out _);
        }),
            "Admitted payload bodies were rejected or truncated instead of completing normally.");
        var after = await PayloadPingAsync(host.Client, Token("payload-8", "mail.read"), false, 256);
        Expect(after.Status == HttpStatusCode.OK && gate.Active == 0,
            "Payload reader capacity was not recovered after completion and cancellation.");
        Console.WriteLine("ADMISSION payload: perUser=2; global=8; maximumJsonReaders=8; knownLarge=4; unknownLength=4; canceledOverflow=2; timeoutRejected=1; known65536Bypass=true; recovered=true");
    }

    private static async Task<AdmissionResponse> PayloadPingAsync(HttpClient client, string token, bool knownLength,
        int bytes, CancellationToken cancellationToken = default)
    {
        var body = new JsonObject
        {
            ["jsonrpc"] = "2.0",
            ["id"] = 1,
            ["method"] = "ping",
            ["params"] = new JsonObject { ["padding"] = "" }
        };
        body["params"]!["padding"] = new string('x', bytes - body.ToJsonString().Length);
        var payload = Encoding.UTF8.GetBytes(body.ToJsonString());
        Expect(payload.Length == bytes, "Payload fixture body did not match its framing boundary.");
        using var request = AdmissionRequest(token, HttpMethod.Post, "/mcp");
        request.Content = new PayloadJsonContent(payload, knownLength);
        request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        if (!knownLength) request.Headers.TransferEncodingChunked = true;
        using var response = await client.SendAsync(request, cancellationToken);
        return await AdmissionResponseAsync(response, cancellationToken);
    }
}

internal sealed class PayloadJsonContent(byte[] bytes, bool knownLength) : HttpContent
{
    protected override bool TryComputeLength(out long length) { length = knownLength ? bytes.Length : 0; return knownLength; }
    protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context) => stream.WriteAsync(bytes).AsTask();
}

internal sealed class PayloadReadGate
{
    private readonly TaskCompletionSource release = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private int reads;
    private int known;
    private int unknown;
    private int active;
    private int maximum;
    public int Reads => Volatile.Read(ref reads);
    public int KnownReads => Volatile.Read(ref known);
    public int UnknownReads => Volatile.Read(ref unknown);
    public int Active => Volatile.Read(ref active);
    public int Maximum => Volatile.Read(ref maximum);
    public void Release() => release.TrySetResult();
    public async Task WaitForReadsAsync(int count)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        while (Reads < count) await Task.Delay(10, deadline.Token);
    }
    public async Task EnterAsync(bool knownLength, CancellationToken cancellationToken)
    {
        Interlocked.Increment(ref reads);
        if (knownLength) Interlocked.Increment(ref known); else Interlocked.Increment(ref unknown);
        var count = Interlocked.Increment(ref active);
        int previous;
        do { previous = maximum; } while (count > previous && Interlocked.CompareExchange(ref maximum, count, previous) != previous);
        await release.Task.WaitAsync(cancellationToken);
    }
    public void Exit() => Interlocked.Decrement(ref active);
}

internal sealed class PayloadReadStartupFilter(PayloadReadGate gate) : IStartupFilter
{
    public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app =>
    {
        app.Use(async (context, nextRequest) =>
        {
            if (HttpMethods.IsPost(context.Request.Method)
                && (context.Request.ContentLength is null || context.Request.ContentLength > 65536))
            {
                var body = new PayloadReadStream(context.Request.Body, gate, context.Request.ContentLength is not null);
                context.Request.Body = body;
                try { await nextRequest(context); }
                finally { if (body.Entered) gate.Exit(); }
            }
            else await nextRequest(context);
        });
        next(app);
    };
}

internal sealed class PayloadReadStream(Stream inner, PayloadReadGate gate, bool knownLength) : Stream
{
    private int entered;
    public bool Entered => Volatile.Read(ref entered) != 0;
    public override bool CanRead => inner.CanRead;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
    public override void Flush() => throw new NotSupportedException();
    public override int Read(byte[] buffer, int offset, int count) => throw new InvalidOperationException("Synchronous body reading was not expected.");
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();
    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        if (Interlocked.Exchange(ref entered, 1) == 0) await gate.EnterAsync(knownLength, cancellationToken);
        return await inner.ReadAsync(buffer, cancellationToken);
    }
}
