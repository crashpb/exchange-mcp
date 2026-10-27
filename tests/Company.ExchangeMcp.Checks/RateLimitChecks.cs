using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Company.ExchangeMcp;
using Company.ExchangeMcp.Security;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

internal sealed partial class Checks
{
    private async Task RateLimitChecksAsync()
    {
        await OperationBudgetWireChecksAsync();
        await EventBudgetWireChecksAsync();
        await AuthenticationBurstWireChecksAsync();
        await PayloadAdmissionChecksAsync();
        await WorkCapacityWireChecksAsync();
        await WorkQueueBoundChecksAsync();
        await UserWorkQueueBoundChecksAsync();
        await StreamCapacityWireChecksAsync();
        await MultiClientAdmissionWireChecksAsync();
    }

    private static async Task UserWorkQueueBoundChecksAsync()
    {
        using var admission = new RequestAdmission(Microsoft.Extensions.Options.Options.Create(new ServiceOptions
        { ConcurrentRequests = 8, ConcurrentRequestsPerUser = 2 }));
        var user = new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub", "queued-user")], "test"));
        using var first = await admission.AcquireOperationAsync(user, CancellationToken.None);
        using var second = await admission.AcquireOperationAsync(user, CancellationToken.None);
        using var cancellation = new CancellationTokenSource();
        var queued = Enumerable.Range(0, 8).Select(_ => admission.AcquireOperationAsync(user, cancellation.Token).AsTask()).ToArray();
        using var overflow = await admission.AcquireOperationAsync(user, CancellationToken.None);
        Expect(!overflow.IsAcquired && overflow.Reason == "user_work_capacity" && queued.All(task => !task.IsCompleted),
            "The per-user work queue did not hold exactly eight requests behind two active operations.");
        cancellation.Cancel();
        foreach (var task in queued) await AssertThrowsAsync<OperationCanceledException>(async () => await task);
        first.Dispose();
        using var recovered = await admission.AcquireOperationAsync(user, CancellationToken.None);
        Expect(recovered.IsAcquired, "Canceled per-user queue entries retained their admission slots.");
        Console.WriteLine("ADMISSION user queue: active=2; waiting=8; overflowRejected=1; canceledWaiting=8; capacityRecovered=true");
    }

    private async Task AuthenticationBurstWireChecksAsync()
    {
        var introspection = new BlockingEnrollmentIntrospectionHandler();
        await using var host = await StartHostAsync(new AdmissionEwsHandler(), false, false,
            configure: builder => builder.Services.AddHttpClient<KeycloakTokenStatus>()
                .ConfigurePrimaryHttpMessageHandler(() => introspection));
        var token = Token("user-a", "mail.read");
        var firstFour = Enumerable.Range(0, 4).Select(_ => AdmissionRpcAsync(host.Client, token, "tools/list", new { })).ToArray();
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        while (introspection.Calls < 4) await Task.Delay(10, deadline.Token);
        var nextTwo = Enumerable.Range(0, 2).Select(_ => AdmissionRpcAsync(host.Client, token, "tools/list", new { })).ToArray();
        var other = AdmissionRpcAsync(host.Client, Token("user-b", "mail.read"), "tools/list", new { });
        try
        {
            while (introspection.Calls < 5) await Task.Delay(10, deadline.Token);
            Expect(introspection.Calls == 5 && nextTwo.All(task => !task.IsCompleted),
                "The six-client authentication burst exceeded per-user capacity or blocked another user's authentication.");
        }
        finally { introspection.Release(); }
        var results = await Task.WhenAll(firstFour.Concat(nextTwo).Append(other)).WaitAsync(TimeSpan.FromSeconds(5));
        Expect(results.All(result => result.Status == HttpStatusCode.OK) && introspection.Calls == 7,
            "The bounded authentication queue dropped a short six-client catalog burst or reused token introspection.");
        Console.WriteLine("ADMISSION auth: sameUser=6; activeSameUser=4; queuedSameUser=2; otherUserAdmitted=true; introspectionCalls=7");
    }

    private static void RateSettings(WebApplicationBuilder builder, int operations = 60, int work = 8,
        int perUser = 2, int transportRate = 600) => builder.Configuration.AddInMemoryCollection(
        new Dictionary<string, string?>
        {
            ["Service:RequestsPerMinute"] = operations.ToString(),
            ["Service:ConcurrentRequests"] = work.ToString(),
            ["Service:ConcurrentRequestsPerUser"] = perUser.ToString(),
            ["Service:TransportRequestsPerMinute"] = transportRate.ToString(),
            ["Service:ConcurrentTransports"] = "64"
        });

    private async Task OperationBudgetWireChecksAsync()
    {
        var exchange = new AdmissionEwsHandler();
        await using var host = await StartHostAsync(exchange, false, false,
            configure: builder => RateSettings(builder, operations: 2));
        var first = Token("user-a", "mail.read", sessionId: "quota-first");
        var second = Token("user-a", "mail.read", azp: "chatgpt-alt", sessionId: "quota-second");
        foreach (var path in new[] { "/", "/mcp", "/mcp/" })
        {
            for (var repeat = 0; repeat < 3; repeat++)
            {
                var initialize = await AdmissionRpcAsync(host.Client, first, "initialize",
                    JsonSerializer.SerializeToNode(InitializeBody())!["params"]!, path: path);
                Expect(initialize.Status == HttpStatusCode.OK, $"Initialize spent work budget on {path}.");
                var notification = await AdmissionRpcAsync(host.Client, first, "notifications/initialized", new { },
                    path: path, notification: true);
                Expect((int)notification.Status is 200 or 202, "Initialized notification spent work budget.");
                foreach (var method in new[] { "ping", "tools/list", "resources/list", "resources/templates/list" })
                {
                    var catalog = await AdmissionRpcAsync(host.Client, first, method, new { }, path: path);
                    Expect(catalog.Status == HttpStatusCode.OK, $"{method} spent work budget.");
                }
            }
            foreach (var method in new[] { HttpMethod.Get, HttpMethod.Delete })
            {
                var protocol = await AdmissionHttpAsync(host.Client, first, method, path);
                Expect(protocol.Status != HttpStatusCode.TooManyRequests, $"{method} spent work budget.");
            }
        }
        var before = exchange.Dispatches;
        foreach (var token in new[] { first, second })
        {
            var accepted = await AdmissionSearchAsync(host.Client, token);
            Expect(accepted.Status == HttpStatusCode.OK && !IsToolError(accepted.Body),
                "Cheap protocol traffic exhausted the mailbox operation quota.");
        }
        var rejected = await AdmissionSearchAsync(host.Client,
            Token("user-a", "mail.read", sessionId: "quota-third"));
        AssertOperationRejection(rejected, "operation_rate");
        var rejectedTarget = await AdmissionRpcAsync(host.Client, first, "tools/call", new
        {
            name = "mail_search",
            arguments = new { folder = "inbox", mailboxHandle = "invalid-target-sentinel" }
        });
        AssertOperationRejection(rejectedTarget, "operation_rate");
        Expect(exchange.Dispatches == before + 2, "An operation quota rejection dispatched EWS.");
        var isolated = await AdmissionSearchAsync(host.Client, Token("user-b", "mail.read"));
        Expect(!IsToolError(isolated.Body), "One user's operation quota exhausted another user's budget.");
        var catalogAfter = await AdmissionRpcAsync(host.Client, first, "tools/list", new { });
        Expect(catalogAfter.Status == HttpStatusCode.OK, "An exhausted work quota blocked catalog recovery.");
        var audit = await AdmissionAuditAsync(host);
        Expect(audit.Contains(rejected.Id, StringComparison.Ordinal)
            && audit.Contains("operation_rate", StringComparison.Ordinal), "The rejection lacked correlated audit evidence.");

        await using var transportHost = await StartHostAsync(new AdmissionEwsHandler(), false, false,
            configure: builder => RateSettings(builder, transportRate: 2));
        var transportToken = Token("user-a", "mail.read");
        await AdmissionRpcAsync(transportHost.Client, transportToken, "ping", new { });
        await AdmissionRpcAsync(transportHost.Client, transportToken, "ping", new { });
        var transportRejected = await AdmissionRpcAsync(transportHost.Client, transportToken, "ping", new { });
        AssertHttpRejection(transportRejected, "transport_rate");
    }

    private async Task EventBudgetWireChecksAsync()
    {
        await using var host = await StartHostAsync(new MailEventProcessorEwsHandler(), false, false,
            configure: builder =>
            {
                RateSettings(builder, operations: 2);
                builder.Services.AddSingleton<IMailEventWebhook>(new RecordingMailEventWebhook());
            });
        var token = Token("user-a", "mail.read");
        for (var i = 0; i < 4; i++)
        {
            var listed = await AdmissionRpcAsync(host.Client, token, "events/list", new { }, modern: true);
            Expect(listed.Status == HttpStatusCode.OK, "Raw event discovery spent work budget.");
        }
        var subscribed = await AdmissionRpcAsync(host.Client, token, "events/subscribe", new
        {
            name = MailEventService.InboxEventName,
            arguments = new { },
            delivery = new { mode = "webhook", url = "https://8.8.8.8/events", secret = "whsec_" + Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)) }
        }, modern: true);
        using var subscribedJson = ParseJson(subscribed.Body);
        var id = subscribedJson.RootElement.GetProperty("result").GetProperty("id").GetString();
        var unsubscribed = await AdmissionRpcAsync(host.Client, token, "events/unsubscribe", new
        {
            name = MailEventService.InboxEventName,
            arguments = new { },
            delivery = new { mode = "webhook", url = "https://8.8.8.8/events" }
        }, modern: true);
        using var unsubscribedJson = ParseJson(unsubscribed.Body);
        Expect(unsubscribed.Status == HttpStatusCode.OK && unsubscribedJson.RootElement.TryGetProperty("result", out _),
            "Raw unsubscribe failed before its work quota could be checked.");
        var rejected = await AdmissionSearchAsync(host.Client, token);
        AssertOperationRejection(rejected, "operation_rate");
        var rawRejected = await AdmissionRpcAsync(host.Client, token, "events/unsubscribe", new { id }, modern: true);
        using var rejectedJson = ParseJson(rawRejected.Body);
        var data = rejectedJson.RootElement.GetProperty("error").GetProperty("data");
        Expect(data.GetProperty("reason").GetString() == "operation_rate"
            && data.GetProperty("dispatchStatus").GetString() == "not_dispatched"
            && data.GetProperty("retrySeconds").GetInt32() > 0,
            "Raw event mutation rejection omitted retry and dispatch evidence.");
    }

    private static async Task WorkQueueBoundChecksAsync()
    {
        using var admission = new RequestAdmission(Microsoft.Extensions.Options.Options.Create(new ServiceOptions
        { ConcurrentRequests = 1, ConcurrentRequestsPerUser = 1 }));
        static ClaimsPrincipal User(int index) => new(new ClaimsIdentity([new Claim("sub", $"queue-{index}")], "test"));
        using var active = await admission.AcquireOperationAsync(User(0), CancellationToken.None);
        using var cancellation = new CancellationTokenSource();
        var queued = Enumerable.Range(1, 64).Select(index =>
            admission.AcquireOperationAsync(User(index), cancellation.Token).AsTask()).ToArray();
        using var overflow = await admission.AcquireOperationAsync(User(65), CancellationToken.None);
        Expect(!overflow.IsAcquired && overflow.Reason == "global_work_capacity" && queued.All(task => !task.IsCompleted),
            "The global work queue was not bounded at 64 waiting operations.");
        cancellation.Cancel();
        foreach (var task in queued) await AssertThrowsAsync<OperationCanceledException>(async () => await task);
        active.Dispose();
        using var after = await admission.AcquireOperationAsync(User(1), CancellationToken.None);
        Expect(after.IsAcquired, "Canceled queue entries retained global or per-user leases.");
        var firstWaiting = admission.AcquireOperationAsync(User(2), CancellationToken.None).AsTask();
        var secondWaiting = admission.AcquireOperationAsync(User(3), CancellationToken.None).AsTask();
        after.Dispose();
        using var firstGranted = await firstWaiting.WaitAsync(TimeSpan.FromSeconds(1));
        Expect(firstGranted.IsAcquired && !secondWaiting.IsCompleted, "Global work admission did not preserve FIFO queue order.");
        firstGranted.Dispose();
        using var secondGranted = await secondWaiting.WaitAsync(TimeSpan.FromSeconds(1));
        Expect(secondGranted.IsAcquired, "A later queued user starved after earlier work completed.");
        Console.WriteLine("ADMISSION queue: active=1; waiting=64; overflowRejected=1; canceledWaiting=64; capacityRecovered=true");
    }

    private async Task WorkCapacityWireChecksAsync()
    {
        var exchange = new AdmissionEwsHandler { Block = true };
        await using var host = await StartHostAsync(exchange, false, false,
            configure: builder =>
            {
                RateSettings(builder, work: 3);
                builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["Service:Mailboxes:user-c"] = "carol@example.test"
                });
            });
        using var cancel = new CancellationTokenSource();
        var a = Token("user-a", "mail.read");
        var b = Token("user-b", "mail.read");
        var held = new List<Task<AdmissionResponse>>();
        try
        {
            held.Add(AdmissionSearchAsync(host.Client, a, cancel.Token));
            held.Add(AdmissionSearchAsync(host.Client, a));
            await exchange.WaitForDispatchesAsync(2);
            using (var userQueueCancel = new CancellationTokenSource())
            {
                var sameUser = AdmissionSearchAsync(host.Client,
                    Token("user-a", "mail.read", azp: "chatgpt-alt"), userQueueCancel.Token);
                await Task.Delay(100);
                Expect(!sameUser.IsCompleted && exchange.Dispatches == 2,
                    "A third client exceeded the per-user work ceiling instead of joining its bounded queue.");
                held.Add(AdmissionSearchAsync(host.Client, b));
                await exchange.WaitForDispatchesAsync(3);
                userQueueCancel.Cancel();
                await AssertThrowsAsync<OperationCanceledException>(async () => await sameUser);
            }
            Expect(exchange.Maximum == 3, "Per-user capacity failed to leave another user work capacity.");
            var userQueueTimeout = await AdmissionSearchAsync(host.Client, a);
            AssertOperationRejection(userQueueTimeout, "user_work_queue_timeout");
            Expect(exchange.Dispatches == 3, "A request that timed out in the per-user work queue dispatched EWS.");
            using (var queuedCancel = new CancellationTokenSource())
            {
                var queued = AdmissionSearchAsync(host.Client, Token("user-c", "mail.read"), queuedCancel.Token);
                await Task.Delay(100);
                Expect(!queued.IsCompleted && exchange.Dispatches == 3, "A globally saturated request bypassed the work queue.");
                queuedCancel.Cancel();
                await AssertThrowsAsync<OperationCanceledException>(async () => await queued);
            }
            var watch = Stopwatch.StartNew();
            var queueTimeout = await AdmissionSearchAsync(host.Client, Token("user-c", "mail.read"));
            AssertOperationRejection(queueTimeout, "work_queue_timeout");
            Expect(watch.Elapsed < TimeSpan.FromSeconds(5) && exchange.Dispatches == 3,
                "A saturated request waited without the bounded admission deadline or dispatched EWS.");
            cancel.Cancel();
            await AssertThrowsAsync<OperationCanceledException>(async () => await held[0]);
            await exchange.WaitForActiveAsync(2);
            var replacement = AdmissionSearchAsync(host.Client, Token("user-c", "mail.read"));
            held.Add(replacement);
            await exchange.WaitForDispatchesAsync(4);
            Expect(exchange.Maximum == 3, "Cancellation leaked capacity or exceeded the global work ceiling.");
        }
        finally { exchange.Release(); }
        foreach (var task in held.Skip(1))
        {
            var result = await task.WaitAsync(TimeSpan.FromSeconds(5));
            Expect(!IsToolError(result.Body), "Admitted work failed after the test gate was released.");
        }
        exchange.FailNext = true;
        var failed = await AdmissionSearchAsync(host.Client, a);
        Expect(IsToolError(failed.Body), "The synthetic EWS failure was not exercised.");
        var recovered = await AdmissionSearchAsync(host.Client, a);
        Expect(!IsToolError(recovered.Body) && exchange.Active == 0, "A failed operation leaked its admission lease.");
        Console.WriteLine($"ADMISSION capacity: maximumEws={exchange.Maximum}/3; perUser=2; queueWaitMs={2000}; canceledQueued=1; canceledExecuting=1; failureCleanup=passed");
    }

    private async Task StreamCapacityWireChecksAsync()
    {
        var exchange = new AdmissionEwsHandler();
        await using var host = await StartHostAsync(exchange, false, false, classicStateful: true,
            configure: builder => RateSettings(builder, work: 1, perUser: 1));
        var token = Token("user-a", "mail.read");
        var streams = new List<HttpResponseMessage>();
        var requests = new List<HttpRequestMessage>();
        string? lastSession = null;
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        try
        {
            foreach (var path in new[] { "/mcp", "/mcp/", "/", "/mcp/" })
            {
                var initialize = await AdmissionRpcAsync(host.Client, token, "initialize",
                    new { protocolVersion = ClassicProtocolVersion, capabilities = new { }, clientInfo = new { name = "admission", version = "1" } },
                    path: path, protocolVersion: ClassicProtocolVersion);
                Expect(!string.IsNullOrWhiteSpace(initialize.Session), "Stream fixture did not establish a stateful session.");
                lastSession = initialize.Session;
                await AdmissionRpcAsync(host.Client, token, "notifications/initialized", new { }, path: path,
                    notification: true, protocolVersion: ClassicProtocolVersion, session: lastSession);
                var request = AdmissionRequest(token, HttpMethod.Get, path, lastSession, ClassicProtocolVersion);
                requests.Add(request);
                var response = await host.Client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellation.Token);
                streams.Add(response);
                Expect(response.StatusCode == HttpStatusCode.OK, $"The classic GET fixture did not stay open on {path}.");
            }
            var overflow = await AdmissionHttpAsync(host.Client, token, HttpMethod.Get, "/mcp/", lastSession,
                ClassicProtocolVersion, cancellation.Token);
            AssertHttpRejection(overflow, "user_stream_capacity");
            var work = await AdmissionSearchAsync(host.Client, token, session: lastSession,
                protocolVersion: ClassicProtocolVersion);
            Expect(!IsToolError(work.Body), "Long GET streams occupied mailbox operation capacity.");
        }
        finally
        {
            cancellation.Cancel();
            foreach (var stream in streams) stream.Dispose();
            foreach (var request in requests) request.Dispose();
        }
        using var afterCancel = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var fresh = await AdmissionRpcAsync(host.Client, token, "initialize",
            new { protocolVersion = ClassicProtocolVersion, capabilities = new { }, clientInfo = new { name = "admission", version = "1" } },
            path: "/mcp/", protocolVersion: ClassicProtocolVersion);
        await AdmissionRpcAsync(host.Client, token, "notifications/initialized", new { }, path: "/mcp/",
            notification: true, protocolVersion: ClassicProtocolVersion, session: fresh.Session);
        using var reopenedRequest = AdmissionRequest(token, HttpMethod.Get, "/mcp/", fresh.Session, ClassicProtocolVersion);
        using var reopened = await host.Client.SendAsync(reopenedRequest, HttpCompletionOption.ResponseHeadersRead, afterCancel.Token);
        Expect(reopened.StatusCode == HttpStatusCode.OK, "Canceled streams leaked their admission slots.");
        afterCancel.Cancel();
    }

    private async Task MultiClientAdmissionWireChecksAsync()
    {
        const int subjects = 24;
        const int clientsPerSubject = 3;
        var exchange = new AdmissionEwsHandler { DelayMilliseconds = 15 };
        await using var host = await StartHostAsync(exchange, false, false, configure: builder =>
        {
            RateSettings(builder);
            builder.Configuration.AddInMemoryCollection(Enumerable.Range(0, subjects).ToDictionary(
                i => $"Service:Mailboxes:load-{i}", i => (string?)$"load{i}@example.test"));
        });
        var latencies = new ConcurrentBag<double>();
        var protocolCount = 0;
        var successfulWork = 0;
        var rejectedWork = 0;
        await Task.WhenAll(Enumerable.Range(0, subjects).SelectMany(subject => Enumerable.Range(0, clientsPerSubject)
            .Select(async client =>
            {
                var token = Token($"load-{subject}", "mail.read", azp: client % 2 == 0 ? "chatgpt-test" : "chatgpt-alt",
                    sessionId: $"synthetic-{client}");
                var path = client == 0 ? "/" : client == 1 ? "/mcp" : "/mcp/";
                foreach (var method in new[] { "initialize", "notifications/initialized", "tools/list", "resources/list", "events/list" })
                {
                    object parameters = method == "initialize"
                        ? JsonSerializer.SerializeToNode(InitializeBody())!["params"]! : new { };
                    var result = await AdmissionRpcAsync(host.Client, token, method, parameters, path: path,
                        notification: method.StartsWith("notifications/", StringComparison.Ordinal), modern: method == "events/list");
                    Expect((int)result.Status is 200 or 202, $"Synthetic protocol request failed: {method}, HTTP {(int)result.Status}.");
                    Interlocked.Increment(ref protocolCount);
                }
                var get = await AdmissionHttpAsync(host.Client, token, HttpMethod.Get, path);
                Expect(get.Status != HttpStatusCode.TooManyRequests, "Synthetic stateless GET hit work admission.");
                Interlocked.Increment(ref protocolCount);
                var watch = Stopwatch.StartNew();
                var work = await AdmissionSearchAsync(host.Client, token, path: path);
                latencies.Add(watch.Elapsed.TotalMilliseconds);
                if (IsToolError(work.Body))
                {
                    AssertOperationRejection(work, "user_work_capacity", "global_work_capacity", "work_queue_timeout", "user_work_queue_timeout");
                    Interlocked.Increment(ref rejectedWork);
                }
                else Interlocked.Increment(ref successfulWork);
            }))).WaitAsync(TimeSpan.FromSeconds(30));
        var ordered = latencies.Order().ToArray();
        Expect(successfulWork == subjects * clientsPerSubject && rejectedWork == 0
            && exchange.Dispatches == successfulWork && exchange.Maximum <= 8 && exchange.Active == 0,
            "Synthetic multi-client outcomes disagreed with actual EWS dispatch or the capacity ceiling.");
        Console.WriteLine($"ADMISSION synthetic: subjects={subjects}; clientsPerSubject={clientsPerSubject}; protocol={protocolCount}; workAccepted={successfulWork}; workRejected={rejectedWork}; ewsDispatches={exchange.Dispatches}; maximumEws={exchange.Maximum}/8; p50Ms={ordered[ordered.Length / 2]:F1}; p95Ms={ordered[(int)(ordered.Length * .95)]:F1}; activeAtEnd={exchange.Active}");
    }

    private static async Task<string> AdmissionAuditAsync(TestHostContext host)
    {
        var settings = host.App.Services.GetRequiredService<Microsoft.Extensions.Options.IOptions<ServiceOptions>>().Value;
        return await ReadSharedAuditAsync(settings.AuditPath);
    }

    private static void AssertOperationRejection(AdmissionResponse response, params string[] reasons)
    {
        Expect(response.Status == HttpStatusCode.OK && IsToolError(response.Body), "Work admission rejection was not an MCP tool error.");
        var data = ToolStructuredData(response.Body);
        Expect(reasons.Contains(data.GetProperty("reason").GetString(), StringComparer.Ordinal)
            && data.GetProperty("retrySeconds").GetInt32() > 0
            && data.GetProperty("dispatchStatus").GetString() == "not_dispatched"
            && IsTrackingId(response.Id)
            && data.GetProperty("tracking").GetProperty("id").GetString() == response.Id,
            "Work rejection omitted the reason, positive retry delay, no-dispatch status or tracking correlation.");
    }

    private static void AssertHttpRejection(AdmissionResponse response, string reason)
    {
        using var json = JsonDocument.Parse(response.Body);
        var data = json.RootElement;
        Expect(response.Status == HttpStatusCode.TooManyRequests && response.RetrySeconds > 0
            && data.GetProperty("reason").GetString() == reason
            && data.GetProperty("tracking").GetProperty("id").GetString() == response.Id && IsTrackingId(response.Id),
            $"HTTP admission rejection omitted Retry-After, {reason} or tracking correlation.");
    }

    private static Task<AdmissionResponse> AdmissionSearchAsync(HttpClient client, string token,
        CancellationToken cancellationToken = default, string path = "/mcp", string? session = null,
        string? protocolVersion = null) =>
        AdmissionRpcAsync(client, token, "tools/call", new { name = "mail_search", arguments = new { folder = "inbox", limit = 1 } },
            path: path, cancellationToken: cancellationToken, session: session, protocolVersion: protocolVersion);

    private static async Task<AdmissionResponse> AdmissionRpcAsync(HttpClient client, string token, string method,
        object parameters, string path = "/mcp", bool notification = false, bool modern = false,
        string? protocolVersion = null, CancellationToken cancellationToken = default, string? session = null)
    {
        var version = protocolVersion ?? (modern ? JulyProtocolVersion : ProtocolVersion);
        var parameterNode = JsonSerializer.SerializeToNode(parameters)!.AsObject();
        if (modern) parameterNode["_meta"] = new JsonObject
        {
            ["io.modelcontextprotocol/protocolVersion"] = version,
            ["io.modelcontextprotocol/clientInfo"] = new JsonObject { ["name"] = "admission-checks", ["version"] = "1" },
            ["io.modelcontextprotocol/clientCapabilities"] = new JsonObject()
        };
        var body = new JsonObject { ["jsonrpc"] = "2.0", ["method"] = method, ["params"] = parameterNode };
        if (!notification) body["id"] = Random.Shared.Next(10, 1000000);
        using var request = AdmissionRequest(token, HttpMethod.Post, path, session, version);
        request.Content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json");
        if (modern) request.Headers.TryAddWithoutValidation("Mcp-Method", method);
        using var response = await client.SendAsync(request, cancellationToken);
        return await AdmissionResponseAsync(response, cancellationToken);
    }

    private static async Task<AdmissionResponse> AdmissionHttpAsync(HttpClient client, string token, HttpMethod method,
        string path, string? session = null, string protocolVersion = ProtocolVersion, CancellationToken cancellationToken = default)
    {
        using var request = AdmissionRequest(token, method, path, session, protocolVersion);
        using var response = await client.SendAsync(request, cancellationToken);
        return await AdmissionResponseAsync(response, cancellationToken);
    }

    private static HttpRequestMessage AdmissionRequest(string token, HttpMethod method, string path,
        string? session = null, string protocolVersion = ProtocolVersion)
    {
        var request = new HttpRequestMessage(method, path);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("text/event-stream"));
        request.Headers.TryAddWithoutValidation("MCP-Protocol-Version", protocolVersion);
        if (session is not null) request.Headers.TryAddWithoutValidation("Mcp-Session-Id", session);
        return request;
    }

    private static async Task<AdmissionResponse> AdmissionResponseAsync(HttpResponseMessage response, CancellationToken token) => new(
        response.StatusCode, await response.Content.ReadAsStringAsync(token),
        response.Headers.TryGetValues("X-Request-ID", out var ids) ? ids.Single() : "",
        response.Headers.RetryAfter?.Delta?.TotalSeconds ?? 0,
        response.Headers.TryGetValues("Mcp-Session-Id", out var sessions) ? sessions.Single() : null);

    private sealed record AdmissionResponse(HttpStatusCode Status, string Body, string Id, double RetrySeconds, string? Session);
}

internal sealed class AdmissionEwsHandler : HttpMessageHandler
{
    private readonly TaskCompletionSource release = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly HttpMessageInvoker inner = new(new RecordingEwsHandler());
    private readonly SemaphoreSlim recordingGate = new(1);
    private int active;
    private int maximum;
    private int dispatches;
    public bool Block { get; set; }
    public bool FailNext { get; set; }
    public int DelayMilliseconds { get; init; }
    public int Active => Volatile.Read(ref active);
    public int Maximum => Volatile.Read(ref maximum);
    public int Dispatches => Volatile.Read(ref dispatches);
    public void Release() { Block = false; release.TrySetResult(); }
    public Task WaitForDispatchesAsync(int count) => WaitUntilAsync(() => Dispatches >= count);
    public Task WaitForActiveAsync(int count) => WaitUntilAsync(() => Active == count);

    private static async Task WaitUntilAsync(Func<bool> predicate)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        while (!predicate()) await Task.Delay(10, deadline.Token);
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        Interlocked.Increment(ref dispatches);
        var count = Interlocked.Increment(ref active);
        int previous;
        do { previous = maximum; } while (count > previous && Interlocked.CompareExchange(ref maximum, count, previous) != previous);
        try
        {
            if (Block) await release.Task.WaitAsync(cancellationToken);
            if (DelayMilliseconds > 0) await Task.Delay(DelayMilliseconds, cancellationToken);
            if (FailNext) { FailNext = false; throw new HttpRequestException("Synthetic EWS failure."); }
            await recordingGate.WaitAsync(cancellationToken);
            try { return await inner.SendAsync(request, cancellationToken); }
            finally { recordingGate.Release(); }
        }
        finally { Interlocked.Decrement(ref active); }
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing) { inner.Dispose(); recordingGate.Dispose(); }
        base.Dispose(disposing);
    }
}
