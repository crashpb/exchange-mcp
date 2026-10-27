using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json.Nodes;
using Company.ExchangeMcp;
using Company.ExchangeMcp.Exchange;
using Company.ExchangeMcp.Security;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;

internal sealed partial class Checks
{
    private async Task MailEventProtocolChecksAsync()
    {
        const string subject = "event-protocol-actor";
        const string mailbox = "alice@example.test";
        var serviceOptions = new ServiceOptions
        {
            Mailboxes = new Dictionary<string, string>(StringComparer.Ordinal) { [subject] = mailbox },
            AllowedClientIds = ["company-mail-checks"],
            AuditPath = Path.Combine(runDirectory, "event-protocol", "audit.jsonl")
        };
        var options = Options.Create(serviceOptions);
        var access = new MailboxAccess(options);
        using var store = new MailEventStateStore(options);
        var exchange = NewEwsClient(new DelegateHandler((_, _) => Task.FromResult(
            new HttpResponseMessage(HttpStatusCode.InternalServerError))));
        var events = new MailEventService(exchange, access, store, new ProtocolTestWebhook(), options);
        var serverOptions = new McpServerOptions();
        using var admission = new RequestAdmission(options);
        using var audit = new AuditLog(options);
        new MailEventProtocol(events, access, NullLogger<MailEventProtocol>.Instance,
            admission, audit, new HttpContextAccessor()).Configure(serverOptions);
#pragma warning disable MCPEXP002
        var handlers = serverOptions.RequestHandlers!.ToDictionary(handler => handler.Method, StringComparer.Ordinal);
#pragma warning restore MCPEXP002
        var user = EventUser(subject, DateTimeOffset.UtcNow.AddHours(1));

        var listed = await handlers["events/list"].Handler(EventRequest("events/list", new JsonObject(), user),
            CancellationToken.None);
        Expect(listed?["events"] is JsonArray definitions && definitions.Count == 1
            && definitions[0]?["name"]?.GetValue<string>() == MailEventService.InboxEventName
            && definitions[0]?["delivery"] is JsonArray delivery && delivery.Single()?.GetValue<string>() == "webhook",
            "events/list did not return the own-Inbox webhook schema.");
        var payloadSchema = listed!["events"]![0]!["payloadSchema"]!;
        Expect(payloadSchema["properties"]?["recipientRole"]?["enum"] is JsonArray roles
            && roles.Select(role => role!.GetValue<string>()).SequenceEqual(["to", "cc", "unknown"])
            && payloadSchema["required"] is JsonArray required
            && required.Any(field => field?.GetValue<string>() == "recipientRole"),
            "The email event schema omitted its bounded To/CC recipient role.");

        await AssertThrowsAsync<McpException>(async () =>
            await handlers["events/list"].Handler(EventRequest("events/list", new JsonObject(),
                new ClaimsPrincipal(new ClaimsIdentity())), CancellationToken.None));

        var legacyRequest = EventRequest("events/list", new JsonObject(), user, "2025-11-25");
        await AssertThrowsAsync<McpProtocolException>(async () =>
            await handlers["events/list"].Handler(legacyRequest, CancellationToken.None));

        var badDelivery = SubscribeRequest(user, new JsonObject
        {
            ["name"] = MailEventService.InboxEventName,
            ["arguments"] = new JsonObject(),
            ["delivery"] = new JsonObject { ["mode"] = "streamable-http", ["url"] = "https://8.8.8.8/events", ["secret"] = "whsec_test" }
        });
        await AssertThrowsAsync<McpProtocolException>(async () =>
            await handlers["events/subscribe"].Handler(badDelivery, CancellationToken.None));

        var extraArgument = SubscribeRequest(user, new JsonObject
        {
            ["name"] = MailEventService.InboxEventName,
            ["arguments"] = new JsonObject { ["folder"] = "inbox" },
            ["delivery"] = new JsonObject { ["mode"] = "webhook", ["url"] = "https://8.8.8.8/events", ["secret"] = "whsec_test" }
        });
        await AssertThrowsAsync<McpProtocolException>(async () =>
            await handlers["events/subscribe"].Handler(extraArgument, CancellationToken.None));

        var invalidCallback = SubscribeRequest(user, new JsonObject
        {
            ["name"] = MailEventService.InboxEventName,
            ["arguments"] = new JsonObject(),
            ["delivery"] = new JsonObject { ["mode"] = "webhook", ["url"] = "http://8.8.8.8/events", ["secret"] = "whsec_test" },
            ["cursor"] = null
        });
        var eventError = await CaptureExceptionAsync<McpProtocolException>(async () =>
            await handlers["events/subscribe"].Handler(invalidCallback, CancellationToken.None));
        Expect((int)eventError.ErrorCode == -32015,
            "Callback validation did not use the event error code.");

        var bounded = MailEventProtocol.ClampLifetimeToToken(user, null);
        Expect(bounded >= 60_000 && bounded < 24 * 60 * 60 * 1000,
            "The default event subscription lifetime was not capped at token expiry.");
        var explicitlyShorter = MailEventProtocol.ClampLifetimeToToken(user, 70_000);
        Expect(explicitlyShorter == 70_000,
            "A user-selected subscription lifetime shorter than token expiry was unexpectedly extended.");
        try
        {
            _ = MailEventProtocol.ClampLifetimeToToken(EventUser(subject, DateTimeOffset.UtcNow.AddSeconds(50)), null);
            throw new InvalidOperationException("A subscription outliving a near-expired token was accepted.");
        }
        catch (MailEventException exception)
        {
            Expect(exception.Reason == "token_lifetime_too_short", "A short token lifetime had the wrong failure reason.");
        }

        Expect(serverOptions.Filters.Message.OutgoingFilters.Count > 0,
            "The outgoing MCP filter for event discovery and callback error reasons was not registered.");

        var recordingWebhook = new RecordingMailEventWebhook();
        var traceLogger = new MailEventTraceLogger();
        await using var host = await StartHostAsync(new MailEventProcessorEwsHandler(), writesEnabled: false,
            sendEnabled: false, configure: builder =>
            {
                // This fixture deliberately holds three calls inside the event-store gate.
                builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
                { ["Service:ConcurrentRequestsPerUser"] = "3" });
                builder.Services.AddSingleton<IMailEventWebhook>(recordingWebhook);
                builder.Services.AddSingleton<ILogger<MailEventProtocol>>(traceLogger);
                builder.Services.PostConfigure<McpServerOptions>(configured =>
                {
                    configured.Filters.Message.IncomingFilters.Add(next => async (context, cancellationToken) =>
                    {
                        if (context.JsonRpcMessage is JsonRpcRequest { Method: "tools/call", Params: JsonObject parameters }
                            && parameters["name"]?.GetValue<string>() == "mail_event_status"
                            && parameters["statusRpcFailureFixture"] is JsonValue flag
                            && flag.TryGetValue<bool>(out var fail) && fail)
                            throw new McpProtocolException("Synthetic status RPC failure.", McpErrorCode.InternalError);
                        await next(context, cancellationToken);
                    });
                    configured.Filters.Message.OutgoingFilters.Insert(0, next => async (context, cancellationToken) =>
                    {
                        if (context.JsonRpcMessage is JsonRpcError error && error.Error.Message == "Synthetic status RPC failure.")
                            error.Error.Data = new JsonObject { ["reason"] = "synthetic_rpc_failure" };
                        await next(context, cancellationToken);
                    });
                });
            });
        var token = Token("user-a", MailboxAccess.Read);
        var discover = await ToolRequestAsync(host.Client, token, "server/discover", new { }, "2026-07-28");
        using (var discoverJson = ParseJson(discover.Body))
        {
            var result = discoverJson.RootElement.GetProperty("result");
            var capabilities = result.GetProperty("capabilities");
            Expect(result.GetProperty("resultType").GetString() == "complete"
                && result.TryGetProperty("supportedVersions", out _)
                && result.TryGetProperty("instructions", out _)
                && result.TryGetProperty("ttlMs", out _)
                && result.TryGetProperty("cacheScope", out _)
                && capabilities.TryGetProperty("events", out var eventCapability)
                && eventCapability.ValueKind == System.Text.Json.JsonValueKind.Object,
                "Modern server/discover did not preserve the native payload and add capabilities.events.");
        }

        var httpList = await ToolRequestAsync(host.Client, token, "events/list", new { }, "2026-07-28");
        using (var httpListJson = ParseJson(httpList.Body))
        {
            var eventDefinitions = httpListJson.RootElement.GetProperty("result").GetProperty("events");
            Expect(httpList.StatusCode == HttpStatusCode.OK && eventDefinitions.GetArrayLength() == 1
                && eventDefinitions[0].GetProperty("name").GetString() == MailEventService.InboxEventName,
                "The authenticated MCP HTTP events/list request did not return the own-Inbox event.");
        }

        var httpCallbackError = await ToolRequestAsync(host.Client, token, "events/subscribe", new
        {
            name = MailEventService.InboxEventName,
            arguments = new { },
            delivery = new { mode = "webhook", url = "http://8.8.8.8/events", secret = "whsec_test" }
        }, "2026-07-28");
        using (var errorJson = ParseJson(httpCallbackError.Body))
        {
            var error = errorJson.RootElement.GetProperty("error");
            Expect(error.GetProperty("code").GetInt32() == -32015
                && error.GetProperty("data").GetProperty("reason").GetString() == "invalid_url",
                "The real MCP HTTP boundary omitted the structured mail-event callback error reason.");
        }

        var callbackUrl = "https://8.8.8.8/events";
        var webhookSecret = "whsec_" + Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        object SubscriptionParameters() => new
        {
            name = MailEventService.InboxEventName,
            arguments = new { },
            delivery = new { mode = "webhook", url = callbackUrl, secret = webhookSecret }
        };

        var initialSubscribe = await ToolRequestAsync(host.Client, token, "events/subscribe",
            SubscriptionParameters(), "2026-07-28");
        using var initialJson = ParseJson(initialSubscribe.Body);
        var initial = initialJson.RootElement.GetProperty("result");
        var subscriptionId = initial.GetProperty("id").GetString();
        var initialExpiry = initial.GetProperty("refreshBefore").GetDateTimeOffset();
        Expect(initialSubscribe.StatusCode == HttpStatusCode.OK && subscriptionId?.StartsWith("sub_", StringComparison.Ordinal) == true
            && initialExpiry > DateTimeOffset.UtcNow && initial.GetProperty("cursor").ValueKind == System.Text.Json.JsonValueKind.Null
            && !initial.GetProperty("truncated").GetBoolean() && recordingWebhook.Deliveries.Count == 0,
            "A valid HTTP events/subscribe did not return the flat finite subscription result without notification replay.");

        var eventStore = host.App.Services.GetRequiredService<MailEventStateStore>();
        var actor = new MailboxIdentity("user-a", "alice@example.test", "chatgpt-test", null, "own", "alice@example.test");
        await eventStore.MarkMissedRangeAsync(MailEventStateStore.CursorKey(actor), "gap-state",
            DateTimeOffset.UtcNow.AddSeconds(1), CancellationToken.None);

        traceLogger.ThrowOnLog = true;
        var refreshedSubscribe = await ToolRequestAsync(host.Client, token, "events/subscribe",
            SubscriptionParameters(), "2026-07-28");
        traceLogger.ThrowOnLog = false;
        Expect(traceLogger.FailedWrites > 0, "The logging-failure regression did not exercise a throwing logger.");
        using (var refreshedJson = ParseJson(refreshedSubscribe.Body))
        {
            var refreshed = refreshedJson.RootElement.GetProperty("result");
            Expect(refreshedSubscribe.StatusCode == HttpStatusCode.OK
                && refreshed.GetProperty("id").GetString() == subscriptionId
                && refreshed.GetProperty("refreshBefore").GetDateTimeOffset() > DateTimeOffset.UtcNow
                && refreshed.GetProperty("cursor").ValueKind == System.Text.Json.JsonValueKind.Null
                && refreshed.GetProperty("truncated").GetBoolean(),
                "Refreshing the same HTTP event subscription changed its ID or hid the stored notification gap.");
        }

        var statusGate = (SemaphoreSlim)typeof(MailEventStateStore)
            .GetField("gate", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!
            .GetValue(eventStore)!;
        await statusGate.WaitAsync();
        Task<(HttpStatusCode StatusCode, string Body, string Id)>[] statusCalls;
        Task mutation;
        try
        {
            statusCalls = Enumerable.Range(0, 3).Select(_ => TrackedToolRequestAsync(host.Client, token,
                new { name = "mail_event_status", arguments = new { } })).ToArray();
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            while (traceLogger.Messages.Count(line => line.StartsWith("MCP event trace request", StringComparison.Ordinal)
                && line.Contains("name=mail_event_status", StringComparison.Ordinal)) < 3)
                await Task.Delay(20, deadline.Token);
            Expect(statusCalls.All(call => !call.IsCompleted),
                "Contended HTTP status calls did not wait asynchronously for the store.");
            await Task.WhenAll(
                ToolRequestAsync(host.Client, token, "server/discover", new { }, JulyProtocolVersion),
                ToolRequestAsync(host.Client, token, "tools/list", new { }, JulyProtocolVersion))
                .WaitAsync(TimeSpan.FromSeconds(5));

            using var cancelled = new CancellationTokenSource();
            var statusUser = new ClaimsPrincipal(new ClaimsIdentity([
                new Claim("sub", "user-a"), new Claim("scope", MailboxAccess.Read),
                new Claim("azp", "chatgpt-test")], "Bearer"));
            var cancelledStatus = new MailEventTools(host.App.Services.GetRequiredService<MailEventService>(),
                host.App.Services.GetRequiredService<MailboxAccess>()).Status(statusUser, cancelled.Token);
            Expect(!cancelledStatus.IsCompleted, "The cancellation test did not contend for the held store gate.");
            cancelled.Cancel();
            await AssertThrowsAsync<OperationCanceledException>(async () =>
                await cancelledStatus.WaitAsync(TimeSpan.FromSeconds(5)));
            mutation = eventStore.MarkPollAttemptAsync(MailEventStateStore.CursorKey(actor),
                DateTimeOffset.UtcNow, CancellationToken.None);
        }
        finally { statusGate.Release(); }
        var statuses = await Task.WhenAll(statusCalls).WaitAsync(TimeSpan.FromSeconds(5));
        await mutation.WaitAsync(TimeSpan.FromSeconds(5));
        Expect(statuses.Select(status => status.Id).Distinct(StringComparer.Ordinal).Count() == statuses.Length,
            "Overlapping status calls shared HTTP operation tracking IDs.");
        foreach (var status in statuses)
        {
            using var statusJson = ParseJson(status.Body);
            var result = statusJson.RootElement.GetProperty("result");
            using var payload = System.Text.Json.JsonDocument.Parse(result.GetProperty("content")[0].GetProperty("text").GetString()!);
            Expect(status.StatusCode == HttpStatusCode.OK && result.GetProperty("_meta").GetProperty("tracking")
                    .GetProperty("id").GetString() == status.Id
                && payload.RootElement.ValueKind == System.Text.Json.JsonValueKind.Array
                && payload.RootElement.GetArrayLength() == 1
                && payload.RootElement[0].GetProperty("id").GetString() == subscriptionId
                && payload.RootElement[0].GetProperty("truncated").GetBoolean(),
                "A populated status response lost its array contract, stored gap, or per-call tracking.");
        }
        foreach (var isolatedToken in new[]
        {
            Token("user-b", MailboxAccess.Read), Token("user-a", MailboxAccess.Read, azp: "chatgpt-alt"),
            Token("user-a", MailboxAccess.Read, sessionId: "other-status-session")
        })
        {
            var isolated = await TrackedToolRequestAsync(host.Client, isolatedToken,
                new { name = "mail_event_status", arguments = new { } });
            using var isolatedJson = ParseJson(isolated.Body);
            using var payload = System.Text.Json.JsonDocument.Parse(isolatedJson.RootElement.GetProperty("result")
                .GetProperty("content")[0].GetProperty("text").GetString()!);
            Expect(payload.RootElement.GetArrayLength() == 0,
                "HTTP status disclosed another subject, OAuth client, or session's subscription.");
        }
        var invalidStatus = await TrackedToolRequestAsync(host.Client, token,
            new { name = "mail_event_status", arguments = "private-status-argument-must-not-appear" });
        using (var invalidJson = ParseJson(invalidStatus.Body))
        {
            var error = invalidJson.RootElement.GetProperty("error");
            var tracking = error.GetProperty("data").GetProperty("tracking");
            Expect(error.GetProperty("code").GetInt32() == -32602
                && tracking.GetProperty("id").GetString() == invalidStatus.Id
                && tracking.GetProperty("outcome").GetString() == "failed"
                && tracking.GetProperty("stage").GetString() == "rpc_validation"
                && !invalidStatus.Body.Contains("private-status-argument-must-not-appear", StringComparison.Ordinal),
                "Malformed status arguments did not return sanitized InvalidParams with HTTP-correlated error tracking.");
        }
        foreach (var parameters in new object[]
        {
            new { name = "mail_event_status" }, new { name = "mail_event_status", arguments = (object?)null }
        })
        {
            var accepted = await TrackedToolRequestAsync(host.Client, token, parameters);
            Expect(!IsToolError(accepted.Body), "Status validation rejected omitted or null arguments.");
        }
        var failedStatus = await TrackedToolRequestAsync(host.Client, token,
            new { name = "mail_event_status", arguments = new { }, statusRpcFailureFixture = true });
        using (var failedJson = ParseJson(failedStatus.Body))
        {
            var error = failedJson.RootElement.GetProperty("error");
            var data = error.GetProperty("data");
            var tracking = data.GetProperty("tracking");
            Expect(error.GetProperty("code").GetInt32() == -32603
                && data.GetProperty("reason").GetString() == "synthetic_rpc_failure"
                && tracking.GetProperty("id").GetString() == failedStatus.Id
                && tracking.GetProperty("stage").GetString() == "rpc_error",
                "A generic status RPC error lost its HTTP tracking or existing error data.");
        }

        var unsubscribed = await ToolRequestAsync(host.Client, token, "events/unsubscribe", new
        {
            name = MailEventService.InboxEventName,
            arguments = new { },
            delivery = new { mode = "webhook", url = callbackUrl }
        }, "2026-07-28");
        using (var unsubscribeJson = ParseJson(unsubscribed.Body))
            Expect(unsubscribed.StatusCode == HttpStatusCode.OK
                && unsubscribeJson.RootElement.GetProperty("result") is { ValueKind: System.Text.Json.JsonValueKind.Object } result
                && !result.EnumerateObject().Any(property => property.Name != "_meta")
                && (await eventStore.StatusAsync(actor, CancellationToken.None)).Count == 0,
                $"The HTTP events/unsubscribe call did not remove the actor's subscription: {unsubscribed.Body}; remaining={(await eventStore.StatusAsync(actor, CancellationToken.None)).Count}.");

        await Task.WhenAll(
            ToolRequestAsync(host.Client, token, "server/discover", new { }, JulyProtocolVersion),
            ToolRequestAsync(host.Client, token, "tools/list", new { }, JulyProtocolVersion));
        const string poison = "private-trace-poison-must-not-appear";
        var poisonedList = await SendMcpAsync(host.Client, token, new
        {
            jsonrpc = "2.0",
            id = poison,
            method = "events/list",
            @params = new
            {
                _meta = new Dictionary<string, object>
                {
                    ["io.modelcontextprotocol/protocolVersion"] = JulyProtocolVersion,
                    ["io.modelcontextprotocol/clientInfo"] = new { name = poison, version = "1.0" },
                    ["io.modelcontextprotocol/clientCapabilities"] = new { },
                    ["private"] = new { subject = poison, callbackUrl, secret = webhookSecret }
                }
            }
        }, protocolVersion: JulyProtocolVersion, mcpMethod: "events/list");
        using (var poisonedJson = ParseJson(poisonedList.Body))
            Expect(poisonedJson.RootElement.GetProperty("id").GetString() == poison
                && poisonedJson.RootElement.TryGetProperty("result", out _),
                "Safe tracing altered the RPC ID or rejected otherwise valid private request metadata.");

        using (var traceDeadline = new CancellationTokenSource(TimeSpan.FromSeconds(5)))
            while (traceLogger.Messages.Count(line => line.StartsWith("MCP event trace response", StringComparison.Ordinal))
                < traceLogger.Messages.Count(line => line.StartsWith("MCP event trace request", StringComparison.Ordinal)))
            {
                if (traceDeadline.IsCancellationRequested)
                    throw new InvalidOperationException("Incomplete metadata trace: " + string.Join(" | ", traceLogger.Messages));
                await Task.Delay(20);
            }
        var messages = traceLogger.Messages.ToArray();
        var requests = messages.Where(line => line.StartsWith("MCP event trace request", StringComparison.Ordinal)).ToArray();
        var responses = messages.Where(line => line.StartsWith("MCP event trace response", StringComparison.Ordinal)).ToArray();
        const string correlation = @"trace=([a-f0-9]{32}) method=(server/discover|tools/list|events/list|events/subscribe|events/unsubscribe|tools/call) protocol=(2026-07-28|2025-11-25)";
        var requestKeys = requests.Select(line => System.Text.RegularExpressions.Regex.Match(line, correlation).Value).ToArray();
        var responseKeys = responses.Select(line => System.Text.RegularExpressions.Regex.Match(line, correlation).Value).ToArray();
        Expect(requestKeys.Length >= 9 && requestKeys.All(key => key.Length > 0)
            && requestKeys.Distinct(StringComparer.Ordinal).Count() == requestKeys.Length
            && responseKeys.Order(StringComparer.Ordinal).SequenceEqual(requestKeys.Order(StringComparer.Ordinal))
            && responses.All(line => line.Contains("http=200", StringComparison.Ordinal)),
            "HTTP discovery traces did not correlate concurrent requests/replies with generated IDs and observed HTTP status.");
        Expect(responses.Any(line => line.Contains("method=server/discover", StringComparison.Ordinal)
                && line.Contains("result=complete eventsCapability=present", StringComparison.Ordinal))
            && responses.Any(line => line.Contains("method=tools/list", StringComparison.Ordinal)
                && line.Contains("mailEventStatus=present", StringComparison.Ordinal))
            && responses.Any(line => line.Contains("method=events/list", StringComparison.Ordinal)
                && line.Contains("events=1 emailReceived=present", StringComparison.Ordinal))
            && responses.Any(line => line.Contains("rpc=-32015", StringComparison.Ordinal)),
            "The trace omitted discovery capability, status-tool/event presence, counts, or the categorized RPC failure.");
        Expect(responses.Any(line => line.Contains("name=mail_event_status tracking=True", StringComparison.Ordinal)
                && line.Contains("rpc=success", StringComparison.Ordinal))
            && responses.Any(line => line.Contains("name=mail_event_status tracking=True", StringComparison.Ordinal)
                && line.Contains("rpc=-32602", StringComparison.Ordinal))
            && responses.Any(line => line.Contains("name=mail_event_status tracking=True", StringComparison.Ordinal)
                && line.Contains("rpc=-32603", StringComparison.Ordinal)),
            "Status tracing omitted the normalized tool name, tracking presence, or safe RPC failure category: "
                + string.Join(" | ", responses.Where(line => line.Contains("name=mail_event_status", StringComparison.Ordinal))));
        var combined = string.Join('\n', messages);
        Expect(!combined.Contains(poison, StringComparison.Ordinal) && !combined.Contains(webhookSecret, StringComparison.Ordinal)
            && !combined.Contains(callbackUrl, StringComparison.Ordinal) && !combined.Contains(token, StringComparison.Ordinal)
            && !combined.Contains("alice@example.test", StringComparison.Ordinal) && !combined.Contains("user-a", StringComparison.Ordinal)
            && !combined.Contains("chatgpt-test", StringComparison.Ordinal),
            "Discovery tracing exposed raw RPC IDs, private metadata, callback details, credentials, or actor identity.");
        Expect(!combined.Contains("private-status-argument-must-not-appear", StringComparison.Ordinal)
            && statuses.All(status => !combined.Contains(status.Id, StringComparison.Ordinal))
            && !combined.Contains(invalidStatus.Id, StringComparison.Ordinal)
            && !combined.Contains(failedStatus.Id, StringComparison.Ordinal)
            && !combined.Contains(subscriptionId!, StringComparison.Ordinal),
            "Status tracing exposed arguments, operation IDs, or subscription IDs.");
        var traceCount = traceLogger.Messages.Count;
        var untracedProfile = await ToolRequestAsync(host.Client, token, "tools/call",
            new { name = "mail_profile", arguments = new { } }, JulyProtocolVersion);
        using (var profileJson = ParseJson(untracedProfile.Body))
            Expect(profileJson.RootElement.TryGetProperty("result", out _) && traceLogger.Messages.Count == traceCount,
                "The metadata trace expanded beyond its discovery/subscription method whitelist.");
        var malformedProfile = await TrackedToolRequestAsync(host.Client, token,
            new { name = "mail_profile", arguments = "private-profile-argument-must-not-appear" });
        using (var profileJson = ParseJson(malformedProfile.Body))
            Expect(profileJson.RootElement.GetProperty("error").GetProperty("code").GetInt32() == -32603
                && traceLogger.Messages.Count == traceCount,
                "The status-only validation or tracing changed another tool's malformed-argument boundary.");

        await statusGate.WaitAsync();
        try
        {
            using var cancelled = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            using var request = new HttpRequestMessage(HttpMethod.Post, "/mcp")
            {
                Content = new StringContent(System.Text.Json.JsonSerializer.Serialize(new
                {
                    jsonrpc = "2.0",
                    id = "cancelled-status-request",
                    method = "tools/call",
                    @params = new { name = "mail_event_status", arguments = new { } }
                }), System.Text.Encoding.UTF8, "application/json")
            };
            request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
            request.Headers.Accept.ParseAdd("application/json");
            request.Headers.Accept.ParseAdd("text/event-stream");
            request.Headers.Add("MCP-Protocol-Version", ProtocolVersion);
            var previousStatusRequests = traceLogger.Messages.Count(line => line.StartsWith("MCP event trace request", StringComparison.Ordinal)
                && line.Contains("name=mail_event_status", StringComparison.Ordinal));
            var cancelledHttp = host.Client.SendAsync(request, cancelled.Token);
            while (traceLogger.Messages.Count(line => line.StartsWith("MCP event trace request", StringComparison.Ordinal)
                && line.Contains("name=mail_event_status", StringComparison.Ordinal)) == previousStatusRequests)
                await Task.Delay(20, cancelled.Token);
            Expect(!cancelledHttp.IsCompleted, "The HTTP cancellation regression did not contend for the store gate.");
            cancelled.Cancel();
            await AssertThrowsAsync<OperationCanceledException>(async () =>
                await cancelledHttp.WaitAsync(TimeSpan.FromSeconds(5)));
        }
        finally { statusGate.Release(); }
        var afterCancellation = await TrackedToolRequestAsync(host.Client, token,
            new { name = "mail_event_status", arguments = new { } });
        Expect(afterCancellation.StatusCode == HttpStatusCode.OK && !IsToolError(afterCancellation.Body),
            "A cancelled contended HTTP status call prevented a later status read.");
    }

    private static JsonRpcRequest EventRequest(string method, JsonNode parameters, ClaimsPrincipal user,
        string protocol = "2026-07-28") => new()
        {
            Method = method,
            Params = parameters,
            Context = new JsonRpcMessageContext { User = user, ProtocolVersion = protocol }
        };

    private static JsonRpcRequest SubscribeRequest(ClaimsPrincipal user, JsonObject parameters) =>
        EventRequest("events/subscribe", parameters, user);

    private static ClaimsPrincipal EventUser(string subject, DateTimeOffset expiry) => new(new ClaimsIdentity(
    [
        new Claim("sub", subject), new Claim("scope", MailboxAccess.Read),
        new Claim("azp", "company-mail-checks"), new Claim("sid", "event-protocol-session"),
        new Claim("exp", expiry.ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture))
    ], "Bearer"));

    private static async Task<TException> CaptureExceptionAsync<TException>(Func<Task> action)
        where TException : Exception
    {
        try { await action().ConfigureAwait(false); }
        catch (TException exception) { return exception; }
        throw new InvalidOperationException($"Expected {typeof(TException).Name}.");
    }

    private sealed class ProtocolTestWebhook : IMailEventWebhook
    {
        public Task VerifyAsync(string callbackUrl, string subscriptionId, string secret, CancellationToken cancellationToken) =>
            Task.CompletedTask;

        public Task<HttpStatusCode> DeliverAsync(string callbackUrl, string subscriptionId, string secret,
            string? previousSecret, MailEventNotification notification, CancellationToken cancellationToken) =>
            Task.FromResult(HttpStatusCode.OK);
    }
}

internal sealed class MailEventTraceLogger : ILogger<MailEventProtocol>
{
    public System.Collections.Concurrent.ConcurrentQueue<string> Messages { get; } = new();
    public bool ThrowOnLog { get; set; }
    private int failedWrites;
    public int FailedWrites => Volatile.Read(ref failedWrites);
    public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
    public bool IsEnabled(LogLevel logLevel) => true;
    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
        Func<TState, Exception?, string> formatter)
    {
        Messages.Enqueue(formatter(state, exception));
        if (ThrowOnLog)
        {
            Interlocked.Increment(ref failedWrites);
            throw new InvalidOperationException("Synthetic trace sink failure.");
        }
    }
}
