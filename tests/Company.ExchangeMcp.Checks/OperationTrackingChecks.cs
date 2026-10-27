using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Configuration;
using Company.ExchangeMcp;
using Company.ExchangeMcp.Security;
using Microsoft.Extensions.DependencyInjection;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;

internal sealed partial class Checks
{
    private const string TrackingChatGptClientId = "https://chatgpt.com/oauth/client.json";

    private async Task OperationTrackingChecksAsync()
    {
        var exchange = new RecordingEwsHandler { DraftMode = true };
        await using var host = await StartHostAsync(exchange, writesEnabled: true, sendEnabled: true,
            configure: builder =>
            {
                builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["Service:AllowedClientIds:2"] = TrackingChatGptClientId
                });
                builder.Services.AddMcpServer().WithTools<TrackingPayloadFixture>();
            });
        var token = Token("user-a", "mail.read mail.write mail.manage mail.send",
            azp: TrackingChatGptClientId, sessionId: "tracking-send");
        var textPayload = await TrackedToolRequestAsync(host.Client, token,
            new { name = "tracking_payload_fixture", arguments = new { } });
        Expect(ToolStructuredData(textPayload.Body).GetProperty("handle").GetString() == "synthetic-handle"
            && ToolStructuredData(textPayload.Body).GetProperty("tracking").GetProperty("id").GetString() == textPayload.Id,
            "Tracking hid a JSON payload returned only in the original text content.");

        var unauthorizedId = string.Empty;
        using (var unauthorized = new HttpRequestMessage(HttpMethod.Post, "/mcp")
        {
            Content = new StringContent("{}", Encoding.UTF8, "application/json")
        })
        {
            unauthorized.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            using var response = await host.Client.SendAsync(unauthorized);
            unauthorizedId = response.Headers.TryGetValues("X-Request-ID", out var unauthorizedIds)
                ? unauthorizedIds.Single() : string.Empty;
            Expect(response.StatusCode == HttpStatusCode.Unauthorized
                && IsTrackingId(unauthorizedId),
                "The HTTP request ID was not returned for a request rejected before MCP authentication.");
        }
        var httpAudit = string.Join("\n", await Task.WhenAll(Directory.GetFiles(runDirectory, "audit-*.jsonl")
            .Select(ReadSharedAuditAsync)));
        Expect(httpAudit.Split('\n', StringSplitOptions.RemoveEmptyEntries).Any(line =>
        {
            using var entry = JsonDocument.Parse(line);
            var value = entry.RootElement;
            return value.TryGetProperty("kind", out var kind) && kind.GetString() == "http"
                && value.TryGetProperty("operationId", out var operationId)
                && operationId.GetString() == unauthorizedId
                && value.TryGetProperty("method", out var method) && method.GetString() == "POST"
                && value.TryGetProperty("path", out var path) && path.GetString() == "/mcp"
                && value.TryGetProperty("statusCode", out var statusCode) && statusCode.GetInt32() == 401;
        }), "The pre-auth HTTP completion was not written as sanitized request metadata.");
        var unknownHttpId = Guid.NewGuid().ToString("N");
        await host.App.Services.GetRequiredService<AuditLog>().RecordHttpAsync(unknownHttpId, "TRACE",
            "/mcp/user?token=must-not-log", 418, -5);
        httpAudit = string.Join("\n", await Task.WhenAll(Directory.GetFiles(runDirectory, "audit-*.jsonl")
            .Select(ReadSharedAuditAsync)));
        Expect(httpAudit.Split('\n', StringSplitOptions.RemoveEmptyEntries).Any(line =>
        {
            using var entry = JsonDocument.Parse(line);
            var value = entry.RootElement;
            return value.TryGetProperty("operationId", out var operationId)
                && operationId.GetString() == unknownHttpId
                && value.TryGetProperty("method", out var method) && method.GetString() == "OTHER"
                && value.TryGetProperty("path", out var path) && path.GetString() == "other"
                && value.TryGetProperty("statusCode", out var statusCode) && statusCode.GetInt32() == 418
                && value.TryGetProperty("elapsedMilliseconds", out var elapsed) && elapsed.GetInt64() == 0;
        }) && !httpAudit.Contains("token=must-not-log", StringComparison.Ordinal),
            "The HTTP audit did not strictly bound method/path metadata or leaked a query string.");

        var resourceAuditCases = new[]
        {
            (Name: (string?)null, Status: HttpStatusCode.BadRequest, Class: "missing"),
            (Name: (string?)SignaturePreviewResources.ResourceUri, Status: HttpStatusCode.OK, Class: "signature_current"),
            (Name: (string?)SignaturePreviewResources.PreviousResourceUri, Status: HttpStatusCode.OK, Class: "signature_previous"),
            (Name: (string?)MailPreviewResources.PreviousResourceUri, Status: HttpStatusCode.OK, Class: "email_previous"),
            (Name: (string?)"private-resource-audit-sentinel", Status: HttpStatusCode.BadRequest, Class: "other")
        };
        var resourceAuditIds = new List<(string Id, bool NamePresent, string Class, int Status)>();
        var exchangeCallsBeforeResources = exchange.Calls.Count;
        foreach (var item in resourceAuditCases)
        {
            var resourceUri = item.Status == HttpStatusCode.OK ? item.Name! : SignaturePreviewResources.ResourceUri;
            using var request = new HttpRequestMessage(HttpMethod.Post, "/mcp")
            {
                Content = new StringContent(JsonSerializer.Serialize(new
                {
                    jsonrpc = "2.0",
                    id = Random.Shared.Next(10, 1_000_000),
                    method = "resources/read",
                    @params = new
                    {
                        uri = resourceUri,
                        _meta = new Dictionary<string, object>
                        {
                            ["io.modelcontextprotocol/protocolVersion"] = JulyProtocolVersion,
                            ["io.modelcontextprotocol/clientCapabilities"] = new { }
                        }
                    }
                }), Encoding.UTF8, "application/json")
            };
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("text/event-stream"));
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            request.Headers.TryAddWithoutValidation("MCP-Protocol-Version", JulyProtocolVersion);
            request.Headers.TryAddWithoutValidation("Mcp-Method", "resources/read");
            if (item.Name is not null) request.Headers.TryAddWithoutValidation("Mcp-Name", item.Name);
            using var response = await host.Client.SendAsync(request);
            Expect(response.StatusCode == item.Status,
                "Resource header auditing changed the SDK's missing, empty or mismatched Mcp-Name validation.");
            var id = response.Headers.GetValues("X-Request-ID").Single();
            resourceAuditIds.Add((id, item.Name is not null, item.Class, (int)item.Status));
            if (response.IsSuccessStatusCode)
            {
                using var result = ParseJson(await response.Content.ReadAsStringAsync());
                Expect(result.RootElement.GetProperty("result").GetProperty("contents")[0]
                    .GetProperty("uri").GetString() == resourceUri,
                    "The audited modern resource read did not reach the registered resource.");
            }
        }
        Expect(exchange.Calls.Count == exchangeCallsBeforeResources,
            "Resource header audit checks dispatched an Exchange request.");
        // HttpClient omits empty headers, so exercise that distinct value at the audit boundary.
        var emptyHeadersId = Guid.NewGuid().ToString("N");
        var privateHeadersId = Guid.NewGuid().ToString("N");
        var auditLog = host.App.Services.GetRequiredService<AuditLog>();
        await auditLog.RecordHttpAsync(emptyHeadersId, "POST", "/mcp", 400, 0, "", "", "");
        await auditLog.RecordHttpAsync(privateHeadersId, "POST", "/mcp", 400, 0,
            "private-protocol-audit-sentinel", "private-method-audit-sentinel", "private-name-audit-sentinel");
        httpAudit = string.Join("\n", await Task.WhenAll(Directory.GetFiles(runDirectory, "audit-*.jsonl")
            .Select(ReadSharedAuditAsync)));
        var httpEntries = httpAudit.Split('\n', StringSplitOptions.RemoveEmptyEntries)
            .Select(line => JsonSerializer.Deserialize<JsonElement>(line))
            .Where(entry => entry.TryGetProperty("kind", out var kind) && kind.GetString() == "http")
            .ToArray();
        foreach (var item in resourceAuditIds)
        {
            var entry = httpEntries.Single(value => value.GetProperty("operationId").GetString() == item.Id);
            Expect(entry.GetProperty("protocolClass").GetString() == JulyProtocolVersion
                && entry.GetProperty("mcpMethodClass").GetString() == "resources_read"
                && entry.GetProperty("mcpNamePresent").GetBoolean() == item.NamePresent
                && entry.GetProperty("resourceClass").GetString() == item.Class
                && entry.GetProperty("statusCode").GetInt32() == item.Status,
                $"HTTP completion audit classified expected {item.Class} as protocol={entry.GetProperty("protocolClass")}, method={entry.GetProperty("mcpMethodClass")}, namePresent={entry.GetProperty("mcpNamePresent")}, resource={entry.GetProperty("resourceClass")}.");
        }
        foreach (var item in new[] { (Id: unauthorizedId, Class: "missing"), (Id: emptyHeadersId, Class: "empty"), (Id: privateHeadersId, Class: "other") })
        {
            var entry = httpEntries.Single(value => value.GetProperty("operationId").GetString() == item.Id);
            Expect(entry.GetProperty("protocolClass").GetString() == item.Class
                && entry.GetProperty("mcpMethodClass").GetString() == item.Class
                && entry.GetProperty("resourceClass").GetString() == item.Class
                && entry.GetProperty("mcpNamePresent").GetBoolean() == (item.Class != "missing"),
                "HTTP audit header classification confused missing, empty or unrecognized values.");
        }
        Expect(!httpAudit.Contains("audit-sentinel", StringComparison.Ordinal)
            && new[] { SignaturePreviewResources.ResourceUri, SignaturePreviewResources.PreviousResourceUri, MailPreviewResources.PreviousResourceUri }
                .All(uri => !httpAudit.Contains(uri, StringComparison.Ordinal)),
            "HTTP completion auditing persisted a raw MCP header or resource URI.");

        var draft = await TrackedToolRequestAsync(host.Client, token, new
        {
            name = "mail_create_draft",
            arguments = new { subject = "Tracking check", body = "Sensitive body fixture", to = new[] { "to@example.test" } }
        });
        Expect(!IsToolError(draft.Body) && IsTrackingId(draft.Id),
            "A successful tool result lacked its server-generated request ID.");
        var draftData = ToolStructuredData(draft.Body);
        Expect(draftData.GetProperty("tracking").GetProperty("id").GetString() == draft.Id
            && ModelText(draft.Body).Contains($"Tracking ID: {draft.Id}.", StringComparison.Ordinal),
            "The successful result did not expose its request ID in structured data and final model-visible text.");
        var createRequest = exchange.Calls.First(call => call.Operation == "CreateItem");
        Expect(createRequest.Headers.TryGetValues("client-request-id", out var draftClientIds)
            && Guid.Parse(draftClientIds.Single()).ToString("N") == draft.Id
            && createRequest.Headers.TryGetValues("return-client-request-id", out var draftReturnIds)
            && draftReturnIds.Single() == "true",
            "A non-send Exchange request did not carry the same MCP operation ID for correlation.");
        var handle = draftData.GetProperty("handle").GetString()!;

        var sent = await TrackedToolRequestAsync(host.Client, token, new
        {
            name = "mail_send_draft",
            arguments = new { draftHandle = handle }
        });
        var sentData = ToolStructuredData(sent.Body);
        var sendRequest = exchange.Calls.Last(call => call.Operation == "SendItem");
        Expect(!IsToolError(sent.Body) && sentData.GetProperty("tracking").GetProperty("id").GetString() == sent.Id
            && sentData.GetProperty("tracking").GetProperty("outcome").GetString() == "acknowledged"
            && sentData.GetProperty("tracking").GetProperty("stage").GetString() == "exchange_send_acknowledged",
            "A successful SendItem did not report Exchange acknowledgement distinctly from delivery.");
        Expect(sendRequest.Headers.TryGetValues("client-request-id", out var clientIds)
            && Guid.Parse(clientIds.Single()).ToString("N") == sent.Id
            && sendRequest.Headers.TryGetValues("return-client-request-id", out var returnIds)
            && returnIds.Single() == "true",
            "The Exchange SendItem request did not carry its MCP tracking ID and request an echo.");
        Expect(ModelText(sent.Body).Contains("does not confirm delivery", StringComparison.Ordinal),
            "The successful send result implied Exchange acknowledgement proves delivery.");

        var replay = await TrackedToolRequestAsync(host.Client, token, new
        {
            name = "mail_send_draft",
            arguments = new { draftHandle = handle }
        });
        Expect(IsToolError(replay.Body) && exchange.SendCount == 1
            && ToolStructuredData(replay.Body).GetProperty("tracking").GetProperty("dispatchStatus").GetString() == "not_dispatched"
            && ToolStructuredData(replay.Body).GetProperty("tracking").GetProperty("reason").GetString() == "replay",
            "A rejected replay was not reported as not dispatched, or reached Exchange again.");

        var profileA = await TrackedToolRequestAsync(host.Client, token, new { name = "mail_profile", arguments = new { } });
        var profileB = await TrackedToolRequestAsync(host.Client,
            Token("user-b", "mail.read", sessionId: "tracking-user-b"), new { name = "mail_profile", arguments = new { } });
        Expect(profileA.Id != profileB.Id
            && ToolStructuredData(profileA.Body).GetProperty("tracking").GetProperty("id").GetString() == profileA.Id
            && ToolStructuredData(profileB.Body).GetProperty("tracking").GetProperty("id").GetString() == profileB.Id,
            "Request IDs were reused across separate calls or mailbox identities.");

        var bindingFailure = await TrackedToolRequestAsync(host.Client, token, new
        {
            name = "mail_search",
            arguments = new { query = 17 }
        });
        Expect(IsToolError(bindingFailure.Body) && IsTrackingId(bindingFailure.Id)
            && ModelText(bindingFailure.Body).Contains(bindingFailure.Id, StringComparison.Ordinal)
            && ToolStructuredData(bindingFailure.Body).GetProperty("tracking").GetProperty("id").GetString() == bindingFailure.Id,
            "A pre-handler argument-binding failure did not return model-visible and structured tracking information.");

        var auditFiles = Directory.GetFiles(runDirectory, "audit-*.jsonl");
        var audit = string.Join("\n", await Task.WhenAll(auditFiles.Select(ReadSharedAuditAsync)));
        Expect(audit.Contains(sent.Id, StringComparison.Ordinal)
            && !audit.Contains("Sensitive body fixture", StringComparison.Ordinal)
            && !audit.Contains("to@example.test", StringComparison.Ordinal)
            && !audit.Contains("Tracking check", StringComparison.Ordinal),
            "The audit log did not link the sent request ID safely or exposed message content.");

        var unknownExchange = new RecordingEwsHandler { DraftMode = true, FailSend = true };
        await using var unknownHost = await StartHostAsync(unknownExchange, writesEnabled: true, sendEnabled: true,
            configure: builder => builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Service:AllowedClientIds:2"] = TrackingChatGptClientId
            }));
        var unknownToken = Token("user-a", "mail.read mail.write mail.manage mail.send",
            azp: TrackingChatGptClientId, sessionId: "tracking-unknown");
        var unknownHandle = unknownHost.App.Services.GetRequiredService<MailboxHandles>().Issue(
            new("user-a", "alice@example.test", TrackingChatGptClientId, "tracking-unknown"),
            "message", "draft-1", "draft-change");
        var unknown = await TrackedToolRequestAsync(unknownHost.Client, unknownToken, new
        {
            name = "mail_send_draft",
            arguments = new { draftHandle = unknownHandle }
        });
        Expect(IsToolError(unknown.Body) && unknownExchange.SendCount == 1
            && ModelText(unknown.Body).Contains("Check Sent Items before retrying", StringComparison.Ordinal)
            && ModelText(unknown.Body).Contains("Send status: unknown", StringComparison.Ordinal)
            && ModelText(unknown.Body).Contains(unknown.Id, StringComparison.Ordinal),
            "An uncertain EWS send did not return an ID, unknown outcome and no-repeat guidance.");

        var rejectedExchange = new SendStatusEwsHandler(new RecordingEwsHandler { DraftMode = true },
            new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(
                    $"<s:Envelope xmlns:s='{SoapNamespace}' xmlns:m='{MessagesNamespace}'><s:Body>"
                    + "<m:SendItemResponse><m:ResponseMessages><m:SendItemResponseMessage ResponseClass='Error'>"
                    + "<m:ResponseCode>ErrorSendAsDenied</m:ResponseCode></m:SendItemResponseMessage>"
                    + "</m:ResponseMessages></m:SendItemResponse></s:Body></s:Envelope>", Encoding.UTF8, "text/xml")
            });
        await using var rejectedHost = await StartHostAsync(rejectedExchange, writesEnabled: true, sendEnabled: true,
            configure: builder => builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Service:AllowedClientIds:2"] = TrackingChatGptClientId
            }));
        var rejectedToken = Token("user-a", "mail.read mail.write mail.manage mail.send",
            azp: TrackingChatGptClientId, sessionId: "tracking-rejected");
        var rejectedHandle = rejectedHost.App.Services.GetRequiredService<MailboxHandles>().Issue(
            new("user-a", "alice@example.test", TrackingChatGptClientId, "tracking-rejected"),
            "message", "draft-1", "draft-change");
        var rejected = await TrackedToolRequestAsync(rejectedHost.Client, rejectedToken, new
        {
            name = "mail_send_draft",
            arguments = new { draftHandle = rejectedHandle }
        });
        Expect(IsToolError(rejected.Body) && rejectedExchange.SendCount == 1
            && ModelText(rejected.Body).Contains("Send status: rejected by Exchange", StringComparison.Ordinal)
            && ModelText(rejected.Body).Contains(rejected.Id, StringComparison.Ordinal),
            "An explicit Exchange SendAs rejection was not distinguished from an uncertain send.");

        var gatewayExchange = new SendStatusEwsHandler(new RecordingEwsHandler { DraftMode = true },
            new HttpResponseMessage(HttpStatusCode.BadGateway) { Content = new StringContent("upstream unavailable") });
        await using var gatewayHost = await StartHostAsync(gatewayExchange, writesEnabled: true, sendEnabled: true,
            configure: builder => builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Service:AllowedClientIds:2"] = TrackingChatGptClientId
            }));
        var gatewayToken = Token("user-a", "mail.read mail.write mail.manage mail.send",
            azp: TrackingChatGptClientId, sessionId: "tracking-gateway");
        var gatewayHandle = gatewayHost.App.Services.GetRequiredService<MailboxHandles>().Issue(
            new("user-a", "alice@example.test", TrackingChatGptClientId, "tracking-gateway"),
            "message", "draft-1", "draft-change");
        var gateway = await TrackedToolRequestAsync(gatewayHost.Client, gatewayToken, new
        {
            name = "mail_send_draft",
            arguments = new { draftHandle = gatewayHandle }
        });
        Expect(IsToolError(gateway.Body) && gatewayExchange.SendCount == 1
            && ModelText(gateway.Body).Contains("Send status: unknown", StringComparison.Ordinal)
            && ModelText(gateway.Body).Contains("Check Sent Items before retrying", StringComparison.Ordinal),
            "An ambiguous HTTP gateway failure was incorrectly reported as a confirmed Exchange rejection.");

        var approvalExchange = new RecordingEwsHandler { DraftMode = true };
        await using var approvalHost = await StartHostAsync(approvalExchange, writesEnabled: true, sendEnabled: true);
        var approvalToken = Token("user-a", "mail.read mail.write mail.manage mail.send", sessionId: "tracking-approval");
        await InitializeAsync(approvalHost.Client, approvalToken, elicitation: true);
        var approvalDraft = await ToolRequestAsync(approvalHost.Client, approvalToken, "tools/call", new
        {
            name = "mail_create_draft",
            arguments = new { subject = "Approval tracking", body = "Synthetic body", to = new[] { "to@example.test" } }
        });
        var approvalHandle = ToolStructuredData(approvalDraft.Body).GetProperty("handle").GetString()!;
        var approval = await ToolRequestAsync(approvalHost.Client, approvalToken, "tools/call", new
        {
            name = "mail_send_draft",
            arguments = new { draftHandle = approvalHandle }
        }, JulyProtocolVersion, elicitation: true);
        Expect(approval.StatusCode == HttpStatusCode.OK
            && InputRequiredState(approval.Body).Length > 0
            && approvalExchange.SendCount == 0,
            "The tracking filter changed the native input-required approval flow or sent before approval.");
    }

    private static async Task<(HttpStatusCode StatusCode, string Body, string Id)> TrackedToolRequestAsync(
        HttpClient client, string token, object parameters)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "/mcp")
        {
            Content = new StringContent(JsonSerializer.Serialize(new
            {
                jsonrpc = "2.0",
                id = Random.Shared.Next(10, 1_000_000),
                method = "tools/call",
                @params = parameters
            }), Encoding.UTF8, "application/json")
        };
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("text/event-stream"));
        request.Headers.TryAddWithoutValidation("MCP-Protocol-Version", ProtocolVersion);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        using var response = await client.SendAsync(request);
        var id = response.Headers.TryGetValues("X-Request-ID", out var ids) ? ids.Single() : string.Empty;
        return (response.StatusCode, await response.Content.ReadAsStringAsync(), id);
    }

    private static string ModelText(string body)
    {
        using var json = ParseJson(body);
        return string.Join("\n", json.RootElement.GetProperty("result").GetProperty("content")
            .EnumerateArray().Where(block => block.TryGetProperty("text", out _))
            .Select(block => block.GetProperty("text").GetString()));
    }

    private static bool IsTrackingId(string value) => value.Length == 32
        && value.All(character => character is >= '0' and <= '9' or >= 'a' and <= 'f');

    private static async Task<string> ReadSharedAuditAsync(string path)
    {
        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        using var reader = new StreamReader(stream);
        return await reader.ReadToEndAsync();
    }

}

[McpServerToolType]
public sealed class TrackingPayloadFixture
{
    [McpServerTool(Name = "tracking_payload_fixture", ReadOnly = true)]
    public static CallToolResult Read() => new()
    {
        Content = [new TextContentBlock { Text = "{\"handle\":\"synthetic-handle\"}" }]
    };
}

internal sealed class SendStatusEwsHandler(HttpMessageHandler inner, HttpResponseMessage sendResponse) : HttpMessageHandler
{
    private readonly HttpMessageInvoker innerInvoker = new(inner, disposeHandler: false);
    public int SendCount { get; private set; }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var body = await request.Content!.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        var document = System.Xml.Linq.XDocument.Parse(body);
        var operation = document.Root!.Element(System.Xml.Linq.XName.Get("Body", OperationTrackingSoapNamespace))!.Elements().Single();
        if (operation.Name.LocalName == "SendItem")
        {
            SendCount++;
            return sendResponse;
        }
        return await innerInvoker.SendAsync(request, cancellationToken).ConfigureAwait(false);
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            innerInvoker.Dispose();
            inner.Dispose();
        }
        base.Dispose(disposing);
    }

    private const string OperationTrackingSoapNamespace = "http://schemas.xmlsoap.org/soap/envelope/";
}
