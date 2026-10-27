using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Company.ExchangeMcp;
using Company.ExchangeMcp.Security;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;

internal sealed partial class Checks
{
    private async Task ResourceAuditChecksAsync()
    {
        await ResourceAuditWireChecksAsync();
        await ResourceAuditFilterChecksAsync();
    }

    private async Task ResourceAuditWireChecksAsync()
    {
        var auditPath = Path.Combine(runDirectory, "resource-audit-wire.jsonl");
        var exchange = new RecordingEwsHandler();
        await using var host = await StartHostAsync(exchange, writesEnabled: false, sendEnabled: false,
            configure: builder => builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Service:AuditPath"] = auditPath
            }));
        var token = Token("user-a", "mail.read");
        await InitializeAsync(host.Client, token);
        var routes = new[]
        {
            (SignaturePreviewResources.Read(), SignaturePreviewResources.ResourceUri, "signature_current"),
            (SignaturePreviewResources.ReadRetained(), SignaturePreviewResources.RetainedResourceUri, "signature_retained"),
            (SignaturePreviewResources.ReadPrevious(), SignaturePreviewResources.PreviousResourceUri, "signature_previous"),
            (SignaturePreviewResources.ReadLegacy(), SignaturePreviewResources.LegacyResourceUri, "signature_legacy"),
            (MailPreviewResources.Read(), MailPreviewResources.ResourceUri, "email_current"),
            (MailPreviewResources.ReadPrior(), MailPreviewResources.PriorResourceUri, "email_prior"),
            (MailPreviewResources.ReadCached(), MailPreviewResources.CachedResourceUri, "email_cached"),
            (MailPreviewResources.ReadRetained(), MailPreviewResources.RetainedResourceUri, "email_retained"),
            (MailPreviewResources.ReadPrevious(), MailPreviewResources.PreviousResourceUri, "email_previous"),
            (MailPreviewResources.ReadLegacy(), MailPreviewResources.LegacyResourceUri, "email_legacy")
        };
        foreach (var (expected, uri, resourceClass) in routes)
        {
            var response = await ReadResourceWithoutRoutingHeadersAsync(host.Client, token, uri);
            using var json = ParseJson(response.Body);
            var returned = json.RootElement.GetProperty("result").GetProperty("contents")[0];
            var content = (TextResourceContents)expected.Contents[0];
            Expect(response.Status == HttpStatusCode.OK && IsTrackingId(response.Id)
                && returned.GetProperty("uri").GetString() == uri
                && returned.GetProperty("mimeType").GetString() == content.MimeType
                && returned.GetProperty("text").GetString() == content.Text,
                "Resource auditing changed a successful SDK resource response or lost its HTTP request ID.");
            var entry = (await ReadResourceAuditEntriesAsync(auditPath)).Single(item => item.GetProperty("operationId").GetString() == response.Id);
            var bytes = Encoding.UTF8.GetBytes(content.Text);
            Expect(entry.GetProperty("resourceClass").GetString() == resourceClass
                && entry.GetProperty("status").GetString() == "completed"
                && entry.GetProperty("mimeClass").GetString() == "mcp_app_html"
                && entry.GetProperty("contentCount").GetInt32() == 1
                && entry.GetProperty("utf8Length").GetInt32() == bytes.Length
                && entry.GetProperty("sha256").GetString() == Convert.ToHexString(SHA256.HashData(bytes)),
                "A headerless actual resources/read was not classified and fingerprinted from its verified static result.");
        }
        const string unknownUri = "ui://private-resource-sentinel/body?token=private-query-sentinel";
        var unknown = await ReadResourceWithoutRoutingHeadersAsync(host.Client, token, unknownUri);
        using var unknownJson = ParseJson(unknown.Body);
        Expect(unknownJson.RootElement.TryGetProperty("error", out _),
            "The resource observer converted an unknown-resource error into success.");
        var entries = await ReadResourceAuditEntriesAsync(auditPath);
        var unknownEntry = entries.Single(item => item.GetProperty("operationId").GetString() == unknown.Id);
        Expect(entries.Length == routes.Length + 1 && unknownEntry.GetProperty("resourceClass").GetString() == "other"
            && unknownEntry.GetProperty("status").GetString() == "failed"
            && unknownEntry.GetProperty("contentCount").GetInt32() == 0
            && !unknownEntry.TryGetProperty("utf8Length", out _) && !unknownEntry.TryGetProperty("sha256", out _),
            "An unknown resource leaked a fingerprint, was misclassified or produced duplicate observation records.");
        var auditText = await ReadSharedAuditAsync(auditPath);
        Expect(!auditText.Contains("private-resource-sentinel", StringComparison.Ordinal)
            && !auditText.Contains("private-query-sentinel", StringComparison.Ordinal)
            && !auditText.Contains("<!doctype", StringComparison.OrdinalIgnoreCase)
            && exchange.Calls.Count == 0,
            "Resource observation retained raw URI/body data or reached Exchange.");
    }

    private async Task ResourceAuditFilterChecksAsync()
    {
        var auditPath = Path.Combine(runDirectory, "resource-audit-filter.jsonl");
        using var audit = new AuditLog(Options.Create(new ServiceOptions { AuditPath = auditPath }));
        var http = new DefaultHttpContext();
        var accessor = new HttpContextAccessor { HttpContext = http };
        using var services = new ServiceCollection().AddSingleton(audit).AddSingleton<IHttpContextAccessor>(accessor).BuildServiceProvider();
        await using var server = McpServer.Create(new StreamServerTransport(Stream.Null, Stream.Null, "resource-audit-checks", null),
            new McpServerOptions { ServerInfo = new() { Name = "resource-audit-checks", Version = "1.0" } }, null, services);
        RequestContext<ReadResourceRequestParams> Context(string uri) => new(server,
            new JsonRpcRequest { Id = new RequestId(1), Method = "resources/read" }, new ReadResourceRequestParams { Uri = uri })
        { Services = services };
        const string privateText = "private-resource-body-sentinel";
        var expected = (TextResourceContents)SignaturePreviewResources.Read().Contents[0];
        var cases = new[]
        {
            (Uri: "ui://private-resource-uri-sentinel", Result: new ReadResourceResult
            { Contents = [new TextResourceContents { Uri = "ui://private-resource-uri-sentinel", MimeType = expected.MimeType, Text = privateText }] }),
            (Uri: expected.Uri, Result: new ReadResourceResult
            { Contents = [new TextResourceContents { Uri = expected.Uri, MimeType = expected.MimeType, Text = privateText }] }),
            (Uri: expected.Uri, Result: new ReadResourceResult
            { Contents = [new TextResourceContents { Uri = expected.Uri, MimeType = "application/private-mime-sentinel", Text = expected.Text }] }),
            (Uri: expected.Uri, Result: new ReadResourceResult
            { Contents = [new TextResourceContents { Uri = "ui://private-resource-uri-sentinel", MimeType = expected.MimeType, Text = expected.Text }] }),
            (Uri: expected.Uri, Result: new ReadResourceResult { Contents = [expected, expected] })
        };
        foreach (var item in cases)
        {
            var before = (await ReadResourceAuditEntriesAsync(auditPath)).Length;
            var id = OperationTracking.EnsureRequestId(http);
            var handlerCalls = 0;
            var wrapped = OperationTracking.WrapReadResource(async (_, _) =>
            {
                handlerCalls++;
                await Task.CompletedTask;
                return item.Result;
            });
            var returned = await wrapped(Context(item.Uri), CancellationToken.None);
            var entries = await ReadResourceAuditEntriesAsync(auditPath);
            var entry = entries[^1];
            Expect(ReferenceEquals(returned, item.Result) && handlerCalls == 1 && entries.Length == before + 1
                && entry.GetProperty("operationId").GetString() == id
                && entry.GetProperty("status").GetString() == "completed"
                && entry.GetProperty("mimeClass").GetString() == "other"
                && !entry.TryGetProperty("utf8Length", out _) && !entry.TryGetProperty("sha256", out _),
                "The resource observer changed a result or fingerprinted unverified/private content.");
        }
        var failure = new InvalidOperationException("private-resource-exception-sentinel");
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        var cancelled = new OperationCanceledException("private-resource-cancellation-sentinel", cancellation.Token);
        foreach (var exception in new Exception[] { failure, cancelled })
        {
            var wrapped = OperationTracking.WrapReadResource(async (_, token) =>
            {
                Expect(token == cancellation.Token, "The resource observer replaced the handler's cancellation token.");
                await Task.CompletedTask;
                throw exception;
            });
            Exception? observed = null;
            try { await wrapped(Context(expected.Uri), cancellation.Token); }
            catch (Exception caught) { observed = caught; }
            var entry = (await ReadResourceAuditEntriesAsync(auditPath))[^1];
            Expect(ReferenceEquals(observed, exception)
                && entry.GetProperty("status").GetString() == (exception is OperationCanceledException ? "cancelled" : "failed")
                && entry.GetProperty("contentCount").GetInt32() == 0,
                "Resource observation masked the original failure/cancellation or wrote a false completion.");
        }
        var auditText = await ReadSharedAuditAsync(auditPath);
        Expect(!auditText.Contains("private-resource-", StringComparison.Ordinal)
            && !auditText.Contains("private-mime-sentinel", StringComparison.Ordinal)
            && !auditText.Contains(expected.Text, StringComparison.Ordinal),
            "Resource observation logged a private body, URI, MIME string or exception message.");
        audit.Dispose();
        var successResult = SignaturePreviewResources.Read();
        var success = OperationTracking.WrapReadResource(async (_, _) => { await Task.CompletedTask; return successResult; });
        Expect(ReferenceEquals(await success(Context(expected.Uri), CancellationToken.None), successResult),
            "An audit write failure changed a successful resource result.");
        var failed = OperationTracking.WrapReadResource(async (_, _) => { await Task.CompletedTask; throw failure; });
        Exception? afterAuditFailure = null;
        try { await failed(Context(expected.Uri), CancellationToken.None); }
        catch (Exception exception) { afterAuditFailure = exception; }
        Expect(ReferenceEquals(afterAuditFailure, failure), "An audit write failure replaced the original resource exception.");
    }

    private static async Task<JsonElement[]> ReadResourceAuditEntriesAsync(string path) =>
        (await ReadSharedAuditAsync(path)).Split('\n', StringSplitOptions.RemoveEmptyEntries).Select(line =>
        {
            using var json = JsonDocument.Parse(line);
            return json.RootElement.Clone();
        }).Where(entry => entry.TryGetProperty("kind", out var kind) && kind.GetString() == "resource").ToArray();

    private static async Task<(HttpStatusCode Status, string Body, string Id)> ReadResourceWithoutRoutingHeadersAsync(
        HttpClient client, string token, string uri)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "/mcp")
        {
            Content = new StringContent(JsonSerializer.Serialize(new
            { jsonrpc = "2.0", id = 1, method = "resources/read", @params = new { uri } }), Encoding.UTF8, "application/json")
        };
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("text/event-stream"));
        request.Headers.TryAddWithoutValidation("MCP-Protocol-Version", ProtocolVersion);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        Expect(!request.Headers.Contains("Mcp-Method") && !request.Headers.Contains("Mcp-Name"),
            "The headerless resource fixture accidentally supplied optional routing headers.");
        using var response = await client.SendAsync(request);
        var id = response.Headers.TryGetValues("X-Request-ID", out var values) ? values.Single() : string.Empty;
        return (response.StatusCode, await response.Content.ReadAsStringAsync(), id);
    }
}
