using System.Text.Json;
using Company.ExchangeMcp.Security;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.AspNetCore;

internal sealed partial class Checks
{
    private const string ClassicProtocolVersion = "2025-06-18";

    private async Task NativeConfirmationChecksAsync()
    {
        var exchange = new RecordingEwsHandler { DraftMode = true };
        await using var host = await StartHostAsync(exchange, writesEnabled: true, sendEnabled: true, classicStateful: true);
        var configuredSessionMode = host.App.Services.GetRequiredService<IOptions<HttpServerTransportOptions>>().Value.SessionMode;

        var declinedForm = new NativeFormResponder(accept: false);
        await using var alice = await CreateNativeClientAsync(host, Token(
            "user-a", "mail.read mail.write mail.manage mail.send", sessionId: "native-a"), declinedForm);
        Expect(!string.IsNullOrWhiteSpace(alice.Client.SessionId),
            $"The native MCP client did not receive a stateful session id (configured={configuredSessionMode}, header={alice.SessionHeader ?? "<none>"}, all={alice.ResponseHeaders ?? "<none>"}, history={alice.ResponseHeaderHistory}, requests={alice.RequestHistory}, bodies={alice.RequestBodyHistory}, protocol={alice.Client.NegotiatedProtocolVersion ?? "<none>"}).");

        var draft = await alice.Client.CallToolAsync("mail_create_draft", new Dictionary<string, object?>
        {
            ["subject"] = "Native confirmation subject",
            ["body"] = "Native confirmation body",
            ["to"] = new[] { "to@example.test" }
        });
        Expect(!draft.IsError.GetValueOrDefault(), "The native MCP client could not create a draft.");
        var draftHandle = NativeData(draft).GetProperty("handle").GetString()!;

        var declined = await alice.Client.CallToolAsync("mail_send_draft", new Dictionary<string, object?>
        {
            ["draftHandle"] = draftHandle
        });
        Expect(!declined.IsError.GetValueOrDefault()
            && NativeData(declined).GetProperty("status").GetString() == "cancelled"
            && declinedForm.Calls == 1
            && declinedForm.LastRequest?.Mode == "form"
            && declinedForm.LastRequest.RequestedSchema?.Properties.ContainsKey("confirm") == true
            && exchange.SendCount == 0,
            "A native classic-form decline was not cancelled before Exchange.");

        declinedForm.Accept = true;
        var accepted = await alice.Client.CallToolAsync("mail_send_draft", new Dictionary<string, object?>
        {
            ["draftHandle"] = draftHandle
        });
        Expect(!accepted.IsError.GetValueOrDefault()
            && NativeData(accepted).GetProperty("status").GetString() == "sent"
            && exchange.SendCount == 1,
            "A native classic-form acceptance did not send exactly one synthetic item.");

        var replayRejected = await NativeRejectedAsync(alice.Client, "mail_send_draft", new Dictionary<string, object?>
        {
            ["draftHandle"] = draftHandle
        });
        Expect(replayRejected && exchange.SendCount == 1,
            "A repeated native send attempt was accepted or retried against Exchange.");

        var changedExchange = new RecordingEwsHandler { DraftMode = true };
        await using var changedHost = await StartHostAsync(changedExchange, writesEnabled: true, sendEnabled: true, classicStateful: true);
        var changedForm = new NativeFormResponder(accept: true)
        {
            BeforeResponse = () => changedExchange.DraftSubject = "Changed during native confirmation"
        };
        await using var changedClient = await CreateNativeClientAsync(changedHost, Token(
            "user-a", "mail.read mail.write mail.manage mail.send", sessionId: "native-changed"), changedForm);
        var changedDraft = await changedClient.Client.CallToolAsync("mail_create_draft", new Dictionary<string, object?>
        {
            ["subject"] = "Native changed subject",
            ["body"] = "Native changed body",
            ["to"] = new[] { "to@example.test" }
        });
        var changedHandle = NativeData(changedDraft).GetProperty("handle").GetString()!;
        var changedRejected = await NativeRejectedAsync(changedClient.Client, "mail_send_draft", new Dictionary<string, object?>
        {
            ["draftHandle"] = changedHandle
        });
        Expect(changedRejected && changedExchange.SendCount == 0,
            "A native confirmation accepted a draft changed while the form was open.");

        var profile = await alice.Client.CallToolAsync("mail_profile", new Dictionary<string, object?>());
        Expect(!profile.IsError.GetValueOrDefault()
            && NativeData(profile).GetProperty("mailbox").GetString() == "alice@example.test",
            "The native client did not retain the current Alice mailbox principal.");

        var reusedByBobRejected = false;
        try
        {
            await using var bobResume = await ResumeNativeClientAsync(host, alice.Client, Token(
                "user-b", "mail.read mail.write mail.manage mail.send", sessionId: "native-b"),
                new NativeFormResponder(accept: true));
            var rejectedProfile = await bobResume.Client.CallToolAsync("mail_profile", new Dictionary<string, object?>());
            reusedByBobRejected = rejectedProfile.IsError == true;
        }
        catch (Exception)
        {
            reusedByBobRejected = true;
        }
        Expect(reusedByBobRejected,
            "A different OAuth principal was allowed to reuse Alice's MCP session.");

        await using var bob = await CreateNativeClientAsync(host, Token(
            "user-b", "mail.read mail.write mail.manage mail.send", sessionId: "native-b"),
            new NativeFormResponder(accept: true));
        var bobProfile = await bob.Client.CallToolAsync("mail_profile", new Dictionary<string, object?>());
        Expect(!bobProfile.IsError.GetValueOrDefault()
            && NativeData(bobProfile).GetProperty("mailbox").GetString() == "bob@example.test",
            "A new native MCP session did not use the current Bob mailbox principal.");

        var beforeCrossUser = exchange.Calls.Count;
        var crossUserRejected = await NativeRejectedAsync(bob.Client, "mail_read", new Dictionary<string, object?>
        {
            ["messageHandle"] = draftHandle
        });
        Expect(crossUserRejected && exchange.Calls.Count == beforeCrossUser,
            "Bob reused Alice's message handle or reached Exchange.");

        await using var alternate = await CreateNativeClientAsync(host, Token(
            "user-a", "mail.read mail.write mail.manage mail.send", azp: "chatgpt-alt", sessionId: "native-alt"),
            new NativeFormResponder(accept: true));
        var beforeAlternate = exchange.SendCount;
        var alternateReplayRejected = await NativeRejectedAsync(alternate.Client, "mail_send_draft", new Dictionary<string, object?>
        {
            ["draftHandle"] = draftHandle
        });
        Expect(alternateReplayRejected && exchange.SendCount == beforeAlternate,
            "A native approval/send replay from a different OAuth client was accepted.");

        await using var changedSid = await CreateNativeClientAsync(host, Token(
            "user-a", "mail.read mail.write mail.manage mail.send", sessionId: "native-other"),
            new NativeFormResponder(accept: true));
        var beforeSid = exchange.SendCount;
        var sidReplayRejected = await NativeRejectedAsync(changedSid.Client, "mail_send_draft", new Dictionary<string, object?>
        {
            ["draftHandle"] = draftHandle
        });
        Expect(sidReplayRejected && exchange.SendCount == beforeSid,
            "A native approval/send replay from a different OAuth session was accepted.");

        await AssertNativeRevocationAsync();
    }

    private async Task AssertNativeRevocationAsync()
    {
        var exchange = new RecordingEwsHandler { DraftMode = true };
        var introspection = new IntrospectionHandler();
        await using var host = await StartHostAsync(exchange, writesEnabled: true, sendEnabled: true, introspection,
            classicStateful: true);
        await using var client = await CreateNativeClientAsync(host, Token(
            "user-a", "mail.read mail.write mail.manage mail.send", sessionId: "native-revocation"),
            new NativeFormResponder(accept: true));

        var before = exchange.Calls.Count;
        var mode = typeof(IntrospectionHandler).GetProperty(nameof(IntrospectionHandler.Mode))!;
        mode.SetValue(introspection, "inactive");
        var rejected = false;
        try
        {
            await client.Client.CallToolAsync("mail_profile", new Dictionary<string, object?>());
        }
        catch (Exception)
        {
            rejected = true;
        }

        Expect(rejected && introspection.Calls >= 2 && exchange.Calls.Count == before,
            "Token revocation after native MCP initialization was not enforced per request.");
    }

    private async Task<NativeClientContext> CreateNativeClientAsync(
        TestHostContext host, string token, NativeFormResponder responder)
    {
        var loggerFactory = LoggerFactory.Create(logging => logging.SetMinimumLevel(LogLevel.None));
        var capture = new NativeCaptureHandler(host.App.GetTestServer().CreateHandler(), ClassicProtocolVersion);
        var httpClient = new HttpClient(capture) { BaseAddress = host.Client.BaseAddress };
        var transport = new HttpClientTransport(new HttpClientTransportOptions
        {
            Endpoint = new Uri(host.Client.BaseAddress!, "/mcp"),
            TransportMode = HttpTransportMode.StreamableHttp,
            OwnsSession = false,
            AdditionalHeaders = new Dictionary<string, string>
            {
                ["Authorization"] = $"Bearer {token}"
            }
        }, httpClient, loggerFactory, true);
        var options = new McpClientOptions
        {
            ProtocolVersion = ClassicProtocolVersion,
            ClientInfo = new Implementation { Name = "company-exchange-native-check", Version = "1.0" },
            Capabilities = new ClientCapabilities
            {
                Elicitation = new ElicitationCapability { Form = new FormElicitationCapability() }
            },
            Handlers = new McpClientHandlers
            {
                ElicitationHandler = responder.HandleAsync
            }
        };
        var client = await McpClient.CreateAsync(transport, options, loggerFactory);
        return new NativeClientContext(client, transport, httpClient, loggerFactory, capture);
    }

    private async Task<NativeClientContext> ResumeNativeClientAsync(
        TestHostContext host, McpClient source, string token, NativeFormResponder responder)
    {
        var loggerFactory = LoggerFactory.Create(logging => logging.SetMinimumLevel(LogLevel.None));
        var capture = new NativeCaptureHandler(host.App.GetTestServer().CreateHandler(), ClassicProtocolVersion);
        var httpClient = new HttpClient(capture) { BaseAddress = host.Client.BaseAddress };
        var transport = new HttpClientTransport(new HttpClientTransportOptions
        {
            Endpoint = new Uri(host.Client.BaseAddress!, "/mcp"),
            TransportMode = HttpTransportMode.StreamableHttp,
            KnownSessionId = source.SessionId,
            OwnsSession = false,
            AdditionalHeaders = new Dictionary<string, string>
            {
                ["Authorization"] = $"Bearer {token}"
            }
        }, httpClient, loggerFactory, true);
        var options = new McpClientOptions
        {
            ProtocolVersion = ClassicProtocolVersion,
            ClientInfo = new Implementation { Name = "company-exchange-native-check", Version = "1.0" },
            Capabilities = new ClientCapabilities
            {
                Elicitation = new ElicitationCapability { Form = new FormElicitationCapability() }
            },
            Handlers = new McpClientHandlers
            {
                ElicitationHandler = responder.HandleAsync
            }
        };
        var resume = new ResumeClientSessionOptions
        {
            ServerCapabilities = source.ServerCapabilities,
            ServerInfo = source.ServerInfo,
            ServerInstructions = source.ServerInstructions,
            NegotiatedProtocolVersion = source.NegotiatedProtocolVersion
        };
        var client = await McpClient.ResumeSessionAsync(transport, resume, options, loggerFactory);
        return new NativeClientContext(client, transport, httpClient, loggerFactory, capture);
    }

    private static JsonElement NativeData(CallToolResult result)
    {
        if (result.StructuredContent is { } structured) return structured;
        var text = result.Content.OfType<TextContentBlock>().FirstOrDefault()?.Text;
        Expect(!string.IsNullOrWhiteSpace(text), "The native tool result omitted structured content.");
        using var document = JsonDocument.Parse(text!);
        return document.RootElement.Clone();
    }

    private static async Task<bool> NativeRejectedAsync(
        McpClient client, string toolName, IReadOnlyDictionary<string, object?> arguments)
    {
        try
        {
            var result = await client.CallToolAsync(toolName, arguments);
            return result.IsError == true;
        }
        catch (Exception)
        {
            return true;
        }
    }
}

internal sealed class NativeFormResponder(bool accept)
{
    public bool Accept { get; set; } = accept;
    public int Calls { get; private set; }
    public ElicitRequestParams? LastRequest { get; private set; }
    public Action? BeforeResponse { get; init; }

    public ValueTask<ElicitResult> HandleAsync(ElicitRequestParams? request, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (request is null) throw new InvalidOperationException("The native elicitation request was null.");
        Calls++;
        LastRequest = request;
        BeforeResponse?.Invoke();
        return ValueTask.FromResult(new ElicitResult
        {
            Action = Accept ? "accept" : "decline",
            Content = new Dictionary<string, JsonElement>
            {
                ["confirm"] = JsonSerializer.SerializeToElement(Accept)
            }
        });
    }
}

internal sealed class NativeClientContext(
    McpClient client, HttpClientTransport transport, HttpClient httpClient,
    ILoggerFactory loggerFactory, NativeCaptureHandler capture) : IAsyncDisposable
{
    public McpClient Client { get; } = client;
    public string? SessionHeader => capture.LastSessionId;
    public string? ResponseHeaders => capture.LastHeaders;
    public string ResponseHeaderHistory => string.Join(" || ", capture.HeaderHistory);
    public string RequestHistory => string.Join(" || ", capture.RequestHistory);
    public string RequestBodyHistory => string.Join(" || ", capture.RequestBodyHistory);

    public async ValueTask DisposeAsync()
    {
        await Client.DisposeAsync();
        await transport.DisposeAsync();
        httpClient.Dispose();
        loggerFactory.Dispose();
    }
}

internal sealed class NativeCaptureHandler(HttpMessageHandler inner, string protocolVersion) : DelegatingHandler(inner)
{
    public string? LastSessionId { get; private set; }
    public string? LastHeaders { get; private set; }
    public List<string> HeaderHistory { get; } = [];
    public List<string> RequestHistory { get; } = [];
    public List<string> RequestBodyHistory { get; } = [];

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        if (!request.Headers.TryGetValues("MCP-Protocol-Version", out var existing)
            || existing.Count() != 1 || existing.Single() != protocolVersion)
        {
            request.Headers.Remove("MCP-Protocol-Version");
            request.Headers.TryAddWithoutValidation("MCP-Protocol-Version", protocolVersion);
        }
        var version = request.Headers.TryGetValues("MCP-Protocol-Version", out var versions)
            ? versions.FirstOrDefault() : null;
        RequestHistory.Add($"{request.Method} {request.RequestUri} {version ?? "<none>"}");
        if (request.Content is not null)
        {
            var body = await request.Content.ReadAsStringAsync(cancellationToken);
            RequestBodyHistory.Add(body.Length > 240 ? body[..240] : body);
        }
        var response = await base.SendAsync(request, cancellationToken);
        LastHeaders = string.Join(";", response.Headers.Select(x => $"{x.Key}={string.Join(',', x.Value)}"));
        HeaderHistory.Add($"{(int)response.StatusCode}:{LastHeaders}");
        if (response.Headers.TryGetValues("Mcp-Session-Id", out var values))
            LastSessionId = values.SingleOrDefault();
        return response;
    }
}
