using System.Net;
using System.Text.Json;
using Company.ExchangeMcp;
using Company.ExchangeMcp.Security;
using Microsoft.Extensions.Configuration;

internal sealed partial class Checks
{
    private async Task ConnectionContinuationChecksAsync()
    {
        const string nativeClient = "exchange-mcp-codex";
        const string hostedClient = "https://chatgpt.com/oauth/client.json";
        const string publicResource = "https://public-mail.example.test/mcp";
        const string fourScopes = "mail.read mail.write mail.manage mail.send";
        var exchange = new RecordingEwsHandler();
        await using var host = await StartHostAsync(exchange, true, true, configure: builder =>
            builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Service:PublicResource"] = publicResource,
                ["Service:AllowedClientIds:2"] = nativeClient,
                ["Service:AllowedClientIds:3"] = hostedClient
            }));
        var trackingIds = new HashSet<string>(StringComparer.Ordinal);
        var profileReads = 0;
        foreach (var protocol in new[] { ProtocolVersion, JulyProtocolVersion })
            foreach (var resource in new[] { Resource, publicResource })
                foreach (var clientId in new[] { nativeClient, hostedClient })
                {
                    var token = Token("user-a", fourScopes + " openid custom.scope", azp: clientId, audience: resource, sessionId: "continuation-session");
                    var catalog = await ToolRequestAsync(host.Client, token, "tools/list", new { }, protocol, absoluteUri: resource);
                    AssertContinuationDescriptor(catalog.Body);
                    if (protocol == JulyProtocolVersion)
                    {
                        var discovery = await ToolRequestAsync(host.Client, token, "server/discover", new { }, protocol, absoluteUri: resource);
                        using var discoveryJson = ParseJson(discovery.Body);
                        var discovered = discoveryJson.RootElement.GetProperty("result");
                        Expect(discovered.GetProperty("capabilities").TryGetProperty("tools", out _)
                            && discovered.GetProperty("instructions").GetString()!.Contains(ConnectionTools.ContinuationTool, StringComparison.Ordinal)
                            && !discovered.TryGetProperty("tools", out _),
                            "Modern discovery lost tool support or opt-in guidance, or invented an inline tool catalog.");
                    }
                    var beforeProfile = exchange.Calls.Count;
                    var profile = await ToolRequestAsync(host.Client, token, "tools/call", new { name = "mail_profile", arguments = new { } }, protocol,
                        absoluteUri: resource);
                    AssertProfileConfigurationRead(beforeProfile);
                    Expect(!IsToolError(profile.Body) && ToolStructuredData(profile.Body).GetProperty("actorMailbox").GetString() == "alice@example.test",
                        "An ordinary four-scope profile required the optional upgrade or changed identity.");
                    using (var profileJson = ParseJson(profile.Body))
                        Expect(!profileJson.RootElement.GetProperty("result").GetProperty("_meta").TryGetProperty("mcp/www_authenticate", out _),
                            "An ordinary profile call triggered optional OAuth consent.");

                    var beforeChallenge = exchange.Calls.Count;
                    var requested = await ToolRequestAsync(host.Client, token, "tools/call",
                        new { name = ConnectionTools.ContinuationTool, arguments = new { } }, protocol, absoluteUri: resource);
                    Expect(exchange.Calls.Count == beforeChallenge, "A continuation challenge dispatched an Exchange operation.");
                    AssertContinuationChallenge(requested, resource, fourScopes + " offline_access");
                    var continuedToken = Token("user-a", fourScopes + " offline_access", azp: clientId, audience: resource, sessionId: "continued-session");
                    var beforeContinued = exchange.Calls.Count;
                    var continued = await ToolRequestAsync(host.Client, continuedToken, "tools/call",
                        new { name = ConnectionTools.ContinuationTool, arguments = new { } }, protocol, absoluteUri: resource);
                    Expect(exchange.Calls.Count == beforeContinued, "A continuation retry dispatched an Exchange operation.");
                    using var continuedJson = ParseJson(continued.Body);
                    var continuedResult = continuedJson.RootElement.GetProperty("result");
                    var continuedData = ToolStructuredData(continued.Body);
                    Expect(!IsToolError(continued.Body) && continuedData.GetProperty("status").GetString() == "offline_scope_present"
                        && continuedData.GetProperty("message").GetString()!.Contains("scope presence only", StringComparison.Ordinal)
                        && continuedData.GetProperty("message").GetString()!.Contains("cannot verify host refresh-token storage", StringComparison.Ordinal)
                        && !continuedResult.GetProperty("_meta").TryGetProperty("mcp/www_authenticate", out _),
                        "A retry with offline_access looped consent or claimed verified token storage or a particular session lifetime.");
                }
        foreach (var protocol in new[] { ProtocolVersion, JulyProtocolVersion })
            foreach (var scopes in new[] { "mail.read", "mail.read mail.manage" })
                foreach (var clientId in new[] { nativeClient, hostedClient })
                {
                    var token = Token("user-a", scopes + " openid custom.scope", azp: clientId);
                    var catalog = await ToolRequestAsync(host.Client, token, "tools/list", new { }, protocol);
                    AssertContinuationDescriptor(catalog.Body);
                    var beforeChallenge = exchange.Calls.Count;
                    var requested = await ToolRequestAsync(host.Client, token, "tools/call",
                        new { name = ConnectionTools.ContinuationTool, arguments = new { } }, protocol);
                    Expect(exchange.Calls.Count == beforeChallenge, "A reduced-scope continuation challenge dispatched an Exchange operation.");
                    AssertContinuationChallenge(requested, Resource, scopes + " offline_access");
                }
        foreach (var clientId in new[] { "chatgpt-test", "chatgpt-alt" })
        {
            var token = Token("user-a", fourScopes, azp: clientId);
            var beforeUnsupported = exchange.Calls.Count;
            var unsupported = await ToolRequestAsync(host.Client, token, "tools/call",
                new { name = ConnectionTools.ContinuationTool, arguments = new { } });
            Expect(exchange.Calls.Count == beforeUnsupported, "Unsupported-client continuation dispatched an Exchange operation.");
            using var unsupportedJson = ParseJson(unsupported.Body);
            Expect(IsToolError(unsupported.Body) && ToolStructuredData(unsupported.Body).GetProperty("status").GetString() == "unsupported_client"
                && !unsupportedJson.RootElement.GetProperty("result").GetProperty("_meta").TryGetProperty("mcp/www_authenticate", out _),
                "An allowed but unsupported client was prompted to upgrade its grant.");
            var beforeProfile = exchange.Calls.Count;
            var profile = await ToolRequestAsync(host.Client, token, "tools/call", new { name = "mail_profile", arguments = new { } });
            AssertProfileConfigurationRead(beforeProfile);
            Expect(!IsToolError(profile.Body), "The optional upgrade disabled an existing client's ordinary tools.");
        }
        var foreignToken = Token("user-b", "mail.read", azp: hostedClient, sessionId: "other-session");
        var beforeForeignProfile = exchange.Calls.Count;
        var foreign = await ToolRequestAsync(host.Client, foreignToken, "tools/call", new { name = "mail_profile", arguments = new { } });
        AssertProfileConfigurationRead(beforeForeignProfile);
        Expect(ToolStructuredData(foreign.Body).GetProperty("actorMailbox").GetString() == "bob@example.test",
            "Optional continuation reused another subject or session's actor context.");
        var beforeForeignContinuation = exchange.Calls.Count;
        var foreignContinuation = await ToolRequestAsync(host.Client, foreignToken, "tools/call",
            new { name = ConnectionTools.ContinuationTool, arguments = new { } });
        Expect(exchange.Calls.Count == beforeForeignContinuation, "Another actor's continuation dispatched an Exchange operation.");
        AssertContinuationChallenge(foreignContinuation, Resource, "mail.read offline_access");
        var beforeSelected = exchange.Calls.Count;
        var selected = await ToolRequestAsync(host.Client, Token("user-a", fourScopes, azp: nativeClient), "tools/call",
            new { name = ConnectionTools.ContinuationTool, arguments = new { mailboxHandle = "foreign-target" } });
        Expect(exchange.Calls.Count == beforeSelected, "A rejected selected-mailbox continuation dispatched an Exchange operation.");
        using (var selectedJson = ParseJson(selected.Body))
            Expect(IsToolError(selected.Body) && !selectedJson.RootElement.GetProperty("result").GetProperty("_meta").TryGetProperty("mcp/www_authenticate", out _),
                "A selected-mailbox call bypassed the own-only continuation guard.");
        foreach (var invalidToken in new[]
        {
            Token("user-a", "offline_access", azp: nativeClient),
            Token("user-z", "mail.read", azp: nativeClient),
            Token("user-a", "mail.read", azp: "unapproved-client"),
            Token("user-a", "mail.read", azp: nativeClient, audience: "https://foreign.example.test/mcp"),
            ExpiredToken("user-a", "mail.read offline_access")
        })
        {
            var beforeRefused = exchange.Calls.Count;
            var refused = await ToolRequestAsync(host.Client, invalidToken, "tools/call",
                new { name = ConnectionTools.ContinuationTool, arguments = new { } });
            Expect(exchange.Calls.Count == beforeRefused, "A refused continuation dispatched an Exchange operation.");
            Expect(refused.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden,
                "Optional continuation bypassed mailbox read, enrollment, client, audience or token expiry validation.");
        }
        Expect(exchange.Calls.Count == profileReads, "A non-profile request dispatched an unexpected Exchange operation.");

        var classicExchange = new RecordingEwsHandler();
        await using var classicHost = await StartHostAsync(classicExchange, true, true, classicStateful: true, configure: builder =>
            builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?> { ["Service:AllowedClientIds:2"] = nativeClient }));
        await using var native = await CreateNativeClientAsync(classicHost, Token("user-a", fourScopes, azp: nativeClient, sessionId: "classic-continuation"),
            new NativeFormResponder(accept: false));
        var beforeClassic = classicExchange.Calls.Count;
        var classic = await native.Client.CallToolAsync(ConnectionTools.ContinuationTool, new Dictionary<string, object?>());
        Expect(classicExchange.Calls.Count == beforeClassic, "Classic native continuation dispatched an Exchange operation.");
        Expect(classic.IsError == true && classic.Meta?["mcp/www_authenticate"] is not null && classic.Meta?["tracking"] is not null,
            "The existing classic/stateful native client lost the optional OAuth challenge or tracking result.");

        void AssertProfileConfigurationRead(int before)
        {
            Expect(exchange.Calls.Count == before + 1 && exchange.LastRequest.Operation == "GetUserConfiguration",
                "An ordinary profile must read only its persisted onboarding configuration.");
            profileReads++;
        }

        void AssertContinuationChallenge((HttpStatusCode StatusCode, string Body) response, string resource, string scopes)
        {
            using var json = ParseJson(response.Body);
            var result = json.RootElement.GetProperty("result");
            var meta = result.GetProperty("_meta");
            var challenge = meta.GetProperty("mcp/www_authenticate")[0].GetString()!;
            var id = meta.GetProperty("tracking").GetProperty("id").GetString()!;
            Expect(response.StatusCode == HttpStatusCode.OK && IsToolError(response.Body)
                && ToolStructuredData(response.Body).GetProperty("status").GetString() == "authorization_required"
                && challenge.StartsWith("Bearer ", StringComparison.Ordinal)
                && challenge.Contains($"resource_metadata=\"{new Uri(resource).GetLeftPart(UriPartial.Authority)}/.well-known/oauth-protected-resource\"", StringComparison.Ordinal)
                && challenge.Contains("error=\"insufficient_scope\"", StringComparison.Ordinal)
                && challenge.Contains("error_description=\"", StringComparison.Ordinal)
                && challenge.Contains($"scope=\"{scopes}\"", StringComparison.Ordinal)
                && !challenge.Contains("custom.scope", StringComparison.Ordinal) && !challenge.Contains("openid", StringComparison.Ordinal)
                && OperationTracking.IsOperationId(id) && trackingIds.Add(id)
                && ToolStructuredData(response.Body).GetProperty("tracking").GetProperty("id").GetString() == id
                && result.GetProperty("content").EnumerateArray().Any(content => content.GetProperty("text").GetString()!.Contains(id, StringComparison.Ordinal)),
                "Optional consent lost current scopes, resource-host binding, explicit tool error or request tracking.");
        }

        static void AssertContinuationDescriptor(string body)
        {
            using var json = ParseJson(body);
            var tools = json.RootElement.GetProperty("result").GetProperty("tools").EnumerateArray().ToArray();
            var tool = tools.Single(tool => tool.GetProperty("name").GetString() == ConnectionTools.ContinuationTool);
            var schemes = tool.GetProperty("securitySchemes");
            Expect(schemes.GetArrayLength() == 1 && schemes[0].GetProperty("type").GetString() == "oauth2"
                && schemes[0].GetProperty("scopes").EnumerateArray().Select(scope => scope.GetString()).SequenceEqual([MailboxAccess.Read, "offline_access"])
                && tool.GetProperty("_meta").GetProperty("securitySchemes").GetRawText() == schemes.GetRawText()
                && tool.GetProperty("annotations").GetProperty("readOnlyHint").GetBoolean()
                && tool.GetProperty("annotations").GetProperty("idempotentHint").GetBoolean()
                && !tool.GetProperty("inputSchema").GetProperty("properties").TryGetProperty("mailboxHandle", out _),
                "Modern or legacy discovery lost the exact read-plus-offline opt-in scopes, matching metadata mirror or own-only annotations.");
            var profile = tools.Single(tool => tool.GetProperty("name").GetString() == "mail_profile");
            Expect(!profile.TryGetProperty("securitySchemes", out _), "Optional OAuth descriptor projection changed an ordinary tool.");
        }
    }
}
