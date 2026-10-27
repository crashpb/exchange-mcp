using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Company.ExchangeMcp.Security;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

internal sealed partial class Checks
{
    private async Task PublicResourceChecksAsync()
    {
        const string publicResource = "https://public-mail.example.test/mcp";
        const string chatGptClient = "https://chatgpt.com/oauth/client.json";
        var exchange = new RecordingEwsHandler();
        var introspection = new IntrospectionHandler();
        await using var host = await StartHostAsync(exchange, true, true, introspection, configure: builder =>
            builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Service:PublicResource"] = publicResource,
                ["Service:AllowedClientIds:2"] = chatGptClient,
                ["Service:TrustedProxyAddresses:0"] = "192.0.2.10",
                ["Service:TrustedProxyAddresses:1"] = "198.51.100.20"
            }));

        foreach (var resource in new[] { Resource, publicResource })
        {
            var origin = new Uri(resource).GetLeftPart(UriPartial.Authority);
            foreach (var path in new[] { "/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp" })
            {
                using var discovery = await host.Client.GetAsync(origin + path);
                using var metadata = JsonDocument.Parse(await discovery.Content.ReadAsStringAsync());
                Expect(discovery.StatusCode == HttpStatusCode.OK
                    && metadata.RootElement.GetProperty("resource").GetString() == resource
                    && metadata.RootElement.GetProperty("authorization_servers")[0].GetString() == Authority,
                    "Resource metadata used the wrong hostname or issuer.");
            }
            using var challenge = await host.Client.PostAsJsonAsync(resource, InitializeBody());
            Expect(challenge.StatusCode == HttpStatusCode.Unauthorized
                && challenge.Headers.WwwAuthenticate.ToString().Contains(
                    $"resource_metadata=\"{origin}/.well-known/oauth-protected-resource\"", StringComparison.Ordinal),
                "The authentication challenge pointed to the other hostname.");
            var token = Token("user-a", "mail.read", audience: resource,
                azp: resource == publicResource ? chatGptClient : "chatgpt-test");
            var accepted = await SendMcpAsync(host.Client, token, InitializeBody(), absoluteUri: resource);
            Expect(accepted.StatusCode == HttpStatusCode.OK, "A valid token failed on its configured hostname.");
            var rejected = await SendMcpAsync(host.Client, token, InitializeBody(),
                absoluteUri: resource == Resource ? publicResource : Resource);
            Expect(rejected.StatusCode == HttpStatusCode.Unauthorized, "A token was accepted on a hostname outside its audiences.");
        }
        Expect(introspection.Calls == 2, "Cross-host tokens reached introspection or a valid request skipped it.");
        var bothAudiences = Token("user-a", "mail.read", azp: chatGptClient, audiences: [Resource, publicResource]);
        foreach (var resource in new[] { Resource, publicResource })
        {
            var accepted = await SendMcpAsync(host.Client, bothAudiences, InitializeBody(), absoluteUri: resource);
            Expect(accepted.StatusCode == HttpStatusCode.OK, "A token explicitly issued for both aliases was rejected.");
        }
        Expect(introspection.Calls == 4, "A dual-audience token skipped online introspection.");

        var publicRoot = new Uri(publicResource).GetLeftPart(UriPartial.Authority) + "/";
        using (var challenge = await host.Client.PostAsJsonAsync(publicRoot, InitializeBody()))
            Expect(challenge.StatusCode == HttpStatusCode.Unauthorized
                && challenge.Headers.WwwAuthenticate.ToString().Contains(
                    $"resource_metadata=\"{new Uri(publicRoot).GetLeftPart(UriPartial.Authority)}/.well-known/oauth-protected-resource\"",
                    StringComparison.Ordinal),
                "The bare public URL did not challenge for the same MCP resource metadata.");

        var publicToken = Token("user-a", "mail.read mail.write mail.manage mail.send", audience: publicResource,
            azp: chatGptClient);
        var rootInitialize = await SendMcpAsync(host.Client, publicToken, InitializeBody(), absoluteUri: publicRoot);
        Expect(rootInitialize.StatusCode == HttpStatusCode.OK,
            "The bare public URL did not initialize the authenticated MCP transport.");
        using (var initialization = ParseJson(rootInitialize.Body))
        {
            var instructions = initialization.RootElement.GetProperty("result").GetProperty("instructions").GetString()!;
            Expect(instructions.Contains("host's normal OAuth flow when needed", StringComparison.Ordinal)
                && instructions.Contains("optional offline_access only when supported and explicitly permitted by company policy for that client", StringComparison.Ordinal)
                && instructions.Contains("Do not repeatedly reauthenticate if the optional request is unsupported or denied", StringComparison.Ordinal)
                && instructions.Contains("discover the currently available tools", StringComparison.Ordinal)
                && instructions.Contains("call mail_profile before mailbox work", StringComparison.Ordinal)
                && instructions.Contains("plain-language Outlook or Exchange MCP request", StringComparison.Ordinal)
                && instructions.Contains("https://chatgpt.com/oauth/client.json", StringComparison.Ordinal)
                && instructions.Contains("normal host approval", StringComparison.Ordinal)
                && instructions.Contains("Other clients require native send confirmation except when the server verifies an explicitly configured standing approval", StringComparison.Ordinal)
                && instructions.Contains("authenticated actor, acting mailbox and every current recipient", StringComparison.Ordinal)
                && instructions.Contains("An existing standing approval does not grant mailbox access or authorize other recipients", StringComparison.Ordinal)
                && instructions.Contains("call mail_reply_draft with the current message handle returned by mail_read", StringComparison.Ordinal)
                && instructions.Contains("Never substitute mail_create_draft with a copied subject or RE: prefix", StringComparison.Ordinal)
                && instructions.Contains("Other guarded actions, including meeting notices and task assignments", StringComparison.Ordinal),
                "The MCP initialize response did not bundle the current client instructions.");
            Expect(instructions[..Math.Min(512, instructions.Length)].Contains("mail_onboarding", StringComparison.Ordinal)
                && instructions[..Math.Min(512, instructions.Length)].Contains("ایمیل شرکت", StringComparison.Ordinal)
                && instructions.Contains("فارسی / English", StringComparison.Ordinal)
                && instructions.Contains("completed or skipped users must not be prompted again", StringComparison.Ordinal)
                && instructions.Contains("mail_capture_signature", StringComparison.Ordinal)
                && instructions.Contains("mail_preview_signature", StringComparison.Ordinal)
                && instructions.Contains("mail_commit_signature", StringComparison.Ordinal)
                && instructions.Contains("never reconstruct or resend the candidate", StringComparison.Ordinal)
                && instructions.Contains("mail_signature_test_draft", StringComparison.Ordinal)
                && instructions.Contains("span dir=ltr", StringComparison.Ordinal)
                && instructions.Contains("ایمیل شرکت", StringComparison.Ordinal),
                "The MCP instructions omitted onboarding, preview approval or Persian direction guidance.");
        }
        var rootTools = await ToolRequestAsync(host.Client, publicToken, "tools/list", new { }, absoluteUri: publicRoot);
        using (var tools = ParseJson(rootTools.Body))
        {
            var names = tools.RootElement.GetProperty("result").GetProperty("tools").EnumerateArray()
                .Select(tool => tool.GetProperty("name").GetString()).ToHashSet(StringComparer.Ordinal);
            Expect(rootTools.StatusCode == HttpStatusCode.OK
                && names.Contains("mail_profile") && names.Contains("mail_send_draft")
                && new[] { "mail_onboarding", "mail_onboarding_update", "mail_preview_signature", "mail_finish_onboarding",
                    "mail_capture_signature", "mail_commit_signature", "mail_signature_test_draft" }
                    .All(names.Contains),
                "The bare public URL did not expose the signed-in mailbox profile and send tools.");
        }
        var wrongAudienceAtRoot = await SendMcpAsync(host.Client, Token("user-a", "mail.read", audience: Resource),
            InitializeBody(), absoluteUri: publicRoot);
        Expect(wrongAudienceAtRoot.StatusCode == HttpStatusCode.Unauthorized,
            "The bare public URL accepted a token issued for the private MCP audience.");
        var wrongHostAtRoot = await SendMcpAsync(host.Client, publicToken, InitializeBody(),
            absoluteUri: "https://unknown.example.test/");
        Expect(wrongHostAtRoot.StatusCode == HttpStatusCode.BadRequest,
            "The bare public URL accepted a request on an unconfigured host.");
        Expect(introspection.Calls == 6, "The bare public URL skipped token introspection or introspected an invalid audience.");

        Expect(exchange.Calls.Count == 0, "Discovery or initialize accessed mailbox data.");
        foreach (var peer in new[] { "192.0.2.10", "198.51.100.20", "203.0.113.30" })
        {
            var response = await host.App.GetTestServer().SendAsync(context =>
            {
                context.Connection.RemoteIpAddress = IPAddress.Parse(peer);
                context.Request.Method = "GET";
                context.Request.Scheme = "http";
                context.Request.Host = new HostString("public-mail.example.test");
                context.Request.Path = "/.well-known/oauth-protected-resource";
                context.Request.Headers["X-Forwarded-Proto"] = "https";
                context.Request.Headers["X-Forwarded-For"] = "203.0.113.40";
            });
            Expect(response.Response.StatusCode == (peer == "203.0.113.30" ? 400 : 200),
                "Forwarded HTTPS was ignored for an exact trusted proxy or accepted from an untrusted peer.");
        }

        var unapproved = await SendMcpAsync(host.Client,
            Token("user-a", "mail.read", audience: publicResource, azp: "unapproved-client"),
            InitializeBody(), absoluteUri: publicResource);
        Expect(unapproved.StatusCode == HttpStatusCode.Unauthorized, "Public access accepted an unapproved OAuth client.");
        using var unknown = await host.Client.GetAsync("https://unknown.example.test/.well-known/oauth-protected-resource");
        Expect(unknown.StatusCode == HttpStatusCode.BadRequest, "An arbitrary Host was accepted for discovery.");
        var plaintext = await SendMcpAsync(host.Client, null, InitializeBody(),
            absoluteUri: publicResource.Replace("https:", "http:", StringComparison.Ordinal));
        Expect(plaintext.StatusCode == HttpStatusCode.BadRequest, "Public MCP accepted plaintext HTTP.");
        var badOrigin = await SendMcpAsync(host.Client, null, InitializeBody(),
            absoluteUri: publicResource, origin: "https://evil.example.test");
        Expect(badOrigin.StatusCode == HttpStatusCode.Forbidden, "Public MCP accepted an unapproved browser origin.");
        foreach (var mode in new[] { "inactive", "extra-audience", "missing-audience" })
        {
            introspection.Mode = mode;
            var revoked = await SendMcpAsync(host.Client,
                bothAudiences,
                InitializeBody(), absoluteUri: publicResource);
            Expect(revoked.StatusCode == HttpStatusCode.Unauthorized, "Public MCP bypassed revocation or introspection audience equality.");
        }

        var settings = host.App.Services.GetRequiredService<IOptions<ServiceOptions>>().Value;
        Expect(settings.IsValid(), "The explicit public resource was rejected.");
        foreach (var invalid in new[] { Resource, "https://MAIL.example.test/mcp", "http://public-mail.example.test/mcp",
            "https://public-mail.example.test/other", publicResource + "?query=1", publicResource + "#fragment" })
        {
            settings.PublicResource = invalid;
            Expect(!settings.IsValid(), "An ambiguous or unsafe public resource was accepted.");
        }
        settings.PublicResource = "";
        Expect(settings.IsValid() && settings.Resources.SequenceEqual(new[] { Resource }),
            "Omitting the public resource changed the legacy configuration contract.");
    }
}
