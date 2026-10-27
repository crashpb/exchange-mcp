using System.Net;
using Company.ExchangeMcp.Security;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

internal sealed partial class Checks
{
    private const string ChatGptOAuthClientId = "https://chatgpt.com/oauth/client.json";

    private async Task ChatGptOAuthSendChecksAsync()
    {
        foreach (var protocol in new[] { ProtocolVersion, JulyProtocolVersion })
        {
            var exchange = new RecordingEwsHandler { DraftMode = true };
            await using var host = await StartHostAsync(exchange, writesEnabled: true, sendEnabled: true,
                configure: AllowChatGptOAuthClient);
            var token = Token("user-a", "mail.read mail.write mail.manage mail.send",
                azp: ChatGptOAuthClientId, sessionId: "chatgpt-send");
            var draft = await ToolRequestAsync(host.Client, token, "tools/call", new
            {
                name = "mail_create_draft",
                arguments = new { subject = "OAuth send", body = "Synthetic body", to = new[] { "to@example.test" } }
            }, protocol);
            Expect(draft.StatusCode == HttpStatusCode.OK && !IsToolError(draft.Body),
                "The exact ChatGPT client could not create its synthetic draft.");
            Expect(ToolStructuredData(draft.Body).GetProperty("signatureStatus").GetString() == "no_default_signature"
                && ToolStructuredData(draft.Body).GetProperty("readyToSend").GetBoolean(),
                "A no-profile synthetic draft fell into signature recovery instead of its normal saved result.");
            var handle = ToolStructuredData(draft.Body).GetProperty("handle").GetString()!;

            foreach (var deniedToken in new[]
            {
                Token("user-a", "mail.read mail.write mail.manage", azp: ChatGptOAuthClientId, sessionId: "chatgpt-send"),
                Token("user-b", "mail.read mail.write mail.manage mail.send", azp: ChatGptOAuthClientId, sessionId: "chatgpt-send")
            })
            {
                var rejected = await ToolRequestAsync(host.Client, deniedToken, "tools/call", new
                {
                    name = "mail_send_draft",
                    arguments = new { draftHandle = handle }
                }, protocol);
                Expect(rejected.StatusCode != HttpStatusCode.OK || IsToolError(rejected.Body),
                    "A missing send grant or different actor bypassed OAuth send checks.");
            }
            Expect(exchange.SendCount == 0, "An unauthorized OAuth send reached Exchange.");

            var forged = await ToolRequestAsync(host.Client, token, "tools/call", new
            {
                name = "mail_send_draft",
                arguments = new { draftHandle = handle },
                requestState = "forged",
                inputResponses = new { send_confirmation = new { action = "accept", content = new { confirm = true } } }
            }, protocol);
            Expect(IsToolError(forged.Body) && exchange.SendCount == 0,
                "A forged native approval was accepted by the OAuth-only path.");

            exchange.DraftChangeKey = "changed-after-handle";
            var stale = await ToolRequestAsync(host.Client, token, "tools/call", new
            {
                name = "mail_send_draft",
                arguments = new { draftHandle = handle }
            }, protocol);
            Expect(IsToolError(stale.Body) && exchange.SendCount == 0,
                "A changed OAuth draft was sent using an old revision handle.");
            exchange.DraftChangeKey = "draft-change";

            var sends = await Task.WhenAll(Enumerable.Range(0, 2).Select(_ => ToolRequestAsync(
                host.Client, token, "tools/call", new
                {
                    name = "mail_send_draft",
                    arguments = new { draftHandle = handle }
                }, protocol)));
            Expect(sends.Count(result => result.StatusCode == HttpStatusCode.OK && !IsToolError(result.Body)) == 1
                && exchange.SendCount == 1 && sends.All(result => !result.Body.Contains("send_confirmation", StringComparison.Ordinal)),
                "Concurrent authorized OAuth calls did not send exactly once without a second form.");

            var replay = await ToolRequestAsync(host.Client, token, "tools/call", new
            {
                name = "mail_send_draft",
                arguments = new { draftHandle = handle }
            }, protocol);
            Expect(IsToolError(replay.Body) && exchange.SendCount == 1, "An OAuth send replay reached Exchange.");
        }

        var uncertainExchange = new RecordingEwsHandler { DraftMode = true, FailSend = true };
        await using (var uncertainHost = await StartHostAsync(uncertainExchange, true, true, configure: AllowChatGptOAuthClient))
        {
            var token = Token("user-a", "mail.read mail.write mail.manage mail.send", azp: ChatGptOAuthClientId);
            var handles = uncertainHost.App.Services.GetRequiredService<MailboxHandles>();
            var handle = handles.Issue(new("user-a", "alice@example.test", ChatGptOAuthClientId),
                "message", "draft-1", "draft-change");
            for (var attempt = 0; attempt < 2; attempt++)
            {
                var result = await ToolRequestAsync(uncertainHost.Client, token, "tools/call", new
                {
                    name = "mail_send_draft",
                    arguments = new { draftHandle = handle }
                });
                Expect(IsToolError(result.Body), "An uncertain send was reported as successful.");
            }
            Expect(uncertainExchange.SendCount == 1, "An uncertain OAuth send was retried against Exchange.");
        }

        foreach (var scenario in new[] { "writes-disabled", "send-disabled", "external-recipient", "native-client", "revoked" })
        {
            var exchange = new RecordingEwsHandler
            {
                DraftMode = true,
                DraftRecipientMode = scenario == "external-recipient" ? "external" : "smtp"
            };
            var introspection = new IntrospectionHandler { Mode = scenario == "revoked" ? "inactive" : "active" };
            await using var host = await StartHostAsync(exchange, scenario != "writes-disabled", scenario is not ("writes-disabled" or "send-disabled"),
                introspection, configure: AllowChatGptOAuthClient);
            var clientId = scenario == "native-client" ? "chatgpt-test" : ChatGptOAuthClientId;
            var token = Token("user-a", "mail.read mail.write mail.manage mail.send", azp: clientId);
            var handle = host.App.Services.GetRequiredService<MailboxHandles>().Issue(
                new("user-a", "alice@example.test", clientId), "message", "draft-1", "draft-change");
            var result = await ToolRequestAsync(host.Client, token, "tools/call", new
            {
                name = "mail_send_draft",
                arguments = new { draftHandle = handle }
            });
            Expect((result.StatusCode != HttpStatusCode.OK || IsToolError(result.Body)) && exchange.SendCount == 0,
                $"The OAuth send path bypassed the {scenario} protection.");
        }
    }

    private static void AllowChatGptOAuthClient(WebApplicationBuilder builder) =>
        builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Service:AllowedClientIds:2"] = ChatGptOAuthClientId
        });
}
