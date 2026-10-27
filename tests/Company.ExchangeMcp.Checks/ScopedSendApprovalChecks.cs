using System.Net;
using System.Security.Claims;
using System.Text;
using System.Xml.Linq;
using Company.ExchangeMcp.Exchange;
using Company.ExchangeMcp.Security;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

internal sealed partial class Checks
{
    private const string ScopedSendClient = "scoped-send-client";
    private const string ScopedSendScopes = "mail.read mail.write mail.send";
    private const string ScopedSendThirdTarget = "22222222-3333-4444-5555-666666666666";

    private async Task ScopedSendApprovalChecksAsync()
    {
        foreach (var protocol in new[] { ProtocolVersion, JulyProtocolVersion })
            foreach (var delegated in new[] { false, true })
            {
                var exchange = new ScopedSendEwsHandler { FromMailbox = delegated ? "bob@example.test" : "alice@example.test" };
                var ldap = ScopedSendLdap();
                var permissions = new SyntheticPermissionReader(Report(new("allowed", "synthetic"),
                    new(protocol == ProtocolVersion ? "allowed" : "denied", "synthetic"),
                    new(protocol == JulyProtocolVersion ? "allowed" : "denied", "synthetic")));
                await using var host = await StartHostAsync(exchange, true, true,
                    configure: ScopedSendConfiguration(ldap, permissions: permissions));
                var clientId = protocol == ProtocolVersion ? ScopedSendClient : "chatgpt-alt";
                var token = EnrollmentToken("user-a", EnrollmentGuidA.ToString("D"), ScopedSendScopes, clientId: clientId);
                await AssertScopedSendProfileAsync(host, token);
                var arguments = ScopedSendArguments(host, clientId: clientId, targetMailbox: delegated ? "bob@example.test" : null);
                var beforeLdap = ldap.Calls.Count;
                var sends = await Task.WhenAll(Enumerable.Range(0, 2).Select(_ => ToolRequestAsync(host.Client, token,
                    "tools/call", new { name = "mail_send_draft", arguments }, protocol)));
                Expect(sends.Count(result => result.StatusCode == HttpStatusCode.OK && !IsToolError(result.Body)) == 1
                    && exchange.SendCount == 1 && sends.All(result => !result.Body.Contains("send_confirmation", StringComparison.Ordinal))
                    && ldap.Calls.Count >= beforeLdap + 4,
                    "A scoped send did not verify the current directory actor and send exactly once without an MCP form.");
                Expect(!delegated || permissions.Calls >= 1
                    && permissions.LastIdentity is { ActorMailbox: "alice@example.test", Mailbox: "bob@example.test" },
                    "A scoped selected-mailbox send skipped its existing actor-bound sending-rights checks.");
                var replay = await ToolRequestAsync(host.Client, token, "tools/call", new { name = "mail_send_draft", arguments }, protocol);
                Expect(IsToolError(replay.Body) && exchange.SendCount == 1, "A scoped send replay reached Exchange.");
            }

        AssertScopedSendConfiguration();
        await AssertScopedSendBoundariesAsync();
        await AssertScopedSendAuthenticationAsync();
        await AssertScopedSendFreshDirectoryCheckAsync();
        await AssertScopedSendContinuationIsolationAsync();
        await AssertScopedSendUncertainAsync();
    }

    private void AssertScopedSendConfiguration()
    {
        ServiceOptions Options()
        {
            var options = EnrollmentServiceOptions(EnrollmentAuditPath("scoped-options"));
            EnableScopedSending(options);
            return options;
        }

        Expect(Options().IsValid(), "A bounded GUID-backed scoped send policy was rejected.");
        var disabled = EnrollmentServiceOptions(EnrollmentAuditPath("scoped-disabled"));
        disabled.AutoEnrollmentEnabled = false;
        Expect(disabled.IsValid() && disabled.SendWithoutNativeConfirmationActor.Length == 0
            && disabled.SendWithoutNativeConfirmationMailboxes.Length == 0
            && disabled.SendWithoutNativeConfirmationClientIds.Length == 0,
            "Scoped sending was enabled by default or changed legacy static configuration.");
        foreach (var invalidate in new Action<ServiceOptions>[]
        {
            options => options.AutoEnrollmentEnabled = false,
            options => options.SendWithoutNativeConfirmationActor = "",
            options => options.SendWithoutNativeConfirmationActor = "unregistered@example.test",
            options => options.Mailboxes["duplicate"] = "ALICE@example.test",
            options => options.SendWithoutNativeConfirmationMailboxes = ["alice@example.test"],
            options => options.SendWithoutNativeConfirmationMailboxes = ["alice@example.test", "ALICE@example.test"],
            options => options.SendWithoutNativeConfirmationMailboxes = ["bob@example.test", "carol@example.test"],
            options => options.SendWithoutNativeConfirmationMailboxes = ["alice@example.test", "Bob <bob@example.test>"],
            options => options.SendWithoutNativeConfirmationMailboxes = ["alice@example.test", "bob@example.test", "carol@example.test"],
            options => options.SendWithoutNativeConfirmationMailboxes = null!,
            options => options.SendWithoutNativeConfirmationClientIds = [],
            options => options.SendWithoutNativeConfirmationClientIds = ["unapproved-client"],
            options => options.SendWithoutNativeConfirmationClientIds = ["CHATGPT-TEST"],
            options => options.SendWithoutNativeConfirmationClientIds = ["chatgpt-test", "chatgpt-test"],
            options => options.SendWithoutNativeConfirmationClientIds = ["chatgpt-test", "chatgpt-alt", "third-client"],
            options => options.SendWithoutNativeConfirmationClientIds = null!
        })
        {
            var options = Options();
            invalidate(options);
            Expect(!options.IsValid(), "An incomplete, unbound or overbroad scoped send configuration was accepted.");
        }
    }

    private async Task AssertScopedSendBoundariesAsync()
    {
        var exchange = new ScopedSendEwsHandler();
        var ldap = ScopedSendLdap();
        await using var host = await StartHostAsync(exchange, true, true, configure: ScopedSendConfiguration(ldap));
        var token = EnrollmentToken("user-a", EnrollmentGuidA.ToString("D"), ScopedSendScopes, clientId: ScopedSendClient);
        await AssertScopedSendProfileAsync(host, token);
        var arguments = ScopedSendArguments(host);

        foreach (var field in new[] { "To", "Cc", "Bcc" })
        {
            exchange.To = ["alice@example.test"];
            exchange.Cc = [];
            exchange.Bcc = [];
            if (field == "To") exchange.To = ["carol@example.test"];
            if (field == "Cc") exchange.Cc = ["carol@example.test"];
            if (field == "Bcc") exchange.Bcc = ["carol@example.test"];
            var result = await ToolRequestAsync(host.Client, token, "tools/call",
                new { name = "mail_send_draft", arguments }, JulyProtocolVersion, elicitation: true);
            Expect(result.Body.Contains("send_confirmation", StringComparison.Ordinal) && exchange.SendCount == 0,
                $"An unapproved current {field} recipient skipped the native confirmation form.");
        }
        exchange.To = ["bob@example.test"];
        exchange.Cc = [];
        exchange.Bcc = [];
        var otherClientToken = EnrollmentToken("user-a", EnrollmentGuidA.ToString("D"), ScopedSendScopes, clientId: "chatgpt-test");
        var otherClient = await ToolRequestAsync(host.Client, otherClientToken, "tools/call",
            new { name = "mail_send_draft", arguments = ScopedSendArguments(host, clientId: "chatgpt-test") },
            JulyProtocolVersion, elicitation: true);
        Expect(otherClient.Body.Contains("send_confirmation", StringComparison.Ordinal) && exchange.SendCount == 0,
            "An allowed OAuth client outside the scoped policy skipped native confirmation.");

        exchange.FromMailbox = "bob@example.test";
        var otherActorToken = EnrollmentToken("user-b", EnrollmentGuidB.ToString("D"), ScopedSendScopes, clientId: ScopedSendClient);
        var otherActor = await ToolRequestAsync(host.Client, otherActorToken, "tools/call",
            new { name = "mail_send_draft", arguments = ScopedSendArguments(host, actorSubject: "user-b", actorMailbox: "bob@example.test") },
            JulyProtocolVersion, elicitation: true);
        Expect(otherActor.Body.Contains("send_confirmation", StringComparison.Ordinal) && exchange.SendCount == 0,
            "The second mailbox's signed-in actor inherited the first actor's scoped approval.");

        exchange.FromMailbox = "carol@example.test";
        var otherTarget = await ToolRequestAsync(host.Client, token, "tools/call",
            new { name = "mail_send_draft", arguments = ScopedSendArguments(host, targetMailbox: "carol@example.test") },
            JulyProtocolVersion, elicitation: true);
        Expect(otherTarget.Body.Contains("send_confirmation", StringComparison.Ordinal) && exchange.SendCount == 0,
            "A third selected mailbox skipped the native form merely because its recipients matched the pair.");

        exchange.FromMailbox = "alice@example.test";
        exchange.To = ["outside@outside.test"];
        var external = await ToolRequestAsync(host.Client, token, "tools/call",
            new { name = "mail_send_draft", arguments });
        Expect(IsToolError(external.Body) && exchange.SendCount == 0,
            "Scoped sending bypassed the global recipient-domain policy.");
        exchange.To = ["bob@example.test"];
        var stale = await ToolRequestAsync(host.Client, token, "tools/call",
            new { name = "mail_send_draft", arguments = ScopedSendArguments(host, changeKey: "old-revision") });
        Expect(IsToolError(stale.Body) && exchange.SendCount == 0, "A stale handle sent a policy-matching draft.");
        var beforeCrossClient = exchange.GetItemCount;
        var crossClient = await ToolRequestAsync(host.Client, otherClientToken, "tools/call",
            new { name = "mail_send_draft", arguments });
        Expect(IsToolError(crossClient.Body) && exchange.GetItemCount == beforeCrossClient && exchange.SendCount == 0,
            "A different OAuth client reused a scoped draft handle.");
        var selectedArguments = ScopedSendArguments(host, targetMailbox: "bob@example.test");
        var discovery = (TestMailboxDiscovery)host.App.Services.GetRequiredService<IMailboxDiscovery>();
        discovery.Rebind(DiscoveryMailboxKey, "reassigned@example.test");
        var beforeRebound = exchange.GetItemCount;
        var rebound = await ToolRequestAsync(host.Client, token, "tools/call",
            new { name = "mail_send_draft", arguments = selectedArguments });
        Expect(IsToolError(rebound.Body) && exchange.GetItemCount == beforeRebound && exchange.SendCount == 0,
            "A scoped send followed a mailbox selector after its canonical address was reassigned.");

        foreach (var rights in new[] { "denied", "unknown" })
        {
            var deniedExchange = new ScopedSendEwsHandler { FromMailbox = "bob@example.test" };
            var deniedPermissions = new SyntheticPermissionReader(Report(new("allowed", "synthetic FullAccess"),
                new(rights, "synthetic"), new(rights, "synthetic")));
            await using var deniedHost = await StartHostAsync(deniedExchange, true, true,
                configure: ScopedSendConfiguration(ScopedSendLdap(), permissions: deniedPermissions));
            var denied = await ToolRequestAsync(deniedHost.Client, token, "tools/call",
                new { name = "mail_send_draft", arguments = ScopedSendArguments(deniedHost, targetMailbox: "bob@example.test") });
            Expect(IsToolError(denied.Body) && deniedExchange.GetItemCount == 0 && deniedExchange.SendCount == 0
                && deniedPermissions.Calls == 1,
                "Scoped sending bypassed denied or unknown delegated sending rights before reading the draft.");
        }
    }

    private async Task AssertScopedSendAuthenticationAsync()
    {
        var exchange = new ScopedSendEwsHandler();
        var ldap = ScopedSendLdap();
        var introspection = new IntrospectionHandler();
        await using var host = await StartHostAsync(exchange, true, true, introspection,
            configure: ScopedSendConfiguration(ldap));
        var arguments = ScopedSendArguments(host);
        foreach (var token in new[]
        {
            EnrollmentToken("user-a", null, ScopedSendScopes, clientId: ScopedSendClient),
            EnrollmentToken("user-a", EnrollmentGuidB.ToString("D"), ScopedSendScopes, clientId: ScopedSendClient),
            EnrollmentToken("user-a", EnrollmentGuidA.ToString("D"), ScopedSendScopes, clientId: ScopedSendClient,
                extraClaims: [new Claim(MailboxEnrollment.DirectoryGuidClaim, EnrollmentGuidB.ToString("D"))]),
            EnrollmentToken("user-a", EnrollmentGuidA.ToString("D"), "mail.read mail.write", clientId: ScopedSendClient),
            EnrollmentToken("user-a", EnrollmentGuidA.ToString("D"), "mail.send", clientId: ScopedSendClient),
            EnrollmentToken("user-a", EnrollmentGuidA.ToString("D"), ScopedSendScopes, clientId: "unapproved-client")
        })
        {
            var result = await ToolRequestAsync(host.Client, token, "tools/call", new { name = "mail_send_draft", arguments });
            Expect((result.StatusCode != HttpStatusCode.OK || IsToolError(result.Body)) && exchange.SendCount == 0,
                "A missing/foreign GUID, missing send scope or unapproved client bypassed scoped sending authorization.");
        }
        var validToken = EnrollmentToken("user-a", EnrollmentGuidA.ToString("D"), ScopedSendScopes, clientId: ScopedSendClient);
        await AssertScopedSendProfileAsync(host, validToken);
        introspection.Mode = "inactive";
        var revoked = await ToolRequestAsync(host.Client, validToken, "tools/call", new { name = "mail_send_draft", arguments });
        Expect(revoked.StatusCode == HttpStatusCode.Unauthorized && exchange.SendCount == 0,
            "A revoked token retained scoped sending approval.");

        foreach (var writesEnabled in new[] { false, true })
        {
            var gatedExchange = new ScopedSendEwsHandler();
            await using var gated = await StartHostAsync(gatedExchange, writesEnabled, false,
                configure: ScopedSendConfiguration(ScopedSendLdap()));
            var result = await ToolRequestAsync(gated.Client, validToken, "tools/call",
                new { name = "mail_send_draft", arguments = ScopedSendArguments(gated) });
            Expect(IsToolError(result.Body) && gatedExchange.SendCount == 0,
                "Scoped sending bypassed the administrator's write/send gates.");
        }

        var staticExchange = new ScopedSendEwsHandler();
        var staticLdap = ScopedSendLdap();
        await using var staticHost = await StartHostAsync(staticExchange, true, true,
            configure: ScopedSendConfiguration(staticLdap, enabled: false, autoEnrollment: false));
        EnableScopedSending(staticHost.App.Services.GetRequiredService<IOptions<ServiceOptions>>().Value);
        var staticToken = Token("user-a", ScopedSendScopes, azp: ScopedSendClient, sessionId: "test-session");
        var staticResult = await ToolRequestAsync(staticHost.Client, staticToken, "tools/call",
            new { name = "mail_send_draft", arguments = ScopedSendArguments(staticHost) }, JulyProtocolVersion, elicitation: true);
        Expect(staticResult.Body.Contains("send_confirmation", StringComparison.Ordinal) && staticExchange.SendCount == 0
            && staticLdap.Calls.Count == 0,
            "A legacy static mapping skipped native confirmation without GUID-backed enrollment.");
    }

    private async Task AssertScopedSendFreshDirectoryCheckAsync()
    {
        var ldap = ScopedSendLdap();
        var exchange = new ScopedSendEwsHandler
        {
            AfterGetItem = () => ldap.Set(EnrollmentGuidA,
                EnrollmentEntry(EnrollmentGuidA, "alice@example.test", userAccountControl: "514"))
        };
        await using var host = await StartHostAsync(exchange, true, true, configure: ScopedSendConfiguration(ldap));
        var token = EnrollmentToken("user-a", EnrollmentGuidA.ToString("D"), ScopedSendScopes, clientId: ScopedSendClient);
        await AssertScopedSendProfileAsync(host, token);
        var before = ldap.Calls.Count;
        var result = await ToolRequestAsync(host.Client, token, "tools/call",
            new { name = "mail_send_draft", arguments = ScopedSendArguments(host) });
        Expect(IsToolError(result.Body) && exchange.GetItemCount == 1 && exchange.SendCount == 0
            && ldap.Calls.Count == before + 2,
            "A directory actor disabled after authentication was not checked again before scoped dispatch.");
    }

    private async Task AssertScopedSendContinuationIsolationAsync()
    {
        var exchange = new ScopedSendEwsHandler();
        await using var host = await StartHostAsync(exchange, true, true,
            configure: ScopedSendConfiguration(ScopedSendLdap(), enabled: false));
        var token = EnrollmentToken("user-a", EnrollmentGuidA.ToString("D"), ScopedSendScopes, clientId: ScopedSendClient);
        var arguments = ScopedSendArguments(host);
        var pending = await ToolRequestAsync(host.Client, token, "tools/call",
            new { name = "mail_send_draft", arguments }, JulyProtocolVersion, elicitation: true);
        var state = InputRequiredState(pending.Body);
        EnableScopedSending(host.App.Services.GetRequiredService<IOptions<ServiceOptions>>().Value);
        foreach (var accept in new[] { false, true })
        {
            var continuation = await ToolRequestAsync(host.Client, token, "tools/call", new
            {
                name = "mail_send_draft",
                arguments,
                requestState = state,
                inputResponses = new { send_confirmation = new { action = accept ? "accept" : "decline", content = new { confirm = accept } } }
            }, JulyProtocolVersion, elicitation: true);
            Expect(IsToolError(continuation.Body) && exchange.SendCount == 0,
                "Enabling scoped approval converted a pending native confirmation continuation into a send.");
        }
        foreach (var request in new object[]
        {
            new { name = "mail_send_draft", arguments, requestState = "forged" },
            new { name = "mail_send_draft", arguments, inputResponses = new { } }
        })
        {
            var forged = await ToolRequestAsync(host.Client, token, "tools/call", request);
            Expect(IsToolError(forged.Body) && exchange.SendCount == 0,
                "A scoped send accepted non-null forged state or confirmation input.");
        }
        var fresh = await ToolRequestAsync(host.Client, token, "tools/call", new { name = "mail_send_draft", arguments });
        Expect(!IsToolError(fresh.Body) && exchange.SendCount == 1,
            "A fresh scoped send was unavailable after rejecting old continuation inputs.");
    }

    private async Task AssertScopedSendUncertainAsync()
    {
        var exchange = new ScopedSendEwsHandler { FailSend = true };
        await using var host = await StartHostAsync(exchange, true, true, configure: ScopedSendConfiguration(ScopedSendLdap()));
        var token = EnrollmentToken("user-a", EnrollmentGuidA.ToString("D"), ScopedSendScopes, clientId: ScopedSendClient);
        var arguments = ScopedSendArguments(host);
        for (var attempt = 0; attempt < 2; attempt++)
        {
            var result = await ToolRequestAsync(host.Client, token, "tools/call", new { name = "mail_send_draft", arguments });
            Expect(IsToolError(result.Body), "An uncertain scoped send was reported as successful.");
        }
        Expect(exchange.SendCount == 1, "A scoped send retried an uncertain Exchange submission.");
    }

    private const string ScopedRecallScopes = "mail.read mail.write mail.manage mail.send";

    private async Task ScopedRecallApprovalChecksAsync()
    {
        foreach (var protocol in new[] { ProtocolVersion, JulyProtocolVersion })
            foreach (var delegated in new[] { false, true })
            {
                var mailbox = delegated ? "bob@example.test" : "alice@example.test";
                var exchange = ScopedRecallExchange(mailbox);
                var ldap = ScopedSendLdap();
                var permissions = new SyntheticPermissionReader(Report(new("allowed", "synthetic"),
                    new("allowed", "synthetic SendAs"), new("denied", "synthetic")));
                await using var host = await StartHostAsync(exchange, true, true,
                    configure: ScopedSendConfiguration(ldap, permissions: permissions));
                var token = EnrollmentToken("user-a", EnrollmentGuidA.ToString("D"), ScopedRecallScopes, clientId: ScopedSendClient);
                await AssertScopedSendProfileAsync(host, token);
                var arguments = ScopedRecallArguments(host, targetMailbox: delegated ? mailbox : null);
                var beforeLdap = ldap.Calls.Count;
                var attempts = await Task.WhenAll(Enumerable.Range(0, 2).Select(_ => ToolRequestAsync(host.Client, token,
                    "tools/call", new { name = "mail_recall_message", arguments }, protocol)));
                Expect(attempts.Count(result => result.StatusCode == HttpStatusCode.OK && !IsToolError(result.Body)) == 1
                    && exchange.CreateCount == 1
                    && attempts.All(result => !result.Body.Contains("recall_confirmation", StringComparison.Ordinal))
                    && ldap.Calls.Count >= beforeLdap + 4,
                    "A configured own/delegated recall did not verify its directory actor and submit exactly once without a form.");
                var submitted = ToolStructuredData(attempts.Single(result => !IsToolError(result.Body)).Body);
                Expect(submitted.GetProperty("status").GetString() == "recall_requested"
                    && !string.IsNullOrWhiteSpace(submitted.GetProperty("recallHandle").GetString())
                    && (!delegated || permissions.Calls >= 1
                        && permissions.LastIdentity is { ActorMailbox: "alice@example.test", Mailbox: "bob@example.test" }),
                    "Configured recall lost its status handle or existing actor-bound SendAs check.");
                var replay = await ToolRequestAsync(host.Client, token, "tools/call",
                    new { name = "mail_recall_message", arguments }, protocol);
                Expect(IsToolError(replay.Body) && exchange.CreateCount == 1, "A configured recall replay reached Exchange.");
            }

        await AssertScopedRecallBoundariesAsync();
        await AssertScopedRecallGatesAsync();
        await AssertScopedRecallContinuationAndReplayAsync();
        await AssertScopedRecallUncertainAsync();
    }

    private async Task AssertScopedRecallBoundariesAsync()
    {
        const string oauthClient = "https://chatgpt.com/oauth/client.json";
        var exchange = ScopedRecallExchange();
        await using var host = await StartHostAsync(exchange, true, true, configure: builder =>
        {
            ScopedSendConfiguration(ScopedSendLdap())(builder);
            builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?> { ["Service:AllowedClientIds:3"] = oauthClient });
        });
        var token = EnrollmentToken("user-a", EnrollmentGuidA.ToString("D"), ScopedRecallScopes, clientId: ScopedSendClient);
        var arguments = ScopedRecallArguments(host);
        foreach (var field in new[] { "To", "Cc", "Bcc" })
        {
            exchange.SourceTo = ["bob@example.test"];
            exchange.SourceCc = [];
            exchange.SourceBcc = [];
            if (field == "To") exchange.SourceTo = ["carol@example.test"];
            if (field == "Cc") exchange.SourceCc = ["carol@example.test"];
            if (field == "Bcc") exchange.SourceBcc = ["carol@example.test"];
            var result = await ToolRequestAsync(host.Client, token, "tools/call",
                new { name = "mail_recall_message", arguments }, JulyProtocolVersion, elicitation: true);
            Expect(result.Body.Contains("recall_confirmation", StringComparison.Ordinal) && exchange.CreateCount == 0,
                $"A recall with an outside {field} recipient skipped native confirmation.");
        }
        exchange.SourceTo = ["bob@example.test"];
        exchange.SourceCc = [];
        exchange.SourceBcc = [];
        foreach (var client in new[] { "chatgpt-test", oauthClient })
        {
            var otherClient = await ToolRequestAsync(host.Client,
                EnrollmentToken("user-a", EnrollmentGuidA.ToString("D"), ScopedRecallScopes, clientId: client),
                "tools/call", new { name = "mail_recall_message", arguments = ScopedRecallArguments(host, clientId: client) },
                JulyProtocolVersion, elicitation: true);
            Expect(otherClient.Body.Contains("recall_confirmation", StringComparison.Ordinal) && exchange.CreateCount == 0,
                "An OAuth client outside the configured recall policy skipped native confirmation.");
        }
        exchange.SourceFrom = exchange.SourceSender = exchange.AutodiscoverSmtp = "bob@example.test";
        var otherActor = await ToolRequestAsync(host.Client,
            EnrollmentToken("user-b", EnrollmentGuidB.ToString("D"), ScopedRecallScopes, clientId: ScopedSendClient),
            "tools/call", new
            {
                name = "mail_recall_message",
                arguments = ScopedRecallArguments(host,
                actorSubject: "user-b", actorMailbox: "bob@example.test")
            }, JulyProtocolVersion, elicitation: true);
        Expect(otherActor.Body.Contains("recall_confirmation", StringComparison.Ordinal) && exchange.CreateCount == 0,
            "The second mailbox's signed-in actor inherited the first actor's configured recall grant.");
        exchange.SourceFrom = exchange.SourceSender = exchange.AutodiscoverSmtp = "carol@example.test";
        var otherTarget = await ToolRequestAsync(host.Client, token, "tools/call",
            new { name = "mail_recall_message", arguments = ScopedRecallArguments(host, targetMailbox: "carol@example.test") },
            JulyProtocolVersion, elicitation: true);
        Expect(otherTarget.Body.Contains("recall_confirmation", StringComparison.Ordinal) && exchange.CreateCount == 0,
            "A third selected mailbox inherited the configured recall grant.");
        exchange.SourceFrom = exchange.SourceSender = exchange.AutodiscoverSmtp = "alice@example.test";
        exchange.SourceTo = ["outside@outside.test"];
        var external = await ToolRequestAsync(host.Client, token, "tools/call", new { name = "mail_recall_message", arguments });
        Expect(IsToolError(external.Body) && exchange.CreateCount == 0, "Configured recall bypassed the recipient-domain policy.");
        exchange.SourceTo = ["bob@example.test"];
        var stale = await ToolRequestAsync(host.Client, token, "tools/call",
            new { name = "mail_recall_message", arguments = ScopedRecallArguments(host, changeKey: "stale") });
        Expect(IsToolError(stale.Body) && exchange.CreateCount == 0, "A stale Sent Items handle submitted a configured recall.");
    }

    private async Task AssertScopedRecallGatesAsync()
    {
        var exchange = ScopedRecallExchange();
        await using var host = await StartHostAsync(exchange, true, true, configure: ScopedSendConfiguration(ScopedSendLdap()));
        var arguments = ScopedRecallArguments(host);
        var validToken = EnrollmentToken("user-a", EnrollmentGuidA.ToString("D"), ScopedRecallScopes, clientId: ScopedSendClient);
        await AssertScopedSendProfileAsync(host, validToken);
        var before = exchange.Calls.Count;
        foreach (var token in new[]
        {
            EnrollmentToken("user-a", null, ScopedRecallScopes, clientId: ScopedSendClient),
            EnrollmentToken("user-a", EnrollmentGuidB.ToString("D"), ScopedRecallScopes, clientId: ScopedSendClient),
            EnrollmentToken("user-a", EnrollmentGuidA.ToString("D"), "mail.read mail.manage", clientId: ScopedSendClient),
            EnrollmentToken("user-a", EnrollmentGuidA.ToString("D"), "mail.read mail.send", clientId: ScopedSendClient)
        })
        {
            var rejected = await ToolRequestAsync(host.Client, token, "tools/call", new { name = "mail_recall_message", arguments });
            Expect((rejected.StatusCode != HttpStatusCode.OK || IsToolError(rejected.Body)) && exchange.Calls.Count == before,
                "Configured recall bypassed its GUID, send or manage gate before source preparation.");
        }
        foreach (var gates in new[] { (Writes: false, Send: false), (Writes: true, Send: false) })
        {
            var disabledExchange = ScopedRecallExchange();
            await using var disabledHost = await StartHostAsync(disabledExchange, gates.Writes, gates.Send,
                configure: ScopedSendConfiguration(ScopedSendLdap()));
            await AssertScopedSendProfileAsync(disabledHost, validToken);
            var beforeDisabled = disabledExchange.Calls.Count;
            var disabled = await ToolRequestAsync(disabledHost.Client, validToken,
                "tools/call", new { name = "mail_recall_message", arguments = ScopedRecallArguments(disabledHost) });
            Expect(IsToolError(disabled.Body) && disabledExchange.Calls.Count == beforeDisabled,
                "Configured recall bypassed disabled writes or sending.");
        }
        foreach (var rights in new[] { "denied", "unknown" })
        {
            var deniedExchange = ScopedRecallExchange("bob@example.test");
            var permissions = new SyntheticPermissionReader(Report(new("allowed", "synthetic FullAccess"),
                new(rights, "synthetic SendAs"), new("allowed", "synthetic SendOnBehalf")));
            await using var deniedHost = await StartHostAsync(deniedExchange, true, true,
                configure: ScopedSendConfiguration(ScopedSendLdap(), permissions: permissions));
            await AssertScopedSendProfileAsync(deniedHost, validToken);
            var beforeDenied = deniedExchange.Calls.Count;
            var denied = await ToolRequestAsync(deniedHost.Client,
                EnrollmentToken("user-a", EnrollmentGuidA.ToString("D"), ScopedRecallScopes, clientId: ScopedSendClient),
                "tools/call", new { name = "mail_recall_message", arguments = ScopedRecallArguments(deniedHost, targetMailbox: "bob@example.test") });
            Expect(IsToolError(denied.Body) && deniedExchange.Calls.Count == beforeDenied && permissions.Calls == 1,
                "Configured recall bypassed denied/unknown SendAs with SendOnBehalf permission.");
        }
        var ldap = ScopedSendLdap();
        var changedExchange = ScopedRecallExchange();
        changedExchange.AfterGetItem = () => ldap.Set(EnrollmentGuidA,
            EnrollmentEntry(EnrollmentGuidA, "alice@example.test", userAccountControl: "514"));
        await using var changedHost = await StartHostAsync(changedExchange, true, true, configure: ScopedSendConfiguration(ldap));
        var changed = await ToolRequestAsync(changedHost.Client,
            EnrollmentToken("user-a", EnrollmentGuidA.ToString("D"), ScopedRecallScopes, clientId: ScopedSendClient),
            "tools/call", new { name = "mail_recall_message", arguments = ScopedRecallArguments(changedHost) });
        Expect(IsToolError(changed.Body) && changedExchange.CreateCount == 0
            && changedExchange.Calls.Any(call => call.Operation == "GetItem"),
            "Configured recall did not recheck an actor disabled after source preparation.");
    }

    private async Task AssertScopedRecallContinuationAndReplayAsync()
    {
        foreach (var nativeFirst in new[] { false, true })
        {
            var exchange = ScopedRecallExchange();
            await using var host = await StartHostAsync(exchange, true, true,
                configure: ScopedSendConfiguration(ScopedSendLdap(), enabled: false));
            var token = EnrollmentToken("user-a", EnrollmentGuidA.ToString("D"), ScopedRecallScopes, clientId: ScopedSendClient);
            var arguments = ScopedRecallArguments(host);
            var pending = await ToolRequestAsync(host.Client, token, "tools/call",
                new { name = "mail_recall_message", arguments }, JulyProtocolVersion, elicitation: true);
            var state = InputRequiredState(pending.Body);
            var accepted = new
            {
                name = "mail_recall_message",
                arguments,
                requestState = state,
                inputResponses = new { recall_confirmation = new { action = "accept", content = new { confirm = true } } }
            };
            if (nativeFirst)
            {
                var native = await ToolRequestAsync(host.Client, token, "tools/call", accepted, JulyProtocolVersion, elicitation: true);
                Expect(!IsToolError(native.Body) && exchange.CreateCount == 1, "The native replay fixture did not submit its recall.");
            }
            var options = host.App.Services.GetRequiredService<IOptions<ServiceOptions>>().Value;
            EnableScopedSending(options);
            foreach (var continuation in new object[]
            {
                accepted,
                new { name = "mail_recall_message", arguments, requestState = state,
                    inputResponses = new { recall_confirmation = new { action = "decline", content = new { confirm = false } } } },
                new { name = "mail_recall_message", arguments, requestState = "forged" },
                new { name = "mail_recall_message", arguments, inputResponses = new { } }
            })
            {
                var rejected = await ToolRequestAsync(host.Client, token, "tools/call", continuation, JulyProtocolVersion, elicitation: true);
                Expect(IsToolError(rejected.Body) && exchange.CreateCount == (nativeFirst ? 1 : 0),
                    "Configured recall accepted native continuation state or confirmation input.");
            }
            var fresh = await ToolRequestAsync(host.Client, token, "tools/call", new { name = "mail_recall_message", arguments });
            Expect(IsToolError(fresh.Body) == nativeFirst && exchange.CreateCount == 1,
                "Native and configured recall did not share their durable replay reservation.");
            options.SendWithoutNativeConfirmationActor = "";
            options.SendWithoutNativeConfirmationMailboxes = [];
            options.SendWithoutNativeConfirmationClientIds = [];
            var nativeReplay = await ToolRequestAsync(host.Client, token, "tools/call", accepted, JulyProtocolVersion, elicitation: true);
            Expect(IsToolError(nativeReplay.Body) && exchange.CreateCount == 1,
                "Returning to native approval repeated a configured recall.");
        }
    }

    private async Task AssertScopedRecallUncertainAsync()
    {
        var exchange = ScopedRecallExchange();
        exchange.ThrowOnCreate = true;
        await using var host = await StartHostAsync(exchange, true, true, configure: ScopedSendConfiguration(ScopedSendLdap()));
        var token = EnrollmentToken("user-a", EnrollmentGuidA.ToString("D"), ScopedRecallScopes, clientId: ScopedSendClient);
        var arguments = ScopedRecallArguments(host);
        var first = await ToolRequestAsync(host.Client, token, "tools/call", new { name = "mail_recall_message", arguments });
        var data = ToolStructuredData(first.Body);
        Expect(!IsToolError(first.Body) && data.GetProperty("status").GetString() == "submission_unverified"
            && data.GetProperty("doNotRetryAutomatically").GetBoolean()
            && !string.IsNullOrWhiteSpace(data.GetProperty("recallHandle").GetString()) && exchange.CreateCount == 1,
            "Configured recall changed uncertain submission status or lost its no-retry handle.");
        var replay = await ToolRequestAsync(host.Client, token, "tools/call", new { name = "mail_recall_message", arguments });
        Expect(IsToolError(replay.Body) && exchange.CreateCount == 1, "An uncertain configured recall was submitted again.");
    }

    private static RecordingRecallHandler ScopedRecallExchange(string mailbox = "alice@example.test") => new()
    {
        SourceFrom = mailbox,
        SourceSender = mailbox,
        AutodiscoverSmtp = mailbox,
        SourceTo = ["BOB@example.test"],
        SourceCc = ["ALICE@example.test"],
        SourceBcc = ["bob@example.test"]
    };

    private static Dictionary<string, object?> ScopedRecallArguments(TestHostContext host, string clientId = ScopedSendClient,
        string actorSubject = "user-a", string actorMailbox = "alice@example.test", string? targetMailbox = null,
        string changeKey = "source-change")
    {
        var actor = new MailboxIdentity(actorSubject, actorMailbox, clientId, "test-session", ActorMailbox: actorMailbox);
        var identity = targetMailbox is null ? actor : actor with
        {
            Mailbox = targetMailbox,
            TargetId = targetMailbox == "bob@example.test" ? DiscoveryMailboxKey : ScopedSendThirdTarget
        };
        var handles = host.App.Services.GetRequiredService<MailboxHandles>();
        var result = new Dictionary<string, object?> { ["messageHandle"] = handles.Issue(identity, "message", "sent-message-1", changeKey) };
        if (targetMailbox is not null)
            result["mailboxHandle"] = handles.Issue(actor, "mailbox-target", identity.TargetId,
                MailboxHandles.TargetBinding(actor, targetMailbox));
        return result;
    }

    private Action<WebApplicationBuilder> ScopedSendConfiguration(EnrollmentLdapFactory ldap, bool enabled = true,
        bool autoEnrollment = true, SyntheticPermissionReader? permissions = null) => builder =>
    {
        EnrollmentHostConfiguration(ldap, EnrollmentAuditPath("scoped-send"), enabled: autoEnrollment)(builder);
        var values = new Dictionary<string, string?>
        {
            ["Service:AllowedClientIds:2"] = ScopedSendClient
        };
        if (enabled)
        {
            values["Service:SendWithoutNativeConfirmationActor"] = "alice@example.test";
            values["Service:SendWithoutNativeConfirmationMailboxes:0"] = "alice@example.test";
            values["Service:SendWithoutNativeConfirmationMailboxes:1"] = "bob@example.test";
            values["Service:SendWithoutNativeConfirmationClientIds:0"] = ScopedSendClient;
            values["Service:SendWithoutNativeConfirmationClientIds:1"] = "chatgpt-alt";
        }
        builder.Configuration.AddInMemoryCollection(values);
        var discovery = new TestMailboxDiscovery(false, "user-a", "user-b");
        discovery.AddTarget("user-a", DiscoveryMailboxKey, "bob@example.test");
        discovery.AddTarget("user-a", ScopedSendThirdTarget, "carol@example.test");
        builder.Services.AddSingleton<IMailboxDiscovery>(discovery);
        builder.Services.AddSingleton<IMailboxDirectory>(discovery);
        builder.Services.AddSingleton<IMailboxPermissionReader>(permissions ?? new SyntheticPermissionReader(
            Report(new("allowed", "synthetic"), new("allowed", "synthetic"), new("denied", "synthetic"))));
    };

    private static EnrollmentLdapFactory ScopedSendLdap()
    {
        var ldap = new EnrollmentLdapFactory();
        ldap.Set(EnrollmentGuidA, EnrollmentEntry(EnrollmentGuidA, "alice@example.test"));
        ldap.Set(EnrollmentGuidB, EnrollmentEntry(EnrollmentGuidB, "bob@example.test"));
        return ldap;
    }

    private static void EnableScopedSending(ServiceOptions options)
    {
        options.SendWithoutNativeConfirmationActor = "alice@example.test";
        options.SendWithoutNativeConfirmationMailboxes = ["alice@example.test", "bob@example.test"];
        options.SendWithoutNativeConfirmationClientIds = ["chatgpt-test", "chatgpt-alt"];
        if (options.AllowedClientIds.Contains(ScopedSendClient, StringComparer.Ordinal))
            options.SendWithoutNativeConfirmationClientIds = [ScopedSendClient, "chatgpt-alt"];
    }

    private static Dictionary<string, object?> ScopedSendArguments(TestHostContext host, string clientId = ScopedSendClient,
        string actorSubject = "user-a", string actorMailbox = "alice@example.test", string? targetMailbox = null,
        string changeKey = "draft-change")
    {
        var actor = new MailboxIdentity(actorSubject, actorMailbox, clientId, "test-session", ActorMailbox: actorMailbox);
        var identity = targetMailbox is null ? actor : actor with
        {
            Mailbox = targetMailbox,
            TargetId = targetMailbox == "bob@example.test" ? DiscoveryMailboxKey : ScopedSendThirdTarget
        };
        var handles = host.App.Services.GetRequiredService<MailboxHandles>();
        var result = new Dictionary<string, object?> { ["draftHandle"] = handles.Issue(identity, "message", "draft-1", changeKey) };
        if (targetMailbox is not null)
            result["mailboxHandle"] = handles.Issue(actor, "mailbox-target", identity.TargetId,
                MailboxHandles.TargetBinding(actor, targetMailbox));
        return result;
    }

    private static async Task AssertScopedSendProfileAsync(TestHostContext host, string token)
    {
        var profile = await ToolRequestAsync(host.Client, token, "tools/call", new { name = "mail_profile", arguments = new { } });
        Expect(profile.StatusCode == HttpStatusCode.OK && !IsToolError(profile.Body),
            "The scoped-send fixture could not establish its current GUID-backed actor.");
    }
}

internal sealed class ScopedSendEwsHandler : HttpMessageHandler
{
    private static readonly XNamespace Soap = "http://schemas.xmlsoap.org/soap/envelope/";
    private static readonly XNamespace M = "http://schemas.microsoft.com/exchange/services/2006/messages";
    private static readonly XNamespace T = "http://schemas.microsoft.com/exchange/services/2006/types";
    private int sendCount;
    private int getItemCount;
    public int SendCount => sendCount;
    public int GetItemCount => getItemCount;
    public string FromMailbox { get; set; } = "alice@example.test";
    public string[] To { get; set; } = ["BOB@example.test"];
    public string[] Cc { get; set; } = ["ALICE@example.test"];
    public string[] Bcc { get; set; } = ["bob@example.test"];
    public bool FailSend { get; init; }
    public Action? AfterGetItem { get; init; }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var document = XDocument.Parse(await request.Content!.ReadAsStringAsync(cancellationToken));
        var operation = document.Root!.Element(Soap + "Body")!.Elements().Single();
        XElement? payload = null;
        switch (operation.Name.LocalName)
        {
            case "GetFolder":
                payload = new XElement(M + "Folders", new XElement(T + "Folder",
                    new XElement(T + "FolderId", new XAttribute("Id", "inbox-id"), new XAttribute("ChangeKey", "inbox-change")),
                    new XElement(T + "EffectiveRights", new XElement(T + "Read", true),
                        new XElement(T + "CreateContents", true), new XElement(T + "Modify", true), new XElement(T + "Delete", true))));
                break;
            case "GetItem":
                Interlocked.Increment(ref getItemCount);
                payload = new XElement(M + "Items", new XElement(T + "Message",
                    new XElement(T + "ItemId", new XAttribute("Id", "draft-1"), new XAttribute("ChangeKey", "draft-change")),
                    new XElement(T + "Subject", "Scoped send"),
                    new XElement(T + "From", Recipient(FromMailbox)),
                    new XElement(T + "ToRecipients", To.Select(Recipient)),
                    new XElement(T + "CcRecipients", Cc.Select(Recipient)),
                    new XElement(T + "BccRecipients", Bcc.Select(Recipient)),
                    new XElement(T + "IsDraft", true), new XElement(T + "Body", new XAttribute("BodyType", "Text"), "Synthetic body"),
                    new XElement(T + "Attachments"), new XElement(T + "Categories")));
                AfterGetItem?.Invoke();
                break;
            case "SendItem":
                Interlocked.Increment(ref sendCount);
                if (FailSend) throw new HttpRequestException("Synthetic uncertain submission.");
                break;
            default:
                throw new InvalidOperationException("Unexpected scoped-send fixture operation.");
        }
        var response = new XDocument(new XElement(Soap + "Envelope",
            new XElement(Soap + "Body", new XElement(M + (operation.Name.LocalName + "Response"),
                new XElement(M + "ResponseMessages", new XElement(M + (operation.Name.LocalName + "ResponseMessage"),
                    new XAttribute("ResponseClass", "Success"), new XElement(M + "ResponseCode", "NoError"), payload))))));
        return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(response.ToString(), Encoding.UTF8, "text/xml") };
    }

    private static XElement Recipient(string address) => new(T + "Mailbox", new XElement(T + "EmailAddress", address),
        new XElement(T + "RoutingType", "SMTP"));
}
