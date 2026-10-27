using System.Collections.Concurrent;
using System.DirectoryServices.Protocols;
using System.Net;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using System.Xml.Linq;
using Company.ExchangeMcp.Exchange;
using Company.ExchangeMcp.Security;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

internal sealed partial class Checks
{
    private const string EnrollmentDirectoryDn = "DC=example,DC=test";
    private static readonly Guid EnrollmentGuidA = Guid.Parse("11111111-2222-3333-4444-555555555555");
    private static readonly Guid EnrollmentGuidB = Guid.Parse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");

    internal async Task MailboxEnrollmentChecksAsync()
    {
        await AssertMcpFirstLoginEnrollmentAndIsolationAsync();
        await AssertFirstLoginRejectsUntrustedTokensBeforeDirectoryAccessAsync();
        await AssertStaticMailboxMigrationAndLegacyBehaviorAsync();
        await AssertAuthenticationAdmissionLimiterAsync();
        await AssertInvalidDirectoryAndExchangeEvidenceDoesNotCommitAsync();
        await AssertEnrollmentBindingPersistenceAndRebindChecksAsync();
        await AssertConcurrentEnrollmentCollisionsAndCapacityAsync();
        AssertEnrollmentRegistryFailsClosed();
    }

    private async Task AssertMcpFirstLoginEnrollmentAndIsolationAsync()
    {
        var auditPath = EnrollmentAuditPath("mcp");
        var ldap = new EnrollmentLdapFactory();
        ldap.Set(EnrollmentGuidA, EnrollmentEntry(EnrollmentGuidA, "carol@example.test",
            "smtp:carol.alias@example.test"));
        ldap.Set(EnrollmentGuidB, EnrollmentEntry(EnrollmentGuidB, "dana@example.test",
            "smtp:dana.alias@example.test"));
        var ews = new EnrollmentEwsHandler();
        using (var rightsHttp = new HttpClient(new EnrollmentEwsHandler()))
        {
            var rights = await NewEnrollmentEwsClient(rightsHttp).GetEffectiveRightsAsync(
                "carol@example.test", "inbox", CancellationToken.None);
            Expect(rights.Read == true, "The enrollment EWS fixture did not return readable Inbox EffectiveRights.");
        }
        var introspection = new IntrospectionHandler();
        await using var host = await StartHostAsync(ews, writesEnabled: true, sendEnabled: false,
            introspection: introspection, configure: EnrollmentHostConfiguration(ldap, auditPath));

        var tokenA = EnrollmentToken("keycloak-subject-a", EnrollmentGuidA.ToString("D"),
            extraClaims: [new Claim("email", "attacker@outside.test"), new Claim("preferred_username", "attacker"),
                new Claim("mailbox", "attacker@outside.test"), new Claim("upn", "attacker@outside.test")]);
        var initializeA = await SendMcpAsync(host.Client, tokenA, InitializeBody());
        Expect(initializeA.StatusCode == HttpStatusCode.OK,
            $"MCP initialize failed for a first-login identity (HTTP {(int)initializeA.StatusCode}: {initializeA.Body}; "
            + $"introspection calls={introspection.Calls}, LDAP searches={ldap.Calls.Count}, EWS requests={ews.Calls.Count}).");
        var initializedA = await SendMcpAsync(host.Client, tokenA,
            new { jsonrpc = "2.0", method = "notifications/initialized", @params = new { } });
        Expect((int)initializedA.StatusCode is 200 or 202, "MCP initialized notification failed for first-login identity A.");
        var tools = await ToolRequestAsync(host.Client, tokenA, "tools/list", new { });
        Expect(tools.StatusCode == HttpStatusCode.OK,
            $"A first-login enrolled user could not use MCP tools/list (HTTP {(int)tools.StatusCode}).");

        var enrollment = host.App.Services.GetRequiredService<MailboxEnrollment>();
        Expect(enrollment.TryGet("keycloak-subject-a", out var mailboxA, out var guidA)
            && mailboxA == "carol@example.test" && guidA == EnrollmentGuidA.ToString("D"),
            "First login did not bind the stable Keycloak subject and AD GUID to the directory primary SMTP address.");
        var principalA = EnrollmentPrincipal("keycloak-subject-a", EnrollmentGuidA.ToString("D"),
            extraClaims: [new Claim("email", "attacker@outside.test"), new Claim("preferred_username", "attacker"),
                new Claim("mailbox", "attacker@outside.test")]);
        var actorA = host.App.Services.GetRequiredService<MailboxAccess>().RequireOwn(principalA, MailboxAccess.Read);
        Expect(actorA.Mailbox == "carol@example.test",
            "A first-login user inherited a mailbox from untrusted email/mailbox claims.");
        var mailboxListA = await ToolRequestAsync(host.Client, tokenA, "tools/call", new
        {
            name = "mail_list_mailboxes",
            arguments = new { }
        });
        var mailboxItemsA = JsonArrayProperty(ToolStructuredData(mailboxListA.Body), "items");
        Expect(!IsToolError(mailboxListA.Body) && mailboxItemsA.Length == 1
            && mailboxItemsA[0].GetProperty("mailbox").GetString() == "carol@example.test",
            "A first-login user inherited a delegated target from untrusted email/mailbox claims.");

        var searchA = await ToolRequestAsync(host.Client, tokenA, "tools/call", new
        {
            name = "mail_search",
            arguments = new { folder = "inbox", offset = 0, limit = 20 }
        });
        Expect(searchA.StatusCode == HttpStatusCode.OK && !IsToolError(searchA.Body),
            "The newly enrolled identity could not read its own mailbox through the actual MCP endpoint.");
        JsonElement searchAData;
        try { searchAData = ToolStructuredData(searchA.Body); }
        catch (JsonException exception)
        {
            throw new InvalidOperationException($"MCP mail_search returned non-JSON tool content: {searchA.Body}", exception);
        }
        var handleA = searchAData.GetProperty("items")[0].GetProperty("handle").GetString()!;

        var tokenB = EnrollmentToken("keycloak-subject-b", EnrollmentGuidB.ToString("D"),
            extraClaims: [new Claim("email", "attacker@outside.test"), new Claim("preferred_username", "attacker"),
                new Claim("mailbox", "attacker@outside.test")]);
        Expect(!enrollment.TryGet("keycloak-subject-b", out _, out _),
            "The second first-login identity was already enrolled before its root MCP request.");
        const string rootEndpoint = "https://mail.example.test/";
        await InitializeEnrollmentMcpAsync(host.Client, tokenB, rootEndpoint);
        var toolsB = await ToolRequestAsync(host.Client, tokenB, "tools/list", new { }, absoluteUri: rootEndpoint);
        using var toolsBJson = ParseJson(toolsB.Body);
        Expect(toolsB.StatusCode == HttpStatusCode.OK
            && toolsBJson.RootElement.GetProperty("result").GetProperty("tools").EnumerateArray()
                .Any(tool => tool.GetProperty("name").GetString() == "mail_profile"),
            "A second first-login identity could not discover mailbox tools at the bare MCP URL.");
        var profileB = await ToolRequestAsync(host.Client, tokenB, "tools/call", new
        {
            name = "mail_profile",
            arguments = new { }
        }, absoluteUri: rootEndpoint);
        var profileBData = ToolStructuredData(profileB.Body);
        Expect(profileB.StatusCode == HttpStatusCode.OK && !IsToolError(profileB.Body)
            && profileBData.GetProperty("mailbox").GetString() == "dana@example.test"
            && profileBData.GetProperty("actorMailbox").GetString() == "dana@example.test",
            "The bare-root mail_profile did not report the second employee's directory-verified mailbox.");
        var searchB = await ToolRequestAsync(host.Client, tokenB, "tools/call", new
        {
            name = "mail_search",
            arguments = new { folder = "inbox", offset = 0, limit = 20 }
        }, absoluteUri: rootEndpoint);
        Expect(searchB.StatusCode == HttpStatusCode.OK && !IsToolError(searchB.Body),
            "A second first-login identity could not use its own mailbox.");

        var ewsBeforeCrossMailboxHandle = ews.Calls.Count;
        var crossMailboxRead = await ToolRequestAsync(host.Client, tokenB, "tools/call", new
        {
            name = "mail_read",
            arguments = new { messageHandle = handleA }
        });
        Expect(IsToolError(crossMailboxRead.Body) && ews.Calls.Count == ewsBeforeCrossMailboxHandle,
            "A newly enrolled user reused another user's mailbox handle or reached EWS.");

        var directoryLookups = ldap.Calls.ToArray();
        Expect(enrollment.Snapshot().OrderBy(actor => actor.Subject, StringComparer.Ordinal).SequenceEqual([
                ("keycloak-subject-a", "carol@example.test"), ("keycloak-subject-b", "dana@example.test")]),
            "First login did not enroll exactly the two authenticated directory users.");
        Expect(directoryLookups.All(call => call.BaseDn == EnrollmentDirectoryDn
                && call.Scope == SearchScope.Subtree && !call.RequestDaclOnly
                && call.Attributes.ToHashSet(StringComparer.OrdinalIgnoreCase).SetEquals([
                    "objectGUID", "userAccountControl", "msExchRecipientTypeDetails", "proxyAddresses",
                    "legacyExchangeDN", "homeMDB"])),
            "Enrollment queried outside its bounded base or requested unexpected LDAP evidence.");
        Expect(directoryLookups.Any(call => call.Filter == EnrollmentGuidFilter(EnrollmentGuidA))
            && directoryLookups.Any(call => call.Filter == EnrollmentGuidFilter(EnrollmentGuidB)),
            "Enrollment did not search with the exact escaped objectGUID and user/person LDAP filter.");
        Expect(ews.Calls.Any(call => call.Operation == "GetFolder" && call.AnchorMailbox == "carol@example.test")
            && ews.Calls.Any(call => call.Operation == "FindItem" && call.AnchorMailbox == "carol@example.test")
            && ews.Calls.Any(call => call.Operation == "GetFolder" && call.AnchorMailbox == "dana@example.test")
            && ews.Calls.Any(call => call.Operation == "FindItem" && call.AnchorMailbox == "dana@example.test")
            && ews.Calls.All(call => call.Authorization is null),
            "EWS did not use each directory-resolved primary SMTP identity, or the MCP bearer token crossed to Exchange.");

        var registryPath = auditPath + ".enrollments.json";
        using var registry = JsonDocument.Parse(await File.ReadAllTextAsync(registryPath));
        var registryText = await File.ReadAllTextAsync(registryPath);
        Expect(registry.RootElement.GetProperty("issuer").GetString() == Authority
            && registry.RootElement.GetProperty("records").GetArrayLength() == 2
            && !registryText.Contains("attacker@outside.test", StringComparison.OrdinalIgnoreCase)
            && !registryText.Contains("carol.alias", StringComparison.OrdinalIgnoreCase),
            "The server registry did not persist issuer-scoped directory bindings without claim-derived aliases.");
    }

    private async Task AssertFirstLoginRejectsUntrustedTokensBeforeDirectoryAccessAsync()
    {
        var ldap = new EnrollmentLdapFactory();
        ldap.Set(EnrollmentGuidA, EnrollmentEntry(EnrollmentGuidA, "carol@example.test"));
        var ews = new EnrollmentEwsHandler();
        var auditPath = EnrollmentAuditPath("token-guard");
        await using var host = await StartHostAsync(ews, writesEnabled: true, sendEnabled: false,
            configure: EnrollmentHostConfiguration(ldap, auditPath));

        var rejected = new[]
        {
            (Token: EnrollmentToken("missing-guid", null), Status: HttpStatusCode.Unauthorized),
            (Token: EnrollmentToken("malformed-guid", "not-a-guid"), Status: HttpStatusCode.Unauthorized),
            (Token: EnrollmentToken("duplicate-guid", EnrollmentGuidA.ToString("D"),
                extraClaims: [new Claim(MailboxEnrollment.DirectoryGuidClaim, EnrollmentGuidB.ToString("D"))]), Status: HttpStatusCode.Unauthorized),
            (Token: EnrollmentToken("wrong-issuer", EnrollmentGuidA.ToString("D"), issuer: "https://other.example.test/realm"), Status: HttpStatusCode.Unauthorized),
            (Token: EnrollmentToken("wrong-client", EnrollmentGuidA.ToString("D"), clientId: "unapproved-client"), Status: HttpStatusCode.Unauthorized),
            (Token: EnrollmentToken("missing-read-scope", EnrollmentGuidA.ToString("D"), scope: "mail.write"), Status: HttpStatusCode.Forbidden)
        };
        foreach (var item in rejected)
        {
            var response = await SendMcpAsync(host.Client, item.Token, InitializeBody());
            Expect(response.StatusCode == item.Status,
                $"First-login token guard returned HTTP {(int)response.StatusCode} instead of {(int)item.Status}.");
        }
        Expect(ldap.Calls.Count == 0 && ews.Calls.Count == 0
            && !File.Exists(auditPath + ".enrollments.json"),
            "An untrusted, unmapped, or read-scope-free token reached LDAP/EWS or created an enrollment.");

        foreach (var mode in new[] { "missing-guid", "mismatch-guid" })
        {
            var modeLdap = new EnrollmentLdapFactory();
            modeLdap.Set(EnrollmentGuidA, EnrollmentEntry(EnrollmentGuidA, "carol@example.test"));
            var modeEws = new EnrollmentEwsHandler();
            var modeAudit = EnrollmentAuditPath(mode);
            await using var modeHost = await StartHostAsync(modeEws, writesEnabled: true, sendEnabled: false,
                introspection: new IntrospectionHandler { Mode = mode },
                configure: EnrollmentHostConfiguration(modeLdap, modeAudit));
            var response = await SendMcpAsync(modeHost.Client,
                EnrollmentToken("introspection-mismatch", EnrollmentGuidA.ToString("D")), InitializeBody());
            Expect(response.StatusCode == HttpStatusCode.Unauthorized
                && modeLdap.Calls.Count == 0 && modeEws.Calls.Count == 0,
                $"Keycloak introspection mode '{mode}' did not reject enrollment before LDAP/EWS.");
        }
    }

    private async Task AssertStaticMailboxMigrationAndLegacyBehaviorAsync()
    {
        var missingLdap = new EnrollmentLdapFactory();
        missingLdap.Set(EnrollmentGuidA, EnrollmentEntry(EnrollmentGuidA, "alice@example.test"));
        var missingEws = new EnrollmentEwsHandler();
        var missingAudit = EnrollmentAuditPath("static-missing-guid");
        await using (var missingHost = await StartHostAsync(missingEws, writesEnabled: true, sendEnabled: false,
            configure: EnrollmentHostConfiguration(missingLdap, missingAudit)))
        {
            var missing = await SendMcpAsync(missingHost.Client,
                EnrollmentToken("user-a", null), InitializeBody());
            Expect(missing.StatusCode == HttpStatusCode.Unauthorized
                && missingLdap.Calls.Count == 0 && missingEws.Calls.Count == 0
                && !File.Exists(missingAudit + ".enrollments.json"),
                "Auto-enrollment accepted a statically mapped identity without the protected AD GUID claim.");
        }

        var ldap = new EnrollmentLdapFactory();
        ldap.Set(EnrollmentGuidA, EnrollmentEntry(EnrollmentGuidA, "alice@example.test"));
        var ews = new EnrollmentEwsHandler();
        var auditPath = EnrollmentAuditPath("static-migration");
        var configure = EnrollmentHostConfiguration(ldap, auditPath);
        await using (var host = await StartHostAsync(ews, writesEnabled: true, sendEnabled: false,
            configure: configure))
        {
            var migration = EnrollmentToken("user-a", EnrollmentGuidA.ToString("D"));
            await InitializeEnrollmentMcpAsync(host.Client, migration);
            var enrollment = host.App.Services.GetRequiredService<MailboxEnrollment>();
            Expect(enrollment.TryGet("user-a", out var mailbox, out var objectGuid)
                && mailbox == "alice@example.test" && objectGuid == EnrollmentGuidA.ToString("D"),
                "A matching legacy static subject was not migrated to its verified AD GUID binding.");

            var otherStaticUser = await SendMcpAsync(host.Client,
                EnrollmentToken("user-b", EnrollmentGuidA.ToString("D")), InitializeBody());
            Expect(otherStaticUser.StatusCode == HttpStatusCode.Unauthorized
                && ldap.Calls.Count == 4 && ews.Calls.Count == 1
                && enrollment.Snapshot().SequenceEqual([("user-a", "alice@example.test")]),
                $"A subject mapped to a different legacy mailbox claimed the existing user's Exchange mailbox "
                + $"(HTTP {(int)otherStaticUser.StatusCode}, LDAP {ldap.Calls.Count}, EWS {ews.Calls.Count}).");

            using var registry = JsonDocument.Parse(await File.ReadAllTextAsync(auditPath + ".enrollments.json"));
            Expect(registry.RootElement.GetProperty("records").GetArrayLength() == 1
                && registry.RootElement.GetProperty("records")[0].GetProperty("subject").GetString() == "user-a",
                "Static migration persisted a conflicting or extra enrollment record.");
        }

        var restartedLdap = new EnrollmentLdapFactory();
        restartedLdap.Set(EnrollmentGuidA, EnrollmentEntry(EnrollmentGuidA, "alice@example.test"));
        var restartedEws = new EnrollmentEwsHandler();
        await using (var restarted = await StartHostAsync(restartedEws, writesEnabled: true, sendEnabled: false,
            configure: EnrollmentHostConfiguration(restartedLdap, auditPath)))
        {
            var migratedToken = EnrollmentToken("user-a", EnrollmentGuidA.ToString("D"));
            await InitializeEnrollmentMcpAsync(restarted.Client, migratedToken);
            var migratedAccess = restarted.App.Services.GetRequiredService<MailboxAccess>();
            var migratedActor = migratedAccess.RequireOwn(
                EnrollmentPrincipal("user-a", EnrollmentGuidA.ToString("D")), MailboxAccess.Read);
            Expect(await migratedAccess.VerifyCurrentActorAsync(migratedActor, CancellationToken.None),
                "A worker-facing actor check rejected a freshly bound, current static-mailbox migration.");

            restartedLdap.Set(EnrollmentGuidA,
                EnrollmentEntry(EnrollmentGuidA, "alice@example.test", userAccountControl: "514"));
            Expect(!await migratedAccess.VerifyCurrentActorAsync(migratedActor, CancellationToken.None),
                "A worker-facing actor check accepted an AD-disabled migrated mailbox owner.");
            restartedLdap.Set(EnrollmentGuidA, EnrollmentEntry(EnrollmentGuidA, "alice@example.test"));
            Expect(await migratedAccess.VerifyCurrentActorAsync(migratedActor, CancellationToken.None),
                "A worker-facing actor check did not recover after the same AD identity was re-enabled.");

            Expect(restarted.App.Services.GetRequiredService<MailboxEnrollment>().Snapshot()
                    .SequenceEqual([("user-a", "alice@example.test")])
                && restartedLdap.Calls.Count == 5 && restartedEws.Calls.Count == 0,
                "A migrated static identity did not load and revalidate without repeating Exchange preflight.");

            restartedLdap.Set(EnrollmentGuidA, EnrollmentEntry(EnrollmentGuidA, "new-alice@example.test"));
            var rebind = await SendMcpAsync(restarted.Client,
                EnrollmentToken("user-a", EnrollmentGuidA.ToString("D")), InitializeBody());
            Expect(rebind.StatusCode == HttpStatusCode.Unauthorized
                && !await migratedAccess.VerifyCurrentActorAsync(migratedActor, CancellationToken.None)
                && restarted.App.Services.GetRequiredService<MailboxEnrollment>().Snapshot()
                    .SequenceEqual([("user-a", "alice@example.test")])
                && restartedEws.Calls.Count == 0,
                "A migrated static binding silently followed an AD primary-SMTP rename.");
        }

        var staticLdap = new EnrollmentLdapFactory();
        var staticEws = new EnrollmentEwsHandler();
        var staticAudit = EnrollmentAuditPath("static-disabled");
        await using var staticHost = await StartHostAsync(staticEws, writesEnabled: true, sendEnabled: false,
            configure: EnrollmentHostConfiguration(staticLdap, staticAudit, enabled: false));
        var staticToken = EnrollmentToken("user-a", null);
        await InitializeEnrollmentMcpAsync(staticHost.Client, staticToken);
        var staticSearch = await ToolRequestAsync(staticHost.Client, staticToken, "tools/call", new
        {
            name = "mail_search",
            arguments = new { folder = "inbox", offset = 0, limit = 20 }
        });
        Expect(staticSearch.StatusCode == HttpStatusCode.OK && !IsToolError(staticSearch.Body)
            && staticLdap.Calls.Count == 0 && staticEws.Calls.Any(call => call.Operation == "FindItem")
            && !File.Exists(staticAudit + ".enrollments.json"),
            "Disabling enrollment broke the legacy static mailbox path or unexpectedly queried LDAP/persisted state.");
    }

    private async Task AssertAuthenticationAdmissionLimiterAsync()
    {
        var ldap = new EnrollmentLdapFactory();
        ldap.Set(EnrollmentGuidA, EnrollmentEntry(EnrollmentGuidA, "carol@example.test"));
        var ews = new EnrollmentEwsHandler();
        var introspection = new BlockingEnrollmentIntrospectionHandler();
        var auditPath = EnrollmentAuditPath("auth-admission");
        await using var host = await StartHostAsync(ews, writesEnabled: true, sendEnabled: false,
            configure: builder =>
            {
                EnrollmentHostConfiguration(ldap, auditPath)(builder);
                builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
                { ["Service:ConcurrentTransports"] = "1" });
                builder.Services.AddHttpClient<Company.ExchangeMcp.Security.KeycloakTokenStatus>()
                    .ConfigurePrimaryHttpMessageHandler(() => introspection);
            });

        var token = EnrollmentToken("limited-subject", EnrollmentGuidA.ToString("D"));
        const string rootEndpoint = "https://mail.example.test/";
        var firstRequest = SendMcpAsync(host.Client, token, InitializeBody(), absoluteUri: rootEndpoint);
        await introspection.WaitUntilCalledAsync(TimeSpan.FromSeconds(5));
        var rejected = await SendMcpAsync(host.Client, token, InitializeBody(), absoluteUri: rootEndpoint);
        Expect(rejected.StatusCode == HttpStatusCode.TooManyRequests && introspection.Calls == 1
            && ldap.Calls.Count == 0 && ews.Calls.Count == 0,
            "A saturated pre-authentication admission limit queued or authenticated a second unauthenticated request.");
        using (var rejectionJson = JsonDocument.Parse(rejected.Body))
            Expect(rejectionJson.RootElement.GetProperty("reason").GetString() == "preauth_capacity",
                "The pre-authentication rejection did not identify its admission phase.");

        introspection.Release();
        var first = await firstRequest.WaitAsync(TimeSpan.FromSeconds(10));
        Expect(first.StatusCode == HttpStatusCode.OK,
            $"The admitted first-login request did not complete after authentication resumed (HTTP {(int)first.StatusCode}).");
        var afterRelease = await ToolRequestAsync(host.Client, token, "tools/list", new { }, absoluteUri: rootEndpoint);
        Expect(afterRelease.StatusCode == HttpStatusCode.OK && introspection.Calls == 2,
            "The pre-authentication permit was not released after the first request completed.");
    }

    private async Task AssertInvalidDirectoryAndExchangeEvidenceDoesNotCommitAsync()
    {
        var scenarios = new (string Name, LdapSearchEntry[] Rows)[]
        {
            ("disabled AD account", [EnrollmentEntry(EnrollmentGuidA, "carol@example.test", userAccountControl: "514")]),
            ("non-user mailbox", [EnrollmentEntry(EnrollmentGuidA, "carol@example.test", recipientType: "4")]),
            ("unapproved SMTP domain", [EnrollmentEntry(EnrollmentGuidA, "carol@outside.example")]),
            ("multiple primary SMTP values", [EnrollmentEntry(EnrollmentGuidA, "carol@example.test", "SMTP:other@example.test")]),
            ("malformed objectGUID bytes", [EnrollmentEntry(EnrollmentGuidB, "carol@example.test")]),
            ("duplicate LDAP rows", [EnrollmentEntry(EnrollmentGuidA, "carol@example.test"), EnrollmentEntry(EnrollmentGuidA, "carol@example.test")]),
            ("missing Exchange mailbox identity", [EnrollmentEntry(EnrollmentGuidA, "carol@example.test", omitHomeMdb: true)]),
            ("missing primary SMTP", [EnrollmentEntry(EnrollmentGuidA, "carol@example.test", primaryAddresses: [])])
        };

        foreach (var scenario in scenarios)
        {
            var context = NewEnrollmentContext($"invalid-{scenario.Name}");
            context.Ldap.Set(EnrollmentGuidA, scenario.Rows);
            using var http = new HttpClient(new EnrollmentEwsHandler());
            var enrolled = await context.Enrollment.EnsureAsync(
                EnrollmentPrincipal($"invalid-{scenario.Name}", EnrollmentGuidA.ToString("D")),
                NewEnrollmentEwsClient(http), context.Access, CancellationToken.None);
            Expect(!enrolled && context.Enrollment.Snapshot().Count == 0
                && !File.Exists(context.RegistryPath),
                $"Invalid directory evidence '{scenario.Name}' was enrolled or persisted.");
            Expect(context.Ldap.Calls.Count == 1,
                $"Invalid directory evidence '{scenario.Name}' did not make exactly one bounded lookup.");
        }

        var noRow = NewEnrollmentContext("directory-not-found");
        using (var http = new HttpClient(new EnrollmentEwsHandler()))
        {
            var enrolled = await noRow.Enrollment.EnsureAsync(
                EnrollmentPrincipal("directory-not-found", EnrollmentGuidA.ToString("D")),
                NewEnrollmentEwsClient(http), noRow.Access, CancellationToken.None);
            Expect(!enrolled && noRow.Ldap.Calls.Count == 1 && noRow.Enrollment.Snapshot().Count == 0,
                "A missing directory object was enrolled.");
        }

        var ldapFailure = NewEnrollmentContext("ldap-failure");
        ldapFailure.Ldap.ThrowOnSearch = true;
        using (var http = new HttpClient(new EnrollmentEwsHandler()))
        {
            var enrolled = await ldapFailure.Enrollment.EnsureAsync(
                EnrollmentPrincipal("ldap-failure", EnrollmentGuidA.ToString("D")),
                NewEnrollmentEwsClient(http), ldapFailure.Access, CancellationToken.None);
            Expect(!enrolled && ldapFailure.Ldap.Calls.Count == 1 && ldapFailure.Enrollment.Snapshot().Count == 0
                && !File.Exists(ldapFailure.RegistryPath),
                "An LDAP outage created or persisted a mailbox enrollment.");
        }

        var denied = NewEnrollmentContext("ews-denied");
        denied.Ldap.Set(EnrollmentGuidA, EnrollmentEntry(EnrollmentGuidA, "carol@example.test"));
        var deniedEws = new EnrollmentEwsHandler(read: false);
        using (var http = new HttpClient(deniedEws))
        {
            var enrolled = await denied.Enrollment.EnsureAsync(
                EnrollmentPrincipal("ews-denied", EnrollmentGuidA.ToString("D")),
                NewEnrollmentEwsClient(http), denied.Access, CancellationToken.None);
            Expect(!enrolled && denied.Ldap.Calls.Count == 1 && deniedEws.Calls.Count == 1
                && denied.Enrollment.Snapshot().Count == 0 && !File.Exists(denied.RegistryPath),
                "Enrollment persisted before Exchange confirmed Inbox read access.");
        }

        var exchangeFailure = NewEnrollmentContext("ews-failure");
        exchangeFailure.Ldap.Set(EnrollmentGuidA, EnrollmentEntry(EnrollmentGuidA, "carol@example.test"));
        var failedEws = new EnrollmentEwsHandler(throwOnGetFolder: true);
        using (var http = new HttpClient(failedEws))
        {
            var enrolled = await exchangeFailure.Enrollment.EnsureAsync(
                EnrollmentPrincipal("ews-failure", EnrollmentGuidA.ToString("D")),
                NewEnrollmentEwsClient(http), exchangeFailure.Access, CancellationToken.None);
            Expect(!enrolled && failedEws.Calls.Count == 1 && exchangeFailure.Ldap.Calls.Count == 1
                && exchangeFailure.Enrollment.Snapshot().Count == 0 && !File.Exists(exchangeFailure.RegistryPath),
                "An Exchange preflight failure created a server-side enrollment.");
        }

        var disabled = NewEnrollmentContext("enrollment-disabled", enabled: false);
        disabled.Ldap.Set(EnrollmentGuidA, EnrollmentEntry(EnrollmentGuidA, "carol@example.test"));
        using (var http = new HttpClient(new EnrollmentEwsHandler()))
        {
            var enrolled = await disabled.Enrollment.EnsureAsync(
                EnrollmentPrincipal("enrollment-disabled", EnrollmentGuidA.ToString("D")),
                NewEnrollmentEwsClient(http), disabled.Access, CancellationToken.None);
            Expect(!enrolled && disabled.Ldap.Calls.Count == 0 && disabled.Enrollment.Snapshot().Count == 0,
                "Automatic enrollment ran while explicitly disabled.");
        }
    }

    private async Task AssertEnrollmentBindingPersistenceAndRebindChecksAsync()
    {
        var context = NewEnrollmentContext("binding-persistence");
        var original = EnrollmentEntry(EnrollmentGuidA, "carol@example.test");
        context.Ldap.Set(EnrollmentGuidA, original);
        var principal = EnrollmentPrincipal("stable-keycloak-sub", EnrollmentGuidA.ToString("D"),
            extraClaims: [new Claim("email", "attacker@example.test"), new Claim("preferred_username", "attacker"),
                new Claim("mail", "attacker@example.test"), new Claim("mailbox", "attacker@example.test")]);
        var ews = new EnrollmentEwsHandler();
        using (var http = new HttpClient(ews))
        {
            Expect(await context.Enrollment.EnsureAsync(principal, NewEnrollmentEwsClient(http), context.Access,
                    CancellationToken.None), "A valid directory user could not be enrolled.");
        }

        using var saved = JsonDocument.Parse(await File.ReadAllTextAsync(context.RegistryPath));
        var savedRoot = saved.RootElement;
        Expect(savedRoot.GetProperty("schemaVersion").GetInt32() == 1
            && savedRoot.GetProperty("issuer").GetString() == Authority
            && savedRoot.GetProperty("records").GetArrayLength() == 1
            && savedRoot.GetProperty("records")[0].GetProperty("subject").GetString() == "stable-keycloak-sub"
            && savedRoot.GetProperty("records")[0].GetProperty("objectGuid").GetString() == EnrollmentGuidA.ToString("D")
            && savedRoot.GetProperty("records")[0].GetProperty("mailbox").GetString() == "carol@example.test"
            && !File.ReadAllText(context.RegistryPath).Contains("attacker", StringComparison.OrdinalIgnoreCase),
            "The enrollment registry did not save only the issuer, stable subject, AD GUID and canonical primary SMTP.");

        var restartedLdap = new EnrollmentLdapFactory();
        restartedLdap.Set(EnrollmentGuidA, original);
        var restarted = NewEnrollmentContext("binding-restart", auditPath: context.AuditPath, ldap: restartedLdap);
        Expect(restarted.Enrollment.Snapshot().SequenceEqual([("stable-keycloak-sub", "carol@example.test")])
            && restartedLdap.Calls.Count == 0,
            "A valid registry binding was not loaded across a service restart.");
        using (var http = new HttpClient(new EnrollmentEwsHandler()))
        {
            Expect(await restarted.Enrollment.EnsureAsync(principal, NewEnrollmentEwsClient(http), restarted.Access,
                    CancellationToken.None)
                && restartedLdap.Calls.Count == 1,
                "A persisted user was not revalidated against the same AD GUID and primary SMTP on login.");
        }
        Expect(await restarted.Enrollment.VerifyCurrentAsync("stable-keycloak-sub", "carol@example.test", CancellationToken.None),
            "A valid persisted mailbox mapping failed its live AD identity check.");

        var changedSubjectGuid = EnrollmentPrincipal("stable-keycloak-sub", EnrollmentGuidB.ToString("D"));
        using (var http = new HttpClient(new EnrollmentEwsHandler()))
        {
            Expect(!await restarted.Enrollment.EnsureAsync(changedSubjectGuid, NewEnrollmentEwsClient(http),
                    restarted.Access, CancellationToken.None)
                && restarted.Enrollment.Snapshot().Single().Mailbox == "carol@example.test",
                "A Keycloak subject was rebound to a different AD objectGUID.");
        }

        restartedLdap.Set(EnrollmentGuidA, EnrollmentEntry(EnrollmentGuidA, "renamed@example.test"));
        using (var http = new HttpClient(new EnrollmentEwsHandler()))
        {
            Expect(!await restarted.Enrollment.EnsureAsync(principal, NewEnrollmentEwsClient(http), restarted.Access,
                    CancellationToken.None)
                && !await restarted.Enrollment.VerifyCurrentAsync("stable-keycloak-sub", "carol@example.test", CancellationToken.None)
                && restarted.Enrollment.Snapshot().Single().Mailbox == "carol@example.test",
                "An AD primary SMTP rebind remained authorized or silently changed the immutable enrollment.");
        }

        var otherIssuerOptions = EnrollmentServiceOptions(context.AuditPath);
        otherIssuerOptions.Authority = "https://other.example.test/realms/company";
        var otherIssuerFailedClosed = false;
        try
        {
            _ = new MailboxEnrollment(Options.Create(otherIssuerOptions), Options.Create(EnrollmentDirectoryOptions()),
                new EnrollmentLdapFactory());
        }
        catch (InvalidDataException) { otherIssuerFailedClosed = true; }
        Expect(otherIssuerFailedClosed,
            "A server enrollment registry created under a different Keycloak issuer was trusted.");
    }

    private async Task AssertConcurrentEnrollmentCollisionsAndCapacityAsync()
    {
        var concurrent = NewEnrollmentContext("concurrent");
        concurrent.Ldap.Set(EnrollmentGuidA, EnrollmentEntry(EnrollmentGuidA, "carol@example.test"));
        var principal = EnrollmentPrincipal("concurrent-subject", EnrollmentGuidA.ToString("D"));
        var ews = new EnrollmentEwsHandler();
        using (var http = new HttpClient(ews))
        {
            var tasks = Enumerable.Range(0, 8).Select(_ => concurrent.Enrollment.EnsureAsync(
                principal, NewEnrollmentEwsClient(http), concurrent.Access, CancellationToken.None));
            var results = await Task.WhenAll(tasks);
            Expect(results.All(result => result) && concurrent.Enrollment.Snapshot().Count == 1
                && concurrent.Ldap.Calls.Count == 9 && ews.Calls.Count == 1,
                "Concurrent first logins duplicated, skipped, or over-probed the single mailbox enrollment.");
        }

        var collision = NewEnrollmentContext("collision");
        collision.Ldap.Set(EnrollmentGuidA, EnrollmentEntry(EnrollmentGuidA, "carol@example.test"));
        collision.Ldap.Set(EnrollmentGuidB, EnrollmentEntry(EnrollmentGuidB, "carol@example.test"));
        var collisionEws = new EnrollmentEwsHandler();
        using (var http = new HttpClient(collisionEws))
        {
            Expect(await collision.Enrollment.EnsureAsync(
                EnrollmentPrincipal("first-subject", EnrollmentGuidA.ToString("D")),
                NewEnrollmentEwsClient(http), collision.Access, CancellationToken.None),
                "The initial unique directory mailbox could not be enrolled.");
            Expect(!await collision.Enrollment.EnsureAsync(
                EnrollmentPrincipal("second-subject", EnrollmentGuidB.ToString("D")),
                NewEnrollmentEwsClient(http), collision.Access, CancellationToken.None),
                "A second Keycloak subject claimed the same canonical mailbox.");
            Expect(collision.Enrollment.Snapshot().Count == 1 && collisionEws.Calls.Count == 1,
                "Mailbox collision handling changed persisted state or reached Exchange again.");
        }

        var capacityAudit = EnrollmentAuditPath("capacity");
        Directory.CreateDirectory(Path.GetDirectoryName(capacityAudit)!);
        var fullRecords = Enumerable.Range(0, 1024).Select(index => new
        {
            subject = $"existing-subject-{index:D4}",
            objectGuid = GuidFromIndex(index).ToString("D"),
            mailbox = $"person{index:D4}@example.test"
        }).ToArray();
        await File.WriteAllBytesAsync(capacityAudit + ".enrollments.json", JsonSerializer.SerializeToUtf8Bytes(new
        {
            schemaVersion = 1,
            issuer = Authority,
            records = fullRecords
        }));
        var capacityLdap = new EnrollmentLdapFactory();
        var capacity = NewEnrollmentContext("capacity", auditPath: capacityAudit, ldap: capacityLdap);
        var capacityEws = new EnrollmentEwsHandler();
        using (var http = new HttpClient(capacityEws))
        {
            Expect(!await capacity.Enrollment.EnsureAsync(
                EnrollmentPrincipal("one-too-many", EnrollmentGuidA.ToString("D")),
                NewEnrollmentEwsClient(http), capacity.Access, CancellationToken.None)
                && capacity.Enrollment.Snapshot().Count == 1024
                && capacityLdap.Calls.Count == 0 && capacityEws.Calls.Count == 0,
                "The 1024-user registry limit was not enforced before LDAP/EWS or allowed an extra record.");
        }
    }

    private void AssertEnrollmentRegistryFailsClosed()
    {
        foreach (var contents in new[]
        {
            "{",
            "{\"schemaVersion\":2,\"issuer\":\"" + Authority + "\",\"records\":[]}",
            "{\"schemaVersion\":1,\"issuer\":\"" + Authority + "\",\"issuer\":\"" + Authority + "\",\"records\":[]}",
            "{\"schemaVersion\":1,\"issuer\":\"https://other.example.test/realm\",\"records\":[]}"
        })
        {
            var auditPath = EnrollmentAuditPath("registry-invalid");
            Directory.CreateDirectory(Path.GetDirectoryName(auditPath)!);
            File.WriteAllText(auditPath + ".enrollments.json", contents);
            var failedClosed = false;
            try
            {
                _ = NewEnrollmentContext("registry-invalid", auditPath: auditPath);
            }
            catch (Exception exception) when (exception is InvalidDataException or JsonException) { failedClosed = true; }
            Expect(failedClosed, "A corrupt, unsupported, duplicate-field, or wrong-issuer enrollment registry was accepted.");
        }

        var oversizedAudit = EnrollmentAuditPath("registry-oversized");
        Directory.CreateDirectory(Path.GetDirectoryName(oversizedAudit)!);
        using (var stream = new FileStream(oversizedAudit + ".enrollments.json", FileMode.CreateNew, FileAccess.Write))
            stream.SetLength(1_048_577);
        var oversizedFailedClosed = false;
        try { _ = NewEnrollmentContext("registry-oversized", auditPath: oversizedAudit); }
        catch (InvalidDataException) { oversizedFailedClosed = true; }
        Expect(oversizedFailedClosed, "An enrollment registry larger than one MiB was loaded.");
    }

    private Action<WebApplicationBuilder> EnrollmentHostConfiguration(EnrollmentLdapFactory ldap, string auditPath,
        bool enabled = true) => builder =>
    {
        builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Service:AutoEnrollmentEnabled"] = enabled.ToString(),
            ["Service:AllowedRecipientDomains:0"] = "example.test",
            ["Service:AuditPath"] = auditPath,
            ["DirectoryPermissions:Host"] = "ldap.example.test",
            ["DirectoryPermissions:Port"] = "636",
            ["DirectoryPermissions:BaseDn"] = EnrollmentDirectoryDn,
            ["DirectoryPermissions:TimeoutSeconds"] = "8"
        });
        builder.Services.AddSingleton<ILdapSearchFacadeFactory>(ldap);
        var discovery = new TestMailboxDiscovery(false, "keycloak-subject-a", "keycloak-subject-b");
        builder.Services.AddSingleton<IMailboxDiscovery>(discovery);
        builder.Services.AddSingleton<IMailboxDirectory>(discovery);
    };

    private static async Task InitializeEnrollmentMcpAsync(HttpClient client, string token, string? absoluteUri = null)
    {
        var response = await SendMcpAsync(client, token, InitializeBody(), absoluteUri: absoluteUri);
        Expect(response.StatusCode == HttpStatusCode.OK,
            $"MCP initialize failed for a first-login identity (HTTP {(int)response.StatusCode}: {response.Body}).");
        var notification = await SendMcpAsync(client, token,
            new { jsonrpc = "2.0", method = "notifications/initialized", @params = new { } }, absoluteUri: absoluteUri);
        Expect((int)notification.StatusCode is 200 or 202,
            $"MCP initialized notification failed for a first-login identity (HTTP {(int)notification.StatusCode}).");
    }

    private EnrollmentContext NewEnrollmentContext(string name, bool enabled = true, string? auditPath = null,
        EnrollmentLdapFactory? ldap = null)
    {
        var path = auditPath ?? EnrollmentAuditPath(name);
        var service = EnrollmentServiceOptions(path);
        service.AutoEnrollmentEnabled = enabled;
        var directory = EnrollmentDirectoryOptions();
        var factory = ldap ?? new EnrollmentLdapFactory();
        var enrollment = new MailboxEnrollment(Options.Create(service), Options.Create(directory), factory);
        var access = new MailboxAccess(Options.Create(service), enrollment);
        return new(path, factory, enrollment, access);
    }

    private ServiceOptions EnrollmentServiceOptions(string auditPath) => new()
    {
        Authority = Authority,
        Resource = Resource,
        IntrospectionClientId = Resource,
        IntrospectionSecretFile = Path.Combine(runDirectory, "keycloak-introspection-secret.txt"),
        AllowedClientIds = ["chatgpt-test", "chatgpt-alt"],
        Mailboxes = new(StringComparer.Ordinal)
        {
            ["user-a"] = "alice@example.test",
            ["user-b"] = "bob@example.test"
        },
        MailboxTargets = new(StringComparer.Ordinal),
        AutoEnrollmentEnabled = true,
        AllowedRecipientDomains = ["example.test"],
        AuditPath = auditPath,
        WritesEnabled = true,
        SendEnabled = false
    };

    private static DirectoryPermissionOptions EnrollmentDirectoryOptions() => new()
    {
        Host = "ldap.example.test",
        Port = 636,
        BaseDn = EnrollmentDirectoryDn,
        TimeoutSeconds = 8
    };

    private EwsClient NewEnrollmentEwsClient(HttpClient http) => new(http,
        Options.Create(new EwsOptions
        {
            Endpoint = "https://mail.example.test/EWS/Exchange.asmx",
            TimeoutSeconds = 10,
            MaxResponseBytes = 2_097_152
        }));

    private string EnrollmentAuditPath(string name) => Path.Combine(runDirectory,
        $"enrollment-{name}-{Guid.NewGuid():N}", "audit.jsonl");

    private string EnrollmentToken(string subject, string? objectGuid, string scope = "mail.read",
        string? issuer = null, string clientId = "chatgpt-test", Claim[]? extraClaims = null)
    {
        var claims = new List<Claim>
        {
            new("sub", subject), new("scope", scope), new("azp", clientId), new("typ", "Bearer"), new("sid", "test-session")
        };
        if (objectGuid is not null) claims.Add(new(MailboxEnrollment.DirectoryGuidClaim, objectGuid));
        if (extraClaims is not null) claims.AddRange(extraClaims);
        var claimsMap = claims.GroupBy(claim => claim.Type, StringComparer.Ordinal)
            .ToDictionary(group => group.Key,
                group => group.Count() == 1 ? (object)group.Single().Value : group.Select(claim => claim.Value).ToArray(),
                StringComparer.Ordinal);
        var token = tokenHandler.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = issuer ?? Authority,
            Audience = Resource,
            Claims = claimsMap,
            NotBefore = DateTime.UtcNow.AddSeconds(-5),
            Expires = DateTime.UtcNow.AddMinutes(5),
            SigningCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.RsaSha256),
            TokenType = "JWT"
        });
        return tokenHandler.WriteToken(token);
    }

    private static ClaimsPrincipal EnrollmentPrincipal(string subject, string? objectGuid, string scope = "mail.read",
        string issuer = Authority, string clientId = "chatgpt-test", string tokenType = "Bearer", Claim[]? extraClaims = null)
    {
        var claims = new List<Claim>
        {
            new("sub", subject), new("iss", issuer), new("scope", scope), new("azp", clientId), new("typ", tokenType),
            new("sid", "test-session")
        };
        if (objectGuid is not null) claims.Add(new(MailboxEnrollment.DirectoryGuidClaim, objectGuid));
        if (extraClaims is not null) claims.AddRange(extraClaims);
        return new ClaimsPrincipal(new ClaimsIdentity(claims, "Bearer"));
    }

    private static LdapSearchEntry EnrollmentEntry(Guid objectGuid, string primarySmtp, string? secondarySmtp = null,
        string userAccountControl = "512", string recipientType = "1", bool omitHomeMdb = false,
        string[]? primaryAddresses = null) => new(
        "CN=Mailbox User,OU=Employees,DC=example,DC=test",
        new Dictionary<string, IReadOnlyList<string>>(StringComparer.OrdinalIgnoreCase)
        {
            ["userAccountControl"] = [userAccountControl],
            ["msExchRecipientTypeDetails"] = [recipientType],
            ["proxyAddresses"] = primaryAddresses ?? (secondarySmtp is null
                ? [$"SMTP:{primarySmtp}"] : [$"SMTP:{primarySmtp}", secondarySmtp]),
            ["legacyExchangeDN"] = ["/o=Example/ou=Exchange Administrative Group/cn=Recipients/cn=MailboxUser"],
            ["homeMDB"] = omitHomeMdb ? [] : ["CN=Mailbox Database,CN=Databases,DC=example,DC=test"]
        },
        new Dictionary<string, IReadOnlyList<byte[]>>(StringComparer.OrdinalIgnoreCase)
        {
            ["objectGUID"] = [objectGuid.ToByteArray()]
        });

    private static string EnrollmentGuidFilter(Guid guid) => "(&(objectCategory=person)(objectClass=user)(objectGUID="
        + string.Concat(guid.ToByteArray().Select(value => "\\" + value.ToString("x2", System.Globalization.CultureInfo.InvariantCulture)))
        + "))";

    private static Guid GuidFromIndex(int index)
    {
        Span<byte> bytes = stackalloc byte[16];
        BitConverter.TryWriteBytes(bytes, index + 1);
        bytes[15] = 1;
        return new Guid(bytes);
    }

    private sealed record EnrollmentContext(string AuditPath, EnrollmentLdapFactory Ldap,
        MailboxEnrollment Enrollment, MailboxAccess Access)
    {
        public string RegistryPath => AuditPath + ".enrollments.json";
    }
}

internal sealed record EnrollmentLdapCall(string BaseDn, string Filter, SearchScope Scope,
    IReadOnlyList<string> Attributes, bool RequestDaclOnly);

internal sealed class EnrollmentLdapFactory : ILdapSearchFacadeFactory
{
    private readonly ConcurrentDictionary<string, IReadOnlyList<LdapSearchEntry>> responses = new(StringComparer.Ordinal);
    private readonly ConcurrentQueue<EnrollmentLdapCall> calls = new();

    public bool ThrowOnSearch { get; set; }
    public IReadOnlyList<EnrollmentLdapCall> Calls => calls.ToArray();

    public void Set(Guid guid, params LdapSearchEntry[] rows) => responses[GuidFilter(guid)] = rows;

    public ILdapSearchFacade Create() => new Facade(this);

    private IReadOnlyList<LdapSearchEntry> Search(string baseDn, string filter, SearchScope scope,
        IReadOnlyList<string> attributes, bool requestDaclOnly, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        calls.Enqueue(new(baseDn, filter, scope, attributes.ToArray(), requestDaclOnly));
        if (ThrowOnSearch) throw new InvalidOperationException("synthetic LDAP unavailable");
        return responses.TryGetValue(filter, out var rows) ? rows : [];
    }

    private static string GuidFilter(Guid guid) => "(&(objectCategory=person)(objectClass=user)(objectGUID="
        + string.Concat(guid.ToByteArray().Select(value => "\\" + value.ToString("x2", System.Globalization.CultureInfo.InvariantCulture)))
        + "))";

    private sealed class Facade(EnrollmentLdapFactory owner) : ILdapSearchFacade
    {
        public IReadOnlyList<LdapSearchEntry> Search(string baseDn, string filter, SearchScope scope,
            IReadOnlyList<string> attributes, bool requestDaclOnly, CancellationToken cancellationToken) =>
            owner.Search(baseDn, filter, scope, attributes, requestDaclOnly, cancellationToken);

        public void Dispose() { }
    }
}

internal sealed record EnrollmentEwsCall(string Operation, string? AnchorMailbox,
    System.Net.Http.Headers.AuthenticationHeaderValue? Authorization);

internal sealed class EnrollmentEwsHandler(bool read = true, bool throwOnGetFolder = false) : HttpMessageHandler
{
    private static readonly XNamespace Soap = "http://schemas.xmlsoap.org/soap/envelope/";
    private static readonly XNamespace Messages = "http://schemas.microsoft.com/exchange/services/2006/messages";
    private static readonly XNamespace Types = "http://schemas.microsoft.com/exchange/services/2006/types";
    private readonly ConcurrentQueue<EnrollmentEwsCall> calls = new();

    public IReadOnlyList<EnrollmentEwsCall> Calls => calls.ToArray();

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        var body = await request.Content!.ReadAsStringAsync(cancellationToken);
        var document = XDocument.Parse(body);
        var operation = document.Root!.Element(Soap + "Body")!.Elements().Single().Name.LocalName;
        var anchor = request.Headers.TryGetValues("X-AnchorMailbox", out var anchors) ? anchors.Single() : null;
        calls.Enqueue(new(operation, anchor, request.Headers.Authorization));
        if (operation == "GetFolder" && throwOnGetFolder)
            throw new HttpRequestException("synthetic EWS unavailable");

        var payload = operation switch
        {
            "GetFolder" => $"<m:Folders><t:Folder><t:FolderId Id='inbox-id' ChangeKey='inbox-change'/>"
                + (read ? "<t:EffectiveRights><t:Read>true</t:Read><t:CreateContents>false</t:CreateContents><t:Modify>false</t:Modify><t:Delete>false</t:Delete></t:EffectiveRights>" :
                    "<t:EffectiveRights><t:Read>false</t:Read><t:CreateContents>false</t:CreateContents><t:Modify>false</t:Modify><t:Delete>false</t:Delete></t:EffectiveRights>")
                + "</t:Folder></m:Folders>",
            "FindItem" => "<m:RootFolder IncludesLastItemInRange='true'><t:Items><t:Message>"
                + "<t:ItemId Id='message-1' ChangeKey='message-change'/><t:Subject>Enrollment test</t:Subject>"
                + "<t:From><t:Mailbox><t:EmailAddress>sender@example.test</t:EmailAddress></t:Mailbox></t:From>"
                + "<t:DateTimeReceived>2026-10-14T10:00:00Z</t:DateTimeReceived><t:IsRead>false</t:IsRead>"
                + "<t:IsDraft>false</t:IsDraft></t:Message></t:Items></m:RootFolder>",
            _ => string.Empty
        };
        var responseClass = operation == "GetFolder" && !read ? "Error" : "Success";
        var responseCode = operation == "GetFolder" && !read ? "ErrorAccessDenied" : "NoError";
        var xml = $"<s:Envelope xmlns:s='{Soap.NamespaceName}' xmlns:m='{Messages.NamespaceName}' xmlns:t='{Types.NamespaceName}'><s:Body>"
            + $"<m:{operation}Response><m:ResponseMessages><m:{operation}ResponseMessage ResponseClass='{responseClass}'>"
            + $"<m:ResponseCode>{responseCode}</m:ResponseCode>{payload}</m:{operation}ResponseMessage></m:ResponseMessages>"
            + $"</m:{operation}Response></s:Body></s:Envelope>";
        return new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(xml, Encoding.UTF8, "text/xml")
        };
    }
}

internal sealed class BlockingEnrollmentIntrospectionHandler : HttpMessageHandler
{
    private readonly TaskCompletionSource<bool> entered = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource<bool> release = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private int calls;

    public int Calls => Volatile.Read(ref calls);

    public Task WaitUntilCalledAsync(TimeSpan timeout) => entered.Task.WaitAsync(timeout);

    public void Release() => release.TrySetResult(true);

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        Interlocked.Increment(ref calls);
        entered.TrySetResult(true);
        await release.Task.WaitAsync(cancellationToken);

        var form = await request.Content!.ReadAsStringAsync(cancellationToken);
        var token = form.Split('&', StringSplitOptions.RemoveEmptyEntries)
            .Select(pair => pair.Split('=', 2))
            .Where(parts => parts.Length == 2 && parts[0] == "token")
            .Select(parts => WebUtility.UrlDecode(parts[1]))
            .SingleOrDefault();
        if (string.IsNullOrWhiteSpace(token))
            return JsonResponse(new { active = false });

        var jwt = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler().ReadJwtToken(token);
        var response = new Dictionary<string, object?>
        {
            ["active"] = true,
            ["typ"] = "Bearer",
            ["sub"] = jwt.Claims.FirstOrDefault(claim => claim.Type == "sub")?.Value,
            ["iss"] = jwt.Issuer,
            ["aud"] = jwt.Audiences.ToArray(),
            ["azp"] = jwt.Claims.FirstOrDefault(claim => claim.Type == "azp")?.Value,
            ["scope"] = jwt.Claims.FirstOrDefault(claim => claim.Type == "scope")?.Value,
            ["exp"] = long.TryParse(jwt.Claims.FirstOrDefault(claim => claim.Type == "exp")?.Value, out var expiry)
                ? expiry : 0
        };
        var guid = jwt.Claims.FirstOrDefault(claim => claim.Type == MailboxEnrollment.DirectoryGuidClaim)?.Value;
        if (guid is not null) response[MailboxEnrollment.DirectoryGuidClaim] = guid;
        return JsonResponse(response);
    }

    private static HttpResponseMessage JsonResponse(object value) => new(HttpStatusCode.OK)
    {
        Content = new StringContent(JsonSerializer.Serialize(value), Encoding.UTF8, "application/json")
    };
}
