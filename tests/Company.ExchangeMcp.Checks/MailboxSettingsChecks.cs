using System.Net;
using System.Text;
using System.Xml.Linq;
using System.Xml.Schema;
using Company.ExchangeMcp;
using Company.ExchangeMcp.Exchange;
using Company.ExchangeMcp.Security;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using ModelContextProtocol;
using ModelContextProtocol.AspNetCore;

internal sealed partial class Checks
{
    private async Task MailboxSettingsChecksAsync()
    {
        var exchange = new MailboxSettingsRecordingHandler();
        var client = NewEwsClient(exchange);

        var oof = await client.GetOofSettingsAsync("alice@example.test", CancellationToken.None);
        Expect(oof.State == "Disabled" && oof.InternalReply == "Keep exact internal text",
            "GetUserOofSettings did not preserve the mailbox reply text.");
        Expect(oof.DeclineMeetingReply == "Decline exact text"
            && oof.CreateOofEvent == true
            && oof.OofEventId == "oof-event-1"
            && oof.EventsToDeleteIdsXml is null,
            "GetUserOofSettings did not preserve the extended Exchange OOF fields.");
        var getOof = exchange.Last("GetUserOofSettingsRequest");
        Expect(getOof.Contains("ExchangeImpersonation", StringComparison.Ordinal)
            && getOof.Contains("PrimarySmtpAddress", StringComparison.Ordinal),
            "OOF requests omitted the impersonation header.");

        exchange.IncludeDestructiveEventIds = true;
        var unsafeOof = await client.GetOofSettingsAsync("alice@example.test", CancellationToken.None);
        Expect(unsafeOof.EventsToDeleteIdsXml?.Contains("event-1", StringComparison.Ordinal) == true,
            "The destructive OOF event-ID fixture was not captured.");
        await AssertThrowsAsync<InvalidOperationException>(() => client.SetOofSettingsAsync("alice@example.test",
            unsafeOof with
            {
                State = "Scheduled",
                ExternalAudience = "Known",
                StartTime = "2026-10-10T09:00:00+03:30",
                EndTime = "2026-10-11T09:00:00+03:30",
                InternalReply = "internal",
                ExternalReply = "external"
            }, CancellationToken.None));
        exchange.IncludeDestructiveEventIds = false;
        oof = await client.GetOofSettingsAsync("alice@example.test", CancellationToken.None);
        await client.SetOofSettingsAsync("alice@example.test",
            oof with
            {
                State = "Scheduled",
                ExternalAudience = "Known",
                StartTime = "2026-10-10T09:00:00+03:30",
                EndTime = "2026-10-11T09:00:00+03:30",
                InternalReply = "internal",
                ExternalReply = "external",
                EventsToDeleteIdsXml = null
            }, CancellationToken.None);
        var setOof = exchange.Last("SetUserOofSettingsRequest");
        Expect(setOof.Contains("<t:OofState>Scheduled</t:OofState>", StringComparison.Ordinal)
            && setOof.Contains("<t:ExternalAudience>Known</t:ExternalAudience>", StringComparison.Ordinal)
            && setOof.Contains("<t:InternalReply", StringComparison.Ordinal)
            && setOof.Contains("<t:DeclineMeetingReply", StringComparison.Ordinal)
            && setOof.Contains("<t:CreateOOFEvent>true</t:CreateOOFEvent>", StringComparison.Ordinal)
            && setOof.Contains("<t:OOFEventID>oof-event-1</t:OOFEventID>", StringComparison.Ordinal)
            && !setOof.Contains("<t:EventsToDeleteIDs>", StringComparison.Ordinal),
            "SetUserOofSettings did not emit the complete bounded settings shape or preserve extended fields.");

        var rules = await client.GetInboxRulesAsync("alice@example.test", CancellationToken.None);
        Expect(rules.OutlookRuleBlobExists == false && rules.Rules.Count == 1
            && rules.Rules[0].Conditions.ContainsSubjectStrings.SequenceEqual(["Report"])
            && !rules.Rules[0].Actions.StopProcessingRules,
            "GetInboxRules did not parse the server rule or Outlook blob state.");
        await client.UpdateInboxRulesAsync("alice@example.test",
            new EwsInboxRuleOperation("create", null,
                new EwsInboxRule("", "Move reports", 3, true,
                    new EwsRulePredicates(["Report"], ["Body"], ["sender@example.test"], ["recipient@example.test"]),
                    new EwsRuleActions("inbox", "sentitems", true, ["Work"], true), [], [], [], false, false)),
            CancellationToken.None);
        var update = exchange.Last("UpdateInboxRules");
        Expect(update.Contains("<m:RemoveOutlookRuleBlob>false</m:RemoveOutlookRuleBlob>", StringComparison.Ordinal)
            && update.Contains("<t:CreateRuleOperation>", StringComparison.Ordinal)
            && update.Contains("<t:ContainsBodyStrings>", StringComparison.Ordinal)
            && update.Contains("<t:FromAddresses>", StringComparison.Ordinal)
            && update.Contains("<t:SentToAddresses>", StringComparison.Ordinal)
            && update.Contains("<t:CopyToFolder>", StringComparison.Ordinal)
            && update.Contains("<t:MoveToFolder>", StringComparison.Ordinal)
            && update.Contains("<t:MarkAsRead>true</t:MarkAsRead>", StringComparison.Ordinal)
            && update.Contains("<t:AssignCategories>", StringComparison.Ordinal)
            && update.Contains("<t:StopProcessingRules>true</t:StopProcessingRules>", StringComparison.Ordinal),
            "UpdateInboxRules did not use the safe server-side rule shape.");

        ValidateMailboxSettingsSchema(exchange);

        exchange.IncludeNamespaceDeclarations = true;
        exchange.IncludeRuleAddressCondition = true;
        exchange.IncludeRichRuleAddressCondition = true;
        var namespacedOof = await client.GetOofSettingsAsync("alice@example.test", CancellationToken.None);
        var namespacedRules = await client.GetInboxRulesAsync("alice@example.test", CancellationToken.None);
        Expect(namespacedOof.InternalReply == "Keep exact internal text"
            && namespacedOof.ExternalReply == "External"
            && namespacedOof.StartTime == "2026-10-10T09:00:00+03:30"
            && namespacedRules.Rules.Count == 1
            && namespacedRules.Rules[0].Conditions.FromAddresses.SequenceEqual(["sender@example.test"])
            && namespacedRules.Rules[0].UnsupportedConditions.Contains("FromAddressesMetadata"),
            "Schema-valid namespace declarations or EmailAddressType metadata on Inbox rule address fields were not preserved.");
        await AssertThrowsAsync<ArgumentException>(() => client.UpdateInboxRulesAsync("alice@example.test",
            new EwsInboxRuleOperation("set", "rule-1", namespacedRules.Rules[0]), CancellationToken.None));
        ValidateMailboxSettingsSchema(exchange);
        exchange.IncludeNamespaceDeclarations = false;
        exchange.IncludeRuleAddressCondition = false;
        exchange.IncludeRichRuleAddressCondition = false;

        var exchangeRuleAddress = new MailboxSettingsRecordingHandler
        {
            IncludeRuleAddressCondition = true,
            IncludeExchangeRuleAddressCondition = true,
            IncludeRuleAddressItemId = true
        };
        var exchangeRules = await NewEwsClient(exchangeRuleAddress)
            .GetInboxRulesAsync("alice@example.test", CancellationToken.None);
        Expect(exchangeRules.Rules[0].Conditions.FromAddresses.SequenceEqual(["/o=Example/ou=Exchange Administrative Group/cn=Recipients/cn=alice"])
            && exchangeRules.Rules[0].UnsupportedConditions.Contains("FromAddressesMetadata"),
            "Exchange EX address metadata was not exposed while preserving the rule write barrier.");
        ValidateMailboxSettingsSchema(exchangeRuleAddress);
        await AssertThrowsAsync<ArgumentException>(() => NewEwsClient(exchangeRuleAddress)
            .UpdateInboxRulesAsync("alice@example.test",
                new EwsInboxRuleOperation("set", "rule-1", exchangeRules.Rules[0]), CancellationToken.None));

        var unknownOofExchange = new MailboxSettingsRecordingHandler { IncludeUnknownOofAttribute = true };
        await AssertThrowsAsync<InvalidOperationException>(() => NewEwsClient(unknownOofExchange)
            .GetOofSettingsAsync("alice@example.test", CancellationToken.None));
        var unknownRuleExchange = new MailboxSettingsRecordingHandler
        {
            IncludeRuleAddressCondition = true,
            IncludeUnknownRuleAddressAttribute = true
        };
        await AssertThrowsAsync<InvalidOperationException>(() => NewEwsClient(unknownRuleExchange)
            .GetInboxRulesAsync("alice@example.test", CancellationToken.None));
        var duplicateRuleAddressExchange = new MailboxSettingsRecordingHandler
        {
            IncludeRuleAddressCondition = true,
            IncludeDuplicateRuleAddressChild = true
        };
        await AssertThrowsAsync<InvalidOperationException>(() => NewEwsClient(duplicateRuleAddressExchange)
            .GetInboxRulesAsync("alice@example.test", CancellationToken.None));
        var unknownRuleAddressChildExchange = new MailboxSettingsRecordingHandler
        {
            IncludeRuleAddressCondition = true,
            IncludeUnknownRuleAddressChild = true
        };
        await AssertThrowsAsync<InvalidOperationException>(() => NewEwsClient(unknownRuleAddressChildExchange)
            .GetInboxRulesAsync("alice@example.test", CancellationToken.None));
        var namespacedItemIdExchange = new MailboxSettingsRecordingHandler
        {
            IncludeRuleAddressCondition = true,
            IncludeExchangeRuleAddressCondition = true,
            IncludeRuleAddressItemId = true,
            IncludeUnknownRuleAddressItemIdAttribute = true
        };
        await AssertThrowsAsync<InvalidOperationException>(() => NewEwsClient(namespacedItemIdExchange)
            .GetInboxRulesAsync("alice@example.test", CancellationToken.None));

        exchange.OutlookRuleBlobExists = true;
        var blocked = await client.GetInboxRulesAsync("alice@example.test", CancellationToken.None);
        Expect(blocked.OutlookRuleBlobExists == true, "Outlook client rule-blob presence was not surfaced.");
        Expect(update.Contains("<m:RemoveOutlookRuleBlob>false</m:RemoveOutlookRuleBlob>", StringComparison.Ordinal),
            "The rule client did not make the Outlook blob preservation flag explicit.");

        exchange.OmitOutlookRuleBlob = true;
        var unavailableBlob = await client.GetInboxRulesAsync("alice@example.test", CancellationToken.None);
        Expect(unavailableBlob.OutlookRuleBlobExists is null && unavailableBlob.Rules.Count == 1,
            "A schema-valid Inbox rule response without OutlookRuleBlobExists was not represented as unavailable.");
        exchange.OmitOutlookRuleBlob = false;
        exchange.OmitInboxRules = true;
        var emptyRules = await client.GetInboxRulesAsync("alice@example.test", CancellationToken.None);
        Expect(emptyRules.OutlookRuleBlobExists == true && emptyRules.Rules.Count == 0,
            "A schema-valid Inbox rule response without InboxRules was not represented as an empty snapshot.");
        exchange.OmitInboxRules = false;

        exchange.OmitOofResponseMessage = true;
        await AssertThrowsAsync<InvalidOperationException>(() => client.SetOofSettingsAsync("alice@example.test",
            oof with { State = "Disabled", EventsToDeleteIdsXml = null }, CancellationToken.None));
        exchange.OmitOofResponseMessage = false;
        ValidateMailboxSettingsSchema(exchange);

        exchange.IncludeUnsupportedRuleFields = true;
        var unsafeSnapshot = await client.GetInboxRulesAsync("alice@example.test", CancellationToken.None);
        Expect(unsafeSnapshot.Rules[0].UnsupportedConditions.Contains("HasAttachments")
            && unsafeSnapshot.Rules[0].UnsupportedExceptions.Contains("FromAddresses"),
            "Unsupported Inbox rule predicates or exceptions were not surfaced.");
        await AssertThrowsAsync<ArgumentException>(() => client.UpdateInboxRulesAsync("alice@example.test",
            new EwsInboxRuleOperation("set", "rule-1", unsafeSnapshot.Rules[0]), CancellationToken.None));
        exchange.IncludeUnsupportedRuleFields = false;
        exchange.UseGenericFolderTarget = true;
        var genericTarget = await client.GetInboxRulesAsync("alice@example.test", CancellationToken.None);
        Expect(genericTarget.Rules[0].UnsupportedActions.Count == 0
            && genericTarget.Rules[0].Actions.MoveToFolder?.StartsWith("ews-folder-id:", StringComparison.Ordinal) == true,
            "A generic Inbox rule folder target was exposed as a DistinguishedFolderId.");
        await client.UpdateInboxRulesAsync("alice@example.test",
            new EwsInboxRuleOperation("set", "rule-1", genericTarget.Rules[0]), CancellationToken.None);
        Expect(exchange.Last("UpdateInboxRules").Contains("<t:FolderId Id=\"AAMk-generic-folder-id\"", StringComparison.Ordinal),
            "A parsed generic rule target did not retain its FolderId wire type.");
        exchange.UseGenericFolderTarget = false;
        ValidateMailboxSettingsSchema(exchange);
        exchange.MalformedOutlookRuleBlob = true;
        await AssertThrowsAsync<InvalidOperationException>(() => client.GetInboxRulesAsync("alice@example.test", CancellationToken.None));
        exchange.MalformedOutlookRuleBlob = false;
        exchange.IncludeReadOnlyRuleFlags = true;
        var readOnly = await client.GetInboxRulesAsync("alice@example.test", CancellationToken.None);
        Expect(readOnly.Rules[0].IsInError && readOnly.Rules[0].IsNotSupported,
            "Inbox rule read-only/error flags were not surfaced.");
        await AssertThrowsAsync<ArgumentException>(() => client.UpdateInboxRulesAsync("alice@example.test",
            new EwsInboxRuleOperation("set", "rule-1", readOnly.Rules[0]), CancellationToken.None));
        exchange.IncludeReadOnlyRuleFlags = false;
        exchange.IncludeTooManyRuleStrings = true;
        await AssertThrowsAsync<InvalidOperationException>(() => client.GetInboxRulesAsync("alice@example.test", CancellationToken.None));
    }

    private async Task MailboxSettingsNativeChecksAsync()
    {
        var exchange = new MailboxSettingsRecordingHandler();
        await using var host = await StartMailboxSettingsHostAsync(exchange, writesEnabled: true, sendEnabled: true);
        var responder = new NativeFormResponder(accept: false);
        await using var client = await CreateNativeClientAsync(host,
            Token("user-a", "mail.read mail.write mail.manage mail.send", sessionId: "mailbox-settings-native"), responder);

        var profile = await client.Client.CallToolAsync("mail_oof", new Dictionary<string, object?>());
        var oofData = NativeData(profile);
        var oofRevision = oofData.GetProperty("revision").GetString()!;
        Expect(oofData.GetProperty("hasOofEvent").GetBoolean()
            && !oofData.TryGetProperty("oofEventId", out _) && !oofData.TryGetProperty("rawSettingsXml", out _),
            "OOF output exposed internal event identifiers or raw settings XML.");
        await using var noSendClient = await CreateNativeClientAsync(host,
            Token("user-a", "mail.read mail.write mail.manage", sessionId: "mailbox-settings-no-send"),
            new NativeFormResponder(accept: true));
        var noSend = await NativeRejectedAsync(noSendClient.Client, "mail_set_oof", new Dictionary<string, object?>
        {
            ["oofRevision"] = oofRevision,
            ["state"] = "Enabled"
        });
        Expect(noSend && responder.Calls == 0 && !exchange.OofSetCalled,
            "OOF activation bypassed the mail.send permission or native confirmation gate.");

        var externalBlocked = await NativeRejectedAsync(client.Client, "mail_set_oof", new Dictionary<string, object?>
        {
            ["oofRevision"] = oofRevision,
            ["state"] = "Enabled",
            ["externalAudience"] = "All"
        });
        Expect(externalBlocked && responder.Calls == 0 && !exchange.OofSetCalled,
            "OOF activation bypassed the external automatic-reply policy.");

        var declined = await client.Client.CallToolAsync("mail_set_oof", new Dictionary<string, object?>
        {
            ["oofRevision"] = oofRevision,
            ["state"] = "Enabled"
        });
        Expect(declined.IsError != true && NativeData(declined).GetProperty("status").GetString() == "cancelled"
            && responder.Calls == 1 && !exchange.OofSetCalled,
            "Declining the OOF activation did not prevent the server write.");

        responder.Accept = true;
        var accepted = await client.Client.CallToolAsync("mail_set_oof", new Dictionary<string, object?>
        {
            ["oofRevision"] = oofRevision,
            ["state"] = "Enabled"
        });
        Expect(accepted.IsError != true && exchange.OofSetCalled && responder.Calls == 2,
            "Accepting the OOF activation did not perform the confirmed server write.");

        var rules = await client.Client.CallToolAsync("mail_inbox_rules", new Dictionary<string, object?>());
        var ruleData = NativeData(rules);
        var ruleHandle = ruleData.GetProperty("items")[0].GetProperty("handle").GetString()!;
        var ruleRevision = ruleData.GetProperty("revision").GetString()!;
        var confirmedDelete = await client.Client.CallToolAsync("mail_delete_inbox_rule", new Dictionary<string, object?>
        {
            ["ruleHandle"] = ruleHandle,
            ["rulesRevision"] = ruleRevision
        });
        Expect(confirmedDelete.IsError != true && responder.Calls == 3 && exchange.RuleUpdateCount == 1,
            "Enabled rule deletion did not use native confirmation before the server write.");

        var refreshedRules = await client.Client.CallToolAsync("mail_inbox_rules", new Dictionary<string, object?>());
        var refreshedData = NativeData(refreshedRules);
        ruleHandle = refreshedData.GetProperty("items")[0].GetProperty("handle").GetString()!;
        ruleRevision = refreshedData.GetProperty("revision").GetString()!;
        exchange.BumpRuleOnNextRead = true;
        var stale = await client.Client.CallToolAsync("mail_delete_inbox_rule", new Dictionary<string, object?>
        {
            ["ruleHandle"] = ruleHandle,
            ["rulesRevision"] = ruleRevision
        });
        Expect(stale.IsError == true && exchange.RuleUpdateCount == 1,
            "Enabled rule deletion did not reject a revision change before writing.");

        exchange.RuleEnabled = false;
        var disabledRules = await client.Client.CallToolAsync("mail_inbox_rules", new Dictionary<string, object?>());
        var disabledData = NativeData(disabledRules);
        var disabledDelete = await client.Client.CallToolAsync("mail_delete_inbox_rule", new Dictionary<string, object?>
        {
            ["ruleHandle"] = disabledData.GetProperty("items")[0].GetProperty("handle").GetString()!,
            ["rulesRevision"] = disabledData.GetProperty("revision").GetString()!
        });
        Expect(disabledDelete.IsError != true && responder.Calls == 3 && exchange.RuleUpdateCount == 2,
            "Disabled rule deletion unexpectedly requested native confirmation or failed to write.");

        exchange.OmitOutlookRuleBlob = true;
        var unavailableBlobRules = await client.Client.CallToolAsync("mail_inbox_rules", new Dictionary<string, object?>());
        var unavailableBlobData = NativeData(unavailableBlobRules);
        Expect((!unavailableBlobData.TryGetProperty("outlookRuleBlobExists", out var unavailableBlob)
                || unavailableBlob.ValueKind == System.Text.Json.JsonValueKind.Null)
            && !unavailableBlobData.GetProperty("writesAvailable").GetBoolean(),
            "An unavailable Outlook client-rule state was exposed as a boolean.");
        var writesBeforeUnavailableBlobDelete = exchange.RuleUpdateCount;
        var unavailableBlobDelete = await client.Client.CallToolAsync("mail_delete_inbox_rule", new Dictionary<string, object?>
        {
            ["ruleHandle"] = unavailableBlobData.GetProperty("items")[0].GetProperty("handle").GetString()!,
            ["rulesRevision"] = unavailableBlobData.GetProperty("revision").GetString()!
        });
        Expect(unavailableBlobDelete.IsError == true && exchange.RuleUpdateCount == writesBeforeUnavailableBlobDelete,
            "Rule deletion proceeded when Exchange did not provide Outlook client-rule state.");
    }

    private async Task<TestHostContext> StartMailboxSettingsHostAsync(MailboxSettingsRecordingHandler exchange,
        bool writesEnabled, bool sendEnabled)
    {
        var passwordPath = Path.Combine(runDirectory, $"mailbox-settings-password-{Guid.NewGuid():N}.txt");
        var introspectionSecretPath = Path.Combine(runDirectory, $"mailbox-settings-introspection-{Guid.NewGuid():N}.txt");
        var auditPath = Path.Combine(runDirectory, $"mailbox-settings-audit-{Guid.NewGuid():N}.jsonl");
        await File.WriteAllTextAsync(passwordPath, "synthetic-password");
        await File.WriteAllTextAsync(introspectionSecretPath, "synthetic-introspection-secret");
        var app = AppHost.Create([], builder =>
        {
            builder.WebHost.UseTestServer();
            builder.Configuration.AddInMemoryCollection(ConfigurationValues(passwordPath, introspectionSecretPath,
                auditPath, writesEnabled, sendEnabled));
            builder.Services.PostConfigure<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme, options =>
            {
                var configuration = new OpenIdConnectConfiguration { Issuer = Authority };
                configuration.SigningKeys.Add(signingKey);
                options.Configuration = configuration;
                options.ConfigurationManager = new StaticConfigurationManager<OpenIdConnectConfiguration>(configuration);
            });
            builder.Services.AddHttpClient<EwsClient>().ConfigurePrimaryHttpMessageHandler(() => exchange);
            builder.Services.AddHttpClient<KeycloakTokenStatus>()
                .ConfigurePrimaryHttpMessageHandler(() => new IntrospectionHandler());
        });
        await app.StartAsync();
        var client = app.GetTestClient();
        client.BaseAddress = new Uri("https://mail.example.test/");
        return new TestHostContext(app, client);
    }

    private static void ValidateMailboxSettingsSchema(MailboxSettingsRecordingHandler handler)
    {
        var schemas = LoadOptionalExchangeSchemas();

        Expect(handler.Bodies.Count > 0 && handler.Responses.Count > 0,
            "Mailbox settings fixture did not capture both SOAP directions.");
        foreach (var envelope in handler.Bodies.Concat(handler.Responses))
        {
            var document = XDocument.Parse(envelope, LoadOptions.PreserveWhitespace);
            var operation = document.Root?.Element(XName.Get("Body", MailboxSettingsRecordingHandler.Soap))?.Elements().Single()
                ?? throw new InvalidOperationException("Mailbox settings SOAP operation was not captured.");
            if (schemas is not null)
                new XDocument(new XElement(operation)).Validate(schemas, (_, error) => throw new InvalidOperationException(
                    $"Exchange 2019 schema rejected mailbox settings SOAP: {error.Message}"));
        }
    }
}

internal sealed class MailboxSettingsRecordingHandler : HttpMessageHandler
{
    public const string Soap = "http://schemas.xmlsoap.org/soap/envelope/";
    public const string Messages = "http://schemas.microsoft.com/exchange/services/2006/messages";
    public const string Types = "http://schemas.microsoft.com/exchange/services/2006/types";
    private readonly List<(string Operation, string Body)> calls = [];
    public List<string> Bodies { get; } = [];
    public List<string> Responses { get; } = [];
    public bool OutlookRuleBlobExists { get; set; }
    public bool OmitOutlookRuleBlob { get; set; }
    public bool OmitInboxRules { get; set; }
    public bool OmitOofResponseMessage { get; set; }
    public bool MalformedOutlookRuleBlob { get; set; }
    public bool IncludeUnsupportedRuleFields { get; set; }
    public bool OofSetCalled { get; private set; }
    public int RuleUpdateCount { get; private set; }
    public bool BumpRuleOnNextRead { get; set; }
    public int RulePriority { get; private set; } = 1;
    public bool RuleEnabled { get; set; } = true;
    public bool UseGenericFolderTarget { get; set; }
    public bool IncludeReadOnlyRuleFlags { get; set; }
    public bool IncludeTooManyRuleStrings { get; set; }
    public bool IncludeDestructiveEventIds { get; set; }
    public bool IncludeNamespaceDeclarations { get; set; }
    public bool IncludeRuleAddressCondition { get; set; }
    public bool IncludeRichRuleAddressCondition { get; set; }
    public bool IncludeExchangeRuleAddressCondition { get; set; }
    public bool IncludeRuleAddressItemId { get; set; }
    public bool IncludeUnknownRuleAddressItemIdAttribute { get; set; }
    public bool IncludeDuplicateRuleAddressChild { get; set; }
    public bool IncludeUnknownRuleAddressChild { get; set; }
    public bool IncludeUnknownOofAttribute { get; set; }
    public bool IncludeUnknownRuleAddressAttribute { get; set; }

    public string Last(string operation) => calls.Last(item => item.Operation == operation).Body;

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        var body = await request.Content!.ReadAsStringAsync(cancellationToken);
        var document = XDocument.Parse(body);
        var operation = document.Root!.Element(XName.Get("Body", Soap))!.Elements().Single().Name.LocalName;
        calls.Add((operation, body));
        Bodies.Add(body);
        var response = operation switch
        {
            "GetUserOofSettingsRequest" => OofResponse(),
            "SetUserOofSettingsRequest" => SetOofResponse(),
            "GetInboxRules" => RulesResponse(),
            "UpdateInboxRules" => UpdateRulesResponse(),
            _ => throw new InvalidOperationException($"Unexpected EWS operation {operation}.")
        };
        var responseName = operation switch
        {
            "GetUserOofSettingsRequest" => "GetUserOofSettingsResponse",
            "SetUserOofSettingsRequest" => "SetUserOofSettingsResponse",
            _ => operation + "Response"
        };
        var result = operation == "GetUserOofSettingsRequest" || (operation == "SetUserOofSettingsRequest" && !OmitOofResponseMessage)
            ? "<m:ResponseMessage ResponseClass='Success'><m:ResponseCode>NoError</m:ResponseCode></m:ResponseMessage>"
            : operation == "SetUserOofSettingsRequest" ? string.Empty
            : "<m:ResponseCode>NoError</m:ResponseCode>";
        var rootClass = operation is "GetUserOofSettingsRequest" or "SetUserOofSettingsRequest"
            ? string.Empty : " ResponseClass='Success'";
        var xml = $"<s:Envelope xmlns:s='{Soap}' xmlns:m='{Messages}' xmlns:t='{Types}'><s:Body><m:{responseName}{rootClass}>{result}{response}</m:{responseName}></s:Body></s:Envelope>";
        Responses.Add(xml);
        return new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(xml, Encoding.UTF8, "text/xml")
        };
    }

    private string OofResponse()
    {
        var eventIds = IncludeDestructiveEventIds
            ? "<t:EventsToDeleteIDs><t:EventToDeleteID>event-1</t:EventToDeleteID></t:EventsToDeleteIDs>"
            : string.Empty;
        var ns = IncludeNamespaceDeclarations ? " xmlns:q='urn:company:mailbox-fixture'" : string.Empty;
        var unknown = IncludeUnknownOofAttribute ? " unexpected='bad'" : string.Empty;
        return $"<t:OofSettings{ns}{unknown}><t:OofState{ns}>Disabled</t:OofState><t:ExternalAudience{ns}>None</t:ExternalAudience><t:Duration{ns}><t:StartTime{ns}>2026-10-10T09:00:00+03:30</t:StartTime><t:EndTime{ns}>2026-10-11T09:00:00+03:30</t:EndTime></t:Duration><t:InternalReply{ns} xml:lang='en-US'><t:Message{ns}>Keep exact internal text</t:Message></t:InternalReply><t:ExternalReply{ns}><t:Message{ns}>External</t:Message></t:ExternalReply><t:DeclineMeetingReply{ns} xml:lang='en-US'><t:Message{ns}>Decline exact text</t:Message></t:DeclineMeetingReply><t:DeclineEventsForScheduledOOF{ns}>true</t:DeclineEventsForScheduledOOF><t:DeclineAllEventsForScheduledOOF{ns}>false</t:DeclineAllEventsForScheduledOOF><t:CreateOOFEvent{ns}>true</t:CreateOOFEvent><t:OOFEventSubject{ns}>OOF calendar</t:OOFEventSubject><t:AutoDeclineFutureRequestsWhenOOF{ns}>true</t:AutoDeclineFutureRequestsWhenOOF><t:OOFEventID{ns}>oof-event-1</t:OOFEventID>{eventIds}</t:OofSettings><m:AllowExternalOof>All</m:AllowExternalOof>";
    }

    private string SetOofResponse()
    {
        OofSetCalled = true;
        return string.Empty;
    }

    private string RulesResponse()
    {
        if (BumpRuleOnNextRead)
        {
            BumpRuleOnNextRead = false;
            RulePriority++;
        }
        var blob = OmitOutlookRuleBlob ? string.Empty
            : $"<m:OutlookRuleBlobExists>{(MalformedOutlookRuleBlob ? "maybe" : OutlookRuleBlobExists.ToString().ToLowerInvariant())}</m:OutlookRuleBlobExists>";
        var conditionExtra = IncludeUnsupportedRuleFields ? "<t:HasAttachments>true</t:HasAttachments>" : string.Empty;
        var exceptions = IncludeUnsupportedRuleFields
            ? "<t:Exceptions><t:FromAddresses><t:Address><t:EmailAddress>sender@example.test</t:EmailAddress></t:Address></t:FromAddresses></t:Exceptions>"
            : "<t:Exceptions/>";
        var readOnly = IncludeReadOnlyRuleFlags
            ? "<t:IsNotSupported>true</t:IsNotSupported><t:IsInError>true</t:IsInError>" : string.Empty;
        var manyStrings = IncludeTooManyRuleStrings
            ? $"<t:ContainsBodyStrings>{string.Concat(Enumerable.Repeat("<t:String>x</t:String>", 101))}</t:ContainsBodyStrings>" : string.Empty;
        var ns = IncludeNamespaceDeclarations ? " xmlns:q='urn:company:mailbox-fixture'" : string.Empty;
        var itemId = IncludeRuleAddressItemId
            ? IncludeUnknownRuleAddressItemIdAttribute
                ? $"<t:ItemId{ns} xmlns:evil='urn:company-mailbox-evil' Id='item-1' evil:Id='evil-item' ChangeKey='key-1'/><t:OriginalDisplayName{ns}>Exchange Sender</t:OriginalDisplayName>"
                : $"<t:ItemId{ns} Id='item-1' ChangeKey='key-1'/><t:OriginalDisplayName{ns}>Exchange Sender</t:OriginalDisplayName>"
            : string.Empty;
        var addressFields = IncludeExchangeRuleAddressCondition
            ? $"<t:Name{ns}>Exchange Sender</t:Name><t:EmailAddress{ns}>/o=Example/ou=Exchange Administrative Group/cn=Recipients/cn=alice</t:EmailAddress><t:RoutingType{ns}>EX</t:RoutingType><t:MailboxType{ns}>Mailbox</t:MailboxType>{itemId}"
            : IncludeRichRuleAddressCondition
                ? $"<t:Name{ns}>Sender Display Name</t:Name><t:EmailAddress{ns}>sender@example.test</t:EmailAddress><t:RoutingType{ns}>SMTP</t:RoutingType><t:MailboxType{ns}>Mailbox</t:MailboxType><t:OriginalDisplayName{ns}>Sender Display Name</t:OriginalDisplayName>"
                : $"<t:EmailAddress{ns}>sender@example.test</t:EmailAddress>";
        if (IncludeDuplicateRuleAddressChild)
            addressFields += $"<t:EmailAddress{ns}>duplicate@example.test</t:EmailAddress>";
        if (IncludeUnknownRuleAddressChild)
            addressFields += $"<t:Unexpected{ns}>bad</t:Unexpected>";
        var addressCondition = IncludeRuleAddressCondition
            ? $"<t:FromAddresses{ns}{(IncludeUnknownRuleAddressAttribute ? " unexpected='bad'" : string.Empty)}><t:Address{ns}>{addressFields}</t:Address></t:FromAddresses>"
            : string.Empty;
        var moveTarget = UseGenericFolderTarget
            ? "<t:FolderId Id='AAMk-generic-folder-id'/></t:MoveToFolder>"
            : "<t:DistinguishedFolderId Id='inbox'/></t:MoveToFolder>";
        var inboxRules = OmitInboxRules ? string.Empty
            : $"<m:InboxRules><t:Rule><t:RuleId>rule-1</t:RuleId><t:DisplayName>Reports</t:DisplayName><t:Priority>{RulePriority}</t:Priority><t:IsEnabled>{RuleEnabled.ToString().ToLowerInvariant()}</t:IsEnabled>{readOnly}<t:Conditions><t:ContainsSubjectStrings><t:String>Report</t:String></t:ContainsSubjectStrings>{addressCondition}{conditionExtra}{manyStrings}</t:Conditions>{exceptions}<t:Actions><t:MoveToFolder>{moveTarget}<t:StopProcessingRules>false</t:StopProcessingRules></t:Actions></t:Rule></m:InboxRules>";
        return blob + inboxRules;
    }

    private string UpdateRulesResponse()
    {
        RuleUpdateCount++;
        return string.Empty;
    }
}
