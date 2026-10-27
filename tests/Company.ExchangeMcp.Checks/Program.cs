using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Xml.Linq;
using Company.ExchangeMcp;
using Company.ExchangeMcp.Exchange;
using Company.ExchangeMcp.Security;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

if (args.Length == 5 && args[0] == "--live-directory-probe")
    return await DirectoryPermissionReaderChecks.LiveDirectoryProbeAsync(args[1], args[2], args[3], args[4]);
if (args.Length == 4 && args[0] == "--live-discovery-probe")
    return await LiveDiscoveryProbe.RunAsync(args[1], args[2], args[3]);
if (args.Length == 4 && args[0] == "--live-mail-streaming-probe")
    return await LiveMailStreamingProbe.RunAsync(args[1], args[2], args[3]);

using var checks = new Checks();
return await checks.RunAsync();

internal sealed partial class Checks : IDisposable
{
    private const string Authority = "https://identity.example.test/realms/company";
    private const string Resource = "https://mail.example.test/mcp";
    private const string ProtocolVersion = "2025-11-25";
    private const string JulyProtocolVersion = "2026-07-28";
    private const string SoapNamespace = "http://schemas.xmlsoap.org/soap/envelope/";
    private const string MessagesNamespace = "http://schemas.microsoft.com/exchange/services/2006/messages";
    private const string TypesNamespace = "http://schemas.microsoft.com/exchange/services/2006/types";
    private readonly RSA signingRsa = RSA.Create(2048);
    private readonly RsaSecurityKey signingKey;
    private readonly JwtSecurityTokenHandler tokenHandler = new();
    private readonly string runDirectory;
    private int passed;
    private int failed;

    public Checks()
    {
        signingKey = new RsaSecurityKey(signingRsa) { KeyId = "checks-key" };
        var projectDirectory = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", ".."));
        runDirectory = Path.Combine(projectDirectory, ".local", "checks", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(runDirectory);
    }

    public async Task<int> RunAsync()
    {
        await CheckAsync("EWS SOAP safety and request shape", DirectEwsChecksAsync);
        await CheckAsync("Full mailbox feature coverage and Exchange 2019 wire schema", FullMailboxChecksAsync);
        await CheckAsync("Rich mail bodies, recipient overrides and inline images", RichMailChecksAsync);
        await CheckAsync("Native reply header provenance, identities, mailbox timezone and retained drafts", ReplyPresentationChecksAsync);
        await CheckAsync("Correlated operation IDs and uncertain Exchange submission", OperationTrackingChecksAsync);
        await CheckAsync("Durable approvals, handles and replay safety across restart", DurableApprovalChecksAsync);
        await CheckAsync("Email review card, draft revisions and safe inline previews", MailPreviewChecksAsync);
        await CheckAsync("Native review entrypoints, bounded references and read-only state", NativeReviewChecksAsync);
        await CheckAsync("Encrypted Inbox subscriptions, bounded delivery and metadata-only reads", MailEventChecksAsync);
        await CheckAsync("Native MCP Events discovery, authorization and callback protocol", MailEventProtocolChecksAsync);
        await CheckAsync("Native recall format, report correlation and approval isolation", RecallChecksAsync);
        await CheckAsync("Calendar operations, recurrence and meeting approval", CalendarChecksAsync);
        await CheckAsync("Calendar native approval and recurrence policy", CalendarPolicyChecksAsync);
        await CheckAsync("Recurring series handles and occurrence resolution", CalendarSeriesChecksAsync);
        await CheckAsync("Calendar metadata, partial updates, search and meeting responses", CalendarCompletenessChecksAsync);
        await CheckAsync("Truthful calendar detail and task acceptance/processing status", StatusTruthfulnessChecksAsync);
        await CheckAsync("Calendar meeting message handle typing", CalendarMeetingMessageChecksAsync);
        await CheckAsync("Calendar move and copy safety guards", CalendarTransferChecksAsync);
        await CheckAsync("Room discovery and meeting availability", RoomChecksAsync);
        await CheckAsync("Mailbox synchronization pages and cursor isolation", SyncChecksAsync);
        await CheckAsync("Automatic replies and protected Inbox rules", MailboxSettingsChecksAsync);
        await CheckAsync("Mailbox settings native approval and concurrency", MailboxSettingsNativeChecksAsync);
        await CheckAsync("Folder permissions and delegate wire contracts", SharingChecksAsync);
        await CheckAsync("Sharing native approval and snapshot isolation", SharingNativeChecksAsync);
        await CheckAsync("Personal contacts and tasks", PeopleTasksChecksAsync);
        await CheckAsync("Contact-group membership append/remove wire and handle safety", ContactGroupMembershipChecksAsync);
        await CheckAsync("Task assignment native EWS wire and replay safety", TaskAssignmentChecksAsync);
        await CheckAsync("Task assignment native confirmation and snapshot binding", TaskAssignmentNativeChecksAsync);
        await CheckAsync("Recurring task assignment plans, native approval and stop-on-uncertain behavior", AssignmentPlanChecksAsync);
        await CheckAsync("Automatic task notice filters, actor authorization, and write gates", TaskNoticeProcessingChecksAsync);
        await CheckAsync("Native task assigner stack and directory identity", TaskAssignerStackChecksAsync);
        await CheckAsync("Mailbox signature profiles and concurrency", SignatureChecksAsync);
        await CheckAsync("Native Office HTML preservation and authored signature boundaries", NativeHtmlChecksAsync);
        await CheckAsync("Automatic saved signature reuse, compatibility and retained failures", AutomaticSignatureChecksAsync);
        await CheckAsync("User onboarding language, preview approval and persistent isolation", OnboardingChecksAsync);
        await CheckAsync("Outlook signature source capture, formatting and safe selection", SignatureCaptureChecksAsync);
        await CheckAsync("Signature capture, handle commit and self-test draft isolation", SignatureCaptureFlowChecksAsync);
        await CheckAsync("Signature preview UI isolation and metadata", SignaturePreviewUiChecksAsync);
        await CheckAsync("Resource read audit classification, privacy and transparent failures", ResourceAuditChecksAsync);
        await CheckAsync("Calendar, contact and task attachment safety", GroupwareAttachmentsChecksAsync);
        await CheckAsync("MCP authentication, transport, tools, and mailbox isolation", McpChecksAsync);
        await CheckAsync("MCP operation quotas, bounded admission and multi-client wire load", RateLimitChecksAsync);
        await CheckAsync("Keycloak token introspection", IntrospectionChecksAsync);
        await CheckAsync("Explicit optional OAuth connection continuation and scope preservation", ConnectionContinuationChecksAsync);
        await CheckAsync("Public MCP hostname, discovery and audience isolation", PublicResourceChecksAsync);
        await CheckAsync("First-login mailbox enrollment and permission isolation", MailboxEnrollmentChecksAsync);
        await CheckAsync("MCP MRTR send approval flow", MrtrChecksAsync);
        await CheckAsync("ChatGPT OAuth send grant, draft revision and replay isolation", ChatGptOAuthSendChecksAsync);
        await CheckAsync("Scoped send approval, current directory identity and replay isolation", ScopedSendApprovalChecksAsync);
        await CheckAsync("MCP native classic form send approval flow", NativeConfirmationChecksAsync);
        await CheckAsync("Delegated mailbox target isolation and wire binding", DeferredMailboxChecksAsync);
        await CheckAsync("Delegated actor-context wire and own-only policy", DelegatedActorContextChecksAsync);
        await CheckAsync("Delegated owner recall wire binding", DelegatedOwnerRecallWireChecksAsync);
        await CheckAsync("Delegated mailbox access, calendar folder identity, and XML booleans", DelegatedMailboxAccessAndCalendarProbeChecksAsync);
        await CheckAsync("Delegated groupware attachments and synchronization cursor binding", DelegatedGroupwareAttachmentAndSyncChecksAsync);
        await CheckAsync("Permission errors through actual MCP wrappers", PermissionErrorsThroughActualMcpChecksAsync);
        await CheckAsync("Directory permission ACL and SID evaluation", DirectoryPermissionChecksAsync);
        await CheckAsync("Directory permission reader evidence", DirectoryPermissionReaderChecksAsync);
        await CheckAsync("Directory empty-attribute and inherited permission completeness", DirectoryCompletenessChecksAsync);
        await CheckAsync("Directory permission MCP guards", DirectoryPermissionMcpChecksAsync);
        await CheckAsync("Directory and Exchange mailbox discovery bounds", MailboxDiscoveryChecksAsync);
        await CheckAsync("Delegated mail sender and approval binding", DelegatedSenderChecksAsync);
        await CheckAsync("MCP tools/list filter cloning and metadata preservation", AssertListToolsFilterIsolationAsync);
        Console.WriteLine($"Checks: {passed} passed, {failed} failed.");
        return failed == 0 ? 0 : 1;
    }

    private async Task CheckAsync(string name, Func<Task> check)
    {
        var filter = Environment.GetEnvironmentVariable("COMPANY_MAIL_CHECK_FILTER");
        if (!string.IsNullOrWhiteSpace(filter) && !name.Contains(filter, StringComparison.OrdinalIgnoreCase)) return;
        try
        {
            await check();
            passed++;
            Console.WriteLine($"PASS {name}");
        }
        catch (Exception exception)
        {
            failed++;
            Console.WriteLine($"FAIL {name}: {exception.Message}");
            Console.WriteLine(exception.StackTrace);
        }
    }

    private async Task DirectEwsChecksAsync()
    {
        var handler = new RecordingEwsHandler();
        var client = NewEwsClient(handler);

        var page = await client.FindMessagesAsync("alice@example.test", "inbox", "A<&", 0, 20, CancellationToken.None);
        Expect(page.Items.Count == 1, "FindItem response was not parsed.");
        Expect(page.Items[0].Body is null, "summary FindItem unexpectedly returned a body.");
        Expect(page.Items[0].From == "Sender", "FindItem sender display-name fallback was not parsed.");
        var search = handler.LastRequest;
        Expect(search.Headers.TryGetValues("X-AnchorMailbox", out var anchors)
            && anchors.Single() == "alice@example.test", "X-AnchorMailbox was not set.");
        Expect(search.Headers.Authorization is null, "The MCP bearer token was forwarded to EWS.");
        Expect(search.Headers.TryGetValues("SOAPAction", out var actions)
            && actions.Single().Contains("/FindItem", StringComparison.Ordinal), "SOAPAction was not set.");

        var searchXml = XDocument.Parse(search.Body);
        var searchOperation = Operation(searchXml);
        var searchChildren = searchOperation.Elements().Select(x => x.Name.LocalName).ToArray();
        Expect(searchChildren.SequenceEqual(["ItemShape", "IndexedPageItemView", "Restriction", "SortOrder", "ParentFolderIds"]),
            "FindItem element order is not EWS-safe.");
        var fields = searchOperation.Element(XName.Get("ItemShape", MessagesNamespace))!.Descendants(XName.Get("FieldURI", TypesNamespace))
            .Select(x => (string?)x.Attribute("FieldURI"))
            .Where(x => x is not null)
            .Select(x => x!)
            .ToArray();
        Expect(fields.Contains("message:IsRead") && !fields.Contains("item:Body")
            && !fields.Contains("message:ToRecipients") && !fields.Contains("item:Attachments"),
            "Summary ItemShape requested body or complex recipient/attachment data.");
        Expect(search.Body.Contains("A&lt;&amp;", StringComparison.Ordinal), "The query was not XML escaped.");

        var message = await client.GetMessageAsync("alice@example.test", "message-1", CancellationToken.None);
        Expect(message.Body == "plain body" && message.Bcc.SequenceEqual(["hidden@example.test"])
            && message.AttachmentNames.SequenceEqual(["report.pdf"]), "Full message properties were not parsed.");

        await client.CreateDraftAsync("alice@example.test",
            new EwsDraftInput("subject<&", "body<&", ["to@example.test"], ["cc@example.test"]), CancellationToken.None);
        var draftXml = XDocument.Parse(handler.LastRequest.Body);
        Expect(!handler.LastRequest.Body.Contains("<script", StringComparison.Ordinal)
            && handler.LastRequest.Body.Contains("subject&lt;&amp;", StringComparison.Ordinal),
            "Draft content was not XML escaped.");
        Expect(Operation(draftXml).Element(XName.Get("SavedItemFolderId", MessagesNamespace)) is not null,
            "Draft did not specify a saved folder.");

        await client.ReplyDraftAsync("alice@example.test", "message-1", "reply", false, CancellationToken.None);
        var replyOperation = Operation(XDocument.Parse(handler.LastRequest.Body));
        Expect(replyOperation.Element(XName.Get("SavedItemFolderId", MessagesNamespace)) is not null
            && replyOperation.Descendants(XName.Get("ReplyToItem", TypesNamespace)).Any(),
            "Reply draft did not use CreateItem/ReplyToItem with Drafts.");

        await client.SetReadStateAsync("alice@example.test", "message-1", "change-1", true, CancellationToken.None);
        var updateOperation = Operation(XDocument.Parse(handler.LastRequest.Body));
        Expect((string?)updateOperation.Attribute("SuppressReadReceipts") == "true"
            && updateOperation.Descendants(XName.Get("ItemChange", TypesNamespace)).Any()
            && updateOperation.Descendants(XName.Get("FieldURI", TypesNamespace))
                .Any(x => (string?)x.Attribute("FieldURI") == "message:IsRead"),
            "SetReadState did not use the message:IsRead EWS field.");

        await client.SoftDeleteAsync("alice@example.test", "message-1", CancellationToken.None);
        var deleteOperation = Operation(XDocument.Parse(handler.LastRequest.Body));
        Expect((string?)deleteOperation.Attribute("DeleteType") == "MoveToDeletedItems"
            && (string?)deleteOperation.Attribute("SuppressReadReceipts") == "true",
            "SoftDelete did not move the item to Deleted Items.");

        await client.SendDraftAsync("alice@example.test", "draft-1", "draft-change", CancellationToken.None);
        var sendOperation = Operation(XDocument.Parse(handler.LastRequest.Body));
        Expect(sendOperation.Descendants(XName.Get("ItemId", TypesNamespace))
            .Any(x => (string?)x.Attribute("ChangeKey") == "draft-change"),
            "SendDraft did not include the current ChangeKey.");

        await AssertEwsFailureAsync(
            new DelegateHandler((_, _) => Task.FromResult(Response(SoapResponse("GetItem", "ErrorItemNotFound", "secret-body")))),
            "secret-body", "message-1", "alice@example.test");
        await AssertEwsFailureAsync(
            new DelegateHandler((_, _) => Task.FromResult(Response("<!DOCTYPE x [<!ENTITY secret 'leak'>]><s:Envelope xmlns:s='http://schemas.xmlsoap.org/soap/envelope/'><s:Body>&secret;</s:Body></s:Envelope>"))),
            "secret", "message-1", "alice@example.test");
        await AssertEwsFailureAsync(
            new DelegateHandler((_, _) => Task.FromResult(Response(SoapResponse("GetItem", "NoError", "", responseClass: "Error")))),
            "message-1", "alice@example.test");
        await AssertEwsFailureAsync(
            new DelegateHandler((_, _) => Task.FromResult(Response(SoapResponseWithSecondError()))),
            "secret-body", "message-1", "alice@example.test");
        var duplicateBody = XDocument.Parse(SoapResponse("GetItem", "NoError", ""));
        duplicateBody.Root!.Element(XName.Get("Body", SoapNamespace))!.Add(
            new XElement(XName.Get("UnexpectedResponse", MessagesNamespace)));
        await AssertEwsFailureAsync(
            new DelegateHandler((_, _) => Task.FromResult(Response(duplicateBody.ToString()))),
            "message-1", "alice@example.test");

        var bounded = NewEwsClient(
            new DelegateHandler((_, _) => Task.FromResult(Response(SoapResponse("GetItem", "NoError", new string('x', 4_000))))),
            maxResponseBytes: 1_024);
        var acceptedOversized = false;
        try
        {
            await bounded.GetMessageAsync("alice@example.test", "message-1", CancellationToken.None);
            acceptedOversized = true;
        }
        catch (InvalidOperationException exception)
        {
            Expect(!exception.Message.Contains("alice@example.test", StringComparison.Ordinal)
                && !exception.Message.Contains("message-1", StringComparison.Ordinal),
                "The bounded-response error leaked mailbox or item data.");
        }
        Expect(!acceptedOversized, "An oversized response was accepted.");

        const string rawFailure = "synthetic-sensitive-server-message";
        var fault = $"<s:Envelope xmlns:s='{SoapNamespace}'><s:Body><s:Fault><faultstring>{rawFailure}</faultstring>"
            + "<detail><ErrorCode>ErrorSchemaValidation</ErrorCode></detail></s:Fault></s:Body></s:Envelope>";
        foreach (var failure in new[]
        {
            (Body: SoapResponse("GetItem", "ErrorInvalidPropertySet", rawFailure, "Error"), Status: HttpStatusCode.OK, Code: "ErrorInvalidPropertySet"),
            (Body: SoapResponse("GetItem", "ErrorInvalidOperation", rawFailure, "Error"), Status: HttpStatusCode.InternalServerError, Code: "ErrorInvalidOperation"),
            (Body: fault, Status: HttpStatusCode.OK, Code: "ErrorSchemaValidation"),
            (Body: fault, Status: HttpStatusCode.InternalServerError, Code: "ErrorSchemaValidation"),
            (Body: "not XML: " + rawFailure, Status: HttpStatusCode.InternalServerError, Code: (string?)null),
            (Body: SoapResponse("GetItem", "ErrorInvalidOperation\n" + rawFailure, rawFailure, "Error"), Status: HttpStatusCode.OK, Code: (string?)null),
            (Body: SoapResponse("GetItem", "ErrorInvalidÅ", rawFailure, "Error"), Status: HttpStatusCode.OK, Code: (string?)null),
            (Body: SoapResponse("GetItem", "Error" + new string('x', 124), rawFailure, "Error"), Status: HttpStatusCode.OK, Code: (string?)null)
        })
        {
            var failureClient = NewEwsClient(new DelegateHandler((_, _) =>
                Task.FromResult(new HttpResponseMessage(failure.Status)
                { Content = new StringContent(failure.Body, Encoding.UTF8, "text/xml") })));
            EwsRequestFailedException? captured = null;
            try { await failureClient.GetMessageAsync("alice@example.test", "message-1", CancellationToken.None); }
            catch (EwsRequestFailedException exception) { captured = exception; }
            Expect(captured is not null && captured.ResponseCode == failure.Code && captured.Operation == "GetItem",
                "Native failure code or operation was lost or retained unsafe response data.");
            Expect(captured!.Message == (failure.Status == HttpStatusCode.OK
                    ? "Exchange returned an unsuccessful response." : "Exchange rejected the request.")
                && !JsonSerializer.Serialize(new { captured.Message, captured.ResponseCode, captured.Operation, captured.ErrorField })
                    .Contains(rawFailure, StringComparison.Ordinal),
                "Native failure metadata exposed server MessageText or fault details.");
        }
        Expect(new EwsRequestFailedException("ErrorInvalidOperation", "GetItem\n" + rawFailure).Operation == "Unknown",
            "Native failure metadata retained an unrecognized operation.");
        foreach (var field in new[]
        {
            (Xml: "<t:ExtendedFieldURI PropertySetId='00062003-0000-0000-C000-000000000046' PropertyId='33043' PropertyType='Integer'/>",
                Expected: "PropertySetId=00062003-0000-0000-c000-000000000046;PropertyId=33043"),
            (Xml: "<t:ExtendedFieldURI PropertySetId='00062008-0000-0000-C000-000000000046' PropertyId='34072' PropertyType='Integer'/>",
                Expected: "PropertySetId=00062008-0000-0000-c000-000000000046;PropertyId=34072"),
            (Xml: "<t:ExtendedFieldURI PropertyTag='0x7d01' PropertyType='Boolean'/>", Expected: "PropertyTag=0x7D01"),
            (Xml: "<t:FieldURI FieldURI='message:From'/>", Expected: "FieldURI=message:From"),
            (Xml: "<t:FieldURI FieldURI='task:Status'/>", Expected: "FieldURI=task:Status"),
            (Xml: $"<t:FieldURI FieldURI='task:Status-{rawFailure}'/>", Expected: (string?)null),
            (Xml: $"<t:ExtendedFieldURI PropertySetId='00062003-0000-0000-C000-000000000046' PropertyId='33043' PropertyName='{rawFailure}'/>",
                Expected: (string?)null),
            (Xml: "<t:ExtendedFieldURI PropertySetId='00000000-0000-0000-0000-000000000001' PropertyId='33043'/>", Expected: (string?)null),
            (Xml: $"<t:ExtendedFieldURI PropertySetId='00062003-0000-0000-C000-000000000046' PropertyId='33043-{rawFailure}'/>",
                Expected: (string?)null),
            (Xml: $"<t:ExtendedFieldURI PropertyTag='0x1080-{rawFailure}'/>", Expected: (string?)null)
        })
        {
            var body = SoapResponse("GetItem", "ErrorInvalidPropertySet", rawFailure, "Error")
                .Replace("</m:GetItemResponseMessage>", "<m:MessageXml>" + field.Xml
                    + "<t:Value>" + rawFailure + "</t:Value></m:MessageXml></m:GetItemResponseMessage>", StringComparison.Ordinal);
            var fieldClient = NewEwsClient(new DelegateHandler((_, _) => Task.FromResult(Response(body))));
            EwsRequestFailedException? captured = null;
            try { await fieldClient.GetMessageAsync("alice@example.test", "message-1", CancellationToken.None); }
            catch (EwsRequestFailedException exception) { captured = exception; }
            Expect(captured is not null && captured.ErrorField == field.Expected
                && !JsonSerializer.Serialize(new { captured.Message, captured.ResponseCode, captured.Operation, captured.ErrorField })
                    .Contains(rawFailure, StringComparison.Ordinal),
                "Native failure field metadata was lost or exposed unrecognized fields, PropertyName or values.");
        }
        var permissionClient = NewEwsClient(new DelegateHandler((_, _) => Task.FromResult(
            new HttpResponseMessage(HttpStatusCode.InternalServerError)
            { Content = new StringContent(SoapResponse("GetItem", "ErrorSendAsDenied", rawFailure, "Error"), Encoding.UTF8, "text/xml") })));
        EwsPermissionDeniedException? permissionFailure = null;
        try { await permissionClient.GetMessageAsync("alice@example.test", "message-1", CancellationToken.None); }
        catch (EwsPermissionDeniedException exception) { permissionFailure = exception; }
        Expect(permissionFailure is not null && permissionFailure.ResponseCode == "ErrorSendAsDenied"
            && permissionFailure.Operation == "GetItem" && !permissionFailure.Message.Contains(rawFailure, StringComparison.Ordinal),
            "Native failure fidelity changed the existing permission exception contract.");
    }

    private async Task McpChecksAsync()
    {
        var exchange = new RecordingEwsHandler();
        await using var host = await StartHostAsync(exchange, writesEnabled: true, sendEnabled: false);
        var client = host.Client;

        var metadata = await client.GetAsync("/.well-known/oauth-protected-resource");
        Expect(metadata.StatusCode == HttpStatusCode.OK, "Protected-resource metadata was not public over HTTPS.");
        var metadataText = await metadata.Content.ReadAsStringAsync();
        Expect(metadataText.Contains(Resource, StringComparison.Ordinal)
            && metadataText.Contains(Authority, StringComparison.Ordinal), "Metadata did not advertise the configured resource.");
        await AssertMetadataScopesAsync(host, [MailboxAccess.Read, MailboxAccess.Write, MailboxAccess.Manage, "offline_access"]);

        await using (var readOnly = await StartHostAsync(new RecordingEwsHandler(), writesEnabled: false, sendEnabled: false))
            await AssertMetadataScopesAsync(readOnly, [MailboxAccess.Read, "offline_access"]);
        await using (var sendEnabled = await StartHostAsync(new RecordingEwsHandler(), writesEnabled: true, sendEnabled: true))
            await AssertMetadataScopesAsync(sendEnabled, [MailboxAccess.Read, MailboxAccess.Write, MailboxAccess.Manage, MailboxAccess.Send, "offline_access"]);
        Expect(MailboxAccess.Scopes.SequenceEqual([MailboxAccess.Read, MailboxAccess.Write, MailboxAccess.Manage, MailboxAccess.Send]),
            "Optional OAuth continuation changed the four mailbox authorization scopes.");

        static async Task AssertMetadataScopesAsync(TestHostContext context, string[] expected)
        {
            foreach (var path in new[] { "/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp" })
            {
                using var response = await context.Client.GetAsync(path);
                Expect(response.StatusCode == HttpStatusCode.OK, $"Protected-resource metadata endpoint {path} was not public over HTTPS.");
                using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
                var actual = document.RootElement.GetProperty("scopes_supported").EnumerateArray()
                    .Select(scope => scope.GetString())
                    .ToArray();
                Expect(actual.SequenceEqual(expected, StringComparer.Ordinal),
                    $"Protected-resource metadata endpoint {path} advertised the wrong scopes.");
            }
        }

        var noAuth = await SendMcpAsync(client, null, InitializeBody());
        Expect(noAuth.StatusCode == HttpStatusCode.Unauthorized, "Unauthenticated MCP request was not rejected.");
        foreach (var invalid in new[]
        {
            Token("user-a", "mail.read", audience: "https://wrong.example.test/mcp"),
            Token("user-a", "mail.read", audience: Resource + "/"),
            Token("user-a", "mail.read", issuer: "https://wrong.example.test/realms/company"),
            Token("user-a", "mail.read", azp: "unknown-client"),
            Token("user-a", "mail.read", tokenType: "ID"),
            ExpiredToken("user-a", "mail.read"),
            ExpiredToken("user-a", "mail.read offline_access"),
            Token("user-a", "mail.read offline_access", audience: "https://wrong.example.test/mcp"),
            Token("user-a", "mail.read offline_access", azp: "unknown-client"),
            InvalidSignatureToken("user-a", "mail.read")
        })
        {
            var response = await SendMcpAsync(client, invalid, InitializeBody());
            Expect(response.StatusCode == HttpStatusCode.Unauthorized, "An invalid JWT was accepted.");
        }

        var noReadScope = await SendMcpAsync(client, Token("user-a", "mail.write"), InitializeBody());
        Expect(noReadScope.StatusCode == HttpStatusCode.Forbidden,
            $"A token without mail.read was accepted (HTTP {(int)noReadScope.StatusCode}).");
        var offlineOnly = await SendMcpAsync(client, Token("user-a", "offline_access"), InitializeBody());
        Expect(offlineOnly.StatusCode == HttpStatusCode.Forbidden, "An offline_access grant authorized mailbox access.");
        var offlineRead = await SendMcpAsync(client, Token("user-a", "mail.read offline_access"), InitializeBody());
        Expect(offlineRead.StatusCode == HttpStatusCode.OK, "Optional offline_access invalidated an authorized mailbox read token.");
        var unmapped = await SendMcpAsync(client, Token("user-z", "mail.read"), InitializeBody());
        Expect(unmapped.StatusCode == HttpStatusCode.Forbidden, "An unmapped mailbox subject was accepted.");

        var plaintextClient = host.App.GetTestClient();
        plaintextClient.BaseAddress = new Uri("http://mail.example.test/");
        var plaintext = await SendMcpAsync(plaintextClient, Token("user-a", "mail.read"), InitializeBody());
        Expect(plaintext.StatusCode == HttpStatusCode.BadRequest, "Plaintext MCP transport was accepted.");
        var wrongHost = await SendMcpAsync(client, Token("user-a", "mail.read"), InitializeBody(), absoluteUri: "https://wrong.example.test/mcp");
        Expect(wrongHost.StatusCode == HttpStatusCode.BadRequest, "A request for the wrong resource host was accepted.");
        var badOrigin = await SendMcpAsync(client, Token("user-a", "mail.read"), InitializeBody(), origin: "https://evil.example.test");
        Expect(badOrigin.StatusCode == HttpStatusCode.Forbidden, "An unapproved Origin was accepted.");

        var userAToken = Token("user-a", "mail.read mail.write mail.manage mail.send");
        await InitializeAsync(client, userAToken);
        var tools = await ToolRequestAsync(client, userAToken, "tools/list", new { });
        Expect(tools.StatusCode == HttpStatusCode.OK, "tools/list failed for a valid token.");
        var toolDocument = ParseJson(tools.Body);
        var toolCatalog = toolDocument.RootElement.GetProperty("result").GetProperty("tools");
        Expect(toolCatalog.EnumerateArray().All(tool => tool.TryGetProperty("description", out var description)
            && !string.IsNullOrWhiteSpace(description.GetString())), "A tool lacks usable agent guidance.");
        var toolNames = toolCatalog.EnumerateArray().Select(tool => tool.GetProperty("name").GetString()).ToHashSet(StringComparer.Ordinal);
        Expect(new[] { "calendar_create_event", "calendar_update_event", "calendar_respond", "calendar_search",
            "calendar_read_meeting_message", "calendar_move_event", "calendar_copy_event", "people_create_contact",
            "task_create", "task_update", "mail_signatures", "mail_apply_signature", "groupware_create_attachment",
            "calendar_read_series", "calendar_list_room_lists", "calendar_list_rooms", "calendar_find_meeting_times",
            "mail_oof", "mail_set_oof", "mail_inbox_rules", "mail_create_inbox_rule", "mail_update_inbox_rule",
            "mail_delete_inbox_rule", "sharing_get_folder_permissions", "sharing_set_folder_permission",
            "sharing_remove_folder_permission", "delegate_list", "delegate_add", "delegate_update", "delegate_remove",
            "mail_sync_folders", "mail_sync_items" }
            .All(toolNames.Contains), "The groupware tool catalog is incomplete.");
        var toolJson = toolCatalog.GetRawText();
        Expect(!toolJson.Contains("ClaimsPrincipal", StringComparison.Ordinal)
            && !toolJson.Contains("CancellationToken", StringComparison.Ordinal)
            && !toolJson.Contains("\"mailbox\"", StringComparison.OrdinalIgnoreCase),
            "The MCP tool schema exposed an injected security parameter.");

        var searchA = await ToolRequestAsync(client, userAToken, "tools/call", new
        {
            name = "mail_search",
            arguments = new { folder = "inbox", offset = 0, limit = 20 }
        });
        Expect(searchA.StatusCode == HttpStatusCode.OK, "User A mailbox search failed.");
        var searchAData = ToolStructuredData(searchA.Body);
        var messageHandle = searchAData.GetProperty("items")[0].GetProperty("handle").GetString()!;
        var userBToken = Token("user-b", "mail.read mail.write mail.manage mail.send");
        var searchB = await ToolRequestAsync(client, userBToken, "tools/call", new
        {
            name = "mail_search",
            arguments = new { folder = "inbox", offset = 0, limit = 20 }
        });
        Expect(searchB.StatusCode == HttpStatusCode.OK, "User B mailbox search failed.");
        var calls = exchange.Calls.Where(call => call.Operation == "FindItem").ToArray();
        Expect(calls.Any(call => call.PrimarySmtpAddress == "alice@example.test")
            && calls.Any(call => call.PrimarySmtpAddress == "bob@example.test"),
            "EWS impersonation did not follow the authenticated mailbox mapping.");
        Expect(calls.All(call => call.Authorization is null), "The ChatGPT bearer token was forwarded to EWS.");

        var beforeCrossUser = exchange.Calls.Count;
        var crossUser = await ToolRequestAsync(client, userBToken, "tools/call", new
        {
            name = "mail_read",
            arguments = new { messageHandle }
        });
        Expect(IsToolError(crossUser.Body) && exchange.Calls.Count == beforeCrossUser,
            $"A user B request reused a user A message handle or reached EWS (status={(int)crossUser.StatusCode}, toolError={IsToolError(crossUser.Body)}, calls={exchange.Calls.Count - beforeCrossUser}).");
        var tampered = messageHandle[..^1] + (messageHandle[^1] == 'A' ? 'B' : 'A');
        var beforeTamper = exchange.Calls.Count;
        var tamperedResponse = await ToolRequestAsync(client, userAToken, "tools/call", new
        {
            name = "mail_read",
            arguments = new { messageHandle = tampered }
        });
        Expect(IsToolError(tamperedResponse.Body) && exchange.Calls.Count == beforeTamper,
            "A tampered message handle reached EWS.");

        foreach (var readScopes in new[] { "mail.read", "mail.read offline_access" })
        {
            var readOnlyDraft = await ToolRequestAsync(client, Token("user-a", readScopes), "tools/call", new
            {
                name = "mail_create_draft",
                arguments = new { subject = "x", body = "y", to = new[] { "to@example.test" } }
            });
            Expect(readOnlyDraft.StatusCode == HttpStatusCode.OK && IsToolError(readOnlyDraft.Body),
                "A read-only token reached a write tool.");
        }
        var draft = await ToolRequestAsync(client, userAToken, "tools/call", new
        {
            name = "mail_create_draft",
            arguments = new { subject = "x", body = "y", to = new[] { "to@example.test" } }
        });
        Expect(draft.StatusCode == HttpStatusCode.OK && !IsToolError(draft.Body), "A permitted draft write failed.");
        var sendDisabled = await ToolRequestAsync(client, userAToken, "tools/call", new
        {
            name = "mail_send_draft",
            arguments = new { draftHandle = messageHandle }
        });
        Expect(sendDisabled.StatusCode == HttpStatusCode.OK && IsToolError(sendDisabled.Body),
            "Send was available while SendEnabled was false.");

        var folders = await ToolRequestAsync(client, userAToken, "tools/call", new
        {
            name = "mail_list_folders",
            arguments = new { }
        });
        Expect(folders.StatusCode == HttpStatusCode.OK && !IsToolError(folders.Body), "Folder listing failed.");
        var folderData = ToolStructuredData(folders.Body);
        var folderHandle = folderData[0].GetProperty("handle").GetString();
        Expect(!string.IsNullOrWhiteSpace(folderHandle), "Folder listing did not return a handle.");

        var restartExchange = new RecordingEwsHandler();
        await using var restarted = await StartHostAsync(restartExchange, writesEnabled: true, sendEnabled: false);
        var restartResult = await ToolRequestAsync(restarted.Client, userAToken, "tools/call", new
        {
            name = "mail_search",
            arguments = new { folder = folderHandle, offset = 0, limit = 20 }
        });
        Expect(IsToolError(restartResult.Body) && restartExchange.Calls.Count == 0,
            "A handle survived an application restart or reached EWS.");
    }

    private async Task MrtrChecksAsync()
    {
        var exchange = new RecordingEwsHandler { DraftMode = true };
        await using var host = await StartHostAsync(exchange, writesEnabled: true, sendEnabled: true);
        var token = Token("user-a", "mail.read mail.write mail.manage mail.send", sessionId: "session-1");
        await InitializeAsync(host.Client, token, elicitation: true);

        var draftResult = await ToolRequestAsync(host.Client, token, "tools/call", new
        {
            name = "mail_create_draft",
            arguments = new { subject = "MRTR subject", body = "MRTR body", to = new[] { "to@example.test" } }
        });
        Expect(draftResult.StatusCode == HttpStatusCode.OK && !IsToolError(draftResult.Body),
            "The MRTR fixture draft could not be created.");
        var draftHandle = ToolStructuredData(draftResult.Body).GetProperty("handle").GetString()!;

        var approvalRequest = await ToolRequestAsync(host.Client, token, "tools/call", new
        {
            name = "mail_send_draft",
            arguments = new { draftHandle }
        }, JulyProtocolVersion, elicitation: true);
        Expect(approvalRequest.StatusCode == HttpStatusCode.OK,
            "The send approval request did not return an MCP response.");
        Expect(approvalRequest.Body.Contains("requestState", StringComparison.Ordinal)
            && approvalRequest.Body.Contains("send_confirmation", StringComparison.Ordinal),
            "The MRTR send approval response did not contain opaque state and confirmation input.");
        var firstState = InputRequiredState(approvalRequest.Body);

        var denied = await ToolRequestAsync(host.Client, token, "tools/call", new
        {
            name = "mail_send_draft",
            requestState = firstState,
            inputResponses = new Dictionary<string, object?>
            {
                ["send_confirmation"] = new { action = "decline", content = new { confirm = false } }
            },
            arguments = new { draftHandle }
        }, JulyProtocolVersion, elicitation: true);
        Expect(denied.StatusCode == HttpStatusCode.OK && !IsToolError(denied.Body)
            && ToolStructuredData(denied.Body).GetProperty("sent").GetBoolean() == false
            && exchange.SendCount == 0,
            "A declined MRTR send was not cancelled before Exchange.");

        var secondApproval = await ToolRequestAsync(host.Client, token, "tools/call", new
        {
            name = "mail_send_draft",
            arguments = new { draftHandle }
        }, JulyProtocolVersion, elicitation: true);
        var secondState = InputRequiredState(secondApproval.Body);

        var alternateClient = Token("user-a", "mail.read mail.write mail.manage mail.send",
            azp: "chatgpt-alt", sessionId: "session-1");
        var beforeAlternate = exchange.SendCount;
        var alternateClientRetry = await ToolRequestAsync(host.Client, alternateClient, "tools/call", new
        {
            name = "mail_send_draft",
            requestState = secondState,
            inputResponses = new Dictionary<string, object?>
            {
                ["send_confirmation"] = new { action = "accept", content = new { confirm = true } }
            },
            arguments = new { draftHandle }
        }, JulyProtocolVersion, elicitation: true);
        Expect(alternateClientRetry.StatusCode == HttpStatusCode.OK && IsToolError(alternateClientRetry.Body)
            && exchange.SendCount == beforeAlternate,
            $"An approval was reusable by another approved OAuth client (status={(int)alternateClientRetry.StatusCode}, toolError={IsToolError(alternateClientRetry.Body)}, sends={exchange.SendCount - beforeAlternate}).");

        var changedSession = Token("user-a", "mail.read mail.write mail.manage mail.send",
            sessionId: "session-2");
        var beforeSession = exchange.SendCount;
        var changedSessionRetry = await ToolRequestAsync(host.Client, changedSession, "tools/call", new
        {
            name = "mail_send_draft",
            requestState = secondState,
            inputResponses = new Dictionary<string, object?>
            {
                ["send_confirmation"] = new { action = "accept", content = new { confirm = true } }
            },
            arguments = new { draftHandle }
        }, JulyProtocolVersion, elicitation: true);
        Expect(changedSessionRetry.StatusCode == HttpStatusCode.OK && IsToolError(changedSessionRetry.Body)
            && exchange.SendCount == beforeSession,
            "An approval was reusable from a different session.");

        var beforeMissingCapability = exchange.Calls.Count;
        var missingCapabilityRetry = await ToolRequestAsync(host.Client, token, "tools/call", new
        {
            name = "mail_send_draft",
            requestState = secondState,
            inputResponses = new Dictionary<string, object?>
            {
                ["send_confirmation"] = new { action = "accept", content = new { confirm = true } }
            },
            arguments = new { draftHandle }
        }, JulyProtocolVersion, elicitation: false);
        var missingCapabilityBlocked = missingCapabilityRetry.StatusCode is HttpStatusCode.OK or HttpStatusCode.BadRequest
            && IsToolError(missingCapabilityRetry.Body)
            && exchange.Calls.Count == beforeMissingCapability + 1
            && exchange.LastRequest.Operation == "GetItem" && exchange.SendCount == 0;
        Expect(missingCapabilityBlocked,
            $"A retry without MRTR form capability did not stop after the current draft read (status={(int)missingCapabilityRetry.StatusCode}, toolError={IsToolError(missingCapabilityRetry.Body)}, calls={exchange.Calls.Count - beforeMissingCapability}).");

        var forgedState = secondState[..^1] + (secondState[^1] == 'A' ? 'B' : 'A');
        var forged = await ToolRequestAsync(host.Client, token, "tools/call", new
        {
            name = "mail_send_draft",
            requestState = forgedState,
            inputResponses = new Dictionary<string, object?>
            {
                ["send_confirmation"] = new { action = "accept", content = new { confirm = true } }
            },
            arguments = new { draftHandle }
        }, JulyProtocolVersion, elicitation: true);
        Expect(forged.StatusCode == HttpStatusCode.OK && IsToolError(forged.Body) && exchange.SendCount == 0,
            "A forged MRTR approval state reached the send path.");

        var changedApproval = await ToolRequestAsync(host.Client, token, "tools/call", new
        {
            name = "mail_send_draft",
            arguments = new { draftHandle }
        }, JulyProtocolVersion, elicitation: true);
        var changedState = InputRequiredState(changedApproval.Body);
        exchange.DraftSubject = "Changed after approval";
        var changedDraft = await ToolRequestAsync(host.Client, token, "tools/call", new
        {
            name = "mail_send_draft",
            requestState = changedState,
            inputResponses = new Dictionary<string, object?>
            {
                ["send_confirmation"] = new { action = "accept", content = new { confirm = true } }
            },
            arguments = new { draftHandle }
        }, JulyProtocolVersion, elicitation: true);
        exchange.DraftSubject = "MRTR subject";
        Expect(changedDraft.StatusCode == HttpStatusCode.OK && IsToolError(changedDraft.Body)
            && exchange.SendCount == 0,
            "A changed draft was accepted after approval.");

        var accepted = await ToolRequestAsync(host.Client, token, "tools/call", new
        {
            name = "mail_send_draft",
            requestState = secondState,
            inputResponses = new Dictionary<string, object?>
            {
                ["send_confirmation"] = new { action = "accept", content = new { confirm = true } }
            },
            arguments = new { draftHandle }
        }, JulyProtocolVersion, elicitation: true);
        Expect(accepted.StatusCode == HttpStatusCode.OK && !IsToolError(accepted.Body)
            && ToolStructuredData(accepted.Body).GetProperty("status").GetString() == "sent"
            && exchange.SendCount == 1,
            "An accepted MRTR send did not reach Exchange exactly once.");

        var replay = await ToolRequestAsync(host.Client, token, "tools/call", new
        {
            name = "mail_send_draft",
            requestState = secondState,
            inputResponses = new Dictionary<string, object?>
            {
                ["send_confirmation"] = new { action = "accept", content = new { confirm = true } }
            },
            arguments = new { draftHandle }
        }, JulyProtocolVersion, elicitation: true);
        Expect(replay.StatusCode == HttpStatusCode.OK && IsToolError(replay.Body) && exchange.SendCount == 1,
            "A replayed MRTR approval was accepted or retried against Exchange.");

        await AssertRecipientGateAsync("unresolved", "incomplete recipient");
        await AssertRecipientGateAsync("non-smtp", "non-SMTP recipient routing");
    }

    private async Task IntrospectionChecksAsync()
    {
        var activeIntrospection = new IntrospectionHandler();
        await using (var active = await StartHostAsync(new RecordingEwsHandler(), writesEnabled: true,
            sendEnabled: false, introspection: activeIntrospection))
        {
            var response = await SendMcpAsync(active.Client,
                Token("user-a", "mail.read"), InitializeBody());
            Expect(response.StatusCode == HttpStatusCode.OK && activeIntrospection.Calls == 1,
                "An active introspected token was not accepted.");
            Expect(activeIntrospection.LastAuthorization is null
                && activeIntrospection.LastForm is not null
                && WebUtility.UrlDecode(activeIntrospection.LastForm).Contains($"client_id={Resource}", StringComparison.Ordinal)
                && WebUtility.UrlDecode(activeIntrospection.LastForm).Contains("client_secret=synthetic-introspection-secret", StringComparison.Ordinal)
                && WebUtility.UrlDecode(activeIntrospection.LastForm).Contains("token=", StringComparison.Ordinal),
                "Introspection did not use client_secret_post or received a bearer header.");
            var continued = await SendMcpAsync(active.Client,
                Token("user-a", "mail.read offline_access"), InitializeBody());
            Expect(continued.StatusCode == HttpStatusCode.OK && activeIntrospection.Calls == 2,
                "Optional offline_access bypassed or failed the current token introspection check.");
        }

        foreach (var mode in new[] { "inactive", "mismatch", "unavailable", "oversized", "wrong-type" })
        {
            var introspection = new IntrospectionHandler { Mode = mode };
            var exchange = new RecordingEwsHandler();
            await using var host = await StartHostAsync(exchange, writesEnabled: true,
                sendEnabled: false, introspection: introspection);
            foreach (var scopes in new[] { "mail.read", "mail.read offline_access" })
            {
                var response = await SendMcpAsync(host.Client, Token("user-a", scopes), InitializeBody());
                Expect(response.StatusCode == HttpStatusCode.Unauthorized && exchange.Calls.Count == 0,
                    $"Introspection mode '{mode}' did not fail closed before EWS.");
            }
        }
    }

    private async Task AssertRecipientGateAsync(string mode, string label)
    {
        var exchange = new RecordingEwsHandler { DraftMode = true, DraftRecipientMode = mode };
        await using var host = await StartHostAsync(exchange, writesEnabled: true, sendEnabled: true);
        var token = Token("user-a", "mail.read mail.write mail.manage mail.send", sessionId: $"recipient-{mode}");
        await InitializeAsync(host.Client, token, elicitation: true);
        var draftResult = await ToolRequestAsync(host.Client, token, "tools/call", new
        {
            name = "mail_create_draft",
            arguments = new { subject = "Recipient gate", body = "body", to = new[] { "to@example.test" } }
        });
        Expect(draftResult.StatusCode == HttpStatusCode.OK && !IsToolError(draftResult.Body),
            $"The {label} fixture draft could not be created.");
        var draftHandle = ToolStructuredData(draftResult.Body).GetProperty("handle").GetString()!;
        var result = await ToolRequestAsync(host.Client, token, "tools/call", new
        {
            name = "mail_send_draft",
            arguments = new { draftHandle }
        }, JulyProtocolVersion, elicitation: true);
        Expect(result.StatusCode == HttpStatusCode.OK && IsToolError(result.Body) && exchange.SendCount == 0,
            $"The {label} was allowed into the send path.");
    }

    private async Task AssertEwsFailureAsync(HttpMessageHandler handler, params string[] forbidden)
    {
        var client = NewEwsClient(handler);
        var accepted = false;
        try
        {
            await client.GetMessageAsync("alice@example.test", "message-1", CancellationToken.None);
            accepted = true;
        }
        catch (InvalidOperationException exception)
        {
            foreach (var value in forbidden)
                Expect(!exception.Message.Contains(value, StringComparison.Ordinal), "An EWS error leaked response data.");
        }
        Expect(!accepted, "An invalid EWS response was accepted.");
    }

    private EwsClient NewEwsClient(HttpMessageHandler handler, long maxResponseBytes = 2_097_152,
        LdapMailboxPermissionReader? taskDirectory = null)
    {
        var http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(10) };
        return new EwsClient(http, Microsoft.Extensions.Options.Options.Create(new EwsOptions
        {
            Endpoint = "https://mail.example.test/EWS/Exchange.asmx",
            TimeoutSeconds = 10,
            MaxResponseBytes = maxResponseBytes
        }), taskDirectory: taskDirectory);
    }

    private async Task<TestHostContext> StartHostAsync(HttpMessageHandler exchange, bool writesEnabled,
        bool sendEnabled, IntrospectionHandler? introspection = null, bool classicStateful = false,
        Action<WebApplicationBuilder>? configure = null)
    {
        var passwordPath = Path.Combine(runDirectory, "exchange-password.txt");
        var introspectionSecretPath = Path.Combine(runDirectory, "keycloak-introspection-secret.txt");
        var auditPath = Path.Combine(runDirectory, $"audit-{Guid.NewGuid():N}.jsonl");
        await File.WriteAllTextAsync(passwordPath, "synthetic-password");
        await File.WriteAllTextAsync(introspectionSecretPath, "synthetic-introspection-secret");
        var app = AppHost.Create([], builder =>
        {
            builder.WebHost.UseTestServer();
            if (!classicStateful)
                builder.Services.PostConfigure<ModelContextProtocol.AspNetCore.HttpServerTransportOptions>(options =>
                    options.SessionMode = ModelContextProtocol.AspNetCore.HttpServerSessionMode.Stateless);
            builder.Configuration.AddInMemoryCollection(ConfigurationValues(passwordPath, introspectionSecretPath,
                auditPath, writesEnabled, sendEnabled));
            builder.Services.PostConfigure<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme, options =>
            {
                var configuration = new OpenIdConnectConfiguration { Issuer = Authority };
                configuration.SigningKeys.Add(signingKey);
                options.Configuration = configuration;
                options.ConfigurationManager = new StaticConfigurationManager<OpenIdConnectConfiguration>(configuration);
            });
            builder.Services.AddHttpClient<EwsClient>()
                .ConfigurePrimaryHttpMessageHandler(() => exchange);
            builder.Services.AddHttpClient<KeycloakTokenStatus>()
                .ConfigurePrimaryHttpMessageHandler(() => introspection ?? new IntrospectionHandler());
            configure?.Invoke(builder);
        });
        await app.StartAsync();
        var client = app.GetTestClient();
        client.BaseAddress = new Uri("https://mail.example.test/");
        return new TestHostContext(app, client);
    }

    private static Dictionary<string, string?> ConfigurationValues(
        string passwordPath, string introspectionSecretPath, string auditPath,
        bool writesEnabled, bool sendEnabled) => new()
        {
            ["Service:Authority"] = Authority,
            ["Service:Resource"] = Resource,
            ["Service:IntrospectionClientId"] = Resource,
            ["Service:IntrospectionSecretFile"] = introspectionSecretPath,
            ["Service:AllowedClientIds:0"] = "chatgpt-test",
            ["Service:AllowedClientIds:1"] = "chatgpt-alt",
            ["Service:AllowedOrigins:0"] = "https://allowed.example.test",
            ["Service:AllowedRecipientDomains:0"] = "example.test",
            ["Service:Mailboxes:user-a"] = "alice@example.test",
            ["Service:Mailboxes:user-b"] = "bob@example.test",
            ["Service:WritesEnabled"] = writesEnabled.ToString(),
            ["Service:SendEnabled"] = sendEnabled.ToString(),
            ["Service:AuditPath"] = auditPath,
            ["Service:RequestsPerMinute"] = "1000",
            ["Service:ConcurrentRequests"] = "8",
            ["Exchange:Endpoint"] = "https://mail.example.test/EWS/Exchange.asmx",
            ["Exchange:Username"] = "synthetic-service",
            ["Exchange:Domain"] = "EXAMPLE",
            ["Exchange:PasswordFile"] = passwordPath,
            ["Exchange:TimeoutSeconds"] = "10",
            ["Exchange:MaxResponseBytes"] = "2097152"
        };

    private string Token(
        string subject,
        string scope,
        string? issuer = null,
        string? audience = null,
        string? azp = null,
        string tokenType = "Bearer",
        string? sessionId = null,
        string[]? audiences = null)
    {
        var claims = new Dictionary<string, object>
        {
            ["sub"] = subject,
            ["scope"] = scope,
            ["azp"] = azp ?? "chatgpt-test",
            ["typ"] = tokenType
        };
        if (sessionId is not null) claims["sid"] = sessionId;
        if (audiences is not null) claims["aud"] = audiences;
        return tokenHandler.WriteToken(tokenHandler.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = issuer ?? Authority,
            Audience = audiences is null ? audience ?? Resource : null,
            Claims = claims,
            NotBefore = DateTime.UtcNow.AddSeconds(-5),
            Expires = DateTime.UtcNow.AddMinutes(5),
            SigningCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.RsaSha256),
            TokenType = "JWT"
        }));
    }

    private string ExpiredToken(string subject, string scope) =>
        tokenHandler.WriteToken(tokenHandler.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = Authority,
            Audience = Resource,
            Claims = new Dictionary<string, object>
            {
                ["sub"] = subject,
                ["scope"] = scope,
                ["azp"] = "chatgpt-test",
                ["typ"] = "Bearer"
            },
            NotBefore = DateTime.UtcNow.AddMinutes(-10),
            Expires = DateTime.UtcNow.AddMinutes(-5),
            SigningCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.RsaSha256),
            TokenType = "JWT"
        }));

    private string InvalidSignatureToken(string subject, string scope)
    {
        using var rsa = RSA.Create(2048);
        var key = new RsaSecurityKey(rsa) { KeyId = "wrong-key" };
        return tokenHandler.WriteToken(tokenHandler.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = Authority,
            Audience = Resource,
            Claims = new Dictionary<string, object>
            {
                ["sub"] = subject,
                ["scope"] = scope,
                ["azp"] = "chatgpt-test",
                ["typ"] = "Bearer"
            },
            NotBefore = DateTime.UtcNow.AddSeconds(-5),
            Expires = DateTime.UtcNow.AddMinutes(5),
            SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.RsaSha256),
            TokenType = "JWT"
        }));
    }

    private static object InitializeBody(bool elicitation = false)
    {
        object capabilities = elicitation
            ? new { elicitation = new { form = new { } } }
            : new { };
        return new
        {
            jsonrpc = "2.0",
            id = 1,
            method = "initialize",
            @params = new
            {
                protocolVersion = ProtocolVersion,
                capabilities,
                clientInfo = new { name = "company-exchange-checks", version = "1.0" }
            }
        };
    }

    private static async Task InitializeAsync(HttpClient client, string token, bool elicitation = false)
    {
        var response = await SendMcpAsync(client, token, InitializeBody(elicitation));
        Expect(response.StatusCode == HttpStatusCode.OK, "MCP initialize failed.");
        using var json = ParseJson(response.Body);
        Expect(json.RootElement.TryGetProperty("result", out var result)
            && result.TryGetProperty("protocolVersion", out _), "MCP initialize response was malformed.");
        var notification = await SendMcpAsync(client, token, new { jsonrpc = "2.0", method = "notifications/initialized", @params = new { } });
        Expect((int)notification.StatusCode is 200 or 202, "MCP initialized notification failed.");
    }

    private static async Task<(HttpStatusCode StatusCode, string Body)> ToolRequestAsync(
        HttpClient client, string token, string method, object parameters,
        string protocolVersion = ProtocolVersion, bool elicitation = false, string? absoluteUri = null)
    {
        object requestParameters = parameters;
        if (protocolVersion == JulyProtocolVersion)
        {
            var node = JsonSerializer.SerializeToNode(parameters)!.AsObject();
            node["_meta"] = new JsonObject
            {
                ["io.modelcontextprotocol/protocolVersion"] = JulyProtocolVersion,
                ["io.modelcontextprotocol/clientInfo"] = new JsonObject
                {
                    ["name"] = "company-exchange-checks",
                    ["version"] = "1.0"
                },
                ["io.modelcontextprotocol/clientCapabilities"] = elicitation
                    ? new JsonObject { ["elicitation"] = new JsonObject { ["form"] = new JsonObject() } }
                    : new JsonObject()
            };
            requestParameters = node;
        }

        return await SendMcpAsync(client, token,
            new { jsonrpc = "2.0", id = Random.Shared.Next(10, 1_000_000), method, @params = requestParameters },
            protocolVersion: protocolVersion, mcpMethod: method, absoluteUri: absoluteUri,
            mcpName: method == "tools/call" ? ((JsonObject)JsonSerializer.SerializeToNode(parameters)!).TryGetPropertyValue("name", out var name) ? name?.GetValue<string>() : null : null);
    }

    private static async Task<(HttpStatusCode StatusCode, string Body)> SendMcpAsync(
        HttpClient client,
        string? token,
        object body,
        string? origin = null,
        string? absoluteUri = null,
        string protocolVersion = ProtocolVersion,
        string? mcpMethod = null,
        string? mcpName = null)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, absoluteUri ?? "/mcp")
        {
            Content = new StringContent(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json")
        };
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("text/event-stream"));
        request.Headers.TryAddWithoutValidation("MCP-Protocol-Version", protocolVersion);
        if (protocolVersion == JulyProtocolVersion)
        {
            request.Headers.TryAddWithoutValidation("Mcp-Method", mcpMethod ?? string.Empty);
            if (mcpName is not null) request.Headers.TryAddWithoutValidation("Mcp-Name", mcpName);
        }
        if (!string.IsNullOrWhiteSpace(token)) request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        if (origin is not null) request.Headers.TryAddWithoutValidation("Origin", origin);
        using var response = await client.SendAsync(request);
        return (response.StatusCode, await response.Content.ReadAsStringAsync());
    }

    private static JsonDocument ParseJson(string body)
    {
        var candidate = body.Trim();
        var data = candidate.Split('\n')
            .Where(line => line.StartsWith("data:", StringComparison.Ordinal))
            .Select(line => line[5..].Trim())
            .LastOrDefault();
        return JsonDocument.Parse(data ?? candidate);
    }

    private static JsonElement ToolStructuredData(string body)
    {
        using var json = ParseJson(body);
        var result = json.RootElement.GetProperty("result");
        if (result.TryGetProperty("structuredContent", out var structured)) return structured.Clone();
        var text = result.GetProperty("content")[0].GetProperty("text").GetString()!;
        using var fallback = JsonDocument.Parse(text);
        return fallback.RootElement.Clone();
    }

    private static bool IsToolError(string body)
    {
        using var json = ParseJson(body);
        if (json.RootElement.TryGetProperty("error", out _)) return true;
        return json.RootElement.TryGetProperty("result", out var result)
            && result.TryGetProperty("isError", out var isError) && isError.GetBoolean();
    }

    private static string InputRequiredState(string body)
    {
        using var json = ParseJson(body);
        var result = json.RootElement.GetProperty("result");
        Expect(result.GetProperty("resultType").GetString() == "input_required",
            "The send response was not an MRTR input-required result.");
        var state = result.GetProperty("requestState").GetString();
        Expect(!string.IsNullOrWhiteSpace(state), "The MRTR response omitted request state.");
        return state!;
    }

    private static XElement Operation(XDocument document) =>
        document.Root!.Element(XName.Get("Body", SoapNamespace))!.Elements().Single();

    private static HttpResponseMessage Response(string body) =>
        new(HttpStatusCode.OK) { Content = new StringContent(body, Encoding.UTF8, "text/xml") };

    private static string SoapResponse(string operation, string code, string messageText,
        string responseClass = "Success") =>
        $"<s:Envelope xmlns:s='{SoapNamespace}' xmlns:m='{MessagesNamespace}' xmlns:t='{TypesNamespace}'><s:Body>"
        + $"<m:{operation}Response><m:ResponseMessages><m:{operation}ResponseMessage ResponseClass='{responseClass}'>"
        + $"<m:ResponseCode>{code}</m:ResponseCode><m:MessageText>{System.Security.SecurityElement.Escape(messageText)}</m:MessageText>"
        + $"</m:{operation}ResponseMessage></m:ResponseMessages></m:{operation}Response></s:Body></s:Envelope>";

    private static string SoapResponseWithSecondError() =>
        $"<s:Envelope xmlns:s='{SoapNamespace}' xmlns:m='{MessagesNamespace}' xmlns:t='{TypesNamespace}'><s:Body>"
        + "<m:GetItemResponse><m:ResponseMessages>"
        + "<m:GetItemResponseMessage ResponseClass='Success'><m:ResponseCode>NoError</m:ResponseCode></m:GetItemResponseMessage>"
        + "<m:GetItemResponseMessage ResponseClass='Success'>"
        + "<m:MessageText>secret-body</m:MessageText></m:GetItemResponseMessage>"
        + "</m:ResponseMessages></m:GetItemResponse></s:Body></s:Envelope>";

    private static void Expect(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException(message);
    }

    public void Dispose()
    {
        signingRsa.Dispose();
        if (Directory.Exists(runDirectory)) Directory.Delete(runDirectory, recursive: true);
    }
}

internal sealed record TestHostContext(WebApplication App, HttpClient Client) : IAsyncDisposable
{
    public async ValueTask DisposeAsync()
    {
        Client.Dispose();
        await App.DisposeAsync();
    }
}

internal sealed record CapturedEwsRequest(
    string Operation,
    string Body,
    HttpRequestHeaders Headers,
    string? PrimarySmtpAddress,
    HttpHeaders? ResponseHeaders = null)
{
    public AuthenticationHeaderValue? Authorization => Headers.Authorization;
}

internal sealed class IntrospectionHandler : HttpMessageHandler
{
    public string Mode { get; set; } = "active";
    public int Calls { get; private set; }
    public string? LastForm { get; private set; }
    public AuthenticationHeaderValue? LastAuthorization { get; private set; }

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        Calls++;
        LastAuthorization = request.Headers.Authorization;
        var form = await request.Content!.ReadAsStringAsync(cancellationToken);
        LastForm = form;
        if (Mode == "unavailable") throw new HttpRequestException("synthetic provider unavailable");
        if (Mode == "oversized")
        {
            return JsonResponse(new { active = true, payload = new string('x', 65 * 1024) });
        }

        var token = form.Split('&', StringSplitOptions.RemoveEmptyEntries)
            .Select(pair => pair.Split('=', 2))
            .Where(parts => parts.Length == 2 && parts[0] == "token")
            .Select(parts => WebUtility.UrlDecode(parts[1]))
            .SingleOrDefault();
        if (string.IsNullOrWhiteSpace(token)) return JsonResponse(new { active = false });

        JwtSecurityToken jwt;
        try { jwt = new JwtSecurityTokenHandler().ReadJwtToken(token); }
        catch (Exception) { return JsonResponse(new { active = false }); }

        var sub = jwt.Claims.FirstOrDefault(x => x.Type == "sub")?.Value;
        var issuer = jwt.Claims.FirstOrDefault(x => x.Type == "iss")?.Value;
        var azp = jwt.Claims.FirstOrDefault(x => x.Type == "azp")?.Value;
        var scope = jwt.Claims.FirstOrDefault(x => x.Type == "scope")?.Value;
        var exp = jwt.Claims.FirstOrDefault(x => x.Type == "exp")?.Value;
        if (Mode == "mismatch") sub = "different-user";
        var response = new Dictionary<string, object?>
        {
            ["active"] = Mode != "inactive",
            ["typ"] = Mode == "wrong-type" ? "Token" : "Bearer",
            ["sub"] = sub,
            ["iss"] = issuer,
            ["aud"] = Mode switch
            {
                "extra-audience" => jwt.Audiences.Append("https://different.example.test/mcp").ToArray(),
                "missing-audience" => jwt.Audiences.Take(1).ToArray(),
                _ => jwt.Audiences.ToArray()
            },
            ["azp"] = azp,
            ["scope"] = scope,
            ["exp"] = long.TryParse(exp, out var expiry) ? expiry : 0
        };
        var guid = jwt.Claims.FirstOrDefault(x => x.Type == "ad_object_guid")?.Value;
        if (guid is not null && Mode != "missing-guid")
            response["ad_object_guid"] = Mode == "mismatch-guid" ? "10000000-0000-0000-0000-000000000000" : guid;
        return JsonResponse(response);
    }

    private static HttpResponseMessage JsonResponse(object value) => new(HttpStatusCode.OK)
    {
        Content = new StringContent(JsonSerializer.Serialize(value), Encoding.UTF8, "application/json")
    };
}

internal sealed class RecordingEwsHandler : HttpMessageHandler
{
    private static readonly XNamespace Soap = "http://schemas.xmlsoap.org/soap/envelope/";
    private static readonly XNamespace M = "http://schemas.microsoft.com/exchange/services/2006/messages";
    private static readonly XNamespace T = "http://schemas.microsoft.com/exchange/services/2006/types";
    public List<CapturedEwsRequest> Calls { get; } = [];
    public bool DraftMode { get; init; }
    public string DraftSubject { get; set; } = "MRTR subject";
    public string DraftChangeKey { get; set; } = "draft-change";
    public bool FailSend { get; init; }
    public string DraftRecipientMode { get; init; } = "smtp";
    public int DraftAttachmentCount { get; init; }
    public long DraftAttachmentBytes { get; init; }
    public string MessageChangeKey { get; set; } = "message-change";
    public string FolderChangeKey { get; set; } = "folder-change";
    public int SendCount { get; private set; }
    public CapturedEwsRequest LastRequest => Calls[^1];

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var body = await request.Content!.ReadAsStringAsync(cancellationToken);
        var document = XDocument.Parse(body);
        var operation = document.Root!.Element(Soap + "Body")!.Elements().Single();
        var mailbox = document.Descendants(T + "PrimarySmtpAddress").SingleOrDefault()?.Value;
        Calls.Add(new CapturedEwsRequest(operation.Name.LocalName, body, request.Headers, mailbox));
        if (operation.Name.LocalName == "SendItem")
        {
            SendCount++;
            if (FailSend) throw new HttpRequestException("Synthetic uncertain send response.");
        }
        return ResponseFor(operation.Name.LocalName, DraftMode, DraftSubject, DraftRecipientMode,
            MessageChangeKey, FolderChangeKey, DraftAttachmentCount, DraftAttachmentBytes, DraftChangeKey);
    }

    private static HttpResponseMessage ResponseFor(string operation, bool draftMode = false,
        string draftSubject = "MRTR subject", string draftRecipientMode = "smtp",
        string messageChangeKey = "message-change", string folderChangeKey = "folder-change",
        int draftAttachmentCount = 0, long draftAttachmentBytes = 0, string draftChangeKey = "draft-change")
    {
        var draftRecipient = draftRecipientMode switch
        {
            "unresolved" => "<t:Mailbox><t:Name>Unresolved recipient</t:Name></t:Mailbox>",
            "non-smtp" => "<t:Mailbox><t:EmailAddress>to@example.test</t:EmailAddress><t:RoutingType>X400</t:RoutingType></t:Mailbox>",
            "external" => "<t:Mailbox><t:EmailAddress>to@outside.test</t:EmailAddress><t:RoutingType>SMTP</t:RoutingType></t:Mailbox>",
            _ => "<t:Mailbox><t:EmailAddress>to@example.test</t:EmailAddress><t:RoutingType>SMTP</t:RoutingType></t:Mailbox>"
        };
        var draftAttachments = draftAttachmentCount == 0
            ? "<t:Attachments/>"
            : $"<t:Attachments><t:ItemAttachment><t:AttachmentId Id='draft-item-attachment'/><t:Name>embedded.msg</t:Name><t:Size>{draftAttachmentBytes}</t:Size></t:ItemAttachment></t:Attachments>";
        var result = operation switch
        {
            "FindFolder" => $"<m:RootFolder IncludesLastItemInRange='true'><t:Folders><t:Folder><t:FolderId Id='folder-1' ChangeKey='{folderChangeKey}'/><t:DisplayName>Inbox</t:DisplayName><t:TotalCount>1</t:TotalCount><t:UnreadCount>1</t:UnreadCount></t:Folder></t:Folders></m:RootFolder>",
            "GetFolder" => $"<m:Folders><t:Folder><t:FolderId Id='folder-1' ChangeKey='{folderChangeKey}'/><t:DisplayName>Inbox</t:DisplayName><t:TotalCount>1</t:TotalCount><t:UnreadCount>1</t:UnreadCount></t:Folder></m:Folders>",
            "FindItem" => $"<m:RootFolder IncludesLastItemInRange='true'><t:Items><t:Message><t:ItemId Id='message-1' ChangeKey='{messageChangeKey}'/><t:Subject>Report</t:Subject><t:From><t:Mailbox><t:Name>Sender</t:Name></t:Mailbox></t:From><t:DateTimeReceived>2026-10-02T10:00:00Z</t:DateTimeReceived><t:IsRead>false</t:IsRead><t:IsDraft>false</t:IsDraft></t:Message></t:Items></m:RootFolder>",
            "GetItem" => draftMode
                ? $"<m:Items><t:Message><t:ItemId Id='draft-1' ChangeKey='{System.Security.SecurityElement.Escape(draftChangeKey)}'/><t:Subject>{System.Security.SecurityElement.Escape(draftSubject)}</t:Subject><t:From><t:Mailbox><t:EmailAddress>alice@example.test</t:EmailAddress></t:Mailbox></t:From><t:ToRecipients>{draftRecipient}</t:ToRecipients><t:CcRecipients/><t:BccRecipients/><t:DateTimeReceived>2026-10-02T10:00:00Z</t:DateTimeReceived><t:IsRead>true</t:IsRead><t:IsDraft>true</t:IsDraft><t:Body BodyType='Text'>MRTR body</t:Body><t:Categories/>{draftAttachments}</t:Message></m:Items>"
                : $"<m:Items><t:Message><t:ItemId Id='message-1' ChangeKey='{messageChangeKey}'/><t:Subject>Report</t:Subject><t:From><t:Mailbox><t:EmailAddress>sender@example.test</t:EmailAddress></t:Mailbox></t:From><t:ToRecipients><t:Mailbox><t:EmailAddress>alice@example.test</t:EmailAddress></t:Mailbox></t:ToRecipients><t:CcRecipients/><t:BccRecipients><t:Mailbox><t:EmailAddress>hidden@example.test</t:EmailAddress></t:Mailbox></t:BccRecipients><t:DateTimeReceived>2026-10-02T10:00:00Z</t:DateTimeReceived><t:IsRead>false</t:IsRead><t:IsDraft>false</t:IsDraft><t:Body BodyType='Text'>plain body</t:Body><t:Categories><t:String>work</t:String></t:Categories><t:Attachments><t:FileAttachment><t:AttachmentId Id='att-1'/><t:Name>report.pdf</t:Name><t:Size>20</t:Size><t:ContentType>application/pdf</t:ContentType></t:FileAttachment></t:Attachments></t:Message></m:Items>",
            "CreateItem" => $"<m:Items><t:Message><t:ItemId Id='draft-1' ChangeKey='draft-change'/></t:Message></m:Items>",
            "MoveItem" => $"<m:Items><t:Message><t:ItemId Id='message-moved' ChangeKey='moved-change'/></t:Message></m:Items>",
            "CreateFolder" => $"<m:Folders><t:Folder><t:FolderId Id='folder-new' ChangeKey='folder-new-change'/><t:DisplayName>New</t:DisplayName><t:TotalCount>0</t:TotalCount><t:UnreadCount>0</t:UnreadCount></t:Folder></m:Folders>",
            _ => string.Empty
        };
        var missingConfiguration = operation == "GetUserConfiguration";
        var response = $"<s:Envelope xmlns:s='{Soap.NamespaceName}' xmlns:m='{M.NamespaceName}' xmlns:t='{T.NamespaceName}'><s:Body><m:{operation}Response><m:ResponseMessages><m:{operation}ResponseMessage ResponseClass='{(missingConfiguration ? "Error" : "Success")}'><m:ResponseCode>{(missingConfiguration ? "ErrorItemNotFound" : "NoError")}</m:ResponseCode></m:{operation}ResponseMessage></m:ResponseMessages>{result}</m:{operation}Response></s:Body></s:Envelope>";
        return new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(response, Encoding.UTF8, "text/xml")
        };
    }
}

internal sealed class DelegateHandler(
    Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> callback) : HttpMessageHandler
{
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
        callback(request, cancellationToken);
}
