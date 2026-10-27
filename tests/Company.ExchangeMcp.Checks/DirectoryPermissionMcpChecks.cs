using System.Collections.Concurrent;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Xml.Linq;
using Company.ExchangeMcp;
using Company.ExchangeMcp.Exchange;
using Company.ExchangeMcp.Security;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using ModelContextProtocol.Protocol;

internal sealed partial class Checks
{
    private async Task DirectoryPermissionMcpChecksAsync()
    {
        await AssertSelectedSendBlockedAsync(new("denied", "synthetic deny"), new("denied", "synthetic deny"), "denied");
        await AssertSelectedSendBlockedAsync(new("unknown", "synthetic uncertainty"), new("unknown", "synthetic uncertainty"), "unknown");
        await AssertSelectedApprovalOnlyAsync(new("allowed", "synthetic SendAs", Direct: true), PermissionDecision.Unknown("not granted"), "SendAs");
        await AssertSelectedApprovalOnlyAsync(PermissionDecision.Unknown("not granted"), new("allowed", "synthetic SendOnBehalf", Direct: true), "SendOnBehalf");
        await AssertOwnSendUnchangedAsync();
        await AssertCalendarTransmissionGuardAsync();
        await AssertMailboxAccessStatesAsync();
        await AssertFolderDenyConflictAsync();
    }

    private async Task AssertSelectedSendBlockedAsync(
        PermissionDecision sendAs, PermissionDecision sendOnBehalf, string label)
    {
        var exchange = new PermissionEwsHandler();
        var reader = new SyntheticPermissionReader(Report(
            new("allowed", "synthetic FullAccess"), sendAs, sendOnBehalf));
        var auditPath = Path.Combine(runDirectory, $"permission-{label}-audit.jsonl");
        await using var host = await StartPermissionHostAsync(exchange, reader, auditPath);
        var responder = new NativeFormResponder(accept: true);
        await using var native = await CreateNativeClientAsync(host,
            Token("user-a", "mail.read mail.write mail.manage mail.send", sessionId: $"permission-{label}"), responder);
        var targetHandle = await TargetHandleAsync(native.Client);
        var draft = await native.Client.CallToolAsync("mail_create_draft", new Dictionary<string, object?>
        {
            ["subject"] = $"Permission {label} draft",
            ["body"] = "Synthetic permission guard",
            ["to"] = new[] { "alice@example.test" },
            ["mailboxHandle"] = targetHandle
        });
        Expect(draft.IsError != true, $"The {label} selected draft fixture could not be created.");
        var draftHandle = NativeData(draft).GetProperty("handle").GetString()!;
        var before = exchange.Calls.Count;
        var blocked = await native.Client.CallToolAsync("mail_send_draft", new Dictionary<string, object?>
        {
            ["draftHandle"] = draftHandle,
            ["mailboxHandle"] = targetHandle
        });
        Expect(blocked.IsError == true && reader.Calls == 1 && responder.Calls == 0
            && exchange.SendCount == 0 && exchange.Calls.Count == before,
            $"Selected {label} sending was not refused before EWS/native approval (error={blocked.IsError}, reads={exchange.Calls.Count - before}, approvals={responder.Calls}, sends={exchange.SendCount}).");
        Expect(reader.LastIdentity is { ActorMailbox: "alice@example.test", Mailbox: "it@example.test", TargetId: DiscoveryMailboxKey },
            $"The {label} permission lookup did not preserve the actor/selected-mailbox binding.");
    }

    private async Task AssertSelectedApprovalOnlyAsync(
        PermissionDecision sendAs, PermissionDecision sendOnBehalf, string label)
    {
        var exchange = new PermissionEwsHandler();
        var reader = new SyntheticPermissionReader(Report(
            new("allowed", "synthetic FullAccess"), sendAs, sendOnBehalf));
        var auditPath = Path.Combine(runDirectory, $"permission-{label}-approval-audit.jsonl");
        await using var host = await StartPermissionHostAsync(exchange, reader, auditPath);
        var responder = new NativeFormResponder(accept: false);
        await using var native = await CreateNativeClientAsync(host,
            Token("user-a", "mail.read mail.write mail.manage mail.send", sessionId: $"permission-{label}-approval"), responder);
        var targetHandle = await TargetHandleAsync(native.Client);
        var draft = await native.Client.CallToolAsync("mail_create_draft", new Dictionary<string, object?>
        {
            ["subject"] = $"Permission {label} approval draft",
            ["body"] = "Synthetic permission approval",
            ["to"] = new[] { "alice@example.test" },
            ["mailboxHandle"] = targetHandle
        });
        Expect(draft.IsError != true, $"The selected {label} approval draft fixture could not be created.");
        var draftHandle = NativeData(draft).GetProperty("handle").GetString()!;
        var result = await native.Client.CallToolAsync("mail_send_draft", new Dictionary<string, object?>
        {
            ["draftHandle"] = draftHandle,
            ["mailboxHandle"] = targetHandle
        });
        Expect(result.IsError != true && NativeData(result).GetProperty("status").GetString() == "cancelled"
            && reader.Calls >= 1 && responder.Calls == 1 && exchange.SendCount == 0
            && reader.LastIdentity is { ActorMailbox: "alice@example.test", Mailbox: "it@example.test", TargetId: DiscoveryMailboxKey },
            $"Allowed selected {label} did not reach native approval without sending (error={result.IsError}, approvals={responder.Calls}, sends={exchange.SendCount}).");
    }

    private async Task AssertOwnSendUnchangedAsync()
    {
        var exchange = new PermissionEwsHandler("alice@example.test");
        var reader = new SyntheticPermissionReader(Report(
            PermissionDecision.Unknown("directory unavailable"),
            PermissionDecision.Unknown("directory unavailable"),
            PermissionDecision.Unknown("directory unavailable")));
        var auditPath = Path.Combine(runDirectory, "permission-own-send-audit.jsonl");
        await using var host = await StartPermissionHostAsync(exchange, reader, auditPath);
        await using var native = await CreateNativeClientAsync(host,
            Token("user-a", "mail.read mail.write mail.manage mail.send", sessionId: "permission-own-send"),
            new NativeFormResponder(accept: true));
        var draft = await native.Client.CallToolAsync("mail_create_draft", new Dictionary<string, object?>
        {
            ["subject"] = "Own mailbox permission probe",
            ["body"] = "Synthetic own-mailbox send",
            ["to"] = new[] { "alice@example.test" }
        });
        Expect(draft.IsError != true, "The own-mailbox send fixture could not create a draft.");
        var send = await native.Client.CallToolAsync("mail_send_draft", new Dictionary<string, object?>
        {
            ["draftHandle"] = NativeData(draft).GetProperty("handle").GetString()!
        });
        Expect(send.IsError != true && NativeData(send).GetProperty("status").GetString() == "sent"
            && exchange.SendCount == 1 && reader.Calls == 0,
            "An own-mailbox send was incorrectly coupled to delegated directory permission checks.");
    }

    private async Task AssertCalendarTransmissionGuardAsync()
    {
        var exchange = new PermissionEwsHandler();
        var reader = new SyntheticPermissionReader(Report(
            PermissionDecision.Unknown("synthetic uncertainty"),
            PermissionDecision.Unknown("synthetic uncertainty"),
            PermissionDecision.Unknown("synthetic uncertainty")));
        var auditPath = Path.Combine(runDirectory, "permission-calendar-audit.jsonl");
        await using var host = await StartPermissionHostAsync(exchange, reader, auditPath);
        await using var native = await CreateNativeClientAsync(host,
            Token("user-a", "mail.read mail.write mail.manage mail.send", sessionId: "permission-calendar"),
            new NativeFormResponder(accept: true));
        var targetHandle = await TargetHandleAsync(native.Client);
        var before = exchange.Calls.Count;
        var blocked = await native.Client.CallToolAsync("calendar_create_event", new Dictionary<string, object?>
        {
            ["subject"] = "Synthetic guarded invitation",
            ["body"] = "Synthetic body",
            ["start"] = "2026-10-12T09:00:00Z",
            ["end"] = "2026-10-12T10:00:00Z",
            ["timeZone"] = "Iran Standard Time",
            ["requiredAttendees"] = new[] { "alice@example.test" },
            ["sendInvitations"] = true,
            ["mailboxHandle"] = targetHandle
        });
        Expect(blocked.IsError == true && reader.Calls == 1 && exchange.Calls.Count == before,
            "An uncertain selected-calendar invitation reached Exchange.");

        var folders = await native.Client.CallToolAsync("calendar_list_folders", new Dictionary<string, object?>
        {
            ["mailboxHandle"] = targetHandle
        });
        var discovered = NativeData(folders);
        Expect(folders.IsError != true && discovered.ValueKind == JsonValueKind.Array
            && discovered.EnumerateArray().Any(folder => folder.GetProperty("folderClass").GetString() == "IPF.Appointment")
            && reader.Calls == 1 && exchange.Calls.Count == before,
            $"A selected calendar read was blocked by the sending-rights guard or failed to use its verified folder snapshot (error={folders.IsError}, content={string.Join(" | ", folders.Content.OfType<TextContentBlock>().Select(item => item.Text))}, EWS calls={exchange.Calls.Count - before}).");
    }

    private async Task AssertMailboxAccessStatesAsync()
    {
        var exchange = new PermissionEwsHandler();
        var reader = new SyntheticPermissionReader(Report(
            new("allowed", "direct FullAccess", Direct: true),
            new("denied", "no SendAs"),
            new("unknown", "group expansion unavailable")));
        var auditPath = Path.Combine(runDirectory, "permission-access-states-audit.jsonl");
        await using var host = await StartPermissionHostAsync(exchange, reader, auditPath);
        await using var native = await CreateNativeClientAsync(host,
            Token("user-a", "mail.read", sessionId: "permission-access-states"),
            new NativeFormResponder(accept: true));
        var targetHandle = await TargetHandleAsync(native.Client);
        var access = await native.Client.CallToolAsync("mail_get_mailbox_access", new Dictionary<string, object?>
        {
            ["folder"] = "inbox",
            ["mailboxHandle"] = targetHandle
        });
        var data = NativeData(access);
        Expect(access.IsError != true && data.GetProperty("fullAccess").GetString() == "allowed"
            && data.GetProperty("sendAs").GetString() == "denied"
            && data.GetProperty("sendOnBehalf").GetString() == "unknown"
            && data.GetProperty("folder").GetProperty("read").GetString() == "true",
            "mail_get_mailbox_access did not preserve separate FullAccess, SendAs, SendOnBehalf and folder-right states.");
        Expect(reader.LastIdentity is { ActorMailbox: "alice@example.test", Mailbox: "it@example.test", TargetId: DiscoveryMailboxKey },
            "mail_get_mailbox_access did not query permissions for the signed-in actor and selected mailbox separately.");
    }

    private async Task AssertFolderDenyConflictAsync()
    {
        var exchange = new FolderDenyEwsHandler();
        var reader = new SyntheticPermissionReader(Report(
            new("allowed", "direct FullAccess", Direct: true),
            PermissionDecision.Unknown("directory unavailable"),
            PermissionDecision.Unknown("directory unavailable")));
        var auditPath = Path.Combine(runDirectory, "permission-folder-deny-audit.jsonl");
        await using var host = await StartPermissionHostAsync(exchange, reader, auditPath);
        await using var native = await CreateNativeClientAsync(host,
            Token("user-a", "mail.read", sessionId: "permission-folder-deny"),
            new NativeFormResponder(accept: true));
        var targetHandle = await TargetHandleAsync(native.Client);
        var access = await native.Client.CallToolAsync("mail_get_mailbox_access", new Dictionary<string, object?>
        {
            ["folder"] = "inbox",
            ["mailboxHandle"] = targetHandle
        });
        var data = NativeData(access);
        Expect(access.IsError != true && data.GetProperty("fullAccess").GetString() == "unknown"
            && data.GetProperty("folder").GetProperty("read").GetString() == "false"
            && !string.IsNullOrWhiteSpace(data.GetProperty("folder").GetProperty("error").GetString()),
            "A native folder denial did not downgrade conflicting directory FullAccess to unknown.");
    }

    private static MailboxPermissionReport Report(
        PermissionDecision fullAccess, PermissionDecision sendAs, PermissionDecision sendOnBehalf) =>
        new(fullAccess, sendAs, sendOnBehalf, DateTimeOffset.UtcNow, "synthetic");

    private async Task<string> TargetHandleAsync(ModelContextProtocol.Client.McpClient client)
    {
        var listing = await client.CallToolAsync("mail_list_mailboxes", new Dictionary<string, object?>());
        Expect(listing.IsError != true, "The permission fixture could not list approved mailboxes.");
        return StringProperty(NativeData(listing).GetProperty("items")
            .EnumerateArray().Single(item => item.GetProperty("kind").GetString() == "delegated"), "mailboxHandle");
    }

    private async Task<TestHostContext> StartPermissionHostAsync(
        HttpMessageHandler exchange, IMailboxPermissionReader permissions, string auditPath)
    {
        var passwordPath = Path.Combine(runDirectory, $"permission-exchange-{Guid.NewGuid():N}.txt");
        var introspectionSecretPath = Path.Combine(runDirectory, $"permission-introspection-{Guid.NewGuid():N}.txt");
        await File.WriteAllTextAsync(passwordPath, "synthetic-password");
        await File.WriteAllTextAsync(introspectionSecretPath, "synthetic-introspection-secret");
        var values = ConfigurationValues(passwordPath, introspectionSecretPath, auditPath,
            writesEnabled: true, sendEnabled: true);
        values["Service:MailboxTargets:user-a:stale"] = "stale@example.test";
        var app = AppHost.Create([], builder =>
        {
            builder.WebHost.UseTestServer();
            builder.Configuration.AddInMemoryCollection(values);
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
                .ConfigurePrimaryHttpMessageHandler(() => new IntrospectionHandler());
            builder.Services.AddSingleton<IMailboxPermissionReader>(permissions);
            builder.Services.AddSingleton<IMailboxDiscovery>(new TestMailboxDiscovery("user-a"));
        });
        await app.StartAsync();
        var client = app.GetTestClient();
        client.BaseAddress = new Uri("https://mail.example.test/");
        return new TestHostContext(app, client);
    }
}

internal sealed class SyntheticPermissionReader(MailboxPermissionReport report) : IMailboxPermissionReader
{
    public int Calls { get; private set; }
    public MailboxIdentity? LastIdentity { get; private set; }

    public Task<MailboxPermissionReport> ReadAsync(MailboxIdentity identity, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Calls++;
        LastIdentity = identity;
        return Task.FromResult(report);
    }
}

internal sealed class PermissionEwsHandler(string getMessageMailbox = "it@example.test") : HttpMessageHandler
{
    private const string SoapNamespace = "http://schemas.xmlsoap.org/soap/envelope/";
    private const string MessagesNamespace = "http://schemas.microsoft.com/exchange/services/2006/messages";
    private const string TypesNamespace = "http://schemas.microsoft.com/exchange/services/2006/types";
    private static readonly XNamespace Soap = SoapNamespace;
    private static readonly XNamespace Messages = MessagesNamespace;
    private static readonly XNamespace Types = TypesNamespace;

    public ConcurrentQueue<DelegatedMailboxCall> Calls { get; } = [];
    public int SendCount { get; private set; }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        var body = await request.Content!.ReadAsStringAsync(cancellationToken);
        var document = XDocument.Parse(body);
        var operation = document.Root!.Element(Soap + "Body")!.Elements().Single().Name.LocalName;
        var requestedFolderId = document.Descendants(Types + "FolderId")
            .Select(folder => (string?)folder.Attribute("Id")).FirstOrDefault(id => !string.IsNullOrWhiteSpace(id))
            ?? document.Descendants(Types + "DistinguishedFolderId")
                .Select(folder => (string?)folder.Attribute("Id")).FirstOrDefault(id => !string.IsNullOrWhiteSpace(id))
            ?? "inbox-id";
        Calls.Enqueue(new DelegatedMailboxCall(operation,
            request.Headers.TryGetValues("X-AnchorMailbox", out var anchors) ? anchors.SingleOrDefault() : null,
            document.Descendants(Types + "PrimarySmtpAddress").SingleOrDefault()?.Value, body));
        if (operation == "SendItem") SendCount++;

        var effectiveRights = operation == "GetFolder"
            && document.Descendants(Types + "FieldURI")
                .Any(field => (string?)field.Attribute("FieldURI") == "folder:EffectiveRights");
        var payload = operation switch
        {
            "CreateItem" => "<m:Items><t:Message><t:ItemId Id='synthetic-draft' ChangeKey='synthetic-draft-change'/></t:Message></m:Items>",
            "GetItem" => MessagePayload(getMessageMailbox),
            "GetFolder" when effectiveRights => $"<m:Folders><t:Folder><t:FolderId Id='{requestedFolderId}' ChangeKey='inbox-change'/><t:DisplayName>Calendar</t:DisplayName><t:FolderClass>IPF.Appointment</t:FolderClass><t:EffectiveRights><t:Read>1</t:Read><t:CreateContents>0</t:CreateContents><t:Modify>1</t:Modify><t:Delete>0</t:Delete></t:EffectiveRights></t:Folder></m:Folders>",
            "GetFolder" => "<m:Folders><t:CalendarFolder><t:FolderId Id='calendar' ChangeKey='calendar-change'/><t:FolderClass>IPF.Appointment</t:FolderClass><t:DisplayName>Calendar</t:DisplayName><t:TotalCount>0</t:TotalCount><t:UnreadCount>0</t:UnreadCount><t:ChildFolderCount>0</t:ChildFolderCount></t:CalendarFolder></m:Folders>",
            "FindFolder" => "<m:RootFolder IncludesLastItemInRange='true'><t:Folders><t:CalendarFolder><t:FolderId Id='calendar' ChangeKey='calendar-change'/><t:FolderClass>IPF.Appointment</t:FolderClass><t:DisplayName>Calendar</t:DisplayName><t:TotalCount>0</t:TotalCount><t:UnreadCount>0</t:UnreadCount><t:ChildFolderCount>0</t:ChildFolderCount></t:CalendarFolder></t:Folders></m:RootFolder>",
            _ => string.Empty
        };
        var response = $"<s:Envelope xmlns:s='{Soap.NamespaceName}' xmlns:m='{Messages.NamespaceName}' xmlns:t='{Types.NamespaceName}'><s:Body><m:{operation}Response><m:ResponseMessages><m:{operation}ResponseMessage ResponseClass='Success'><m:ResponseCode>NoError</m:ResponseCode>{payload}</m:{operation}ResponseMessage></m:ResponseMessages></m:{operation}Response></s:Body></s:Envelope>";
        return new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(response, Encoding.UTF8, "text/xml")
        };
    }

    private static string MessagePayload(string mailbox) =>
        $"<m:Items><t:Message><t:ItemId Id='synthetic-draft' ChangeKey='synthetic-draft-change'/>"
        + $"<t:Subject>synthetic permission draft</t:Subject><t:From><t:Mailbox><t:EmailAddress>{mailbox}</t:EmailAddress></t:Mailbox></t:From>"
        + "<t:ToRecipients><t:Mailbox><t:EmailAddress>alice@example.test</t:EmailAddress></t:Mailbox></t:ToRecipients>"
        + "<t:CcRecipients/><t:BccRecipients/><t:Body BodyType='Text'>synthetic body</t:Body>"
        + "<t:IsRead>true</t:IsRead><t:IsDraft>true</t:IsDraft><t:Attachments/></t:Message></m:Items>";
}

internal sealed class FolderDenyEwsHandler : HttpMessageHandler
{
    private const string SoapNamespace = "http://schemas.xmlsoap.org/soap/envelope/";
    private const string MessagesNamespace = "http://schemas.microsoft.com/exchange/services/2006/messages";
    private const string TypesNamespace = "http://schemas.microsoft.com/exchange/services/2006/types";
    private static readonly XNamespace Soap = SoapNamespace;
    private static readonly XNamespace Messages = MessagesNamespace;

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        var body = await request.Content!.ReadAsStringAsync(cancellationToken);
        var document = XDocument.Parse(body);
        var operation = document.Root!.Element(Soap + "Body")!.Elements().Single().Name.LocalName;
        var hasEffectiveRights = document.Descendants(XName.Get("FieldURI", TypesNamespace))
            .Any(field => (string?)field.Attribute("FieldURI") == "folder:EffectiveRights");
        if (operation == "GetFolder" && hasEffectiveRights)
        {
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(
                    $"<s:Envelope xmlns:s='{Soap.NamespaceName}' xmlns:m='{Messages.NamespaceName}'><s:Body>"
                    + "<m:GetFolderResponse><m:ResponseMessages><m:GetFolderResponseMessage ResponseClass='Error'>"
                    + "<m:ResponseCode>ErrorAccessDenied</m:ResponseCode><m:MessageText>synthetic</m:MessageText>"
                    + "</m:GetFolderResponseMessage></m:ResponseMessages></m:GetFolderResponse></s:Body></s:Envelope>",
                    Encoding.UTF8, "text/xml")
            };
        }

        return new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(
                $"<s:Envelope xmlns:s='{Soap.NamespaceName}' xmlns:m='{Messages.NamespaceName}'><s:Body>"
                + $"<m:{operation}Response><m:ResponseMessages><m:{operation}ResponseMessage ResponseClass='Success'>"
                + "<m:ResponseCode>NoError</m:ResponseCode></m:"
                + $"{operation}ResponseMessage></m:ResponseMessages></m:{operation}Response></s:Body></s:Envelope>",
                Encoding.UTF8, "text/xml")
        };
    }
}
