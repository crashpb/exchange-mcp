using System.Net;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using System.Xml.Linq;
using System.Xml.Schema;
using Company.ExchangeMcp;
using Company.ExchangeMcp.Security;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Options;
using ModelContextProtocol;

internal sealed partial class Checks
{
    private async Task SyncChecksAsync()
    {
        var handler = new SyncRecordingHandler();
        var exchange = NewEwsClient(handler);
        var page = await exchange.SyncFoldersAsync("alice@example.test", null, CancellationToken.None);
        Expect(page.Changes.Single().Kind == "calendar-folder" && !page.IncludesLastChange,
            "Folder synchronization lost the typed calendar folder or continuation flag.");
        var items = await exchange.SyncItemsAsync("alice@example.test", "calendar", "state-before", 100, CancellationToken.None);
        Expect(items.Changes.Count == 3 && items.Changes[0].Kind == "calendar-event"
            && items.Changes[1].Change == "Delete" && items.Changes[2].IsRead == true
            && items.Changes[2].Kind == "read-state",
            "Item synchronization lost a typed event, tombstone or read-state change.");
        var wire = XDocument.Parse(handler.Bodies[^1]);
        Expect(wire.Descendants(XName.Get("BaseShape", TypesNamespace)).Single().Value == "IdOnly"
            && wire.Descendants(XName.Get("SyncScope", MessagesNamespace)).Single().Value == "NormalItems"
            && wire.Descendants(XName.Get("SyncState", MessagesNamespace)).Single().Value == "state-before",
            "Item synchronization requested content, associated items or lost its state.");
        var calls = handler.Bodies.Count;
        await AssertThrowsAsync<ArgumentException>(() => exchange.SyncItemsAsync("alice@example.test", "calendar", null, 513, CancellationToken.None));
        await AssertThrowsAsync<ArgumentException>(() => exchange.SyncFoldersAsync("alice@example.test", "", CancellationToken.None));
        Expect(calls == handler.Bodies.Count, "Invalid synchronization input reached Exchange.");
        handler.Malformed = true;
        await AssertThrowsAsync<InvalidOperationException>(() => exchange.SyncItemsAsync("alice@example.test", "calendar", null, 100, CancellationToken.None));
        handler.Malformed = false;

        var options = Options.Create(new ServiceOptions
        {
            AllowedClientIds = ["checks"],
            Mailboxes = new() { ["user-a"] = "alice@example.test", ["user-b"] = "bob@example.test" },
            AuditPath = Path.Combine(runDirectory, "sync-audit.jsonl")
        });
        var protection = new EphemeralDataProtectionProvider();
        using var audit = new AuditLog(options);
        var handles = new MailboxHandles(protection);
        var tools = new MailboxSyncTools(exchange, new MailboxAccess(options), handles, audit, protection);
        var user = SyncUser("user-a");
        var first = JsonSerializer.SerializeToElement(await tools.Items(user, CancellationToken.None, "calendar"));
        var cursor = first.GetProperty("cursor").GetString()!;
        var eventHandle = first.GetProperty("changes")[0].GetProperty("handle").GetString()!;
        var identity = new MailboxIdentity("user-a", "alice@example.test", "checks");
        Expect(handles.Resolve(identity, "calendar-event", eventHandle).Id == "event-sync-1",
            "Synchronized event handle was not usable by the existing calendar tools.");
        var second = JsonSerializer.SerializeToElement(await tools.Items(user, CancellationToken.None, "calendar", cursor));
        Expect(first.GetProperty("changes")[0].GetProperty("objectKey").GetString()
            == second.GetProperty("changes")[0].GetProperty("objectKey").GetString(),
            "A synchronized object's stable key changed between pages.");
        handler.NoChangeKey = true;
        var noKey = JsonSerializer.SerializeToElement(await tools.Items(user, CancellationToken.None, "calendar"));
        Expect(noKey.GetProperty("changes")[0].GetProperty("handle").ValueKind == JsonValueKind.Null,
            "An object without its current change key received a mutable handle.");
        handler.NoChangeKey = false;
        handler.SearchFolder = true;
        var search = JsonSerializer.SerializeToElement(await tools.Folders(user, CancellationToken.None));
        Expect(search.GetProperty("changes")[0].GetProperty("kind").GetString() == "search-folder"
            && search.GetProperty("changes")[0].GetProperty("handle").ValueKind == JsonValueKind.Null,
            "A search folder received an ordinary mutable folder handle.");
        handler.SearchFolder = false;
        calls = handler.Bodies.Count;
        await AssertThrowsAsync<McpException>(() => tools.Items(SyncUser("user-b"), CancellationToken.None, "calendar", cursor));
        await AssertThrowsAsync<McpException>(() => tools.Items(user, CancellationToken.None, "inbox", cursor));
        await AssertThrowsAsync<McpException>(() => tools.Folders(user, CancellationToken.None, cursor));
        await AssertThrowsAsync<McpException>(() => tools.Items(user, CancellationToken.None, "calendar", "tampered"));
        await AssertThrowsAsync<McpException>(() => tools.Items(SyncUser("user-a", ""), CancellationToken.None, "calendar", cursor));
        var restart = new EphemeralDataProtectionProvider();
        var restarted = new MailboxSyncTools(exchange, new MailboxAccess(options), new MailboxHandles(restart), audit, restart);
        await AssertThrowsAsync<McpException>(() => restarted.Items(user, CancellationToken.None, "calendar", cursor));
        Expect(calls == handler.Bodies.Count, "A foreign, wrong-folder, tampered, unscoped or pre-restart cursor reached Exchange.");
        ValidateSyncSchema(handler.Bodies);
    }

    private static ClaimsPrincipal SyncUser(string subject, string scope = "mail.read") => new(new ClaimsIdentity(
        [new("sub", subject), new("azp", "checks"), new("scope", scope)], "checks"));

    private static void ValidateSyncSchema(IEnumerable<string> requests)
    {
        var schemas = LoadOptionalExchangeSchemas();
        foreach (var request in requests)
        {
            var operation = XDocument.Parse(request).Root!.Element(XName.Get("Body", SoapNamespace))!.Elements().Single();
            if (schemas is not null)
                new XDocument(new XElement(operation)).Validate(schemas, (_, error) => throw new InvalidOperationException(
                    $"Exchange 2019 rejected synchronization: {error.Message}"));
        }
    }
}

internal sealed class SyncRecordingHandler : HttpMessageHandler
{
    public List<string> Bodies { get; } = [];
    public bool Malformed { get; set; }
    public bool NoChangeKey { get; set; }
    public bool SearchFolder { get; set; }
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var body = await request.Content!.ReadAsStringAsync(cancellationToken);
        Bodies.Add(body);
        var operation = XDocument.Parse(body).Root!.Element(XName.Get("Body", "http://schemas.xmlsoap.org/soap/envelope/"))!
            .Elements().Single().Name.LocalName;
        var folders = operation == "SyncFolderHierarchy";
        var changes = folders ? "<t:Create><t:CalendarFolder><t:FolderId Id='calendar-sync-1' ChangeKey='folder-key'/></t:CalendarFolder></t:Create>"
            : "<t:Create><t:CalendarItem><t:ItemId Id='event-sync-1' ChangeKey='event-key'/></t:CalendarItem></t:Create><t:Delete><t:ItemId Id='deleted-1'/></t:Delete><t:ReadFlagChange><t:ItemId Id='read-1'/><t:IsRead>true</t:IsRead></t:ReadFlagChange>";
        if (NoChangeKey) changes = changes.Replace(" ChangeKey='event-key'", "", StringComparison.Ordinal);
        if (SearchFolder) changes = changes.Replace("CalendarFolder", "SearchFolder", StringComparison.Ordinal);
        var last = folders ? "IncludesLastFolderInRange" : "IncludesLastItemInRange";
        var state = Malformed ? "" : "<m:SyncState>state-after</m:SyncState>";
        return new(HttpStatusCode.OK)
        {
            Content = new StringContent($"<s:Envelope xmlns:s='http://schemas.xmlsoap.org/soap/envelope/' xmlns:m='http://schemas.microsoft.com/exchange/services/2006/messages' xmlns:t='http://schemas.microsoft.com/exchange/services/2006/types'><s:Body><m:{operation}Response><m:ResponseMessages><m:{operation}ResponseMessage ResponseClass='Success'><m:ResponseCode>NoError</m:ResponseCode>{state}<m:{last}>{(folders ? "false" : "true")}</m:{last}><m:Changes>{changes}</m:Changes></m:{operation}ResponseMessage></m:ResponseMessages></m:{operation}Response></s:Body></s:Envelope>", Encoding.UTF8, "text/xml")
        };
    }
}
