using System.Net;
using System.Diagnostics;
using System.Text;
using System.Text.Json;
using System.Xml.Linq;
using Company.ExchangeMcp.Exchange;
using Company.ExchangeMcp.Security;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;
using ModelContextProtocol;

internal sealed partial class Checks
{
    private async Task EventMessageReadChecksAsync()
    {
        var provider = new EphemeralDataProtectionProvider();
        var handles = new MailboxHandles(provider);
        var actor = new MailboxIdentity("user-a", "alice@example.test", "chatgpt-test", "event-session");
        var observedAt = DateTimeOffset.UtcNow.AddMinutes(-81);
        var eventHandle = handles.IssueEventMessage(actor, "original", "old-key", observedAt, EventMessageReadHandler.SearchKey);
        var protector = provider.CreateProtector("Company.ExchangeMcp.MailboxHandles.v1").ToTimeLimitedDataProtector();
        _ = protector.Unprotect(eventHandle, out var eventExpiry);
        Expect(eventExpiry == observedAt.AddHours(48)
            && handles.ResolveMessageForRead(actor, eventHandle).Kind == "event-message",
            "An 81-minute-old event reference expired early or renewed its original 48-hour deadline.");
        var ordinary = handles.Issue(actor, "message", "original", "old-key");
        _ = protector.Unprotect(ordinary, out var ordinaryExpiry);
        Expect(ordinaryExpiry > DateTimeOffset.UtcNow.AddMinutes(14)
            && ordinaryExpiry <= DateTimeOffset.UtcNow.AddMinutes(15), "Ordinary message handle lifetime changed.");
        foreach (var wrong in new[] { actor with { Subject = "other" }, actor with { Mailbox = "other@example.test" },
            actor with { ClientId = "other" }, actor with { SessionId = "other" },
            actor with { TargetId = "delegated", ActorMailbox = "other@example.test" } })
            await AssertThrowsAsync<McpException>(() =>
            {
                handles.ResolveMessageForRead(wrong, eventHandle);
                return Task.CompletedTask;
            });
        foreach (var value in new[] { "invalid", handles.IssueEventMessage(actor, "original", "key",
            DateTimeOffset.UtcNow.AddHours(-49), EventMessageReadHandler.SearchKey) })
            await AssertThrowsAsync<McpException>(() =>
            {
                handles.ResolveMessageForRead(actor, value);
                return Task.CompletedTask;
            });
        await AssertThrowsAsync<McpException>(() =>
        {
            handles.Resolve(actor, "message", eventHandle);
            return Task.CompletedTask;
        });

        var durablePath = Path.Combine(runDirectory, "event-read-handles", "audit.jsonl");
        string durableHandle;
        using (var durable = new DurableDataProtectionProvider(durablePath))
            durableHandle = new MailboxHandles(durable).IssueEventMessage(actor, "original", "old-key", observedAt,
                EventMessageReadHandler.SearchKey);
        using (var durable = new DurableDataProtectionProvider(durablePath))
            Expect(new MailboxHandles(durable).ResolveMessageForRead(actor, durableHandle).EventSearchKey == EventMessageReadHandler.SearchKey,
                "Restarting the protection provider lost a delayed event read reference.");

        var handler = new EventMessageReadHandler();
        await using var host = await StartHostAsync(handler, writesEnabled: true, sendEnabled: true);
        var hostHandles = host.App.Services.GetRequiredService<MailboxHandles>();
        var readHandle = hostHandles.IssueEventMessage(actor, "original", "old-key", observedAt, EventMessageReadHandler.SearchKey);
        var token = Token(actor.Subject, "mail.read mail.write mail.manage mail.send", sessionId: actor.SessionId);
        async Task<(HttpStatusCode StatusCode, string Body)> ReadAsync(string value) =>
            await ToolRequestAsync(host.Client, token, "tools/call", new { name = "mail_read", arguments = new { messageHandle = value } });

        var direct = await ReadAsync(readHandle);
        Expect(!IsToolError(direct.Body) && ToolStructuredData(direct.Body).GetProperty("body").GetString() == "event body"
            && handler.Calls.Count == 1 && handler.Calls[0].Name.LocalName == "GetItem",
            "The delayed event did not read its exact original item directly.");
        var freshHandle = ToolStructuredData(direct.Body).GetProperty("handle").GetString()!;
        Expect(hostHandles.Resolve(actor, "message", freshHandle).Id == "original",
            "An event read did not return an ordinary fresh message handle.");
        handler.Calls.Clear();
        Expect(!IsToolError((await ReadAsync(freshHandle)).Body) && handler.Calls.Count == 1,
            "The ordinary message read path stopped accepting fresh message handles.");
        var unstamped = hostHandles.IssueEventMessage(actor, "original", "old-key", observedAt, null);
        handler.Calls.Clear();
        Expect(!IsToolError((await ReadAsync(unstamped)).Body) && handler.Calls.Count == 1,
            "An older pending event without a lookup stamp could not read its original item.");
        handler.Mode = "moved";
        handler.Calls.Clear();
        Expect(IsToolError((await ReadAsync(unstamped)).Body) && handler.Calls.Count == 1,
            "An unstamped event guessed a moved item through fallback lookup.");
        handler.Calls.Clear();
        Expect(IsToolError((await ReadAsync(freshHandle)).Body) && handler.Calls.Count == 1,
            "An ordinary handle used notification-only moved-message recovery.");
        handler.Calls.Clear();
        var moved = await ReadAsync(readHandle);
        Expect(!IsToolError(moved.Body) && ToolStructuredData(moved.Body).GetProperty("body").GetString() == "event body"
            && handler.Calls.Select(call => call.Name.LocalName).SequenceEqual(["GetItem", "FindFolder", "FindItem", "GetItem"])
            && hostHandles.Resolve(actor, "message", ToolStructuredData(moved.Body).GetProperty("handle").GetString()!).Id == "moved",
            "An 81-minute-old event did not recover its exact message after a move to Deleted Items.");
        var lookup = handler.Calls.Single(call => call.Name.LocalName == "FindItem");
        XNamespace m = MessagesNamespace;
        XNamespace t = TypesNamespace;
        Expect(lookup.Element(m + "IndexedPageItemView")?.Attribute("MaxEntriesReturned")?.Value == "2"
            && lookup.Element(m + "Restriction")?.Element(t + "IsEqualTo")?.Element(t + "ExtendedFieldURI")?.Attribute("PropertyTag")?.Value == "0x300B"
            && lookup.Element(m + "Restriction")?.Descendants(t + "Constant").Single().Attribute("Value")?.Value == EventMessageReadHandler.SearchKey
            && !lookup.Descendants(t + "FieldURI").Any(), "Moved-message recovery used a broad or body-bearing search.");

        foreach (var (name, arguments) in new (string, object)[]
        {
            ("mail_mark_read", new { messageHandle = readHandle, isRead = true }),
            ("mail_move", new { messageHandle = readHandle, destinationFolder = "deleteditems" }),
            ("mail_delete", new { messageHandle = readHandle }),
            ("mail_reply_draft", new { messageHandle = readHandle, body = "reply" }),
            ("mail_set_categories", new { messageHandle = readHandle, categories = new[] { "category" } }),
            ("mail_send_draft", new { draftHandle = readHandle })
        })
        {
            handler.Calls.Clear();
            var refused = await ToolRequestAsync(host.Client, token, "tools/call", new { name, arguments });
            Expect(IsToolError(refused.Body) && handler.Calls.Count == 0,
                "A mutation accepted an event-only read reference or reached Exchange.");
        }
        var hostProtector = host.App.Services.GetRequiredService<IDataProtectionProvider>()
            .CreateProtector("Company.ExchangeMcp.MailboxHandles.v1").ToTimeLimitedDataProtector();
        var expiredOrdinary = hostProtector.Protect(JsonSerializer.Serialize(new MailboxHandle(actor.Subject, actor.Mailbox,
            "message", "original", "old-key", actor.ClientId, actor.SessionId)), DateTimeOffset.UtcNow.AddMinutes(-1));
        handler.Calls.Clear();
        var expiredRead = await ReadAsync(expiredOrdinary);
        Expect(IsToolError(expiredRead.Body) && handler.Calls.Count == 0,
            "An expired ordinary message handle reached Exchange or used event recovery.");
        handler.Calls.Clear();
        var wrongSession = await ToolRequestAsync(host.Client, Token(actor.Subject, "mail.read", sessionId: "other"),
            "tools/call", new { name = "mail_read", arguments = new { messageHandle = readHandle } });
        Expect(IsToolError(wrongSession.Body) && handler.Calls.Count == 0,
            "An event reference crossed its session binding through the actual MCP endpoint.");

        foreach (var mode in new[] { "missing", "duplicate", "truncated", "missing-completeness", "omitted-items",
            "partial", "lookup-mismatch", "final-mismatch", "mismatch", "denied", "busy" })
        {
            handler.Mode = mode;
            handler.Calls.Clear();
            var refused = await ReadAsync(readHandle);
            Expect(IsToolError(refused.Body), "An unavailable, ambiguous, incomplete, or mismatched notification was read.");
            if (mode is "mismatch" or "denied" or "busy")
                Expect(handler.Calls.Count == 1, "Notification recovery ran without an original ItemNotFound response.");
        }
        handler.Mode = "moved";
        handler.FolderCount = 128;
        handler.Calls.Clear();
        var bounded = await ReadAsync(readHandle);
        Expect(IsToolError(bounded.Body) && handler.Calls.All(call => call.Name.LocalName != "FindItem"),
            "Notification lookup exceeded its 128-folder bound.");
        handler.FolderCount = 33;
        handler.Calls.Clear();
        var batched = await ReadAsync(readHandle);
        Expect(!IsToolError(batched.Body) && handler.Calls.Count(call => call.Name.LocalName == "FindItem") == 3
            && handler.Calls.Where(call => call.Name.LocalName == "FindItem").All(call => call.Element(m + "ParentFolderIds")!.Elements().Count() <= 16),
            "Notification lookup did not inspect all folders in bounded batches.");
        handler.FolderCount = 3;
        foreach (var invalid in new[] { "bad", Convert.ToBase64String(new byte[257]), " " + EventMessageReadHandler.SearchKey })
        {
            handler.Calls.Clear();
            var invalidReference = hostHandles.IssueEventMessage(actor, "original", "key", observedAt, invalid);
            Expect(IsToolError((await ReadAsync(invalidReference)).Body) && handler.Calls.Count == 0,
                "An invalid protected notification identity reached Exchange.");
        }
        handler.Mode = "oversized";
        await AssertThrowsAsync<InvalidOperationException>(() => NewEwsClient(handler)
            .GetMessageSummaryAsync(actor.Mailbox, "original", CancellationToken.None));

        var cancelledHandler = new EventMessageReadHandler { Mode = "moved", Delay = TimeSpan.FromSeconds(1) };
        using (var cancelled = new CancellationTokenSource(TimeSpan.FromMilliseconds(20)))
            await AssertThrowsAsync<OperationCanceledException>(() => NewEwsClient(cancelledHandler)
                .GetEventMessageAsync(actor.Mailbox, "original", EventMessageReadHandler.SearchKey, cancelled.Token));
        // Several individually fast requests must still share the lookup's 30-second budget.
        var slowHandler = new EventMessageReadHandler { Mode = "moved", FolderCount = 33, Delay = TimeSpan.FromSeconds(7) };
        var elapsed = Stopwatch.StartNew();
        await AssertThrowsAsync<TimeoutException>(() => NewEwsClient(slowHandler)
            .GetEventMessageAsync(actor.Mailbox, "original", EventMessageReadHandler.SearchKey, CancellationToken.None));
        Expect(elapsed.Elapsed.TotalSeconds is >= 29 and < 45 && slowHandler.Calls.Count == 5,
            "The cumulative notification lookup deadline was reset for each Exchange request.");
    }
}

internal sealed class EventMessageReadHandler : HttpMessageHandler
{
    internal const string SearchKey = "AQIDBAUGBwgJCgsMDQ4PEA==";
    private static readonly XNamespace S = "http://schemas.xmlsoap.org/soap/envelope/";
    private static readonly XNamespace M = "http://schemas.microsoft.com/exchange/services/2006/messages";
    private static readonly XNamespace T = "http://schemas.microsoft.com/exchange/services/2006/types";
    public string Mode { get; set; } = "direct";
    public int FolderCount { get; set; } = 3;
    public TimeSpan Delay { get; set; }
    public List<XElement> Calls { get; } = [];

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var document = XDocument.Parse(await request.Content!.ReadAsStringAsync(cancellationToken));
        var operation = document.Root!.Element(S + "Body")!.Elements().Single();
        Calls.Add(new XElement(operation));
        if (Delay > TimeSpan.Zero) await Task.Delay(Delay, cancellationToken);
        if (request.Headers.GetValues("X-AnchorMailbox").Single() != "alice@example.test")
            throw new InvalidOperationException("Notification lookup left the authenticated mailbox.");
        var name = operation.Name.LocalName;
        XElement Success(XElement body) => new(M + (name + "ResponseMessage"), new XAttribute("ResponseClass", "Success"),
            new XElement(M + "ResponseCode", "NoError"), body);
        XElement Error(string code) => new(M + (name + "ResponseMessage"), new XAttribute("ResponseClass", "Error"),
            new XElement(M + "ResponseCode", code));
        XElement Stamp(string key) => new(T + "ExtendedProperty",
            new XElement(T + "ExtendedFieldURI", new XAttribute("PropertyTag", "0x300B"), new XAttribute("PropertyType", "Binary")),
            new XElement(T + "Value", key));
        XElement Message(string id, string key) => new(T + "Message",
            new XElement(T + "ItemId", new XAttribute("Id", id), new XAttribute("ChangeKey", "current-key")),
            new XElement(T + "Subject", "Event subject"), new XElement(T + "Body", new XAttribute("BodyType", "Text"), "event body"), Stamp(key));
        XElement[] responses;
        if (name == "GetItem")
        {
            var id = operation.Element(M + "ItemIds")!.Element(T + "ItemId")!.Attribute("Id")!.Value;
            var key = Mode is "mismatch" or "final-mismatch" ? Convert.ToBase64String(new byte[16])
                : Mode == "oversized" ? Convert.ToBase64String(new byte[257]) : SearchKey;
            responses = Mode is "denied" or "busy" ? [Error(Mode == "denied" ? "ErrorAccessDenied" : "ErrorServerBusy")]
                : id == "original" && Mode is not ("direct" or "mismatch" or "oversized") ? [Error("ErrorItemNotFound")]
                : [Success(new XElement(M + "Items", Message(id, key)))];
        }
        else if (name == "FindFolder")
            responses = [Success(new XElement(M + "RootFolder", new XAttribute("IncludesLastItemInRange", "true"),
                new XElement(T + "Folders", Enumerable.Range(0, FolderCount).Select(index => new XElement(T + "Folder",
                    new XElement(T + "FolderId", new XAttribute("Id", index == 0 ? "deleted-folder" : "folder-" + index)),
                    new XElement(T + "DisplayName", index == 0 ? "Deleted Items" : "Folder"))))))];
        else if (name == "FindItem")
        {
            responses = operation.Element(M + "ParentFolderIds")!.Elements().Select(folder =>
            {
                var id = folder.Attribute("Id")!.Value;
                var hit = id == "deleted-folder" && Mode != "missing" || id == "folder-2" && Mode == "duplicate";
                var root = new XElement(M + "RootFolder",
                    Mode == "missing-completeness" && hit ? null : new XAttribute("IncludesLastItemInRange", !(Mode == "truncated" && hit)),
                    Mode == "omitted-items" && hit ? null : new XElement(T + "Items", hit
                        ? new XElement(T + "Message", new XElement(T + "ItemId", new XAttribute("Id", id == "deleted-folder" ? "moved" : "copy")),
                            Stamp(Mode == "lookup-mismatch" ? Convert.ToBase64String(new byte[16]) : SearchKey)) : null));
                return Success(root);
            }).ToArray();
            if (Mode == "partial") responses = responses.Skip(1).ToArray();
        }
        else throw new InvalidOperationException("Unexpected notification test operation.");
        var response = new XDocument(new XElement(S + "Envelope", new XElement(S + "Body", new XElement(M + (name + "Response"),
            new XElement(M + "ResponseMessages", responses)))));
        return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(response.ToString(), Encoding.UTF8, "text/xml") };
    }
}
