using System.Net;
using System.Text;
using System.Xml.Schema;
using System.Xml.Linq;
using Company.ExchangeMcp.Exchange;
using Company.ExchangeMcp;
using Company.ExchangeMcp.Security;
using Microsoft.Extensions.Options;
using System.Text.Json;
using ModelContextProtocol;

internal sealed partial class Checks
{
    // Called by the runner after the parent adds RoomTools to the MCP catalog.
    private async Task RoomChecksAsync()
    {
        var handler = new RoomRecordingHandler();
        var client = NewEwsClient(handler);

        var lists = await client.ListRoomListsAsync("alice@example.test", CancellationToken.None);
        Expect(lists.Count == 2 && lists[0].Address == "rooms-east@example.test"
            && lists[0].MailboxType == "PublicDL" && lists[1].Name == "Rooms West",
            "GetRoomLists did not parse Exchange room-list addresses.");
        var listOperation = RoomOperation(XDocument.Parse(handler.LastBody));
        Expect(listOperation.Name.LocalName == "GetRoomLists" && !listOperation.Elements().Any(),
            "GetRoomLists emitted an unexpected request body.");

        var rooms = await client.ListRoomsAsync("alice@example.test", "rooms-east@example.test", CancellationToken.None);
        Expect(rooms.Count == 2 && rooms[0].Address == "room-101@example.test"
            && rooms[0].Name.Contains("101", StringComparison.Ordinal)
            && rooms[1].MailboxType == "Mailbox",
            "GetRooms did not parse room mailbox addresses.");
        var roomsOperation = RoomOperation(XDocument.Parse(handler.LastBody));
        Expect(roomsOperation.Name.LocalName == "GetRooms"
            && roomsOperation.Element(XName.Get("RoomList", RoomRecordingHandler.Messages))
                ?.Element(XName.Get("EmailAddress", RoomRecordingHandler.Types))?.Value == "rooms-east@example.test",
            "GetRooms did not send the room-list address in the Exchange-defined shape.");

        handler.ReturnEmpty = true;
        var empty = await client.ListRoomListsAsync("alice@example.test", CancellationToken.None);
        Expect(empty.Count == 0, "An empty Exchange room-list response was not represented as an empty result.");
        handler.ReturnEmpty = false;
        ValidateRoomSchema(handler);
        await RoomAvailabilityPolicyChecksAsync();
    }

    private async Task RoomAvailabilityPolicyChecksAsync()
    {
        var handler = new AvailabilityPolicyHandler { InnerHandler = new CalendarRecordingHandler() };
        var options = Options.Create(new ServiceOptions
        {
            AllowedClientIds = ["checks"],
            Mailboxes = new() { ["user-a"] = "alice@example.test" },
            AllowedRecipientDomains = ["example.test"],
            AuditPath = Path.Combine(runDirectory, "rooms-audit.jsonl")
        });
        using var audit = new AuditLog(options);
        var tools = new RoomTools(NewEwsClient(handler), new MailboxAccess(options), audit);
        var result = JsonSerializer.SerializeToElement(await tools.FindMeetingTimes(SyncUser("user-a"),
            "2026-10-10T04:00:00Z", "2026-10-10T08:00:00Z", ["to@example.test"], 30,
            CancellationToken.None, "Iran Standard Time", 30, 1));
        Expect(result.GetProperty("truncated").GetBoolean() && result.GetProperty("status").GetString() == "partial"
            && result.GetProperty("suggestions")[0].GetProperty("start").GetDateTimeOffset().Offset == TimeSpan.FromHours(3.5),
            "Meeting suggestions hid truncation or mislabeled UTC as the requested time zone.");
        var none = JsonSerializer.SerializeToElement(await tools.FindMeetingTimes(SyncUser("user-a"),
            "2026-10-10T05:30:00Z", "2026-10-10T06:30:00Z", ["to@example.test"], 30, CancellationToken.None));
        Expect(none.GetProperty("status").GetString() == "no_available_slot",
            "Meeting suggestions included a busy interval.");
        foreach (var view in new[] { "None", "MergedOnly" })
        {
            handler.ViewType = view;
            await AssertThrowsAsync<McpException>(() => tools.FindMeetingTimes(SyncUser("user-a"),
                "2026-10-10T04:00:00Z", "2026-10-10T08:00:00Z", ["to@example.test"], 30, CancellationToken.None));
        }
        handler.ViewType = null;
        handler.RemoveEventArray = true;
        handler.Merged = "00002200";
        var merged = JsonSerializer.SerializeToElement(await tools.FindMeetingTimes(SyncUser("user-a"),
            "2026-10-10T04:00:00Z", "2026-10-10T08:00:00Z", ["to@example.test"], 30,
            CancellationToken.None, maxSuggestions: 100));
        Expect(merged.GetProperty("suggestions").GetArrayLength() == 6,
            "Merged-only fallback did not conservatively exclude occupied intervals.");
        foreach (var invalidMerged in new[] { "", "0000", "0000000x" })
        {
            handler.Merged = invalidMerged;
            await AssertThrowsAsync<McpException>(() => tools.FindMeetingTimes(SyncUser("user-a"),
                "2026-10-10T04:00:00Z", "2026-10-10T08:00:00Z", ["to@example.test"], 30, CancellationToken.None));
        }
        handler.RemoveEventArray = false;
        handler.Merged = null;
        handler.InvalidEventTime = true;
        await AssertThrowsAsync<InvalidOperationException>(() => tools.FindMeetingTimes(SyncUser("user-a"),
            "2026-10-10T04:00:00Z", "2026-10-10T08:00:00Z", ["to@example.test"], 30, CancellationToken.None));
        handler.InvalidEventTime = false;
        handler.RemoveResponse = true;
        await AssertThrowsAsync<InvalidOperationException>(() => tools.FindMeetingTimes(SyncUser("user-a"),
            "2026-10-10T04:00:00Z", "2026-10-10T08:00:00Z", ["to@example.test"], 30, CancellationToken.None));
        handler.RemoveResponse = false;
        var calls = handler.Calls;
        await AssertThrowsAsync<McpException>(() => tools.FindMeetingTimes(SyncUser("user-a", ""),
            "2026-10-10T04:00:00Z", "2026-10-10T08:00:00Z", ["to@example.test"], 30, CancellationToken.None));
        await AssertThrowsAsync<McpException>(() => tools.FindMeetingTimes(SyncUser("user-a"),
            "2026-10-10T08:00:00Z", "2026-10-10T04:00:00Z", ["to@example.test"], 30, CancellationToken.None));
        Expect(calls == handler.Calls, "Missing scope or an inverted range reached the availability service.");
    }

    private static XElement RoomOperation(XDocument document) =>
        document.Root!.Element(XName.Get("Body", RoomRecordingHandler.Soap))!.Elements().Single();

    private static void ValidateRoomSchema(RoomRecordingHandler handler)
    {
        var schemas = LoadOptionalExchangeSchemas();
        foreach (var body in handler.Bodies.Concat(handler.Responses))
        {
            var operation = RoomOperation(XDocument.Parse(body, LoadOptions.PreserveWhitespace));
            if (schemas is not null)
                new XDocument(new XElement(operation)).Validate(schemas, (_, error) =>
                    throw new InvalidOperationException($"Exchange 2019 schema rejected room operation: {error.Message}"));
        }
    }
}

internal sealed class AvailabilityPolicyHandler : DelegatingHandler
{
    public string? ViewType { get; set; }
    public bool RemoveResponse { get; set; }
    public bool RemoveEventArray { get; set; }
    public string? Merged { get; set; }
    public bool InvalidEventTime { get; set; }
    public int Calls { get; private set; }
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        Calls++;
        var response = await base.SendAsync(request, cancellationToken);
        var document = XDocument.Parse(await response.Content.ReadAsStringAsync(cancellationToken));
        if (ViewType is not null)
            document.Descendants(XName.Get("FreeBusyViewType", RoomRecordingHandler.Types)).Single().Value = ViewType;
        if (RemoveResponse) document.Descendants(XName.Get("FreeBusyResponse", RoomRecordingHandler.Messages)).Remove();
        if (RemoveEventArray) document.Descendants(XName.Get("CalendarEventArray", RoomRecordingHandler.Types)).Remove();
        if (Merged is not null)
            document.Descendants(XName.Get("MergedFreeBusy", RoomRecordingHandler.Types)).Single().Value = Merged;
        if (InvalidEventTime)
            document.Descendants(XName.Get("StartTime", RoomRecordingHandler.Types)).Single().Value = "invalid";
        response.Content.Dispose();
        response.Content = new StringContent(document.ToString(), Encoding.UTF8, "text/xml");
        return response;
    }
}

internal sealed class RoomRecordingHandler : HttpMessageHandler
{
    public const string Soap = "http://schemas.xmlsoap.org/soap/envelope/";
    public const string Messages = "http://schemas.microsoft.com/exchange/services/2006/messages";
    public const string Types = "http://schemas.microsoft.com/exchange/services/2006/types";
    public List<string> Bodies { get; } = [];
    public List<string> Responses { get; } = [];
    public string LastBody => Bodies[^1];
    public bool ReturnEmpty { get; set; }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        var body = await request.Content!.ReadAsStringAsync(cancellationToken);
        Bodies.Add(body);
        var operation = RoomOperation(XDocument.Parse(body));
        var payload = operation.Name.LocalName switch
        {
            "GetRoomLists" => ReturnEmpty
                ? "<m:RoomLists/>"
                : "<m:RoomLists><t:Address><t:Name>Rooms East</t:Name><t:EmailAddress>rooms-east@example.test</t:EmailAddress><t:RoutingType>SMTP</t:RoutingType><t:MailboxType>PublicDL</t:MailboxType></t:Address><t:Address><t:Name>Rooms West</t:Name><t:EmailAddress>rooms-west@example.test</t:EmailAddress><t:RoutingType>SMTP</t:RoutingType><t:MailboxType>PublicDL</t:MailboxType></t:Address></m:RoomLists>",
            "GetRooms" => "<m:Rooms><t:Room><t:Id><t:Name>Conference Room 101</t:Name><t:EmailAddress>room-101@example.test</t:EmailAddress><t:RoutingType>SMTP</t:RoutingType><t:MailboxType>Mailbox</t:MailboxType></t:Id></t:Room><t:Room><t:Id><t:Name>Conference Room 102</t:Name><t:EmailAddress>room-102@example.test</t:EmailAddress><t:RoutingType>SMTP</t:RoutingType><t:MailboxType>Mailbox</t:MailboxType></t:Id></t:Room></m:Rooms>",
            _ => string.Empty
        };
        var response = $"<s:Envelope xmlns:s='{Soap}' xmlns:m='{Messages}' xmlns:t='{Types}'><s:Body><m:{operation.Name.LocalName}Response ResponseClass='Success'><m:ResponseCode>NoError</m:ResponseCode>{payload}</m:{operation.Name.LocalName}Response></s:Body></s:Envelope>";
        Responses.Add(response);
        return new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(response, Encoding.UTF8, "text/xml")
        };
    }

    private static XElement RoomOperation(XDocument document) =>
        document.Root!.Element(XName.Get("Body", Soap))!.Elements().Single();
}
