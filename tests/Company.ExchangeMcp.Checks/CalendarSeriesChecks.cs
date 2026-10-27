using System.Net;
using System.Text;
using System.Xml.Linq;
using System.Xml.Schema;
using Company.ExchangeMcp.Exchange;

internal sealed partial class Checks
{
    private async Task CalendarSeriesChecksAsync()
    {
        var handler = new CalendarSeriesRecordingHandler();
        var client = NewEwsClient(handler);

        var master = await client.GetRecurringMasterFromOccurrenceAsync(
            "alice@example.test", "occurrence-1", "occurrence-change", CancellationToken.None);
        Expect(master.CalendarItemType == "RecurringMaster" && master.IsRecurring,
            "RecurringMaster item type did not identify the event as recurring when IsRecurring was false.");

        var operation = XDocument.Parse(handler.LastBody).Descendants(XName.Get("GetItem", CalendarSeriesRecordingHandler.Messages)).Single();
        var masterId = operation.Descendants(XName.Get("RecurringMasterItemId", CalendarSeriesRecordingHandler.Types)).Single();
        Expect((string?)masterId.Attribute("OccurrenceId") == "occurrence-1"
            && (string?)masterId.Attribute("ChangeKey") == "occurrence-change"
            && masterId.Attributes().Count() == 2,
            "RecurringMasterItemId did not carry the employee-bound occurrence id and current change key exactly.");

        handler.ReturnItemType = "Occurrence";
        handler.OmitIsRecurringFlag = true;
        var occurrence = await client.GetCalendarEventAsync(
            "alice@example.test", "occurrence-1", CancellationToken.None);
        Expect(occurrence.CalendarItemType == "Occurrence" && occurrence.IsRecurring,
            "Occurrence item type did not identify the event as recurring when IsRecurring was absent.");

        handler.ReturnItemType = "Single";
        handler.OmitIsRecurringFlag = false;
        handler.IsRecurringFlag = false;
        var single = await client.GetCalendarEventAsync(
            "alice@example.test", "single-1", CancellationToken.None);
        Expect(single.CalendarItemType == "Single" && !single.IsRecurring,
            "A normal single calendar item was incorrectly identified as recurring.");

        handler.ReturnSingleItem = true;
        await AssertThrowsAsync<InvalidOperationException>(() => client.GetRecurringMasterFromOccurrenceAsync(
            "alice@example.test", "occurrence-1", "occurrence-change", CancellationToken.None));
        await AssertThrowsAsync<ArgumentException>(() => client.GetRecurringMasterFromOccurrenceAsync(
            "alice@example.test", "", "occurrence-change", CancellationToken.None));
        ValidateCalendarSeriesSchema(handler);

        var exchange = new CalendarPolicyRecordingHandler { RecurringSeriesMode = true };
        await using var host = await StartCalendarHostAsync(exchange, writesEnabled: true, sendEnabled: false);
        var token = Token("user-a", "mail.read mail.write mail.manage", sessionId: "calendar-series");
        await InitializeAsync(host.Client, token);

        var created = await ToolRequestAsync(host.Client, token, "tools/call", new
        {
            name = "calendar_create_event",
            arguments = new
            {
                subject = "Series test",
                body = "Body",
                start = "2026-10-10T09:00:00+03:30",
                end = "2026-10-10T10:00:00+03:30",
                timeZone = "Iran Standard Time",
                recurrencePattern = "daily",
                recurrenceNumberOfOccurrences = 3,
                sendInvitations = false
            }
        });
        Expect(!IsToolError(created.Body), "Recurring calendar creation failed in the MCP fixture.");
        var createdData = ToolStructuredData(created.Body);
        var eventHandle = createdData.GetProperty("handle").GetString()!;
        var seriesHandle = createdData.GetProperty("seriesHandle").GetString()!;
        Expect(createdData.GetProperty("scope").GetString() == "series"
            && !string.IsNullOrWhiteSpace(seriesHandle),
            "Recurring calendar creation did not return a usable typed series handle.");

        var readMaster = await ToolRequestAsync(host.Client, token, "tools/call", new
        {
            name = "calendar_read_event",
            arguments = new { eventHandle }
        });
        Expect(!IsToolError(readMaster.Body)
            && ToolStructuredData(readMaster.Body).GetProperty("calendarItemType").GetString() == "RecurringMaster",
            "The compatible event handle could not read the new recurring master.");

        var wrongTypeWrites = exchange.CalendarWriteCount;
        var wrongType = await ToolRequestAsync(host.Client, token, "tools/call", new
        {
            name = "calendar_update_event",
            arguments = SeriesUpdateArguments(eventHandle, "series")
        });
        Expect(IsToolError(wrongType.Body) && exchange.CalendarWriteCount == wrongTypeWrites,
            "An event handle was accepted for a series update or reached Exchange.");

        var updated = await ToolRequestAsync(host.Client, token, "tools/call", new
        {
            name = "calendar_update_event",
            arguments = SeriesUpdateArguments(seriesHandle, "series")
        });
        Expect(!IsToolError(updated.Body), "A valid typed series update failed.");
        var updatedSeriesHandle = ToolStructuredData(updated.Body).GetProperty("handle").GetString()!;

        var staleBefore = exchange.CalendarWriteCount;
        exchange.MasterChangeKey = "series-master-stale";
        var stale = await ToolRequestAsync(host.Client, token, "tools/call", new
        {
            name = "calendar_update_event",
            arguments = SeriesUpdateArguments(updatedSeriesHandle, "series")
        });
        Expect(IsToolError(stale.Body) && exchange.CalendarWriteCount == staleBefore,
            "A stale series handle reached the calendar update operation.");
        exchange.MasterChangeKey = "series-master-v2";

        var deleted = await ToolRequestAsync(host.Client, token, "tools/call", new
        {
            name = "calendar_delete_event",
            arguments = new { eventHandle = updatedSeriesHandle, scope = "series", sendCancellations = false }
        });
        Expect(!IsToolError(deleted.Body) && exchange.DeleteCount == 1,
            "A valid typed series delete failed or did not issue one recoverable delete.");

        var listed = await ToolRequestAsync(host.Client, token, "tools/call", new
        {
            name = "calendar_list_events",
            arguments = new { start = "2026-10-10T00:00:00Z", end = "2026-10-11T00:00:00Z" }
        });
        Expect(!IsToolError(listed.Body), "The occurrence fixture could not be listed.");
        var occurrenceHandle = ToolStructuredData(listed.Body).GetProperty("items")[0]
            .GetProperty("occurrenceHandle").GetString()!;

        var masterFromOccurrence = await ToolRequestAsync(host.Client, token, "tools/call", new
        {
            name = "calendar_read_series",
            arguments = new { occurrenceHandle }
        });
        Expect(!IsToolError(masterFromOccurrence.Body)
            && exchange.MasterLookupCount == 1
            && ToolStructuredData(masterFromOccurrence.Body).GetProperty("calendarItemType").GetString() == "RecurringMaster",
            "calendar_read_series did not resolve the occurrence to its recurring master.");

        var beforeCrossUser = exchange.RequestCount;
        var crossUser = await ToolRequestAsync(host.Client, Token("user-b", "mail.read", sessionId: "calendar-series-b"),
            "tools/call", new { name = "calendar_read_series", arguments = new { occurrenceHandle } });
        Expect(IsToolError(crossUser.Body) && exchange.RequestCount == beforeCrossUser,
            "A calendar occurrence handle was reusable by another mailbox identity.");

        var beforeWrongKind = exchange.RequestCount;
        var wrongKind = await ToolRequestAsync(host.Client, token, "tools/call", new
        {
            name = "calendar_read_series",
            arguments = new { occurrenceHandle = eventHandle }
        });
        Expect(IsToolError(wrongKind.Body) && exchange.RequestCount == beforeWrongKind,
            "A calendar event handle was accepted as an occurrence handle.");

        var staleBeforeRead = exchange.MasterLookupCount;
        exchange.OccurrenceChangeKey = "occurrence-stale";
        var staleOccurrence = await ToolRequestAsync(host.Client, token, "tools/call", new
        {
            name = "calendar_read_series",
            arguments = new { occurrenceHandle }
        });
        Expect(IsToolError(staleOccurrence.Body) && exchange.MasterLookupCount == staleBeforeRead,
            "A stale occurrence handle reached the recurring-master lookup.");

        ValidateCalendarSeriesSchema(exchange);
    }

    private static Dictionary<string, object?> SeriesUpdateArguments(string handle, string scope) => new()
    {
        ["eventHandle"] = handle,
        ["subject"] = "Updated series",
        ["body"] = "Updated body",
        ["start"] = "2026-10-10T09:00:00+03:30",
        ["end"] = "2026-10-10T10:00:00+03:30",
        ["timeZone"] = "Iran Standard Time",
        ["scope"] = scope,
        ["sendUpdates"] = false
    };

    private static void ValidateCalendarSeriesSchema(CalendarSeriesRecordingHandler handler) =>
        ValidateCalendarSeriesSchema(handler.Bodies, handler.Responses);

    private static void ValidateCalendarSeriesSchema(CalendarPolicyRecordingHandler handler) =>
        ValidateCalendarSeriesSchema(handler.Bodies, handler.Responses);

    private static void ValidateCalendarSeriesSchema(IReadOnlyList<string> requests, IReadOnlyList<string> responses)
    {
        var schemas = LoadOptionalExchangeSchemas();
        Expect(requests.Count > 0 && responses.Count > 0, "Calendar series fixture did not capture both SOAP directions.");
        foreach (var envelope in requests.Concat(responses))
        {
            var document = XDocument.Parse(envelope, LoadOptions.PreserveWhitespace);
            var operation = document.Root?.Element(XName.Get("Body", CalendarSeriesRecordingHandler.Soap))?.Elements().Single()
                ?? throw new InvalidOperationException("Calendar series SOAP operation was not captured.");
            if (schemas is not null)
                new XDocument(new XElement(operation)).Validate(schemas, (_, error) => throw new InvalidOperationException(
                    $"Exchange 2019 schema rejected calendar series SOAP: {error.Message}"));
        }
    }
}

internal sealed class CalendarSeriesRecordingHandler : HttpMessageHandler
{
    public const string Soap = "http://schemas.xmlsoap.org/soap/envelope/";
    public const string Messages = "http://schemas.microsoft.com/exchange/services/2006/messages";
    public const string Types = "http://schemas.microsoft.com/exchange/services/2006/types";
    public string LastBody { get; private set; } = string.Empty;
    public bool ReturnSingleItem { get; set; }
    public string ReturnItemType { get; set; } = "RecurringMaster";
    public bool? IsRecurringFlag { get; set; } = false;
    public bool OmitIsRecurringFlag { get; set; }
    public List<string> Bodies { get; } = [];
    public List<string> Responses { get; } = [];

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        LastBody = await request.Content!.ReadAsStringAsync(cancellationToken);
        Bodies.Add(LastBody);
        var itemType = ReturnSingleItem ? "Single" : ReturnItemType;
        var response = Response("GetItem", $"<m:Items>{CalendarItem("master-1", "master-change", itemType, IsRecurringFlag, OmitIsRecurringFlag)}</m:Items>");
        Responses.Add(response);
        return new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(response, Encoding.UTF8, "text/xml")
        };
    }

    private static string Response(string operation, string payload) =>
        $"<s:Envelope xmlns:s='{Soap}' xmlns:m='{Messages}' xmlns:t='{Types}'><s:Body><m:{operation}Response><m:ResponseMessages><m:{operation}ResponseMessage ResponseClass='Success'><m:ResponseCode>NoError</m:ResponseCode>{payload}</m:{operation}ResponseMessage></m:ResponseMessages></m:{operation}Response></s:Body></s:Envelope>";

    private static string CalendarItem(string id, string changeKey, string itemType, bool? isRecurring, bool omitIsRecurring) =>
        $"<t:CalendarItem><t:ItemId Id='{id}' ChangeKey='{changeKey}'/><t:Subject>Series</t:Subject><t:Body BodyType='Text'>Body</t:Body><t:Start>2026-10-10T05:30:00Z</t:Start><t:End>2026-10-10T06:30:00Z</t:End><t:IsAllDayEvent>false</t:IsAllDayEvent><t:LegacyFreeBusyStatus>Busy</t:LegacyFreeBusyStatus><t:Location>Room 1</t:Location><t:IsMeeting>false</t:IsMeeting><t:IsCancelled>false</t:IsCancelled>{(omitIsRecurring ? string.Empty : $"<t:IsRecurring>{(isRecurring ?? itemType is "RecurringMaster" or "Occurrence" or "Exception").ToString().ToLowerInvariant()}</t:IsRecurring>")}<t:CalendarItemType>{itemType}</t:CalendarItemType><t:StartTimeZone Id='Iran Standard Time'/><t:IsOrganizer>true</t:IsOrganizer></t:CalendarItem>";
}

internal sealed partial class CalendarPolicyRecordingHandler
{
    public bool RecurringSeriesMode { get; set; }
    public string MasterChangeKey { get; set; } = "series-master-v1";
    public string OccurrenceChangeKey { get; set; } = "occurrence-v1";
    public int RequestCount { get; private set; }
    public int DeleteCount { get; private set; }
    public int MasterLookupCount { get; private set; }
    public List<string> Bodies { get; } = [];
    public List<string> Responses { get; } = [];

    private string BuildRecurringSeriesResponse(string operation, XDocument request)
    {
        var operationElement = request.Root!.Element(XName.Get("Body", Soap))!.Elements().Single();
        var isMasterLookup = operationElement.Descendants(XName.Get("RecurringMasterItemId", Types)).Any();
        if (isMasterLookup) MasterLookupCount++;
        if (operation is "CreateItem" or "UpdateItem" or "DeleteItem") CalendarWriteCount++;
        if (operation == "DeleteItem") DeleteCount++;

        var requestedOccurrence = operationElement.Descendants(XName.Get("ItemId", Types))
            .Any(x => (string?)x.Attribute("Id") == "occurrence-1");
        var itemId = isMasterLookup || !requestedOccurrence && operation != "FindItem" ? "series-master" : "occurrence-1";
        var itemType = itemId == "occurrence-1" ? "Occurrence" : "RecurringMaster";
        var itemChangeKey = itemType == "Occurrence" ? OccurrenceChangeKey : MasterChangeKey;
        var item = CalendarItem(itemId, itemChangeKey, itemType);
        string payload;
        if (operation == "FindItem")
            payload = $"<m:RootFolder IncludesLastItemInRange='true'><t:Items>{CalendarItem("occurrence-1", OccurrenceChangeKey, "Occurrence")}</t:Items></m:RootFolder>";
        else if (operation is "CreateItem" or "UpdateItem")
        {
            var returnedKey = operation == "CreateItem" ? MasterChangeKey : "series-master-v2";
            if (operation == "UpdateItem") MasterChangeKey = returnedKey;
            payload = $"<m:Items><t:CalendarItem><t:ItemId Id='series-master' ChangeKey='{returnedKey}'/></t:CalendarItem></m:Items>";
        }
        else if (operation == "DeleteItem")
            payload = string.Empty;
        else
            payload = $"<m:Items>{item}</m:Items>";
        return Response(operation, payload);
    }

    private static string Response(string operation, string payload) =>
        $"<s:Envelope xmlns:s='{Soap}' xmlns:m='{Messages}' xmlns:t='{Types}'><s:Body><m:{operation}Response><m:ResponseMessages><m:{operation}ResponseMessage ResponseClass='Success'><m:ResponseCode>NoError</m:ResponseCode>{payload}</m:{operation}ResponseMessage></m:ResponseMessages></m:{operation}Response></s:Body></s:Envelope>";

    private static string CalendarItem(string id, string changeKey, string itemType) =>
        $"<t:CalendarItem><t:ItemId Id='{id}' ChangeKey='{changeKey}'/><t:Subject>Series</t:Subject><t:Body BodyType='Text'>Body</t:Body><t:Start>2026-10-10T05:30:00Z</t:Start><t:End>2026-10-10T06:30:00Z</t:End><t:IsAllDayEvent>false</t:IsAllDayEvent><t:LegacyFreeBusyStatus>Busy</t:LegacyFreeBusyStatus><t:Location>Room 1</t:Location><t:IsMeeting>false</t:IsMeeting><t:IsCancelled>false</t:IsCancelled><t:IsRecurring>{(itemType != "Single").ToString().ToLowerInvariant()}</t:IsRecurring><t:CalendarItemType>{itemType}</t:CalendarItemType><t:StartTimeZone Id='Iran Standard Time'/><t:IsOrganizer>true</t:IsOrganizer></t:CalendarItem>";
}
