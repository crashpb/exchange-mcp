using System.Net;
using System.Text;
using System.Xml.Linq;
using System.Xml.Schema;
using Company.ExchangeMcp;
using Company.ExchangeMcp.Exchange;
using Company.ExchangeMcp.Security;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

internal sealed partial class Checks
{
    private const int MaxGroupwareFileBytes = 5 * 1024 * 1024;

    private async Task GroupwareAttachmentsChecksAsync()
    {
        var exchange = new GroupwareAttachmentRecordingHandler();
        var direct = NewEwsClient(exchange);

        await AssertThrowsAsync<InvalidOperationException>(() => direct.GetGroupwareAttachmentsAsync(
            "alice@example.test", "contact-1", "calendar", CancellationToken.None));
        Expect(exchange.Calls[^1].Operation == "GetItem",
            "The wrong groupware item kind did not reach the typed EWS read.");

        await using var host = await StartGroupwareHostAsync(exchange, writesEnabled: true, sendEnabled: false);
        var token = Token("user-a", "mail.read mail.write mail.manage");
        await InitializeAsync(host.Client, token);
        var handles = host.App.Services.GetRequiredService<MailboxHandles>();
        var alice = new MailboxIdentity("user-a", "alice@example.test", "chatgpt-test");

        var eventHandle = handles.Issue(alice, "calendar-event", "calendar-1", "calendar-1-change");
        var wrongKindHandle = handles.Issue(alice, "calendar-event", "contact-1", "contact-1-change");
        var beforeWrongKindWrite = exchange.Calls.Count;
        var wrongKindWrite = await ToolRequestAsync(host.Client, token, "tools/call", new
        {
            name = "groupware_create_attachment",
            arguments = new
            {
                kind = "calendar",
                itemHandle = wrongKindHandle,
                name = "wrong-kind.txt",
                contentBase64 = Convert.ToBase64String(new byte[] { 0 }),
                contentType = "text/plain"
            }
        });
        Expect(IsToolError(wrongKindWrite.Body)
            && !exchange.Calls.Skip(beforeWrongKindWrite).Any(call => call.Operation == "CreateAttachment"),
            "A typed groupware handle for the wrong EWS item kind reached a write.");

        var listed = await ToolRequestAsync(host.Client, token, "tools/call", new
        {
            name = "groupware_list_attachments",
            arguments = new { kind = "calendar", itemHandle = eventHandle }
        });
        Expect(!IsToolError(listed.Body), "Calendar attachment listing failed.");
        var listData = ToolStructuredData(listed.Body);
        Expect(listData.GetProperty("count").GetInt32() == 2
            && listData.GetProperty("bytes").GetInt64() == 10
            && listData.GetProperty("items").GetArrayLength() == 1,
            "Attachment listing did not count file and embedded item attachments separately.");
        var attachmentHandle = listData.GetProperty("items")[0].GetProperty("handle").GetString()!;
        var read = await ToolRequestAsync(host.Client, token, "tools/call", new
        {
            name = "groupware_read_attachment",
            arguments = new { attachmentHandle }
        });
        Expect(!IsToolError(read.Body)
            && ToolStructuredData(read.Body).GetProperty("contentBase64").GetString() == "bm90ZQ==",
            "A current, owned groupware attachment could not be read intact.");

        var beforeCrossUser = exchange.Calls.Count;
        var crossUser = await ToolRequestAsync(host.Client, Token("user-b", "mail.read"), "tools/call", new
        {
            name = "groupware_read_attachment",
            arguments = new { attachmentHandle }
        });
        Expect(IsToolError(crossUser.Body) && exchange.Calls.Count == beforeCrossUser,
            "A groupware attachment handle crossed mailbox identities or reached EWS.");

        exchange.SetChangeKey("calendar-1", "calendar-1-new");
        var beforeStale = exchange.Calls.Count;
        var stale = await ToolRequestAsync(host.Client, token, "tools/call", new
        {
            name = "groupware_read_attachment",
            arguments = new { attachmentHandle }
        });
        Expect(IsToolError(stale.Body)
            && !exchange.Calls.Skip(beforeStale).Any(call => call.Operation == "GetAttachment"),
            "A stale groupware attachment handle reached GetAttachment.");

        var currentEventHandle = handles.Issue(alice, "calendar-event", "calendar-1", "calendar-1-new");
        var created = await ToolRequestAsync(host.Client, token, "tools/call", new
        {
            name = "groupware_create_attachment",
            arguments = new
            {
                kind = "calendar",
                itemHandle = currentEventHandle,
                name = "new.txt",
                contentBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes("new")),
                contentType = "text/plain"
            }
        });
        Expect(!IsToolError(created.Body), "A valid groupware attachment was not saved.");
        var createdData = ToolStructuredData(created.Body);
        var refreshedEventHandle = createdData.GetProperty("handle").GetString()!;
        var createdAttachmentHandle = createdData.GetProperty("attachmentHandle").GetString()!;
        Expect(refreshedEventHandle != currentEventHandle,
            "A groupware attachment write did not issue a refreshed item handle.");

        var beforeOldHandle = exchange.Calls.Count;
        var oldHandleWrite = await ToolRequestAsync(host.Client, token, "tools/call", new
        {
            name = "groupware_create_attachment",
            arguments = new
            {
                kind = "calendar",
                itemHandle = currentEventHandle,
                name = "stale.txt",
                contentBase64 = Convert.ToBase64String(new byte[] { 1 }),
                contentType = "application/octet-stream"
            }
        });
        Expect(IsToolError(oldHandleWrite.Body)
            && !exchange.Calls.Skip(beforeOldHandle).Any(call => call.Operation == "CreateAttachment"),
            "The pre-write groupware item handle remained usable after its ChangeKey advanced.");

        var createdRead = await ToolRequestAsync(host.Client, token, "tools/call", new
        {
            name = "groupware_read_attachment",
            arguments = new { attachmentHandle = createdAttachmentHandle }
        });
        Expect(!IsToolError(createdRead.Body),
            "The refreshed groupware attachment handle could not read the newly saved file.");

        var attendeeHandle = handles.Issue(alice, "calendar-event", "meeting-attendee", "meeting-attendee-change");
        var attendeeList = await ToolRequestAsync(host.Client, token, "tools/call", new
        {
            name = "groupware_list_attachments",
            arguments = new { kind = "calendar", itemHandle = attendeeHandle }
        });
        Expect(!IsToolError(attendeeList.Body), "Attendee meeting attachment listing failed.");
        var attendeeAttachment = ToolStructuredData(attendeeList.Body).GetProperty("items")[0]
            .GetProperty("handle").GetString()!;
        var beforeAttendeeWrite = exchange.Calls.Count;
        var attendeeCreate = await ToolRequestAsync(host.Client, token, "tools/call", new
        {
            name = "groupware_create_attachment",
            arguments = new
            {
                kind = "calendar",
                itemHandle = attendeeHandle,
                name = "blocked.txt",
                contentBase64 = Convert.ToBase64String(new byte[] { 2 }),
                contentType = "text/plain"
            }
        });
        var attendeeDelete = await ToolRequestAsync(host.Client, token, "tools/call", new
        {
            name = "groupware_delete_attachment",
            arguments = new { attachmentHandle = attendeeAttachment }
        });
        Expect(IsToolError(attendeeCreate.Body) && IsToolError(attendeeDelete.Body)
            && !exchange.Calls.Skip(beforeAttendeeWrite).Any(call => call.Operation is "CreateAttachment" or "DeleteAttachment"),
            "An attendee meeting attachment reached an EWS write.");

        var inlineCollision = await ToolRequestAsync(host.Client, token, "tools/call", new
        {
            name = "groupware_create_attachment",
            arguments = new
            {
                kind = "calendar",
                itemHandle = refreshedEventHandle,
                name = "duplicate.png",
                contentBase64 = Convert.ToBase64String(new byte[] { 3 }),
                contentType = "image/png",
                isInline = true,
                contentId = "cid-existing"
            }
        });
        Expect(IsToolError(inlineCollision.Body), "A duplicate inline ContentId was accepted.");

        exchange.RemoveAttachment("calendar-1", "att-created-2", preserveChangeKey: true);
        var beforeMembership = exchange.Calls.Count;
        var missingMembership = await ToolRequestAsync(host.Client, token, "tools/call", new
        {
            name = "groupware_read_attachment",
            arguments = new { attachmentHandle = createdAttachmentHandle }
        });
        Expect(IsToolError(missingMembership.Body)
            && !exchange.Calls.Skip(beforeMembership).Any(call => call.Operation == "GetAttachment"),
            "A groupware attachment handle was usable after the file left its parent item.");

        var exactFile = await direct.CreateFileAttachmentAsync("alice@example.test", "limit-contact",
            "limit-contact-change", "five.bin", new byte[MaxGroupwareFileBytes],
            "application/octet-stream", CancellationToken.None);
        Expect(exactFile.Attachment.Size == MaxGroupwareFileBytes,
            "A file at the 5 MiB groupware attachment boundary was rejected.");
        await AssertThrowsAsync<ArgumentException>(() => direct.CreateFileAttachmentAsync("alice@example.test",
            "limit-contact", "limit-contact-new", "five-plus-one.bin",
            new byte[MaxGroupwareFileBytes + 1], "application/octet-stream", CancellationToken.None));

        var aggregateHandle = handles.Issue(alice, "task", "aggregate-task", "aggregate-task-change");
        var aggregateCreate = await ToolRequestAsync(host.Client, token, "tools/call", new
        {
            name = "groupware_create_attachment",
            arguments = new
            {
                kind = "task",
                itemHandle = aggregateHandle,
                name = "last-byte.bin",
                contentBase64 = Convert.ToBase64String(new byte[] { 4 }),
                contentType = "application/octet-stream"
            }
        });
        Expect(!IsToolError(aggregateCreate.Body),
            "An attachment that exactly reached the 10 MiB aggregate boundary was rejected.");
        var aggregateData = ToolStructuredData(aggregateCreate.Body);
        var aggregateCurrentHandle = aggregateData.GetProperty("handle").GetString()!;
        var beforeAggregateOverflow = exchange.Calls.Count;
        var aggregateOverflow = await ToolRequestAsync(host.Client, token, "tools/call", new
        {
            name = "groupware_create_attachment",
            arguments = new
            {
                kind = "task",
                itemHandle = aggregateCurrentHandle,
                name = "overflow.bin",
                contentBase64 = Convert.ToBase64String(new byte[] { 5 }),
                contentType = "application/octet-stream"
            }
        });
        Expect(IsToolError(aggregateOverflow.Body)
            && !exchange.Calls.Skip(beforeAggregateOverflow).Any(call => call.Operation == "CreateAttachment"),
            "The 10 MiB groupware attachment aggregate limit was not enforced.");

        var countHandle = handles.Issue(alice, "task", "count-task", "count-task-change");
        var beforeCount = exchange.Calls.Count;
        var countOverflow = await ToolRequestAsync(host.Client, token, "tools/call", new
        {
            name = "groupware_create_attachment",
            arguments = new
            {
                kind = "task",
                itemHandle = countHandle,
                name = "one-too-many.bin",
                contentBase64 = Convert.ToBase64String(new byte[] { 6 }),
                contentType = "application/octet-stream"
            }
        });
        Expect(IsToolError(countOverflow.Body)
            && !exchange.Calls.Skip(beforeCount).Any(call => call.Operation == "CreateAttachment"),
            "The 100 attachment count limit was not enforced.");

        var removed = await ToolRequestAsync(host.Client, token, "tools/call", new
        {
            name = "groupware_delete_attachment",
            arguments = new { attachmentHandle = aggregateData.GetProperty("attachmentHandle").GetString()! }
        });
        Expect(!IsToolError(removed.Body), "An owned task attachment could not be removed.");
        var removedData = ToolStructuredData(removed.Body);
        var afterRemoval = await ToolRequestAsync(host.Client, token, "tools/call", new
        {
            name = "groupware_list_attachments",
            arguments = new { kind = "task", itemHandle = removedData.GetProperty("handle").GetString()! }
        });
        Expect(!IsToolError(afterRemoval.Body)
            && removedData.GetProperty("handle").GetString() != aggregateCurrentHandle
            && !removedData.GetProperty("meetingUpdateSent").GetBoolean()
            && ToolStructuredData(afterRemoval.Body).GetProperty("count").GetInt32() == 1
            && ToolStructuredData(afterRemoval.Body).GetProperty("bytes").GetInt64() == 10 * 1024 * 1024 - 1,
            "Attachment removal did not refresh the handle and preserve the embedded attachment.");

        var assignedHandle = handles.Issue(alice, "task", "assigned-task", "assigned-task-change");
        var assignedList = await ToolRequestAsync(host.Client, token, "tools/call", new
        {
            name = "groupware_list_attachments",
            arguments = new { kind = "task", itemHandle = assignedHandle }
        });
        Expect(!IsToolError(assignedList.Body), "Assigned task attachment listing failed.");
        var assignedAttachment = ToolStructuredData(assignedList.Body).GetProperty("items")[0]
            .GetProperty("handle").GetString()!;
        var beforeAssignedWrite = exchange.Calls.Count;
        var assignedCreate = await ToolRequestAsync(host.Client, token, "tools/call", new
        {
            name = "groupware_create_attachment",
            arguments = new
            {
                kind = "task",
                itemHandle = assignedHandle,
                name = "bypass.txt",
                contentBase64 = Convert.ToBase64String(new byte[] { 2 }),
                contentType = "text/plain"
            }
        });
        var assignedDelete = await ToolRequestAsync(host.Client, token, "tools/call", new
        {
            name = "groupware_delete_attachment",
            arguments = new { attachmentHandle = assignedAttachment }
        });
        Expect(IsToolError(assignedCreate.Body) && IsToolError(assignedDelete.Body)
            && !exchange.Calls.Skip(beforeAssignedWrite).Any(call => call.Operation is "CreateAttachment" or "DeleteAttachment"),
            "Assigned task attachment writes bypassed the native task assignment workflow.");

        ValidateGroupwareCapturedOperations(exchange);
    }

    private async Task<TestHostContext> StartGroupwareHostAsync(
        GroupwareAttachmentRecordingHandler exchange, bool writesEnabled, bool sendEnabled)
    {
        var passwordPath = Path.Combine(runDirectory, "groupware-exchange-password.txt");
        var introspectionSecretPath = Path.Combine(runDirectory, "groupware-introspection-secret.txt");
        var auditPath = Path.Combine(runDirectory, $"groupware-audit-{Guid.NewGuid():N}.jsonl");
        await File.WriteAllTextAsync(passwordPath, "synthetic-password");
        await File.WriteAllTextAsync(introspectionSecretPath, "synthetic-introspection-secret");
        var app = AppHost.Create([], builder =>
        {
            builder.WebHost.UseTestServer();
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
                .ConfigurePrimaryHttpMessageHandler(() => new IntrospectionHandler());
        });
        await app.StartAsync();
        var client = app.GetTestClient();
        client.BaseAddress = new Uri("https://mail.example.test/");
        return new TestHostContext(app, client);
    }

    private static void ValidateGroupwareCapturedOperations(GroupwareAttachmentRecordingHandler exchange)
    {
        var schemas = LoadOptionalExchangeSchemas();
        Expect(exchange.Calls.Any(call => call.Operation == "GetItem")
            && exchange.Calls.Any(call => call.Operation == "CreateAttachment")
            && exchange.Calls.Any(call => call.Operation == "GetAttachment")
            && exchange.Calls.Any(call => call.Operation == "DeleteAttachment"),
            "The groupware fixture did not capture every attachment SOAP operation.");
        foreach (var call in exchange.Calls)
        {
            var document = XDocument.Parse(call.Body, LoadOptions.PreserveWhitespace);
            var body = document.Root?.Element(XName.Get("Body", "http://schemas.xmlsoap.org/soap/envelope/"));
            Expect(body is not null && body.Elements().Count() == 1,
                $"SOAP operation {call.Operation} did not have exactly one Body child.");
            if (schemas is not null)
                new XDocument(new XElement(body!.Elements().Single())).Validate(schemas, (_, error) =>
                    throw new InvalidOperationException($"Exchange 2019 schema rejected {call.Operation}: {error.Message}"));
        }
    }
}

internal sealed class GroupwareAttachmentRecordingHandler : HttpMessageHandler
{
    private const int AggregateLimit = 10 * 1024 * 1024;
    private const int AttachmentLimit = 100;
    private const string SoapNamespace = "http://schemas.xmlsoap.org/soap/envelope/";
    private const string MessagesNamespace = "http://schemas.microsoft.com/exchange/services/2006/messages";
    private const string TypesNamespace = "http://schemas.microsoft.com/exchange/services/2006/types";
    private static readonly XNamespace S = SoapNamespace;
    private static readonly XNamespace M = MessagesNamespace;
    private static readonly XNamespace T = TypesNamespace;
    private readonly Dictionary<string, GroupwareItem> items = new(StringComparer.Ordinal)
    {
        ["calendar-1"] = new("calendar", "calendar-1", "calendar-1-change", false, false,
            [new("att-calendar-1", "note.png", 3, "image/png", true, "cid-existing", "bm90ZQ==")],
            [new("embedded-calendar", "embedded.msg", 7, null, false, null, null)]),
        ["meeting-attendee"] = new("calendar", "meeting-attendee", "meeting-attendee-change", true, false,
            [new("attendee-file", "agenda.txt", 1, "text/plain", false, null, "agenda")], []),
        ["contact-1"] = new("contact", "contact-1", "contact-1-change", false, false, [], []),
        ["limit-contact"] = new("contact", "limit-contact", "limit-contact-change", false, false, [], []),
        ["aggregate-task"] = new("task", "aggregate-task", "aggregate-task-change", false, false, [],
            [new("embedded-limit", "embedded.msg", AggregateLimit - 1, null, false, null, null)]),
        ["assigned-task"] = new("task", "assigned-task", "assigned-task-change", false, false,
            [new("assigned-file", "assigned.txt", 1, "text/plain", false, null, "x")], [], true),
        ["count-task"] = new("task", "count-task", "count-task-change", false, false, [],
            Enumerable.Range(0, AttachmentLimit)
                .Select(index => new GroupwareAttachment($"embedded-{index}", $"embedded-{index}.msg", 0, null, false, null, null))
                .ToList())
    };

    public List<CapturedEwsRequest> Calls { get; } = [];

    public void SetChangeKey(string id, string changeKey) => items[id].ChangeKey = changeKey;

    public void RemoveAttachment(string id, string attachmentId, bool preserveChangeKey)
    {
        items[id].Files.RemoveAll(file => file.Id == attachmentId);
        if (!preserveChangeKey) items[id].ChangeKey += "-updated";
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        var body = await request.Content!.ReadAsStringAsync(cancellationToken);
        var document = XDocument.Parse(body);
        var operation = document.Root!.Element(S + "Body")!.Elements().Single();
        var mailbox = document.Descendants(T + "PrimarySmtpAddress").SingleOrDefault()?.Value;
        Calls.Add(new CapturedEwsRequest(operation.Name.LocalName, body, request.Headers, mailbox));
        return operation.Name.LocalName switch
        {
            "GetItem" => GetItem(operation),
            "CreateAttachment" => CreateAttachment(operation),
            "GetAttachment" => GetAttachment(operation),
            "DeleteAttachment" => DeleteAttachment(operation),
            _ => Response(SoapResponse(operation.Name.LocalName, "ErrorInvalidPropertyRequest", "unsupported synthetic operation"))
        };
    }

    private HttpResponseMessage GetItem(XElement operation)
    {
        var id = operation.Descendants(T + "ItemId").Single().Attribute("Id")!.Value;
        return items.TryGetValue(id, out var item)
            ? Response(ItemResponse(item))
            : Response(SoapResponse("GetItem", "ErrorItemNotFound", "missing"));
    }

    private HttpResponseMessage CreateAttachment(XElement operation)
    {
        var parent = operation.Element(M + "ParentItemId")!;
        var id = parent.Attribute("Id")!.Value;
        var file = operation.Descendants(T + "FileAttachment").Single();
        var content = Convert.FromBase64String(file.Element(T + "Content")!.Value);
        var item = items[id];
        var attachmentId = $"att-created-{item.Files.Count + item.Embedded.Count}";
        item.Files.Add(new GroupwareAttachment(attachmentId, file.Element(T + "Name")!.Value,
            content.Length, file.Element(T + "ContentType")?.Value,
            bool.TryParse(file.Element(T + "IsInline")?.Value, out var inline) && inline,
            file.Element(T + "ContentId")?.Value, Convert.ToBase64String(content)));
        item.ChangeKey += "-new";
        var response = $"<m:CreateAttachmentResponse><m:ResponseMessages><m:CreateAttachmentResponseMessage ResponseClass='Success'><m:ResponseCode>NoError</m:ResponseCode></m:CreateAttachmentResponseMessage></m:ResponseMessages><m:Attachments><t:FileAttachment><t:AttachmentId Id='{attachmentId}' RootItemId='{item.Id}' RootItemChangeKey='{item.ChangeKey}'/><t:Name>{EscapeXml(file.Element(T + "Name")!.Value)}</t:Name><t:Size>{content.Length}</t:Size></t:FileAttachment></m:Attachments></m:CreateAttachmentResponse>";
        return Response(Envelope(response));
    }

    private HttpResponseMessage GetAttachment(XElement operation)
    {
        var id = operation.Descendants(T + "AttachmentId").Single().Attribute("Id")!.Value;
        var file = items.Values.SelectMany(item => item.Files).SingleOrDefault(file => file.Id == id)
            ?? throw new InvalidOperationException("Synthetic attachment was not found.");
        var bytes = file.ContentBase64 ?? Convert.ToBase64String(Encoding.UTF8.GetBytes(file.Name));
        var response = $"<m:GetAttachmentResponse><m:ResponseMessages><m:GetAttachmentResponseMessage ResponseClass='Success'><m:ResponseCode>NoError</m:ResponseCode></m:GetAttachmentResponseMessage></m:ResponseMessages><m:Attachments><t:FileAttachment><t:AttachmentId Id='{file.Id}'/><t:Name>{EscapeXml(file.Name)}</t:Name><t:ContentType>{EscapeXml(file.ContentType ?? "application/octet-stream")}</t:ContentType><t:Size>{file.Size}</t:Size><t:IsInline>{System.Xml.XmlConvert.ToString(file.IsInline)}</t:IsInline>{(file.ContentId is null ? "" : $"<t:ContentId>{EscapeXml(file.ContentId)}</t:ContentId>")}<t:Content>{bytes}</t:Content></t:FileAttachment></m:Attachments></m:GetAttachmentResponse>";
        return Response(Envelope(response));
    }

    private HttpResponseMessage DeleteAttachment(XElement operation)
    {
        var id = operation.Descendants(T + "AttachmentId").Single().Attribute("Id")!.Value;
        var item = items.Values.Single(item => item.Files.Any(file => file.Id == id));
        item.Files.RemoveAll(file => file.Id == id);
        item.ChangeKey += "-deleted";
        var response = $"<m:DeleteAttachmentResponse><m:ResponseMessages><m:DeleteAttachmentResponseMessage ResponseClass='Success'><m:ResponseCode>NoError</m:ResponseCode></m:DeleteAttachmentResponseMessage></m:ResponseMessages><m:RootItemId RootItemId='{item.Id}' RootItemChangeKey='{item.ChangeKey}'/></m:DeleteAttachmentResponse>";
        return Response(Envelope(response));
    }

    private static string ItemResponse(GroupwareItem item)
    {
        var type = item.Kind switch { "calendar" => "CalendarItem", "contact" => "Contact", "task" => "Task", _ => "Message" };
        var flags = item.Kind == "calendar"
            ? $"<t:IsMeeting>{System.Xml.XmlConvert.ToString(item.IsMeeting)}</t:IsMeeting><t:IsOrganizer>{System.Xml.XmlConvert.ToString(item.IsOrganizer)}</t:IsOrganizer>"
            : string.Empty;
        var attachments = string.Concat(item.Files.Concat(item.Embedded).Select(file =>
            file.ContentType is null
                ? $"<t:ItemAttachment><t:AttachmentId Id='{file.Id}'/><t:Name>{EscapeXml(file.Name)}</t:Name><t:Size>{file.Size}</t:Size></t:ItemAttachment>"
                : $"<t:FileAttachment><t:AttachmentId Id='{file.Id}'/><t:Name>{EscapeXml(file.Name)}</t:Name><t:Size>{file.Size}</t:Size><t:ContentType>{EscapeXml(file.ContentType)}</t:ContentType>{(file.IsInline ? "<t:IsInline>true</t:IsInline>" : "")}{(file.ContentId is null ? "" : $"<t:ContentId>{EscapeXml(file.ContentId)}</t:ContentId>")}</t:FileAttachment>"));
        var assignment = item.IsAssignedTask
            ? "<t:ExtendedProperty><t:ExtendedFieldURI PropertySetId='00062003-0000-0000-C000-000000000046' PropertyId='33043' PropertyType='Integer'/><t:Value>2</t:Value></t:ExtendedProperty><t:ExtendedProperty><t:ExtendedFieldURI PropertySetId='00062003-0000-0000-C000-000000000046' PropertyId='33065' PropertyType='Integer'/><t:Value>2</t:Value></t:ExtendedProperty>"
            : string.Empty;
        var result = $"<m:GetItemResponse><m:ResponseMessages><m:GetItemResponseMessage ResponseClass='Success'><m:ResponseCode>NoError</m:ResponseCode></m:GetItemResponseMessage></m:ResponseMessages><m:Items><t:{type}><t:ItemId Id='{item.Id}' ChangeKey='{item.ChangeKey}'/>{flags}<t:Attachments>{attachments}</t:Attachments>{assignment}</t:{type}></m:Items></m:GetItemResponse>";
        return Envelope(result);
    }

    private static string SoapResponse(string operation, string code, string message) =>
        Envelope($"<m:{operation}Response><m:ResponseMessages><m:{operation}ResponseMessage ResponseClass='Error'><m:ResponseCode>{code}</m:ResponseCode><m:MessageText>{EscapeXml(message)}</m:MessageText></m:{operation}ResponseMessage></m:ResponseMessages></m:{operation}Response>");

    private static string Envelope(string body) =>
        $"<s:Envelope xmlns:s='{SoapNamespace}' xmlns:m='{MessagesNamespace}' xmlns:t='{TypesNamespace}'><s:Body>{body}</s:Body></s:Envelope>";

    private static HttpResponseMessage Response(string body) => new(HttpStatusCode.OK)
    {
        Content = new StringContent(body, Encoding.UTF8, "text/xml")
    };

    private static string EscapeXml(string value) => System.Security.SecurityElement.Escape(value) ?? string.Empty;
}

internal sealed class GroupwareItem(
    string kind, string id, string changeKey, bool isMeeting, bool isOrganizer,
    List<GroupwareAttachment> files, List<GroupwareAttachment> embedded, bool isAssignedTask = false)
{
    public string Kind { get; } = kind;
    public string Id { get; } = id;
    public string ChangeKey { get; set; } = changeKey;
    public bool IsMeeting { get; } = isMeeting;
    public bool IsOrganizer { get; } = isOrganizer;
    public List<GroupwareAttachment> Files { get; } = files;
    public List<GroupwareAttachment> Embedded { get; } = embedded;
    public bool IsAssignedTask { get; } = isAssignedTask;
}

internal sealed record GroupwareAttachment(string Id, string Name, int Size, string? ContentType,
    bool IsInline, string? ContentId, string? ContentBase64);
