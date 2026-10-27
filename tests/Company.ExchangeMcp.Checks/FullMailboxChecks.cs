using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Xml;
using System.Xml.Linq;
using System.Xml.Schema;
using Company.ExchangeMcp.Exchange;
using Company.ExchangeMcp.Security;
using Microsoft.Extensions.Options;
using ModelContextProtocol;

internal sealed partial class Checks
{
    private async Task FullMailboxChecksAsync()
    {
        Expect(ResolveExchangeSchemaDirectory(null) is null && ResolveExchangeSchemaDirectory("") is null,
            "An unset optional schema directory did not select baseline checks.");
        ExpectThrows<InvalidOperationException>(() => ResolveExchangeSchemaDirectory(Path.Combine(runDirectory, "missing-schema")),
            "An explicitly missing schema directory silently selected baseline checks.");
        var incompleteSchemaDirectory = Path.Combine(runDirectory, "incomplete-schema");
        Directory.CreateDirectory(incompleteSchemaDirectory);
        File.WriteAllText(Path.Combine(incompleteSchemaDirectory, "xml.xsd"), "synthetic incomplete schema fixture");
        ExpectThrows<InvalidOperationException>(() => ResolveExchangeSchemaDirectory(incompleteSchemaDirectory),
            "An explicitly incomplete schema directory silently selected baseline checks.");

        var captureDirectory = Path.Combine(runDirectory, "full-mail-soap");
        Directory.CreateDirectory(captureDirectory);
        var exchange = new FullMailboxRecordingHandler(captureDirectory);
        var client = NewEwsClient(exchange);

        var after = new DateTimeOffset(2026, 10, 1, 0, 0, 0, TimeSpan.Zero);
        var before = new DateTimeOffset(2026, 10, 4, 0, 0, 0, TimeSpan.Zero);
        var firstPage = await client.FindMessagesAsync("alice@example.test", "inbox", null, 0, 2,
            CancellationToken.None, after, before, "sender@example.test", unread: true);
        Expect(firstPage.Items.Count == 2 && firstPage.NextOffset == 2,
            "The full-mail search fixture did not return a bounded first page.");
        var secondPage = await client.FindMessagesAsync("alice@example.test", "inbox", null, 2, 2,
            CancellationToken.None, after, before, "sender@example.test", unread: true);
        Expect(secondPage.Items.Count == 1 && secondPage.NextOffset is null,
            "The full-mail search fixture did not terminate paging safely.");
        var search = exchange.Last("FindItem");
        Expect(search.Body.Contains("IsGreaterThanOrEqualTo", StringComparison.Ordinal)
            && search.Body.Contains("IsLessThan", StringComparison.Ordinal)
            && search.Body.Contains("message:From", StringComparison.Ordinal)
            && search.Body.Contains("message:IsRead", StringComparison.Ordinal)
            && search.Body.Contains("2026-10-01T00:00:00.000Z", StringComparison.Ordinal)
            && search.Body.Contains("2026-10-04T00:00:00.000Z", StringComparison.Ordinal),
            "The date, sender, or unread search restriction was not emitted as requested.");
        var received = await client.GetMessageAsync("alice@example.test", "message-1", CancellationToken.None);
        Expect(received.AttachmentCount == 2 && received.TotalAttachmentBytes == 9 * 1024 * 1024 + 20
            && received.AttachmentNames.SequenceEqual(["duplicate.bin", "duplicate.bin"]),
            "Attachment metadata did not include item attachments or preserve duplicate names.");

        var draft = await client.CreateDraftAsync("alice@example.test",
            new EwsDraftInput("Bcc draft", "body", ["to@example.test"], ["cc@example.test"], ["bcc@example.test"]),
            CancellationToken.None);
        var create = exchange.Last("CreateItem");
        Expect(create.Body.Contains("BccRecipients", StringComparison.Ordinal)
            && create.Body.Contains("bcc@example.test", StringComparison.Ordinal)
            && create.Body.Contains("MessageDisposition=\"SaveOnly\"", StringComparison.Ordinal),
            "CreateDraft did not preserve Bcc recipients or SaveOnly semantics.");

        var edited = await client.UpdateDraftAsync("alice@example.test", draft.Id, draft.ChangeKey,
            new EwsDraftInput("Edited", "edited body", ["to@example.test"], [], ["bcc@example.test"]),
            CancellationToken.None);
        var update = exchange.Last("UpdateItem");
        Expect(edited.Id == "draft-1-updated"
            && update.Body.Contains($"Id=\"{draft.Id}\"", StringComparison.Ordinal)
            && update.Body.Contains($"ChangeKey=\"{draft.ChangeKey}\"", StringComparison.Ordinal)
            && update.Body.Contains("BccRecipients", StringComparison.Ordinal)
            && update.Body.Contains("ConflictResolution=\"NeverOverwrite\"", StringComparison.Ordinal),
            "Draft editing did not use the current ChangeKey or preserve Bcc recipients.");

        await client.ForwardDraftAsync("alice@example.test", "message-1", "message-change",
            "Forward note", ["to@example.test"], [], [], CancellationToken.None);
        var forward = exchange.Last("CreateItem");
        Expect(forward.Body.Contains("ForwardItem", StringComparison.Ordinal)
            && forward.Body.Contains("ReferenceItemId", StringComparison.Ordinal)
            && forward.Body.Contains("Id=\"message-1\"", StringComparison.Ordinal)
            && forward.Body.Contains("NewBodyContent", StringComparison.Ordinal)
            && forward.Body.Contains("MessageDisposition=\"SaveOnly\"", StringComparison.Ordinal),
            "Forwarding did not create a SaveOnly draft referencing the received message.");

        await client.ReplyDraftAsync("alice@example.test", "message-1", "message-change", "Reply", true,
            CancellationToken.None);
        Expect(exchange.Last("CreateItem").Body.Contains("ReplyAllToItem", StringComparison.Ordinal),
            "Reply-all did not use the received message reference.");

        await client.SetReadStateAsync("alice@example.test", "message-1", "message-change", true,
            CancellationToken.None);
        Expect(exchange.Last("UpdateItem").Body.Contains("message:IsRead", StringComparison.Ordinal),
            "Mark-read did not update message:IsRead.");
        await client.MoveMessageAsync("alice@example.test", "message-1", "message-change", "folder-archive",
            CancellationToken.None);
        Expect(exchange.Last("MoveItem").Body.Contains("ChangeKey=\"message-change\"", StringComparison.Ordinal),
            "Move did not use the current message ChangeKey.");
        await client.SoftDeleteAsync("alice@example.test", "message-1", "message-change", CancellationToken.None);
        Expect(exchange.Last("DeleteItem").Body.Contains("DeleteType=\"MoveToDeletedItems\"", StringComparison.Ordinal),
            "Message delete was not the recoverable MoveToDeletedItems form.");

        var folder = await client.CreateFolderAsync("alice@example.test", "msgfolderroot", "Project", CancellationToken.None);
        Expect(folder.Id == "folder-new", "CreateFolder did not parse its returned folder.");
        var fetchedFolder = await client.GetFolderAsync("alice@example.test", folder.Id, CancellationToken.None);
        Expect(fetchedFolder.Id == "folder-new" && fetchedFolder.ChangeKey == "folder-change-2",
            "GetFolder did not return the current folder identifier and ChangeKey.");
        await client.RenameFolderAsync("alice@example.test", folder.Id, folder.ChangeKey, "Renamed", CancellationToken.None);
        Expect(exchange.Last("UpdateFolder").Body.Contains("folder:DisplayName", StringComparison.Ordinal),
            "RenameFolder did not update folder:DisplayName.");
        await client.SoftDeleteFolderAsync("alice@example.test", folder.Id, folder.ChangeKey, CancellationToken.None);
        Expect(exchange.Last("DeleteFolder").Body.Contains("DeleteType=\"MoveToDeletedItems\"", StringComparison.Ordinal),
            "DeleteFolder was not a recoverable MoveToDeletedItems delete.");
        await client.UpdateCategoriesAsync("alice@example.test", "message-1", "message-change", ["work", "urgent"],
            CancellationToken.None);
        Expect(exchange.Last("UpdateItem").Body.Contains("item:Categories", StringComparison.Ordinal)
            && exchange.Last("UpdateItem").Body.Contains("urgent", StringComparison.Ordinal),
            "Category updates did not replace the message category field.");

        var attachment = await client.CreateFileAttachmentAsync("alice@example.test", draft.Id, draft.ChangeKey,
            "report.txt", Encoding.UTF8.GetBytes("synthetic attachment"), "text/plain", CancellationToken.None);
        var createAttachment = exchange.Last("CreateAttachment");
        Expect(createAttachment.Body.Contains("ParentItemId", StringComparison.Ordinal)
            && createAttachment.Body.Contains($"Id=\"{draft.Id}\"", StringComparison.Ordinal)
            && createAttachment.Body.Contains($"ChangeKey=\"{draft.ChangeKey}\"", StringComparison.Ordinal),
            "CreateAttachment did not use the Microsoft ParentItemId attribute form.");
        var attachmentContent = await client.GetAttachmentAsync("alice@example.test", attachment.Attachment.Id,
            CancellationToken.None);
        Expect(Encoding.UTF8.GetString(attachmentContent.Content) == "synthetic attachment",
            "GetAttachment did not return the bounded file content.");
        var deletedAttachment = await client.DeleteAttachmentAsync("alice@example.test", attachment.Attachment.Id,
            CancellationToken.None);
        Expect(deletedAttachment.Id == "draft-1" && deletedAttachment.ChangeKey == "draft-change-2",
            "DeleteAttachment did not parse the Microsoft m:RootItemId response.");

        var boundaryAttachment = await client.CreateFileAttachmentAsync("alice@example.test", draft.Id, draft.ChangeKey,
            "five-megabytes.bin", new byte[5 * 1024 * 1024], "application/octet-stream", CancellationToken.None);
        Expect(boundaryAttachment.Attachment.Size == 5 * 1024 * 1024
            && exchange.Last("CreateAttachment").Body.Contains("Content", StringComparison.Ordinal),
            "A file attachment at the 5 MiB boundary was not accepted.");

        var beforeInvalid = exchange.Calls.Count;
        await AssertThrowsAsync<ArgumentException>(() => client.CreateDraftAsync("alice@example.test",
            new EwsDraftInput("bad", "body", ["bad address"], [], []), CancellationToken.None));
        await AssertThrowsAsync<ArgumentException>(() => client.FindMessagesAsync("alice@example.test", "inbox", null,
            0, 1, CancellationToken.None, before, after));
        await AssertThrowsAsync<ArgumentException>(() => client.CreateFileAttachmentAsync("alice@example.test", draft.Id,
            draft.ChangeKey, "too-big.bin", new byte[5 * 1024 * 1024 + 1], null, CancellationToken.None));
        Expect(exchange.Calls.Count == beforeInvalid,
            "Invalid full-mail input reached the synthetic Exchange transport.");

        var uncertain = new FullMailboxRecordingHandler(Path.Combine(runDirectory, "uncertain"))
        {
            ThrowOnSend = true
        };
        var uncertainClient = NewEwsClient(uncertain);
        await AssertThrowsAsync<InvalidOperationException>(() => uncertainClient.SendDraftAsync("alice@example.test",
            "draft-1", "draft-change", CancellationToken.None));
        Expect(uncertain.Calls.Count == 1,
            "An uncertain SendItem write was automatically retried.");

        ValidateCapturedOperations(exchange, captureDirectory);
        await FullMailboxPolicyChecksAsync();
        await FullMailboxToolSurfaceChecksAsync();
    }

    private async Task FullMailboxPolicyChecksAsync()
    {
        var secret = Path.Combine(runDirectory, "policy-secret");
        await File.WriteAllTextAsync(secret, "synthetic");
        var options = new ServiceOptions
        {
            Authority = Authority,
            Resource = Resource,
            IntrospectionClientId = "synthetic-client",
            IntrospectionSecretFile = secret,
            AllowedClientIds = ["chatgpt-test"],
            AllowedOrigins = ["https://allowed.example.test"],
            Mailboxes = new Dictionary<string, string> { ["user-a"] = "alice@example.test" },
            WritesEnabled = false,
            SendEnabled = true,
            AllowedRecipientDomains = ["example.test"],
            AuditPath = Path.Combine(runDirectory, "policy-audit.jsonl")
        };
        Expect(!options.IsValid(), "SendEnabled was accepted while WritesEnabled was disabled.");
        options.WritesEnabled = true;
        options.AllowedRecipientDomains = [];
        Expect(!options.IsValid() && !options.AllowExternalRecipients,
            "Sending without a recipient policy was accepted.");
        options.AllowExternalRecipients = true;
        Expect(options.IsValid(), "Explicit external-recipient policy was rejected.");

        var access = new MailboxAccess(Options.Create(options));
        access.ValidateRecipients(["external@example.net"]);
        options.AllowExternalRecipients = false;
        options.AllowedRecipientDomains = ["example.test"];
        var restricted = new MailboxAccess(Options.Create(options));
        await AssertThrowsAsync<McpException>(() =>
        {
            restricted.ValidateRecipients(["external@example.net"]);
            return Task.CompletedTask;
        });
        restricted.ValidateRecipients(Enumerable.Range(0, 100).Select(i => $"u{i}@example.test").ToArray());
        await AssertThrowsAsync<McpException>(() =>
        {
            restricted.ValidateRecipients(Enumerable.Range(0, 101).Select(i => $"u{i}@example.test").ToArray());
            return Task.CompletedTask;
        });
    }

    private async Task FullMailboxToolSurfaceChecksAsync()
    {
        var exchange = new RecordingEwsHandler();
        await using var host = await StartHostAsync(exchange, writesEnabled: true, sendEnabled: true);
        var token = Token("user-a", "mail.read mail.write mail.manage mail.send");
        await InitializeAsync(host.Client, token);
        var response = await ToolRequestAsync(host.Client, token, "tools/list", new { });
        Expect(response.StatusCode == HttpStatusCode.OK, "Full-mail tools/list failed.");
        using var json = ParseJson(response.Body);
        var names = json.RootElement.GetProperty("result").GetProperty("tools").EnumerateArray()
            .Select(tool => tool.GetProperty("name").GetString()).Where(x => x is not null).ToArray();
        var expected = new[]
        {
            "mail_profile", "mail_list_folders", "mail_search", "mail_read", "mail_create_draft",
            "mail_edit_draft", "mail_forward_draft", "mail_reply_draft", "mail_mark_read", "mail_move",
            "mail_create_folder", "mail_rename_folder", "mail_delete_folder", "mail_set_categories",
            "mail_list_attachments", "mail_read_attachment", "mail_create_attachment", "mail_delete_attachment",
            "mail_delete", "mail_send_draft"
        };
        var ordinaryMailNames = names.Where(name => name is not null && expected.Contains(name, StringComparer.Ordinal)).ToArray();
        Expect(ordinaryMailNames.Length == expected.Length
            && ordinaryMailNames.ToHashSet(StringComparer.Ordinal).SetEquals(expected),
            $"Full-mail tool surface was incomplete: expected {expected.Length}, got {names.Length}.");

        var before = exchange.Calls.Count;
        var validRecipients = Enumerable.Range(0, 50).Select(index => $"to{index}@example.test").ToArray();
        var validCombined = await ToolRequestAsync(host.Client, token, "tools/call", new
        {
            name = "mail_create_draft",
            arguments = new { subject = "combined", body = "body", to = validRecipients, cc = validRecipients }
        });
        Expect(!IsToolError(validCombined.Body), "A 100-recipient draft was rejected.");
        var beforeTooManyRecipients = exchange.Calls.Count;
        var tooManyRecipients = await ToolRequestAsync(host.Client, token, "tools/call", new
        {
            name = "mail_create_draft",
            arguments = new
            {
                subject = "combined too many",
                body = "body",
                to = Enumerable.Range(0, 51).Select(index => $"to{index}@example.test").ToArray(),
                cc = validRecipients
            }
        });
        Expect(IsToolError(tooManyRecipients.Body) && exchange.Calls.Count == beforeTooManyRecipients,
            "A draft with more than 100 combined recipients reached EWS.");

        var aggregateExchange = new RecordingEwsHandler
        {
            DraftMode = true,
            DraftAttachmentCount = 1,
            DraftAttachmentBytes = 9 * 1024 * 1024
        };
        await using (var aggregateHost = await StartHostAsync(aggregateExchange, writesEnabled: true, sendEnabled: true))
        {
            await InitializeAsync(aggregateHost.Client, token);
            var aggregateDraft = await ToolRequestAsync(aggregateHost.Client, token, "tools/call", new
            {
                name = "mail_create_draft",
                arguments = new { subject = "attachment aggregate", body = "body", to = new[] { "to@example.test" } }
            });
            var aggregateHandle = ToolStructuredData(aggregateDraft.Body).GetProperty("handle").GetString()!;
            var attachmentPayload = Convert.ToBase64String(new byte[2 * 1024 * 1024]);
            var aggregateResult = await ToolRequestAsync(aggregateHost.Client, token, "tools/call", new
            {
                name = "mail_create_attachment",
                arguments = new { draftHandle = aggregateHandle, name = "duplicate-name.bin", contentBase64 = attachmentPayload }
            });
            Expect(IsToolError(aggregateResult.Body)
                    && !aggregateExchange.Calls.Any(call => call.Operation == "CreateAttachment"),
                    "A 9 MiB existing attachment plus a 2 MiB upload exceeded the 10 MiB aggregate gate but reached EWS.");
        }

        before = exchange.Calls.Count;
        var missingWrite = await ToolRequestAsync(host.Client, Token("user-a", "mail.read"), "tools/call", new
        {
            name = "mail_edit_draft",
            arguments = new { draftHandle = "synthetic", subject = "x", body = "y", to = new[] { "to@example.test" } }
        });
        Expect(IsToolError(missingWrite.Body) && exchange.Calls.Count == before,
            "A token without mail.write reached a full-mail write tool.");
        var missingManage = await ToolRequestAsync(host.Client, Token("user-a", "mail.read mail.write"), "tools/call", new
        {
            name = "mail_mark_read",
            arguments = new { messageHandle = "synthetic", isRead = true }
        });
        Expect(IsToolError(missingManage.Body) && exchange.Calls.Count == before,
            "A token without mail.manage reached a mailbox-management tool.");
        var missingSend = await ToolRequestAsync(host.Client, Token("user-a", "mail.read mail.write mail.manage"), "tools/call", new
        {
            name = "mail_send_draft",
            arguments = new { draftHandle = "synthetic" }
        });
        Expect(IsToolError(missingSend.Body) && exchange.Calls.Count == before,
            "A token without mail.send reached the send tool.");

        var search = await ToolRequestAsync(host.Client, token, "tools/call", new
        {
            name = "mail_search",
            arguments = new { folder = "inbox", offset = 0, limit = 1 }
        });
        var messageHandle = ToolStructuredData(search.Body).GetProperty("items")[0].GetProperty("handle").GetString()!;
        var listed = await ToolRequestAsync(host.Client, token, "tools/call", new
        {
            name = "mail_list_attachments",
            arguments = new { messageHandle }
        });
        Expect(!IsToolError(listed.Body), "Attachment listing failed for a permitted mailbox read.");
        var attachmentHandle = ToolStructuredData(listed.Body).GetProperty("items")[0].GetProperty("handle").GetString()!;
        var beforeCrossUser = exchange.Calls.Count;
        var crossUser = await ToolRequestAsync(host.Client, Token("user-b", "mail.read"), "tools/call", new
        {
            name = "mail_read_attachment",
            arguments = new { attachmentHandle }
        });
        Expect(IsToolError(crossUser.Body) && exchange.Calls.Count == beforeCrossUser,
            "An attachment handle crossed mailbox identities or reached EWS.");

        exchange.MessageChangeKey = "message-current";
        var beforeStaleRead = exchange.Calls.Count;
        var staleRead = await ToolRequestAsync(host.Client, token, "tools/call", new
        {
            name = "mail_mark_read",
            arguments = new { messageHandle, isRead = true }
        });
        Expect(IsToolError(staleRead.Body)
            && !exchange.Calls.Skip(beforeStaleRead).Any(call => call.Operation == "UpdateItem"),
            "A stale message handle reached an EWS write.");

        var folders = await ToolRequestAsync(host.Client, token, "tools/call", new
        {
            name = "mail_list_folders",
            arguments = new { }
        });
        var folderHandle = ToolStructuredData(folders.Body)[0].GetProperty("handle").GetString()!;
        exchange.FolderChangeKey = "folder-current";
        var beforeStaleFolder = exchange.Calls.Count;
        var staleRename = await ToolRequestAsync(host.Client, token, "tools/call", new
        {
            name = "mail_rename_folder",
            arguments = new { folderHandle, name = "Renamed" }
        });
        var staleDelete = await ToolRequestAsync(host.Client, token, "tools/call", new
        {
            name = "mail_delete_folder",
            arguments = new { folderHandle }
        });
        Expect(IsToolError(staleRename.Body) && IsToolError(staleDelete.Body)
            && !exchange.Calls.Skip(beforeStaleFolder).Any(call => call.Operation is "UpdateFolder" or "DeleteFolder"),
            "A stale folder handle reached an EWS write.");
    }

    private static string? ResolveExchangeSchemaDirectory(string? configuredDirectory)
    {
        if (string.IsNullOrEmpty(configuredDirectory)) return null;
        var directory = Path.GetFullPath(configuredDirectory);
        Expect(File.Exists(Path.Combine(directory, "xml.xsd"))
            && File.Exists(Path.Combine(directory, "types.xsd"))
            && File.Exists(Path.Combine(directory, "messages.xsd")),
            "EXCHANGE_EWS_SCHEMA_DIR must contain xml.xsd, types.xsd, and messages.xsd.");
        return directory;
    }

    private static XmlSchemaSet? LoadOptionalExchangeSchemas()
    {
        var directory = ResolveExchangeSchemaDirectory(Environment.GetEnvironmentVariable("EXCHANGE_EWS_SCHEMA_DIR"));
        if (directory is null)
        {
            Console.WriteLine("SKIP Exchange 2019 XSD validation: EXCHANGE_EWS_SCHEMA_DIR is not configured; behavioral checks still run.");
            return null;
        }
        var schemas = new XmlSchemaSet { XmlResolver = null };
        schemas.Add("http://www.w3.org/XML/1998/namespace", Path.Combine(directory, "xml.xsd"));
        schemas.Add("http://schemas.microsoft.com/exchange/services/2006/types", Path.Combine(directory, "types.xsd"));
        schemas.Add("http://schemas.microsoft.com/exchange/services/2006/messages", Path.Combine(directory, "messages.xsd"));
        schemas.Compile();
        return schemas;
    }

    private static void ValidateCapturedOperations(FullMailboxRecordingHandler exchange, string captureDirectory)
    {
        var schemas = LoadOptionalExchangeSchemas();
        Expect(exchange.Calls.Count >= 15, "The full-mail fixture did not capture every generated SOAP operation.");
        foreach (var call in exchange.Calls)
        {
            var document = XDocument.Parse(call.Body, LoadOptions.PreserveWhitespace);
            var body = document.Root?.Element(XName.Get("Body", "http://schemas.xmlsoap.org/soap/envelope/"));
            Expect(body is not null && body.Elements().Count() == 1,
                $"SOAP operation {call.Operation} did not have exactly one Body child.");
            var operation = body!.Elements().Single();
            Expect(operation.Name != XName.Get("Envelope", "http://schemas.xmlsoap.org/soap/envelope/"),
                $"SOAP operation {call.Operation} captured the Envelope as its operation child.");
            if (schemas is not null)
                new XDocument(new XElement(operation)).Validate(schemas, (_, error) => throw new InvalidOperationException(
                    $"Exchange 2019 schema rejected {call.Operation}: {error.Message}"));
            File.WriteAllText(Path.Combine(captureDirectory, $"{call.Sequence:000}-{call.Operation}.xml"), call.Body,
                new UTF8Encoding(false));
        }
    }

    private static async Task AssertThrowsAsync<TException>(Func<Task> action) where TException : Exception
    {
        try
        {
            await action();
        }
        catch (TException)
        {
            return;
        }
        throw new InvalidOperationException($"Expected {typeof(TException).Name}.");
    }
}

internal sealed class FullMailboxRecordingHandler(string captureDirectory) : HttpMessageHandler
{
    private const string SoapNamespace = "http://schemas.xmlsoap.org/soap/envelope/";
    private const string MessagesNamespace = "http://schemas.microsoft.com/exchange/services/2006/messages";
    private const string TypesNamespace = "http://schemas.microsoft.com/exchange/services/2006/types";
    private static readonly XNamespace S = SoapNamespace;
    private static readonly XNamespace M = MessagesNamespace;
    private static readonly XNamespace T = TypesNamespace;
    private int sequence;

    public List<CapturedFullMailboxRequest> Calls { get; } = [];
    public bool ThrowOnSend { get; init; }

    public CapturedFullMailboxRequest Last(string operation) => Calls.Last(call => call.Operation == operation);

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var body = await request.Content!.ReadAsStringAsync(cancellationToken);
        var document = XDocument.Parse(body);
        var operation = document.Root!.Element(S + "Body")!.Elements().Single();
        var captured = new CapturedFullMailboxRequest(++sequence, operation.Name.LocalName, body, request.Headers);
        Calls.Add(captured);
        Directory.CreateDirectory(captureDirectory);
        await File.WriteAllTextAsync(Path.Combine(captureDirectory, $"{captured.Sequence:000}-{captured.Operation}.xml"), body,
            new UTF8Encoding(false), cancellationToken);
        if (ThrowOnSend && operation.Name.LocalName == "SendItem")
            throw new HttpRequestException("synthetic uncertain transport outcome");
        return Response(operation.Name.LocalName, captured.Sequence);
    }

    private static HttpResponseMessage Response(string operation, int sequence)
    {
        var result = operation switch
        {
            "FindItem" => sequence == 1
                ? "<m:RootFolder IncludesLastItemInRange='false' IndexedPagingOffset='2'><t:Items>"
                    + "<t:Message><t:ItemId Id='message-1' ChangeKey='message-change'/><t:Subject>First</t:Subject><t:IsRead>false</t:IsRead><t:DateTimeReceived>2026-10-03T00:00:00Z</t:DateTimeReceived></t:Message>"
                    + "<t:Message><t:ItemId Id='message-2' ChangeKey='message-change-2'/><t:Subject>Second</t:Subject><t:IsRead>false</t:IsRead><t:DateTimeReceived>2026-10-02T00:00:00Z</t:DateTimeReceived></t:Message>"
                    + "</t:Items></m:RootFolder>"
                : "<m:RootFolder IncludesLastItemInRange='true'><t:Items><t:Message><t:ItemId Id='message-3' ChangeKey='message-change-3'/><t:Subject>Third</t:Subject><t:IsRead>false</t:IsRead><t:DateTimeReceived>2026-10-01T00:00:00Z</t:DateTimeReceived></t:Message></t:Items></m:RootFolder>",
            "GetItem" => "<m:Items><t:Message><t:ItemId Id='message-1' ChangeKey='message-change'/><t:Subject>Received</t:Subject>"
                + "<t:From><t:Mailbox><t:EmailAddress>sender@example.test</t:EmailAddress></t:Mailbox></t:From><t:ToRecipients/><t:CcRecipients/><t:BccRecipients/>"
                + "<t:IsRead>false</t:IsRead><t:IsDraft>false</t:IsDraft><t:Body BodyType='Text'>synthetic body</t:Body>"
                + "<t:Attachments><t:FileAttachment><t:AttachmentId Id='att-1'/><t:Name>duplicate.bin</t:Name><t:Size>20</t:Size><t:ContentType>text/plain</t:ContentType></t:FileAttachment>"
                + "<t:ItemAttachment><t:AttachmentId Id='att-item'/><t:Name>duplicate.bin</t:Name><t:Size>9437184</t:Size></t:ItemAttachment></t:Attachments>"
                + "</t:Message></m:Items>",
            "CreateItem" => sequence == 3
                ? "<m:Items><t:Message><t:ItemId Id='draft-1' ChangeKey='draft-change'/></t:Message></m:Items>"
                : "<m:Items><t:Message><t:ItemId Id='draft-1-updated' ChangeKey='draft-change-2'/></t:Message></m:Items>",
            "UpdateItem" or "MoveItem" => "<m:Items><t:Message><t:ItemId Id='draft-1-updated' ChangeKey='draft-change-2'/></t:Message></m:Items>",
            "CreateFolder" or "UpdateFolder" => "<m:Folders><t:Folder><t:FolderId Id='folder-new' ChangeKey='folder-change-2'/><t:DisplayName>Renamed</t:DisplayName><t:TotalCount>0</t:TotalCount><t:UnreadCount>0</t:UnreadCount></t:Folder></m:Folders>",
            "GetFolder" => "<m:Folders><t:Folder><t:FolderId Id='folder-new' ChangeKey='folder-change-2'/><t:DisplayName>Project</t:DisplayName><t:TotalCount>0</t:TotalCount><t:UnreadCount>0</t:UnreadCount></t:Folder></m:Folders>",
            "CreateAttachment" => "<m:Attachments><t:FileAttachment><t:AttachmentId Id='att-new' RootItemId='draft-1' RootItemChangeKey='draft-change-2'/><t:Name>report.txt</t:Name><t:Size>20</t:Size><t:ContentType>text/plain</t:ContentType></t:FileAttachment></m:Attachments>",
            "GetAttachment" => "<m:Attachments><t:FileAttachment><t:AttachmentId Id='att-1'/><t:Name>report.txt</t:Name><t:ContentType>text/plain</t:ContentType><t:Content>c3ludGhldGljIGF0dGFjaG1lbnQ=</t:Content></t:FileAttachment></m:Attachments>",
            "DeleteAttachment" => "<m:RootItemId RootItemId='draft-1' RootItemChangeKey='draft-change-2'/>",
            _ => string.Empty
        };
        var response = $"<s:Envelope xmlns:s='{SoapNamespace}' xmlns:m='{MessagesNamespace}' xmlns:t='{TypesNamespace}'><s:Body>"
            + $"<m:{operation}Response><m:ResponseMessages><m:{operation}ResponseMessage ResponseClass='Success'><m:ResponseCode>NoError</m:ResponseCode></m:{operation}ResponseMessage></m:ResponseMessages>{result}</m:{operation}Response>"
            + "</s:Body></s:Envelope>";
        return new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(response, Encoding.UTF8, "text/xml")
        };
    }
}

internal sealed record CapturedFullMailboxRequest(int Sequence, string Operation, string Body, HttpRequestHeaders Headers);
