using System.Net;
using System.Text;
using System.Xml.Linq;
using System.Xml.Schema;
using Company.ExchangeMcp.Exchange;
using Company.ExchangeMcp.Security;

internal sealed partial class Checks
{
    private async Task RichMailChecksAsync()
    {
        const string emptyHtml = "<div dir='rtl'><p style='margin:0'><a href='https://example.test/'><span><img src='cid:logo@example.test'/></span></a><span style='font-family:Arial,sans-serif'/></p><p/><div/><a href='mailto:person@example.test'/><strong/><br/><hr/><table><colgroup><col/></colgroup><tr><td/></tr></table><SPAN xmlns='http://www.w3.org/1999/xhtml'/></div>";
        var normalizedEmpty = RichBody.Validate(emptyHtml, "HTML");
        // HTML consumers discard XML's self-closing marker; only void elements can survive that safely.
        var exchangeRoundTrip = RichBody.NormalizeExchangeHtml(normalizedEmpty.Replace(" />", ">", StringComparison.Ordinal));
        var emptyRoot = XElement.Parse("<root>" + normalizedEmpty + "</root>");
        Expect(emptyRoot.Descendants().Where(element => element.Name.LocalName is not ("img" or "br" or "hr" or "col"))
                .All(element => !element.IsEmpty)
            && emptyRoot.Descendants().Where(element => element.Name.LocalName is "img" or "br" or "hr" or "col")
                .All(element => element.IsEmpty)
            && normalizedEmpty.Contains("<span style=\"font-family:Arial,sans-serif\"></span>", StringComparison.Ordinal)
            && normalizedEmpty.Contains("<p></p>", StringComparison.Ordinal)
            && normalizedEmpty.Contains("<div></div>", StringComparison.Ordinal)
            && normalizedEmpty.Contains("<a href=\"mailto:person@example.test\"></a>", StringComparison.Ordinal)
            && emptyRoot.Descendants("p").First().Attribute("style")?.Value == "margin:0"
            && emptyRoot.Descendants("img").Single().Attribute("src")?.Value == "cid:logo@example.test"
            && exchangeRoundTrip == normalizedEmpty
            && RichBody.Validate(normalizedEmpty, "HTML") == normalizedEmpty,
            "Empty non-void HTML elements lost their closing tags, attributes, void handling or stable Exchange round-trip.");

        const string html = "<p style='color:#123'>Hello <strong>world</strong></p>"
            + "<table><tbody><tr><th>Key</th><td>Value</td></tr></tbody></table>"
            + "<p><img src='cid:logo@example.test' alt='Logo'/></p>";
        var normalized = RichBody.Validate(html, "HTML");
        Expect(normalized.Contains("<table>", StringComparison.Ordinal)
            && normalized.Contains("cid:logo@example.test", StringComparison.Ordinal),
            "Safe XHTML tables and CID images were not preserved.");
        Expect(RichBody.Preview(normalized, "HTML").Contains("Hello world", StringComparison.Ordinal),
            "HTML preview did not preserve readable text.");
        var layout = RichBody.Validate("<table style='width:480pt;height:.5pt;border-collapse:collapse;border-spacing:0 2px;table-layout:fixed'><tr><td>Layout</td></tr></table>", "HTML");
        Expect(layout.Contains("width:480pt", StringComparison.Ordinal)
            && layout.Contains("border-spacing:0 2px", StringComparison.Ordinal),
            "Captured signature table dimensions and spacing were lost.");
        const string persian = "<div dir='rtl' lang='fa' style='direction:rtl;text-align:right'>سلام "
            + "<span dir='ltr'>alice@example.test</span><table dir='rtl'><tr><td>ایمیل شرکت</td></tr></table></div>";
        var rtl = RichBody.Validate(persian, "HTML");
        Expect(rtl.Contains("dir=\"rtl\"", StringComparison.Ordinal)
            && rtl.Contains("dir=\"ltr\"", StringComparison.Ordinal)
            && rtl.Contains("lang=\"fa\"", StringComparison.Ordinal)
            && RichBody.Preview(rtl, "HTML").Contains("سلام alice@example.test", StringComparison.Ordinal),
            "Persian RTL, mixed LTR addresses or table direction was lost.");
        foreach (var invalid in new[]
        {
            "<p><span></p>",
            string.Concat(Enumerable.Repeat("<span/>", RichBody.MaxLength / 7)),
            "<div dir='rtl;url(https://tracker.example.test)'>bad</div>",
            "<div style='direction:rtl!important'>bad</div>",
            "<div style='direction:var(--external)'>bad</div>",
            "<div style='width:99999999px'>bad</div>",
            "<div style='height:var(--untrusted)'>bad</div>",
            "<table style='border-spacing:0 1px 2px'><tr><td>bad</td></tr></table>",
            "<table style='border-collapse:other'><tr><td>bad</td></tr></table>",
            "<table style='table-layout:other'><tr><td>bad</td></tr></table>"
        })
            await AssertThrowsAsync<ArgumentException>(() =>
            {
                _ = RichBody.Validate(invalid, "HTML");
                return Task.CompletedTask;
            });
        await AssertThrowsAsync<ArgumentException>(() =>
        {
            _ = RichBody.Validate("<script>alert(1)</script>", "HTML");
            return Task.CompletedTask;
        });
        await AssertThrowsAsync<ArgumentException>(() =>
        {
            _ = RichBody.Validate("<img src='https://tracker.example.test/pixel.gif'/>", "HTML");
            return Task.CompletedTask;
        });

        var handler = new RichRecordingEwsHandler();
        var client = NewEwsClient(handler);
        await client.CreateDraftAsync("alice@example.test",
            new EwsDraftInput("Empty formatting", emptyHtml, ["to@example.test"], [], [], "HTML"), CancellationToken.None);
        var emptyDraftBody = Operation(XDocument.Parse(handler.LastBody)).Descendants(XName.Get("Body", TypesNamespace)).Single().Value;
        Expect(emptyDraftBody == normalizedEmpty
            && RichBody.NormalizeExchangeHtml(emptyDraftBody.Replace(" />", ">", StringComparison.Ordinal)) == normalizedEmpty,
            "The EWS draft serialization boundary reintroduced self-closing non-void HTML elements.");
        await client.CreateDraftAsync("alice@example.test",
            new EwsDraftInput("Persian", persian, ["to@example.test"], [], [], "HTML"), CancellationToken.None);
        Expect(Operation(XDocument.Parse(handler.LastBody)).Descendants(XName.Get("Body", TypesNamespace))
            .Single().Value.Contains("dir=\"rtl\"", StringComparison.Ordinal),
            "Persian RTL did not reach the EWS draft body.");
        var read = await client.GetMessageAsync("alice@example.test", "message-1", CancellationToken.None);
        Expect(read.BodyType == "HTML" && read.Body?.Contains("<p>", StringComparison.Ordinal) == true
            && read.Attachments.Single().IsInline && read.Attachments.Single().ContentId == "logo@example.test",
            "Reading a rich message did not preserve its HTML body type or inline CID metadata.");

        var nativeHtml = ReplyPresentationHandler.OfficeBody("<html><head></head><body>قدیمی</body></html>");
        var nativeDraft = read with { Id = "draft-1", ChangeKey = "draft-change", IsDraft = true };
        var nativeResult = await client.UpdateNativeDraftBodyAsync("alice@example.test", nativeDraft, nativeHtml, CancellationToken.None);
        var nativeUpdate = Operation(XDocument.Parse(handler.LastBody));
        Expect(nativeResult.Id == "draft-1" && nativeResult.ChangeKey == "native-updated"
            && nativeUpdate.Attribute("ConflictResolution")?.Value == "NeverOverwrite"
            && nativeUpdate.Descendants(XName.Get("ItemId", TypesNamespace)).Single().Attribute("ChangeKey")?.Value == "draft-change"
            && nativeUpdate.Descendants(XName.Get("SetItemField", TypesNamespace)).Count() == 1
            && nativeUpdate.Descendants(XName.Get("FieldURI", TypesNamespace)).Single().Attribute("FieldURI")?.Value == "item:Body"
            && nativeUpdate.Descendants(XName.Get("Body", TypesNamespace)).Single().Value.Contains("mso-style-name", StringComparison.Ordinal),
            "Stored native HTML draft body update lost Word formatting, its expected revision, or the body-only NeverOverwrite boundary.");
        var beforeInvalidNative = handler.Operations.Count;
        foreach (var invalidDraft in new[] { nativeDraft with { IsDraft = false }, nativeDraft with { ChangeKey = "" }, nativeDraft with { Id = "" }, nativeDraft with { BodyType = "Text" } })
            await AssertThrowsAsync<ArgumentException>(() => client.UpdateNativeDraftBodyAsync("alice@example.test", invalidDraft, nativeHtml, CancellationToken.None));
        await AssertThrowsAsync<ArgumentException>(() => client.UpdateNativeDraftBodyAsync("alice@example.test", nativeDraft,
            "<html><head><style>p{background:url(https://tracker.example.test)}</style></head><body>bad</body></html>", CancellationToken.None));
        await AssertThrowsAsync<ArgumentException>(() => client.UpdateDraftAsync("alice@example.test", nativeDraft.Id, nativeDraft.ChangeKey,
            new EwsDraftInput("strict authored edit", nativeHtml, ["to@example.test"], [], [], "HTML"), CancellationToken.None));
        Expect(handler.Operations.Count == beforeInvalidNative,
            "Invalid native draft state, active content, or an authored Office HTML edit reached Exchange.");

        await client.CreateDraftAsync("alice@example.test",
            new EwsDraftInput("rich", html, ["to@example.test"], ["cc@example.test"], ["bcc@example.test"], "HTML"),
            CancellationToken.None);
        var create = Operation(XDocument.Parse(handler.LastBody));
        var createBody = create.Descendants(XName.Get("Body", TypesNamespace)).Single();
        Expect((string?)createBody.Attribute("BodyType") == "HTML"
            && createBody.Value.Contains("<table>", StringComparison.Ordinal)
            && !createBody.Elements().Any(),
            "HTML draft body was not emitted as escaped EWS HTML text.");
        var createRecipients = create.Descendants(XName.Get("BccRecipients", TypesNamespace)).Single();
        Expect(createRecipients.Descendants(XName.Get("EmailAddress", TypesNamespace)).Single().Value == "bcc@example.test",
            "Bcc recipient did not reach the EWS compose request.");

        await client.ReplyDraftAsync("alice@example.test", "message-1", "message-change", html, true,
            CancellationToken.None, "HTML", ["override@example.test"], ["reply-cc@example.test"], ["reply-bcc@example.test"]);
        var reply = Operation(XDocument.Parse(handler.LastBody));
        var replyItem = reply.Descendants(XName.Get("ReplyAllToItem", TypesNamespace)).Single();
        Expect(replyItem.Descendants(XName.Get("ToRecipients", TypesNamespace)).Single()
                .Descendants(XName.Get("EmailAddress", TypesNamespace)).Single().Value == "override@example.test"
            && replyItem.Descendants(XName.Get("NewBodyContent", TypesNamespace)).Single().Attribute("BodyType")?.Value == "HTML",
            "Reply overrides or HTML body type were not emitted.");

        var attachment = await client.CreateFileAttachmentAsync("alice@example.test", "draft-1", "draft-change",
            "logo.png", [137, 80, 78, 71, 13, 10, 26, 10], "image/png", CancellationToken.None, true, "logo@example.test");
        Expect(attachment.Attachment.IsInline && attachment.Attachment.ContentId == "logo@example.test",
            "Inline CID metadata was not returned from attachment creation.");
        var attachmentXml = Operation(XDocument.Parse(handler.LastBody));
        var file = attachmentXml.Descendants(XName.Get("FileAttachment", TypesNamespace)).Single();
        Expect(file.Element(XName.Get("ContentId", TypesNamespace))?.Value == "logo@example.test"
            && file.Element(XName.Get("IsInline", TypesNamespace))?.Value == "true",
            "Inline attachment metadata was not emitted in EWS order.");
        var beforeInvalidImage = handler.Operations.Count;
        await AssertThrowsAsync<ArgumentException>(() => client.CreateFileAttachmentAsync("alice@example.test", "draft-1", "draft-change",
            "fake.png", [1, 2, 3], "image/png", CancellationToken.None, true, "fake"));
        await AssertThrowsAsync<ArgumentException>(() => client.CreateFileAttachmentAsync("alice@example.test", "draft-1", "draft-change",
            "active.svg", Encoding.UTF8.GetBytes("<svg><script>alert(1)</script></svg>"), "image/svg+xml", CancellationToken.None, true, "active"));
        Expect(handler.Operations.Count == beforeInvalidImage, "Unsafe inline image content reached Exchange.");

        var textMessage = new EwsMessage("id", "key", "subject", "alice@example.test", [], [], [], [], null,
            true, true, "body", [], "Text")
        {
            Attachments = [new EwsAttachment("att", "logo.png", 3, false, "image/png")]
        };
        var htmlMessage = textMessage with { BodyType = "HTML" };
        var inlineMessage = htmlMessage with
        {
            Attachments = [new EwsAttachment("att", "logo.png", 3, true, "image/png", "logo@example.test")]
        };
        Expect(SendGuard.Digest(textMessage) != SendGuard.Digest(htmlMessage)
            && SendGuard.Digest(htmlMessage) != SendGuard.Digest(inlineMessage),
            "Send approval digest did not bind body type and inline attachment metadata.");

        ValidateRichSchema(handler);
    }

    private static void ValidateRichSchema(RichRecordingEwsHandler handler)
    {
        var schemas = LoadOptionalExchangeSchemas();
        Expect(handler.Operations.Count >= 4, "Rich-mail fixture did not capture every EWS operation.");
        foreach (var operation in handler.Operations)
            if (schemas is not null)
                new XDocument(operation).Validate(schemas, (_, error) => throw new InvalidOperationException(
                    $"Exchange 2019 rich-mail request failed schema validation: {error.Message}"));
    }
}

internal sealed class RichRecordingEwsHandler : HttpMessageHandler
{
    private static readonly XNamespace S = "http://schemas.xmlsoap.org/soap/envelope/";
    private static readonly XNamespace M = "http://schemas.microsoft.com/exchange/services/2006/messages";
    private static readonly XNamespace T = "http://schemas.microsoft.com/exchange/services/2006/types";

    public List<XElement> Operations { get; } = [];
    public string LastBody { get; private set; } = string.Empty;

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        LastBody = await request.Content!.ReadAsStringAsync(cancellationToken);
        var document = XDocument.Parse(LastBody);
        var operation = new XElement(document.Root!.Element(S + "Body")!.Elements().Single());
        Operations.Add(operation);
        var name = operation.Name.LocalName;
        var result = name switch
        {
            "GetItem" => "<m:Items><t:Message><t:ItemId Id='message-1' ChangeKey='message-change'/>"
                + "<t:Subject>Rich message</t:Subject><t:From><t:Mailbox><t:EmailAddress>sender@example.test</t:EmailAddress></t:Mailbox></t:From>"
                + "<t:ToRecipients/><t:CcRecipients/><t:BccRecipients/><t:IsRead>false</t:IsRead><t:IsDraft>false</t:IsDraft>"
                + "<t:Body BodyType='HTML'>&lt;p&gt;received&lt;/p&gt;</t:Body><t:Categories/>"
                + "<t:Attachments><t:FileAttachment><t:AttachmentId Id='logo-1'/><t:Name>logo.png</t:Name><t:Size>3</t:Size>"
                + "<t:ContentType>image/png</t:ContentType><t:ContentId>logo@example.test</t:ContentId><t:IsInline>true</t:IsInline></t:FileAttachment></t:Attachments>"
                + "</t:Message></m:Items>",
            "CreateAttachment" => "<m:Attachments><t:FileAttachment><t:AttachmentId Id='logo-2' RootItemId='draft-1' RootItemChangeKey='draft-change'/>"
                + "<t:Name>logo.png</t:Name><t:ContentType>image/png</t:ContentType><t:ContentId>logo@example.test</t:ContentId>"
                + "<t:IsInline>true</t:IsInline><t:Size>3</t:Size></t:FileAttachment></m:Attachments>",
            "CreateItem" => "<m:Items><t:Message><t:ItemId Id='draft-1' ChangeKey='draft-change'/></t:Message></m:Items>",
            "UpdateItem" => "<m:Items><t:Message><t:ItemId Id='draft-1' ChangeKey='native-updated'/></t:Message></m:Items>",
            _ => string.Empty
        };
        var response = $"<s:Envelope xmlns:s='{S.NamespaceName}' xmlns:m='{M.NamespaceName}' xmlns:t='{T.NamespaceName}'><s:Body>"
            + $"<m:{name}Response><m:ResponseMessages><m:{name}ResponseMessage ResponseClass='Success'><m:ResponseCode>NoError</m:ResponseCode></m:{name}ResponseMessage></m:ResponseMessages>{result}</m:{name}Response>"
            + "</s:Body></s:Envelope>";
        return new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(response, Encoding.UTF8, "text/xml")
        };
    }
}
