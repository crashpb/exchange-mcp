using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Xml.Linq;
using Company.ExchangeMcp;
using Company.ExchangeMcp.Exchange;
using Company.ExchangeMcp.Security;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Options;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;

internal sealed partial class Checks
{
    private async Task MailPreviewChecksAsync()
    {
        var image = new byte[] { 137, 80, 78, 71, 13, 10, 26, 10 };
        var handler = new MailPreviewEwsHandler(image) { ReportedSize = image.Length + 208 };
        var options = Options.Create(new ServiceOptions
        {
            AllowedClientIds = ["checks"],
            Mailboxes = new() { ["user-a"] = "alice@example.test" },
            WritesEnabled = true,
            SendEnabled = true,
            AuditPath = Path.Combine(runDirectory, "mail-preview-audit.jsonl")
        });
        var access = new MailboxAccess(options);
        var handles = new MailboxHandles(new EphemeralDataProtectionProvider());
        var tool = new MailPreviewTools(NewEwsClient(handler), access, handles, new MailReviewStore());
        var identity = new MailboxIdentity("user-a", "alice@example.test", "checks", "session-1");
        var user = SignatureTestUser("user-a", "alice@example.test", "checks", "session-1", "mail.read mail.write mail.send");
        var draftHandle = handles.Issue(identity, "message", "draft-1", "draft-current");

        var result = await tool.Preview(user, draftHandle, CancellationToken.None);
        var structured = result.StructuredContent ?? throw new InvalidOperationException("Draft preview omitted structured content.");
        Expect(structured.GetProperty("status").GetString() == "draft_preview_ready"
            && structured.GetProperty("draftHandle").GetString() is { Length: > 20 }
            && structured.GetProperty("from").GetString() == "alice@example.test"
            && structured.GetProperty("to")[0].GetString() == "to@example.test"
            && structured.GetProperty("cc")[0].GetString() == "cc@example.test"
            && structured.GetProperty("bcc")[0].GetString() == "hidden@example.test"
            && structured.GetProperty("subject").GetString() == "Draft <review>"
            && structured.GetProperty("editable").GetBoolean()
            && structured.GetProperty("sendable").GetBoolean()
            && structured.GetProperty("bodyText").GetString()?.Contains("سلام", StringComparison.Ordinal) == true
            && structured.GetProperty("bodyText").GetString()?.Contains("[inline image cid:logo]", StringComparison.Ordinal) == true
            && structured.GetProperty("attachments")[0].GetProperty("name").GetString() == "logo.png"
            && structured.GetProperty("attachments")[0].GetProperty("contentType").GetString() == "image/png"
            && structured.GetProperty("attachments")[0].GetProperty("isInline").GetBoolean(),
            "The preview did not return the authoritative headers, hidden recipients, body text and attachment summary.");
        var metadata = result.Meta?["emailPreview"]?.AsObject()
            ?? throw new InvalidOperationException("Private email preview metadata was missing.");
        var previewHtml = metadata["html"]?.GetValue<string>() ?? string.Empty;
        Expect(previewHtml.Contains($"data:image/png;base64,{Convert.ToBase64String(image)}", StringComparison.Ordinal)
            && previewHtml.Contains("<i>italic</i><ins>inserted</ins>", StringComparison.Ordinal)
            && previewHtml.Contains("class=\"MsoNormal\"", StringComparison.Ordinal)
            && previewHtml.Contains("margin-top:3px;margin-bottom:5px", StringComparison.Ordinal)
            && metadata["body"]?.GetValue<string>().Contains("cid:logo", StringComparison.Ordinal) == true
            && metadata["mailboxHandle"] is null
            && metadata["editable"]?.GetValue<bool>() == true
            && metadata["sendable"]?.GetValue<bool>() == true
            && metadata["attachments"]?[0]?["name"]?.GetValue<string>() == "logo.png"
            && metadata["attachments"]?[0]?["isInline"]?.GetValue<bool>() == true,
            "The preview did not privately render the verified inline image or preserve the edit body.");
        var modelFacing = JsonSerializer.Serialize(result.StructuredContent) + JsonSerializer.Serialize(result.Content);
        Expect(!modelFacing.Contains(Convert.ToBase64String(image), StringComparison.Ordinal)
            && !modelFacing.Contains("data:image/png;base64,", StringComparison.OrdinalIgnoreCase),
            "Inline image bytes escaped private preview metadata into model-visible content.");
        Expect(handler.Operations.SequenceEqual(["GetItem", "GetAttachment", "GetItem"]),
            "Draft preview performed a write, omitted its final freshness read, or fetched extra data.");

        var oversizedImage = new byte[512 * 1024 + 1];
        image.CopyTo(oversizedImage, 0);
        var oversizedHandler = new MailPreviewEwsHandler(oversizedImage)
        {
            ReportedSize = oversizedImage.Length + 208,
            HtmlBody = "<p><img src=\"cid:logo\"/><img src=\"cid:logo\"/></p>"
        };
        var oversizedResult = await new MailPreviewTools(NewEwsClient(oversizedHandler), access, handles, new MailReviewStore())
            .Preview(user, draftHandle, CancellationToken.None);
        var oversizedMetadata = oversizedResult.Meta?["emailPreview"]?.AsObject()
            ?? throw new InvalidOperationException("The oversized-image preview omitted private metadata.");
        var oversizedStructured = oversizedResult.StructuredContent
            ?? throw new InvalidOperationException("The oversized-image preview omitted structured content.");
        var oversizedHtml = oversizedMetadata["html"]?.GetValue<string>() ?? string.Empty;
        Expect(oversizedStructured.GetProperty("editable").GetBoolean()
            && oversizedStructured.GetProperty("warnings").GetArrayLength() == 1
            && oversizedHtml.Contains("inline image omitted from preview", StringComparison.Ordinal)
            && !oversizedHtml.Contains("data:image/png;base64,", StringComparison.OrdinalIgnoreCase)
            && oversizedHandler.Operations.SequenceEqual(["GetItem", "GetAttachment", "GetItem"]),
            "A repeated oversized CID was embedded, fetched more than once, or omitted without a warning/final freshness read.");

        var manyImageBody = string.Concat(Enumerable.Range(1, 10).Select(index =>
            $"<img src=\"cid:{(index == 1 ? "logo" : $"logo-{index}")}\"/>"));
        var manyOversizedHandler = new MailPreviewEwsHandler(oversizedImage)
        {
            ImageCount = 10,
            ReportedSize = oversizedImage.Length + 208,
            HtmlBody = manyImageBody
        };
        var manyOversizedResult = await new MailPreviewTools(NewEwsClient(manyOversizedHandler), access, handles, new MailReviewStore())
            .Preview(user, draftHandle, CancellationToken.None);
        var manyOversizedMetadata = manyOversizedResult.Meta?["emailPreview"]?.AsObject()
            ?? throw new InvalidOperationException("The many-image preview omitted private metadata.");
        var manyOversizedStructured = manyOversizedResult.StructuredContent
            ?? throw new InvalidOperationException("The many-image preview omitted structured content.");
        var manyOversizedHtml = manyOversizedMetadata["html"]?.GetValue<string>() ?? string.Empty;
        Expect(manyOversizedStructured.GetProperty("warnings").GetArrayLength() == 1
            && !manyOversizedHtml.Contains("data:image/png;base64,", StringComparison.OrdinalIgnoreCase)
            && manyOversizedHandler.Operations.Count(operation => operation == "GetAttachment") == 8
            && manyOversizedHandler.Operations[0] == "GetItem"
            && manyOversizedHandler.Operations[^1] == "GetItem",
            "The preview exceeded eight distinct image fetches or skipped the final freshness read after omitting images.");

        var envelopeHandler = new MailPreviewEwsHandler(image)
        {
            HtmlBody = "<html><head><meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\"></head><body><table><tr><td><p class=\"MsoNormal\" style=\"margin:0;white-space:normal\" dir=\"rtl\">سلام<img src=\"cid:logo\"><i>Disclaimer</i><a href=\"https://example.test/\" target=\"_BLANK\">Web</a><a href=\"mailto:contact@example.test\" TARGET=\"_blank\">Email</a></p></td></tr></table></body></html>"
        };
        var envelopeTool = new MailPreviewTools(NewEwsClient(envelopeHandler), access, handles, new MailReviewStore());
        var envelopeResult = await envelopeTool.Preview(user, draftHandle, CancellationToken.None);
        var envelopeMetadata = envelopeResult.Meta?["emailPreview"]?.AsObject()
            ?? throw new InvalidOperationException("The Exchange envelope preview omitted private metadata.");
        var envelopeStructured = envelopeResult.StructuredContent
            ?? throw new InvalidOperationException("The Exchange envelope preview omitted structured content.");
        var envelopeHtml = envelopeMetadata["html"]?.GetValue<string>() ?? string.Empty;
        Expect(envelopeStructured.GetProperty("bodyText").GetString()?.Contains("سلام", StringComparison.Ordinal) == true
            && envelopeStructured.GetProperty("bodyText").GetString()?.Contains("[inline image cid:logo]", StringComparison.Ordinal) == true
            && envelopeStructured.GetProperty("editable").GetBoolean()
            && envelopeStructured.GetProperty("warnings").GetArrayLength() == 0
            && !envelopeHtml.Contains("<html", StringComparison.Ordinal)
            && !envelopeHtml.Contains("Content-Type", StringComparison.Ordinal)
            && !envelopeHtml.Contains("target=", StringComparison.OrdinalIgnoreCase)
            && envelopeHtml.Contains("<table>", StringComparison.Ordinal)
            && envelopeHtml.Contains("margin:0;white-space:normal", StringComparison.Ordinal)
            && envelopeHtml.Contains("<i>Disclaimer</i>", StringComparison.Ordinal)
            && envelopeHtml.Contains("href=\"https://example.test/\"", StringComparison.Ordinal)
            && envelopeHtml.Contains("href=\"mailto:contact@example.test\"", StringComparison.Ordinal)
            && envelopeHtml.Contains($"data:image/png;base64,{Convert.ToBase64String(image)}", StringComparison.Ordinal)
            && envelopeHandler.Operations.SequenceEqual(["GetItem", "GetAttachment", "GetItem"]),
            "A stored Exchange HTML envelope with passive blank link targets lost its editable HTML, logo or signature spacing.");

        const string headContents = "Visible disclaimer <strong>before</strong>";
        const string headTextBody = "<html><head>" + headContents + "</head><body><p>Message</p></body></html>";
        var headTextHandler = new MailPreviewEwsHandler(image) { HtmlBody = headTextBody, ImageCount = 0 };
        var headTextResult = await new MailPreviewTools(NewEwsClient(headTextHandler), access, handles, new MailReviewStore())
            .Preview(user, draftHandle, CancellationToken.None);
        var headTextMetadata = headTextResult.Meta?["emailPreview"]?.AsObject()
            ?? throw new InvalidOperationException("Head-content preview omitted private metadata.");
        var headHtml = headTextMetadata["html"]!.GetValue<string>();
        var headText = headTextMetadata["bodyText"]!.GetValue<string>();
        Expect(headHtml.Contains(headContents, StringComparison.Ordinal)
            && XElement.Parse("<root>" + headHtml + "</root>").Value == "Visible disclaimer beforeMessage"
            && headText.Contains("Visible disclaimer before", StringComparison.Ordinal)
            && headText.IndexOf("Visible disclaimer before", StringComparison.Ordinal) < headText.IndexOf("Message", StringComparison.Ordinal)
            && headTextMetadata["body"]!.GetValue<string>() == RichBody.NormalizeExchangeHtml(headTextBody)
            && headTextMetadata["editable"]?.GetValue<bool>() == true
            && headTextMetadata["sendable"]?.GetValue<bool>() == true
            && headTextHandler.HtmlBody == headTextBody && headTextHandler.Operations.SequenceEqual(["GetItem", "GetItem"]),
            "Envelope projection lost validated head text/children or their order, changed the stored draft, or performed a write.");

        const string defaultSignature = "<table id='saved-signature'><tr><td>Regards, English signature</td></tr></table>";
        const string ltrSignature = "<table id='saved-signature' dir='ltr' style='direction:ltr;text-align:left'><tr><td>Regards, English signature</td></tr></table>";
        const string rtlSignature = "<div id='saved-signature' dir='rtl' style='direction:rtl;text-align:right'>با احترام</div>";
        foreach (var (stored, savedSignature) in new[]
        {
            ("<p id='authored'>English message.</p>" + defaultSignature, defaultSignature),
            ("<div id='authored' dir='rtl' lang='fa' style='direction:rtl;text-align:right'>متن فارسی</div>" + defaultSignature, defaultSignature),
            ("<div id='authored' dir='rtl' lang='fa' style='direction:rtl;text-align:right'>متن فارسی</div>" + ltrSignature, ltrSignature),
            ("<p id='authored' dir='ltr'>English message.</p>" + rtlSignature, rtlSignature),
            ("<html dir='rtl' lang='fa' style='direction:rtl;text-align:right'><body dir='ltr' lang='en' style='direction:ltr;text-align:left'><p id='authored'>English <ins>message</ins>.</p>" + rtlSignature + "</body></html>", rtlSignature),
            ("<body dir='rtl' lang='fa' style='direction:rtl;text-align:right'><p id='authored'>متن فارسی</p>" + ltrSignature + "</body>", ltrSignature),
            ("<html dir='rtl' lang='fa' style='direction:rtl;text-align:right'><p id='authored'>متن فارسی</p>" + ltrSignature + "</html>", ltrSignature)
        })
        {
            var directionHandler = new MailPreviewEwsHandler(image) { Subject = "موضوع فارسی", HtmlBody = stored, ImageCount = 0 };
            var directionResult = await new MailPreviewTools(NewEwsClient(directionHandler), access, handles, new MailReviewStore())
                .Preview(user, draftHandle, CancellationToken.None);
            var directionMetadata = directionResult.Meta?["emailPreview"]?.AsObject()
                ?? throw new InvalidOperationException("Direction preview omitted private metadata.");
            var display = XElement.Parse("<root>" + directionMetadata["html"]!.GetValue<string>() + "</root>");
            var original = XElement.Parse("<root>" + stored + "</root>");
            foreach (var id in new[] { "authored", "saved-signature" })
            {
                var originalPart = original.Descendants().Single(element => (string?)element.Attribute("id") == id);
                var displayedPart = display.Descendants().Single(element => (string?)element.Attribute("id") == id);
                Expect(XNode.DeepEquals(originalPart, displayedPart)
                    && originalPart.Ancestors().Select(element => (string?)element.Attribute("dir")).Where(value => value is not null)
                        .SequenceEqual(displayedPart.Ancestors().Select(element => (string?)element.Attribute("dir")).Where(value => value is not null))
                    && originalPart.Ancestors().Select(element => (string?)element.Attribute("style")).Where(value => value is not null)
                        .SequenceEqual(displayedPart.Ancestors().Select(element => (string?)element.Attribute("style")).Where(value => value is not null)),
                    "The preview changed authored/signature content or lost explicit document/body/nested direction inheritance.");
            }
            Expect(directionMetadata["language"]?.GetValue<string>() == "fa"
                && directionMetadata["body"]?.GetValue<string>() == RichBody.NormalizeExchangeHtml(stored)
                && directionMetadata["editable"]?.GetValue<bool>() == true
                && directionMetadata["sendable"]?.GetValue<bool>() == true
                && XNode.DeepEquals(display.Descendants().Single(element => (string?)element.Attribute("id") == "saved-signature"), XElement.Parse(savedSignature))
                && directionHandler.HtmlBody == stored && directionHandler.Operations.SequenceEqual(["GetItem", "GetItem"]),
                "Persian preview localization changed the stored draft/signature, disabled strict HTML editing, or performed a write.");
        }
        ExpectThrows<ArgumentException>(() => RichBody.Validate("<a href=\"https://example.test/\" target=\"_blank\">Web</a>", "HTML"),
            "Strict rich-body validation accepted a target attribute outside Exchange normalization.");
        foreach (var unsafeLink in new[]
        {
            "<a href=\"https://example.test/\" target=\"_top\">Web</a>",
            "<a href=\"https://example.test/\" target=\"_self\">Web</a>",
            "<a href=\"https://example.test/\" target=\"_blank\" onclick=\"alert(1)\">Web</a>",
            "<a href=\"javascript:alert(1)\" target=\"_BLANK\">Web</a>",
            "<a xmlns:x=\"urn:unsafe\" href=\"https://example.test/\" x:target=\"_blank\">Web</a>",
            "<div target=\"_blank\">Text</div>"
        })
            ExpectThrows<ArgumentException>(() => RichBody.NormalizeExchangeHtml(unsafeLink),
                "Exchange link normalization accepted an unsafe target, URL, event handler or namespaced attribute.");

        var nativeHtml = "<html xmlns:o=\"urn:schemas-microsoft-com:office:office\"><head><meta name=\"Generator\" content=\"Microsoft Word\"><style><!-- p.MsoNormal {margin:0;font-family:Arial;mso-style-name:Normal;} --></style></head><body lang=\"FA\" style=\"direction:rtl\"><div class=\"WordSection1\"><p class=\"MsoNormal\">Current reply<o:p>&nbsp;</o:p></p><div id=\"divRplyFwdMsg\"><p>From: previous@example.test</p><p>Subject: Original message</p></div><blockquote><table cellpadding=\"3\"><tr><td><p class=\"MsoNormal\">Quoted Office content<img src=\"cid:logo\"></p></td></tr></table></blockquote></div></body></html>";
        var nativeHandler = new MailPreviewEwsHandler(image) { HtmlBody = nativeHtml };
        var nativeResult = await new MailPreviewTools(NewEwsClient(nativeHandler), access, handles, new MailReviewStore())
            .Preview(user, draftHandle, CancellationToken.None);
        var nativeMetadata = nativeResult.Meta?["emailPreview"]?.AsObject()
            ?? throw new InvalidOperationException("The native Office preview omitted private metadata.");
        var nativeStructured = nativeResult.StructuredContent
            ?? throw new InvalidOperationException("The native Office preview omitted structured content.");
        var nativePreview = nativeMetadata["html"]?.GetValue<string>() ?? string.Empty;
        Expect(!nativeStructured.GetProperty("editable").GetBoolean()
            && nativeStructured.GetProperty("sendable").GetBoolean()
            && nativeMetadata["editable"]?.GetValue<bool>() == false
            && nativeMetadata["sendable"]?.GetValue<bool>() == true
            && nativeMetadata["body"]?.GetValue<string>() == nativeHtml
            && nativeStructured.GetProperty("bodyText").GetString()?.Contains("Quoted Office content", StringComparison.Ordinal) == true
            && nativePreview.Contains("Current reply", StringComparison.Ordinal)
            && nativePreview.Contains("From: previous@example.test", StringComparison.Ordinal)
            && nativePreview.Contains("<blockquote>", StringComparison.Ordinal)
            && nativePreview.Contains("Quoted Office content", StringComparison.Ordinal)
            && nativePreview.Contains($"data:image/png;base64,{Convert.ToBase64String(image)}", StringComparison.Ordinal)
            && !nativePreview.Contains("<o:p", StringComparison.OrdinalIgnoreCase)
            && !nativePreview.Contains("<style", StringComparison.OrdinalIgnoreCase)
            && nativeStructured.GetProperty("warnings").EnumerateArray().Any(warning =>
                warning.GetString()?.Contains("display copy", StringComparison.Ordinal) == true)
            && nativeHandler.Operations.SequenceEqual(["GetItem", "GetAttachment", "GetItem"]),
            "A passive native Office draft lost quoted content or its CID logo, changed its stored edit body, or failed to separate send and edit permissions.");

        var officeHtml = "<html><head><style>p{behavior:url(x)}</style></head><body><p>سلام&nbsp;Office</p><script>alert(1)</script></body></html>";
        var unsupportedHandler = new MailPreviewEwsHandler(image) { HtmlBody = officeHtml };
        var unsupportedTool = new MailPreviewTools(NewEwsClient(unsupportedHandler), access, handles, new MailReviewStore());
        var unsupportedResult = await unsupportedTool.Preview(user, draftHandle, CancellationToken.None);
        var unsupportedMetadata = unsupportedResult.Meta?["emailPreview"]?.AsObject()
            ?? throw new InvalidOperationException("The unsupported HTML fallback omitted private metadata.");
        var unsupportedStructured = unsupportedResult.StructuredContent
            ?? throw new InvalidOperationException("The unsupported HTML fallback omitted structured content.");
        var fallbackHtml = unsupportedMetadata["html"]?.GetValue<string>() ?? string.Empty;
        Expect(unsupportedStructured.GetProperty("bodyText").GetString() == "سلام Office"
            && !unsupportedStructured.GetProperty("editable").GetBoolean()
            && !unsupportedStructured.GetProperty("sendable").GetBoolean()
            && unsupportedMetadata["sendable"]?.GetValue<bool>() == false
            && unsupportedStructured.GetProperty("warnings").GetArrayLength() == 1
            && unsupportedMetadata["body"]?.GetValue<string>() == officeHtml
            && !fallbackHtml.Contains("<script", StringComparison.OrdinalIgnoreCase)
            && !fallbackHtml.Contains("behavior:url", StringComparison.OrdinalIgnoreCase)
            && unsupportedHandler.Operations.SequenceEqual(["GetItem", "GetItem"]),
            "Unsupported stored Office HTML was not reduced to a safe read-only text preview without changing the draft.");

        foreach (var unsafeHtml in new[]
        {
            nativeHtml.Replace("Current reply", "<script>alert(1)</script>Current reply", StringComparison.Ordinal),
            nativeHtml.Replace("cid:logo", "https://external.example.test/tracking.png", StringComparison.Ordinal),
            nativeHtml.Replace("<blockquote>", "<blockquote onclick=\"alert(1)\">", StringComparison.Ordinal),
            nativeHtml.Replace("margin:0", "margin:0;background-image:url(https://external.example.test/tracking.png)", StringComparison.Ordinal)
        })
        {
            var unsafeHandler = new MailPreviewEwsHandler(image) { HtmlBody = unsafeHtml };
            var unsafeResult = await new MailPreviewTools(NewEwsClient(unsafeHandler), access, handles, new MailReviewStore())
                .Preview(user, draftHandle, CancellationToken.None);
            var unsafeStructured = unsafeResult.StructuredContent
                ?? throw new InvalidOperationException("The unsafe native Office fallback omitted structured content.");
            var unsafeMetadata = unsafeResult.Meta?["emailPreview"]?.AsObject()
                ?? throw new InvalidOperationException("The unsafe native Office fallback omitted private metadata.");
            var unsafePreview = unsafeMetadata["html"]?.GetValue<string>() ?? string.Empty;
            Expect(!unsafeStructured.GetProperty("editable").GetBoolean()
                && !unsafeStructured.GetProperty("sendable").GetBoolean()
                && unsafeMetadata["body"]?.GetValue<string>() == unsafeHtml
                && !unsafePreview.Contains("<script", StringComparison.OrdinalIgnoreCase)
                && !unsafePreview.Contains("<img", StringComparison.OrdinalIgnoreCase)
                && !unsafePreview.Contains("onclick=", StringComparison.OrdinalIgnoreCase)
                && unsafeHandler.Operations.SequenceEqual(["GetItem", "GetItem"]),
                "Active or remotely loaded native Office HTML became sendable, rendered unsafe markup, fetched attachment content, or changed the stored body.");
        }

        var staleHandler = new MailPreviewEwsHandler(image);
        var staleTool = new MailPreviewTools(NewEwsClient(staleHandler), access, handles, new MailReviewStore());
        var staleHandle = handles.Issue(identity, "message", "draft-1", "older-change");
        await AssertThrowsAsync<McpException>(() => staleTool.Preview(user, staleHandle, CancellationToken.None));
        Expect(staleHandler.Operations.SequenceEqual(["GetItem"]),
            "A stale draft handle fetched content or attempted an operation after rejection.");

        var changedDuringPreview = new MailPreviewEwsHandler(image) { ChangeOnFinalRead = true };
        await AssertThrowsAsync<McpException>(() => new MailPreviewTools(NewEwsClient(changedDuringPreview), access, handles, new MailReviewStore())
            .Preview(user, draftHandle, CancellationToken.None));
        Expect(changedDuringPreview.Operations.SequenceEqual(["GetItem", "GetAttachment", "GetItem"]),
            "A draft changed during image loading was returned as a current preview.");

        var notDraft = new MailPreviewEwsHandler(image) { IsDraft = false };
        var notDraftTool = new MailPreviewTools(NewEwsClient(notDraft), access, handles, new MailReviewStore());
        await AssertThrowsAsync<McpException>(() => notDraftTool.Preview(user, draftHandle, CancellationToken.None));
        Expect(notDraft.Operations.SequenceEqual(["GetItem"]), "The preview accepted a non-draft message.");

        var resource = MailPreviewResources.Read().Contents.OfType<TextResourceContents>().Single();
        var csp = resource.Meta?["ui"]?["csp"]?.AsObject()
            ?? throw new InvalidOperationException("The mail preview UI omitted CSP metadata.");
        var html = resource.Text;
        foreach (var card in new[] { html, SignaturePreviewResources.Read().Contents.OfType<TextResourceContents>().Single().Text })
        {
            Expect(card.Contains("const allowedTags = new Set(\"a b blockquote br caption code col colgroup del div em h1 h2 h3 h4 h5 h6 hr i img ins li ol p pre s small span strong sub sup table tbody td tfoot th thead tr u ul\".split(\" \"))", StringComparison.Ordinal),
                "A preview card rejected an element supported by the safe rich-body fragment subset.");
            Expect(card.Contains("background-color:#fff; color:#111; color-scheme:light;", StringComparison.Ordinal)
                && card.Contains("var(--color-text-primary, light-dark(#202124, #f1f3f4))", StringComparison.Ordinal)
                && card.Contains("applyHostContext(message.result?.hostContext)", StringComparison.Ordinal)
                && card.Contains("ui/notifications/host-context-changed", StringComparison.Ordinal)
                && card.Contains("applyHostContext(message.params)", StringComparison.Ordinal),
                "A preview card omitted its readable email canvas, themed controls or host theme updates.");
            Expect(!card.Contains("p.MsoNormal, li.MsoNormal, div.MsoNormal", StringComparison.Ordinal),
                "The preview repaired signature paragraph formatting that was missing from the saved body.");
            Expect(card.Contains("sandbox=\"\"", StringComparison.Ordinal)
                && card.Contains(".srcdoc = emailDocument(template.innerHTML, data.language)", StringComparison.Ordinal)
                && card.Contains("white-space:normal", StringComparison.Ordinal)
                && !card.Contains("allow-scripts", StringComparison.Ordinal)
                && !card.Contains("allow-same-origin", StringComparison.Ordinal),
                "A preview inherited host layout or enabled script/origin privileges in its email document.");
            Expect(card.Contains("<!doctype html><html lang=\"${language}\"><head>", StringComparison.Ordinal),
                "A preview inferred the email canvas direction from UI language instead of preserving content direction.");
        }
        Expect(resource.Uri == MailPreviewResources.ResourceUri
            && resource.MimeType == MailPreviewResources.ResourceMimeType
            && csp["connectDomains"]?.AsArray().Count == 0 && csp["resourceDomains"]?.AsArray().Count == 0,
            "The mail preview resource URI, MIME type or no-network CSP changed.");
        Expect(html.Contains("mail_send_draft", StringComparison.Ordinal)
            && html.Contains("mail_edit_draft", StringComparison.Ordinal)
            && html.Contains("mail_preview_draft", StringComparison.Ordinal)
            && html.Contains("ui/notifications/initialized", StringComparison.Ordinal)
            && html.Contains("tools/call", StringComparison.Ordinal)
            && html.Contains("result?.structuredContent?.tracking?.id", StringComparison.Ordinal)
            && html.Contains("Tracking ID:", StringComparison.Ordinal)
            && html.Contains("Exchange acknowledged the send request; delivery is not confirmed.", StringComparison.Ordinal)
            && html.Contains("The send request did not reach Exchange.", StringComparison.Ordinal)
            && html.Contains("Exchange rejected the send request.", StringComparison.Ordinal)
            && html.Contains("sendStatus", StringComparison.Ordinal)
            && html.Contains("typeof data.editable !== \"boolean\"", StringComparison.Ordinal)
            && html.Contains("typeof data.sendable !== \"boolean\"", StringComparison.Ordinal)
            && html.Contains("get(\"send\").hidden = !(data.sendable ?? data.editable)", StringComparison.Ordinal)
            && html.Contains("if (!(current.sendable ?? current.editable)) return", StringComparison.Ordinal)
            && html.Contains("get(\"edit\").hidden = !data.editable", StringComparison.Ordinal)
            && html.Contains("the draft is unchanged", StringComparison.Ordinal)
            && html.Contains("Refresh Drafts before trying again", StringComparison.Ordinal)
            && html.Contains("پیش‌نویس تغییر نکرد", StringComparison.Ordinal)
            && html.Contains("attachShadow({ mode: \"closed\" })", StringComparison.Ordinal),
            "The send/edit/cancel card omitted an action, no-retry guidance, Persian support or closed-shadow isolation.");
        Expect(html.Contains("if (!current || sendStarted) return", StringComparison.Ordinal)
            && html.Contains("if (closed || sendStarted || editStarted) return", StringComparison.Ordinal)
            && !html.Contains("sendStarted = false;\n                editStarted = false", StringComparison.Ordinal)
            && html.Contains("closed = true", StringComparison.Ordinal)
            && html.Contains("cancel:\"Don't send\"", StringComparison.Ordinal)
            && html.Contains("cancel:\"ارسال نکن\"", StringComparison.Ordinal)
            && html.Contains("get(\"send\").hidden = true", StringComparison.Ordinal)
            && html.Contains("setStatus(labels[current.language].statusSent, result)", StringComparison.Ordinal)
            && html.Contains("if (!current || get(\"cancel\").disabled) return", StringComparison.Ordinal),
            "The card allowed duplicate sends, sending stale unsaved edits, or blocked closing after a terminal send result.");
        var renderStart = html.IndexOf("function showPayload(data)", StringComparison.Ordinal);
        var validateHtml = html.IndexOf("every(validateNode)", renderStart, StringComparison.Ordinal);
        var acceptData = html.IndexOf("current = data", renderStart, StringComparison.Ordinal);
        Expect(validateHtml > renderStart && acceptData > validateHtml,
            "The card accepted actionable draft data before validating its rendered HTML.");
        var approvalHandlerStart = html.IndexOf("function showApprovalRequired(result)", StringComparison.Ordinal);
        var approvalHandlerEnd = approvalHandlerStart < 0 ? -1
            : html.IndexOf("function selectorArgs()", approvalHandlerStart, StringComparison.Ordinal);
        var approvalHandler = approvalHandlerStart >= 0 && approvalHandlerEnd > approvalHandlerStart
            ? html[approvalHandlerStart..approvalHandlerEnd] : string.Empty;
        Expect(html.Contains("function isApprovalRequired(value)", StringComparison.Ordinal)
            && html.Contains("resultType === \"input_required\"", StringComparison.Ordinal)
            && html.Contains("if (isApprovalRequired(result))", StringComparison.Ordinal)
            && html.Contains("if (isApprovalRequired(error))", StringComparison.Ordinal)
            && approvalHandler.Contains("get(\"send\").disabled = true", StringComparison.Ordinal)
            && !approvalHandler.Contains("callTool(", StringComparison.Ordinal)
            && html.Contains("No email was sent", StringComparison.Ordinal)
            && html.Contains("this card will not retry", StringComparison.Ordinal),
            "The card did not distinguish host confirmation from send status, or it retried/bypassed the approval flow.");
        Expect(html.Contains("error.rpcCode = message.error.code", StringComparison.Ordinal)
            && html.Contains("error.rpcData = message.error.data", StringComparison.Ordinal),
            "The MCP app discarded JSON-RPC error code or data needed to interpret approval responses.");
        Expect(!html.Contains("fetch(", StringComparison.OrdinalIgnoreCase)
            && !html.Contains("XMLHttpRequest", StringComparison.Ordinal)
            && !html.Contains("WebSocket", StringComparison.Ordinal)
            && !html.Contains("EventSource", StringComparison.Ordinal)
            && !html.Contains("<script src=", StringComparison.OrdinalIgnoreCase)
            && html.Contains("if (!current || get(\"cancel\").disabled) return", StringComparison.Ordinal)
            && html.Contains("mailboxHandle:current.mailboxHandle", StringComparison.Ordinal),
            "The mail preview used external code/network access or dropped its delegated mailbox selector.");
        Expect(MailPreviewResources.ResourceUri == "ui://exchange-mcp/email-preview-v6.html"
            && MailPreviewResources.ReadPrior().Contents.Single().Uri == "ui://exchange-mcp/email-preview-v5.html"
            && MailPreviewResources.ReadCached().Contents.Single().Uri == "ui://exchange-mcp/email-preview-v4.html"
            && MailPreviewResources.ReadRetained().Contents.Single().Uri == "ui://exchange-mcp/email-preview-v3.html"
            && MailPreviewResources.ReadPrevious().Contents.Single().Uri == "ui://exchange-mcp/email-preview-v2.html"
            && MailPreviewResources.ReadLegacy().Contents.Single().Uri == "ui://exchange-mcp/email-preview-v1.html",
            "The new mail preview version dropped a previously advertised resource alias.");
    }
}

internal sealed class MailPreviewEwsHandler(byte[] image) : HttpMessageHandler
{
    private static readonly XNamespace Soap = "http://schemas.xmlsoap.org/soap/envelope/";
    private static readonly XNamespace Messages = "http://schemas.microsoft.com/exchange/services/2006/messages";
    private static readonly XNamespace Types = "http://schemas.microsoft.com/exchange/services/2006/types";

    public bool IsDraft { get; init; } = true;
    public string Subject { get; init; } = "Draft <review>";
    public string HtmlBody { get; init; } = "<p class=\"MsoNormal\" style=\"margin-top:3px;margin-bottom:5px\" dir=\"rtl\">سلام<img src=\"cid:logo\"/><i>italic</i><ins>inserted</ins></p>";
    public int ImageCount { get; init; } = 1;
    public int? ReportedSize { get; init; }
    public bool ChangeOnFinalRead { get; init; }
    public List<string> Operations { get; } = [];

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var body = await request.Content!.ReadAsStringAsync(cancellationToken);
        var operation = XDocument.Parse(body).Root!.Element(Soap + "Body")!.Elements().Single();
        var name = operation.Name.LocalName;
        Operations.Add(name);
        var responseContent = name switch
        {
            "GetItem" => ItemResponse(),
            "GetAttachment" => AttachmentResponse(operation.Descendants(Types + "AttachmentId").Single()
                .Attribute("Id")!.Value),
            _ => throw new InvalidOperationException($"Unexpected EWS operation: {name}.")
        };
        var response = new XElement(Soap + "Envelope",
            new XAttribute(XNamespace.Xmlns + "s", Soap),
            new XAttribute(XNamespace.Xmlns + "m", Messages),
            new XAttribute(XNamespace.Xmlns + "t", Types),
            new XElement(Soap + "Body", responseContent));
        return new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(response.ToString(SaveOptions.DisableFormatting), Encoding.UTF8, "text/xml")
        };
    }

    private XElement ItemResponse() => new(Messages + "GetItemResponse",
        new XElement(Messages + "ResponseMessages",
            new XElement(Messages + "GetItemResponseMessage", new XAttribute("ResponseClass", "Success"),
                new XElement(Messages + "ResponseCode", "NoError"))),
        new XElement(Messages + "Items", new XElement(Types + "Message",
            new XElement(Types + "ItemId", new XAttribute("Id", "draft-1"),
                new XAttribute("ChangeKey", ChangeOnFinalRead && Operations.Count(operation => operation == "GetItem") > 1 ? "changed-during-preview" : "draft-current")),
            new XElement(Types + "Subject", Subject),
            new XElement(Types + "From", new XElement(Types + "Mailbox", new XElement(Types + "EmailAddress", "alice@example.test"))),
            Recipients("ToRecipients", "to@example.test"),
            Recipients("CcRecipients", "cc@example.test"),
            Recipients("BccRecipients", "hidden@example.test"),
            new XElement(Types + "IsDraft", IsDraft),
            new XElement(Types + "IsRead", true),
            new XElement(Types + "Body", new XAttribute("BodyType", "HTML"), HtmlBody),
            new XElement(Types + "Attachments", Enumerable.Range(1, ImageCount).Select(index =>
                new XElement(Types + "FileAttachment",
                    new XElement(Types + "AttachmentId", new XAttribute("Id", ImageId(index))),
                    new XElement(Types + "Name", ImageName(index)),
                    new XElement(Types + "Size", ReportedSize ?? image.Length),
                    new XElement(Types + "ContentType", "image/png"), new XElement(Types + "IsInline", true),
                    new XElement(Types + "ContentId", ImageContentId(index))))))));

    private XElement AttachmentResponse(string id)
    {
        var index = int.Parse(id["image-".Length..], System.Globalization.CultureInfo.InvariantCulture);
        if (index < 1 || index > ImageCount) throw new InvalidOperationException("Unexpected image attachment id.");
        return new(Messages + "GetAttachmentResponse",
            new XElement(Messages + "ResponseMessages",
                new XElement(Messages + "GetAttachmentResponseMessage", new XAttribute("ResponseClass", "Success"),
                    new XElement(Messages + "ResponseCode", "NoError"))),
            new XElement(Messages + "Attachments", new XElement(Types + "FileAttachment",
                new XElement(Types + "AttachmentId", new XAttribute("Id", id)),
                new XElement(Types + "Name", ImageName(index)),
                new XElement(Types + "ContentType", "image/png"),
                new XElement(Types + "IsInline", true),
                new XElement(Types + "ContentId", ImageContentId(index)),
                new XElement(Types + "Content", Convert.ToBase64String(image)))));
    }

    private static string ImageId(int index) => $"image-{index}";
    private static string ImageName(int index) => index == 1 ? "logo.png" : $"logo-{index}.png";
    private static string ImageContentId(int index) => index == 1 ? "logo" : $"logo-{index}";

    private static XElement Recipients(string name, string address) => new(Types + name,
        new XElement(Types + "Mailbox", new XElement(Types + "EmailAddress", address)));
}
