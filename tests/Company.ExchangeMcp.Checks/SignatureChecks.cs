using System.Net;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using System.Xml.Linq;
using System.Xml.Schema;
using Company.ExchangeMcp;
using Company.ExchangeMcp.Exchange;
using Company.ExchangeMcp.Security;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Options;
using ModelContextProtocol;

internal sealed partial class Checks
{
    private const string NativeReplyHtml = """
        <html><head><meta http-equiv="Content-Type" content="text/html; charset=utf-8"><meta content="text/html; charset=us-ascii"></head><body><div dir="ltr" lang="en" style="font-family:Calibri; font-size:11pt"><p>New <strong>reply</strong>.</p></div><hr tabindex="-1" style="display:inline-block; width:98%"><div id="divRplyFwdMsg" dir="ltr"><font face="Calibri, sans-serif" color="#000000" style="font-size:11pt"><b>From:</b> sender<br><b>Sent:</b> time<br><b>To:</b> recipient<br><b>Subject:</b> test</font><div>&nbsp;</div></div><div><div dir="ltr" lang="en" style="font-family:Calibri; font-size:11pt"><p>Original.</p></div></div></body></html>
        """;

    private async Task SignatureChecksAsync()
    {
        var handler = new SignatureRecordingHandler();
        var exchange = NewEwsClient(handler);
        var store = new SignatureStore();
        var initial = await store.ReadAsync(exchange, "alice@example.test", CancellationToken.None);
        Expect(initial.Revision == "new" && initial.Settings.Profiles.Length == 0,
            "A missing configuration did not return empty signature settings.");
        Expect(initial.Limits.MaxProfiles == SignatureStore.MaxProfiles
            && initial.Limits.MaxBodyCharacters == SignatureStore.MaxBodyCharacters
            && initial.Limits.MaxImagesPerProfile == SignatureStore.MaxImagesPerProfile
            && initial.Limits.MaxImageBytes == SignatureStore.MaxImageBytes
            && initial.Limits.MaxTotalImageBytes == SignatureStore.MaxTotalImageBytes
            && initial.Limits.MaxSerializedBytes == SignatureStore.MaxSerializedBytes
            && initial.Limits.MaxUseRules == SignatureStore.MaxUseRules
            && initial.Usage.ProfilesUsed == 0 && initial.Usage.ProfilesRemaining == SignatureStore.MaxProfiles
            && initial.Usage.ImagesUsed == 0 && initial.Usage.ImagesRemaining == SignatureStore.MaxProfiles * SignatureStore.MaxImagesPerProfile
            && initial.Usage.SerializedBytes == 0
            && initial.Usage.SerializedBytesRemaining == SignatureStore.MaxSerializedBytes,
            "An empty signature snapshot did not expose the configured limits and remaining usage.");
        var profile = new MailSignature("Work", "<b>Alice</b><table><tr><td>Company</td></tr></table>", "HTML", []);
        var saved = await store.UpdateAsync(exchange, "alice@example.test", initial.Revision,
            _ => new([profile], "Work", "Work"), CancellationToken.None);
        var read = await store.ReadAsync(exchange, "alice@example.test", CancellationToken.None);
        Expect(read.Revision == saved.Revision && read.Settings.Profiles.Single().Body == profile.Body,
            "Signature persistence did not round trip body, defaults and revision.");
        Expect(read.Usage.ProfilesUsed == 1 && read.Usage.ProfilesRemaining == SignatureStore.MaxProfiles - 1
            && read.Usage.SerializedBytes == handler.ConfigurationBytes
            && read.Usage.SerializedBytesRemaining == SignatureStore.MaxSerializedBytes - handler.ConfigurationBytes,
            "A saved signature snapshot did not report persisted byte usage and remaining capacity.");
        var writes = handler.Writes;
        await AssertThrowsAsync<McpException>(() => store.UpdateAsync(exchange, "alice@example.test", "new",
            _ => new([], null, null), CancellationToken.None));
        Expect(handler.Writes == writes, "A stale signature revision overwrote the saved configuration.");
        var concurrent = await Task.WhenAll(Enumerable.Range(0, 2).Select(async index =>
        {
            try
            {
                await store.UpdateAsync(exchange, "alice@example.test", saved.Revision,
                    before => before with { Profiles = [profile with { Body = $"<b>Change {index}</b>" }] }, CancellationToken.None);
                return true;
            }
            catch (McpException) { return false; }
        }));
        Expect(concurrent.Count(result => result) == 1 && handler.Writes == writes + 1,
            "Concurrent signature changes did not reject one stale writer.");
        Expect(SignatureStore.Append("<unsafe text>", "Text", profile).Contains("&lt;unsafe text&gt;", StringComparison.Ordinal),
            "Plain draft text was not escaped when appending an HTML signature.");
        await AssertThrowsAsync<ArgumentException>(() =>
        {
            SignatureStore.Validate(new([profile with { Body = "<img src='https://tracking.example.test/a'/>" }], null, null));
            return Task.CompletedTask;
        });
        await AssertThrowsAsync<McpException>(() =>
        {
            SignatureStore.Validate(new([profile with { Images = [new("logo.png", "image/png", "logo", "AQID")] }], null, null));
            return Task.CompletedTask;
        });
        var logo = new SignatureImage("logo.png", "image/png", "logo", "iVBORw0KGgo=");
        SignatureStore.Validate(new([profile with { Body = "<img src='cid:logo'/>", Images = [logo] }], null, null));
        await AssertThrowsAsync<McpException>(() =>
        {
            SignatureStore.Validate(new([profile with { Body = "<img src='cid:missing'/>", Images = [logo] }], null, null));
            return Task.CompletedTask;
        });
        handler.Error = "ErrorAccessDenied";
        await AssertThrowsAsync<InvalidOperationException>(() => store.ReadAsync(exchange, "alice@example.test", CancellationToken.None));
        handler.Error = null;
        handler.Error = "ErrorItemNotFound";
        handler.IncludeFault = true;
        await AssertThrowsAsync<InvalidOperationException>(() => store.ReadAsync(exchange, "alice@example.test", CancellationToken.None));
        handler.Error = null;
        handler.IncludeFault = false;

        await SignatureQuotaChecksAsync();
        SignatureHtmlSecurityChecks();
        SignatureAppendFullEnvelopeCheck();
        SignatureReplyPlacementChecks();
        await SignatureToolNormalizationCheckAsync();
        await SignatureApplyNativeReplyCheckAsync();
        await SignatureApplyAttachmentRefreshCheckAsync();
        await SignatureApplyContentIdCollisionCheckAsync();
        await SignatureUseRulesChecksAsync();

        var schemas = LoadOptionalExchangeSchemas();
        foreach (var operation in handler.Operations)
            if (schemas is not null)
                new XDocument(operation).Validate(schemas, (_, error) => throw new InvalidOperationException(
                    $"Exchange 2019 signature request failed schema validation: {error.Message}"));
    }

    private async Task SignatureQuotaChecksAsync()
    {
        var handler = new SignatureRecordingHandler();
        var exchange = NewEwsClient(handler);
        var store = new SignatureStore();

        var eleven = new SignatureSettings(
            Enumerable.Range(0, 11).Select(index => new MailSignature($"Profile {index}", "body", "Text", [])).ToArray(),
            null, null);
        await AssertThrowsAsync<McpException>(() => store.UpdateAsync(exchange, "alice@example.test", "new",
            _ => eleven, CancellationToken.None));
        Expect(handler.Writes == 0, "The 11th signature profile reached EWS before quota validation.");

        var ten = new SignatureSettings(
            Enumerable.Range(0, 10).Select(index => new MailSignature($"Profile {index}", "body", "Text", [])).ToArray(),
            null, null);
        var saved = await store.UpdateAsync(exchange, "alice@example.test", "new", _ => ten, CancellationToken.None);
        var writes = handler.Writes;
        var replacement = await store.UpdateAsync(exchange, "alice@example.test", saved.Revision,
            before => before with
            {
                Profiles = before.Profiles.Select(profile => profile.Name == "Profile 4"
                    ? profile with { Body = "replaced" } : profile).ToArray()
            }, CancellationToken.None);
        Expect(replacement.Settings.Profiles.Length == 10 && handler.Writes == writes + 1,
            "Replacing an existing profile consumed a slot or failed to persist.");

        var controlHandler = new SignatureRecordingHandler();
        var controlExchange = NewEwsClient(controlHandler);
        var controlStore = new SignatureStore();
        foreach (var badName in new[] { "Bad\r\nName", "Bad\tName" })
        {
            await AssertThrowsAsync<McpException>(() => controlStore.UpdateAsync(controlExchange, "alice@example.test", "new",
                _ => new([new MailSignature(badName, "body", "Text", [])], null, null), CancellationToken.None));
        }
        var imageName = new SignatureImage("logo\t.png", "image/png", "logo", PngBase64(8));
        await AssertThrowsAsync<McpException>(() => controlStore.UpdateAsync(controlExchange, "alice@example.test", "new",
            _ => new([new MailSignature("Image name", "<img src=\"cid:logo\"/>", "HTML", [imageName])], null, null), CancellationToken.None));
        Expect(controlHandler.Writes == 0,
            "Control characters in signature profile or image names reached EWS before validation.");

        var text = new MailSignature("Text", "line one\r\n\tline two \"quoted\" \\ slash Ω", "Text", []);
        SignatureStore.Validate(new([text], null, null));
        await AssertThrowsAsync<McpException>(() =>
        {
            SignatureStore.Validate(new([text with { Body = new string('x', 65_537) }], null, null));
            return Task.CompletedTask;
        });
        await AssertThrowsAsync<McpException>(() =>
        {
            SignatureStore.Validate(new([text with { Body = "safe\0text" }], null, null));
            return Task.CompletedTask;
        });

        var eightImages = Enumerable.Range(0, 8)
            .Select(index => new SignatureImage($"{index}.png", "image/png", $"image-{index}", PngBase64(8)))
            .ToArray();
        var eightBody = string.Concat(eightImages.Select(image => $"<img src=\"cid:{image.ContentId}\"/>"));
        SignatureStore.Validate(new([new MailSignature("Eight", eightBody, "HTML", eightImages)], null, null));
        await AssertThrowsAsync<McpException>(() =>
        {
            var nine = eightImages.Append(new SignatureImage("8.png", "image/png", "image-8", PngBase64(8))).ToArray();
            SignatureStore.Validate(new([new MailSignature("Nine", eightBody + "<img src=\"cid:image-8\"/>", "HTML", nine)], null, null));
            return Task.CompletedTask;
        });

        var halfMiB = new SignatureImage("large.png", "image/png", "large", PngBase64(524_288));
        SignatureStore.Validate(new([new MailSignature("Half", "<img src=\"cid:large\"/>", "HTML", [halfMiB])], null, null));
        await AssertThrowsAsync<McpException>(() =>
        {
            var tooLarge = halfMiB with { ContentBase64 = PngBase64(524_289) };
            SignatureStore.Validate(new([new MailSignature("Too large", "<img src=\"cid:large\"/>", "HTML", [tooLarge])], null, null));
            return Task.CompletedTask;
        });

        var twoMiB = Enumerable.Range(0, 4)
            .Select(index => new SignatureImage($"large-{index}.png", "image/png", $"large-{index}", PngBase64(524_288)))
            .ToArray();
        var twoMiBBody = string.Concat(twoMiB.Select(image => $"<img src=\"cid:{image.ContentId}\"/>"));
        SignatureStore.Validate(new([new MailSignature("Two MiB", twoMiBBody, "HTML", twoMiB)], null, null));
        await AssertThrowsAsync<McpException>(() =>
        {
            var over = twoMiB.Append(new SignatureImage("over.png", "image/png", "over", PngBase64(8))).ToArray();
            SignatureStore.Validate(new([new MailSignature("Over", twoMiBBody + "<img src=\"cid:over\"/>", "HTML", over)], null, null));
            return Task.CompletedTask;
        });

        var exactHandler = new SignatureRecordingHandler();
        var exactExchange = NewEwsClient(exactHandler, 16 * 1024 * 1024);
        var exactStore = new SignatureStore();
        var exactSettings = CreateExactQuotaSettings();
        var exactBytes = JsonSerializer.SerializeToUtf8Bytes(exactSettings);
        Expect(exactBytes.Length == SignatureStore.MaxSerializedBytes,
            $"The exact signature quota fixture was {exactBytes.Length} bytes, not 3 MiB.");
        var exact = await exactStore.UpdateAsync(exactExchange, "alice@example.test", "new", _ => exactSettings,
            CancellationToken.None);
        var exactWrites = exactHandler.Writes;
        await AssertThrowsAsync<McpException>(() => exactStore.UpdateAsync(exactExchange, "alice@example.test", exact.Revision,
            before => before with
            {
                Profiles = before.Profiles.Select(profile => profile.Name == "QuotaText"
                    ? profile with { Body = profile.Body + "x" } : profile).ToArray()
            }, CancellationToken.None));
        Expect(exactHandler.Writes == exactWrites,
            "A signature configuration over 3 MiB reached EWS before the byte quota rejected it.");
    }

    private static void SignatureHtmlSecurityChecks()
    {
        var logo = new SignatureImage("logo.png", "image/png", "logo", PngBase64(8));
        const string exchangeHtml = "<html><head><meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\"></head><body><div>draft&nbsp;word &lt;script&gt;alert(1)&lt;/script&gt;<br></div><img alt=\"quoted'>\" src=\"cid:logo\"></body></html>";
        var normalizedExchangeHtml = RichBody.NormalizeExchangeHtml(exchangeHtml);
        var normalizedDocument = XDocument.Parse("<root>" + normalizedExchangeHtml + "</root>");
        var normalizedText = normalizedDocument.Descendants()
            .Single(element => element.Name.LocalName.Equals("div", StringComparison.OrdinalIgnoreCase)).Value;
        var normalizedImage = normalizedDocument.Descendants()
            .Single(element => element.Name.LocalName.Equals("img", StringComparison.OrdinalIgnoreCase));
        Expect(!normalizedExchangeHtml.Contains("<meta", StringComparison.OrdinalIgnoreCase)
            && normalizedText == "draft\u00a0word <script>alert(1)</script>"
            && normalizedExchangeHtml.Contains("&lt;script&gt;alert(1)&lt;/script&gt;", StringComparison.Ordinal)
            && !normalizedDocument.Descendants().Any(element => element.Name.LocalName.Equals("script", StringComparison.OrdinalIgnoreCase))
            && normalizedExchangeHtml.Contains("<br />", StringComparison.Ordinal)
            && normalizedImage.Attribute("alt")?.Value == "quoted'>"
            && normalizedImage.Attribute("src")?.Value == "cid:logo"
            && RichBody.Validate(normalizedExchangeHtml, "HTML") == normalizedExchangeHtml,
            "Safe Exchange HTML was not normalized to a strict XHTML fragment while preserving text and CID image data.");
        foreach (var body in new[]
        {
            "<meta http-equiv=\"refresh\" content=\"0;url=https://evil.example\"><div>x</div>",
            "<meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\" name=\"extra\"><div>x</div>",
            "<meta http-equiv=\"Content-Type\" HTTP-EQUIV=\"Content-Type\" content=\"text/html; charset=utf-8\"><div>x</div>",
              "<div>x&copy;</div>",
              "<div>x&NBSP;</div>",
            "<script>alert(1)</script>",
            "<a href=\"javascript:alert(1)\">x</a>",
            "<img src=\"https://evil.example/image.png\">",
            "<div onclick=\"alert(1)\">x</div>"
        })
        {
            ExpectThrows<ArgumentException>(() => RichBody.NormalizeExchangeHtml(body),
                $"Unsafe Exchange HTML was normalized or accepted: {body}");
        }
        var invalidBodies = new[]
        {
            "<script>alert(1)</script>",
            "<div onclick=\"alert(1)\">x</div>",
            "<!DOCTYPE root [<!ENTITY xxe SYSTEM 'file:///secret'>]><div>&xxe;</div>",
            "<a href=\"javascript:alert(1)\">x</a>",
            "<div style=\"background-image:url(https://tracking.example.test/x)\">x</div>",
            "<div style=\"color:ex\\75ression(alert(1))\">x</div>",
            "<img src=\"https://tracking.example.test/logo.png\"/>",
            "<img src=\"cid:logo\" SRC=\"cid:logo\"/>"
        };
        foreach (var body in invalidBodies)
        {
            ExpectThrows<ArgumentException>(() => SignatureStore.Validate(
                new([new MailSignature("Unsafe", body, "HTML", [logo])], null, null)),
                $"Unsafe signature HTML was accepted: {body}");
        }

        SignatureStore.Validate(new([new MailSignature("Uppercase CID", "<IMG SRC=\"CID:logo\"/>", "HTML", [logo])], null, null));
        var nested = string.Concat(Enumerable.Repeat("<div>", 65)) + "x" + string.Concat(Enumerable.Repeat("</div>", 65));
        ExpectThrows<ArgumentException>(() => SignatureStore.Validate(
            new([new MailSignature("Deep", nested, "HTML", [])], null, null)),
            "Signature HTML nesting exceeded the configured depth limit.");
    }

    private static void SignatureAppendFullEnvelopeCheck()
    {
        const string current = "<html><head></head><body><div>draft<br /></div></body></html>";
        var signature = new MailSignature("Envelope", "<p>signature text</p>", "HTML", []);
        var appended = SignatureStore.Append(current, "HTML", signature);
        var document = XDocument.Parse("<root>" + appended + "</root>");
        var html = document.Root!.Elements().Single(element => element.Name.LocalName == "html");
        var body = html.Elements().Single(element => element.Name.LocalName == "body");
        var head = html.Elements().Single(element => element.Name.LocalName == "head");
        Expect(document.Root.Elements().Count() == 1
            && body.Descendants().Any(element => element.Value.Contains("signature text", StringComparison.Ordinal))
            && !head.Value.Contains("signature text", StringComparison.Ordinal),
            "Appending a signature to a full HTML envelope placed content outside the body.");
    }

    private static void SignatureReplyPlacementChecks()
    {
        var signature = new MailSignature("Reply", "<p id=\"signature\" dir=\"rtl\">امضا</p>", "HTML", []);
        var normalized = RichBody.NormalizeExchangeHtml(NativeReplyHtml);
        var reply = SignatureStore.Append(normalized, "HTML", signature, "reply");
        var root = XElement.Parse("<root>" + reply + "</root>");
        var body = root.Element("html")!.Element("body")!;
        var marker = body.Descendants("div").Single(element => (string?)element.Attribute("id") == "divRplyFwdMsg");
        var inserted = body.Element("p")!;
        Expect(root.Elements().Count() == 1 && inserted.Attribute("id")?.Value == "signature"
            && inserted.ElementsAfterSelf().First().Name.LocalName == "hr"
            && marker.ElementsBeforeSelf().Last().Name.LocalName == "hr"
            && body.Value.Contains("New reply.", StringComparison.Ordinal)
            && body.Value.Contains("Original.", StringComparison.Ordinal)
            && body.Value.Contains("From: senderSent: timeTo: recipientSubject: test", StringComparison.Ordinal)
            && body.Value.Contains('\u00a0') && inserted.Attribute("dir")?.Value == "rtl"
            && marker.Attribute("dir")?.Value == "ltr"
            && marker.Element("span")?.Attribute("style")?.Value == "color:#000000;font-family:Calibri, sans-serif;font-size:11pt"
            && body.Element("hr")?.Attribute("style")?.Value.Trim() == "width:98%",
            "The native Exchange reply fixture lost content, formatting, envelope or placement above the history separator.");
        var newBody = XElement.Parse(SignatureStore.Append(normalized, "HTML", signature)).Element("body")!;
        Expect(newBody.Elements().Last().Attribute("id")?.Value == "signature",
            "Context new stopped appending at the body end when a quote marker was present.");

        const string nested = "<div><p>Current divRplyFwdMsg text</p><hr /><p>Still current</p><div><p>Wrapper</p><hr /> \n<div id='divRplyFwdMsg'>Header</div><blockquote dir='rtl'><p>History</p><img src='cid:quoted'/><div id='divRplyFwdMsg'>Older header</div></blockquote></div></div>";
        var nestedRoot = XElement.Parse("<root>" + SignatureStore.Append(nested, "HTML", signature, "reply") + "</root>");
        var nestedSignature = nestedRoot.Descendants("p").Single(element => (string?)element.Attribute("id") == "signature");
        var firstMarker = nestedRoot.Descendants("div").First(element => (string?)element.Attribute("id") == "divRplyFwdMsg");
        Expect(nestedSignature.Parent == firstMarker.Parent
            && nestedSignature.ElementsAfterSelf().First().Name.LocalName == "hr"
            && nestedRoot.Elements().Single().Elements().ElementAt(2).Value == "Still current"
            && nestedRoot.Descendants("blockquote").Single().Attribute("dir")?.Value == "rtl"
            && nestedRoot.Descendants("img").Single().Attribute("src")?.Value == "cid:quoted"
            && nestedRoot.Descendants("div").Count(element => (string?)element.Attribute("id") == "divRplyFwdMsg") == 2,
            "Reply placement matched unrelated text/hr, chose an older nested marker, or changed history/CID structure.");
        var noHr = SignatureStore.Append("<p>Current</p><div id='divRplyFwdMsg'>Header</div><p>History</p>", "HTML", signature, "reply");
        Expect(XElement.Parse("<root>" + noHr + "</root>").Elements().ElementAt(2).Attribute("id")?.Value == "signature",
            "A marker without a separator did not receive the signature immediately before it.");
        foreach (var unmarked in new[] { "<p>Current divRplyFwdMsg text</p><hr /><p>End</p>", "<div id='other'>Current</div>" })
            Expect(XElement.Parse("<root>" + SignatureStore.Append(unmarked, "HTML", signature, "reply") + "</root>")
                    .Elements().Last().Attribute("id")?.Value == "signature",
                "An unmarked reply did not retain append fallback behavior.");
        Expect(SignatureStore.Append("Current\r\nHistory", "Text", new("Plain", "Signature", "Text", []), "reply")
                == "Current\r\nHistory\r\n\r\nSignature",
            "Text reply signature behavior changed.");
        ExpectThrows<ArgumentException>(() => RichBody.Validate(NativeReplyHtml, "HTML"),
            "General HTML validation began accepting Exchange-only wrappers.");
    }

    private async Task SignatureApplyNativeReplyCheckAsync()
    {
        var handler = new SignatureRecordingHandler { ApplyMode = true, ApplyHtmlBody = NativeReplyHtml };
        var exchange = NewEwsClient(handler);
        var store = new SignatureStore();
        var image = new SignatureImage("signature.png", "image/png", "signature-logo", PngBase64(8));
        await store.UpdateAsync(exchange, "alice@example.test", "new", _ => new(
            [new MailSignature("Default reply", "<p id=\"applied-signature\">Reply signature</p><img src=\"cid:signature-logo\"/>", "HTML", [image])],
            null, "Default reply"), CancellationToken.None);
        var options = Options.Create(new ServiceOptions
        {
            AllowedClientIds = ["checks"],
            Mailboxes = new() { ["user-a"] = "alice@example.test" },
            WritesEnabled = true,
            AuditPath = Path.Combine(runDirectory, "signature-native-reply-audit.jsonl")
        });
        using var audit = new AuditLog(options);
        var handles = new MailboxHandles(new EphemeralDataProtectionProvider());
        var tools = new SignatureTools(exchange, new MailboxAccess(options), handles, audit, store);
        var draft = handles.Issue(new("user-a", "alice@example.test", "checks"), "message", "draft-1", "draft-0");
        var result = JsonSerializer.SerializeToElement(await tools.Apply(SyncUser("user-a", "mail.write"), draft,
            CancellationToken.None, context: "reply"));
        var operation = handler.Operations.Single(element => element.Name.LocalName == "UpdateItem");
        var sentBody = operation.Descendants(XName.Get("Body", TypesNamespace)).Single();
        var html = XElement.Parse(sentBody.Value);
        var body = html.Element("body")!;
        Expect(result.GetProperty("signature").GetString() == "Default reply"
            && sentBody.Attribute("BodyType")?.Value == "HTML"
            && body.Element("p")?.Attribute("id")?.Value == "applied-signature"
            && body.Elements().ToList().FindIndex(element => element.Name.LocalName == "img")
                < body.Elements().ToList().FindIndex(element => element.Name.LocalName == "hr")
            && handler.DraftUpdates == 1 && handler.AttachmentCreates == 1
            && operation.Descendants(XName.Get("ItemId", TypesNamespace)).Single().Attribute("ChangeKey")?.Value == "draft-0",
            "Native default-reply apply required manual cleanup, ignored the current ChangeKey, or wrote outside the envelope/history boundary.");

        foreach (var unsafeHtml in new[]
        {
            "<script>alert(1)</script>", "<img src='https://external.example/image.png'>",
            "<div onclick='alert(1)'>x</div>",
            "<font face='Calibri' onload='alert(1)'>x</font>",
            "<font face='Calibri' FACE='Arial'>x</font>",
            "<font xmlns:x='urn:unsafe' x:style='color:red'>x</font>",
            "<font style='background-image:url(https://external.example)'>x</font>",
            "<div>malformed", "<meta http-equiv='refresh' content='0;url=https://external.example'>"
        })
        {
            handler.ApplyHtmlBody = NativeReplyHtml.Replace("Original.", unsafeHtml, StringComparison.Ordinal);
            var updates = handler.DraftUpdates;
            var attachments = handler.AttachmentCreates;
            // A fresh handle matches the read-only handler's current revision after its attachment refresh.
            var current = handles.Issue(new("user-a", "alice@example.test", "checks"), "message", "draft-1", "draft-after-1");
            await AssertThrowsAsync<ArgumentException>(() => tools.Apply(SyncUser("user-a", "mail.write"), current,
                CancellationToken.None, context: "reply"));
            Expect(handler.DraftUpdates == updates && handler.AttachmentCreates == attachments,
                "Unsafe or malformed quoted history reached EWS draft/attachment writes.");
        }
    }

    private async Task SignatureToolNormalizationCheckAsync()
    {
        var handler = new SignatureRecordingHandler();
        var exchange = NewEwsClient(handler);
        var options = Options.Create(new ServiceOptions
        {
            AllowedClientIds = ["checks"],
            Mailboxes = new() { ["user-a"] = "alice@example.test" },
            WritesEnabled = true,
            AuditPath = Path.Combine(runDirectory, "signature-tools-audit.jsonl")
        });
        using var audit = new AuditLog(options);
        var tools = new SignatureTools(exchange, new MailboxAccess(options),
            new MailboxHandles(new EphemeralDataProtectionProvider()), audit, new SignatureStore());
        var initial = await new SignatureStore().ReadAsync(exchange, "alice@example.test", CancellationToken.None);
        const string raw = "<DIV class=\"brand\"><P>Hello &amp; <B>team</B></P></DIV>";
        var result = (SignatureSnapshot)await tools.Save(SyncUser("user-a", "mail.write"), initial.Revision,
            "Normalized", raw, CancellationToken.None, "html");
        var saved = result.Settings.Profiles.Single(profile => profile.Name == "Normalized");
        Expect(saved.BodyType == "HTML" && saved.Body == RichBody.Validate(raw, "HTML")
            && !saved.Body.Contains("<script", StringComparison.OrdinalIgnoreCase),
            "mail_save_signature did not persist a normalized safe HTML fragment.");
        await AssertThrowsAsync<ArgumentException>(() => tools.Save(SyncUser("user-a", "mail.write"), result.Revision,
            "Reject meta", "<meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\"><div>x</div>",
            CancellationToken.None, "html"));
        Expect(handler.Writes == 1,
            "A strict pasted signature containing Exchange-only metadata reached the UserConfiguration write.");
    }

    private async Task SignatureApplyAttachmentRefreshCheckAsync()
    {
        var handler = new SignatureRecordingHandler
        {
            ApplyMode = true,
            ApplyHtmlBody = "<html><head><meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\"></head><body><div>draft<br></div></body></html>"
        };
        var exchange = NewEwsClient(handler);
        var store = new SignatureStore();
        var images = Enumerable.Range(0, 2)
            .Select(index => new SignatureImage($"apply-{index}.png", "image/png", $"apply-{index}", PngBase64(8)))
            .ToArray();
        var body = string.Concat(images.Select(image => $"<img src=\"cid:{image.ContentId}\"/>"));
        await store.UpdateAsync(exchange, "alice@example.test", "new", _ => new(
            [new MailSignature("With images", body, "HTML", images)], "With images", null), CancellationToken.None);

        var options = Options.Create(new ServiceOptions
        {
            AllowedClientIds = ["checks"],
            Mailboxes = new() { ["user-a"] = "alice@example.test" },
            WritesEnabled = true,
            AuditPath = Path.Combine(runDirectory, "signature-apply-audit.jsonl")
        });
        using var audit = new AuditLog(options);
        var protection = new EphemeralDataProtectionProvider();
        var handles = new MailboxHandles(protection);
        var tools = new SignatureTools(exchange, new MailboxAccess(options), handles, audit, store);
        var identity = new MailboxIdentity("user-a", "alice@example.test", "checks");
        var draftHandle = handles.Issue(identity, "message", "draft-1", "draft-0");
        var result = await tools.Apply(SyncUser("user-a", "mail.write"), draftHandle, CancellationToken.None,
            "With images", "new");
        var resultJson = JsonSerializer.SerializeToElement(result);
        var returnedHandle = resultJson.GetProperty("handle").GetString()!;
        var returned = handles.Resolve(identity, "message", returnedHandle);

        Expect(resultJson.GetProperty("status").GetString() == "signature_applied"
            && returned.Id == "draft-1" && returned.ChangeKey == "draft-after-2"
            && handler.MessageReads == 3 && handler.DraftUpdates == 1 && handler.AttachmentCreates == 2,
            "Applying a two-image signature did not refresh an empty attachment parent ChangeKey.");
        var messages = XNamespace.Get(MessagesNamespace);
        var attachmentOperations = handler.Operations.Where(operation => operation.Name.LocalName == "CreateAttachment").ToArray();
        Expect(attachmentOperations.Length == 2
            && (string?)attachmentOperations[0].Descendants(messages + "ParentItemId").Single().Attribute("ChangeKey") == "draft-update"
            && (string?)attachmentOperations[1].Descendants(messages + "ParentItemId").Single().Attribute("ChangeKey") == "draft-after-1",
            "The second inline signature image did not use the refreshed draft ChangeKey.");
    }

    private async Task SignatureApplyContentIdCollisionCheckAsync()
    {
        var handler = new SignatureRecordingHandler
        {
            ApplyMode = true,
            ExistingContentId = "APPLY-0",
            ApplyHtmlBody = "<html><head><meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\"></head><body><div>draft<br></div></body></html>"
        };
        var exchange = NewEwsClient(handler);
        var store = new SignatureStore();
        var image = new SignatureImage("apply.png", "image/png", "apply-0", PngBase64(8));
        await store.UpdateAsync(exchange, "alice@example.test", "new", _ => new(
            [new MailSignature("Collision", "<img src=\"cid:apply-0\"/>", "HTML", [image])], "Collision", null), CancellationToken.None);

        var options = Options.Create(new ServiceOptions
        {
            AllowedClientIds = ["checks"],
            Mailboxes = new() { ["user-a"] = "alice@example.test" },
            WritesEnabled = true,
            AuditPath = Path.Combine(runDirectory, "signature-collision-audit.jsonl")
        });
        using var audit = new AuditLog(options);
        var handles = new MailboxHandles(new EphemeralDataProtectionProvider());
        var tools = new SignatureTools(exchange, new MailboxAccess(options), handles, audit, store);
        var identity = new MailboxIdentity("user-a", "alice@example.test", "checks");
        var draftHandle = handles.Issue(identity, "message", "draft-1", "draft-0");
        await AssertThrowsAsync<McpException>(() => tools.Apply(SyncUser("user-a", "mail.write"), draftHandle,
            CancellationToken.None, "Collision", "new"));
        Expect(handler.DraftUpdates == 0 && handler.AttachmentCreates == 0,
            "A case-variant existing inline CID was not rejected before draft or attachment writes.");
    }

    private static SignatureSettings CreateExactQuotaSettings()
    {
        var images = Enumerable.Range(0, 8)
            .Select(index => new SignatureImage($"q{index}.png", "image/png", $"q{index}", PngBase64(262_144)))
            .ToArray();
        var imageBody = string.Concat(images.Select(image => $"<img src=\"cid:{image.ContentId}\"/>"));
        var fixedProfiles = new List<MailSignature>
        {
            new("QuotaImages", imageBody, "HTML", images),
            new("Escaped", "Quotes: \"quoted\" \\ slash Ω\r\n\t", "Text", []),
            new("FillerA", new string('f', 65_536), "Text", []),
            new("FillerB", new string('g', 65_536), "Text", []),
            new("FillerC", new string('h', 65_536), "Text", []),
            new("FillerD", new string('i', 65_536), "Text", []),
            new("FillerE", new string('j', 65_536), "Text", [])
        };
        var prefix = "quota ";
        var low = 0;
        var high = 65_536;
        while (low <= high)
        {
            var middle = low + ((high - low) / 2);
            var settings = new SignatureSettings(fixedProfiles.Append(
                new MailSignature("QuotaText", prefix + new string('x', middle), "Text", [])).ToArray(), null, null);
            var length = JsonSerializer.SerializeToUtf8Bytes(settings).Length;
            if (length == SignatureStore.MaxSerializedBytes) return settings;
            if (length < SignatureStore.MaxSerializedBytes) low = middle + 1;
            else high = middle - 1;
        }
        throw new InvalidOperationException("Could not construct the exact 3 MiB signature quota fixture.");
    }

    private static string PngBase64(int size)
    {
        var bytes = new byte[size];
        new byte[] { 137, 80, 78, 71, 13, 10, 26, 10 }.CopyTo(bytes, 0);
        return Convert.ToBase64String(bytes);
    }

    private static void ExpectThrows<TException>(Action action, string message) where TException : Exception
    {
        try { action(); }
        catch (TException) { return; }
        throw new InvalidOperationException(message);
    }

}

internal sealed class SignatureRecordingHandler : HttpMessageHandler
{
    private static readonly XNamespace S = "http://schemas.xmlsoap.org/soap/envelope/";
    private static readonly XNamespace M = "http://schemas.microsoft.com/exchange/services/2006/messages";
    private static readonly XNamespace T = "http://schemas.microsoft.com/exchange/services/2006/types";
    public List<XElement> Operations { get; } = [];
    public int Writes { get; private set; }
    public int ConfigurationBytes => data is null ? 0 : Convert.FromBase64String(data).Length;
    public bool ApplyMode { get; init; }
    public string? ExistingContentId { get; init; }
    public string ApplyHtmlBody { get; set; } = "<div>draft</div>";
    public string[] ApplyTo { get; set; } = [];
    public string[] ApplyCc { get; set; } = [];
    public string[] ApplyBcc { get; set; } = [];
    public int MessageReads { get; private set; }
    public int DraftUpdates { get; private set; }
    public int AttachmentCreates { get; private set; }
    public string DraftChangeKey { get; private set; } = "draft-0";
    public string? Error { get; set; }
    public bool IncludeFault { get; set; }
    private string? data;
    private readonly List<XElement> createdAttachments = [];

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var document = XDocument.Parse(await request.Content!.ReadAsStringAsync(cancellationToken));
        var operation = document.Root!.Element(S + "Body")!.Elements().Single();
        Operations.Add(new(operation));
        var name = operation.Name.LocalName;
        var error = Error ?? (name == "GetUserConfiguration" && data is null ? "ErrorItemNotFound" : null);
        XElement? config = null;
        if (error is null)
        {
            if (name is "CreateUserConfiguration" or "UpdateUserConfiguration")
            { data = operation.Descendants(T + "BinaryData").Single().Value; Writes++; }
            else if (ApplyMode && name == "GetItem")
            {
                MessageReads++;
                config = new(T + "Message",
                    new XElement(T + "ItemId", new XAttribute("Id", "draft-1"), new XAttribute("ChangeKey", DraftChangeKey)),
                    new XElement(T + "Subject", "Draft"),
                    new XElement(T + "IsDraft", true),
                    new XElement(T + "ToRecipients", ApplyTo.Select(address => new XElement(T + "Mailbox", new XElement(T + "EmailAddress", address)))),
                    new XElement(T + "CcRecipients", ApplyCc.Select(address => new XElement(T + "Mailbox", new XElement(T + "EmailAddress", address)))),
                    new XElement(T + "BccRecipients", ApplyBcc.Select(address => new XElement(T + "Mailbox", new XElement(T + "EmailAddress", address)))),
                    new XElement(T + "Body", new XAttribute("BodyType", "HTML"), ApplyHtmlBody),
                    new XElement(T + "Attachments", ExistingContentId is null ? null : new XElement(T + "FileAttachment",
                        new XElement(T + "AttachmentId", new XAttribute("Id", "existing-attachment")),
                        new XElement(T + "Name", "existing.png"),
                        new XElement(T + "Size", 8),
                        new XElement(T + "ContentType", "image/png"),
                        new XElement(T + "ContentId", ExistingContentId),
                        new XElement(T + "IsInline", true)), createdAttachments.Select(attachment => new XElement(T + "FileAttachment",
                            attachment.Elements().Where(element => element.Name != T + "Content").Select(element => new XElement(element))))));
            }
            else if (ApplyMode && name == "UpdateItem")
            {
                DraftUpdates++;
                ApplyHtmlBody = operation.Descendants(T + "Body").Single().Value;
                DraftChangeKey = "draft-update";
                config = new(T + "Message",
                    new XElement(T + "ItemId", new XAttribute("Id", "draft-1"), new XAttribute("ChangeKey", "draft-update")));
            }
            else if (ApplyMode && name == "CreateAttachment")
            {
                AttachmentCreates++;
                DraftChangeKey = $"draft-after-{AttachmentCreates}";
                var file = new XElement(operation.Descendants(T + "FileAttachment").Single());
                file.AddFirst(new XElement(T + "AttachmentId", new XAttribute("Id", $"attachment-{AttachmentCreates}")));
                file.Add(new XElement(T + "Size", Convert.FromBase64String(file.Element(T + "Content")!.Value).Length));
                createdAttachments.Add(file);
                var attachmentId = new XElement(T + "AttachmentId",
                    new XAttribute("Id", $"attachment-{AttachmentCreates}"),
                    new XAttribute("RootItemId", "draft-1"));
                if (AttachmentCreates == 2)
                    attachmentId.Add(new XAttribute("RootItemChangeKey", "draft-after-2"));
                config = new(T + "FileAttachment", attachmentId);
            }
            else if (ApplyMode && name == "GetAttachment")
            {
                var id = operation.Descendants(T + "AttachmentId").Single().Attribute("Id")!.Value;
                config = new(M + "Attachments", new XElement(createdAttachments.Single(attachment => attachment.Element(T + "AttachmentId")!.Attribute("Id")!.Value == id)));
            }
            else config = new(M + "UserConfiguration", new XElement(T + "BinaryData", data));
        }
        var response = new XDocument(new XElement(S + "Envelope", new XElement(S + "Body",
            new XElement(M + (name + "Response"), new XElement(M + "ResponseMessages",
                new XElement(M + (name + "ResponseMessage"), new XAttribute("ResponseClass", error is null ? "Success" : "Error"),
                    new XElement(M + "ResponseCode", error ?? "NoError"), config))))));
        if (IncludeFault) response.Root!.Element(S + "Body")!.Add(new XElement(S + "Fault"));
        return new(HttpStatusCode.OK) { Content = new StringContent(response.ToString(), Encoding.UTF8, "text/xml") };
    }
}
