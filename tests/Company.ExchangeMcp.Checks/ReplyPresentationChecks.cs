using System.Net;
using System.Text;
using System.Xml.Linq;
using System.Xml.Schema;
using Company.ExchangeMcp;
using Company.ExchangeMcp.Exchange;
using Company.ExchangeMcp.Security;

internal sealed partial class Checks
{
    private async Task ReplyPresentationChecksAsync()
    {
        foreach (var setting in new[] { "Iran Standard Time", "UTC", "Unknown/Invalid", "", "denied" })
        {
            var handler = new ReplyPresentationHandler { TimeZone = setting };
            var client = NewEwsClient(handler);
            var original = await client.GetMessageAsync("alice@example.test", "source", CancellationToken.None);
            Expect(original.From == "sender@example.test" && original.To.SequenceEqual(["to@example.test"])
                && original.SenderIdentity?.Address == "delegate@example.test" && original.FromIdentity?.Name == "فرستنده <script>"
                && original.SentUtc == "2026-10-19T10:03:11.0000000+00:00"
                && original.ReceivedUtc != original.SentUtc && original.Importance == "High",
                "Original rich metadata was flattened, replaced Sent with Received, or changed the scalar recipient semantics.");
            Expect(SendGuard.Digest(original) == SendGuard.Digest(original with
            {
                FromIdentity = null,
                SenderIdentity = null,
                ToIdentities = [],
                CcIdentities = [],
                SentUtc = null,
                Importance = null
            }), "Presentation-only metadata changed the existing send approval digest contract.");
            const string submitted = "<div dir='rtl'>پاسخ <b>new</b></div>";
            _ = EwsClient.FormatReplyHeader(ReplyPresentationHandler.NativeBody("fixture-nonce", submitted), original,
                "fixture-nonce", submitted, TimeZoneInfo.Utc);
            var result = await client.ReplyDraftAsync("alice@example.test", original.Id, original.ChangeKey, submitted, false,
                CancellationToken.None, "HTML", source: new("alice@example.test", original));
            Expect(result.Id == "draft" && result.ChangeKey == "updated" && result.PresentationWarning is null,
                "A verifiable native HTML reply did not complete its bounded header update.");
            var created = handler.Operations.Single(operation => operation.Name.LocalName == "CreateItem");
            Expect(created.Descendants(XName.Get("ReplyToItem", TypesNamespace)).Count() == 1
                && created.Descendants(XName.Get("ReferenceItemId", TypesNamespace)).Single().Attribute("Id")?.Value == "source"
                && created.Descendants(XName.Get("ReferenceItemId", TypesNamespace)).Single().Attribute("ChangeKey")?.Value == "source-key",
                "Header presentation lost the native reply relationship/source revision.");
            var update = handler.Operations.Single(operation => operation.Name.LocalName == "UpdateItem");
            Expect(update.Attribute("ConflictResolution")?.Value == "NeverOverwrite"
                && update.Descendants(XName.Get("SetItemField", TypesNamespace)).Count() == 1
                && update.Descendants(XName.Get("FieldURI", TypesNamespace)).Single().Attribute("FieldURI")?.Value == "item:Body"
                && update.Descendants(XName.Get("ItemId", TypesNamespace)).Single().Attribute("ChangeKey")?.Value == "fresh-key",
                "Header presentation rewrote recipients/subject/sender or failed to use the freshly read draft revision.");
            var html = update.Descendants(XName.Get("Body", TypesNamespace)).Single().Value;
            var root = XElement.Parse(html);
            var header = root.Descendants("div").First(element => (string?)element.Attribute("id") == "divRplyFwdMsg");
            var history = root.Descendants("div").Single(element => (string?)element.Attribute("id") == "old-history");
            Expect(header.Value.Contains("فرستنده <script>", StringComparison.Ordinal)
                && !header.Descendants("script").Any() && header.Value.Contains("Subject: Subject <unsafe>", StringComparison.Ordinal)
                && header.Value.Contains("Sender: Delegate", StringComparison.Ordinal)
                && header.Value.Contains("Importance: High", StringComparison.Ordinal)
                && !header.Value.Contains("hidden@example.test", StringComparison.Ordinal)
                && header.Descendants("a").All(link => link.Attribute("dir")?.Value == "ltr")
                && header.Descendants("a").Any(link => link.Attribute("href")?.Value == "mailto:sender@example.test")
                && header.Value.Contains(setting == "Iran Standard Time" ? "13:33:11 +03:30 (Iran Standard Time)" : "10:03:11 +00:00 (UTC)", StringComparison.Ordinal)
                && history.Attribute("dir")?.Value == "rtl" && history.Value.Contains("قدیمی", StringComparison.Ordinal)
                && history.Descendants("img").Single().Attribute("src")?.Value == "cid:old-logo"
                && !html.Contains("company-reply-", StringComparison.Ordinal),
                "Reply header content, timezone, safe encoding, Bcc privacy, quote/CID preservation, or nonce cleanup failed.");
            var withSignature = SignatureStore.AppendToExchangeHtml(html, new("Default", "<p id='signature'>Signature</p>", "HTML", []), "reply");
            Expect(withSignature.IndexOf("id=\"signature\"", StringComparison.Ordinal)
                < withSignature.IndexOf("<hr", StringComparison.Ordinal), "Default reply signature stopped preceding the native quote separator.");
            var optionsRead = handler.Operations.Single(operation => operation.Name.LocalName == "GetUserConfiguration");
            Expect(optionsRead.Descendants(XName.Get("UserConfigurationName", MessagesNamespace)).Single().Attribute("Name")?.Value == "OWA.UserOptions"
                && optionsRead.Descendants(XName.Get("DistinguishedFolderId", TypesNamespace)).Single().Attribute("Id")?.Value == "root"
                && optionsRead.Element(XName.Get("UserConfigurationProperties", MessagesNamespace))?.Value == "Dictionary",
                "Reply formatting read an unrelated mailbox configuration or a non-Dictionary property.");
            ValidateReplyPresentationSchema(handler.Operations);
        }

        foreach (var newline in new[] { "\r\n", "\n", "\r" })
        {
            var handler = new ReplyPresentationHandler();
            var client = NewEwsClient(handler);
            var source = await client.GetMessageAsync("alice@example.test", "source", CancellationToken.None);
            var result = await client.ReplyDraftAsync("alice@example.test", source.Id, source.ChangeKey,
                "پاسخ <literal> &" + newline + "Second line", true, CancellationToken.None,
                source: new("alice@example.test", source));
            var create = handler.Operations.Single(operation => operation.Name.LocalName == "CreateItem");
            var authored = create.Descendants(XName.Get("NewBodyContent", TypesNamespace)).Single();
            var html = handler.Operations.Single(operation => operation.Name.LocalName == "UpdateItem")
                .Descendants(XName.Get("Body", TypesNamespace)).Single().Value;
            var root = XElement.Parse(html);
            Expect(result.PresentationWarning is null && authored.Attribute("BodyType")?.Value == "HTML"
                && authored.Value.Contains("&lt;literal&gt; &amp;<br />", StringComparison.Ordinal)
                && root.Value.Contains("پاسخ <literal> &", StringComparison.Ordinal)
                && root.Descendants("table").Single().Attribute("style")?.Value == "font-family:Peyda;font-size:12pt"
                && root.Descendants("img").Single().Attribute("src")?.Value == "cid:old-logo"
                && create.Descendants(XName.Get("ReplyAllToItem", TypesNamespace)).Count() == 1
                && !handler.Operations.Any(operation => operation.Name.LocalName is "CreateAttachment" or "GetAttachment"),
                "A Text-authored native reply flattened an HTML source, interpreted literal markup, lost its quote image, or copied attachments.");
        }

        foreach (var failure in new[] { "source-image-missing", "source-image-not-inline", "draft-image-missing", "draft-image-not-inline", "duplicate-image", "changed-image", "missing-quoted-image", "source-body-missing" })
            foreach (var forward in new[] { false, true })
            {
                var handler = new ReplyPresentationHandler { Failure = failure };
                var client = NewEwsClient(handler);
                var source = await client.GetMessageAsync("alice@example.test", "source", CancellationToken.None);
                if (failure == "source-body-missing") source = source with { Body = null };
                var result = forward
                    ? await client.ForwardDraftAsync("alice@example.test", source.Id, source.ChangeKey, "Forward", ["to@example.test"], [], [],
                        CancellationToken.None, source: new("alice@example.test", source))
                    : await client.ReplyDraftAsync("alice@example.test", source.Id, source.ChangeKey, "Reply", false,
                        CancellationToken.None, source: new("alice@example.test", source));
                Expect(result.PresentationWarning?.Contains("(phase: quoted_images)", StringComparison.Ordinal) == true
                    && result.Id == "draft" && result.ChangeKey == "fresh-key"
                    && handler.Operations.Count(operation => operation.Name.LocalName == "CreateItem") == 1
                    && !handler.Operations.Any(operation => operation.Name.LocalName is "UpdateItem" or "CreateAttachment" or "GetAttachment"),
                    "A missing, ambiguous, altered or non-inline quoted image did not retain one incomplete draft before any rewrite.");
            }

        var legacyHandler = new ReplyPresentationHandler();
        await NewEwsClient(legacyHandler).ReplyDraftAsync("alice@example.test", "source", "source-key", "<literal> & text", false, CancellationToken.None);
        Expect(legacyHandler.Operations.Count == 1
            && legacyHandler.Operations.Single().Descendants(XName.Get("NewBodyContent", TypesNamespace)).Single() is { } legacyBody
            && legacyBody.Attribute("BodyType")?.Value == "Text" && legacyBody.Value == "<literal> & text",
            "Legacy source-null SDK replies changed their Text wire contract.");
        var legacyForwardHandler = new ReplyPresentationHandler();
        await NewEwsClient(legacyForwardHandler).ForwardDraftAsync("alice@example.test", "source", "source-key", "<literal> & text",
            ["to@example.test"], [], [], CancellationToken.None);
        Expect(legacyForwardHandler.Operations.Count == 1
            && legacyForwardHandler.Operations.Single().Descendants(XName.Get("NewBodyContent", TypesNamespace)).Single() is { } legacyForwardBody
            && legacyForwardBody.Attribute("BodyType")?.Value == "Text" && legacyForwardBody.Value == "<literal> & text",
            "Legacy source-null SDK forwards changed their Text wire contract.");

        var plainHandler = new ReplyPresentationHandler();
        var plainClient = NewEwsClient(plainHandler);
        var plainSource = (await plainClient.GetMessageAsync("alice@example.test", "source", CancellationToken.None)) with { BodyType = "Text", Body = "Original <literal>" };
        var plainResult = await plainClient.ReplyDraftAsync("alice@example.test", plainSource.Id, plainSource.ChangeKey, "Reply <literal> &", false,
            CancellationToken.None, source: new("alice@example.test", plainSource));
        var plainBody = plainHandler.Operations.Single(operation => operation.Name.LocalName == "CreateItem")
            .Descendants(XName.Get("NewBodyContent", TypesNamespace)).Single();
        Expect(plainResult.PresentationWarning is null && plainBody.Attribute("BodyType")?.Value == "Text" && plainBody.Value == "Reply <literal> &"
            && plainHandler.Operations.Count == 2, "A supplied plaintext source was promoted or interpreted as HTML.");

        foreach (var forward in new[] { false, true })
        {
            var handler = new ReplyPresentationHandler { OfficeEnvelope = true };
            var client = NewEwsClient(handler);
            var source = await client.GetMessageAsync("alice@example.test", "source", CancellationToken.None);
            var result = forward
                ? await client.ForwardDraftAsync("alice@example.test", source.Id, source.ChangeKey, "Forward <literal> &\r\nSecond line",
                    ["forward@example.test"], ["cc@example.test"], ["bcc@example.test"], CancellationToken.None, source: new("alice@example.test", source))
                : await client.ReplyDraftAsync("alice@example.test", source.Id, source.ChangeKey, "Reply <literal> &\r\nSecond line", false,
                    CancellationToken.None, source: new("alice@example.test", source));
            var create = handler.Operations.Single(operation => operation.Name.LocalName == "CreateItem");
            var update = handler.Operations.Single(operation => operation.Name.LocalName == "UpdateItem");
            var html = update.Descendants(XName.Get("Body", TypesNamespace)).Single().Value;
            var root = RichBody.ParseExchangeHtml(html);
            Expect(result.PresentationWarning is null && result.ChangeKey == "updated"
                && create.Descendants(XName.Get(forward ? "ForwardItem" : "ReplyToItem", TypesNamespace)).Count() == 1
                && create.Descendants(XName.Get("NewBodyContent", TypesNamespace)).Single().Attribute("BodyType")?.Value == "HTML"
                && html.Contains("mso-style-name", StringComparison.Ordinal) && html.Contains("@page WordSection1", StringComparison.Ordinal)
                && root.Descendants().Any(element => element.Name.LocalName == "p" && element.Name.NamespaceName == "urn:schemas-microsoft-com:office:office")
                && root.Value.Contains(forward ? "Forward <literal> &" : "Reply <literal> &", StringComparison.Ordinal)
                && root.Descendants("img").Single().Attribute("src")?.Value == "cid:old-logo"
                && !html.Contains(forward ? "company-forward-" : "company-reply-", StringComparison.Ordinal)
                && !handler.Operations.Any(operation => operation.Name.LocalName is "CreateAttachment" or "GetAttachment")
                && update.Descendants(XName.Get("SetItemField", TypesNamespace)).Count() == 1
                && update.Descendants(XName.Get("FieldURI", TypesNamespace)).Single().Attribute("FieldURI")?.Value == "item:Body",
                "A native Office HTML reply/forward lost its passive Word document, literal authored text, CID, native relationship, or body-only update.");
            if (forward)
            {
                var native = await client.GetMessageAsync("alice@example.test", "draft", CancellationToken.None);
                Expect(native.Attachments.Any(attachment => attachment.Name == "report.pdf" && !attachment.IsInline)
                    && create.Descendants(XName.Get("ToRecipients", TypesNamespace)).Single().Value == "forward@example.test"
                    && create.Descendants(XName.Get("CcRecipients", TypesNamespace)).Single().Value == "cc@example.test"
                    && create.Descendants(XName.Get("BccRecipients", TypesNamespace)).Single().Value == "bcc@example.test",
                    "Native forwarding lost ordinary attachments or explicit recipients.");
            }
            ValidateReplyPresentationSchema(handler.Operations);
        }

        foreach (var failure in new[] { "missing-header", "duplicate-nonce", "changed-body", "unsafe-history", "update-failure", "read-failure", "changed-revision" })
            foreach (var forward in new[] { false, true })
            {
                var handler = new ReplyPresentationHandler { Failure = failure };
                var client = NewEwsClient(handler);
                var source = await client.GetMessageAsync("alice@example.test", "source", CancellationToken.None);
                var retained = forward
                    ? await client.ForwardDraftAsync("alice@example.test", source.Id, source.ChangeKey, "<p>Forward</p>", ["to@example.test"], [], [],
                        CancellationToken.None, "HTML", source: new("alice@example.test", source))
                    : await client.ReplyDraftAsync("alice@example.test", source.Id, source.ChangeKey, "<p>Reply</p>", false,
                        CancellationToken.None, "HTML", source: new("alice@example.test", source));
                Expect(retained.Id == "draft" && retained.PresentationWarning?.Contains("do not create another reply", StringComparison.Ordinal) == true
                    && handler.Operations.Count(operation => operation.Name.LocalName == "CreateItem") == 1
                    && handler.Operations.Count(operation => operation.Name.LocalName == "UpdateItem") == (failure == "update-failure" ? 1 : 0),
                    "An ambiguous/unsafe/failed native header was overwritten, lost its retained draft, or retried creation.");
                Expect(retained.ChangeKey == (failure == "changed-revision" ? "concurrent-key" : "fresh-key"),
                    "A retained draft warning did not preserve its latest known ChangeKey.");
                var expectedPhase = failure == "read-failure" ? "draft_read" : failure == "changed-revision" ? "revision_check"
                    : failure == "update-failure" ? "header_write" : "header_format";
                Expect(retained.PresentationWarning!.Contains("(phase: " + expectedPhase + ")", StringComparison.Ordinal),
                    "A retained draft warning lacked a bounded diagnostic phase.");
            }

        var bindingHandler = new ReplyPresentationHandler();
        var bindingClient = NewEwsClient(bindingHandler);
        var snapshot = await bindingClient.GetMessageAsync("alice@example.test", "source", CancellationToken.None);
        foreach (var badSource in new[] { new EwsReplySource("other@example.test", snapshot), new EwsReplySource("alice@example.test", snapshot with { Id = "other" }), new EwsReplySource("alice@example.test", snapshot with { ChangeKey = "stale" }) })
        {
            await AssertThrowsAsync<ArgumentException>(() => bindingClient.ReplyDraftAsync("alice@example.test", "source", "source-key", "<p>Reply</p>", false,
                CancellationToken.None, "HTML", source: badSource));
            await AssertThrowsAsync<ArgumentException>(() => bindingClient.ForwardDraftAsync("alice@example.test", "source", "source-key", "Forward",
                ["to@example.test"], [], [], CancellationToken.None, source: badSource));
        }
        Expect(bindingHandler.Operations.Count == 1, "A mismatched mailbox/source ID/revision reached EWS before validation.");

        const string nonce = "company-reply-test";
        const string liveSubmitted = "<p>This is a <b>native HTML reply</b> with my default signature above the original header.</p><p>Keep this conversation for inspection in Outlook.</p>";
        const string liveReturned = "\r\n<p>This is a <b>native HTML reply</b> with my default signature above the original header.</p>\r\n<p>Keep this conversation for inspection in Outlook.</p>\r\n";
        var liveBody = "<html>\r\n<head><meta http-equiv='Content-Type' content='text/html; charset=utf-8'><meta content='text/html; charset=us-ascii'></head>\r\n<body>\r\n<div id='" + nonce + "'>" + liveReturned
            + "</div>\r\n<hr tabindex='-1' style='display:inline-block; width:98%'>\r\n<div id='divRplyFwdMsg' dir='ltr'><font face='Calibri, sans-serif' color='#000000' style='font-size:11pt'><b>From:</b> alias<br>\r\n<b>Sent:</b> Monday, time<br>\r\n<b>To:</b> Alice Example<br>\r\n<b>Subject:</b> test</font>\r\n<div>&nbsp;</div>\r\n</div>\r\n<div>\r\n<p>original</p>\r\n<p>keep</p>\r\n</div>\r\n</body>\r\n</html>\r\n";
        var liveFormatted = EwsClient.FormatReplyHeader(liveBody, snapshot, nonce, liveSubmitted, TimeZoneInfo.Utc);
        var liveFormattedLines = liveFormatted.Replace("\r\n", "\n", StringComparison.Ordinal);
        Expect(liveFormattedLines.Contains(liveReturned.Replace("\r\n", "\n", StringComparison.Ordinal), StringComparison.Ordinal)
            && liveFormattedLines.Contains("<p>original</p>\n<p>keep</p>", StringComparison.Ordinal),
            "Exchange's live CRLF formatting was rejected or changed while formatting only the generated header.");
        const string styledSubmitted = "<div id='styled-authored' dir='rtl' lang='fa' style='direction:rtl;text-align:right;font-family:Peyda;font-size:12pt'>پاسخ <a href='https://example.test/original'>پیوند</a><img src='cid:authored-logo' alt='Logo' width='96' /></div>";
        const string styledReturned = "<div lang='fa' style='direction:rtl; text-align:right; font-family:Peyda; font-size:12pt' dir='rtl' id='styled-authored'>پاسخ <a href='https://example.test/original'>پیوند</a><img alt='Logo' width='96' src='cid:authored-logo' /></div>";
        Expect(!XNode.DeepEquals(XElement.Parse(styledSubmitted), XElement.Parse(styledReturned))
            && !XNode.DeepEquals(XElement.Parse("<img src='cid:logo' alt='Logo' />"), XElement.Parse("<img alt='Logo' src='cid:logo' />"))
            && !XNode.DeepEquals(XElement.Parse("<div style='direction:rtl;text-align:right' />"), XElement.Parse("<div style='direction:rtl; text-align:right' />")),
            "The native presentation regression fixture no longer exercises literal attribute-order and CSS-spacing differences.");
        foreach (var serverBody in new[]
        {
            styledReturned,
            styledReturned.Replace("direction:rtl; text-align:right; font-family:Peyda; font-size:12pt",
                "direction : rtl ; text-align : right ; font-family : Peyda ; font-size : 12pt", StringComparison.Ordinal),
            styledReturned.Replace("<div ", "<DIV xmlns='http://www.w3.org/1999/xhtml' ", StringComparison.Ordinal)
                .Replace("</div>", "</DIV>", StringComparison.Ordinal)
        })
        {
            var styledFormatted = EwsClient.FormatReplyHeader(ReplyPresentationHandler.NativeBody(nonce, serverBody), snapshot,
                nonce, styledSubmitted, TimeZoneInfo.Utc);
            var styledRoot = RichBody.ParseExchangeHtml(styledFormatted);
            var styledAuthored = styledRoot.Descendants().Single(element => (string?)element.Attribute("id") == "styled-authored");
            var serverAuthored = XElement.Parse(serverBody);
            Expect(XNode.DeepEquals(styledAuthored, serverAuthored)
                && styledFormatted.IndexOf("styled-authored", StringComparison.Ordinal) < styledFormatted.IndexOf("<hr", StringComparison.Ordinal)
                && !styledFormatted.Contains(nonce, StringComparison.Ordinal),
                "Equivalent RTL/Peyda CSS delimiter spacing or HTML attribute spelling/order failed provenance, changed persisted authored HTML, or lost its pre-signature placement.");
        }
        foreach (var changed in new[]
        {
            styledReturned.Replace("پاسخ", "تغییر", StringComparison.Ordinal),
            styledReturned.Replace("https://example.test/original", "https://example.test/changed", StringComparison.Ordinal),
            styledReturned.Replace("font-size:12pt", "font-size:13pt", StringComparison.Ordinal),
            styledReturned.Replace("font-family:Peyda", "font-family:Pey da", StringComparison.Ordinal),
            styledReturned.Replace("font-family:Peyda", "font-family:&#160;Peyda", StringComparison.Ordinal),
            styledReturned.Replace("direction:rtl; text-align:right", "text-align:right; direction:rtl", StringComparison.Ordinal),
            styledReturned.Replace("font-size:12pt'", "font-size:12pt; font-size:12pt'", StringComparison.Ordinal),
            styledReturned.Replace("cid:authored-logo", "cid:changed-logo", StringComparison.Ordinal)
        })
            ExpectThrows<InvalidOperationException>(() => EwsClient.FormatReplyHeader(ReplyPresentationHandler.NativeBody(nonce, changed),
                snapshot, nonce, styledSubmitted, TimeZoneInfo.Utc),
                "Native HTML comparison accepted changed text, links, CSS values/order/duplicates, or CID references.");
        foreach (var style in new[] { "", " style='white-space:normal'", " style='white-space:nowrap'" })
        {
            const string firstLine = "Disposable native reply &lt;literal&gt; &amp; preserved quote.";
            const string secondLine = "Keep the original HTML and inline image.";
            var brSubmitted = "<div" + style + ">" + firstLine + "<br />" + secondLine + "</div>";
            var brReturned = "\r\n<div" + style + ">" + firstLine + "<br>\r\n  \t" + secondLine + "</div>\r\n";
            var brFormatted = EwsClient.FormatReplyHeader(ReplyPresentationHandler.NativeBody(nonce, brReturned), snapshot,
                nonce, brSubmitted, TimeZoneInfo.Utc);
            var brRoot = XElement.Parse(brFormatted);
            Expect(brRoot.Value.Contains("Disposable native reply <literal> & preserved quote.", StringComparison.Ordinal)
                && brFormatted.Replace("\r\n", "\n", StringComparison.Ordinal).Contains("<br />\n  \t" + secondLine, StringComparison.Ordinal)
                && brRoot.Descendants("img").Single().Attribute("src")?.Value == "cid:old-logo",
                "Harmless Exchange indentation after BR failed authored provenance, changed literal text, or rewrote actual body/quote whitespace.");
        }
        const string inlineAfterBreak = "<p>one<br />\r\n <b>two</b></p>";
        var inlineBreakFormatted = EwsClient.FormatReplyHeader(ReplyPresentationHandler.NativeBody(nonce, inlineAfterBreak), snapshot,
            nonce, "<p>one<br /><b>two</b></p>", TimeZoneInfo.Utc);
        Expect(inlineBreakFormatted.Replace("\r\n", "\n", StringComparison.Ordinal).Contains("<br />\n <b>two</b>", StringComparison.Ordinal),
            "Whitespace-only indentation after BR was rejected or removed from the actual message.");
        foreach (var pair in new[]
        {
            (Submitted: "<p><b>one</b> <i>two</i></p>", Returned: "<p><b>one</b>\r\n<i>two</i></p>"),
            (Submitted: "<p><b>one</b><i>two</i></p>", Returned: "<p><b>one</b>\r\n<i>two</i></p>"),
            (Submitted: "<p><b>one</b> <i>two</i></p>", Returned: "<p><b>one</b><i>two</i></p>"),
            (Submitted: "<b>one</b><i>two</i>", Returned: "\r\n<b>one</b><i>two</i>\r\n"),
            (Submitted: "<p>word word</p>", Returned: "<p>word\r\nword</p>"),
            (Submitted: "<div>one<br />two words</div>", Returned: "<div>one<br />two\r\nwords</div>"),
            (Submitted: "<div>one<br /> two</div>", Returned: "<div>one<br />two</div>"),
            (Submitted: "<div>one<br />two</div>", Returned: "<div>one<br />\r\n&#160;two</div>"),
            (Submitted: "<pre>one<br />two</pre>", Returned: "<pre>one<br />\r\ntwo</pre>"),
            (Submitted: "<div><code>one<br />two</code></div>", Returned: "<div><code>one<br />\r\ntwo</code></div>"),
            (Submitted: "<div style='white-space:pre'>one<br />two</div>", Returned: "<div style='white-space:pre'>one<br />\r\ntwo</div>"),
            (Submitted: "<div style='white-space:pre-wrap'>one<br />two</div>", Returned: "<div style='white-space:pre-wrap'>one<br />\r\ntwo</div>"),
            (Submitted: "<div style='white-space:pre-line'>one<br />two</div>", Returned: "<div style='white-space:pre-line'>one<br />\r\ntwo</div>"),
            (Submitted: "<div style='white-space:pre-wrap'><span>one<br />two</span></div>", Returned: "<div style='white-space:pre-wrap'><span>one<br />\r\ntwo</span></div>"),
            (Submitted: "<pre><div>one</div><div>two</div></pre>", Returned: "<pre>\r\n<div>one</div>\r\n<div>two</div>\r\n</pre>"),
            (Submitted: "<div style='white-space:pre-wrap'><p>one</p><p>two</p></div>", Returned: "<div style='white-space:pre-wrap'><p>one</p>\r\n<p>two</p></div>"),
            (Submitted: "<p>one</p><p>two</p>", Returned: "<p>one</p>\r\n&#160;<p>two</p>")
        })
            ExpectThrows<InvalidOperationException>(() => EwsClient.FormatReplyHeader(ReplyPresentationHandler.NativeBody(nonce, pair.Returned),
                snapshot, nonce, pair.Submitted, TimeZoneInfo.Utc), "Meaningful inline/preformatted/NBSP whitespace changes passed reply-body provenance.");
        const string forged = "<div id='divRplyFwdMsg'>Caller marker</div><p>Submitted</p>";
        var formatted = EwsClient.FormatReplyHeader(ReplyPresentationHandler.NativeBody(nonce, forged), snapshot, nonce, forged, TimeZoneInfo.Utc);
        var formattedRoot = XElement.Parse(formatted);
        Expect(formattedRoot.Descendants("div").First(element => (string?)element.Attribute("id") == "divRplyFwdMsg").Value == "Caller marker",
            "Header formatting trusted an earlier caller-supplied quote marker.");
        var exSource = snapshot with { FromIdentity = new("Legacy user", "/o=Org/ou=Site/cn=Recipients/cn=user", "EX") };
        var exHeader = XElement.Parse(EwsClient.FormatReplyHeader(ReplyPresentationHandler.NativeBody(nonce, "<p>Reply</p>"), exSource,
            nonce, "<p>Reply</p>", TimeZoneInfo.Utc)).Descendants("div").First(element => (string?)element.Attribute("id") == "divRplyFwdMsg");
        Expect(exHeader.Value.Contains("[EX]", StringComparison.Ordinal) && !exHeader.Descendants("a").Any(link => link.Value.Contains("/o=", StringComparison.Ordinal)),
            "An EX identity was guessed into an SMTP link.");
        ExpectThrows<InvalidOperationException>(() => EwsClient.FormatReplyHeader(ReplyPresentationHandler.NativeBody(nonce, "<p>Reply</p>"),
            snapshot with { SentUtc = null }, nonce, "<p>Reply</p>", TimeZoneInfo.Utc), "Missing DateTimeSent fell back to Received.");
        var punctuation = snapshot with { FromIdentity = new("Punctuation", "sender?cc=hidden@example.test", "SMTP") };
        var punctuationHeader = XElement.Parse(EwsClient.FormatReplyHeader(ReplyPresentationHandler.NativeBody(nonce, "<p>Reply</p>"), punctuation,
            nonce, "<p>Reply</p>", TimeZoneInfo.Utc));
        Expect(punctuationHeader.Descendants("a").Any(link => link.Attribute("href")?.Value == "mailto:sender%3Fcc%3Dhidden@example.test")
            && punctuationHeader.Descendants("a").All(link => !link.Attribute("href")!.Value.Contains('?')),
            "SMTP address URI punctuation became mailto query/header parameters.");
    }

    private static void ValidateReplyPresentationSchema(IEnumerable<XElement> operations)
    {
        var schemas = LoadOptionalExchangeSchemas();
        foreach (var operation in operations)
            if (schemas is not null)
                new XDocument(operation).Validate(schemas, (_, error) =>
                    throw new InvalidOperationException("Reply presentation request schema: " + error.Message));
    }
}

internal sealed class ReplyPresentationHandler : HttpMessageHandler
{
    private static readonly XNamespace S = "http://schemas.xmlsoap.org/soap/envelope/";
    private static readonly XNamespace M = "http://schemas.microsoft.com/exchange/services/2006/messages";
    private static readonly XNamespace T = "http://schemas.microsoft.com/exchange/services/2006/types";
    public List<XElement> Operations { get; } = [];
    public string TimeZone { get; init; } = "Iran Standard Time";
    public string? Failure { get; init; }
    public bool OfficeEnvelope { get; init; }
    private string submitted = string.Empty;
    private bool forwarding;

    internal const string OriginalBody = "<div id='old-history' dir='rtl'>قدیمی<table style='font-family:Peyda;font-size:12pt'><tr><td>جدول<img src='cid:old-logo'></td></tr></table><div id='divRplyFwdMsg'>Older marker</div></div>";

    internal static string NativeBody(string nonce, string content) => "<html><head><meta http-equiv='Content-Type' content='text/html; charset=utf-8'><meta content='text/html; charset=us-ascii'></head><body>"
        + "<div dir='ltr'><div id='" + nonce + "'>" + content + "</div></div><hr tabindex='-1' style='display:inline-block; width:98%'>"
        + "<div id='divRplyFwdMsg' dir='ltr'><font face='Calibri, sans-serif' color='#000000' style='font-size:11pt'><b>From:</b> sender<br><b>Sent:</b> time<br><b>To:</b> recipient<br><b>Subject:</b> test</font><div>&nbsp;</div></div>"
        + OriginalBody + "</body></html>";

    internal static string OfficeBody(string body) => body.Replace("<html>", "<html xmlns:o='urn:schemas-microsoft-com:office:office' xmlns:w='urn:schemas-microsoft-com:office:word'>", StringComparison.Ordinal)
        .Replace("</head>", "<meta name='Generator' content='Microsoft Word 15'><style>p.MsoNormal { mso-style-name:Normal; margin:0cm; font-family:Calibri; } @page WordSection1 { size:595.3pt 841.9pt; margin:72pt; } .WordSection1 { page:WordSection1; }</style></head>", StringComparison.Ordinal)
        .Replace("قدیمی", "<p class='MsoNormal' style='mso-margin-top-alt:auto'>قدیمی<o:p>&nbsp;</o:p></p>", StringComparison.Ordinal);

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var document = XDocument.Parse(await request.Content!.ReadAsStringAsync(cancellationToken));
        var operation = document.Root!.Element(S + "Body")!.Elements().Single();
        Operations.Add(new(operation));
        var name = operation.Name.LocalName;
        XElement? result = null;
        var denied = name == "GetUserConfiguration" && TimeZone == "denied";
        if (name == "GetUserConfiguration" && !denied)
            result = new(M + "UserConfiguration", new XElement(T + "Dictionary", TimeZone.Length == 0 ? null : new XElement(T + "DictionaryEntry",
                new XElement(T + "DictionaryKey", new XElement(T + "Type", "String"), new XElement(T + "Value", "timezone")),
                new XElement(T + "DictionaryValue", new XElement(T + "Type", "String"), new XElement(T + "Value", TimeZone)))));
        if (name == "CreateItem")
        {
            submitted = operation.Descendants(T + "NewBodyContent").Single().Value;
            forwarding = operation.Descendants(T + "ForwardItem").Any();
            result = new(M + "Items", new XElement(T + "Message", new XElement(T + "ItemId", new XAttribute("Id", "draft"), new XAttribute("ChangeKey", "fresh-key"))));
        }
        if (name == "GetItem")
        {
            var source = operation.Descendants(T + "ItemId").Single().Attribute("Id")!.Value == "source";
            if (!source && Failure == "read-failure") throw new HttpRequestException();
            var wrapper = source ? null : XElement.Parse(submitted);
            var nonce = wrapper?.Attribute("id")?.Value ?? string.Empty;
            var content = wrapper is null ? string.Empty : string.Concat(wrapper.Nodes().Select(node => node.ToString(SaveOptions.DisableFormatting)));
            var body = source ? OriginalBody : NativeBody(nonce, content);
            if (OfficeEnvelope) body = OfficeBody(source ? "<html><head></head><body>" + body + "</body></html>" : body);
            if (!source && Failure == "missing-header") body = "<html><body>" + submitted + "<p>No generated header</p></body></html>";
            if (!source && Failure == "duplicate-nonce") body = body.Replace("</body>", submitted + "</body>", StringComparison.Ordinal);
            if (!source && Failure == "changed-body") body = NativeBody(nonce, "<p>Changed reply</p>");
            if (!source && Failure == "unsafe-history") body = body.Replace("قدیمی", "<script>active()</script>", StringComparison.Ordinal);
            if (!source && Failure == "missing-quoted-image") body = body.Replace("<img src='cid:old-logo'>", string.Empty, StringComparison.Ordinal);
            var attachments = new XElement(T + "Attachments");
            if (Failure != (source ? "source-image-missing" : "draft-image-missing"))
                attachments.Add(Image(source, Failure == (source ? "source-image-not-inline" : "draft-image-not-inline")));
            if (!source && Failure == "duplicate-image") attachments.Add(Image(false, false));
            if (source || forwarding) attachments.Add(new XElement(T + "FileAttachment", new XElement(T + "AttachmentId", new XAttribute("Id", "ordinary")),
                new XElement(T + "Name", "report.pdf"), new XElement(T + "ContentType", "application/pdf"), new XElement(T + "Size", 321), new XElement(T + "IsInline", false)));
            result = new(M + "Items", new XElement(T + "Message",
                new XElement(T + "ItemId", new XAttribute("Id", source ? "source" : "draft"), new XAttribute("ChangeKey", source ? "source-key" : Failure == "changed-revision" ? "concurrent-key" : "fresh-key")),
                new XElement(T + "Subject", "Subject <unsafe>"), new XElement(T + "Importance", "High"),
                new XElement(T + "DateTimeSent", "2026-10-19T10:03:11Z"), new XElement(T + "DateTimeReceived", "2026-10-19T10:08:20Z"),
                new XElement(T + "From", Mailbox("فرستنده <script>", "sender@example.test")), new XElement(T + "Sender", Mailbox("Delegate", "delegate@example.test")),
                new XElement(T + "ToRecipients", Mailbox("Recipient", "to@example.test")), new XElement(T + "CcRecipients", Mailbox("Copy", "copy@example.test")),
                new XElement(T + "BccRecipients", Mailbox("Hidden", "hidden@example.test")), new XElement(T + "IsDraft", !source),
                new XElement(T + "Body", new XAttribute("BodyType", "HTML"), body), attachments));
        }
        if (name == "UpdateItem")
        {
            if (Failure == "update-failure") throw new HttpRequestException();
            result = new(M + "Items", new XElement(T + "Message", new XElement(T + "ItemId", new XAttribute("Id", "draft"), new XAttribute("ChangeKey", "updated"))));
        }
        var response = new XDocument(new XElement(S + "Envelope", new XElement(S + "Body", new XElement(M + (name + "Response"),
            new XElement(M + "ResponseMessages", new XElement(M + (name + "ResponseMessage"), new XAttribute("ResponseClass", denied ? "Error" : "Success"),
                new XElement(M + "ResponseCode", denied ? "ErrorAccessDenied" : "NoError"), result))))));
        return new(HttpStatusCode.OK) { Content = new StringContent(response.ToString(), Encoding.UTF8, "text/xml") };
    }

    private XElement Image(bool source, bool notInline) => new(T + "FileAttachment",
        new XElement(T + "AttachmentId", new XAttribute("Id", source ? "source-image" : "native-quote-image")),
        new XElement(T + "Name", "brand.png"), new XElement(T + "ContentType", "image/png"),
        new XElement(T + "ContentId", "old-logo"), new XElement(T + "Size", !source && Failure == "changed-image" ? 45 : 44),
        new XElement(T + "IsInline", !notInline));

    private static XElement Mailbox(string name, string address) => new(T + "Mailbox", new XElement(T + "Name", name),
        new XElement(T + "EmailAddress", address), new XElement(T + "RoutingType", "SMTP"));
}
