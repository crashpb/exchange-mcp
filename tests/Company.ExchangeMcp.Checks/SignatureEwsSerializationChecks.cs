using System.Text.Json;
using System.Xml.Linq;
using Company.ExchangeMcp;
using Company.ExchangeMcp.Exchange;
using Company.ExchangeMcp.Security;
using Microsoft.AspNetCore.DataProtection;

internal sealed partial class Checks
{
    private const string SerializerSignatureHtml = "<div id='serializer-signature'><div lang='EN-US'><div class='WordSection1'><table width='420' style='border-collapse:collapse'><tbody><tr><td width='100' style='padding:0'><img src='cid:serializer-logo' width='80' height='40' /></td><td width='320'><p>Service <b>Desk</b> contact</p><p>This generic disclaimer covers any replies and attached files.</p></td></tr></tbody></table></div></div></div>";

    private async Task SignatureEwsSerializationChecksAsync()
    {
        SignatureWhitespaceComparisonChecks();
        foreach (var kind in new[] { "new", "reply", "forward" })
        {
            var handler = new SignatureCaptureFlowHandler { DraftBodyReadback = EwsFormattedSignatureBody };
            var exchange = NewEwsClient(handler);
            var options = SignatureReuseOptions("ews-serialization-" + kind);
            using var audit = new AuditLog(options);
            var access = new MailboxAccess(options);
            var handles = new MailboxHandles(new EphemeralDataProtectionProvider());
            var store = new SignatureStore();
            var image = new SignatureImage("generic-logo.png", "image/png", "serializer-logo", handler.SourceImageBase64);
            var initial = await store.UpdateAsync(exchange, "alice@example.test", "new", _ => new(
                [new("Default", SerializerSignatureHtml, "HTML", [image])], "Default", "Default"), CancellationToken.None);
            var mailbox = new MailboxTools(exchange, access, handles, audit, null!, null!, null!, store);
            var signatures = new SignatureTools(exchange, access, handles, audit, store);
            var user = SignatureTestUser("user-a", "alice@example.test", "checks", "session-1", "mail.read mail.write");
            var source = handles.Issue(PreviewIdentity(), "message", handler.SourceId, handler.SourceChangeKey);
            var created = JsonSerializer.SerializeToElement(kind switch
            {
                "reply" => await mailbox.ReplyDraft(user, source, "<p>Authored reply.</p>", CancellationToken.None, bodyType: "HTML"),
                "forward" => await mailbox.ForwardDraft(user, source, "<p>Authored forward.</p>", ["to@example.test"], CancellationToken.None, bodyType: "HTML"),
                _ => await mailbox.CreateDraft(user, "EWS serialization", "<p>Authored message.</p>", ["to@example.test"], CancellationToken.None, bodyType: "HTML")
            });
            Expect(created.GetProperty("status").GetString() == (kind == "new" ? "draft_saved" : kind + "_draft_saved")
                && created.GetProperty("signatureStatus").GetString() == "signature_applied"
                && created.GetProperty("readyToSend").GetBoolean(),
                "Harmless EWS block formatting or text wrapping incorrectly made the " + kind + " draft incomplete.");
            var handle = created.GetProperty("handle").GetString()!;
            var reference = handles.Resolve(PreviewIdentity(), "message", handle);
            var before = await exchange.GetMessageAsync("alice@example.test", reference.Id, CancellationToken.None);
            Expect(before.Body != handler.LastCreatedBody && before.Body!.Replace("\r\n", "\n", StringComparison.Ordinal).Contains("any\n replies", StringComparison.Ordinal),
                "The EWS serialization fixture did not actually change block whitespace and normal text line wrapping.");
            var root = XElement.Parse("<root>" + before.Body + "</root>", LoadOptions.PreserveWhitespace);
            var own = root.Descendants("div").Single(element => (string?)element.Attribute("id") == "serializer-signature");
            var ownAttachment = before.Attachments.Single(attachment => attachment.ContentId == image.ContentId);
            Expect(own.Descendants("table").Single().Descendants("tr").Count() == 1
                && own.Descendants("td").Select(cell => (string?)cell.Attribute("width")).SequenceEqual(["100", "320"])
                && own.Descendants("img").Single().Attribute("src")?.Value == "cid:serializer-logo"
                && before.Attachments.Count == (kind == "new" ? 1 : 2) && ownAttachment.IsInline,
                "The generic serializer fixture altered signature geometry, image count or exact CID.");
            if (kind != "new")
                Expect(root.Descendants("div").Single(element => (string?)element.Attribute("id") == "quoted-history")
                        .Descendants("img").Single().Attribute("src")?.Value == "cid:source-logo"
                    && before.Attachments.Single(attachment => attachment.ContentId == "source-logo").IsInline,
                    "The serializer fixture lost the native quoted source image while applying the own signature.");
            var bytes = await exchange.GetAttachmentAsync("alice@example.test", ownAttachment.Id, CancellationToken.None);
            Expect(bytes.Content.SequenceEqual(Convert.FromBase64String(image.ContentBase64)),
                "EWS whitespace compatibility changed exact signature image bytes.");
            var updates = handler.DraftUpdates;
            var imageWrites = handler.AttachmentWrites;
            var applied = JsonSerializer.SerializeToElement(await signatures.Apply(user, handle, CancellationToken.None, context: kind == "new" ? "new" : "reply"));
            var after = await exchange.GetMessageAsync("alice@example.test", reference.Id, CancellationToken.None);
            Expect(applied.GetProperty("status").GetString() == "signature_already_applied"
                && applied.GetProperty("handle").GetString() == handle
                && after.Body == before.Body && handler.DraftUpdates == updates && handler.AttachmentWrites == imageWrites,
                "Legacy apply duplicated or rewrote the EWS-formatted " + kind + " signature.");
            Expect((await store.ReadAsync(exchange, "alice@example.test", CancellationToken.None)).Revision == initial.Revision
                && handler.SendItemCalls == 0, "EWS formatting compatibility changed saved settings or sent mail.");
        }
    }

    private static string EwsFormattedSignatureBody(string body)
    {
        if (!body.Contains("serializer-signature", StringComparison.Ordinal)) return body;
        var root = XElement.Parse("<root>" + body + "</root>", LoadOptions.PreserveWhitespace);
        foreach (var element in root.DescendantsAndSelf().ToArray())
        {
            var blocks = element.Elements().Where(child => child.Name.LocalName is "html" or "head" or "body" or "div"
                or "p" or "table" or "tbody" or "tr" or "td").ToArray();
            foreach (var child in blocks)
            {
                child.AddBeforeSelf(new XText("\r\n"));
                child.AddAfterSelf(new XText("\r\n"));
            }
            if (element.Name.LocalName == "div" && element.Elements().Any(child => child.Name.LocalName == "br"))
                element.Add(new XText("\r\n"));
        }
        foreach (var text in root.DescendantNodes().OfType<XText>())
            text.Value = text.Value.Replace("any replies", "any\r\n replies", StringComparison.Ordinal);
        root.Add(new XText("\r\n"));
        return string.Concat(root.Nodes().Select(node => node.ToString(SaveOptions.DisableFormatting)));
    }

    private static void SignatureWhitespaceComparisonChecks()
    {
        var profile = new MailSignature("Default", SerializerSignatureHtml, "HTML", []);
        var compact = SignatureStore.Append("<p>Authored.</p>", "HTML", profile);
        var formatted = EwsFormattedSignatureBody(compact);
        Expect(SignatureStore.HasExactAppendedSignature(formatted, "HTML", profile, "new")
            && SignatureStore.HasExactAppendedSignature("<html><head></head><body>\r\n" + formatted + "\r\n</body></html>", "HTML", profile, "new"),
            "The comparison rejected harmless EWS block CRLF/trailing whitespace or normal text wrapping.");
        foreach (var changed in new[]
        {
            compact.Replace("Service <b>", "Service<b>", StringComparison.Ordinal),
            compact.Replace("Desk</b> contact", "Desk</b>contact", StringComparison.Ordinal),
            compact.Replace("any replies", "any other replies", StringComparison.Ordinal),
            compact.Replace("width=\"320\"", "width=\"319\"", StringComparison.Ordinal),
            compact.Replace("border-collapse:collapse", "border-collapse:separate", StringComparison.Ordinal),
            compact.Replace("cid:serializer-logo", "cid:SERIALIZER-LOGO", StringComparison.Ordinal),
            compact.Replace("<b>Desk</b>", "<i>Desk</i>", StringComparison.Ordinal),
            compact.Replace("attached files.", "attached files.<br />", StringComparison.Ordinal)
        })
            Expect(!SignatureStore.HasExactAppendedSignature(changed, "HTML", profile, "new"),
                "Whitespace tolerance accepted a meaningful text, inline-spacing, layout, element, style or CID change.");

        foreach (var whitespace in new[] { "\u00a0", "\u2003", "\u202f" })
        {
            var unicode = new MailSignature("Unicode", "<p>First" + whitespace + "Last</p>", "HTML", []);
            var original = SignatureStore.Append("<p>Authored.</p>", "HTML", unicode);
            Expect(!SignatureStore.HasExactAppendedSignature(original.Replace(whitespace, " ", StringComparison.Ordinal), "HTML", unicode, "new"),
                "Whitespace tolerance collapsed a meaningful NBSP or Unicode space.");
        }
        foreach (var markup in new[]
        {
            "<pre>Line one\n  Line two</pre>",
            "<PRE>Line one\n  Line two</PRE>",
            "<div style='white-space:pre'><p>Line one\n  Line two</p></div>",
            "<div style='white-space:pre-wrap'><p>Line one\n  Line two</p></div>",
            "<div style='white-space:pre-line'><p>Line one\n  Line two</p></div>",
            "<div style='white-space:break-spaces'><p>Line one\n  Line two</p></div>",
            "<div style='white-space:pre'><p><span style='white-space:inherit'>Line one\n  Line two</span></p></div>"
        })
        {
            var preserved = new MailSignature("Preserved", markup, "HTML", []);
            var original = SignatureStore.Append("<p>Authored.</p>", "HTML", preserved);
            Expect(SignatureStore.HasExactAppendedSignature(original, "HTML", preserved, "new"),
                "An unchanged whitespace-preserving signature no longer matched itself.");
            foreach (var changed in new[] { original.Replace("\n  ", " ", StringComparison.Ordinal), original.Replace("\n  ", "\n ", StringComparison.Ordinal) })
                Expect(!SignatureStore.HasExactAppendedSignature(changed, "HTML", preserved, "new"),
                    "Whitespace tolerance changed preformatted text or inherited white-space content.");
        }
        var inline = new MailSignature("Inline", "<p><span>One</span> <span>Two</span></p>", "HTML", []);
        var inlineBody = SignatureStore.Append("<p>Authored.</p>", "HTML", inline);
        Expect(SignatureStore.HasExactAppendedSignature(inlineBody.Replace("</span> <span>", "</span>\r\n <span>", StringComparison.Ordinal), "HTML", inline, "new"),
            "Normal HTML text wrapping changed an otherwise preserved inline separating space.");
        Expect(!SignatureStore.HasExactAppendedSignature(inlineBody.Replace("</span> <span>", "</span><span>", StringComparison.Ordinal), "HTML", inline, "new"),
            "Whitespace-only inline separation was incorrectly discarded.");
        var inherited = new MailSignature("Inherited", "<p>Line one Line two</p>", "HTML", []);
        var inheritedBody = "<html><body style='white-space:pre'>"
            + SignatureStore.Append("<p>Authored.</p>", "HTML", inherited) + "</body></html>";
        Expect(!SignatureStore.HasExactAppendedSignature(inheritedBody.Replace("Line one Line two", "Line one\n Line two", StringComparison.Ordinal), "HTML", inherited, "new"),
            "The comparison lost whitespace preservation inherited from outside the signature fragment.");
    }
}
