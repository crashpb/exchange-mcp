using System.Xml.Linq;
using Company.ExchangeMcp;
using Company.ExchangeMcp.Exchange;

internal sealed partial class Checks
{
    private Task NativeHtmlChecksAsync()
    {
        const string native = """
            <html xmlns:o="urn:schemas-microsoft-com:office:office"><head><meta http-equiv="Content-Type" content="text/html; charset=utf-8"><meta name="Generator" content="Microsoft Word"><style type="text/css"><!--
            /* Font Definitions */
            @font-face {font-family:"Calibri";panose-1:2 15 5 2 2 2 4 3 2 4;}
            p.MsoNormal {margin:0cm;font-family:"Calibri",sans-serif;mso-fareast-language:EN-US;unicode-bidi:embed;}
            --></style></head><body><div class="WordSection1"><p class="MsoNormal" style="font-family:'Calibri';mso-margin-top-alt:auto;unicode-bidi:embed">Hello team.<o:p>&nbsp;</o:p></p><!-- authored spacing -->
            <hr tabindex="-1" style="display:inline-block;width:98%"><div id="divRplyFwdMsg"><font face="Calibri" size="2" color="#000000">From: sender</font></div><p style="font-family:'Calibri';mso-bidi-font-family:Arial">پیام قدیمی<img src="cid:original-logo"></p></div></body></html>
            """;
        var original = RichBody.ParseExchangeHtml(native);
        var roundTrip = RichBody.SerializeExchangeHtml(original);
        Expect(XNode.DeepEquals(original, RichBody.ParseExchangeHtml(roundTrip))
            && roundTrip.Contains("@font-face", StringComparison.Ordinal)
            && roundTrip.Contains("<!-- authored spacing -->", StringComparison.Ordinal)
            && roundTrip.Contains("cid:original-logo", StringComparison.Ordinal),
            "Native Office passive markup, comments, whitespace or CID history changed during round-trip.");
        Expect(RichBody.SerializeExchangeHtml(RichBody.ParseExchangeHtml("<!-- preserve <br> &nbsp; exactly --><p>x</p>"))
            .StartsWith("<!-- preserve <br> &nbsp; exactly -->", StringComparison.Ordinal),
            "Native HTML normalization rewrote literal markup or entities inside comments.");
        var signature = new MailSignature("Native", "<p id='native-signature'>Signature</p><img src='cid:signature-logo' />", "HTML", []);
        var appended = SignatureStore.AppendToExchangeHtml(native, signature, "reply");
        var after = RichBody.ParseExchangeHtml(appended);
        var inserted = after.Descendants().Single(element => (string?)element.Attribute("id") == "native-signature");
        var quote = after.Descendants().Single(element => (string?)element.Attribute("id") == "divRplyFwdMsg");
        Expect(inserted.NodesAfterSelf().Contains(quote.PreviousNode!)
            && SignatureStore.HasExactAppendedSignature(appended, "HTML", signature, "reply")
            && !SignatureStore.HasExactAppendedSignature(native, "HTML", signature, "reply"),
            "Native signature insertion or exact deduplication lost the authored/history boundary.");
        var image = inserted.NextNode!;
        inserted.PreviousNode!.Remove();
        inserted.Remove();
        image.Remove();
        Expect(XNode.DeepEquals(original, after), "Signature insertion changed existing native Office markup.");
        var withComment = appended.Replace("<hr ", "<!-- signature boundary -->\n<hr ", StringComparison.Ordinal);
        Expect(SignatureStore.HasExactAppendedSignature(withComment, "HTML", signature, "reply"),
            "Passive native comments broke exact signature deduplication.");
        foreach (var htmlNamespace in new[] { "http://www.w3.org/TR/REC-html40", "http://www.w3.org/1999/xhtml" })
        {
            var namespaced = native.Replace("<html xmlns:o=", "<html xmlns='" + htmlNamespace + "' xmlns:o=", StringComparison.Ordinal);
            var namespacedOriginal = RichBody.ParseExchangeHtml(namespaced);
            var namespacedAppended = RichBody.ParseExchangeHtml(SignatureStore.AppendToExchangeHtml(namespaced, signature, "reply"));
            var namespacedQuote = namespacedAppended.Descendants().Single(element => (string?)element.Attribute("id") == "divRplyFwdMsg");
            var originalQuote = namespacedOriginal.Descendants().Single(element => (string?)element.Attribute("id") == "divRplyFwdMsg");
            Expect(XNode.DeepEquals(originalQuote, namespacedQuote)
                && XNode.DeepEquals(namespacedOriginal.Descendants().First(element => element.Name.LocalName == "head"),
                    namespacedAppended.Descendants().First(element => element.Name.LocalName == "head"))
                && SignatureStore.HasExactAppendedSignature(RichBody.SerializeExchangeHtml(namespacedAppended), "HTML", signature, "reply"),
                "Known native HTML namespace changed Office history or prevented signature insertion/deduplication.");
            foreach (var element in namespacedAppended.Descendants().Where(element => element.Name.Namespace == XNamespace.None))
            {
                element.Name = XNamespace.Get(htmlNamespace) + element.Name.LocalName;
                element.Attributes().Where(attribute => attribute.IsNamespaceDeclaration).Remove();
            }
            Expect(SignatureStore.HasExactAppendedSignature(RichBody.SerializeExchangeHtml(namespacedAppended), "HTML", signature, "reply"),
                "Inherited native HTML namespace prevented exact signature deduplication.");
        }
        var settings = new SignatureSettings([signature], null, null,
            UseRules: [new("Native", Context: "reply", BodyLanguage: "en")]);
        Expect(SignatureStore.Select(settings, null, "reply", [], native, "HTML").Source == "rule",
            "Native Word metadata or quoted history influenced the authored reply language.");
        foreach (var unsafeHtml in new[]
        {
            "<script>alert(1)</script>", "<object></object>", "<form></form>", "<iframe></iframe>",
            "<p onclick='alert(1)'>x</p>", "<a href='javascript:alert(1)'>x</a>",
            "<img src='https://example.test/image.png'>", "<p style='behavior:url(test.htc)'>x</p>",
            "<p style='width:expression(alert(1))'>x</p>", "<style>@import 'https://example.test/style';</style>",
            "<style>p{background:u/**/rl(https://example.test/image)}</style>",
            "<style>p{background:image-set('https://example.test/image' 1x)}</style>",
            "<style>p{background:u\\72l(https://example.test/image)}</style>",
            "<p style=\"filter:progid:DXImageTransform.Microsoft.AlphaImageLoader(src='https://example.test/image')\">x</p>",
            "<style>p{-ms-filter:&quot;progid:DXImageTransform.Microsoft.AlphaImageLoader(src='https://example.test/image')&quot;;}</style>",
            "<style>p{-ms-/**/filter : 'alpha(opacity=50)';}</style>",
            "<style>p{filter:pro/**/gid : DXImageTransform.Microsoft.AlphaImageLoader(src='https://example.test/image');}</style>",
            "<p style=\"filter:AlphaImageLoader(src='https://example.test/image')\">x</p>",
            "<meta http-equiv='refresh' content='0;url=https://example.test'>", "<p id='a' ID='b'>x</p>",
            "<p xmlns:x='urn:test' x:style='color:red'>x</p>", "<p>unclosed",
            "<p xmlns='urn:unknown'>x</p>",
            "<!DOCTYPE html><p>x</p>", "<?processing unsafe?>", "<!--[if IE]><script>alert(1)</script><![endif]-->"
        })
            ExpectThrows<ArgumentException>(() => RichBody.ParseExchangeHtml(unsafeHtml),
                "Active, ambiguous or malformed native Exchange markup was accepted.");
        ExpectThrows<ArgumentException>(() => RichBody.ParseExchangeHtml(new string('x', RichBody.MaxLength + 1)),
            "Native Exchange HTML length was unbounded.");
        ExpectThrows<ArgumentException>(() => RichBody.ParseExchangeHtml(string.Concat(Enumerable.Repeat("<div>", RichBody.MaxHtmlDepth + 1))
            + string.Concat(Enumerable.Repeat("</div>", RichBody.MaxHtmlDepth + 1))), "Native Exchange HTML nesting was unbounded.");
        ExpectThrows<ArgumentException>(() => RichBody.SerializeExchangeHtml(new XElement("root", new string('x', RichBody.MaxLength + 1))),
            "Native Exchange HTML serialization exceeded the length limit.");
        Expect(RichBody.SerializeExchangeHtml(RichBody.ParseExchangeHtml("<div /><font />")) == "<div></div><font></font>",
            "Native HTML serialization omitted non-void closing tags.");
        ExpectThrows<ArgumentException>(() => SignatureStore.AppendToExchangeHtml(native,
            new("Unsafe", "<p style=\"font-family:'Calibri';mso-font-kerning:0pt\">x</p>", "HTML", []), "reply"),
            "Native HTML preservation relaxed authored signature validation.");
        ExpectThrows<ArgumentException>(() => RichBody.Validate(native, "HTML"),
            "Native HTML preservation relaxed authored body validation.");
        ExpectThrows<ArgumentException>(() => RichBody.NormalizeExchangeHtml(native),
            "Native HTML preservation relaxed authored Exchange normalization.");
        ExpectThrows<ArgumentException>(() => RichBody.Validate("<p xmlns='http://www.w3.org/TR/REC-html40'>x</p>", "HTML"),
            "Native Word HTML namespace support relaxed authored validation.");
        return Task.CompletedTask;
    }
}
