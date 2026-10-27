using System.Text;
using System.Xml.Linq;
using Company.ExchangeMcp.Exchange;

internal sealed partial class Checks
{
    private Task SignatureCaptureChecksAsync()
    {
        OutlookTableCapturePreservesStructureAndFormatting();
        OutlookCommentWrappedStylesPreserveParagraphLayout();
        CaptureDoesNotInheritLayoutProperties();
        CapturePreservesNativeBoldAndItalicInheritance();
        CaptureRetainsRelativeTypographyContextAtEveryBoundary();
        CapturePreservesSupportedCssCascadeOrder();
        CaptureRequiresAnExplicitFragmentForAmbiguousBodies();
        CaptureStopsAtQuotedThreadBoundaries();
        CaptureRejectsActiveOrRemoteContent();
        return Task.CompletedTask;
    }

    private static void OutlookTableCapturePreservesStructureAndFormatting()
    {
        var source = new StringBuilder("<html xmlns='http://www.w3.org/TR/REC-html40' xmlns:o='urn:schemas-microsoft-com:office:office'><head><xml xmlns:o='urn:schemas-microsoft-com:office:office'><o:OfficeDocumentSettings><o:AllowPNG/></o:OfficeDocumentSettings></xml><style type='text/css'>body{direction:rtl;font-family:'Arial',sans-serif;color:#123456}.MsoNormalTable{border-collapse:separate;width:500px;mso-table-lspace:0pt}.MsoNormalTable td{border:1px solid #778899}.MsoNormal{font-size:11pt;color:#654321}</style></head><body dir='rtl' lang='fa'><p>Message body outside signature</p>");
        var expectedText = new StringBuilder();
        source.Append("<table class='MsoNormalTable' cellspacing='2' cellpadding='3' border='1' align='center'><!-- passive Outlook comment -->");
        for (var row = 1; row <= 12; row++)
        {
            source.Append("<tr>");
            for (var column = 1; column <= 13; column++)
            {
                var cellText = $"R{row}C{column}" + (row == 1 && column == 1 ? " Café" : string.Empty);
                expectedText.Append(cellText);
                var cellHtmlText = cellText.Replace(" ", "&nbsp;", StringComparison.Ordinal);
                if (row == 1 && column == 1) cellHtmlText = "<o:p>" + cellHtmlText + "</o:p>";
                source.Append("<td width='38' valign='middle'>");
                if (row <= 3 && column <= 8)
                    source.Append("<p class='MsoNormal'><span>").Append(cellHtmlText).Append("</span></p>");
                else if (row <= 3 && column == 9)
                    source.Append("<p class='MsoNormal'>").Append(cellHtmlText).Append("</p>");
                else source.Append(cellHtmlText);
                if (row == 12 && column == 13) source.Append("<img src='cid:company-logo' width='24' height='12'>");
                source.Append("</td>");
            }
            source.Append("</tr>");
        }
        source.Append("</table><blockquote><table><tr><td>Quoted table</td></tr></table></blockquote></body></html>");

        var parts = SignatureCapture.FindParts(source.ToString(), "HTML");
        Expect(parts.Count == 1 && parts[0].Id == "table:0" && parts[0].Kind == "table"
            && parts[0].TextPreview.Contains("R1C1", StringComparison.Ordinal)
            && parts[0].TextPreview.Contains("Café", StringComparison.Ordinal)
            && parts[0].Warnings.Any(warning => warning.Contains("Quoted", StringComparison.Ordinal)),
            "A single signature table was not separated from message text and quoted content.");

        var captured = SignatureCapture.Extract(source.ToString(), "HTML", parts[0].Id);
        var root = XElement.Parse("<root>" + captured.Body + "</root>");
        var table = root.Descendants("table").Single();
        var rows = table.Elements("tr").ToArray();
        Expect(captured.BodyType == "HTML" && rows.Length == 12
            && table.Descendants("td").Count() == 156
            && table.Descendants("p").Count() == 27
            && table.Descendants("span").Count() == 24
            && table.Value == expectedText.ToString()
            && !captured.Body.Contains("Message body outside signature", StringComparison.Ordinal)
            && !captured.Body.Contains("passive Outlook comment", StringComparison.Ordinal)
            && !captured.Body.Contains("Quoted table", StringComparison.Ordinal),
            "Capture rebuilt or lost text/table structure instead of preserving the selected Outlook table.");
        var style = table.Attribute("style")?.Value ?? string.Empty;
        var firstCell = table.Descendants("td").First();
        var cellStyle = firstCell.Attribute("style")?.Value ?? string.Empty;
        var paragraphStyle = firstCell.Descendants("p").First().Attribute("style")?.Value ?? string.Empty;
        Expect(table.Ancestors().Any(element => element.Attribute("dir")?.Value == "rtl" && element.Attribute("lang")?.Value == "fa")
            && style.Contains("border-collapse:separate", StringComparison.Ordinal)
            && style.Contains("border-spacing:2px", StringComparison.Ordinal)
            && style.Contains("width:500px", StringComparison.Ordinal)
            && style.Contains("margin-left:auto", StringComparison.Ordinal)
            && style.Contains("margin-right:auto", StringComparison.Ordinal)
            && cellStyle.Contains("padding:3px", StringComparison.Ordinal)
            && cellStyle.Contains("vertical-align:middle", StringComparison.Ordinal)
            && cellStyle.Contains("border:1px solid #778899", StringComparison.Ordinal)
            && paragraphStyle.Contains("font-size:11pt", StringComparison.Ordinal)
            && paragraphStyle.Contains("color:#654321", StringComparison.Ordinal),
            "Safe Outlook table layout, inherited RTL, or font/color formatting was not retained.");
        Expect(captured.ReferencedContentIds.SequenceEqual(["company-logo"], StringComparer.OrdinalIgnoreCase)
            && captured.Warnings.Any(warning => warning.Contains("comments", StringComparison.OrdinalIgnoreCase))
            && captured.Warnings.Any(warning => warning.Contains("unsupported email styling", StringComparison.OrdinalIgnoreCase)),
            "Only referenced CID images were not reported, or dropped passive Office CSS lacked a warning.");

        const string unsupportedInlineStyle = "<html><body><table><tr><td><span style='mso-ligatures:standardcontextual;word-wrap:break-word'>Keep this text</span></td></tr></table></body></html>";
        var unsupportedParts = SignatureCapture.FindParts(unsupportedInlineStyle, "HTML");
        var unsupportedCapture = SignatureCapture.Extract(unsupportedInlineStyle, "HTML", unsupportedParts[0].Id);
        Expect(unsupportedCapture.Body.Contains("Keep this text", StringComparison.Ordinal)
            && !unsupportedCapture.Body.Contains("mso-ligatures", StringComparison.OrdinalIgnoreCase)
            && !unsupportedCapture.Body.Contains("word-wrap", StringComparison.OrdinalIgnoreCase)
            && unsupportedCapture.Warnings.Any(warning => warning.Contains("unsupported email styling", StringComparison.OrdinalIgnoreCase)),
            "Unsupported-only inline CSS leaked through capture or the source text was lost.");
    }

    private static void OutlookCommentWrappedStylesPreserveParagraphLayout()
    {
        const string source = "<html><head><style><!-- /* Style Definitions */ p.MsoNormal,li.MsoNormal,div.MsoNormal{margin:0in;font-size:12.0pt;font-family:\"Aptos\",sans-serif;mso-ligatures:standardcontextual;} --> .Accent{color:#123456}</style></head><body><table><tr><td><p class='MsoNormal Accent'><span>Example role</span></p><p class='MsoNormal' style='margin-top:2pt;font-size:10pt;font-family:Arial'>Example department</p></td></tr></table><!-- Ordinary body comment --></body></html>";
        var captured = SignatureCapture.Extract(source, "HTML", "table:0");
        var paragraphs = XElement.Parse("<root>" + captured.Body + "</root>").Descendants("p").ToArray();
        var normalStyle = paragraphs[0].Attribute("style")?.Value ?? string.Empty;
        var overriddenStyle = paragraphs[1].Attribute("style")?.Value ?? string.Empty;
        Expect(normalStyle.Contains("margin:0in", StringComparison.Ordinal)
            && normalStyle.Contains("font-size:12.0pt", StringComparison.Ordinal)
            && normalStyle.Contains("font-family:Aptos,sans-serif", StringComparison.Ordinal)
            && normalStyle.Contains("color:#123456", StringComparison.Ordinal)
            && paragraphs[0].Element("span")?.Attribute("style") is null
            && overriddenStyle.Contains("margin:0in", StringComparison.Ordinal)
            && overriddenStyle.Contains("margin-top:2pt", StringComparison.Ordinal)
            && overriddenStyle.Contains("font-size:10pt", StringComparison.Ordinal)
            && overriddenStyle.Contains("font-family:Arial", StringComparison.Ordinal)
            && !overriddenStyle.Contains("font-size:12.0pt", StringComparison.Ordinal)
            && !captured.Body.Contains("mso-ligatures", StringComparison.Ordinal)
            && !captured.Body.Contains("Ordinary body comment", StringComparison.Ordinal),
            "Outlook comment-wrapped stylesheet lost paragraph margins/fonts, surrounding CSS, inheritance or inline overrides.");
    }

    private static void CaptureDoesNotInheritLayoutProperties()
    {
        const string source = "<html><body style='font-family:Arial;font-size:12pt;color:#123456'><table style='width:600px;margin:5px;border-collapse:collapse'><tr><td style='width:300px;padding:4px;border:1px solid black'><p style='margin:0in;font-size:9pt'><span>Detail</span><img src='cid:logo' width='24' height='12'/></p></td></tr></table></body></html>";
        var captured = SignatureCapture.Extract(source, "HTML", "table:0");
        var root = XElement.Parse("<root>" + captured.Body + "</root>");
        var table = root.Descendants("table").Single();
        var cell = table.Descendants("td").Single();
        Expect(table.Attribute("style")?.Value.Contains("width:600px", StringComparison.Ordinal) == true
            && table.Attribute("style")?.Value.Contains("margin:5px", StringComparison.Ordinal) == true
            && cell.Attribute("style")?.Value.Contains("width:300px", StringComparison.Ordinal) == true
            && cell.Attribute("style")?.Value.Contains("padding:4px", StringComparison.Ordinal) == true
            && cell.Attribute("style")?.Value.Contains("border:1px solid black", StringComparison.Ordinal) == true,
            "Capture changed the table or cell's own layout properties.");
        foreach (var element in table.Descendants().Where(element => element.Name.LocalName is "p" or "span" or "img"))
        {
            var style = element.Attribute("style")?.Value ?? string.Empty;
            var properties = style.Split(';', StringSplitOptions.RemoveEmptyEntries)
                .Select(declaration => declaration.Split(':', 2)[0]).ToArray();
            Expect(!properties.Intersect(["width", "height", "padding", "border"], StringComparer.OrdinalIgnoreCase).Any()
                && (element.Name.LocalName == "p" || !properties.Contains("margin", StringComparer.OrdinalIgnoreCase))
                && !properties.Contains("font-family", StringComparer.OrdinalIgnoreCase)
                && !properties.Contains("color", StringComparer.OrdinalIgnoreCase)
                && (element.Name.LocalName == "p" || !properties.Contains("font-size", StringComparer.OrdinalIgnoreCase)),
                "Capture leaked ancestor layout into paragraph/span/image styles or lost genuine inherited typography.");
        }
        Expect(table.Descendants("p").Single().Attribute("style")?.Value.Contains("margin:0in", StringComparison.Ordinal) == true
            && table.Ancestors().Any(element => element.Attribute("style")?.Value == "font-family:Arial;font-size:12pt;color:#123456")
            && table.Descendants("img").Single().Attribute("width")?.Value == "24"
            && table.Descendants("img").Single().Attribute("height")?.Value == "12"
            && captured.ReferencedContentIds.SequenceEqual(["logo"]),
            "Capture changed the paragraph's own margin, image dimensions or CID reference.");
    }

    private static void CapturePreservesNativeBoldAndItalicInheritance()
    {
        const string source = "<html><body style='font-weight:400;font-style:oblique;color:#123456'><div id='_MailAutoSig'><b id='bold'><span><span>Bold</span></span></b><strong id='strong'><span>Strong</span></strong><i id='italic'><span><span>Italic</span></span></i><em id='emphasis'><span>Emphasis</span></em><b id='normal-bold' style='font-weight:normal'><span>Explicit normal weight</span></b><i id='normal-italic' style='font-style:normal'><span>Explicit normal style</span></i><span id='ordinary'>Ordinary</span></div></body></html>";
        var captured = SignatureCapture.Extract(source, "HTML", "signature:0");
        var root = XElement.Parse("<root>" + captured.Body + "</root>");
        foreach (var (id, property) in new[] { ("bold", "font-weight"), ("strong", "font-weight"), ("italic", "font-style"), ("emphasis", "font-style") })
        {
            var semantic = root.Descendants().Single(element => element.Attribute("id")?.Value == id);
            Expect(semantic.DescendantsAndSelf().All(element => !(element.Attribute("style")?.Value ?? string.Empty)
                    .Split(';', StringSplitOptions.RemoveEmptyEntries).Any(declaration => declaration.StartsWith(property + ":", StringComparison.Ordinal))),
                "Capture overrode native bold/italic formatting or compounded its relative weight on nested spans.");
        }
        foreach (var (id, declaration) in new[] { ("normal-bold", "font-weight:normal"), ("normal-italic", "font-style:normal") })
        {
            var semantic = root.Descendants().Single(element => element.Attribute("id")?.Value == id);
            Expect(semantic.Attribute("style")?.Value.Contains(declaration, StringComparison.Ordinal) == true
                && semantic.Descendants().All(element => element.Attribute("style") is null),
                "Capture lost an explicit inline override of native bold/italic formatting.");
        }
        var ordinary = root.Descendants().Single(element => element.Attribute("id")?.Value == "ordinary");
        Expect(ordinary.Attribute("style") is null
            && ordinary.Ancestors().Any(element => element.Attribute("style")?.Value == "font-weight:400;font-style:oblique;color:#123456"),
            "Capture lost ordinary inherited font weight/style outside semantic formatting elements.");
    }

    private static void CaptureRetainsRelativeTypographyContextAtEveryBoundary()
    {
        const string content = "<span id='relative' style='font-size:2em;line-height:150%;font-weight:bolder'><span id='nested'>Relative</span><span style='font-size:50%'>Override</span><b>Bold</b><i>Italic</i><small>Small</small><sup>Sup</sup><code>Code</code></span>";
        foreach (var (fragment, partId) in new[]
        {
            ("<table><tr><td>" + content + "</td></tr></table>", "table:0"),
            ("<div id='_MailAutoSig'>" + content + "</div>", "signature:0"),
            ("<p>Excluded prefix</p><p>" + content + "</p>", "blocks:1")
        })
        {
            var source = "<html dir='rtl' lang='fa' style='font-size:20px;margin:30px'><body style='font-size:125%;padding:40px'>"
                + "<div dir='ltr' lang='en' style='font-size:80%;width:600px;padding:4px'><p>Private message</p>"
                + fragment + "<blockquote>Private quote</blockquote></div></body></html>";
            // The suffix fixture has one additional block before its selected paragraph.
            var selectedId = partId == "blocks:1" ? "blocks:2" : partId;
            var captured = SignatureCapture.Extract(source, "HTML", selectedId);
            var root = XElement.Parse("<root>" + captured.Body + "</root>");
            var relative = root.Descendants().Single(element => element.Attribute("id")?.Value == "relative");
            Expect(XNode.DeepEquals(relative, XElement.Parse(content))
                && relative.Ancestors().Any(element => element.Attribute("style")?.Value == "font-size:20px"
                    && element.Attribute("dir")?.Value == "rtl" && element.Attribute("lang")?.Value == "fa")
                && relative.Ancestors().Any(element => element.Attribute("style")?.Value == "font-size:125%")
                && relative.Ancestors().Any(element => element.Attribute("style")?.Value == "font-size:80%;width:600px;padding:4px"
                    && element.Attribute("dir")?.Value == "ltr" && element.Attribute("lang")?.Value == "en")
                && root.Value == "RelativeOverrideBoldItalicSmallSupCode"
                && !captured.Body.Contains("margin:30px", StringComparison.Ordinal)
                && !captured.Body.Contains("padding:40px", StringComparison.Ordinal),
                "A candidate boundary copied relative typography into descendants, discarded ancestor context, or included sibling/quoted content.");
        }

        var headingCapture = SignatureCapture.Extract("<html><body style='font-size:20px;font-family:Arial'><div id='_MailAutoSig'><h1><small>Heading</small></h1></div></body></html>", "HTML", "signature:0");
        Expect(XNode.DeepEquals(XElement.Parse("<root>" + headingCapture.Body + "</root>").Descendants("h1").Single(),
                XElement.Parse("<h1><small>Heading</small></h1>")),
            "Capture materialized document typography onto native heading/small defaults.");

        var bodyless = SignatureCapture.Extract("<html dir='rtl' style='font-size:20px;margin:30px'><div id='_MailAutoSig' style='font-size:2em'><span>Bodyless</span></div></html>", "HTML", "signature:0");
        var bodylessRoot = XElement.Parse("<root>" + bodyless.Body + "</root>");
        Expect(bodylessRoot.Value == "Bodyless"
            && bodylessRoot.Descendants("span").Single().Attribute("style") is null
            && bodylessRoot.Descendants().Any(element => element.Attribute("dir")?.Value == "rtl" && element.Attribute("style")?.Value == "font-size:20px")
            && !bodyless.Body.Contains("margin:30px", StringComparison.Ordinal),
            "Capture lost the document's inheritance context when the source omitted a body element.");

        const string trailingText = "<html style='font-size:20px'><body><div dir='rtl' lang='fa' style='font-size:2em'><p>Private body</p>Regards<span> Name</span></div></body></html>";
        var textCapture = SignatureCapture.Extract(trailingText, "HTML", "blocks:1");
        var textRoot = XElement.Parse("<root>" + textCapture.Body + "</root>");
        Expect(textRoot.Value == "Regards Name"
            && textRoot.Descendants().Any(element => element.Attribute("style")?.Value == "font-size:2em"
                && element.Attribute("dir")?.Value == "rtl" && element.Attribute("lang")?.Value == "fa")
            && textRoot.Descendants("span").Single().Attribute("style") is null
            && !textRoot.Descendants("p").Any(),
            "Trailing text capture lost its original inline flow/context or included the preceding message block.");
    }

    private static void CapturePreservesSupportedCssCascadeOrder()
    {
        const string source = "<html><head><style>#chosen{color:blue}.layout{margin-left:2px;margin:4px;margin-left:8px;color:red}p{margin:16px;color:black}.layout{padding:3px}.layout{padding:5px}</style></head><body><div id='_MailAutoSig'><p id='chosen' class='layout' style='margin-top:1px;margin:6px;margin-top:9px'>Signature</p></div></body></html>";
        var captured = SignatureCapture.Extract(source, "HTML", "signature:0");
        var paragraph = XElement.Parse("<root>" + captured.Body + "</root>").Descendants("p").Single();
        var declarations = paragraph.Attribute("style")!.Value.Split(';');
        Expect(declarations.Contains("color:blue") && declarations.Contains("padding:5px")
            && !declarations.Contains("color:red") && !declarations.Contains("margin:16px")
            && Array.IndexOf(declarations, "margin-left:8px") < Array.IndexOf(declarations, "margin:6px")
            && Array.IndexOf(declarations, "margin:6px") < Array.IndexOf(declarations, "margin-top:9px"),
            "Supported selector specificity, equal-specificity source order, or inline shorthand/longhand order was lost: " + paragraph.Attribute("style")!.Value);

        const string classSource = "<html><head><style>.layout{margin-left:2px;margin:4px;margin-left:8px}p{margin:16px}</style></head><body><div id='_MailAutoSig'><p class='layout'>Signature</p></div></body></html>";
        var classCapture = SignatureCapture.Extract(classSource, "HTML", "signature:0");
        var classStyle = XElement.Parse("<root>" + classCapture.Body + "</root>").Descendants("p").Single().Attribute("style")!.Value;
        Expect(classStyle == "margin:4px;margin-left:8px",
            "A later tag rule overrode a class rule or a repeated longhand moved ahead of its shorthand.");
    }

    private static void CaptureRequiresAnExplicitFragmentForAmbiguousBodies()
    {
        const string multipleTables = "<html><body><p>Message intro</p><table><tr><td>First block</td></tr></table><table><tr><td>Second block</td></tr></table><div id='divRplyFwdMsg'><table><tr><td>Old quoted table</td></tr></table></div></body></html>";
        var tableParts = SignatureCapture.FindParts(multipleTables, "HTML");
        Expect(tableParts.Count == 2 && tableParts.Select(part => part.Id).SequenceEqual(["table:0", "table:1"]),
            "Multiple candidate tables were not returned as separate explicit choices.");
        var first = SignatureCapture.Extract(multipleTables, "HTML", "table:0");
        var second = SignatureCapture.Extract(multipleTables, "HTML", "table:1");
        Expect(first.Body.Contains("First block", StringComparison.Ordinal) && !first.Body.Contains("Second block", StringComparison.Ordinal)
            && second.Body.Contains("Second block", StringComparison.Ordinal) && !second.Body.Contains("Old quoted table", StringComparison.Ordinal),
            "Selecting a table copied the full email or quoted message rather than the selected source tree.");

        const string signatureBeforeOutlookQuote = "<html><body><p>Regards,</p><table><tr><td>Original signature table</td></tr></table><div id='divRplyFwdMsg'><table><tr><td>Quoted old signature</td></tr></table></div></body></html>";
        var beforeQuote = SignatureCapture.FindParts(signatureBeforeOutlookQuote, "HTML");
        Expect(beforeQuote.Count == 1 && beforeQuote[0].TextPreview.Contains("Original signature table", StringComparison.Ordinal)
            && SignatureCapture.Extract(signatureBeforeOutlookQuote, "HTML", beforeQuote[0].Id).Body.Contains("Original signature table", StringComparison.Ordinal),
            "An original signature table before Outlook's quoted-message marker was dropped.");

        const string paragraphs = "<html><body><div><p>Message body</p><p>Regards</p><p>Example Name</p></div></body></html>";
        var paragraphParts = SignatureCapture.FindParts(paragraphs, "HTML");
        Expect(paragraphParts.Count == 2 && paragraphParts[0].Id == "blocks:2" && paragraphParts[1].Id == "blocks:1"
            && paragraphParts.All(part => !part.TextPreview.Contains("Message body", StringComparison.Ordinal)),
            "Ambiguous paragraph signatures did not offer bounded trailing fragments without offering the whole message.");
        var trailing = SignatureCapture.Extract(paragraphs, "HTML", paragraphParts[1].Id);
        Expect(trailing.Body.Contains("Regards", StringComparison.Ordinal) && trailing.Body.Contains("Example Name", StringComparison.Ordinal)
            && !trailing.Body.Contains("Message body", StringComparison.Ordinal),
            "The selected trailing paragraph fragment changed its source text or included the email body.");

        var marked = SignatureCapture.FindParts("<html><body><p>Message body</p><div id='_MailAutoSig'><table><tr><td>Marked signature</td></tr></table></div></body></html>", "HTML");
        Expect(marked.Count == 1 && marked[0].Id == "signature:0" && marked[0].Kind == "signature"
            && SignatureCapture.Extract("<html><body><p>Message body</p><div id='_MailAutoSig'><table><tr><td>Marked signature</td></tr></table></div></body></html>", "HTML", marked[0].Id).Body.Contains("Marked signature", StringComparison.Ordinal),
            "An explicit Outlook signature marker was not captured as its own source fragment.");

        Expect(SignatureCapture.FindParts("<html><body><p>Only message paragraph</p></body></html>", "HTML").Count == 0,
            "A whole single-paragraph message was offered as a signature without an explicit boundary.");

        var invalidLayout = SignatureCapture.Extract(
            "<html><body><table style='width:500;border-spacing:2'><tr><td>Signature</td></tr></table></body></html>",
            "HTML", "table:0");
        Expect(!invalidLayout.Body.Contains("width:500;", StringComparison.Ordinal)
            && !invalidLayout.Body.Contains("border-spacing:2;", StringComparison.Ordinal)
            && invalidLayout.Warnings.Any(warning => warning.Contains("sizing", StringComparison.OrdinalIgnoreCase)),
            "Invalid unitless CSS table sizes were retained as if they were valid pixel values.");

        var textParts = SignatureCapture.FindParts("Message body\nRegards\nExample Name", "Text");
        Expect(textParts.Count == 2 && textParts.All(part => !part.TextPreview.Contains("Message body", StringComparison.Ordinal))
            && SignatureCapture.Extract("Message body\nRegards\nExample Name", "Text", "blocks:1").Body == "Regards\nExample Name",
            "Plain-text capture offered or returned the full email instead of an explicitly bounded suffix.");
    }

    private static void CaptureStopsAtQuotedThreadBoundaries()
    {
        const string originalSeparator = "Hello\n\nRegards,\nExample Name\n\n-----Original Message-----\nFrom: colleague@example.test\nSent: Monday\nTo: user@example.test\nSubject: Earlier mail\nQuoted body must not be captured";
        var separatorParts = SignatureCapture.FindParts(originalSeparator, "Text");
        Expect(separatorParts.Count > 0 && separatorParts.All(part =>
                !part.TextPreview.Contains("colleague@example.test", StringComparison.Ordinal)
                && !part.TextPreview.Contains("Quoted body", StringComparison.Ordinal))
            && SignatureCapture.Extract(originalSeparator, "Text", "blocks:1").Body == "Regards,\nExample Name",
            "Text signature capture included content from after the Outlook original-message separator.");

        const string headerOnly = "Hello\nBest regards,\nExample Name\n\nFrom: colleague@example.test\nSent: Monday\nTo: user@example.test\nSubject: Earlier mail\nQuoted body must not be captured";
        var headerParts = SignatureCapture.FindParts(headerOnly, "Text");
        Expect(headerParts.Count > 0 && headerParts.All(part =>
                !part.TextPreview.Contains("colleague@example.test", StringComparison.Ordinal)
                && !part.TextPreview.Contains("Quoted body", StringComparison.Ordinal))
            && SignatureCapture.Extract(headerOnly, "Text", "blocks:1").Body == "Best regards,\nExample Name",
            "Text signature capture did not stop at a quoted Outlook header block.");

        const string persianHeader = "سلام\nبا احترام\nنام کاربر\n\nاز: colleague@example.test\nارسال‌شده: دوشنبه\nبه: user@example.test\nموضوع: پیام قبلی\nمتن قدیمی نباید ذخیره شود";
        var persianParts = SignatureCapture.FindParts(persianHeader, "Text");
        Expect(persianParts.Count > 0 && persianParts.All(part => !part.TextPreview.Contains("متن قدیمی", StringComparison.Ordinal))
            && SignatureCapture.Extract(persianHeader, "Text", "blocks:1").Body == "با احترام\nنام کاربر",
            "Text signature capture did not stop at the Persian quoted-header block.");

        const string rfcQuote = "Hi\nRegards,\nExample Name\n\nOn Tuesday, colleague@example.test wrote:\n> Previous message one\n> Previous message two";
        var rfcParts = SignatureCapture.FindParts(rfcQuote, "Text");
        Expect(rfcParts.Count > 0 && rfcParts.All(part =>
                !part.TextPreview.Contains("Previous message", StringComparison.Ordinal)
                && !part.TextPreview.Contains("colleague@example.test", StringComparison.Ordinal))
            && SignatureCapture.Extract(rfcQuote, "Text", "blocks:1").Body == "Regards,\nExample Name",
            "Text signature capture included an RFC-style On-wrote or greater-than quoted block.");
    }

    private static void CaptureRejectsActiveOrRemoteContent()
    {
        var rejected = new Action[]
        {
            () => SignatureCapture.FindParts("<!DOCTYPE html><html><body><table><tr><td>A</td></tr></table></body></html>", "HTML"),
            () => SignatureCapture.FindParts("<html><body><script>alert(1)</script><table><tr><td>A</td></tr></table></body></html>", "HTML"),
            () => SignatureCapture.FindParts("<html><body><table onclick='alert(1)'><tr><td>A</td></tr></table></body></html>", "HTML"),
            () => SignatureCapture.FindParts("<html><body><table><tr><td><img src='https://example.test/logo.png'></td></tr></table></body></html>", "HTML"),
            () => SignatureCapture.FindParts("<html><head><style>table{background-image:url(https://example.test/x)}</style></head><body><table><tr><td>A</td></tr></table></body></html>", "HTML"),
            () => SignatureCapture.FindParts("<html><head><style><!-- p.MsoNormal{background-image:url(https://example.test/x)} --></style></head><body><table><tr><td>A</td></tr></table></body></html>", "HTML"),
            () => SignatureCapture.FindParts("<html><head><style><!-- p.MsoNormal{width:expression(alert(1))} --></style></head><body><table><tr><td>A</td></tr></table></body></html>", "HTML"),
            () => SignatureCapture.FindParts("<html><head><style><!-- @import 'https://example.test/style.css'; --></style></head><body><table><tr><td>A</td></tr></table></body></html>", "HTML"),
            () => SignatureCapture.FindParts("<html><head><link rel='stylesheet' href='https://example.test/style.css'></head><body><table><tr><td>A</td></tr></table></body></html>", "HTML"),
            () => SignatureCapture.FindParts("<html><body><meta http-equiv='refresh' content='0;url=https://example.test'></body></html>", "HTML"),
            () => SignatureCapture.FindParts(new string('x', SignatureCapture.MaxSourceLength + 1), "Text"),
            () => SignatureCapture.FindParts("<html><body>" + string.Concat(Enumerable.Range(0, 70).Select(_ => "<div>"))
                + "Deep" + string.Concat(Enumerable.Range(0, 70).Select(_ => "</div>")) + "</body></html>", "HTML")
        };
        foreach (var attempt in rejected)
        {
            var didReject = false;
            try { attempt(); }
            catch (ArgumentException) { didReject = true; }
            Expect(didReject, "The signature capture parser accepted active, remote, or over-limit content.");
        }
    }
}
