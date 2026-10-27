using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.Linq;

namespace Company.ExchangeMcp.Exchange;

public sealed record SignatureCapturePart(string Id, string Kind, string TextPreview, IReadOnlyList<string> Warnings);

public sealed record SignatureCaptureResult(string Body, string BodyType,
    IReadOnlyList<string> ReferencedContentIds, IReadOnlyList<string> Warnings);

/// <summary>
/// Captures a user-selected, bounded piece of an Exchange message without asking an agent to
/// reconstruct its markup. This parser never fetches URLs or attachment bytes.
/// </summary>
public static class SignatureCapture
{
    public const int MaxSourceLength = 1_048_576;
    public const int MaxCandidateLength = 65_536;
    public const int MaxParts = 32;
    private const int MaxNodes = 10_000;
    private const int MaxReferencedImages = 32;
    private const string XhtmlNamespace = "http://www.w3.org/1999/xhtml";
    private const string Html4Namespace = "http://www.w3.org/TR/REC-html40";

    private static readonly Regex VoidTags = new(
        "<(?<name>img|br|hr|meta|link|col|input)\\b(?<tail>(?:\"[^\"]*\"|'[^']*'|[^'\">])*)>",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));
    private static readonly Regex NamedEntity = new("&(?<name>[A-Za-z][A-Za-z0-9]+);",
        RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));
    private static readonly Regex DangerousCss = new(
        "(?:url\\s*\\(|expression\\s*\\(|javascript\\s*:|vbscript\\s*:|data\\s*:|@import|-moz-binding|behavior\\s*:)",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));
    private static readonly Regex CssRule = new("(?<selector>[^{}]+)\\{(?<body>[^{}]*)\\}",
        RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));
    private static readonly Regex CssComment = new("/\\*.*?\\*/", RegexOptions.Singleline | RegexOptions.CultureInvariant,
        TimeSpan.FromSeconds(1));
    private static readonly Regex WhiteSpace = new("\\s+", RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));
    private static readonly Regex ExplicitTextQuote = new(
        "^\\s*(?:-{2,}\\s*(?:original message|forwarded message|پیام اصلی|پیام قبلی)\\s*-{2,}|begin forwarded message:|on\\s+.{1,200}\\s+wrote:)\\s*$",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));
    private static readonly Regex ReplyHeader = new(
        "^\\s*(?<label>from|sent|to|subject|date|cc|bcc|از|فرستنده|ارسال(?:\\s|‌)?شده|به|موضوع|تاریخ|رونوشت(?:\\s+مخفی)?)\\s*:",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));
    private static readonly Regex SimpleSelector = new(
        "^(?<tag>[A-Za-z][A-Za-z0-9-]*)?(?<rest>(?:[.#][A-Za-z_][A-Za-z0-9_-]*)*)$",
        RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));

    private static readonly HashSet<string> SafeElements = new(StringComparer.OrdinalIgnoreCase)
    {
        "a", "b", "blockquote", "br", "caption", "code", "col", "colgroup", "del", "div", "em",
        "h1", "h2", "h3", "h4", "h5", "h6", "hr", "i", "img", "li", "ol", "p", "pre", "s",
        "small", "span", "strong", "sub", "sup", "table", "tbody", "td", "tfoot", "th", "thead",
        "tr", "u", "ul"
    };

    // Keep this aligned with RichBody's deliberately small inline CSS allowlist. The last four
    // layout properties are also being added to RichBody for captured Outlook tables.
    private static readonly HashSet<string> SafeCss = new(StringComparer.OrdinalIgnoreCase)
    {
        "background-color", "border", "border-bottom", "border-collapse", "border-color", "border-left",
        "border-radius", "border-right", "border-spacing", "border-style", "border-top", "border-width",
        "color", "direction", "font-family", "font-size", "font-style", "font-weight", "height", "line-height",
        "margin", "margin-bottom", "margin-left", "margin-right", "margin-top", "padding", "padding-bottom",
        "padding-left", "padding-right", "padding-top", "table-layout", "text-align", "text-decoration",
        "vertical-align", "white-space", "width"
    };

    private static readonly HashSet<string> InheritedCss = new(StringComparer.OrdinalIgnoreCase)
    {
        "color", "direction", "font-family", "font-size", "font-style", "font-weight", "line-height",
        "text-align", "white-space"
    };

    public static IReadOnlyList<SignatureCapturePart> FindParts(string body, string bodyType)
    {
        var source = Parse(body, bodyType);
        var candidates = FindCandidates(source);
        return candidates.Select(candidate => new SignatureCapturePart(candidate.Id, candidate.Kind,
            Preview(candidate), Warnings(source.Warnings))).ToArray();
    }

    public static SignatureCaptureResult Extract(string body, string bodyType, string partId)
    {
        if (string.IsNullOrWhiteSpace(partId) || partId.Length > 32)
            throw new ArgumentException("A valid signature part ID is required.", nameof(partId));
        var source = Parse(body, bodyType);
        var candidate = FindCandidates(source).SingleOrDefault(item => item.Id == partId)
            ?? throw new ArgumentException("The selected signature part is unavailable. Refresh the message and select a listed part.", nameof(partId));

        string captured;
        if (source.BodyType == "Text")
        {
            captured = candidate.TextBody ?? throw new ArgumentException("The selected text part is unavailable.", nameof(partId));
        }
        else
        {
            captured = string.Concat(candidate.Nodes.Select(node => node.ToString(SaveOptions.DisableFormatting)));
            if (captured.Length > MaxCandidateLength)
                throw new ArgumentException("The selected signature part exceeds the 64 KiB capture limit.", nameof(partId));
            captured = RichBody.Validate(captured, "HTML");
        }
        if (captured.Length > MaxCandidateLength)
            throw new ArgumentException("The normalized signature part exceeds the 64 KiB capture limit.", nameof(partId));

        var contentIds = source.BodyType == "Text" ? Array.Empty<string>() : FindContentIds(captured);
        return new SignatureCaptureResult(captured, source.BodyType, contentIds, Warnings(source.Warnings));
    }

    internal static (string Html, string[] Warnings) RenderMessage(string body)
    {
        var source = Parse(body, "HTML", removeQuotedAreas: false);
        var html = string.Concat(CaptureContext(source.Body, source.Body.Nodes())
            .Select(node => node.ToString(SaveOptions.DisableFormatting)));
        return (RichBody.Validate(html, "HTML"), Warnings(source.Warnings).ToArray());
    }

    private static ParsedSource Parse(string body, string bodyType, bool removeQuotedAreas = true)
    {
        ArgumentNullException.ThrowIfNull(body);
        var normalizedType = RichBody.NormalizeBodyType(bodyType);
        if (body.Length > MaxSourceLength)
            throw new ArgumentException("The selected email body exceeds the 1 MiB source limit.", nameof(body));
        if (normalizedType == "Text") return ParseText(body);

        try
        {
            var root = removeQuotedAreas ? ParseXml(NormalizeHtml(body)) : RichBody.ParseExchangeHtml(body);
            if (root.DescendantsAndSelf().Count() > MaxNodes)
                throw new ArgumentException("The selected email body contains too many HTML nodes.", nameof(body));

            var warnings = new List<string>();
            var styleRules = ReadStyles(root, warnings);
            ApplyStyles(root, styleRules, warnings);
            CleanTree(root, warnings);
            NormalizeNamespaces(root, warnings);
            var bodyElement = root.DescendantsAndSelf().FirstOrDefault(IsBodyElement);
            if (bodyElement is null)
            {
                var html = root.DescendantsAndSelf().FirstOrDefault(IsHtmlElement);
                var nodes = (html?.Nodes() ?? root.Nodes()).Where(node => node is not XElement element
                    || !IsHeadElement(element)).Select(CloneNode).ToArray();
                bodyElement = new XElement("body", nodes);
                if (html is not null) html.ReplaceNodes(bodyElement);
            }
            else
            {
                bodyElement.Name = "body";
            }

            if (removeQuotedAreas) RemoveQuotedAreas(bodyElement, warnings);
            return new ParsedSource("HTML", bodyElement, null, warnings);
        }
        catch (RegexMatchTimeoutException exception)
        {
            throw new ArgumentException("The selected email body exceeded an HTML parsing limit.", nameof(body), exception);
        }
        catch (XmlException exception)
        {
            throw new ArgumentException("The selected email body is not safe, bounded XHTML and could not be captured.", nameof(body), exception);
        }
    }

    private static ParsedSource ParseText(string body)
    {
        var lines = body.Replace("\r\n", "\n", StringComparison.Ordinal).Replace('\r', '\n')
            .Split('\n').Select((line, index) => new TextLine(index, line)).ToArray();
        if (lines.Length > MaxNodes)
            throw new ArgumentException("The selected plain-text email contains too many lines.", nameof(body));
        return new ParsedSource("Text", new XElement("body"), lines, []);
    }

    private static string NormalizeHtml(string body)
    {
        var normalized = VoidTags.Replace(body, static match =>
        {
            var open = match.Value[..^1].TrimEnd();
            return open.EndsWith("/", StringComparison.Ordinal) ? match.Value : open + " />";
        });
        return NamedEntity.Replace(normalized, match =>
        {
            var name = match.Groups["name"].Value;
            if (name.Equals("amp", StringComparison.OrdinalIgnoreCase)
                || name.Equals("lt", StringComparison.OrdinalIgnoreCase)
                || name.Equals("gt", StringComparison.OrdinalIgnoreCase)
                || name.Equals("quot", StringComparison.OrdinalIgnoreCase)
                || name.Equals("apos", StringComparison.OrdinalIgnoreCase)) return match.Value;
            var decoded = WebUtility.HtmlDecode(match.Value);
            if (decoded == match.Value) return match.Value;
            var encoded = new StringBuilder();
            foreach (var rune in decoded.EnumerateRunes())
                encoded.Append("&#x").Append(rune.Value.ToString("X", System.Globalization.CultureInfo.InvariantCulture)).Append(';');
            return encoded.ToString();
        });
    }

    private static XElement ParseXml(string fragment)
    {
        var document = $"<root>{fragment}</root>";
        var settings = new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Prohibit,
            XmlResolver = null,
            MaxCharactersInDocument = MaxSourceLength + 32
        };
        using (var scan = XmlReader.Create(new StringReader(document), settings))
        {
            while (scan.Read())
            {
                if (scan.Depth > RichBody.MaxHtmlDepth + 2)
                    throw new ArgumentException("The selected email body exceeds the HTML nesting limit.");
                if (scan.NodeType == XmlNodeType.DocumentType)
                    throw new ArgumentException("Document type declarations are not allowed.");
            }
        }
        using var reader = XmlReader.Create(new StringReader(document), settings);
        return XElement.Load(reader, LoadOptions.PreserveWhitespace);
    }

    private static List<StyleRule> ReadStyles(XElement root, List<string> warnings)
    {
        var rules = new List<StyleRule>();
        foreach (var style in root.Descendants().Where(element => NameIs(element, "style")).ToArray())
        {
            // Outlook wraps stylesheet text in HTML comments; include it in the same CSS validation.
            var css = string.Concat(style.DescendantNodes().Select(node => node switch
            {
                XComment comment => comment.Value,
                XText text => text.Value,
                _ => string.Empty
            }));
            css = css.Replace("<!--", string.Empty, StringComparison.Ordinal)
                .Replace("-->", string.Empty, StringComparison.Ordinal);
            css = CssComment.Replace(css, string.Empty);
            if (DangerousCss.IsMatch(css))
                throw new ArgumentException("The selected email contains active or remotely loaded CSS.");
            foreach (Match match in CssRule.Matches(css))
            {
                var selector = match.Groups["selector"].Value.Trim();
                if (selector.StartsWith('@'))
                {
                    AddWarning(warnings, "Some unsupported email styling was omitted.");
                    continue;
                }
                var declarations = ParseDeclarations(match.Groups["body"].Value, warnings);
                if (declarations.Count == 0) continue;
                foreach (var item in selector.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
                {
                    if (!IsSupportedSelector(item))
                    {
                        AddWarning(warnings, "Some unsupported email styling was omitted.");
                        continue;
                    }
                    rules.Add(new StyleRule(item, declarations));
                    if (rules.Count > 256)
                        throw new ArgumentException("The selected email contains too many style rules.");
                }
            }
        }
        return rules;
    }

    private static void ApplyStyles(XElement root, IReadOnlyList<StyleRule> rules, List<string> warnings)
    {
        var elements = root.DescendantsAndSelf().ToArray();
        var orderedRules = rules.OrderBy(rule => (rule.Selector.Count(character => character == '#'),
            rule.Selector.Count(character => character == '.'),
            rule.Selector.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries)
                .Count(part => char.IsAsciiLetter(part[0])))).ToArray();
        var declarations = elements.ToDictionary(element => element, _ => new OrderedDictionary<string, string>(StringComparer.OrdinalIgnoreCase));
        foreach (var element in elements) ApplyLegacyAttributes(element, declarations[element], warnings);
        foreach (var table in elements.Where(element => NameIs(element, "table")))
        {
            var cellPadding = RawAttribute(table, "cellpadding");
            if (!string.IsNullOrWhiteSpace(cellPadding) && IsDimension(cellPadding))
            {
                foreach (var cell in table.Descendants().Where(element => NameIs(element, "td") || NameIs(element, "th")))
                    declarations[cell].TryAdd("padding", NormalizeLegacyDimension(cellPadding));
            }
        }
        foreach (var element in elements)
        {
            foreach (var rule in orderedRules)
                if (Matches(element, rule.Selector))
                    foreach (var declaration in rule.Declarations)
                    {
                        declarations[element].Remove(declaration.Key);
                        declarations[element][declaration.Key] = declaration.Value;
                    }
            var inline = RawAttribute(element, "style");
            element.Attributes().FirstOrDefault(attribute => attribute.Name.LocalName.Equals("style", StringComparison.OrdinalIgnoreCase))?.Remove();
            if (!string.IsNullOrWhiteSpace(inline))
                foreach (var declaration in ParseDeclarations(inline, warnings))
                {
                    declarations[element].Remove(declaration.Key);
                    declarations[element][declaration.Key] = declaration.Value;
                }
            if (declarations[element].Count > 0)
                SetAttribute(element, "style", string.Join(";", declarations[element].Select(item => item.Key + ":" + item.Value)));
        }
    }

    private static void ApplyLegacyAttributes(XElement element, OrderedDictionary<string, string> css, List<string> warnings)
    {
        var align = RawAttribute(element, "align");
        if (!string.IsNullOrWhiteSpace(align))
        {
            var value = align.Trim().ToLowerInvariant();
            if (NameIs(element, "table"))
            {
                if (value == "center") { css["margin-left"] = "auto"; css["margin-right"] = "auto"; }
                else if (value == "right") { css["margin-left"] = "auto"; css["margin-right"] = "0"; }
                else if (value == "left") { css["margin-left"] = "0"; css["margin-right"] = "auto"; }
                else AddWarning(warnings, "Some unsupported email alignment was omitted.");
            }
            else if (value is "left" or "right" or "center" or "justify") css["text-align"] = value;
            else AddWarning(warnings, "Some unsupported email alignment was omitted.");
        }
        var valign = RawAttribute(element, "valign");
        if (!string.IsNullOrWhiteSpace(valign))
        {
            var value = valign.Trim().ToLowerInvariant();
            if (value is "top" or "middle" or "bottom" or "baseline") css["vertical-align"] = value;
            else AddWarning(warnings, "Some unsupported email alignment was omitted.");
        }
        var cellSpacing = RawAttribute(element, "cellspacing");
        if (NameIs(element, "table") && IsDimension(cellSpacing)
            && IsBorderSpacing(NormalizeLegacyDimension(cellSpacing!)))
        {
            css["border-spacing"] = NormalizeLegacyDimension(cellSpacing!);
            css.TryAdd("border-collapse", "separate");
        }
        var border = RawAttribute(element, "border");
        if (NameIs(element, "table") && IsIntegerInRange(border, 0, 10))
        {
            css["border"] = int.Parse(border!, System.Globalization.CultureInfo.InvariantCulture) == 0
                ? "none" : int.Parse(border!, System.Globalization.CultureInfo.InvariantCulture).ToString(System.Globalization.CultureInfo.InvariantCulture) + "px solid";
        }
        var background = RawAttribute(element, "bgcolor");
        if (!string.IsNullOrWhiteSpace(background) && IsSafeColor(background)) css["background-color"] = background.Trim();
        else if (!string.IsNullOrWhiteSpace(background)) AddWarning(warnings, "Some unsupported email colors were omitted.");
    }

    private static OrderedDictionary<string, string> ParseDeclarations(string source, List<string> warnings)
    {
        if (DangerousCss.IsMatch(source))
            throw new ArgumentException("The selected email contains active or remotely loaded CSS.");
        var declarations = new OrderedDictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var item in source.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var separator = item.IndexOf(':');
            if (separator <= 0) { AddWarning(warnings, "Some unsupported email styling was omitted."); continue; }
            var property = item[..separator].Trim().ToLowerInvariant();
            var value = item[(separator + 1)..].Replace("\r", " ", StringComparison.Ordinal)
                .Replace("\n", " ", StringComparison.Ordinal).Replace("\t", " ", StringComparison.Ordinal).Trim();
            if (property.StartsWith("mso-", StringComparison.OrdinalIgnoreCase) || !SafeCss.Contains(property))
            {
                AddWarning(warnings, "Some unsupported email styling was omitted.");
                continue;
            }
            if (property.Equals("font-family", StringComparison.OrdinalIgnoreCase))
                value = NormalizeFontFamilies(value);
            if (value.Length == 0 || value.Length > 1024 || value.Any(char.IsControl)
                || value.Contains('\\') || value.Contains('<') || value.Contains('>')
                || value.Contains('"') || value.Contains('\''))
                throw new ArgumentException("The selected email contains unsafe inline styling.");
            if (property.Equals("direction", StringComparison.OrdinalIgnoreCase)
                && !new[] { "ltr", "rtl" }.Contains(value, StringComparer.OrdinalIgnoreCase))
                throw new ArgumentException("The selected email contains unsupported text direction.");
            if (property.Equals("border-collapse", StringComparison.OrdinalIgnoreCase)
                && !new[] { "collapse", "separate" }.Contains(value, StringComparer.OrdinalIgnoreCase))
            { AddWarning(warnings, "Some unsupported email table styling was omitted."); continue; }
            if (property.Equals("table-layout", StringComparison.OrdinalIgnoreCase)
                && !new[] { "auto", "fixed" }.Contains(value, StringComparer.OrdinalIgnoreCase))
            { AddWarning(warnings, "Some unsupported email table styling was omitted."); continue; }
            if (((property is "width" or "height") && !IsCssDimension(value, allowKeywords: true))
                || property.Equals("border-spacing", StringComparison.OrdinalIgnoreCase) && !IsBorderSpacing(value))
            { AddWarning(warnings, "Some unsupported email table sizing was omitted."); continue; }
            declarations.Remove(property);
            declarations[property] = value;
        }
        return declarations;
    }

    private static void CleanTree(XElement root, List<string> warnings)
    {
        var removableNodes = root.DescendantNodes().Where(node => node is XComment or XProcessingInstruction).ToArray();
        foreach (var node in removableNodes) node.Remove();
        if (removableNodes.Length > 0)
            AddWarning(warnings, "Email comments and processing instructions were removed.");
        var elements = root.DescendantsAndSelf().ToArray();
        foreach (var element in elements)
        {
            var name = element.Name.LocalName;
            if (name.Equals("script", StringComparison.OrdinalIgnoreCase)
                || name.Equals("iframe", StringComparison.OrdinalIgnoreCase)
                || name.Equals("object", StringComparison.OrdinalIgnoreCase)
                || name.Equals("embed", StringComparison.OrdinalIgnoreCase)
                || name.Equals("form", StringComparison.OrdinalIgnoreCase)
                || name.Equals("svg", StringComparison.OrdinalIgnoreCase)
                || name.Equals("math", StringComparison.OrdinalIgnoreCase)
                || name.Equals("video", StringComparison.OrdinalIgnoreCase)
                || name.Equals("audio", StringComparison.OrdinalIgnoreCase)
                || name.Equals("canvas", StringComparison.OrdinalIgnoreCase)
                || name.Equals("base", StringComparison.OrdinalIgnoreCase))
                throw new ArgumentException("Active or embedded content is not allowed in a captured signature.");
            if (element.Name.NamespaceName.Contains("schemas-microsoft-com:office", StringComparison.OrdinalIgnoreCase)
                && name.Equals("p", StringComparison.OrdinalIgnoreCase))
            {
                element.ReplaceWith(element.Nodes().Select(CloneNode));
                AddWarning(warnings, "Office paragraph wrappers were removed; text and children were kept.");
                continue;
            }
            if (name.Equals("link", StringComparison.OrdinalIgnoreCase))
                throw new ArgumentException("Remote or linked stylesheets are not allowed in a captured signature.");
            if (name.Equals("meta", StringComparison.OrdinalIgnoreCase))
            {
                if (RawAttribute(element, "http-equiv")?.Equals("refresh", StringComparison.OrdinalIgnoreCase) == true)
                    throw new ArgumentException("Active HTML refresh directives are not allowed in a captured signature.");
                element.Remove();
                continue;
            }
            if (element.Ancestors().Any(ancestor => NameIs(ancestor, "head")
                || NameIs(ancestor, "title") || NameIs(ancestor, "style"))
                && !new[] { "head", "title", "style" }.Contains(name, StringComparer.OrdinalIgnoreCase))
                continue;
            if (element.Name.Namespace != XNamespace.None
                && element.Name.NamespaceName != XhtmlNamespace && element.Name.NamespaceName != Html4Namespace)
                throw new ArgumentException("Unsupported namespaced content is not allowed in a captured signature.");
            if (name.Equals("title", StringComparison.OrdinalIgnoreCase)
                || name.Equals("head", StringComparison.OrdinalIgnoreCase) || name.Equals("style", StringComparison.OrdinalIgnoreCase))
            {
                element.Remove();
                continue;
            }
            if (name.Equals("font", StringComparison.OrdinalIgnoreCase)) ConvertFontElement(element, warnings);
            else if (name.Equals("center", StringComparison.OrdinalIgnoreCase))
            {
                element.Name = "div";
                var styles = ParseStyleMap(RawAttribute(element, "style"));
                styles["text-align"] = "center";
                SetAttribute(element, "style", string.Join(";", styles.Select(item => item.Key + ":" + item.Value)));
            }
            if (!SafeElements.Contains(element.Name.LocalName)
                && !new[] { "root", "html", "body" }.Contains(element.Name.LocalName, StringComparer.OrdinalIgnoreCase))
                throw new ArgumentException($"Unsupported HTML element '{name}' is not allowed in a captured signature.");

            foreach (var attribute in element.Attributes().Where(attribute => !attribute.IsNamespaceDeclaration).ToArray())
            {
                var attributeName = attribute.Name.LocalName;
                if (attributeName.StartsWith("on", StringComparison.OrdinalIgnoreCase))
                    throw new ArgumentException("Active event handlers are not allowed in a captured signature.");
                if (attributeName.Equals("background", StringComparison.OrdinalIgnoreCase))
                    throw new ArgumentException("Remote background images are not allowed in a captured signature.");
                if (attribute.Name.Namespace == XNamespace.None && attributeName.Equals("name", StringComparison.OrdinalIgnoreCase)
                    && IsSignatureMarker(element))
                {
                    SetAttribute(element, "id", attribute.Value);
                    attribute.Remove();
                    continue;
                }
                if (attribute.Name.Namespace != XNamespace.None)
                {
                    if (attribute.Name.Namespace == XNamespace.Xml && attributeName.Equals("lang", StringComparison.OrdinalIgnoreCase))
                    {
                        SetAttribute(element, "lang", attribute.Value);
                        attribute.Remove();
                        continue;
                    }
                    attribute.Remove();
                    AddWarning(warnings, "Some Office-specific email metadata was removed.");
                    continue;
                }
                if (new[] { "cellpadding", "cellspacing", "align", "valign", "border", "bgcolor" }
                    .Contains(attributeName, StringComparer.OrdinalIgnoreCase))
                { attribute.Remove(); continue; }
                if (attributeName.Equals("class", StringComparison.OrdinalIgnoreCase))
                {
                    if (attribute.Value.Length > 256 || attribute.Value.Any(character =>
                            !(char.IsAsciiLetterOrDigit(character) || character is '_' or '-' or ' ')))
                    { attribute.Remove(); AddWarning(warnings, "Some unsupported Office-specific formatting was removed."); }
                    continue;
                }
                if (attributeName.Equals("style", StringComparison.OrdinalIgnoreCase)
                    || attributeName.Equals("width", StringComparison.OrdinalIgnoreCase)
                    || attributeName.Equals("height", StringComparison.OrdinalIgnoreCase)
                    || attributeName.Equals("dir", StringComparison.OrdinalIgnoreCase)
                    || attributeName.Equals("lang", StringComparison.OrdinalIgnoreCase)
                    || attributeName.Equals("id", StringComparison.OrdinalIgnoreCase)
                    || attributeName.Equals("href", StringComparison.OrdinalIgnoreCase)
                    || attributeName.Equals("src", StringComparison.OrdinalIgnoreCase)
                    || attributeName.Equals("alt", StringComparison.OrdinalIgnoreCase)
                    || attributeName.Equals("title", StringComparison.OrdinalIgnoreCase)
                    || attributeName.Equals("colspan", StringComparison.OrdinalIgnoreCase)
                    || attributeName.Equals("rowspan", StringComparison.OrdinalIgnoreCase)
                    || attributeName.Equals("scope", StringComparison.OrdinalIgnoreCase))
                    continue;
                attribute.Remove();
                AddWarning(warnings, "Some unsupported Office-specific formatting was removed.");
            }
            if (NameIs(element, "img"))
            {
                var src = RawAttribute(element, "src");
                if (src is null || !src.StartsWith("cid:", StringComparison.OrdinalIgnoreCase))
                    throw new ArgumentException("Only message-local CID images can be captured; remote images are not fetched.");
                if (!IsSimpleContentId(src[4..]))
                    throw new ArgumentException("The selected email contains an invalid inline image reference.");
            }
            foreach (var attributeName in new[] { "width", "height" })
            {
                var attribute = element.Attribute(attributeName);
                if (attribute is not null && !IsDimension(attribute.Value))
                {
                    attribute.Remove();
                    AddWarning(warnings, "Some unsupported email sizing was omitted.");
                }
            }
            foreach (var attributeName in new[] { "colspan", "rowspan" })
            {
                var attribute = element.Attribute(attributeName);
                if (attribute is not null && !IsIntegerInRange(attribute.Value, 1, 100))
                {
                    attribute.Remove();
                    AddWarning(warnings, "Some unsupported email table sizing was omitted.");
                }
            }
        }
    }

    private static IReadOnlyList<XNode> CaptureContext(XElement body, IEnumerable<XNode> nodes)
    {
        var selected = nodes.ToHashSet();
        var ancestors = selected.SelectMany(node => node.Ancestors()).ToHashSet();

        XNode CopyBranch(XNode node)
        {
            if (selected.Contains(node)) return CloneNode(node);
            var element = (XElement)node;
            var children = element.Nodes().Where(child => selected.Contains(child)
                || child is XElement branch && ancestors.Contains(branch)).Select(CopyBranch);
            if (!IsBodyElement(element) && !IsHtmlElement(element))
                return new XElement(element.Name, element.Attributes(), children);

            // Keep document inheritance without importing the email body's page layout.
            var context = new XElement("div", children);
            var style = ParseStyleMap(RawAttribute(element, "style"))
                .Where(pair => InheritedCss.Contains(pair.Key)).ToArray();
            if (style.Length > 0)
                SetAttribute(context, "style", string.Join(";", style.Select(pair => pair.Key + ":" + pair.Value)));
            foreach (var attribute in new[] { "dir", "lang" })
                if (RawAttribute(element, attribute) is { } value) SetAttribute(context, attribute, value);
            return context;
        }

        var root = body.Ancestors().FirstOrDefault(IsHtmlElement) ?? body;
        return [CopyBranch(root)];
    }

    private static IReadOnlyList<Candidate> FindCandidates(ParsedSource source)
    {
        if (source.BodyType == "Text") return FindTextCandidates(source.TextLines ?? []);
        var body = source.Body;
        var markers = body.DescendantsAndSelf().Where(IsSignatureMarker)
            .Where(element => !NameIs(element, "body") && !NameIs(element, "html") && !IsQuoted(element))
            .Where(element => !element.Ancestors().Any(ancestor => IsSignatureMarker(ancestor)))
            .ToArray();
        if (markers.Length > 0)
            return Bounded(markers.Select((node, index) => new Candidate("signature:" + index, "signature", CaptureContext(body, [node]), null)).ToArray());

        var tables = body.Descendants().Where(element => NameIs(element, "table")
            && !element.Ancestors().Any(ancestor => NameIs(ancestor, "table") || IsQuoted(ancestor))).ToArray();
        if (tables.Length > 0)
            return Bounded(tables.Select((node, index) => new Candidate("table:" + index, "table", CaptureContext(body, [node]), null)).ToArray());

        var blocks = new List<XNode>();
        foreach (var child in body.Nodes()) CollectBlocks(child, blocks);
        // Offer only trailing fragments that exclude the whole message. Never auto-select or
        // surface the complete body as a signature when no explicit boundary or table exists.
        if (blocks.Count < 2) return [];
        var candidates = new List<Candidate>();
        var first = Math.Max(1, blocks.Count - MaxParts);
        for (var start = blocks.Count - 1; start >= first; start--)
        {
            var nodes = CaptureContext(body, blocks.Skip(start));
            candidates.Add(new Candidate("blocks:" + start, "blocks", nodes, null));
        }
        return candidates.Where(candidate => CandidateLength(candidate) <= MaxCandidateLength).ToArray();
    }

    private static IReadOnlyList<Candidate> FindTextCandidates(IReadOnlyList<TextLine> lines)
    {
        var quoteStart = FindTextQuoteStart(lines);
        var unquotedLines = lines.Where(line => line.Index < quoteStart).ToArray();
        var nonempty = unquotedLines.Where(line => !string.IsNullOrWhiteSpace(line.Text)).ToArray();
        if (nonempty.Length < 2) return [];
        var candidates = new List<Candidate>();
        var first = Math.Max(1, nonempty.Length - MaxParts);
        for (var start = nonempty.Length - 1; start >= first; start--)
        {
            var selected = unquotedLines.Where(line => line.Index >= nonempty[start].Index
                && line.Index <= nonempty[^1].Index).Select(line => line.Text).ToArray();
            var candidateBody = string.Join("\n", selected);
            if (candidateBody.Length <= MaxCandidateLength)
                candidates.Add(new Candidate("blocks:" + start, "blocks", [], candidateBody));
        }
        return candidates;
    }

    internal static int FindTextQuoteOffset(string body)
    {
        var quoteLine = FindTextQuoteStart(ParseText(body).TextLines ?? []);
        if (quoteLine == int.MaxValue) return body.Length;
        var line = 0;
        for (var offset = 0; offset < body.Length; offset++)
        {
            if (line == quoteLine) return offset;
            if (body[offset] == '\r')
            {
                if (offset + 1 < body.Length && body[offset + 1] == '\n') offset++;
                line++;
            }
            else if (body[offset] == '\n') line++;
        }
        return body.Length;
    }

    private static int FindTextQuoteStart(IReadOnlyList<TextLine> lines)
    {
        for (var index = 0; index < lines.Count; index++)
        {
            if (ExplicitTextQuote.IsMatch(lines[index].Text)
                || lines[index].Text.TrimStart().StartsWith('>')) return lines[index].Index;
            if (!TryGetReplyHeader(lines[index].Text, out var firstLabel) || firstLabel != "from") continue;

            var labels = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { firstLabel };
            var blankLines = 0;
            for (var next = index + 1; next < lines.Count && next < index + 9; next++)
            {
                if (TryGetReplyHeader(lines[next].Text, out var label)) labels.Add(label);
                else if (string.IsNullOrWhiteSpace(lines[next].Text) && blankLines++ == 0) continue;
                else if (char.IsWhiteSpace(lines[next].Text.FirstOrDefault()) && labels.Count > 1) continue;
                else break;

                if (labels.Count >= 2 && labels.Overlaps(["sent", "to", "subject", "date", "cc", "bcc"]))
                    return lines[index].Index;
            }
        }
        return int.MaxValue;
    }

    private static bool TryGetReplyHeader(string line, out string label)
    {
        var match = ReplyHeader.Match(line);
        if (!match.Success)
        {
            label = string.Empty;
            return false;
        }
        label = match.Groups["label"].Value.ToLowerInvariant();
        if (label is "از" or "فرستنده") label = "from";
        else if (label is "ارسال شده" or "ارسال‌شده") label = "sent";
        else if (label == "به") label = "to";
        else if (label == "موضوع") label = "subject";
        else if (label == "تاریخ") label = "date";
        else if (label.StartsWith("رونوشت", StringComparison.Ordinal)) label = "cc";
        return true;
    }

    private static void CollectBlocks(XNode node, List<XNode> output)
    {
        if (node is XText text)
        {
            if (!string.IsNullOrWhiteSpace(text.Value)) output.Add(text);
            return;
        }
        if (node is not XElement element || IsQuoted(element) || IsSignatureMarker(element)) return;
        if (NameIs(element, "table")) return;
        var children = element.Elements().Where(child => !IsQuoted(child)).ToArray();
        var hasBlockChildren = children.Any(IsBlockElement);
        if (hasBlockChildren)
        {
            foreach (var child in element.Nodes()) CollectBlocks(child, output);
        }
        else if (element.DescendantNodesAndSelf().OfType<XText>().Any(text => !string.IsNullOrWhiteSpace(text.Value)))
        {
            output.Add(element);
        }
    }

    private static IReadOnlyList<Candidate> Bounded(Candidate[] candidates)
    {
        if (candidates.Length > MaxParts)
            throw new ArgumentException("The selected email contains more than 32 signature candidates; choose a narrower source message.");
        return candidates;
    }

    private static bool IsBlockElement(XElement element) =>
        new[] { "div", "p", "table", "ul", "ol", "li", "blockquote", "pre", "h1", "h2", "h3", "h4", "h5", "h6" }
            .Any(name => NameIs(element, name));

    private static bool IsSignatureMarker(XElement element)
    {
        static bool Matches(string? value) => value is not null && value.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries)
            .Any(token => token.Equals("signature", StringComparison.OrdinalIgnoreCase)
                || token.Equals("_MailAutoSig", StringComparison.OrdinalIgnoreCase));
        return Matches(RawAttribute(element, "id")) || Matches(RawAttribute(element, "class"))
            || Matches(RawAttribute(element, "name"));
    }

    private static bool IsQuoted(XElement element)
    {
        if (NameIs(element, "blockquote")) return true;
        return IsQuotedMarker(RawAttribute(element, "id")) || IsQuotedMarker(RawAttribute(element, "class"));
    }

    private static bool IsQuotedMarker(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return false;
        var compact = new string(value.Where(char.IsAsciiLetterOrDigit).Select(char.ToLowerInvariant).ToArray());
        if (compact.Contains("divrplyfwdmsg", StringComparison.Ordinal)
            || compact.Contains("divreplyfwdmsg", StringComparison.Ordinal)
            || compact.Contains("divfwdmsg", StringComparison.Ordinal)
            || compact.Contains("quoted", StringComparison.Ordinal)
            || compact.Contains("forwardedmessage", StringComparison.Ordinal)) return true;
        return value.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries).Any(token =>
            token.Equals("gmail_quote", StringComparison.OrdinalIgnoreCase)
            || token.StartsWith("gmail_quote_", StringComparison.OrdinalIgnoreCase)
            || token.Equals("protonmail_quote", StringComparison.OrdinalIgnoreCase)
            || token.Equals("yahoo_quoted", StringComparison.OrdinalIgnoreCase)
            || token.Equals("moz-cite-prefix", StringComparison.OrdinalIgnoreCase));
    }

    private static void RemoveQuotedAreas(XElement body, List<string> warnings)
    {
        var quotes = body.Descendants().Where(IsQuoted).Where(element => !element.Ancestors().Any(IsQuoted)).ToArray();
        if (quotes.Length == 0) return;
        foreach (var quote in quotes) quote.Remove();
        AddWarning(warnings, "Quoted or forwarded message sections were excluded from signature candidates.");
    }

    private static string Preview(Candidate candidate)
    {
        if (candidate.TextBody is not null)
        {
            var plain = WhiteSpace.Replace(candidate.TextBody, " ").Trim();
            return plain.Length <= 240 ? plain : plain[..237] + "...";
        }
        var nodes = candidate.Nodes;
        var text = string.Join(" ", nodes.SelectMany(node => node is XElement element
                ? element.DescendantNodesAndSelf().OfType<XText>().Select(item => item.Value)
                : node is XText plain ? [plain.Value] : Array.Empty<string>()))
            .Trim();
        text = WhiteSpace.Replace(text, " ");
        return text.Length <= 240 ? text : text[..237] + "...";
    }

    private static string[] FindContentIds(string html)
    {
        var root = XElement.Parse("<root>" + html + "</root>", LoadOptions.PreserveWhitespace);
        var ids = root.DescendantsAndSelf().Where(element => NameIs(element, "img"))
            .Select(element => RawAttribute(element, "src")?[4..])
            .Where(id => !string.IsNullOrWhiteSpace(id)).Select(id => id!)
            .Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        if (ids.Length > MaxReferencedImages)
            throw new ArgumentException("The selected signature references more than 32 inline images.");
        return ids;
    }

    private static bool IsSupportedSelector(string selector)
    {
        if (selector.Length > 256 || selector.IndexOfAny(['>', '+', '~', ':', '[', ']']) >= 0) return false;
        return selector.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries).All(part => SimpleSelector.IsMatch(part));
    }

    private static bool Matches(XElement element, string selector)
    {
        var parts = selector.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length == 0 || !MatchesSimple(element, parts[^1])) return false;
        var current = element.Parent;
        for (var i = parts.Length - 2; i >= 0; i--)
        {
            while (current is not null && !MatchesSimple(current, parts[i])) current = current.Parent;
            if (current is null) return false;
            current = current.Parent;
        }
        return true;
    }

    private static bool MatchesSimple(XElement element, string selector)
    {
        var match = SimpleSelector.Match(selector);
        if (!match.Success) return false;
        var tag = match.Groups["tag"].Value;
        if (tag.Length > 0 && !element.Name.LocalName.Equals(tag, StringComparison.OrdinalIgnoreCase)) return false;
        foreach (Match part in Regex.Matches(match.Groups["rest"].Value, "[.#][A-Za-z_][A-Za-z0-9_-]*", RegexOptions.CultureInvariant))
        {
            var value = part.Value[1..];
            if (part.Value[0] == '.' && !(RawAttribute(element, "class") ?? string.Empty).Split((char[]?)null,
                    StringSplitOptions.RemoveEmptyEntries).Contains(value, StringComparer.OrdinalIgnoreCase)) return false;
            if (part.Value[0] == '#' && !string.Equals(RawAttribute(element, "id"), value, StringComparison.OrdinalIgnoreCase)) return false;
        }
        return true;
    }

    private static void NormalizeNamespaces(XElement root, List<string> warnings)
    {
        foreach (var element in root.DescendantsAndSelf().ToArray())
        {
            if (element.Name.Namespace == XNamespace.None || element.Name.NamespaceName == XhtmlNamespace
                || element.Name.NamespaceName == Html4Namespace)
            {
                element.Name = element.Name.LocalName.ToLowerInvariant();
                continue;
            }
            if (element.Name.NamespaceName.Contains("schemas-microsoft-com:office", StringComparison.OrdinalIgnoreCase)
                && element.Name.LocalName.Equals("p", StringComparison.OrdinalIgnoreCase))
            {
                element.ReplaceWith(element.Nodes().Select(CloneNode));
                AddWarning(warnings, "Office paragraph wrappers were removed; text and children were kept.");
                continue;
            }
            throw new ArgumentException("Unsupported namespaced content is not allowed in a captured signature.");
        }
    }

    private static Dictionary<string, string> ParseStyleMap(string? style) => string.IsNullOrWhiteSpace(style)
        ? new(StringComparer.OrdinalIgnoreCase)
        : style.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(item => (Separator: item.IndexOf(':'), Text: item))
            .Where(item => item.Separator > 0)
            .ToDictionary(item => item.Text[..item.Separator].Trim(), item => item.Text[(item.Separator + 1)..].Trim(), StringComparer.OrdinalIgnoreCase);

    private static bool IsDimension(string? value) => value is not null && Regex.IsMatch(value.Trim(),
        "^(?:[0-9]{1,5}(?:\\.[0-9]{1,2})?(?:px|pt)?|(?:100|[0-9]{1,2})%)$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    private static bool IsCssDimension(string value, bool allowKeywords = false)
    {
        var normalized = value.Trim();
        if (allowKeywords && new[] { "auto", "inherit", "initial", "unset" }.Contains(normalized, StringComparer.OrdinalIgnoreCase))
            return true;
        return IsCssLength(normalized, allowPercent: true);
    }

    private static bool IsBorderSpacing(string value) => value.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries) is { Length: 1 or 2 } values
        && values.All(part => IsCssLength(part, allowPercent: false));

    private static bool IsCssLength(string value, bool allowPercent)
    {
        var units = allowPercent ? "px|pt|pc|in|cm|mm|em|rem|%" : "px|pt|pc|in|cm|mm|em|rem";
        var match = Regex.Match(value.Trim(), $"^(?<number>[0-9]{{1,5}}(?:\\.[0-9]{{1,2}})?)(?<unit>{units})?$",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        return match.Success
            && (match.Groups["unit"].Success || decimal.TryParse(match.Groups["number"].Value,
                System.Globalization.NumberStyles.AllowDecimalPoint, System.Globalization.CultureInfo.InvariantCulture, out var unitless) && unitless == 0)
            && decimal.TryParse(match.Groups["number"].Value,
                System.Globalization.NumberStyles.AllowDecimalPoint, System.Globalization.CultureInfo.InvariantCulture, out var size)
            && size <= 16_384;
    }

    private static string NormalizeLegacyDimension(string value)
    {
        var normalized = value.Trim();
        return normalized.Equals("0", StringComparison.Ordinal) || Regex.IsMatch(normalized, "^[0-9]+(?:\\.[0-9]+)?$", RegexOptions.CultureInvariant)
            ? normalized.Equals("0", StringComparison.Ordinal) ? "0" : normalized + "px"
            : normalized;
    }

    private static bool IsIntegerInRange(string? value, int min, int max) => value is not null
        && int.TryParse(value.Trim(), System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var parsed)
        && parsed >= min && parsed <= max;

    private static bool IsSafeColor(string value) => Regex.IsMatch(value.Trim(),
        "^(?:#[0-9A-Fa-f]{3}|#[0-9A-Fa-f]{6}|[A-Za-z]{1,20})$", RegexOptions.CultureInvariant);

    private static bool IsSimpleContentId(string value) => value.Length is > 0 and <= 128
        && value.All(character => char.IsAsciiLetterOrDigit(character) || character is '.' or '_' or '-' or '@');

    private static int CandidateLength(Candidate candidate) => candidate.TextBody?.Length
        ?? candidate.Nodes.Sum(node => node.ToString(SaveOptions.DisableFormatting).Length);

    private static string NormalizeFontFamilies(string value)
    {
        var families = value.Split(',', StringSplitOptions.TrimEntries);
        for (var i = 0; i < families.Length; i++)
        {
            var family = families[i];
            if (family.Length >= 2 && family[0] == family[^1] && family[0] is '\'' or '"')
            {
                family = family[1..^1];
                if (family.Any(character => !(char.IsAsciiLetterOrDigit(character) || character is ' ' or '-' or '_')))
                    throw new ArgumentException("The selected email contains an unsafe font name.");
                families[i] = family;
            }
            else if (family.Contains('"') || family.Contains('\''))
                throw new ArgumentException("The selected email contains an unsafe font name.");
        }
        return string.Join(",", families);
    }

    private static void ConvertFontElement(XElement element, List<string> warnings)
    {
        var styles = ParseStyleMap(RawAttribute(element, "style"));
        var face = RawAttribute(element, "face");
        var color = RawAttribute(element, "color");
        var size = RawAttribute(element, "size");
        if (!string.IsNullOrWhiteSpace(face)) styles.TryAdd("font-family", NormalizeFontFamilies(face));
        if (!string.IsNullOrWhiteSpace(color) && IsSafeColor(color)) styles.TryAdd("color", color.Trim());
        else if (!string.IsNullOrWhiteSpace(color)) AddWarning(warnings, "Some unsupported email colors were omitted.");
        var fontSizes = new[] { "8pt", "10pt", "12pt", "14pt", "18pt", "24pt", "36pt" };
        if (IsIntegerInRange(size, 1, 7)) styles.TryAdd("font-size", fontSizes[int.Parse(size!, System.Globalization.CultureInfo.InvariantCulture) - 1]);
        foreach (var attribute in element.Attributes().Where(attribute =>
                     new[] { "face", "color", "size", "style" }.Contains(attribute.Name.LocalName, StringComparer.OrdinalIgnoreCase)).ToArray()) attribute.Remove();
        element.Name = "span";
        if (styles.Count > 0) SetAttribute(element, "style", string.Join(";", styles.Select(item => item.Key + ":" + item.Value)));
        AddWarning(warnings, "Legacy font markup was converted to safe inline styling.");
    }

    private static bool IsBodyElement(XElement element) => NameIs(element, "body");
    private static bool IsHtmlElement(XElement element) => NameIs(element, "html");
    private static bool IsHeadElement(XElement element) => NameIs(element, "head");
    private static bool NameIs(XElement element, string name) => element.Name.LocalName.Equals(name, StringComparison.OrdinalIgnoreCase);
    private static string? RawAttribute(XElement element, string name) => element.Attributes()
        .FirstOrDefault(attribute => attribute.Name.LocalName.Equals(name, StringComparison.OrdinalIgnoreCase))?.Value;
    private static void SetAttribute(XElement element, string name, string value)
    {
        var existing = element.Attributes().FirstOrDefault(attribute => attribute.Name.LocalName.Equals(name, StringComparison.OrdinalIgnoreCase));
        if (existing is null) element.SetAttributeValue(name, value); else existing.Value = value;
    }
    private static XNode CloneNode(XNode node) => node switch
    {
        XElement element => new XElement(element),
        XCData cdata => new XText(cdata.Value),
        XText text => new XText(text.Value),
        XComment => new XText(string.Empty),
        _ => throw new ArgumentException("Unsupported markup node.")
    };
    private static void AddWarning(List<string> warnings, string warning)
    {
        if (!warnings.Contains(warning, StringComparer.Ordinal)) warnings.Add(warning);
    }
    private static IReadOnlyList<string> Warnings(IReadOnlyList<string> warnings) => warnings.ToArray();

    private sealed record StyleRule(string Selector, IReadOnlyDictionary<string, string> Declarations);
    private sealed record TextLine(int Index, string Text);
    private sealed record ParsedSource(string BodyType, XElement Body, IReadOnlyList<TextLine>? TextLines, List<string> Warnings);
    private sealed record Candidate(string Id, string Kind, IReadOnlyList<XNode> Nodes, string? TextBody);
}
