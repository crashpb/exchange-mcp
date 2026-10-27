using System.Net;
using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.Linq;

namespace Company.ExchangeMcp.Exchange;

/// <summary>Validates the small, deliberately safe XHTML subset accepted for mail bodies.</summary>
public static class RichBody
{
    public const int MaxLength = 80_000;
    public const int MaxHtmlDepth = 64;

    public static bool HasImageHeader(byte[] bytes, string type) => type switch
    {
        "image/png" => bytes.AsSpan().StartsWith(new byte[] { 137, 80, 78, 71, 13, 10, 26, 10 }),
        "image/jpeg" => bytes.Length >= 3 && bytes[0] == 255 && bytes[1] == 216 && bytes[2] == 255,
        "image/gif" => bytes.AsSpan().StartsWith("GIF87a"u8) || bytes.AsSpan().StartsWith("GIF89a"u8),
        _ => false
    };

    private const string XhtmlNamespace = "http://www.w3.org/1999/xhtml";
    private const string Html4Namespace = "http://www.w3.org/TR/REC-html40";
    private static readonly HashSet<string> Elements = new(StringComparer.OrdinalIgnoreCase)
    {
        "a", "b", "blockquote", "body", "br", "caption", "code", "col", "colgroup", "del", "div",
        "em", "h1", "h2", "h3", "h4", "h5", "h6", "head", "hr", "html", "i", "img", "ins", "li",
        "ol", "p", "pre", "s", "small", "span", "strong", "sub", "sup", "table", "tbody", "td", "tfoot",
        "th", "thead", "tr", "u", "ul"
    };

    private static readonly HashSet<string> VoidElements = new(StringComparer.OrdinalIgnoreCase)
    {
        "br", "col", "hr", "img"
    };

    private static readonly HashSet<string> Attributes = new(StringComparer.OrdinalIgnoreCase)
    {
        "alt", "class", "colspan", "dir", "height", "href", "id", "lang", "rowspan", "scope", "src", "style",
        "title", "width"
    };

    private static readonly HashSet<string> ExchangeAttributes = new(Attributes, StringComparer.OrdinalIgnoreCase)
    {
        "align", "background", "bgcolor", "border", "cellpadding", "cellspacing", "charset", "clear", "color", "content",
        "face", "http-equiv", "link", "name", "size", "start", "tabindex", "target", "text", "type", "valign", "vlink"
    };

    private static readonly HashSet<string> CssProperties = new(StringComparer.OrdinalIgnoreCase)
    {
        "background-color", "border", "border-bottom", "border-collapse", "border-color", "border-left", "border-radius", "border-spacing",
        "border-right", "border-style", "border-top", "border-width", "color", "direction", "font-family", "font-size",
        "font-style", "font-weight", "line-height", "margin", "margin-bottom", "margin-left", "margin-right",
        "margin-top", "padding", "padding-bottom", "padding-left", "padding-right", "padding-top",
        "text-align", "text-decoration", "vertical-align", "white-space", "width", "height", "table-layout"
    };

    // Exchange wraps HTML drafts in a document envelope and emits HTML void tags without XHTML '/>'.
    // Keep this narrowly scoped: the result still goes through the strict XHTML validator below.
    private static readonly Regex ExchangeVoidTag = new(
        "<(?<name>img|br|hr|col|meta)\\b(?<tail>(?:\"[^\"]*\"|'[^']*'|[^'\">])*)>",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant,
        TimeSpan.FromSeconds(1));
    private static readonly Regex ExchangeMarkup = new(
        "<!--.*?-->|<(?<name>[A-Za-z][A-Za-z0-9:._-]*)\\b(?<tail>(?:\"[^\"]*\"|'[^']*'|[^'\">])*)>|[^<]+",
        RegexOptions.Singleline | RegexOptions.CultureInvariant,
        TimeSpan.FromSeconds(1));
    private static readonly Regex ExchangeContentType = new(
        "^text/html[ \\t\\r\\n]*;[ \\t\\r\\n]*charset[ \\t\\r\\n]*=[ \\t\\r\\n]*[A-Za-z0-9][A-Za-z0-9._-]{0,31}[ \\t\\r\\n]*$",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant,
        TimeSpan.FromSeconds(1));

    public static string Validate(string body, string bodyType)
    {
        ArgumentNullException.ThrowIfNull(body);
        var normalizedType = NormalizeBodyType(bodyType);
        if (body.Length > MaxLength)
            throw new ArgumentException("The message body exceeds the 80000 character limit.", nameof(body));
        if (normalizedType == "Text") return body;

        var root = ParseFragment(body);
        foreach (var node in root.Nodes()) ValidateNode(node);
        // HTML consumers ignore '/>' on non-void tags, so retain an explicit end tag even when empty.
        foreach (var element in root.Descendants().Where(element => element.IsEmpty && !VoidElements.Contains(element.Name.LocalName)))
            element.Add(new XText(string.Empty));
        var normalized = string.Concat(root.Nodes().Select(node => node.ToString(SaveOptions.DisableFormatting)));
        if (normalized.Length > MaxLength)
            throw new ArgumentException("The message body exceeds the 80000 character limit.", nameof(body));
        return normalized;
    }

    /// <summary>
    /// Normalizes the bounded HTML document shape returned by Exchange before strict validation.
    /// Converts only known passive Exchange metadata, font wrappers and reply separators.
    /// </summary>
    public static string NormalizeExchangeHtml(string body)
    {
        ArgumentNullException.ThrowIfNull(body);
        if (body.Length > MaxLength)
            throw new ArgumentException("The message body exceeds the 80000 character limit.", nameof(body));

        string normalized;
        try
        {
            // EWS returns HTML's common NBSP entity, which is not a predefined XML entity.
            // Normalize only this exact entity; all other unknown entities still fail strict XML parsing.
            normalized = ExchangeVoidTag.Replace(body.Replace("&nbsp;", "&#160;", StringComparison.Ordinal), static match =>
            {
                var tag = match.Value;
                var open = tag[..^1];
                return open.TrimEnd().EndsWith("/", StringComparison.Ordinal)
                    ? tag
                    : open.TrimEnd() + " />";
            });
        }
        catch (RegexMatchTimeoutException exception)
        {
            throw new ArgumentException("HTML body normalization timed out.", nameof(body), exception);
        }

        if (normalized.Length > MaxLength)
            throw new ArgumentException("The message body exceeds the 80000 character limit.", nameof(body));

        var root = ParseFragment(normalized);
        foreach (var element in root.Descendants().ToArray())
        {
            if (element.Attributes().Where(attribute => !attribute.IsNamespaceDeclaration)
                .GroupBy(attribute => attribute.Name.LocalName, StringComparer.OrdinalIgnoreCase).Any(group => group.Count() > 1))
                throw new ArgumentException("HTML body contains duplicate attributes.", nameof(body));
            if (element.Name.LocalName.Equals("meta", StringComparison.OrdinalIgnoreCase) && IsExchangeContentTypeMeta(element))
                element.Remove();
            if (element.Name.Namespace != XNamespace.None && element.Name.Namespace != XhtmlNamespace) continue;
            if (element.Name.LocalName.Equals("a", StringComparison.OrdinalIgnoreCase))
            {
                var target = FindAttribute(element, "target");
                if (target is { Name.NamespaceName: "" } && target.Value.Equals("_blank", StringComparison.OrdinalIgnoreCase))
                    target.Remove();
            }
            if (element.Name.LocalName.Equals("font", StringComparison.OrdinalIgnoreCase))
            {
                if (element.Attributes().Any(attribute => !attribute.IsNamespaceDeclaration && attribute.Name.Namespace != XNamespace.None))
                    throw new ArgumentException("Exchange font attributes must not be namespaced.", nameof(body));
                var style = FindAttribute(element, "style")?.Value ?? string.Empty;
                ValidateStyle(style);
                foreach (var (attributeName, property) in new[] { ("face", "font-family"), ("color", "color") })
                {
                    var attribute = FindAttribute(element, attributeName);
                    if (attribute is null || attribute.Name.Namespace != XNamespace.None) continue;
                    if (attribute.Value.IndexOfAny([';', ':', '{', '}']) >= 0)
                        throw new ArgumentException("Exchange font attribute contains an unsafe value.", nameof(body));
                    var declaration = property + ":" + attribute.Value;
                    ValidateStyle(declaration);
                    style = declaration + ";" + style;
                    attribute.Remove();
                }
                element.Name = element.Name.Namespace + "span";
                if (style.Length > 0)
                {
                    FindAttribute(element, "style")?.Remove();
                    element.SetAttributeValue("style", style);
                }
            }
            if (element.Name.LocalName.Equals("hr", StringComparison.OrdinalIgnoreCase))
            {
                var tabIndex = FindAttribute(element, "tabindex");
                if (tabIndex is { Name.NamespaceName: "", Value: "-1" }) tabIndex.Remove();
                var style = FindAttribute(element, "style");
                if (style is not null && style.Name.Namespace == XNamespace.None)
                {
                    if (style.Value.Length > 2048 || style.Value.Any(char.IsControl))
                        throw new ArgumentException("Exchange separator style is invalid.", nameof(body));
                    style.Value = string.Join(';', style.Value.Split(';').Where(declaration =>
                    {
                        var pair = declaration.Split(':');
                        return pair.Length != 2 || !pair[0].Trim().Equals("display", StringComparison.OrdinalIgnoreCase)
                            || !pair[1].Trim().Equals("inline-block", StringComparison.OrdinalIgnoreCase);
                    }));
                }
            }
        }

        // Validate after removal so unsupported meta tags and all other HTML remain rejected.
        var candidate = string.Concat(root.Nodes().Select(node => node.ToString(SaveOptions.DisableFormatting)));
        return Validate(candidate, "HTML");
    }

    // Native Exchange history is preserved separately from the intentionally small authored-body subset.
    internal static XElement ParseExchangeHtml(string body)
    {
        ArgumentNullException.ThrowIfNull(body);
        if (body.Length > MaxLength)
            throw new ArgumentException("The message body exceeds the 80000 character limit.", nameof(body));
        string normalized;
        try
        {
            normalized = ExchangeMarkup.Replace(body, static match =>
            {
                if (match.Value.StartsWith("<!--", StringComparison.Ordinal)) return match.Value;
                var value = match.Value.Replace("&nbsp;", "&#160;", StringComparison.Ordinal);
                var name = match.Groups["name"].Value;
                return (VoidElements.Contains(name) || name.Equals("meta", StringComparison.OrdinalIgnoreCase))
                    && !value[..^1].TrimEnd().EndsWith("/", StringComparison.Ordinal)
                        ? value[..^1].TrimEnd() + " />" : value;
            });
        }
        catch (RegexMatchTimeoutException exception)
        {
            throw new ArgumentException("HTML body normalization timed out.", nameof(body), exception);
        }
        if (normalized.Length > MaxLength)
            throw new ArgumentException("The message body exceeds the 80000 character limit.", nameof(body));
        var root = ParseFragment(normalized);
        foreach (var node in root.Nodes()) ValidateExchangeNode(node);
        return root;
    }

    internal static string SerializeExchangeHtml(XElement root)
    {
        foreach (var element in root.Descendants().Where(element => element.IsEmpty
            && !VoidElements.Contains(element.Name.LocalName) && !element.Name.LocalName.Equals("meta", StringComparison.OrdinalIgnoreCase)))
            element.Add(new XText(string.Empty));
        var body = string.Concat(root.Nodes().Select(node => node.ToString(SaveOptions.DisableFormatting)));
        _ = ParseExchangeHtml(body);
        return body;
    }

    internal static bool IsExchangeHtmlNamespace(XNamespace value) =>
        value == XNamespace.None || value == XhtmlNamespace || value == Html4Namespace;

    private static void ValidateExchangeNode(XNode node)
    {
        if (node is XText) return;
        if (node is XComment comment)
        {
            // Outlook conditional comments can activate their markup in older Office rendering engines.
            if (comment.Value.Contains("[if", StringComparison.OrdinalIgnoreCase)
                && comment.Value.Contains('<'))
                throw new ArgumentException("Native HTML contains an unsupported conditional comment.", nameof(node));
            return;
        }
        if (node is not XElement element)
            throw new ArgumentException("HTML body contains an unsupported node.", nameof(node));
        var name = element.Name.LocalName;
        var officeParagraph = name.Equals("p", StringComparison.OrdinalIgnoreCase)
            && element.Name.NamespaceName == "urn:schemas-microsoft-com:office:office";
        if (!officeParagraph && (!IsExchangeHtmlNamespace(element.Name.Namespace)
            || (!Elements.Contains(name) && !new[] { "font", "meta", "style", "title" }.Contains(name, StringComparer.OrdinalIgnoreCase))))
            throw new ArgumentException($"HTML element '{name}' is not allowed in native Exchange content.", nameof(node));
        if (element.Attributes().Where(attribute => !attribute.IsNamespaceDeclaration)
            .GroupBy(attribute => attribute.Name.LocalName, StringComparer.OrdinalIgnoreCase).Any(group => group.Count() > 1))
            throw new ArgumentException("HTML body contains duplicate attributes.", nameof(node));
        foreach (var attribute in element.Attributes().Where(attribute => !attribute.IsNamespaceDeclaration))
        {
            var attributeName = attribute.Name.LocalName;
            var xmlLanguage = attribute.Name == XNamespace.Xml + "lang";
            if ((!xmlLanguage && attribute.Name.Namespace != XNamespace.None) || !ExchangeAttributes.Contains(attributeName))
                throw new ArgumentException($"Native HTML attribute '{attributeName}' is not allowed.", nameof(node));
            if (attribute.Value.Length > 4096 || attribute.Value.Any(character => char.IsControl(character)
                && (attributeName != "style" || character is not ('\r' or '\n' or '\t'))))
                throw new ArgumentException("Native HTML attribute is invalid.", nameof(node));
            if (attributeName.Equals("style", StringComparison.OrdinalIgnoreCase))
                ValidateExchangeCss(attribute.Value, false);
            else if (attributeName.Equals("background", StringComparison.OrdinalIgnoreCase))
                throw new ArgumentException("Native HTML background URLs are not allowed.", nameof(node));
            else ValidateAttribute(element, attribute);
        }
        if (name.Equals("img", StringComparison.OrdinalIgnoreCase))
        {
            var source = FindAttribute(element, "src")?.Value;
            if (source is null || !source.StartsWith("cid:", StringComparison.OrdinalIgnoreCase) || !IsSafeContentId(source[4..]))
                throw new ArgumentException("Images must reference an inline CID attachment.", nameof(node));
        }
        if (name.Equals("meta", StringComparison.OrdinalIgnoreCase))
        {
            var httpEquiv = FindAttribute(element, "http-equiv");
            if (httpEquiv is not null && !IsExchangeContentTypeMeta(new XElement("meta",
                element.Attributes().Where(attribute => !attribute.IsNamespaceDeclaration).Select(attribute => new XAttribute(attribute)))))
                throw new ArgumentException("Native HTML metadata must not change document behavior.", nameof(node));
        }
        if (name.Equals("style", StringComparison.OrdinalIgnoreCase))
        {
            if (element.Nodes().Any(child => child is not (XText or XComment)))
                throw new ArgumentException("Native HTML style content is invalid.", nameof(node));
            ValidateExchangeCss(string.Concat(element.Nodes().Select(child => child is XComment cssComment
                ? cssComment.Value : ((XText)child).Value)), true);
        }
        foreach (var child in element.Nodes()) ValidateExchangeNode(child);
    }

    private static void ValidateExchangeCss(string css, bool stylesheet)
    {
        string uncommented;
        try
        {
            uncommented = Regex.Replace(css, @"/\*.*?\*/", string.Empty, RegexOptions.Singleline | RegexOptions.CultureInvariant,
                TimeSpan.FromSeconds(1));
        }
        catch (RegexMatchTimeoutException exception)
        {
            throw new ArgumentException("Native CSS validation timed out.", nameof(css), exception);
        }
        var compact = string.Concat(uncommented.Where(character => !char.IsWhiteSpace(character)));
        if (css.Contains('\\') || css.Any(character => char.IsControl(character) && character is not ('\r' or '\n' or '\t'))
            || uncommented.Contains("/*", StringComparison.Ordinal) || uncommented.Contains("*/", StringComparison.Ordinal)
            || compact.Contains("url(", StringComparison.OrdinalIgnoreCase) || compact.Contains("expression", StringComparison.OrdinalIgnoreCase)
            || compact.Contains("behavior:", StringComparison.OrdinalIgnoreCase) || compact.Contains("-moz-binding", StringComparison.OrdinalIgnoreCase)
            || compact.Contains("progid:", StringComparison.OrdinalIgnoreCase) || compact.Contains("-ms-filter:", StringComparison.OrdinalIgnoreCase)
            || compact.Contains("alphaimageloader(", StringComparison.OrdinalIgnoreCase)
            || compact.Contains("javascript", StringComparison.OrdinalIgnoreCase) || compact.Contains("vbscript", StringComparison.OrdinalIgnoreCase)
            || compact.Contains("data:", StringComparison.OrdinalIgnoreCase) || compact.Contains("@import", StringComparison.OrdinalIgnoreCase)
            || compact.Contains("image-set(", StringComparison.OrdinalIgnoreCase) || compact.Contains("src(", StringComparison.OrdinalIgnoreCase)
            || uncommented.Contains('<')
            || (!stylesheet && (uncommented.IndexOfAny(['{', '}', '@']) >= 0 || css.Length > 4096)))
            throw new ArgumentException("Native HTML CSS contains an unsafe value.", nameof(css));
    }

    public static string Preview(string body, string bodyType)
    {
        ArgumentNullException.ThrowIfNull(body);
        var normalizedType = NormalizeBodyType(bodyType);
        if (normalizedType == "Text") return body;
        try
        {
            var root = ParseFragment(Validate(body, normalizedType));
            var output = new System.Text.StringBuilder();
            foreach (var node in root.Nodes()) AppendPreview(node, output);
            return output.ToString().Trim();
        }
        catch (ArgumentException)
        {
            return "[HTML body could not be safely previewed]";
        }
    }

    public static string NormalizeBodyType(string? bodyType) =>
        string.IsNullOrWhiteSpace(bodyType) || bodyType.Equals("Text", StringComparison.OrdinalIgnoreCase)
            ? "Text"
            : bodyType.Equals("HTML", StringComparison.OrdinalIgnoreCase)
                ? "HTML"
                : throw new ArgumentException("BodyType must be Text or HTML.", nameof(bodyType));

    private static XElement ParseFragment(string body)
    {
        try
        {
            var xml = $"<root>{body}</root>";
            var settings = new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit,
                XmlResolver = null,
                MaxCharactersInDocument = MaxLength + 64
            };
            // Bound nesting before building or recursively validating an untrusted fragment.
            using (var scan = XmlReader.Create(new StringReader(xml), settings))
                while (scan.Read())
                    if (scan.Depth > MaxHtmlDepth)
                        throw new ArgumentException("HTML body exceeds the nesting limit.", nameof(body));
            using var reader = XmlReader.Create(new StringReader(xml), settings);
            return XElement.Load(reader, LoadOptions.PreserveWhitespace);
        }
        catch (XmlException ex)
        {
            throw new ArgumentException("HTML body must be a well-formed XHTML fragment.", nameof(body), ex);
        }
    }

    private static void ValidateNode(XNode node)
    {
        if (node is XText) return;
        if (node is not XElement element)
            throw new ArgumentException("HTML body contains an unsupported node.", nameof(node));

        var localName = element.Name.LocalName;
        if (!Elements.Contains(localName)
            || (element.Name.Namespace != XNamespace.None && element.Name.Namespace != XhtmlNamespace))
            throw new ArgumentException($"HTML element '{localName}' is not allowed.", nameof(node));

        if (element.Attributes().Where(attribute => !attribute.IsNamespaceDeclaration)
            .GroupBy(attribute => attribute.Name.LocalName, StringComparer.OrdinalIgnoreCase).Any(group => group.Count() > 1))
            throw new ArgumentException("HTML body contains duplicate attributes.", nameof(node));

        foreach (var attribute in element.Attributes())
        {
            if (attribute.IsNamespaceDeclaration) continue;
            if (attribute.Name.Namespace != XNamespace.None || !Attributes.Contains(attribute.Name.LocalName))
                throw new ArgumentException($"HTML attribute '{attribute.Name.LocalName}' is not allowed.", nameof(node));
            ValidateAttribute(element, attribute);
        }

        if (localName.Equals("img", StringComparison.OrdinalIgnoreCase))
        {
            var source = FindAttribute(element, "src")?.Value;
            if (string.IsNullOrWhiteSpace(source) || !source.StartsWith("cid:", StringComparison.OrdinalIgnoreCase)
                || !IsSafeContentId(source[4..]))
                throw new ArgumentException("Images must reference an inline CID attachment.", nameof(node));
        }

        foreach (var child in element.Nodes()) ValidateNode(child);
    }

    private static void ValidateAttribute(XElement element, XAttribute attribute)
    {
        var name = attribute.Name.LocalName;
        var value = attribute.Value;
        if (value.Length > 4096 || value.Any(char.IsControl))
            throw new ArgumentException($"HTML attribute '{name}' is invalid.", nameof(element));
        if (name.Equals("style", StringComparison.OrdinalIgnoreCase))
        {
            ValidateStyle(value);
            return;
        }
        if (name.Equals("dir", StringComparison.OrdinalIgnoreCase)
            && !new[] { "rtl", "ltr", "auto" }.Contains(value, StringComparer.OrdinalIgnoreCase))
            throw new ArgumentException("HTML direction must be rtl, ltr or auto.", nameof(element));
        if (name.Equals("href", StringComparison.OrdinalIgnoreCase))
        {
            if (!Uri.TryCreate(value, UriKind.Absolute, out var uri)
                || (uri.Scheme != Uri.UriSchemeHttps && uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeMailto))
                throw new ArgumentException("Links may use only http, https, or mailto URIs.", nameof(element));
            return;
        }
        if (name.Equals("src", StringComparison.OrdinalIgnoreCase)
            && (!element.Name.LocalName.Equals("img", StringComparison.OrdinalIgnoreCase)
                || !value.StartsWith("cid:", StringComparison.OrdinalIgnoreCase)))
            throw new ArgumentException("Only CID image sources are allowed.", nameof(element));
    }

    private static void ValidateStyle(string style)
    {
        var compact = string.Concat(style.Where(character => !char.IsWhiteSpace(character)));
        if (style.Length > 2048 || style.Contains('\\') || style.Contains("/*", StringComparison.Ordinal)
            || compact.Contains("url(", StringComparison.OrdinalIgnoreCase)
            || style.Contains("expression", StringComparison.OrdinalIgnoreCase)
            || style.Contains("javascript", StringComparison.OrdinalIgnoreCase)
            || style.Contains("vbscript", StringComparison.OrdinalIgnoreCase)
            || style.Contains("data:", StringComparison.OrdinalIgnoreCase)
            || style.Contains("@import", StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("Inline CSS contains an unsafe value.", nameof(style));

        foreach (var declaration in style.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var separator = declaration.IndexOf(':');
            if (separator <= 0 || declaration.AsSpan(separator + 1).ContainsAny(['<', '>', '\"', '\'']))
                throw new ArgumentException("Inline CSS contains an unsupported declaration.", nameof(style));
            var property = declaration[..separator].Trim();
            if (!CssProperties.Contains(property))
            {
                var safeName = property.Length is > 0 and <= 64
                    && property.All(character => char.IsAsciiLetterOrDigit(character) || character == '-');
                throw new ArgumentException(safeName ? $"Inline CSS property '{property}' is not supported."
                    : "Inline CSS contains an unsupported property.", nameof(style));
            }
            if (declaration[..separator].Trim().Equals("direction", StringComparison.OrdinalIgnoreCase)
                && !new[] { "rtl", "ltr" }.Contains(declaration[(separator + 1)..].Trim(), StringComparer.OrdinalIgnoreCase))
                throw new ArgumentException("CSS direction must be rtl or ltr.", nameof(style));
            var value = declaration[(separator + 1)..].Trim();
            if (property.Equals("border-collapse", StringComparison.OrdinalIgnoreCase)
                && !new[] { "collapse", "separate" }.Contains(value, StringComparer.OrdinalIgnoreCase))
                throw new ArgumentException("CSS border-collapse must be collapse or separate.", nameof(style));
            if (property.Equals("table-layout", StringComparison.OrdinalIgnoreCase)
                && !new[] { "auto", "fixed" }.Contains(value, StringComparer.OrdinalIgnoreCase))
                throw new ArgumentException("CSS table-layout must be auto or fixed.", nameof(style));
            if ((property.Equals("width", StringComparison.OrdinalIgnoreCase)
                    || property.Equals("height", StringComparison.OrdinalIgnoreCase))
                && !new[] { "auto", "inherit", "initial", "unset" }.Contains(value, StringComparer.OrdinalIgnoreCase)
                && !IsLayoutLength(value))
                throw new ArgumentException("CSS dimensions must be bounded lengths.", nameof(style));
            if (property.Equals("border-spacing", StringComparison.OrdinalIgnoreCase))
            {
                var lengths = value.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (lengths.Length is < 1 or > 2 || lengths.Any(length => !IsLayoutLength(length)))
                    throw new ArgumentException("CSS border-spacing must contain one or two bounded lengths.", nameof(style));
            }
        }
    }

    private static bool IsLayoutLength(string value)
    {
        var match = Regex.Match(value, @"^(?<number>(?:[0-9]+(?:\.[0-9]+)?|\.[0-9]+))(?:px|pt|pc|in|cm|mm|em|rem|%)?$",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));
        return match.Success && decimal.TryParse(match.Groups["number"].Value,
            System.Globalization.NumberStyles.AllowDecimalPoint, System.Globalization.CultureInfo.InvariantCulture,
            out var size) && size <= 16_384;
    }

    private static bool IsSafeContentId(string value) =>
        value.Length is > 0 and <= 255 && value.All(character =>
            char.IsLetterOrDigit(character) || character is '.' or '-' or '_' or '+' or '@' or '%' or ':' or '/');

    private static bool IsExchangeContentTypeMeta(XElement element)
    {
        if (element.Name.Namespace != XNamespace.None)
            return false;
        var attributes = element.Attributes().ToArray();
        if (attributes.Length is < 1 or > 2 || attributes.Any(attribute => attribute.Name.Namespace != XNamespace.None))
            return false;
        var httpEquiv = attributes.FirstOrDefault(attribute =>
            attribute.Name.LocalName.Equals("http-equiv", StringComparison.OrdinalIgnoreCase));
        var content = attributes.FirstOrDefault(attribute =>
            attribute.Name.LocalName.Equals("content", StringComparison.OrdinalIgnoreCase));
        if (content is null || (attributes.Length == 2 && (httpEquiv is null
            || !httpEquiv.Value.Equals("Content-Type", StringComparison.OrdinalIgnoreCase))))
            return false;
        try { return ExchangeContentType.IsMatch(content.Value); }
        catch (RegexMatchTimeoutException exception)
        {
            throw new ArgumentException("HTML metadata validation timed out.", nameof(element), exception);
        }
    }

    private static XAttribute? FindAttribute(XElement element, string name) =>
        element.Attributes().SingleOrDefault(attribute => attribute.Name.LocalName.Equals(name, StringComparison.OrdinalIgnoreCase));

    private static void AppendPreview(XNode node, System.Text.StringBuilder output)
    {
        if (node is XText text)
        {
            output.Append(text.Value);
            return;
        }
        if (node is not XElement element) return;
        var name = element.Name.LocalName;
        if (name.Equals("img", StringComparison.OrdinalIgnoreCase))
        {
            output.Append("[inline image ").Append(FindAttribute(element, "src")?.Value ?? "cid:unknown").Append(']');
            return;
        }
        var block = name is "p" or "div" or "li" or "tr" or "h1" or "h2" or "h3" or "h4" or "h5" or "h6" or "br" or "hr";
        if (block && output.Length > 0 && output[^1] != '\n') output.AppendLine();
        foreach (var child in element.Nodes()) AppendPreview(child, output);
        if (block && output.Length > 0 && output[^1] != '\n') output.AppendLine();
        if (name.Equals("a", StringComparison.OrdinalIgnoreCase) && FindAttribute(element, "href") is { } href)
            output.Append(" (").Append(WebUtility.HtmlEncode(WebUtility.HtmlDecode(href.Value))).Append(')');
    }
}
