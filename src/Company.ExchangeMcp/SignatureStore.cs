using System.Collections.Concurrent;
using System.Net.Mail;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Xml.Linq;
using Company.ExchangeMcp.Exchange;
using ModelContextProtocol;

namespace Company.ExchangeMcp;

public sealed record SignatureImage(string Name, string ContentType, string ContentId, string ContentBase64);
public sealed record MailSignature(string Name, string Body, string BodyType, SignatureImage[] Images);
public sealed record OnboardingSettings(string? Language, string Status,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? Stage = null);
public sealed record SignatureUseRule(string Signature, string? Context = null, string? RecipientAddress = null,
    string? RecipientDomain = null, string? BodyLanguage = null);
public sealed record SignatureSettings(MailSignature[] Profiles, string? NewMessages, string? Replies,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] OnboardingSettings? Onboarding = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] SignatureUseRule[]? UseRules = null);
public sealed record SignatureSelection(string? Name, string Source, string? Warning = null);
public sealed record SignatureLimits(
    int MaxProfiles,
    int MaxBodyCharacters,
    int MaxImagesPerProfile,
    int MaxImageBytes,
    int MaxTotalImageBytes,
    int MaxSerializedBytes,
    int MaxUseRules = SignatureStore.MaxUseRules);

public sealed record SignatureUsage(
    int ProfilesUsed,
    int ProfilesRemaining,
    int ImagesUsed,
    int ImagesRemaining,
    int ImageBytesUsed,
    int ImageBytesRemaining,
    int SerializedBytes,
    int SerializedBytesRemaining)
{
    public static SignatureUsage Empty => new(0, SignatureStore.MaxProfiles, 0,
        SignatureStore.MaxProfiles * SignatureStore.MaxImagesPerProfile, 0,
        SignatureStore.MaxTotalImageBytes, 0, SignatureStore.MaxSerializedBytes);
}

public sealed record SignatureSnapshot(SignatureSettings Settings, string Revision)
{
    public SignatureLimits Limits { get; init; } = SignatureStore.Limits;
    public SignatureUsage Usage { get; init; } = SignatureUsage.Empty;
}

public sealed class SignatureStore
{
    public const int MaxProfiles = 10;
    public const int MaxUseRules = 20;
    public const int MaxBodyCharacters = 65_536;
    public const int MaxImagesPerProfile = 8;
    public const int MaxImageBytes = 512 * 1024;
    public const int MaxTotalImageBytes = 2 * 1024 * 1024;
    public const int MaxSerializedBytes = EwsClient.MaxSignatureConfigurationBytes;

    public static SignatureLimits Limits { get; } = new(
        MaxProfiles,
        MaxBodyCharacters,
        MaxImagesPerProfile,
        MaxImageBytes,
        MaxTotalImageBytes,
        MaxSerializedBytes);

    // EWS UserConfiguration has no compare-and-swap token; keep one active MCP writer.
    private readonly ConcurrentDictionary<string, SemaphoreSlim> gates = new(StringComparer.OrdinalIgnoreCase);
    private static readonly JsonSerializerOptions Json = new() { MaxDepth = 12 };

    public async Task<SignatureSnapshot> ReadAsync(EwsClient exchange, string mailbox, CancellationToken cancellationToken)
    {
        var bytes = await exchange.GetSignatureConfigurationAsync(mailbox, cancellationToken);
        if (bytes is null)
            return new(new([], null, null), "new") { Usage = SignatureUsage.Empty };
        if (bytes.Length > MaxSerializedBytes)
            throw new McpException("The saved signature configuration exceeds 3 MiB.");
        try
        {
            var settings = JsonSerializer.Deserialize<SignatureSettings>(bytes, Json)
                ?? throw new JsonException();
            Validate(settings);
            return Snapshot(settings, Convert.ToHexString(SHA256.HashData(bytes)), bytes.Length);
        }
        catch (Exception exception) when (exception is JsonException or ArgumentException or McpException)
        { throw new McpException("The saved signature configuration is invalid. Contact the administrator."); }
    }

    public async Task<SignatureSnapshot> UpdateAsync(EwsClient exchange, string mailbox, string expectedRevision,
        Func<SignatureSettings, SignatureSettings> update, CancellationToken cancellationToken)
    {
        var gate = gates.GetOrAdd(mailbox, _ => new(1, 1));
        await gate.WaitAsync(cancellationToken);
        try
        {
            var before = await ReadAsync(exchange, mailbox, cancellationToken);
            if (!string.Equals(before.Revision, expectedRevision, StringComparison.Ordinal))
                throw new McpException("Signatures changed. Read them again before saving.");
            var after = update(before.Settings);
            var bytes = SerializeValidated(after);
            var revision = Convert.ToHexString(SHA256.HashData(bytes));
            var snapshot = Snapshot(after, revision, bytes.Length);
            await exchange.SaveSignatureConfigurationAsync(mailbox, bytes, before.Revision == "new", cancellationToken);
            return snapshot;
        }
        finally { gate.Release(); }
    }

    public static void Validate(SignatureSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        if (settings.Onboarding is { } onboarding
            && ((onboarding.Language is not null && onboarding.Language is not ("fa" or "en"))
                || onboarding.Status is not ("pending" or "completed" or "skipped")
                || (onboarding.Stage is not null && onboarding.Stage is not ("signature" or "more_signatures_and_rules"))
                || (onboarding.Status != "pending" && onboarding.Language is null)))
            throw new McpException("Saved onboarding state is invalid.");
        if (settings.Profiles is null || settings.Profiles.Length > MaxProfiles)
            throw new McpException("A mailbox supports at most 10 Company Mail signature profiles.");
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var imageBytes = 0;
        foreach (var profile in settings.Profiles)
        {
            if (profile is null || string.IsNullOrWhiteSpace(profile.Name) || profile.Name.Length > 80
                || profile.Name.Any(char.IsControl) || !names.Add(profile.Name))
                throw new McpException("Signature names must be unique, nonempty and at most 80 characters.");
            if (profile.Body is null || profile.Body.Length > MaxBodyCharacters || profile.Body.Contains('\0')
                || profile.BodyType is not ("Text" or "HTML"))
                throw new McpException("Signatures support Text or HTML bodies up to 65536 characters.");
            var body = RichBody.Validate(profile.Body, profile.BodyType);
            if (profile.Images is null || profile.Images.Length > MaxImagesPerProfile)
                throw new McpException("A signature supports at most 8 inline images.");
            var ids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var image in profile.Images)
            {
                if (image is null || string.IsNullOrWhiteSpace(image.Name) || image.Name.Length > 255
                    || image.Name.Any(char.IsControl) || image.Name.Contains('/') || image.Name.Contains('\\')
                    || image.ContentType is not ("image/png" or "image/jpeg" or "image/gif")
                    || string.IsNullOrWhiteSpace(image.ContentId) || image.ContentId.Length > 128
                    || image.ContentId.Any(c => !(char.IsAsciiLetterOrDigit(c) || c is '.' or '_' or '-' or '@'))
                    || !ids.Add(image.ContentId) || image.ContentBase64 is null || image.ContentBase64.Length > 699052)
                    throw new McpException("Invalid signature image: use a PNG, JPEG or GIF up to 512 KiB with a unique simple ContentId.");
                byte[] bytes;
                try { bytes = Convert.FromBase64String(image.ContentBase64); }
                catch (FormatException) { throw new McpException("Invalid signature image data."); }
                if (bytes.Length is < 1 or > MaxImageBytes || !RichBody.HasImageHeader(bytes, image.ContentType))
                    throw new McpException("The signature image does not match its declared PNG, JPEG or GIF content type.");
                imageBytes = checked(imageBytes + bytes.Length);
                if (imageBytes > MaxTotalImageBytes)
                    throw new McpException("All signature images together must fit within 2 MiB.");
            }
            if (profile.BodyType == "Text" && profile.Images.Length != 0)
                throw new McpException("Inline signature images require an HTML body.");
            if (profile.BodyType == "HTML" && XElement.Parse("<root>" + body + "</root>").Descendants()
                .Where(element => element.Name.LocalName.Equals("img", StringComparison.OrdinalIgnoreCase))
                .Any(element =>
                {
                    var source = element.Attributes()
                        .Single(attribute => attribute.Name.LocalName.Equals("src", StringComparison.OrdinalIgnoreCase)).Value;
                    return !source.StartsWith("cid:", StringComparison.OrdinalIgnoreCase)
                        || !ids.Contains(source[4..]);
                }))
                throw new McpException("Each signature CID image must have a matching uploaded image.");
        }
        if ((settings.NewMessages is not null && !names.Contains(settings.NewMessages))
            || (settings.Replies is not null && !names.Contains(settings.Replies)))
            throw new McpException("Default signatures must name an existing profile, or be null.");
        if ((settings.UseRules?.Length ?? 0) > MaxUseRules)
            throw new McpException("A mailbox supports at most 20 signature use rules.");
        foreach (var rule in settings.UseRules ?? [])
        {
            if (rule is null || rule.Signature is null || !names.Contains(rule.Signature)
                || (rule.Context is not null && rule.Context is not ("new" or "reply"))
                || (rule.BodyLanguage is not null && rule.BodyLanguage is not ("en" or "fa"))
                || (rule.RecipientAddress is not null && !IsRuleAddress(rule.RecipientAddress))
                || (rule.RecipientDomain is not null && !IsRuleDomain(rule.RecipientDomain))
                || (rule.RecipientAddress is not null && rule.RecipientDomain is not null)
                || (rule.Context is null && rule.BodyLanguage is null && rule.RecipientAddress is null && rule.RecipientDomain is null))
                throw new McpException("Signature rules must reference an existing profile and at least one supported condition: context new/reply, body language en/fa, or one exact bare SMTP address/ASCII domain. No wildcards or expressions.");
        }
    }

    public static SignatureSelection Select(SignatureSettings settings, string? name, string context,
        IReadOnlyList<string> recipients, string body, string bodyType)
    {
        if (context is not ("new" or "reply")) throw new ArgumentException("Signature context must be new or reply.", nameof(context));
        if (name is not null) return new(name, "explicit");
        var fallback = context == "new" ? settings.NewMessages : settings.Replies;
        string? language = null;
        var inspectedLanguage = false;
        foreach (var rule in settings.UseRules ?? [])
        {
            if (rule.Context is not null && rule.Context != context) continue;
            if (rule.BodyLanguage is not null)
            {
                if (!inspectedLanguage)
                {
                    language = DetectBodyLanguage(body, bodyType, context);
                    inspectedLanguage = true;
                }
                if (language != rule.BodyLanguage) continue;
            }
            if (rule.RecipientAddress is not null || rule.RecipientDomain is not null)
            {
                if (recipients.Count == 0) continue;
                var matches = recipients.Count(address => IsRuleAddress(address)
                    && (rule.RecipientAddress is not null
                        ? address.Equals(rule.RecipientAddress, StringComparison.OrdinalIgnoreCase)
                        : address[(address.LastIndexOf('@') + 1)..].Equals(rule.RecipientDomain, StringComparison.OrdinalIgnoreCase)));
                if (matches == 0) continue;
                if (matches != recipients.Count)
                    return new(fallback, "default", "Recipient conditions matched only some To/Cc/Bcc recipients. Used the context default; choose a signature explicitly to override.");
            }
            return new(rule.Signature, "rule");
        }
        return new(fallback, "default");
    }

    private static bool IsRuleDomain(string domain) => domain.Length is > 0 and <= 253
        && domain.Split('.').All(label => label.Length is > 0 and <= 63
            && char.IsAsciiLetterOrDigit(label[0]) && char.IsAsciiLetterOrDigit(label[^1])
            && label.All(character => char.IsAsciiLetterOrDigit(character) || character == '-'));

    private static bool IsRuleAddress(string address) => address.Length is > 0 and <= 320
        && !address.Any(character => char.IsControl(character) || char.IsWhiteSpace(character))
        && MailAddress.TryCreate(address, out var parsed) && parsed.Address.Equals(address, StringComparison.OrdinalIgnoreCase)
        && address.LastIndexOf('@') > 0 && IsRuleDomain(address[(address.LastIndexOf('@') + 1)..]);

    private static string? DetectBodyLanguage(string body, string bodyType, string context)
    {
        if (bodyType == "HTML")
        {
            var root = RichBody.ParseExchangeHtml(body);
            var marker = context == "reply" ? root.Descendants().FirstOrDefault(element =>
                element.Name.LocalName.Equals("div", StringComparison.OrdinalIgnoreCase)
                && element.Attributes().Any(attribute => attribute.Name.LocalName.Equals("id", StringComparison.OrdinalIgnoreCase)
                    && attribute.Value.Equals("divRplyFwdMsg", StringComparison.OrdinalIgnoreCase))) : null;
            if (marker is not null)
            {
                // Do not classify the authored reply using the quoted message's language.
                for (XNode? node = marker; node?.Parent is not null; node = node.Parent)
                    node.NodesAfterSelf().Remove();
                marker.Remove();
            }
            root.Descendants().Where(element => new[] { "head", "style", "title", "meta" }
                .Contains(element.Name.LocalName, StringComparer.OrdinalIgnoreCase)).Remove();
            body = string.Concat(root.DescendantNodes().OfType<XText>().Select(text => text.Value));
        }
        else if (context == "reply")
            body = body[..SignatureCapture.FindTextQuoteOffset(body)];
        var languages = body.Where(char.IsLetter).Select(character => character is >= '\u0600' and <= '\u06ff'
            ? "fa" : character is >= 'A' and <= 'Z' or >= 'a' and <= 'z' ? "en" : "other").Distinct().ToArray();
        return languages.Length == 1 && languages[0] != "other" ? languages[0] : null;
    }

    internal static byte[] SerializeValidated(SignatureSettings settings)
    {
        Validate(settings);
        var bytes = JsonSerializer.SerializeToUtf8Bytes(settings, Json);
        if (bytes.Length > MaxSerializedBytes)
            throw new McpException("The combined signature configuration exceeds 3 MiB.");
        return bytes;
    }

    public static string Append(string body, string bodyType, MailSignature signature, string context = "new")
    {
        if (context is not ("new" or "reply")) throw new ArgumentException("Signature context must be new or reply.", nameof(context));
        _ = RichBody.Validate(body, bodyType);
        var textQuote = bodyType == "Text" && context == "reply" ? SignatureCapture.FindTextQuoteOffset(body) : body.Length;
        var hasTextQuote = textQuote < body.Length;
        if (bodyType == "Text" && signature.BodyType == "Text")
            return hasTextQuote
                ? body[..textQuote] + "\r\n\r\n" + signature.Body + "\r\n\r\n" + body[textQuote..]
                : body + "\r\n\r\n" + signature.Body;
        var first = bodyType == "HTML" ? body : ToHtml(body[..(hasTextQuote ? textQuote : body.Length)]);
        var second = signature.BodyType == "HTML" ? signature.Body : ToHtml(signature.Body);
        if (bodyType == "HTML")
        {
            var root = XElement.Parse("<root>" + first + "</root>", LoadOptions.PreserveWhitespace);
            InsertSignature(root, second, context);
            return RichBody.Validate(string.Concat(root.Nodes().Select(node => node.ToString(SaveOptions.DisableFormatting))), "HTML");
        }
        var quoted = hasTextQuote ? "<hr /><div id=\"divRplyFwdMsg\">" + ToHtml(body[textQuote..]) + "</div>" : string.Empty;
        return RichBody.Validate(first + "<div><br /></div>" + second + quoted, "HTML");
    }

    internal static string AppendToExchangeHtml(string body, MailSignature signature, string context)
    {
        if (context is not ("new" or "reply")) throw new ArgumentException("Signature context must be new or reply.", nameof(context));
        var root = RichBody.ParseExchangeHtml(body);
        var signatureBody = RichBody.Validate(signature.Body, signature.BodyType);
        InsertSignature(root, signature.BodyType == "HTML" ? signatureBody : ToHtml(signatureBody), context);
        return RichBody.SerializeExchangeHtml(root);
    }

    private static void InsertSignature(XElement root, string html, string context)
    {
        var (container, boundary) = AppendLocation(root, context);
        var appended = XElement.Parse("<root>" + RichBody.Validate("<div><br /></div>" + html, "HTML")
            + "</root>", LoadOptions.PreserveWhitespace);
        if (boundary is not null) boundary.AddBeforeSelf(appended.Nodes());
        else container.Add(appended.Nodes());
    }

    internal static bool HasExactAppendedSignature(string body, string bodyType, MailSignature signature, string context)
    {
        if (bodyType == "Text")
        {
            var canonicalBody = body.Replace("\r\n", "\n", StringComparison.Ordinal).Replace('\r', '\n');
            var canonicalSignature = signature.Body.Replace("\r\n", "\n", StringComparison.Ordinal).Replace('\r', '\n');
            var textQuote = context == "reply" ? SignatureCapture.FindTextQuoteOffset(canonicalBody) : canonicalBody.Length;
            if (textQuote < canonicalBody.Length)
            {
                canonicalBody = canonicalBody[..textQuote];
                if (!canonicalBody.EndsWith("\n\n", StringComparison.Ordinal)) return false;
                canonicalBody = canonicalBody[..^2];
            }
            return signature.BodyType == "Text" && canonicalBody.EndsWith("\n\n" + canonicalSignature, StringComparison.Ordinal);
        }
        var root = RichBody.ParseExchangeHtml(body);
        var (container, boundary) = AppendLocation(root, context);
        var expected = RichBody.Validate("<div><br /></div>"
            + (signature.BodyType == "HTML" ? signature.Body : ToHtml(signature.Body)), "HTML");
        var authored = boundary is null ? container.Nodes() : boundary.NodesBeforeSelf();
        var parent = boundary?.Parent ?? container;
        var preserve = parent.AncestorsAndSelf().Any(element => PreservesHtmlWhitespace(element, false));
        var expectedRoot = CanonicalSignatureNodes(XElement.Parse("<root>" + expected + "</root>", LoadOptions.PreserveWhitespace).Nodes(), preserve);
        var authoredRoot = CanonicalSignatureNodes(authored, preserve);
        var tail = new XElement("root", authoredRoot.Nodes().TakeLast(expectedRoot.Nodes().Count()));
        return XNode.DeepEquals(tail, expectedRoot);
    }

    private static XElement CanonicalSignatureNodes(IEnumerable<XNode> nodes, bool preserve)
    {
        var root = new XElement("root", nodes.Where(node => node is not XComment).Select(node => node is XElement element
            ? (XNode)new XElement(element) : new XText(((XText)node).Value)));
        root.DescendantNodes().OfType<XComment>().Remove();
        // Exchange can inherit the document's standard HTML namespace onto the saved signature.
        foreach (var element in root.Descendants().Where(element => RichBody.IsExchangeHtmlNamespace(element.Name.Namespace)))
        {
            element.Name = element.Name.LocalName;
            element.Attributes().Where(attribute => attribute.IsNamespaceDeclaration).Remove();
        }
        CanonicalizeHtmlWhitespace(root, preserve);
        return root;
    }

    private static void CanonicalizeHtmlWhitespace(XElement element, bool inheritedPreserve)
    {
        var preserve = PreservesHtmlWhitespace(element, inheritedPreserve);
        foreach (var node in element.Nodes().ToArray())
        {
            if (node is XElement child) CanonicalizeHtmlWhitespace(child, preserve);
            else if (node is XText text && !preserve)
            {
                var value = new StringBuilder(text.Value.Length);
                var previousSpace = false;
                foreach (var character in text.Value)
                {
                    var space = character is ' ' or '\t' or '\r' or '\n' or '\f';
                    if (!space || !previousSpace) value.Append(space ? ' ' : character);
                    previousSpace = space;
                }
                var normalized = value.ToString();
                if ((text.PreviousNode is null && IsHtmlBlock(element)) || IsHtmlWhitespaceBoundary(text.PreviousNode))
                    normalized = normalized.TrimStart(' ');
                if ((text.NextNode is null && IsHtmlBlock(element)) || IsHtmlWhitespaceBoundary(text.NextNode))
                    normalized = normalized.TrimEnd(' ');
                if (normalized.Length == 0) text.Remove();
                else text.Value = normalized;
            }
        }
    }

    // shortcut: CSS resets remain preserving; model the cascade only if actual EWS signatures require it.
    private static bool PreservesHtmlWhitespace(XElement element, bool inheritedPreserve) =>
        inheritedPreserve || element.Name.LocalName.Equals("pre", StringComparison.OrdinalIgnoreCase)
        || element.Attributes().Where(attribute => attribute.Name.LocalName.Equals("style", StringComparison.OrdinalIgnoreCase))
            .SelectMany(attribute => attribute.Value.Split(';')).Any(declaration =>
            {
                var pair = declaration.Split(':', 2);
                return pair.Length == 2 && pair[0].Trim().Equals("white-space", StringComparison.OrdinalIgnoreCase)
                    && !pair[1].Trim().Equals("normal", StringComparison.OrdinalIgnoreCase)
                    && !pair[1].Trim().Equals("nowrap", StringComparison.OrdinalIgnoreCase);
            });

    private static bool IsHtmlWhitespaceBoundary(XNode? node) => node is XElement element
        && (IsHtmlBlock(element) || element.Name.LocalName.Equals("br", StringComparison.OrdinalIgnoreCase));

    private static bool IsHtmlBlock(XElement element) => element.Name.LocalName.ToLowerInvariant() is
        "root" or "blockquote" or "body" or "caption" or "colgroup" or "div" or "h1" or "h2" or "h3"
        or "h4" or "h5" or "h6" or "hr" or "li" or "ol" or "p" or "pre" or "table" or "tbody"
        or "td" or "tfoot" or "th" or "thead" or "tr" or "ul";

    private static (XElement Container, XNode? Boundary) AppendLocation(XElement root, string context)
    {
        var elements = root.Elements().ToArray();
        var container = root;
        if (elements.Length == 1 && elements[0].Name.LocalName.Equals("html", StringComparison.OrdinalIgnoreCase))
        {
            var bodies = elements[0].Elements()
                .Where(element => element.Name.LocalName.Equals("body", StringComparison.OrdinalIgnoreCase)).ToArray();
            if (bodies.Length == 1) container = bodies[0];
        }
        var quote = context == "reply" ? container.Descendants().FirstOrDefault(element =>
            element.Name.LocalName.Equals("div", StringComparison.OrdinalIgnoreCase)
            && element.Attributes().Any(attribute => attribute.Name.LocalName.Equals("id", StringComparison.OrdinalIgnoreCase)
                && attribute.Value.Equals("divRplyFwdMsg", StringComparison.OrdinalIgnoreCase))) : null;
        if (quote is null) return (container, null);
        var previous = quote.PreviousNode;
        while (previous is XText text && string.IsNullOrWhiteSpace(text.Value)) previous = previous.PreviousNode;
        return (container, previous is XElement separator && separator.Name.LocalName.Equals("hr", StringComparison.OrdinalIgnoreCase)
            ? separator : quote);
    }

    private static string ToHtml(string text) => "<div>" + System.Net.WebUtility.HtmlEncode(text)
        .Replace("\r\n", "\n", StringComparison.Ordinal).Replace("\n", "<br />", StringComparison.Ordinal) + "</div>";

    private static SignatureSnapshot Snapshot(SignatureSettings settings, string revision, int serializedBytes)
    {
        var profiles = settings.Profiles.Length;
        var images = settings.Profiles.Sum(profile => profile.Images.Length);
        var imageBytes = settings.Profiles
            .SelectMany(profile => profile.Images)
            .Sum(image => Convert.FromBase64String(image.ContentBase64).Length);
        return new SignatureSnapshot(settings, revision)
        {
            Usage = new(
                profiles,
                MaxProfiles - profiles,
                images,
                MaxProfiles * MaxImagesPerProfile - images,
                imageBytes,
                MaxTotalImageBytes - imageBytes,
                serializedBytes,
                MaxSerializedBytes - serializedBytes)
        };
    }
}
