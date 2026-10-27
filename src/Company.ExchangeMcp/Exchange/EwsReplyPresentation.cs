using System.Globalization;
using System.Net.Mail;
using System.Xml.Linq;

namespace Company.ExchangeMcp.Exchange;

public sealed partial class EwsClient
{
    private async Task<TimeZoneInfo> ReadReplyTimeZoneAsync(string mailbox, CancellationToken cancellationToken)
    {
        try
        {
            var operation = new XElement(M + "GetUserConfiguration",
                new XElement(M + "UserConfigurationName", new XAttribute("Name", "OWA.UserOptions"),
                    new XElement(T + "DistinguishedFolderId", new XAttribute("Id", "root"))),
                new XElement(M + "UserConfigurationProperties", "Dictionary"));
            var document = await SendAsync(mailbox, operation, cancellationToken, allowMissingUserConfiguration: true).ConfigureAwait(false);
            var entries = document.Descendants(M + "UserConfiguration").SingleOrDefault()?.Element(T + "Dictionary")?.Elements(T + "DictionaryEntry").Where(entry =>
                entry.Element(T + "DictionaryKey")?.Element(T + "Type")?.Value == "String"
                && entry.Element(T + "DictionaryKey")?.Elements(T + "Value").Count() == 1
                && entry.Element(T + "DictionaryKey")?.Element(T + "Value")?.Value.Equals("timezone", StringComparison.OrdinalIgnoreCase) == true).ToArray();
            if (entries is null || entries.Length != 1) return TimeZoneInfo.Utc;
            var value = entries[0].Element(T + "DictionaryValue");
            if (value?.Element(T + "Type")?.Value != "String" || value.Elements(T + "Value").Count() != 1) return TimeZoneInfo.Utc;
            return ResolveTimeZone(value.Element(T + "Value")!.Value);
        }
        catch (Exception exception) when (!cancellationToken.IsCancellationRequested && exception is not OutOfMemoryException)
        { return TimeZoneInfo.Utc; }
    }

    private async Task<EwsItemRef> PresentReplyAsync(string mailbox, EwsItemRef draft, EwsMessage source,
        string nonce, string submittedBody, TimeZoneInfo zone, CancellationToken cancellationToken)
    {
        var phase = "draft_read";
        try
        {
            var current = await GetMessageAsync(mailbox, draft.Id, cancellationToken).ConfigureAwait(false);
            phase = "revision_check";
            if (current.Id != draft.Id || !current.IsDraft || string.IsNullOrEmpty(current.ChangeKey) || current.BodyType != "HTML")
                throw new InvalidOperationException("The native reply draft could not be verified.");
            var expectedKey = draft.ChangeKey;
            draft = new(current.Id, current.ChangeKey);
            if (current.ChangeKey != expectedKey)
                throw new InvalidOperationException("The native reply changed before header formatting.");
            phase = "header_format";
            var body = FormatReplyHeader(current.Body ?? string.Empty, source, nonce, submittedBody, zone);
            phase = "quoted_images";
            ValidateQuotedReplyImages(source, current, nonce);
            phase = "header_write";
            return await UpdateNativeDraftBodyAsync(mailbox, current, body, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is not OutOfMemoryException)
        {
            return draft with { PresentationWarning = "The unsent native reply or forward was retained, but its presentation update failed or is uncertain (phase: " + phase + "). Read this draft before editing or sending; do not create another reply or forward." };
        }
    }

    private static void ValidateQuotedReplyImages(EwsMessage source, EwsMessage draft, string nonce)
    {
        if (source.BodyType != "HTML") return;
        if (source.Body is null) throw new InvalidOperationException("The original HTML body could not be verified.");
        var original = RichBody.ParseExchangeHtml(source.Body);
        var current = RichBody.ParseExchangeHtml(draft.Body ?? string.Empty);
        var authored = current.Descendants().Single(element => (string?)element.Attribute("id") == nonce);
        authored.Remove();
        var quotedReferences = ReplyImageReferences(current);
        foreach (var reference in ReplyImageReferences(original).GroupBy(value => value, StringComparer.OrdinalIgnoreCase))
        {
            var sourceImages = source.Attachments.Where(image => ReplyContentId(image.ContentId).Equals(reference.Key, StringComparison.OrdinalIgnoreCase)).ToArray();
            var draftImages = draft.Attachments.Where(image => ReplyContentId(image.ContentId).Equals(reference.Key, StringComparison.OrdinalIgnoreCase)).ToArray();
            if (sourceImages.Length != 1 || draftImages.Length != 1
                || quotedReferences.Count(value => value.Equals(reference.Key, StringComparison.OrdinalIgnoreCase)) != reference.Count())
                throw new InvalidOperationException("A quoted inline image is missing or ambiguous.");
            var before = sourceImages[0];
            var after = draftImages[0];
            if (!before.IsInline || !after.IsInline || before.Size <= 0 || before.Size != after.Size
                || string.IsNullOrWhiteSpace(before.Name) || before.Name != after.Name
                || string.IsNullOrWhiteSpace(before.ContentType) || !before.ContentType.StartsWith("image/", StringComparison.OrdinalIgnoreCase)
                || !string.Equals(before.ContentType, after.ContentType, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("A quoted inline image changed its attachment metadata.");
        }
    }

    private static string[] ReplyImageReferences(XElement root) => root.Descendants()
        .Where(element => element.Name.LocalName.Equals("img", StringComparison.OrdinalIgnoreCase))
        .Select(element => element.Attributes().Single(attribute => attribute.Name.LocalName.Equals("src", StringComparison.OrdinalIgnoreCase)).Value)
        .Where(value => value.StartsWith("cid:", StringComparison.OrdinalIgnoreCase)).Select(value => value[4..])
        .ToArray();

    private static string ReplyContentId(string? value) => (value ?? string.Empty).Trim().Trim('<', '>');

    internal static string FormatReplyHeader(string body, EwsMessage source, string nonce, string submittedBody, TimeZoneInfo zone)
    {
        var root = RichBody.ParseExchangeHtml(body);
        var wrappers = root.Descendants().Where(element => element.Attributes().Any(attribute =>
            attribute.Name.LocalName.Equals("id", StringComparison.OrdinalIgnoreCase) && attribute.Value == nonce)).ToArray();
        if (wrappers.Length != 1 || !wrappers[0].Name.LocalName.Equals("div", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("The newly submitted reply body could not be uniquely verified.");
        var wrapper = wrappers[0];
        var submitted = XElement.Parse("<root>" + RichBody.NormalizeExchangeHtml(submittedBody) + "</root>", LoadOptions.PreserveWhitespace);
        var returned = new XElement("root", wrapper.Nodes());
        if (!PreservesReplyWhitespace(wrapper))
        {
            RemoveReplyBlockFormattingWhitespace(returned);
            RemoveReplyBlockFormattingWhitespace(submitted);
        }
        NormalizeReplyComparison(returned);
        NormalizeReplyComparison(submitted);
        if (!XNode.DeepEquals(returned, submitted))
            throw new InvalidOperationException("The submitted reply body changed before header formatting.");
        var anchor = wrapper;
        while (NextReplyNode(anchor) is null && anchor.Parent is { } parent && parent != root
            && parent.Nodes().All(node => node == anchor || node is XText text && string.IsNullOrWhiteSpace(text.Value)))
            anchor = parent;
        var separator = NextReplyNode(anchor) as XElement;
        var marker = separator is not null ? NextReplyNode(separator) as XElement : null;
        if (separator?.Name.LocalName.ToLowerInvariant() != "hr" || marker?.Name.LocalName.ToLowerInvariant() != "div"
            || !marker.Attributes().Any(attribute => attribute.Name.LocalName.Equals("id", StringComparison.OrdinalIgnoreCase)
                && attribute.Value.Equals("divRplyFwdMsg", StringComparison.OrdinalIgnoreCase)))
            throw new InvalidOperationException("The newly generated native reply header could not be verified.");
        var oldHeader = marker.Elements().FirstOrDefault();
        if (oldHeader is null || oldHeader.Name.LocalName.ToLowerInvariant() is not ("span" or "font")
            || oldHeader.Descendants().Any(element => !new[] { "b", "strong", "br", "span" }.Contains(element.Name.LocalName.ToLowerInvariant()))
            || !new[] { "From:", "Sent:", "To:", "Subject:" }.All(label => oldHeader.Value.Contains(label, StringComparison.Ordinal))
            || marker.Nodes().Any(node => node != oldHeader && !(node is XText text && string.IsNullOrWhiteSpace(text.Value))
                && !(node is XElement blank && blank.Name.LocalName.Equals("div", StringComparison.OrdinalIgnoreCase)
                    && !blank.Elements().Any() && string.IsNullOrWhiteSpace(blank.Value))))
            throw new InvalidOperationException("The native header structure is ambiguous; quoted history was retained.");
        if (source.FromIdentity is null || source.SentUtc is null || source.ToIdentities.Count != source.To.Count
            || source.CcIdentities.Count != source.Cc.Count || source.ToIdentities.Count + source.CcIdentities.Count > MaxRecipients
            || !DateTimeOffset.TryParse(source.SentUtc, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var sent))
            throw new InvalidOperationException("The original message header metadata is incomplete.");
        var header = new XElement(oldHeader.Name, new XAttribute("dir", "ltr"), new XAttribute("style", "font-family:Calibri,sans-serif;font-size:11pt;color:#000000"));
        AddReplyHeaderLine(header, "From", ReplyIdentity(source.FromIdentity));
        if (source.SenderIdentity is { } sender && sender != source.FromIdentity)
            AddReplyHeaderLine(header, "Sender", ReplyIdentity(sender));
        AddReplyHeaderLine(header, "Sent", new XElement("span", new XAttribute("dir", "ltr"),
            TimeZoneInfo.ConvertTime(sent, zone).ToString("dddd, dd MMMM yyyy HH:mm:ss zzz", CultureInfo.InvariantCulture)
                + " (" + zone.Id + ")"));
        AddReplyHeaderLine(header, "To", ReplyIdentities(source.ToIdentities));
        if (source.CcIdentities.Count > 0) AddReplyHeaderLine(header, "Cc", ReplyIdentities(source.CcIdentities));
        AddReplyHeaderLine(header, "Subject", source.Subject);
        if (source.Importance is "High" or "Low") AddReplyHeaderLine(header, "Importance", source.Importance);
        else if (source.Importance is not (null or "Normal")) throw new InvalidOperationException("The original message importance is invalid.");
        oldHeader.ReplaceWith(header);
        wrapper.ReplaceWith(wrapper.Nodes().ToArray());
        return RichBody.SerializeExchangeHtml(root);
    }

    private static XNode? NextReplyNode(XNode node)
    {
        var next = node.NextNode;
        while (next is XText text && string.IsNullOrWhiteSpace(text.Value)) next = next.NextNode;
        return next;
    }

    private static void NormalizeReplyComparison(XElement content)
    {
        // Exchange rewrites HTML spelling and CSS delimiter spacing; compare clones without rewriting the draft.
        foreach (var element in content.Descendants())
        {
            if (RichBody.IsExchangeHtmlNamespace(element.Name.Namespace))
                element.Name = element.Name.LocalName.ToLowerInvariant();
            var attributes = element.Attributes().Where(attribute => !attribute.IsNamespaceDeclaration
                || !RichBody.IsExchangeHtmlNamespace(attribute.Value)).Select(attribute =>
            {
                var name = attribute.Name.Namespace == XNamespace.None
                    ? XName.Get(attribute.Name.LocalName.ToLowerInvariant()) : attribute.Name;
                var value = attribute.Value;
                if (name == "style")
                    value = string.Join(';', value.Split(';').Select(declaration =>
                    {
                        var separator = declaration.IndexOf(':');
                        return separator < 0 ? declaration.Trim(' ', '\t', '\r', '\n')
                            : declaration[..separator].Trim(' ', '\t', '\r', '\n') + ":"
                                + declaration[(separator + 1)..].Trim(' ', '\t', '\r', '\n');
                    }));
                return new XAttribute(name, value);
            }).OrderBy(attribute => attribute.Name.ToString(), StringComparer.Ordinal).ToArray();
            element.ReplaceAttributes(attributes);
        }
    }

    private static void RemoveReplyBlockFormattingWhitespace(XElement content)
    {
        foreach (var text in content.DescendantNodes().OfType<XText>().ToArray())
        {
            if (!text.Value.Contains('\r') && !text.Value.Contains('\n')) continue;
            if (text.Parent is not { } parent || PreservesReplyWhitespace(parent)) continue;
            if (text.PreviousNode is XElement lineBreak && lineBreak.Name.LocalName.Equals("br", StringComparison.OrdinalIgnoreCase))
            {
                // Under normal whitespace, Exchange's indentation after BR has no visible content.
                var start = 0;
                while (start < text.Value.Length && text.Value[start] is ' ' or '\t' or '\r' or '\n') start++;
                if (text.Value.AsSpan(0, start).ContainsAny('\r', '\n'))
                {
                    text.Value = text.Value[start..];
                    if (text.Value.Length == 0) text.Remove();
                }
                continue;
            }
            if (text.Value.Any(character => character is not (' ' or '\t' or '\r' or '\n'))
                || !new[] { "root", "div", "body", "blockquote", "li", "td", "th", "caption", "table", "thead", "tbody", "tfoot", "tr", "ul", "ol" }
                    .Contains(parent.Name.LocalName.ToLowerInvariant())) continue;
            if ((text.PreviousNode is null || text.PreviousNode is XElement previous && IsReplyBlock(previous))
                && (text.NextNode is null || text.NextNode is XElement next && IsReplyBlock(next))
                && (text.PreviousNode is XElement || text.NextNode is XElement))
                text.Remove();
        }
    }

    private static bool IsReplyBlock(XElement element) =>
        new[] { "p", "div", "table", "blockquote", "ul", "ol", "li", "thead", "tbody", "tfoot", "tr", "td", "th", "caption", "h1", "h2", "h3", "h4", "h5", "h6", "hr", "pre" }
            .Contains(element.Name.LocalName.ToLowerInvariant());

    private static bool PreservesReplyWhitespace(XElement element) => element.AncestorsAndSelf().Any(ancestor =>
        ancestor.Name.LocalName.Equals("pre", StringComparison.OrdinalIgnoreCase)
        || ancestor.Name.LocalName.Equals("code", StringComparison.OrdinalIgnoreCase)
        || ancestor.Attributes().Where(attribute => attribute.Name.LocalName.Equals("style", StringComparison.OrdinalIgnoreCase))
            .SelectMany(attribute => attribute.Value.Split(';')).Any(declaration =>
            {
                var pair = declaration.Split(':');
                return pair.Length == 2 && pair[0].Trim().Equals("white-space", StringComparison.OrdinalIgnoreCase)
                    && !new[] { "normal", "nowrap" }.Contains(pair[1].Trim(), StringComparer.OrdinalIgnoreCase);
            }));

    private static void AddReplyHeaderLine(XElement header, string label, object value) =>
        header.Add(new XElement("b", label + ": "), value, new XElement("br"));

    private static IEnumerable<object> ReplyIdentities(IReadOnlyList<EwsMailboxIdentity> identities) =>
        identities.SelectMany((identity, index) => index == 0 ? new object[] { ReplyIdentity(identity) } : new object[] { "; ", ReplyIdentity(identity) });

    private static XElement ReplyIdentity(EwsMailboxIdentity identity)
    {
        if ((identity.Name?.Length ?? 0) > 1024 || (identity.Address?.Length ?? 0) > MaxMailboxLength
            || (identity.RoutingType?.Length ?? 0) > 32 || (identity.RoutingType?.Any(char.IsControl) ?? false)
            || (identity.Name?.Any(char.IsControl) ?? false) || (identity.Address?.Any(char.IsControl) ?? false))
            throw new InvalidOperationException("The original message mailbox identity is invalid.");
        var name = string.IsNullOrWhiteSpace(identity.Name) ? null : identity.Name;
        var address = identity.Address;
        var span = new XElement("span", new XAttribute("dir", "auto"));
        var smtp = (identity.RoutingType is null || identity.RoutingType.Equals("SMTP", StringComparison.OrdinalIgnoreCase))
            && address is not null && MailAddress.TryCreate(address, out var parsed)
            && parsed.Address.Equals(address, StringComparison.OrdinalIgnoreCase) && address.Contains('@');
        if (name is not null) span.Add(name);
        if (smtp)
        {
            if (name is not null) span.Add(" <");
            var at = address!.LastIndexOf('@');
            span.Add(new XElement("a", new XAttribute("dir", "ltr"),
                new XAttribute("href", "mailto:" + Uri.EscapeDataString(address[..at]) + "@" + Uri.EscapeDataString(address[(at + 1)..])), address));
            if (name is not null) span.Add(">");
        }
        else
        {
            if (name is not null) span.Add(" <");
            span.Add(new XElement("span", new XAttribute("dir", "ltr"), address ?? "[unresolved mailbox]"));
            if (name is not null) span.Add(">");
            span.Add(" [" + (identity.RoutingType ?? "unresolved") + "]");
        }
        return span;
    }
}
