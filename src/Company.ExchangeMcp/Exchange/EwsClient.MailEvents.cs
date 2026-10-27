using System.Xml.Linq;
using System.Text;
using System.Xml;

namespace Company.ExchangeMcp.Exchange;

public sealed partial class EwsClient
{
    public async Task<EwsMessage> GetMessageSummaryAsync(string mailbox, string itemId,
        CancellationToken cancellationToken)
    {
        var normalizedMailbox = ValidateMailbox(mailbox);
        var normalizedItemId = ValidateItemId(itemId, "item");
        var shape = MessageShape(summaryOnly: true);
        shape.Element(T + "AdditionalProperties")!.Add(Field("message:ToRecipients"), Field("message:CcRecipients"),
            RecallExtendedField("0x300B", "Binary"));
        var operation = new XElement(M + "GetItem", shape,
            new XElement(M + "ItemIds", ItemReference(normalizedItemId)));
        var document = await SendAsync(normalizedMailbox, operation, cancellationToken).ConfigureAwait(false);
        var item = RequiredReturnedItem(document);
        return ParseMessage(item) with { EventSearchKey = ReadEventSearchKey(item) };
    }

    public async Task<EwsMessage> GetEventMessageAsync(string mailbox, string itemId, string? searchKey,
        CancellationToken cancellationToken)
    {
        var ownMailbox = ValidateOwnStreamingMailbox(mailbox);
        var originalId = ValidateItemId(itemId, "item");
        var key = searchKey is null ? null : ValidateEventSearchKey(searchKey);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(30));

        async Task<EwsMessage> ReadExactAsync(string id)
        {
            var shape = MessageShape();
            shape.Element(T + "AdditionalProperties")!.Add(RecallExtendedField("0x300B", "Binary"));
            var document = await SendAsync(ownMailbox, new XElement(M + "GetItem", shape,
                new XElement(M + "ItemIds", ItemReference(id))), timeout.Token).ConfigureAwait(false);
            var item = RequiredReturnedItem(document);
            if (searchKey is not null && ReadEventSearchKey(item) != searchKey)
                throw new InvalidOperationException("The notification message identity no longer matches its reference.");
            return ParseMessage(item);
        }

        try
        {
            try { return await ReadExactAsync(originalId).ConfigureAwait(false); }
            catch (EwsRequestFailedException exception) when (exception.ResponseCode == "ErrorItemNotFound" && key is not null) { }

            // Search keys survive moves and copies; inspect every bounded folder before accepting one match.
            var folders = (await ListFoldersAsync(ownMailbox, timeout.Token).ConfigureAwait(false))
                .Select(folder => folder.Id).Prepend("msgfolderroot").Distinct(StringComparer.Ordinal).ToArray();
            if (folders.Length > 128)
                throw new InvalidOperationException("The notification message lookup exceeded its 128-folder limit.");
            var matches = new HashSet<string>(StringComparer.Ordinal);
            foreach (var batch in folders.Chunk(16))
            {
                var operation = new XElement(M + "FindItem", new XAttribute("Traversal", "Shallow"),
                    new XElement(M + "ItemShape", new XElement(T + "BaseShape", "IdOnly"),
                        new XElement(T + "AdditionalProperties", RecallExtendedField("0x300B", "Binary"))),
                    new XElement(M + "IndexedPageItemView", new XAttribute("MaxEntriesReturned", 2),
                        new XAttribute("Offset", 0), new XAttribute("BasePoint", "Beginning")),
                    new XElement(M + "Restriction", RecallBinaryEquals("0x300B", key!)),
                    new XElement(M + "ParentFolderIds", batch.Select(FolderReference)));
                var document = await SendAsync(ownMailbox, operation, timeout.Token).ConfigureAwait(false);
                var responses = document.Root!.Element(Soap + "Body")!.Element(M + "FindItemResponse")!
                    .Element(M + "ResponseMessages")!.Elements(M + "FindItemResponseMessage").ToArray();
                if (responses.Length != batch.Length || responses.Any(response => response.Elements(M + "RootFolder").Count() != 1))
                    throw new InvalidOperationException("Exchange returned an incomplete notification message lookup.");
                foreach (var response in responses)
                {
                    var root = response.Element(M + "RootFolder")!;
                    var items = root.Element(T + "Items")?.Elements().ToArray();
                    if (!IncludesLastItem(root) || items is null || items.Length > 2)
                        throw new InvalidOperationException("Exchange returned an incomplete notification message lookup.");
                    foreach (var item in items)
                    {
                        if (item.Name != T + "Message" || ReadEventSearchKey(item) != searchKey)
                            throw new InvalidOperationException("Exchange returned a mismatched notification message identity.");
                        matches.Add(ValidateItemId((string?)item.Element(T + "ItemId")?.Attribute("Id") ?? "", "item"));
                        if (matches.Count > 1)
                            throw new InvalidOperationException("The notification message lookup is ambiguous; no message was selected.");
                    }
                }
            }
            if (matches.Count != 1)
                throw new InvalidOperationException("The notification message is no longer available in this mailbox.");
            return await ReadExactAsync(matches.Single()).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new TimeoutException("The notification message lookup timed out.");
        }
    }

    private static string? ReadEventSearchKey(XElement item)
    {
        var key = RecallTryReadExtendedBinary(item, "0x300B");
        if (key is null) return null;
        if (key.Length is < 1 or > 256)
            throw new InvalidOperationException("Exchange returned an invalid notification message identity.");
        return Convert.ToBase64String(key);
    }

    private static byte[] ValidateEventSearchKey(string value)
    {
        if (value.Length is < 4 or > 344)
            throw new InvalidOperationException("The notification message identity is invalid.");
        try
        {
            var key = Convert.FromBase64String(value);
            if (key.Length is < 1 or > 256 || Convert.ToBase64String(key) != value)
                throw new FormatException();
            return key;
        }
        catch (FormatException)
        {
            throw new InvalidOperationException("The notification message identity is invalid.");
        }
    }

    public async Task<string> SubscribeInboxStreamingAsync(string mailbox, CancellationToken cancellationToken)
    {
        var ownMailbox = ValidateOwnStreamingMailbox(mailbox);
        var operation = new XElement(M + "Subscribe", new XElement(M + "StreamingSubscriptionRequest",
            new XElement(T + "FolderIds", FolderReference("inbox")),
            new XElement(T + "EventTypes", new XElement(T + "EventType", "NewMailEvent"),
                new XElement(T + "EventType", "CreatedEvent"), new XElement(T + "EventType", "MovedEvent"))));
        var document = await SendAsync(ownMailbox, operation, cancellationToken).ConfigureAwait(false);
        return ValidateItemId(RequiredElement(document, M + "SubscriptionId").Value, "subscription");
    }

    public async Task UnsubscribeStreamingAsync(string mailbox, string subscriptionId, CancellationToken cancellationToken)
    {
        await SendAsync(ValidateOwnStreamingMailbox(mailbox), new XElement(M + "Unsubscribe",
            new XElement(M + "SubscriptionId", ValidateItemId(subscriptionId, "subscription"))), cancellationToken).ConfigureAwait(false);
    }

    public async Task ReadInboxStreamingAsync(string mailbox, string subscriptionId, HttpClient streamingClient,
        Func<CancellationToken, Task> reconcile, CancellationToken cancellationToken)
    {
        var actor = ValidateOwnStreamingMailbox(mailbox);
        var id = ValidateItemId(subscriptionId, "subscription");
        var operation = new XElement(M + "GetStreamingEvents",
            new XElement(M + "SubscriptionIds", new XElement(T + "SubscriptionId", id)),
            new XElement(M + "ConnectionTimeout", 1));
        using var request = new HttpRequestMessage(HttpMethod.Post, _endpoint)
        {
            Content = new StringContent(BuildEnvelope(actor, actor, operation).ToString(SaveOptions.DisableFormatting),
                Encoding.UTF8, "text/xml")
        };
        request.Headers.TryAddWithoutValidation("X-AnchorMailbox", actor);
        request.Headers.TryAddWithoutValidation("SOAPAction", $"\"{MessagesNamespace}/GetStreamingEvents\"");
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(_options.TimeoutSeconds));
        using var response = await streamingClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token)
            .ConfigureAwait(false);
        timeout.CancelAfter(TimeSpan.FromSeconds(75));
        if (!response.IsSuccessStatusCode)
            throw new EwsRequestFailedException(null, "GetStreamingEvents", rejected: true);
        await using var stream = await response.Content.ReadAsStreamAsync(timeout.Token).ConfigureAwait(false);
        await ReadStreamingEnvelopesAsync(stream, id, (int)_options.MaxResponseBytes, reconcile, timeout.Token).ConfigureAwait(false);
    }

    private string ValidateOwnStreamingMailbox(string mailbox)
    {
        var (actor, target) = ResolveRequestMailboxes(ValidateMailbox(mailbox));
        if (!actor.Equals(target, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Inbox streaming is limited to the actor's own mailbox.");
        return actor;
    }

    // EWS sends consecutive SOAP documents in one HTTP body; declarations may repeat at document boundaries.
    internal static async Task ReadStreamingEnvelopesAsync(Stream source, string subscriptionId, int maxEnvelopeBytes,
        Func<CancellationToken, Task> reconcile, CancellationToken cancellationToken)
    {
        var buffer = new byte[8192];
        using var frame = new MemoryStream();
        var markup = new StringBuilder();
        var inMarkup = false;
        var depth = 0;
        var rootSeen = false;
        char quote = '\0';
        int count;
        while ((count = await source.ReadAsync(buffer, cancellationToken).ConfigureAwait(false)) != 0)
        {
            for (var index = 0; index < count; index++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var value = buffer[index];
                if (frame.Length >= maxEnvelopeBytes)
                    throw new InvalidOperationException("The Exchange streaming envelope exceeded the configured limit.");
                frame.WriteByte(value);
                if (!inMarkup)
                {
                    if (value != '<') continue;
                    inMarkup = true;
                    markup.Clear();
                }
                markup.Append((char)value);
                if (markup.Length > 16 * 1024)
                    throw new InvalidOperationException("The Exchange streaming markup exceeded the configured limit.");
                var token = markup.ToString(0, Math.Min(markup.Length, 9));
                var lastTwo = markup.Length >= 2 ? markup.ToString(markup.Length - 2, 2) : "";
                var lastThree = markup.Length >= 3 ? markup.ToString(markup.Length - 3, 3) : "";
                if (token.StartsWith("<!--", StringComparison.Ordinal))
                {
                    if (lastThree != "-->") continue;
                }
                else if (token.StartsWith("<![CDATA[", StringComparison.Ordinal))
                {
                    if (lastThree != "]]>") continue;
                }
                else if (token.StartsWith("<?", StringComparison.Ordinal))
                {
                    if (lastTwo != "?>") continue;
                }
                else
                {
                    if (quote != '\0')
                    {
                        if (value == quote) quote = '\0';
                        continue;
                    }
                    if (value is (byte)'\'' or (byte)'"') { quote = (char)value; continue; }
                    if (value != '>') continue;
                    if (token.StartsWith("<!", StringComparison.Ordinal))
                        throw new InvalidOperationException("Exchange streaming DTD markup is forbidden.");
                    if (token.StartsWith("</", StringComparison.Ordinal)) depth--;
                    else
                    {
                        rootSeen = true;
                        if (lastTwo != "/>") depth++;
                    }
                    if (depth is < 0 or > 64)
                        throw new InvalidOperationException("The Exchange streaming XML nesting is invalid.");
                }
                inMarkup = false;
                if (!rootSeen || depth != 0) continue;
                var xml = new UTF8Encoding(false, true).GetString(frame.GetBuffer(), 0, (int)frame.Length)
                    .TrimStart('\uFEFF', ' ', '\t', '\r', '\n');
                using var reader = XmlReader.Create(new StringReader(xml), new XmlReaderSettings
                {
                    DtdProcessing = DtdProcessing.Prohibit,
                    XmlResolver = null,
                    MaxCharactersInDocument = maxEnvelopeBytes,
                    CloseInput = false
                });
                var document = XDocument.Load(reader);
                ValidateResponse(document, "GetStreamingEvents");
                var messages = document.Root!.Element(Soap + "Body")!.Element(M + "GetStreamingEventsResponse")!
                    .Element(M + "ResponseMessages")!.Elements(M + "GetStreamingEventsResponseMessage").ToArray();
                var changed = false;
                foreach (var notification in messages.SelectMany(message => message.Element(M + "Notifications")?.Elements(M + "Notification") ?? []))
                {
                    if (notification.Element(T + "SubscriptionId")?.Value != subscriptionId)
                        throw new InvalidOperationException("Exchange streaming returned an unexpected subscription.");
                    changed |= notification.Elements().Any(element => element.Name == T + "NewMailEvent"
                        || element.Name == T + "CreatedEvent" || element.Name == T + "MovedEvent");
                }
                if (changed) await reconcile(cancellationToken).ConfigureAwait(false);
                var status = messages.Select(message => message.Element(M + "ConnectionStatus")?.Value).ToArray();
                if (status.Any(value => value is not null and not ("OK" or "Closed")))
                    throw new InvalidOperationException("Exchange streaming returned an invalid connection status.");
                if (status.Contains("Closed")) return;
                frame.SetLength(0);
                rootSeen = false;
            }
        }
        if (rootSeen || inMarkup || Encoding.UTF8.GetString(frame.ToArray()).Trim('\uFEFF', ' ', '\t', '\r', '\n').Length != 0)
            throw new InvalidOperationException("The Exchange streaming response ended before a complete envelope.");
        throw new IOException("The Exchange streaming connection ended without a closed status.");
    }
}
