using System.Buffers.Binary;
using System.Globalization;
using System.Net;
using System.Text;
using System.Xml;
using System.Xml.Linq;

namespace Company.ExchangeMcp.Exchange;

public sealed partial class EwsClient
{
    private const int RecallMaxReportTagBytes = 8 * 1024;
    private const int RecallSearchKeyBytes = 16;
    private const int RecallStoreHeaderBytes = 60;
    private const int RecallMaxEntryIdBytes = 64 * 1024;
    private const uint RecallStoreExtensionMagic = 4_096_935_657;
    private const uint RecallTagVersion = 0x0002_0001;
    private const string RecallReportSuccessClass = "IPM.Recall.Report.Success";
    private const string RecallReportFailureClass = "IPM.Recall.Report.Failure";
    private const string RecallNoticeBody = "This is a recall message.";
    private const string AutodiscoverRequestNamespace =
        "http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006";
    private const string AutodiscoverResponseNamespace =
        "http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a";

    private static readonly XNamespace RecallAutodiscoverRequest = AutodiscoverRequestNamespace;
    private static readonly XNamespace RecallAutodiscoverResponse = AutodiscoverResponseNamespace;

    public async Task<EwsRecallRequest> PrepareRecallAsync(
        string mailbox,
        string itemId,
        CancellationToken cancellationToken)
    {
        var normalizedMailbox = ValidateMailbox(mailbox);
        var normalizedItemId = ValidateItemId(itemId, "item");
        var phase = "source_folder";
        try
        {
            var sentItems = await GetFolderAsync(normalizedMailbox, "sentitems", cancellationToken).ConfigureAwait(false);
            phase = "source_message";
            var source = await GetRecallSourceAsync(normalizedMailbox, normalizedItemId, cancellationToken).ConfigureAwait(false);
            phase = "source_validation";
            RecallValidateSource(normalizedMailbox, sentItems.Id, source);
            phase = "mailbox_identity";
            var identity = await GetRecallIdentityAsync(normalizedMailbox, cancellationToken).ConfigureAwait(false);
            phase = "report_tag";
            var storeEntryId = RecallBuildStoreEntryId(source.StoreEntryId, identity.SmtpAddress, identity.LegacyDn);
            var reportTag = RecallBuildReportTag(storeEntryId, source, source.MessageCodePage);

            return new EwsRecallRequest(
                source.Id,
                source.ChangeKey,
                source.Subject,
                source.To,
                source.Cc,
                source.Bcc,
                Convert.ToBase64String(source.SearchKey),
                Convert.ToBase64String(reportTag));
        }
        catch (Exception exception) when (exception is not (OperationCanceledException or EwsPermissionDeniedException
            or ModelContextProtocol.McpException or OutOfMemoryException or StackOverflowException or AccessViolationException))
        {
            // Preparation has no writes; do not expose source data or exception details in the public failure.
            throw new RecallPreparationException(phase);
        }
    }

    public async Task SubmitRecallAsync(
        string mailbox,
        EwsRecallRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        var normalizedMailbox = ValidateMailbox(mailbox);
        var validated = RecallValidateRequest(request);

        var message = new XElement(
            T + "Message",
            new XElement(T + "ItemClass", "IPM.Outlook.Recall"),
            new XElement(T + "Subject", "Recall: " + validated.Subject),
            new XElement(T + "Body", new XAttribute("BodyType", "Text"), RecallNoticeBody),
            RecallExtendedProperty("0x0031", "Binary", Convert.ToBase64String(validated.ReportTag)),
            RecallExtendedProperty("0x6800", "Binary", Convert.ToBase64String(validated.SearchKey)),
            RecallExtendedProperty("0x6801", "Integer", "17"),
            RecallExtendedProperty("0x6802", "String", "IPM.Note"),
            RecallExtendedProperty("0x6803", "Boolean", "true"),
            RecallExtendedProperty("0x6804", "Integer", "0"),
            RecallExtendedProperty("0x003D", "String", "Recall: "),
            RecallExtendedProperty("0x0E1D", "String", validated.Subject),
            RecallExtendedProperty("0x0070", "String", validated.Subject),
            RecallNamedExtendedProperty("34074", "Integer", "1"),
            RecallExtendedProperty("0x0026", "Integer", "1"),
            RecallExtendedProperty(
                "0x0015",
                "SystemTime",
                DateTimeOffset.UtcNow.AddHours(48).ToString("yyyy-MM-ddTHH:mm:ss.fffZ", CultureInfo.InvariantCulture)),
            RecallRecipientsElement("ToRecipients", validated.To),
            RecallRecipientsElement("CcRecipients", validated.Cc),
            RecallRecipientsElement("BccRecipients", validated.Bcc),
            new XElement(T + "From", MailboxElement(normalizedMailbox)));

        var operation = new XElement(
            M + "CreateItem",
            new XAttribute("MessageDisposition", "SendAndSaveCopy"),
            new XElement(M + "SavedItemFolderId", FolderReference("sentitems")),
            new XElement(M + "Items", message));

        await SendAsync(normalizedMailbox, operation, cancellationToken).ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<EwsRecallReport>> GetRecallReportsAsync(
        string mailbox,
        string reportTagBase64,
        CancellationToken cancellationToken)
    {
        var normalizedMailbox = ValidateMailbox(mailbox);
        var reportTag = RecallDecodeReportTag(reportTagBase64);
        RecallValidateReportTagShape(reportTag);
        var reports = new List<EwsRecallReport>();
        var seenIds = new HashSet<string>(StringComparer.Ordinal);

        foreach (var folder in new[] { "inbox", "deleteditems", "recoverableitemsdeletions" })
        {
            var offset = 0;
            for (var page = 0; page < 6; page++)
            {
                var operation = new XElement(
                    M + "FindItem",
                    new XAttribute("Traversal", "Shallow"),
                    RecallReportShape(),
                    new XElement(
                        M + "IndexedPageItemView",
                        new XAttribute("MaxEntriesReturned", 20),
                        new XAttribute("Offset", offset),
                        new XAttribute("BasePoint", "Beginning")),
                    new XElement(M + "Restriction", RecallBinaryEquals("0x0031", reportTag)),
                    new XElement(M + "ParentFolderIds", RecallStatusFolderReference(folder)));

                var document = await SendAsync(normalizedMailbox, operation, cancellationToken).ConfigureAwait(false);
                var rootFolder = document.Descendants(M + "RootFolder").FirstOrDefault();
                var items = rootFolder?.Element(T + "Items")?.Elements()
                    .Where(item => item.Name.Namespace == T)
                    .ToArray() ?? Array.Empty<XElement>();

                foreach (var item in items)
                {
                    var id = item.Element(T + "ItemId")?.Attribute("Id")?.Value;
                    var itemClass = item.Element(T + "ItemClass")?.Value;
                    if (string.IsNullOrWhiteSpace(id)
                        || (!string.Equals(itemClass, RecallReportSuccessClass, StringComparison.Ordinal)
                            && !string.Equals(itemClass, RecallReportFailureClass, StringComparison.Ordinal)))
                    {
                        continue;
                    }

                    var returnedTag = RecallTryReadExtendedBinary(item, "0x0031");
                    if (returnedTag is null || !returnedTag.AsSpan().SequenceEqual(reportTag) || !seenIds.Add(id))
                    {
                        continue;
                    }

                    reports.Add(new EwsRecallReport(
                        string.Equals(itemClass, RecallReportSuccessClass, StringComparison.Ordinal) ? "success" : "failure",
                        item.Element(T + "Subject")?.Value ?? string.Empty,
                        ParseReceivedUtc(item.Element(T + "DateTimeReceived")?.Value)));
                }

                if (rootFolder is null)
                {
                    throw new InvalidOperationException("Exchange returned an incomplete recall report result.");
                }

                var includesLastItem = RecallReadIncludesLastItemInRange(rootFolder);
                if (includesLastItem)
                {
                    break;
                }

                if (page == 5)
                {
                    throw new InvalidOperationException("The Exchange recall report result exceeded the bounded six-page limit.");
                }

                var nextOffset = ReadOffset(rootFolder, offset + items.Length);
                if (nextOffset <= offset)
                {
                    throw new InvalidOperationException("The Exchange recall report result could not be paged safely.");
                }

                offset = nextOffset;
            }
        }

        return reports;
    }

    public async Task<EwsRecallTracking> GetRecallTrackingAsync(
        string mailbox,
        string itemId,
        string changeKey,
        CancellationToken cancellationToken)
    {
        var normalizedMailbox = ValidateMailbox(mailbox);
        var normalizedItemId = ValidateItemId(itemId, "item");
        var normalizedChangeKey = ValidateChangeKey(changeKey);
        var operation = new XElement(
            M + "GetItem",
            RecallTrackingShape(),
            new XElement(M + "ItemIds", ItemReference(normalizedItemId, normalizedChangeKey)));
        var document = await SendAsync(normalizedMailbox, operation, cancellationToken).ConfigureAwait(false);
        var item = RequiredReturnedItem(document);
        var itemReference = item.Element(T + "ItemId");
        var returnedId = itemReference?.Attribute("Id")?.Value;
        var returnedChangeKey = itemReference?.Attribute("ChangeKey")?.Value;
        if (!string.Equals(returnedId, normalizedItemId, StringComparison.Ordinal)
            || !string.Equals(returnedChangeKey, normalizedChangeKey, StringComparison.Ordinal))
        {
            throw new InvalidOperationException("The Exchange recall tracking item is invalid.");
        }

        if (!string.Equals(item.Element(T + "ItemClass")?.Value, "IPM.Outlook.Recall", StringComparison.Ordinal)
            || RecallReadBoolRequired(item.Element(T + "IsDraft")))
        {
            throw new InvalidOperationException("The Exchange recall tracking item is invalid.");
        }

        var from = RecallParseSmtpMailbox(item.Element(T + "From"));
        var sender = RecallParseSmtpMailbox(item.Element(T + "Sender"));
        if (!string.Equals(from, normalizedMailbox, StringComparison.OrdinalIgnoreCase)
            || !string.Equals(sender, normalizedMailbox, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("The Exchange recall tracking item is not owned by this mailbox.");
        }

        var to = RecallParseRecipients(item.Element(T + "ToRecipients"));
        var cc = RecallParseRecipients(item.Element(T + "CcRecipients"));
        var bcc = RecallParseRecipients(item.Element(T + "BccRecipients"));
        RecallValidateRecipients(to, cc, bcc);

        var reportTag = Convert.ToBase64String(RecallReadExtendedBinary(item, "0x0031"));
        var searchKeyBytes = RecallReadExtendedBinary(item, "0x6800");
        RecallValidateSearchKey(searchKeyBytes);
        var searchKey = Convert.ToBase64String(searchKeyBytes);
        ValidateRecallTag(reportTag, searchKey);

        var subject = RecallReadExtendedString(item, "0x0E1D");
        RecallValidateTrackingSubject(subject);
        return new EwsRecallTracking(reportTag, searchKey, subject, to.Count + cc.Count + bcc.Count);
    }

    internal static void ValidateRecallTag(string reportTag, string expectedSearchKey)
    {
        try
        {
            var searchKey = RecallDecodeSearchKey(expectedSearchKey);
            var decodedTag = RecallDecodeReportTag(reportTag);
            RecallValidateReportTagBinding(decodedTag, searchKey);
        }
        catch (InvalidOperationException exception)
        {
            throw new ArgumentException("The recall tag is invalid.", nameof(reportTag), exception);
        }
    }

    private async Task<EwsRecallSource> GetRecallSourceAsync(
        string mailbox,
        string itemId,
        CancellationToken cancellationToken)
    {
        var operation = new XElement(
            M + "GetItem",
            RecallSourceShape(),
            new XElement(M + "ItemIds", ItemReference(itemId)));
        var document = await SendAsync(mailbox, operation, cancellationToken).ConfigureAwait(false);
        var item = RequiredReturnedItem(document);
        var itemReference = item.Element(T + "ItemId");
        var id = itemReference?.Attribute("Id")?.Value;
        var changeKey = itemReference?.Attribute("ChangeKey")?.Value;
        if (string.IsNullOrWhiteSpace(id) || !string.Equals(id, itemId, StringComparison.Ordinal) ||
            string.IsNullOrWhiteSpace(changeKey))
        {
            throw new InvalidOperationException("The Exchange source message is invalid.");
        }

        var parentFolderId = item.Element(T + "ParentFolderId")?.Attribute("Id")?.Value;
        var from = RecallParseSmtpMailbox(item.Element(T + "From"));
        var sender = RecallParseSmtpMailbox(item.Element(T + "Sender"));
        var to = RecallParseRecipients(item.Element(T + "ToRecipients"));
        var cc = RecallParseRecipients(item.Element(T + "CcRecipients"));
        var bcc = RecallParseRecipients(item.Element(T + "BccRecipients"));
        var entryId = RecallReadExtendedBinary(item, "0x0FFF");
        var sourceParentId = RecallReadExtendedBinary(item, "0x0E09");
        var storeEntryId = RecallReadExtendedBinary(item, "0x0FFB");
        var searchKey = RecallReadExtendedBinary(item, "0x300B");
        var codePage = RecallReadExtendedInteger(item, "0x3FFD");

        return new EwsRecallSource(
            id,
            changeKey,
            item.Element(T + "Subject")?.Value ?? string.Empty,
            from,
            sender,
            parentFolderId ?? string.Empty,
            to,
            cc,
            bcc,
            entryId,
            sourceParentId,
            storeEntryId,
            searchKey,
            codePage,
            RecallReadBoolRequired(item.Element(T + "IsDraft")),
            item.Element(T + "ItemClass")?.Value ?? string.Empty);
    }

    private async Task<RecallIdentity> GetRecallIdentityAsync(
        string mailbox,
        CancellationToken cancellationToken)
    {
        var request = new XDocument(
            new XElement(
                RecallAutodiscoverRequest + "Autodiscover",
                new XElement(
                    RecallAutodiscoverRequest + "Request",
                    new XElement(RecallAutodiscoverRequest + "EMailAddress", mailbox),
                    new XElement(
                        RecallAutodiscoverRequest + "AcceptableResponseSchema",
                        AutodiscoverResponseNamespace))));
        var endpoint = new Uri(_endpoint, "/Autodiscover/Autodiscover.xml");

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(_options.TimeoutSeconds));
        using var httpRequest = new HttpRequestMessage(HttpMethod.Post, endpoint)
        {
            Content = new StringContent(request.ToString(SaveOptions.DisableFormatting), Encoding.UTF8, "text/xml")
        };
        if (!httpRequest.Headers.TryAddWithoutValidation("X-AnchorMailbox", mailbox))
        {
            throw new InvalidOperationException("The Exchange Autodiscover request could not be prepared.");
        }

        HttpResponseMessage response;
        try
        {
            response = await _httpClient.SendAsync(httpRequest, HttpCompletionOption.ResponseHeadersRead, timeout.Token)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new TimeoutException(TimeoutError);
        }
        catch (HttpRequestException)
        {
            throw new InvalidOperationException("The Exchange Autodiscover request failed.");
        }

        using (response)
        {
            if (response.RequestMessage?.RequestUri is { } actual
                && (!string.Equals(actual.Scheme, endpoint.Scheme, StringComparison.OrdinalIgnoreCase)
                    || !string.Equals(actual.Host, endpoint.Host, StringComparison.OrdinalIgnoreCase)
                    || actual.Port != endpoint.Port))
            {
                throw new InvalidOperationException("Exchange Autodiscover returned an invalid redirect.");
            }

            byte[] payload;
            try
            {
                payload = await ReadBoundedAsync(response, timeout.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                throw new TimeoutException(TimeoutError);
            }
            catch (HttpRequestException)
            {
                throw new InvalidOperationException("The Exchange Autodiscover response could not be read.");
            }

            if (response.StatusCode != HttpStatusCode.OK)
            {
                throw new InvalidOperationException("Exchange Autodiscover rejected the request.");
            }

            XDocument document;
            try
            {
                using var stream = new MemoryStream(payload, writable: false);
                using var reader = XmlReader.Create(
                    stream,
                    new XmlReaderSettings
                    {
                        DtdProcessing = DtdProcessing.Prohibit,
                        XmlResolver = null,
                        MaxCharactersInDocument = _options.MaxResponseBytes
                    });
                document = XDocument.Load(reader, LoadOptions.None);
            }
            catch (XmlException)
            {
                throw new InvalidOperationException("Exchange returned an invalid Autodiscover response.");
            }

            try
            {
                var responseElements = document.Descendants(RecallAutodiscoverResponse + "Response").Take(2).ToArray();
                var responseElement = responseElements.Length == 1 ? responseElements[0] : null;
                var user = responseElement?.Element(RecallAutodiscoverResponse + "User");
                var smtp = user?.Element(RecallAutodiscoverResponse + "AutoDiscoverSMTPAddress")?.Value;
                var legacyDn = user?.Element(RecallAutodiscoverResponse + "LegacyDN")?.Value;
                var normalizedSmtp = smtp is null ? string.Empty : NormalizeAddress(smtp);
                if (string.IsNullOrWhiteSpace(normalizedSmtp)
                    || !string.Equals(normalizedSmtp, mailbox, StringComparison.OrdinalIgnoreCase)
                    || !RecallIsAscii(normalizedSmtp)
                    || string.IsNullOrWhiteSpace(legacyDn)
                    || !RecallIsAscii(legacyDn)
                    || (!legacyDn.StartsWith("/o=", StringComparison.OrdinalIgnoreCase)
                        && !legacyDn.StartsWith("o=", StringComparison.OrdinalIgnoreCase))
                    || legacyDn.Length > MaxItemIdLength
                    || legacyDn.Any(char.IsControl))
                {
                    throw new InvalidOperationException("Exchange Autodiscover returned an invalid mailbox identity.");
                }

                return new RecallIdentity(normalizedSmtp, legacyDn);
            }
            catch (ArgumentException)
            {
                throw new InvalidOperationException("Exchange Autodiscover returned an invalid mailbox identity.");
            }
        }
    }

    private static void RecallValidateSource(string mailbox, string sentFolderId, EwsRecallSource source)
    {
        _ = ValidateItemId(source.Id, "item");
        _ = ValidateChangeKey(source.ChangeKey);
        if (!string.Equals(source.ItemClass, "IPM.Note", StringComparison.Ordinal)
            || source.IsDraft
            || !string.Equals(source.ParentFolderId, sentFolderId, StringComparison.Ordinal)
            || !string.Equals(source.From, mailbox, StringComparison.OrdinalIgnoreCase)
            || !string.Equals(source.Sender, mailbox, StringComparison.OrdinalIgnoreCase)
            || !string.Equals(source.From, source.Sender, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("The selected Exchange message is not a recallable sent message.");
        }

        RecallValidateSubject(source.Subject);
        if (source.Subject.Length > 990)
        {
            throw new InvalidOperationException("The selected Exchange message subject is too long for recall.");
        }
        RecallValidateRecipients(source.To, source.Cc, source.Bcc);
        RecallValidateBinary(source.EntryId, "entry identifier");
        RecallValidateBinary(source.ParentEntryId, "parent entry identifier");
        RecallValidateStore(source.StoreEntryId);
        RecallValidateSearchKey(source.SearchKey);
        if (source.MessageCodePage is < 0 or > ushort.MaxValue)
        {
            throw new InvalidOperationException("The Exchange source message code page is invalid.");
        }
    }

    private static RecallValidatedRequest RecallValidateRequest(EwsRecallRequest request)
    {
        var id = ValidateItemId(request.Id, "request item");
        var changeKey = ValidateChangeKey(request.ChangeKey);
        RecallValidateSubject(request.Subject);
        if (request.Subject.Length > 990)
        {
            throw new ArgumentException("The recall subject is too long.", nameof(request));
        }

        var to = RecallNormalizeRecipients(request.To, nameof(request.To));
        var cc = RecallNormalizeRecipients(request.Cc, nameof(request.Cc));
        var bcc = RecallNormalizeRecipients(request.Bcc, nameof(request.Bcc));
        RecallValidateRecipients(to, cc, bcc);
        ValidateRecallTag(request.ReportTag, request.SearchKey);
        var searchKey = RecallDecodeSearchKey(request.SearchKey);
        var reportTag = RecallDecodeReportTag(request.ReportTag);
        return new RecallValidatedRequest(id, changeKey, request.Subject, to, cc, bcc, searchKey, reportTag);
    }

    private static void RecallValidateSubject(string subject)
    {
        if (subject is null || subject.Length > 998 || subject.IndexOfAny(['\r', '\n', '\0']) >= 0)
        {
            throw new ArgumentException("The recall subject is invalid.", nameof(subject));
        }
    }

    private static void RecallValidateRecipients(
        IReadOnlyList<string> to,
        IReadOnlyList<string> cc,
        IReadOnlyList<string> bcc)
    {
        var count = to.Count + cc.Count + bcc.Count;
        if (count is < 1 or > 100)
        {
            throw new InvalidOperationException("The recall recipient count is invalid.");
        }
    }

    private static IReadOnlyList<string> RecallNormalizeRecipients(
        IReadOnlyList<string> recipients,
        string parameterName)
    {
        ArgumentNullException.ThrowIfNull(recipients, parameterName);
        if (recipients.Count > 100)
        {
            throw new ArgumentException("The recall recipient list is too long.", parameterName);
        }

        return recipients.Select(address => NormalizeAddress(address)).ToArray();
    }

    private static string RecallParseSmtpMailbox(XElement? mailbox)
    {
        var sourceMailbox = mailbox?.Element(T + "Mailbox");
        var routing = sourceMailbox?.Element(T + "RoutingType")?.Value;
        var address = sourceMailbox?.Element(T + "EmailAddress")?.Value;
        if (string.IsNullOrWhiteSpace(address) || (!string.IsNullOrWhiteSpace(routing) && !string.Equals(routing, "SMTP", StringComparison.OrdinalIgnoreCase)))
        {
            throw new InvalidOperationException("The Exchange message contains a non-SMTP sender.");
        }

        try
        {
            return NormalizeAddress(address);
        }
        catch (ArgumentException)
        {
            throw new InvalidOperationException("The Exchange message contains an invalid sender.");
        }
    }

    private static IReadOnlyList<string> RecallParseRecipients(XElement? recipients)
    {
        if (recipients is null)
        {
            return Array.Empty<string>();
        }

        var result = new List<string>();
        foreach (var mailbox in recipients.Elements(T + "Mailbox"))
        {
            var routing = mailbox.Element(T + "RoutingType")?.Value;
            var address = mailbox.Element(T + "EmailAddress")?.Value;
            if (string.IsNullOrWhiteSpace(address)
                || !string.Equals(routing, "SMTP", StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException("The Exchange message contains a non-SMTP recipient.");
            }

            try
            {
                result.Add(NormalizeAddress(address));
            }
            catch (ArgumentException)
            {
                throw new InvalidOperationException("The Exchange message contains an invalid recipient.");
            }
        }

        return result;
    }

    private static XElement RecallSourceShape() =>
        new XElement(
            M + "ItemShape",
            new XElement(T + "BaseShape", "IdOnly"),
            new XElement(
                T + "AdditionalProperties",
                Field("item:ItemClass"),
                Field("item:IsDraft"),
                Field("item:Subject"),
                Field("item:ParentFolderId"),
                Field("message:From"),
                Field("message:Sender"),
                Field("message:ToRecipients"),
                Field("message:CcRecipients"),
                Field("message:BccRecipients"),
                RecallExtendedField("0x0FFF", "Binary"),
                RecallExtendedField("0x0E09", "Binary"),
                RecallExtendedField("0x0FFB", "Binary"),
                RecallExtendedField("0x300B", "Binary"),
                RecallExtendedField("0x3FFD", "Integer")));

    private static XElement RecallTrackingShape() =>
        new XElement(
            M + "ItemShape",
            new XElement(T + "BaseShape", "IdOnly"),
            new XElement(
                T + "AdditionalProperties",
                Field("item:ItemClass"),
                Field("item:IsDraft"),
                Field("message:From"),
                Field("message:Sender"),
                Field("message:ToRecipients"),
                Field("message:CcRecipients"),
                Field("message:BccRecipients"),
                RecallExtendedField("0x0031", "Binary"),
                RecallExtendedField("0x6800", "Binary"),
                RecallExtendedField("0x0E1D", "String")));

    private static XElement RecallReportShape() =>
        new XElement(
            M + "ItemShape",
            new XElement(T + "BaseShape", "IdOnly"),
            new XElement(
                T + "AdditionalProperties",
                Field("item:ItemClass"),
                Field("item:Subject"),
                Field("item:DateTimeReceived"),
                RecallExtendedField("0x0031", "Binary")));

    private static XElement RecallExtendedField(string propertyTag, string propertyType) =>
        new XElement(
            T + "ExtendedFieldURI",
            new XAttribute("PropertyTag", propertyTag),
            new XAttribute("PropertyType", propertyType));

    private static XElement RecallNamedExtendedProperty(string propertyId, string propertyType, string value) =>
        new XElement(
            T + "ExtendedProperty",
            new XElement(
                T + "ExtendedFieldURI",
                new XAttribute("DistinguishedPropertySetId", "Common"),
                new XAttribute("PropertyId", propertyId),
                new XAttribute("PropertyType", propertyType)),
            new XElement(T + "Value", value));

    private static XElement RecallExtendedProperty(string propertyTag, string propertyType, string value) =>
        new XElement(
            T + "ExtendedProperty",
            RecallExtendedField(propertyTag, propertyType),
            new XElement(T + "Value", value));

    private static XElement RecallRecipientsElement(string elementName, IReadOnlyList<string> recipients) =>
        new XElement(
            T + elementName,
            recipients.Select(address => new XElement(
                T + "Mailbox",
                new XElement(T + "EmailAddress", address),
                new XElement(T + "RoutingType", "SMTP"))));

    private static XElement RecallBinaryEquals(string propertyTag, byte[] value) =>
        new XElement(
            T + "IsEqualTo",
            RecallExtendedField(propertyTag, "Binary"),
            new XElement(
                T + "FieldURIOrConstant",
                new XElement(T + "Constant", new XAttribute("Value", Convert.ToBase64String(value)))));

    private static XElement RecallStatusFolderReference(string folder) =>
        string.Equals(folder, "recoverableitemsdeletions", StringComparison.OrdinalIgnoreCase)
            ? new XElement(T + "DistinguishedFolderId", new XAttribute("Id", "recoverableitemsdeletions"))
            : FolderReference(folder);

    private static byte[] RecallReadExtendedBinary(XElement item, string propertyTag) =>
        RecallTryReadExtendedBinary(item, propertyTag)
        ?? throw new InvalidOperationException("The Exchange message is missing a required binary property.");

    private static byte[]? RecallTryReadExtendedBinary(XElement item, string propertyTag)
    {
        foreach (var extended in item.Elements(T + "ExtendedProperty"))
        {
            var uri = extended.Element(T + "ExtendedFieldURI");
            if (!RecallPropertyTagEquals(uri, propertyTag))
            {
                continue;
            }

            var text = extended.Element(T + "Value")?.Value;
            if (string.IsNullOrWhiteSpace(text))
            {
                throw new InvalidOperationException("The Exchange binary property is invalid.");
            }

            try
            {
                var value = Convert.FromBase64String(text);
                if (value.Length > RecallMaxEntryIdBytes)
                {
                    throw new InvalidOperationException("The Exchange binary property is too large.");
                }

                return value;
            }
            catch (FormatException)
            {
                throw new InvalidOperationException("The Exchange binary property is invalid.");
            }
        }

        return null;
    }

    private static string RecallReadExtendedString(XElement item, string propertyTag)
    {
        foreach (var extended in item.Elements(T + "ExtendedProperty"))
        {
            if (!RecallPropertyTagEquals(extended.Element(T + "ExtendedFieldURI"), propertyTag))
            {
                continue;
            }

            var value = extended.Element(T + "Value")?.Value;
            if (value is null)
            {
                throw new InvalidOperationException("The Exchange string property is invalid.");
            }

            return value;
        }

        throw new InvalidOperationException("The Exchange message is missing a required string property.");
    }

    private static void RecallValidateTrackingSubject(string subject)
    {
        RecallValidateSubject(subject);
        if (subject.Length > 990 || subject.Any(char.IsControl))
        {
            throw new InvalidOperationException("The Exchange recall tracking subject is invalid.");
        }
    }

    private static int RecallReadExtendedInteger(XElement item, string propertyTag)
    {
        foreach (var extended in item.Elements(T + "ExtendedProperty"))
        {
            var uri = extended.Element(T + "ExtendedFieldURI");
            if (RecallPropertyTagEquals(uri, propertyTag))
            {
                return int.TryParse(extended.Element(T + "Value")?.Value, NumberStyles.Integer,
                    CultureInfo.InvariantCulture, out var value) && value is >= 0 and <= ushort.MaxValue
                    ? value
                    : throw new InvalidOperationException("The Exchange integer property is invalid.");
            }
        }

        return 0;
    }

    private static bool RecallReadBoolRequired(XElement? element) =>
        element is not null && bool.TryParse(element.Value, out var value)
            ? value
            : throw new InvalidOperationException("The Exchange message draft flag is invalid.");

    private static void RecallValidateBinary(byte[] value, string name)
    {
        if (value.Length is < 1 or > RecallMaxEntryIdBytes)
        {
            throw new InvalidOperationException("The Exchange " + name + " is invalid.");
        }
    }

    private static void RecallValidateStore(byte[] value)
    {
        RecallValidateBinary(value, "store entry identifier");
        if (value.Length < RecallStoreHeaderBytes
            || value.AsSpan(0, RecallStoreHeaderBytes).IndexOfAnyExcept((byte)0) < 0)
        {
            throw new InvalidOperationException("The Exchange store entry identifier is invalid.");
        }
    }

    private static void RecallValidateSearchKey(byte[] value)
    {
        if (value.Length != RecallSearchKeyBytes)
        {
            throw new InvalidOperationException("The Exchange source search key is invalid.");
        }
    }

    private static byte[] RecallDecodeSearchKey(string base64)
    {
        byte[] value;
        try
        {
            value = Convert.FromBase64String(base64 ?? string.Empty);
        }
        catch (FormatException)
        {
            throw new ArgumentException("The recall search key is invalid.", nameof(base64));
        }

        if (value.Length != RecallSearchKeyBytes)
        {
            throw new ArgumentException("The recall search key is invalid.", nameof(base64));
        }

        return value;
    }

    private static byte[] RecallDecodeReportTag(string base64)
    {
        byte[] value;
        try
        {
            value = Convert.FromBase64String(base64 ?? string.Empty);
        }
        catch (FormatException)
        {
            throw new ArgumentException("The recall report tag is invalid.", nameof(base64));
        }

        if (value.Length is < 13 or > RecallMaxReportTagBytes)
        {
            throw new ArgumentException("The recall report tag is invalid.", nameof(base64));
        }

        return value;
    }

    private static void RecallValidateReportTagBinding(byte[] reportTag, byte[] searchKey)
    {
        var components = RecallReadTagComponents(reportTag);
        RecallValidateReportTagShape(components);
        if (!components[4].AsSpan().SequenceEqual(searchKey))
        {
            throw new ArgumentException("The recall report tag is not bound to the source message.", nameof(reportTag));
        }
    }

    private static void RecallValidateReportTagShape(byte[] reportTag) =>
        RecallValidateReportTagShape(RecallReadTagComponents(reportTag));

    private static void RecallValidateReportTagShape(IReadOnlyList<byte[]> components)
    {
        if (components.Count != 6
            || components[0].Length < RecallStoreHeaderBytes
            || components[1].Length == 0
            || components[2].Length == 0
            || components[3].Length != 0
            || components[4].Length != RecallSearchKeyBytes
            || (components[5].Length > 0 && components[5][^1] != 0))
        {
            throw new ArgumentException("The recall report tag is not bound to the source message.", nameof(components));
        }

        try
        {
            RecallValidateStore(components[0]);
        }
        catch (InvalidOperationException exception)
        {
            throw new ArgumentException("The recall report tag store component is invalid.", nameof(components), exception);
        }
    }

    private static List<byte[]> RecallReadTagComponents(byte[] reportTag)
    {
        var cookie = Encoding.ASCII.GetBytes("PCDFEB09\0");
        if (reportTag.Length < cookie.Length + sizeof(uint)
            || !reportTag.AsSpan(0, cookie.Length).SequenceEqual(cookie)
            || BinaryPrimitives.ReadUInt32LittleEndian(reportTag.AsSpan(cookie.Length, sizeof(uint))) != RecallTagVersion)
        {
            throw new ArgumentException("The recall report tag has an invalid header.", nameof(reportTag));
        }

        var position = cookie.Length + sizeof(uint);
        var result = new List<byte[]>(6);
        for (var index = 0; index < 6; index++)
        {
            if (position > reportTag.Length - sizeof(uint))
            {
                throw new ArgumentException("The recall report tag is truncated.", nameof(reportTag));
            }

            var length = BinaryPrimitives.ReadUInt32LittleEndian(reportTag.AsSpan(position, sizeof(uint)));
            position += sizeof(uint);
            if (length > RecallMaxReportTagBytes || length > reportTag.Length - position)
            {
                throw new ArgumentException("The recall report tag component is invalid.", nameof(reportTag));
            }

            result.Add(reportTag.AsSpan(position, checked((int)length)).ToArray());
            position += checked((int)length);
        }

        if (position != reportTag.Length)
        {
            throw new ArgumentException("The recall report tag has trailing data.", nameof(reportTag));
        }

        return result;
    }

    private static byte[] RecallBuildStoreEntryId(byte[] sourceStore, string canonicalSmtp, string canonicalLegacyDn)
    {
        RecallValidateStore(sourceStore);
        if (!RecallIsAscii(canonicalSmtp) || !RecallIsAscii(canonicalLegacyDn))
        {
            throw new InvalidOperationException("The canonical Exchange identity is not ASCII.");
        }

        var smtpBytes = Encoding.ASCII.GetBytes(canonicalSmtp);
        var legacyDnBytes = Encoding.ASCII.GetBytes(canonicalLegacyDn);
        var smtpUnicode = Encoding.Unicode.GetBytes(canonicalSmtp + "\0");
        using var stream = new MemoryStream();
        stream.Write(sourceStore, 0, RecallStoreHeaderBytes);
        stream.Write(smtpBytes);
        stream.WriteByte(0);
        stream.Write(legacyDnBytes);
        stream.WriteByte(0);

        RecallWriteUInt32(stream, RecallStoreExtensionMagic);
        RecallWriteUInt32(stream, checked((uint)(18 + smtpUnicode.Length)));
        RecallWriteUInt32(stream, 2);
        RecallWriteUInt32(stream, 16);
        stream.Write(smtpUnicode);
        stream.WriteByte(0);
        stream.WriteByte(0);
        return stream.ToArray();
    }

    private static byte[] RecallBuildReportTag(byte[] storeEntryId, EwsRecallSource source, int codePage)
    {
        RecallValidateStore(storeEntryId);
        RecallValidateBinary(source.ParentEntryId, "parent entry identifier");
        RecallValidateBinary(source.EntryId, "entry identifier");
        RecallValidateSearchKey(source.SearchKey);

        byte[] subjectBytes = [];
        // MS-OXOMSG permits omitted ANSIText; never invent a code page or replace unrepresentable text.
        if (codePage is > 0 and <= ushort.MaxValue && codePage is not (1200 or 1201 or 12000 or 12001 or 65000))
        {
            try
            {
                Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
                var encoding = Encoding.GetEncoding(codePage, EncoderFallback.ExceptionFallback, DecoderFallback.ExceptionFallback);
                subjectBytes = encoding.GetBytes(source.Subject + "\0");
            }
            catch (Exception exception) when (exception is ArgumentException or NotSupportedException) { }
        }

        using var stream = new MemoryStream();
        stream.Write(Encoding.ASCII.GetBytes("PCDFEB09\0"));
        RecallWriteUInt32(stream, RecallTagVersion);
        RecallWriteTagComponent(stream, storeEntryId);
        RecallWriteTagComponent(stream, source.ParentEntryId);
        RecallWriteTagComponent(stream, source.EntryId);
        RecallWriteTagComponent(stream, Array.Empty<byte>());
        RecallWriteTagComponent(stream, source.SearchKey);
        RecallWriteTagComponent(stream, subjectBytes);
        var result = stream.ToArray();
        if (result.Length > RecallMaxReportTagBytes)
        {
            throw new InvalidOperationException("The recall report tag is too large.");
        }

        return result;
    }

    private static void RecallWriteTagComponent(Stream stream, byte[] value)
    {
        RecallWriteUInt32(stream, checked((uint)value.Length));
        stream.Write(value);
    }

    private static void RecallWriteUInt32(Stream stream, uint value)
    {
        Span<byte> bytes = stackalloc byte[sizeof(uint)];
        BinaryPrimitives.WriteUInt32LittleEndian(bytes, value);
        stream.Write(bytes);
    }

    private static bool RecallReadIncludesLastItemInRange(XElement rootFolder)
    {
        var value = (string?)rootFolder.Attribute("IncludesLastItemInRange");
        if (value is null || !bool.TryParse(value, out var includesLastItem))
        {
            throw new InvalidOperationException(
                "The Exchange recall report result has an invalid paging completion flag.");
        }

        return includesLastItem;
    }

    private static bool RecallPropertyTagEquals(XElement? uri, string expectedTag)
    {
        var actualTag = (string?)uri?.Attribute("PropertyTag");
        if (string.IsNullOrWhiteSpace(actualTag))
        {
            return false;
        }

        return RecallTryParseHexTag(actualTag, out var actual)
            && RecallTryParseHexTag(expectedTag, out var expected)
            && actual == expected;
    }

    private static bool RecallTryParseHexTag(string value, out uint parsed)
    {
        value = value.Trim();
        if (value.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            value = value[2..];
        }

        return uint.TryParse(value, NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out parsed);
    }

    private static bool RecallIsAscii(string value) => value.All(character => character <= 0x7F);

    private sealed record EwsRecallSource(
        string Id,
        string ChangeKey,
        string Subject,
        string From,
        string Sender,
        string ParentFolderId,
        IReadOnlyList<string> To,
        IReadOnlyList<string> Cc,
        IReadOnlyList<string> Bcc,
        byte[] EntryId,
        byte[] ParentEntryId,
        byte[] StoreEntryId,
        byte[] SearchKey,
        int MessageCodePage,
        bool IsDraft,
        string ItemClass);

    private sealed record RecallIdentity(string SmtpAddress, string LegacyDn);

    private sealed record RecallValidatedRequest(
        string Id,
        string ChangeKey,
        string Subject,
        IReadOnlyList<string> To,
        IReadOnlyList<string> Cc,
        IReadOnlyList<string> Bcc,
        byte[] SearchKey,
        byte[] ReportTag);
}
