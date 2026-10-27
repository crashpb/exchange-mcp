using System.Buffers.Binary;
using System.Net;
using System.Text;
using System.Xml.Schema;
using System.Xml.Linq;
using Company.ExchangeMcp;
using Company.ExchangeMcp.Exchange;
using Company.ExchangeMcp.Security;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using ModelContextProtocol.AspNetCore;

internal sealed partial class Checks
{
    private const string RecallAutodiscoverRequestNamespace =
        "http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006";
    private const string RecallAutodiscoverResponseNamespace =
        "http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a";
    private const string RecallSoapNamespace = "http://schemas.xmlsoap.org/soap/envelope/";
    private const string RecallMessagesNamespace = "http://schemas.microsoft.com/exchange/services/2006/messages";
    private const string RecallTypesNamespace = "http://schemas.microsoft.com/exchange/services/2006/types";
    private const string RecallMailbox = "alice@example.test";

    private async Task RecallChecksAsync()
    {
        await RecallEwsChecksAsync();
        await RecallSourceValidationChecksAsync();
        await RecallReportChecksAsync();
        await RecallToolChecksAsync();
        await ScopedRecallApprovalChecksAsync();
    }

    private async Task RecallEwsChecksAsync()
    {
        var handler = new RecordingRecallHandler();
        var client = NewEwsClient(handler);
        var request = await client.PrepareRecallAsync(RecallMailbox, "sent-message-1", CancellationToken.None);

        Expect(request.Id == "sent-message-1" && request.ChangeKey == handler.SourceChangeKey
            && request.Subject == handler.SourceSubject
            && request.To.SequenceEqual(["to@example.test", "second@example.test"])
            && request.Cc.SequenceEqual(["cc@example.test"])
            && request.Bcc.SequenceEqual(["bcc@example.test"])
            && Convert.FromBase64String(request.SearchKey).AsSpan().SequenceEqual(handler.SearchKey),
            "Recall preparation did not preserve the source identity, subject or recipient order.");

        var folder = handler.Calls.Single(call => call.Operation == "GetFolder");
        var source = handler.Calls.Single(call => call.Operation == "GetItem");
        Expect(folder.Body.Contains("DistinguishedFolderId Id=\"sentitems\"", StringComparison.Ordinal)
            && source.Body.Contains("PropertyTag=\"0x0FFF\"", StringComparison.Ordinal)
            && source.Body.Contains("PropertyTag=\"0x0E09\"", StringComparison.Ordinal)
            && source.Body.Contains("PropertyTag=\"0x0FFB\"", StringComparison.Ordinal)
            && source.Body.Contains("PropertyTag=\"0x300B\"", StringComparison.Ordinal)
            && source.Body.Contains("PropertyTag=\"0x3FFD\"", StringComparison.Ordinal)
            && source.Body.Contains("message:From", StringComparison.Ordinal)
            && source.Body.Contains("message:Sender", StringComparison.Ordinal)
            && source.Body.Contains("message:CcRecipients", StringComparison.Ordinal)
            && source.Body.Contains("message:BccRecipients", StringComparison.Ordinal),
            "Recall source preparation omitted a required sent-message property.");

        var autodiscover = handler.Calls.Single(call => call.Operation == "Autodiscover");
        var autodiscoverDocument = XDocument.Parse(autodiscover.Body);
        Expect(autodiscover.Method == HttpMethod.Post
            && autodiscover.RequestUri.AbsolutePath == "/Autodiscover/Autodiscover.xml"
            && autodiscover.Body.Contains(RecallMailbox, StringComparison.Ordinal)
            && autodiscoverDocument.Root?.Name == XName.Get("Autodiscover", RecallAutodiscoverRequestNamespace)
            && autodiscoverDocument.Descendants(XName.Get("AcceptableResponseSchema", RecallAutodiscoverRequestNamespace))
                .Single().Value == RecallAutodiscoverResponseNamespace,
            "Recall Autodiscover did not use the Exchange 2006 XML endpoint and schema.");

        ValidateRecallTagBytes(request, handler);

        var persianHandler = new RecordingRecallHandler { SourceCodePage = 1256, SourceSubject = "لغو فاکتور" };
        var persianRequest = await NewEwsClient(persianHandler).PrepareRecallAsync(
            RecallMailbox, "sent-message-1", CancellationToken.None);
        Expect(persianRequest.Subject == persianHandler.SourceSubject,
            "Recall preparation did not preserve a CP1256 Persian source subject.");
        ValidateRecallTagBytes(persianRequest, persianHandler);

        var utf8Handler = new RecordingRecallHandler { SourceCodePage = 65001, SourceSubject = "لغو فاکتور" };
        var utf8Request = await NewEwsClient(utf8Handler).PrepareRecallAsync(RecallMailbox, "sent-message-1", CancellationToken.None);
        ValidateRecallTagBytes(utf8Request, utf8Handler);

        foreach (var codePage in new int?[] { 1252, 0, null, 1200, 1201, 12000, 12001, 65000, 65535 })
        {
            var unicodeHandler = new RecordingRecallHandler { SourceCodePage = codePage, SourceSubject = "لغو فاکتور 😀" };
            var unicodeClient = NewEwsClient(unicodeHandler);
            var unicodeRequest = await unicodeClient.PrepareRecallAsync(RecallMailbox, "sent-message-1", CancellationToken.None);
            ValidateRecallTagBytes(unicodeRequest, unicodeHandler, omitAnsi: true);
            await unicodeClient.SubmitRecallAsync(RecallMailbox, unicodeRequest, CancellationToken.None);
            var unicodeCreate = XDocument.Parse(unicodeHandler.Calls.Single(call => call.Operation == "CreateItem").Body);
            var unicodeFields = unicodeCreate.Descendants(XName.Get("ExtendedProperty", RecallTypesNamespace)).ToArray();
            Expect(unicodeCreate.Descendants(XName.Get("Subject", RecallTypesNamespace)).Single().Value == "Recall: " + unicodeHandler.SourceSubject
                && new[] { "0x0E1D", "0x0070" }.All(tag => unicodeFields.Single(property =>
                    property.Element(XName.Get("ExtendedFieldURI", RecallTypesNamespace))?.Attribute("PropertyTag")?.Value == tag)
                    .Element(XName.Get("Value", RecallTypesNamespace))?.Value == unicodeHandler.SourceSubject),
                "An omitted optional ANSI report-tag subject altered the Unicode recall subject fields.");

            unicodeHandler.TrackingReportTag = Convert.FromBase64String(unicodeRequest.ReportTag);
            unicodeHandler.TrackingSubject = unicodeHandler.SourceSubject;
            var recovered = await unicodeClient.GetRecallTrackingAsync(RecallMailbox, "recall-notice-1", "notice-change", CancellationToken.None);
            Expect(recovered.ReportTag == unicodeRequest.ReportTag && recovered.Subject == unicodeHandler.SourceSubject,
                "Status recovery rejected a report tag with omitted optional ANSI text.");
            var mismatchedKey = unicodeHandler.SearchKey.ToArray();
            mismatchedKey[0] ^= 0x40;
            await AssertThrowsAsync<ArgumentException>(() => unicodeClient.SubmitRecallAsync(RecallMailbox,
                unicodeRequest with { SearchKey = Convert.ToBase64String(mismatchedKey) }, CancellationToken.None));
            Expect(unicodeHandler.CreateCount == 1, "An empty optional ANSI component weakened source search-key correlation.");
        }

        await client.SubmitRecallAsync(RecallMailbox, request, CancellationToken.None);
        var create = handler.Calls.Last(call => call.Operation == "CreateItem");
        var createOperation = XDocument.Parse(create.Body).Root!.Element(XName.Get("Body", RecallSoapNamespace))!.Elements().Single();
        var properties = createOperation.Descendants(XName.Get("ExtendedProperty", RecallTypesNamespace))
            .Select(element =>
            {
                var field = element.Element(XName.Get("ExtendedFieldURI", RecallTypesNamespace));
                var tag = (string?)field?.Attribute("PropertyTag")
                    ?? "named:" + (string?)field?.Attribute("PropertyId");
                return (Tag: tag, Type: (string?)field?.Attribute("PropertyType"), Value: element.Element(XName.Get("Value", RecallTypesNamespace))?.Value);
            }).ToArray();
        string Property(string tag) => properties.Single(property => property.Tag == tag).Value!;
        Expect((string?)createOperation.Attribute("MessageDisposition") == "SendAndSaveCopy"
            && createOperation.Descendants(XName.Get("SavedItemFolderId", RecallMessagesNamespace))
                .Descendants(XName.Get("DistinguishedFolderId", RecallTypesNamespace))
                .Single().Attribute("Id")?.Value == "sentitems"
            && createOperation.Descendants(XName.Get("From", RecallTypesNamespace))
                .Elements(XName.Get("Mailbox", RecallTypesNamespace))
                .Elements(XName.Get("EmailAddress", RecallTypesNamespace))
                .Single().Value == RecallMailbox
            && createOperation.Descendants(XName.Get("ItemClass", RecallTypesNamespace)).Single().Value == "IPM.Outlook.Recall"
            && Property("0x6800") == request.SearchKey
            && Property("0x6801") == "17" && Property("0x6802") == "IPM.Note"
            && Property("0x6803") == "true" && Property("0x6804") == "0"
            && Property("0x003D") == "Recall: " && Property("0x0E1D") == handler.SourceSubject
            && Property("0x0070") == handler.SourceSubject
            && properties.Single(property => property.Tag == "named:34074").Type == "Integer"
            && properties.Single(property => property.Tag == "named:34074").Value == "1"
            && Property("0x0026") == "1"
            && createOperation.Descendants(XName.Get("ToRecipients", RecallTypesNamespace)).Single().Elements(XName.Get("Mailbox", RecallTypesNamespace))
                .Select(mailbox => mailbox.Element(XName.Get("EmailAddress", RecallTypesNamespace))?.Value)
                .SequenceEqual(request.To)
            && createOperation.Descendants(XName.Get("CcRecipients", RecallTypesNamespace)).Single().Elements(XName.Get("Mailbox", RecallTypesNamespace))
                .Select(mailbox => mailbox.Element(XName.Get("EmailAddress", RecallTypesNamespace))?.Value)
                .SequenceEqual(request.Cc)
            && createOperation.Descendants(XName.Get("BccRecipients", RecallTypesNamespace)).Single().Elements(XName.Get("Mailbox", RecallTypesNamespace))
                .Select(mailbox => mailbox.Element(XName.Get("EmailAddress", RecallTypesNamespace))?.Value)
                .SequenceEqual(request.Bcc),
            "Recall submission did not preserve native properties, Sent Items save semantics or To/Cc/Bcc.");

        var expiry = DateTimeOffset.Parse(Property("0x0015"));
        Expect(expiry > DateTimeOffset.UtcNow.AddHours(47)
            && expiry < DateTimeOffset.UtcNow.AddHours(49),
            "Recall submission did not set a bounded 48-hour report expiry.");

        var uncertain = new RecordingRecallHandler { ThrowOnCreate = true };
        var uncertainClient = NewEwsClient(uncertain);
        var uncertainRequest = await uncertainClient.PrepareRecallAsync(RecallMailbox, "sent-message-1", CancellationToken.None);
        await AssertThrowsAsync<InvalidOperationException>(() => uncertainClient.SubmitRecallAsync(
            RecallMailbox, uncertainRequest, CancellationToken.None));
        Expect(uncertain.CreateCount == 1, "An uncertain recall submission was retried automatically.");

        ValidateRecallSchema(handler);
    }

    private async Task RecallSourceValidationChecksAsync()
    {
        foreach (var invalid in new[] { "draft", "not-sent", "foreign-from", "foreign-sender" })
        {
            var handler = new RecordingRecallHandler();
            switch (invalid)
            {
                case "draft": handler.SourceIsDraft = true; break;
                case "not-sent": handler.SourceParentFolderId = "inbox-id"; break;
                case "foreign-from": handler.SourceFrom = "other@example.test"; break;
                case "foreign-sender": handler.SourceSender = "other@example.test"; break;
            }

            await AssertThrowsAsync<InvalidOperationException>(() => NewEwsClient(handler)
                .PrepareRecallAsync(RecallMailbox, "sent-message-1", CancellationToken.None));
            Expect(!handler.Calls.Any(call => call.Operation == "Autodiscover"),
                $"Invalid {invalid} recall source reached Autodiscover.");
        }

        foreach (var codePage in new[] { -1, 65536, int.MaxValue })
        {
            var invalidCodePage = new RecordingRecallHandler { SourceCodePage = codePage };
            await AssertThrowsAsync<RecallPreparationException>(() => NewEwsClient(invalidCodePage)
                .PrepareRecallAsync(RecallMailbox, "sent-message-1", CancellationToken.None));
            Expect(invalidCodePage.CreateCount == 0, "An out-of-range source code page reached recall submission.");
        }

        foreach (var expected in new Exception[]
        {
            new EwsPermissionDeniedException("ErrorAccessDenied", "GetItem"),
            new ModelContextProtocol.McpException("safe permission boundary")
        })
        {
            var guarded = new RecordingRecallHandler { SourceFailure = expected };
            Exception? actual = null;
            try { await NewEwsClient(guarded).PrepareRecallAsync(RecallMailbox, "sent-message-1", CancellationToken.None); }
            catch (Exception exception) { actual = exception; }
            Expect(ReferenceEquals(actual, expected), "Recall preparation replaced a cancellation or permission-boundary error.");
        }
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();
        await AssertThrowsAsync<OperationCanceledException>(() => NewEwsClient(new RecordingRecallHandler())
            .PrepareRecallAsync(RecallMailbox, "sent-message-1", cancelled.Token));
        var privateFailureHandler = new RecordingRecallHandler { SourceFailure = new InvalidOperationException("private source data") };
        RecallPreparationException? privateFailure = null;
        try { await NewEwsClient(privateFailureHandler).PrepareRecallAsync(RecallMailbox, "sent-message-1", CancellationToken.None); }
        catch (RecallPreparationException exception) { privateFailure = exception; }
        Expect(privateFailure is { Phase: "source_message", Reason: "preparation_failed", InnerException: null }
            && privateFailure.Data.Count == 0 && !privateFailure.Message.Contains("private source data", StringComparison.Ordinal),
            "Recall preparation retained private exception details in its typed public failure.");

        var maliciousIdentity = new RecordingRecallHandler { AutodiscoverSmtp = "attacker@example.test" };
        await AssertThrowsAsync<InvalidOperationException>(() => NewEwsClient(maliciousIdentity)
            .PrepareRecallAsync(RecallMailbox, "sent-message-1", CancellationToken.None));

        var wrongReturnedId = new RecordingRecallHandler { ReturnedSourceId = "different-message" };
        await AssertThrowsAsync<InvalidOperationException>(() => NewEwsClient(wrongReturnedId)
            .PrepareRecallAsync(RecallMailbox, "sent-message-1", CancellationToken.None));
        Expect(!wrongReturnedId.Calls.Any(call => call.Operation == "Autodiscover"),
            "A source response for a different item reached Autodiscover.");

        var maliciousLegacyDn = new RecordingRecallHandler { AutodiscoverLegacyDn = "o=evil\0/ou=Exchange" };
        await AssertThrowsAsync<InvalidOperationException>(() => NewEwsClient(maliciousLegacyDn)
            .PrepareRecallAsync(RecallMailbox, "sent-message-1", CancellationToken.None));

        var dtd = new RecordingRecallHandler
        {
            AutodiscoverXml = "<!DOCTYPE x [<!ENTITY secret 'leak'>]><a:Autodiscover xmlns:a='"
                + RecallAutodiscoverResponseNamespace + "'><a:Response><a:User><a:AutoDiscoverSMTPAddress>&secret;</a:AutoDiscoverSMTPAddress>"
                + "<a:LegacyDN>o=example</a:LegacyDN></a:User></a:Response></a:Autodiscover>"
        };
        await AssertThrowsAsync<InvalidOperationException>(() => NewEwsClient(dtd)
            .PrepareRecallAsync(RecallMailbox, "sent-message-1", CancellationToken.None));
        Expect(!dtd.Calls.Any(call => call.Operation == "CreateItem"),
            "A malicious Autodiscover response reached a recall write.");

        var malformedTagHandler = new RecordingRecallHandler();
        var malformedTagClient = NewEwsClient(malformedTagHandler);
        var malformedRequest = new EwsRecallRequest("id", "change", "subject", ["to@example.test"], [], [],
            Convert.ToBase64String(malformedTagHandler.SearchKey), Convert.ToBase64String([1, 2, 3]));
        await AssertThrowsAsync<ArgumentException>(() => malformedTagClient.SubmitRecallAsync(
            RecallMailbox, malformedRequest, CancellationToken.None));
        Expect(malformedTagHandler.CreateCount == 0, "A malformed recall report tag reached CreateItem.");
    }

    private async Task RecallReportChecksAsync()
    {
        var handler = new RecordingRecallHandler();
        var client = NewEwsClient(handler);
        var prepared = await client.PrepareRecallAsync(RecallMailbox, "sent-message-1", CancellationToken.None);
        var reportTag = Convert.FromBase64String(prepared.ReportTag);
        var wrongTag = reportTag.ToArray();
        wrongTag[^1] ^= 0x40;
        handler.Reports.Add(new RecallReportFixture("inbox", "success-1", "IPM.Recall.Report.Success", reportTag,
            "Recall: Quarterly résumé", "2026-10-11T09:00:00Z"));
        handler.Reports.Add(new RecallReportFixture("deleteditems", "failure-1", "IPM.Recall.Report.Failure", reportTag,
            "Recall: Quarterly résumé", "2026-10-11T09:01:00Z"));
        handler.Reports.Add(new RecallReportFixture("recoverableitemsdeletions", "wrong-tag", "IPM.Recall.Report.Success", wrongTag,
            "wrong", "2026-10-11T09:02:00Z"));
        handler.Reports.Add(new RecallReportFixture("inbox", "wrong-class", "IPM.Note", reportTag,
            "wrong class", "2026-10-11T09:03:00Z"));
        handler.Reports.Add(new RecallReportFixture("inbox", "success-1", "IPM.Recall.Report.Success", reportTag,
            "duplicate", "2026-10-11T09:04:00Z"));

        var reports = await client.GetRecallReportsAsync(RecallMailbox, prepared.ReportTag, CancellationToken.None);
        Expect(reports.Count == 2
            && reports.Select(report => report.Outcome).OrderBy(value => value).SequenceEqual(["failure", "success"])
            && reports.All(report => report.Subject == "Recall: Quarterly résumé"),
            "Recall report filtering did not retain exactly the correlated success and failure classes.");

        var searches = handler.Calls.Where(call => call.Operation == "FindItem").ToArray();
        Expect(searches.Length == 3
            && searches.All(call => call.Body.Contains("MaxEntriesReturned=\"20\"", StringComparison.Ordinal)
                && call.Body.Contains("PropertyTag=\"0x0031\"", StringComparison.Ordinal)
                && call.Body.Contains(Convert.ToBase64String(reportTag), StringComparison.Ordinal)),
            "Recall report searches did not use a bounded exact report-tag restriction.");
        Expect(searches[0].Body.Contains("DistinguishedFolderId Id=\"inbox\"", StringComparison.Ordinal)
            && searches[1].Body.Contains("DistinguishedFolderId Id=\"deleteditems\"", StringComparison.Ordinal)
            && searches[2].Body.Contains("DistinguishedFolderId Id=\"recoverableitemsdeletions\"", StringComparison.Ordinal),
            "Recall reports were not searched across Inbox, Deleted Items and Recoverable Deletions.");

        await AssertThrowsAsync<ArgumentException>(() => client.GetRecallReportsAsync(
            RecallMailbox, Convert.ToBase64String([1, 2, 3]), CancellationToken.None));
        Expect(searches.Length == handler.Calls.Count(call => call.Operation == "FindItem"),
            "An invalid report tag reached Exchange.");

        var truncatedHandler = new RecordingRecallHandler { TruncateReports = true };
        var truncatedClient = NewEwsClient(truncatedHandler);
        var truncatedRequest = await truncatedClient.PrepareRecallAsync(
            RecallMailbox, "sent-message-1", CancellationToken.None);
        InvalidOperationException? truncatedFailure = null;
        try
        {
            await truncatedClient.GetRecallReportsAsync(RecallMailbox, truncatedRequest.ReportTag, CancellationToken.None);
        }
        catch (InvalidOperationException exception)
        {
            truncatedFailure = exception;
        }
        Expect(truncatedFailure?.Message.Contains("bounded six-page limit", StringComparison.Ordinal) == true,
            $"Recall status pagination failed for the wrong reason: {truncatedFailure?.Message ?? "no exception"}.");
        var truncatedSearches = truncatedHandler.Calls.Where(call => call.Operation == "FindItem").ToArray();
        Expect(truncatedSearches.Length == 6,
            "Recall status pagination did not stop at its bounded six-page limit.");
        Expect(truncatedSearches.All(call => call.Body.Contains("MaxEntriesReturned=\"20\"", StringComparison.Ordinal)),
            "Recall status pagination omitted the bounded page size.");
        Expect(truncatedSearches.All(call => call.Body.Contains("Offset=\"", StringComparison.Ordinal)),
            "Recall status pagination omitted its page offsets.");

        foreach (var invalidPagingFlag in new string?[] { null, "unknown" })
        {
            var invalidPaging = new RecordingRecallHandler { ReportIncludesLastItemInRange = invalidPagingFlag };
            var invalidPagingClient = NewEwsClient(invalidPaging);
            var invalidPagingRequest = await invalidPagingClient.PrepareRecallAsync(
                RecallMailbox, "sent-message-1", CancellationToken.None);
            await AssertThrowsAsync<InvalidOperationException>(() => invalidPagingClient.GetRecallReportsAsync(
                RecallMailbox, invalidPagingRequest.ReportTag, CancellationToken.None));
            Expect(invalidPaging.Calls.Count(call => call.Operation == "FindItem") == 1,
                "Recall status paging did not fail closed on an invalid completion flag.");
        }
        ValidateRecallSchema(handler);
    }

    private async Task RecallToolChecksAsync()
    {
        await AssertRecallToolDiscoveryAsync();
        var exchange = new RecordingRecallHandler();
        await using var host = await StartRecallHostAsync(exchange, writesEnabled: true, sendEnabled: true, classicStateful: true);
        var token = Token("user-a", "mail.read mail.write mail.manage mail.send", sessionId: "recall-a");

        var form = new NativeFormResponder(accept: false);
        await using var alice = await CreateNativeClientAsync(host, token, form);
        var search = await alice.Client.CallToolAsync("mail_search", new Dictionary<string, object?>
        {
            ["folder"] = "sentitems",
            ["limit"] = 20
        });
        Expect(search.IsError != true, "The recall Sent Items fixture could not be searched.");
        var messageHandle = NativeData(search).GetProperty("items")[0].GetProperty("handle").GetString()!;

        var declined = await alice.Client.CallToolAsync("mail_recall_message", new Dictionary<string, object?>
        {
            ["messageHandle"] = messageHandle
        });
        Expect(declined.IsError != true && NativeData(declined).GetProperty("status").GetString() == "cancelled"
            && form.Calls == 1 && exchange.CreateCount == 0,
            "A declined recall confirmation was not cancelled before CreateItem.");

        form.Accept = true;
        var accepted = await alice.Client.CallToolAsync("mail_recall_message", new Dictionary<string, object?>
        {
            ["messageHandle"] = messageHandle
        });
        Expect(accepted.IsError != true && NativeData(accepted).GetProperty("status").GetString() == "recall_requested"
            && exchange.CreateCount == 1,
            "An accepted recall did not submit exactly one native recall notice.");
        var recallHandle = NativeData(accepted).GetProperty("recallHandle").GetString()!;

        var pending = await alice.Client.CallToolAsync("mail_recall_status", new Dictionary<string, object?>
        {
            ["recallHandle"] = recallHandle
        });
        Expect(pending.IsError != true && NativeData(pending).GetProperty("status").GetString() == "pending_or_unreported"
            && NativeData(pending).GetProperty("allRecipientCopiesVerified").GetBoolean() == false,
            "A recall with no reports was not surfaced as pending or unreported.");

        exchange.Reports.Add(new RecallReportFixture("inbox", "tool-success", "IPM.Recall.Report.Success",
            Convert.FromBase64String(exchange.SubmittedReportTag), "Recall: Quarterly résumé", "2026-10-11T10:00:00Z"));
        var reported = await alice.Client.CallToolAsync("mail_recall_status", new Dictionary<string, object?>
        {
            ["recallHandle"] = recallHandle
        });
        Expect(reported.IsError != true && NativeData(reported).GetProperty("status").GetString() == "reports_received"
            && NativeData(reported).GetProperty("successReports").GetInt32() == 1,
            "A correlated recall success report was not surfaced by status.");

        exchange.ReturnTrackingNoticeOnSearch = true;
        var noticeSearch = await alice.Client.CallToolAsync("mail_search", new Dictionary<string, object?>
        {
            ["folder"] = "deleteditems",
            ["limit"] = 20
        });
        Expect(noticeSearch.IsError != true, "The moved recall notice fixture could not be searched.");
        var noticeHandle = NativeData(noticeSearch).GetProperty("items")[0].GetProperty("handle").GetString()!;
        var recovered = await alice.Client.CallToolAsync("mail_recall_status", new Dictionary<string, object?>
        {
            ["messageHandle"] = noticeHandle
        });
        var recoveredData = NativeData(recovered);
        Expect(recovered.IsError != true
            && recoveredData.GetProperty("status").GetString() == "reports_received"
            && recoveredData.GetProperty("successReports").GetInt32() == 1
            && recoveredData.GetProperty("failureReports").GetInt32() == 0
            && recoveredData.GetProperty("originalSubject").GetString() == exchange.SourceSubject
            && recoveredData.GetProperty("originalRecipientCount").GetInt32() == 4
            && !string.IsNullOrWhiteSpace(recoveredData.GetProperty("recallHandle").GetString()),
            "A fresh message handle did not recover the native recall tracking fields and correlated report.");
        var trackingGetItem = exchange.Calls.Last(call => call.Operation == "GetItem");
        Expect(trackingGetItem.Body.Contains("PropertyTag=\"0x0031\"", StringComparison.Ordinal)
            && trackingGetItem.Body.Contains("PropertyTag=\"0x6800\"", StringComparison.Ordinal)
            && trackingGetItem.Body.Contains("PropertyTag=\"0x0E1D\"", StringComparison.Ordinal)
            && trackingGetItem.Body.Contains("message:From", StringComparison.Ordinal)
            && trackingGetItem.Body.Contains("message:Sender", StringComparison.Ordinal)
            && trackingGetItem.Body.Contains("message:ToRecipients", StringComparison.Ordinal)
            && trackingGetItem.Body.Contains("message:CcRecipients", StringComparison.Ordinal)
            && trackingGetItem.Body.Contains("message:BccRecipients", StringComparison.Ordinal),
            "Native recall tracking recovery did not request the protected notice identity, tag, key and recipient fields.");

        var recoveredHandle = recoveredData.GetProperty("recallHandle").GetString()!;
        var recoveredAgain = await alice.Client.CallToolAsync("mail_recall_status", new Dictionary<string, object?>
        {
            ["recallHandle"] = recoveredHandle
        });
        var recoveredAgainData = NativeData(recoveredAgain);
        Expect(recoveredAgain.IsError != true
            && recoveredAgainData.GetProperty("status").GetString() == "reports_received"
            && recoveredAgainData.GetProperty("successReports").GetInt32() == 1
            && recoveredAgainData.GetProperty("originalSubject").GetString() == exchange.SourceSubject,
            "The opaque handle returned by native tracking recovery did not preserve the exact correlated status.");

        var readOnlyExchange = new RecordingRecallHandler
        {
            ReturnTrackingNoticeOnSearch = true,
            TrackingReportTag = Convert.FromBase64String(exchange.SubmittedReportTag),
            TrackingSearchKey = exchange.SearchKey.ToArray()
        };
        readOnlyExchange.Reports.Add(new RecallReportFixture("inbox", "readonly-success", "IPM.Recall.Report.Success",
            Convert.FromBase64String(exchange.SubmittedReportTag), "Recall: Quarterly résumé", "2026-10-11T10:00:00Z"));
        await using var readOnlyHost = await StartRecallHostAsync(readOnlyExchange,
            writesEnabled: false, sendEnabled: false, classicStateful: true);
        await using var readOnlyClient = await CreateNativeClientAsync(readOnlyHost,
            Token("user-a", "mail.read", sessionId: "recall-readonly"), new NativeFormResponder(accept: false));
        var readOnlySearch = await readOnlyClient.Client.CallToolAsync("mail_search", new Dictionary<string, object?>
        {
            ["folder"] = "deleteditems",
            ["limit"] = 20
        });
        var readOnlyNoticeHandle = NativeData(readOnlySearch).GetProperty("items")[0].GetProperty("handle").GetString()!;
        var readOnlyRecovered = await readOnlyClient.Client.CallToolAsync("mail_recall_status", new Dictionary<string, object?>
        {
            ["messageHandle"] = readOnlyNoticeHandle
        });
        Expect(readOnlyRecovered.IsError != true
            && NativeData(readOnlyRecovered).GetProperty("status").GetString() == "reports_received"
            && readOnlyExchange.CreateCount == 0,
            "Read-only recall tracking recovery required write/send access or emitted a write.");

        foreach (var invalid in new[] { "wrong-id", "wrong-change-key", "wrong-class", "draft", "foreign-from", "foreign-sender",
            "missing-tag", "malformed-tag", "missing-key", "malformed-key", "mismatch-key", "missing-subject", "invalid-subject",
            "no-recipients", "invalid-recipient-routing", "too-many-recipients" })
        {
            var invalidExchange = new RecordingRecallHandler
            {
                ReturnTrackingNoticeOnSearch = true,
                TrackingReportTag = Convert.FromBase64String(exchange.SubmittedReportTag),
                TrackingSearchKey = exchange.SearchKey.ToArray(),
                TrackingSubject = exchange.SourceSubject
            };
            switch (invalid)
            {
                case "wrong-id": invalidExchange.ReturnedTrackingId = "other-notice"; break;
                case "wrong-change-key": invalidExchange.ReturnedTrackingChangeKey = "other-change"; break;
                case "wrong-class": invalidExchange.TrackingItemClass = "IPM.Note"; break;
                case "draft": invalidExchange.TrackingIsDraft = true; break;
                case "foreign-from": invalidExchange.TrackingFrom = "other@example.test"; break;
                case "foreign-sender": invalidExchange.TrackingSender = "other@example.test"; break;
                case "missing-tag": invalidExchange.TrackingIncludeReportTag = false; break;
                case "malformed-tag": invalidExchange.TrackingReportTag = [1, 2, 3]; break;
                case "missing-key": invalidExchange.TrackingIncludeSearchKey = false; break;
                case "malformed-key": invalidExchange.TrackingSearchKey = [1, 2, 3]; break;
                case "mismatch-key": invalidExchange.TrackingSearchKey = exchange.SearchKey.ToArray(); invalidExchange.TrackingSearchKey[0] ^= 0x40; break;
                case "missing-subject": invalidExchange.TrackingIncludeSubject = false; break;
                case "invalid-subject": invalidExchange.TrackingSubject = "bad\nsubject"; break;
                case "no-recipients": invalidExchange.TrackingTo = []; invalidExchange.TrackingCc = []; invalidExchange.TrackingBcc = []; break;
                case "invalid-recipient-routing": invalidExchange.TrackingRecipientRouting = "X500"; break;
                case "too-many-recipients": invalidExchange.TrackingTo = Enumerable.Range(0, 101).Select(index => $"user{index}@example.test").ToArray(); break;
            }

            await using var invalidHost = await StartRecallHostAsync(invalidExchange,
                writesEnabled: true, sendEnabled: true, classicStateful: true);
            await using var invalidClient = await CreateNativeClientAsync(invalidHost,
                Token("user-a", "mail.read mail.write mail.manage mail.send", sessionId: "recall-invalid-" + invalid),
                new NativeFormResponder(accept: true));
            var invalidSearch = await invalidClient.Client.CallToolAsync("mail_search", new Dictionary<string, object?>
            {
                ["folder"] = "deleteditems",
                ["limit"] = 20
            });
            var invalidNoticeHandle = NativeData(invalidSearch).GetProperty("items")[0].GetProperty("handle").GetString()!;
            var beforeReports = invalidExchange.Calls.Count(call => call.Operation == "FindItem");
            var rejected = await NativeRejectedAsync(invalidClient.Client, "mail_recall_status", new Dictionary<string, object?>
            {
                ["messageHandle"] = invalidNoticeHandle
            });
            Expect(rejected && invalidExchange.Calls.Count(call => call.Operation == "FindItem") == beforeReports,
                $"Malformed native recall tracking notice '{invalid}' was accepted or reached report search.");
        }

        var bothArguments = await NativeRejectedAsync(alice.Client, "mail_recall_status", new Dictionary<string, object?>
        {
            ["recallHandle"] = recallHandle,
            ["messageHandle"] = noticeHandle
        });
        var neitherArgument = await NativeRejectedAsync(alice.Client, "mail_recall_status", new Dictionary<string, object?>());
        Expect(bothArguments && neitherArgument,
            "Recall status accepted both tracking arguments or accepted neither argument.");

        await using var bob = await CreateNativeClientAsync(host,
            Token("user-b", "mail.read mail.write mail.manage mail.send", sessionId: "recall-b"),
            new NativeFormResponder(accept: true));
        var beforeCrossUser = exchange.Calls.Count;
        var crossUser = await NativeRejectedAsync(bob.Client, "mail_recall_status", new Dictionary<string, object?>
        {
            ["recallHandle"] = recallHandle
        });
        Expect(crossUser && exchange.Calls.Count == beforeCrossUser,
            "A different mailbox reused a recall status handle or reached Exchange.");

        var beforeMessageCrossUser = exchange.Calls.Count;
        var messageCrossUser = await NativeRejectedAsync(bob.Client, "mail_recall_status", new Dictionary<string, object?>
        {
            ["messageHandle"] = noticeHandle
        });
        var beforeWrongKind = exchange.Calls.Count;
        var wrongKind = await NativeRejectedAsync(alice.Client, "mail_recall_status", new Dictionary<string, object?>
        {
            ["messageHandle"] = recallHandle
        });
        var beforeRecoveredCrossUser = exchange.Calls.Count;
        var recoveredCrossUser = await NativeRejectedAsync(bob.Client, "mail_recall_status", new Dictionary<string, object?>
        {
            ["recallHandle"] = recoveredHandle
        });
        var corruptedRecovered = recoveredHandle[..^1] + (recoveredHandle[^1] == 'A' ? 'B' : 'A');
        var beforeCorruptedRecovered = exchange.Calls.Count;
        var corruptedRecovery = await NativeRejectedAsync(alice.Client, "mail_recall_status", new Dictionary<string, object?>
        {
            ["recallHandle"] = corruptedRecovered
        });
        Expect(messageCrossUser && exchange.Calls.Count == beforeMessageCrossUser
            && wrongKind && exchange.Calls.Count == beforeWrongKind
            && recoveredCrossUser && exchange.Calls.Count == beforeRecoveredCrossUser
            && corruptedRecovery && exchange.Calls.Count == beforeCorruptedRecovered,
            "Recall message or recovered handles crossed mailbox, kind or integrity boundaries.");

        var staleExchange = new RecordingRecallHandler();
        await using var staleHost = await StartRecallHostAsync(staleExchange, writesEnabled: true, sendEnabled: true, classicStateful: true);
        await using var staleClient = await CreateNativeClientAsync(staleHost, Token(
            "user-a", "mail.read mail.write mail.manage mail.send", sessionId: "recall-stale"),
            new NativeFormResponder(accept: true));
        var staleSearch = await staleClient.Client.CallToolAsync("mail_search", new Dictionary<string, object?>
        {
            ["folder"] = "sentitems",
            ["limit"] = 20
        });
        var staleHandle = NativeData(staleSearch).GetProperty("items")[0].GetProperty("handle").GetString()!;
        staleExchange.SourceChangeKey = "new-change";
        var stale = await NativeRejectedAsync(staleClient.Client, "mail_recall_message", new Dictionary<string, object?>
        {
            ["messageHandle"] = staleHandle
        });
        Expect(stale && staleExchange.CreateCount == 0,
            "A stale Sent Items handle reached recall confirmation or submission.");

        await AssertRecallApprovalBindingAsync();
        await AssertRecallPreparationFailureAsync();
        await AssertRecallUncertainSubmissionAsync();
        await AssertRecallPermissionDeniedSubmissionAsync();
        ValidateRecallSchema(exchange);
    }

    private async Task AssertRecallPreparationFailureAsync()
    {
        var exchange = new RecordingRecallHandler();
        await using var host = await StartRecallHostAsync(exchange, writesEnabled: true, sendEnabled: true, classicStateful: false);
        var token = Token("user-a", "mail.read mail.write mail.manage mail.send", sessionId: "recall-preparation");
        await InitializeAsync(host.Client, token, elicitation: true);
        var search = await ToolRequestAsync(host.Client, token, "tools/call", new
        {
            name = "mail_search",
            arguments = new { folder = "sentitems", limit = 20 }
        });
        var messageHandle = ToolStructuredData(search.Body).GetProperty("items")[0].GetProperty("handle").GetString()!;
        exchange.SourceFailure = new InvalidOperationException("sensitive synthetic source exception");
        var failure = await ToolRequestAsync(host.Client, token, "tools/call", new
        {
            name = "mail_recall_message",
            arguments = new { messageHandle }
        }, JulyProtocolVersion, elicitation: true);
        var data = ToolStructuredData(failure.Body);
        var tracking = data.GetProperty("tracking");
        Expect(IsToolError(failure.Body) && data.GetProperty("status").GetString() == "recall_preparation_failed"
            && !data.GetProperty("submitted").GetBoolean()
            && data.GetProperty("phase").GetString() == "source_message"
            && data.GetProperty("reason").GetString() == "preparation_failed"
            && tracking.GetProperty("phase").GetString() == "source_message"
            && tracking.GetProperty("reason").GetString() == "preparation_failed"
            && tracking.GetProperty("outcome").GetString() == "failed"
            && tracking.GetProperty("sendStatus").GetString() == "not_dispatched"
            && exchange.CreateCount == 0
            && !failure.Body.Contains("sensitive synthetic source exception", StringComparison.Ordinal)
            && !failure.Body.Contains(exchange.SourceSubject, StringComparison.Ordinal),
            "A preparation failure was not an explicit safe, unsubmitted tool error.");
        var auditPath = host.App.Services.GetRequiredService<Microsoft.Extensions.Options.IOptions<ServiceOptions>>().Value.AuditPath;
        var audit = await ReadSharedAuditAsync(auditPath);
        var entries = audit.Split('\n', StringSplitOptions.RemoveEmptyEntries)
            .Select(line => System.Text.Json.JsonDocument.Parse(line).RootElement.Clone())
            .Where(entry => entry.TryGetProperty("operationId", out var id) && id.GetString() == tracking.GetProperty("id").GetString())
            .ToArray();
        Expect(entries.Any(entry => entry.TryGetProperty("outcome", out var outcome) && outcome.GetString() == "failed")
            && !entries.Any(entry => entry.TryGetProperty("outcome", out var outcome) && outcome.GetString() is "completed" or "approval_required")
            && !audit.Contains("sensitive synthetic source exception", StringComparison.Ordinal),
            "A preparation failure was audited as completed or leaked its underlying exception.");
    }

    private async Task AssertRecallToolDiscoveryAsync()
    {
        var exchange = new RecordingRecallHandler();
        await using var host = await StartRecallHostAsync(exchange, writesEnabled: true, sendEnabled: true, classicStateful: false);
        var token = Token("user-a", "mail.read mail.write mail.manage mail.send", sessionId: "recall-discovery");
        await InitializeAsync(host.Client, token);
        var catalog = await ToolRequestAsync(host.Client, token, "tools/list", new { });
        var catalogJson = ParseJson(catalog.Body);
        var names = catalogJson.RootElement.GetProperty("result").GetProperty("tools").EnumerateArray()
            .Select(tool => tool.GetProperty("name").GetString()).ToHashSet(StringComparer.Ordinal);
        Expect(names.Contains("mail_recall_message") && names.Contains("mail_recall_status"),
            "Recall tools were not discoverable through MCP.");
    }

    private async Task AssertRecallApprovalBindingAsync()
    {
        var exchange = new RecordingRecallHandler();
        await using var host = await StartRecallHostAsync(exchange, writesEnabled: true, sendEnabled: true, classicStateful: false);
        var token = Token("user-a", "mail.read mail.write mail.manage mail.send", sessionId: "recall-binding-a");
        await InitializeAsync(host.Client, token, elicitation: true);
        var search = await ToolRequestAsync(host.Client, token, "tools/call", new
        {
            name = "mail_search",
            arguments = new { folder = "sentitems", limit = 20 }
        });
        var messageHandle = ToolStructuredData(search.Body).GetProperty("items")[0].GetProperty("handle").GetString()!;
        var first = await ToolRequestAsync(host.Client, token, "tools/call", new
        {
            name = "mail_recall_message",
            arguments = new { messageHandle }
        }, JulyProtocolVersion, elicitation: true);
        var state = InputRequiredState(first.Body);
        var before = exchange.CreateCount;
        var wrongSession = await ToolRequestAsync(host.Client, Token(
            "user-a", "mail.read mail.write mail.manage mail.send", azp: "chatgpt-alt", sessionId: "recall-binding-b"),
            "tools/call", new
            {
                name = "mail_recall_message",
                requestState = state,
                inputResponses = new { recall_confirmation = new { action = "accept", content = new { confirm = true } } },
                arguments = new { messageHandle }
            }, JulyProtocolVersion, elicitation: true);
        Expect(IsToolError(wrongSession.Body) && exchange.CreateCount == before,
            "A recall approval was reusable across OAuth client or session bindings.");

        exchange.SourceSubject = "Changed after recall approval";
        var changedRequest = await ToolRequestAsync(host.Client, token, "tools/call", new
        {
            name = "mail_recall_message",
            requestState = state,
            inputResponses = new { recall_confirmation = new { action = "accept", content = new { confirm = true } } },
            arguments = new { messageHandle }
        }, JulyProtocolVersion, elicitation: true);
        Expect(IsToolError(changedRequest.Body) && exchange.CreateCount == before,
            "A recall approval was reusable after the reviewed JSON payload changed.");
    }

    private async Task AssertRecallUncertainSubmissionAsync()
    {
        var exchange = new RecordingRecallHandler { ThrowOnCreate = true };
        await using var host = await StartRecallHostAsync(exchange, writesEnabled: true, sendEnabled: true, classicStateful: false);
        var token = Token("user-a", "mail.read mail.write mail.manage mail.send", sessionId: "recall-uncertain");
        await InitializeAsync(host.Client, token, elicitation: true);
        var first = await ToolRequestAsync(host.Client, token, "tools/call", new
        {
            name = "mail_search",
            arguments = new { folder = "sentitems", limit = 20 }
        });
        var messageHandle = ToolStructuredData(first.Body).GetProperty("items")[0].GetProperty("handle").GetString()!;
        var approval = await ToolRequestAsync(host.Client, token, "tools/call", new
        {
            name = "mail_recall_message",
            arguments = new { messageHandle }
        }, JulyProtocolVersion, elicitation: true);
        var state = InputRequiredState(approval.Body);
        var result = await ToolRequestAsync(host.Client, token, "tools/call", new
        {
            name = "mail_recall_message",
            requestState = state,
            inputResponses = new { recall_confirmation = new { action = "accept", content = new { confirm = true } } },
            arguments = new { messageHandle }
        }, JulyProtocolVersion, elicitation: true);
        Expect(!IsToolError(result.Body), "The uncertain recall result was an MCP tool error.");
        var data = ToolStructuredData(result.Body);
        Expect(data.GetProperty("status").GetString() == "submission_unverified"
            && data.GetProperty("doNotRetryAutomatically").GetBoolean()
            && !string.IsNullOrWhiteSpace(data.GetProperty("recallHandle").GetString())
            && data.GetProperty("tracking").GetProperty("outcome").GetString() == "unknown"
            && data.GetProperty("tracking").GetProperty("sendStatus").GetString() == "unknown"
            && !data.TryGetProperty("submitted", out _)
            && exchange.CreateCount == 1,
            "An uncertain recall submission did not return a status handle and no-retry result.");
        var replay = await ToolRequestAsync(host.Client, token, "tools/call", new
        {
            name = "mail_recall_message",
            requestState = state,
            inputResponses = new { recall_confirmation = new { action = "accept", content = new { confirm = true } } },
            arguments = new { messageHandle }
        }, JulyProtocolVersion, elicitation: true);
        Expect(IsToolError(replay.Body) && exchange.CreateCount == 1,
            "An uncertain recall approval was replayed into another submission.");
    }

    private async Task AssertRecallPermissionDeniedSubmissionAsync()
    {
        var exchange = new RecordingRecallHandler { AccessDeniedOnCreate = true };
        await using var host = await StartRecallHostAsync(exchange, writesEnabled: true, sendEnabled: true, classicStateful: false);
        var token = Token("user-a", "mail.read mail.write mail.manage mail.send", sessionId: "recall-permission-denied");
        await InitializeAsync(host.Client, token, elicitation: true);
        var first = await ToolRequestAsync(host.Client, token, "tools/call", new
        {
            name = "mail_search",
            arguments = new { folder = "sentitems", limit = 20 }
        });
        var messageHandle = ToolStructuredData(first.Body).GetProperty("items")[0].GetProperty("handle").GetString()!;
        var approval = await ToolRequestAsync(host.Client, token, "tools/call", new
        {
            name = "mail_recall_message",
            arguments = new { messageHandle }
        }, JulyProtocolVersion, elicitation: true);
        var state = InputRequiredState(approval.Body);
        var accepted = new
        {
            name = "mail_recall_message",
            requestState = state,
            inputResponses = new { recall_confirmation = new { action = "accept", content = new { confirm = true } } },
            arguments = new { messageHandle }
        };
        var result = await ToolRequestAsync(host.Client, token, "tools/call", accepted,
            JulyProtocolVersion, elicitation: true);
        Expect(!IsToolError(result.Body), "An explicit recall permission denial was returned as an MCP protocol error.");
        var data = ToolStructuredData(result.Body);
        const string expectedMessage = "Exchange denied access required to submit this recall. No recall was submitted. Check mailbox permissions before trying again.";
        Expect(data.GetProperty("status").GetString() == "permission_denied"
            && data.GetProperty("doNotRetryAutomatically").GetBoolean()
            && !string.IsNullOrWhiteSpace(data.GetProperty("recallHandle").GetString())
            && data.GetProperty("message").GetString() == expectedMessage
            && data.GetProperty("tracking").GetProperty("outcome").GetString() == "rejected"
            && data.GetProperty("tracking").GetProperty("sendStatus").GetString() == "rejected"
            && exchange.CreateCount == 1,
            "An explicit recall permission denial did not return its safe status handle or made more than one submission.");
        var replay = await ToolRequestAsync(host.Client, token, "tools/call", accepted,
            JulyProtocolVersion, elicitation: true);
        Expect(IsToolError(replay.Body) && exchange.CreateCount == 1,
            "A permission-denied recall approval was replayed or submitted more than once.");
    }

    private async Task<TestHostContext> StartRecallHostAsync(RecordingRecallHandler exchange,
        bool writesEnabled, bool sendEnabled, bool classicStateful)
    {
        var passwordPath = Path.Combine(runDirectory, $"recall-password-{Guid.NewGuid():N}.txt");
        var introspectionSecretPath = Path.Combine(runDirectory, $"recall-introspection-{Guid.NewGuid():N}.txt");
        var auditPath = Path.Combine(runDirectory, $"recall-audit-{Guid.NewGuid():N}.jsonl");
        await File.WriteAllTextAsync(passwordPath, "synthetic-password");
        await File.WriteAllTextAsync(introspectionSecretPath, "synthetic-introspection-secret");
        var app = AppHost.Create([], builder =>
        {
            builder.WebHost.UseTestServer();
            if (!classicStateful)
            {
                builder.Services.PostConfigure<HttpServerTransportOptions>(options =>
                    options.SessionMode = HttpServerSessionMode.Stateless);
            }

            builder.Configuration.AddInMemoryCollection(ConfigurationValues(passwordPath, introspectionSecretPath,
                auditPath, writesEnabled, sendEnabled));
            builder.Services.PostConfigure<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme, options =>
            {
                var configuration = new OpenIdConnectConfiguration { Issuer = Authority };
                configuration.SigningKeys.Add(signingKey);
                options.Configuration = configuration;
                options.ConfigurationManager = new StaticConfigurationManager<OpenIdConnectConfiguration>(configuration);
            });
            builder.Services.AddHttpClient<EwsClient>()
                .ConfigurePrimaryHttpMessageHandler(() => exchange);
            builder.Services.AddHttpClient<KeycloakTokenStatus>()
                .ConfigurePrimaryHttpMessageHandler(() => new IntrospectionHandler());
        });
        await app.StartAsync();
        var client = app.GetTestClient();
        client.BaseAddress = new Uri("https://mail.example.test/");
        return new TestHostContext(app, client);
    }

    private static void ValidateRecallTagBytes(EwsRecallRequest request, RecordingRecallHandler handler, bool omitAnsi = false)
    {
        var tag = Convert.FromBase64String(request.ReportTag);
        var position = 0;
        var cookie = Encoding.ASCII.GetBytes("PCDFEB09\0");
        Expect(tag.AsSpan(0, cookie.Length).SequenceEqual(cookie), "Recall report tag cookie was incorrect.");
        position += cookie.Length;
        Expect(BinaryPrimitives.ReadUInt32LittleEndian(tag.AsSpan(position, 4)) == 0x0002_0001,
            "Recall report tag version was incorrect.");
        position += 4;
        var components = new List<byte[]>();
        for (var index = 0; index < 6; index++)
        {
            var length = checked((int)BinaryPrimitives.ReadUInt32LittleEndian(tag.AsSpan(position, 4)));
            position += 4;
            components.Add(tag.AsSpan(position, length).ToArray());
            position += length;
        }

        var expectedStore = new List<byte>(handler.StoreEntryId.Take(60));
        expectedStore.AddRange(Encoding.ASCII.GetBytes("alice@example.test\0"));
        expectedStore.AddRange(Encoding.ASCII.GetBytes("o=Example/ou=Exchange Administrative Group/cn=Recipients/cn=alice\0"));
        Span<byte> uintBytes = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(uintBytes, 4_096_935_657);
        expectedStore.AddRange(uintBytes.ToArray());
        BinaryPrimitives.WriteUInt32LittleEndian(uintBytes, (uint)(18 + Encoding.Unicode.GetByteCount("alice@example.test\0")));
        expectedStore.AddRange(uintBytes.ToArray());
        BinaryPrimitives.WriteUInt32LittleEndian(uintBytes, 2);
        expectedStore.AddRange(uintBytes.ToArray());
        BinaryPrimitives.WriteUInt32LittleEndian(uintBytes, 16);
        expectedStore.AddRange(uintBytes.ToArray());
        expectedStore.AddRange(Encoding.Unicode.GetBytes("alice@example.test\0"));
        expectedStore.AddRange([0, 0]);
        Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
        var expectedSubject = omitAnsi ? Array.Empty<byte>() : Encoding.GetEncoding(handler.SourceCodePage!.Value).GetBytes(handler.SourceSubject + "\0");
        Expect(components[0].SequenceEqual(expectedStore)
            && components[1].SequenceEqual(handler.ParentEntryId)
            && components[2].SequenceEqual(handler.EntryId)
            && components[3].Length == 0
            && components[4].SequenceEqual(handler.SearchKey)
            && components[5].SequenceEqual(expectedSubject)
            && position == tag.Length,
            "Recall report tag binary components did not match the native format.");
    }

    private static void ValidateRecallSchema(RecordingRecallHandler handler)
    {
        var schemas = LoadOptionalExchangeSchemas();
        foreach (var call in handler.Calls.Where(call => call.Operation is "GetFolder" or "GetItem" or "CreateItem" or "FindItem"))
        {
            var document = XDocument.Parse(call.Body, LoadOptions.PreserveWhitespace);
            var operation = document.Root?.Element(XName.Get("Body", RecallSoapNamespace))?.Elements().Single()
                ?? throw new InvalidOperationException("Recall SOAP operation was not captured.");
            if (schemas is not null)
                new XDocument(new XElement(operation)).Validate(schemas, (_, error) => throw new InvalidOperationException(
                    $"Exchange 2019 schema rejected recall operation: {error.Message}"));
        }
    }
}

internal sealed record RecallCapturedRequest(
    string Operation,
    string Body,
    HttpMethod Method,
    Uri RequestUri);

internal sealed record RecallReportFixture(
    string Folder,
    string Id,
    string ItemClass,
    byte[] ReportTag,
    string Subject,
    string ReceivedUtc);

internal sealed class RecordingRecallHandler : HttpMessageHandler
{
    private const string AutodiscoverResponseNamespace =
        "http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a";
    private static readonly XNamespace S = "http://schemas.xmlsoap.org/soap/envelope/";
    private static readonly XNamespace M = "http://schemas.microsoft.com/exchange/services/2006/messages";
    private static readonly XNamespace T = "http://schemas.microsoft.com/exchange/services/2006/types";

    public List<RecallCapturedRequest> Calls { get; } = [];
    public List<RecallReportFixture> Reports { get; } = [];
    public string SourceChangeKey { get; set; } = "source-change";
    public string SourceSubject { get; set; } = "Quarterly résumé";
    public string SourceParentFolderId { get; set; } = "sent-folder-id";
    public string ReturnedSourceId { get; set; } = "sent-message-1";
    public string SourceFrom { get; set; } = "alice@example.test";
    public string SourceSender { get; set; } = "alice@example.test";
    public string SourceItemClass { get; set; } = "IPM.Note";
    public IReadOnlyList<string> SourceTo { get; set; } = ["to@example.test", "second@example.test"];
    public IReadOnlyList<string> SourceCc { get; set; } = ["cc@example.test"];
    public IReadOnlyList<string> SourceBcc { get; set; } = ["bcc@example.test"];
    public bool SourceIsDraft { get; set; }
    public int? SourceCodePage { get; set; } = 1252;
    public Exception? SourceFailure { get; set; }
    public Action? AfterGetItem { get; set; }
    public string AutodiscoverSmtp { get; set; } = "alice@example.test";
    public string AutodiscoverLegacyDn { get; set; } = "o=Example/ou=Exchange Administrative Group/cn=Recipients/cn=alice";
    public string? AutodiscoverXml { get; set; }
    public bool TruncateReports { get; set; }
    public string? ReportIncludesLastItemInRange { get; set; } = "true";
    public bool ThrowOnCreate { get; set; }
    public bool AccessDeniedOnCreate { get; set; }
    public bool ReturnTrackingNoticeOnSearch { get; set; }
    public string NoticeItemId { get; set; } = "recall-notice-1";
    public string NoticeChangeKey { get; set; } = "notice-change";
    public string ReturnedTrackingId { get; set; } = "recall-notice-1";
    public string ReturnedTrackingChangeKey { get; set; } = "notice-change";
    public string TrackingItemClass { get; set; } = "IPM.Outlook.Recall";
    public bool TrackingIsDraft { get; set; }
    public string TrackingFrom { get; set; } = "alice@example.test";
    public string TrackingSender { get; set; } = "alice@example.test";
    public string TrackingSubject { get; set; } = "Quarterly résumé";
    public bool TrackingIncludeReportTag { get; set; } = true;
    public byte[] TrackingReportTag { get; set; } = [];
    public bool TrackingIncludeSearchKey { get; set; } = true;
    public byte[] TrackingSearchKey { get; set; } = [];
    public bool TrackingIncludeSubject { get; set; } = true;
    public IReadOnlyList<string> TrackingTo { get; set; } = ["to@example.test", "second@example.test"];
    public IReadOnlyList<string> TrackingCc { get; set; } = ["cc@example.test"];
    public IReadOnlyList<string> TrackingBcc { get; set; } = ["bcc@example.test"];
    public string TrackingRecipientRouting { get; set; } = "SMTP";
    public int CreateCount { get; private set; }
    public string SubmittedReportTag { get; private set; } = string.Empty;
    public byte[] SearchKey { get; } = Enumerable.Range(1, 16).Select(value => (byte)value).ToArray();
    public byte[] EntryId { get; } = Enumerable.Range(0x21, 12).Select(value => (byte)value).ToArray();
    public byte[] ParentEntryId { get; } = Enumerable.Range(0x31, 12).Select(value => (byte)value).ToArray();
    public byte[] StoreEntryId { get; } = Enumerable.Range(0, 66).Select(value => (byte)value).ToArray();

    public RecordingRecallHandler()
    {
        StoreEntryId[0] = 0x7A;
        StoreEntryId[60] = 0xEE;
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var body = request.Content is null ? string.Empty : await request.Content.ReadAsStringAsync(cancellationToken);
        if (request.RequestUri?.AbsolutePath.EndsWith("/Autodiscover/Autodiscover.xml", StringComparison.OrdinalIgnoreCase) == true)
        {
            Calls.Add(new RecallCapturedRequest("Autodiscover", body, request.Method, request.RequestUri));
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                RequestMessage = request,
                Content = new StringContent(AutodiscoverXml ?? BuildAutodiscoverResponse(AutodiscoverSmtp, AutodiscoverLegacyDn), Encoding.UTF8, "text/xml")
            };
        }

        var document = XDocument.Parse(body);
        var operation = document.Root!.Element(S + "Body")!.Elements().Single();
        var operationName = operation.Name.LocalName;
        Calls.Add(new RecallCapturedRequest(operationName, body, request.Method, request.RequestUri!));
        if (operationName == "GetItem" && SourceFailure is { } failure) throw failure;
        var response = operationName switch
        {
            "GetFolder" => SoapResponse(operationName, new XElement(M + "Folders", Folder())),
            "GetItem" => SoapResponse(operationName, new XElement(M + "Items",
                IsTrackingNoticeRequest(operation) ? TrackingNotice() : SourceMessage())),
            "CreateItem" => CreateResponse(operationName, operation),
            "FindItem" => FindResponse(operation),
            _ => SoapResponse(operationName)
        };
        if (operationName == "GetItem") AfterGetItem?.Invoke();
        return response;
    }

    private HttpResponseMessage CreateResponse(string operationName, XElement operation)
    {
        CreateCount++;
        SubmittedReportTag = operation.Descendants(T + "ExtendedProperty")
            .Select(element => element.Element(T + "ExtendedFieldURI"))
            .Where(field => field?.Attribute("PropertyTag")?.Value == "0x0031")
            .Select(field => field!.Parent!.Element(T + "Value")?.Value)
            .SingleOrDefault() ?? string.Empty;
        if (AccessDeniedOnCreate) return SoapResponse(operationName, responseCode: "ErrorAccessDenied");
        if (ThrowOnCreate) throw new HttpRequestException("synthetic uncertain recall write");
        return SoapResponse(operationName);
    }

    private HttpResponseMessage FindResponse(XElement operation)
    {
        if (operation.Descendants(T + "ExtendedFieldURI").Any(field => field.Attribute("PropertyTag")?.Value == "0x0031"))
        {
            var folder = operation.Descendants(T + "DistinguishedFolderId").SingleOrDefault()?.Attribute("Id")?.Value ?? string.Empty;
            var payload = new XElement(M + "RootFolder",
                new XElement(T + "Items", Reports.Where(report => report.Folder == folder).Select(Report)));
            var includesLastItemInRange = TruncateReports ? "false" : ReportIncludesLastItemInRange;
            if (includesLastItemInRange is not null)
                payload.SetAttributeValue("IncludesLastItemInRange", includesLastItemInRange);
            if (TruncateReports)
            {
                var offsetText = operation.Descendants(M + "IndexedPageItemView").SingleOrDefault()?.Attribute("Offset")?.Value;
                var offset = int.TryParse(offsetText, System.Globalization.NumberStyles.Integer,
                    System.Globalization.CultureInfo.InvariantCulture, out var parsedOffset) ? parsedOffset : 0;
                payload.SetAttributeValue("IndexedPagingOffset",
                    (offset + 20).ToString(System.Globalization.CultureInfo.InvariantCulture));
            }
            return SoapResponse("FindItem", payload);
        }

        var requestedFolder = operation.Descendants(T + "DistinguishedFolderId").SingleOrDefault()?.Attribute("Id")?.Value;
        return SoapResponse("FindItem", new XElement(M + "RootFolder",
            new XAttribute("IncludesLastItemInRange", "true"), new XElement(T + "Items",
                ReturnTrackingNoticeOnSearch && string.Equals(requestedFolder, "deleteditems", StringComparison.OrdinalIgnoreCase)
                    ? TrackingNotice(summaryOnly: true) : SourceMessage())));
    }

    private XElement Folder() => new(T + "Folder",
        new XElement(T + "FolderId", new XAttribute("Id", "sent-folder-id"), new XAttribute("ChangeKey", "folder-change")),
        new XElement(T + "DisplayName", "Sent Items"), new XElement(T + "TotalCount", "1"), new XElement(T + "UnreadCount", "0"),
        new XElement(T + "EffectiveRights", new XElement(T + "Read", true), new XElement(T + "CreateContents", false),
            new XElement(T + "Modify", false), new XElement(T + "Delete", false)));

    private XElement SourceMessage() => new(T + "Message",
        new XElement(T + "ItemId", new XAttribute("Id", ReturnedSourceId), new XAttribute("ChangeKey", SourceChangeKey)),
        new XElement(T + "ItemClass", SourceItemClass), new XElement(T + "IsDraft", SourceIsDraft),
        new XElement(T + "Subject", SourceSubject), new XElement(T + "ParentFolderId", new XAttribute("Id", SourceParentFolderId)),
        Mailbox("From", SourceFrom), Mailbox("Sender", SourceSender), Recipients("ToRecipients", SourceTo),
        Recipients("CcRecipients", SourceCc), Recipients("BccRecipients", SourceBcc),
        Extended("0xFFF", "Binary", EntryId), Extended("0xE09", "Binary", ParentEntryId),
        Extended("0xFFB", "Binary", StoreEntryId), Extended("0x300B", "Binary", SearchKey),
        SourceCodePage is null ? null : new XElement(T + "ExtendedProperty", new XElement(T + "ExtendedFieldURI", new XAttribute("PropertyTag", "0x3FFD"), new XAttribute("PropertyType", "Integer")), new XElement(T + "Value", SourceCodePage)));

    private bool IsTrackingNoticeRequest(XElement operation)
    {
        var itemId = operation.Descendants(T + "ItemId").SingleOrDefault()?.Attribute("Id")?.Value;
        return string.Equals(itemId, NoticeItemId, StringComparison.Ordinal);
    }

    private XElement TrackingNotice(bool summaryOnly = false)
    {
        var reportTag = TrackingReportTag.Length == 0 && SubmittedReportTag.Length > 0
            ? Convert.FromBase64String(SubmittedReportTag) : TrackingReportTag;
        var searchKey = TrackingSearchKey.Length == 0 ? SearchKey : TrackingSearchKey;
        var message = new XElement(T + "Message",
            new XElement(T + "ItemId", new XAttribute("Id", summaryOnly ? NoticeItemId : ReturnedTrackingId),
                new XAttribute("ChangeKey", summaryOnly ? NoticeChangeKey : ReturnedTrackingChangeKey)),
            new XElement(T + "ItemClass", TrackingItemClass), new XElement(T + "IsDraft", TrackingIsDraft),
            Mailbox("From", TrackingFrom), Mailbox("Sender", TrackingSender),
            TrackingRecipients("ToRecipients", TrackingTo), TrackingRecipients("CcRecipients", TrackingCc), TrackingRecipients("BccRecipients", TrackingBcc));
        if (!summaryOnly)
        {
            if (TrackingIncludeReportTag) message.Add(Extended("0x0031", "Binary", reportTag));
            if (TrackingIncludeSearchKey) message.Add(Extended("0x6800", "Binary", searchKey));
            if (TrackingIncludeSubject) message.Add(Extended("0x0E1D", "String", TrackingSubject));
        }
        else
        {
            message.Add(new XElement(T + "Subject", "Recall: " + TrackingSubject),
                new XElement(T + "DateTimeReceived", "2026-10-11T10:00:00Z"));
        }

        return message;
    }

    private static XElement Report(RecallReportFixture report) => new(T + "Message",
        new XElement(T + "ItemId", new XAttribute("Id", report.Id), new XAttribute("ChangeKey", "report-change")),
        new XElement(T + "ItemClass", report.ItemClass), new XElement(T + "Subject", report.Subject),
        new XElement(T + "DateTimeReceived", report.ReceivedUtc), Extended("0x31", "Binary", report.ReportTag));

    private static XElement Mailbox(string name, string address) => new(T + name,
        new XElement(T + "Mailbox", new XElement(T + "EmailAddress", address), new XElement(T + "RoutingType", "SMTP")));

    private static XElement Recipients(string name, IReadOnlyList<string> addresses) => new(T + name,
        addresses.Select(address => new XElement(T + "Mailbox", new XElement(T + "EmailAddress", address), new XElement(T + "RoutingType", "SMTP"))));

    private XElement TrackingRecipients(string name, IReadOnlyList<string> addresses) => new(T + name,
        addresses.Select(address => new XElement(T + "Mailbox", new XElement(T + "EmailAddress", address),
            new XElement(T + "RoutingType", TrackingRecipientRouting))));

    private static XElement Extended(string tag, string type, byte[] value) => new(T + "ExtendedProperty",
        new XElement(T + "ExtendedFieldURI", new XAttribute("PropertyTag", tag), new XAttribute("PropertyType", type)),
        new XElement(T + "Value", Convert.ToBase64String(value)));

    private static XElement Extended(string tag, string type, string value) => new(T + "ExtendedProperty",
        new XElement(T + "ExtendedFieldURI", new XAttribute("PropertyTag", tag), new XAttribute("PropertyType", type)),
        new XElement(T + "Value", value));

    private static HttpResponseMessage SoapResponse(string operationName, XElement? payload = null,
        string responseCode = "NoError")
    {
        var document = new XDocument(new XElement(S + "Envelope", new XAttribute(XNamespace.Xmlns + "s", S),
            new XAttribute(XNamespace.Xmlns + "m", M), new XAttribute(XNamespace.Xmlns + "t", T),
            new XElement(S + "Body", new XElement(M + (operationName + "Response"),
                new XElement(M + "ResponseMessages", new XElement(M + (operationName + "ResponseMessage"),
                    new XAttribute("ResponseClass", responseCode == "NoError" ? "Success" : "Error"),
                    new XElement(M + "ResponseCode", responseCode), payload))))));
        return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(document.ToString(SaveOptions.DisableFormatting), Encoding.UTF8, "text/xml") };
    }

    private static string BuildAutodiscoverResponse(string smtp, string legacyDn) =>
        $"<a:Autodiscover xmlns:a='{AutodiscoverResponseNamespace}'><a:Response><a:User>"
        + $"<a:AutoDiscoverSMTPAddress>{System.Security.SecurityElement.Escape(smtp)}</a:AutoDiscoverSMTPAddress>"
        + $"<a:LegacyDN>{System.Security.SecurityElement.Escape(legacyDn)}</a:LegacyDN>"
        + "</a:User></a:Response></a:Autodiscover>";
}
