using System.Net;
using System.Text.Json;
using System.Xml.Linq;
using Company.ExchangeMcp.Exchange;
using Company.ExchangeMcp.Security;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;

// Explicit operator-only qualification in the existing checks executable; creates no mailbox items or application endpoints.
internal static class LiveMailStreamingProbe
{
    public static async Task<int> RunAsync(string configPath, string ownMailbox, string disposableSubjectPrefix)
    {
        if (disposableSubjectPrefix.Length is < 16 or > 100 || !disposableSubjectPrefix.StartsWith("MCP-STREAM-", StringComparison.Ordinal))
            return 2;
        string? subscription = null;
        using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(3));
        var counts = new Dictionary<string, int>(StringComparer.Ordinal) { ["to"] = 0, ["cc"] = 0, ["unknown"] = 0 };
        var notifications = 0;
        var reconciliations = 0;
        var unsubscribeConfirmed = false;
        try
        {
            var configuration = new ConfigurationBuilder().AddJsonFile(Path.GetFullPath(configPath)).AddEnvironmentVariables().Build();
            var options = configuration.GetSection("Exchange").Get<EwsOptions>() ?? new();
            var settings = new ServiceOptions { Mailboxes = new(StringComparer.Ordinal) { ["streaming-probe"] = ownMailbox } };
            var access = new MailboxAccess(Options.Create(settings));
            var identity = new MailboxIdentity("streaming-probe", ownMailbox, "streaming-probe", "probe", "own", ownMailbox);
            using var selected = access.SelectTarget(identity);
            using var handler = new ProbeHandler(ownMailbox)
            {
                InnerHandler = new HttpClientHandler
                {
                    Credentials = new NetworkCredential(options.Username, File.ReadAllText(options.PasswordFile).TrimEnd('\r', '\n'), options.Domain),
                    AllowAutoRedirect = false,
                    UseCookies = false,
                    AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate
                }
            };
            using var http = new HttpClient(handler) { Timeout = Timeout.InfiniteTimeSpan };
            var client = new EwsClient(http, Options.Create(options), access);
            try
            {
                var rights = await client.GetEffectiveRightsAsync(ownMailbox, "inbox", deadline.Token);
                if (rights.Read != true) throw new InvalidOperationException("Own Inbox read rights were not verified.");
                var baselineService = new Company.ExchangeMcp.MailEventService(client, access, null!, null!, Options.Create(settings));
                var state = await baselineService.ReadCompleteBaselineAsync(ownMailbox, deadline.Token);
                subscription = await client.SubscribeInboxStreamingAsync(ownMailbox, deadline.Token);
                var seen = new HashSet<string>(StringComparer.Ordinal);
                async Task Reconcile(CancellationToken token)
                {
                    reconciliations++;
                    for (var pageNumber = 0; pageNumber < 64; pageNumber++)
                    {
                        var page = await client.SyncItemsAsync(ownMailbox, "inbox", state, 32, token);
                        foreach (var change in page.Changes.Where(change => change.Change == "Create" && change.Kind == "message"))
                        {
                            var message = await client.GetMessageSummaryAsync(ownMailbox, change.Id, token);
                            if (!message.Subject.StartsWith(disposableSubjectPrefix, StringComparison.Ordinal) || !seen.Add(change.Id)) continue;
                            var role = message.To.Contains(ownMailbox, StringComparer.OrdinalIgnoreCase) ? "to"
                                : message.Cc.Contains(ownMailbox, StringComparer.OrdinalIgnoreCase) ? "cc" : "unknown";
                            counts[role]++;
                        }
                        state = page.State;
                        if (page.IncludesLastChange) break;
                    }
                    Console.WriteLine(JsonSerializer.Serialize(new { stage = "reconciled", notifications, reconciliations, roles = counts }));
                }
                await Reconcile(deadline.Token);
                Console.WriteLine(JsonSerializer.Serialize(new { stage = "stream_ready", bodyReads = 0, timeoutSeconds = 180 }));
                while (!deadline.IsCancellationRequested && (counts["to"] == 0 || counts["cc"] == 0))
                    await client.ReadInboxStreamingAsync(ownMailbox, subscription, http, async token =>
                    {
                        notifications++;
                        await Reconcile(token);
                        if (counts["to"] > 0 && counts["cc"] > 0) deadline.Cancel();
                    }, deadline.Token);
            }
            catch (OperationCanceledException) when (deadline.IsCancellationRequested) { }
            finally
            {
                if (subscription is not null)
                {
                    using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                    await client.UnsubscribeStreamingAsync(ownMailbox, subscription, cleanup.Token);
                    unsubscribeConfirmed = true;
                }
            }
        }
        catch (OperationCanceledException) when (deadline.IsCancellationRequested) { }
        catch (Exception exception)
        {
            Console.WriteLine(JsonSerializer.Serialize(new
            {
                stage = "failure",
                failureType = exception.GetType().Name,
                responseCode = (exception as EwsRequestFailedException)?.ResponseCode
            }));
        }
        Console.WriteLine(JsonSerializer.Serialize(new
        {
            stage = "complete",
            notifications,
            reconciliations,
            roles = counts,
            unsubscribeConfirmed,
            bodyReads = 0,
            sentMessages = 0
        }));
        return notifications > 0 && counts["to"] > 0 && counts["cc"] > 0 && unsubscribeConfirmed ? 0 : 1;
    }

    private sealed class ProbeHandler(string ownMailbox) : DelegatingHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var xml = XDocument.Parse(await request.Content!.ReadAsStringAsync(cancellationToken));
            XNamespace soap = "http://schemas.xmlsoap.org/soap/envelope/";
            XNamespace types = "http://schemas.microsoft.com/exchange/services/2006/types";
            var operation = xml.Root!.Element(soap + "Body")!.Elements().Single();
            if (operation.Name.LocalName is not ("Subscribe" or "Unsubscribe" or "GetStreamingEvents" or "GetFolder" or "SyncFolderItems" or "GetItem")
                || request.Headers.GetValues("X-AnchorMailbox").Single() != ownMailbox
                || xml.Descendants(types + "PrimarySmtpAddress").Single().Value != ownMailbox
                || operation.Descendants(types + "FieldURI").Any(field => (string?)field.Attribute("FieldURI") is "item:Body" or "item:Attachments"))
                throw new InvalidOperationException("Live streaming probe refused an operation outside own Inbox notification qualification.");
            return await base.SendAsync(request, cancellationToken);
        }
    }
}
