using System.Net;
using System.Text.Json;
using System.Xml;
using System.Xml.Linq;
using Company.ExchangeMcp.Exchange;
using Company.ExchangeMcp.Security;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

// A read-only operator check: its HTTP handler refuses every operation except folder metadata reads.
internal static class LiveDiscoveryProbe
{
    public static async Task<int> RunAsync(string configPath, string actorMailbox, string targetMailbox)
    {
        try
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(3));
            var configuration = new ConfigurationBuilder().AddJsonFile(Path.GetFullPath(configPath))
                .AddEnvironmentVariables().Build();
            var directory = configuration.GetSection("DirectoryPermissions").Get<DirectoryPermissionOptions>() ?? new();
            var options = configuration.GetSection("Exchange").Get<EwsOptions>() ?? new();
            var settings = configuration.GetSection("Service").Get<ServiceOptions>() ?? new();
            var factory = new LdapSearchFacadeFactory(Options.Create(directory), Options.Create(options));
            var reader = new LdapMailboxPermissionReader(Options.Create(directory), factory,
                NullLogger<LdapMailboxPermissionReader>.Instance, Options.Create(options));
            var candidates = await ((IMailboxDirectory)reader).ListAsync(deadline.Token);
            var catalogProbe = targetMailbox == "@catalog";
            if (catalogProbe) targetMailbox = actorMailbox;
            MailboxDirectoryCandidate candidate;
            if (targetMailbox == "@unassigned")
            {
                MailboxDirectoryCandidate? found = null;
                foreach (var entry in candidates.Where(value => value.RecipientTypeDetails == 1
                    && !value.Mailbox.Equals(actorMailbox, StringComparison.OrdinalIgnoreCase))
                    .OrderBy(value => value.Mailbox, StringComparer.OrdinalIgnoreCase).Take(8))
                {
                    var check = await reader.ReadAsync(new MailboxIdentity("read-only-probe", entry.Mailbox,
                        "read-only-probe", "probe", entry.Key, actorMailbox), deadline.Token);
                    if (check.FullAccess.State == "denied") { found = entry; break; }
                }
                candidate = found ?? throw new InvalidOperationException("No bounded negative-control candidate was found.");
                targetMailbox = candidate.Mailbox;
            }
            else candidate = candidates.Single(value => value.Mailbox.Equals(targetMailbox, StringComparison.OrdinalIgnoreCase));
            var identity = new MailboxIdentity("read-only-probe", targetMailbox, "read-only-probe", "probe",
                candidate.Key, actorMailbox);
            if (!catalogProbe)
            {
                var permissions = await reader.ReadAsync(identity, deadline.Token);
                Console.WriteLine(JsonSerializer.Serialize(new { permissions.FullAccess, permissions.SendAs, permissions.SendOnBehalf }));
            }
            settings.Mailboxes = new(StringComparer.Ordinal) { ["read-only-probe"] = actorMailbox };
            settings.AutoEnrollmentEnabled = false;
            settings.WritesEnabled = false;
            settings.SendEnabled = false;
            var access = new MailboxAccess(Options.Create(settings));
            var password = File.ReadAllText(options.PasswordFile).TrimEnd('\r', '\n');
            using var transport = new HttpClientHandler
            {
                Credentials = new NetworkCredential(options.Username, password, options.Domain),
                AllowAutoRedirect = false,
                UseCookies = false
            };
            password = string.Empty;
            using var diagnostics = new MetadataOnlyHandler(actorMailbox) { InnerHandler = transport, Verbose = !catalogProbe };
            using var http = new HttpClient(diagnostics);
            var client = new EwsClient(http, Options.Create(options), access, reader);
            if (catalogProbe)
            {
                var discovery = new MailboxDiscovery(access, reader, reader, client, NullLogger<MailboxDiscovery>.Instance);
                var actorIdentity = identity with { Mailbox = actorMailbox, ActorMailbox = actorMailbox, TargetId = "own" };
                MailboxDiscoverySnapshot result = null!;
                for (var pass = 0; pass < 12; pass++)
                {
                    result = await discovery.DiscoverAsync(actorIdentity, deadline.Token);
                    Console.WriteLine(JsonSerializer.Serialize(new
                    {
                        pass = pass + 1,
                        result.Complete,
                        result.CatalogScanComplete,
                        result.CandidateCount,
                        result.ScannedCount,
                        result.PermissionCheckFailures,
                        result.IncompleteFolderTargets,
                        result.CapacityLimited,
                        result.CatalogFailures,
                        targets = result.Targets.Count
                    }));
                    if (result.CatalogScanComplete) break;
                    await Task.Delay(TimeSpan.FromSeconds(6), deadline.Token);
                }
                var progressMap = typeof(MailboxDiscovery).GetField("progressByActor",
                    System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!.GetValue(discovery)!;
                var values = (System.Collections.IEnumerable)progressMap.GetType().GetProperty("Values")!.GetValue(progressMap)!;
                var progress = values.Cast<object>().Single();
                var candidateRows = (MailboxDirectoryCandidate[])progress.GetType().GetProperty("Candidates")!.GetValue(progress)!;
                var incomplete = (bool[])progress.GetType().GetProperty("FolderIncomplete")!.GetValue(progress)!;
                Console.WriteLine(JsonSerializer.Serialize(new
                {
                    incompleteBuckets = candidateRows
                    .Where((_, index) => incomplete[index])
                    .GroupBy(row => new
                    {
                        row.RecipientTypeDetails,
                        companyPrimary = settings.AllowedRecipientDomains.Contains(
                        row.Mailbox[(row.Mailbox.LastIndexOf('@') + 1)..], StringComparer.OrdinalIgnoreCase)
                    })
                    .Select(group => new { group.Key.RecipientTypeDetails, group.Key.companyPrimary, count = group.Count() }).ToArray()
                }));
                foreach (var row in candidateRows.Where((_, index) => incomplete[index])
                    .Where(row => row.RecipientTypeDetails == 1 && settings.AllowedRecipientDomains.Contains(
                        row.Mailbox[(row.Mailbox.LastIndexOf('@') + 1)..], StringComparer.OrdinalIgnoreCase)))
                {
                    diagnostics.InspectAnomalies = true;
                    using var rowSelection = access.SelectTarget(identity with { Mailbox = row.Mailbox, TargetId = row.Key });
                    var method = typeof(EwsClient).GetMethod("DiscoverMailboxFolderMetadataAsync",
                        System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!;
                    var metadata = await (Task<EwsMailboxFolderDiscovery>)method.Invoke(client,
                        [row, deadline.Token])!;
                    Console.WriteLine(JsonSerializer.Serialize(new
                    {
                        stage = "incomplete_company_user_metadata",
                        metadata.Complete,
                        folders = metadata.Folders.Count
                    }));
                    diagnostics.InspectAnomalies = false;
                }
                Console.WriteLine(JsonSerializer.Serialize(new { responseCodes = diagnostics.ResponseCodes }));
                return result.CatalogScanComplete ? 0 : 1;
            }
            using var selected = access.SelectTarget(identity);
            var actor = await client.DiscoverMailboxFoldersAsync(targetMailbox, deadline.Token);
            Console.WriteLine(JsonSerializer.Serialize(new { stage = "actor", actor.Complete, folders = actor.Folders.Count }));
            if (candidate.RecipientTypeDetails is 1 or 4 or 16 or 32)
            {
                var method = typeof(EwsClient).GetMethod("DiscoverMailboxFolderMetadataAsync",
                    System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!;
                var metadata = await (Task<EwsMailboxFolderDiscovery>)method.Invoke(client,
                    [candidate, deadline.Token])!;
                var verified = await client.GetMailboxFolderRightsAsync(targetMailbox, metadata.Folders.Select(folder => folder.Id).ToArray(), deadline.Token);
                Console.WriteLine(JsonSerializer.Serialize(new
                {
                    stage = "metadata_rechecked_as_actor",
                    metadata.Complete,
                    metadataFolders = metadata.Folders.Count,
                    accessibleFolders = verified.Count
                }));
            }
            return 0;
        }
        catch (Exception exception)
        {
            Console.WriteLine(JsonSerializer.Serialize(new { failureType = exception.GetType().Name }));
            return 1;
        }
    }

    private sealed class MetadataOnlyHandler(string actorMailbox) : DelegatingHandler
    {
        public bool Verbose { get; init; } = true;
        public bool InspectAnomalies { get; set; }
        private readonly Dictionary<string, XElement> inspectedFolders = new(StringComparer.Ordinal);
        public System.Collections.Concurrent.ConcurrentDictionary<string, int> ResponseCodes { get; } = new(StringComparer.Ordinal);
        private static readonly XNamespace Soap = "http://schemas.xmlsoap.org/soap/envelope/";
        private static readonly XNamespace Messages = "http://schemas.microsoft.com/exchange/services/2006/messages";
        private static readonly XNamespace Types = "http://schemas.microsoft.com/exchange/services/2006/types";

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var sent = Parse(await request.Content!.ReadAsStringAsync(cancellationToken));
            var operation = sent.Descendants(Soap + "Body").Elements().Single().Name.LocalName;
            if (operation is not ("GetFolder" or "FindFolder")) throw new InvalidOperationException("Read-only metadata probe blocked an operation.");
            var actor = sent.Descendants(Types + "ConnectingSID").Descendants(Types + "PrimarySmtpAddress").SingleOrDefault()?.Value;
            var response = await base.SendAsync(request, cancellationToken);
            await response.Content.LoadIntoBufferAsync(16 * 1024 * 1024, cancellationToken);
            var received = Parse(await response.Content.ReadAsStringAsync(cancellationToken));
            var root = received.Descendants(Messages + "RootFolder").SingleOrDefault();
            foreach (var code in received.Descendants(Messages + "ResponseCode"))
                if (code.Value.Length <= 100 && code.Value.All(char.IsAsciiLetterOrDigit))
                    ResponseCodes.AddOrUpdate(code.Value, 1, (_, count) => count + 1);
            if (InspectAnomalies)
            {
                var parse = typeof(EwsClient).GetMethod("ParseFolderElement", System.Reflection.BindingFlags.Static
                    | System.Reflection.BindingFlags.NonPublic)!;
                foreach (var folder in received.Descendants().Where(element => element.Parent?.Name is var parent
                    && (parent == Types + "Folders" || parent == Messages + "Folders")
                    && element.Element(Types + "FolderId") is not null))
                {
                    object?[] arguments = [folder, null, false];
                    _ = parse.Invoke(null, arguments);
                    var id = (string?)folder.Element(Types + "FolderId")?.Attribute("Id") ?? string.Empty;
                    if (!(bool)arguments[2]!) Console.WriteLine(JsonSerializer.Serialize(new
                    {
                        stage = "invalid_folder_metadata",
                        nameMissing = string.IsNullOrWhiteSpace(folder.Element(Types + "DisplayName")?.Value),
                        nameLength = folder.Element(Types + "DisplayName")?.Value.Length,
                        nameControls = folder.Element(Types + "DisplayName")?.Value.Any(char.IsControl),
                        classLength = folder.Element(Types + "FolderClass")?.Value.Length,
                        rightsFields = folder.Element(Types + "EffectiveRights")?.Elements().Count()
                    }));
                    if (inspectedFolders.TryGetValue(id, out var previous))
                        Console.WriteLine(JsonSerializer.Serialize(new
                        {
                            stage = "repeated_folder_metadata",
                            sameName = previous.Element(Types + "DisplayName")?.Value == folder.Element(Types + "DisplayName")?.Value,
                            sameClass = previous.Element(Types + "FolderClass")?.Value == folder.Element(Types + "FolderClass")?.Value,
                            sameRights = XNode.DeepEquals(previous.Element(Types + "EffectiveRights"), folder.Element(Types + "EffectiveRights"))
                        }));
                    else inspectedFolders.Add(id, folder);
                }
            }
            if (Verbose) Console.WriteLine(JsonSerializer.Serialize(new
            {
                operation,
                context = string.Equals(actor, actorMailbox, StringComparison.OrdinalIgnoreCase) ? "actor" : "metadata_owner",
                http = (int)response.StatusCode,
                codes = received.Descendants(Messages + "ResponseCode").Select(element =>
                    element.Value.Length <= 100 && element.Value.All(char.IsAsciiLetterOrDigit) ? element.Value : "invalid_code").ToArray(),
                faultCodes = received.Descendants().Where(element => element.Name.LocalName == "faultcode")
                    .Select(element => element.Value.Split(':').Last()).Where(value => value.Length <= 100
                        && value.All(char.IsAsciiLetterOrDigit)).ToArray(),
                folders = received.Descendants(Types + "FolderId").Count(),
                effectiveRights = received.Descendants(Types + "EffectiveRights").Count(),
                includesLast = (string?)root?.Attribute("IncludesLastItemInRange"),
                hasNextOffset = root?.Attribute("IndexedPagingOffset") is not null
            }));
            return response;
        }

        private static XDocument Parse(string text)
        {
            using var input = new StringReader(text);
            using var xml = XmlReader.Create(input, new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null });
            return XDocument.Load(xml);
        }
    }
}
