using System.Net;
using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Xml.Linq;
using Company.ExchangeMcp;
using Company.ExchangeMcp.Exchange;
using Company.ExchangeMcp.Security;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

internal sealed partial class Checks
{
    private async Task TaskNoticeProcessingChecksAsync()
    {
        AssertTaskNoticeActorConfiguration();
        await AssertTaskNoticeShutdownCancellationAsync();
        await AssertTaskNoticePollingAndProcessedFilterAsync();
        await AssertDuplicateRoutesSelectOnePermittedActorAsync();
        await AssertAllEnrolledTargetSelectionAsync();
        await AssertFolderRightsDiscoverTargetsWithoutLegacyMappingsAsync();
        await AssertTaskNoticeUsesFreshFolderRightsAsync();
        await AssertLegacyTaskNoticeStateMigrationAsync();
        await AssertAutomaticTaskNoticeDoesNotAcceptNewRequestsAsync();
        await AssertTaskNoticeWorkerGatesAsync();
        await AssertStaleTaskNoticeCursorsArePrunedAsync();
        await AssertCandidateBookmarkAndShrinkingQueryWrapAsync();
        await AssertCandidateBookmarkSkipsTwentyOrdinaryRequestsAsync();
        await AssertCandidateBookmarkScansAcrossSixHundredNoticesAsync();
        await AssertTemporaryTaskNoticeFailureRecoversAsync();
        await AssertPendingTaskNoticeSurvivesRestartAsync();
        await AssertDelegatedTaskRouteSurvivesExpiredDiscoveryAcrossMailboxRotationAsync();
        await AssertSharedMailboxPendingStateIsActorIndependentAsync();
        await AssertDelegatedRightsRevocationStopsBeforePendingAsync();
        await AssertTaskNoticeStateSaturationStopsBeforeWriteAsync();
    }

    private async Task AssertTaskNoticeShutdownCancellationAsync()
    {
        var options = NewTaskNoticeOptions(Path.Combine(runDirectory, "task-notice-shutdown-audit.jsonl"),
            [], writesEnabled: false);
        using var provider = new ServiceCollection().BuildServiceProvider();
        using var processor = new TaskNoticeProcessor(Options.Create(options),
            provider.GetRequiredService<IServiceScopeFactory>(), NullLogger<TaskNoticeProcessor>.Instance);
        await processor.StartAsync(CancellationToken.None);
        await Task.Yield();
        await processor.StopAsync(CancellationToken.None);
        Expect(processor.ExecuteTask?.IsCompletedSuccessfully == true,
            "Normal task-worker shutdown surfaced its timer cancellation as a background-service failure.");
    }

    private void AssertTaskNoticeActorConfiguration()
    {
        var secret = Path.Combine(runDirectory, "task-notice-config-secret.txt");
        File.WriteAllText(secret, "synthetic-secret");
        ServiceOptions NewOptions() => new()
        {
            Authority = Authority,
            Resource = Resource,
            IntrospectionClientId = Resource,
            IntrospectionSecretFile = secret,
            AllowedClientIds = ["company-mail-test"],
            Mailboxes = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["user-a"] = "alice@example.test"
            },
            AuditPath = Path.Combine(runDirectory, "task-notice-config-audit.jsonl")
        };

        var disabledByDefault = NewOptions();
        Expect(disabledByDefault.TaskNoticeProcessingActors.Length == 0
            && !disabledByDefault.TaskNoticeProcessingAllEnrolledUsers && disabledByDefault.IsValid(),
            "Automatic task processing was not disabled by default.");

        var optedIn = NewOptions();
        optedIn.TaskNoticeProcessingActors = ["ALICE@example.test"];
        Expect(optedIn.IsValid(), "A uniquely configured actor could not opt in to task notice processing.");

        var allEnrolled = NewOptions();
        allEnrolled.TaskNoticeProcessingAllEnrolledUsers = true;
        allEnrolled.Mailboxes["user-b"] = "bob@example.test";
        Expect(allEnrolled.TaskNoticeProcessingActors.Length == 0 && allEnrolled.IsValid(),
            "All-enrolled processing required a separate actor list or rejected configured mailbox identities.");

        var duplicate = NewOptions();
        duplicate.TaskNoticeProcessingActors = ["alice@example.test", "ALICE@example.test"];
        Expect(!duplicate.IsValid(), "Duplicate automatic task-processing actors were accepted.");

        var missingRoute = NewOptions();
        missingRoute.TaskNoticeProcessingActors = ["unconfigured@example.test"];
        Expect(!missingRoute.IsValid(), "An automatic task-processing actor without a mailbox route was accepted.");

        var ambiguousRoute = NewOptions();
        ambiguousRoute.Mailboxes["user-b"] = "alice@example.test";
        ambiguousRoute.TaskNoticeProcessingActors = ["alice@example.test"];
        Expect(!ambiguousRoute.IsValid(), "An actor SMTP address mapped to multiple identities was accepted.");
    }

    private async Task AssertTaskNoticePollingAndProcessedFilterAsync()
    {
        var handler = new TaskAssignmentRecordingHandler();
        var client = NewEwsClient(handler);

        await client.ListTaskAssignmentMessagesAsync("alice@example.test", 0, 20, CancellationToken.None);
        var interactive = Operation(XDocument.Parse(handler.Calls.Last(call => call.Operation == "FindItem").Body));
        var interactiveRestriction = interactive.Element(XName.Get("Restriction", MessagesNamespace))!;
        Expect(!interactiveRestriction.Descendants(XName.Get("ExtendedFieldURI", TypesNamespace))
                .Any(field => (string?)field.Attribute("PropertyTag") == "0x7D01"),
            "The existing interactive task-message listing unexpectedly acquired the background processed filter.");

        await client.ListUnprocessedTaskAssignmentMessagesAsync(
            "alice@example.test", 0, 20, CancellationToken.None);
        var automatic = Operation(XDocument.Parse(handler.Calls.Last(call => call.Operation == "FindItem").Body));
        var restriction = automatic.Element(XName.Get("Restriction", MessagesNamespace))?.Elements().Single();
        var and = restriction?.Name == XName.Get("And", TypesNamespace) ? restriction : null;
        var classFilter = and?.Elements(XName.Get("Or", TypesNamespace)).FirstOrDefault();
        var processedFilter = and?.Elements(XName.Get("Or", TypesNamespace)).Skip(1).SingleOrDefault();
        Expect(and is not null && classFilter?.Elements(XName.Get("IsEqualTo", TypesNamespace)).Count() == 4
            && processedFilter?.Elements(XName.Get("Not", TypesNamespace)).SingleOrDefault()?
                .Element(XName.Get("Exists", TypesNamespace))?.Element(XName.Get("ExtendedFieldURI", TypesNamespace))?
                .Attribute("PropertyTag")?.Value == "0x7D01"
            && processedFilter.Elements(XName.Get("IsEqualTo", TypesNamespace)).SingleOrDefault()?
                .Element(XName.Get("ExtendedFieldURI", TypesNamespace))?.Attribute("PropertyTag")?.Value == "0x7D01"
            && processedFilter.Elements(XName.Get("IsEqualTo", TypesNamespace)).SingleOrDefault()?
                .Element(XName.Get("FieldURIOrConstant", TypesNamespace))?
                .Element(XName.Get("Constant", TypesNamespace))?.Attribute("Value")?.Value == "false",
            "Automatic polling did not use the exact task-notice classes plus server-side unprocessed filter.");

        var rightsHandler = new TaskNoticeRightsProbeHandler(tasksModify: true);
        var rightsClient = NewEwsClient(rightsHandler);
        var rights = await rightsClient.GetEffectiveRightsAsync("alice@example.test", "tasks", CancellationToken.None);
        Expect(rights.Read == true && rights.Modify == true
            && rightsHandler.LastFolderId == "tasks"
            && rightsHandler.LastBody.Contains("DistinguishedFolderId", StringComparison.Ordinal)
            && rightsHandler.LastBody.Contains("Id=\"tasks\"", StringComparison.Ordinal),
            "The task-folder rights probe did not use Exchange's distinguished Tasks folder alias.");
    }

    private async Task AssertAutomaticTaskNoticeDoesNotAcceptNewRequestsAsync()
    {
        var ordinary = new TaskAssignmentRecordingHandler();
        var client = NewEwsClient(ordinary);
        var action = await client.PrepareTaskProcessAsync(
            "alice@example.test", "request-1", CancellationToken.None, skipOrdinaryRequest: true);
        Expect(action is null && ordinary.CreateItemCount == 0 && ordinary.UpdateItemCount == 0,
            "Automatic processing did not skip a genuine To task request before any write.");

        var alreadyProcessed = new TaskAssignmentRecordingHandler
        {
            Mode = TaskAssignmentFixtureMode.Processed,
            ProcessMessage = true,
            NativeAcceptedResponse = true,
            ReturnLocalTaskForFind = true,
            TaskRequestVersion = 3,
            TaskVersion = 3,
            LocalTaskVersion = 4
        };
        await AssertThrowsAsync<InvalidOperationException>(() => NewEwsClient(alreadyProcessed).PrepareTaskProcessAsync(
            "alice@example.test", "request-1", CancellationToken.None, skipOrdinaryRequest: true));
        Expect(alreadyProcessed.CreateItemCount == 0 && alreadyProcessed.UpdateItemCount == 0,
            "An already processed older native handoff reached the tracker write path.");
    }

    private async Task AssertDuplicateRoutesSelectOnePermittedActorAsync()
    {
        var auditPath = Path.Combine(runDirectory, "task-notice-duplicate-routes.jsonl");
        var secret = Path.Combine(runDirectory, "task-notice-duplicate-routes-secret.txt");
        File.WriteAllText(secret, "synthetic-secret");
        var options = new ServiceOptions
        {
            Authority = Authority,
            Resource = Resource,
            IntrospectionClientId = Resource,
            IntrospectionSecretFile = secret,
            AllowedClientIds = ["company-mail-test"],
            Mailboxes = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["user-a"] = "alice@example.test",
                ["user-b"] = "bob@example.test"
            },
            TaskNoticeProcessingActors = ["alice@example.test", "bob@example.test"],
            WritesEnabled = true,
            AuditPath = auditPath
        };
        var handler = new TaskNoticeRightsProbeHandler(tasksModify: true);
        var permission = new SyntheticPermissionReader(new MailboxPermissionReport(
            new PermissionDecision("allowed", "synthetic grant", Direct: true),
            PermissionDecision.Unknown("not used"), PermissionDecision.Unknown("not used"),
            DateTimeOffset.UtcNow, "synthetic-task-notice-permissions"));
        var httpClients = new List<HttpClient>();
        var services = new ServiceCollection();
        services.AddScoped(_ => new MailboxAccess(Options.Create(options)));
        services.AddScoped(serviceProvider =>
        {
            var http = new HttpClient(handler);
            httpClients.Add(http);
            return new EwsClient(http, Options.Create(new EwsOptions
            {
                Endpoint = "https://mail.example.test/EWS/Exchange.asmx",
                TimeoutSeconds = 10,
                MaxResponseBytes = 2_097_152
            }), serviceProvider.GetRequiredService<MailboxAccess>());
        });
        services.AddScoped(_ => new AuditLog(Options.Create(options)));
        services.AddSingleton<IMailboxPermissionReader>(permission);
        var discovery = new TestMailboxDiscovery(false, "user-a", "user-b");
        discovery.AddTarget("user-a", SharedMailboxKey, "shared@example.test");
        discovery.AddTarget("user-b", SharedMailboxKey, "shared@example.test");
        services.AddSingleton<IMailboxDiscovery>(discovery);
        services.AddSingleton<IMailboxDirectory>(discovery);
        using var provider = services.BuildServiceProvider();
        var processor = new TaskNoticeProcessor(Options.Create(options),
            provider.GetRequiredService<IServiceScopeFactory>(), NullLogger<TaskNoticeProcessor>.Instance);
        await processor.RunOnceAsync();

        var sharedFolders = handler.FolderIds.Zip(handler.FolderTargetMailboxes)
            .Zip(handler.FolderActorMailboxes)
            .Where(entry => string.Equals(entry.First.Second, "shared@example.test", StringComparison.OrdinalIgnoreCase))
            .Select(entry => (Folder: entry.First.First, Actor: entry.Second)).ToArray();
        Expect(permission.Calls == 0
            && sharedFolders.Select(entry => entry.Folder).SequenceEqual(["inbox", "tasks"])
            && sharedFolders.All(entry => entry.Actor == "alice@example.test")
            && handler.FindItemCalls == 3
            && handler.FindItemTargetMailboxes
                .Select(mailbox => mailbox.ToLowerInvariant())
                .Distinct(StringComparer.Ordinal)
                .OrderBy(mailbox => mailbox, StringComparer.Ordinal)
                .SequenceEqual(["alice@example.test", "bob@example.test", "shared@example.test"])
            && handler.UpdateItemCalls == 0 && handler.CreateItemCalls == 0,
            $"A duplicated delegated mailbox was not assigned once to the first deterministically permitted actor while retaining each actor's own mailbox scan: permissionCalls={permission.Calls}, sharedFolders={string.Join(',', sharedFolders.Select(entry => $"{entry.Folder}/{entry.Actor}"))}, findTargets={string.Join(',', handler.FindItemTargetMailboxes)}, updates={handler.UpdateItemCalls}, creates={handler.CreateItemCalls}.");
        foreach (var http in httpClients) http.Dispose();
    }

    private async Task AssertAllEnrolledTargetSelectionAsync()
    {
        var rotationOptions = NewTaskNoticeOptions(
            Path.Combine(runDirectory, "task-notice-all-enrolled-rotation.jsonl"), [], writesEnabled: true);
        rotationOptions.TaskNoticeProcessingAllEnrolledUsers = true;
        rotationOptions.Mailboxes.Clear();
        for (var index = 0; index < 20; index++)
            rotationOptions.Mailboxes[$"user-{index:D2}"] = $"user{index:D2}@example.test";
        var rotationHandler = new TaskNoticeRightsProbeHandler(tasksModify: true);
        var rotationClients = new List<HttpClient>();
        using (var provider = CreateTaskNoticeServiceProvider(rotationOptions, rotationHandler,
            new SyntheticPermissionReader(new MailboxPermissionReport(
                PermissionDecision.Unknown("not used"), PermissionDecision.Unknown("not used"),
                PermissionDecision.Unknown("not used"), DateTimeOffset.UtcNow, "synthetic-task-notice-permissions")),
            rotationClients))
        {
            var processor = new TaskNoticeProcessor(Options.Create(rotationOptions),
                provider.GetRequiredService<IServiceScopeFactory>(), NullLogger<TaskNoticeProcessor>.Instance);
            await processor.RunOnceAsync();
            var firstPass = rotationHandler.FindItemActorMailboxes.ToArray();
            await processor.RunOnceAsync();
            var secondPass = rotationHandler.FindItemActorMailboxes.Skip(firstPass.Length).ToArray();
            Expect(firstPass.Length == 16 && firstPass.Distinct(StringComparer.OrdinalIgnoreCase).Count() == 16
                && secondPass.Length == 16 && secondPass.Distinct(StringComparer.OrdinalIgnoreCase).Count() == 16
                && rotationHandler.FindItemActorMailboxes.Distinct(StringComparer.OrdinalIgnoreCase).Count() == 20
                && rotationHandler.UpdateItemCalls == 0 && rotationHandler.CreateItemCalls == 0,
                "All-enrolled processing did not rotate fairly through the configured mailbox set with a 16-mailbox pass bound.");
        }
        foreach (var http in rotationClients) http.Dispose();

        var duplicateOwnOptions = NewTaskNoticeOptions(
            Path.Combine(runDirectory, "task-notice-all-enrolled-duplicate-own.jsonl"), [], writesEnabled: true);
        duplicateOwnOptions.TaskNoticeProcessingAllEnrolledUsers = true;
        duplicateOwnOptions.Mailboxes["user-b"] = "alice@example.test";
        var duplicateOwnHandler = new TaskNoticeRightsProbeHandler(tasksModify: true);
        var duplicateOwnPermission = new SyntheticPermissionReader(new MailboxPermissionReport(
            new PermissionDecision("allowed", "synthetic grant", Direct: true), PermissionDecision.Unknown("not used"),
            PermissionDecision.Unknown("not used"), DateTimeOffset.UtcNow, "synthetic-task-notice-permissions"));
        var duplicateOwnClients = new List<HttpClient>();
        using (var provider = CreateTaskNoticeServiceProvider(duplicateOwnOptions, duplicateOwnHandler,
            duplicateOwnPermission, duplicateOwnClients))
        {
            var processor = new TaskNoticeProcessor(Options.Create(duplicateOwnOptions),
                provider.GetRequiredService<IServiceScopeFactory>(), NullLogger<TaskNoticeProcessor>.Instance);
            await processor.RunOnceAsync();
            Expect(duplicateOwnHandler.TotalCalls == 0 && duplicateOwnPermission.Calls == 0,
                "An ambiguous physical mailbox with multiple enrolled own identities was not blocked before Exchange access.");
        }
        foreach (var http in duplicateOwnClients) http.Dispose();

        var overLimitOptions = NewTaskNoticeOptions(
            Path.Combine(runDirectory, "task-notice-all-enrolled-over-limit.jsonl"), [], writesEnabled: true);
        overLimitOptions.TaskNoticeProcessingAllEnrolledUsers = true;
        overLimitOptions.Mailboxes.Clear();
        for (var index = 0; index < 1025; index++)
            overLimitOptions.Mailboxes[$"user-{index:D4}"] = $"user{index:D4}@example.test";
        var overLimitHandler = new TaskNoticeRightsProbeHandler(tasksModify: true);
        var overLimitLogger = new TaskNoticeRecordingLogger();
        var overLimitClients = new List<HttpClient>();
        using (var provider = CreateTaskNoticeServiceProvider(overLimitOptions, overLimitHandler,
            new SyntheticPermissionReader(new MailboxPermissionReport(
                PermissionDecision.Unknown("not used"), PermissionDecision.Unknown("not used"),
                PermissionDecision.Unknown("not used"), DateTimeOffset.UtcNow, "synthetic-task-notice-permissions")),
            overLimitClients))
        {
            var processor = new TaskNoticeProcessor(Options.Create(overLimitOptions),
                provider.GetRequiredService<IServiceScopeFactory>(), overLimitLogger);
            await processor.RunOnceAsync();
            Expect(overLimitHandler.TotalCalls == 0
                && overLimitLogger.Messages.Any(message => message.Contains("canonical mailbox limit", StringComparison.Ordinal)),
                "The all-enrolled worker did not fail closed before Exchange access when over 1,024 canonical mailboxes were configured.");
        }
        foreach (var http in overLimitClients) http.Dispose();

        await AssertSharedMailboxFolderRightsFallbackAsync(firstDelegateTasksModify: true,
            expectedFirstActorFolderIds: ["inbox", "tasks"]);
        await AssertSharedMailboxFolderRightsFallbackAsync(firstDelegateTasksModify: false,
            expectedFirstActorFolderIds: ["inbox", "tasks", "inbox", "tasks"]);
    }

    private async Task AssertFolderRightsDiscoverTargetsWithoutLegacyMappingsAsync()
    {
        var auditPath = Path.Combine(runDirectory, "task-notice-empty-legacy-targets-audit.jsonl");
        var options = NewTaskNoticeOptions(auditPath, ["alice@example.test"], writesEnabled: true);
        var permissions = new SyntheticPermissionReader(new MailboxPermissionReport(
            new PermissionDecision("denied", "Full Access is not required when native task-folder rights exist"),
            PermissionDecision.Unknown("not used"), PermissionDecision.Unknown("not used"),
            DateTimeOffset.UtcNow, "synthetic-task-notice-permissions"));
        var handler = new TaskNoticeRightsProbeHandler(tasksModify: true);
        var httpClients = new List<HttpClient>();
        var discovery = new TestMailboxDiscovery(false, "user-a");
        var candidate = new MailboxDirectoryCandidate(DiscoveryMailboxKey, "it@example.test", "IT", 1);
        discovery.AddTarget("user-a", candidate.Key, candidate.Mailbox);
        using var provider = CreateTaskNoticeServiceProvider(options, handler, permissions, httpClients, discovery);
        var processor = new TaskNoticeProcessor(Options.Create(options),
            provider.GetRequiredService<IServiceScopeFactory>(), NullLogger<TaskNoticeProcessor>.Instance);

        await processor.RunOnceAsync();
        var delegatedRights = handler.FolderIds.Zip(handler.FolderTargetMailboxes)
            .Zip(handler.FolderActorMailboxes)
            .Where(entry => string.Equals(entry.First.Second, candidate.Mailbox, StringComparison.OrdinalIgnoreCase))
            .Select(entry => (Folder: entry.First.First, Actor: entry.Second)).ToArray();
        Expect(options.MailboxTargets.Count == 0 && permissions.Calls == 0
            && delegatedRights.Select(entry => entry.Folder).SequenceEqual(["inbox", "tasks"])
            && delegatedRights.All(entry => entry.Actor == "alice@example.test")
            && handler.FindItemTargetMailboxes.Contains(candidate.Mailbox, StringComparer.OrdinalIgnoreCase)
            && discovery.DirectoryResolveKeys.Contains(candidate.Key, StringComparer.Ordinal),
            "Automatic task tracking required a legacy route or treated Full Access as a substitute for live Inbox/Tasks rights.");

        var beforeFolderChecks = handler.FolderTargetMailboxes.Count;
        var beforeFinds = handler.FindItemTargetMailboxes.Count;
        discovery.OverrideDirectoryResolution(candidate with { Mailbox = "renamed@example.test" });
        await processor.RunOnceAsync();
        var driftCalls = handler.FolderTargetMailboxes.Skip(beforeFolderChecks).ToArray();
        Expect(discovery.DirectoryResolveKeys.Count(key => key == candidate.Key) >= 2
            && !driftCalls.Contains(candidate.Mailbox, StringComparer.OrdinalIgnoreCase)
            && !handler.FindItemTargetMailboxes.Skip(beforeFinds).Contains(candidate.Mailbox, StringComparer.OrdinalIgnoreCase),
            "Task notice processing reused a stale directory GUID-to-primary-SMTP binding.");
        foreach (var http in httpClients) http.Dispose();
    }

    private async Task AssertSharedMailboxFolderRightsFallbackAsync(
        bool firstDelegateTasksModify,
        string[] expectedFirstActorFolderIds)
    {
        var auditPath = Path.Combine(runDirectory,
            $"task-notice-all-enrolled-shared-folder-rights-{firstDelegateTasksModify}.jsonl");
        var options = NewTaskNoticeOptions(auditPath, [], writesEnabled: true);
        options.TaskNoticeProcessingAllEnrolledUsers = true;
        options.Mailboxes["user-b"] = "bob@example.test";
        var permissionReader = new SyntheticPermissionReader(new MailboxPermissionReport(
            PermissionDecision.Unknown("Full Access is not used for Inbox/Tasks folder rights"),
            PermissionDecision.Unknown("not used"), PermissionDecision.Unknown("not used"),
            DateTimeOffset.UtcNow, "synthetic-task-notice-permissions"));
        var handler = new TaskNoticeRightsProbeHandler(tasksModify: true);
        handler.TaskModifyByActor["alice@example.test"] = firstDelegateTasksModify;
        handler.TaskModifyByActor["bob@example.test"] = true;
        var httpClients = new List<HttpClient>();
        var discovery = new TestMailboxDiscovery(false, "user-a", "user-b");
        discovery.AddTarget("user-a", SharedMailboxKey, "shared@example.test");
        discovery.AddTarget("user-b", SharedMailboxKey, "shared@example.test");
        using (var provider = CreateTaskNoticeServiceProvider(options, handler, permissionReader, httpClients, discovery))
        {
            var processor = new TaskNoticeProcessor(Options.Create(options),
                provider.GetRequiredService<IServiceScopeFactory>(), NullLogger<TaskNoticeProcessor>.Instance);
            await processor.RunOnceAsync();
            var sharedFolderEntries = handler.FolderIds.Zip(handler.FolderTargetMailboxes)
                .Zip(handler.FolderActorMailboxes)
                .Where(entry => string.Equals(entry.First.Second, "shared@example.test", StringComparison.OrdinalIgnoreCase))
                .Select(entry => (Folder: entry.First.First, Actor: entry.Second)).ToArray();
            Expect(permissionReader.Calls == 0
                && sharedFolderEntries.Select(entry => entry.Folder).SequenceEqual(expectedFirstActorFolderIds)
                && sharedFolderEntries.All(entry => entry.Actor is "alice@example.test" or "bob@example.test")
                && handler.FindItemTargetMailboxes.Count(mailbox => string.Equals(mailbox,
                    "shared@example.test", StringComparison.OrdinalIgnoreCase)) == 1
                && handler.FindItemActorMailboxes.Last() == (firstDelegateTasksModify
                    ? "alice@example.test" : "bob@example.test")
                && handler.UpdateItemCalls == 0 && handler.CreateItemCalls == 0,
                $"An all-enrolled shared mailbox did not fail over using fresh Inbox/Tasks folder rights: folders={string.Join(',', sharedFolderEntries.Select(entry => $"{entry.Folder}/{entry.Actor}"))}, targets={string.Join(',', handler.FindItemTargetMailboxes)}, actors={string.Join(',', handler.FindItemActorMailboxes)}, updates={handler.UpdateItemCalls}, creates={handler.CreateItemCalls}.");
        }
        foreach (var http in httpClients) http.Dispose();
    }

    private async Task AssertTaskNoticeUsesFreshFolderRightsAsync()
    {
        var options = NewTaskNoticeOptions(
            Path.Combine(runDirectory, "task-notice-stale-full-access-audit.jsonl"),
            ["alice@example.test"], writesEnabled: true);
        var handler = new TaskNoticeRightsProbeHandler(tasksModify: true);
        var permissionReader = new TaskNoticeDelayedPermissionReader(TimeSpan.FromSeconds(6));
        var httpClients = new List<HttpClient>();
        var discovery = new TestMailboxDiscovery(false, "user-a");
        discovery.AddTarget("user-a", DiscoveryMailboxKey, "it@example.test");
        using (var provider = CreateTaskNoticeServiceProvider(options, handler, permissionReader, httpClients, discovery))
        {
            var processor = new TaskNoticeProcessor(Options.Create(options),
                provider.GetRequiredService<IServiceScopeFactory>(), NullLogger<TaskNoticeProcessor>.Instance);
            await processor.RunOnceAsync();
            Expect(permissionReader.Calls == 0
                && handler.FolderIds.Zip(handler.FolderTargetMailboxes)
                    .Zip(handler.FolderActorMailboxes)
                    .Any(entry => string.Equals(entry.First.Second, "it@example.test", StringComparison.OrdinalIgnoreCase)
                        && entry.First.First == "tasks" && entry.Second == "alice@example.test")
                && handler.FindItemTargetMailboxes.Contains("it@example.test", StringComparer.OrdinalIgnoreCase)
                && handler.UpdateItemCalls == 0 && handler.CreateItemCalls == 0,
                "Automatic task tracking did not use fresh delegated Inbox/Tasks EffectiveRights independently of the legacy Full Access reader.");
        }
        foreach (var http in httpClients) http.Dispose();
    }

    private async Task AssertLegacyTaskNoticeStateMigrationAsync()
    {
        var migratedAuditPath = Path.Combine(runDirectory, "task-notice-v2-empty-audit.jsonl");
        var migratedOptions = NewTaskNoticeOptions(migratedAuditPath, ["alice@example.test"], writesEnabled: true);
        var oldRouteHash = new string('a', 64);
        var oldBookmarkHash = new string('b', 64);
        var v2EmptyState = JsonSerializer.Serialize(new
        {
            version = 2,
            targetCursor = 7,
            scanOffsets = new Dictionary<string, int> { [oldRouteHash] = 300 },
            scanBookmarks = new Dictionary<string, string> { [oldRouteHash] = oldBookmarkHash },
            entries = Array.Empty<object>()
        });
        File.WriteAllText(migratedAuditPath + ".task-notices.json", v2EmptyState);
        var migrationHandler = new TaskNoticeRightsProbeHandler(tasksModify: true);
        var migrationClients = new List<HttpClient>();
        using (var provider = CreateTaskNoticeServiceProvider(migratedOptions, migrationHandler,
            new SyntheticPermissionReader(new MailboxPermissionReport(
                PermissionDecision.Unknown("not used"), PermissionDecision.Unknown("not used"),
                PermissionDecision.Unknown("not used"), DateTimeOffset.UtcNow, "synthetic-task-notice-permissions")),
            migrationClients))
        {
            var processor = new TaskNoticeProcessor(Options.Create(migratedOptions),
                provider.GetRequiredService<IServiceScopeFactory>(), NullLogger<TaskNoticeProcessor>.Instance);
            await processor.RunOnceAsync();
            using var state = JsonDocument.Parse(File.ReadAllBytes(migratedAuditPath + ".task-notices.json"));
            var root = state.RootElement;
            Expect(root.GetProperty("version").GetInt32() == 3
                && root.GetProperty("targetCursor").GetInt32() == 0
                && !root.GetProperty("scanOffsets").TryGetProperty(oldRouteHash, out _)
                && !root.GetProperty("scanBookmarks").TryGetProperty(oldRouteHash, out _)
                && !File.ReadAllText(migratedAuditPath + ".task-notices.json").Contains(oldBookmarkHash, StringComparison.Ordinal),
                "An empty actor-bound v2 task-notice state did not migrate to canonical v3 mailbox cursors from zero.");
        }
        foreach (var http in migrationClients) http.Dispose();

        foreach (var status in new[] { "pending", "quarantined" })
        {
            var heldAuditPath = Path.Combine(runDirectory, $"task-notice-v2-{status}-audit.jsonl");
            var heldOptions = NewTaskNoticeOptions(heldAuditPath, ["alice@example.test"], writesEnabled: true);
            var legacyKey = new string(status == "pending" ? 'c' : 'd', 64);
            var legacyState = JsonSerializer.Serialize(new
            {
                version = 2,
                targetCursor = 0,
                scanOffsets = new Dictionary<string, int>(),
                scanBookmarks = new Dictionary<string, string>(),
                entries = new[]
                {
                    new { keyHash = legacyKey, status, code = status == "pending" ? "in_flight" : "payload_rejected",
                        updatedUtc = DateTimeOffset.UtcNow }
                }
            });
            var statePath = heldAuditPath + ".task-notices.json";
            File.WriteAllText(statePath, legacyState);
            var before = File.ReadAllBytes(statePath);
            var heldHandler = new TaskNoticeRightsProbeHandler(tasksModify: true);
            var heldLogger = new TaskNoticeRecordingLogger();
            var heldClients = new List<HttpClient>();
            using (var provider = CreateTaskNoticeServiceProvider(heldOptions, heldHandler,
                new SyntheticPermissionReader(new MailboxPermissionReport(
                    PermissionDecision.Unknown("not used"), PermissionDecision.Unknown("not used"),
                    PermissionDecision.Unknown("not used"), DateTimeOffset.UtcNow, "synthetic-task-notice-permissions")),
                heldClients))
            {
                var processor = new TaskNoticeProcessor(Options.Create(heldOptions),
                    provider.GetRequiredService<IServiceScopeFactory>(), heldLogger);
                await processor.RunOnceAsync();
                Expect(before.SequenceEqual(File.ReadAllBytes(statePath)) && heldHandler.TotalCalls == 0
                    && heldLogger.Messages.Any(message => message.Contains("legacy uncertain state", StringComparison.Ordinal))
                    && heldLogger.Messages.All(message => !message.Contains("alice@example.test", StringComparison.Ordinal)
                        && !message.Contains(legacyKey, StringComparison.Ordinal)),
                    $"A legacy v2 {status} hold was not preserved while automatic processing failed closed for reconciliation.");
            }
            foreach (var http in heldClients) http.Dispose();
        }
    }

    private ServiceProvider CreateTaskNoticeServiceProvider(
        ServiceOptions options,
        HttpMessageHandler handler,
        IMailboxPermissionReader permissionReader,
        ICollection<HttpClient>? httpClients = null,
        TestMailboxDiscovery? discovery = null)
    {
        var services = new ServiceCollection();
        services.AddScoped(_ => new MailboxAccess(Options.Create(options)));
        services.AddScoped(serviceProvider =>
        {
            var http = new HttpClient(handler);
            httpClients?.Add(http);
            return new EwsClient(http, Options.Create(new EwsOptions
            {
                Endpoint = "https://mail.example.test/EWS/Exchange.asmx",
                TimeoutSeconds = 10,
                MaxResponseBytes = 2_097_152
            }), serviceProvider.GetRequiredService<MailboxAccess>());
        });
        services.AddScoped(_ => new AuditLog(Options.Create(options)));
        services.AddSingleton(permissionReader);
        services.AddSingleton<IMailboxPermissionReader>(permissionReader);
        discovery ??= new TestMailboxDiscovery(false, options.Mailboxes.Keys.ToArray());
        services.AddSingleton<IMailboxDiscovery>(discovery);
        services.AddSingleton<IMailboxDirectory>(discovery);
        return services.BuildServiceProvider();
    }

    private async Task AssertCandidateBookmarkAndShrinkingQueryWrapAsync()
    {
        var auditPath = Path.Combine(runDirectory, "task-notice-cursor-audit.jsonl");
        var options = NewTaskNoticeOptions(auditPath, ["alice@example.test"], writesEnabled: true);
        var handler = new TaskNoticeCursorHandler(totalItems: 350);
        var permission = new SyntheticPermissionReader(new MailboxPermissionReport(
            PermissionDecision.Unknown("not used"), PermissionDecision.Unknown("not used"),
            PermissionDecision.Unknown("not used"), DateTimeOffset.UtcNow, "synthetic-task-notice-permissions"));
        var httpClients = new List<HttpClient>();
        var services = new ServiceCollection();
        services.AddScoped(_ => new MailboxAccess(Options.Create(options)));
        services.AddScoped(serviceProvider =>
        {
            var http = new HttpClient(handler);
            httpClients.Add(http);
            return new EwsClient(http, Options.Create(new EwsOptions
            {
                Endpoint = "https://mail.example.test/EWS/Exchange.asmx",
                TimeoutSeconds = 10,
                MaxResponseBytes = 2_097_152
            }), serviceProvider.GetRequiredService<MailboxAccess>());
        });
        services.AddScoped(_ => new AuditLog(Options.Create(options)));
        services.AddSingleton<IMailboxPermissionReader>(permission);
        RegisterTaskNoticeDiscovery(services, options);
        using var provider = services.BuildServiceProvider();
        var scopes = provider.GetRequiredService<IServiceScopeFactory>();
        var processor = new TaskNoticeProcessor(Options.Create(options), scopes,
            NullLogger<TaskNoticeProcessor>.Instance);

        await processor.RunOnceAsync();
        Expect(handler.FindOffsets.SequenceEqual([0, 100, 200]) && handler.GetItemCalls == 3,
            $"The first bounded snapshot did not advance across pages while safely retrying its front notice: offsets={string.Join(',', handler.FindOffsets)}, get={handler.GetItemCalls}.");

        handler.TotalItems = 250;
        await processor.RunOnceAsync();
        Expect(handler.FindOffsets.Last() == 300,
            "The shrinking unprocessed query did not exercise the saved offset beyond its new end.");
        await processor.RunOnceAsync();
        Expect(handler.FindOffsets.TakeLast(3).SequenceEqual([0, 100, 200])
            && handler.GetItemCalls == 6 && handler.UpdateItemCalls == 0 && handler.CreateItemCalls == 0,
            "The bounded scanner failed to wrap to the query prefix after shrink or wrote while retrying its front notice.");

        var state = File.ReadAllText(auditPath + ".task-notices.json");
        Expect(state.Contains("scanBookmarks", StringComparison.Ordinal)
            && state.Contains("\"scanOffsets\"", StringComparison.Ordinal)
            && !state.Contains("cursor-000", StringComparison.Ordinal)
            && !state.Contains("alice@example.test", StringComparison.Ordinal),
            "Durable task scan fairness state did not keep only hashed bookmarks and offsets.");
        foreach (var http in httpClients) http.Dispose();
    }

    private async Task AssertTemporaryTaskNoticeFailureRecoversAsync()
    {
        var auditPath = Path.Combine(runDirectory, "task-notice-recovery-audit.jsonl");
        var options = NewTaskNoticeOptions(auditPath, ["alice@example.test"], writesEnabled: true);
        var handler = new TaskNoticeRecoveryHandler
        {
            ProcessMessage = true,
            ReturnLocalTaskForFind = true,
            NativeUpdatedResponse = true,
            OmitTaskRequestVersion = true,
            AcceptedFlagOverride = true,
            TaskNoticeItemClass = "IPM.TaskRequest.Update",
            TaskVersion = 5,
            LocalTaskVersion = 2,
            NativeTaskPercentComplete = 50,
            TaskGlobalId = TaskAssignmentRecordingHandler.WrongGlobalIdValue
        };
        var permission = new SyntheticPermissionReader(new MailboxPermissionReport(
            PermissionDecision.Unknown("not used"), PermissionDecision.Unknown("not used"),
            PermissionDecision.Unknown("not used"), DateTimeOffset.UtcNow, "synthetic-task-notice-permissions"));
        var httpClients = new List<HttpClient>();
        var services = new ServiceCollection();
        services.AddScoped(_ => new MailboxAccess(Options.Create(options)));
        services.AddScoped(serviceProvider =>
        {
            var http = new HttpClient(handler);
            httpClients.Add(http);
            return new EwsClient(http, Options.Create(new EwsOptions
            {
                Endpoint = "https://mail.example.test/EWS/Exchange.asmx",
                TimeoutSeconds = 10,
                MaxResponseBytes = 2_097_152
            }), serviceProvider.GetRequiredService<MailboxAccess>());
        });
        services.AddScoped(_ => new AuditLog(Options.Create(options)));
        services.AddSingleton<IMailboxPermissionReader>(permission);
        RegisterTaskNoticeDiscovery(services, options);
        using var provider = services.BuildServiceProvider();
        var scopes = provider.GetRequiredService<IServiceScopeFactory>();
        var processor = new TaskNoticeProcessor(Options.Create(options), scopes,
            NullLogger<TaskNoticeProcessor>.Instance);

        await processor.RunOnceAsync();
        var beforeRecovery = File.ReadAllText(auditPath + ".task-notices.json");
        Expect(handler.UpdateItemCount == 0 && handler.CreateItemCount == 0
            && beforeRecovery.Contains("\"entries\":[]", StringComparison.Ordinal),
            "A temporarily missing task tracker was durably quarantined or reached an EWS write.");

        handler.TaskGlobalId = TaskAssignmentRecordingHandler.GlobalIdForChecks;
        await processor.RunOnceAsync();
        Expect(handler.UpdateItemCount == 2 && handler.CreateItemCount == 0
            && !handler.Calls.Any(call => call.Operation is "CreateItem" or "SendItem")
            && File.ReadAllLines(auditPath).Any(line => line.Contains("completed", StringComparison.Ordinal)),
            $"A task notice did not recover after its tracker became available: updates={handler.UpdateItemCount}, calls={string.Join(',', handler.Calls.Select(call => call.Operation).GroupBy(value => value).Select(group => $"{group.Key}:{group.Count()}"))}, completedAudit={File.ReadAllLines(auditPath).Any(line => line.Contains("completed", StringComparison.Ordinal))}.");
        foreach (var http in httpClients) http.Dispose();
    }

    private async Task AssertCandidateBookmarkScansAcrossSixHundredNoticesAsync()
    {
        var auditPath = Path.Combine(runDirectory, "task-notice-large-window-audit.jsonl");
        var options = NewTaskNoticeOptions(auditPath, ["alice@example.test"], writesEnabled: true);
        var handler = new TaskNoticeFairnessHandler(ordinaryCount: 600);
        var permission = new SyntheticPermissionReader(new MailboxPermissionReport(
            PermissionDecision.Unknown("not used"), PermissionDecision.Unknown("not used"),
            PermissionDecision.Unknown("not used"), DateTimeOffset.UtcNow, "synthetic-task-notice-permissions"));
        var httpClients = new List<HttpClient>();
        var services = new ServiceCollection();
        services.AddScoped(_ => new MailboxAccess(Options.Create(options)));
        services.AddScoped(serviceProvider =>
        {
            var http = new HttpClient(handler);
            httpClients.Add(http);
            return new EwsClient(http, Options.Create(new EwsOptions
            {
                Endpoint = "https://mail.example.test/EWS/Exchange.asmx",
                TimeoutSeconds = 10,
                MaxResponseBytes = 2_097_152
            }), serviceProvider.GetRequiredService<MailboxAccess>());
        });
        services.AddScoped(_ => new AuditLog(Options.Create(options)));
        services.AddSingleton<IMailboxPermissionReader>(permission);
        RegisterTaskNoticeDiscovery(services, options);
        using var provider = services.BuildServiceProvider();
        var scopes = provider.GetRequiredService<IServiceScopeFactory>();

        for (var pass = 0; pass < 30; pass++)
        {
            var processor = new TaskNoticeProcessor(Options.Create(options), scopes,
                NullLogger<TaskNoticeProcessor>.Instance);
            await processor.RunOnceAsync();
        }

        Expect(handler.OrdinaryRequestReads == 600 && handler.ValidUpdateReads == 0
            && handler.UpdateItemCount == 0,
            $"The durable bounded cursor did not cover all 600 ordinary notices before the valid tail: ordinary={handler.OrdinaryRequestReads}, valid={handler.ValidUpdateReads}.");

        var tailProcessor = new TaskNoticeProcessor(Options.Create(options), scopes,
            NullLogger<TaskNoticeProcessor>.Instance);
        await tailProcessor.RunOnceAsync();
        Expect(handler.ValidUpdateReads >= 2 && handler.UpdateItemCount >= 2
            && handler.CreateItemCount == 0
            && !handler.Calls.Any(call => call.Operation is "CreateItem" or "SendItem"),
            "The scan failed to move to the valid 601st notice after exhausting two full bounded windows.");
        await tailProcessor.RunOnceAsync();
        Expect(handler.ValidUpdateReads == 2 && handler.UpdateItemCount == 2
            && handler.OrdinaryRequestReads == 620,
            "The successfully processed last notice reappeared after its marker removed it from the unprocessed query.");
        foreach (var http in httpClients) http.Dispose();
    }

    private async Task AssertCandidateBookmarkSkipsTwentyOrdinaryRequestsAsync()
    {
        var auditPath = Path.Combine(runDirectory, "task-notice-candidate-bookmark-audit.jsonl");
        var options = NewTaskNoticeOptions(auditPath, ["alice@example.test"], writesEnabled: true);
        var handler = new TaskNoticeFairnessHandler();
        var permission = new SyntheticPermissionReader(new MailboxPermissionReport(
            PermissionDecision.Unknown("not used"), PermissionDecision.Unknown("not used"),
            PermissionDecision.Unknown("not used"), DateTimeOffset.UtcNow, "synthetic-task-notice-permissions"));
        var httpClients = new List<HttpClient>();
        var services = new ServiceCollection();
        services.AddScoped(_ => new MailboxAccess(Options.Create(options)));
        services.AddScoped(serviceProvider =>
        {
            var http = new HttpClient(handler);
            httpClients.Add(http);
            return new EwsClient(http, Options.Create(new EwsOptions
            {
                Endpoint = "https://mail.example.test/EWS/Exchange.asmx",
                TimeoutSeconds = 10,
                MaxResponseBytes = 2_097_152
            }), serviceProvider.GetRequiredService<MailboxAccess>());
        });
        services.AddScoped(_ => new AuditLog(Options.Create(options)));
        services.AddSingleton<IMailboxPermissionReader>(permission);
        RegisterTaskNoticeDiscovery(services, options);
        using var provider = services.BuildServiceProvider();
        var scopes = provider.GetRequiredService<IServiceScopeFactory>();

        var firstRun = new TaskNoticeProcessor(Options.Create(options), scopes,
            NullLogger<TaskNoticeProcessor>.Instance);
        await firstRun.RunOnceAsync();
        var savedState = File.ReadAllText(auditPath + ".task-notices.json");
        Expect(handler.OrdinaryRequestReads == 20 && handler.ValidUpdateReads == 0
            && handler.UpdateItemCount == 0 && handler.CreateItemCount == 0
            && savedState.Contains("scanBookmarks", StringComparison.Ordinal)
            && !savedState.Contains("valid-tail", StringComparison.Ordinal),
            $"The 20-notice pass did not stop before its valid tail or persist a hash-only candidate bookmark: ordinary={handler.OrdinaryRequestReads}, valid={handler.ValidUpdateReads}, updates={handler.UpdateItemCount}, stateHasBookmarks={savedState.Contains("scanBookmarks", StringComparison.Ordinal)}.");

        var caseChangedOptions = NewTaskNoticeOptions(auditPath, ["ALICE@example.test"], writesEnabled: true);
        caseChangedOptions.Mailboxes["user-a"] = "ALICE@example.test";
        var restarted = new TaskNoticeProcessor(Options.Create(caseChangedOptions), scopes,
            NullLogger<TaskNoticeProcessor>.Instance);
        await restarted.RunOnceAsync();
        var restartState = File.ReadAllText(auditPath + ".task-notices.json");
        Expect(handler.OrdinaryRequestReads == 20 && handler.ValidUpdateReads >= 2 && handler.UpdateItemCount >= 2
            && handler.CreateItemCount == 0
            && !handler.Calls.Any(call => call.Operation is "CreateItem" or "SendItem"),
            $"The persisted candidate bookmark failed to reach the valid 21st task after restart without sending: valid={handler.ValidUpdateReads}, updates={handler.UpdateItemCount}, creates={handler.CreateItemCount}, state={restartState}, operations={string.Join(',', handler.Calls.Select(call => call.Operation).GroupBy(value => value).Select(group => $"{group.Key}:{group.Count()}"))}.");
        foreach (var http in httpClients) http.Dispose();
    }

    private async Task AssertTaskNoticeWorkerGatesAsync()
    {
        var validOptions = NewTaskNoticeOptions(Path.Combine(runDirectory, "task-notice-disabled-audit.jsonl"),
            actors: ["alice@example.test"], writesEnabled: false);
        var disabledStatePath = validOptions.AuditPath + ".task-notices.json";
        File.WriteAllText(disabledStatePath, "{");
        using (var emptyServices = new ServiceCollection().BuildServiceProvider())
        {
            var disabledLogger = new TaskNoticeRecordingLogger();
            var disabled = new TaskNoticeProcessor(Options.Create(validOptions),
                emptyServices.GetRequiredService<IServiceScopeFactory>(),
                disabledLogger);
            await disabled.RunOnceAsync();
            Expect(disabledLogger.Messages.Count == 0 && File.ReadAllText(disabledStatePath) == "{",
                "The disabled task worker read or changed an existing corrupt state file before checking its write gate.");
        }

        var optedOutOptions = NewTaskNoticeOptions(Path.Combine(runDirectory, "task-notice-opted-out-audit.jsonl"),
            actors: [], writesEnabled: true);
        var optedOutStatePath = optedOutOptions.AuditPath + ".task-notices.json";
        File.WriteAllText(optedOutStatePath, "{");
        using (var emptyServices = new ServiceCollection().BuildServiceProvider())
        {
            var optedOutLogger = new TaskNoticeRecordingLogger();
            var optedOut = new TaskNoticeProcessor(Options.Create(optedOutOptions),
                emptyServices.GetRequiredService<IServiceScopeFactory>(), optedOutLogger);
            await optedOut.RunOnceAsync();
            Expect(optedOutLogger.Messages.Count == 0 && File.ReadAllText(optedOutStatePath) == "{",
                "The empty-actor default read or changed an existing corrupt state file before the opt-in gate.");
        }

        var corruptOptions = NewTaskNoticeOptions(Path.Combine(runDirectory, "task-notice-corrupt-audit.jsonl"),
            actors: ["alice@example.test"], writesEnabled: true);
        File.WriteAllText(corruptOptions.AuditPath + ".task-notices.json", "{");
        using (var emptyServices = new ServiceCollection().BuildServiceProvider())
        {
            var failClosed = new TaskNoticeProcessor(Options.Create(corruptOptions),
                emptyServices.GetRequiredService<IServiceScopeFactory>(),
                NullLogger<TaskNoticeProcessor>.Instance);
            await failClosed.RunOnceAsync();
        }

        var wrongShapeOptions = NewTaskNoticeOptions(Path.Combine(runDirectory, "task-notice-shape-audit.jsonl"),
            actors: ["alice@example.test"], writesEnabled: true);
        File.WriteAllText(wrongShapeOptions.AuditPath + ".task-notices.json",
            "{\"version\":\"1\",\"targetCursor\":0,\"scanOffsets\":{},\"entries\":[]}");
        using (var emptyServices = new ServiceCollection().BuildServiceProvider())
        {
            var failClosed = new TaskNoticeProcessor(Options.Create(wrongShapeOptions),
                emptyServices.GetRequiredService<IServiceScopeFactory>(),
                NullLogger<TaskNoticeProcessor>.Instance);
            await failClosed.RunOnceAsync();
        }

        foreach (var fullAccessState in new[] { "unknown", "denied" })
        {
            var auditPath = Path.Combine(runDirectory, $"task-notice-rights-{fullAccessState}.jsonl");
            var options = NewTaskNoticeOptions(auditPath, ["alice@example.test"], writesEnabled: true);
            var permission = new SyntheticPermissionReader(new MailboxPermissionReport(
                new PermissionDecision(fullAccessState, "synthetic delegation result"),
                PermissionDecision.Unknown("not used"), PermissionDecision.Unknown("not used"),
                DateTimeOffset.UtcNow, "synthetic-task-notice-permissions"));
            var handler = new TaskNoticeRightsProbeHandler(tasksModify: false);
            var discovery = new TestMailboxDiscovery(false, "user-a");
            discovery.AddTarget("user-a", DiscoveryMailboxKey, "it@example.test");
            var services = new ServiceCollection();
            services.AddScoped(_ => new MailboxAccess(Options.Create(options)));
            services.AddScoped(serviceProvider =>
            {
                var http = new HttpClient(handler);
                handler.HttpClients.Add(http);
                return new EwsClient(http, Options.Create(new EwsOptions
                {
                    Endpoint = "https://mail.example.test/EWS/Exchange.asmx",
                    TimeoutSeconds = 10,
                    MaxResponseBytes = 2_097_152
                }), serviceProvider.GetRequiredService<MailboxAccess>());
            });
            services.AddScoped(_ => new AuditLog(Options.Create(options)));
            services.AddSingleton<IMailboxPermissionReader>(permission);
            services.AddSingleton<IMailboxDiscovery>(discovery);
            services.AddSingleton<IMailboxDirectory>(discovery);
            using var provider = services.BuildServiceProvider();
            var processor = new TaskNoticeProcessor(Options.Create(options),
                provider.GetRequiredService<IServiceScopeFactory>(), NullLogger<TaskNoticeProcessor>.Instance);
            await processor.RunOnceAsync();

            var delegatedFolders = handler.FolderIds.Zip(handler.FolderTargetMailboxes)
                .Where(entry => string.Equals(entry.Second, "it@example.test", StringComparison.OrdinalIgnoreCase))
                .Select(entry => entry.First).ToArray();
            Expect(permission.Calls == 0 && discovery.DirectoryResolveKeys.Contains(DiscoveryMailboxKey, StringComparer.Ordinal)
                && delegatedFolders.SequenceEqual(["inbox", "tasks"])
                && handler.FindItemCalls == 0 && handler.UpdateItemCalls == 0 && handler.CreateItemCalls == 0,
                $"Fresh delegated Inbox/Tasks rights did not block notice processing when Tasks Modify was absent (Full Access state: {fullAccessState}).");
            foreach (var http in handler.HttpClients) http.Dispose();
        }
    }

    private async Task AssertPendingTaskNoticeSurvivesRestartAsync()
    {
        var auditPath = Path.Combine(runDirectory, "task-notice-pending-audit.jsonl");
        var options = NewTaskNoticeOptions(auditPath, ["alice@example.test"], writesEnabled: true);
        var handler = new TaskNoticeFailureHandler
        {
            ProcessMessage = true,
            ReturnLocalTaskForFind = true,
            NativeUpdatedResponse = true,
            OmitTaskRequestVersion = true,
            AcceptedFlagOverride = true,
            TaskNoticeItemClass = "IPM.TaskRequest.Update",
            TaskVersion = 5,
            LocalTaskVersion = 2,
            NativeTaskPercentComplete = 50
        };
        var permissions = new SyntheticPermissionReader(new MailboxPermissionReport(
            PermissionDecision.Unknown("not used"), PermissionDecision.Unknown("not used"),
            PermissionDecision.Unknown("not used"), DateTimeOffset.UtcNow, "synthetic-task-notice-permissions"));
        var httpClients = new List<HttpClient>();
        var services = new ServiceCollection();
        services.AddScoped(_ => new MailboxAccess(Options.Create(options)));
        services.AddScoped(serviceProvider =>
        {
            var http = new HttpClient(handler);
            httpClients.Add(http);
            return new EwsClient(http, Options.Create(new EwsOptions
            {
                Endpoint = "https://mail.example.test/EWS/Exchange.asmx",
                TimeoutSeconds = 10,
                MaxResponseBytes = 2_097_152
            }), serviceProvider.GetRequiredService<MailboxAccess>());
        });
        services.AddScoped(_ => new AuditLog(Options.Create(options)));
        services.AddSingleton<IMailboxPermissionReader>(permissions);
        RegisterTaskNoticeDiscovery(services, options);
        using var provider = services.BuildServiceProvider();
        var scopes = provider.GetRequiredService<IServiceScopeFactory>();

        var firstRun = new TaskNoticeProcessor(Options.Create(options), scopes,
            NullLogger<TaskNoticeProcessor>.Instance);
        await firstRun.RunOnceAsync();
        var statePath = auditPath + ".task-notices.json";
        var pendingState = File.ReadAllText(statePath);
        Expect(handler.UpdateItemCount == 1 && handler.ProcessedMarkCalls == 1
            && handler.CreateItemCount == 0
            && !handler.Calls.Any(call => call.Operation is "CreateItem" or "SendItem")
            && pendingState.Contains("\"status\":\"pending\"", StringComparison.Ordinal)
            && !pendingState.Contains("request-1", StringComparison.Ordinal)
            && !pendingState.Contains("alice@example.test", StringComparison.Ordinal),
            "A failed processed-marker write did not leave a hash-only durable pending record after the tracker update.");

        var secondRun = new TaskNoticeProcessor(Options.Create(options), scopes,
            NullLogger<TaskNoticeProcessor>.Instance);
        await secondRun.RunOnceAsync();
        var pendingAfterRestart = File.ReadAllText(statePath);
        Expect(handler.UpdateItemCount == 1 && handler.ProcessedMarkCalls == 1
            && pendingAfterRestart == pendingState,
            "Restart replayed a task notice whose tracker write succeeded but processed marker was uncertain.");

        Expect(File.ReadAllLines(auditPath).All(line => !line.Contains("request-1", StringComparison.Ordinal)
                && !line.Contains("alice@example.test", StringComparison.Ordinal)
                && !line.Contains("Task Request: Verify", StringComparison.Ordinal)),
            "The automatic task-notice audit leaked a mailbox address, message ID, or subject.");
        foreach (var http in httpClients) http.Dispose();
    }

    private async Task AssertSharedMailboxPendingStateIsActorIndependentAsync()
    {
        var auditPath = Path.Combine(runDirectory, "task-notice-shared-pending-audit.jsonl");
        var options = NewTaskNoticeOptions(auditPath, [], writesEnabled: true);
        options.TaskNoticeProcessingAllEnrolledUsers = true;
        options.Mailboxes["user-b"] = "bob@example.test";
        var handler = new TaskNoticeFailureHandler
        {
            ActiveTaskMailbox = "shared@example.test",
            ProcessMessage = true,
            ReturnLocalTaskForFind = true,
            NativeUpdatedResponse = true,
            OmitTaskRequestVersion = true,
            AcceptedFlagOverride = true,
            TaskNoticeItemClass = "IPM.TaskRequest.Update",
            TaskRequestRecipient = "shared@example.test",
            NativeTaskOwnerName = "shared@example.test",
            NativeTaskOwnerAddress = "shared@example.test",
            NativeLocalTaskOwnerAddress = "shared@example.test",
            NativeResponseTaskOwnerAddress = "shared@example.test",
            NativeResponseSender = "shared@example.test",
            TaskVersion = 5,
            LocalTaskVersion = 2,
            NativeTaskPercentComplete = 50
        };
        handler.TaskModifyByActor["alice@example.test"] = true;
        handler.TaskModifyByActor["bob@example.test"] = true;
        var permissionReader = new SyntheticPermissionReader(new MailboxPermissionReport(
            PermissionDecision.Unknown("Full Access is not used for Inbox/Tasks folder rights"),
            PermissionDecision.Unknown("not used"), PermissionDecision.Unknown("not used"),
            DateTimeOffset.UtcNow, "synthetic-task-notice-permissions"));
        var httpClients = new List<HttpClient>();
        var discovery = new TestMailboxDiscovery(false, "user-a", "user-b");
        discovery.AddTarget("user-a", SharedMailboxKey, "shared@example.test");
        discovery.AddTarget("user-b", SharedMailboxKey, "shared@example.test");
        using var provider = CreateTaskNoticeServiceProvider(options, handler, permissionReader, httpClients, discovery);
        var scopes = provider.GetRequiredService<IServiceScopeFactory>();
        var firstRun = new TaskNoticeProcessor(Options.Create(options), scopes, NullLogger<TaskNoticeProcessor>.Instance);
        await firstRun.RunOnceAsync();
        var statePath = auditPath + ".task-notices.json";
        var pendingState = File.ReadAllText(statePath);
        using var pendingDocument = JsonDocument.Parse(pendingState);
        var statuses = pendingDocument.RootElement.GetProperty("entries").EnumerateArray()
            .Select(entry => entry.GetProperty("status").GetString()).ToArray();
        Expect(handler.UpdateItemCount == 1 && handler.ProcessedMarkCalls == 1
            && pendingState.Contains("\"status\":\"pending\"", StringComparison.Ordinal)
            && !pendingState.Contains("request-1", StringComparison.Ordinal)
            && !pendingState.Contains("shared@example.test", StringComparison.Ordinal),
            $"The shared-mailbox fixture did not leave one hash-only uncertain update before the actor-change restart: updates={handler.UpdateItemCount}, markers={handler.ProcessedMarkCalls}, statuses={string.Join(',', statuses)}, stateHasPending={pendingState.Contains("\"status\":\"pending\"", StringComparison.Ordinal)}, operations={string.Join(',', handler.Calls.Select(call => call.Operation))}.");

        var actorRightsBeforeRestart = handler.FolderRightsReads.Count;
        handler.TaskModifyByActor["alice@example.test"] = false;
        handler.TaskModifyByActor["bob@example.test"] = true;
        var secondRun = new TaskNoticeProcessor(Options.Create(options), scopes, NullLogger<TaskNoticeProcessor>.Instance);
        await secondRun.RunOnceAsync();
        Expect(permissionReader.Calls == 0
            && handler.FolderRightsReads.Skip(actorRightsBeforeRestart).Any(entry =>
                entry.Actor == "alice@example.test" && entry.Folder == "tasks" && !entry.Modify)
            && handler.FolderRightsReads.Skip(actorRightsBeforeRestart).Any(entry =>
                entry.Actor == "bob@example.test" && entry.Folder == "tasks" && entry.Modify)
            && handler.UpdateItemCount == 1 && handler.ProcessedMarkCalls == 1
            && File.ReadAllText(statePath) == pendingState
            && !handler.Calls.Any(call => call.Operation is "CreateItem" or "SendItem"),
            "Changing native folder rights caused a canonical shared-mailbox pending notice to be replayed.");
        foreach (var http in httpClients) http.Dispose();
    }

    private async Task AssertDelegatedTaskRouteSurvivesExpiredDiscoveryAcrossMailboxRotationAsync()
    {
        const int enrolledActors = 327;
        var auditPath = Path.Combine(runDirectory, "task-notice-expired-discovery-rotation-audit.jsonl");
        var options = NewTaskNoticeOptions(auditPath, [], writesEnabled: true);
        options.TaskNoticeProcessingAllEnrolledUsers = true;
        options.Mailboxes.Clear();
        var subjects = new string[enrolledActors];
        for (var index = 0; index < enrolledActors; index++)
        {
            var subject = $"user-{index:D4}";
            var mailbox = index < 15
                ? $"a-user-{index:D3}@example.test"
                : $"z-user-{index:D3}@example.test";
            subjects[index] = subject;
            options.Mailboxes[subject] = mailbox;
        }

        var firstActor = options.Mailboxes[subjects[0]];
        var sharedMailbox = "m-shared@example.test";
        var discovery = new TestMailboxDiscovery(false, subjects);
        discovery.RequirePrimedCache = true;
        discovery.AddTarget(subjects[0], SharedMailboxKey, sharedMailbox);
        var handler = new TaskNoticeFailureHandler
        {
            ActiveTaskMailbox = sharedMailbox,
            ProcessMessage = true,
            ReturnLocalTaskForFind = true,
            NativeUpdatedResponse = true,
            OmitTaskRequestVersion = true,
            AcceptedFlagOverride = true,
            TaskNoticeItemClass = "IPM.TaskRequest.Update",
            TaskRequestRecipient = sharedMailbox,
            NativeTaskOwnerName = sharedMailbox,
            NativeTaskOwnerAddress = sharedMailbox,
            NativeLocalTaskOwnerAddress = sharedMailbox,
            NativeResponseTaskOwnerAddress = sharedMailbox,
            NativeResponseSender = sharedMailbox,
            TaskVersion = 5,
            LocalTaskVersion = 2,
            NativeTaskPercentComplete = 50
        };
        handler.TaskModifyByActor[firstActor] = true;
        var permissions = new SyntheticPermissionReader(new MailboxPermissionReport(
            PermissionDecision.Unknown("not used"), PermissionDecision.Unknown("not used"),
            PermissionDecision.Unknown("not used"), DateTimeOffset.UtcNow, "synthetic-task-notice-permissions"));
        var httpClients = new List<HttpClient>();
        using var provider = CreateTaskNoticeServiceProvider(options, handler, permissions, httpClients, discovery);
        var processor = new TaskNoticeProcessor(Options.Create(options),
            provider.GetRequiredService<IServiceScopeFactory>(), NullLogger<TaskNoticeProcessor>.Instance);

        await processor.RunOnceAsync();
        var statePath = auditPath + ".task-notices.json";
        var pendingState = File.ReadAllText(statePath);
        using (var pending = JsonDocument.Parse(pendingState))
            Expect(handler.UpdateItemCount == 1 && handler.ProcessedMarkCalls == 1
                && pending.RootElement.GetProperty("entries").EnumerateArray()
                    .Any(entry => entry.GetProperty("status").GetString() == "pending")
                && !pendingState.Contains(sharedMailbox, StringComparison.Ordinal)
                && !pendingState.Contains(firstActor, StringComparison.Ordinal),
                "The retained delegated route did not create one redacted pending task before cache expiry.");

        discovery.ExpireCachedSnapshots();
        discovery.FailDiscoveries = true;
        handler.TaskModifyByActor[firstActor] = false;
        var firstRightsReadAfterExpiry = handler.FolderRightsReads.Count;
        for (var pass = 2; pass <= 22; pass++)
            await processor.RunOnceAsync();

        var afterRotation = File.ReadAllText(statePath);
        using var retained = JsonDocument.Parse(afterRotation);
        var pendingCount = retained.RootElement.GetProperty("entries").EnumerateArray()
            .Count(entry => entry.GetProperty("status").GetString() == "pending");
        Expect(discovery.DiscoveryCalls == 22
            && options.MailboxTargets.Count == 0
            && handler.FolderRightsReads.Skip(firstRightsReadAfterExpiry).Any(entry =>
                entry.Actor == firstActor && entry.Target == sharedMailbox && entry.Folder == "tasks" && !entry.Modify)
            && handler.UpdateItemCount == 1 && handler.ProcessedMarkCalls == 1 && pendingCount == 1
            && afterRotation.Contains("\"scanBookmarks\"", StringComparison.Ordinal)
            && !afterRotation.Contains(sharedMailbox, StringComparison.Ordinal)
            && !afterRotation.Contains(firstActor, StringComparison.Ordinal),
            "The 327-user worker lost a delegated route or replayed a pending task after discovery-cache expiry and a 22-pass mailbox rotation instead of rechecking current folder rights.");
        foreach (var http in httpClients) http.Dispose();
    }

    private async Task AssertDelegatedRightsRevocationStopsBeforePendingAsync()
    {
        var auditPath = Path.Combine(runDirectory, "task-notice-revoked-rights-audit.jsonl");
        var options = NewTaskNoticeOptions(auditPath, ["alice@example.test"], writesEnabled: true);
        var handler = new TaskNoticeFailureHandler
        {
            ActiveTaskMailbox = "it@example.test",
            ProcessMessage = true,
            ReturnLocalTaskForFind = true,
            NativeUpdatedResponse = true,
            OmitTaskRequestVersion = true,
            AcceptedFlagOverride = true,
            TaskNoticeItemClass = "IPM.TaskRequest.Update",
            TaskRequestRecipient = "it@example.test",
            NativeTaskOwnerName = "it@example.test",
            NativeTaskOwnerAddress = "it@example.test",
            NativeLocalTaskOwnerAddress = "it@example.test",
            NativeResponseTaskOwnerAddress = "it@example.test",
            NativeResponseSender = "it@example.test",
            TaskVersion = 5,
            LocalTaskVersion = 2,
            NativeTaskPercentComplete = 50
        };
        var discovery = new TestMailboxDiscovery(false, "user-a");
        discovery.AddTarget("user-a", SharedMailboxKey, "it@example.test");
        discovery.OverrideDirectoryResolution(new MailboxDirectoryCandidate(
            SharedMailboxKey, "renamed@example.test", "Information Technology", 1));
        var permissionReader = new SyntheticPermissionReader(new MailboxPermissionReport(
            PermissionDecision.Unknown("folder rights are authoritative"),
            PermissionDecision.Unknown("not used"), PermissionDecision.Unknown("not used"),
            DateTimeOffset.UtcNow, "synthetic-task-notice-permissions"));
        var httpClients = new List<HttpClient>();
        using var provider = CreateTaskNoticeServiceProvider(options, handler, permissionReader, httpClients, discovery);
        var processor = new TaskNoticeProcessor(Options.Create(options),
            provider.GetRequiredService<IServiceScopeFactory>(), NullLogger<TaskNoticeProcessor>.Instance);
        await processor.RunOnceAsync();
        var state = File.ReadAllText(auditPath + ".task-notices.json");
        Expect(options.MailboxTargets.Count == 0
            && discovery.DirectoryResolveKeys.Contains(SharedMailboxKey, StringComparer.Ordinal)
            && handler.FolderRightsReads.All(entry => !string.Equals(entry.Target, "it@example.test", StringComparison.OrdinalIgnoreCase))
            && handler.UpdateItemCount == 0 && handler.ProcessedMarkCalls == 0
            && !state.Contains("\"status\":\"pending\"", StringComparison.Ordinal)
            && !File.ReadAllLines(auditPath).Any(line => line.Contains("started", StringComparison.Ordinal))
            && !handler.Calls.Any(call => call.Operation is "CreateItem" or "SendItem"),
            "A discovered target whose current AD primary SMTP no longer matched its GUID was used for task notice processing.");
        foreach (var http in httpClients) http.Dispose();
    }

    private static void RegisterTaskNoticeDiscovery(ServiceCollection services, ServiceOptions options)
    {
        var discovery = new TestMailboxDiscovery(false, options.Mailboxes.Keys.ToArray());
        services.AddSingleton<IMailboxDiscovery>(discovery);
        services.AddSingleton<IMailboxDirectory>(discovery);
    }

    private async Task AssertTaskNoticeStateSaturationStopsBeforeWriteAsync()
    {
        var auditPath = Path.Combine(runDirectory, "task-notice-state-saturation-audit.jsonl");
        var options = NewTaskNoticeOptions(auditPath, ["alice@example.test"], writesEnabled: true);
        var statePath = auditPath + ".task-notices.json";
        var updatedUtc = DateTimeOffset.UtcNow;
        var heldHashes = Enumerable.Range(0, 2048)
            .Select(index => index.ToString("x64", CultureInfo.InvariantCulture)).ToArray();
        var heldState = JsonSerializer.Serialize(new
        {
            version = 3,
            targetCursor = 0,
            scanOffsets = new Dictionary<string, int>(),
            scanBookmarks = new Dictionary<string, string>(),
            entries = heldHashes.Select(keyHash => new
            {
                keyHash,
                status = "quarantined",
                code = "payload_rejected",
                updatedUtc
            }).ToArray()
        });
        File.WriteAllText(statePath, heldState);
        var handler = new TaskNoticeFailureHandler
        {
            ProcessMessage = true,
            ReturnLocalTaskForFind = true,
            NativeUpdatedResponse = true,
            OmitTaskRequestVersion = true,
            AcceptedFlagOverride = true,
            TaskNoticeItemClass = "IPM.TaskRequest.Update",
            TaskVersion = 5,
            LocalTaskVersion = 2,
            NativeTaskPercentComplete = 50
        };
        var logger = new TaskNoticeRecordingLogger();
        var httpClients = new List<HttpClient>();
        using (var provider = CreateTaskNoticeServiceProvider(options, handler,
            new SyntheticPermissionReader(new MailboxPermissionReport(
                PermissionDecision.Unknown("not used"), PermissionDecision.Unknown("not used"),
                PermissionDecision.Unknown("not used"), DateTimeOffset.UtcNow, "synthetic-task-notice-permissions")),
            httpClients))
        {
            var processor = new TaskNoticeProcessor(Options.Create(options),
                provider.GetRequiredService<IServiceScopeFactory>(), logger);
            await processor.RunOnceAsync();
            var requestsAfterSaturation = handler.Calls.Count;
            await processor.RunOnceAsync();
            using var state = JsonDocument.Parse(File.ReadAllBytes(statePath));
            var savedHashes = state.RootElement.GetProperty("entries").EnumerateArray()
                .Select(entry => entry.GetProperty("keyHash").GetString()).ToHashSet(StringComparer.Ordinal);
            Expect(savedHashes.Count == 2048 && heldHashes.All(savedHashes.Contains)
                && state.RootElement.GetProperty("version").GetInt32() == 3
                && handler.UpdateItemCount == 0 && handler.ProcessedMarkCalls == 0
                && handler.Calls.Count == requestsAfterSaturation
                && !handler.Calls.Any(call => call.Operation is "CreateItem" or "SendItem")
                && logger.Messages.Any(message => message.Contains("state could not be written", StringComparison.Ordinal)),
                "A full durable hold store did not preserve all existing hashes and stop before a tracker write.");
        }
        foreach (var http in httpClients) http.Dispose();
    }

    private async Task AssertStaleTaskNoticeCursorsArePrunedAsync()
    {
        var auditPath = Path.Combine(runDirectory, "task-notice-stale-cursor-audit.jsonl");
        var options = NewTaskNoticeOptions(auditPath, ["alice@example.test"], writesEnabled: true);
        var statePath = auditPath + ".task-notices.json";
        var staleRoutes = Enumerable.Range(1, 1024)
            .Select(index => index.ToString("x64", CultureInfo.InvariantCulture)).ToArray();
        var staleBookmarks = Enumerable.Range(10_001, 1024)
            .Select(index => index.ToString("x64", CultureInfo.InvariantCulture)).ToArray();
        File.WriteAllText(statePath, JsonSerializer.Serialize(new
        {
            version = 3,
            targetCursor = 0,
            scanOffsets = staleRoutes.ToDictionary(route => route, _ => 100, StringComparer.Ordinal),
            scanBookmarks = staleRoutes.Zip(staleBookmarks)
                .ToDictionary(pair => pair.First, pair => pair.Second, StringComparer.Ordinal),
            entries = Array.Empty<object>()
        }));
        var handler = new TaskNoticeRightsProbeHandler(tasksModify: true);
        var httpClients = new List<HttpClient>();
        using (var provider = CreateTaskNoticeServiceProvider(options, handler,
            new SyntheticPermissionReader(new MailboxPermissionReport(
                PermissionDecision.Unknown("not used"), PermissionDecision.Unknown("not used"),
                PermissionDecision.Unknown("not used"), DateTimeOffset.UtcNow, "synthetic-task-notice-permissions")),
            httpClients))
        {
            var processor = new TaskNoticeProcessor(Options.Create(options),
                provider.GetRequiredService<IServiceScopeFactory>(), NullLogger<TaskNoticeProcessor>.Instance);
            await processor.RunOnceAsync();
            using var state = JsonDocument.Parse(File.ReadAllBytes(statePath));
            var savedOffsets = state.RootElement.GetProperty("scanOffsets").EnumerateObject()
                .Select(property => property.Name).ToHashSet(StringComparer.Ordinal);
            var savedBookmarks = state.RootElement.GetProperty("scanBookmarks").EnumerateObject()
                .Select(property => property.Name).ToHashSet(StringComparer.Ordinal);
            Expect(handler.FindItemCalls == 1
                && staleRoutes.All(route => !savedOffsets.Contains(route) && !savedBookmarks.Contains(route))
                && savedOffsets.Count <= 1 && savedBookmarks.Count == 0
                && handler.UpdateItemCalls == 0 && handler.CreateItemCalls == 0,
                "Stale bounded cursor hashes for removed targets were not pruned before processing the active target.");
        }
        foreach (var http in httpClients) http.Dispose();
    }

    private ServiceOptions NewTaskNoticeOptions(string auditPath, string[] actors, bool writesEnabled)
    {
        var secret = Path.Combine(runDirectory, "task-notice-worker-secret.txt");
        if (!File.Exists(secret)) File.WriteAllText(secret, "synthetic-secret");
        return new ServiceOptions
        {
            Authority = Authority,
            Resource = Resource,
            IntrospectionClientId = Resource,
            IntrospectionSecretFile = secret,
            AllowedClientIds = ["company-mail-test"],
            Mailboxes = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["user-a"] = "alice@example.test"
            },
            TaskNoticeProcessingActors = actors,
            WritesEnabled = writesEnabled,
            MailboxTargets = new Dictionary<string, Dictionary<string, string>>(StringComparer.Ordinal),
            AuditPath = auditPath
        };
    }
}

internal sealed class TaskNoticeRightsProbeHandler(bool tasksModify) : HttpMessageHandler
{
    private static readonly XNamespace Soap = "http://schemas.xmlsoap.org/soap/envelope/";
    private static readonly XNamespace Messages = "http://schemas.microsoft.com/exchange/services/2006/messages";
    private static readonly XNamespace Types = "http://schemas.microsoft.com/exchange/services/2006/types";

    public List<string> FolderIds { get; } = [];
    public List<string> FolderActorMailboxes { get; } = [];
    public List<string> FolderTargetMailboxes { get; } = [];
    public List<string> FindItemActorMailboxes { get; } = [];
    public List<string> FindItemTargetMailboxes { get; } = [];
    public List<HttpClient> HttpClients { get; } = [];
    public Dictionary<string, bool> TaskModifyByActor { get; } = new(StringComparer.OrdinalIgnoreCase);
    public string LastBody { get; private set; } = string.Empty;
    public string? LastFolderId { get; private set; }
    public string? LastActorMailbox { get; private set; }
    public int FindItemCalls { get; private set; }
    public int UpdateItemCalls { get; private set; }
    public int CreateItemCalls { get; private set; }
    public int TotalCalls { get; private set; }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        LastBody = await request.Content!.ReadAsStringAsync(cancellationToken);
        var document = XDocument.Parse(LastBody);
        var operation = document.Root!.Element(Soap + "Body")!.Elements().Single().Name.LocalName;
        TotalCalls++;
        LastActorMailbox = document.Descendants(Types + "PrimarySmtpAddress").SingleOrDefault()?.Value;
        if (operation == "FindItem") FindItemCalls++;
        if (operation == "UpdateItem") UpdateItemCalls++;
        if (operation == "CreateItem") CreateItemCalls++;
        var ids = document.Descendants(Types + "DistinguishedFolderId")
            .Select(folder => (string?)folder.Attribute("Id")).Where(value => value is not null).ToArray();
        if (operation == "GetFolder")
        {
            LastFolderId = ids.SingleOrDefault();
            FolderIds.Add(LastFolderId ?? string.Empty);
            FolderActorMailboxes.Add(LastActorMailbox ?? string.Empty);
            FolderTargetMailboxes.Add(ExtractTargetMailbox(document));
        }
        if (operation == "FindItem")
        {
            FindItemActorMailboxes.Add(LastActorMailbox ?? string.Empty);
            FindItemTargetMailboxes.Add(ExtractTargetMailbox(document));
        }
        var modify = LastFolderId == "tasks"
            ? TaskModifyByActor.TryGetValue(LastActorMailbox ?? string.Empty, out var actorTasksModify)
                ? actorTasksModify : tasksModify
            : true;
        var payload = operation == "GetFolder"
            ? "<m:Folders><t:Folder><t:FolderId Id='rights-probe' ChangeKey='rights-change'/>"
                + $"<t:EffectiveRights><t:Read>true</t:Read><t:CreateContents>false</t:CreateContents><t:Modify>{modify.ToString().ToLowerInvariant()}</t:Modify><t:Delete>false</t:Delete></t:EffectiveRights>"
                + "</t:Folder></m:Folders>"
            : operation == "FindItem"
                ? "<m:RootFolder IncludesLastItemInRange='true'><t:Items/></m:RootFolder>"
                : string.Empty;
        return new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(
                $"<s:Envelope xmlns:s='{Soap.NamespaceName}' xmlns:m='{Messages.NamespaceName}' xmlns:t='{Types.NamespaceName}'><s:Body><m:{operation}Response><m:ResponseMessages><m:{operation}ResponseMessage ResponseClass='Success'><m:ResponseCode>NoError</m:ResponseCode>{payload}</m:{operation}ResponseMessage></m:ResponseMessages></m:{operation}Response></s:Body></s:Envelope>",
                Encoding.UTF8, "text/xml")
        };
    }

    private static string ExtractTargetMailbox(XDocument document)
    {
        var folder = document.Descendants(Types + "DistinguishedFolderId").SingleOrDefault();
        return folder?.Element(Types + "Mailbox")?.Element(Types + "EmailAddress")?.Value
            ?? document.Descendants(Types + "PrimarySmtpAddress").SingleOrDefault()?.Value
            ?? string.Empty;
    }
}

internal sealed class TaskNoticeSequencePermissionReader(string[] fullAccessStates) : IMailboxPermissionReader
{
    public List<MailboxIdentity> Identities { get; } = [];

    public Task<MailboxPermissionReport> ReadAsync(MailboxIdentity identity, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Identities.Add(identity);
        var state = fullAccessStates[Math.Min(Identities.Count - 1, fullAccessStates.Length - 1)];
        return Task.FromResult(new MailboxPermissionReport(
            new PermissionDecision(state, "synthetic permission result", Direct: state == "allowed"),
            PermissionDecision.Unknown("not used"), PermissionDecision.Unknown("not used"),
            DateTimeOffset.UtcNow, "synthetic-task-notice-permissions"));
    }
}

internal sealed class TaskNoticeDelayedPermissionReader(TimeSpan delay) : IMailboxPermissionReader
{
    public int Calls { get; private set; }

    public async Task<MailboxPermissionReport> ReadAsync(MailboxIdentity identity, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Calls++;
        var checkedAt = DateTimeOffset.UtcNow;
        await Task.Delay(delay, cancellationToken);
        return new MailboxPermissionReport(
            new PermissionDecision("allowed", "synthetic delayed grant", Direct: true),
            PermissionDecision.Unknown("not used"), PermissionDecision.Unknown("not used"),
            checkedAt, "synthetic-task-notice-permissions");
    }
}

internal sealed class TaskNoticeFailureHandler : TaskAssignmentRecordingHandler
{
    private static readonly XNamespace Soap = "http://schemas.xmlsoap.org/soap/envelope/";
    private static readonly XNamespace Messages = "http://schemas.microsoft.com/exchange/services/2006/messages";
    private static readonly XNamespace Types = "http://schemas.microsoft.com/exchange/services/2006/types";

    public int ProcessedMarkCalls { get; private set; }
    public string ActiveTaskMailbox { get; set; } = "alice@example.test";
    public Dictionary<string, bool> TaskModifyByActor { get; } = new(StringComparer.OrdinalIgnoreCase);
    public List<(string Actor, string Target, string Folder, bool Modify)> FolderRightsReads { get; } = [];

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        var body = await request.Content!.ReadAsStringAsync(cancellationToken);
        var document = XDocument.Parse(body);
        var operation = document.Root!.Element(Soap + "Body")!.Elements().Single().Name.LocalName;
        if (operation == "GetFolder")
        {
            var actor = document.Descendants(Types + "PrimarySmtpAddress").SingleOrDefault()?.Value ?? string.Empty;
            var folder = document.Descendants(Types + "DistinguishedFolderId").SingleOrDefault()?.Attribute("Id")?.Value
                ?? string.Empty;
            var target = ExtractTargetMailbox(document);
            var modify = folder != "tasks" || !TaskModifyByActor.TryGetValue(actor, out var actorTasksModify)
                || actorTasksModify;
            FolderRightsReads.Add((actor, target, folder, modify));
            var payload = "<m:Folders><t:Folder><t:FolderId Id='rights-probe' ChangeKey='rights-change'/>"
                + "<t:EffectiveRights><t:Read>true</t:Read><t:CreateContents>false</t:CreateContents>"
                + $"<t:Modify>{modify.ToString().ToLowerInvariant()}</t:Modify><t:Delete>false</t:Delete></t:EffectiveRights></t:Folder></m:Folders>";
            return SuccessResponse("GetFolder", payload);
        }

        if (operation == "FindItem" && !string.Equals(ExtractTargetMailbox(document), ActiveTaskMailbox,
                StringComparison.OrdinalIgnoreCase))
            return SuccessResponse("FindItem", "<m:RootFolder IncludesLastItemInRange='true' IndexedPagingOffset='0'><t:Items/></m:RootFolder>");

        var isProcessedMark = operation == "UpdateItem"
            && document.Descendants(Types + "ExtendedFieldURI")
                .Any(field => (string?)field.Attribute("PropertyTag") == "0x7D01");
        if (isProcessedMark)
        {
            ProcessedMarkCalls++;
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(
                    $"<s:Envelope xmlns:s='{Soap.NamespaceName}' xmlns:m='{Messages.NamespaceName}' xmlns:t='{Types.NamespaceName}'><s:Body>"
                    + "<m:UpdateItemResponse><m:ResponseMessages><m:UpdateItemResponseMessage ResponseClass='Error'>"
                    + "<m:MessageText>Synthetic marker failure</m:MessageText><m:ResponseCode>ErrorServerBusy</m:ResponseCode>"
                    + "</m:UpdateItemResponseMessage></m:ResponseMessages></m:UpdateItemResponse></s:Body></s:Envelope>",
                    Encoding.UTF8, "text/xml")
            };
        }

        return await base.SendAsync(request, cancellationToken);
    }

    private static HttpResponseMessage SuccessResponse(string operation, string payload) => new(HttpStatusCode.OK)
    {
        Content = new StringContent(
            $"<s:Envelope xmlns:s='{Soap.NamespaceName}' xmlns:m='{Messages.NamespaceName}' xmlns:t='{Types.NamespaceName}'><s:Body>"
            + $"<m:{operation}Response><m:ResponseMessages><m:{operation}ResponseMessage ResponseClass='Success'>"
            + $"<m:ResponseCode>NoError</m:ResponseCode>{payload}</m:{operation}ResponseMessage></m:ResponseMessages>"
            + $"</m:{operation}Response></s:Body></s:Envelope>", Encoding.UTF8, "text/xml")
    };

    private static string ExtractTargetMailbox(XDocument document)
    {
        var folder = document.Descendants(Types + "DistinguishedFolderId").SingleOrDefault();
        return folder?.Element(Types + "Mailbox")?.Element(Types + "EmailAddress")?.Value
            ?? document.Descendants(Types + "PrimarySmtpAddress").SingleOrDefault()?.Value
            ?? string.Empty;
    }
}

internal sealed class TaskNoticeRecoveryHandler : TaskAssignmentRecordingHandler
{
    private static readonly XNamespace Soap = "http://schemas.xmlsoap.org/soap/envelope/";
    private static readonly XNamespace Messages = "http://schemas.microsoft.com/exchange/services/2006/messages";
    private static readonly XNamespace Types = "http://schemas.microsoft.com/exchange/services/2006/types";

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        var document = XDocument.Parse(await request.Content!.ReadAsStringAsync(cancellationToken));
        var operation = document.Root!.Element(Soap + "Body")!.Elements().Single().Name.LocalName;
        if (operation == "GetFolder")
            return SuccessResponse("GetFolder",
                "<m:Folders><t:Folder><t:FolderId Id='rights-probe' ChangeKey='rights-change'/>"
                + "<t:EffectiveRights><t:Read>true</t:Read><t:CreateContents>false</t:CreateContents>"
                + "<t:Modify>true</t:Modify><t:Delete>false</t:Delete></t:EffectiveRights></t:Folder></m:Folders>");
        return await base.SendAsync(request, cancellationToken);
    }

    private static HttpResponseMessage SuccessResponse(string operation, string payload) => new(HttpStatusCode.OK)
    {
        Content = new StringContent(
            $"<s:Envelope xmlns:s='{Soap.NamespaceName}' xmlns:m='{Messages.NamespaceName}' xmlns:t='{Types.NamespaceName}'><s:Body>"
            + $"<m:{operation}Response><m:ResponseMessages><m:{operation}ResponseMessage ResponseClass='Success'>"
            + $"<m:ResponseCode>NoError</m:ResponseCode>{payload}</m:{operation}ResponseMessage></m:ResponseMessages>"
            + $"</m:{operation}Response></s:Body></s:Envelope>", Encoding.UTF8, "text/xml")
    };
}

internal sealed class TaskNoticeRecordingLogger : ILogger<TaskNoticeProcessor>
{
    public List<string> Messages { get; } = [];
    public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
    public bool IsEnabled(LogLevel logLevel) => true;
    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
        Func<TState, Exception?, string> formatter) => Messages.Add(formatter(state, exception));
}

internal sealed class TaskNoticeCursorHandler(int totalItems) : HttpMessageHandler
{
    private static readonly XNamespace Soap = "http://schemas.xmlsoap.org/soap/envelope/";
    private static readonly XNamespace Messages = "http://schemas.microsoft.com/exchange/services/2006/messages";
    private static readonly XNamespace Types = "http://schemas.microsoft.com/exchange/services/2006/types";

    public int TotalItems { get; set; } = totalItems;
    public List<int> FindOffsets { get; } = [];
    public int GetItemCalls { get; private set; }
    public int UpdateItemCalls { get; private set; }
    public int CreateItemCalls { get; private set; }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        var document = XDocument.Parse(await request.Content!.ReadAsStringAsync(cancellationToken));
        var operation = document.Root!.Element(Soap + "Body")!.Elements().Single().Name.LocalName;
        if (operation == "GetItem") GetItemCalls++;
        if (operation == "UpdateItem") UpdateItemCalls++;
        if (operation == "CreateItem") CreateItemCalls++;

        string payload;
        if (operation == "GetFolder")
        {
            payload = "<m:Folders><t:Folder><t:FolderId Id='rights-probe' ChangeKey='rights-change'/>"
                + "<t:EffectiveRights><t:Read>true</t:Read><t:CreateContents>false</t:CreateContents>"
                + "<t:Modify>true</t:Modify><t:Delete>false</t:Delete></t:EffectiveRights></t:Folder></m:Folders>";
        }
        else if (operation == "FindItem")
        {
            var folder = document.Descendants(Types + "DistinguishedFolderId").SingleOrDefault();
            var folderId = (string?)folder?.Attribute("Id");
            var view = document.Descendants(Messages + "IndexedPageItemView").SingleOrDefault();
            var offset = int.Parse((string?)view?.Attribute("Offset") ?? "0", CultureInfo.InvariantCulture);
            FindOffsets.Add(offset);
            var end = offset >= TotalItems || offset + 100 >= TotalItems;
            var next = Math.Min(TotalItems, offset + 100);
            var message = folderId == "inbox" && offset < TotalItems
                ? CursorMessage($"cursor-{offset:D3}") : string.Empty;
            payload = $"<m:RootFolder IncludesLastItemInRange='{end.ToString().ToLowerInvariant()}' IndexedPagingOffset='{next}'><t:Items>{message}</t:Items></m:RootFolder>";
        }
        else if (operation == "GetItem")
        {
            payload = "<m:Items/>";
        }
        else payload = string.Empty;

        return SuccessResponse(operation, payload);
    }

    private static HttpResponseMessage SuccessResponse(string operation, string payload) => new(HttpStatusCode.OK)
    {
        Content = new StringContent(
            $"<s:Envelope xmlns:s='{Soap.NamespaceName}' xmlns:m='{Messages.NamespaceName}' xmlns:t='{Types.NamespaceName}'><s:Body>"
            + $"<m:{operation}Response><m:ResponseMessages><m:{operation}ResponseMessage ResponseClass='Success'>"
            + $"<m:ResponseCode>NoError</m:ResponseCode>{payload}</m:{operation}ResponseMessage></m:ResponseMessages>"
            + $"</m:{operation}Response></s:Body></s:Envelope>", Encoding.UTF8, "text/xml")
    };

    private static string CursorMessage(string id) =>
        $"<t:Message><t:ItemId Id='{id}' ChangeKey='cursor-change'/><t:ItemClass>IPM.TaskRequest.Update</t:ItemClass>"
        + "<t:ExtendedProperty><t:ExtendedFieldURI PropertyTag='0x7D01' PropertyType='Boolean'/>"
        + "<t:Value>not-a-boolean</t:Value></t:ExtendedProperty></t:Message>";
}

internal sealed class TaskNoticeFairnessHandler(int ordinaryCount = 20) : TaskAssignmentRecordingHandler
{
    private static readonly XNamespace Soap = "http://schemas.xmlsoap.org/soap/envelope/";
    private static readonly XNamespace Messages = "http://schemas.microsoft.com/exchange/services/2006/messages";
    private static readonly XNamespace Types = "http://schemas.microsoft.com/exchange/services/2006/types";
    private const string ValidTailId = "valid-tail";
    private const string ValidTailGlobalId = TaskAssignmentRecordingHandler.GlobalIdForChecks;
    private bool validTailProcessed;

    public int OrdinaryRequestReads { get; private set; }
    public int ValidUpdateReads { get; private set; }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        var body = await request.Content!.ReadAsStringAsync(cancellationToken);
        var document = XDocument.Parse(body);
        var operation = document.Root!.Element(Soap + "Body")!.Elements().Single().Name.LocalName;
        var folderId = document.Descendants(Types + "DistinguishedFolderId").SingleOrDefault()?.Attribute("Id")?.Value;
        if (operation == "GetFolder")
        {
            return SuccessResponse("GetFolder",
                "<m:Folders><t:Folder><t:FolderId Id='rights-probe' ChangeKey='rights-change'/>"
                + "<t:EffectiveRights><t:Read>true</t:Read><t:CreateContents>false</t:CreateContents>"
                + "<t:Modify>true</t:Modify><t:Delete>false</t:Delete></t:EffectiveRights></t:Folder></m:Folders>");
        }
        if (operation == "FindItem" && folderId == "inbox")
        {
            var view = document.Descendants(Messages + "IndexedPageItemView").Single();
            var offset = int.Parse(view.Attribute("Offset")!.Value, CultureInfo.InvariantCulture);
            var limit = int.Parse(view.Attribute("MaxEntriesReturned")!.Value, CultureInfo.InvariantCulture);
            var all = Enumerable.Range(1, ordinaryCount).Select(index => TaskNoticeMessage(
                $"ordinary-{index:D4}", "IPM.TaskRequest", TaskAssignmentRecordingHandler.GlobalIdForChecks, 2));
            if (!validTailProcessed)
                all = all.Append(TaskNoticeMessage(ValidTailId, "IPM.TaskRequest.Update", ValidTailGlobalId, 5));
            var items = all.ToArray();
            var page = items.Skip(offset).Take(limit).ToArray();
            var nextOffset = offset + page.Length;
            var includesLast = nextOffset >= items.Length;
            var messages = string.Concat(page);
            return SuccessResponse("FindItem",
                $"<m:RootFolder IncludesLastItemInRange='{includesLast.ToString().ToLowerInvariant()}' IndexedPagingOffset='{nextOffset}'><t:Items>{messages}</t:Items></m:RootFolder>");
        }

        if (operation == "GetItem" && body.Contains("FieldURI=\"item:Attachments\"", StringComparison.Ordinal)
            && body.Contains("FieldURI=\"message:From\"", StringComparison.Ordinal))
        {
            var itemId = document.Descendants(Types + "ItemId").Single().Attribute("Id")!.Value;
            TaskRequestId = itemId;
            if (itemId == ValidTailId)
            {
                ValidUpdateReads++;
                ProcessMessage = true;
                ReturnLocalTaskForFind = true;
                NativeUpdatedResponse = true;
                TaskRequestGlobalId = ValidTailGlobalId;
                TaskAttachmentGlobalId = ValidTailGlobalId;
                TaskGlobalId = ValidTailGlobalId;
                TaskVersion = 5;
                LocalTaskVersion = 2;
                OmitTaskRequestVersion = true;
                AcceptedFlagOverride = true;
            }
            else
            {
                OrdinaryRequestReads++;
                ProcessMessage = false;
                NativeUpdatedResponse = false;
                TaskRequestGlobalId = TaskAssignmentRecordingHandler.GlobalIdForChecks;
                TaskAttachmentGlobalId = null;
                TaskGlobalId = TaskAssignmentRecordingHandler.GlobalIdForChecks;
                TaskVersion = 2;
                TaskRequestVersion = 2;
                OmitTaskRequestVersion = false;
                AcceptedFlagOverride = null;
            }
        }

        if (operation == "UpdateItem"
            && body.Contains("PropertyTag=\"0x7D01\"", StringComparison.Ordinal))
            validTailProcessed = true;

        return await base.SendAsync(request, cancellationToken);
    }

    private static string TaskNoticeMessage(string id, string itemClass, string globalId, int version)
    {
        var mode = itemClass switch
        {
            "IPM.TaskRequest.Update" => 4,
            "IPM.TaskRequest.Accept" => 2,
            "IPM.TaskRequest.Decline" => 3,
            _ => 1
        };
        return $"<t:Message><t:ItemId Id='{id}' ChangeKey='change-{id}'/><t:ItemClass>{itemClass}</t:ItemClass>"
            + "<t:Subject>Task Request: synthetic</t:Subject>"
            + "<t:From><t:Mailbox><t:EmailAddress>bob@example.test</t:EmailAddress></t:Mailbox></t:From>"
            + "<t:Sender><t:Mailbox><t:EmailAddress>bob@example.test</t:EmailAddress></t:Mailbox></t:Sender>"
            + "<t:InternetMessageHeaders><t:InternetMessageHeader HeaderName='X-MS-Exchange-Organization-AuthAs'>Internal</t:InternetMessageHeader></t:InternetMessageHeaders>"
            + "<t:ToRecipients><t:Mailbox><t:EmailAddress>alice@example.test</t:EmailAddress></t:Mailbox></t:ToRecipients>"
            + "<t:IsRead>false</t:IsRead>"
            + $"<t:ExtendedProperty><t:ExtendedFieldURI PropertySetId='00062008-0000-0000-C000-000000000046' PropertyId='0x8519' PropertyType='Binary'/><t:Value>{globalId}</t:Value></t:ExtendedProperty>"
            + $"<t:ExtendedProperty><t:ExtendedFieldURI PropertySetId='00062008-0000-0000-C000-000000000046' PropertyId='0x8518' PropertyType='Integer'/><t:Value>{mode}</t:Value></t:ExtendedProperty>"
            + $"<t:ExtendedProperty><t:ExtendedFieldURI PropertySetId='00062003-0000-0000-C000-000000000046' PropertyId='0x8112' PropertyType='Integer'/><t:Value>{version}</t:Value></t:ExtendedProperty>"
            + "<t:ExtendedProperty><t:ExtendedFieldURI PropertyTag='0x7D01' PropertyType='Boolean'/><t:Value>false</t:Value></t:ExtendedProperty>"
            + "</t:Message>";
    }

    private static HttpResponseMessage SuccessResponse(string operation, string payload) => new(HttpStatusCode.OK)
    {
        Content = new StringContent(
            $"<s:Envelope xmlns:s='{Soap.NamespaceName}' xmlns:m='{Messages.NamespaceName}' xmlns:t='{Types.NamespaceName}'><s:Body>"
            + $"<m:{operation}Response><m:ResponseMessages><m:{operation}ResponseMessage ResponseClass='Success'>"
            + $"<m:ResponseCode>NoError</m:ResponseCode>{payload}</m:{operation}ResponseMessage></m:ResponseMessages>"
            + $"</m:{operation}Response></s:Body></s:Envelope>", Encoding.UTF8, "text/xml")
    };
}
