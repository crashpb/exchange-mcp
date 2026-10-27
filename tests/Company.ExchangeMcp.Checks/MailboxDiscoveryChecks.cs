using System.DirectoryServices.Protocols;
using System.Net;
using System.Text;
using System.Xml.Linq;
using Microsoft.Extensions.DependencyInjection;
using Company.ExchangeMcp.Exchange;
using Company.ExchangeMcp.Security;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

internal sealed partial class Checks
{
    private static readonly Guid DiscoveryMailboxGuid = Guid.Parse("11111111-2222-3333-4444-555555555555");
    internal const string DiscoveryMailboxKey = "11111111-2222-3333-4444-555555555555";
    internal const string SharedMailboxKey = "bbbbbbbb-bbbb-cccc-dddd-eeeeeeeeeeee";

    private async Task MailboxDiscoveryChecksAsync()
    {
        await AssertLdapMailboxDiscoveryPagesAsync();
        await AssertLdapMailboxDiscoveryFailsClosedAsync();
        await AssertEwsMailboxFolderDiscoveryBoundsAsync();
        await AssertMailboxDiscoveryRechecksActorAsync();
        await AssertMailboxMetadataOwnerFallbackRechecksActorAsync();
        await AssertConcealedFolderDenialsCompleteDiscoveryAsync();
        await AssertMailboxDiscoveryContinuationAndLimitsAsync();
        await AssertMailboxDiscoverySlowFrontProgressAsync();
        await AssertFolderPagingAndContextAsync();
    }

    private async Task AssertMailboxDiscoveryContinuationAndLimitsAsync()
    {
        var settings = new ServiceOptions
        {
            AllowedClientIds = ["chatgpt-test"],
            Mailboxes = new(StringComparer.Ordinal) { ["user-a"] = "alice@example.test" },
            AllowedRecipientDomains = ["example.test"]
        };
        var actor = new MailboxIdentity("user-a", "alice@example.test", "chatgpt-test", "continuation-session");
        var candidates = Enumerable.Range(0, 60).Select(index => new MailboxDirectoryCandidate(
            Guid.Parse($"{index + 1:D8}-2222-3333-4444-555555555555").ToString("D"),
            $"target{index:D2}@example.test", $"Target {index:D2}", 1)).ToArray();
        var access = new MailboxAccess(Options.Create(settings));
        var reader = new RecordingMailboxPermissionReader(fullAccessAllowed: true);
        var discovery = new MailboxDiscovery(access, new StaticMailboxDirectory(candidates), reader,
            NewDiscoveryEwsClient(new FolderDiscoveryHandler(), access), NullLogger<MailboxDiscovery>.Instance);

        var parallel = await Task.WhenAll(discovery.DiscoverAsync(actor, CancellationToken.None),
            discovery.DiscoverAsync(actor, CancellationToken.None));
        Expect(parallel.All(snapshot => snapshot.CandidateCount == candidates.Length
                && snapshot.ScannedCount == 60 && snapshot.CatalogScanComplete
                && snapshot.Targets.Count == 60 && snapshot.Complete)
            && reader.Calls == 60
            && parallel.All(snapshot => snapshot.Targets.Any(target => target.Candidate.Key == candidates[59].Key)),
            "One ordinary mailbox discovery call did not scan past 48 candidates or concurrent calls repeated its completed scan.");

        var resumed = await discovery.DiscoverAsync(actor, CancellationToken.None);
        Expect(resumed.CandidateCount == 60 && resumed.ScannedCount == 60
            && resumed.CatalogScanComplete && resumed.Complete && resumed.Targets.Count == 60
            && resumed.PermissionCheckFailures == 0 && resumed.IncompleteFolderTargets == 0
            && resumed.ScanStartedAt != default,
            "A complete mailbox scan was not reused from its verified cache.");

        var failedOnce = 1;
        var retryReader = new RecordingMailboxPermissionReader(read: (identity, _) =>
        {
            if (identity.Mailbox == candidates[59].Mailbox && Interlocked.Exchange(ref failedOnce, 0) == 1)
                throw new IOException("Synthetic directory failure.");
            return Task.FromResult(RecordingMailboxPermissionReader.AllowedReport);
        });
        var retryDiscovery = new MailboxDiscovery(access, new StaticMailboxDirectory(candidates), retryReader,
            NewDiscoveryEwsClient(new FolderDiscoveryHandler(), access), NullLogger<MailboxDiscovery>.Instance);
        var failedPass = await retryDiscovery.DiscoverAsync(actor, CancellationToken.None);
        Expect(failedPass.CatalogScanComplete && !failedPass.Complete && failedPass.PermissionCheckFailures == 1
            && failedPass.Targets.All(target => target.Candidate.Key != candidates[59].Key)
            && retryDiscovery.Cached(actor) is { Complete: false },
            "A failed tail candidate was exposed or a partially verified scan claimed completeness.");

        var deniedReport = new MailboxPermissionReport(new("denied", "no FullAccess"), new("denied", "no SendAs"),
            new("denied", "no SendOnBehalf"), DateTimeOffset.UtcNow, "test");
        var fallbackHandler = new FolderDiscoveryHandler { FailActorFolderRights = true };
        var fallbackDiscovery = new MailboxDiscovery(access, new StaticMailboxDirectory([candidates[0]]),
            new RecordingMailboxPermissionReader(read: (_, _) => Task.FromResult(deniedReport)),
            NewDiscoveryEwsClient(fallbackHandler, access), NullLogger<MailboxDiscovery>.Instance);
        var failedFallback = await fallbackDiscovery.DiscoverAsync(actor, CancellationToken.None);
        Expect(failedFallback.CatalogScanComplete && !failedFallback.Complete
            && failedFallback.IncompleteFolderTargets == 1 && failedFallback.PermissionCheckFailures == 0
            && failedFallback.Targets.Count == 1 && !failedFallback.Targets[0].FolderAccess.Complete,
            "A failed owner-metadata rights recheck reused complete actor hierarchy evidence and hid unresolved custom shares.");
        await Task.Delay(TimeSpan.FromSeconds(5.1));
        Expect(retryDiscovery.Cached(actor) is null, "Incomplete permission evidence was cached for the full success lifetime.");
        var retried = await retryDiscovery.DiscoverAsync(actor, CancellationToken.None);
        Expect(retried.Complete && retried.Targets.Count == 60 && retried.PermissionCheckFailures == 0
            && retryReader.Calls == 61 && retryReader.CallsFor(candidates[59].Mailbox) == 2,
            "Retrying unresolved discovery evidence repeated successful candidates or permanently omitted the failed tail mailbox.");
        fallbackHandler.FailActorFolderRights = false;
        var retriedFallback = await fallbackDiscovery.DiscoverAsync(actor, CancellationToken.None);
        Expect(retriedFallback.Complete && retriedFallback.IncompleteFolderTargets == 0,
            "A failed owner-metadata fallback was not retried after the partial cache expired.");

        var cancelCandidates = Enumerable.Range(0, 50).Select(index => new MailboxDirectoryCandidate(
            Guid.Parse($"{index + 101:D8}-3333-4444-5555-666666666666").ToString("D"),
            $"cancel{index:D2}@example.test", $"Cancel {index:D2}", 1)).ToArray();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var blockOnce = 1;
        var cancelReader = new RecordingMailboxPermissionReader(fullAccessAllowed: true, async (identity, token) =>
        {
            if (string.Equals(identity.Mailbox, cancelCandidates[0].Mailbox, StringComparison.OrdinalIgnoreCase)
                && Interlocked.Exchange(ref blockOnce, 0) == 1)
            {
                entered.TrySetResult();
                await Task.Delay(Timeout.InfiniteTimeSpan, token);
            }
            return RecordingMailboxPermissionReader.AllowedReport;
        });
        var cancelAccess = new MailboxAccess(Options.Create(settings));
        var cancelDiscovery = new MailboxDiscovery(cancelAccess, new StaticMailboxDirectory(cancelCandidates),
            cancelReader, NewDiscoveryEwsClient(new FolderDiscoveryHandler(), cancelAccess), NullLogger<MailboxDiscovery>.Instance);
        using (var cancellation = new CancellationTokenSource())
        {
            var inFlight = cancelDiscovery.DiscoverAsync(actor, cancellation.Token);
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            cancellation.Cancel();
            await AssertThrowsAsync<OperationCanceledException>(() => inFlight);
        }
        var afterCancellation = await cancelDiscovery.DiscoverAsync(actor, CancellationToken.None);
        Expect(cancelReader.CallsFor(cancelCandidates[0].Mailbox) >= 2
            && afterCancellation.Targets.Any(target => target.Candidate.Key == cancelCandidates[0].Key),
            "A caller-canceled candidate was marked scanned instead of remaining pending for the next pass.");

        var revokedCandidate = new MailboxDirectoryCandidate(DiscoveryMailboxKey, "revoked@example.test", "Revoked", 1);
        var mutableDirectory = new MutableMailboxDirectory(revokedCandidate);
        var revokedHandler = new FolderDiscoveryHandler();
        var revokeAccess = new MailboxAccess(Options.Create(settings));
        var revokedDiscovery = new MailboxDiscovery(revokeAccess, mutableDirectory,
            new RecordingMailboxPermissionReader(), NewDiscoveryEwsClient(revokedHandler, revokeAccess), NullLogger<MailboxDiscovery>.Instance);
        var initiallyAccessible = await revokedDiscovery.DiscoverAsync(actor, CancellationToken.None);
        revokedHandler.DenyAllForActor = true;
        Expect(await revokedDiscovery.ResolveAsync(actor, revokedCandidate.Key, CancellationToken.None) is null
            && revokedDiscovery.Cached(actor) is null,
            "A revoked target selection trusted cached access or failed to invalidate its stale discovery snapshot.");
        var refreshed = await revokedDiscovery.DiscoverAsync(actor, CancellationToken.None);
        Expect(initiallyAccessible.Targets.Any(target => target.Candidate.Key == revokedCandidate.Key)
            && refreshed.CatalogScanComplete && refreshed.Targets.All(target => target.Candidate.Key != revokedCandidate.Key),
            "A completed denial did not remove a previously retained mailbox route after a fresh scan.");

        var deniedIncompleteCandidate = new MailboxDirectoryCandidate(
            Guid.Parse("dddddddd-eeee-ffff-aaaa-bbbbbbbbbbbb").ToString("D"), "denied@example.test", "Denied", 4);
        var deniedIncompleteAccess = new MailboxAccess(Options.Create(settings));
        var deniedIncompleteHandler = new FolderDiscoveryHandler { DenyAllForActor = true, DenyMetadataOwner = true };
        var deniedIncompleteDiscovery = new MailboxDiscovery(deniedIncompleteAccess,
            new StaticMailboxDirectory([deniedIncompleteCandidate]), new RecordingMailboxPermissionReader(),
            NewDiscoveryEwsClient(deniedIncompleteHandler, deniedIncompleteAccess), NullLogger<MailboxDiscovery>.Instance);
        var deniedIncomplete = await deniedIncompleteDiscovery.DiscoverAsync(actor, CancellationToken.None);
        Expect(deniedIncomplete.CatalogScanComplete && !deniedIncomplete.Complete
            && deniedIncomplete.IncompleteFolderTargets == 1 && deniedIncomplete.Targets.Count == 0
            && deniedIncompleteHandler.Calls.Count(call => call.ConnectingSid == deniedIncompleteCandidate.Mailbox) == 1,
            "An inaccessible mailbox with incomplete folder evidence was omitted from aggregate incompleteness.");

        var unknownNoAccessCandidate = new MailboxDirectoryCandidate(
            Guid.Parse("eeeeeeee-ffff-aaaa-bbbb-cccccccccccc").ToString("D"), "unknown@example.test", "Unknown", 4);
        var unknownNoAccessAccess = new MailboxAccess(Options.Create(settings));
        var unknownNoAccessHandler = new FolderDiscoveryHandler { HideReadAccessForActor = true };
        var unknownNoAccessDiscovery = new MailboxDiscovery(unknownNoAccessAccess,
            new StaticMailboxDirectory([unknownNoAccessCandidate]), new RecordingMailboxPermissionReader(),
            NewDiscoveryEwsClient(unknownNoAccessHandler, unknownNoAccessAccess), NullLogger<MailboxDiscovery>.Instance);
        var unknownNoAccess = await unknownNoAccessDiscovery.DiscoverAsync(actor, CancellationToken.None);
        Expect(unknownNoAccess.CatalogScanComplete && !unknownNoAccess.Complete
            && unknownNoAccess.PermissionCheckFailures == 1 && unknownNoAccess.IncompleteFolderTargets == 0
            && unknownNoAccess.Targets.Count == 0
            && unknownNoAccessHandler.Calls.Any(call => call.Operation == "GetFolder"),
            "A complete EWS scan with no folder access omitted unresolved directory grants from aggregate completeness.");

        var unknownSendCandidate = new MailboxDirectoryCandidate(
            Guid.Parse("ffffffff-aaaa-bbbb-cccc-dddddddddddd").ToString("D"), "readable@example.test", "Readable", 4);
        var unknownSendAccess = new MailboxAccess(Options.Create(settings));
        var unknownSendReport = new MailboxPermissionReport(new("denied", "synthetic FullAccess denial"),
            PermissionDecision.Unknown("synthetic SendAs visibility gap"),
            new("denied", "synthetic Send on Behalf denial"), DateTimeOffset.UtcNow, "test");
        var unknownSendDiscovery = new MailboxDiscovery(unknownSendAccess,
            new StaticMailboxDirectory([unknownSendCandidate]),
            new RecordingMailboxPermissionReader(read: (_, _) => Task.FromResult(unknownSendReport)),
            NewDiscoveryEwsClient(new FolderDiscoveryHandler(), unknownSendAccess), NullLogger<MailboxDiscovery>.Instance);
        var unknownSend = await unknownSendDiscovery.DiscoverAsync(actor, CancellationToken.None);
        Expect(unknownSend.CatalogScanComplete && !unknownSend.Complete
            && unknownSend.PermissionCheckFailures == 1 && unknownSend.Targets.Count == 1
            && unknownSend.Targets[0].Permissions.SendAs.State == "unknown"
            && unknownSend.Targets[0].FolderAccess.Folders.Any(folder => folder.Rights.Read == true),
            "A readable mailbox with an unknown Send As decision was omitted or reported as fully verified.");

        var capCandidates = new[] { new MailboxDirectoryCandidate(
            Guid.Parse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").ToString("D"), "cap@example.test", "Cap", 1) };
        var capAccess = new MailboxAccess(Options.Create(settings));
        var capDiscovery = new MailboxDiscovery(capAccess, new StaticMailboxDirectory(capCandidates),
            new RecordingMailboxPermissionReader(fullAccessAllowed: true),
            NewDiscoveryEwsClient(new FolderDiscoveryHandler(), capAccess), NullLogger<MailboxDiscovery>.Instance);
        typeof(MailboxDiscovery).GetField("retainedTargets", System.Reflection.BindingFlags.NonPublic
                | System.Reflection.BindingFlags.Instance)!.SetValue(capDiscovery, 4096);
        var capResult = await capDiscovery.DiscoverAsync(actor, CancellationToken.None);
        Expect(capResult.CapacityLimited && !capResult.CatalogScanComplete && capResult.Targets.Count == 0
            && capResult.ScannedCount == 0,
            "Mailbox discovery exceeded its bounded verified-target metadata capacity.");

        var emptyAccessMap = new Dictionary<string, string>(StringComparer.Ordinal);
        for (var index = 0; index < 1025; index++)
            emptyAccessMap[$"subject-{index:D4}"] = $"actor{index:D4}@example.test";
        var actorCapSettings = new ServiceOptions { Mailboxes = emptyAccessMap };
        var actorCapDiscovery = new MailboxDiscovery(new MailboxAccess(Options.Create(actorCapSettings)),
            new StaticMailboxDirectory([]), new RecordingMailboxPermissionReader(),
            NewDiscoveryEwsClient(new FolderDiscoveryHandler()), NullLogger<MailboxDiscovery>.Instance);
        MailboxDiscoverySnapshot? actorCapResult = null;
        for (var index = 0; index < 1025; index++)
        {
            var mailbox = emptyAccessMap[$"subject-{index:D4}"];
            actorCapResult = await actorCapDiscovery.DiscoverAsync(new($"subject-{index:D4}", mailbox),
                CancellationToken.None);
        }
        Expect(actorCapResult is { CapacityLimited: true, CatalogScanComplete: false, Targets.Count: 0 },
            "Mailbox discovery retained per-actor progress beyond its bounded 1024-actor capacity.");

        var progressMap = typeof(MailboxDiscovery).GetField("progressByActor", System.Reflection.BindingFlags.NonPublic
            | System.Reflection.BindingFlags.Instance)!.GetValue(actorCapDiscovery)!;
        var progressEntries = ((System.Collections.IEnumerable)progressMap).Cast<object>().ToArray();
        var progressCandidates = candidates;
        var scanStartedAt = DateTimeOffset.UtcNow.AddHours(-1);
        var stalePartialAt = DateTimeOffset.UtcNow.AddSeconds(-6);
        var partialSnapshot = new MailboxDiscoverySnapshot([], false, stalePartialAt,
            progressCandidates.Length, 48, false, 0, 0, false, 0, scanStartedAt);
        foreach (var entry in progressEntries)
        {
            var state = entry.GetType().GetProperty("Value")!.GetValue(entry)!;
            var stateType = state.GetType();
            stateType.GetProperty("Candidates")!.SetValue(state, progressCandidates);
            stateType.GetProperty("Scanned")!.SetValue(state, Enumerable.Range(0, progressCandidates.Length)
                .Select(index => index < 48).ToArray());
            stateType.GetProperty("PermissionFailures")!.SetValue(state, new bool[progressCandidates.Length]);
            stateType.GetProperty("FolderIncomplete")!.SetValue(state, new bool[progressCandidates.Length]);
            stateType.GetProperty("NextIndex")!.SetValue(state, 48);
            stateType.GetProperty("ScanStartedAt")!.SetValue(state, scanStartedAt);
            stateType.GetProperty("LastTouchedAt")!.SetValue(state, DateTimeOffset.UtcNow.AddMinutes(-6));
            stateType.GetField("Snapshot", System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.NonPublic
                | System.Reflection.BindingFlags.Instance)!
                .SetValue(state, partialSnapshot);
        }
        var oldPartial = new MailboxIdentity("subject-0000", emptyAccessMap["subject-0000"], "chatgpt-test", "idle-session");
        var evictExpiredProgress = typeof(MailboxDiscovery).GetMethod("EvictExpiredProgress",
            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)!;
        evictExpiredProgress.Invoke(actorCapDiscovery, [DateTimeOffset.UtcNow.AddHours(23)]);
        var retainedProgress = ((System.Collections.IEnumerable)progressMap).Cast<object>().ToArray();
        var retainedCursors = retainedProgress.All(entry =>
        {
            var state = entry.GetType().GetProperty("Value")!.GetValue(entry)!;
            return (int)state.GetType().GetProperty("NextIndex")!.GetValue(state)! == 48;
        });
        Expect(retainedProgress.Length == 1024 && actorCapDiscovery.Cached(oldPartial) is null && retainedCursors,
            "Actor progress was evicted when its five-second partial snapshot expired, losing round-robin coverage for a large user pool.");
        evictExpiredProgress.Invoke(actorCapDiscovery, [DateTimeOffset.UtcNow.AddHours(25)]);
        Expect(!((System.Collections.IEnumerable)progressMap).Cast<object>().Any(),
            "Abandoned actor progress was not eventually evicted after the bounded idle-retention period.");
    }

    private async Task AssertMailboxDiscoverySlowFrontProgressAsync()
    {
        var settings = new ServiceOptions { Mailboxes = new(StringComparer.Ordinal) { ["user-a"] = "alice@example.test" } };
        var actor = new MailboxIdentity("user-a", "alice@example.test", "chatgpt-test", "slow-front");
        var candidates = Enumerable.Range(0, 8).Select(index => new MailboxDirectoryCandidate(
            Guid.Parse($"{index + 1:D8}-4444-5555-6666-777777777777").ToString("D"),
            $"slow{index:D2}@example.test", null, 1)).ToArray();
        var slowMailboxes = candidates.Take(6).Select(candidate => candidate.Mailbox).ToHashSet(StringComparer.Ordinal);
        var blocked = true;
        var reader = new RecordingMailboxPermissionReader(read: async (identity, token) =>
        {
            if (blocked && slowMailboxes.Contains(identity.Mailbox))
                await Task.Delay(Timeout.InfiniteTimeSpan, token);
            return RecordingMailboxPermissionReader.AllowedReport;
        });
        var access = new MailboxAccess(Options.Create(settings));
        var discovery = new MailboxDiscovery(access, new StaticMailboxDirectory(candidates), reader,
            NewDiscoveryEwsClient(new FolderDiscoveryHandler(), access), NullLogger<MailboxDiscovery>.Instance,
            TimeSpan.FromSeconds(1));
        var first = await discovery.DiscoverAsync(actor, CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(5));
        Expect(first.ScannedCount == 0 && !first.CatalogScanComplete && reader.Calls == 6,
            "The slow-front fixture did not hit its bounded deadline with six started pending candidates.");
        await Task.Delay(TimeSpan.FromSeconds(5.1));
        var second = await discovery.DiscoverAsync(actor, CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(5));
        Expect(second.ScannedCount == 2 && !second.CatalogScanComplete
            && candidates.Skip(6).All(candidate => second.Targets.Any(target => target.Candidate.Key == candidate.Key)),
            "Deadline continuation restarted the same slow front instead of advancing past candidates whose checks actually started.");
        blocked = false;
        await Task.Delay(TimeSpan.FromSeconds(5.1));
        var completed = await discovery.DiscoverAsync(actor, CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(5));
        Expect(completed.Complete && completed.ScannedCount == 8 && completed.Targets.Count == 8
            && candidates.Take(6).All(candidate => reader.CallsFor(candidate.Mailbox) >= 2),
            "Deadline-canceled candidates were lost instead of being retried after later catalog targets progressed.");
    }

    private async Task AssertLdapMailboxDiscoveryPagesAsync()
    {
        var entries = Enumerable.Range(0, 33).Select(index => MailboxEntry(
            Guid.Parse($"{index + 1:D8}-2222-3333-4444-555555555555"), $"user{index:D2}@example.test")).ToArray();
        var factory = new MailboxPageFactory((cookie, call) => call switch
        {
            1 when cookie.Length == 0 => new(entries[..32], [0x21]),
            2 when cookie.SequenceEqual(new byte[] { 0x21 }) => new(entries[32..], []),
            _ => throw new InvalidOperationException("Unexpected mailbox page cursor.")
        });
        var directory = NewMailboxDirectory(factory);
        var results = await directory.ListAsync(CancellationToken.None);
        Expect(results.Count == 33 && factory.Pages.Count == 2
            && factory.Pages[0].PageSize == 32 && factory.Pages[0].Cookie.Length == 0
            && factory.Pages[1].Cookie.SequenceEqual(new byte[] { 0x21 })
            && results.Select(item => item.Mailbox).Distinct(StringComparer.OrdinalIgnoreCase).Count() == 33,
            "Paged LDAP mailbox discovery did not carry its cookie and return more than one page.");
        Expect(factory.Pages.All(page => page.Filter.Contains("objectClass=user", StringComparison.Ordinal)
                && page.Attributes.Contains("objectGUID", StringComparer.OrdinalIgnoreCase)
                && page.Scope == SearchScope.Subtree && !page.RequestDaclOnly),
            "Mailbox discovery did not request bounded mailbox identity metadata from the directory.");
    }

    private async Task AssertLdapMailboxDiscoveryFailsClosedAsync()
    {
        var first = MailboxEntry(DiscoveryMailboxGuid, "first@example.test");
        var second = MailboxEntry(Guid.Parse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"), "second@example.test");
        await AssertThrowsAsync<InvalidDataException>(() => NewMailboxDirectory(new MailboxPageFactory((_, _) =>
            new([first, second with { BinaryAttributes = first.BinaryAttributes }], [])))
            .ListAsync(CancellationToken.None));

        var badPrimary = MailboxEntry(Guid.NewGuid(), "bad@example.test", primaryProxies: ["smtp:bad@example.test"]);
        var badResults = await NewMailboxDirectory(new MailboxPageFactory((_, _) => new([badPrimary], [])))
            .ListAsync(CancellationToken.None);
        Expect(badResults.Count == 0, "LDAP mailbox discovery accepted a record without one canonical primary SMTP address.");

        var overlongCookie = new MailboxPageFactory((_, _) => new([], new byte[16 * 1024 + 1]));
        await AssertThrowsAsync<InvalidDataException>(() => NewMailboxDirectory(overlongCookie).ListAsync(CancellationToken.None));

        var repeatedCookie = new MailboxPageFactory((_, call) => new([call == 1 ? first : second], [0x55]));
        await AssertThrowsAsync<InvalidDataException>(() => NewMailboxDirectory(repeatedCookie).ListAsync(CancellationToken.None));

        var pageCalls = 0;
        var truncated = new MailboxPageFactory((_, _) => new([], BitConverter.GetBytes(++pageCalls)));
        await AssertThrowsAsync<InvalidDataException>(() => NewMailboxDirectory(truncated).ListAsync(CancellationToken.None));
        Expect(pageCalls == 32, "LDAP mailbox discovery silently truncated results at its page limit.");

        var completeLimitCalls = 0;
        var atLimit = new MailboxPageFactory((_, call) =>
        {
            var page = Enumerable.Range((call - 1) * 32, 32)
                .Select(index => MailboxEntry(Guid.Parse($"{index + 1:D8}-3333-4444-5555-666666666666"), $"limit{index:D4}@example.test"))
                .ToArray();
            completeLimitCalls++;
            return new(page, call == 32 ? [] : BitConverter.GetBytes(call));
        });
        Expect((await NewMailboxDirectory(atLimit).ListAsync(CancellationToken.None)).Count == 1024
            && completeLimitCalls == 32,
            "LDAP mailbox discovery did not accept exactly its configured result cap without truncation.");

        var changedKeyFactory = new MailboxPageFactory((_, _) => new([], []), _ => [second]);
        await AssertThrowsAsync<InvalidDataException>(() => NewMailboxDirectory(changedKeyFactory)
            .ResolveAsync(DiscoveryMailboxKey, CancellationToken.None));

        var changedPrimaryFactory = new MailboxPageFactory((_, _) => new([], []), _ =>
            [MailboxEntry(DiscoveryMailboxGuid, "reassigned@example.test")]);
        var changedPrimary = await NewMailboxDirectory(changedPrimaryFactory)
            .ResolveAsync(DiscoveryMailboxKey, CancellationToken.None);
        Expect(changedPrimary?.Mailbox == "reassigned@example.test",
            "LDAP did not resolve the current primary SMTP for the same stable objectGUID.");
    }

    private async Task AssertEwsMailboxFolderDiscoveryBoundsAsync()
    {
        var actorMailbox = "alice@example.test";
        var access = new MailboxAccess(Options.Create(new ServiceOptions
        {
            Mailboxes = new(StringComparer.Ordinal) { ["user-a"] = actorMailbox }
        }));
        var actor = new MailboxIdentity("user-a", "target@example.test", "chatgpt-test", "folder-discovery-check",
            DiscoveryMailboxKey, actorMailbox);
        var mixed = new FolderDiscoveryHandler(deniedFolder: "tasks");
        EwsMailboxFolderDiscovery partial;
        using (access.SelectTarget(actor))
            partial = await NewDiscoveryEwsClient(mixed, access).DiscoverMailboxFoldersAsync("target@example.test", CancellationToken.None);
        Expect(partial.Complete && partial.Folders.All(folder => folder.DistinguishedId != "tasks")
            && partial.Folders.Any(folder => folder.DistinguishedId == "inbox")
            && mixed.KnownFolderIds.Order(StringComparer.Ordinal).SequenceEqual(
                ["calendar", "contacts", "deleteditems", "drafts", "inbox", "msgfolderroot", "sentitems", "tasks"])
            && mixed.Calls.First(call => call.Operation == "GetFolder").FolderReferences.SequenceEqual(
                ["DistinguishedFolderId:inbox", "DistinguishedFolderId:calendar", "DistinguishedFolderId:tasks",
                    "DistinguishedFolderId:contacts", "DistinguishedFolderId:drafts", "DistinguishedFolderId:sentitems",
                    "DistinguishedFolderId:deleteditems", "DistinguishedFolderId:msgfolderroot"]),
            $"EWS mailbox discovery did not retain accessible known folders while handling an item-level denial (complete={partial.Complete}, folders={string.Join(',', partial.Folders.Select(folder => $"{folder.DistinguishedId}:{folder.Name}"))}, known={string.Join(',', mixed.KnownFolderIds)}, operations={string.Join(',', mixed.Calls.Select(call => call.Operation))}).");

        var deniedRoot = new FolderDiscoveryHandler(deniedFolder: "msgfolderroot");
        EwsMailboxFolderDiscovery incomplete;
        using (access.SelectTarget(actor))
            incomplete = await NewDiscoveryEwsClient(deniedRoot, access).DiscoverMailboxFoldersAsync("target@example.test", CancellationToken.None);
        Expect(!incomplete.Complete && incomplete.Folders.Any(folder => folder.DistinguishedId == "inbox")
            && deniedRoot.FindFolderCalls == 0,
            "EWS mailbox discovery treated a denied mailbox root as a complete hierarchy.");

        var capped = new FolderDiscoveryHandler(enumerateHierarchy: true);
        var folders = await NewDiscoveryEwsClient(capped).DiscoverMailboxFoldersAsync("target@example.test", CancellationToken.None);
        Expect(folders.Folders.Count == 512 && !folders.Complete && capped.FindFolderCalls == 6,
            "EWS mailbox discovery did not enforce the 512-folder cap as an incomplete result.");

        var numeric = new FolderDiscoveryHandler(enumerateHierarchy: true, hierarchyFolderCount: 120, numericBooleans: true);
        var numericFolders = await NewDiscoveryEwsClient(numeric).DiscoverMailboxFoldersAsync("target@example.test", CancellationToken.None);
        Expect(numericFolders.Complete && numericFolders.Folders.Count == 128 && numeric.FindFolderCalls == 2,
            "XML numeric pagination booleans caused missing folders or false incomplete discovery.");
    }

    private async Task AssertFolderPagingAndContextAsync()
    {
        var numeric = new FolderDiscoveryHandler(enumerateHierarchy: true, hierarchyFolderCount: 120, numericBooleans: true);
        var folders = await NewDiscoveryEwsClient(numeric).ListFoldersAsync("alice@example.test", CancellationToken.None);
        Expect(folders.Count == 120 && numeric.FindFolderCalls == 2
            && folders.Single(folder => folder.Id == "extra-001").ParentId == "extra-000",
            "Ordinary folder listing stopped on XML 0 or dropped the native parent identity.");
        foreach (var invalid in new[] { "", "invalid", "False" })
        {
            var malformed = new FolderDiscoveryHandler { PageCompletenessOverride = invalid };
            await AssertThrowsAsync<InvalidOperationException>(() => NewDiscoveryEwsClient(malformed)
                .ListFoldersAsync("alice@example.test", CancellationToken.None));
            var incomplete = await NewDiscoveryEwsClient(malformed)
                .DiscoverMailboxFoldersAsync("alice@example.test", CancellationToken.None);
            Expect(!incomplete.Complete, "Malformed XML pagination was reported as a complete folder hierarchy.");
        }
        var missingFlag = new FolderDiscoveryHandler { OmitPageCompleteness = true };
        await AssertThrowsAsync<InvalidOperationException>(() => NewDiscoveryEwsClient(missingFlag)
            .ListFoldersAsync("alice@example.test", CancellationToken.None));
        var missingCollection = new FolderDiscoveryHandler { OmitFolderCollection = true };
        await AssertThrowsAsync<InvalidOperationException>(() => NewDiscoveryEwsClient(missingCollection)
            .ListFoldersAsync("alice@example.test", CancellationToken.None));

        var discovery = new TestMailboxDiscovery("user-a");
        discovery.SetFolderDiscovery(DiscoveryMailboxKey,
        [
            new("root", "Top of Information Store", "IPF.Note", "msgfolderroot", new(true, false, false, false)),
            new("parent", "Projects", "IPF.Note", null, new(true, false, false, false), ParentId: "root"),
            new("child", "Reports", "IPF.Note", null, new(true, false, false, false), ParentId: "parent"),
            new("orphan", "Reports", "IPF.Note", null, new(true, false, false, false), ParentId: "owner-only-parent"),
            new("cycle", "Cycle", "IPF.Note", null, new(true, false, false, false), ParentId: "cycle")
        ], true);
        await using var host = await StartHostAsync(new FolderDiscoveryHandler(), writesEnabled: false, sendEnabled: false,
            configure: builder => builder.Services.AddSingleton<IMailboxDiscovery>(discovery));
        await using var native = await CreateNativeClientAsync(host,
            Token("user-a", "mail.read", sessionId: "folder-context"), new NativeFormResponder(accept: false));
        var result = await native.Client.CallToolAsync("mail_list_folders", new Dictionary<string, object?>
        {
            ["mailboxHandle"] = await TargetHandleAsync(native.Client)
        });
        var listed = NativeData(result).EnumerateArray().ToArray();
        var nested = listed.Single(folder => folder.GetProperty("name").GetString() == "Reports"
            && folder.TryGetProperty("parentHandle", out var parent) && parent.ValueKind == System.Text.Json.JsonValueKind.String);
        var orphan = listed.Single(folder => folder.GetProperty("name").GetString() == "Reports"
            && (!folder.TryGetProperty("parentHandle", out var parent) || parent.ValueKind == System.Text.Json.JsonValueKind.Null));
        Expect(result.IsError != true && nested.GetProperty("path").GetProperty("complete").GetBoolean()
            && nested.GetProperty("path").GetProperty("segments").EnumerateArray().Select(segment => segment.GetString())
                .SequenceEqual(["Projects", "Reports"])
            && !orphan.GetProperty("path").GetProperty("complete").GetBoolean()
            && orphan.GetProperty("path").GetProperty("segments").GetArrayLength() == 1
            && !listed.Single(folder => folder.GetProperty("name").GetString() == "Cycle")
                .GetProperty("path").GetProperty("complete").GetBoolean()
            && !NativeData(result).GetRawText().Contains("owner-only-parent", StringComparison.Ordinal),
            "Folder context lost accessible ancestry, leaked a hidden parent identity, or treated an incomplete/cyclic path as complete.");
    }

    private async Task AssertMailboxDiscoveryRechecksActorAsync()
    {
        var settings = new ServiceOptions
        {
            AllowedClientIds = ["chatgpt-test"],
            Mailboxes = new(StringComparer.Ordinal) { ["user-a"] = "alice@example.test" },
            AllowedRecipientDomains = ["example.test"]
        };
        var access = new MailboxAccess(Options.Create(settings));
        var candidate = new MailboxDirectoryCandidate(DiscoveryMailboxKey, "it@example.test", "Information Technology", 1);
        var directory = new MutableMailboxDirectory(candidate);
        var permissionReader = new RecordingMailboxPermissionReader();
        var ewsHandler = new FolderDiscoveryHandler();
        var discovery = new MailboxDiscovery(access, directory, permissionReader, NewDiscoveryEwsClient(ewsHandler, access), NullLogger<MailboxDiscovery>.Instance);
        var actor = new MailboxIdentity("user-a", "alice@example.test", "chatgpt-test", "test-session");

        var listed = await discovery.DiscoverAsync(actor, CancellationToken.None);
        var actorCalls = ewsHandler.Calls.Where(call => call.ConnectingSid == actor.Mailbox).ToArray();
        var metadataOwnerCalls = ewsHandler.Calls.Where(call => call.ConnectingSid == candidate.Mailbox).ToArray();
        Expect(listed.Targets.Count == 1
            && permissionReader.Calls == 1
            && permissionReader.LastIdentity is { Mailbox: "it@example.test", ActorMailbox: "alice@example.test", TargetId: DiscoveryMailboxKey }
            && actorCalls.Length > 0 && actorCalls.All(call => call.Anchor == "alice@example.test"
                && call.ConnectingSid == "alice@example.test"
                && call.Operation is "GetFolder" or "FindFolder"
                && call.MailboxOwners.All(owner => owner == "it@example.test")
                && !call.Body.Contains("GetItem", StringComparison.Ordinal)
                && !call.Body.Contains("FindItem", StringComparison.Ordinal))
            && metadataOwnerCalls.Length > 0 && metadataOwnerCalls.All(call => call.Anchor == candidate.Mailbox
                && call.Operation is "GetFolder" or "FindFolder"
                && call.Body.Contains("IdOnly", StringComparison.Ordinal)
                && !call.Body.Contains("GetItem", StringComparison.Ordinal)
                && !call.Body.Contains("FindItem", StringComparison.Ordinal)
                && !call.Body.Contains("item:Body", StringComparison.Ordinal)
                && !call.Body.Contains("item:Attachments", StringComparison.Ordinal))
            && ewsHandler.Calls.Count == actorCalls.Length + metadataOwnerCalls.Length,
            "Mailbox discovery did not restrict actor requests to the selected mailbox or owner fallback to IdOnly folder metadata.");

        settings.Mailboxes["user-a"] = "changed@example.test";
        var beforeEws = ewsHandler.Calls.Count;
        var beforePermissions = permissionReader.Calls;
        var stale = await discovery.ResolveAsync(actor, DiscoveryMailboxKey, CancellationToken.None);
        Expect(stale is null && ewsHandler.Calls.Count == beforeEws && permissionReader.Calls == beforePermissions,
            "Selecting a discovered mailbox skipped the current signed-in actor mailbox recheck.");
    }

    private async Task AssertMailboxMetadataOwnerFallbackRechecksActorAsync()
    {
        var settings = new ServiceOptions
        {
            AllowedClientIds = ["chatgpt-test"],
            Mailboxes = new(StringComparer.Ordinal) { ["user-a"] = "alice@example.test" },
            AllowedRecipientDomains = ["example.test"]
        };
        var access = new MailboxAccess(Options.Create(settings));
        var candidate = new MailboxDirectoryCandidate(DiscoveryMailboxKey, "it@example.test", "IT", 1);
        var directory = new MutableMailboxDirectory(candidate);
        var handler = new FolderDiscoveryHandler(deniedFolder: "msgfolderroot", enumerateHierarchy: true,
            hierarchyFolderCount: 2);
        var ews = NewDiscoveryEwsClient(handler, access);
        var discovery = new MailboxDiscovery(access, directory, new RecordingMailboxPermissionReader(), ews, NullLogger<MailboxDiscovery>.Instance);
        var actor = new MailboxIdentity("user-a", "alice@example.test", "chatgpt-test", "metadata-session");

        var snapshot = await discovery.DiscoverAsync(actor, CancellationToken.None);
        var target = await discovery.ResolveAsync(actor, candidate.Key, CancellationToken.None);
        var ownerCalls = handler.Calls.Where(call => call.ConnectingSid == candidate.Mailbox).ToArray();
        var actorFolderCheck = handler.Calls.Where(call => call.Operation == "GetFolder"
                && call.FolderIds.Contains("extra-000", StringComparer.Ordinal))
            .ToArray();
        Expect(snapshot.CatalogScanComplete && !snapshot.Complete && snapshot.PermissionCheckFailures == 1
            && target is not null && target.FolderAccess.Complete
            && target.FolderAccess.Folders.All(folder => folder.Id != "extra-000")
            && target.FolderAccess.Folders.Any(folder => folder.Id == "extra-001"
                && folder.Rights.Read == true && folder.Rights.Create == false
                && folder.Rights.Modify == false && folder.Rights.Delete == false)
            && ownerCalls.Length > 0 && ownerCalls.All(call => call.Anchor == candidate.Mailbox
                && call.Operation is "GetFolder" or "FindFolder"
                && call.Body.Contains("IdOnly", StringComparison.Ordinal)
                && !call.Body.Contains("GetItem", StringComparison.Ordinal)
                && !call.Body.Contains("CreateItem", StringComparison.Ordinal))
            && actorFolderCheck.Length > 0 && actorFolderCheck.All(call => call.Anchor == actor.Mailbox
                && call.ConnectingSid == actor.Mailbox
                && !call.Body.Contains("<t:Mailbox>", StringComparison.Ordinal)),
            "Owner metadata folder IDs or rights were exposed without a fresh actor-bound rights check.");

        var hiddenHierarchyHandler = new FolderDiscoveryHandler(enumerateHierarchy: true,
            hierarchyFolderCount: 2, hideActorHierarchy: true);
        var hiddenHierarchyPermissions = new RecordingMailboxPermissionReader();
        var hiddenHierarchyAccess = new MailboxAccess(Options.Create(settings));
        var hiddenHierarchyDiscovery = new MailboxDiscovery(hiddenHierarchyAccess, directory,
            hiddenHierarchyPermissions, NewDiscoveryEwsClient(hiddenHierarchyHandler, hiddenHierarchyAccess), NullLogger<MailboxDiscovery>.Instance);
        var hiddenSnapshot = await hiddenHierarchyDiscovery.DiscoverAsync(actor, CancellationToken.None);
        var hiddenTarget = await hiddenHierarchyDiscovery.ResolveAsync(actor, candidate.Key, CancellationToken.None);
        var hiddenOwnerCalls = hiddenHierarchyHandler.Calls
            .Where(call => call.ConnectingSid == candidate.Mailbox).ToArray();
        var hiddenActorIdChecks = hiddenHierarchyHandler.Calls.Where(call => call.Operation == "GetFolder"
                && call.ConnectingSid == actor.Mailbox && call.FolderIds.Length > 0)
            .ToArray();
        var hiddenActorCheckedIds = hiddenActorIdChecks.SelectMany(call => call.FolderIds)
            .ToHashSet(StringComparer.Ordinal);
        Expect(hiddenSnapshot.CatalogScanComplete && !hiddenSnapshot.Complete
            && hiddenSnapshot.PermissionCheckFailures == 1
            && hiddenTarget is not null && hiddenTarget.FolderAccess.Complete
            && hiddenTarget.Permissions.FullAccess.State == "unknown"
            && hiddenOwnerCalls.Any(call => call.Operation == "FindFolder")
            && hiddenOwnerCalls.All(call => call.Operation is "GetFolder" or "FindFolder"
                && call.Body.Contains("IdOnly", StringComparison.Ordinal)
                && !call.Body.Contains("GetItem", StringComparison.Ordinal)
                && !call.Body.Contains("FindItem", StringComparison.Ordinal)
                && !call.Body.Contains("item:Body", StringComparison.Ordinal)
                && !call.Body.Contains("item:Attachments", StringComparison.Ordinal))
            && hiddenActorIdChecks.Length > 0
            && hiddenActorCheckedIds.Contains("extra-000") && hiddenActorCheckedIds.Contains("extra-001")
            && hiddenActorCheckedIds.Contains("folder-msgfolderroot")
            && hiddenTarget.FolderAccess.Folders.All(folder => folder.Id != "extra-000"
                && folder.Id != "folder-msgfolderroot")
            && hiddenTarget.FolderAccess.Folders.Single(folder => folder.Id == "extra-001").Rights
                == new EwsFolderAccessRights(true, false, false, false),
            "A successful but incomplete actor hierarchy did not trigger owner-only metadata enumeration followed by fresh actor rights checks; owner rights/content leaked or denied IDs were retained.");

        foreach (var invalid in new[]
        {
            candidate with { Key = "not-a-guid" },
            candidate with { RecipientTypeDetails = 128 },
            candidate with { Mailbox = "invalid-address" }
        })
        {
            var invalidAccess = new MailboxAccess(Options.Create(settings));
            var invalidDirectory = new MutableMailboxDirectory(invalid);
            var invalidHandler = new FolderDiscoveryHandler(deniedFolder: "msgfolderroot");
            var invalidDiscovery = new MailboxDiscovery(invalidAccess, invalidDirectory,
                new RecordingMailboxPermissionReader(), NewDiscoveryEwsClient(invalidHandler, invalidAccess), NullLogger<MailboxDiscovery>.Instance);
            var invalidSnapshot = await invalidDiscovery.DiscoverAsync(actor, CancellationToken.None);
            Expect(!invalidSnapshot.Complete
                && invalidHandler.Calls.All(call => call.ConnectingSid == actor.Mailbox),
                "Owner metadata fallback ran for a malformed or non-native directory mailbox candidate.");
        }

        foreach (var recipientType in new long[] { 1, 4, 16, 32 })
        {
            var aliasCandidate = candidate with { Mailbox = "it@outside.test", RecipientTypeDetails = recipientType };
            var aliasAccess = new MailboxAccess(Options.Create(settings));
            var aliasHandler = new FolderDiscoveryHandler(deniedFolder: "msgfolderroot", enumerateHierarchy: true,
                hierarchyFolderCount: 2)
            { WhitespaceFolderName = true };
            var aliasDiscovery = new MailboxDiscovery(aliasAccess, new MutableMailboxDirectory(aliasCandidate),
                new RecordingMailboxPermissionReader(), NewDiscoveryEwsClient(aliasHandler, aliasAccess), NullLogger<MailboxDiscovery>.Instance);
            var aliasTarget = await aliasDiscovery.ResolveAsync(actor, aliasCandidate.Key, CancellationToken.None);
            Expect(aliasTarget is { FolderAccess.Complete: true }
                && aliasHandler.Calls.Any(call => call.ConnectingSid == aliasCandidate.Mailbox && call.Operation == "FindFolder")
                && aliasHandler.Calls.Any(call => call.ConnectingSid == actor.Mailbox && call.FolderIds.Length > 0)
                && aliasTarget.FolderAccess.Folders.All(folder => folder.Rights.Create != true)
                && aliasTarget.FolderAccess.Folders.Single(folder => folder.Id == "extra-001").Name == "(unnamed folder)",
                "Native mailbox metadata or a safely labeled whitespace folder skipped actor rights checks or lost completeness.");
        }
    }

    private static LdapMailboxPermissionReader NewMailboxDirectory(MailboxPageFactory factory) => new(
        Options.Create(new DirectoryPermissionOptions
        {
            Host = "ldap.example.test",
            Port = 636,
            BaseDn = "DC=example,DC=test",
            TimeoutSeconds = 8
        }), factory, NullLogger<LdapMailboxPermissionReader>.Instance);

    private async Task AssertConcealedFolderDenialsCompleteDiscoveryAsync()
    {
        var settings = new ServiceOptions
        {
            Mailboxes = new(StringComparer.Ordinal) { ["user-a"] = "alice@example.test" },
            AllowedRecipientDomains = ["example.test"]
        };
        var actor = new MailboxIdentity("user-a", "alice@example.test", "chatgpt-test", "concealment-check");
        var access = new MailboxAccess(Options.Create(settings));
        var handler = new FolderDiscoveryHandler(enumerateHierarchy: true, hierarchyFolderCount: 2)
        {
            DenyAllForActor = true,
            ConcealDeniedFolders = true
        };
        var denied = new MailboxPermissionReport(new("denied", "no Full Access"), new("denied", "no Send As"),
            new("denied", "no Send on Behalf"), DateTimeOffset.UtcNow, "test");
        var discovery = new MailboxDiscovery(access,
            new MutableMailboxDirectory(new(DiscoveryMailboxKey, "target@example.test", null, 1)),
            new RecordingMailboxPermissionReader(read: (_, _) => Task.FromResult(denied)),
            NewDiscoveryEwsClient(handler, access), NullLogger<MailboxDiscovery>.Instance);
        var result = await discovery.DiscoverAsync(actor, CancellationToken.None);
        Expect(result.Complete && result.CatalogScanComplete && result.IncompleteFolderTargets == 0
            && result.PermissionCheckFailures == 0 && result.Targets.Count == 0
            && handler.Calls.Any(call => call.ConnectingSid == "target@example.test" && call.Operation == "FindFolder")
            && handler.Calls.Any(call => call.ConnectingSid == actor.Mailbox && call.FolderIds.Length > 0),
            "Exchange folder concealment errors were treated as scan failures or exposed owner-only folder access.");
    }

    private EwsClient NewDiscoveryEwsClient(HttpMessageHandler handler, MailboxAccess? access = null) => new(new HttpClient(handler),
        Options.Create(new EwsOptions
        {
            Endpoint = "https://mail.example.test/EWS/Exchange.asmx",
            TimeoutSeconds = 10,
            MaxResponseBytes = 2_097_152
        }), access);

    private static LdapSearchEntry MailboxEntry(Guid guid, string mailbox, string[]? primaryProxies = null)
    {
        var smtp = primaryProxies ?? [$"SMTP:{mailbox}"];
        return new($"CN={mailbox.Split('@')[0]},DC=example,DC=test",
            new Dictionary<string, IReadOnlyList<string>>(StringComparer.OrdinalIgnoreCase)
            {
                ["objectCategory"] = ["CN=Person,CN=Schema,CN=Configuration,DC=example,DC=test"],
                ["objectClass"] = ["top", "person", "organizationalPerson", "user"],
                ["displayName"] = [mailbox],
                ["proxyAddresses"] = smtp,
                ["msExchRecipientTypeDetails"] = ["1"],
                ["homeMDB"] = ["CN=Mailbox Database"],
                ["legacyExchangeDN"] = [$"/o=Example/ou=Exchange Administrative Group/cn=Recipients/cn={mailbox}"]
            },
            new Dictionary<string, IReadOnlyList<byte[]>>(StringComparer.OrdinalIgnoreCase)
            {
                ["objectGUID"] = [guid.ToByteArray()]
            });
    }
}

internal sealed class MailboxPageFactory(
    Func<byte[], int, LdapSearchPage> page,
    Func<string, IReadOnlyList<LdapSearchEntry>>? search = null) : ILdapSearchFacadeFactory
{
    private readonly Func<byte[], int, LdapSearchPage> pageHandler = page;
    private readonly Func<string, IReadOnlyList<LdapSearchEntry>>? searchHandler = search;
    private int pageCalls;
    public List<MailboxPageRequest> Pages { get; } = [];
    public ILdapSearchFacade Create() => new Facade(this);

    private sealed class Facade(MailboxPageFactory owner) : ILdapSearchFacade
    {
        public IReadOnlyList<LdapSearchEntry> Search(string baseDn, string filter, SearchScope scope,
            IReadOnlyList<string> attributes, bool requestDaclOnly, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return owner.searchHandler?.Invoke(filter) ?? [];
        }

        public LdapSearchPage SearchPage(string baseDn, string filter, SearchScope scope,
            IReadOnlyList<string> attributes, bool requestDaclOnly, byte[] cookie, int pageSize,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            owner.Pages.Add(new(baseDn, filter, scope, attributes.ToArray(), requestDaclOnly, cookie.ToArray(), pageSize));
            return owner.pageHandler(cookie, Interlocked.Increment(ref owner.pageCalls));
        }

        public void Dispose() { }
    }
}

internal sealed record MailboxPageRequest(string BaseDn, string Filter, SearchScope Scope,
    IReadOnlyList<string> Attributes, bool RequestDaclOnly, byte[] Cookie, int PageSize);

internal sealed class MutableMailboxDirectory(MailboxDirectoryCandidate candidate) : IMailboxDirectory
{
    public Task<IReadOnlyList<MailboxDirectoryCandidate>> ListAsync(CancellationToken cancellationToken) =>
        Task.FromResult<IReadOnlyList<MailboxDirectoryCandidate>>([candidate]);
    public Task<MailboxDirectoryCandidate?> ResolveAsync(string key, CancellationToken cancellationToken) =>
        Task.FromResult<MailboxDirectoryCandidate?>(candidate);
}

internal sealed class StaticMailboxDirectory(IReadOnlyList<MailboxDirectoryCandidate> candidates) : IMailboxDirectory
{
    public Task<IReadOnlyList<MailboxDirectoryCandidate>> ListAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(candidates);
    }

    public Task<MailboxDirectoryCandidate?> ResolveAsync(string key, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(candidates.FirstOrDefault(candidate => candidate.Key == key));
    }
}

internal sealed class RecordingMailboxPermissionReader(bool fullAccessAllowed = false,
    Func<MailboxIdentity, CancellationToken, Task<MailboxPermissionReport>>? read = null) : IMailboxPermissionReader
{
    private int calls;
    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, int> callsByMailbox = new(StringComparer.OrdinalIgnoreCase);
    public int Calls => Volatile.Read(ref calls);
    public MailboxIdentity? LastIdentity { get; private set; }
    public static MailboxPermissionReport AllowedReport => new(new("allowed", "synthetic FullAccess"),
        new("denied", "synthetic SendAs denial"), new("denied", "synthetic Send on Behalf denial"),
        DateTimeOffset.UtcNow, "test");

    public int CallsFor(string mailbox) => callsByMailbox.GetValueOrDefault(mailbox);

    public async Task<MailboxPermissionReport> ReadAsync(MailboxIdentity identity, CancellationToken cancellationToken)
    {
        Interlocked.Increment(ref calls);
        callsByMailbox.AddOrUpdate(identity.Mailbox, 1, static (_, current) => current + 1);
        LastIdentity = identity;
        if (read is not null)
            return await read(identity, cancellationToken).ConfigureAwait(false);
        return fullAccessAllowed ? AllowedReport : new MailboxPermissionReport(PermissionDecision.Unknown("test"),
            PermissionDecision.Unknown("test"), PermissionDecision.Unknown("test"), DateTimeOffset.UtcNow, "test");
    }
}

internal sealed class FolderDiscoveryHandler(string? deniedFolder = null, bool enumerateHierarchy = false,
    string denyRootForActorMailbox = "alice@example.test", int hierarchyFolderCount = 600,
    bool hideActorHierarchy = false, bool numericBooleans = false) : HttpMessageHandler
{
    private static readonly XNamespace Soap = "http://schemas.xmlsoap.org/soap/envelope/";
    private static readonly XNamespace Messages = "http://schemas.microsoft.com/exchange/services/2006/messages";
    private static readonly XNamespace Types = "http://schemas.microsoft.com/exchange/services/2006/types";
    public List<FolderDiscoveryCall> Calls { get; } = [];
    public int FindFolderCalls { get; private set; }
    public bool DenyAllForActor { get; set; }
    public bool DenyMetadataOwner { get; set; }
    public bool HideReadAccessForActor { get; set; }
    public bool ConcealDeniedFolders { get; set; }
    public bool WhitespaceFolderName { get; set; }
    public string? PageCompletenessOverride { get; set; }
    public bool OmitPageCompleteness { get; set; }
    public bool OmitFolderCollection { get; set; }
    public bool FailActorFolderRights { get; set; }
    public string[] KnownFolderIds => Calls.SelectMany(call => call.KnownFolderIds).Distinct(StringComparer.Ordinal).ToArray();

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var body = await request.Content!.ReadAsStringAsync(cancellationToken);
        var document = XDocument.Parse(body);
        var operation = document.Root!.Element(Soap + "Body")!.Elements().Single();
        var name = operation.Name.LocalName;
        var connectingSid = document.Descendants(Types + "PrimarySmtpAddress").SingleOrDefault()?.Value;
        var ids = operation.Descendants(Types + "DistinguishedFolderId")
            .Select(element => (string?)element.Attribute("Id")).Where(id => id is not null).Cast<string>().ToArray();
        var rawFolderIds = operation.Descendants(Types + "FolderId")
            .Select(element => (string?)element.Attribute("Id")).Where(id => id is not null).Cast<string>().ToArray();
        var references = operation.Descendants().Where(element => element.Name == Types + "DistinguishedFolderId"
                || element.Name == Types + "FolderId")
            .Select(element => $"{element.Name.LocalName}:{(string?)element.Attribute("Id")}").ToArray();
        var owners = operation.Descendants(Types + "DistinguishedFolderId")
            .Select(element => element.Element(Types + "Mailbox")?.Element(Types + "EmailAddress")?.Value)
            .Where(owner => owner is not null).Cast<string>().ToArray();
        lock (Calls)
            Calls.Add(new(name, request.Headers.TryGetValues("X-AnchorMailbox", out var anchors) ? anchors.SingleOrDefault() : null,
                connectingSid, ids, rawFolderIds, references, owners, body));
        if (FailActorFolderRights && rawFolderIds.Length > 0 && connectingSid == denyRootForActorMailbox)
            throw new HttpRequestException("Synthetic actor folder-rights lookup failure.");
        if (DenyMetadataOwner && connectingSid != denyRootForActorMailbox)
            return new HttpResponseMessage(HttpStatusCode.InternalServerError)
            {
                Content = new StringContent(
                new XElement(Soap + "Envelope", new XElement(Soap + "Body", new XElement(Soap + "Fault",
                    new XElement("faultcode", "a:ErrorImpersonateUserDenied"), new XElement("faultstring", "Denied"))))
                .ToString(SaveOptions.DisableFormatting), Encoding.UTF8, "text/xml")
            };
        XElement responseBody;
        if (name == "FindFolder")
        {
            FindFolderCalls++;
            var view = operation.Element(Messages + "IndexedPageFolderView");
            var offset = (int?)view?.Attribute("Offset") ?? 0;
            var actorHierarchyHidden = (hideActorHierarchy || DenyAllForActor)
                && string.Equals(connectingSid, denyRootForActorMailbox, StringComparison.OrdinalIgnoreCase);
            var visibleFolderCount = actorHierarchyHidden ? 0 : hierarchyFolderCount;
            var entries = enumerateHierarchy && offset < visibleFolderCount
                ? Enumerable.Range(offset, Math.Min(100, visibleFolderCount - offset))
                    .Select(index => FolderElement($"extra-{index:D3}", null, create: true, modify: true, delete: true)).ToArray()
                : [];
            var lastPage = !enumerateHierarchy || actorHierarchyHidden || offset + entries.Length >= visibleFolderCount;
            var root = new XElement(Messages + "RootFolder", new XAttribute("IncludesLastItemInRange",
                    PageCompletenessOverride ?? (numericBooleans ? (lastPage ? "1" : "0") : lastPage.ToString().ToLowerInvariant())),
                new XAttribute("IndexedPagingOffset", offset + entries.Length),
                new XElement(Types + "Folders", entries));
            if (OmitPageCompleteness) root.Attribute("IncludesLastItemInRange")!.Remove();
            if (OmitFolderCollection) root.Element(Types + "Folders")!.Remove();
            responseBody = new(Messages + "FindFolderResponse", new XElement(Messages + "ResponseMessages",
                new XElement(Messages + "FindFolderResponseMessage", new XAttribute("ResponseClass", "Success"),
                    new XElement(Messages + "ResponseCode", "NoError"),
                    new XElement(root))));
        }
        else
        {
            var messages = ids.Select(id =>
            {
                var denied = (id == deniedFolder || DenyAllForActor) && string.Equals(connectingSid,
                    denyRootForActorMailbox, StringComparison.OrdinalIgnoreCase);
                var ownerRead = !string.Equals(connectingSid, denyRootForActorMailbox, StringComparison.OrdinalIgnoreCase);
                var actorRead = !HideReadAccessForActor || ownerRead;
                return new XElement(Messages + "GetFolderResponseMessage", new XAttribute("ResponseClass", denied ? "Error" : "Success"),
                    new XElement(Messages + "ResponseCode", denied ? (ConcealDeniedFolders ? "ErrorItemNotFound" : "ErrorAccessDenied") : "NoError"),
                    denied ? new XElement(Messages + "MessageText", "Access denied") : new XElement(Messages + "Folders",
                        FolderElement($"folder-{id}", id, read: actorRead, create: ownerRead, modify: ownerRead, delete: ownerRead)));
            });
            if (rawFolderIds.Length > 0)
            {
                var folderResponses = rawFolderIds.Select(id =>
                {
                    var denied = DenyAllForActor && string.Equals(connectingSid, denyRootForActorMailbox,
                        StringComparison.OrdinalIgnoreCase);
                    var read = !denied && (!HideReadAccessForActor || connectingSid != denyRootForActorMailbox)
                        && id is not ("extra-000" or "folder-msgfolderroot");
                    return new XElement(Messages + "GetFolderResponseMessage", new XAttribute("ResponseClass", denied ? "Error" : "Success"),
                        new XElement(Messages + "ResponseCode", denied ? (ConcealDeniedFolders ? "ErrorItemNotFound" : "ErrorAccessDenied") : "NoError"),
                        denied ? new XElement(Messages + "MessageText", "Access denied")
                            : new XElement(Messages + "Folders", FolderElement(id, null, read, create: false, modify: false, delete: false)));
                });
                responseBody = new(Messages + "GetFolderResponse", new XElement(Messages + "ResponseMessages", folderResponses));
            }
            else
                responseBody = new(Messages + "GetFolderResponse", new XElement(Messages + "ResponseMessages", messages));
        }
        if (WhitespaceFolderName)
            foreach (var nameElement in responseBody.Descendants(Types + "DisplayName").Where(element => element.Value == "extra-001"))
                nameElement.Value = "\t";
        var envelope = new XElement(Soap + "Envelope", new XAttribute(XNamespace.Xmlns + "s", Soap),
            new XAttribute(XNamespace.Xmlns + "m", Messages), new XAttribute(XNamespace.Xmlns + "t", Types),
            new XElement(Soap + "Body", responseBody));
        return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(envelope.ToString(SaveOptions.DisableFormatting), Encoding.UTF8, "text/xml") };
    }

    private static XElement FolderElement(string id, string? distinguishedId, bool read = true, bool create = false,
        bool modify = false, bool delete = false) => new(Types + "Folder",
        new XElement(Types + "FolderId", new XAttribute("Id", id), new XAttribute("ChangeKey", "change")),
        new XElement(Types + "ParentFolderId", new XAttribute("Id", id == "extra-001" ? "extra-000" : "folder-msgfolderroot")),
        new XElement(Types + "DisplayName", distinguishedId ?? id),
        new XElement(Types + "FolderClass", "IPF.Note"),
        new XElement(Types + "EffectiveRights", new XElement(Types + "Read", read.ToString().ToLowerInvariant()),
            new XElement(Types + "CreateAssociated", "false"), new XElement(Types + "CreateContents", create.ToString().ToLowerInvariant()),
            new XElement(Types + "CreateHierarchy", "false"), new XElement(Types + "Modify", modify.ToString().ToLowerInvariant()),
            new XElement(Types + "Delete", delete.ToString().ToLowerInvariant())));
}

internal sealed record FolderDiscoveryCall(string Operation, string? Anchor, string? ConnectingSid,
    string[] KnownFolderIds, string[] FolderIds, string[] FolderReferences, string[] MailboxOwners, string Body);

internal sealed class TestMailboxDiscovery : IMailboxDiscovery, IMailboxDirectory
{
    private readonly HashSet<string> allowed;
    private readonly HashSet<string> primedSubjects = new(StringComparer.Ordinal);
    private readonly Dictionary<string, DiscoveredMailbox> targets = new(StringComparer.Ordinal);
    private readonly HashSet<string> revoked = new(StringComparer.Ordinal);
    private bool hasDirectoryOverride;
    private MailboxDirectoryCandidate? directoryOverride;

    public TestMailboxDiscovery(params string[] allowedSubjects) : this(true, allowedSubjects) { }

    public bool FailDiscoveries { get; set; }
    public bool RequirePrimedCache { get; set; }
    public int DiscoveryCalls { get; private set; }

    public TestMailboxDiscovery(bool seedDefaultTarget, params string[] allowedSubjects)
    {
        allowed = new(allowedSubjects, StringComparer.Ordinal);
        if (seedDefaultTarget) AddTarget("user-a", Checks.DiscoveryMailboxKey, "it@example.test");
    }

    public MailboxDiscoverySnapshot? Cached(MailboxIdentity actor) => (!RequirePrimedCache || primedSubjects.Contains(actor.Subject))
        ? Snapshot(actor) : null;
    public void Invalidate(MailboxIdentity actor) { }
    public void ExpireCachedSnapshots() => primedSubjects.Clear();
    public void Rebind(string key, string mailbox) => AddTarget("user-a", key, mailbox);
    public void Revoke(string key) => revoked.Add(key);
    public void OverrideDirectoryResolution(MailboxDirectoryCandidate? candidate)
    {
        hasDirectoryOverride = true;
        directoryOverride = candidate;
    }
    public List<string> DirectoryResolveKeys { get; } = [];
    public void AddTarget(string subject, string key, string mailbox) =>
        targets[subject + "\0" + key] = CreateTarget(key, mailbox);
    public void SetFolderDiscoveryComplete(string key, bool complete)
    {
        foreach (var entry in targets.Where(pair => pair.Value.Candidate.Key == key).ToArray())
            targets[entry.Key] = entry.Value with
            {
                FolderAccess = entry.Value.FolderAccess with { Complete = complete }
            };
    }
    public void SetFolderDiscovery(string key, IReadOnlyList<EwsDiscoveredFolder> folders, bool complete)
    {
        foreach (var entry in targets.Where(pair => pair.Value.Candidate.Key == key).ToArray())
            targets[entry.Key] = entry.Value with { FolderAccess = new(folders, complete) };
    }

    public Task<IReadOnlyList<MailboxDirectoryCandidate>> ListAsync(CancellationToken cancellationToken) =>
        Task.FromResult<IReadOnlyList<MailboxDirectoryCandidate>>(targets.Values.Select(target => target.Candidate)
            .Where(candidate => !revoked.Contains(candidate.Key)).DistinctBy(candidate => candidate.Key).ToArray());

    public Task<MailboxDirectoryCandidate?> ResolveAsync(string key, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        DirectoryResolveKeys.Add(key);
        return Task.FromResult(hasDirectoryOverride ? directoryOverride
            : targets.Values.Select(target => target.Candidate).FirstOrDefault(candidate =>
                candidate.Key == key && !revoked.Contains(candidate.Key)));
    }

    public Task<MailboxDiscoverySnapshot> DiscoverAsync(MailboxIdentity actor, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        DiscoveryCalls++;
        if (FailDiscoveries)
            throw new InvalidOperationException("Synthetic mailbox-discovery failure.");
        primedSubjects.Add(actor.Subject);
        return Task.FromResult(Snapshot(actor));
    }

    public Task<DiscoveredMailbox?> ResolveAsync(MailboxIdentity actor, string key, CancellationToken cancellationToken) =>
        Task.FromResult(!allowed.Contains(actor.Subject) || revoked.Contains(key)
            ? null : targets.GetValueOrDefault(actor.Subject + "\0" + key));

    private MailboxDiscoverySnapshot Snapshot(MailboxIdentity actor) => new(
        allowed.Contains(actor.Subject)
            ? targets.Where(pair => pair.Key.StartsWith(actor.Subject + "\0", StringComparison.Ordinal)
                && !revoked.Contains(pair.Value.Candidate.Key)).Select(pair => pair.Value).ToArray()
            : [], allowed.Contains(actor.Subject), DateTimeOffset.UtcNow);

    private static DiscoveredMailbox CreateTarget(string key, string mailbox) => new(
        new(key, mailbox, "Information Technology", 1),
        new(PermissionDecision.Unknown("test"), PermissionDecision.Unknown("test"), PermissionDecision.Unknown("test"), DateTimeOffset.UtcNow, "test"),
        new([
            new("inbox-id", "Inbox", "IPF.Note", "inbox", new(true, false, false, false), "inbox-change"),
            new("calendar-id", "Calendar", "IPF.Appointment", "calendar", new(true, true, false, false), "calendar-change"),
            new("tasks-id", "Tasks", "IPF.Task", "tasks", new(true, true, true, false), "tasks-change")
        ], true));
}
