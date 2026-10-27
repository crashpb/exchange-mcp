using System.Collections.Concurrent;
using Company.ExchangeMcp.Exchange;

namespace Company.ExchangeMcp.Security;

public sealed record DiscoveredMailbox(MailboxDirectoryCandidate Candidate,
    MailboxPermissionReport Permissions, EwsMailboxFolderDiscovery FolderAccess);

public sealed record MailboxDiscoverySnapshot(IReadOnlyList<DiscoveredMailbox> Targets,
    bool Complete, DateTimeOffset CheckedAt, int CandidateCount = 0, int ScannedCount = 0,
    bool CatalogScanComplete = true, int PermissionCheckFailures = 0, int IncompleteFolderTargets = 0,
    bool CapacityLimited = false, int CatalogFailures = 0, DateTimeOffset ScanStartedAt = default);

public interface IMailboxDiscovery
{
    Task<MailboxDiscoverySnapshot> DiscoverAsync(MailboxIdentity actor, CancellationToken cancellationToken);
    Task<DiscoveredMailbox?> ResolveAsync(MailboxIdentity actor, string key, CancellationToken cancellationToken);
    MailboxDiscoverySnapshot? Cached(MailboxIdentity actor);
    void Invalidate(MailboxIdentity actor);
}

/// <summary>Discovery caches metadata; every selected target is resolved and authorized again.</summary>
public sealed class MailboxDiscovery(MailboxAccess access, IMailboxDirectory directory,
    IMailboxPermissionReader permissions, EwsClient ews,
    ILogger<MailboxDiscovery> logger) : IMailboxDiscovery
{
    private static readonly TimeSpan CacheLifetime = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan PartialCacheLifetime = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan PassLifetime = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan ProgressIdleLifetime = TimeSpan.FromHours(24);
    private const int MaximumCachedActors = 1024;
    private const int MaximumRetainedTargets = 4096;
    private const int MaximumCandidates = 1024;
    private const int MaximumConcurrentChecks = 6;
    private readonly TimeSpan passLifetime = PassLifetime;

    internal MailboxDiscovery(MailboxAccess access, IMailboxDirectory directory,
        IMailboxPermissionReader permissions, EwsClient ews, ILogger<MailboxDiscovery> logger, TimeSpan passLifetime)
        : this(access, directory, permissions, ews, logger)
    {
        if (passLifetime <= TimeSpan.Zero || passLifetime > PassLifetime)
            throw new ArgumentOutOfRangeException(nameof(passLifetime));
        this.passLifetime = passLifetime;
    }

    private readonly ConcurrentDictionary<string, ActorProgress> progressByActor = new(StringComparer.Ordinal);
    private readonly object progressLock = new();
    private readonly SemaphoreSlim catalogGate = new(1, 1);
    private readonly SemaphoreSlim checkGate = new(MaximumConcurrentChecks, MaximumConcurrentChecks);
    private MailboxCatalog? catalog;
    private long catalogGeneration;
    private int retainedTargets;

    public MailboxDiscoverySnapshot? Cached(MailboxIdentity actor)
    {
        if (!progressByActor.TryGetValue(CacheKey(actor), out var progress)
            || Volatile.Read(ref progress.Invalidated) != 0)
            return null;

        var snapshot = Volatile.Read(ref progress.Snapshot);
        if (snapshot is null) return null;
        var freshness = snapshot.Complete ? CacheLifetime : PartialCacheLifetime;
        var checkedAt = snapshot.Complete ? progress.CoverageCheckedAt : snapshot.CheckedAt;
        return checkedAt != default && DateTimeOffset.UtcNow - checkedAt <= freshness ? snapshot : null;
    }

    public void Invalidate(MailboxIdentity actor)
    {
        if (progressByActor.TryGetValue(CacheKey(actor), out var progress))
            Interlocked.Exchange(ref progress.Invalidated, 1);
    }

    public async Task<MailboxDiscoverySnapshot> DiscoverAsync(MailboxIdentity actor, CancellationToken cancellationToken)
    {
        actor = OwnActor(actor);
        if (!await access.VerifyCurrentActorAsync(actor, cancellationToken).ConfigureAwait(false))
        {
            Invalidate(actor);
            throw new ModelContextProtocol.McpException("Your current directory mailbox access could not be verified.");
        }

        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(passLifetime);
        MailboxCatalog currentCatalog;
        try
        {
            currentCatalog = await GetCatalogAsync(deadline.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception exception) when (exception is not OutOfMemoryException and not StackOverflowException)
        {
            logger.LogDebug("Mailbox discovery could not load the bounded directory catalog after {ExceptionType}.",
                exception.GetType().Name);
            return new([], false, DateTimeOffset.UtcNow, 0, 0, false, 0, 0, false, 1, DateTimeOffset.UtcNow);
        }

        var candidates = currentCatalog.Candidates.Where(candidate =>
                !string.Equals(candidate.Mailbox, actor.Mailbox, StringComparison.OrdinalIgnoreCase))
            .ToArray();
        var actorKey = CacheKey(actor);
        var progress = AcquireProgress(actorKey, currentCatalog, candidates);
        if (progress is null)
        {
            logger.LogDebug("Mailbox discovery stopped at its bounded actor-progress limit.");
            return new([], false, DateTimeOffset.UtcNow, candidates.Length, 0, false, 0, 0, true, 0,
                DateTimeOffset.UtcNow);
        }

        try
        {
            await progress.Gate.WaitAsync(deadline.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            ReleaseProgress(progress);
            throw;
        }
        catch (OperationCanceledException) when (deadline.IsCancellationRequested)
        {
            var snapshot = Volatile.Read(ref progress.Snapshot);
            var mayReturnSnapshot = snapshot is not null && Volatile.Read(ref progress.Invalidated) == 0;
            ReleaseProgress(progress);
            var now = DateTimeOffset.UtcNow;
            logger.LogDebug("Mailbox discovery waited for the actor's active bounded pass until its deadline.");
            return mayReturnSnapshot ? snapshot!
                : new([], false, now, candidates.Length, 0, false, 0, 0, false, 0, now);
        }
        catch
        {
            ReleaseProgress(progress);
            throw;
        }

        try
        {
            var now = DateTimeOffset.UtcNow;
            if (Volatile.Read(ref progress.Invalidated) != 0)
            {
                ResetProgress(progress, candidates, currentCatalog.Generation, now);
                Interlocked.Exchange(ref progress.Invalidated, 0);
            }
            else
                ReconcileCatalog(progress, candidates, currentCatalog.Generation, now);

            if (progress.CoverageCheckedAt != default && now - progress.CoverageCheckedAt > CacheLifetime)
                ResetProgress(progress, candidates, currentCatalog.Generation, now);

            if (IsSnapshotFresh(progress, now))
                return progress.Snapshot!;

            // Retry unresolved evidence after the short cache without discarding completed catalog coverage.
            for (var index = 0; index < progress.Candidates.Length; index++)
                if (progress.PermissionFailures[index] || progress.FolderIncomplete[index])
                    progress.Scanned[index] = false;

            var selected = SelectPending(progress, MaximumCandidates);
            if (selected.Length > 0)
            {
                progress.CapacityLimited = false;
                try
                {
                    await Parallel.ForEachAsync(selected,
                        new ParallelOptions { MaxDegreeOfParallelism = MaximumConcurrentChecks, CancellationToken = deadline.Token },
                        async (index, token) =>
                        {
                            await checkGate.WaitAsync(token).ConfigureAwait(false);
                            try
                            {
                                lock (progress.TargetLock)
                                    progress.NextIndex = (index + 1) % progress.Candidates.Length;
                                var candidate = progress.Candidates[index];
                                var target = await CheckAsync(actor, candidate, token).ConfigureAwait(false);
                                StoreCheckResult(progress, index, target);
                            }
                            catch (OperationCanceledException) when (token.IsCancellationRequested) { throw; }
                            catch (Exception exception) when (exception is not OutOfMemoryException and not StackOverflowException)
                            {
                                StoreCheckFailure(progress, index);
                                logger.LogDebug("Mailbox discovery left one target unverified after {ExceptionType}.",
                                    exception.GetType().Name);
                            }
                            finally { checkGate.Release(); }
                        }).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
                catch (OperationCanceledException) when (deadline.IsCancellationRequested)
                {
                    logger.LogDebug("Mailbox discovery stopped at its bounded per-pass deadline.");
                }
            }

            var snapshot = BuildSnapshot(progress, DateTimeOffset.UtcNow);
            Volatile.Write(ref progress.Snapshot, snapshot);
            return snapshot;
        }
        finally
        {
            progress.Gate.Release();
            ReleaseProgress(progress);
        }
    }

    public async Task<DiscoveredMailbox?> ResolveAsync(MailboxIdentity actor, string key, CancellationToken cancellationToken)
    {
        actor = OwnActor(actor);
        if (!Guid.TryParseExact(key, "D", out var guid) || guid == Guid.Empty
            || !await access.VerifyCurrentActorAsync(actor, cancellationToken).ConfigureAwait(false))
            return null;
        var candidate = await directory.ResolveAsync(key, cancellationToken).ConfigureAwait(false);
        if (candidate is null || !string.Equals(candidate.Key, key, StringComparison.Ordinal)
            || string.Equals(candidate.Mailbox, actor.Mailbox, StringComparison.OrdinalIgnoreCase))
            return null;
        var target = await CheckAsync(actor, candidate, cancellationToken).ConfigureAwait(false);
        if (!HasAccess(target)) { Invalidate(actor); return null; }
        return target;
    }

    private async Task<MailboxCatalog> GetCatalogAsync(CancellationToken cancellationToken)
    {
        var current = Volatile.Read(ref catalog);
        if (current is not null && DateTimeOffset.UtcNow - current.CheckedAt <= CacheLifetime)
            return current;

        await catalogGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            current = Volatile.Read(ref catalog);
            if (current is not null && DateTimeOffset.UtcNow - current.CheckedAt <= CacheLifetime)
                return current;

            var candidates = await directory.ListAsync(cancellationToken).ConfigureAwait(false);
            if (candidates.Count > MaximumCandidates)
                throw new InvalidDataException("Mailbox directory exceeded the bounded candidate count.");
            var sorted = candidates.OrderBy(candidate => candidate.Mailbox, StringComparer.OrdinalIgnoreCase)
                .ThenBy(candidate => candidate.Key, StringComparer.Ordinal).ToArray();
            if (sorted.Select(candidate => candidate.Key).Distinct(StringComparer.Ordinal).Count() != sorted.Length)
                throw new InvalidDataException("Mailbox directory returned duplicate stable target identifiers.");

            current = new(sorted, DateTimeOffset.UtcNow, Interlocked.Increment(ref catalogGeneration));
            Volatile.Write(ref catalog, current);
            return current;
        }
        finally { catalogGate.Release(); }
    }

    private ActorProgress? AcquireProgress(string key, MailboxCatalog currentCatalog,
        MailboxDirectoryCandidate[] candidates)
    {
        lock (progressLock)
        {
            var now = DateTimeOffset.UtcNow;
            if (progressByActor.TryGetValue(key, out var existing))
            {
                existing.ActiveReferences++;
                existing.LastTouchedAt = now;
                return existing;
            }

            EvictExpiredProgress(now);
            if (progressByActor.Count >= MaximumCachedActors)
                return null;

            var progress = new ActorProgress(candidates, currentCatalog.Generation, now)
            {
                ActiveReferences = 1
            };
            progressByActor[key] = progress;
            return progress;
        }
    }

    private void EvictExpiredProgress(DateTimeOffset now)
    {
        foreach (var entry in progressByActor)
        {
            var progress = entry.Value;
            var invalidated = Volatile.Read(ref progress.Invalidated) != 0;
            var expired = now - progress.LastTouchedAt > ProgressIdleLifetime;
            if (progress.ActiveReferences != 0 || (!invalidated && !expired))
                continue;
            if (progressByActor.TryRemove(entry.Key, out var removed))
                ReleaseTargets(removed);
        }
    }

    private void ReleaseProgress(ActorProgress progress)
    {
        lock (progressLock)
        {
            progress.ActiveReferences--;
            progress.LastTouchedAt = DateTimeOffset.UtcNow;
        }
    }

    private void ReconcileCatalog(ActorProgress progress, MailboxDirectoryCandidate[] candidates,
        long generation, DateTimeOffset now)
    {
        if (progress.CatalogGeneration == generation) return;

        var old = progress.Candidates.Select((candidate, index) => (candidate, index))
            .ToDictionary(entry => entry.candidate.Key, entry => entry.index, StringComparer.Ordinal);
        var updated = new bool[candidates.Length];
        var permissionFailures = new bool[candidates.Length];
        var folderIncomplete = new bool[candidates.Length];
        var targets = new Dictionary<string, DiscoveredMailbox>(StringComparer.Ordinal);
        var oldTargets = progress.Targets;
        var previousCursorKey = progress.NextIndex < progress.Candidates.Length
            ? progress.Candidates[progress.NextIndex].Key : null;
        var addedOrChanged = false;
        for (var index = 0; index < candidates.Length; index++)
        {
            var candidate = candidates[index];
            if (old.TryGetValue(candidate.Key, out var oldIndex)
                && string.Equals(progress.Candidates[oldIndex].Mailbox, candidate.Mailbox, StringComparison.OrdinalIgnoreCase))
            {
                updated[index] = progress.Scanned[oldIndex];
                permissionFailures[index] = progress.PermissionFailures[oldIndex];
                folderIncomplete[index] = progress.FolderIncomplete[oldIndex];
                if (oldTargets.TryGetValue(candidate.Key, out var retained))
                    targets[candidate.Key] = retained with { Candidate = candidate };
                old.Remove(candidate.Key);
            }
            else
                addedOrChanged = true;
        }

        var oldCursor = progress.NextIndex;
        progress.Candidates = candidates;
        progress.Scanned = updated;
        progress.PermissionFailures = permissionFailures;
        progress.FolderIncomplete = folderIncomplete;
        progress.Targets = targets;
        if (oldTargets.Count > targets.Count)
            Interlocked.Add(ref retainedTargets, targets.Count - oldTargets.Count);
        progress.CatalogGeneration = generation;
        progress.NextIndex = previousCursorKey is null
            ? Math.Min(oldCursor, Math.Max(0, updated.Length - 1))
            : Array.FindIndex(candidates, candidate => string.Equals(candidate.Key, previousCursorKey, StringComparison.Ordinal));
        if (progress.NextIndex < 0) progress.NextIndex = Math.Min(oldCursor, Math.Max(0, updated.Length - 1));
        progress.CoverageCheckedAt = updated.All(item => item) && progress.CoverageCheckedAt != default
            ? progress.CoverageCheckedAt : default;
        progress.CapacityLimited = false;
        if (addedOrChanged) progress.ScanStartedAt = now;
        Volatile.Write(ref progress.Snapshot, null);
    }

    private void ResetProgress(ActorProgress progress, MailboxDirectoryCandidate[] candidates,
        long generation, DateTimeOffset now)
    {
        ReleaseTargets(progress);
        progress.Candidates = candidates;
        progress.Scanned = new bool[candidates.Length];
        progress.PermissionFailures = new bool[candidates.Length];
        progress.FolderIncomplete = new bool[candidates.Length];
        progress.Targets = new(StringComparer.Ordinal);
        progress.CatalogGeneration = generation;
        progress.NextIndex = 0;
        progress.CoverageCheckedAt = default;
        progress.CapacityLimited = false;
        progress.ScanStartedAt = now;
        Volatile.Write(ref progress.Snapshot, null);
    }

    private static int[] SelectPending(ActorProgress progress, int maximum)
    {
        var selected = new List<int>(Math.Min(maximum, progress.Candidates.Length));
        if (progress.Candidates.Length == 0) return [];
        var start = progress.NextIndex % progress.Candidates.Length;
        for (var offset = 0; offset < progress.Candidates.Length && selected.Count < maximum; offset++)
        {
            var index = (start + offset) % progress.Candidates.Length;
            if (!progress.Scanned[index])
                selected.Add(index);
        }
        return selected.ToArray();
    }

    private void StoreCheckResult(ActorProgress progress, int index, DiscoveredMailbox target)
    {
        lock (progress.TargetLock)
        {
            var candidate = progress.Candidates[index];
            progress.Scanned[index] = true;
            progress.PermissionFailures[index] = target.Permissions.FullAccess.State == "unknown"
                || target.Permissions.SendAs.State == "unknown"
                || target.Permissions.SendOnBehalf.State == "unknown";
            progress.FolderIncomplete[index] = !target.FolderAccess.Complete;
            if (!HasAccess(target))
            {
                RemoveTarget(progress, candidate.Key);
                return;
            }

            var summaries = SummarizeFolders(target.FolderAccess.Folders);
            var limitedFolders = summaries.Length != target.FolderAccess.Folders.Count;
            var verified = target with
            {
                FolderAccess = new(summaries, target.FolderAccess.Complete && !limitedFolders)
            };
            if (!progress.Targets.ContainsKey(candidate.Key))
            {
                if (!TryReserveTarget())
                {
                    progress.Scanned[index] = false;
                    progress.FolderIncomplete[index] = false;
                    progress.CapacityLimited = true;
                    return;
                }
            }
            progress.Targets[candidate.Key] = verified;
        }
    }

    private void StoreCheckFailure(ActorProgress progress, int index)
    {
        lock (progress.TargetLock)
        {
            var candidate = progress.Candidates[index];
            RemoveTarget(progress, candidate.Key);
            progress.Scanned[index] = true;
            progress.PermissionFailures[index] = true;
            progress.FolderIncomplete[index] = false;
        }
    }

    private static EwsDiscoveredFolder[] SummarizeFolders(IReadOnlyList<EwsDiscoveredFolder> folders)
    {
        var defaults = folders.Where(folder => folder.DistinguishedId is not null).Take(8).ToArray();
        return defaults.Length > 0 ? defaults : folders.Take(1).ToArray();
    }

    private bool TryReserveTarget()
    {
        while (true)
        {
            var current = Volatile.Read(ref retainedTargets);
            if (current >= MaximumRetainedTargets) return false;
            if (Interlocked.CompareExchange(ref retainedTargets, current + 1, current) == current)
                return true;
        }
    }

    private void RemoveTarget(ActorProgress progress, string key)
    {
        if (progress.Targets.Remove(key))
            Interlocked.Decrement(ref retainedTargets);
    }

    private void ReleaseTargets(ActorProgress progress)
    {
        if (progress.Targets.Count > 0)
            Interlocked.Add(ref retainedTargets, -progress.Targets.Count);
        progress.Targets.Clear();
    }

    private MailboxDiscoverySnapshot BuildSnapshot(ActorProgress progress, DateTimeOffset now)
    {
        var candidateCount = progress.Candidates.Length;
        var scannedCount = progress.Scanned.Count(item => item);
        var catalogScanComplete = scannedCount == candidateCount && !progress.CapacityLimited;
        var permissionFailures = progress.PermissionFailures.Count(item => item);
        var incompleteFolders = progress.FolderIncomplete.Count(item => item);
        if (catalogScanComplete && progress.CoverageCheckedAt == default)
            progress.CoverageCheckedAt = now;
        var complete = catalogScanComplete && permissionFailures == 0 && incompleteFolders == 0;
        return new(progress.Candidates.Where(candidate => progress.Targets.ContainsKey(candidate.Key))
                .Select(candidate => progress.Targets[candidate.Key]).ToArray(),
            complete, now, candidateCount, scannedCount, catalogScanComplete, permissionFailures,
            incompleteFolders, progress.CapacityLimited, 0, progress.ScanStartedAt);
    }

    private static bool IsSnapshotFresh(ActorProgress progress, DateTimeOffset now)
    {
        var snapshot = Volatile.Read(ref progress.Snapshot);
        if (snapshot is null || Volatile.Read(ref progress.Invalidated) != 0) return false;
        var checkedAt = snapshot.Complete ? progress.CoverageCheckedAt : snapshot.CheckedAt;
        var maxAge = snapshot.Complete ? CacheLifetime : PartialCacheLifetime;
        return checkedAt != default && now - checkedAt <= maxAge;
    }

    private async Task<DiscoveredMailbox> CheckAsync(MailboxIdentity actor, MailboxDirectoryCandidate candidate,
        CancellationToken cancellationToken)
    {
        var identity = actor with { Mailbox = candidate.Mailbox, ActorMailbox = actor.Mailbox, TargetId = candidate.Key };
        using var selection = access.SelectTarget(identity);
        var report = await permissions.ReadAsync(identity, cancellationToken).ConfigureAwait(false);
        var folders = await ews.DiscoverMailboxFoldersAsync(candidate.Mailbox, cancellationToken).ConfigureAwait(false);
        if ((!folders.Complete || report.FullAccess.State != "allowed")
            && EwsClient.SupportsFolderMetadataDiscovery(candidate))
        {
            // Invisible custom shares need hierarchy IDs; only the actor's subsequent native rights are returned.
            try
            {
                var metadata = await ews.DiscoverMailboxFolderMetadataAsync(candidate, cancellationToken).ConfigureAwait(false);
                var verified = await ews.GetMailboxFolderRightsAsync(candidate.Mailbox,
                    metadata.Folders.Select(folder => folder.Id).ToArray(), cancellationToken).ConfigureAwait(false);
                var known = metadata.Folders.ToDictionary(folder => folder.Id, StringComparer.Ordinal);
                var merged = folders.Folders.Where(folder => !known.ContainsKey(folder.Id))
                    .ToDictionary(folder => folder.Id, StringComparer.Ordinal);
                foreach (var folder in verified)
                    merged[folder.Id] = folder with { DistinguishedId = known[folder.Id].DistinguishedId };
                folders = new(merged.Values.ToArray(), metadata.Complete);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (Exception exception) when (exception is not OutOfMemoryException and not StackOverflowException)
            {
                folders = folders with { Complete = false };
                logger.LogDebug("Custom folder discovery remained incomplete after {ExceptionType}.", exception.GetType().Name);
            }
        }
        return new(candidate, report, folders);
    }

    private static bool HasAccess(DiscoveredMailbox target) => target.FolderAccess.Folders.Count > 0
        || target.Permissions.FullAccess.State == "allowed" || target.Permissions.SendAs.State == "allowed"
        || target.Permissions.SendOnBehalf.State == "allowed";

    private static MailboxIdentity OwnActor(MailboxIdentity actor) => actor with
    {
        Mailbox = actor.ActorMailbox ?? actor.Mailbox,
        ActorMailbox = actor.ActorMailbox ?? actor.Mailbox,
        TargetId = "own"
    };

    private static string CacheKey(MailboxIdentity actor) => actor.Subject + "\0"
        + (actor.ActorMailbox ?? actor.Mailbox).ToUpperInvariant();

    private sealed record MailboxCatalog(MailboxDirectoryCandidate[] Candidates, DateTimeOffset CheckedAt, long Generation);

    private sealed class ActorProgress(MailboxDirectoryCandidate[] candidates, long generation, DateTimeOffset startedAt)
    {
        public SemaphoreSlim Gate { get; } = new(1, 1);
        public object TargetLock { get; } = new();
        public MailboxDirectoryCandidate[] Candidates { get; set; } = candidates;
        public bool[] Scanned { get; set; } = new bool[candidates.Length];
        public bool[] PermissionFailures { get; set; } = new bool[candidates.Length];
        public bool[] FolderIncomplete { get; set; } = new bool[candidates.Length];
        public Dictionary<string, DiscoveredMailbox> Targets { get; set; } = new(StringComparer.Ordinal);
        public long CatalogGeneration { get; set; } = generation;
        public int NextIndex { get; set; }
        public DateTimeOffset ScanStartedAt { get; set; } = startedAt;
        public DateTimeOffset CoverageCheckedAt { get; set; }
        public DateTimeOffset LastTouchedAt { get; set; } = startedAt;
        public MailboxDiscoverySnapshot? Snapshot;
        public int Invalidated;
        public int ActiveReferences;
        public bool CapacityLimited;
    }
}
