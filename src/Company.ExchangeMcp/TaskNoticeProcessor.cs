using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Xml;
using System.Xml.Linq;
using Company.ExchangeMcp.Exchange;
using Company.ExchangeMcp.Security;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Company.ExchangeMcp;

public sealed class TaskNoticeProcessor : BackgroundService
{
    private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(30);
    private const int PageSize = 100;
    private const int MaxPagesPerMailbox = 3;
    private const int MaxNoticesPerMailbox = 20;
    private const int MaxMailboxesPerPass = 16;
    private const int MaxCanonicalMailboxes = 1024;
    private static readonly XNamespace Messages = "http://schemas.microsoft.com/exchange/services/2006/messages";
    private static readonly XNamespace Types = "http://schemas.microsoft.com/exchange/services/2006/types";

    private readonly ServiceOptions options;
    private readonly IServiceScopeFactory scopes;
    private readonly ILogger<TaskNoticeProcessor> logger;
    private readonly SemaphoreSlim passGate = new(1, 1);
    private readonly HashSet<string> blockedRoutes = new(StringComparer.Ordinal);
    private readonly HashSet<string> reportedTransientNotices = new(StringComparer.Ordinal);
    private readonly TaskNoticeStateStore? state;
    private readonly Dictionary<string, HashSet<string>> discoveredActorRoutes = new(StringComparer.Ordinal);
    private readonly Dictionary<string, MailboxDirectoryCandidate> discoveredCandidates = new(StringComparer.Ordinal);
    private int discoveryActorCursor;
    private bool auditUnavailable;
    private bool targetLimitReported;
    private bool discoveryLimitReported;

    public TaskNoticeProcessor(
        IOptions<ServiceOptions> options,
        IServiceScopeFactory scopes,
        ILogger<TaskNoticeProcessor> logger)
    {
        this.options = options?.Value ?? throw new ArgumentNullException(nameof(options));
        this.scopes = scopes ?? throw new ArgumentNullException(nameof(scopes));
        this.logger = logger ?? throw new ArgumentNullException(nameof(logger));
        if (!this.options.WritesEnabled || !TaskNoticeProcessingEnabled(this.options))
            return;
        try
        {
            state = new TaskNoticeStateStore(this.options.AuditPath);
            if (state.RequiresLegacyReconciliation)
                logger.LogCritical("Automatic task notice processing is disabled until legacy uncertain state is reconciled.");
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException
            or JsonException or InvalidDataException or InvalidOperationException or ArgumentException or FormatException)
        {
            logger.LogCritical("Automatic task notice processing is disabled because its private state is unavailable.");
        }
    }

    public async Task RunOnceAsync(CancellationToken cancellationToken = default)
    {
        if (state is null || !state.IsAvailable || state.RequiresLegacyReconciliation
            || !options.WritesEnabled || auditUnavailable || !TaskNoticeProcessingEnabled(options))
            return;
        if (!await passGate.WaitAsync(0, cancellationToken).ConfigureAwait(false)) return;
        try
        {
            using var scope = scopes.CreateScope();
            var services = scope.ServiceProvider;
            var exchange = services.GetRequiredService<EwsClient>();
            var access = services.GetRequiredService<MailboxAccess>();
            var discovery = services.GetRequiredService<IMailboxDiscovery>();
            var directory = services.GetRequiredService<IMailboxDirectory>();
            var audit = services.GetRequiredService<AuditLog>();
            var targets = await BuildTargetsAsync(access, discovery, cancellationToken).ConfigureAwait(false);
            if (targets.Count == 0) return;
            state.PruneScanState(targets.Select(target => RouteKey(target.Mailbox)).ToHashSet(StringComparer.Ordinal));
            var start = Math.Abs(state.NextTargetCursor % targets.Count);
            var count = Math.Min(MaxMailboxesPerPass, targets.Count);
            for (var index = 0; index < count && !auditUnavailable && state is { IsAvailable: true }; index++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var targetIndex = (start + index) % targets.Count;
                var target = targets[targetIndex];
                try
                {
                    state.SetNextTargetCursor((targetIndex + 1) % targets.Count);
                    await ProcessTargetAsync(exchange, access, directory, audit, target, cancellationToken)
                        .ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    throw;
                }
                catch (IOException) when (state is not null && !state.IsAvailable)
                {
                    throw;
                }
                catch (UnauthorizedAccessException) when (state is not null && !state.IsAvailable)
                {
                    throw;
                }
                catch (Exception exception) when (exception is not OutOfMemoryException and not StackOverflowException)
                {
                    await RecordRouteBlockedOnceAsync(audit, target.AuditIdentity, RouteKey(target.Mailbox), cancellationToken)
                        .ConfigureAwait(false);
                }
            }
        }
        catch (IOException)
        {
            logger.LogCritical("Automatic task notice processing is disabled because its private state could not be written.");
            state?.Disable();
        }
        catch (UnauthorizedAccessException)
        {
            logger.LogCritical("Automatic task notice processing is disabled because its private state could not be written.");
            state?.Disable();
        }
        finally { passGate.Release(); }
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await Task.Yield();
        using var timer = new PeriodicTimer(PollInterval);
        try
        {
            do
            {
                try { await RunOnceAsync(stoppingToken).ConfigureAwait(false); }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
                catch (Exception exception) when (exception is not OutOfMemoryException and not StackOverflowException)
                {
                    logger.LogError("Automatic task notice pass stopped after {FailureType}.", exception.GetType().Name);
                }
            }
            while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false));
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { }
    }

    private static bool TaskNoticeProcessingEnabled(ServiceOptions value) =>
        value.TaskNoticeProcessingAllEnrolledUsers || value.TaskNoticeProcessingActors is { Length: > 0 };

    private async Task<List<TaskNoticeMailboxTarget>> BuildTargetsAsync(MailboxAccess access,
        IMailboxDiscovery discovery, CancellationToken cancellationToken)
    {
        var routes = new List<MailboxIdentity>();
        var actors = new List<(string Subject, string Mailbox)>();
        if (options.TaskNoticeProcessingAllEnrolledUsers)
            actors.AddRange(access.GetEnrolledActors());
        else
        {
            foreach (var actorAddress in options.TaskNoticeProcessingActors)
            {
                var matches = options.Mailboxes.Where(entry =>
                    string.Equals(entry.Value, actorAddress, StringComparison.OrdinalIgnoreCase)).ToArray();
                if (matches.Length == 1) actors.Add((matches[0].Key, matches[0].Value));
            }
        }

        var enrolledSubjects = actors.Select(actor => actor.Subject).ToHashSet(StringComparer.Ordinal);
        foreach (var removed in discoveredActorRoutes.Keys.Where(subject => !enrolledSubjects.Contains(subject)).ToArray())
            discoveredActorRoutes.Remove(removed);
        if (actors.Count == 0) { discoveredCandidates.Clear(); return []; }
        if (actors.Count > MaxCanonicalMailboxes)
        {
            if (!targetLimitReported)
                logger.LogCritical("Automatic task notice processing is disabled because its canonical mailbox limit was exceeded.");
            targetLimitReported = true;
            return [];
        }
        var warmIndex = discoveryActorCursor % actors.Count;
        discoveryActorCursor = (warmIndex + 1) % actors.Count;
        for (var actorIndex = 0; actorIndex < actors.Count; actorIndex++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var (subject, ownMailbox) = actors[actorIndex];
            var actor = new MailboxIdentity(subject, ownMailbox, "task-notice-worker", null, "own", ownMailbox);
            routes.Add(actor);
            MailboxDiscoverySnapshot? snapshot = null;
            try
            {
                snapshot = actorIndex == warmIndex
                    ? await discovery.DiscoverAsync(actor, cancellationToken).ConfigureAwait(false)
                    : discovery.Cached(actor);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (Exception exception) when (exception is not OutOfMemoryException and not StackOverflowException)
            {
                discovery.Invalidate(actor);
                logger.LogDebug("Task notice discovery skipped delegated routes for one actor ({FailureType}).",
                    exception.GetType().Name);
            }
            if (snapshot is not null)
            {
                if (!discoveredActorRoutes.TryGetValue(subject, out var known))
                    discoveredActorRoutes[subject] = known = new(StringComparer.Ordinal);
                if (snapshot.Complete) known.Clear();
                foreach (var target in snapshot.Targets)
                {
                    var candidate = target.Candidate;
                    if (!discoveredCandidates.ContainsKey(candidate.Key) && discoveredCandidates.Count >= MaxCanonicalMailboxes)
                    {
                        if (!discoveryLimitReported)
                            logger.LogError("Automatic delegated discovery reached its bounded route-metadata limit; some routes remain unverified.");
                        discoveryLimitReported = true;
                        continue;
                    }
                    discoveredCandidates[candidate.Key] = candidate with { DisplayName = null };
                    known.Add(candidate.Key);
                }
            }
            // Worker routing metadata outlives interactive caches; current rights are checked before every operation.
            if (!discoveredActorRoutes.TryGetValue(subject, out var retained)) continue;
            foreach (var key in retained)
            {
                if (!discoveredCandidates.TryGetValue(key, out var candidate)) continue;
                routes.Add(actor with
                {
                    Mailbox = candidate.Mailbox,
                    TargetId = candidate.Key,
                    ActorMailbox = ownMailbox
                });
            }
        }
        var retainedKeys = discoveredActorRoutes.Values.SelectMany(keys => keys).ToHashSet(StringComparer.Ordinal);
        foreach (var removed in discoveredCandidates.Keys.Where(key => !retainedKeys.Contains(key)).ToArray())
            discoveredCandidates.Remove(removed);
        var targets = routes.GroupBy(target => target.Mailbox, StringComparer.OrdinalIgnoreCase)
            .Select(group =>
            {
                var ordered = group.OrderBy(target => target.Subject, StringComparer.Ordinal)
                    .ThenBy(target => target.TargetId, StringComparer.Ordinal).ToArray();
                var own = ordered.Where(target => target.TargetId == "own").ToArray();
                MailboxIdentity[] candidates = own.Length == 1 ? own
                    : own.Length > 1 ? Array.Empty<MailboxIdentity>()
                    : ordered.Where(target => target.TargetId != "own").ToArray();
                return new TaskNoticeMailboxTarget(NormalizeSmtpForHash(group.Key),
                    own.FirstOrDefault() ?? ordered[0], candidates, AmbiguousOwn: own.Length > 1);
            })
            .OrderBy(target => target.Mailbox, StringComparer.OrdinalIgnoreCase)
            .ThenBy(target => target.Mailbox, StringComparer.Ordinal).ToList();
        if (targets.Count <= MaxCanonicalMailboxes)
        {
            targetLimitReported = false;
            return targets;
        }
        if (!targetLimitReported)
            logger.LogCritical("Automatic task notice processing is disabled because its canonical mailbox limit was exceeded.");
        targetLimitReported = true;
        return [];
    }

    private async Task<bool> HasTaskProcessingRightsAsync(
        EwsClient exchange,
        MailboxAccess access,
        IMailboxDirectory directory,
        MailboxIdentity target,
        CancellationToken cancellationToken)
    {
        using var selected = access.SelectTarget(target);
        try
        {
            if (!await access.VerifyCurrentActorAsync(target, cancellationToken).ConfigureAwait(false))
                return false;
            if (!string.Equals(target.TargetId, "own", StringComparison.Ordinal))
            {
                var candidate = await directory.ResolveAsync(target.TargetId, cancellationToken).ConfigureAwait(false);
                if (candidate is null)
                {
                    discoveredCandidates.Remove(target.TargetId);
                    foreach (var known in discoveredActorRoutes.Values) known.Remove(target.TargetId);
                    return false;
                }
                if (!string.Equals(candidate.Key, target.TargetId, StringComparison.Ordinal))
                    return false;
                if (!string.Equals(candidate.Mailbox, target.Mailbox, StringComparison.OrdinalIgnoreCase))
                {
                    discoveredCandidates[target.TargetId] = candidate with { DisplayName = null };
                    return false;
                }
            }

            var inboxRights = await exchange.GetEffectiveRightsAsync(target.Mailbox, "inbox", cancellationToken)
                .ConfigureAwait(false);
            var taskRights = await exchange.GetEffectiveRightsAsync(target.Mailbox, "tasks", cancellationToken)
                .ConfigureAwait(false);
            return inboxRights.Read == true && inboxRights.Modify == true
                && taskRights.Read == true && taskRights.Modify == true;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception) when (exception is not OutOfMemoryException and not StackOverflowException)
        {
            return false;
        }
    }

    private async Task ProcessTargetAsync(
        EwsClient exchange,
        MailboxAccess access,
        IMailboxDirectory directory,
        AuditLog audit,
        TaskNoticeMailboxTarget mailboxTarget,
        CancellationToken cancellationToken)
    {
        var routeKey = RouteKey(mailboxTarget.Mailbox);
        if (mailboxTarget.AmbiguousOwn || mailboxTarget.Candidates.Count == 0)
        {
            await RecordRouteBlockedOnceAsync(audit, mailboxTarget.AuditIdentity, routeKey, cancellationToken)
                .ConfigureAwait(false);
            return;
        }

        MailboxIdentity? target = null;
        foreach (var candidate in mailboxTarget.Candidates)
        {
            if (await HasTaskProcessingRightsAsync(exchange, access, directory, candidate, cancellationToken)
                .ConfigureAwait(false))
            {
                target = candidate;
                break;
            }
        }
        if (target is null)
        {
            await RecordRouteBlockedOnceAsync(audit, mailboxTarget.AuditIdentity, routeKey, cancellationToken)
                .ConfigureAwait(false);
            return;
        }

        using var selected = access.SelectTarget(target);
        blockedRoutes.Remove(routeKey);

        var offset = state!.GetScanOffset(routeKey);
        var (snapshot, nextOffset) = await ReadSnapshotAsync(exchange, mailboxTarget.Mailbox, offset, cancellationToken)
            .ConfigureAwait(false);
        var attempts = 0;
        var pausedGlobals = new HashSet<string>(StringComparer.Ordinal);
        var candidates = snapshot.Select((message, position) => (message, position))
            .Where(item => !item.message.IsProcessed)
            .GroupBy(item => item.message.GlobalTaskId ?? string.Empty, StringComparer.Ordinal)
            .OrderBy(group => group.Key, StringComparer.Ordinal)
            .SelectMany(group => group.OrderBy(item => item.message.Version ?? int.MinValue)
                .ThenBy(item => item.position))
            .Select(item => item.message).ToArray();
        var bookmark = state.GetScanBookmark(routeKey);
        var startIndex = bookmark is null ? -1
            : Array.FindIndex(candidates, message => NoticeKey(mailboxTarget.Mailbox, message.Id) == bookmark);
        if (startIndex < 0) startIndex = 0;
        string? nextBookmark = null;
        var stoppedAtCandidateLimit = false;

        // Keep each bounded EWS snapshot linear. Wrapping here would revisit
        // the same front candidates after reaching the page end and starve
        // later windows indefinitely when notices remain unprocessed.
        for (var candidateIndex = startIndex; candidateIndex < candidates.Length; candidateIndex++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var message = candidates[candidateIndex];
            var global = message.GlobalTaskId ?? string.Empty;
            var key = NoticeKey(mailboxTarget.Mailbox, message.Id);
            var followingBookmark = candidateIndex + 1 < candidates.Length
                ? NoticeKey(mailboxTarget.Mailbox, candidates[candidateIndex + 1].Id) : null;
            var existingStatus = state.GetStatus(key);
            if (existingStatus is not null)
            {
                if (existingStatus == "pending" && global.Length > 0) pausedGlobals.Add(global);
                nextBookmark = followingBookmark;
                continue;
            }
            if (!EwsClient.IsSupportedTaskAssignmentMessageClass(message.ItemClass)
                || global.Length > 0 && pausedGlobals.Contains(global))
            {
                nextBookmark = followingBookmark;
                continue;
            }
            if (attempts >= MaxNoticesPerMailbox)
            {
                nextBookmark = key;
                stoppedAtCandidateLimit = true;
                break;
            }
            attempts++;
            var result = await ProcessCandidateAsync(exchange, access, directory, audit, target,
                mailboxTarget.Mailbox, message, key, cancellationToken)
                .ConfigureAwait(false);
            nextBookmark = followingBookmark;
            if (result == CandidateResult.PauseGlobal && global.Length > 0) pausedGlobals.Add(global);
            if (state is null || !state.IsAvailable || auditUnavailable) return;
        }
        // Keep the same bounded EWS window while a candidate bookmark still
        // has unexamined entries in it. Advancing the page offset here would
        // make that hash disappear from the next snapshot and could replay the
        // same first 20 notices forever.
        state.SetScanOffset(routeKey, stoppedAtCandidateLimit ? offset : nextOffset);
        state.SetScanBookmark(routeKey, nextBookmark);
    }

    private async Task<(IReadOnlyList<EwsTaskAssignmentMessage> Items, int NextOffset)> ReadSnapshotAsync(
        EwsClient exchange, string mailbox, int startOffset, CancellationToken cancellationToken)
    {
        var messages = new List<EwsTaskAssignmentMessage>(PageSize * MaxPagesPerMailbox);
        var offset = startOffset;
        var nextOffset = 0;
        for (var pageNumber = 0; pageNumber < MaxPagesPerMailbox; pageNumber++)
        {
            var page = await exchange.ListUnprocessedTaskAssignmentMessagesAsync(mailbox, offset, PageSize, cancellationToken)
                .ConfigureAwait(false);
            if (page.Items.Count == 0)
            {
                // Unprocessed-only results shrink as notices are marked. If a
                // saved offset has moved past the new end, restart at zero on
                // the next pass instead of preserving a cursor into old indexes.
                nextOffset = 0;
                break;
            }
            messages.AddRange(page.Items);
            if (page.NextOffset is null)
            {
                // Reaching the current end wraps the bounded scanner. This is
                // required because a successful marker removes entries and
                // changes every later numeric offset in the server-side query.
                nextOffset = 0;
                break;
            }
            if (page.NextOffset <= offset)
                throw new InvalidOperationException("Exchange returned a non-advancing task notice page.");
            offset = page.NextOffset.Value;
            nextOffset = offset;
        }
        return (messages, nextOffset);
    }

    private async Task<CandidateResult> ProcessCandidateAsync(
        EwsClient exchange,
        MailboxAccess access,
        IMailboxDirectory directory,
        AuditLog audit,
        MailboxIdentity target,
        string physicalMailbox,
        EwsTaskAssignmentMessage message,
        string key,
        CancellationToken cancellationToken)
    {
        EwsTaskAction? action;
        try
        {
            action = await exchange.PrepareTaskProcessAsync(target.Mailbox, message.Id, cancellationToken,
                skipOrdinaryRequest: true)
                .ConfigureAwait(false);
            if (action is null) return CandidateResult.Skipped;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception exception) when (exception is not OutOfMemoryException and not StackOverflowException)
        {
            if (reportedTransientNotices.Count < 1024 && reportedTransientNotices.Add(key))
                await RecordAsync(audit, target, "blocked", key, cancellationToken).ConfigureAwait(false);
            return CandidateResult.PauseGlobal;
        }

        if (!IsSafeProcessAction(action, target, message))
        {
            state!.Quarantine(key, "payload_rejected");
            if (!await RecordAsync(audit, target, "blocked", key, cancellationToken).ConfigureAwait(false))
                return CandidateResult.PauseGlobal;
            return CandidateResult.PauseGlobal;
        }

        if (!await HasTaskProcessingRightsAsync(exchange, access, directory, target, cancellationToken)
                .ConfigureAwait(false))
        {
            await RecordRouteBlockedOnceAsync(audit, target, RouteKey(physicalMailbox), cancellationToken)
                .ConfigureAwait(false);
            return CandidateResult.PauseGlobal;
        }

        state!.MarkPending(key);
        if (!await RecordAsync(audit, target, "started", key, cancellationToken).ConfigureAwait(false))
            return CandidateResult.PauseGlobal;
        try
        {
            var result = await exchange.ExecuteTaskActionAsync(target.Mailbox, action, cancellationToken)
                .ConfigureAwait(false);
            if (result.Operation != "process" || result.SourceId != message.Id || result.Sent
                || !result.Applied || result.Status != "completed")
            {
                await RecordAsync(audit, target, "unverified", key, CancellationToken.None).ConfigureAwait(false);
                return CandidateResult.PauseGlobal;
            }
            if (!await RecordAsync(audit, target, "completed", key, CancellationToken.None).ConfigureAwait(false))
                return CandidateResult.PauseGlobal;
            state.Complete(key);
            reportedTransientNotices.Remove(key);
            return CandidateResult.Completed;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            await RecordAsync(audit, target, "unverified", key, CancellationToken.None).ConfigureAwait(false);
            throw;
        }
        catch (Exception exception) when (exception is not OutOfMemoryException and not StackOverflowException)
        {
            await RecordAsync(audit, target, "unverified", key, CancellationToken.None).ConfigureAwait(false);
            return CandidateResult.PauseGlobal;
        }
    }

    private static bool IsSafeProcessAction(
        EwsTaskAction action,
        MailboxIdentity target,
        EwsTaskAssignmentMessage message)
    {
        if (action.Operation != "process" || string.IsNullOrWhiteSpace(action.PayloadXml)
            || Encoding.UTF8.GetByteCount(action.PayloadXml) > 512 * 1024
            || !string.Equals(action.Mailbox, target.Mailbox, StringComparison.OrdinalIgnoreCase)
            || !string.Equals(action.SourceId, message.Id, StringComparison.Ordinal))
            return false;
        try
        {
            using var reader = XmlReader.Create(new StringReader(action.PayloadXml!), new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit,
                XmlResolver = null,
                MaxCharactersInDocument = 512 * 1024
            });
            var root = XElement.Load(reader);
            var changes = root.Element(Messages + "ItemChanges")?.Elements(Types + "ItemChange").ToArray();
            return root.Name == Messages + "UpdateItem"
                && (string?)root.Attribute("ConflictResolution") == "NeverOverwrite"
                && changes?.Length == 1
                && !root.Descendants(Types + "Message").Any()
                && !root.Descendants().Any(element => element.Name == Messages + "SendItem"
                    || element.Name == Messages + "CreateItem");
        }
        catch (Exception exception) when (exception is XmlException or InvalidOperationException or ArgumentException)
        {
            return false;
        }
    }

    private async Task RecordRouteBlockedOnceAsync(
        AuditLog audit, MailboxIdentity target, string routeKey, CancellationToken cancellationToken)
    {
        if (blockedRoutes.Add(routeKey))
            await RecordAsync(audit, target, "blocked", routeKey, cancellationToken).ConfigureAwait(false);
    }

    private async Task<bool> RecordAsync(
        AuditLog audit,
        MailboxIdentity target,
        string outcome,
        string operationId,
        CancellationToken cancellationToken)
    {
        if (auditUnavailable) return false;
        try
        {
            await audit.RecordAsync(target, "task_notice_process", outcome, operationId, cancellationToken)
                .ConfigureAwait(false);
            return true;
        }
        catch (Exception exception) when (exception is not OutOfMemoryException and not StackOverflowException)
        {
            auditUnavailable = true;
            logger.LogCritical("Automatic task notice processing is disabled because its audit write failed.");
            return false;
        }
    }

    private static string RouteKey(string physicalMailbox) => Hash(NormalizeSmtpForHash(physicalMailbox));

    private static string NoticeKey(string physicalMailbox, string messageId) => Hash(string.Join('\n',
        NormalizeSmtpForHash(physicalMailbox), messageId));

    private static string NormalizeSmtpForHash(string address) => address.Trim().ToUpperInvariant();

    private static string Hash(string value) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value)))
        .ToLowerInvariant();

    private sealed record TaskNoticeMailboxTarget(
        string Mailbox,
        MailboxIdentity AuditIdentity,
        IReadOnlyList<MailboxIdentity> Candidates,
        bool AmbiguousOwn);

    private enum CandidateResult { Skipped, Completed, PauseGlobal }

    private sealed class TaskNoticeStateStore
    {
        private const int CurrentVersion = 3;
        private const int ActorBoundVersion = 2;
        private const int MaxEntries = 2048;
        private const int MaxCursors = 1024;
        private const int MaxFileBytes = 512 * 1024;
        private static readonly UnixFileMode PrivateFileMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        private readonly string path;
        private readonly Dictionary<string, StateEntry> entries = new(StringComparer.Ordinal);
        private readonly Dictionary<string, int> scanOffsets = new(StringComparer.Ordinal);
        private readonly Dictionary<string, string> scanBookmarks = new(StringComparer.Ordinal);
        private int targetCursor;
        private bool available = true;

        public TaskNoticeStateStore(string auditPath)
        {
            path = Path.GetFullPath(auditPath) + ".task-notices.json";
            Load();
        }

        public bool IsAvailable => available;
        public bool RequiresLegacyReconciliation { get; private set; }
        public int NextTargetCursor => targetCursor;

        public string? GetStatus(string key) => entries.TryGetValue(key, out var entry) ? entry.Status : null;

        public int GetScanOffset(string routeKey) => scanOffsets.TryGetValue(routeKey, out var offset) ? offset : 0;

        public string? GetScanBookmark(string routeKey) => scanBookmarks.TryGetValue(routeKey, out var bookmark) ? bookmark : null;

        public void SetNextTargetCursor(int value)
        {
            EnsureAvailable();
            targetCursor = Math.Max(0, value);
            Save();
        }

        public void PruneScanState(IReadOnlySet<string> currentRoutes)
        {
            EnsureAvailable();
            var changed = false;
            foreach (var routeKey in scanOffsets.Keys.Where(key => !currentRoutes.Contains(key)).ToArray())
                changed |= scanOffsets.Remove(routeKey);
            foreach (var routeKey in scanBookmarks.Keys.Where(key => !currentRoutes.Contains(key)).ToArray())
                changed |= scanBookmarks.Remove(routeKey);
            if (changed) Save();
        }

        public void SetScanOffset(string routeKey, int value)
        {
            EnsureAvailable();
            if (!scanOffsets.ContainsKey(routeKey) && scanOffsets.Count >= MaxCursors)
            {
                available = false;
                throw new IOException("The task notice cursor store is full.");
            }
            scanOffsets[routeKey] = Math.Clamp(value, 0, 100_000_000);
            Save();
        }

        public void SetScanBookmark(string routeKey, string? bookmark)
        {
            EnsureAvailable();
            if (bookmark is null)
                scanBookmarks.Remove(routeKey);
            else
            {
                if (!IsHash(bookmark)) throw new IOException("The task notice bookmark is invalid.");
                if (!scanBookmarks.ContainsKey(routeKey) && scanBookmarks.Count >= MaxCursors)
                {
                    available = false;
                    throw new IOException("The task notice bookmark store is full.");
                }
                scanBookmarks[routeKey] = bookmark;
            }
            Save();
        }

        public void MarkPending(string key) => Add(key, new StateEntry("pending", "in_flight", DateTimeOffset.UtcNow));
        public void Quarantine(string key, string code) => Add(key, new StateEntry("quarantined", code, DateTimeOffset.UtcNow));

        public void Complete(string key)
        {
            EnsureAvailable();
            if (!entries.TryGetValue(key, out var entry) || entry.Status != "pending")
                throw new IOException("The pending task notice state changed unexpectedly.");
            entries.Remove(key);
            Save();
        }

        public void Disable() => available = false;

        private void Add(string key, StateEntry entry)
        {
            EnsureAvailable();
            if (!IsHash(key) || entries.ContainsKey(key))
            {
                available = false;
                throw new IOException("The task notice state key is invalid or already present.");
            }
            if (entries.Count >= MaxEntries)
            {
                available = false;
                throw new IOException("The task notice state store is full.");
            }
            entries.Add(key, entry);
            Save();
        }

        private void EnsureAvailable()
        {
            if (!available) throw new IOException("The task notice state store is unavailable.");
        }

        private void Load()
        {
            if (!File.Exists(path)) return;
            var info = new FileInfo(path);
            if (info.Length is < 1 or > MaxFileBytes) throw new InvalidDataException("The task notice state size is invalid.");
            var bytes = File.ReadAllBytes(path);
            using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 8 });
            var root = document.RootElement;
            RequireObject(root, ["version", "targetCursor", "scanOffsets", "scanBookmarks", "entries"]);
            var version = root.GetProperty("version").GetInt32();
            if (version is not (CurrentVersion or ActorBoundVersion))
                throw new InvalidDataException("The task notice state version is invalid.");
            targetCursor = root.GetProperty("targetCursor").GetInt32();
            if (targetCursor < 0) throw new InvalidDataException("The task notice cursor is invalid.");
            var cursors = root.GetProperty("scanOffsets");
            if (cursors.ValueKind != JsonValueKind.Object || cursors.EnumerateObject().Count() > MaxCursors)
                throw new InvalidDataException("The task notice cursor state is invalid.");
            RequireUniqueProperties(cursors);
            foreach (var cursor in cursors.EnumerateObject())
            {
                var value = cursor.Value.GetInt32();
                if (!IsHash(cursor.Name) || value < 0 || value > 100_000_000)
                    throw new InvalidDataException("The task notice cursor state is invalid.");
                scanOffsets.Add(cursor.Name, value);
            }
            var bookmarks = root.GetProperty("scanBookmarks");
            if (bookmarks.ValueKind != JsonValueKind.Object || bookmarks.EnumerateObject().Count() > MaxCursors)
                throw new InvalidDataException("The task notice bookmark state is invalid.");
            RequireUniqueProperties(bookmarks);
            foreach (var bookmark in bookmarks.EnumerateObject())
            {
                var value = bookmark.Value.GetString();
                if (!IsHash(bookmark.Name) || value is null || !IsHash(value))
                    throw new InvalidDataException("The task notice bookmark state is invalid.");
                scanBookmarks.Add(bookmark.Name, value);
            }
            var storedEntries = root.GetProperty("entries");
            if (storedEntries.ValueKind != JsonValueKind.Array || storedEntries.GetArrayLength() > MaxEntries)
                throw new InvalidDataException("The task notice pending state is invalid.");
            foreach (var stored in storedEntries.EnumerateArray())
            {
                RequireObject(stored, ["keyHash", "status", "code", "updatedUtc"]);
                var key = stored.GetProperty("keyHash").GetString();
                var status = stored.GetProperty("status").GetString();
                var code = stored.GetProperty("code").GetString();
                var updated = stored.GetProperty("updatedUtc").GetDateTimeOffset();
                if (key is null || !IsHash(key) || status is not ("pending" or "quarantined")
                    || code is null || code.Length is < 1 or > 32
                    || code.Any(value => !(value is >= 'a' and <= 'z' or '_'))
                    || updated == default || !entries.TryAdd(key, new StateEntry(status, code, updated)))
                    throw new InvalidDataException("The task notice pending state is invalid.");
            }
            if (version == ActorBoundVersion)
            {
                if (entries.Count > 0)
                    RequiresLegacyReconciliation = true;
                else
                {
                    // v2 cursors include the former actor route in their hash.
                    // With no holds to preserve, restart fairly from zero.
                    targetCursor = 0;
                    scanOffsets.Clear();
                    scanBookmarks.Clear();
                }
            }
            if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(path, PrivateFileMode);
        }

        private void Save()
        {
            EnsureAvailable();
            try
            {
                var bytes = JsonSerializer.SerializeToUtf8Bytes(new
                {
                    version = CurrentVersion,
                    targetCursor,
                    scanOffsets,
                    scanBookmarks,
                    entries = entries.Select(entry => new
                    {
                        keyHash = entry.Key,
                        status = entry.Value.Status,
                        code = entry.Value.Code,
                        updatedUtc = entry.Value.UpdatedUtc
                    }).ToArray()
                });
                if (bytes.Length > MaxFileBytes) throw new IOException("The task notice state store is full.");
                var temporary = path + ".tmp";
                using (var stream = new FileStream(temporary, FileMode.Create, FileAccess.Write, FileShare.None,
                    4096, FileOptions.WriteThrough))
                {
                    if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(temporary, PrivateFileMode);
                    stream.Write(bytes);
                    stream.Flush(flushToDisk: true);
                }
                File.Move(temporary, path, overwrite: true);
                if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(path, PrivateFileMode);
            }
            catch
            {
                available = false;
                throw;
            }
        }

        private static void RequireObject(JsonElement element, string[] expected)
        {
            if (element.ValueKind != JsonValueKind.Object) throw new InvalidDataException("The task notice state object is invalid.");
            RequireUniqueProperties(element);
            var names = element.EnumerateObject().Select(property => property.Name).ToHashSet(StringComparer.Ordinal);
            if (!names.SetEquals(expected)) throw new InvalidDataException("The task notice state fields are invalid.");
        }

        private static void RequireUniqueProperties(JsonElement element)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in element.EnumerateObject())
                if (!names.Add(property.Name)) throw new InvalidDataException("The task notice state contains duplicate fields.");
        }

        private static bool IsHash(string value) => value.Length == 64
            && value.All(character => character is >= '0' and <= '9' or >= 'a' and <= 'f');

        private sealed record StateEntry(string Status, string Code, DateTimeOffset UpdatedUtc);
    }

}
