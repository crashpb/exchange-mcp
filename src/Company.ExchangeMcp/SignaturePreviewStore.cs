using System.Security.Cryptography;
using System.Text.Json;
using Company.ExchangeMcp.Security;
using ModelContextProtocol;

namespace Company.ExchangeMcp;

public sealed record SignaturePreviewCandidate(
    MailSignature Profile,
    string Revision,
    bool MakeDefaultForNew,
    bool MakeDefaultForReplies,
    bool ReplaceExisting,
    string? Language,
    bool CompleteOnboarding,
    string? SourceId = null,
    string? SourceChangeKey = null,
    string[]? Warnings = null);

public sealed record PendingSignaturePreview(string Handle, SignaturePreviewCandidate Candidate, DateTimeOffset ExpiresAt);

public sealed class SignaturePreviewStore
{
    public const int MaxEntries = 64;
    public const int MaxBufferedBytes = 32 * 1024 * 1024;
    public static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(15);

    private static readonly JsonSerializerOptions Json = new() { MaxDepth = 12 };
    private readonly object gate = new();
    private readonly Dictionary<string, Entry> entries = new(StringComparer.Ordinal);
    private readonly Dictionary<ActorMailbox, string> activeByMailbox = [];
    private readonly TimeProvider clock;
    private int bufferedBytes;

    public SignaturePreviewStore(TimeProvider? clock = null) => this.clock = clock ?? TimeProvider.System;

    public string Stage(MailboxIdentity identity, SignaturePreviewCandidate candidate)
    {
        var binding = Binding.From(identity);
        var copy = CopyAndValidate(candidate);
        var size = JsonSerializer.SerializeToUtf8Bytes(copy, Json).Length;
        if (size > MaxBufferedBytes)
            throw new McpException("This signature preview exceeds the temporary preview capacity.");

        lock (gate)
        {
            RemoveExpired(clock.GetUtcNow());
            var actorMailbox = new ActorMailbox(binding.Subject, binding.Mailbox);
            var hadPrior = activeByMailbox.TryGetValue(actorMailbox, out var priorHandle);
            var priorSize = hadPrior && entries.TryGetValue(priorHandle!, out var prior) ? prior.Size : 0;
            if ((!hadPrior && entries.Count >= MaxEntries) || bufferedBytes - priorSize + size > MaxBufferedBytes)
                throw new McpException("Signature preview storage is temporarily full. Wait for an existing preview to expire and try again.");

            if (hadPrior) Remove(priorHandle!);
            string handle;
            do { handle = Base64Url(RandomNumberGenerator.GetBytes(32)); }
            while (entries.ContainsKey(handle));

            entries.Add(handle, new(binding, copy, clock.GetUtcNow() + Lifetime, size));
            activeByMailbox[actorMailbox] = handle;
            bufferedBytes += size;
            return handle;
        }
    }

    public SignaturePreviewCandidate Peek(MailboxIdentity identity, string handle) => Get(identity, handle, consume: false);

    public SignaturePreviewCandidate Consume(MailboxIdentity identity, string handle) => Get(identity, handle, consume: true);

    public PendingSignaturePreview? Latest(MailboxIdentity identity)
    {
        var binding = Binding.From(identity, requireSession: false);
        if (string.IsNullOrWhiteSpace(identity.SessionId)) return null;
        lock (gate)
        {
            RemoveExpired(clock.GetUtcNow());
            var actorMailbox = new ActorMailbox(binding.Subject, binding.Mailbox);
            return activeByMailbox.TryGetValue(actorMailbox, out var handle)
                && entries.TryGetValue(handle, out var entry) && entry.Binding == binding
                    ? new(handle, CopyCandidate(entry.Candidate), entry.ExpiresAt) : null;
        }
    }

    public SignaturePreviewCandidate BeginTest(MailboxIdentity identity, string handle)
    {
        var binding = Binding.From(identity);
        if (!IsHandle(handle)) throw InvalidHandle();
        lock (gate)
        {
            RemoveExpired(clock.GetUtcNow());
            if (!entries.TryGetValue(handle, out var entry) || entry.Binding != binding)
                throw InvalidHandle();
            if (entry.TestAttempted)
                throw new McpException("A test draft was already attempted for this preview. Inspect Drafts before doing anything else; do not retry it.");

            // Reserve before the first EWS CreateItem: an uncertain response must not create a duplicate draft.
            entries[handle] = entry with { TestAttempted = true };
            return CopyCandidate(entry.Candidate);
        }
    }

    public static SignatureSettings ApplyCandidate(SignatureSettings before, SignaturePreviewCandidate candidate)
    {
        ArgumentNullException.ThrowIfNull(before);
        ArgumentNullException.ThrowIfNull(candidate);
        var existing = before.Profiles.SingleOrDefault(profile =>
            string.Equals(profile.Name, candidate.Profile.Name, StringComparison.OrdinalIgnoreCase));
        if (existing is not null && !candidate.ReplaceExisting)
            throw new McpException("A signature with this name already exists. Choose another name or explicitly approve replacing it.");
        if (existing is null && candidate.ReplaceExisting)
            throw new McpException("replaceExisting was approved but no signature with this name exists. Preview again.");

        var onboarding = before.Onboarding;
        if (candidate.CompleteOnboarding)
        {
            if (onboarding is not { Status: "pending", Language: "fa" or "en" }
                || onboarding.Language != candidate.Language)
                throw new McpException("The onboarding language or status changed. Preview the signature again.");
            onboarding = onboarding with { Stage = "more_signatures_and_rules" };
        }

        var updated = before with
        {
            Profiles = before.Profiles.Where(profile => !string.Equals(profile.Name, candidate.Profile.Name,
                    StringComparison.OrdinalIgnoreCase))
                .Append(CopyProfile(candidate.Profile)).ToArray(),
            NewMessages = candidate.MakeDefaultForNew ? candidate.Profile.Name : before.NewMessages,
            Replies = candidate.MakeDefaultForReplies ? candidate.Profile.Name : before.Replies,
            Onboarding = onboarding
        };
        _ = SignatureStore.SerializeValidated(updated);
        return updated;
    }

    private SignaturePreviewCandidate Get(MailboxIdentity identity, string handle, bool consume)
    {
        var binding = Binding.From(identity);
        if (!IsHandle(handle)) throw InvalidHandle();
        lock (gate)
        {
            RemoveExpired(clock.GetUtcNow());
            if (!entries.TryGetValue(handle, out var entry) || entry.Binding != binding)
                throw InvalidHandle();
            var result = CopyCandidate(entry.Candidate);
            if (consume) Remove(handle);
            return result;
        }
    }

    private void RemoveExpired(DateTimeOffset now)
    {
        foreach (var (handle, entry) in entries.Where(pair => pair.Value.ExpiresAt <= now).ToArray())
            Remove(handle);
    }

    private void Remove(string handle)
    {
        if (!entries.Remove(handle, out var entry)) return;
        bufferedBytes -= entry.Size;
        var actorMailbox = new ActorMailbox(entry.Binding.Subject, entry.Binding.Mailbox);
        if (activeByMailbox.TryGetValue(actorMailbox, out var active) && active == handle)
            activeByMailbox.Remove(actorMailbox);
    }

    private static SignaturePreviewCandidate CopyAndValidate(SignaturePreviewCandidate candidate)
    {
        ArgumentNullException.ThrowIfNull(candidate);
        if (candidate.Profile is null || candidate.Profile.Images is null || candidate.Profile.Images.Any(image => image is null))
            throw new McpException("The signature preview is invalid. Preview it again.");
        if (string.IsNullOrWhiteSpace(candidate.Revision) || candidate.Revision.Length > 256
            || candidate.Revision.Any(char.IsControl)
            || (candidate.Language is not null && candidate.Language is not ("fa" or "en"))
            || (candidate.CompleteOnboarding && candidate.Language is null)
            || ((candidate.SourceId is null) != (candidate.SourceChangeKey is null))
            || candidate.SourceId is { Length: 0 or > 4096 }
            || candidate.SourceChangeKey is { Length: 0 or > 512 }
            || candidate.SourceId?.Any(char.IsControl) == true
            || candidate.SourceChangeKey?.Any(char.IsControl) == true
            || (candidate.Warnings?.Length ?? 0) > 20
            || (candidate.Warnings?.Any(warning => warning is null || warning.Length > 500) ?? false))
            throw new McpException("The signature preview is invalid. Preview it again.");
        var copy = CopyCandidate(candidate);
        _ = SignatureStore.SerializeValidated(new([copy.Profile], null, null));
        return copy;
    }

    private static SignaturePreviewCandidate CopyCandidate(SignaturePreviewCandidate candidate) => candidate with
    {
        Profile = CopyProfile(candidate.Profile),
        Warnings = candidate.Warnings?.ToArray()
    };

    private static MailSignature CopyProfile(MailSignature profile) => profile with
    {
        Images = profile.Images?.Select(image => image with { }).ToArray() ?? []
    };

    private static bool IsHandle(string? handle) => handle is { Length: 43 }
        && handle.All(character => char.IsAsciiLetterOrDigit(character) || character is '-' or '_');

    private static string Base64Url(byte[] bytes) => Convert.ToBase64String(bytes)
        .TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static McpException InvalidHandle() => new("This signature preview is invalid, expired or belongs to another connection. Preview again before saving.");

    private readonly record struct ActorMailbox(string Subject, string Mailbox);
    private readonly record struct Binding(string Subject, string Mailbox, string ClientId, string SessionId)
    {
        public static Binding From(MailboxIdentity identity, bool requireSession = true)
        {
            if (identity.TargetId != "own" || string.IsNullOrWhiteSpace(identity.Subject)
                || string.IsNullOrWhiteSpace(identity.Mailbox) || string.IsNullOrWhiteSpace(identity.ClientId)
                || requireSession && string.IsNullOrWhiteSpace(identity.SessionId)
                || !string.Equals(identity.ActorMailbox ?? identity.Mailbox, identity.Mailbox, StringComparison.OrdinalIgnoreCase))
                throw new McpException("Signature preview requires a session-bound connection to your own mailbox.");
            return new(identity.Subject, identity.Mailbox.ToUpperInvariant(), identity.ClientId, identity.SessionId ?? string.Empty);
        }
    }

    private sealed record Entry(Binding Binding, SignaturePreviewCandidate Candidate, DateTimeOffset ExpiresAt,
        int Size, bool TestAttempted = false);
}
