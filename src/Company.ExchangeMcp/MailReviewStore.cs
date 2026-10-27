using System.Text;
using Company.ExchangeMcp.Security;

namespace Company.ExchangeMcp;

public sealed record LatestReviewedDraft(string DraftHandle, string? MailboxHandle, DateTimeOffset ExpiresAt);

public sealed class MailReviewStore(TimeProvider? clock = null)
{
    public const int MaxEntries = 2048;
    public const int MaxBufferedBytes = 8 * 1024 * 1024;
    public static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(15);

    private readonly TimeProvider clock = clock ?? TimeProvider.System;
    private readonly object gate = new();
    private readonly Dictionary<Binding, Entry> entries = [];
    private int bufferedBytes;

    public bool Record(MailboxIdentity actor, string draftHandle, string? mailboxHandle)
    {
        var binding = Binding.From(actor);
        if (binding is null) return false;
        lock (gate)
        {
            var now = clock.GetUtcNow();
            RemoveExpired(now);
            // A newer preview must never reopen an older draft when its reference cannot be retained.
            if (entries.Remove(binding, out var prior)) bufferedBytes -= prior.Size;
            if (!Valid(draftHandle, 16384) || mailboxHandle is not null && !Valid(mailboxHandle, 16384))
                return false;
            var size = Encoding.UTF8.GetByteCount(binding.Subject) + Encoding.UTF8.GetByteCount(binding.Mailbox)
                + Encoding.UTF8.GetByteCount(binding.ClientId) + Encoding.UTF8.GetByteCount(binding.SessionId)
                + Encoding.UTF8.GetByteCount(draftHandle) + Encoding.UTF8.GetByteCount(mailboxHandle ?? string.Empty);
            if (entries.Count >= MaxEntries || bufferedBytes + size > MaxBufferedBytes)
                return false;
            entries[binding] = new(new(draftHandle, mailboxHandle, now + Lifetime), size);
            bufferedBytes += size;
            return true;
        }
    }

    public LatestReviewedDraft? Get(MailboxIdentity actor)
    {
        var binding = Binding.From(actor);
        if (binding is null) return null;
        lock (gate)
        {
            RemoveExpired(clock.GetUtcNow());
            return entries.TryGetValue(binding, out var entry) ? entry.Reference : null;
        }
    }

    private void RemoveExpired(DateTimeOffset now)
    {
        foreach (var (binding, entry) in entries.Where(pair => pair.Value.Reference.ExpiresAt <= now).ToArray())
        {
            entries.Remove(binding);
            bufferedBytes -= entry.Size;
        }
    }

    private static bool Valid(string? value, int maximum) => !string.IsNullOrWhiteSpace(value)
        && value.Length <= maximum && !value.Any(char.IsControl);

    private sealed record Binding(string Subject, string Mailbox, string ClientId, string SessionId)
    {
        public static Binding? From(MailboxIdentity actor) => actor.TargetId == "own"
            && Valid(actor.Subject, 1024) && Valid(actor.Mailbox, 1024) && Valid(actor.ClientId, 1024)
            && Valid(actor.SessionId, 1024)
            && string.Equals(actor.ActorMailbox ?? actor.Mailbox, actor.Mailbox, StringComparison.Ordinal)
                ? new(actor.Subject, actor.Mailbox, actor.ClientId, actor.SessionId!) : null;
    }

    private sealed record Entry(LatestReviewedDraft Reference, int Size);
}
