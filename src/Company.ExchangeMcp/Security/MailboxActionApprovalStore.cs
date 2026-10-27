using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using ModelContextProtocol;

namespace Company.ExchangeMcp.Security;

public sealed class MailboxActionApprovalException(string message, string reason) : McpException(message)
{
    public string Reason { get; } = reason;
}

/// <summary>Reservations are committed before dispatch and uncertain attempts never expire automatically.</summary>
public sealed class MailboxActionApprovalStore
{
    public const int MaxEntries = 10000;
    public const int MaxStateBytes = 8 * 1024 * 1024;
    public static readonly TimeSpan ApprovalLifetime = TimeSpan.FromMinutes(15);
    // Recall's 48-hour handle only reads reports; handles that authorize actions expire after 15 minutes.
    public static readonly TimeSpan AcknowledgedRetention = TimeSpan.FromHours(1);
    private static readonly JsonSerializerOptions Json = new() { MaxDepth = 12 };
    private readonly IDataProtector protector;
    private readonly string statePath;
    private readonly string lockPath;
    private readonly TimeProvider clock;
    private readonly object gate = new();

    public MailboxActionApprovalStore(IDataProtectionProvider protection, string auditPath, TimeProvider? clock = null)
    {
        this.clock = clock ?? TimeProvider.System;
        protector = protection.CreateProtector("Company.ExchangeMcp.ActionRegistry.v1");
        var directory = Path.GetFullPath(auditPath) + ".mcp-state";
        statePath = Path.Combine(directory, "approvals.enc");
        lockPath = Path.Combine(directory, "approvals.lock");
        try
        {
            Directory.CreateDirectory(directory);
            if (!OperatingSystem.IsWindows())
                File.SetUnixFileMode(directory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            using var fileLock = AcquireLock();
            var marker = Path.Combine(directory, "approvals.initialized");
            if (!File.Exists(statePath))
            {
                if (File.Exists(marker)) throw new IOException("The approval registry is missing.");
                Save(new());
            }
            _ = Load();
            using var markerStream = new FileStream(marker, FileMode.OpenOrCreate, FileAccess.Write, FileShare.None);
            markerStream.Flush(flushToDisk: true);
        }
        catch (Exception ex) when (IsStorageFailure(ex)) { throw StorageFailure(); }
    }

    public DateTimeOffset ExpiresAt() => clock.GetUtcNow() + ApprovalLifetime;

    public void Stage(string nonce, string fingerprint, DateTimeOffset expiresAt) => Access(state =>
    {
        if (expiresAt <= clock.GetUtcNow() || expiresAt > clock.GetUtcNow() + ApprovalLifetime)
            throw new MailboxActionApprovalException("The mailbox action approval expired. Request approval again.", "expired");
        if (state.Pending.Count >= MaxEntries) throw Capacity();
        if (!state.Pending.TryAdd(nonce, new(fingerprint, expiresAt))) throw Replay();
    }, save: true);

    public void RequirePending(string nonce, string fingerprint, DateTimeOffset expiresAt) => Access(state =>
    {
        if (expiresAt <= clock.GetUtcNow())
            throw new MailboxActionApprovalException("The mailbox action approval expired. Request approval again.", "expired");
        if (!state.Pending.TryGetValue(nonce, out var pending)) throw Replay();
        if (pending.Fingerprint != fingerprint || pending.ExpiresAt != expiresAt)
            throw new MailboxActionApprovalException("The mailbox action approval does not match the requested action.", "binding_mismatch");
    });

    public void Reserve(string key, string? nonce, string fingerprint, string mailbox, string action, string itemId)
    {
        Access(state =>
        {
            if (state.Attempts.ContainsKey(key)) throw Replay();
            if (nonce is not null)
            {
                if (!state.Pending.TryGetValue(nonce, out var pending)) throw Replay();
                if (pending.Fingerprint != fingerprint)
                    throw new MailboxActionApprovalException("The mailbox action approval does not match the requested action.", "binding_mismatch");
            }
            if (state.Attempts.Count >= MaxEntries) throw Capacity();
            if (nonce is not null) state.Pending.Remove(nonce);
            state.Attempts.Add(key, new(nonce, fingerprint, mailbox, action, itemId));
        }, save: true);
        OperationTracking.Current?.RegisterApprovalCompletion(action, () => Acknowledge(key, fingerprint));
    }

    public void Acknowledge(string key, string fingerprint) => Access(state =>
    {
        // Verified delegate reconciliation may already have removed this exact hold.
        if (!state.Attempts.TryGetValue(key, out var held)) return;
        if (held.Fingerprint != fingerprint) throw new InvalidOperationException("The completed approval reservation changed.");
        state.Attempts[key] = held with { AcknowledgedAt = clock.GetUtcNow() };
    }, save: true);

    public void Cancel(string nonce, string fingerprint) => Access(state =>
    {
        if (state.Pending.TryGetValue(nonce, out var pending) && pending.Fingerprint == fingerprint)
            state.Pending.Remove(nonce);
    }, save: true);

    public void CompleteVerified(string key, string nonce, string mailbox, string itemId, bool removed) => Access(state =>
    {
        if (!state.Attempts.TryGetValue(key, out var attempt) || attempt.Nonce != nonce)
            throw new InvalidOperationException("The delegate action has no consumed replay record to complete.");
        state.Attempts.Remove(key);
        if (removed)
            foreach (var held in state.Attempts.Where(pair => pair.Value.Action is "delegate_add" or "delegate_update"
                && pair.Value.Mailbox == mailbox && pair.Value.ItemId.Equals(itemId, StringComparison.OrdinalIgnoreCase))
                .Select(pair => pair.Key).ToArray())
                state.Attempts.Remove(held);
    }, save: true);

    public static string Fingerprint<T>(T approval) => Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(approval)));

    private void Access(Action<State> action, bool save = false)
    {
        lock (gate)
        {
            try
            {
                using var fileLock = AcquireLock();
                var state = Load();
                foreach (var nonce in state.Pending.Where(pair => pair.Value.ExpiresAt <= clock.GetUtcNow()).Select(pair => pair.Key).ToArray())
                    state.Pending.Remove(nonce);
                foreach (var key in state.Attempts.Where(pair => pair.Value.AcknowledgedAt is { } acknowledged
                    && acknowledged <= clock.GetUtcNow() - AcknowledgedRetention).Select(pair => pair.Key).ToArray())
                    state.Attempts.Remove(key);
                action(state);
                if (save) Save(state);
            }
            catch (Exception ex) when (IsStorageFailure(ex)) { throw StorageFailure(); }
        }
    }

    private FileStream AcquireLock() => new(lockPath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);

    private State Load()
    {
        using var stream = new FileStream(statePath, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (stream.Length is < 32 or > MaxStateBytes + 32) throw new IOException("Invalid approval registry size.");
        var encrypted = new byte[checked((int)stream.Length)];
        stream.ReadExactly(encrypted);
        var plaintext = protector.Unprotect(encrypted);
        try
        {
            if (plaintext.Length > MaxStateBytes) throw new IOException("The approval registry is too large.");
            var state = JsonSerializer.Deserialize<State>(plaintext, Json) ?? throw new JsonException();
            if (state.Version != 1 || state.Pending is null || state.Attempts is null
                || state.Pending.Count > MaxEntries || state.Attempts.Count > MaxEntries
                || state.Pending.Any(pair => pair.Key.Length != 32 || pair.Value is null || pair.Value.Fingerprint is not { Length: 64 })
                || state.Attempts.Any(pair => pair.Key.Length != 64 || pair.Value is null || pair.Value.Fingerprint is not { Length: 64 }
                    || pair.Value.Mailbox is not { Length: > 0 and <= 512 }
                    || pair.Value.Action is not { Length: > 0 and <= 128 }
                    || pair.Value.ItemId is not { Length: <= 8192 }))
                throw new JsonException("The approval registry is invalid.");
            return state;
        }
        finally { CryptographicOperations.ZeroMemory(plaintext); }
    }

    private void Save(State state)
    {
        var plaintext = JsonSerializer.SerializeToUtf8Bytes(state, Json);
        byte[] encrypted;
        try
        {
            if (plaintext.Length > MaxStateBytes) throw Capacity();
            encrypted = protector.Protect(plaintext);
        }
        finally { CryptographicOperations.ZeroMemory(plaintext); }
        var temporary = statePath + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            var options = new FileStreamOptions
            {
                Mode = FileMode.CreateNew,
                Access = FileAccess.Write,
                Share = FileShare.None,
                Options = FileOptions.WriteThrough
            };
            if (!OperatingSystem.IsWindows()) options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
            using (var stream = new FileStream(temporary, options))
            { stream.Write(encrypted); stream.Flush(flushToDisk: true); }
            File.Move(temporary, statePath, overwrite: true);
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }

    private static bool IsStorageFailure(Exception ex) => ex is IOException or UnauthorizedAccessException or CryptographicException or JsonException;
    private static MailboxActionApprovalException StorageFailure() => new("Mailbox action approval storage is unavailable. No new action was dispatched; contact the administrator.", "storage_unavailable");
    private static MailboxActionApprovalException Replay() => new("The mailbox action approval is invalid, expired or already used, or the action already had an attempt. Verify the mailbox before retrying.", "replay");
    private static MailboxActionApprovalException Capacity() => new("Mailbox action approval capacity is exhausted. Existing uncertain attempts were retained; contact the administrator.", "capacity");
    private sealed class State
    {
        public int Version { get; set; } = 1;
        public Dictionary<string, Pending> Pending { get; set; } = new(StringComparer.Ordinal);
        public Dictionary<string, Attempt> Attempts { get; set; } = new(StringComparer.Ordinal);
    }
    private sealed record Pending(string Fingerprint, DateTimeOffset ExpiresAt);
    private sealed record Attempt(string? Nonce, string Fingerprint, string Mailbox, string Action, string ItemId,
        DateTimeOffset? AcknowledgedAt = null);
}
