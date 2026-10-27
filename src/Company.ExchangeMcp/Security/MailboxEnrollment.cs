using System.Globalization;
using System.Security.Claims;
using System.Text.Json;
using Company.ExchangeMcp.Exchange;
using Microsoft.Extensions.Options;

namespace Company.ExchangeMcp.Security;

/// <summary>Opt-in, server-side binding from a signed directory GUID claim to one Exchange mailbox.</summary>
public sealed class MailboxEnrollment
{
    public const string DirectoryGuidClaim = "ad_object_guid";
    private const int SchemaVersion = 1;
    private const int MaxRecords = 1024;
    private const int MaxFileBytes = 1024 * 1024;
    private static readonly UnixFileMode PrivateFileMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
    private readonly ServiceOptions service;
    private readonly DirectoryPermissionOptions directory;
    private readonly ILdapSearchFacadeFactory searchFactory;
    private readonly string path = "";
    private readonly SemaphoreSlim gate = new(1, 1);
    private readonly Dictionary<string, EnrollmentRecord> records = new(StringComparer.Ordinal);
    private volatile bool available = true;

    public MailboxEnrollment(
        IOptions<ServiceOptions> serviceOptions,
        IOptions<DirectoryPermissionOptions> directoryOptions,
        ILdapSearchFacadeFactory searchFactory)
    {
        service = serviceOptions?.Value ?? throw new ArgumentNullException(nameof(serviceOptions));
        directory = directoryOptions?.Value ?? throw new ArgumentNullException(nameof(directoryOptions));
        this.searchFactory = searchFactory ?? throw new ArgumentNullException(nameof(searchFactory));
        if (!service.AutoEnrollmentEnabled) return;
        if (!directory.IsConfigured || !directory.IsValid() || service.AllowedRecipientDomains.Length == 0)
            throw new InvalidOperationException("Automatic mailbox enrollment requires trusted LDAPS and approved recipient domains.");

        path = Path.GetFullPath(service.AuditPath) + ".enrollments.json";
        Load();
    }

    public bool Enabled => service.AutoEnrollmentEnabled && available;

    public IReadOnlyList<(string Subject, string Mailbox)> Snapshot()
    {
        lock (records)
        {
            if (!Enabled) return [];
            return records.Values.OrderBy(record => record.Subject, StringComparer.Ordinal)
                .Select(record => (record.Subject, record.Mailbox)).ToArray();
        }
    }

    public bool TryGet(string subject, out string mailbox, out string objectGuid)
    {
        lock (records)
        {
            if (Enabled && records.TryGetValue(subject, out var record))
            {
                mailbox = record.Mailbox;
                objectGuid = record.ObjectGuid;
                return true;
            }
        }
        mailbox = "";
        objectGuid = "";
        return false;
    }

    public async Task<bool> EnsureAsync(
        ClaimsPrincipal principal,
        EwsClient exchange,
        MailboxAccess access,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(principal);
        ArgumentNullException.ThrowIfNull(exchange);
        ArgumentNullException.ThrowIfNull(access);

        var subject = principal.FindFirst("sub")?.Value;
        var clientId = principal.FindFirst("azp")?.Value;
        if (principal.Identity?.IsAuthenticated != true || subject is null || !ValidSubject(subject)
            || principal.FindFirst("iss")?.Value != service.Authority
            || principal.FindFirst("typ")?.Value != "Bearer"
            || string.IsNullOrWhiteSpace(clientId)
            || !service.AllowedClientIds.Contains(clientId, StringComparer.Ordinal)
            || !MailboxAccess.HasScope(principal, MailboxAccess.Read))
            return false;
        if (!service.AutoEnrollmentEnabled)
            return service.Mailboxes.TryGetValue(subject, out var staticMailbox)
                && ServiceOptions.IsMailbox(staticMailbox);
        if (!service.AutoEnrollmentEnabled || !TryClaimGuid(principal, out var claimedGuid)) return false;

        EnrollmentRecord? established;
        lock (records)
        {
            if (!Enabled) return false;
            records.TryGetValue(subject, out established);
        }
        if (established is not null)
        {
            if (!string.Equals(established.ObjectGuid, claimedGuid.ToString("D"), StringComparison.Ordinal)) return false;
            try
            {
                // Current AD checks are independent; only first-enrollment persistence is serialized.
                var current = await ResolveByGuidAsync(claimedGuid, cancellationToken).ConfigureAwait(false);
                lock (records)
                    return Enabled && records.TryGetValue(subject, out var retained) && retained == established
                        && current is not null && string.Equals(current.Mailbox, retained.Mailbox, StringComparison.OrdinalIgnoreCase)
                        && !HasStaticCollision(subject, current.Mailbox);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (Exception exception) when (exception is not OutOfMemoryException and not StackOverflowException) { return false; }
        }

        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (!Enabled) return false;
            EnrollmentRecord? existing;
            lock (records) records.TryGetValue(subject, out existing);
            if (existing is not null)
            {
                if (!string.Equals(existing.ObjectGuid, claimedGuid.ToString("D"), StringComparison.Ordinal))
                    return false;
                var current = await ResolveByGuidAsync(claimedGuid, cancellationToken).ConfigureAwait(false);
                return Enabled && current is not null && string.Equals(current.Mailbox, existing.Mailbox, StringComparison.OrdinalIgnoreCase)
                    && !HasStaticCollision(subject, current.Mailbox);
            }

            if (records.Count >= MaxRecords) return false;

            var candidate = await ResolveByGuidAsync(claimedGuid, cancellationToken).ConfigureAwait(false);
            if (candidate is null || HasStaticOrDynamicCollision(subject, claimedGuid, candidate.Mailbox)) return false;

            var actor = new MailboxIdentity(subject, candidate.Mailbox,
                principal.FindFirst("azp")?.Value ?? "", principal.FindFirst("sid")?.Value, "own", candidate.Mailbox);
            using (access.SelectTarget(actor))
            {
                var inbox = await exchange.GetEffectiveRightsAsync(candidate.Mailbox, "inbox", cancellationToken)
                    .ConfigureAwait(false);
                if (inbox.Read != true) return false;
            }

            cancellationToken.ThrowIfCancellationRequested();
            var verified = await ResolveByGuidAsync(claimedGuid, cancellationToken).ConfigureAwait(false);
            if (verified is null || !string.Equals(verified.Mailbox, candidate.Mailbox, StringComparison.OrdinalIgnoreCase)
                || HasStaticOrDynamicCollision(subject, claimedGuid, verified.Mailbox))
                return false;

            var entry = new EnrollmentRecord(subject, claimedGuid.ToString("D"), verified.Mailbox);
            try { Save(records.Values.Append(entry).ToArray()); }
            catch
            {
                available = false;
                throw;
            }
            lock (records) records.Add(subject, entry);
            return true;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception) when (exception is not OutOfMemoryException and not StackOverflowException)
        {
            return false;
        }
        finally { gate.Release(); }
    }

    public async Task<bool> VerifyCurrentAsync(string subject, string mailbox, CancellationToken cancellationToken)
    {
        if (!TryGet(subject, out var registeredMailbox, out var objectGuid)
            || !string.Equals(registeredMailbox, mailbox, StringComparison.OrdinalIgnoreCase)
            || !Guid.TryParseExact(objectGuid, "D", out var guid))
            return false;
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            var current = await ResolveByGuidAsync(guid, cancellationToken).ConfigureAwait(false);
            return current is not null && string.Equals(current.Mailbox, registeredMailbox, StringComparison.OrdinalIgnoreCase);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception exception) when (exception is not OutOfMemoryException and not StackOverflowException) { return false; }
    }

    private Task<ResolvedMailbox?> ResolveByGuidAsync(Guid guid, CancellationToken cancellationToken) =>
        Task.Run(() => ResolveByGuid(guid, cancellationToken), cancellationToken);

    private ResolvedMailbox? ResolveByGuid(Guid guid, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        using var ldap = searchFactory.Create();
        var rows = ldap.Search(directory.BaseDn, GuidFilter(guid), System.DirectoryServices.Protocols.SearchScope.Subtree,
            ["objectGUID", "userAccountControl", "msExchRecipientTypeDetails", "proxyAddresses", "legacyExchangeDN", "homeMDB"],
            requestDaclOnly: false, cancellationToken);
        if (rows.Count != 1) return null;
        var entry = rows[0];
        var guids = entry.Binary("objectGUID");
        if (guids.Count != 1 || guids[0].Length != 16 || new Guid(guids[0]) != guid
            || string.IsNullOrWhiteSpace(entry.DistinguishedName))
            return null;

        var uacValues = entry.Text("userAccountControl");
        var recipientValues = entry.Text("msExchRecipientTypeDetails");
        if (uacValues.Count != 1 || !int.TryParse(uacValues[0], NumberStyles.None, CultureInfo.InvariantCulture, out var uac)
            || (uac & 512) == 0 || (uac & 2) != 0
            || recipientValues.Count != 1 || !long.TryParse(recipientValues[0], NumberStyles.None, CultureInfo.InvariantCulture, out var recipientType)
            || recipientType != 1
            || !HasSingleRequiredText(entry, "legacyExchangeDN")
            || !HasSingleRequiredText(entry, "homeMDB"))
            return null;

        var primary = entry.Text("proxyAddresses").Where(value => value.StartsWith("SMTP:", StringComparison.Ordinal)).ToArray();
        if (primary.Length != 1) return null;
        var mailbox = primary[0][5..];
        if (mailbox.Length > 320 || !ServiceOptions.IsMailbox(mailbox) || !IsAllowedDomain(mailbox)) return null;
        return new(mailbox);
    }

    private bool HasStaticOrDynamicCollision(string subject, Guid guid, string mailbox)
    {
        if (HasStaticCollision(subject, mailbox)
            || HasDynamicCollision(guid, mailbox)) return true;
        return false;
    }

    private bool HasDynamicCollision(Guid guid, string mailbox)
    {
        lock (records)
            return records.Values.Any(record =>
                string.Equals(record.ObjectGuid, guid.ToString("D"), StringComparison.Ordinal)
                || string.Equals(record.Mailbox, mailbox, StringComparison.OrdinalIgnoreCase));
    }

    private bool IsAllowedDomain(string mailbox)
    {
        var at = mailbox.LastIndexOf('@');
        return at > 0 && service.AllowedRecipientDomains.Contains(mailbox[(at + 1)..], StringComparer.OrdinalIgnoreCase);
    }

    private void Load()
    {
        if (!File.Exists(path)) return;
        try
        {
            if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(path, PrivateFileMode);
            var info = new FileInfo(path);
            if (info.Length is < 1 or > MaxFileBytes) throw new InvalidDataException("Enrollment registry size is invalid.");
            using var document = JsonDocument.Parse(File.ReadAllBytes(path), new JsonDocumentOptions { MaxDepth = 8 });
            var root = document.RootElement;
            RequireObject(root, ["schemaVersion", "issuer", "records"]);
            if (root.GetProperty("schemaVersion").GetInt32() != SchemaVersion
                || root.GetProperty("issuer").GetString() != service.Authority)
                throw new InvalidDataException("Enrollment registry schema is invalid.");
            var storedRecords = root.GetProperty("records");
            if (storedRecords.ValueKind != JsonValueKind.Array || storedRecords.GetArrayLength() > MaxRecords)
                throw new InvalidDataException("Enrollment registry entries are invalid.");
            var guids = new HashSet<string>(StringComparer.Ordinal);
            var mailboxes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var stored in storedRecords.EnumerateArray())
            {
                RequireObject(stored, ["subject", "objectGuid", "mailbox"]);
                var subject = stored.GetProperty("subject").GetString();
                var guidText = stored.GetProperty("objectGuid").GetString();
                var mailbox = stored.GetProperty("mailbox").GetString();
                if (!ValidSubject(subject) || guidText is null || !Guid.TryParseExact(guidText, "D", out var guid)
                    || guid == Guid.Empty || guid.ToString("D") != guidText || mailbox is null || mailbox.Length > 320
                    || !ServiceOptions.IsMailbox(mailbox)
                    || !IsAllowedDomain(mailbox!) || HasStaticCollision(subject!, mailbox!)
                    || !guids.Add(guidText) || !mailboxes.Add(mailbox!)
                    || !records.TryAdd(subject!, new(subject!, guidText, mailbox!)))
                    throw new InvalidDataException("Enrollment registry contains an invalid or conflicting binding.");
            }
        }
        catch
        {
            records.Clear();
            throw;
        }
    }

    private bool HasStaticCollision(string subject, string mailbox) =>
        service.Mailboxes.TryGetValue(subject, out var own)
            && !string.Equals(own, mailbox, StringComparison.OrdinalIgnoreCase)
        || service.Mailboxes.Any(entry => entry.Key != subject
            && string.Equals(entry.Value, mailbox, StringComparison.OrdinalIgnoreCase));

    private void Save(IReadOnlyCollection<EnrollmentRecord> entries)
    {
        if (!available) throw new IOException("Enrollment registry is unavailable.");
        if (entries.Count > MaxRecords) throw new InvalidDataException("Enrollment registry is full.");
        var bytes = JsonSerializer.SerializeToUtf8Bytes(new
        {
            schemaVersion = SchemaVersion,
            issuer = service.Authority,
            records = entries.OrderBy(record => record.Subject, StringComparer.Ordinal)
                .Select(record => new { subject = record.Subject, objectGuid = record.ObjectGuid, mailbox = record.Mailbox }).ToArray()
        });
        if (bytes.Length > MaxFileBytes) throw new InvalidDataException("Enrollment registry is full.");
        var directoryPath = Path.GetDirectoryName(path)!;
        var directoryExists = Directory.Exists(directoryPath);
        Directory.CreateDirectory(directoryPath);
        if (!directoryExists && !OperatingSystem.IsWindows()) File.SetUnixFileMode(directoryPath,
            UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        var temporary = path + ".tmp";
        if (File.Exists(temporary) && !OperatingSystem.IsWindows()) File.SetUnixFileMode(temporary, PrivateFileMode);
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

    private static bool TryClaimGuid(ClaimsPrincipal principal, out Guid guid)
    {
        guid = Guid.Empty;
        var claims = principal.FindAll(DirectoryGuidClaim).ToArray();
        return claims.Length == 1 && Guid.TryParseExact(claims[0].Value, "D", out guid)
            && guid != Guid.Empty && guid.ToString("D") == claims[0].Value;
    }

    private static bool ValidSubject(string? subject) => !string.IsNullOrWhiteSpace(subject)
        && subject.Length <= 256 && !subject.Any(char.IsControl);

    private static bool HasSingleRequiredText(LdapSearchEntry entry, string attribute)
    {
        var values = entry.Text(attribute);
        return values.Count == 1 && !string.IsNullOrWhiteSpace(values[0]) && values[0].Length <= 4096;
    }

    private static string GuidFilter(Guid guid) => "(&(objectCategory=person)(objectClass=user)(objectGUID="
        + string.Concat(guid.ToByteArray().Select(value => "\\" + value.ToString("x2", CultureInfo.InvariantCulture)))
        + "))";

    private static void RequireObject(JsonElement element, string[] expected)
    {
        if (element.ValueKind != JsonValueKind.Object) throw new InvalidDataException("Enrollment registry record is invalid.");
        var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (var property in element.EnumerateObject())
            if (!names.Add(property.Name)) throw new InvalidDataException("Enrollment registry has duplicate fields.");
        if (!names.SetEquals(expected)) throw new InvalidDataException("Enrollment registry fields are invalid.");
    }

    private sealed record EnrollmentRecord(string Subject, string ObjectGuid, string Mailbox);
    private sealed record ResolvedMailbox(string Mailbox);
}
