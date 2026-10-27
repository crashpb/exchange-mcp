using System.DirectoryServices.Protocols;
using System.Globalization;
using Company.ExchangeMcp.Security;
using Microsoft.Extensions.Options;

namespace Company.ExchangeMcp.Exchange;

public sealed partial class LdapMailboxPermissionReader : IMailboxDirectory
{
    private const int MailboxPageSize = 32;
    private const int MaximumMailboxPages = 32;
    private const int MaximumMailboxEntries = 1_024;
    private const int MaximumPageCookieBytes = 16 * 1024;
    private static readonly TimeSpan MaximumDiscoveryDuration = TimeSpan.FromSeconds(30);
    private static readonly HashSet<long> EligibleRecipientTypes = [1, 4, 16, 32];
    private static readonly string[] MailboxDirectoryAttributes =
    [
        "objectGUID", "objectCategory", "objectClass", "displayName", "proxyAddresses",
        "msExchRecipientTypeDetails", "homeMDB", "legacyExchangeDN"
    ];

    public async Task<IReadOnlyList<MailboxDirectoryCandidate>> ListAsync(CancellationToken cancellationToken)
    {
        EnsureDiscoveryConfigured();
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(MaximumDiscoveryDuration);
        try
        {
            return await Task.Run(() => ListSynchronously(deadline.Token), deadline.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new TimeoutException("The directory mailbox discovery exceeded its time limit.");
        }
    }

    public async Task<MailboxDirectoryCandidate?> ResolveAsync(string key, CancellationToken cancellationToken)
    {
        EnsureDiscoveryConfigured();
        if (!Guid.TryParseExact(key, "D", out var objectGuid)
            || !string.Equals(key, objectGuid.ToString("D"), StringComparison.Ordinal))
            return null;

        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(MaximumDiscoveryDuration);
        try
        {
            return await Task.Run(() => ResolveSynchronously(objectGuid, deadline.Token), deadline.Token)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new TimeoutException("The directory mailbox lookup exceeded its time limit.");
        }
    }

    private void EnsureDiscoveryConfigured()
    {
        var settings = directoryOptions.Value;
        if (!settings.IsConfigured || !settings.IsValid())
            throw new InvalidOperationException("Directory mailbox discovery is not configured.");
    }

    private IReadOnlyList<MailboxDirectoryCandidate> ListSynchronously(CancellationToken cancellationToken)
    {
        var candidates = new List<MailboxDirectoryCandidate>();
        var seenKeys = new HashSet<string>(StringComparer.Ordinal);
        var seenMailboxes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var seenCookies = new HashSet<string>(StringComparer.Ordinal);
        var cookie = Array.Empty<byte>();
        using var ldap = searchFactory.Create();

        for (var pageNumber = 0; pageNumber < MaximumMailboxPages; pageNumber++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var page = ldap.SearchPage(directoryOptions.Value.BaseDn, MailboxRecipientFilter, SearchScope.Subtree,
                MailboxDirectoryAttributes, requestDaclOnly: false, cookie, MailboxPageSize, cancellationToken);
            if (page.Entries.Count > MailboxPageSize || page.Cookie.Length > MaximumPageCookieBytes)
                throw new InvalidDataException("Directory mailbox discovery exceeded a page limit.");
            if (candidates.Count + page.Entries.Count > MaximumMailboxEntries)
                throw new InvalidDataException("Directory mailbox discovery exceeded its result limit.");

            foreach (var entry in page.Entries)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (!TryParseMailboxCandidate(entry, out var candidate))
                    continue;
                if (!seenKeys.Add(candidate.Key) || !seenMailboxes.Add(candidate.Mailbox))
                    throw new InvalidDataException("Directory mailbox identities are ambiguous.");
                candidates.Add(candidate);
            }

            if (page.Cookie.Length == 0)
                return candidates.OrderBy(candidate => candidate.Mailbox, StringComparer.OrdinalIgnoreCase)
                    .ThenBy(candidate => candidate.Key, StringComparer.Ordinal).ToArray();
            var cookieKey = Convert.ToHexString(page.Cookie);
            if (!seenCookies.Add(cookieKey))
                throw new InvalidDataException("Directory mailbox discovery returned a repeated page cookie.");
            cookie = page.Cookie;
        }

        throw new InvalidDataException("Directory mailbox discovery exceeded its page limit.");
    }

    private MailboxDirectoryCandidate? ResolveSynchronously(Guid objectGuid, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        using var ldap = searchFactory.Create();
        var rows = ldap.Search(directoryOptions.Value.BaseDn, ObjectGuidFilter(objectGuid), SearchScope.Subtree,
            MailboxDirectoryAttributes, requestDaclOnly: false, cancellationToken);
        if (rows.Count == 0)
            return null;
        if (rows.Count != 1 || !TryParseMailboxCandidate(rows[0], out var candidate)
            || !string.Equals(candidate.Key, objectGuid.ToString("D"), StringComparison.Ordinal))
            throw new InvalidDataException("The requested directory mailbox could not be uniquely resolved.");
        return candidate;
    }

    private static bool TryParseMailboxCandidate(LdapSearchEntry entry, out MailboxDirectoryCandidate candidate)
    {
        candidate = null!;
        var guidValues = entry.Binary("objectGUID");
        if (guidValues.Count != 1 || guidValues[0].Length != 16)
            return false;
        var objectGuid = new Guid(guidValues[0]);
        if (objectGuid == Guid.Empty)
            return false;

        if (!entry.Text("objectCategory").Any(value => value.StartsWith("CN=Person,", StringComparison.OrdinalIgnoreCase))
            || !entry.Text("objectClass").Contains("user", StringComparer.OrdinalIgnoreCase)
            || entry.Text("msExchRecipientTypeDetails").Count != 1
            || !long.TryParse(entry.Text("msExchRecipientTypeDetails")[0], NumberStyles.None,
                CultureInfo.InvariantCulture, out var recipientType)
            || !EligibleRecipientTypes.Contains(recipientType)
            || !HasSingleNonEmpty(entry.Text("homeMDB"))
            || !HasSingleNonEmpty(entry.Text("legacyExchangeDN")))
            return false;

        string? primary = null;
        var smtpAddresses = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var proxy in entry.Text("proxyAddresses"))
        {
            if (!proxy.StartsWith("smtp:", StringComparison.OrdinalIgnoreCase))
                continue;
            var address = proxy[5..];
            if (!ServiceOptions.IsMailbox(address) || !smtpAddresses.Add(address))
                return false;
            if (proxy.StartsWith("SMTP:", StringComparison.Ordinal))
            {
                if (primary is not null)
                    return false;
                primary = address;
            }
        }
        if (primary is null || !ServiceOptions.IsMailbox(primary))
            return false;

        var displayNames = entry.Text("displayName");
        var displayName = displayNames.Count == 1 && displayNames[0].Length is > 0 and <= 256
            && !displayNames[0].Any(char.IsControl) ? displayNames[0] : null;
        candidate = new(objectGuid.ToString("D"), primary, displayName, recipientType);
        return true;
    }

    private static bool HasSingleNonEmpty(IReadOnlyList<string> values) =>
        values.Count == 1 && !string.IsNullOrWhiteSpace(values[0]);

    private const string MailboxRecipientFilter =
        "(&(objectCategory=person)(objectClass=user)(homeMDB=*)(legacyExchangeDN=*)" +
        "(|(msExchRecipientTypeDetails=1)(msExchRecipientTypeDetails=4)" +
        "(msExchRecipientTypeDetails=16)(msExchRecipientTypeDetails=32)))";

    private static string ObjectGuidFilter(Guid objectGuid) =>
        "(objectGUID=" + string.Concat(objectGuid.ToByteArray().Select(value => $"\\{value:x2}")) + ")";

    private LdapSearchEntry? ResolveTargetForPermission(
        ILdapSearchFacade ldap, Guid objectGuid, CancellationToken cancellationToken)
    {
        var attributes = MailboxDirectoryAttributes.Concat(TargetAttributes)
            .Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        var rows = ldap.Search(directoryOptions.Value.BaseDn, ObjectGuidFilter(objectGuid), SearchScope.Subtree,
            attributes, requestDaclOnly: true, cancellationToken);
        if (rows.Count == 0)
            return null;
        if (rows.Count != 1 || !TryParseMailboxCandidate(rows[0], out var candidate)
            || !string.Equals(candidate.Key, objectGuid.ToString("D"), StringComparison.Ordinal))
            throw new InvalidDataException("The selected directory mailbox could not be uniquely resolved.");
        return rows[0];
    }
}
