using System.DirectoryServices.Protocols;
using Company.ExchangeMcp.Security;

namespace Company.ExchangeMcp.Exchange;

public sealed record PermissionDecision(
    string State,
    string Reason,
    bool Direct = false,
    bool ViaGroup = false,
    bool Inherited = false,
    bool MatchingDeny = false)
{
    public static PermissionDecision Unknown(string reason) => new("unknown", reason);
}

public sealed record MailboxPermissionReport(
    PermissionDecision FullAccess,
    PermissionDecision SendAs,
    PermissionDecision SendOnBehalf,
    DateTimeOffset CheckedAt,
    string Source);

public interface IMailboxPermissionReader
{
    Task<MailboxPermissionReport> ReadAsync(MailboxIdentity identity, CancellationToken cancellationToken);
}

public sealed record MailboxDirectoryCandidate(string Key, string Mailbox, string? DisplayName, long RecipientTypeDetails = 0);

public interface IMailboxDirectory
{
    Task<IReadOnlyList<MailboxDirectoryCandidate>> ListAsync(CancellationToken cancellationToken);

    Task<MailboxDirectoryCandidate?> ResolveAsync(string key, CancellationToken cancellationToken);
}

/// <summary>Small synchronous seam around LDAP, so permission evaluation can be tested without a directory.</summary>
public interface ILdapSearchFacadeFactory
{
    ILdapSearchFacade Create();
}

public interface ILdapSearchFacade : IDisposable
{
    IReadOnlyList<LdapSearchEntry> Search(
        string baseDn,
        string filter,
        SearchScope scope,
        IReadOnlyList<string> attributes,
        bool requestDaclOnly,
        CancellationToken cancellationToken);

    LdapSearchPage SearchPage(
        string baseDn,
        string filter,
        SearchScope scope,
        IReadOnlyList<string> attributes,
        bool requestDaclOnly,
        byte[] cookie,
        int pageSize,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(cookie);
        return new(Search(baseDn, filter, scope, attributes, requestDaclOnly, cancellationToken), []);
    }
}

public sealed record LdapSearchPage(IReadOnlyList<LdapSearchEntry> Entries, byte[] Cookie);

public sealed record LdapSearchEntry(
    string DistinguishedName,
    IReadOnlyDictionary<string, IReadOnlyList<string>> TextAttributes,
    IReadOnlyDictionary<string, IReadOnlyList<byte[]>> BinaryAttributes)
{
    public bool HasText(string name) => TextAttributes.ContainsKey(name);

    public bool HasBinary(string name) => BinaryAttributes.ContainsKey(name);

    public IReadOnlyList<string> Text(string name) => TextAttributes.TryGetValue(name, out var values)
        ? values : [];

    public IReadOnlyList<byte[]> Binary(string name) => BinaryAttributes.TryGetValue(name, out var values)
        ? values : [];
}
