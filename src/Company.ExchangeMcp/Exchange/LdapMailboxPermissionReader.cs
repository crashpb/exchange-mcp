using System.DirectoryServices.Protocols;
using System.Net;
using Company.ExchangeMcp.Security;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Company.ExchangeMcp.Exchange;

public sealed partial class LdapMailboxPermissionReader(
    IOptions<DirectoryPermissionOptions> directoryOptions,
    ILdapSearchFacadeFactory searchFactory,
    ILogger<LdapMailboxPermissionReader> logger,
    IOptions<EwsOptions>? exchangeOptions = null) : IMailboxPermissionReader
{
    private static readonly string[] ActorAttributes = ["objectSid"];
    private static readonly string[] ActorScopeAttributes = ["objectSid", "tokenGroups", "sIDHistory"];
    private static readonly string[] TargetAttributes = [
        "publicDelegates", "msExchMailboxSecurityDescriptor", "nTSecurityDescriptor"];
    private static readonly string[] DelegateAttributes = ["objectSid"];

    public async Task<MailboxPermissionReport> ReadAsync(
        MailboxIdentity identity, CancellationToken cancellationToken)
    {
        var checkedAt = DateTimeOffset.UtcNow;
        var settings = directoryOptions.Value;
        if (!settings.IsConfigured)
            return UnknownReport(checkedAt, "directory permission lookup is not configured");
        if (!settings.IsValid())
            return UnknownReport(checkedAt, "directory permission lookup has invalid server configuration");

        try
        {
            return await Task.Run(() => ReadSynchronously(identity, checkedAt, cancellationToken), cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception) when (exception is not OutOfMemoryException and not StackOverflowException)
        {
            // Directory failures are deliberately fail-closed and contain no directory values in logs.
            logger.LogDebug("Directory permission lookup returned unknown after {ExceptionType}.",
                exception.GetType().Name);
            return UnknownReport(checkedAt, "directory permission lookup failed");
        }
    }

    private MailboxPermissionReport ReadSynchronously(
        MailboxIdentity identity, DateTimeOffset checkedAt, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var actorMailbox = identity.ActorMailbox ?? identity.Mailbox;
        var targetMailbox = identity.Mailbox;
        if (!ServiceOptions.IsMailbox(actorMailbox) || !ServiceOptions.IsMailbox(targetMailbox))
            return UnknownReport(checkedAt, "mailbox identity is invalid");

        using var ldap = searchFactory.Create();
        var actorRows = ldap.Search(
            directoryOptions.Value.BaseDn,
            $"(mail={EscapeFilter(actorMailbox)})",
            SearchScope.Subtree,
            ActorAttributes,
            requestDaclOnly: false,
            cancellationToken);
        if (actorRows.Count != 1 || string.IsNullOrWhiteSpace(actorRows[0].DistinguishedName))
            return UnknownReport(checkedAt, "authenticated actor was not uniquely resolved");

        var actor = actorRows[0];
        var actorSidBytes = SingleSid(actor.Binary("objectSid"));
        if (actorSidBytes is null)
            return UnknownReport(checkedAt, "authenticated actor SID is unavailable");

        cancellationToken.ThrowIfCancellationRequested();
        var actorScopeRows = ldap.Search(
            actor.DistinguishedName,
            "(objectClass=*)",
            SearchScope.Base,
            ActorScopeAttributes,
            requestDaclOnly: false,
            cancellationToken);
        if (actorScopeRows.Count != 1)
            return UnknownReport(checkedAt, "authenticated actor token groups are unavailable");

        var actorScope = actorScopeRows[0];
        var actorSid = DirectoryAclEvaluator.SidKey(actorSidBytes);
        var actorKeys = new HashSet<string>(StringComparer.Ordinal) { actorSid };
        var groupsComplete = actorScope.HasBinary("tokenGroups");
        if (groupsComplete)
            AddSidKeys(actorScope.Binary("tokenGroups"), actorKeys);
        AddSidKeys(actorScope.Binary("sIDHistory"), actorKeys);

        cancellationToken.ThrowIfCancellationRequested();
        IReadOnlyList<LdapSearchEntry> targetRows;
        if (Guid.TryParse(identity.TargetId, out var targetGuid))
        {
            var targetEntry = ResolveTargetForPermission(ldap, targetGuid, cancellationToken);
            if (targetEntry is null || !TryParseMailboxCandidate(targetEntry, out var candidate)
                || !string.Equals(candidate.Mailbox, targetMailbox, StringComparison.OrdinalIgnoreCase))
                return UnknownReport(checkedAt, "target directory mailbox binding could not be verified");
            targetRows = [targetEntry];
        }
        else
        {
            targetRows = ldap.Search(
                directoryOptions.Value.BaseDn,
                $"(mail={EscapeFilter(targetMailbox)})",
                SearchScope.Subtree,
                TargetAttributes,
                requestDaclOnly: true,
                cancellationToken);
        }
        if (targetRows.Count != 1)
            return UnknownReport(checkedAt, "target mailbox was not uniquely resolved");

        var target = targetRows[0];
        var fullAccess = DirectoryAclEvaluator.Evaluate(
            SingleOptionalSid(target.Binary("msExchMailboxSecurityDescriptor")),
            actorSid,
            actorKeys,
            groupsComplete,
            sendAs: false);
        var sendAs = DirectoryAclEvaluator.Evaluate(
            SingleOptionalSid(target.Binary("nTSecurityDescriptor")),
            actorSid,
            actorKeys,
            groupsComplete,
            sendAs: true);
        var sendOnBehalf = ReadSendOnBehalf(
            ldap, target, actor.DistinguishedName, actorSid, actorKeys, groupsComplete, cancellationToken);

        return new(fullAccess, sendAs, sendOnBehalf, checkedAt, "exchange-ldap");
    }

    private PermissionDecision ReadSendOnBehalf(
        ILdapSearchFacade ldap,
        LdapSearchEntry target,
        string actorDn,
        string actorSid,
        IReadOnlySet<string> actorKeys,
        bool groupsComplete,
        CancellationToken cancellationToken)
    {
        if (target.TextAttributes.Keys.Any(name => name.StartsWith("publicDelegates;", StringComparison.OrdinalIgnoreCase)))
            return PermissionDecision.Unknown("Send on Behalf delegate values are incomplete");
        if (!target.HasText("publicDelegates"))
        {
            return CanReadPublicDelegates(ldap, target, cancellationToken)
                ? new("denied", "Send on Behalf attribute is readable and has no delegates")
                : PermissionDecision.Unknown("Send on Behalf directory attribute is unavailable");
        }

        var delegates = target.Text("publicDelegates");
        foreach (var delegateDn in delegates)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (string.Equals(delegateDn, actorDn, StringComparison.OrdinalIgnoreCase))
                return new("allowed", "direct Send on Behalf grant", Direct: true);
            if (string.IsNullOrWhiteSpace(delegateDn))
                return PermissionDecision.Unknown("Send on Behalf delegate is malformed");

            var delegateRows = ldap.Search(delegateDn, "(objectClass=*)", SearchScope.Base, DelegateAttributes,
                requestDaclOnly: false, cancellationToken);
            if (delegateRows.Count != 1)
                return PermissionDecision.Unknown("Send on Behalf delegate could not be resolved");
            var delegateSid = SingleSid(delegateRows[0].Binary("objectSid"));
            if (delegateSid is null)
                return PermissionDecision.Unknown("Send on Behalf delegate SID is unavailable");
            var delegateKey = DirectoryAclEvaluator.SidKey(delegateSid);
            if (actorKeys.Contains(delegateKey))
            {
                var direct = string.Equals(delegateKey, actorSid, StringComparison.Ordinal);
                return new("allowed", direct ? "direct Send on Behalf grant" : "group Send on Behalf grant",
                    Direct: direct, ViaGroup: !direct);
            }
        }

        return groupsComplete
            ? new("denied", "no matching Send on Behalf grant")
            : PermissionDecision.Unknown("directory groups are incomplete");
    }

    private bool CanReadPublicDelegates(ILdapSearchFacade ldap, LdapSearchEntry target,
        CancellationToken cancellationToken)
    {
        var username = exchangeOptions?.Value.Username;
        if (string.IsNullOrWhiteSpace(username) || username.Length > 256 || username.Any(char.IsControl))
            return false;
        var account = username.Contains('\\') ? username[(username.LastIndexOf('\\') + 1)..] : username;
        var rows = ldap.Search(directoryOptions.Value.BaseDn,
            $"(&(objectClass=user)(|(sAMAccountName={EscapeFilter(account)})(userPrincipalName={EscapeFilter(account)})))",
            SearchScope.Subtree, ActorAttributes, requestDaclOnly: false, cancellationToken);
        if (rows.Count != 1 || string.IsNullOrWhiteSpace(rows[0].DistinguishedName)) return false;
        var sidBytes = SingleSid(rows[0].Binary("objectSid"));
        if (sidBytes is null) return false;
        // AD computes tokenGroups only for a base-scope search of the resolved principal.
        var scope = ldap.Search(rows[0].DistinguishedName, "(objectClass=*)", SearchScope.Base,
            ActorScopeAttributes, requestDaclOnly: false, cancellationToken);
        if (scope.Count != 1 || !scope[0].HasBinary("tokenGroups")) return false;
        var currentSid = SingleSid(scope[0].Binary("objectSid"));
        if (currentSid is null || !sidBytes.AsSpan().SequenceEqual(currentSid)) return false;
        var sid = DirectoryAclEvaluator.SidKey(sidBytes);
        var keys = new HashSet<string>(StringComparer.Ordinal) { sid };
        AddSidKeys(scope[0].Binary("tokenGroups"), keys);
        AddSidKeys(scope[0].Binary("sIDHistory"), keys);
        // The Exchange schema places publicDelegates in the Personal Information property set.
        var attribute = new Guid(Convert.FromBase64String("mv/48JER0BGgYACqAGwz7Q=="));
        var propertySet = new Guid(Convert.FromBase64String("hri1d0qU0RGuvQAA+ANnwQ=="));
        return DirectoryAclEvaluator.EvaluatePropertyRead(
            SingleOptionalSid(target.Binary("nTSecurityDescriptor")), sid, keys, true,
            attribute, propertySet).State == "allowed";
    }

    private static byte[]? SingleOptionalSid(IReadOnlyList<byte[]> values) => values.Count switch
    {
        0 => null,
        1 => values[0],
        _ => throw new InvalidDataException("Directory security descriptor attribute has multiple values.")
    };

    private static byte[]? SingleSid(IReadOnlyList<byte[]> values) => values.Count == 1 ? values[0] : null;

    private static void AddSidKeys(IEnumerable<byte[]> values, ISet<string> keys)
    {
        foreach (var value in values)
            keys.Add(DirectoryAclEvaluator.SidKey(value));
    }

    private static string EscapeFilter(string value) => value.Replace("\\", "\\5c", StringComparison.Ordinal)
        .Replace("*", "\\2a", StringComparison.Ordinal)
        .Replace("(", "\\28", StringComparison.Ordinal)
        .Replace(")", "\\29", StringComparison.Ordinal)
        .Replace("\0", "\\00", StringComparison.Ordinal);

    private static MailboxPermissionReport UnknownReport(DateTimeOffset checkedAt, string reason) => new(
        PermissionDecision.Unknown(reason),
        PermissionDecision.Unknown(reason),
        PermissionDecision.Unknown(reason),
        checkedAt,
        "exchange-ldap");
}

public sealed class LdapSearchFacadeFactory(
    IOptions<DirectoryPermissionOptions> directoryOptions,
    IOptions<EwsOptions> exchangeOptions) : ILdapSearchFacadeFactory
{
    public ILdapSearchFacade Create() => new LdapSearchFacade(directoryOptions.Value, exchangeOptions.Value);
}

internal sealed class LdapSearchFacade : ILdapSearchFacade
{
    private const int MaxEntries = 32;
    private const int MaxPageCookieBytes = 16 * 1024;
    private const int MaxValues = 128;
    private const int MaxSecurityDescriptorBytes = 65_536;
    private const int MaxSidBytes = 68;
    private const int MaxTextValueCharacters = 4096;
    private const int MaxDistinguishedNameCharacters = 4096;
    private static readonly HashSet<string> BinaryAttributeNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "objectGUID", "objectSid", "tokenGroups", "sIDHistory", "msExchMailboxSecurityDescriptor", "nTSecurityDescriptor"
    };
    private readonly LdapConnection connection;

    public LdapSearchFacade(DirectoryPermissionOptions directory, EwsOptions exchange)
    {
        if (!directory.IsConfigured || !directory.IsValid())
            throw new InvalidOperationException("Invalid directory permission settings.");
        var password = File.ReadAllText(exchange.PasswordFile).TrimEnd('\r', '\n');
        if (string.IsNullOrEmpty(password) || password.Length > 8192)
            throw new InvalidOperationException("Invalid Exchange credential file.");

        connection = Connect(directory, exchange, password);
        password = string.Empty;
    }

    private static LdapConnection Connect(
        DirectoryPermissionOptions directory, EwsOptions exchange, string password)
    {
        var connection = new LdapConnection(new LdapDirectoryIdentifier(
            directory.Host, directory.Port, fullyQualifiedDnsHostName: true, connectionless: false));
        try
        {
            connection.AuthType = AuthType.Basic;
            connection.Credential = new NetworkCredential(
                string.IsNullOrWhiteSpace(exchange.Domain) ? exchange.Username : $"{exchange.Domain}\\{exchange.Username}",
                password);
            connection.Timeout = TimeSpan.FromSeconds(directory.TimeoutSeconds);
            connection.SessionOptions.ProtocolVersion = 3;
            connection.SessionOptions.SecureSocketLayer = true;
            connection.SessionOptions.ReferralChasing = ReferralChasingOptions.None;
            // OpenLDAP performs native chain and hostname validation; never install an accept-all callback.
            if (OperatingSystem.IsLinux())
            {
                connection.SessionOptions.TrustedCertificatesDirectory = "/etc/ssl/certs";
                connection.SessionOptions.StartNewTlsSessionContext();
            }
            connection.Bind();
            return connection;
        }
        catch
        {
            connection.Dispose();
            throw;
        }
    }

    public IReadOnlyList<LdapSearchEntry> Search(
        string baseDn,
        string filter,
        SearchScope scope,
        IReadOnlyList<string> attributes,
        bool requestDaclOnly,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var request = new SearchRequest(baseDn, filter, scope, attributes.ToArray())
        {
            SizeLimit = MaxEntries,
            TimeLimit = connection.Timeout
        };
        if (requestDaclOnly)
        {
            var control = new SecurityDescriptorFlagControl(SecurityMasks.Dacl)
            {
                IsCritical = true,
                ServerSide = true
            };
            request.Controls.Add(control);
        }
        var response = (SearchResponse)connection.SendRequest(request, connection.Timeout);
        if (response.Entries.Count > MaxEntries)
            throw new InvalidDataException("Directory search exceeded its result limit.");
        return response.Entries.Cast<SearchResultEntry>().Select(ReadEntry).ToArray();
    }

    public LdapSearchPage SearchPage(
        string baseDn,
        string filter,
        SearchScope scope,
        IReadOnlyList<string> attributes,
        bool requestDaclOnly,
        byte[] cookie,
        int pageSize,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (pageSize is < 1 or > MaxEntries)
            throw new ArgumentOutOfRangeException(nameof(pageSize));
        if (cookie is null || cookie.Length > MaxPageCookieBytes)
            throw new InvalidDataException("Directory paging cookie exceeded its size limit.");
        var request = new SearchRequest(baseDn, filter, scope, attributes.ToArray())
        {
            SizeLimit = MaxEntries,
            TimeLimit = connection.Timeout
        };
        request.Controls.Add(new PageResultRequestControl(pageSize) { Cookie = cookie.ToArray() });
        if (requestDaclOnly)
        {
            var control = new SecurityDescriptorFlagControl(SecurityMasks.Dacl)
            {
                IsCritical = true,
                ServerSide = true
            };
            request.Controls.Add(control);
        }
        var response = (SearchResponse)connection.SendRequest(request, connection.Timeout);
        cancellationToken.ThrowIfCancellationRequested();
        if (response.Entries.Count > pageSize)
            throw new InvalidDataException("Directory search exceeded its page limit.");
        var controls = response.Controls.OfType<PageResultResponseControl>().ToArray();
        if (controls.Length != 1 || controls[0].Cookie.Length > MaxPageCookieBytes)
            throw new InvalidDataException("Directory paging returned an invalid cookie.");
        return new(response.Entries.Cast<SearchResultEntry>().Select(ReadEntry).ToArray(), controls[0].Cookie.ToArray());
    }

    public void Dispose() => connection.Dispose();

    private static LdapSearchEntry ReadEntry(SearchResultEntry entry)
    {
        var text = new Dictionary<string, IReadOnlyList<string>>(StringComparer.OrdinalIgnoreCase);
        var binary = new Dictionary<string, IReadOnlyList<byte[]>>(StringComparer.OrdinalIgnoreCase);
        foreach (DirectoryAttribute attribute in entry.Attributes.Values)
        {
            if (BinaryAttributeNames.Contains(attribute.Name))
            {
                var values = attribute.GetValues(typeof(byte[])).OfType<byte[]>().ToArray();
                if (attribute.Name.Equals("objectGUID", StringComparison.OrdinalIgnoreCase)
                    && (values.Length != 1 || values[0].Length != 16))
                    throw new InvalidDataException("Directory object GUID must be one 16-byte value.");
                var maximum = attribute.Name.Equals("msExchMailboxSecurityDescriptor", StringComparison.OrdinalIgnoreCase)
                    || attribute.Name.Equals("nTSecurityDescriptor", StringComparison.OrdinalIgnoreCase)
                    ? MaxSecurityDescriptorBytes : MaxSidBytes;
                if (values.Length > MaxValues || values.Any(value => value.Length > maximum))
                    throw new InvalidDataException("Directory binary attribute exceeded its value limit.");
                binary[attribute.Name] = values.Select(value => value.ToArray()).ToArray();
                continue;
            }

            var strings = attribute.GetValues(typeof(string)).OfType<string>().Take(MaxValues + 1).ToArray();
            if (strings.Length > MaxValues || strings.Any(value => value.Length > MaxTextValueCharacters
                || value.Any(char.IsControl)))
                throw new InvalidDataException("Directory text attribute exceeded its value limit.");
            text[attribute.Name] = strings;
        }
        if (entry.DistinguishedName.Length is 0 or > MaxDistinguishedNameCharacters
            || entry.DistinguishedName.Any(char.IsControl))
            throw new InvalidDataException("Directory distinguished name exceeded its value limit.");
        return new(entry.DistinguishedName, text, binary);
    }
}
