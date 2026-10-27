using System.Buffers.Binary;
using System.DirectoryServices.Protocols;
using Company.ExchangeMcp.Exchange;
using Company.ExchangeMcp.Security;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

internal sealed partial class Checks
{
    internal async Task DirectoryPermissionReaderChecksAsync()
    {
        await AssertReaderResolvesActorTargetAndGroupsAsync();
        await AssertReaderFailsClosedForIncompleteEvidenceAsync();
        await AssertReaderFailsClosedForMalformedAndDuplicateEvidenceAsync();
        await AssertReaderHonorsFailureAndCancellationAsync();
    }

    private static async Task AssertReaderResolvesActorTargetAndGroupsAsync()
    {
        const string actorMailbox = "\"actor*\"@example.test";
        const string targetMailbox = "\"target*\"@example.test";
        const string actorDn = "CN=Actor,DC=example,DC=test";
        const string targetDn = "CN=Target,DC=example,DC=test";
        const string delegateDn = "CN=Mailbox Delegates,DC=example,DC=test";
        const string actorSid = "S-1-5-21-111-222-333-1101";
        const string groupSid = "S-1-5-21-111-222-333-2201";
        const string historySid = "S-1-5-21-111-222-333-3301";

        var factory = new RecordingLdapFactory([
            [Entry(actorDn, binary: Binary("objectSid", ReaderSidBytes(actorSid)))],
            [Entry(actorDn, binary: Binary("objectSid", ReaderSidBytes(actorSid),
                "tokenGroups", ReaderSidBytes(groupSid), "sIDHistory", ReaderSidBytes(historySid)))],
            [Entry(targetDn,
                text: Text("publicDelegates", delegateDn),
                binary: Binary("msExchMailboxSecurityDescriptor", Descriptor(
                    StandardAce(historySid, allow: true, mask: 1)),
                    "nTSecurityDescriptor", Descriptor(
                        StandardAce(groupSid, allow: true, mask: 0x100))))],
            [Entry(delegateDn, binary: Binary("objectSid", ReaderSidBytes(groupSid)))]]);
        var reader = NewReader(factory);
        var report = await reader.ReadAsync(
            new MailboxIdentity("subject", targetMailbox, "client", TargetId: "target", ActorMailbox: actorMailbox),
            CancellationToken.None);

        Expect(report.FullAccess.State == "allowed" && !report.FullAccess.Direct && report.FullAccess.ViaGroup,
            "The LDAP reader did not resolve a Full Access grant through SID history.");
        Expect(report.SendAs.State == "allowed" && report.SendAs.ViaGroup,
            "The LDAP reader did not resolve a group Send As grant.");
        Expect(report.SendOnBehalf.State == "allowed" && report.SendOnBehalf.ViaGroup,
            "The LDAP reader did not resolve a group Send on Behalf grant.");
        Expect(factory.Records.Count == 4, "The reader performed an unexpected number of LDAP searches.");
        Expect(factory.Records[0].Scope == SearchScope.Subtree
            && factory.Records[0].Filter.Contains("\\2a", StringComparison.Ordinal),
            "The actor mailbox filter was not safely escaped.");
        Expect(factory.Records[1].Scope == SearchScope.Base
            && factory.Records[2].Scope == SearchScope.Subtree
            && factory.Records[2].RequestDaclOnly
            && factory.Records[2].Attributes.Contains("msExchMailboxSecurityDescriptor", StringComparer.OrdinalIgnoreCase)
            && factory.Records[2].Attributes.Contains("nTSecurityDescriptor", StringComparer.OrdinalIgnoreCase),
            "The reader did not isolate actor scope, target scope, and DACL-only target reads.");
        Expect(factory.Records.All(x => x.BaseDn != actorMailbox && x.BaseDn != targetMailbox),
            "The reader used a caller mailbox address as an LDAP base DN.");
    }

    private static async Task AssertReaderFailsClosedForIncompleteEvidenceAsync()
    {
        const string actorDn = "CN=Actor,DC=example,DC=test";
        const string targetDn = "CN=Target,DC=example,DC=test";
        const string delegateDn = "CN=Delegates,DC=example,DC=test";
        const string actorSid = "S-1-5-21-111-222-333-1101";
        const string groupSid = "S-1-5-21-111-222-333-2201";
        var factory = new RecordingLdapFactory([
            [Entry(actorDn, binary: Binary("objectSid", ReaderSidBytes(actorSid)))],
            [Entry(actorDn, binary: Binary("objectSid", ReaderSidBytes(actorSid),
                "tokenGroups;range=0-1499", ReaderSidBytes(groupSid)))],
            [Entry(targetDn,
                text: Text("publicDelegates", delegateDn),
                binary: Binary("msExchMailboxSecurityDescriptor", Descriptor(
                    StandardAce(actorSid, allow: true, mask: 1)),
                    "nTSecurityDescriptor", Descriptor(
                        StandardAce(groupSid, allow: true, mask: 0x100))))],
            [Entry(delegateDn, binary: Binary("objectSid", ReaderSidBytes(groupSid)))]]);
        var report = await NewReader(factory).ReadAsync(
            new MailboxIdentity("subject", "target@example.test", "client", TargetId: "target", ActorMailbox: "actor@example.test"),
            CancellationToken.None);

        Expect(report.FullAccess.State == "unknown" && report.SendAs.State == "unknown"
            && report.SendOnBehalf.State == "unknown",
            "Incomplete ranged tokenGroups evidence was converted into a grant or denial.");
    }

    private static async Task AssertReaderFailsClosedForMalformedAndDuplicateEvidenceAsync()
    {
        var duplicateFactory = new RecordingLdapFactory([
            [Entry("CN=Actor,DC=example,DC=test", binary: Binary("objectSid", ReaderSidBytes("S-1-5-21-1-2-3-4")))],
            [Entry("CN=Actor,DC=example,DC=test", binary: Binary("objectSid", ReaderSidBytes("S-1-5-21-1-2-3-4"),
                "tokenGroups", ReaderSidBytes("S-1-5-21-1-2-3-5")))],
            [Entry("CN=Target-1,DC=example,DC=test"), Entry("CN=Target-2,DC=example,DC=test")]]);
        var duplicate = await NewReader(duplicateFactory).ReadAsync(
            new MailboxIdentity("subject", "target@example.test", "client", TargetId: "target", ActorMailbox: "actor@example.test"),
            CancellationToken.None);
        Expect(Unknown(duplicate), "Duplicate target resolution did not fail closed.");

        var missingFactory = new RecordingLdapFactory([
            [Entry("CN=Actor,DC=example,DC=test", binary: Binary("objectSid", ReaderSidBytes("S-1-5-21-1-2-3-4")))],
            [Entry("CN=Actor,DC=example,DC=test", binary: Binary("objectSid", ReaderSidBytes("S-1-5-21-1-2-3-4"),
                "tokenGroups", ReaderSidBytes("S-1-5-21-1-2-3-5")))],
            [Entry("CN=Target,DC=example,DC=test")]]);
        var missing = await NewReader(missingFactory).ReadAsync(
            new MailboxIdentity("subject", "target@example.test", "client", TargetId: "target", ActorMailbox: "actor@example.test"),
            CancellationToken.None);
        Expect(Unknown(missing), "Missing target permission attributes did not fail closed.");

        var malformedFactory = new RecordingLdapFactory([
            [Entry("CN=Actor,DC=example,DC=test", binary: Binary("objectSid", new byte[] { 1, 1, 0 }))]]);
        var malformed = await NewReader(malformedFactory).ReadAsync(
            new MailboxIdentity("subject", "target@example.test", "client", TargetId: "target", ActorMailbox: "actor@example.test"),
            CancellationToken.None);
        Expect(Unknown(malformed), "Malformed actor SID evidence did not fail closed.");
    }

    private static async Task AssertReaderHonorsFailureAndCancellationAsync()
    {
        var failing = new RecordingLdapFactory([], throwOnCreate: true);
        var failed = await NewReader(failing).ReadAsync(
            new MailboxIdentity("subject", "target@example.test", "client", TargetId: "target", ActorMailbox: "actor@example.test"),
            CancellationToken.None);
        Expect(Unknown(failed) && !failed.Source.Contains("target@example.test", StringComparison.Ordinal),
            "LDAP transport failure leaked a mailbox or produced a permissive result.");

        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        var cancelled = false;
        try
        {
            await NewReader(new RecordingLdapFactory([])).ReadAsync(
                new MailboxIdentity("subject", "target@example.test", "client", TargetId: "target", ActorMailbox: "actor@example.test"),
                cancellation.Token);
        }
        catch (OperationCanceledException)
        {
            cancelled = true;
        }
        Expect(cancelled, "A cancelled LDAP permission read was not cancelled.");
    }

    private static LdapMailboxPermissionReader NewReader(RecordingLdapFactory factory) => new(
        Options.Create(new DirectoryPermissionOptions
        {
            Host = "ldap.example.test",
            Port = 636,
            BaseDn = "DC=example,DC=test",
            TimeoutSeconds = 8
        }),
        factory,
        NullLogger<LdapMailboxPermissionReader>.Instance);

    private static bool Unknown(MailboxPermissionReport report) =>
        report.FullAccess.State == "unknown"
        && report.SendAs.State == "unknown"
        && report.SendOnBehalf.State == "unknown";

    private static LdapSearchEntry Entry(
        string dn,
        Dictionary<string, IReadOnlyList<string>>? text = null,
        Dictionary<string, IReadOnlyList<byte[]>>? binary = null) =>
        new(dn, text ?? new(StringComparer.OrdinalIgnoreCase), binary ?? new(StringComparer.OrdinalIgnoreCase));

    private static Dictionary<string, IReadOnlyList<string>> Text(string name, params string[] values) =>
        new(StringComparer.OrdinalIgnoreCase) { [name] = values };

    private static Dictionary<string, IReadOnlyList<byte[]>> Binary(params object[] values)
    {
        var result = new Dictionary<string, IReadOnlyList<byte[]>>(StringComparer.OrdinalIgnoreCase);
        for (var i = 0; i < values.Length; i += 2)
            result[(string)values[i]] = [(byte[])values[i + 1]];
        return result;
    }

    private static byte[] Descriptor(byte[] ace)
    {
        var descriptor = new byte[20 + 8 + ace.Length];
        descriptor[0] = 1;
        BinaryPrimitives.WriteUInt16LittleEndian(descriptor.AsSpan(2, 2), 0x8004);
        BinaryPrimitives.WriteUInt32LittleEndian(descriptor.AsSpan(16, 4), 20);
        descriptor[20] = 4;
        BinaryPrimitives.WriteUInt16LittleEndian(descriptor.AsSpan(22, 2), checked((ushort)(8 + ace.Length)));
        BinaryPrimitives.WriteUInt16LittleEndian(descriptor.AsSpan(24, 2), 1);
        ace.AsSpan().CopyTo(descriptor.AsSpan(28));
        return descriptor;
    }

    private static byte[] StandardAce(string sid, bool allow, uint mask)
    {
        var bytes = ReaderSidBytes(sid);
        var ace = new byte[8 + bytes.Length];
        ace[0] = allow ? (byte)0 : (byte)1;
        BinaryPrimitives.WriteUInt16LittleEndian(ace.AsSpan(2, 2), checked((ushort)ace.Length));
        BinaryPrimitives.WriteUInt32LittleEndian(ace.AsSpan(4, 4), mask);
        bytes.AsSpan().CopyTo(ace.AsSpan(8));
        return ace;
    }

    private static byte[] ReaderSidBytes(string sid)
    {
        var parts = sid.Split('-');
        var result = new byte[8 + ((parts.Length - 3) * 4)];
        result[0] = 1;
        result[1] = checked((byte)(parts.Length - 3));
        var authority = ulong.Parse(parts[2], System.Globalization.CultureInfo.InvariantCulture);
        for (var i = 0; i < 6; i++)
            result[2 + i] = (byte)(authority >> (40 - (i * 8)));
        for (var i = 3; i < parts.Length; i++)
            BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(8 + ((i - 3) * 4), 4),
                uint.Parse(parts[i], System.Globalization.CultureInfo.InvariantCulture));
        return result;
    }

}

public static class DirectoryPermissionReaderChecks
{
    public static async Task<int> LiveDirectoryProbeAsync(
        string configPath, string actorMailbox, string targetMailbox, string hostOverride)
    {
        try
        {
            var fullPath = Path.GetFullPath(configPath);
            var configuration = new ConfigurationBuilder()
                .SetBasePath(Path.GetDirectoryName(fullPath) ?? AppContext.BaseDirectory)
                .AddJsonFile(Path.GetFileName(fullPath), optional: false, reloadOnChange: false)
                .AddEnvironmentVariables()
                .Build();
            var directory = configuration.GetSection("DirectoryPermissions").Get<DirectoryPermissionOptions>() ?? new();
            if (!string.IsNullOrWhiteSpace(hostOverride))
                directory.Host = hostOverride;
            var exchange = configuration.GetSection("Exchange").Get<EwsOptions>() ?? new();
            var factory = new LdapSearchFacadeFactory(Options.Create(directory), Options.Create(exchange));
            var reader = new LdapMailboxPermissionReader(
                Options.Create(directory), factory, NullLogger<LdapMailboxPermissionReader>.Instance);
            var report = await reader.ReadAsync(new MailboxIdentity(
                "live-directory-probe", targetMailbox, "live-directory-probe",
                TargetId: "probe", ActorMailbox: actorMailbox), CancellationToken.None);
            PrintDecision("FullAccess", report.FullAccess);
            PrintDecision("SendAs", report.SendAs);
            PrintDecision("SendOnBehalf", report.SendOnBehalf);
            return new[] { report.FullAccess, report.SendAs, report.SendOnBehalf }
                .All(x => x.State is "allowed" or "denied") ? 0 : 1;
        }
        catch (OperationCanceledException)
        {
            PrintUnknown("live directory probe cancelled");
            return 1;
        }
        catch (Exception)
        {
            PrintUnknown("live directory probe failed");
            return 1;
        }
    }

    private static void PrintDecision(string name, PermissionDecision decision)
    {
        var state = decision.State is "allowed" or "denied" or "unknown" ? decision.State : "unknown";
        var reason = SanitizeReason(decision.Reason);
        Console.WriteLine($"{name}: {state}; {reason}");
    }

    private static void PrintUnknown(string reason)
    {
        PrintDecision("FullAccess", PermissionDecision.Unknown(reason));
        PrintDecision("SendAs", PermissionDecision.Unknown(reason));
        PrintDecision("SendOnBehalf", PermissionDecision.Unknown(reason));
    }

    private static string SanitizeReason(string? reason)
    {
        if (string.IsNullOrWhiteSpace(reason) || reason.Any(char.IsControl))
            return "unspecified";
        return reason.Length <= 256 ? reason : reason[..256];
    }
}

internal sealed class RecordingLdapFactory : ILdapSearchFacadeFactory
{
    private readonly IReadOnlyList<IReadOnlyList<LdapSearchEntry>> responses;
    private readonly bool throwOnCreate;
    private readonly List<LdapSearchRequest> records = [];
    private int responseIndex;

    public RecordingLdapFactory(
        IReadOnlyList<IReadOnlyList<LdapSearchEntry>> responses,
        bool throwOnCreate = false)
    {
        this.responses = responses;
        this.throwOnCreate = throwOnCreate;
    }

    public IReadOnlyList<LdapSearchRequest> Records => records;

    public ILdapSearchFacade Create()
    {
        if (throwOnCreate)
            throw new InvalidOperationException("synthetic LDAP failure");
        return new RecordingLdapFacade(this);
    }

    private sealed class RecordingLdapFacade(RecordingLdapFactory owner) : ILdapSearchFacade
    {
        public IReadOnlyList<LdapSearchEntry> Search(
            string baseDn,
            string filter,
            SearchScope scope,
            IReadOnlyList<string> attributes,
            bool requestDaclOnly,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            owner.records.Add(new(baseDn, filter, scope, attributes.ToArray(), requestDaclOnly));
            return owner.responseIndex < owner.responses.Count
                ? owner.responses[owner.responseIndex++]
                : [];
        }

        public void Dispose()
        {
        }
    }
}

internal sealed record LdapSearchRequest(
    string BaseDn,
    string Filter,
    SearchScope Scope,
    IReadOnlyList<string> Attributes,
    bool RequestDaclOnly);
