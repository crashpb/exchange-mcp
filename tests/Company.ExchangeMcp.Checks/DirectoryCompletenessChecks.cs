using Company.ExchangeMcp.Exchange;
using Company.ExchangeMcp.Security;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

internal sealed partial class Checks
{
    private async Task DirectoryCompletenessChecksAsync()
    {
        const string actorSid = "S-1-5-21-111-222-333-1101";
        const string serviceSid = "S-1-5-21-111-222-333-4401";
        var attribute = new Guid(Convert.FromBase64String("mv/48JER0BGgYACqAGwz7Q=="));
        var propertySet = new Guid(Convert.FromBase64String("hri1d0qU0RGuvQAA+ANnwQ=="));
        var serviceKey = SidKey(serviceSid);
        var keys = new HashSet<string>(StringComparer.Ordinal) { serviceKey };
        ExpectState(DirectoryAclEvaluator.EvaluatePropertyRead(
            Descriptor([StandardAce(serviceSid, true, 0x80000000)]),
            serviceKey, keys, true, attribute, propertySet), "allowed", "generic read proves attribute readability");
        ExpectState(DirectoryAclEvaluator.EvaluatePropertyRead(
            Descriptor([ObjectAce(serviceSid, true, 0x10, objectType: propertySet)]),
            serviceKey, keys, true, attribute, propertySet), "allowed", "property-set read");
        ExpectState(DirectoryAclEvaluator.EvaluatePropertyRead(
            Descriptor([ObjectAce(serviceSid, false, 0x10, objectType: attribute),
                StandardAce(serviceSid, true, 0x80000000)]),
            serviceKey, keys, true, attribute, propertySet), "denied", "attribute deny before generic read");
        ExpectState(DirectoryAclEvaluator.EvaluatePropertyRead(
            Descriptor([ObjectAce(serviceSid, true, 0x10, objectType: Guid.NewGuid())]),
            serviceKey, keys, true, attribute, propertySet), "denied", "unrelated attribute read");
        ExpectState(DirectoryAclEvaluator.EvaluatePropertyRead(
            Descriptor([StandardAce(serviceSid, true, 0x80000000)]),
            serviceKey, keys, false, attribute, propertySet), "unknown", "incomplete service groups");
        ExpectState(DirectoryAclEvaluator.Evaluate(
            Descriptor([StandardAce(actorSid, true, 0x80000000)]), SidKey(actorSid),
            new HashSet<string>(), true, true), "denied", "generic read cannot grant Send As");

        foreach (var readable in new[] { true, false })
        {
            var actor = Entry("CN=Actor,DC=example,DC=test", binary: Binary("objectSid", ReaderSidBytes(actorSid)));
            var actorScope = Entry(actor.DistinguishedName, binary: Binary("objectSid", ReaderSidBytes(actorSid),
                "tokenGroups", ReaderSidBytes("S-1-5-11")));
            var target = Entry("CN=Target,DC=example,DC=test", binary: Binary(
                "msExchMailboxSecurityDescriptor", Descriptor([]),
                "nTSecurityDescriptor", Descriptor([ObjectAce(serviceSid, readable, 0x10, objectType: attribute)])));
            var service = Entry("CN=Service,DC=example,DC=test", binary: Binary("objectSid", ReaderSidBytes(serviceSid),
                "tokenGroups", ReaderSidBytes("S-1-5-11")));
            var factory = new RecordingLdapFactory([[actor], [actorScope], [target], [service], [service]]);
            var reader = new LdapMailboxPermissionReader(Options.Create(new DirectoryPermissionOptions
            {
                Host = "ldap.example.test",
                BaseDn = "DC=example,DC=test"
            }), factory, NullLogger<LdapMailboxPermissionReader>.Instance,
                Options.Create(new EwsOptions { Username = "svc_exchange_mcp" }));
            var report = await reader.ReadAsync(new MailboxIdentity("actor", "target@example.test", "client",
                TargetId: "probe", ActorMailbox: "actor@example.test"), CancellationToken.None);
            Expect(report.SendOnBehalf.State == (readable ? "denied" : "unknown"),
                "An omitted delegation attribute was treated as empty without proving property read access.");
            Expect(factory.Records.Count == 5 && factory.Records[^2].Filter.Contains("sAMAccountName=svc_exchange_mcp", StringComparison.Ordinal)
                && factory.Records[^1].Scope == System.DirectoryServices.Protocols.SearchScope.Base
                && factory.Records[^1].BaseDn == service.DistinguishedName,
                "Missing-attribute evidence was not checked for the bound service identity.");
        }
    }
}
