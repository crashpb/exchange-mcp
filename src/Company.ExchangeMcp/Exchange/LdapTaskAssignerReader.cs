using System.DirectoryServices.Protocols;
using Company.ExchangeMcp.Security;

namespace Company.ExchangeMcp.Exchange;

public sealed partial class LdapMailboxPermissionReader
{
    public Task<TaskAssignerEntry> ResolveTaskAssignerAsync(string mailbox, CancellationToken cancellationToken)
    {
        if (!ServiceOptions.IsMailbox(mailbox) || !directoryOptions.Value.IsConfigured || !directoryOptions.Value.IsValid())
            throw new InvalidOperationException("The task assigner cannot be uniquely resolved through the configured directory.");
        return Task.Run(() =>
        {
            using var ldap = searchFactory.Create();
            var rows = ldap.Search(directoryOptions.Value.BaseDn,
                $"(&(objectClass=user)(mail={EscapeFilter(mailbox)}))", SearchScope.Subtree,
                ["legacyExchangeDN", "displayName"], requestDaclOnly: false, cancellationToken);
            if (rows.Count != 1 || rows[0].Text("legacyExchangeDN").Count != 1)
                throw new InvalidOperationException("The task assigner has no unique Exchange directory identity.");
            var displayNames = rows[0].Text("displayName");
            var entry = new TaskAssignerEntry(rows[0].Text("legacyExchangeDN")[0],
                displayNames.Count == 1 && displayNames[0].All(value => value is >= ' ' and <= '~')
                    ? displayNames[0] : mailbox);
            _ = TaskAssignerStack.Encode([entry]);
            return entry;
        }, cancellationToken);
    }
}
