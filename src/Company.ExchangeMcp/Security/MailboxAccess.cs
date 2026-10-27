using System.Security.Claims;
using Microsoft.Extensions.Options;
using ModelContextProtocol;

namespace Company.ExchangeMcp.Security;

public sealed record MailboxIdentity(string Subject, string Mailbox, string ClientId = "", string? SessionId = null,
    string TargetId = "own", string? ActorMailbox = null);

public sealed class MailboxAccess(IOptions<ServiceOptions> options, MailboxEnrollment? enrollment = null)
{
    public const string Read = "mail.read";
    public const string Write = "mail.write";
    public const string Manage = "mail.manage";
    public const string Send = "mail.send";
    public static readonly string[] Scopes = [Read, Write, Manage, Send];

    public static bool HasScope(ClaimsPrincipal user, string scope) => user.FindAll("scope")
        .SelectMany(x => x.Value.Split(' ', StringSplitOptions.RemoveEmptyEntries))
        .Contains(scope, StringComparer.Ordinal);

    public MailboxIdentity Require(ClaimsPrincipal user, string scope)
    {
        var actor = RequireOwn(user, scope);
        var selected = selectedTarget.Value;
        return selected is not null && selected.Subject == actor.Subject
            && selected.ClientId == actor.ClientId && selected.SessionId == actor.SessionId
            && string.Equals(selected.ActorMailbox ?? selected.Mailbox, actor.Mailbox, StringComparison.OrdinalIgnoreCase)
            ? selected
            : actor;
    }

    public MailboxIdentity RequireOwn(ClaimsPrincipal user, string scope)
    {
        if (user.Identity?.IsAuthenticated != true || !HasScope(user, scope))
            throw new McpException("This operation requires the appropriate mailbox permission.");
        var subject = user.FindFirst("sub")?.Value;
        if (string.IsNullOrWhiteSpace(subject) || !TryGetOwnMailbox(subject, out var mailbox)
            || !MatchesRegisteredGuid(user, subject))
            throw new McpException("This account is not enrolled for mailbox access.");
        var clientId = user.FindFirst("azp")?.Value;
        if (string.IsNullOrWhiteSpace(clientId) || !options.Value.AllowedClientIds.Contains(clientId, StringComparer.Ordinal))
            throw new McpException("This OAuth client is not approved for mailbox access.");
        if (scope != Read && !options.Value.WritesEnabled)
            throw new McpException("Mailbox changes are disabled by the administrator.");
        if (scope == Send && !options.Value.SendEnabled)
            throw new McpException("Sending is disabled by the administrator.");
        return new(subject, mailbox, clientId, user.FindFirst("sid")?.Value, "own", mailbox);
    }

    public bool IsEnrolled(ClaimsPrincipal user)
    {
        var subject = user.FindFirst("sub")?.Value;
        return user.Identity?.IsAuthenticated == true && !string.IsNullOrWhiteSpace(subject)
            && TryGetOwnMailbox(subject, out _) && MatchesRegisteredGuid(user, subject);
    }

    public IReadOnlyList<(string Subject, string Mailbox)> GetEnrolledActors()
    {
        var actors = options.Value.Mailboxes.Select(entry => (entry.Key, entry.Value)).ToList();
        if (enrollment is { Enabled: true })
            actors.AddRange(enrollment.Snapshot().Where(dynamic => !options.Value.Mailboxes.ContainsKey(dynamic.Subject)));
        return actors.OrderBy(actor => actor.Item1, StringComparer.Ordinal).ToArray();
    }

    public async Task<bool> VerifyCurrentActorAsync(MailboxIdentity identity, CancellationToken cancellationToken)
    {
        var actorMailbox = identity.ActorMailbox ?? identity.Mailbox;
        if (!options.Value.AutoEnrollmentEnabled && options.Value.Mailboxes.TryGetValue(identity.Subject, out var configured))
            return string.Equals(configured, actorMailbox, StringComparison.OrdinalIgnoreCase);
        return enrollment is not null
            && await enrollment.VerifyCurrentAsync(identity.Subject, actorMailbox, cancellationToken).ConfigureAwait(false);
    }

    private bool TryGetOwnMailbox(string subject, out string mailbox)
    {
        if (options.Value.Mailboxes.TryGetValue(subject, out mailbox!)) return true;
        return enrollment is not null && enrollment.TryGet(subject, out mailbox, out _);
    }

    private bool MatchesRegisteredGuid(ClaimsPrincipal user, string subject)
    {
        if (!options.Value.AutoEnrollmentEnabled && options.Value.Mailboxes.ContainsKey(subject)) return true;
        return enrollment is not null && enrollment.TryGet(subject, out _, out var expectedGuid)
            && user.FindAll(MailboxEnrollment.DirectoryGuidClaim).Count() == 1
            && string.Equals(user.FindFirst(MailboxEnrollment.DirectoryGuidClaim)?.Value, expectedGuid, StringComparison.Ordinal);
    }

    public IDisposable SelectTarget(MailboxIdentity target)
    {
        if (string.IsNullOrWhiteSpace(target.ActorMailbox))
            throw new McpException("Exchange mailbox selection is missing its authenticated actor context.");
        var previous = selectedTarget.Value;
        selectedTarget.Value = target;
        return new SelectionScope(() => selectedTarget.Value = previous);
    }

    /// <summary>Returns the immutable per-call identity currently selected by the request filter.</summary>
    public MailboxIdentity? CurrentSelection => selectedTarget.Value;

    private readonly AsyncLocal<MailboxIdentity?> selectedTarget = new();

    private sealed class SelectionScope(Action restore) : IDisposable
    {
        public void Dispose() => restore();
    }

    public void ValidateRecipients(IEnumerable<string> recipients)
    {
        var addresses = recipients.ToArray();
        if (addresses.Length is < 1 or > 100 || addresses.Any(x => !ServiceOptions.IsMailbox(x)))
            throw new McpException("Supply between 1 and 100 plain email addresses.");
        if (!options.Value.AllowExternalRecipients && addresses.Any(x => !options.Value.AllowedRecipientDomains.Contains(
            x[(x.LastIndexOf('@') + 1)..], StringComparer.OrdinalIgnoreCase)))
            throw new McpException("One or more recipient domains are not approved for sending.");
    }
}
