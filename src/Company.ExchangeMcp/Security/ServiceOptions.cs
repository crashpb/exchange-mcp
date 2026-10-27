using System.Net.Mail;

namespace Company.ExchangeMcp.Security;

public sealed class ServiceOptions
{
    public string Authority { get; set; } = "";
    public string Resource { get; set; } = "";
    public string PublicResource { get; set; } = "";
    public string[] Resources => string.IsNullOrEmpty(PublicResource) ? [Resource] : [Resource, PublicResource];
    public string IntrospectionClientId { get; set; } = "";
    public string IntrospectionSecretFile { get; set; } = "";
    public string[] AllowedClientIds { get; set; } = [];
    public string[] AllowedOrigins { get; set; } = [];
    public string[] TrustedProxyAddresses { get; set; } = [];
    public Dictionary<string, string> Mailboxes { get; set; } = new(StringComparer.Ordinal);
    // Accepted only so old protected stack files can be read during rollout; authorization never uses it.
    public Dictionary<string, Dictionary<string, string>> MailboxTargets { get; set; } = new(StringComparer.Ordinal);
    public bool AutoEnrollmentEnabled { get; set; }
    public bool TaskNoticeProcessingAllEnrolledUsers { get; set; }
    public string[] TaskNoticeProcessingActors { get; set; } = [];
    public bool WritesEnabled { get; set; }
    public bool SendEnabled { get; set; }
    public string SendWithoutNativeConfirmationActor { get; set; } = "";
    public string[] SendWithoutNativeConfirmationMailboxes { get; set; } = [];
    public string[] SendWithoutNativeConfirmationClientIds { get; set; } = [];
    public bool AllowExternalRecipients { get; set; }
    public string[] AllowedRecipientDomains { get; set; } = [];
    public string AuditPath { get; set; } = "";
    public int RequestsPerMinute { get; set; } = 60;
    public int ConcurrentRequests { get; set; } = 8;
    public int ConcurrentRequestsPerUser { get; set; } = 2;
    public int TransportRequestsPerMinute { get; set; } = 600;
    public int ConcurrentTransports { get; set; } = 64;

    public static bool IsHttpsUrl(string value) => Uri.TryCreate(value, UriKind.Absolute, out var uri)
        && uri.Scheme == Uri.UriSchemeHttps && string.IsNullOrEmpty(uri.UserInfo)
        && string.IsNullOrEmpty(uri.Query) && string.IsNullOrEmpty(uri.Fragment);

    public static bool IsMailbox(string value) => !string.IsNullOrWhiteSpace(value)
        && MailAddress.TryCreate(value, out var address)
        && string.Equals(address.Address, value, StringComparison.OrdinalIgnoreCase)
        && !value.Contains('\r') && !value.Contains('\n');

    public string? ResourceForHost(string? host) => Resources.FirstOrDefault(value =>
        string.Equals(new Uri(value).Authority, host, StringComparison.OrdinalIgnoreCase));

    public bool IsValid() => IsHttpsUrl(Authority) && IsHttpsUrl(Resource)
        && (string.IsNullOrEmpty(PublicResource) || IsHttpsUrl(PublicResource)
            && new Uri(PublicResource).AbsolutePath == new Uri(Resource).AbsolutePath
            && !string.Equals(new Uri(PublicResource).Authority, new Uri(Resource).Authority, StringComparison.OrdinalIgnoreCase))
        && !string.IsNullOrWhiteSpace(IntrospectionClientId)
        && !string.IsNullOrWhiteSpace(IntrospectionSecretFile)
        && File.Exists(IntrospectionSecretFile)
        && new FileInfo(IntrospectionSecretFile).Length is >= 1 and <= 8192
        && AllowedClientIds.Length > 0 && AllowedClientIds.All(x => !string.IsNullOrWhiteSpace(x))
        && AllowedOrigins.All(IsHttpsUrl)
        && TrustedProxyAddresses.All(x => System.Net.IPAddress.TryParse(x, out _))
        && Mailboxes is not null && (Mailboxes.Count > 0 || AutoEnrollmentEnabled)
        && Mailboxes.All(x => !string.IsNullOrWhiteSpace(x.Key) && IsMailbox(x.Value))
        && TaskNoticeProcessingActors is not null && TaskNoticeProcessingActors.Length <= 16
        && TaskNoticeProcessingActors.All(IsMailbox)
        && TaskNoticeProcessingActors.Distinct(StringComparer.OrdinalIgnoreCase).Count() == TaskNoticeProcessingActors.Length
        && TaskNoticeProcessingActors.All(actor => Mailboxes.Values.Count(mailbox =>
            string.Equals(mailbox, actor, StringComparison.OrdinalIgnoreCase)) == 1)
        && IsSendWithoutNativeConfirmationValid()
        && RequestsPerMinute is >= 1 and <= 1000 && ConcurrentRequests is >= 1 and <= 64
        && ConcurrentRequestsPerUser is >= 1 and <= 8
        && TransportRequestsPerMinute is >= 1 and <= 10000
        && ConcurrentTransports is >= 1 and <= 256
        && !string.IsNullOrWhiteSpace(AuditPath)
        && AllowedRecipientDomains is not null
        && AllowedRecipientDomains.All(x => Uri.CheckHostName(x) == UriHostNameType.Dns)
        && (!AutoEnrollmentEnabled || AllowedRecipientDomains.Length > 0)
        && (!SendEnabled || WritesEnabled && (AllowExternalRecipients || AllowedRecipientDomains.Length > 0));

    private bool IsSendWithoutNativeConfirmationValid() =>
        SendWithoutNativeConfirmationMailboxes is not null && SendWithoutNativeConfirmationClientIds is not null
        && (string.IsNullOrEmpty(SendWithoutNativeConfirmationActor)
            && SendWithoutNativeConfirmationMailboxes.Length == 0 && SendWithoutNativeConfirmationClientIds.Length == 0
            || AutoEnrollmentEnabled && IsMailbox(SendWithoutNativeConfirmationActor)
            && Mailboxes.Values.Count(mailbox => string.Equals(mailbox, SendWithoutNativeConfirmationActor,
                StringComparison.OrdinalIgnoreCase)) == 1
            && SendWithoutNativeConfirmationMailboxes.Length == 2
            && SendWithoutNativeConfirmationMailboxes.All(IsMailbox)
            && SendWithoutNativeConfirmationMailboxes.Distinct(StringComparer.OrdinalIgnoreCase).Count() == 2
            && SendWithoutNativeConfirmationMailboxes.Contains(SendWithoutNativeConfirmationActor, StringComparer.OrdinalIgnoreCase)
            && SendWithoutNativeConfirmationClientIds.Length is >= 1 and <= 2
            && SendWithoutNativeConfirmationClientIds.All(client => AllowedClientIds.Contains(client, StringComparer.Ordinal))
            && SendWithoutNativeConfirmationClientIds.Distinct(StringComparer.Ordinal).Count() == SendWithoutNativeConfirmationClientIds.Length);
}
