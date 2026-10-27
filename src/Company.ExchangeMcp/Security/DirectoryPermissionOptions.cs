namespace Company.ExchangeMcp.Security;

/// <summary>Server-side directory lookup settings. An empty section disables the reader.</summary>
public sealed class DirectoryPermissionOptions
{
    public string Host { get; set; } = string.Empty;

    public int Port { get; set; } = 636;

    public string BaseDn { get; set; } = string.Empty;

    public int TimeoutSeconds { get; set; } = 8;

    public bool IsConfigured => !string.IsNullOrWhiteSpace(Host)
        || !string.IsNullOrWhiteSpace(BaseDn);

    public bool IsValid()
    {
        if (!IsConfigured)
            return string.IsNullOrWhiteSpace(Host) && string.IsNullOrWhiteSpace(BaseDn)
                && Port == 636 && TimeoutSeconds == 8;

        var host = Host.Trim();
        var validHost = host.Length is > 0 and <= 253
            && !host.Contains('/') && !host.Contains('\\') && !host.Contains(':')
            && !host.Any(char.IsControl)
            && Uri.CheckHostName(host) is UriHostNameType.Dns;
        var validBase = BaseDn.Trim() is { Length: > 0 and <= 1024 } baseDn
            && !baseDn.Any(char.IsControl);
        return validHost && validBase && Port == 636
            && TimeoutSeconds is >= 1 and <= 30;
    }
}
