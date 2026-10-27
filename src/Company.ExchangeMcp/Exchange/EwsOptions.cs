namespace Company.ExchangeMcp.Exchange;

public sealed class EwsOptions
{
    public string Endpoint { get; set; } = string.Empty;

    // These values are configuration metadata for the authentication handler. The EWS
    // client never reads credentials or constructs an Authorization header.
    public string Username { get; set; } = string.Empty;

    public string Domain { get; set; } = string.Empty;

    public string PasswordFile { get; set; } = string.Empty;

    public int TimeoutSeconds { get; set; } = 30;

    public long MaxResponseBytes { get; set; } = 16_777_216;
}
