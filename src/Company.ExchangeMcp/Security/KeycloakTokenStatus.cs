using System.Globalization;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Options;

namespace Company.ExchangeMcp.Security;

/// <summary>
/// Performs an uncached Keycloak token introspection check for each authenticated request.
/// </summary>
public sealed class KeycloakTokenStatus(HttpClient httpClient, IOptions<ServiceOptions> options)
{
    private const long MaxResponseBytes = 64 * 1024;
    private const int MaxTokenLength = 64 * 1024;
    private const int MaxSecretLength = 8192;
    private static readonly TimeSpan RequestTimeout = TimeSpan.FromSeconds(10);
    private readonly HttpClient _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
    private readonly ServiceOptions _options = options?.Value ?? throw new ArgumentNullException(nameof(options));
    private readonly Uri _endpoint = BuildEndpoint(options?.Value ?? throw new ArgumentNullException(nameof(options)));

    public async Task<bool> IsCurrentAsync(
        string accessToken,
        ClaimsPrincipal principal,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(accessToken) || accessToken.Length > MaxTokenLength
            || principal.Identity?.IsAuthenticated != true)
        {
            return false;
        }

        try
        {
            var secret = ReadSecret(_options.IntrospectionSecretFile);
            if (secret is null) return false;

            using var request = new HttpRequestMessage(HttpMethod.Post, _endpoint)
            {
                Content = new FormUrlEncodedContent(new Dictionary<string, string>
                {
                    ["client_id"] = _options.IntrospectionClientId,
                    ["client_secret"] = secret,
                    ["token"] = accessToken
                })
            };
            request.Headers.Accept.ParseAdd("application/json");
            request.Headers.CacheControl = new System.Net.Http.Headers.CacheControlHeaderValue { NoStore = true };

            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(RequestTimeout);
            using var response = await _httpClient.SendAsync(
                request,
                HttpCompletionOption.ResponseHeadersRead,
                timeout.Token).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode
                || response.Content.Headers.ContentLength is > MaxResponseBytes)
            {
                return false;
            }

            var payload = await ReadBoundedAsync(response, timeout.Token).ConfigureAwait(false);
            if (payload is null) return false;
            using var document = JsonDocument.Parse(payload, new JsonDocumentOptions { MaxDepth = 16 });
            return Matches(document.RootElement, principal);
        }
        catch (Exception)
        {
            // Authentication must fail closed without exposing token, secret, or provider details.
            return false;
        }
    }

    private static Uri BuildEndpoint(ServiceOptions options)
    {
        var authority = options.Authority.TrimEnd('/') + "/";
        return new Uri(new Uri(authority, UriKind.Absolute),
            "protocol/openid-connect/token/introspect");
    }

    private static string? ReadSecret(string path)
    {
        try
        {
            var value = File.ReadAllText(path).TrimEnd('\r', '\n');
            return value.Length is > 0 and <= MaxSecretLength ? value : null;
        }
        catch (Exception)
        {
            return null;
        }
    }

    private static async Task<byte[]?> ReadBoundedAsync(
        HttpResponseMessage response,
        CancellationToken cancellationToken)
    {
        await using var source = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        await using var destination = new MemoryStream();
        var buffer = new byte[16 * 1024];
        long total = 0;
        int read;
        while ((read = await source.ReadAsync(buffer.AsMemory(), cancellationToken).ConfigureAwait(false)) > 0)
        {
            total += read;
            if (total > MaxResponseBytes) return null;
            await destination.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
        }

        return destination.ToArray();
    }

    private bool Matches(JsonElement response, ClaimsPrincipal principal)
    {
        if (!response.TryGetProperty("active", out var active) || active.ValueKind != JsonValueKind.True
            || !StringProperty(response, "typ", "Bearer")
            || !StringProperty(response, "sub", Claim(principal, "sub"))
            || !StringProperty(response, "iss", Claim(principal, "iss"))
            || !AudienceMatches(response, principal)
            || !ClientMatches(response, principal)
            || !ScopeMatches(response, principal)
            || !DirectoryIdentityMatches(response, principal)
            || !ExpiryMatches(response, principal))
        {
            return false;
        }

        return true;
    }

    private static bool DirectoryIdentityMatches(JsonElement response, ClaimsPrincipal principal)
    {
        var claims = principal.FindAll("ad_object_guid").ToArray();
        if (claims.Length == 0) return !response.TryGetProperty("ad_object_guid", out _);
        return claims.Length == 1 && Guid.TryParseExact(claims[0].Value, "D", out var guid)
            && guid != Guid.Empty && StringProperty(response, "ad_object_guid", claims[0].Value);
    }

    private bool AudienceMatches(JsonElement response, ClaimsPrincipal principal)
    {
        var expected = principal.FindAll("aud").Select(x => x.Value)
            .Where(x => !string.IsNullOrWhiteSpace(x)).ToHashSet(StringComparer.Ordinal);
        if (expected.Count == 0) return false;
        if (!TryAudience(response, out var actual)) return false;
        return actual.Overlaps(_options.Resources) && actual.SetEquals(expected);
    }

    private static bool TryAudience(JsonElement response, out HashSet<string> values)
    {
        values = new HashSet<string>(StringComparer.Ordinal);
        if (!response.TryGetProperty("aud", out var audience)) return false;
        if (audience.ValueKind == JsonValueKind.String)
        {
            var value = audience.GetString();
            if (!string.IsNullOrWhiteSpace(value)) values.Add(value);
            return values.Count == 1;
        }
        if (audience.ValueKind != JsonValueKind.Array) return false;
        foreach (var item in audience.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.String || string.IsNullOrWhiteSpace(item.GetString())) return false;
            values.Add(item.GetString()!);
        }
        return values.Count > 0;
    }

    private static bool ClientMatches(JsonElement response, ClaimsPrincipal principal)
    {
        var expected = Claim(principal, "azp");
        if (string.IsNullOrWhiteSpace(expected)) return false;
        var azp = OptionalString(response, "azp");
        var clientId = OptionalString(response, "client_id");
        if (azp is null && clientId is null) return false;
        return (azp is null || azp == expected) && (clientId is null || clientId == expected);
    }

    private static bool ScopeMatches(JsonElement response, ClaimsPrincipal principal)
    {
        var expected = principal.FindAll("scope").SelectMany(x => x.Value.Split(' ', StringSplitOptions.RemoveEmptyEntries))
            .ToHashSet(StringComparer.Ordinal);
        var actual = OptionalString(response, "scope")?.Split(' ', StringSplitOptions.RemoveEmptyEntries)
            .ToHashSet(StringComparer.Ordinal);
        return actual is not null && actual.SetEquals(expected);
    }

    private static bool ExpiryMatches(JsonElement response, ClaimsPrincipal principal)
    {
        if (!TryInt64(response, "exp", out var actual)
            || !long.TryParse(Claim(principal, "exp"), NumberStyles.Integer, CultureInfo.InvariantCulture, out var expected))
        {
            return false;
        }

        return actual == expected && actual > DateTimeOffset.UtcNow.ToUnixTimeSeconds();
    }

    private static bool StringProperty(JsonElement element, string name, string? expected) =>
        expected is not null && element.TryGetProperty(name, out var value)
        && value.ValueKind == JsonValueKind.String && value.GetString() == expected;

    private static string? OptionalString(JsonElement element, string name) =>
        element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString() : null;

    private static bool TryInt64(JsonElement element, string name, out long value)
    {
        value = 0;
        return element.TryGetProperty(name, out var property) && property.ValueKind == JsonValueKind.Number
            && property.TryGetInt64(out value);
    }

    private static string? Claim(ClaimsPrincipal principal, string name) => principal.FindFirst(name)?.Value;
}
