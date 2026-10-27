using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Options;
using ModelContextProtocol.Protocol;

namespace Company.ExchangeMcp.Security;

// Operation metadata only: never log tokens, mailbox addresses, message IDs, subjects, bodies or recipients.
public sealed class AuditLog : IDisposable
{
    private readonly StreamWriter writer;
    private readonly SemaphoreSlim gate = new(1, 1);
    private bool disposed;

    public AuditLog(IOptions<ServiceOptions> options)
    {
        var path = Path.GetFullPath(options.Value.AuditPath);
        var directory = Path.GetDirectoryName(path)!;
        Directory.CreateDirectory(directory);
        if (!OperatingSystem.IsWindows())
            File.SetUnixFileMode(directory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        var stream = new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.Read,
            4096, FileOptions.Asynchronous | FileOptions.WriteThrough);
        writer = new StreamWriter(stream, new UTF8Encoding(false)) { AutoFlush = true };
        if (!OperatingSystem.IsWindows())
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
    }

    public async Task RecordAsync(MailboxIdentity identity, string operation, string outcome,
        string operationId, CancellationToken cancellationToken)
    {
        var tracking = OperationTracking.Current;
        var actor = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(identity.Subject)));
        var target = identity.TargetId == "own" ? "own"
            : Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(identity.TargetId)));
        var entry = JsonSerializer.Serialize(new
        {
            utc = DateTimeOffset.UtcNow,
            actor,
            target,
            operation,
            outcome,
            operationId = tracking?.Id ?? operationId,
            stage = tracking?.Stage,
            sendStatus = tracking is { } current && (current.Tool == "mail_send_draft" || current.ExchangeSendAttempted)
                ? current.SendOutcome : null
        });
        await WriteAsync(entry, cancellationToken).ConfigureAwait(false);
    }

    public async Task RecordTrackingAsync(string operationId, string operation, string outcome, string stage,
        string? sendStatus,
        CancellationToken cancellationToken)
    {
        if (!OperationTracking.IsOperationId(operationId)) throw new ArgumentException("The operation ID is invalid.", nameof(operationId));
        if (operation.Length is < 1 or > 80 || operation.Any(character => !char.IsAsciiLetterOrDigit(character) && character is not ('_' or '-')))
            throw new ArgumentException("The operation name is invalid.", nameof(operation));
        if (outcome is not ("in_progress" or "completed" or "failed" or "approval_required" or "cancelled"
            or "not_dispatched" or "rejected" or "acknowledged" or "unknown"))
            throw new ArgumentException("The operation outcome is invalid.", nameof(outcome));
        if (stage.Length is < 1 or > 64 || stage.Any(character => !char.IsAsciiLetterOrDigit(character) && character is not ('_' or '-')))
            throw new ArgumentException("The operation stage is invalid.", nameof(stage));
        if (sendStatus is not (null or "not_dispatched" or "rejected" or "acknowledged" or "unknown"))
            throw new ArgumentException("The send status is invalid.", nameof(sendStatus));
        var entry = JsonSerializer.Serialize(new
        {
            utc = DateTimeOffset.UtcNow,
            operation,
            outcome,
            operationId,
            stage,
            sendStatus
        });
        await WriteAsync(entry, cancellationToken).ConfigureAwait(false);
    }

    public async Task RecordHttpAsync(string operationId, string? method, string? path, int statusCode,
        long elapsedMilliseconds, string? protocolVersion = null, string? mcpMethod = null, string? mcpName = null)
    {
        if (!OperationTracking.IsOperationId(operationId)) throw new ArgumentException("The operation ID is invalid.", nameof(operationId));
        if (statusCode is < 100 or > 599) throw new ArgumentOutOfRangeException(nameof(statusCode));
        var safeMethod = method is "GET" or "POST" or "OPTIONS" or "HEAD" or "DELETE" ? method : "OTHER";
        var safePath = path is "/" or "/mcp" or "/mcp/" or "/.well-known/oauth-protected-resource"
            or "/.well-known/oauth-protected-resource/mcp" ? path : "other";
        var entry = JsonSerializer.Serialize(new
        {
            utc = DateTimeOffset.UtcNow,
            kind = "http",
            operationId,
            method = safeMethod,
            path = safePath,
            statusCode,
            elapsedMilliseconds = Math.Clamp(elapsedMilliseconds, 0, 86_400_000),
            protocolClass = protocolVersion switch
            {
                null => "missing",
                "" => "empty",
                "2026-07-28" => "2026-07-28",
                "2024-11-05" or "2025-03-26" or "2025-06-18" or "2025-11-25" => "classic",
                _ => "other"
            },
            mcpMethodClass = mcpMethod switch
            {
                null => "missing",
                "" => "empty",
                "resources/read" => "resources_read",
                "resources/list" => "resources_list",
                _ => "other"
            },
            mcpNamePresent = mcpName is not null,
            resourceClass = mcpName switch
            {
                null => "missing",
                "" => "empty",
                _ => ResourceClass(mcpName)
            }
        });
        await WriteAsync(entry, CancellationToken.None).ConfigureAwait(false);
    }

    public async Task RecordResourceAsync(string operationId, string? resourceUri, string status,
        ReadResourceResult? result, CancellationToken cancellationToken)
    {
        if (!OperationTracking.IsOperationId(operationId)) throw new ArgumentException("The operation ID is invalid.", nameof(operationId));
        if (status is not ("completed" or "failed" or "cancelled"))
            throw new ArgumentException("The resource status is invalid.", nameof(status));
        var resourceClass = ResourceClass(resourceUri);
        var expected = StaticResourceContents(resourceClass);
        var matching = expected is not null && result?.Contents is { Count: 1 } contents
            && contents[0] is TextResourceContents content && content.Uri == resourceUri
            && content.MimeType == expected.MimeType
            && string.Equals(content.Text, expected.Text, StringComparison.Ordinal);
        var entry = new Dictionary<string, object?>
        {
            ["utc"] = DateTimeOffset.UtcNow,
            ["kind"] = "resource",
            ["operationId"] = operationId,
            ["resourceClass"] = resourceClass,
            ["status"] = status,
            ["mimeClass"] = matching ? "mcp_app_html" : "other",
            ["contentCount"] = result?.Contents?.Count ?? 0
        };
        if (matching)
        {
            var bytes = Encoding.UTF8.GetBytes(((TextResourceContents)result!.Contents[0]).Text);
            entry["utf8Length"] = bytes.Length;
            entry["sha256"] = Convert.ToHexString(SHA256.HashData(bytes));
        }
        await WriteAsync(JsonSerializer.Serialize(entry), cancellationToken).ConfigureAwait(false);
    }

    private static string ResourceClass(string? uri) => uri switch
    {
        SignaturePreviewResources.ResourceUri => "signature_current",
        SignaturePreviewResources.RetainedResourceUri => "signature_retained",
        SignaturePreviewResources.PreviousResourceUri => "signature_previous",
        SignaturePreviewResources.LegacyResourceUri => "signature_legacy",
        MailPreviewResources.ResourceUri => "email_current",
        MailPreviewResources.PriorResourceUri => "email_prior",
        MailPreviewResources.CachedResourceUri => "email_cached",
        MailPreviewResources.RetainedResourceUri => "email_retained",
        MailPreviewResources.PreviousResourceUri => "email_previous",
        MailPreviewResources.LegacyResourceUri => "email_legacy",
        _ => "other"
    };

    private static TextResourceContents? StaticResourceContents(string resourceClass) => resourceClass switch
    {
        "signature_current" or "signature_retained" or "signature_previous" or "signature_legacy"
            => (TextResourceContents)SignaturePreviewResources.Read().Contents[0],
        "email_current" or "email_prior" or "email_cached" or "email_retained" or "email_previous" or "email_legacy"
            => (TextResourceContents)MailPreviewResources.Read().Contents[0],
        _ => null
    };

    private async Task WriteAsync(string entry, CancellationToken cancellationToken)
    {
        await gate.WaitAsync(cancellationToken);
        try
        {
            ObjectDisposedException.ThrowIf(disposed, this);
            await writer.WriteLineAsync(entry.AsMemory(), cancellationToken);
            await writer.FlushAsync(cancellationToken);
        }
        finally { gate.Release(); }
    }

    public void Dispose()
    {
        gate.Wait();
        try
        {
            if (disposed) return;
            disposed = true;
            writer.Dispose();
        }
        finally { gate.Release(); }
        // HTTP completion callbacks may still be waiting on this gate during shutdown.
    }
}
