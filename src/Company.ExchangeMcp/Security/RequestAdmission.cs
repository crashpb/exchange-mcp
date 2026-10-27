using System.Security.Claims;
using System.Threading.RateLimiting;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Options;

namespace Company.ExchangeMcp.Security;

/// <summary>Separate transport, authentication and parsed mailbox-operation budgets.</summary>
public sealed class RequestAdmission : IDisposable
{
    public const string RejectionItem = "Company.ExchangeMcp.AdmissionRejection";
    private readonly PartitionedRateLimiter<string> operationRate;
    private readonly PartitionedRateLimiter<string> userWork;
    private readonly PartitionedRateLimiter<string> transportRate;
    private readonly PartitionedRateLimiter<string> userTransport;
    private readonly PartitionedRateLimiter<string> userStream;
    private readonly PartitionedRateLimiter<string> userAuthentication;
    private readonly PartitionedRateLimiter<string> userPayload;
    private readonly ConcurrencyLimiter work;
    private readonly ConcurrencyLimiter transports;
    private readonly ConcurrencyLimiter streams = Concurrency(128);
    private readonly ConcurrencyLimiter authentication = Concurrency(8, 64);
    private readonly ConcurrencyLimiter preAuthentication;
    private readonly ConcurrencyLimiter payloads;

    public RequestAdmission(IOptions<ServiceOptions> options)
    {
        var settings = options.Value;
        operationRate = Window(settings.RequestsPerMinute);
        userWork = Users(settings.ConcurrentRequestsPerUser, 8);
        transportRate = Window(settings.TransportRequestsPerMinute);
        userTransport = Users(4, 16);
        userStream = Users(4);
        userAuthentication = Users(4, 16);
        userPayload = Users(settings.ConcurrentRequestsPerUser, 8);
        work = Concurrency(settings.ConcurrentRequests, 64);
        transports = Concurrency(settings.ConcurrentTransports, 128);
        preAuthentication = Concurrency(settings.ConcurrentTransports);
        payloads = Concurrency(settings.ConcurrentRequests, 64);
    }

    public AdmissionLease AcquirePreAuthentication() => Take(preAuthentication.AttemptAcquire(), "preauth_capacity");

    public async ValueTask<AdmissionLease> AcquireAuthenticationAsync(ClaimsPrincipal user, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var subject = Subject(user);
        var lease = Take(transportRate.AttemptAcquire(subject), "transport_rate");
        if (!lease.IsAcquired) return lease;
        return await AcquirePairAsync(lease, userAuthentication, subject, authentication,
            "user_auth_capacity", "global_auth_capacity", "auth_queue_timeout", cancellationToken).ConfigureAwait(false);
    }

    public async ValueTask<AdmissionLease> AcquireTransportAsync(ClaimsPrincipal user, bool stream, bool largePayload,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var subject = Subject(user);
        if (stream)
        {
            var streaming = Take(userStream.AttemptAcquire(subject), "user_stream_capacity");
            if (streaming.IsAcquired) streaming.Add(streams.AttemptAcquire(), "global_stream_capacity");
            return streaming;
        }
        var lease = new AdmissionLease();
        using var waiting = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        waiting.CancelAfter(TimeSpan.FromSeconds(2));
        var timeoutReason = "transport_queue_timeout";
        try
        {
            if (!lease.Add(await userTransport.AcquireAsync(subject, 1, waiting.Token).ConfigureAwait(false), "user_transport_capacity")) return lease;
            if (largePayload)
            {
                timeoutReason = "payload_queue_timeout";
                if (!lease.Add(await userPayload.AcquireAsync(subject, 1, waiting.Token).ConfigureAwait(false), "user_payload_capacity")) return lease;
                if (!lease.Add(await payloads.AcquireAsync(1, waiting.Token).ConfigureAwait(false), "global_payload_capacity")) return lease;
                timeoutReason = "transport_queue_timeout";
            }
            lease.Add(await transports.AcquireAsync(1, waiting.Token).ConfigureAwait(false), "global_transport_capacity");
            cancellationToken.ThrowIfCancellationRequested();
            return lease;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            lease.Reject(timeoutReason, 2);
            return lease;
        }
        catch { lease.Dispose(); throw; }
    }

    private static async ValueTask<AdmissionLease> AcquirePairAsync(AdmissionLease lease,
        PartitionedRateLimiter<string> users, string subject, ConcurrencyLimiter global,
        string userReason, string globalReason, string timeoutReason, CancellationToken cancellationToken)
    {
        using var waiting = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        waiting.CancelAfter(TimeSpan.FromSeconds(2));
        try
        {
            if (!lease.Add(await users.AcquireAsync(subject, 1, waiting.Token).ConfigureAwait(false), userReason)) return lease;
            lease.Add(await global.AcquireAsync(1, waiting.Token).ConfigureAwait(false), globalReason);
            cancellationToken.ThrowIfCancellationRequested();
            return lease;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            lease.Reject(timeoutReason, 2);
            return lease;
        }
        catch { lease.Dispose(); throw; }
    }

    public async ValueTask<AdmissionLease> AcquireOperationAsync(ClaimsPrincipal user, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var subject = Subject(user);
        var lease = Take(operationRate.AttemptAcquire(subject), "operation_rate");
        if (!lease.IsAcquired) return lease;
        using var waiting = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        waiting.CancelAfter(TimeSpan.FromSeconds(2));
        var timeoutReason = "user_work_queue_timeout";
        try
        {
            if (!lease.Add(await userWork.AcquireAsync(subject, 1, waiting.Token).ConfigureAwait(false), "user_work_capacity")) return lease;
            timeoutReason = "work_queue_timeout";
            lease.Add(await work.AcquireAsync(1, waiting.Token).ConfigureAwait(false), "global_work_capacity");
            cancellationToken.ThrowIfCancellationRequested();
            return lease;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            lease.Reject(timeoutReason, 2);
            return lease;
        }
        catch { lease.Dispose(); throw; }
    }

    public static bool IsMcpPath(PathString path) => path.Value?.TrimEnd('/') is "" or "/mcp"
        || string.Equals(path.Value?.TrimEnd('/'), "/mcp", StringComparison.OrdinalIgnoreCase);

    public static JsonObject RejectionData(string id, string reason, int retrySeconds) => new()
    {
        ["reason"] = reason,
        ["retrySeconds"] = retrySeconds,
        ["dispatchStatus"] = "not_dispatched",
        ["tracking"] = new JsonObject
        {
            ["id"] = id,
            ["outcome"] = "not_dispatched",
            ["stage"] = "admission_" + reason,
            ["reason"] = reason,
            ["retrySeconds"] = retrySeconds,
            ["dispatchStatus"] = "not_dispatched"
        }
    };

    public static async Task RecordRejectionAsync(AuditLog audit, string id, string operation, string reason)
    {
        try
        {
            await audit.RecordTrackingAsync(id, operation, "not_dispatched", "admission_" + reason, null,
                CancellationToken.None).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is IOException or ObjectDisposedException) { }
    }

    public static async Task RejectHttpAsync(HttpContext context, AdmissionLease lease)
    {
        var id = OperationTracking.EnsureRequestId(context);
        await RecordRejectionAsync(context.RequestServices.GetRequiredService<AuditLog>(), id, "http_admission", lease.Reason);
        context.Response.StatusCode = StatusCodes.Status429TooManyRequests;
        context.Response.Headers.RetryAfter = lease.RetrySeconds.ToString(System.Globalization.CultureInfo.InvariantCulture);
        var data = RejectionData(id, lease.Reason, lease.RetrySeconds);
        data["error"] = "request_admission_rejected";
        await context.Response.WriteAsJsonAsync(data, context.RequestAborted);
    }

    private static string Subject(ClaimsPrincipal user) => user.Identity?.IsAuthenticated == true
        && user.FindFirst("sub")?.Value is { Length: > 0 } subject
        ? "user:" + subject : "anonymous";

    private static PartitionedRateLimiter<string> Window(int limit) => PartitionedRateLimiter.Create<string, string>(
        subject => RateLimitPartition.GetFixedWindowLimiter(subject, _ => new()
        { PermitLimit = limit, Window = TimeSpan.FromMinutes(1), QueueLimit = 0, AutoReplenishment = true }));

    // Partitioned limiters reclaim idle subject entries; no permanent per-user semaphore dictionary.
    private static PartitionedRateLimiter<string> Users(int limit, int queue = 0) => PartitionedRateLimiter.Create<string, string>(
        subject => RateLimitPartition.GetConcurrencyLimiter(subject, _ => new()
        { PermitLimit = limit, QueueLimit = queue, QueueProcessingOrder = QueueProcessingOrder.OldestFirst }));

    private static ConcurrencyLimiter Concurrency(int limit, int queue = 0) => new(new()
    { PermitLimit = limit, QueueLimit = queue, QueueProcessingOrder = QueueProcessingOrder.OldestFirst });

    private static AdmissionLease Take(RateLimitLease lease, string reason)
    {
        var result = new AdmissionLease();
        result.Add(lease, reason);
        return result;
    }

    public void Dispose()
    {
        operationRate.Dispose(); userWork.Dispose(); transportRate.Dispose(); userTransport.Dispose();
        userStream.Dispose(); userAuthentication.Dispose(); work.Dispose(); transports.Dispose();
        userPayload.Dispose(); payloads.Dispose(); streams.Dispose(); authentication.Dispose(); preAuthentication.Dispose();
    }

    public sealed class AdmissionLease : IDisposable
    {
        private readonly List<RateLimitLease> held = [];
        public bool IsAcquired { get; private set; } = true;
        public string Reason { get; private set; } = "";
        public int RetrySeconds { get; private set; } = 1;

        internal bool Add(RateLimitLease lease, string reason)
        {
            if (lease.IsAcquired) { held.Add(lease); return true; }
            var retry = lease.TryGetMetadata(MetadataName.RetryAfter, out var after)
                ? Math.Clamp((int)Math.Ceiling(after.TotalSeconds), 1, 60) : 1;
            lease.Dispose();
            Reject(reason, retry);
            return false;
        }

        internal void Reject(string reason, int retry)
        {
            Dispose(); IsAcquired = false; Reason = reason; RetrySeconds = retry;
        }

        public void Dispose()
        {
            for (var index = held.Count - 1; index >= 0; index--) held[index].Dispose();
            held.Clear();
        }
    }
}
