using System.ComponentModel;
using System.Globalization;
using System.Security.Claims;
using System.Text.Json;
using System.Text.Json.Nodes;
using Company.ExchangeMcp.Security;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;

namespace Company.ExchangeMcp;

/// <summary>Raw MCP Events protocol methods, available only to the July 2026 protocol.</summary>
public sealed class MailEventProtocol(MailEventService events, MailboxAccess access,
    ILogger<MailEventProtocol> logger, RequestAdmission admission, AuditLog audit,
    IHttpContextAccessor httpContextAccessor) : IConfigureOptions<McpServerOptions>
{
    private const string EventsProtocolVersion = "2026-07-28";
    private const string ErrorReasonPrefix = "company-mail-event-reason:";
    private const string AdmissionErrorPrefix = "company-mail-admission:";
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private const string TraceItemKey = "Company.ExchangeMcp.MailEventProtocol.Trace";

    public void Configure(McpServerOptions options)
    {
#pragma warning disable MCPEXP002
        options.RequestHandlers ??= [];
        options.RequestHandlers.Add(new McpServerRequestHandler
        {
            Method = "events/list",
            Handler = (request, cancellationToken) => ListAsync(request, cancellationToken)
        });
        options.RequestHandlers.Add(new McpServerRequestHandler
        {
            Method = "events/subscribe",
            Handler = (request, cancellationToken) => AdmitAsync(request, SubscribeAsync, cancellationToken)
        });
        options.RequestHandlers.Add(new McpServerRequestHandler
        {
            Method = "events/unsubscribe",
            Handler = (request, cancellationToken) => AdmitAsync(request, UnsubscribeAsync, cancellationToken)
        });
#pragma warning restore MCPEXP002

        options.Filters.Message.IncomingFilters.Add(next => async (context, cancellationToken) =>
        {
            TraceRequest(context);
            if (context.JsonRpcMessage is JsonRpcRequest request && IsStatusRequest(request)
                && request.Params is JsonObject parameters && parameters["arguments"] is { } arguments
                && arguments is not JsonObject)
                throw InvalidParams("The mail event status arguments must be an object.");
            await next(context, cancellationToken).ConfigureAwait(false);
        });
        options.Filters.Message.OutgoingFilters.Add(next => async (context, cancellationToken) =>
        {
            AddEventsCapability(context);
            AddEventErrorReason(context);
            AddAdmissionError(context);
            TraceResponse(context);
            await next(context, cancellationToken).ConfigureAwait(false);
        });
    }

    private void TraceRequest(MessageContext context)
    {
        try
        {
            if (context.JsonRpcMessage is not JsonRpcRequest request) return;
            var isStatus = IsStatusRequest(request);
            if (!isStatus && request.Method is not ("server/discover" or "tools/list" or "events/list" or "events/subscribe" or "events/unsubscribe")) return;
            var protocol = request.Context?.ProtocolVersion switch
            {
                "2026-07-28" => "2026-07-28",
                "2025-11-25" => "2025-11-25",
                "2025-06-18" => "2025-06-18",
                "2025-03-26" => "2025-03-26",
                "2024-11-05" => "2024-11-05",
                null => "missing",
                _ => "unknown"
            };
            var trace = new EventRequestTrace(Guid.NewGuid().ToString("N"), request.Id, request.Method, protocol,
                isStatus ? "mail_event_status" : "not_applicable");
            context.Items[TraceItemKey] = trace;
            var http = context.Services?.GetService<IHttpContextAccessor>()?.HttpContext;
            if (http is not null) http.Items[TraceItemKey] = trace;
            logger.LogInformation("MCP event trace request trace={TraceId} method={Method} protocol={Protocol} name={ToolName}",
                trace.Id, trace.Method, trace.Protocol, trace.ToolName);
        }
        catch (Exception exception) when (exception is not OutOfMemoryException and not StackOverflowException) { }
    }

    private void TraceResponse(MessageContext context)
    {
        try
        {
            var http = context.Services?.GetService<IHttpContextAccessor>()?.HttpContext;
            context.Items.TryGetValue(TraceItemKey, out var value);
            // SDK error replies retain the HTTP request but replace the message context and its Items.
            if (value is not EventRequestTrace && http is not null) http.Items.TryGetValue(TraceItemKey, out value);
            if (value is not EventRequestTrace trace)
                return;
            JsonObject? result;
            string rpc;
            if (context.JsonRpcMessage is JsonRpcResponse response && response.Id.Equals(trace.RequestId))
            {
                result = response.Result as JsonObject;
                rpc = "success";
            }
            else if (context.JsonRpcMessage is JsonRpcError error && error.Id.Equals(trace.RequestId))
            {
                if (trace.ToolName == "mail_event_status" && http is not null)
                {
                    var id = OperationTracking.EnsureRequestId(http);
                    var data = error.Error.Data as JsonObject ?? new JsonObject();
                    if (error.Error.Data is not null && error.Error.Data is not JsonObject)
                        data["data"] = JsonSerializer.SerializeToNode(error.Error.Data, JsonOptions);
                    if (data.ContainsKey("tracking")) data = new JsonObject { ["data"] = data };
                    data["tracking"] = new JsonObject
                    {
                        ["id"] = id,
                        ["outcome"] = "failed",
                        ["stage"] = error.Error.Code == -32602 ? "rpc_validation" : "rpc_error"
                    };
                    error.Error.Data = data;
                }
                result = null;
                rpc = error.Error.Code is -32700 or -32600 or -32601 or -32602 or -32603 or -32015 or -32022
                    ? error.Error.Code.ToString(CultureInfo.InvariantCulture) : "other_error";
            }
            else return;
            var resultType = result?["resultType"] is JsonValue type && type.TryGetValue<string>(out var name)
                && name == "complete" ? "complete" : "not_observed";
            var capability = trace.Method == "server/discover" && result is not null
                ? result["capabilities"] is JsonObject capabilities && capabilities["events"] is JsonObject ? "present" : "absent"
                : "not_observed";
            var tools = result?["tools"] as JsonArray;
            var definitions = result?["events"] as JsonArray;
            var toolsCount = SafeCount(tools);
            var eventsCount = SafeCount(definitions);
            var hasStatus = ContainsName(tools, "mail_event_status");
            var hasInbox = ContainsName(definitions, MailEventService.InboxEventName);
            var hasTracking = result?["_meta"] is JsonObject metadata && metadata["tracking"] is JsonObject
                || context.JsonRpcMessage is JsonRpcError { Error.Data: JsonObject errorData }
                    && errorData["tracking"] is JsonObject;
            void Record(string httpStatus)
            {
                try
                {
                    logger.LogInformation("MCP event trace response trace={TraceId} method={Method} protocol={Protocol} http={HttpStatus} rpc={RpcStatus} result={ResultType} eventsCapability={EventsCapability} tools={ToolCount} mailEventStatus={MailEventStatus} events={EventCount} emailReceived={EmailReceived} name={ToolName} tracking={TrackingPresent}",
                        trace.Id, trace.Method, trace.Protocol, httpStatus, rpc, resultType, capability,
                        toolsCount, hasStatus, eventsCount, hasInbox, trace.ToolName, hasTracking);
                }
                catch (Exception exception) when (exception is not OutOfMemoryException and not StackOverflowException) { }
            }
            if (http is null) Record("not_observed");
            else http.Response.OnCompleted(() =>
            {
                try
                {
                    Record(http.Response.StatusCode is >= 100 and <= 599
                        ? http.Response.StatusCode.ToString(CultureInfo.InvariantCulture) : "unknown");
                }
                catch (Exception exception) when (exception is not OutOfMemoryException and not StackOverflowException) { }
                return Task.CompletedTask;
            });
        }
        catch (Exception exception) when (exception is not OutOfMemoryException and not StackOverflowException) { }
    }

    private static string SafeCount(JsonArray? values) => values is null ? "not_observed"
        : values.Count > 2048 ? "over_limit" : values.Count.ToString(CultureInfo.InvariantCulture);

    private static bool IsStatusRequest(JsonRpcRequest request) => request.Method == "tools/call"
        && request.Params is JsonObject parameters && parameters["name"] is JsonValue toolName
        && toolName.TryGetValue<string>(out var name) && name == "mail_event_status";

    private async ValueTask<JsonNode?> AdmitAsync(JsonRpcRequest request,
        Func<JsonRpcRequest, CancellationToken, ValueTask<JsonNode?>> next, CancellationToken cancellationToken)
    {
        var http = httpContextAccessor.HttpContext;
        var user = request.Context?.User ?? throw new McpException("An authenticated employee identity is required.");
        using var lease = await admission.AcquireOperationAsync(user, cancellationToken);
        if (lease.IsAcquired) return await next(request, cancellationToken).ConfigureAwait(false);
        var id = http is null ? Guid.NewGuid().ToString("N") : OperationTracking.EnsureRequestId(http);
        await RequestAdmission.RecordRejectionAsync(audit, id,
            request.Method == "events/subscribe" ? "events_subscribe" : "events_unsubscribe", lease.Reason);
        throw new McpProtocolException(AdmissionErrorPrefix + lease.Reason + ":"
            + lease.RetrySeconds.ToString(CultureInfo.InvariantCulture) + ":" + id, (McpErrorCode)(-32029));
    }

    private static void AddAdmissionError(MessageContext context)
    {
        if (context.JsonRpcMessage is not JsonRpcError error || error.Error.Code != -32029
            || !error.Error.Message.StartsWith(AdmissionErrorPrefix, StringComparison.Ordinal)) return;
        var parts = error.Error.Message[AdmissionErrorPrefix.Length..].Split(':');
        if (parts.Length != 3 || !IsSafeReason(parts[0]) || !OperationTracking.IsOperationId(parts[2])
            || !int.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out var retry) || retry is < 1 or > 60) return;
        error.Error.Message = "Exchange MCP is busy. Retry after the indicated delay; no mailbox work was dispatched.";
        error.Error.Data = RequestAdmission.RejectionData(parts[2], parts[0], retry);
    }

    private static string ContainsName(JsonArray? values, string expected) => values is null ? "not_observed"
        : values.Count > 2048 ? "over_limit"
        : values.Any(value => value is JsonObject item && item["name"] is JsonValue name
            && name.TryGetValue<string>(out var text) && text == expected) ? "present" : "absent";

    private sealed record EventRequestTrace(string Id, RequestId RequestId, string Method, string Protocol, string ToolName);

    private ValueTask<JsonNode?> ListAsync(JsonRpcRequest request, CancellationToken cancellationToken)
    {
        _ = RequireActor(request);
        RequireEventsProtocol(request);
        var parameters = GetParameters(request, "cursor");
        RequireNullCursor(parameters);
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult(JsonSerializer.SerializeToNode(events.ListEvents(), JsonOptions));
    }

    private async ValueTask<JsonNode?> SubscribeAsync(JsonRpcRequest request, CancellationToken cancellationToken)
    {
        var user = request.Context?.User
            ?? throw new McpException("An authenticated employee identity is required.");
        var actor = access.RequireOwn(user, MailboxAccess.Read);
        RequireEventsProtocol(request);
        var parameters = GetParameters(request, "name", "arguments", "delivery", "cursor", "ttlMs");
        RequireNullCursor(parameters);

        var name = RequiredString(parameters, "name");
        var arguments = RequiredObject(parameters, "arguments");
        if (arguments.Count != 0)
            throw InvalidParams("Only unfiltered own-Inbox notifications are supported.");
        var delivery = RequiredObject(parameters, "delivery");
        RequireExactProperties(delivery, "mode", "url", "secret");
        if (RequiredString(delivery, "mode") != "webhook")
            throw InvalidParams("Only webhook event delivery is supported.");
        var callbackUrl = RequiredString(delivery, "url");
        var secret = RequiredString(delivery, "secret");
        try
        {
            var requestedTtl = OptionalTtl(parameters);
            var ttlMs = ClampLifetimeToToken(user, requestedTtl);
            var result = await events.SubscribeAsync(actor, name, arguments.Deserialize<JsonElement>(),
                callbackUrl, secret, ttlMs, cancellationToken).ConfigureAwait(false);
            return new JsonObject
            {
                ["id"] = result.Id,
                ["refreshBefore"] = result.RefreshBefore.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture),
                ["cursor"] = result.Cursor,
                ["truncated"] = result.Truncated
            };
        }
        catch (MailEventException exception)
        {
            throw EventProtocolError(exception);
        }
    }

    private async ValueTask<JsonNode?> UnsubscribeAsync(JsonRpcRequest request, CancellationToken cancellationToken)
    {
        var actor = RequireActor(request);
        RequireEventsProtocol(request);
        var parameters = GetParameters(request, "name", "arguments", "delivery", "cursor");
        RequireNullCursor(parameters);
        var name = RequiredString(parameters, "name");
        var arguments = RequiredObject(parameters, "arguments");
        if (arguments.Count != 0)
            throw InvalidParams("Only unfiltered own-Inbox notifications are supported.");
        var delivery = RequiredObject(parameters, "delivery");
        RequireExactProperties(delivery, "mode", "url");
        if (RequiredString(delivery, "mode") != "webhook")
            throw InvalidParams("Only webhook event delivery is supported.");
        var callbackUrl = RequiredString(delivery, "url");

        try
        {
            await events.UnsubscribeAsync(actor, name, arguments.Deserialize<JsonElement>(), callbackUrl,
                cancellationToken).ConfigureAwait(false);
            return new JsonObject();
        }
        catch (MailEventException exception)
        {
            throw EventProtocolError(exception);
        }
    }

    private MailboxIdentity RequireActor(JsonRpcRequest request)
    {
        var user = request.Context?.User;
        if (user is null)
            throw new McpException("An authenticated employee identity is required.");
        return access.RequireOwn(user, MailboxAccess.Read);
    }

    private static void RequireEventsProtocol(JsonRpcRequest request)
    {
        if (request.Context?.ProtocolVersion != EventsProtocolVersion)
            throw new McpProtocolException("The mail events methods require MCP protocol 2026-07-28.",
                McpErrorCode.UnsupportedProtocolVersion);
    }

    private static JsonObject GetParameters(JsonRpcRequest request, params string[] allowed)
    {
        if (request.Params is null)
            return new JsonObject();
        if (request.Params is not JsonObject parameters)
            throw InvalidParams("Event method parameters must be an object.");
        var permitted = allowed.Append("_meta").ToHashSet(StringComparer.Ordinal);
        if (parameters.Any(property => !permitted.Contains(property.Key)))
            throw InvalidParams("Event method parameters contain an unsupported field.");
        if (parameters.TryGetPropertyValue("_meta", out var meta) && meta is not JsonObject)
            throw InvalidParams("The per-request metadata must be an object.");
        return parameters;
    }

    private static JsonObject RequiredObject(JsonObject parameters, string property)
    {
        if (!parameters.TryGetPropertyValue(property, out var value) || value is not JsonObject result)
            throw InvalidParams($"The '{property}' field must be an object.");
        return result;
    }

    private static string RequiredString(JsonObject parameters, string property)
    {
        if (!parameters.TryGetPropertyValue(property, out var value) || value is not JsonValue jsonValue
            || !jsonValue.TryGetValue<string>(out var result) || result is null)
            throw InvalidParams($"The '{property}' field must be a string.");
        return result;
    }

    private static long? OptionalTtl(JsonObject parameters)
    {
        if (!parameters.TryGetPropertyValue("ttlMs", out var value) || value is null)
            return null;
        if (value is JsonValue jsonValue && jsonValue.TryGetValue<long>(out var ttl))
            return ttl;
        throw InvalidParams("The 'ttlMs' field must be an integer or null.");
    }

    private static void RequireNullCursor(JsonObject parameters)
    {
        if (parameters.TryGetPropertyValue("cursor", out var cursor) && cursor is not null)
            throw InvalidParams("Event cursors are not supported; provide null or omit the field.");
    }

    private static void RequireExactProperties(JsonObject value, params string[] fields)
    {
        var expected = fields.ToHashSet(StringComparer.Ordinal);
        if (value.Count != expected.Count || value.Any(property => !expected.Contains(property.Key)))
            throw InvalidParams("The event delivery object contains missing or unsupported fields.");
    }

    internal static long ClampLifetimeToToken(ClaimsPrincipal user, long? requestedTtlMs)
    {
        const long defaultLifetimeMs = 24 * 60 * 60 * 1000;
        const long minimumLifetimeMs = 60 * 1000;
        const long expirySafetyMarginMs = 5 * 1000;
        var expiryClaim = user.FindFirst("exp")?.Value ?? user.FindFirst(ClaimTypes.Expiration)?.Value;
        if (!long.TryParse(expiryClaim, NumberStyles.None, CultureInfo.InvariantCulture, out var expirySeconds)
            || expirySeconds <= 0 || expirySeconds > DateTimeOffset.MaxValue.ToUnixTimeSeconds())
            throw new McpException("The authenticated session has no valid expiry; refresh sign-in and retry.");

        long requested = requestedTtlMs ?? defaultLifetimeMs;
        if (requested <= 0)
            return requested;
        var nowMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        var available = expirySeconds * 1000 - nowMs - expirySafetyMarginMs;
        if (available < minimumLifetimeMs)
            throw new MailEventException("The signed-in session expires too soon to create a notification subscription.",
                "token_lifetime_too_short");
        return Math.Min(requested, available);
    }

    private static McpProtocolException EventProtocolError(MailEventException exception)
    {
        var reason = IsSafeReason(exception.Reason) ? exception.Reason : "internal_error";
        return new McpProtocolException(ErrorReasonPrefix + reason,
            (McpErrorCode)(-32015));
    }

    private static void AddEventsCapability(MessageContext context)
    {
        if (context.JsonRpcMessage.Context?.ProtocolVersion != EventsProtocolVersion
            || context.JsonRpcMessage is not JsonRpcResponse response
            || response.Result is not JsonObject result
            || result["resultType"]?.GetValue<string>() != "complete"
            || result["supportedVersions"] is not JsonArray
            || result["capabilities"] is not JsonObject capabilities)
            return;

        if (!capabilities.ContainsKey("events"))
            capabilities["events"] = new JsonObject();
    }

    private static void AddEventErrorReason(MessageContext context)
    {
        if (context.JsonRpcMessage is not JsonRpcError error || error.Error.Code != -32015
            || !error.Error.Message.StartsWith(ErrorReasonPrefix, StringComparison.Ordinal))
            return;
        var reason = error.Error.Message[ErrorReasonPrefix.Length..];
        if (!IsSafeReason(reason)) return;
        error.Error.Message = "The mail event operation could not be completed.";
        error.Error.Data = new JsonObject { ["reason"] = reason };
    }

    private static bool IsSafeReason(string value) => value.Length is > 0 and <= 64
        && value.All(character => character is >= 'a' and <= 'z' or >= '0' and <= '9' or '_' or '-');

    private static McpProtocolException InvalidParams(string message) =>
        new(message, McpErrorCode.InvalidParams);
}

[McpServerToolType]
public sealed class MailEventTools(MailEventService events, MailboxAccess access)
{
    [McpServerTool(Name = "mail_event_status", ReadOnly = true, Destructive = false, Idempotent = true, OpenWorld = false)]
    [Description("Show this user's own Inbox notification subscriptions, expiry, pending count, and any delivery gap or stopped reason. Does not expose webhook URLs or signing secrets.")]
    public async Task<object> Status(ClaimsPrincipal user,
        CancellationToken cancellationToken) => await events.StatusAsync(access.RequireOwn(user, MailboxAccess.Read), cancellationToken)
            .ConfigureAwait(false);
}
