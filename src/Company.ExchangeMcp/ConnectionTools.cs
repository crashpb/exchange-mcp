using System.ComponentModel;
using System.Security.Claims;
using System.Text.Json;
using System.Text.Json.Nodes;
using Company.ExchangeMcp.Security;
using Microsoft.Extensions.Options;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;

namespace Company.ExchangeMcp;

[McpServerToolType]
public sealed class ConnectionTools(MailboxAccess access, IHttpContextAccessor http,
    IOptions<ServiceOptions> settings) : IConfigureOptions<McpServerOptions>
{
    internal const string ContinuationTool = "mail_request_connection_continuation";
    private const string DescriptorRequestKey = "Company.ExchangeMcp.ConnectionDescriptorRequest";

    [McpServerTool(Name = ContinuationTool, ReadOnly = true, Destructive = false, Idempotent = true, OpenWorld = false)]
    [Description("Only after the user explicitly asks to stay signed in to Exchange MCP, request optional connection continuation through the host's normal OAuth consent flow when this client's company policy permits it. Own mailbox only. Ordinary mailbox work never requires this tool. An offline_access scope claim alone does not prove refresh-token storage or a particular session lifetime. Do not loop sign-ins or retry unsupported consent.")]
    public async Task<CallToolResult> RequestContinuation(ClaimsPrincipal user, CancellationToken cancellationToken)
    {
        var actor = access.RequireOwn(user, MailboxAccess.Read);
        if (!await access.VerifyCurrentActorAsync(actor, cancellationToken).ConfigureAwait(false))
            throw new McpException("The current mailbox identity could not be verified.");
        if (actor.ClientId is not ("exchange-mcp-codex" or "https://chatgpt.com/oauth/client.json"))
            return Result("unsupported_client", "Company policy does not enable connection continuation for this client. Keep using the current connection; do not repeat authorization.", isError: true);
        if (MailboxAccess.HasScope(user, "offline_access"))
            return Result("offline_scope_present", "The current validated access token includes offline_access. This verifies scope presence only; Exchange MCP cannot verify host refresh-token storage or how long the host will stay signed in.");

        var resource = settings.Value.ResourceForHost(http.HttpContext?.Request.Host.Value)
            ?? throw new McpException("The current MCP resource could not be verified.");
        var metadata = new Uri(new Uri(resource), "/.well-known/oauth-protected-resource");
        var scopes = string.Join(' ', MailboxAccess.Scopes.Where(scope => MailboxAccess.HasScope(user, scope)).Append("offline_access"));
        var challenge = $"Bearer resource_metadata=\"{metadata}\", error=\"insufficient_scope\", "
            + "error_description=\"Optional connection continuation requires host OAuth consent for offline_access.\", "
            + $"scope=\"{scopes}\"";
        return Result("authorization_required", "Use the host's normal OAuth consent flow to approve optional connection continuation while preserving current mailbox permissions. If unsupported or denied, keep the current connection and do not loop sign-ins.",
            isError: true, meta: new JsonObject { ["mcp/www_authenticate"] = new JsonArray(challenge) });
    }

    private static CallToolResult Result(string status, string message, bool isError = false, JsonObject? meta = null)
    {
        var payload = JsonSerializer.SerializeToElement(new { status, message });
        return new CallToolResult
        {
            IsError = isError,
            StructuredContent = payload,
            Content = [new TextContentBlock { Text = payload.GetRawText() }],
            Meta = meta
        };
    }

    public void Configure(McpServerOptions options)
    {
        options.Filters.Message.IncomingFilters.Add(next => async (context, cancellationToken) =>
        {
            if (context.JsonRpcMessage is JsonRpcRequest request && request.Method is "tools/list" or "server/discover")
                context.Items[DescriptorRequestKey] = request.Id;
            await next(context, cancellationToken).ConfigureAwait(false);
        });
        options.Filters.Message.OutgoingFilters.Add(next => async (context, cancellationToken) =>
        {
            if (context.JsonRpcMessage is JsonRpcResponse response && response.Result is JsonObject result
                && context.Items.TryGetValue(DescriptorRequestKey, out var requestId) && response.Id.Equals(requestId)
                && result["tools"] is JsonArray tools)
                foreach (var tool in tools.OfType<JsonObject>().Where(tool => tool["name"]?.GetValue<string>() == ContinuationTool))
                {
                    // Only this explicit opt-in tool asks the host for optional continuation before invocation.
                    var schemes = new JsonArray(new JsonObject { ["type"] = "oauth2", ["scopes"] = new JsonArray(MailboxAccess.Read, "offline_access") });
                    tool["securitySchemes"] = schemes;
                    var meta = tool["_meta"] as JsonObject ?? new JsonObject();
                    meta["securitySchemes"] = schemes.DeepClone();
                    tool["_meta"] = meta;
                    if (tool["inputSchema"] is JsonObject schema && schema["properties"] is JsonObject properties)
                        properties.Remove("mailboxHandle");
                }
            await next(context, cancellationToken).ConfigureAwait(false);
        });
    }
}
