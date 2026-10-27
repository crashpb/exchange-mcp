using System.Text.Json;
using System.Text.Json.Nodes;
using Company.ExchangeMcp.Exchange;
using Company.ExchangeMcp.Security;
using Microsoft.Extensions.DependencyInjection;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;

namespace Company.ExchangeMcp;

/// <summary>Applies an optional, per-call mailbox target without keeping selection in a session.</summary>
public sealed class MailboxTargetFilters(MailboxAccess access, MailboxHandles handles,
    IMailboxPermissionReader permissions, IMailboxDiscovery discovery)
{
    private const string Selector = "mailboxHandle";
    private static readonly HashSet<string> DelegatedTools = new(StringComparer.Ordinal)
    {
        "mail_profile",
        "mail_list_folders", "mail_search", "mail_read",
        "mail_create_draft", "mail_edit_draft", "mail_preview_draft", "mail_forward_draft", "mail_reply_draft",
        "mail_mark_read", "mail_move", "mail_create_folder", "mail_rename_folder", "mail_delete_folder",
        "mail_set_categories", "mail_list_attachments", "mail_read_attachment",
        "mail_create_attachment", "mail_delete_attachment", "mail_delete", "mail_send_draft",
        "mail_sync_folders", "mail_sync_items", "mail_get_mailbox_access",
        "mail_recall_message", "mail_recall_status",
        "mail_signatures", "mail_save_signature", "mail_signature_defaults", "mail_signature_rules", "mail_delete_signature", "mail_apply_signature",
        "mail_inbox_rules", "mail_create_inbox_rule", "mail_update_inbox_rule", "mail_delete_inbox_rule",
        "calendar_list_folders", "calendar_create_folder", "calendar_rename_folder", "calendar_delete_folder",
        "calendar_list_events", "calendar_search", "calendar_read_meeting_message", "calendar_move_event",
        "calendar_copy_event", "calendar_freebusy", "calendar_read_event", "calendar_read_series",
        "calendar_create_event", "calendar_update_event", "calendar_delete_event", "calendar_respond",
        "calendar_list_room_lists", "calendar_list_rooms", "calendar_find_meeting_times",
        "task_list_folders", "task_list", "task_search", "task_read", "task_create", "task_update",
        "task_complete", "task_reopen", "task_delete", "task_create_folder", "task_rename_folder", "task_delete_folder",
        "task_assignment_messages", "task_read_assignment_message", "task_assignment_status",
        "task_assign", "task_reassign", "task_respond", "task_update_assignment", "task_process_update",
        "task_plan_assignments", "task_execute_assignment_plan",
        "groupware_list_attachments", "groupware_read_attachment",
        "groupware_create_attachment", "groupware_delete_attachment",
        "people_list_contacts", "people_search_contacts", "people_read_contact",
        "people_create_contact", "people_update_contact", "people_delete_contact",
        "people_list_contact_groups", "people_search_contact_groups", "people_read_contact_group",
        "people_create_contact_group", "people_update_contact_group", "people_delete_contact_group",
        "people_list_contact_folders", "people_create_contact_folder", "people_rename_contact_folder",
        "people_delete_contact_folder", "people_resolve_directory",
        "sharing_get_folder_permissions", "sharing_set_folder_permission", "sharing_remove_folder_permission",
        "delegate_list", "delegate_add", "delegate_update", "delegate_remove"
    };

    public static McpRequestFilter<ListToolsRequestParams, ListToolsResult> WrapListTools =>
        next => async (context, cancellationToken) =>
        {
            var result = await next(context, cancellationToken);
            return new ListToolsResult
            {
                Tools = result.Tools.Select(CloneTool).ToList(),
                TimeToLive = result.TimeToLive,
                CacheScope = result.CacheScope,
                NextCursor = result.NextCursor,
                Meta = CloneMeta(result.Meta),
                ResultType = result.ResultType
            };
        };

    public static McpRequestFilter<CallToolRequestParams, CallToolResult> WrapCallTool =>
        next => async (context, cancellationToken) =>
        {
            var filter = context.Services!.GetRequiredService<MailboxTargetFilters>();
            try
            {
                return await filter.InvokeAsync(next, context, cancellationToken);
            }
            catch (EwsPermissionDeniedException ex)
            {
                // Keep Exchange's bounded, typed permission result while
                // preventing SOAP, mailbox IDs or transport details from
                // reaching the MCP client.
                throw new McpException(ex.Message);
            }
        };

    private async ValueTask<CallToolResult> InvokeAsync(
        McpRequestHandler<CallToolRequestParams, CallToolResult> next,
        RequestContext<CallToolRequestParams> context,
        CancellationToken cancellationToken)
    {
        var request = context.Params!;
        var arguments = request.Arguments;
        var actor = access.RequireOwn(context.User!, MailboxAccess.Read);
        if (arguments is null || !arguments.TryGetValue(Selector, out var selector))
        {
            using var ownSelection = access.SelectTarget(actor);
            return await next(context, cancellationToken);
        }

        if (request.Name == "mail_list_mailboxes")
            throw new McpException("mail_list_mailboxes lists discovered choices and does not accept a mailbox selector.");
        if (!DelegatedTools.Contains(request.Name))
            throw new McpException($"Selected-mailbox support is not available for '{request.Name}'. Use this operation in the signed-in mailbox; selected-mailbox support is limited to the reviewed mail, calendar, tasks, contacts, signatures, rules, sharing and attachment operations.");
        if (selector.ValueKind != JsonValueKind.String || string.IsNullOrWhiteSpace(selector.GetString()))
            throw new McpException("mailboxHandle must be a non-empty string returned by mail_list_mailboxes.");

        if (string.IsNullOrWhiteSpace(actor.SessionId))
            throw new McpException("Mailbox target selection requires a session-bound OAuth token.");
        var handle = handles.Resolve(actor, "mailbox-target", selector.GetString()!);
        var discovered = await discovery.ResolveAsync(actor, handle.Id, cancellationToken).ConfigureAwait(false);
        if (discovered is null || !string.Equals(discovered.Candidate.Key, handle.Id, StringComparison.Ordinal)
            || !string.Equals(handle.ChangeKey,
                MailboxHandles.TargetBinding(actor, discovered.Candidate.Mailbox), StringComparison.Ordinal))
            throw new McpException("This mailbox target is no longer authorized. Refresh mail_list_mailboxes.");

        var target = actor with
        {
            Mailbox = discovered.Candidate.Mailbox,
            TargetId = discovered.Candidate.Key,
            ActorMailbox = actor.Mailbox
        };
        if (RequiresSendingRights(request))
        {
            var grants = await permissions.ReadAsync(target, cancellationToken);
            if (request.Name is "mail_recall_message" or "task_assign" or "task_reassign" or "task_respond" or "task_update_assignment" or "task_execute_assignment_plan"
                && grants.SendAs.State != "allowed")
                throw new McpException("Native recalls and task notices require verified SendAs permission for the selected mailbox. SendOnBehalf alone is not supported for these native operations.");
            if (grants.SendAs.State != "allowed" && grants.SendOnBehalf.State != "allowed")
                throw new McpException(grants.SendAs.State == "denied" && grants.SendOnBehalf.State == "denied"
                    ? "Your account has neither SendAs nor SendOnBehalf permission for this mailbox. Viewing or FullAccess does not permit sending."
                    : "Sending rights for this mailbox could not be verified. Use mail_get_mailbox_access; unknown permissions do not permit sending.");
        }
        var forwardedArguments = new Dictionary<string, JsonElement>(arguments, StringComparer.Ordinal);
        forwardedArguments.Remove(Selector);
        var forwardedRequest = new CallToolRequestParams
        {
            Name = request.Name,
            Arguments = forwardedArguments,
            Meta = request.Meta,
            InputResponses = request.InputResponses,
            RequestState = request.RequestState
        };
        try
        {
            context.Params = forwardedRequest;
            using var selection = access.SelectTarget(target);
            return await next(context, cancellationToken);
        }
        finally
        {
            context.Params = request;
        }
    }

    private static JsonElement AddSelector(JsonElement schema)
    {
        JsonObject root;
        try
        {
            root = JsonNode.Parse(schema.GetRawText()) as JsonObject
                ?? throw new McpException("MCP tool schema is invalid.");
        }
        catch (McpException)
        {
            throw;
        }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException or ArgumentException)
        {
            throw new McpException("MCP tool schema is invalid.");
        }

        root["type"] ??= "object";
        var properties = root["properties"] as JsonObject;
        if (root["properties"] is not null && properties is null)
            throw new McpException("MCP tool schema is invalid.");
        properties ??= new JsonObject();
        properties[Selector] ??= new JsonObject
        {
            ["type"] = "string",
            ["description"] = "Optional opaque handle from mail_list_mailboxes; binds this call to that approved mailbox."
        };
        root["properties"] = properties;
        using var document = JsonDocument.Parse(root.ToJsonString());
        return document.RootElement.Clone();
    }

    private static bool RequiresSendingRights(CallToolRequestParams request) => request.Name switch
    {
        "mail_send_draft" or "mail_recall_message" => true,
        "task_assign" or "task_reassign" or "task_respond" or "task_update_assignment" or "task_execute_assignment_plan" => true,
        "calendar_create_event" => BooleanArgument(request, "sendInvitations", false),
        "calendar_update_event" => BooleanArgument(request, "sendUpdates", false),
        "calendar_delete_event" => BooleanArgument(request, "sendCancellations", false),
        "calendar_respond" => BooleanArgument(request, "sendResponse", true),
        _ => false
    };

    private static bool BooleanArgument(CallToolRequestParams request, string name, bool fallback)
    {
        if (request.Arguments is null || !request.Arguments.TryGetValue(name, out var value)) return fallback;
        if (value.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
            throw new McpException($"{name} must be a boolean.");
        return value.GetBoolean();
    }

    private static Tool CloneTool(Tool tool)
    {
        var meta = CloneMeta(tool.Meta);
        if (tool.Name is "mail_capture_signature" or "mail_preview_signature" or "mail_preview_saved_signature")
        {
            meta ??= new JsonObject();
            meta["ui"] = new JsonObject { ["resourceUri"] = SignaturePreviewResources.ResourceUri };
            meta["openai/outputTemplate"] = SignaturePreviewResources.ResourceUri;
            meta["openai/ui"] = new JsonObject { ["preferredModelDisplayMode"] = "inline" };
        }
        if (tool.Name == "mail_preview_draft")
        {
            meta ??= new JsonObject();
            meta["ui"] = new JsonObject { ["resourceUri"] = MailPreviewResources.ResourceUri };
            meta["openai/outputTemplate"] = MailPreviewResources.ResourceUri;
            meta["openai/ui"] = new JsonObject { ["preferredModelDisplayMode"] = "inline" };
        }
        var reviewTool = tool.Name is "mail_review_email" or "mail_review_signature";
        if (reviewTool)
        {
            var resource = tool.Name == "mail_review_email"
                ? MailPreviewResources.ResourceUri : SignaturePreviewResources.ResourceUri;
            meta ??= new JsonObject();
            meta["ui"] = new JsonObject { ["resourceUri"] = resource };
            meta["openai/outputTemplate"] = resource;
            meta["openai/ui"] = new JsonObject
            {
                ["preferredModelDisplayMode"] = "inline",
                ["entrypoints"] = new JsonArray(new JsonObject { ["type"] = "thread" })
            };
        }
        return new Tool
        {
            Name = tool.Name,
            Title = tool.Name switch
            {
                "mail_review_email" => "Exchange MCP email review",
                "mail_review_signature" => "Exchange MCP signature review",
                _ => tool.Title
            },
            Description = tool.Description,
            InputSchema = tool.Name is "mail_list_mailboxes" or "mail_preview_saved_signature" || reviewTool
                ? tool.InputSchema.Clone()
                : AddSelector(tool.InputSchema),
            OutputSchema = tool.OutputSchema?.Clone(),
            Annotations = CloneAnnotations(tool.Annotations),
            Icons = tool.Icons?.Select(CloneIcon).ToList(),
            Meta = meta
        };
    }

    private static ToolAnnotations? CloneAnnotations(ToolAnnotations? annotations)
    {
        return annotations is null
            ? null
            : new ToolAnnotations
            {
                Title = annotations.Title,
                ReadOnlyHint = annotations.ReadOnlyHint,
                DestructiveHint = annotations.DestructiveHint,
                IdempotentHint = annotations.IdempotentHint,
                OpenWorldHint = annotations.OpenWorldHint
            };
    }

    private static Icon CloneIcon(Icon icon)
    {
        return new Icon
        {
            Source = icon.Source,
            MimeType = icon.MimeType,
            Sizes = icon.Sizes?.ToList(),
            Theme = icon.Theme
        };
    }

    private static JsonObject? CloneMeta(JsonObject? meta)
    {
        return meta?.DeepClone() as JsonObject;
    }
}
