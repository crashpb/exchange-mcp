using System.ComponentModel;
using System.Security.Claims;
using System.Text.Json;
using System.Text.Json.Nodes;
using Company.ExchangeMcp.Exchange;
using Company.ExchangeMcp.Security;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;

namespace Company.ExchangeMcp;

[McpServerToolType]
public sealed class MailReviewTools(EwsClient exchange, MailboxAccess access, MailReviewStore reviews,
    SignatureStore signatures, SignaturePreviewStore previews)
{
    [McpServerTool(Name = "mail_review_email", ReadOnly = true, Destructive = false, Idempotent = true, OpenWorld = false,
        UseStructuredContent = true, OutputSchemaType = typeof(ReviewOutput))]
    [Description("Review the latest draft successfully previewed on this OAuth connection. Prefer mail_preview_draft's inline result for ordinary email preparation; do not open an extra view automatically. This optional review reloads that draft through the ordinary authenticated preview before showing controls. No draft is selected by search, edited or sent. An empty review requires preparing a draft preview first.")]
    public CallToolResult ReviewEmail(ClaimsPrincipal user)
    {
        var actor = access.RequireOwn(user, MailboxAccess.Read);
        var latest = reviews.Get(actor);
        if (latest is null)
            return Empty("emailReviewBootstrap", "There is no current reviewed draft on this connection. Ask Exchange MCP to preview the intended draft first.");
        return Result(new("email_review_ready", "latest_reviewed_draft",
            "Reload the latest reviewed draft through mail_preview_draft before displaying email controls.", null, latest.ExpiresAt),
            new JsonObject
            {
                ["emailReviewBootstrap"] = new JsonObject
                {
                    ["available"] = true,
                    ["draftHandle"] = latest.DraftHandle,
                    ["mailboxHandle"] = latest.MailboxHandle
                }
            });
    }

    [McpServerTool(Name = "mail_review_signature", ReadOnly = true, Destructive = false, Idempotent = true, OpenWorld = false,
        UseStructuredContent = true, OutputSchemaType = typeof(ReviewOutput))]
    [Description("Open the optional signature review conversation view only when the user asks for that view. Reviews the current pending signature without consuming or extending it, otherwise the saved default (or sole profile). For ordinary read-only saved signature display use mail_preview_saved_signature. Capture/preview results already provide inline reviews. Does not stage, save or change signatures, defaults or setup and does not create or send email.")]
    public async Task<CallToolResult> ReviewSignature(ClaimsPrincipal user, CancellationToken cancellationToken)
    {
        var actor = access.RequireOwn(user, MailboxAccess.Read);
        var snapshot = await signatures.ReadAsync(exchange, actor.Mailbox, cancellationToken).ConfigureAwait(false);
        var pending = previews.Latest(actor);
        if (pending is not null)
        {
            if (!string.Equals(snapshot.Revision, pending.Candidate.Revision, StringComparison.Ordinal))
                return Empty("signatureReviewBootstrap", "Signature settings changed. Ask Exchange MCP to prepare the signature preview again.");
            var updated = SignaturePreviewStore.ApplyCandidate(snapshot.Settings, pending.Candidate);
            var metadata = SignaturePreviewResources.CreateMetadata(pending.Candidate.Profile, pending.Candidate.Language,
                new { forNewMessages = updated.NewMessages, forReplies = updated.Replies }, pending.Candidate.Warnings ?? []);
            metadata["signaturePreview"]!["reviewState"] = "pending";
            return Result(new("signature_review_ready", "pending",
                "Review the pending signature. Saving still requires explicit confirmation with the same preview handle.",
                pending.Handle, pending.ExpiresAt), metadata);
        }

        return SavedSignature(snapshot.Settings);
    }

    [McpServerTool(Name = "mail_preview_saved_signature", ReadOnly = true, Destructive = false, Idempotent = true, OpenWorld = false,
        UseStructuredContent = true, OutputSchemaType = typeof(ReviewOutput))]
    [Description("Show the signed-in user's saved default signature (or the only saved profile) inline, read-only. Always reads saved settings, even when an unsaved or stale preview exists; never consumes, extends or restages that preview. Does not save or change signatures, defaults or setup and does not create or send email. For capture/edit use the existing signature preview workflow; open a separate review view only when explicitly requested.")]
    public async Task<CallToolResult> PreviewSavedSignature(ClaimsPrincipal user, CancellationToken cancellationToken)
    {
        var actor = access.RequireOwn(user, MailboxAccess.Read);
        var snapshot = await signatures.ReadAsync(exchange, actor.Mailbox, cancellationToken).ConfigureAwait(false);
        return SavedSignature(snapshot.Settings);
    }

    private static CallToolResult SavedSignature(SignatureSettings settings)
    {
        var selectedName = settings.NewMessages ?? settings.Replies;
        var saved = selectedName is not null
            ? settings.Profiles.Single(profile => string.Equals(profile.Name, selectedName, StringComparison.OrdinalIgnoreCase))
            : settings.Profiles.Length == 1 ? settings.Profiles[0] : null;
        if (saved is null)
            return Empty("signatureReviewBootstrap", settings.Profiles.Length == 0
                ? "No signature is available. Ask Exchange MCP to prepare a signature preview."
                : "There are several saved signatures and no default. Ask Exchange MCP to show the signatures and choose one to review.");
        var savedMetadata = SignaturePreviewResources.CreateMetadata(saved, settings.Onboarding?.Language,
            new { forNewMessages = settings.NewMessages, forReplies = settings.Replies }, []);
        savedMetadata["signaturePreview"]!["reviewState"] = "saved";
        return Result(new("signature_review_ready", "saved",
            "Read-only inspection of the saved signature. Nothing was changed and there is no pending save action.", null, null),
            savedMetadata);
    }

    public sealed record ReviewOutput(string status, string reviewState, string message,
        string? previewHandle, DateTimeOffset? previewExpiresAt);

    private static CallToolResult Empty(string bootstrap, string message) => Result(
        new("review_empty", "empty", message, null, null),
        new JsonObject { [bootstrap] = new JsonObject { ["available"] = false, ["message"] = message } });

    private static CallToolResult Result(ReviewOutput output, JsonObject metadata) => new()
    {
        StructuredContent = JsonSerializer.SerializeToElement(output),
        Content = [new TextContentBlock { Text = JsonSerializer.Serialize(output) }],
        Meta = metadata
    };
}
