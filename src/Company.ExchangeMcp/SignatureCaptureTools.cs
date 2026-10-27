using System.ComponentModel;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Xml.Linq;
using Company.ExchangeMcp.Exchange;
using Company.ExchangeMcp.Security;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;

namespace Company.ExchangeMcp;

[McpServerToolType]
public sealed class SignatureCaptureTools(EwsClient exchange, MailboxAccess access, MailboxHandles handles,
    AuditLog audit, SignatureStore signatures, SignaturePreviewStore previews)
{
    private const int MaxNameLength = 80;
    private static readonly JsonSerializerOptions Json = new() { MaxDepth = 12 };

    [McpServerTool(Name = "mail_capture_signature", ReadOnly = true, Destructive = false, Idempotent = true, OpenWorld = false,
        UseStructuredContent = true, OutputSchemaType = typeof(CaptureOutput))]
    [Description("Copy a signature from exactly one email the user chose. Pass its current handle from mail_search/mail_read; if multiple signature parts are found, ask the user to choose one returned part ID. Copy supported source formatting and only referenced inline PNG/JPEG/GIF images; report omitted formatting warnings. Returns an unsaved candidate preview and a 15-minute handle, not a preview or repair of an existing saved profile. Name collisions require the user's explicit replacement approval. Show the preview and wait for explicit confirmation before calling mail_commit_signature; verify the saved result before claiming the profile was updated. Own mailbox only; never send email.")]
    public Task<CallToolResult> Capture(ClaimsPrincipal user, string messageHandle, string name,
        CancellationToken cancellationToken, string? part = null, bool makeDefaultForNew = false,
        bool makeDefaultForReplies = false, bool replaceExisting = false) =>
        Run(user, MailboxAccess.Read, "signature_capture", async (identity, ct) =>
        {
            RequireSession(identity);
            if (name is null || name.Length > MaxNameLength || name.Any(char.IsControl) || HasHiddenBidi(name))
                throw new McpException("Choose a signature name up to 80 characters without control or hidden direction characters.");

            var snapshot = await signatures.ReadAsync(exchange, identity.Mailbox, ct).ConfigureAwait(false);
            if (snapshot.Settings.Onboarding is { Status: "pending", Language: null })
                throw new McpException("Choose your onboarding language with mail_onboarding_update before capturing a signature.");
            var messageRef = handles.Resolve(identity, "message", messageHandle);
            if (string.IsNullOrWhiteSpace(messageRef.ChangeKey))
                throw new McpException("This message handle has no current change key. Read the chosen email again.");
            var message = await exchange.GetMessageAsync(identity.Mailbox, messageRef.Id, ct).ConfigureAwait(false);
            RequireCurrentSource(messageRef, message);
            if (string.IsNullOrWhiteSpace(message.Body))
                throw new McpException("The chosen email has no signature content to copy.");

            IReadOnlyList<SignatureCapturePart> parts;
            try { parts = SignatureCapture.FindParts(message.Body, message.BodyType); }
            catch (ArgumentException)
            { throw new McpException("The chosen email could not be safely inspected for a signature. Choose another email or paste the signature."); }

            if (parts.Count == 0)
                throw new McpException("No signature part was found in the chosen email. Choose another email or paste the signature.");
            if (part is null && parts.Count > 1)
                return BasicResult(new PartSelectionOutput(
                    status: "signature_part_selection_required",
                    parts: parts.Select(candidate => new CapturePart(candidate.Id, candidate.Kind,
                        candidate.TextPreview, candidate.Warnings)).ToArray(),
                    instruction: "Ask the user which part to copy, then call mail_capture_signature again with that part ID."),
                    "Several signature areas were found. Choose one part ID before previewing.");

            var selected = part is null ? parts.Single()
                : parts.SingleOrDefault(candidate => string.Equals(candidate.Id, part, StringComparison.Ordinal));
            if (selected is null)
                throw new McpException("That signature part ID is not in the chosen email. Use one of the returned part IDs.");

            SignatureCaptureResult extracted;
            try { extracted = SignatureCapture.Extract(message.Body, message.BodyType, selected.Id); }
            catch (ArgumentException)
            { throw new McpException("That signature part could not be safely copied. Choose another part or paste the signature."); }
            var bodyType = extracted.BodyType;
            var body = extracted.Body;
            var copiedImages = await CopyReferencedImagesAsync(identity.Mailbox, message, extracted.ReferencedContentIds, ct)
                .ConfigureAwait(false);
            body = bodyType == "HTML" ? RewriteContentIds(body, copiedImages.ContentIds) : body;
            var images = copiedImages.Images;
            if (HasHiddenBidi(name) || HasHiddenBidi(body) || images.Any(image => HasHiddenBidi(image.Name)))
                throw new McpException("The chosen signature contains hidden direction controls. Choose another part or remove those controls before saving.");
            body = RichBody.Validate(body, bodyType);
            if (HasHiddenBidi(body))
                throw new McpException("The chosen signature contains hidden direction controls. Choose another part or remove those controls before saving.");
            var profile = new MailSignature(name, body, bodyType, images);
            SignatureStore.Validate(new([profile], null, null));

            var language = snapshot.Settings.Onboarding?.Language ?? (ContainsPersian(body) ? "fa" : "en");
            var candidate = new SignaturePreviewCandidate(profile, snapshot.Revision, makeDefaultForNew,
                makeDefaultForReplies, replaceExisting, language,
                snapshot.Settings.Onboarding is { Status: "pending", Language: "fa" or "en" },
                message.Id, message.ChangeKey, extracted.Warnings.ToArray());
            var updated = SignaturePreviewStore.ApplyCandidate(snapshot.Settings, candidate);
            var previewHandle = previews.Stage(identity, candidate);
            return PreviewResult(previewHandle, candidate, updated, snapshot.Settings,
                new CaptureSource(message.Subject, message.From, message.ReceivedUtc, selected.Kind),
                images);
        }, cancellationToken);

    [McpServerTool(Name = "mail_commit_signature", ReadOnly = false, Destructive = false, Idempotent = false, OpenWorld = false)]
    [Description("Save a signature preview only after showing it and receiving the user's explicit confirmation. Pass its exact previewHandle once. The server rechecks the selected email's change key, the signature settings revision and quotas; it consumes the preview before the atomic profile update. If the result is uncertain, call mail_signatures and mail_onboarding to verify before starting a new preview. Own mailbox only; never sends email.")]
    public Task<CallToolResult> Commit(ClaimsPrincipal user, string previewHandle, CancellationToken cancellationToken) =>
        Run(user, MailboxAccess.Write, "signature_commit", async (identity, ct) =>
        {
            RequireSession(identity);
            var candidate = previews.Peek(identity, previewHandle);
            var current = await signatures.ReadAsync(exchange, identity.Mailbox, ct).ConfigureAwait(false);
            if (!string.Equals(current.Revision, candidate.Revision, StringComparison.Ordinal))
                throw new McpException("Signature settings changed after this preview. Read mail_signatures and preview again.");
            if (candidate.SourceId is not null)
            {
                var source = await exchange.GetMessageAsync(identity.Mailbox, candidate.SourceId, ct).ConfigureAwait(false);
                if (!string.Equals(source.Id, candidate.SourceId, StringComparison.Ordinal)
                    || !string.Equals(source.ChangeKey, candidate.SourceChangeKey, StringComparison.Ordinal))
                    throw new McpException("The source email changed after preview. Capture it again before saving.");
            }
            _ = SignaturePreviewStore.ApplyCandidate(current.Settings, candidate);

            var consumed = previews.Consume(identity, previewHandle);
            var saved = await signatures.UpdateAsync(exchange, identity.Mailbox, consumed.Revision,
                before => SignaturePreviewStore.ApplyCandidate(before, consumed), ct).ConfigureAwait(false);
            return BasicResult(new
            {
                status = "signature_saved",
                signatureName = consumed.Profile.Name,
                profiles = saved.Settings.Profiles.Select(profile => profile.Name).ToArray(),
                defaults = new { newMessages = saved.Settings.NewMessages, replies = saved.Settings.Replies },
                onboardingStatus = saved.Settings.Onboarding?.Status,
                nextStep = saved.Settings.Onboarding?.Status == "pending" ? "more_signatures_and_rules" : null,
                instruction = saved.Settings.Onboarding?.Status == "pending"
                    ? "Ask whether the user wants more signature profiles. If multiple profiles exist, ask about special use rules and save approved supported preferences with mail_signature_rules. Explicitly finish onboarding only after the user's answers."
                    : null,
                revision = saved.Revision,
                usage = saved.Usage
            }, "The signature profile was saved.");
        }, cancellationToken);

    private async Task<CopiedImages> CopyReferencedImagesAsync(string mailbox, EwsMessage message,
        IReadOnlyList<string> referencedContentIds, CancellationToken cancellationToken)
    {
        if (referencedContentIds.Count > SignatureStore.MaxImagesPerProfile)
            throw new McpException("This signature references more than 8 inline images. Choose a simpler part.");
        var normalizedReferences = referencedContentIds.Select(NormalizeContentId).ToArray();
        if (normalizedReferences.Any(string.IsNullOrWhiteSpace)
            || normalizedReferences.Distinct(StringComparer.OrdinalIgnoreCase).Count() != normalizedReferences.Length)
            throw new McpException("The signature contains duplicate or invalid image references. Choose another part.");

        var images = new List<SignatureImage>(normalizedReferences.Length);
        var contentIds = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var totalBytes = 0;
        for (var index = 0; index < normalizedReferences.Length; index++)
        {
            var contentId = normalizedReferences[index];
            if (contentId.Length is 0 or > 512 || contentId.Any(char.IsControl))
                throw new McpException("The signature contains an invalid inline image reference.");
            var matches = message.Attachments.Where(attachment =>
                string.Equals(NormalizeContentId(attachment.ContentId), contentId, StringComparison.OrdinalIgnoreCase)).ToArray();
            if (matches.Length != 1 || !matches[0].IsInline)
                throw new McpException("An inline image in the selected signature is missing or ambiguous. Choose another part.");
            var metadata = matches[0];
            var type = NormalizeImageType(metadata.ContentType);
            if (type is null)
                throw new McpException("Signature images must be inline PNG, JPEG or GIF files within the mailbox image limits.");

            var content = await exchange.GetAttachmentAsync(mailbox, metadata.Id, cancellationToken).ConfigureAwait(false);
            if (content.Id != metadata.Id || content.Name != metadata.Name || !content.IsInline
                || !string.Equals(NormalizeContentId(content.ContentId), contentId, StringComparison.OrdinalIgnoreCase)
                || NormalizeImageType(content.ContentType) != type
                || !RichBody.HasImageHeader(content.Content, type))
                throw new McpException("An inline image did not match the selected email's verified attachment metadata.");

            if (content.Content.Length is < 1 or > SignatureStore.MaxImageBytes
                || totalBytes + content.Content.Length > SignatureStore.MaxTotalImageBytes)
                throw new McpException("Signature images must be inline PNG, JPEG or GIF files within the mailbox image limits.");

            totalBytes += content.Content.Length;
            var digest = Convert.ToHexString(SHA256.HashData(content.Content)).ToLowerInvariant()[..16];
            var extension = type switch { "image/jpeg" => "jpg", "image/gif" => "gif", _ => "png" };
            var newContentId = $"signature-image-{index + 1}-{digest}";
            images.Add(new($"signature-image-{index + 1}.{extension}", type,
                newContentId, Convert.ToBase64String(content.Content)));
            contentIds.Add(contentId, newContentId);
        }

        var refreshed = await exchange.GetMessageAsync(mailbox, message.Id, cancellationToken).ConfigureAwait(false);
        if (!string.Equals(refreshed.ChangeKey, message.ChangeKey, StringComparison.Ordinal))
            throw new McpException("The source email changed while its signature was being copied. Capture it again.");
        return new(images.ToArray(), contentIds);
    }

    private static string RewriteContentIds(string body, IReadOnlyDictionary<string, string> contentIds)
    {
        try
        {
            var root = XElement.Parse("<root>" + body + "</root>", LoadOptions.PreserveWhitespace);
            var sourceIds = new List<string>();
            foreach (var image in root.Descendants().Where(element => element.Name.LocalName.Equals("img", StringComparison.OrdinalIgnoreCase)))
            {
                var source = image.Attributes().SingleOrDefault(attribute =>
                    attribute.Name.LocalName.Equals("src", StringComparison.OrdinalIgnoreCase));
                if (source is null || !source.Value.StartsWith("cid:", StringComparison.OrdinalIgnoreCase))
                    throw new McpException("The selected signature contains an image that is not an inline CID attachment.");
                var contentId = NormalizeContentId(source.Value[4..]);
                if (!contentIds.TryGetValue(contentId, out var replacement))
                    throw new McpException("An inline image in the selected signature could not be matched safely.");
                source.Value = "cid:" + replacement;
                sourceIds.Add(contentId);
            }
            if (sourceIds.Distinct(StringComparer.OrdinalIgnoreCase).Count() != contentIds.Count)
                throw new McpException("The selected signature image references did not match the copied inline images.");
            return string.Concat(root.Nodes().Select(node => node.ToString(SaveOptions.DisableFormatting)));
        }
        catch (McpException) { throw; }
        catch (Exception exception) when (exception is System.Xml.XmlException or InvalidOperationException or ArgumentException)
        { throw new McpException("The selected signature's inline image references could not be rewritten safely."); }
    }

    private CallToolResult PreviewResult(string handle, SignaturePreviewCandidate candidate, SignatureSettings updated,
        SignatureSettings before, CaptureSource source, IReadOnlyList<SignatureImage> images)
    {
        // The parser's candidate excerpt is intentionally short for disambiguation only.
        // The final fallback must include every name, contact detail and disclaimer.
        var textPreview = RichBody.Preview(candidate.Profile.Body, candidate.Profile.BodyType);
        var defaultChanges = new CaptureDefaults(
            newMessages: updated.NewMessages,
            replies: updated.Replies,
            willChangeNewMessages: candidate.MakeDefaultForNew
                || before.NewMessages is not null && string.Equals(before.NewMessages, candidate.Profile.Name, StringComparison.OrdinalIgnoreCase),
            willChangeReplies: candidate.MakeDefaultForReplies
                || before.Replies is not null && string.Equals(before.Replies, candidate.Profile.Name, StringComparison.OrdinalIgnoreCase));
        var data = new CapturePreviewOutput(
            status: "signature_preview_ready",
            signatureName: candidate.Profile.Name,
            textPreview,
            bodyType: candidate.Profile.BodyType,
            imageCount: images.Count,
            layout: SummarizeLayout(candidate.Profile),
            images: images.Select(image => new CaptureImage(
                image.Name,
                image.ContentType,
                sizeBytes: Convert.FromBase64String(image.ContentBase64).Length,
                sha256: Convert.ToHexString(SHA256.HashData(Convert.FromBase64String(image.ContentBase64))).ToLowerInvariant())).ToArray(),
            defaults: defaultChanges,
            replacesExistingProfile: before.Profiles.Any(profile =>
                string.Equals(profile.Name, candidate.Profile.Name, StringComparison.OrdinalIgnoreCase)),
            source,
            warnings: candidate.Warnings,
            previewHandle: handle,
            expiresInSeconds: (int)SignaturePreviewStore.Lifetime.TotalSeconds,
            confirmationInstruction: "Show this preview and proposed defaults. Save only after the user explicitly confirms by calling mail_commit_signature with this previewHandle.");
        return new CallToolResult
        {
            Content = [new TextContentBlock { Text = $"Signature preview ready: {candidate.Profile.Name}. {data.textPreview}\nProposed defaults: new messages={updated.NewMessages ?? "none"}; replies={updated.Replies ?? "none"}. Confirm before saving." }],
            StructuredContent = JsonSerializer.SerializeToElement(data, Json),
            Meta = SignaturePreviewResources.CreateMetadata(candidate.Profile, candidate.Language,
                new { forNewMessages = updated.NewMessages, forReplies = updated.Replies }, candidate.Warnings ?? [])
        };
    }

    private static CaptureLayout SummarizeLayout(MailSignature profile)
    {
        if (profile.BodyType != "HTML") return new(0, 0, 0);
        var root = XElement.Parse("<root>" + RichBody.Validate(profile.Body, "HTML") + "</root>", LoadOptions.PreserveWhitespace);
        return new(
            rows: root.Descendants().Count(element => element.Name.LocalName.Equals("tr", StringComparison.OrdinalIgnoreCase)),
            cells: root.Descendants().Count(element => element.Name.LocalName.Equals("td", StringComparison.OrdinalIgnoreCase)
                || element.Name.LocalName.Equals("th", StringComparison.OrdinalIgnoreCase)),
            images: root.Descendants().Count(element => element.Name.LocalName.Equals("img", StringComparison.OrdinalIgnoreCase)));
    }

    [JsonDerivedType(typeof(PartSelectionOutput))]
    [JsonDerivedType(typeof(CapturePreviewOutput))]
    public abstract record CaptureOutput(string status);
    public sealed record PartSelectionOutput(string status, IReadOnlyList<CapturePart> parts,
        string instruction) : CaptureOutput(status);
    public sealed record CapturePreviewOutput(string status, string signatureName, string textPreview, string bodyType,
        int imageCount, CaptureLayout layout, IReadOnlyList<CaptureImage> images, CaptureDefaults defaults,
        bool replacesExistingProfile, CaptureSource source, IReadOnlyList<string>? warnings, string previewHandle,
        int expiresInSeconds, string confirmationInstruction) : CaptureOutput(status);
    public sealed record CaptureLayout(int rows, int cells, int images);
    public sealed record CapturePart([property: JsonPropertyName("Id")] string Id,
        [property: JsonPropertyName("Kind")] string Kind,
        [property: JsonPropertyName("TextPreview")] string TextPreview,
        [property: JsonPropertyName("Warnings")] IReadOnlyList<string> Warnings);
    public sealed record CaptureImage([property: JsonPropertyName("Name")] string Name,
        [property: JsonPropertyName("ContentType")] string ContentType, int sizeBytes, string sha256);
    public sealed record CaptureDefaults(string? newMessages, string? replies, bool willChangeNewMessages, bool willChangeReplies);
    public sealed record CaptureSource(string subject, string? from, string? receivedUtc, string part);

    private static CallToolResult BasicResult<T>(T data, string text) => new()
    {
        Content = [new TextContentBlock { Text = text }],
        StructuredContent = JsonSerializer.SerializeToElement(data, Json)
    };

    private async Task<CallToolResult> Run(ClaimsPrincipal user, string scope, string operation,
        Func<MailboxIdentity, CancellationToken, Task<CallToolResult>> action, CancellationToken cancellationToken)
    {
        var identity = access.RequireOwn(user, scope);
        var operationId = Guid.NewGuid().ToString("N");
        await audit.RecordAsync(identity, operation, "started", operationId, cancellationToken).ConfigureAwait(false);
        CallToolResult result;
        try { result = await action(identity, cancellationToken).ConfigureAwait(false); }
        catch
        {
            await audit.RecordAsync(identity, operation, "failed_or_uncertain", operationId, CancellationToken.None).ConfigureAwait(false);
            throw;
        }
        try { await audit.RecordAsync(identity, operation, "completed", operationId, CancellationToken.None).ConfigureAwait(false); }
        catch { throw new McpException("The operation completed but audit recording failed. Do not repeat it; contact the administrator."); }
        return result;
    }

    private static void RequireCurrentSource(MailboxHandle reference, EwsMessage current)
    {
        if (current.Id != reference.Id || string.IsNullOrEmpty(current.ChangeKey)
            || !string.Equals(current.ChangeKey, reference.ChangeKey, StringComparison.Ordinal))
            throw new McpException("This email handle is stale or no longer identifies the same message. Read the chosen email again.");
    }

    private static void RequireSession(MailboxIdentity identity)
    {
        if (string.IsNullOrWhiteSpace(identity.SessionId))
            throw new McpException("Signature capture requires a session-bound connection. Reconnect Exchange MCP and try again.");
    }

    private static bool HasHiddenBidi(string value) => value.Any(character =>
        character is >= '\u202A' and <= '\u202E' or >= '\u2066' and <= '\u2069');

    private static bool ContainsPersian(string value) => value.Any(character =>
        character is >= '\u0600' and <= '\u06FF' or >= '\u0750' and <= '\u077F'
            or >= '\u08A0' and <= '\u08FF' or >= '\uFB50' and <= '\uFDFF' or >= '\uFE70' and <= '\uFEFF');

    private static string NormalizeContentId(string? value)
    {
        var contentId = value?.Trim() ?? string.Empty;
        return contentId.Length >= 2 && contentId[0] == '<' && contentId[^1] == '>'
            ? contentId[1..^1] : contentId;
    }

    private static string? NormalizeImageType(string? value) => value?.Trim().ToLowerInvariant() switch
    {
        "image/png" => "image/png",
        "image/jpeg" => "image/jpeg",
        "image/gif" => "image/gif",
        _ => null
    };

    private sealed record CopiedImages(SignatureImage[] Images, IReadOnlyDictionary<string, string> ContentIds);
}
