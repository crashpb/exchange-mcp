using System.ComponentModel;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using System.Xml.Linq;
using Company.ExchangeMcp.Exchange;
using Company.ExchangeMcp.Security;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;

namespace Company.ExchangeMcp;

[McpServerToolType]
public sealed class SignatureTestTools(EwsClient exchange, MailboxAccess access, MailboxHandles handles,
    AuditLog audit, SignatureStore signatures, SignaturePreviewStore previews)
{
    [McpServerTool(Name = "mail_signature_test_draft", ReadOnly = false, Destructive = false, Idempotent = false, OpenWorld = false)]
    [Description("After the user chooses 'send a test to myself', create one unsent test draft using the exact signature preview and inline images. The recipient is fixed to the signed-in user's own mailbox, with no Cc/Bcc. Does not save a signature, change defaults or send. Show the returned recipients/subject/signature preview, then use ordinary mail_send_draft only if the user requested sending. One draft attempt per preview; never repeat an uncertain attempt. The same preview can still be committed after the user checks Outlook. Own mailbox only.")]
    public async Task<CallToolResult> Create(ClaimsPrincipal user, string previewHandle, CancellationToken cancellationToken)
    {
        var identity = access.RequireOwn(user, MailboxAccess.Write);
        var operationId = Guid.NewGuid().ToString("N");
        await audit.RecordAsync(identity, "signature_test_draft", "started", operationId, cancellationToken);
        CallToolResult result;
        try
        {
            var candidate = previews.Peek(identity, previewHandle);
            var current = await signatures.ReadAsync(exchange, identity.Mailbox, cancellationToken);
            if (current.Revision != candidate.Revision)
                throw new McpException("Signature settings changed after preview. Prepare a new preview before testing.");
            if (candidate.SourceId is not null)
            {
                var source = await exchange.GetMessageAsync(identity.Mailbox, candidate.SourceId, cancellationToken);
                if (source.Id != candidate.SourceId || source.ChangeKey != candidate.SourceChangeKey)
                    throw new McpException("The source email changed after preview. Capture it again before testing.");
            }
            candidate = previews.BeginTest(identity, previewHandle);
            var profile = candidate.Profile;
            var subject = candidate.Language == "fa" ? "Exchange MCP — آزمایش امضا" : "Exchange MCP — Signature test";
            EwsItemRef draft;
            try
            {
                draft = await exchange.CreateDraftAsync(identity.Mailbox,
                    new(subject, profile.Body, [identity.Mailbox], [], [], profile.BodyType), cancellationToken);
                foreach (var image in profile.Images)
                {
                    var attachment = await exchange.CreateFileAttachmentAsync(identity.Mailbox, draft.Id, draft.ChangeKey,
                        image.Name, Convert.FromBase64String(image.ContentBase64), image.ContentType, cancellationToken,
                        isInline: true, contentId: image.ContentId);
                    draft = attachment.Parent;
                    if (string.IsNullOrEmpty(draft.ChangeKey))
                    {
                        var refreshed = await exchange.GetMessageAsync(identity.Mailbox, draft.Id, cancellationToken);
                        if (!refreshed.IsDraft || string.IsNullOrEmpty(refreshed.ChangeKey))
                            throw new InvalidOperationException("The test draft could not be refreshed.");
                        draft = new(refreshed.Id, refreshed.ChangeKey);
                    }
                }
                var saved = await exchange.GetMessageAsync(identity.Mailbox, draft.Id, cancellationToken);
                if (!saved.IsDraft || string.IsNullOrEmpty(saved.ChangeKey) || saved.Subject != subject
                    || saved.To.Count != 1 || !string.Equals(saved.To[0], identity.Mailbox, StringComparison.OrdinalIgnoreCase)
                    || saved.Cc.Count != 0 || saved.Bcc.Count != 0 || !MatchesBody(saved, profile)
                    || saved.Attachments.Count != profile.Images.Length
                    || profile.Images.Any(image => !saved.Attachments.Any(attachment => attachment.IsInline
                        && attachment.ContentId == image.ContentId && attachment.ContentType == image.ContentType
                        && attachment.Name == image.Name && attachment.Size == Convert.FromBase64String(image.ContentBase64).Length)))
                    throw new InvalidOperationException("The test draft verification failed.");
                foreach (var image in profile.Images)
                {
                    var attachment = saved.Attachments.Single(item => item.ContentId == image.ContentId);
                    var content = await exchange.GetAttachmentAsync(identity.Mailbox, attachment.Id, cancellationToken);
                    if (!CryptographicOperations.FixedTimeEquals(content.Content, Convert.FromBase64String(image.ContentBase64)))
                        throw new InvalidOperationException("The test draft image verification failed.");
                }
                draft = new(saved.Id, saved.ChangeKey);
            }
            catch
            {
                throw new McpException("A signature test draft may have been created, but its write or verification is uncertain. Inspect Drafts for the Exchange MCP signature test; do not repeat this test or send an unverified draft.");
            }
            var view = new
            {
                status = "signature_test_draft_ready",
                sent = false,
                signatureSaved = false,
                draftHandle = handles.Issue(identity, "message", draft.Id, draft.ChangeKey),
                to = new[] { identity.Mailbox },
                cc = Array.Empty<string>(),
                bcc = Array.Empty<string>(),
                subject,
                bodyPreview = RichBody.Preview(profile.Body, profile.BodyType),
                images = profile.Images.Select(image => new
                {
                    image.Name,
                    image.ContentType,
                    sizeBytes = Convert.FromBase64String(image.ContentBase64).Length
                }),
                nextAction = "Only if the user requested the self-test send, call mail_send_draft with draftHandle using its normal approval. Ask them to inspect the received signature in Outlook, then commit the same preview only after confirmation. Do not automatically delete their test email."
            };
            result = new()
            {
                StructuredContent = JsonSerializer.SerializeToElement(view),
                Content = [new TextContentBlock { Text = JsonSerializer.Serialize(view) }]
            };
        }
        catch
        {
            await audit.RecordAsync(identity, "signature_test_draft", "failed_or_uncertain", operationId, CancellationToken.None);
            throw;
        }
        try { await audit.RecordAsync(identity, "signature_test_draft", "completed", operationId, CancellationToken.None); }
        catch { throw new McpException("The test draft completed but audit recording failed. Do not repeat it; inspect Drafts."); }
        return result;
    }

    private static bool MatchesBody(EwsMessage message, MailSignature profile)
    {
        if (message.Body is null || message.BodyType != profile.BodyType) return false;
        if (profile.BodyType == "Text") return message.Body == profile.Body;
        try
        {
            return XNode.DeepEquals(ComparisonTree(message.Body), ComparisonTree(profile.Body));
        }
        catch (Exception exception) when (exception is ArgumentException or System.Xml.XmlException or InvalidOperationException)
        { return false; }
    }

    private static XElement ComparisonTree(string body)
    {
        var root = XElement.Parse("<root>" + RichBody.NormalizeExchangeHtml(body) + "</root>", LoadOptions.PreserveWhitespace);
        foreach (var head in root.Descendants().Where(element =>
                     element.Name.LocalName.Equals("head", StringComparison.OrdinalIgnoreCase)).ToArray())
        {
            if (!string.IsNullOrWhiteSpace(head.Value) || head.HasElements)
                throw new InvalidOperationException("The test draft contains unexpected header content.");
            head.Remove();
        }
        foreach (var envelope in root.Descendants().Where(element =>
                     element.Name.LocalName.Equals("html", StringComparison.OrdinalIgnoreCase)
                     || element.Name.LocalName.Equals("body", StringComparison.OrdinalIgnoreCase)).ToArray())
            envelope.ReplaceWith(envelope.Nodes().ToArray());
        foreach (var element in root.Descendants())
        {
            element.Name = element.Name.LocalName.ToLowerInvariant();
            var attributes = element.Attributes().Where(attribute => !attribute.IsNamespaceDeclaration)
                .Select(attribute => new XAttribute(attribute.Name.LocalName.ToLowerInvariant(),
                    attribute.Name.LocalName.Equals("style", StringComparison.OrdinalIgnoreCase)
                        ? string.Join(";", attribute.Value.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                            .Select(declaration => declaration.Split(':', 2, StringSplitOptions.TrimEntries))
                            .Select(pair => pair[0].ToLowerInvariant() + ":" + pair[1]).Order(StringComparer.Ordinal))
                        : attribute.Value)).OrderBy(attribute => attribute.Name.LocalName, StringComparer.Ordinal).ToArray();
            element.ReplaceAttributes(attributes);
        }
        return root;
    }
}
