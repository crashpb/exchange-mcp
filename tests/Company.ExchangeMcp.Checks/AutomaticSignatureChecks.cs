using System.Text.Json;
using System.Xml.Linq;
using Company.ExchangeMcp;
using Company.ExchangeMcp.Exchange;
using Company.ExchangeMcp.Security;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Options;
using ModelContextProtocol;

internal sealed partial class Checks
{
    private async Task AutomaticSignatureChecksAsync()
    {
        await AutomaticSignatureSelectionChecksAsync();
        await AutomaticSignatureFailureChecksAsync();
        await SignatureSaveImagePreservationChecksAsync();
        await SignatureExactIdempotenceChecksAsync();
        await SignatureTextQuoteChecksAsync();
        await SignatureHtmlSourceTextReplyChecksAsync();
        await SignatureNativeOfficeSharedImageChecksAsync();
        await ExistingSignaturePreviewEditChecksAsync();
        await SignatureEwsSerializationChecksAsync();
    }

    private async Task SignatureNativeOfficeSharedImageChecksAsync()
    {
        const string original = "<html><head><meta name='Generator' content='Microsoft Word 15' /><style><!-- p.MsoNormal { mso-margin-top-alt:auto; font-family:\"B Nazanin\"; } --></style></head><body><p class='MsoNormal' dir='rtl' style='unicode-bidi:embed'>Quoted Office mail<img src='cid:source-logo' /></p></body></html>";
        foreach (var forward in new[] { false, true })
        {
            var handler = new SignatureCaptureFlowHandler { SourceHtml = original };
            var exchange = NewEwsClient(handler);
            var options = SignatureReuseOptions(forward ? "office-forward-shared-image" : "office-reply-shared-image");
            using var audit = new AuditLog(options);
            var access = new MailboxAccess(options);
            var handles = new MailboxHandles(new EphemeralDataProtectionProvider());
            var store = new SignatureStore();
            const string signature = "<p>Saved shared logo<img src='cid:source-logo' /></p>";
            var image = new SignatureImage("brand.png", "image/png", "source-logo", handler.SourceImageBase64);
            await store.UpdateAsync(exchange, "alice@example.test", "new", _ => new(
                [new("Default", signature, "HTML", [image])], "Default", "Default"), CancellationToken.None);
            var configuration = handler.SignatureConfiguration!;
            var mailbox = new MailboxTools(exchange, access, handles, audit, null!, null!, null!, store);
            var user = SignatureTestUser("user-a", "alice@example.test", "checks", "session-1", "mail.read mail.write");
            var source = handles.Issue(PreviewIdentity(), "message", handler.SourceId, handler.SourceChangeKey);
            var result = JsonSerializer.SerializeToElement(forward
                ? await mailbox.ForwardDraft(user, source, "Fresh forward", ["to@example.test"], CancellationToken.None)
                : await mailbox.ReplyDraft(user, source, "Fresh reply", CancellationToken.None, to: ["to@example.test"]));
            var reference = handles.Resolve(PreviewIdentity(), "message", result.GetProperty("handle").GetString()!);
            var readback = await exchange.GetMessageAsync("alice@example.test", reference.Id, CancellationToken.None);
            var root = RichBody.ParseExchangeHtml(readback.Body!);
            Expect(result.GetProperty("readyToSend").GetBoolean()
                && result.GetProperty("signatureStatus").GetString() == "signature_applied"
                && readback.BodyType == "HTML"
                && root.Descendants("meta").Any(element => (string?)element.Attribute("name") == "Generator")
                && root.Descendants("style").Single().Nodes().OfType<XComment>().Single().Value.Contains("mso-margin-top-alt:auto", StringComparison.Ordinal)
                && root.Descendants("img").Count(element => (string?)element.Attribute("src") == "cid:source-logo") == 2
                && readback.Attachments.Count == 1 && readback.Attachments.Single().IsInline
                && handler.AttachmentWrites == 0 && handler.SendItemCalls == 0
                && configuration.AsSpan().SequenceEqual(handler.SignatureConfiguration!),
                "A native Office reply/forward lost passive history, flattened HTML, duplicated a quoted logo, or changed the saved profile.");
            var tools = new SignatureTools(exchange, access, handles, audit, store);
            var writes = handler.DraftUpdates;
            var reapplied = JsonSerializer.SerializeToElement(await tools.Apply(user, result.GetProperty("handle").GetString()!,
                CancellationToken.None, context: "reply"));
            Expect(reapplied.GetProperty("status").GetString() == "signature_already_applied"
                && handler.DraftUpdates == writes && handler.AttachmentWrites == 0,
                "Reapplying a shared-image native signature duplicated the body or attachment.");
        }
    }
    private async Task SignatureHtmlSourceTextReplyChecksAsync()
    {
        const string original = "<div dir='rtl'><table style='font-family:Peyda;font-size:12pt'><tr><td>متن اصلی<img src='cid:source-logo' /></td></tr></table></div>";
        var handler = new SignatureCaptureFlowHandler { SourceHtml = original };
        var exchange = NewEwsClient(handler);
        var options = SignatureReuseOptions("html-source-text-reply");
        using var audit = new AuditLog(options);
        var access = new MailboxAccess(options);
        var handles = new MailboxHandles(new EphemeralDataProtectionProvider());
        var store = new SignatureStore();
        var signatureImage = new SignatureImage("own.png", "image/png", "own-logo", handler.SourceImageBase64);
        var saved = await store.UpdateAsync(exchange, "alice@example.test", "new", _ => new(
            [new("Default", "<p id='own-signature'>Own signature<img src='cid:own-logo' /></p>", "HTML", [signatureImage])],
            "Default", "Default"), CancellationToken.None);
        var configuration = handler.SignatureConfiguration!;
        var tools = new MailboxTools(exchange, access, handles, audit, null!, null!, null!, store);
        var user = SignatureTestUser("user-a", "alice@example.test", "checks", "session-1", "mail.read mail.write");
        var source = handles.Issue(PreviewIdentity(), "message", handler.SourceId, handler.SourceChangeKey);
        var result = JsonSerializer.SerializeToElement(await tools.ReplyDraft(user, source, "پاسخ <literal> &\r\nSecond line", CancellationToken.None));
        var body = handler.LastCreatedBody!;
        var root = XElement.Parse(body);
        var draft = await exchange.GetMessageAsync("alice@example.test", "draft-1", CancellationToken.None);
        var native = handler.Operations.Single(operation => operation.Name.LocalName == "CreateItem");
        var reference = native.Descendants(XName.Get("ReferenceItemId", TypesNamespace)).Single();
        Expect(result.GetProperty("readyToSend").GetBoolean() && result.GetProperty("signatureStatus").GetString() == "signature_applied"
            && handler.LastCreatedBodyType == "HTML"
            && root.Value.Contains("پاسخ <literal> &", StringComparison.Ordinal)
            && root.Descendants("table").Single().Attribute("style")?.Value == "font-family:Peyda;font-size:12pt"
            && root.Descendants("div").Any(element => element.Attribute("dir")?.Value == "rtl")
            && body.IndexOf("id=\"own-signature\"", StringComparison.Ordinal) < body.IndexOf("<hr", StringComparison.Ordinal)
            && root.Descendants("img").Count() == 2
            && draft.Attachments.Count == 2 && draft.Attachments.All(image => image.IsInline)
            && draft.Attachments.Select(image => image.ContentId).Distinct().Count() == 2
            && handler.AttachmentWrites == 1 && handler.CreatedAttachmentBytes.Single().SequenceEqual(Convert.FromBase64String(signatureImage.ContentBase64))
            && reference.Attribute("Id")?.Value == handler.SourceId && reference.Attribute("ChangeKey")?.Value == handler.SourceChangeKey
            && handler.DraftCreates == 1 && handler.SendItemCalls == 0,
            "The production Text reply path lost source RTL/font/table/CID, misplaced or duplicated the own signature/image, or changed native thread binding.");
        var after = await store.ReadAsync(exchange, "alice@example.test", CancellationToken.None);
        Expect(after.Revision == saved.Revision && handler.SignatureConfiguration!.SequenceEqual(configuration)
            && after.Settings.Replies == "Default" && after.Settings.NewMessages == "Default",
            "Reply composition changed the stored signature/defaults or profile bytes.");
        handler.DraftBodyReadback = html =>
        {
            var changed = XElement.Parse(html);
            changed.Descendants("img").Where(image => (string?)image.Attribute("src") == "cid:source-logo").Remove();
            return changed.ToString(SaveOptions.DisableFormatting);
        };
        var incomplete = JsonSerializer.SerializeToElement(await tools.ReplyDraft(user, source, "Keep the original image", CancellationToken.None,
            includeSignature: false));
        Expect(incomplete.GetProperty("status").GetString() == "draft_incomplete"
            && !incomplete.GetProperty("readyToSend").GetBoolean()
            && incomplete.GetProperty("warning").GetString()?.Contains("(phase: quoted_images)", StringComparison.Ordinal) == true
            && handler.DraftCreates == 2 && handler.AttachmentWrites == 1 && handler.SendItemCalls == 0,
            "A production reply with a lost source image was reported ready to send or copied/retried its attachment.");
    }

    private async Task AutomaticSignatureSelectionChecksAsync()
    {
        var handler = new SignatureCaptureFlowHandler();
        var exchange = NewEwsClient(handler);
        var options = SignatureReuseOptions("selection");
        using var audit = new AuditLog(options);
        var access = new MailboxAccess(options);
        var handles = new MailboxHandles(new EphemeralDataProtectionProvider());
        var store = new SignatureStore();
        var mailbox = new MailboxTools(exchange, access, handles, audit, null!, null!, null!, store);
        var user = SignatureTestUser("user-a", "alice@example.test", "checks", "session-1", "mail.read mail.write");
        var initial = await store.UpdateAsync(exchange, "alice@example.test", "new", _ => new(
            [new("Default", "Default signature", "Text", []), new("Client", "Client signature", "Text", [])],
            "Default", "Default", UseRules: [new("Client", RecipientDomain: "example.test")]), CancellationToken.None);

        async Task<JsonElement> Create(string[]? cc = null, string[]? bcc = null, bool include = true, string? name = null) =>
            JsonSerializer.SerializeToElement(await mailbox.CreateDraft(user, "Selection", "Authored body", ["to@example.test"],
                CancellationToken.None, cc, bcc, includeSignature: include, signatureName: name));

        var rule = await Create(["cc@example.test"], ["bcc@example.test"]);
        Expect(rule.GetProperty("signature").GetString() == "Client" && rule.GetProperty("selectionSource").GetString() == "rule"
            && handler.LastCreatedBody == "Authored body\n\nClient signature",
            "Automatic creation did not apply ordered rules using every To/Cc/Bcc recipient.");
        foreach (var outside in new[] { "cc", "bcc" })
        {
            var mixed = await Create(outside == "cc" ? ["other@outside.test"] : null, outside == "bcc" ? ["other@outside.test"] : null);
            Expect(mixed.GetProperty("signature").GetString() == "Default"
                && mixed.GetProperty("warning").GetString() is not null,
                "A mixed " + outside + " recipient bypassed automatic safe default fallback.");
        }
        var named = await Create(name: "Default");
        Expect(named.GetProperty("signature").GetString() == "Default" && named.GetProperty("selectionSource").GetString() == "explicit",
            "An explicit automatic signature override did not take precedence over rules.");
        var disabled = await Create(include: false);
        Expect(disabled.GetProperty("signatureStatus").GetString() == "disabled" && handler.LastCreatedBody == "Authored body",
            "includeSignature=false still appended a signature.");
        await store.UpdateAsync(exchange, "alice@example.test", initial.Revision,
            before => before with { NewMessages = null, Replies = null, UseRules = [] }, CancellationToken.None);
        var noDefault = await Create();
        Expect(noDefault.GetProperty("signatureStatus").GetString() == "no_default_signature"
            && noDefault.GetProperty("readyToSend").GetBoolean() && handler.LastCreatedBody == "Authored body",
            "A mailbox without defaults changed the body or became an incomplete draft.");
        handler.NativeQuotedHtml = "<p style='text-underline-position:under'>Office quote</p>";
        var source = handles.Issue(PreviewIdentity(), "message", handler.SourceId, handler.SourceChangeKey);
        var noDefaultForward = JsonSerializer.SerializeToElement(await mailbox.ForwardDraft(user, source, "<p>Forward</p>",
            ["to@example.test"], CancellationToken.None, bodyType: "HTML"));
        Expect(noDefaultForward.GetProperty("signatureStatus").GetString() == "no_default_signature"
            && noDefaultForward.GetProperty("readyToSend").GetBoolean()
            && handler.LastCreatedBody!.Contains("text-underline-position:under", StringComparison.Ordinal),
            "A native forward without a selected signature unnecessarily validated or changed unsupported quoted Office HTML.");
        handler.NativeQuotedHtml = null;
        noDefault = await Create();
        var draft = noDefault.GetProperty("handle").GetString()!;
        await mailbox.EditDraft(user, draft, "Edited", "Edited body", ["to@example.test"], CancellationToken.None);
        Expect(handler.LastCreatedBody == "Edited body", "mail_edit_draft unexpectedly appended an automatic signature.");

        var selected = PreviewIdentity() with { Mailbox = "team@example.test", TargetId = "team@example.test", ActorMailbox = "alice@example.test" };
        using (access.SelectTarget(selected))
        {
            var delegated = await Create(name: "Client");
            var delegatedHandle = handles.Resolve(selected, "message", delegated.GetProperty("handle").GetString()!);
            Expect(delegatedHandle.Id.StartsWith("draft-", StringComparison.Ordinal)
                && handler.ConfigurationMailboxes[^1] == "team@example.test",
                "Automatic signatures used the actor's configuration or issued an own-mailbox handle for a selected mailbox.");
            ExpectThrows<McpException>(() => handles.Resolve(PreviewIdentity(), "message", delegated.GetProperty("handle").GetString()!),
                "A selected-mailbox automatic draft handle crossed into the actor mailbox.");
        }
        Expect(handler.SendItemCalls == 0, "Automatic signature selection sent mail.");
    }

    private async Task AutomaticSignatureFailureChecksAsync()
    {
        foreach (var failure in new[] { "configuration", "update", "image-write", "image-bytes", "partial-body", "quota", "cid-collision", "missing-name" })
        {
            var handler = new SignatureCaptureFlowHandler();
            var exchange = NewEwsClient(handler);
            var options = SignatureReuseOptions(failure);
            using var audit = new AuditLog(options);
            var access = new MailboxAccess(options);
            var handles = new MailboxHandles(new EphemeralDataProtectionProvider());
            var store = new SignatureStore();
            var image = new SignatureImage("brand.png", "image/png", "saved-logo", handler.SourceImageBase64);
            const string signature = "<table><tr><td>Saved signature<img src='cid:saved-logo' /></td></tr></table>";
            await store.UpdateAsync(exchange, "alice@example.test", "new", _ => new(
                [new("Default", signature, "HTML", [image])], "Default", "Default"), CancellationToken.None);
            var mailbox = new MailboxTools(exchange, access, handles, audit, null!, null!, null!, store);
            var user = SignatureTestUser("user-a", "alice@example.test", "checks", "session-1", "mail.read mail.write");
            handler.FailSignatureRead = failure == "configuration";
            handler.FailNextDraftUpdate = failure == "update";
            handler.FailNextAttachmentCreate = failure == "image-write";
            handler.WrongNextDraftAttachmentReadback = failure == "image-bytes";
            handler.WrongNextDraftBodyReadback = failure == "partial-body";
            handler.ExtraAttachmentCount = failure == "quota" ? EwsClient.MaxAttachments : 0;
            var body = failure == "cid-collision" ? "<p>Authored<img src='cid:saved-logo' /></p>" : "<p>Authored</p>";
            var result = JsonSerializer.SerializeToElement(await mailbox.CreateDraft(user, "Failure", body, ["to@example.test"],
                CancellationToken.None, bodyType: "HTML", signatureName: failure == "missing-name" ? "Missing" : null));
            Expect(result.GetProperty("status").GetString() == "draft_incomplete"
                && result.GetProperty("signatureStatus").GetString() == "failed_or_uncertain"
                && !result.GetProperty("readyToSend").GetBoolean()
                && !string.IsNullOrWhiteSpace(result.GetProperty("warning").GetString())
                && handler.DraftCreates == 1 && handler.SendItemCalls == 0,
                "Automatic " + failure + " failed without retaining exactly one incomplete unsent draft.");
            var retained = result.GetProperty("handle").GetString();
            Expect(retained is not null && handles.Resolve(PreviewIdentity(), "message", retained).Id == "draft-1",
                "Automatic " + failure + " discarded a recoverable draft handle.");
        }
    }

    private async Task SignatureSaveImagePreservationChecksAsync()
    {
        var handler = new SignatureCaptureFlowHandler();
        var exchange = NewEwsClient(handler);
        var options = SignatureReuseOptions("save");
        using var audit = new AuditLog(options);
        var tools = new SignatureTools(exchange, new MailboxAccess(options), new MailboxHandles(new EphemeralDataProtectionProvider()), audit,
            new SignatureStore());
        var user = SignatureTestUser("user-a", "alice@example.test", "checks", "session-1", "mail.read mail.write");
        var image = new SignatureImage("brand.png", "image/png", "saved-logo", handler.SourceImageBase64);
        var saved = (SignatureSnapshot)await tools.Save(user, "new", "Default", "<p>Before<img src='cid:saved-logo' /></p>",
            CancellationToken.None, "HTML", [image]);
        var updated = (SignatureSnapshot)await tools.Save(user, saved.Revision, "default", "<p>After<img src='cid:saved-logo' /></p>",
            CancellationToken.None, "HTML");
        Expect(updated.Settings.Profiles.Single().Images.Single() == image,
            "Omitting images from an existing profile update discarded or changed server-owned image bytes.");
        var writes = handler.ConfigurationWrites;
        await AssertThrowsAsync<McpException>(() => tools.Save(user, saved.Revision, "Default", "stale", CancellationToken.None));
        await AssertThrowsAsync<McpException>(() => tools.Save(user, updated.Revision, "Default", "<img src='cid:saved-logo' />",
            CancellationToken.None, "HTML", []));
        Expect(handler.ConfigurationWrites == writes, "A stale save or invalid explicit image clear wrote signature settings.");
        var cleared = (SignatureSnapshot)await tools.Save(user, updated.Revision, "Default", "No images", CancellationToken.None, images: []);
        Expect(cleared.Settings.Profiles.Single().Images.Length == 0, "Explicit [] did not clear unused stored signature images.");
        var created = (SignatureSnapshot)await tools.Save(user, cleared.Revision, "New text", "New text", CancellationToken.None);
        Expect(created.Settings.Profiles.Single(profile => profile.Name == "New text").Images.Length == 0,
            "A new text profile with omitted images inherited another profile's bytes.");
    }

    private async Task SignatureExactIdempotenceChecksAsync()
    {
        foreach (var bodyType in new[] { "Text", "HTML" })
        {
            var handler = new SignatureCaptureFlowHandler();
            var exchange = NewEwsClient(handler);
            var options = SignatureReuseOptions("exact-" + bodyType);
            using var audit = new AuditLog(options);
            var access = new MailboxAccess(options);
            var handles = new MailboxHandles(new EphemeralDataProtectionProvider());
            var store = new SignatureStore();
            var signature = bodyType == "Text" ? "Exact signature\r\nSecond line" : "<div><p><b>Exact signature</b></p></div>";
            await store.UpdateAsync(exchange, "alice@example.test", "new", _ => new([new("Default", signature, bodyType, []),
                new("Other", bodyType == "Text" ? "Other signature" : "<p>Other signature</p>", bodyType, [])],
                "Default", "Default"), CancellationToken.None);
            var mailbox = new MailboxTools(exchange, access, handles, audit, null!, null!, null!, store);
            var signatures = new SignatureTools(exchange, access, handles, audit, store);
            var user = SignatureTestUser("user-a", "alice@example.test", "checks", "session-1", "mail.read mail.write");
            var created = JsonSerializer.SerializeToElement(await mailbox.CreateDraft(user, "Exact", bodyType == "HTML" ? "<p>Authored</p>" : "Authored",
                ["to@example.test"], CancellationToken.None, bodyType: bodyType));
            var originalBody = handler.LastCreatedBody;
            var writes = handler.DraftUpdates;
            var applied = JsonSerializer.SerializeToElement(await signatures.Apply(user, created.GetProperty("handle").GetString()!, CancellationToken.None));
            Expect(applied.GetProperty("status").GetString() == "signature_already_applied" && handler.DraftUpdates == writes
                && handler.LastCreatedBody == originalBody, "Exact " + bodyType + " auto→manual apply was not a write-free no-op.");
            await AssertThrowsAsync<McpException>(() => signatures.Apply(user, created.GetProperty("handle").GetString()!,
                CancellationToken.None, "Other"));
            Expect(handler.DraftUpdates == writes && handler.LastCreatedBody == originalBody,
                "Applying a different saved " + bodyType + " profile appended a second signature to an already signed draft.");
            if (bodyType == "HTML")
            {
                handler.NativeQuotedHtml = signature;
                var source = handles.Issue(PreviewIdentity(), "message", handler.SourceId, handler.SourceChangeKey);
                var reply = JsonSerializer.SerializeToElement(await mailbox.ReplyDraft(user, source, "<p>New reply</p>", CancellationToken.None,
                    bodyType: "HTML"));
                var html = XElement.Parse("<root>" + handler.LastCreatedBody + "</root>");
                Expect(reply.GetProperty("signatureStatus").GetString() == "signature_applied"
                    && html.Descendants("b").Count(element => element.Value == "Exact signature") == 2,
                    "A signature inside quoted native history falsely suppressed the new authored signature.");
            }
        }
    }

    private IOptions<ServiceOptions> SignatureReuseOptions(string suffix) => Options.Create(new ServiceOptions
    {
        AllowedClientIds = ["checks"],
        Mailboxes = new() { ["user-a"] = "alice@example.test" },
        WritesEnabled = true,
        AuditPath = Path.Combine(runDirectory, "signature-reuse-" + suffix + ".jsonl")
    });

    private async Task SignatureTextQuoteChecksAsync()
    {
        foreach (var signatureType in new[] { "Text", "HTML", "HTML with trailing hr" })
        {
            foreach (var newline in new[] { "\r\n", "\n", "\r" })
            {
                var handler = new SignatureCaptureFlowHandler
                {
                    NativeQuotedText = "From: sender@example.test" + newline + "Sent: earlier" + newline + "Quoted original قدیمی" + newline + newline + "Shared footer"
                };
                var exchange = NewEwsClient(handler);
                var options = SignatureReuseOptions("quoted-text-" + signatureType + newline.Length);
                using var audit = new AuditLog(options);
                var access = new MailboxAccess(options);
                var handles = new MailboxHandles(new EphemeralDataProtectionProvider());
                var store = new SignatureStore();
                var footer = signatureType == "Text" ? "Shared footer" : "<div><p><b>Shared footer</b></p></div>"
                    + (signatureType == "HTML with trailing hr" ? "<hr />" : string.Empty);
                await store.UpdateAsync(exchange, "alice@example.test", "new", _ => new([new("Default", footer, signatureType == "Text" ? "Text" : "HTML", [])],
                    "Default", "Default", UseRules: [new("Default", Context: "reply", BodyLanguage: "en")]), CancellationToken.None);
                var mailbox = new MailboxTools(exchange, access, handles, audit, null!, null!, null!, store);
                var signatures = new SignatureTools(exchange, access, handles, audit, store);
                var user = SignatureTestUser("user-a", "alice@example.test", "checks", "session-1", "mail.read mail.write");
                var source = handles.Issue(PreviewIdentity(), "message", handler.SourceId, handler.SourceChangeKey);
                var reply = JsonSerializer.SerializeToElement(await mailbox.ReplyDraft(user, source, "Authored reply", CancellationToken.None));
                var body = handler.LastCreatedBody!;
                Expect(reply.GetProperty("signatureStatus").GetString() == "signature_applied"
                    && reply.GetProperty("selectionSource").GetString() == "rule"
                    && body.IndexOf("Shared footer", StringComparison.Ordinal) < body.IndexOf("From:", StringComparison.Ordinal)
                    && body.IndexOf("Shared footer", StringComparison.Ordinal) != body.LastIndexOf("Shared footer", StringComparison.Ordinal),
                    "A quoted text footer falsely suppressed or misplaced the new " + signatureType + " reply signature.");
                if (signatureType != "Text")
                {
                    var root = XElement.Parse("<root>" + body + "</root>");
                    Expect(root.Descendants("b").Single().Value == "Shared footer"
                        && root.Descendants("div").Single(element => (string?)element.Attribute("id") == "divRplyFwdMsg").Value
                            .Contains("Quoted original", StringComparison.Ordinal),
                        "A text reply with an HTML signature lost its converted quote boundary or signature markup.");
                }
                var writes = handler.DraftUpdates;
                var applied = JsonSerializer.SerializeToElement(await signatures.Apply(user, reply.GetProperty("handle").GetString()!,
                    CancellationToken.None, context: "reply"));
                Expect(applied.GetProperty("status").GetString() == "signature_already_applied"
                    && handler.DraftUpdates == writes && handler.LastCreatedBody == body,
                    "Legacy apply duplicated a " + signatureType + " signature before quoted text history.");
            }
        }
    }

    private async Task ExistingSignaturePreviewEditChecksAsync()
    {
        foreach (var status in new[] { "completed", "skipped" })
        {
            var handler = new SignatureCaptureFlowHandler();
            var exchange = NewEwsClient(handler);
            var options = SignatureReuseOptions("preview-" + status);
            using var audit = new AuditLog(options);
            var access = new MailboxAccess(options);
            var handles = new MailboxHandles(new EphemeralDataProtectionProvider());
            var store = new SignatureStore();
            var previews = new SignaturePreviewStore();
            var tools = new OnboardingTools(exchange, access, audit, store, previews);
            var capture = new SignatureCaptureTools(exchange, access, handles, audit, store, previews);
            var user = SignatureTestUser("user-a", "alice@example.test", "checks", "session-1", "mail.read mail.write");
            var image = new SignatureImage("brand.png", "image/png", "saved-logo", handler.SourceImageBase64);
            var initial = await store.UpdateAsync(exchange, "alice@example.test", "new", _ => new(
                [new("Default", "<p>Before<img src='cid:saved-logo' /></p>", "HTML", [image])], "Default", "Default",
                new("en", status)), CancellationToken.None);
            var preview = await tools.Preview(user, initial.Revision, "Default", "<p>Edited<img src='cid:saved-logo' /></p>",
                CancellationToken.None, "HTML", replaceExisting: true);
            var previewHandle = preview.StructuredContent!.Value.GetProperty("previewHandle").GetString()!;
            Expect(previews.Peek(PreviewIdentity(), previewHandle).Profile.Images.Single() == image && handler.ConfigurationWrites == 1,
                "Previewing an existing " + status + " signature discarded bytes or wrote settings before commit.");
            await capture.Commit(user, previewHandle, CancellationToken.None);
            var saved = await store.ReadAsync(exchange, "alice@example.test", CancellationToken.None);
            Expect(saved.Revision != initial.Revision && saved.Settings.Onboarding == initial.Settings.Onboarding
                && saved.Settings.NewMessages == "Default" && saved.Settings.Replies == "Default"
                && saved.Settings.Profiles.Single().Images.Single() == image
                && saved.Settings.Profiles.Single().Body.Contains("Edited", StringComparison.Ordinal),
                "A confirmed edit reset " + status + " onboarding, defaults or stored image bytes.");
            var writes = handler.ConfigurationWrites;
            await AssertThrowsAsync<McpException>(() => tools.Preview(user, initial.Revision, "Default", "stale",
                CancellationToken.None, replaceExisting: true));
            Expect(handler.ConfigurationWrites == writes, "A stale existing-profile preview wrote settings.");
            try
            {
                await tools.Preview(user, saved.Revision, "Default", "<p style='text-underline-position:under'>Edit</p>",
                    CancellationToken.None, "HTML", replaceExisting: true);
                throw new InvalidOperationException("Unsupported CSS was accepted by signature preview.");
            }
            catch (McpException exception)
            {
                Expect(exception.Message.Contains("text-underline-position", StringComparison.Ordinal),
                    "Signature preview hid the unsupported CSS property from the edit failure.");
            }
        }
    }
}
