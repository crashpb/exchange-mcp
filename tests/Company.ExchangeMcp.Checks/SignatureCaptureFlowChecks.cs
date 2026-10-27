using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
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
    private const string LongDisclaimer = "This message and any attached files are confidential. If you are not the intended recipient, please notify the sender, delete all copies, and do not distribute or rely on the contents. End-of-signature disclaimer.";

    private async Task SignatureCaptureFlowChecksAsync()
    {
        await SignaturePreviewStoreChecksAsync();
        await SignatureCaptureOnboardingStateChecksAsync();
        await SignatureCaptureAndTestDraftChecksAsync();
        await SignatureCaptureCommitApplyFidelityChecksAsync();
    }

    private async Task SignatureCaptureCommitApplyFidelityChecksAsync()
    {
        var source = new StringBuilder("<html><head><style><!-- p.MsoNormal,li.MsoNormal,div.MsoNormal{margin:0in;font-size:12.0pt;font-family:\"Aptos\",sans-serif;line-height:14pt;mso-ligatures:standardcontextual;} --></style></head><body><div id='_MailAutoSig'><table width='480' cellspacing='0' cellpadding='0' border='0' style='border-collapse:collapse'><tr><td rowspan='12' width='96' valign='top'><p class='MsoNormal'>Example brand</p><p class='MsoNormal'>Example subtitle</p><img src='cid:source-logo' width='96' height='48' /></td><td width='384'><p class='MsoNormal'>Example role</p></td></tr>");
        for (var row = 1; row < 12; row++)
            source.Append("<tr><td width='384'><p class='MsoNormal'")
                .Append(row == 11 ? " style='font-size:10pt;margin-top:3px;margin-bottom:5px'" : string.Empty)
                .Append(">Example detail ").Append(row).Append("</p></td></tr>");
        source.Append("</table></div></body></html>");
        var handler = new SignatureCaptureFlowHandler { SourceHtml = source.ToString() };
        var exchange = NewEwsClient(handler);
        var options = Options.Create(new ServiceOptions
        {
            AllowedClientIds = ["checks"],
            Mailboxes = new() { ["user-a"] = "alice@example.test" },
            WritesEnabled = true,
            SendEnabled = false,
            AuditPath = Path.Combine(runDirectory, "signature-capture-fidelity-audit.jsonl")
        });
        using var audit = new AuditLog(options);
        var access = new MailboxAccess(options);
        var handles = new MailboxHandles(new EphemeralDataProtectionProvider());
        var store = new SignatureStore();
        var previews = new SignaturePreviewStore();
        var capture = new SignatureCaptureTools(exchange, access, handles, audit, store, previews);
        var signatures = new SignatureTools(exchange, access, handles, audit, store);
        var mailbox = new MailboxTools(exchange, access, handles, audit, null!, null!, null!, store);
        var identity = PreviewIdentity();
        var user = SignatureTestUser("user-a", "alice@example.test", "checks", "session-1", "mail.read mail.write");
        var sourceHandle = handles.Issue(identity, "message", handler.SourceId, handler.SourceChangeKey);
        var preview = await capture.Capture(user, sourceHandle, "Fidelity", CancellationToken.None,
            makeDefaultForNew: true, makeDefaultForReplies: true);
        var previewHandle = preview.StructuredContent!.Value.GetProperty("previewHandle").GetString()!;
        var candidate = previews.Peek(identity, previewHandle).Profile;
        AssertParagraphAndTableFidelity(candidate.Body);
        var previewHtml = preview.Meta!["signaturePreview"]!["html"]!.GetValue<string>();
        AssertParagraphAndTableFidelity(previewHtml);
        Expect(candidate.Images.Single().ContentBase64 == handler.SourceImageBase64
            && previewHtml.Contains("data:image/png;base64," + handler.SourceImageBase64, StringComparison.Ordinal)
            && handler.ConfigurationWrites == 0,
            "The fidelity preview changed source image bytes or persisted the candidate before confirmation.");

        await capture.Commit(user, previewHandle, CancellationToken.None);
        var saved = (SignatureSnapshot)await signatures.List(user, CancellationToken.None);
        var profile = saved.Settings.Profiles.Single();
        AssertParagraphAndTableFidelity(profile.Body);
        Expect(profile.Body == candidate.Body && profile.Images.Single().ContentBase64 == handler.SourceImageBase64
            && saved.Settings.NewMessages == "Fidelity" && saved.Settings.Replies == "Fidelity",
            "Confirmed signature readback changed the canonical HTML/image or failed to persist both defaults.");
        // The compose fixture uses supported canonical HTML; raw Office history remains a separate retained-draft case.
        handler.NativeQuotedHtml = profile.Body.Replace("cid:" + profile.Images.Single().ContentId, "cid:source-logo", StringComparison.Ordinal);

        foreach (var kind in new[] { "new", "reply", "forward" })
        {
            var context = kind == "new" ? "new" : "reply";
            var created = JsonSerializer.SerializeToElement(kind switch
            {
                "reply" => await mailbox.ReplyDraft(user, sourceHandle, "<p>Fresh reply</p>", CancellationToken.None,
                    bodyType: "HTML", to: [identity.Mailbox]),
                "forward" => await mailbox.ForwardDraft(user, sourceHandle, "<p>Fresh forward</p>", [identity.Mailbox],
                    CancellationToken.None, bodyType: "HTML"),
                _ => await mailbox.CreateDraft(user, "Signature fidelity", "<p>Fresh message</p>", [identity.Mailbox],
                    CancellationToken.None, bodyType: "HTML")
            });
            var currentHandle = created.GetProperty("handle").GetString()!;
            var draft = handles.Resolve(identity, "message", currentHandle);
            var readback = await exchange.GetMessageAsync(identity.Mailbox, draft.Id, CancellationToken.None);
            var savedTable = XElement.Parse("<root>" + profile.Body + "</root>").Descendants("table").Single();
            var appliedRoot = XElement.Parse("<root>" + readback.Body + "</root>");
            var ownRoot = new XElement(appliedRoot);
            ownRoot.Descendants("div").SingleOrDefault(element => (string?)element.Attribute("id") == "quoted-history")?.Remove();
            AssertParagraphAndTableFidelity(ownRoot.ToString());
            var ownAttachment = readback.Attachments.Single(attachment => attachment.ContentId == profile.Images[0].ContentId);
            Expect(created.GetProperty("signature").GetString() == "Fidelity"
                && created.GetProperty("signatureStatus").GetString() == "signature_applied"
                && created.GetProperty("readyToSend").GetBoolean()
                && created.GetProperty("selectionSource").GetString() == "default"
                && XNode.DeepEquals(savedTable, ownRoot.Descendants("table").Single())
                && readback.Attachments.Count == (kind == "new" ? 1 : 2) && ownAttachment.IsInline,
                "Applying the saved new/reply default changed signature HTML geometry/styles or CID attachment identity.");
            var image = await exchange.GetAttachmentAsync(identity.Mailbox, ownAttachment.Id, CancellationToken.None);
            Expect(image.Content.SequenceEqual(Convert.FromBase64String(handler.SourceImageBase64)),
                "Applying the saved default changed the captured inline image bytes.");
            var updates = handler.DraftUpdates;
            var attachments = handler.AttachmentWrites;
            var applied = JsonSerializer.SerializeToElement(await signatures.Apply(user, currentHandle, CancellationToken.None,
                context: context));
            var afterApply = await exchange.GetMessageAsync(identity.Mailbox, draft.Id, CancellationToken.None);
            Expect(applied.GetProperty("status").GetString() == "signature_already_applied"
                && afterApply.Body == readback.Body && handler.DraftUpdates == updates && handler.AttachmentWrites == attachments,
                "An older client's manual apply after automatic reuse duplicated or rewrote the saved signature/images.");
            if (context == "reply")
            {
                var ordered = appliedRoot.Descendants().ToArray();
                var quoted = appliedRoot.Descendants("div").Single(element => (string?)element.Attribute("id") == "quoted-history");
                Expect(Array.IndexOf(ordered, ordered.First(element => element.Name.LocalName == "table"))
                        < Array.IndexOf(ordered, ordered.Single(element => (string?)element.Attribute("id") == "divRplyFwdMsg"))
                    && XNode.DeepEquals(XElement.Parse("<root>" + handler.NativeQuotedHtml + "</root>").Elements().Single(), quoted.Elements().Single())
                    && quoted.Descendants("img").Single().Attribute("src")?.Value == "cid:source-logo"
                    && readback.Attachments.Single(attachment => attachment.ContentId == "source-logo").IsInline,
                    "The faithful saved reply signature was not placed before intact native quoted history.");
                var native = handler.Operations.Last(operation => operation.Name.LocalName == "CreateItem")
                    .Descendants(XName.Get(kind == "reply" ? "ReplyToItem" : "ForwardItem", TypesNamespace)).Single();
                Expect(native.Descendants(XName.Get("ReferenceItemId", TypesNamespace)).Single().Attribute("Id")?.Value == handler.SourceId,
                    "Automatic signature reuse lost the native source-message relationship.");
            }
        }
        var after = (SignatureSnapshot)await signatures.List(user, CancellationToken.None);
        Expect(after.Revision == saved.Revision && handler.ConfigurationWrites == 1 && handler.DraftUpdates == 5
            && handler.SendItemCalls == 0,
            $"Automatic defaults changed profile state or unexpected writes: config={handler.ConfigurationWrites}, updates={handler.DraftUpdates}, sends={handler.SendItemCalls}.");

        static void AssertParagraphAndTableFidelity(string html)
        {
            var root = XElement.Parse("<root>" + html + "</root>");
            var table = root.Descendants("table").Single();
            var paragraphs = table.Descendants("p").ToArray();
            var tableStyle = (string?)table.Attribute("style") ?? string.Empty;
            Expect(table.Descendants("tr").Count() == 12 && table.Descendants("td").Count() == 13
                && (string?)table.Descendants("td").First().Attribute("rowspan") == "12"
                && (string?)table.Descendants("td").First().Attribute("width") == "96"
                && table.Descendants("td").Skip(1).All(cell => (string?)cell.Attribute("width") == "384")
                && (string?)table.Attribute("width") == "480"
                && tableStyle.Contains("border-collapse:collapse", StringComparison.Ordinal)
                && tableStyle.Split(';').Contains("border-spacing:0", StringComparer.Ordinal)
                && table.Descendants("td").All(cell => ((string?)cell.Attribute("style"))?.Split(';').Contains("padding:0", StringComparer.Ordinal) == true)
                && (string?)table.Descendants("img").Single().Attribute("width") == "96"
                && (string?)table.Descendants("img").Single().Attribute("height") == "48"
                && paragraphs.Length == 14 && !root.Descendants("style").Any(),
                "Signature table geometry changed or depended on a preview-only stylesheet.");
            foreach (var element in table.Descendants().Where(element => element.Name.LocalName is "p" or "img"))
                Expect(!((string?)element.Attribute("style") ?? string.Empty).Split(';', StringSplitOptions.RemoveEmptyEntries)
                    .Select(declaration => declaration.Split(':', 2)[0]).Any(property => property is "width" or "height" or "vertical-align"
                        || property.StartsWith("padding", StringComparison.Ordinal) || property.StartsWith("border", StringComparison.Ordinal)),
                    "A captured/saved/applied paragraph or image inherited table/cell layout absent from the source.");
            for (var index = 0; index < paragraphs.Length; index++)
            {
                var style = (string?)paragraphs[index].Attribute("style") ?? string.Empty;
                Expect(style.Contains("margin:0in", StringComparison.Ordinal)
                    && style.Contains("font-family:Aptos,sans-serif", StringComparison.Ordinal)
                    && style.Contains("line-height:14pt", StringComparison.Ordinal)
                    && style.Contains(index == paragraphs.Length - 1 ? "font-size:10pt" : "font-size:12.0pt", StringComparison.Ordinal)
                    && (index != paragraphs.Length - 1 || style.Contains("margin-top:3px", StringComparison.Ordinal)
                        && style.Contains("margin-bottom:5px", StringComparison.Ordinal)),
                    "A captured/saved/applied paragraph lost canonical Outlook CSS or its explicit inline overrides.");
            }
        }
    }

    private async Task SignaturePreviewStoreChecksAsync()
    {
        var clock = new SignatureTestClock(DateTimeOffset.Parse("2026-10-18T10:00:00Z"));
        var store = new SignaturePreviewStore(clock);
        var identity = PreviewIdentity();
        var candidate = PreviewCandidate();
        var first = store.Stage(identity, candidate);

        foreach (var wrongIdentity in new[]
        {
            identity with { Subject = "someone-else" },
            identity with { ClientId = "other-client" },
            identity with { SessionId = "other-session" },
            identity with { Mailbox = "bob@example.test", ActorMailbox = "bob@example.test" }
        })
            ExpectThrows<McpException>(() => store.Peek(wrongIdentity, first),
                "A signature preview was readable from another subject, client, session or mailbox.");

        var begun = store.BeginTest(identity, first);
        Expect(begun.Profile.Body == candidate.Profile.Body,
            "Beginning the self-test changed the staged signature.");
        ExpectThrows<McpException>(() => store.BeginTest(identity, first),
            "The same preview allowed a second self-test attempt.");
        Expect(store.Peek(identity, first).Profile.Name == candidate.Profile.Name,
            "Beginning a self-test consumed the preview needed for commit.");
        Expect(store.Consume(identity, first).Profile.Name == candidate.Profile.Name,
            "The test preview could not still be committed after the test draft was prepared.");
        ExpectThrows<McpException>(() => store.Peek(identity, first),
            "A consumed signature preview could be replayed.");

        var replaced = store.Stage(identity, candidate);
        var replacement = store.Stage(identity, candidate with { Profile = candidate.Profile with { Name = "Work 2" } });
        ExpectThrows<McpException>(() => store.Peek(identity, replaced),
            "A mailbox retained multiple live signature previews.");
        Expect(store.Peek(identity, replacement).Profile.Name == "Work 2",
            "Replacing a mailbox's active preview did not retain the new candidate.");

        var expiring = store.Stage(identity, candidate with { Profile = candidate.Profile with { Name = "Expiring" } });
        clock.Advance(SignaturePreviewStore.Lifetime + TimeSpan.FromSeconds(1));
        ExpectThrows<McpException>(() => store.Peek(identity, expiring),
            "An expired signature preview remained usable.");

        var bounded = new SignaturePreviewStore(clock);
        for (var index = 0; index < SignaturePreviewStore.MaxEntries; index++)
        {
            var mailbox = $"user-{index}@example.test";
            bounded.Stage(PreviewIdentity($"subject-{index}", mailbox), candidate);
        }
        ExpectThrows<McpException>(() => bounded.Stage(PreviewIdentity("extra", "extra@example.test"), candidate),
            "The signature preview store exceeded its entry cap.");

        var byteBounded = new SignaturePreviewStore();
        var large = LargePreviewCandidate();
        var accepted = 0;
        for (var index = 0; index < 20; index++)
        {
            try
            {
                var mailbox = $"large-{index}@example.test";
                byteBounded.Stage(PreviewIdentity($"large-{index}", mailbox), large);
                accepted++;
            }
            catch (McpException) { break; }
        }
        Expect(accepted is >= 10 and < 20,
            "The preview store did not enforce its aggregate byte cap independently of the entry cap.");

        foreach (var status in new[] { "pending", "completed", "skipped" })
        {
            var before = new SignatureSettings([], null, null, new("en", status));
            var after = SignaturePreviewStore.ApplyCandidate(before, candidate with { CompleteOnboarding = false });
            Expect(after.Onboarding == before.Onboarding,
                "Saving a signature completed pending onboarding or reset a completed/skipped preference.");
        }
        var pending = new SignatureSettings([], null, null, new("en", "pending", "signature"));
        var approved = SignaturePreviewStore.ApplyCandidate(pending, candidate with { CompleteOnboarding = true });
        Expect(approved.Onboarding is { Status: "pending", Stage: "more_signatures_and_rules" },
            "An approved onboarding preview did not persist the follow-up stage while leaving setup pending.");
    }

    private async Task SignatureCaptureOnboardingStateChecksAsync()
    {
        var handler = new SignatureCaptureFlowHandler();
        var exchange = NewEwsClient(handler);
        var settings = new SignatureStore();
        var initial = await settings.UpdateAsync(exchange, "alice@example.test", "new",
            _ => new([], null, null, new(null, "pending")), CancellationToken.None);
        var options = Options.Create(new ServiceOptions
        {
            AllowedClientIds = ["checks"],
            WritesEnabled = true,
            Mailboxes = new() { ["user-a"] = "alice@example.test" },
            AuditPath = Path.Combine(runDirectory, "signature-language-first-audit.jsonl")
        });
        using var audit = new AuditLog(options);
        var handles = new MailboxHandles(new EphemeralDataProtectionProvider());
        var previews = new SignaturePreviewStore();
        var tools = new SignatureCaptureTools(exchange, new MailboxAccess(options), handles, audit, settings, previews);
        var user = SignatureTestUser("user-a", "alice@example.test", "checks", "session-1", "mail.read mail.write");
        var handle = handles.Issue(PreviewIdentity(), "message", handler.SourceId, handler.SourceChangeKey);
        var reads = handler.RequestCount;
        await AssertThrowsAsync<McpException>(() => tools.Capture(user, handle, "First", CancellationToken.None));
        Expect(handler.RequestCount == reads + 1 && handler.ConfigurationWrites == 1,
            "Onboarding capture read source content or saved a slot before the user chose a language.");
        await settings.UpdateAsync(exchange, "alice@example.test", initial.Revision,
            before => before with { Onboarding = new("en", "pending") }, CancellationToken.None);
        var preview = await tools.Capture(user, handle, "First", CancellationToken.None);
        Expect(handler.ConfigurationWrites == 2, "Capturing the first onboarding signature saved its slot before approval.");
        var previewHandle = preview.StructuredContent!.Value.GetProperty("previewHandle").GetString()!;
        var committed = await tools.Commit(user, previewHandle, CancellationToken.None);
        Expect(committed.StructuredContent!.Value.GetProperty("onboardingStatus").GetString() == "pending"
            && committed.StructuredContent!.Value.GetProperty("nextStep").GetString() == "more_signatures_and_rules"
            && handler.ConfigurationWrites == 3 && handler.SendItemCalls == 0,
            "First approved signature ended onboarding before the follow-up questions, or sent mail.");
        Expect((await settings.ReadAsync(exchange, "alice@example.test", CancellationToken.None)).Settings.Onboarding
            is { Status: "pending", Stage: "more_signatures_and_rules" },
            "The follow-up stage after first approved capture was not durable.");
    }

    private async Task SignatureCaptureAndTestDraftChecksAsync()
    {
        var exchangeHandler = new SignatureCaptureFlowHandler();
        var exchange = NewEwsClient(exchangeHandler);
        var options = Options.Create(new ServiceOptions
        {
            AllowedClientIds = ["checks"],
            Mailboxes = new() { ["user-a"] = "alice@example.test", ["user-b"] = "bob@example.test" },
            WritesEnabled = true,
            SendEnabled = false,
            AuditPath = Path.Combine(runDirectory, "signature-capture-flow-audit.jsonl")
        });
        using var audit = new AuditLog(options);
        var access = new MailboxAccess(options);
        var handles = new MailboxHandles(new EphemeralDataProtectionProvider());
        var signatures = new SignatureStore();
        var previews = new SignaturePreviewStore();
        var capture = new SignatureCaptureTools(exchange, access, handles, audit, signatures, previews);
        var testDraft = new SignatureTestTools(exchange, access, handles, audit, signatures, previews);
        var commit = new SignatureCaptureTools(exchange, access, handles, audit, signatures, previews);
        var identity = PreviewIdentity();
        var user = SignatureTestUser("user-a", "alice@example.test", "checks", "session-1", "mail.read mail.write");
        var sourceHandle = handles.Issue(identity, "message", exchangeHandler.SourceId, exchangeHandler.SourceChangeKey);

        var oversizedHandler = new SignatureCaptureFlowHandler(
            Convert.FromBase64String(PngBase64(SignatureStore.MaxImageBytes + 1)));
        var oversizedCapture = new SignatureCaptureTools(NewEwsClient(oversizedHandler), access, handles, audit,
            signatures, new SignaturePreviewStore());
        var oversizedSourceHandle = handles.Issue(identity, "message", oversizedHandler.SourceId,
            oversizedHandler.SourceChangeKey);
        await AssertThrowsAsync<McpException>(() => oversizedCapture.Capture(user, oversizedSourceHandle,
            "Oversized", CancellationToken.None));
        Expect(oversizedHandler.RequestCount == 3,
            "Signature capture did not reject an oversized downloaded image before re-reading/staging it.");

        var preview = await capture.Capture(user, sourceHandle, "Work", CancellationToken.None,
            makeDefaultForNew: true);
        var previewData = preview.StructuredContent ?? throw new InvalidOperationException("The signature preview omitted structured data.");
        Expect(previewData.GetProperty("status").GetString() == "signature_preview_ready",
            "Capturing a single source signature did not produce a preview.");
        var previewHandle = previewData.GetProperty("previewHandle").GetString()!;
        var candidate = previews.Peek(identity, previewHandle);
        Expect(candidate.Profile.BodyType == "HTML"
            && candidate.Profile.Body.Contains("<table", StringComparison.OrdinalIgnoreCase)
            && candidate.Profile.Body.Contains("dir=\"rtl\"", StringComparison.OrdinalIgnoreCase)
            && candidate.Profile.Body.Contains("پشتیبانی", StringComparison.Ordinal)
            && candidate.Profile.Body.Contains(LongDisclaimer, StringComparison.Ordinal)
            && candidate.Profile.Images.Single().ContentBase64 == exchangeHandler.SourceImageBase64,
            "Capture flattened the source table/direction or changed the exact referenced inline image bytes.");
        var fullTextPreview = RichBody.Preview(candidate.Profile.Body, candidate.Profile.BodyType);
        Expect(fullTextPreview.Length > 240 && fullTextPreview.EndsWith(LongDisclaimer, StringComparison.Ordinal)
            && previewData.GetProperty("textPreview").GetString() == fullTextPreview
            && JsonSerializer.Serialize(preview.Content).Contains(LongDisclaimer, StringComparison.Ordinal),
            "The final model-facing preview truncated the signature's full contact or disclaimer text to the parser's short excerpt.");
        var layout = previewData.GetProperty("layout");
        Expect(layout.GetProperty("rows").GetInt32() == 1 && layout.GetProperty("cells").GetInt32() == 1
            && layout.GetProperty("images").GetInt32() == 1,
            "The source preview omitted its bounded table/image layout summary.");
        var modelFacing = JsonSerializer.Serialize(preview.Content) + JsonSerializer.Serialize(preview.StructuredContent);
        var signatureImageBase64 = candidate.Profile.Images.Single().ContentBase64;
        var previewMeta = JsonSerializer.Serialize(preview.Meta);
        var signatureHtml = preview.Meta?["signaturePreview"]?["html"]?.GetValue<string>() ?? string.Empty;
        Expect(XElement.Parse("<root>" + signatureHtml + "</root>").Descendants()
                .Any(element => element.Name.LocalName == "i" && element.Value == LongDisclaimer),
            "The validated signature preview lost its italic disclaimer markup.");
        Expect(!modelFacing.Contains(signatureImageBase64, StringComparison.Ordinal)
            && !modelFacing.Contains("data:image/png;base64,", StringComparison.OrdinalIgnoreCase)
            && previewMeta.Contains("data:image/png;base64," + signatureImageBase64, StringComparison.Ordinal)
            && previewMeta.Contains("forNewMessages", StringComparison.Ordinal)
            && previewData.GetProperty("images")[0].GetProperty("sha256").GetString()
                == Convert.ToHexString(SHA256.HashData(Convert.FromBase64String(signatureImageBase64))).ToLowerInvariant(),
            "Preview metadata did not keep exact image rendering private from model-facing content or report the exact image hash.");
        Expect(exchangeHandler.ConfigurationWrites == 0 && exchangeHandler.DraftCreates == 0
            && exchangeHandler.SendItemCalls == 0,
            "Capturing a signature wrote settings, created a draft or sent a message.");

        var beforeNoScope = exchangeHandler.RequestCount;
        await AssertThrowsAsync<McpException>(() => testDraft.Create(
            SignatureTestUser("user-a", "alice@example.test", "checks", "session-1", "mail.read"),
            previewHandle, CancellationToken.None));
        Expect(exchangeHandler.RequestCount == beforeNoScope && exchangeHandler.DraftCreates == 0,
            "The self-test drafted mail without the mailbox write scope.");

        await AssertThrowsAsync<McpException>(() => testDraft.Create(
            SignatureTestUser("user-b", "bob@example.test", "checks", "session-b", "mail.write"),
            previewHandle, CancellationToken.None));
        Expect(exchangeHandler.DraftCreates == 0 && exchangeHandler.SendItemCalls == 0,
            "A different employee used the staged signature test or caused a message send.");

        exchangeHandler.SourceChangeKey = "source-changed";
        await AssertThrowsAsync<McpException>(() => testDraft.Create(user, previewHandle, CancellationToken.None));
        Expect(exchangeHandler.DraftCreates == 0,
            "The test draft was created after its captured source email changed.");
        exchangeHandler.SourceChangeKey = "source-change-1";

        var draft = await testDraft.Create(user, previewHandle, CancellationToken.None);
        var draftData = draft.StructuredContent ?? throw new InvalidOperationException("The signature test draft omitted structured data.");
        Expect(draftData.GetProperty("status").GetString() == "signature_test_draft_ready"
            && !draftData.GetProperty("sent").GetBoolean()
            && !draftData.GetProperty("signatureSaved").GetBoolean()
            && draftData.GetProperty("to").GetArrayLength() == 1
            && draftData.GetProperty("to")[0].GetString() == "alice@example.test"
            && draftData.GetProperty("cc").GetArrayLength() == 0
            && draftData.GetProperty("bcc").GetArrayLength() == 0,
            "The signature test did not produce a self-only unsent draft with no Cc/Bcc or profile writes.");
        Expect(exchangeHandler.DraftCreates == 1 && exchangeHandler.SendItemCalls == 0
            && exchangeHandler.ConfigurationWrites == 0
            && exchangeHandler.LastCreatedBody == candidate.Profile.Body
            && exchangeHandler.LastCreatedBodyType == candidate.Profile.BodyType
            && exchangeHandler.CreatedAttachmentBytes.Count == 1
            && exchangeHandler.CreatedAttachmentBytes[0].SequenceEqual(Convert.FromBase64String(signatureImageBase64)),
            "The self-test draft was not created once with the exact captured body and inline image bytes.");
        var draftFacing = JsonSerializer.Serialize(draft.Content) + JsonSerializer.Serialize(draft.StructuredContent);
        Expect(!draftFacing.Contains(signatureImageBase64, StringComparison.Ordinal)
            && previews.Peek(identity, previewHandle).Profile.Name == "Work",
            "The test result exposed image bytes to the model or consumed the preview needed for commit.");

        await AssertThrowsAsync<McpException>(() => testDraft.Create(user, previewHandle, CancellationToken.None));
        Expect(exchangeHandler.DraftCreates == 1,
            "A repeated self-test request created a duplicate draft for one preview.");

        var saved = await commit.Commit(user, previewHandle, CancellationToken.None);
        Expect(saved.StructuredContent?.GetProperty("status").GetString() == "signature_saved"
            && exchangeHandler.ConfigurationWrites == 1 && exchangeHandler.SendItemCalls == 0,
            "The same preview could not be committed after the user checked its test draft, or commit sent mail.");
        var savedSettings = JsonSerializer.Deserialize<SignatureSettings>(Encoding.UTF8.GetString(exchangeHandler.SignatureConfiguration!))!;
        Expect(savedSettings.NewMessages == "Work" && savedSettings.Profiles.Single().Body == candidate.Profile.Body
            && savedSettings.Profiles.Single().Images.Single().ContentBase64 == signatureImageBase64,
            "Commit did not preserve the exact candidate profile, image and requested default.");
        await AssertThrowsAsync<McpException>(() => commit.Commit(user, previewHandle, CancellationToken.None));
        Expect(exchangeHandler.ConfigurationWrites == 1,
            "A committed signature preview could be replayed to write mailbox settings again.");

        await AssertUncertainTestAttemptAsync(capture, testDraft, user, sourceHandle, previews,
            identity, exchangeHandler, "Create uncertainty", failCreate: true);
        await AssertUncertainTestAttemptAsync(capture, testDraft, user, sourceHandle, previews,
            identity, exchangeHandler, "Attachment uncertainty", failCreate: false);
        var wrongReadbackPreview = await capture.Capture(user, sourceHandle, "Wrong image readback", CancellationToken.None);
        var wrongReadbackHandle = wrongReadbackPreview.StructuredContent!.Value.GetProperty("previewHandle").GetString()!;
        var wrongReadbackCreates = exchangeHandler.DraftCreates;
        exchangeHandler.WrongNextDraftAttachmentReadback = true;
        await AssertThrowsAsync<McpException>(() => testDraft.Create(user, wrongReadbackHandle, CancellationToken.None));
        var afterWrongReadback = exchangeHandler.DraftCreates;
        await AssertThrowsAsync<McpException>(() => testDraft.Create(user, wrongReadbackHandle, CancellationToken.None));
        Expect(afterWrongReadback == wrongReadbackCreates + 1 && exchangeHandler.DraftCreates == afterWrongReadback,
            "A test draft with incorrect image bytes was accepted or automatically recreated.");

        var wrongBodyPreview = await capture.Capture(user, sourceHandle, "Wrong body readback", CancellationToken.None);
        var wrongBodyHandle = wrongBodyPreview.StructuredContent!.Value.GetProperty("previewHandle").GetString()!;
        var wrongBodyCreates = exchangeHandler.DraftCreates;
        exchangeHandler.WrongNextDraftBodyReadback = true;
        await AssertThrowsAsync<McpException>(() => testDraft.Create(user, wrongBodyHandle, CancellationToken.None));
        var afterWrongBodyReadback = exchangeHandler.DraftCreates;
        await AssertThrowsAsync<McpException>(() => testDraft.Create(user, wrongBodyHandle, CancellationToken.None));
        Expect(afterWrongBodyReadback == wrongBodyCreates + 1 && exchangeHandler.DraftCreates == afterWrongBodyReadback,
            "A test draft with altered HTML topology was accepted or automatically recreated.");
        Expect(exchangeHandler.SendItemCalls == 0,
            "A test draft was automatically sent.");
    }

    private async Task AssertUncertainTestAttemptAsync(SignatureCaptureTools capture, SignatureTestTools testDraft,
        ClaimsPrincipal user, string sourceHandle, SignaturePreviewStore previews, MailboxIdentity identity,
        SignatureCaptureFlowHandler handler, string name, bool failCreate)
    {
        var preview = await capture.Capture(user, sourceHandle, name, CancellationToken.None);
        var handle = (preview.StructuredContent ?? throw new InvalidOperationException("The signature preview omitted structured data."))
            .GetProperty("previewHandle").GetString()!;
        var createsBefore = handler.DraftCreates;
        var attachmentWritesBefore = handler.AttachmentWrites;
        if (failCreate) handler.FailNextDraftCreate = true;
        else handler.FailNextAttachmentCreate = true;

        await AssertThrowsAsync<McpException>(() => testDraft.Create(user, handle, CancellationToken.None));
        var createsAfterFailure = handler.DraftCreates;
        var attachmentsAfterFailure = handler.AttachmentWrites;
        Expect(createsAfterFailure == createsBefore + 1
            && attachmentsAfterFailure == attachmentWritesBefore + (failCreate ? 0 : 1),
            "The injected uncertain test-draft write did not reach exactly the intended EWS operation.");
        await AssertThrowsAsync<McpException>(() => testDraft.Create(user, handle, CancellationToken.None));
        Expect(handler.DraftCreates == createsAfterFailure && handler.AttachmentWrites == attachmentsAfterFailure
            && previews.Peek(identity, handle).Profile.Name == name,
            "An uncertain test draft was automatically retried or its preview was consumed.");
    }

    private static SignaturePreviewCandidate PreviewCandidate() => new(
        new MailSignature("Work", "short signature", "Text", []), "new", false, false,
        false, "en", false);

    private static SignaturePreviewCandidate LargePreviewCandidate()
    {
        var images = Enumerable.Range(0, 4).Select(index => new SignatureImage(
            $"large-{index}.png", "image/png", $"large-{index}", PngBase64(SignatureStore.MaxImageBytes))).ToArray();
        var body = string.Concat(images.Select(image => $"<img src=\"cid:{image.ContentId}\"/>"));
        return new(new("Large", body, "HTML", images), "new", false, false, false, "en", false);
    }

    private static MailboxIdentity PreviewIdentity(string subject = "user-a", string mailbox = "alice@example.test",
        string client = "checks", string session = "session-1") =>
        new(subject, mailbox, client, session, "own", mailbox);

    private static ClaimsPrincipal SignatureTestUser(string subject, string mailbox, string client, string session,
        string scopes) => new(new ClaimsIdentity(
    [
        new Claim("sub", subject), new Claim("azp", client), new Claim("sid", session),
        new Claim("scope", scopes)
    ], "signature-checks"));

    private sealed class SignatureTestClock(DateTimeOffset utcNow) : TimeProvider
    {
        private DateTimeOffset now = utcNow;
        public override DateTimeOffset GetUtcNow() => now;
        public void Advance(TimeSpan amount) => now += amount;
    }

    private sealed class SignatureCaptureFlowHandler : HttpMessageHandler
    {
        private static readonly XNamespace Soap = "http://schemas.xmlsoap.org/soap/envelope/";
        private static readonly XNamespace Messages = "http://schemas.microsoft.com/exchange/services/2006/messages";
        private static readonly XNamespace Types = "http://schemas.microsoft.com/exchange/services/2006/types";
        private readonly byte[] sourceImage;
        private readonly List<TestAttachment> draftAttachments = [];
        private string? signatureConfiguration;
        private int draftSequence;
        private string draftChangeKey = "draft-change-1";
        private string[] draftTo = [];
        private string[] draftCc = [];
        private string[] draftBcc = [];

        public SignatureCaptureFlowHandler(byte[]? sourceImage = null) => this.sourceImage = sourceImage ?? PngBytes(24);

        public string SourceId { get; } = "source-message-1";
        public string SourceChangeKey { get; set; } = "source-change-1";
        public string SourceImageBase64 => Convert.ToBase64String(sourceImage);
        public string? SourceHtml { get; init; }
        public int RequestCount { get; private set; }
        public int ConfigurationWrites { get; private set; }
        public int DraftCreates { get; private set; }
        public int DraftUpdates { get; private set; }
        public int AttachmentWrites { get; private set; }
        public int SendItemCalls { get; private set; }
        public bool FailNextDraftCreate { get; set; }
        public bool FailNextAttachmentCreate { get; set; }
        public bool WrongNextDraftAttachmentReadback { get; set; }
        public bool WrongNextDraftBodyReadback { get; set; }
        public string? LastCreatedBody { get; private set; }
        public string? LastCreatedBodyType { get; private set; }
        public List<byte[]> CreatedAttachmentBytes { get; } = [];
        public List<XElement> Operations { get; } = [];
        public List<string> ConfigurationMailboxes { get; } = [];
        public string? NativeQuotedHtml { get; set; }
        public string? NativeQuotedText { get; set; }
        public bool FailSignatureRead { get; set; }
        public bool FailNextDraftUpdate { get; set; }
        public int ExtraAttachmentCount { get; set; }
        public Func<string, string>? DraftBodyReadback { get; set; }
        public byte[]? SignatureConfiguration => signatureConfiguration is null
            ? null : Convert.FromBase64String(signatureConfiguration);

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            RequestCount++;
            var xml = XDocument.Parse(await request.Content!.ReadAsStringAsync(cancellationToken).ConfigureAwait(false));
            var operation = xml.Root!.Element(Soap + "Body")!.Elements().Single();
            var name = operation.Name.LocalName;
            Operations.Add(new(operation));
            if (name == "GetUserConfiguration")
            {
                ConfigurationMailboxes.Add(xml.Descendants(Types + "PrimarySmtpAddress").SingleOrDefault()?.Value ?? string.Empty);
                if (operation.Descendants(Messages + "UserConfigurationName").Single().Attribute("Name")?.Value == "OWA.UserOptions")
                    return Response(name, error: "ErrorItemNotFound");
                if (FailSignatureRead) return Response(name, error: "ErrorAccessDenied");
            }
            return name switch
            {
                "GetUserConfiguration" => GetSignatureConfiguration(name),
                "CreateUserConfiguration" or "UpdateUserConfiguration" => SaveSignatureConfiguration(operation, name),
                "GetItem" => GetItem(operation, name),
                "GetAttachment" => GetAttachment(operation, name),
                "CreateItem" => CreateDraft(operation, name),
                "UpdateItem" => UpdateDraft(operation, name),
                "CreateAttachment" => CreateDraftAttachment(operation, name),
                "SendItem" => CountSend(name),
                _ => throw new InvalidOperationException($"Unexpected EWS operation in signature capture test: {name}.")
            };
        }

        private HttpResponseMessage GetSignatureConfiguration(string operationName) => signatureConfiguration is null
            ? Response(operationName, error: "ErrorItemNotFound")
            : Response(operationName, new XElement(Messages + "UserConfiguration",
                new XElement(Types + "BinaryData", signatureConfiguration)));

        private HttpResponseMessage SaveSignatureConfiguration(XElement operation, string operationName)
        {
            signatureConfiguration = operation.Descendants(Types + "BinaryData").Single().Value;
            ConfigurationWrites++;
            return Response(operationName);
        }

        private HttpResponseMessage GetItem(XElement operation, string operationName)
        {
            var itemId = operation.Descendants(Types + "ItemId").Single().Attribute("Id")!.Value;
            return itemId == SourceId
                ? Response(operationName, SourceMessage())
                : itemId == DraftId
                    ? Response(operationName, DraftMessage())
                    : Response(operationName, error: "ErrorItemNotFound");
        }

        private HttpResponseMessage GetAttachment(XElement operation, string operationName)
        {
            var id = operation.Descendants(Types + "AttachmentId").Single().Attribute("Id")!.Value;
            if (id == "source-logo")
                return AttachmentResponse(operationName, id, "brand.png", "image/png", "source-logo", sourceImage);
            var draftAttachment = draftAttachments.SingleOrDefault(attachment => attachment.Id == id);
            if (draftAttachment is null) return Response(operationName, error: "ErrorAttachmentNotFound");
            var bytes = draftAttachment.Content;
            if (WrongNextDraftAttachmentReadback)
            {
                WrongNextDraftAttachmentReadback = false;
                bytes = bytes.ToArray();
                bytes[^1] ^= 0x01;
            }
            return AttachmentResponse(operationName, id, draftAttachment.Name, draftAttachment.ContentType,
                draftAttachment.ContentId, bytes, draftAttachment.IsInline);
        }

        private HttpResponseMessage AttachmentResponse(string operationName, string id, string name,
            string contentType, string contentId, byte[] bytes, bool isInline = true)
        {
            return Response(operationName, new XElement(Messages + "Attachments", new XElement(Types + "FileAttachment",
                new XElement(Types + "AttachmentId", new XAttribute("Id", id)),
                new XElement(Types + "Name", name),
                new XElement(Types + "ContentType", contentType),
                new XElement(Types + "ContentId", contentId),
                new XElement(Types + "IsInline", isInline),
                new XElement(Types + "Content", Convert.ToBase64String(bytes)))));
        }

        private HttpResponseMessage CreateDraft(XElement operation, string operationName)
        {
            var message = operation.Element(Messages + "Items")!.Elements().Single();
            var native = message.Name.LocalName is "ReplyToItem" or "ReplyAllToItem" or "ForwardItem";
            var body = message.Element(Types + (native ? "NewBodyContent" : "Body"))!;
            var id = DraftIdFor(++draftSequence);
            LastCreatedSubject = message.Element(Types + "Subject")?.Value ?? "RE: Signature reference";
            LastCreatedBody = native && (string?)body.Attribute("BodyType") == "HTML"
                ? "<html><body><div>" + body.Value + "</div><hr /><div id='divRplyFwdMsg'><span><b>From:</b> sender<br /><b>Sent:</b> time<br /><b>To:</b> recipient<br /><b>Subject:</b> test</span></div><div id='quoted-history'>"
                    + (NativeQuotedHtml ?? SourceHtml ?? SourceBody) + "</div></body></html>"
                : body.Value + (native && NativeQuotedText is not null ? "\r\n\r\n" + NativeQuotedText : string.Empty);
            LastCreatedBodyType = (string?)body.Attribute("BodyType");
            draftTo = Recipients(message, "ToRecipients", native ? ["sender@example.test"] : []);
            draftCc = Recipients(message, "CcRecipients", []);
            draftBcc = Recipients(message, "BccRecipients", []);
            draftChangeKey = "draft-change-1";
            DraftCreates++;
            draftAttachments.Clear();
            if (native && (string?)body.Attribute("BodyType") == "HTML" && NativeQuotedText is null)
                draftAttachments.Add(new("native-source-logo", "brand.png", "image/png", "source-logo", true, sourceImage.Length + 208, sourceImage));
            var response = Response(operationName, new XElement(Messages + "Items",
                new XElement(Types + "Message", new XElement(Types + "ItemId",
                    new XAttribute("Id", id), new XAttribute("ChangeKey", "draft-change-1")))));
            if (FailNextDraftCreate)
            {
                FailNextDraftCreate = false;
                return Response(operationName, error: "ErrorServerBusy");
            }
            return response;
        }

        private HttpResponseMessage CreateDraftAttachment(XElement operation, string operationName)
        {
            var file = operation.Descendants(Types + "FileAttachment").Single();
            var id = $"draft-attachment-{AttachmentWrites + 1}";
            var bytes = Convert.FromBase64String(file.Element(Types + "Content")!.Value);
            CreatedAttachmentBytes.Add(bytes);
            draftAttachments.Add(new(id, file.Element(Types + "Name")!.Value,
                file.Element(Types + "ContentType")!.Value, file.Element(Types + "ContentId")!.Value,
                (string?)file.Element(Types + "IsInline") == "true", bytes.Length, bytes));
            AttachmentWrites++;
            draftChangeKey = "draft-change-after-attachment";
            var response = Response(operationName, new XElement(Messages + "Attachments",
                new XElement(Types + "FileAttachment", new XElement(Types + "AttachmentId",
                    new XAttribute("Id", id), new XAttribute("RootItemId", DraftId),
                    new XAttribute("RootItemChangeKey", "draft-change-after-attachment")))));
            if (FailNextAttachmentCreate)
            {
                FailNextAttachmentCreate = false;
                return Response(operationName, error: "ErrorServerBusy");
            }
            return response;
        }

        private HttpResponseMessage UpdateDraft(XElement operation, string operationName)
        {
            if (FailNextDraftUpdate)
            {
                FailNextDraftUpdate = false;
                return Response(operationName, error: "ErrorServerBusy");
            }
            var body = operation.Descendants(Types + "Body").Single();
            LastCreatedBody = body.Value;
            LastCreatedBodyType = (string?)body.Attribute("BodyType");
            LastCreatedSubject = operation.Descendants(Types + "Subject").SingleOrDefault()?.Value ?? LastCreatedSubject;
            foreach (var message in operation.Descendants(Types + "Message"))
            {
                draftTo = Recipients(message, "ToRecipients", draftTo);
                draftCc = Recipients(message, "CcRecipients", draftCc);
                draftBcc = Recipients(message, "BccRecipients", draftBcc);
            }
            DraftUpdates++;
            draftChangeKey = "draft-after-update";
            return Response(operationName, new XElement(Messages + "Items",
                new XElement(Types + "Message", new XElement(Types + "ItemId",
                    new XAttribute("Id", DraftId), new XAttribute("ChangeKey", "draft-after-update")))));
        }

        private HttpResponseMessage CountSend(string operationName)
        {
            SendItemCalls++;
            return Response(operationName);
        }

        private XElement SourceMessage() => new(Types + "Message",
            new XElement(Types + "ItemId", new XAttribute("Id", SourceId), new XAttribute("ChangeKey", SourceChangeKey)),
            new XElement(Types + "Subject", "Signature reference"),
            new XElement(Types + "From", new XElement(Types + "Mailbox",
                new XElement(Types + "Name", "Sender"), new XElement(Types + "EmailAddress", "sender@example.test"))),
            new XElement(Types + "DateTimeReceived", "2026-10-18T09:00:00Z"),
            new XElement(Types + "DateTimeSent", "2026-10-18T09:00:00Z"),
            new XElement(Types + "IsRead", true),
            new XElement(Types + "IsDraft", false),
            new XElement(Types + "Body", new XAttribute("BodyType", NativeQuotedText is null ? "HTML" : "Text"),
                NativeQuotedText ?? NativeQuotedHtml ?? SourceHtml ?? SourceBody),
            new XElement(Types + "Attachments", new XElement(Types + "FileAttachment",
                new XElement(Types + "AttachmentId", new XAttribute("Id", "source-logo")),
                new XElement(Types + "Name", "brand.png"), new XElement(Types + "Size", sourceImage.Length + 208),
                new XElement(Types + "ContentType", "image/png"), new XElement(Types + "ContentId", "source-logo"),
                new XElement(Types + "IsInline", true))));

        private XElement DraftMessage()
        {
            var body = LastCreatedBody ?? string.Empty;
            body = DraftBodyReadback?.Invoke(body) ?? body;
            if (WrongNextDraftBodyReadback && body.Contains("<img", StringComparison.OrdinalIgnoreCase))
            {
                WrongNextDraftBodyReadback = false;
                var image = body.IndexOf("<img", StringComparison.OrdinalIgnoreCase);
                body = body.Insert(image, "</td><td>");
            }
            return new XElement(Types + "Message",
                new XElement(Types + "ItemId", new XAttribute("Id", DraftId), new XAttribute("ChangeKey", draftChangeKey)),
                new XElement(Types + "Subject", LastCreatedSubject),
                RecipientElement("ToRecipients", draftTo), RecipientElement("CcRecipients", draftCc), RecipientElement("BccRecipients", draftBcc),
                new XElement(Types + "IsDraft", true),
                new XElement(Types + "Body", new XAttribute("BodyType", LastCreatedBodyType ?? "HTML"), body),
                new XElement(Types + "Attachments", draftAttachments.Select(attachment => new XElement(Types + "FileAttachment",
                    new XElement(Types + "AttachmentId", new XAttribute("Id", attachment.Id)),
                    new XElement(Types + "Name", attachment.Name), new XElement(Types + "Size", attachment.Size),
                    new XElement(Types + "ContentType", attachment.ContentType), new XElement(Types + "ContentId", attachment.ContentId),
                    new XElement(Types + "IsInline", attachment.IsInline))).Concat(Enumerable.Range(0, ExtraAttachmentCount).Select(index =>
                        new XElement(Types + "FileAttachment", new XElement(Types + "AttachmentId", new XAttribute("Id", "extra-" + index)),
                            new XElement(Types + "Name", "extra.txt"), new XElement(Types + "Size", 1))))));
        }

        private static string[] Recipients(XElement message, string name, string[] fallback) =>
            message.Element(Types + name)?.Descendants(Types + "EmailAddress").Select(element => element.Value).ToArray() ?? fallback;

        private static XElement RecipientElement(string name, string[] addresses) => new(Types + name,
            addresses.Select(address => new XElement(Types + "Mailbox", new XElement(Types + "EmailAddress", address))));

        private string LastCreatedSubject { get; set; } = string.Empty;
        private string DraftId => DraftIdFor(draftSequence);
        private static string DraftIdFor(int sequence) => $"draft-{sequence}";

        private HttpResponseMessage Response(string operationName, XElement? payload = null, string? error = null)
        {
            var responseMessage = new XElement(Messages + operationName + "ResponseMessage",
                new XAttribute("ResponseClass", error is null ? "Success" : "Error"),
                new XElement(Messages + "ResponseCode", error ?? "NoError"), payload);
            var xml = new XDocument(new XElement(Soap + "Envelope",
                new XElement(Soap + "Body", new XElement(Messages + operationName + "Response",
                    new XElement(Messages + "ResponseMessages", responseMessage)))));
            return new(HttpStatusCode.OK) { Content = new StringContent(xml.ToString(), Encoding.UTF8, "text/xml") };
        }

        private static string SourceBody => $"<div id=\"_MailAutoSig\"><table><tr><td dir=\"rtl\">پشتیبانی <img alt=\"brand\" src=\"cid:source-logo\" /><i>{LongDisclaimer}</i></td></tr></table></div>";
        private static byte[] PngBytes(int size)
        {
            var bytes = new byte[size];
            new byte[] { 137, 80, 78, 71, 13, 10, 26, 10 }.CopyTo(bytes, 0);
            return bytes;
        }

        private sealed record TestAttachment(string Id, string Name, string ContentType, string ContentId,
            bool IsInline, int Size, byte[] Content);
    }
}
