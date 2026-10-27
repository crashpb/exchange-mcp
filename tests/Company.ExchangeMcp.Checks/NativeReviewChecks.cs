using System.Net;
using System.Security.Claims;
using System.Text.Json;
using System.Text.Json.Nodes;
using Company.ExchangeMcp;
using Company.ExchangeMcp.Security;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using ModelContextProtocol;

internal sealed partial class Checks
{
    private async Task NativeReviewChecksAsync()
    {
        NativeReviewReferenceChecks();
        await NativeReviewReadOnlyChecksAsync();
        await NativeReviewWireChecksAsync();
    }

    private static void NativeReviewReferenceChecks()
    {
        var clock = new SignatureTestClock(DateTimeOffset.Parse("2026-10-21T12:00:00Z"));
        var store = new MailReviewStore(clock);
        var actor = PreviewIdentity();
        Expect(store.Get(actor) is null && store.Record(actor, "draft-one", "delegated-selector"),
            "An empty review cache did not accept the first explicit preview reference.");
        var first = store.Get(actor)!;
        Expect(first.DraftHandle == "draft-one" && first.MailboxHandle == "delegated-selector"
            && first.ExpiresAt == clock.GetUtcNow().AddMinutes(15),
            "Review storage changed the original draft/delegated selector or its 15-minute deadline.");
        foreach (var other in new[]
        {
            actor with { Subject = "other" }, actor with { ClientId = "other" },
            actor with { SessionId = "other" }, actor with { Mailbox = "other@example.test", ActorMailbox = "other@example.test" },
            actor with { ActorMailbox = "other@example.test" }, actor with { SessionId = null }, actor with { SessionId = "" },
            actor with { TargetId = "delegated", Mailbox = "shared@example.test" }
        })
            Expect(store.Get(other) is null, "A review reference escaped its own actor/client/session/mailbox binding.");
        clock.Advance(TimeSpan.FromMinutes(14));
        Expect(store.Get(actor)!.ExpiresAt == first.ExpiresAt, "Reading a review renewed its expiry.");
        clock.Advance(TimeSpan.FromMinutes(1));
        Expect(store.Get(actor) is null, "A reference remained readable at its exact expiry boundary.");
        Expect(store.Record(actor, "newer", null) && store.Record(actor, "latest", "original-selector")
            && store.Get(actor)!.DraftHandle == "latest", "The latest successful preview did not replace the earlier reference.");
        Expect(store.Record(actor, new string('x', 16384), null), "An exact-limit opaque draft handle was declined.");
        foreach (var invalid in new[] { "", " ", "bad\nhandle", new string('x', 16385) })
        {
            Expect(store.Record(actor, "prior", null), "The invalid-reference fixture could not seed its prior review.");
            Expect(!store.Record(actor, invalid, null) && store.Get(actor) is null,
                "An unrecordable newly previewed draft left an older unrelated draft available.");
        }
        Expect(!store.Record(actor with { SessionId = null }, "draft", null)
            && !store.Record(actor with { SessionId = "" }, "draft", null),
            "A review reference accepted a connection without a nonempty session ID.");

        var countBounded = new MailReviewStore(clock);
        for (var index = 0; index < 2048; index++)
            Expect(countBounded.Record(actor with { Subject = $"subject-{index}" }, "draft", null),
                "The review cache rejected a valid reference before its entry bound.");
        Expect(!countBounded.Record(actor with { Subject = "overflow" }, "draft", null)
            && countBounded.Record(actor with { Subject = "subject-0" }, "replacement", null)
            && countBounded.Get(actor with { Subject = "subject-1" })?.DraftHandle == "draft",
            "Review entry capacity evicted another connection, prevented replacement, or exceeded 2048 entries.");
        clock.Advance(TimeSpan.FromMinutes(15));
        Expect(countBounded.Record(actor, "after-expiry", null), "Expired entries did not release review capacity.");

        var bytesBounded = new MailReviewStore(clock);
        var large = new string('界', 4096);
        var accepted = 0;
        while (accepted < 2048 && bytesBounded.Record(actor with { Subject = $"bytes-{accepted}" }, large, large)) accepted++;
        Expect(accepted > 0 && accepted < 400
            && accepted * 2L * System.Text.Encoding.UTF8.GetByteCount(large) <= 8 * 1024 * 1024,
            "Review byte capacity did not account for UTF-8 reference bytes within the 8 MiB limit.");
        Expect(bytesBounded.Get(actor with { Subject = "bytes-0" })?.DraftHandle == large,
            "A failed byte-capacity insertion evicted an earlier connection's reference.");
        Expect(!bytesBounded.Record(actor with { Subject = "bytes-0" }, new string('界', 16384), new string('界', 16384))
            && bytesBounded.Get(actor with { Subject = "bytes-0" }) is null,
            "A declined oversized replacement left the older draft available for review.");
    }

    private async Task NativeReviewReadOnlyChecksAsync()
    {
        var options = Options.Create(new ServiceOptions
        {
            AllowedClientIds = ["checks"],
            Mailboxes = new() { ["user-a"] = "alice@example.test" },
            WritesEnabled = false,
            SendEnabled = false
        });
        var access = new MailboxAccess(options);
        var actor = PreviewIdentity();
        var user = SignatureTestUser(actor.Subject, actor.Mailbox, actor.ClientId, actor.SessionId!, "mail.read");
        var noSession = new ClaimsPrincipal(new ClaimsIdentity(user.Claims.Where(claim => claim.Type != "sid"), "checks"));
        var clock = new SignatureTestClock(DateTimeOffset.Parse("2026-10-21T12:00:00Z"));
        var references = new MailReviewStore(clock);
        var signatures = new SignatureStore();
        var pending = new SignaturePreviewStore(clock);
        var handler = new SignatureRecordingHandler();
        var exchange = NewEwsClient(handler);
        var tools = new MailReviewTools(exchange, access, references, signatures, pending);
        var empty = tools.ReviewEmail(user);
        Expect(empty.Meta?["emailReviewBootstrap"]?["available"]?.GetValue<bool>() == false
            && handler.Operations.Count == 0, "An empty email entrypoint read or wrote Exchange, or offered an actionable draft.");
        references.Record(actor, "private-draft-handle", "delegated-selector");
        var review = tools.ReviewEmail(user);
        var bootstrap = review.Meta!["emailReviewBootstrap"]!;
        Expect(bootstrap["available"]!.GetValue<bool>() && bootstrap["draftHandle"]!.GetValue<string>() == "private-draft-handle"
            && bootstrap["mailboxHandle"]!.GetValue<string>() == "delegated-selector"
            && handler.Operations.Count == 0
            && !JsonSerializer.Serialize(review.StructuredContent).Contains("private-draft-handle", StringComparison.Ordinal)
            && !JsonSerializer.Serialize(review.Content).Contains("delegated-selector", StringComparison.Ordinal),
            "Email entrypoint changed/read the target or leaked private bootstrap handles to model-visible output.");
        Expect(tools.ReviewEmail(noSession).Meta?["emailReviewBootstrap"]?["available"]?.GetValue<bool>() == false,
            "Email review without a session threw or reused another connection's reference.");

        var image = new SignatureImage("logo.png", "image/png", "logo", PngBase64(8));
        var profile = new MailSignature("Default", "<p dir=\"rtl\">سلام<img src=\"cid:logo\"/></p>", "HTML", [image]);
        var saved = await signatures.UpdateAsync(exchange, actor.Mailbox, "new",
            _ => new([profile], "Default", "Default", new("fa", "completed")), CancellationToken.None);
        var writes = handler.Writes;
        var candidate = new SignaturePreviewCandidate(profile with { Name = "Pending", Body = "<b>Pending</b><img src=\"cid:logo\"/>" },
            saved.Revision, true, false, false, "fa", false);
        var handle = pending.Stage(actor, candidate);
        var before = pending.Latest(actor)!;
        before.Candidate.Profile.Images[0] = image with { Name = "changed-copy.png" };
        Expect(pending.Peek(actor, handle).Profile.Images[0].Name == "logo.png",
            "Reading the latest pending signature exposed mutable stored image state.");
        clock.Advance(TimeSpan.FromMinutes(5));
        var savedInline = await tools.PreviewSavedSignature(user, CancellationToken.None);
        var expectedSaved = SignaturePreviewResources.CreateMetadata(profile, "fa",
            new { forNewMessages = "Default", forReplies = "Default" }, []);
        expectedSaved["signaturePreview"]!["reviewState"] = "saved";
        Expect(JsonNode.DeepEquals(savedInline.Meta, expectedSaved)
            && savedInline.StructuredContent!.Value.GetProperty("previewHandle").ValueKind == JsonValueKind.Null
            && savedInline.StructuredContent.Value.GetProperty("previewExpiresAt").ValueKind == JsonValueKind.Null
            && pending.Latest(actor)!.Handle == handle && pending.Latest(actor)!.ExpiresAt == before.ExpiresAt
            && JsonSerializer.Serialize(pending.Peek(actor, handle)) == JsonSerializer.Serialize(candidate)
            && handler.Writes == writes,
            "Saved inline preview preferred or changed a pending candidate, changed exact saved metadata, or wrote settings.");
        var pendingReview = await tools.ReviewSignature(user, CancellationToken.None);
        var repeated = await tools.ReviewSignature(user, CancellationToken.None);
        var after = pending.Latest(actor)!;
        Expect(after.Handle == handle && after.ExpiresAt == before.ExpiresAt
            && pending.Peek(actor, handle).Profile.Body == candidate.Profile.Body
            && pendingReview.StructuredContent!.Value.GetProperty("previewHandle").GetString() == handle
            && pendingReview.Meta?["signaturePreview"]?["reviewState"]?.GetValue<string>() == "pending"
            && JsonNode.DeepEquals(pendingReview.Meta, repeated.Meta),
            "Opening/reopening signature review restaged, consumed, renewed, or changed the exact pending candidate.");
        var expected = SignaturePreviewResources.CreateMetadata(candidate.Profile, "fa",
            new { forNewMessages = "Pending", forReplies = (string?)null }, []);
        Expect(pendingReview.Meta?["signaturePreview"]?["html"]?.GetValue<string>()
            == expected["signaturePreview"]?["html"]?.GetValue<string>()
            && handler.Writes == writes, "Pending review changed authoritative HTML/CID image bytes or wrote signature settings.");
        foreach (var wrong in new[] { actor with { SessionId = "other" }, actor with { ClientId = "other" }, actor with { Subject = "other" } })
            Expect(pending.Latest(wrong) is null, "Latest pending signature escaped its full connection binding.");

        var changed = await signatures.UpdateAsync(exchange, actor.Mailbox, saved.Revision,
            beforeSettings => beforeSettings with { Replies = null }, CancellationToken.None);
        writes = handler.Writes;
        var staleInline = await tools.PreviewSavedSignature(user, CancellationToken.None);
        expectedSaved["signaturePreview"]!["defaults"]!["forReplies"] = null;
        Expect(JsonNode.DeepEquals(staleInline.Meta, expectedSaved)
            && pending.Latest(actor)!.Handle == handle && pending.Latest(actor)!.ExpiresAt == before.ExpiresAt
            && JsonSerializer.Serialize(pending.Peek(actor, handle)) == JsonSerializer.Serialize(candidate)
            && handler.Writes == writes,
            "A stale pending candidate blocked saved inline display or was consumed, changed, restaged or extended.");
        var stale = await tools.ReviewSignature(user, CancellationToken.None);
        Expect(stale.Meta?["signatureReviewBootstrap"]?["available"]?.GetValue<bool>() == false
            && stale.Meta?["signaturePreview"] is null && pending.Latest(actor)!.Handle == handle && handler.Writes == writes,
            "A stale-revision review consumed its candidate or changed signature settings.");
        pending.Consume(actor, handle);
        var fallback = await tools.ReviewSignature(user, CancellationToken.None);
        Expect(fallback.Meta?["signaturePreview"]?["reviewState"]?.GetValue<string>() == "saved"
            && fallback.Meta?["signaturePreview"]?["html"]?.GetValue<string>()
                == SignaturePreviewResources.CreateMetadata(profile, "fa", new { forNewMessages = "Default", forReplies = (string?)null }, [])
                    ["signaturePreview"]?["html"]?.GetValue<string>()
            && pending.Latest(actor) is null && handler.Writes == writes,
            "Saved-default fallback restaged a candidate, changed saved HTML/image bytes, or wrote settings.");
        var expiring = pending.Stage(actor, candidate with { Revision = changed.Revision });
        clock.Advance(TimeSpan.FromMinutes(15));
        var expiredReview = await tools.ReviewSignature(user, CancellationToken.None);
        Expect(pending.Latest(actor) is null
            && expiredReview.Meta?["signaturePreview"]?["reviewState"]?.GetValue<string>() == "saved"
            && expiredReview.StructuredContent!.Value.GetProperty("previewHandle").ValueKind == JsonValueKind.Null,
            "An expired signature candidate remained pending or was silently restaged.");
        ExpectThrows<McpException>(() => pending.Peek(actor, expiring), "An expired review retained a committable signature handle.");
        var final = await signatures.ReadAsync(exchange, actor.Mailbox, CancellationToken.None);
        Expect(final.Revision == changed.Revision && final.Settings.Onboarding?.Status == "completed",
            "Review changed the saved revision or onboarding state.");
        var noDefault = await signatures.UpdateAsync(exchange, actor.Mailbox, final.Revision,
            beforeSettings => beforeSettings with
            {
                NewMessages = null,
                Replies = null,
                Profiles = [profile, profile with { Name = "Other" }]
            }, CancellationToken.None);
        writes = handler.Writes;
        var unavailable = await tools.ReviewSignature(user, CancellationToken.None);
        Expect(JsonNode.DeepEquals(unavailable.Meta, (await tools.PreviewSavedSignature(user, CancellationToken.None)).Meta),
            "Saved inline display selected a profile with multiple saved signatures and no default.");
        Expect(unavailable.Meta?["signatureReviewBootstrap"]?["available"]?.GetValue<bool>() == false
            && handler.Writes == writes && pending.Latest(actor) is null && noDefault.Settings.Profiles.Length == 2,
            "A signature without a default was silently staged, saved or selected.");
        var defaults = await signatures.UpdateAsync(exchange, actor.Mailbox, noDefault.Revision,
            beforeSettings => beforeSettings with { NewMessages = "Other", Replies = "Default" }, CancellationToken.None);
        writes = handler.Writes;
        var newDefault = await tools.ReviewSignature(user, CancellationToken.None);
        Expect(JsonNode.DeepEquals(newDefault.Meta, (await tools.PreviewSavedSignature(user, CancellationToken.None)).Meta),
            "Saved inline display changed the new-message default selection.");
        Expect(newDefault.Meta?["signaturePreview"]?["signatureName"]?.GetValue<string>() == "Other"
            && handler.Writes == writes, "Saved review ignored the new-message default or changed its settings.");
        var replyOnly = await signatures.UpdateAsync(exchange, actor.Mailbox, defaults.Revision,
            beforeSettings => beforeSettings with { NewMessages = null }, CancellationToken.None);
        writes = handler.Writes;
        var replyDefault = await tools.ReviewSignature(user, CancellationToken.None);
        Expect(JsonNode.DeepEquals(replyDefault.Meta, (await tools.PreviewSavedSignature(user, CancellationToken.None)).Meta),
            "Saved inline display changed the reply-only default selection.");
        Expect(replyDefault.Meta?["signaturePreview"]?["signatureName"]?.GetValue<string>() == "Default"
            && handler.Writes == writes, "Saved review ignored the reply default when no new-message default exists.");
        var single = await signatures.UpdateAsync(exchange, actor.Mailbox, replyOnly.Revision,
            beforeSettings => beforeSettings with { Profiles = [profile], Replies = null }, CancellationToken.None);
        writes = handler.Writes;
        var singleReview = await tools.ReviewSignature(noSession, CancellationToken.None);
        Expect(JsonNode.DeepEquals(singleReview.Meta, (await tools.PreviewSavedSignature(noSession, CancellationToken.None)).Meta),
            "Saved inline display changed the sole-profile fallback or required a session.");
        Expect(singleReview.Meta?["signaturePreview"]?["reviewState"]?.GetValue<string>() == "saved"
            && single.Revision == (await signatures.ReadAsync(exchange, actor.Mailbox, CancellationToken.None)).Revision
            && handler.Writes == writes && pending.Latest(actor) is null,
            "Sole-profile read-only inspection without a session failed, staged state or changed the saved settings.");

        var previewHandler = new MailPreviewEwsHandler(Convert.FromBase64String(image.ContentBase64));
        var handles = new MailboxHandles(new EphemeralDataProtectionProvider());
        var preview = new MailPreviewTools(NewEwsClient(previewHandler), access, handles, references);
        var draftHandle = handles.Issue(actor, "message", "draft-1", "draft-current");
        await preview.Preview(user, draftHandle, CancellationToken.None);
        var recorded = references.Get(actor)!;
        Expect(recorded.DraftHandle != "private-draft-handle" && recorded.MailboxHandle is null,
            "An ordinary successful preview did not refresh the native review reference.");
        var failedPreview = new MailPreviewTools(NewEwsClient(new MailPreviewEwsHandler([]) { IsDraft = false }), access, handles, references);
        await AssertThrowsAsync<McpException>(() => failedPreview.Preview(user, draftHandle, CancellationToken.None));
        Expect(references.Get(actor)!.DraftHandle == recorded.DraftHandle,
            "A failed preview displaced the last successful native review reference.");
        var sidlessHandle = handles.Issue(actor with { SessionId = null }, "message", "draft-1", "draft-current");
        var sidless = await preview.Preview(noSession, sidlessHandle, CancellationToken.None);
        Expect(sidless.StructuredContent!.Value.GetProperty("status").GetString() == "draft_preview_ready"
            && references.Get(actor with { SessionId = null }) is null,
            "Missing review session state broke an otherwise valid ordinary draft preview.");
        var full = new MailReviewStore();
        for (var index = 0; index < 2048; index++) full.Record(actor with { Subject = $"full-{index}" }, "draft", null);
        var uncached = await new MailPreviewTools(NewEwsClient(previewHandler), access, handles, full)
            .Preview(user, draftHandle, CancellationToken.None);
        Expect(uncached.StructuredContent!.Value.GetProperty("status").GetString() == "draft_preview_ready" && full.Get(actor) is null,
            "A full native-review cache broke ordinary successful draft preview.");
        var delegated = actor with { TargetId = "shared-id", Mailbox = "shared@example.test" };
        using (access.SelectTarget(delegated))
        {
            var delegatedDraft = handles.Issue(delegated, "message", "draft-1", "draft-current");
            var delegatedPreview = await preview.Preview(user, delegatedDraft, CancellationToken.None);
            var selector = delegatedPreview.Meta!["emailPreview"]!["mailboxHandle"]!.GetValue<string>();
            var delegatedReview = tools.ReviewEmail(user);
            Expect(delegatedReview.Meta?["emailReviewBootstrap"]?["mailboxHandle"]?.GetValue<string>() == selector
                && delegatedReview.Meta?["emailReviewBootstrap"]?["draftHandle"]?.GetValue<string>()
                    == delegatedPreview.StructuredContent!.Value.GetProperty("draftHandle").GetString(),
                "Native review dropped or reconstructed the originating delegated draft selector.");
        }
    }

    private async Task NativeReviewWireChecksAsync()
    {
        foreach (var protocol in new[] { ProtocolVersion, JulyProtocolVersion })
        {
            var handler = new SignatureRecordingHandler();
            await using var host = await StartHostAsync(handler, writesEnabled: false, sendEnabled: false,
                configure: builder => builder.Services.AddSingleton<IDataProtectionProvider>(new EphemeralDataProtectionProvider()));
            var token = Token("user-a", "mail.read", sessionId: "native-review-session");
            if (protocol == ProtocolVersion) await InitializeAsync(host.Client, token);
            var listed = await ToolRequestAsync(host.Client, token, "tools/list", new { }, protocol);
            using var document = ParseJson(listed.Body);
            var tools = document.RootElement.GetProperty("result").GetProperty("tools").EnumerateArray().ToArray();
            foreach (var (name, resource) in new[]
            {
                ("mail_review_email", MailPreviewResources.ResourceUri),
                ("mail_review_signature", SignaturePreviewResources.ResourceUri)
            })
            {
                var tool = tools.Single(item => item.GetProperty("name").GetString() == name);
                var schema = tool.GetProperty("inputSchema");
                Expect(schema.GetProperty("type").GetString() == "object"
                    && (!schema.TryGetProperty("properties", out var properties) || !properties.EnumerateObject().Any())
                    && (!schema.TryGetProperty("required", out var required) || required.GetArrayLength() == 0),
                    "A native entrypoint required model-generated arguments instead of {}.");
                var annotations = tool.GetProperty("annotations");
                Expect(annotations.GetProperty("readOnlyHint").GetBoolean()
                    && !annotations.GetProperty("destructiveHint").GetBoolean()
                    && annotations.GetProperty("idempotentHint").GetBoolean(),
                    "Native review discovery advertised a mutating or non-idempotent entrypoint.");
                var meta = tool.GetProperty("_meta");
                Expect(meta.GetProperty("ui").GetProperty("resourceUri").GetString() == resource
                    && meta.GetProperty("openai/outputTemplate").GetString() == resource
                    && meta.GetProperty("openai/ui").GetProperty("preferredModelDisplayMode").GetString() == "inline"
                    && meta.GetProperty("openai/ui").GetProperty("entrypoints").EnumerateArray()
                        .Select(item => item.GetProperty("type").GetString()).SequenceEqual(new[] { "thread" }),
                    "A native review descriptor changed its UI route, omitted inline preference or advertised other than one thread entrypoint.");
                var called = await ToolRequestAsync(host.Client, token, "tools/call", new { name, arguments = new { } }, protocol);
                using var calledDocument = ParseJson(called.Body);
                Expect(called.StatusCode == HttpStatusCode.OK && !IsToolError(called.Body),
                    $"Native {{}} invocation failed through the actual SDK for {protocol}/{name}: {called.Body}");
                var result = calledDocument.RootElement.GetProperty("result");
                var outputSchema = tool.GetProperty("outputSchema");
                Expect(PreviewSchemaMatches(outputSchema, result.GetProperty("structuredContent"), outputSchema),
                    "The actual native entrypoint result violated its SDK output schema.");
                var mistyped = JsonNode.Parse(result.GetProperty("structuredContent").GetRawText())!.AsObject();
                mistyped["status"] = 42;
                Expect(!PreviewSchemaMatches(outputSchema, JsonSerializer.SerializeToElement(mistyped), outputSchema),
                    "The native entrypoint output schema accepted a mistyped public status field.");
                var key = name == "mail_review_email" ? "emailReviewBootstrap" : "signatureReviewBootstrap";
                Expect(!result.GetProperty("_meta").GetProperty(key).GetProperty("available").GetBoolean(),
                    "An empty actual MCP entrypoint exposed active controls.");
                var actor = new MailboxIdentity("user-a", "alice@example.test", "chatgpt-test", "native-review-session", "own", "alice@example.test");
                if (name == "mail_review_email")
                    host.App.Services.GetRequiredService<MailReviewStore>().Record(actor, "wire-private-draft", "wire-delegated-selector");
                else host.App.Services.GetRequiredService<SignaturePreviewStore>().Stage(actor, PreviewCandidate());
                var ready = await ToolRequestAsync(host.Client, token, "tools/call", new { name, arguments = new { } }, protocol);
                using var readyDocument = ParseJson(ready.Body);
                var readyResult = readyDocument.RootElement.GetProperty("result");
                Expect(ready.StatusCode == HttpStatusCode.OK && !IsToolError(ready.Body)
                    && PreviewSchemaMatches(outputSchema, readyResult.GetProperty("structuredContent"), outputSchema),
                    "An available native review entrypoint failed actual {} invocation or its public output schema.");
                if (name == "mail_review_email")
                    Expect(readyResult.GetProperty("_meta").GetProperty(key).GetProperty("draftHandle").GetString() == "wire-private-draft"
                        && readyResult.GetProperty("_meta").GetProperty(key).GetProperty("mailboxHandle").GetString() == "wire-delegated-selector"
                        && !readyResult.GetProperty("structuredContent").ToString().Contains("wire-private-draft", StringComparison.Ordinal),
                        "Actual native email review lost private opaque selector data or exposed it publicly.");
                else Expect(readyResult.GetProperty("_meta").GetProperty("signaturePreview").GetProperty("reviewState").GetString() == "pending"
                        && readyResult.GetProperty("structuredContent").GetProperty("previewHandle").GetString()
                            == host.App.Services.GetRequiredService<SignaturePreviewStore>().Latest(actor)!.Handle,
                        "Actual native signature review changed its pending handle or review label.");
            }
            Expect(handler.Writes == 0 && handler.Operations.All(operation => operation.Name.LocalName == "GetUserConfiguration"),
                "Native entrypoint wire calls created drafts, sent mail or changed profiles.");
            var savedTool = tools.Single(tool => tool.GetProperty("name").GetString() == "mail_preview_saved_signature");
            var savedSchema = savedTool.GetProperty("inputSchema");
            Expect(savedSchema.GetProperty("type").GetString() == "object"
                && (!savedSchema.TryGetProperty("properties", out var savedProperties) || !savedProperties.EnumerateObject().Any())
                && (!savedSchema.TryGetProperty("required", out var savedRequired) || savedRequired.GetArrayLength() == 0)
                && savedTool.GetProperty("annotations").GetProperty("readOnlyHint").GetBoolean()
                && !savedTool.GetProperty("annotations").GetProperty("destructiveHint").GetBoolean()
                && savedTool.GetProperty("annotations").GetProperty("idempotentHint").GetBoolean(),
                "Saved inline preview discovery lost its own-only {} schema or read-only annotations.");
            var emptySaved = await ToolRequestAsync(host.Client, token, "tools/call",
                new { name = "mail_preview_saved_signature", arguments = new { } }, protocol);
            Expect(!IsToolError(emptySaved.Body)
                && ToolStructuredData(emptySaved.Body).GetProperty("status").GetString() == "review_empty",
                "Saved inline preview did not handle the absence of saved signatures through the actual SDK.");
            var rejectedSelector = await ToolRequestAsync(host.Client, token, "tools/call",
                new { name = "mail_preview_saved_signature", arguments = new { mailboxHandle = "unsupported" } }, protocol);
            Expect(IsToolError(rejectedSelector.Body), "Saved inline preview accepted an unsupported mailbox selector.");
            Expect(handler.Writes == 0 && handler.Operations.All(operation => operation.Name.LocalName == "GetUserConfiguration"),
                "Empty saved inline preview or a rejected selector changed settings or performed unrelated Exchange operations.");
            var savedActor = new MailboxIdentity("user-a", "alice@example.test", "chatgpt-test", "native-review-session", "own", "alice@example.test");
            var store = host.App.Services.GetRequiredService<SignatureStore>();
            var previewStore = host.App.Services.GetRequiredService<SignaturePreviewStore>();
            var image = new SignatureImage("saved.png", "image/png", "saved-logo", PngBase64(8));
            var savedProfile = new MailSignature("Saved", "<table dir=\"rtl\"><tr><td>سلام</td><td><img src=\"cid:saved-logo\"/></td></tr></table>", "HTML", [image]);
            var snapshot = await store.UpdateAsync(NewEwsClient(handler), savedActor.Mailbox, "new",
                _ => new([savedProfile], "Saved", "Saved", new("fa", "completed")), CancellationToken.None);
            var candidate = PreviewCandidate() with { Revision = snapshot.Revision };
            var pendingHandle = previewStore.Stage(savedActor, candidate);
            var pendingBefore = previewStore.Latest(savedActor)!;
            await CheckSavedInlineAsync(snapshot, savedProfile);
            foreach (var (settings, selected) in new (SignatureSettings Settings, MailSignature? Selected)[]
            {
                (snapshot.Settings with { Profiles = [savedProfile, savedProfile with { Name = "Other" }], NewMessages = "Other", Replies = "Saved" }, savedProfile with { Name = "Other" }),
                (snapshot.Settings with { Profiles = [savedProfile, savedProfile with { Name = "Other" }], NewMessages = null }, savedProfile),
                (snapshot.Settings with { NewMessages = null, Replies = null }, savedProfile),
                (snapshot.Settings with { Profiles = [savedProfile, savedProfile with { Name = "Other" }], NewMessages = null, Replies = null }, null),
                (snapshot.Settings with { Profiles = [], NewMessages = null, Replies = null }, null)
            })
            {
                snapshot = await store.UpdateAsync(NewEwsClient(handler), savedActor.Mailbox, snapshot.Revision,
                    _ => settings, CancellationToken.None);
                Expect(snapshot.Revision != candidate.Revision, "Saved inline stale-candidate fixture did not change the revision.");
                await CheckSavedInlineAsync(snapshot, selected);
            }

            async Task CheckSavedInlineAsync(SignatureSnapshot expectedSnapshot, MailSignature? selected)
            {
                var writes = handler.Writes;
                var operationCount = handler.Operations.Count;
                for (var repeat = 0; repeat < 2; repeat++)
                {
                    var called = await ToolRequestAsync(host.Client, token, "tools/call",
                        new { name = "mail_preview_saved_signature", arguments = new { } }, protocol);
                    using var calledDocument = ParseJson(called.Body);
                    var result = calledDocument.RootElement.GetProperty("result");
                    var output = result.GetProperty("structuredContent");
                    var outputSchema = savedTool.GetProperty("outputSchema");
                    Expect(called.StatusCode == HttpStatusCode.OK && !IsToolError(called.Body)
                        && PreviewSchemaMatches(outputSchema, output, outputSchema)
                        && output.GetProperty("previewHandle").ValueKind == JsonValueKind.Null
                        && output.GetProperty("previewExpiresAt").ValueKind == JsonValueKind.Null,
                        "Saved inline {} invocation failed the actual SDK schema or offered a pending save handle.");
                    if (selected is null)
                        Expect(output.GetProperty("status").GetString() == "review_empty"
                            && !result.GetProperty("_meta").TryGetProperty("signaturePreview", out _),
                            "Saved inline display invented a signature for absent or ambiguous saved selection.");
                    else
                    {
                        var expected = SignaturePreviewResources.CreateMetadata(selected, expectedSnapshot.Settings.Onboarding?.Language,
                            new { forNewMessages = expectedSnapshot.Settings.NewMessages, forReplies = expectedSnapshot.Settings.Replies }, []);
                        expected["signaturePreview"]!["reviewState"] = "saved";
                        Expect(output.GetProperty("reviewState").GetString() == "saved"
                            && JsonNode.DeepEquals(JsonNode.Parse(result.GetProperty("_meta").GetProperty("signaturePreview").GetRawText()), expected["signaturePreview"])
                            && !output.ToString().Contains(image.ContentBase64, StringComparison.Ordinal)
                            && !result.GetProperty("content").ToString().Contains(image.ContentBase64, StringComparison.Ordinal)
                            && !result.GetProperty("content").ToString().Contains(selected.Body, StringComparison.Ordinal),
                            "Saved inline display changed saved HTML/CID bytes, selection or label, or exposed image bytes publicly.");
                    }
                    Expect(previewStore.Latest(savedActor)!.Handle == pendingHandle
                        && previewStore.Latest(savedActor)!.ExpiresAt == pendingBefore.ExpiresAt
                        && JsonSerializer.Serialize(previewStore.Peek(savedActor, pendingHandle)) == JsonSerializer.Serialize(candidate),
                        "Saved inline display changed, consumed, restaged or extended the current/stale pending candidate.");
                }
                var after = await store.ReadAsync(NewEwsClient(handler), savedActor.Mailbox, CancellationToken.None);
                Expect(handler.Writes == writes && after.Revision == expectedSnapshot.Revision
                    && JsonSerializer.Serialize(after.Settings) == JsonSerializer.Serialize(expectedSnapshot.Settings)
                    && handler.Operations.Skip(operationCount).All(operation => operation.Name.LocalName == "GetUserConfiguration"),
                    "Saved inline display wrote signatures, defaults/setup, created mail or performed operations beyond configuration reads.");
            }
            foreach (var (name, resource) in new[]
            {
                ("mail_capture_signature", SignaturePreviewResources.ResourceUri),
                ("mail_preview_signature", SignaturePreviewResources.ResourceUri),
                ("mail_preview_saved_signature", SignaturePreviewResources.ResourceUri),
                ("mail_preview_draft", MailPreviewResources.ResourceUri)
            })
            {
                var meta = tools.Single(tool => tool.GetProperty("name").GetString() == name).GetProperty("_meta");
                var display = meta.GetProperty("openai/ui");
                Expect(meta.GetProperty("ui").GetProperty("resourceUri").GetString() == resource
                    && meta.GetProperty("openai/outputTemplate").GetString() == resource
                    && display.GetProperty("preferredModelDisplayMode").GetString() == "inline"
                    && !display.TryGetProperty("entrypoints", out _),
                    "An existing producer changed its UI route, lost inline display or gained native review entrypoints.");
            }
            Expect(handler.Operations.All(operation => operation.Name.LocalName is "GetUserConfiguration" or "CreateUserConfiguration" or "UpdateUserConfiguration"),
                "Native entrypoint or saved inline wire calls created drafts or sent mail.");
        }
    }
}
