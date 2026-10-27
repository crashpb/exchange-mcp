using System.Net;
using System.Security.Claims;
using System.Text.Json;
using System.Xml.Linq;
using Company.ExchangeMcp;
using Company.ExchangeMcp.Security;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

internal sealed partial class Checks
{
    private async Task OnboardingChecksAsync()
    {
        var exchange = new OnboardingRecordingHandler(new SignatureRecordingHandler());
        var store = new SignatureStore();
        const string mailbox = "alice@example.test";
        const string privateBody = "Existing signature body must not appear in onboarding state.";
        var seeded = await store.UpdateAsync(NewEwsClient(exchange), mailbox, "new", _ =>
            new([new MailSignature("Existing", privateBody, "Text", [])], "Existing", "Existing"), CancellationToken.None);
        var priorWrites = exchange.Writes;
        const string publicResource = "https://public-mail.example.test/mcp";
        const string chatGptClient = "https://chatgpt.com/oauth/client.json";

        await using var host = await StartHostAsync(exchange, writesEnabled: true, sendEnabled: false, configure: builder =>
        {
            builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Service:PublicResource"] = publicResource,
                ["Service:AllowedClientIds:2"] = chatGptClient
            });
            builder.Services.AddSingleton<IDataProtectionProvider>(new EphemeralDataProtectionProvider());
        });
        var aliceToken = Token("user-a", "mail.read mail.write", sessionId: "onboarding-session-a");
        await InitializeAsync(host.Client, aliceToken);
        var readOnlyToken = Token("user-a", "mail.read", sessionId: "onboarding-session-a");
        var beforeProfile = exchange.Operations.Count;
        var profile = await OnboardingCallAsync(host, readOnlyToken, "mail_profile", new { });
        var incomingMail = profile.GetProperty("incomingMail");
        Expect(incomingMail.GetProperty("eventName").GetString() == MailEventService.InboxEventName
            && incomingMail.GetProperty("scope").GetString() == "own_inbox"
            && incomingMail.GetProperty("subscription").GetString() == "host_managed_opt_in"
            && incomingMail.GetProperty("requiresHostSupport").GetBoolean()
            && incomingMail.GetProperty("statusTool").GetString() == "mail_event_status"
            && incomingMail.GetProperty("subscriptionStatus").GetString() == "not_checked"
            && !incomingMail.TryGetProperty("active", out _)
            && !incomingMail.TryGetProperty("hostSupported", out _)
            && incomingMail.GetProperty("requests").GetProperty("fa").GetString()!.Contains("ایمیل جدید", StringComparison.Ordinal)
            && incomingMail.GetProperty("requests").GetProperty("en").GetString()!.Contains("new company mail", StringComparison.Ordinal)
            && profile.GetProperty("onboarding").GetProperty("showGuideOnRequest").GetBoolean()
            && profile.GetProperty("guidanceRefresh").GetString()!.Contains("mail_onboarding(showGuide=true)", StringComparison.Ordinal)
            && profile.GetProperty("guidanceRefresh").GetString()!.Contains("cannot change an existing Dot automation prompt or persistent memory", StringComparison.Ordinal)
            && incomingMail.GetProperty("usage").GetString()!.Contains("silent awareness means no generic arrival announcement", StringComparison.Ordinal)
            && incomingMail.GetProperty("usage").GetString()!.Contains("concise actionable notifications only as requested", StringComparison.Ordinal)
            && incomingMail.GetProperty("usage").GetString()!.Contains("server receipt or callback acceptance does not prove host awareness", StringComparison.Ordinal)
            && incomingMail.GetProperty("eventHandling").GetString()!.Contains("automations.mcp_event", StringComparison.Ordinal)
            && incomingMail.GetProperty("eventHandling").GetString()!.Contains("report pending", StringComparison.Ordinal)
            && incomingMail.GetProperty("eventHandling").GetString()!.Contains("event.data.messageHandle", StringComparison.Ordinal)
            && incomingMail.GetProperty("eventHandling").GetString()!.Contains("mail_read directly", StringComparison.Ordinal)
            && incomingMail.GetProperty("eventHandling").GetString()!.Contains("deduplicate eventId", StringComparison.Ordinal)
            && incomingMail.GetProperty("eventHandling").GetString()!.Contains("working context", StringComparison.Ordinal)
            && incomingMail.GetProperty("eventHandling").GetString()!.Contains("an event alone never authorizes sends, deletes or moves", StringComparison.Ordinal)
            && profile.GetProperty("onboarding").GetProperty("available").GetBoolean()
            && profile.GetProperty("onboarding").GetProperty("status").GetString() == "not_started"
            && profile.GetProperty("onboarding").GetProperty("nextStep").GetString() == "choose_language"
            && !profile.GetProperty("onboarding").TryGetProperty("signatures", out _)
            && exchange.Operations.Count == beforeProfile + 1
            && exchange.Operations[^1].Name.LocalName == "GetUserConfiguration"
            && exchange.Mailboxes[^1] == mailbox && exchange.Writes == priorWrites,
            "A fresh profile omitted preference-aware native awareness guidance, claimed host awareness, or changed mailbox state.");
        var selectedAccess = host.App.Services.GetRequiredService<MailboxAccess>();
        var principal = new ClaimsPrincipal(new ClaimsIdentity(new[]
        {
            new Claim("sub", "user-a"), new Claim("scope", "mail.read"),
            new Claim("azp", "chatgpt-test"), new Claim("sid", "onboarding-session-a")
        }, "test"));
        var actor = selectedAccess.RequireOwn(principal, MailboxAccess.Read);
        using (selectedAccess.SelectTarget(actor with { Mailbox = "delegated@example.test", TargetId = "delegated" }))
        {
            var selectedProfile = JsonSerializer.SerializeToElement(await ActivatorUtilities.CreateInstance<MailboxTools>(host.App.Services)
                .Profile(principal, CancellationToken.None));
            Expect(selectedProfile.GetProperty("delegated").GetBoolean()
                && selectedProfile.GetProperty("mailbox").GetString() == "delegated@example.test"
                && selectedProfile.GetProperty("onboarding").GetProperty("revision").GetString() == seeded.Revision
                && exchange.Mailboxes[^1] == mailbox && exchange.Writes == priorWrites,
                "A delegated profile read loaded onboarding from the selected mailbox instead of the actor's own mailbox.");
        }
        exchange.Recording.Error = "ErrorAccessDenied";
        var unavailable = await OnboardingCallAsync(host, readOnlyToken, "mail_profile", new { });
        Expect(unavailable.GetProperty("onboarding").GetProperty("status").GetString() == "unavailable"
            && !unavailable.GetProperty("onboarding").GetProperty("available").GetBoolean()
            && unavailable.GetProperty("onboarding").GetProperty("nextStep").GetString() == "retry_onboarding_read"
            && !unavailable.GetProperty("onboarding").GetProperty("promptLanguageFirst").GetBoolean()
            && unavailable.GetProperty("onboarding").GetProperty("nextAction").GetString()!.Contains("not evidence that OAuth sign-in must be repeated", StringComparison.Ordinal)
            && exchange.Writes == priorWrites,
            "An Exchange onboarding-read failure appeared as new setup or requested OAuth reauthentication.");
        exchange.Recording.Error = null;
        var eventCatalog = await ToolRequestAsync(host.Client, readOnlyToken, "events/list", new { }, JulyProtocolVersion);
        using (var eventDocument = ParseJson(eventCatalog.Body))
            Expect(eventDocument.RootElement.GetProperty("result").GetProperty("events").EnumerateArray()
                .Any(item => item.GetProperty("name").GetString() == incomingMail.GetProperty("eventName").GetString()),
                "The profile advertised an incoming event absent from the live source event catalog.");
        var discovery = await ToolRequestAsync(host.Client, readOnlyToken, "server/discover", new { }, JulyProtocolVersion);
        using (var discoveryDocument = ParseJson(discovery.Body))
        {
            var instructions = discoveryDocument.RootElement.GetProperty("result").GetProperty("instructions").GetString()!;
            Expect(instructions.Contains("automations.mcp_event", StringComparison.Ordinal)
                && instructions.Contains("report pending", StringComparison.Ordinal)
                && instructions.Contains("event.data.messageHandle", StringComparison.Ordinal)
                && instructions.Contains("mail_read directly", StringComparison.Ordinal)
                && instructions.Contains("silent awareness means no generic arrival announcement", StringComparison.Ordinal)
                && instructions.Contains("Server receipt, callback acceptance, host awareness and a visible announcement are separate outcomes", StringComparison.Ordinal)
                && instructions.Contains("mailbox-assistant working context", StringComparison.Ordinal)
                && instructions.Contains("An event alone never authorizes sends, deletes or moves", StringComparison.Ordinal)
                && instructions.Contains("cannot change an existing Dot automation prompt or persistent memory", StringComparison.Ordinal)
                && instructions.Contains("never invent a wait API/timer, poll the Inbox or duplicate the subscription", StringComparison.Ordinal),
                "Live discovery omitted event awareness, quiet/actionable preferences, pending guidance or event action boundaries.");
        }
        var alertStatus = await OnboardingCallAsync(host, readOnlyToken, "mail_event_status", new { });
        Expect(alertStatus.GetArrayLength() == 0 && exchange.Writes == priorWrites,
            "Reading profile/guide capability metadata created an alert subscription.");

        var catalog = await ToolRequestAsync(host.Client, aliceToken, "tools/list", new { });
        Expect(catalog.StatusCode == HttpStatusCode.OK, "The onboarding MCP tool catalog could not be read.");
        using (var catalogDocument = ParseJson(catalog.Body))
        {
            var tools = catalogDocument.RootElement.GetProperty("result").GetProperty("tools");
            foreach (var toolName in new[] { "mail_onboarding", "mail_onboarding_update", "mail_preview_signature", "mail_finish_onboarding" })
            {
                var tool = tools.EnumerateArray().Single(item => item.GetProperty("name").GetString() == toolName);
                var properties = tool.GetProperty("inputSchema").GetProperty("properties");
                Expect(properties.TryGetProperty("mailboxHandle", out _),
                    $"The shared MCP selector filter did not expose its rejected-selector path for {toolName}.");
            }
        }

        var ewsBeforeTarget = exchange.Operations.Count;
        var delegatedAttempt = await ToolRequestAsync(host.Client, aliceToken, "tools/call", new
        {
            name = "mail_onboarding",
            arguments = new { mailboxHandle = "not-a-valid-target-handle" }
        });
        Expect(delegatedAttempt.StatusCode == HttpStatusCode.OK && IsToolError(delegatedAttempt.Body)
            && exchange.Operations.Count == ewsBeforeTarget,
            "The own-mailbox onboarding tool accepted a delegated mailbox selector or reached EWS.");

        var initial = await OnboardingCallAsync(host, aliceToken, "mail_onboarding", new { });
        Expect(initial.GetProperty("status").GetString() == "not_started"
            && initial.GetProperty("promptLanguageFirst").GetBoolean()
            && initial.GetProperty("languageChoices").GetProperty("fa").GetString() == "فارسی"
            && initial.GetProperty("languageChoices").GetProperty("en").GetString() == "English"
            && initial.GetProperty("prompt").GetString()!.Contains("choose Persian (fa) or English (en)", StringComparison.Ordinal)
            && !initial.TryGetProperty("guide", out _)
            && exchange.Writes == priorWrites,
            "The first onboarding response did not ask for language before showing the guide or writing state.");
        var firstRevision = initial.GetProperty("revision").GetString()!;

        await OnboardingErrorAsync(host, Token("user-a", "mail.read", sessionId: "onboarding-session-a"),
            "mail_onboarding_update", new { action = "choose_language", revision = firstRevision, language = "fa" });
        await OnboardingErrorAsync(host, aliceToken, "mail_onboarding_update",
            new { action = "skip", revision = firstRevision });
        Expect(exchange.Writes == priorWrites,
            "A read-only token or a language-less skip changed the saved onboarding configuration.");

        var selected = await OnboardingCallAsync(host, aliceToken, "mail_onboarding_update",
            new { action = "choose_language", language = "fa", revision = firstRevision });
        Expect(selected.GetProperty("language").GetString() == "fa"
            && selected.GetProperty("status").GetString() == "pending"
            && selected.GetProperty("guide").GetProperty("steps").GetArrayLength() == 3
            && selected.GetProperty("guide").GetProperty("steps")[1].GetString()!.Contains("تنظیم فعلی را حفظ می‌کند", StringComparison.Ordinal)
            && selected.GetProperty("guide").GetProperty("capabilities").GetString()!.Contains("با Exchange MCP", StringComparison.Ordinal)
            && selected.GetProperty("signatures").GetProperty("profiles")[0].GetString() == "Existing"
            && !JsonSerializer.Serialize(selected).Contains(privateBody, StringComparison.Ordinal),
            "Selecting Persian did not show the concise Persian guide and profile metadata without private signature content.");
        var pendingProfile = await OnboardingCallAsync(host, readOnlyToken, "mail_profile", new { });
        Expect(pendingProfile.GetProperty("onboarding").GetProperty("status").GetString() == "pending"
            && pendingProfile.GetProperty("onboarding").GetProperty("nextStep").GetString() == "signature_setup"
            && pendingProfile.GetProperty("onboarding").GetProperty("language").GetString() == "fa",
            "A profile did not expose persisted pending language/setup state.");
        var revision = selected.GetProperty("revision").GetString()!;
        var persianGuide = selected.GetProperty("guide");
        Expect(persianGuide.GetProperty("notifications").GetString()!.Contains("اتصال زندهٔ Exchange", StringComparison.Ordinal)
            && !persianGuide.GetProperty("notifications").GetString()!.Contains("۱۵", StringComparison.Ordinal)
            && persianGuide.GetProperty("notifications").GetString()!.Contains("automations.mcp_event", StringComparison.Ordinal)
            && persianGuide.GetProperty("notifications").GetString()!.Contains("در انتظار", StringComparison.Ordinal)
            && persianGuide.GetProperty("notifications").GetString()!.Contains("event.data.messageHandle", StringComparison.Ordinal)
            && persianGuide.GetProperty("notifications").GetString()!.Contains("mail_read مستقیم", StringComparison.Ordinal)
            && persianGuide.GetProperty("notifications").GetString()!.Contains("آگاهی بی‌صدا یعنی بدون اعلان عمومی", StringComparison.Ordinal)
            && persianGuide.GetProperty("notifications").GetString()!.Contains("اعلان کوتاه و کاربردی فقط مطابق درخواست شماست", StringComparison.Ordinal)
            && persianGuide.GetProperty("notifications").GetString()!.Contains("به معنی آگاهی Dot یا نمایش اعلان نیست", StringComparison.Ordinal)
            && persianGuide.GetProperty("notifications").GetString()!.Contains("رویداد به‌تنهایی مجوز ارسال، حذف یا جابه‌جایی نیست", StringComparison.Ordinal)
            && persianGuide.GetProperty("refreshKnowledge").GetString()!.Contains("به‌روز کن", StringComparison.Ordinal)
            && persianGuide.GetProperty("refreshKnowledge").GetString()!.Contains("متن اتوماسیون موجود Dot و حافظهٔ پایدار آن", StringComparison.Ordinal),
            "The Persian guide omitted preference-aware event awareness or its safety and host-update boundaries.");
        Expect(exchange.Writes == priorWrites + 1, "Selecting a language did not persist exactly one onboarding-state update.");

        var alternateClientToken = Token("user-a", "mail.read mail.write", azp: "chatgpt-alt", sessionId: "onboarding-session-a");
        var fromOtherClient = await OnboardingCallAsync(host, alternateClientToken, "mail_onboarding", new { });
        Expect(fromOtherClient.GetProperty("language").GetString() == "fa"
            && fromOtherClient.GetProperty("status").GetString() == "pending",
            "The chosen onboarding language or pending state did not persist across approved MCP clients.");
        var publicRoot = new Uri(publicResource).GetLeftPart(UriPartial.Authority) + "/";
        var chatGptToken = Token("user-a", "mail.read", audience: publicResource, azp: chatGptClient,
            sessionId: "onboarding-session-a");
        var chatGptRead = await ToolRequestAsync(host.Client, chatGptToken, "tools/call", new
        {
            name = "mail_onboarding",
            arguments = new { }
        }, absoluteUri: publicRoot);
        Expect(chatGptRead.StatusCode == HttpStatusCode.OK && !IsToolError(chatGptRead.Body)
            && ToolStructuredData(chatGptRead.Body).GetProperty("language").GetString() == "fa",
            "The public ChatGPT OAuth client could not read the persisted language through the public MCP hostname.");

        var collision = new
        {
            revision,
            name = "Existing",
            body = "Replacement body",
            bodyType = "Text",
            makeDefaultForNew = false,
            makeDefaultForReplies = false
        };
        var writesBeforeCollision = exchange.Writes;
        await OnboardingErrorAsync(host, aliceToken, "mail_preview_signature", collision);
        var replacementPreview = await OnboardingCallAsync(host, aliceToken, "mail_preview_signature",
            new
            {
                revision,
                name = "Existing",
                body = "Replacement body",
                bodyType = "Text",
                makeDefaultForNew = false,
                makeDefaultForReplies = false,
                replaceExisting = true
            });
        Expect(replacementPreview.GetProperty("replacesExistingProfile").GetBoolean()
            && replacementPreview.GetProperty("affectedExistingDefaults").GetProperty("newMessages").GetBoolean()
            && replacementPreview.GetProperty("affectedExistingDefaults").GetProperty("replies").GetBoolean()
            && replacementPreview.GetProperty("defaults").GetProperty("willChangeNewMessages").GetBoolean()
            && replacementPreview.GetProperty("defaults").GetProperty("willChangeReplies").GetBoolean()
            && exchange.Writes == writesBeforeCollision,
            "An explicitly previewed same-name replacement did not reveal that both existing defaults' content would change.");

        var unsafeRemoteImage = await OnboardingCallErrorBodyAsync(host, aliceToken, "mail_preview_signature", new
        {
            revision,
            name = "Unsafe",
            body = "<img src=\"https://tracking.example.test/pixel.png\" />",
            bodyType = "HTML"
        });
        var hiddenBidi = await OnboardingCallErrorBodyAsync(host, aliceToken, "mail_preview_signature", new
        {
            revision,
            name = "Unsafe bidi",
            body = "Safe\u202Etxt",
            bodyType = "Text"
        });
        var entityHiddenBidi = await OnboardingCallErrorBodyAsync(host, aliceToken, "mail_preview_signature", new
        {
            revision,
            name = "Encoded unsafe bidi",
            body = "<p>&#x202E;spoof</p>",
            bodyType = "HTML"
        });
        Expect(unsafeRemoteImage && hiddenBidi && entityHiddenBidi && exchange.Writes == writesBeforeCollision,
            "Unsafe HTML or hidden bidi controls reached the saved signature configuration.");

        var png = PngBase64(8);
        var candidate = new
        {
            revision,
            name = "Persian Work",
            body = "<p dir=\"ltr\">English address: person@example.test</p><p>می\u200Cخواهم سلام</p><img src=\"cid:brand\" />",
            bodyType = "HTML",
            images = new[] { new { name = "brand.png", contentType = "image/png", contentId = "brand", contentBase64 = png } },
            makeDefaultForNew = false,
            makeDefaultForReplies = true,
            replaceExisting = false
        };
        var preview = await OnboardingCallAsync(host, aliceToken, "mail_preview_signature", candidate);
        var safeBody = preview.GetProperty("signature").GetProperty("safeBody").GetString()!;
        var previewJson = JsonSerializer.Serialize(preview);
        Expect(preview.GetProperty("status").GetString() == "signature_preview_ready"
            && safeBody.Contains("dir=\"rtl\"", StringComparison.Ordinal)
            && safeBody.Contains("lang=\"fa\"", StringComparison.Ordinal)
            && safeBody.Contains("<p dir=\"ltr\">English address: person@example.test</p>", StringComparison.Ordinal)
            && preview.GetProperty("signature").GetProperty("images")[0].GetProperty("sizeBytes").GetInt32() == 8
            && !previewJson.Contains(png, StringComparison.Ordinal)
            && preview.GetProperty("defaults").GetProperty("forNewMessages").GetString() == "Existing"
            && preview.GetProperty("defaults").GetProperty("forReplies").GetString() == "Persian Work"
            && !preview.GetProperty("defaults").GetProperty("willChangeNewMessages").GetBoolean()
            && preview.GetProperty("defaults").GetProperty("willChangeReplies").GetBoolean()
            && preview.GetProperty("appearanceNote").GetString()!.Contains("client may render it differently", StringComparison.Ordinal)
            && exchange.Writes == writesBeforeCollision,
            "The sanitized Persian preview lost mixed-direction content, exposed image bytes, changed the wrong defaults, or wrote before confirmation.");
        var previewHandle = preview.GetProperty("previewHandle").GetString()!;

        var finishArguments = new
        {
            revision,
            previewHandle,
            name = candidate.name,
            body = candidate.body,
            bodyType = candidate.bodyType,
            images = candidate.images,
            makeDefaultForNew = candidate.makeDefaultForNew,
            makeDefaultForReplies = candidate.makeDefaultForReplies,
            replaceExisting = candidate.replaceExisting
        };
        var writesBeforeInvalidProofs = exchange.Writes;
        await OnboardingErrorAsync(host, Token("user-b", "mail.read mail.write", sessionId: "onboarding-session-b"),
            "mail_finish_onboarding", finishArguments);
        await OnboardingErrorAsync(host, alternateClientToken, "mail_finish_onboarding", finishArguments);
        await OnboardingErrorAsync(host, Token("user-a", "mail.read mail.write", sessionId: "different-session"),
            "mail_finish_onboarding", finishArguments);
        await OnboardingErrorAsync(host, aliceToken, "mail_finish_onboarding", new
        {
            revision,
            previewHandle,
            name = candidate.name,
            body = "changed after preview",
            bodyType = candidate.bodyType,
            images = candidate.images,
            makeDefaultForNew = candidate.makeDefaultForNew,
            makeDefaultForReplies = candidate.makeDefaultForReplies,
            replaceExisting = candidate.replaceExisting
        });
        Expect(exchange.Writes == writesBeforeInvalidProofs,
            "An altered, other-user, other-client, or other-session preview handle reached EWS configuration writes.");

        var changedLanguage = await OnboardingCallAsync(host, aliceToken, "mail_onboarding_update",
            new { action = "choose_language", language = "en", revision });
        Expect(changedLanguage.GetProperty("language").GetString() == "en"
            && changedLanguage.GetProperty("guide").GetProperty("steps")[0].GetString()!.StartsWith("1)", StringComparison.Ordinal),
            "Changing the selected language did not return the English guide.");
        var englishRevision = changedLanguage.GetProperty("revision").GetString()!;
        await OnboardingErrorAsync(host, aliceToken, "mail_finish_onboarding", finishArguments);
        var writesBeforeEnglishPreview = exchange.Writes;
        var englishPreview = await OnboardingCallAsync(host, aliceToken, "mail_preview_signature", new
        {
            revision = englishRevision,
            name = candidate.name,
            body = candidate.body,
            bodyType = candidate.bodyType,
            images = candidate.images,
            makeDefaultForNew = candidate.makeDefaultForNew,
            makeDefaultForReplies = candidate.makeDefaultForReplies,
            replaceExisting = candidate.replaceExisting
        });
        var englishHandle = englishPreview.GetProperty("previewHandle").GetString()!;
        Expect(englishPreview.GetProperty("signature").GetProperty("safeBody").GetString()!.Contains("dir=\"rtl\"", StringComparison.Ordinal)
            && exchange.Writes == writesBeforeEnglishPreview,
            "Persian signature direction depended on the selected UI language or the preview wrote state.");

        var finish = await OnboardingCallAsync(host, aliceToken, "mail_finish_onboarding", new
        {
            revision = englishRevision,
            previewHandle = englishHandle,
            name = candidate.name,
            body = candidate.body,
            bodyType = candidate.bodyType,
            images = candidate.images,
            makeDefaultForNew = candidate.makeDefaultForNew,
            makeDefaultForReplies = candidate.makeDefaultForReplies,
            replaceExisting = candidate.replaceExisting
        });
        Expect(finish.GetProperty("status").GetString() == "pending"
            && finish.GetProperty("nextStep").GetString() == "more_signatures_and_rules"
            && finish.GetProperty("stage").GetString() == "more_signatures_and_rules"
            && finish.GetProperty("signatures").GetProperty("defaults").GetProperty("forNewMessages").GetString() == "Existing"
            && finish.GetProperty("signatures").GetProperty("defaults").GetProperty("forReplies").GetString() == "Persian Work"
            && finish.GetProperty("signatures").GetProperty("profiles").GetArrayLength() == 2
            && exchange.Writes == writesBeforeEnglishPreview + 1,
            "Confirmed signature save did not preserve pending setup for additional signatures and usage rules.");
        var afterSaveProfile = await OnboardingCallAsync(host, readOnlyToken, "mail_profile", new { });
        Expect(afterSaveProfile.GetProperty("onboarding").GetProperty("nextStep").GetString() == "more_signatures_and_rules"
            && afterSaveProfile.GetProperty("onboarding").GetProperty("revision").GetString() == finish.GetProperty("revision").GetString()
            && exchange.Writes == writesBeforeEnglishPreview + 1,
            "A profile read lost the saved onboarding stage or mutated setup after first signature approval.");
        finish = await OnboardingCallAsync(host, aliceToken, "mail_finish_onboarding", new
        {
            revision = finish.GetProperty("revision").GetString(),
            keepExisting = true
        });
        Expect(finish.GetProperty("status").GetString() == "completed",
            "Explicitly finishing setup after additional-signature/rule answers did not complete onboarding.");
        var completedRevision = finish.GetProperty("revision").GetString()!;
        await OnboardingErrorAsync(host, aliceToken, "mail_finish_onboarding", new
        {
            revision = englishRevision,
            previewHandle = englishHandle,
            name = candidate.name,
            body = candidate.body,
            bodyType = candidate.bodyType,
            images = candidate.images,
            makeDefaultForNew = candidate.makeDefaultForNew,
            makeDefaultForReplies = candidate.makeDefaultForReplies,
            replaceExisting = candidate.replaceExisting
        });
        var quiet = await OnboardingCallAsync(host, aliceToken, "mail_onboarding", new { });
        var completedProfile = await OnboardingCallAsync(host, readOnlyToken, "mail_profile", new { });
        Expect(quiet.GetProperty("status").GetString() == "completed"
            && OnboardingGuideSuppressed(quiet)
            && completedProfile.GetProperty("onboarding").GetProperty("nextStep").GetString() == "none"
            && OnboardingGuideSuppressed(completedProfile.GetProperty("onboarding")),
            "Completed onboarding kept displaying the guide by default.");
        var writesBeforeGuide = exchange.Writes;
        var guideAgain = await OnboardingCallAsync(host, readOnlyToken, "mail_onboarding", new { showGuide = true });
        Expect(guideAgain.GetProperty("guide").GetProperty("capabilities").GetString()!.StartsWith("Exchange MCP lets", StringComparison.Ordinal)
            && guideAgain.GetProperty("guide").GetProperty("notifications").GetString()!.Contains("Exchange streaming", StringComparison.Ordinal)
            && !guideAgain.GetProperty("guide").GetProperty("notifications").GetString()!.Contains("15 seconds", StringComparison.Ordinal)
            && guideAgain.GetProperty("guide").GetProperty("notifications").GetString()!.Contains("automations.mcp_event", StringComparison.Ordinal)
            && guideAgain.GetProperty("guide").GetProperty("notifications").GetString()!.Contains("report pending", StringComparison.Ordinal)
            && guideAgain.GetProperty("guide").GetProperty("notifications").GetString()!.Contains("event.data.messageHandle", StringComparison.Ordinal)
            && guideAgain.GetProperty("guide").GetProperty("notifications").GetString()!.Contains("mail_read directly", StringComparison.Ordinal)
            && guideAgain.GetProperty("guide").GetProperty("notifications").GetString()!.Contains("working context for awareness and triage", StringComparison.Ordinal)
            && guideAgain.GetProperty("guide").GetProperty("notifications").GetString()!.Contains("Silent awareness means no generic arrival announcement", StringComparison.Ordinal)
            && guideAgain.GetProperty("guide").GetProperty("notifications").GetString()!.Contains("concise actionable notifications follow your request", StringComparison.Ordinal)
            && guideAgain.GetProperty("guide").GetProperty("notifications").GetString()!.Contains("does not prove Dot awareness or an announcement", StringComparison.Ordinal)
            && guideAgain.GetProperty("guide").GetProperty("notifications").GetString()!.Contains("An event alone never authorizes sends, deletes or moves", StringComparison.Ordinal)
            && guideAgain.GetProperty("guide").GetProperty("refreshKnowledge").GetString()!.Contains("Refresh Exchange MCP", StringComparison.Ordinal)
            && guideAgain.GetProperty("guide").GetProperty("refreshKnowledge").GetString()!.Contains("cannot force a host cache refresh or change an existing Dot automation prompt or persistent memory", StringComparison.Ordinal)
            && guideAgain.GetProperty("status").GetString() == "completed"
            && guideAgain.GetProperty("language").GetString() == quiet.GetProperty("language").GetString()
            && guideAgain.GetProperty("revision").GetString() == completedRevision
            && guideAgain.GetProperty("signatures").GetRawText() == quiet.GetProperty("signatures").GetRawText()
            && exchange.Writes == writesBeforeGuide,
            "Reading the completed user's guide changed setup or omitted preference-aware awareness and host-update boundaries.");

        var reset = await OnboardingCallAsync(host, aliceToken, "mail_onboarding_update",
            new { action = "reset", revision = completedRevision });
        Expect(reset.GetProperty("status").GetString() == "pending"
            && reset.GetProperty("language").GetString() == "en"
            && reset.GetProperty("signatures").GetProperty("profiles").GetArrayLength() == 2
            && reset.GetProperty("signatures").GetProperty("defaults").GetProperty("forNewMessages").GetString() == "Existing"
            && reset.GetProperty("signatures").GetProperty("defaults").GetProperty("forReplies").GetString() == "Persian Work",
            "Reset changed the language, saved profiles or defaults instead of only reopening onboarding.");
        var skipped = await OnboardingCallAsync(host, aliceToken, "mail_onboarding_update",
            new { action = "skip", revision = reset.GetProperty("revision").GetString() });
        Expect(skipped.GetProperty("status").GetString() == "skipped"
            && OnboardingGuideSuppressed(skipped),
            "Skip did not persist the skipped state quietly.");
        var skippedProfile = await OnboardingCallAsync(host, readOnlyToken, "mail_profile", new { });
        Expect(skippedProfile.GetProperty("onboarding").GetProperty("status").GetString() == "skipped"
            && skippedProfile.GetProperty("onboarding").GetProperty("nextStep").GetString() == "none"
            && OnboardingGuideSuppressed(skippedProfile.GetProperty("onboarding")),
            "A skipped user's profile restarted setup or displayed the guide.");
        var writesBeforeSkippedGuide = exchange.Writes;
        var skippedGuide = await OnboardingCallAsync(host, readOnlyToken, "mail_onboarding", new { showGuide = true });
        Expect(skippedGuide.GetProperty("guide").ValueKind == JsonValueKind.Object
            && skippedGuide.GetProperty("status").GetString() == "skipped"
            && skippedGuide.GetProperty("revision").GetString() == skipped.GetProperty("revision").GetString()
            && skippedGuide.GetProperty("language").GetString() == skipped.GetProperty("language").GetString()
            && skippedGuide.GetProperty("signatures").GetRawText() == skipped.GetProperty("signatures").GetRawText()
            && exchange.Writes == writesBeforeSkippedGuide,
            "Reading guidance for a skipped user reset setup or changed language/signatures/defaults.");
        var resetSkipped = await OnboardingCallAsync(host, aliceToken, "mail_onboarding_update",
            new { action = "reset", revision = skipped.GetProperty("revision").GetString() });
        var kept = await OnboardingCallAsync(host, aliceToken, "mail_finish_onboarding", new
        {
            revision = resetSkipped.GetProperty("revision").GetString(),
            keepExisting = true
        });
        Expect(kept.GetProperty("status").GetString() == "completed"
            && kept.GetProperty("signatures").GetProperty("defaults").GetProperty("forNewMessages").GetString() == "Existing"
            && kept.GetProperty("signatures").GetProperty("defaults").GetProperty("forReplies").GetString() == "Persian Work"
            && kept.GetProperty("signatures").GetProperty("profiles").GetArrayLength() == 2,
            "Keeping existing profiles did not finish without changing signature data or defaults.");

        var bobExchange = new SignatureRecordingHandler();
        await using var bobHost = await StartHostAsync(bobExchange, writesEnabled: true, sendEnabled: false, configure: builder =>
            builder.Services.AddSingleton<IDataProtectionProvider>(new EphemeralDataProtectionProvider()));
        var bobToken = Token("user-b", "mail.read mail.write", sessionId: "onboarding-session-b");
        await InitializeAsync(bobHost.Client, bobToken);
        var bobInitial = await OnboardingCallAsync(bobHost, bobToken, "mail_onboarding", new { });
        Expect(bobInitial.GetProperty("status").GetString() == "not_started"
            && bobInitial.GetProperty("promptLanguageFirst").GetBoolean()
            && bobExchange.Writes == 0,
            "A second enrolled user did not receive an independent, write-free language prompt.");
        var bobLanguage = await OnboardingCallAsync(bobHost, bobToken, "mail_onboarding_update", new
        {
            action = "choose_language",
            revision = bobInitial.GetProperty("revision").GetString(),
            language = "en"
        });
        var bobWrites = bobExchange.Writes;
        var bobProfile = await OnboardingCallAsync(bobHost, bobToken, "mail_profile", new { });
        var bobSetup = bobProfile.GetProperty("onboarding");
        Expect(bobLanguage.GetProperty("nextStep").GetString() == "signature_setup"
            && bobSetup.GetProperty("nextStep").GetString() == "signature_setup"
            && bobSetup.GetProperty("guide").GetProperty("steps")[0].GetString()!.Contains("latest Sent", StringComparison.Ordinal)
            && bobSetup.GetProperty("guide").GetProperty("steps")[1].GetString()!.Contains("without claiming rendered output", StringComparison.Ordinal)
            && bobSetup.GetProperty("guide").GetProperty("steps")[2].GetString()!.Contains("user's answers", StringComparison.Ordinal)
            && bobSetup.GetProperty("guide").GetProperty("maintenance").GetString()!.Contains("healthy checks are silent", StringComparison.Ordinal)
            && bobExchange.Operations.All(operation => operation.Name.LocalName is "GetUserConfiguration" or "CreateUserConfiguration")
            && bobExchange.Writes == bobWrites,
            "A language-selected new user's profile did not offer preview-first Sent signature setup without scanning or mutating.");
    }

    private async Task<JsonElement> OnboardingCallAsync(TestHostContext host, string token, string name, object arguments)
    {
        var response = await ToolRequestAsync(host.Client, token, "tools/call", new { name, arguments });
        Expect(response.StatusCode == HttpStatusCode.OK && !IsToolError(response.Body),
            $"MCP onboarding tool {name} failed: {response.Body}");
        return ToolStructuredData(response.Body);
    }

    private async Task OnboardingErrorAsync(TestHostContext host, string token, string name, object arguments)
    {
        var response = await ToolRequestAsync(host.Client, token, "tools/call", new { name, arguments });
        Expect(response.StatusCode == HttpStatusCode.OK && IsToolError(response.Body),
            $"MCP onboarding tool {name} accepted an invalid or unauthorized request: {response.Body}");
    }

    private async Task<bool> OnboardingCallErrorBodyAsync(TestHostContext host, string token, string name, object arguments)
    {
        var response = await ToolRequestAsync(host.Client, token, "tools/call", new { name, arguments });
        return response.StatusCode == HttpStatusCode.OK && IsToolError(response.Body);
    }

    private static bool OnboardingGuideSuppressed(JsonElement view) =>
        !view.TryGetProperty("guide", out var guide) || guide.ValueKind == JsonValueKind.Null;
}

internal sealed class OnboardingRecordingHandler(SignatureRecordingHandler recording) : DelegatingHandler(recording)
{
    public SignatureRecordingHandler Recording => recording;
    public List<XElement> Operations => recording.Operations;
    public int Writes => recording.Writes;
    public List<string> Mailboxes { get; } = [];

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var document = XDocument.Parse(await request.Content!.ReadAsStringAsync(cancellationToken));
        Mailboxes.Add(document.Descendants(XName.Get("PrimarySmtpAddress", "http://schemas.microsoft.com/exchange/services/2006/types")).Single().Value);
        return await base.SendAsync(request, cancellationToken);
    }
}
