using System.Text.Json;
using System.Xml.Linq;
using Company.ExchangeMcp;
using Company.ExchangeMcp.Security;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Options;
using ModelContextProtocol;

internal sealed partial class Checks
{
    private async Task SignatureUseRulesChecksAsync()
    {
        MailSignature[] profiles = [new("Default", "Default signature", "Text", []), new("Persian", "امضا", "Text", []),
            new("Client", "Client signature", "Text", [])];
        var rules = new[] { new SignatureUseRule("Client", "reply", RecipientDomain: "example.test", BodyLanguage: "fa"),
            new SignatureUseRule("Persian", BodyLanguage: "fa") };
        var settings = new SignatureSettings(profiles, "Default", "Default", new("en", "pending"), rules);
        SignatureStore.Validate(settings);
        ExpectThrows<McpException>(() => SignatureStore.Validate(settings with { Onboarding = new("en", "pending", "unknown") }),
            "An unsupported onboarding stage was accepted.");
        SignatureSelection Select(string[] recipients, string body = "سلام", string context = "reply", string? name = null) =>
            SignatureStore.Select(settings, name, context, recipients, body, "Text");
        Expect(Select(["one@example.test", "TWO@EXAMPLE.TEST"]).Name == "Client"
            && Select(["one@example.test"], context: "new").Name == "Persian"
            && Select(["one@sub.example.test"]).Name == "Persian"
            && Select(["one@example.test.evil"]).Name == "Persian"
            && Select(["one@example.test"], name: "Default").Source == "explicit",
            "Signature rules lost first-match ordering, exact domain matching, context or explicit override.");
        var mixed = Select(["one@example.test", "other@outside.test"]);
        Expect(mixed.Name == "Default" && mixed.Warning is not null
            && Select(["one@example.test", "[unresolved recipient]"]).Warning is not null
            && Select(["one@example.test"], "سلام Hello").Name == "Default"
            && Select(["one@example.test"], "123").Name == "Default"
            && Select([], "Hello").Name == "Default",
            "Mixed recipients, unresolved recipients or mixed/unknown body languages selected a conditional signature.");
        var exact = settings with { UseRules = [new("Client", RecipientAddress: "one@example.test")] };
        Expect(SignatureStore.Select(exact, null, "new", ["ONE@example.test"], "Hello", "Text").Name == "Client"
            && SignatureStore.Select(exact, null, "new", ["other@example.test"], "Hello", "Text").Name == "Default",
            "The exact-address rule matched a different recipient or ignored case-insensitive SMTP matching.");
        var reply = "<div><p>سلام</p><hr/><div id='divRplyFwdMsg'>From Alice</div><p>English quoted history</p></div>";
        Expect(SignatureStore.Select(settings, null, "reply", ["one@example.test"], reply, "HTML").Name == "Client",
            "Quoted HTML reply history changed the authored body's language classification.");
        var english = settings with { UseRules = [new("Client", BodyLanguage: "en")] };
        Expect(SignatureStore.Select(english, null, "new", [], "<p>Hello &amp; welcome</p>", "HTML").Name == "Client",
            "The English body condition did not inspect HTML text.");
        foreach (var invalid in new SignatureUseRule[]
        {
            new("missing", Context: "new"), new("Client"), new("Client", Context: "forward"),
            new("Client", BodyLanguage: "fr"), new("Client", RecipientDomain: "*.example.test"),
            new("Client", RecipientDomain: "example.test/"), new("Client", RecipientAddress: "Alice <one@example.test>"),
            new("Client", RecipientAddress: "one@example.test\r\n"),
            new("Client", RecipientAddress: "one@example.test", RecipientDomain: "example.test"), null!
        })
            ExpectThrows<McpException>(() => SignatureStore.Validate(settings with { UseRules = [invalid] }),
                "An unsupported or malformed signature rule was accepted.");
        SignatureStore.Validate(settings with { UseRules = Enumerable.Repeat(rules[0], 20).ToArray() });
        ExpectThrows<McpException>(() => SignatureStore.Validate(settings with { UseRules = Enumerable.Repeat(rules[0], 21).ToArray() }),
            "The signature rule quota accepted a 21st rule.");
        var old = JsonSerializer.Deserialize<SignatureSettings>("{\"Profiles\":[],\"NewMessages\":null,\"Replies\":null}")!;
        SignatureStore.Validate(old);
        Expect(old.UseRules is null, "Old signature settings no longer read without new preference fields.");

        var handler = new SignatureRecordingHandler
        {
            ApplyMode = true,
            ApplyTo = ["one@example.test"],
            ApplyCc = ["two@example.test"],
            ApplyBcc = ["three@example.test"],
            ApplyHtmlBody = reply
        };
        var exchange = NewEwsClient(handler);
        var store = new SignatureStore();
        var initial = await store.UpdateAsync(exchange, "alice@example.test", "new", _ => settings with { UseRules = null }, CancellationToken.None);
        var options = Options.Create(new ServiceOptions
        {
            AllowedClientIds = ["checks"],
            WritesEnabled = true,
            Mailboxes = new() { ["user-a"] = "alice@example.test" },
            AuditPath = Path.Combine(runDirectory, "signature-rules-audit.jsonl")
        });
        using var audit = new AuditLog(options);
        var handles = new MailboxHandles(new EphemeralDataProtectionProvider());
        var tools = new SignatureTools(exchange, new MailboxAccess(options), handles, audit, store);
        var user = SyncUser("user-a", "mail.read mail.write mail.manage");
        var saved = (SignatureSnapshot)await tools.Rules(user, initial.Revision, rules, CancellationToken.None);
        var read = await store.ReadAsync(exchange, "alice@example.test", CancellationToken.None);
        Expect(read.Settings.UseRules!.SequenceEqual(rules) && read.Settings.Onboarding == settings.Onboarding
            && read.Usage.SerializedBytes > initial.Usage.SerializedBytes,
            "Use rules did not persist alongside onboarding or count toward serialized storage usage.");
        var writes = handler.Writes;
        await AssertThrowsAsync<McpException>(() => tools.Rules(user, initial.Revision, [], CancellationToken.None));
        await AssertThrowsAsync<McpException>(() => tools.Rules(SyncUser("user-a"), read.Revision, [], CancellationToken.None));
        await AssertThrowsAsync<McpException>(() => tools.Delete(user, read.Revision, "Client", CancellationToken.None));
        Expect(handler.Writes == writes, "Stale/unprivileged rule changes or referenced profile deletion wrote settings.");
        var replaced = (SignatureSnapshot)await tools.Save(user, saved.Revision, "Client", "Client updated", CancellationToken.None);
        Expect(replaced.Settings.UseRules!.SequenceEqual(rules) && replaced.Settings.NewMessages == "Default"
            && replaced.Settings.Replies == "Default", "Saving a profile discarded signature rules or existing defaults.");

        string Draft() => handles.Issue(new("user-a", "alice@example.test", "checks"), "message", "draft-1", handler.DraftChangeKey);
        var applied = JsonSerializer.SerializeToElement(await tools.Apply(user, Draft(), CancellationToken.None, context: "reply"));
        var appliedBody = handler.Operations.Last(operation => operation.Name.LocalName == "UpdateItem")
            .Descendants(XName.Get("Body", TypesNamespace)).Single().Value;
        Expect(applied.GetProperty("signature").GetString() == "Client" && applied.GetProperty("selectionSource").GetString() == "rule"
            && appliedBody.IndexOf("Client updated", StringComparison.Ordinal) < appliedBody.IndexOf("divRplyFwdMsg", StringComparison.Ordinal),
            "mail_apply_signature did not select from the current draft or preserve placement before native history.");
        handler.ApplyBcc = ["outside@other.test"];
        handler.ApplyHtmlBody = reply;
        var fallback = JsonSerializer.SerializeToElement(await tools.Apply(user, Draft(), CancellationToken.None, context: "reply"));
        Expect(fallback.GetProperty("signature").GetString() == "Default" && fallback.GetProperty("warning").GetString() is not null,
            "A mixed Bcc recipient bypassed safe rule fallback.");
        handler.ApplyHtmlBody = reply;
        var explicitApply = JsonSerializer.SerializeToElement(await tools.Apply(user, Draft(), CancellationToken.None, "Persian", "reply"));
        Expect(explicitApply.GetProperty("signature").GetString() == "Persian" && explicitApply.GetProperty("selectionSource").GetString() == "explicit",
            "An explicit signature failed to override persisted preferences.");
        var cleared = (SignatureSnapshot)await tools.Rules(user, replaced.Revision, [], CancellationToken.None);
        var deleted = (SignatureSnapshot)await tools.Delete(user, cleared.Revision, "Client", CancellationToken.None);
        Expect(deleted.Settings.UseRules!.Length == 0 && deleted.Settings.Onboarding == settings.Onboarding,
            "Explicitly clearing preferences/deleting a profile changed onboarding state.");
        var quota = CreateExactQuotaSettings();
        var quotaHandler = new SignatureRecordingHandler();
        await AssertThrowsAsync<McpException>(() => new SignatureStore().UpdateAsync(NewEwsClient(quotaHandler), "alice@example.test", "new",
            _ => quota with { UseRules = [new("QuotaText", Context: "new")] }, CancellationToken.None));
        Expect(quotaHandler.Writes == 0, "Signature preferences bypassed the aggregate 3 MiB serialized quota.");
    }
}
