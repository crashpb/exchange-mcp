using System.Xml.Linq;
using Company.ExchangeMcp.Exchange;
using Company.ExchangeMcp.Security;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

internal sealed partial class Checks
{
    /// <summary>
    /// Verifies that delegated native recall keeps the authenticated actor in
    /// ExchangeImpersonation while binding the selected mailbox to the source,
    /// From field and saved Sent Items folder. This proves the wire boundary
    /// without touching a live mailbox.
    /// </summary>
    private async Task DelegatedOwnerRecallWireChecksAsync()
    {
        var handler = new RecordingRecallHandler
        {
            SourceFrom = "it@example.test",
            SourceSender = "it@example.test",
            AutodiscoverSmtp = "it@example.test",
            AutodiscoverLegacyDn = "o=Example/ou=Exchange Administrative Group/cn=Recipients/cn=it"
        };
        var access = new MailboxAccess(Options.Create(new ServiceOptions
        {
            AllowedClientIds = ["chatgpt-test"],
            Mailboxes = new Dictionary<string, string>(StringComparer.Ordinal) { ["user-a"] = "alice@example.test" },
            WritesEnabled = true,
            SendEnabled = true
        }));
        var client = new EwsClient(
            new HttpClient(handler),
            Options.Create(new EwsOptions
            {
                Endpoint = "https://mail.example.test/EWS/Exchange.asmx",
                TimeoutSeconds = 10,
                MaxResponseBytes = 2_097_152
            }),
            access);
        using var selection = access.SelectTarget(new MailboxIdentity(
            "user-a", "it@example.test", "chatgpt-test", "delegated-owner-recall", "it-target", "alice@example.test"));

        var request = await client.PrepareRecallAsync("it@example.test", "sent-message-1", CancellationToken.None);
        await client.SubmitRecallAsync("it@example.test", request, CancellationToken.None);

        var autodiscover = handler.Calls.Single(call => call.Operation == "Autodiscover");
        Expect(autodiscover.Body.Contains("it@example.test", StringComparison.Ordinal),
            "Delegated recall autodiscover did not use the selected mailbox identity.");
        var create = handler.Calls.Single(call => call.Operation == "CreateItem");
        var document = XDocument.Parse(create.Body);
        const string types = "http://schemas.microsoft.com/exchange/services/2006/types";
        var primary = document.Descendants(XName.Get("PrimarySmtpAddress", types)).Single().Value;
        var targetFolders = document.Descendants(XName.Get("DistinguishedFolderId", types))
            .Select(folder => folder.Element(XName.Get("Mailbox", types))
                ?.Element(XName.Get("EmailAddress", types))?.Value)
            .Where(value => !string.IsNullOrWhiteSpace(value)).ToArray();
        var from = document.Descendants(XName.Get("From", types))
            .Elements(XName.Get("Mailbox", types))
            .Elements(XName.Get("EmailAddress", types))
            .Single().Value;
        Expect(primary == "alice@example.test" && targetFolders.SequenceEqual(["it@example.test"]) && from == "it@example.test",
            "Delegated recall did not preserve actor impersonation and selected-mailbox From/Sent Items routing.");

        await DelegatedSendingRightsFilterChecksAsync();
    }

    private async Task DelegatedSendingRightsFilterChecksAsync()
    {
        await DelegatedRecallSendingRightsChecksAsync();
        await DelegatedTaskPlanSendingRightsChecksAsync();
    }

    private async Task DelegatedRecallSendingRightsChecksAsync()
    {
        const string session = "delegated-recall-rights";
        var exchange = new RecordingRecallHandler
        {
            SourceFrom = "it@example.test",
            SourceSender = "it@example.test",
            AutodiscoverSmtp = "it@example.test",
            AutodiscoverLegacyDn = "o=Example/ou=Exchange Administrative Group/cn=Recipients/cn=it"
        };
        var permissions = new MutableDelegatedPermissionReader(DelegatedSendingReport(
            PermissionDecision.Unknown("synthetic directory unavailable"),
            PermissionDecision.Unknown("synthetic directory unavailable")));
        var auditPath = Path.Combine(runDirectory, "delegated-recall-rights-audit.jsonl");
        await using var host = await StartDelegatedHostAsync(exchange, auditPath,
            classicStateful: true, permissions: permissions);
        var responder = new NativeFormResponder(accept: false);
        await using var native = await CreateNativeClientAsync(host,
            Token("user-a", "mail.read mail.write mail.manage mail.send", sessionId: session), responder);
        var targetHandle = await TargetHandleAsync(native.Client);
        var search = await native.Client.CallToolAsync("mail_search", new Dictionary<string, object?>
        {
            ["folder"] = "sentitems",
            ["limit"] = 20,
            ["mailboxHandle"] = targetHandle
        });
        Expect(search.IsError != true, "The delegated recall-rights fixture could not search Sent Items.");
        var messageHandle = NativeData(search).GetProperty("items")[0].GetProperty("handle").GetString()!;
        var arguments = new Dictionary<string, object?>
        {
            ["messageHandle"] = messageHandle,
            ["mailboxHandle"] = targetHandle
        };

        var denials = new[]
        {
            (Label: "SendOnBehalf only", SendAs: new PermissionDecision("denied", "synthetic deny"),
                SendOnBehalf: new PermissionDecision("allowed", "synthetic SendOnBehalf", Direct: true),
                Message: "Native recalls and task notices require verified SendAs permission"),
            (Label: "both denied", SendAs: new PermissionDecision("denied", "synthetic deny"),
                SendOnBehalf: new PermissionDecision("denied", "synthetic deny"),
                Message: "Native recalls and task notices require verified SendAs permission"),
            (Label: "unknown", SendAs: PermissionDecision.Unknown("synthetic uncertainty"),
                SendOnBehalf: PermissionDecision.Unknown("synthetic uncertainty"),
                Message: "Native recalls and task notices require verified SendAs permission")
        };
        foreach (var denial in denials)
        {
            permissions.Report = DelegatedSendingReport(denial.SendAs, denial.SendOnBehalf);
            var callsBefore = exchange.Calls.Count;
            var readsBefore = permissions.Calls;
            var blocked = await native.Client.CallToolAsync("mail_recall_message", arguments);
            Expect(blocked.IsError == true && ResultText(blocked).Contains(denial.Message, StringComparison.Ordinal)
                && permissions.Calls == readsBefore + 1 && responder.Calls == 0
                && exchange.Calls.Count == callsBefore && exchange.CreateCount == 0,
                $"Delegated recall with {denial.Label} was not rejected before EWS or native approval.");
            Expect(permissions.LastIdentity is { ActorMailbox: "alice@example.test", Mailbox: "it@example.test", TargetId: DiscoveryMailboxKey },
                $"Delegated recall {denial.Label} lookup lost actor/target identity binding.");
        }

        permissions.Report = DelegatedSendingReport(
            new PermissionDecision("allowed", "synthetic SendAs", Direct: true),
            PermissionDecision.Unknown("not granted"));
        var allowedCallsBefore = exchange.Calls.Count;
        var allowedReadsBefore = permissions.Calls;
        var allowed = await native.Client.CallToolAsync("mail_recall_message", arguments);
        Expect(allowed.IsError != true && NativeData(allowed).GetProperty("status").GetString() == "cancelled"
            && permissions.Calls > allowedReadsBefore && responder.Calls == 1
            && exchange.Calls.Count > allowedCallsBefore && exchange.CreateCount == 0,
            $"A delegated recall with SendAs permission did not reach native approval without submitting a notice (error={allowed.IsError}, response={ResultText(allowed)}, permissionReads={permissions.Calls - allowedReadsBefore}, approvalCalls={responder.Calls}, ewsCalls={exchange.Calls.Count - allowedCallsBefore}, createItems={exchange.CreateCount}).");
    }

    private async Task DelegatedTaskPlanSendingRightsChecksAsync()
    {
        const string session = "delegated-task-plan-rights";
        var exchange = new AssignmentPlanRecordingHandler { UnassignedTask = true };
        var permissions = new MutableDelegatedPermissionReader(DelegatedSendingReport(
            PermissionDecision.Unknown("synthetic directory unavailable"),
            PermissionDecision.Unknown("synthetic directory unavailable")));
        var auditPath = Path.Combine(runDirectory, "delegated-task-plan-rights-audit.jsonl");
        await using var host = await StartDelegatedHostAsync(exchange, auditPath,
            classicStateful: true, permissions: permissions);
        var responder = new NativeFormResponder(accept: false);
        await using var native = await CreateNativeClientAsync(host,
            Token("user-a", "mail.read mail.write mail.manage mail.send", sessionId: session), responder);
        var targetHandle = await TargetHandleAsync(native.Client);
        var targetIdentity = new MailboxIdentity("user-a", "it@example.test", "chatgpt-test", session,
            DiscoveryMailboxKey, "alice@example.test");
        var taskHandle = host.App.Services.GetRequiredService<MailboxHandles>()
            .Issue(targetIdentity, "task", "task-1", exchange.TaskChangeKey);
        var plan = await native.Client.CallToolAsync("task_plan_assignments", new Dictionary<string, object?>
        {
            ["taskHandle"] = taskHandle,
            ["assignees"] = new[] { "bob@example.test" },
            ["throughDate"] = "2026-01-12",
            ["mailboxHandle"] = targetHandle
        });
        Expect(plan.IsError != true, "The delegated task-plan sending-rights fixture could not be planned.");
        var planHandle = NativeData(plan).GetProperty("planHandle").GetString()!;
        var arguments = new Dictionary<string, object?>
        {
            ["planHandle"] = planHandle,
            ["mailboxHandle"] = targetHandle
        };

        var denials = new[]
        {
            (Label: "SendOnBehalf only", SendAs: new PermissionDecision("denied", "synthetic deny"),
                SendOnBehalf: new PermissionDecision("allowed", "synthetic SendOnBehalf", Direct: true),
                Message: "Native recalls and task notices require verified SendAs permission"),
            (Label: "both denied", SendAs: new PermissionDecision("denied", "synthetic deny"),
                SendOnBehalf: new PermissionDecision("denied", "synthetic deny"),
                Message: "Native recalls and task notices require verified SendAs permission"),
            (Label: "unknown", SendAs: PermissionDecision.Unknown("synthetic uncertainty"),
                SendOnBehalf: PermissionDecision.Unknown("synthetic uncertainty"),
                Message: "Native recalls and task notices require verified SendAs permission")
        };
        foreach (var denial in denials)
        {
            permissions.Report = DelegatedSendingReport(denial.SendAs, denial.SendOnBehalf);
            var callsBefore = exchange.Calls.Count;
            var readsBefore = permissions.Calls;
            var blocked = await native.Client.CallToolAsync("task_execute_assignment_plan", arguments);
            Expect(blocked.IsError == true && ResultText(blocked).Contains(denial.Message, StringComparison.Ordinal)
                && permissions.Calls == readsBefore + 1 && responder.Calls == 0
                && exchange.Calls.Count == callsBefore && exchange.CreateItemCount == 0 && exchange.UpdateItemCount == 0,
                $"Delegated task-plan execution with {denial.Label} was not rejected before EWS, native approval or writes.");
            Expect(permissions.LastIdentity is { ActorMailbox: "alice@example.test", Mailbox: "it@example.test", TargetId: DiscoveryMailboxKey },
                $"Delegated task-plan {denial.Label} lookup lost actor/target identity binding.");
        }

        permissions.Report = DelegatedSendingReport(
            new PermissionDecision("allowed", "synthetic SendAs", Direct: true),
            PermissionDecision.Unknown("not granted"));
        var allowedCallsBefore = exchange.Calls.Count;
        var allowedReadsBefore = permissions.Calls;
        var allowed = await native.Client.CallToolAsync("task_execute_assignment_plan", arguments);
        Expect(allowed.IsError != true && NativeData(allowed).GetProperty("status").GetString() == "cancelled"
            && permissions.Calls > allowedReadsBefore && responder.Calls == 1
            && exchange.Calls.Count > allowedCallsBefore && exchange.CreateItemCount == 0 && exchange.UpdateItemCount == 0,
            $"A delegated task plan with SendAs permission did not reach native approval without writing (error={allowed.IsError}, response={ResultText(allowed)}, permissionReads={permissions.Calls - allowedReadsBefore}, approvalCalls={responder.Calls}, ewsCalls={exchange.Calls.Count - allowedCallsBefore}, creates={exchange.CreateItemCount}, updates={exchange.UpdateItemCount}).");
    }

    private static MailboxPermissionReport DelegatedSendingReport(
        PermissionDecision sendAs, PermissionDecision sendOnBehalf) =>
        new(new PermissionDecision("allowed", "synthetic FullAccess"), sendAs, sendOnBehalf,
            DateTimeOffset.UtcNow, "synthetic-delegated-sending");

    private sealed class MutableDelegatedPermissionReader(MailboxPermissionReport report) : IMailboxPermissionReader
    {
        public MailboxPermissionReport Report { get; set; } = report;
        public int Calls { get; private set; }
        public MailboxIdentity? LastIdentity { get; private set; }

        public Task<MailboxPermissionReport> ReadAsync(MailboxIdentity identity, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Calls++;
            LastIdentity = identity;
            return Task.FromResult(Report);
        }
    }
}
