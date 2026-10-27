using System.Net;
using System.Text;
using System.Xml.Linq;
using Company.ExchangeMcp.Exchange;
using Company.ExchangeMcp.Security;
using Microsoft.Extensions.DependencyInjection;

internal sealed partial class Checks
{
    private async Task ContactGroupMembershipChecksAsync()
    {
        var calls = new List<CapturedEwsRequest>();
        var client = NewEwsClient(new ContactGroupMembershipRecordingHandler(calls));
        var group = await client.GetContactGroupAsync("alice@example.test", "group-1", CancellationToken.None);
        Expect(group.Members.Count == 2
            && group.Members[0].ServerMemberKey == "member-remove"
            && group.Members[0].ItemId == "contact-1"
            && group.Members[1].ServerMemberKey == "member-keep"
            && group.Members[1].MailboxType == "PrivateDL"
            && group.Members[1].ItemId == "group-child",
            "Contact group parsing did not retain member keys and mailbox metadata.");

        var updated = await client.UpdateContactGroupMembersAsync("alice@example.test", group,
            "Engineering Core", ["new@example.test"], ["member-remove"], CancellationToken.None);
        Expect(updated.Id == group.Id && updated.ChangeKey == "group-change-2",
            "Contact group membership update did not return the updated item reference.");
        var updateCall = calls.Single(call => call.Operation == "UpdateItem");
        var updateXml = XDocument.Parse(updateCall.Body);
        var update = Operation(updateXml);
        var itemChange = update.Element(XName.Get("ItemChanges", MessagesNamespace))!
            .Element(XName.Get("ItemChange", TypesNamespace))!;
        var itemId = itemChange.Element(XName.Get("ItemId", TypesNamespace))!;
        var updates = itemChange.Element(XName.Get("Updates", TypesNamespace))!;
        var deletion = updates.Elements(XName.Get("DeleteItemField", TypesNamespace)).Single();
        var indexedMember = deletion.Element(XName.Get("IndexedFieldURI", TypesNamespace))!;
        var append = updates.Elements(XName.Get("AppendToItemField", TypesNamespace)).Single();
        var appendField = append.Element(XName.Get("FieldURI", TypesNamespace))!;
        var appendedEmails = append.Element(XName.Get("DistributionList", TypesNamespace))!
            .Element(XName.Get("Members", TypesNamespace))!
            .Elements(XName.Get("Member", TypesNamespace))
            .Select(member => member.Element(XName.Get("Mailbox", TypesNamespace))!
                .Element(XName.Get("EmailAddress", TypesNamespace))!.Value)
            .ToArray();
        Expect((string?)update.Attribute("ConflictResolution") == "NeverOverwrite"
            && (string?)itemId.Attribute("Id") == group.Id
            && (string?)itemId.Attribute("ChangeKey") == group.ChangeKey,
            "Contact group membership updates did not use the exact group ID and current change key.");
        Expect((string?)indexedMember.Attribute("FieldURI") == "distributionlist:Members:Member"
            && (string?)indexedMember.Attribute("FieldIndex") == "member-remove",
            "Contact group removal did not target the selected server member key.");
        Expect((string?)appendField.Attribute("FieldURI") == "distributionlist:Members"
            && appendedEmails.SequenceEqual(["new@example.test"]),
            "Contact group addition did not append the requested address.");
        Expect(updates.Elements(XName.Get("SetItemField", TypesNamespace))
                .Any(field => (string?)field.Element(XName.Get("FieldURI", TypesNamespace))?.Attribute("FieldURI") == "contacts:DisplayName")
            && !updates.Elements(XName.Get("SetItemField", TypesNamespace))
                .Any(field => ((string?)field.Element(XName.Get("FieldURI", TypesNamespace))?.Attribute("FieldURI"))?.StartsWith("distributionlist:Members", StringComparison.Ordinal) == true)
            && calls.All(call => call.Operation != "CreateItem"),
            "Contact group update replaced membership or recreated the group.");
        ValidatePeopleTasksSchema(calls);

        var beforeInvalidUpdate = calls.Count;
        await AssertThrowsAsync<InvalidOperationException>(() => client.UpdateContactGroupMembersAsync(
            "alice@example.test", group with { Members = [group.Members[0], group.Members[0]] },
            null, ["extra@example.test"], null, CancellationToken.None));
        await AssertThrowsAsync<ArgumentException>(() => client.UpdateContactGroupMembersAsync(
            "alice@example.test", group, null, null, ["member-missing"], CancellationToken.None));
        Expect(calls.Count == beforeInvalidUpdate,
            "Duplicate or missing current member keys reached Exchange.");

        await ContactGroupMembershipHandleChecksAsync();
    }

    private async Task ContactGroupMembershipHandleChecksAsync()
    {
        var calls = new List<CapturedEwsRequest>();
        var handler = new ContactGroupMembershipRecordingHandler(calls);
        await using var host = await StartHostAsync(handler, writesEnabled: true, sendEnabled: false);
        var token = Token("user-a", "mail.read mail.write");
        await InitializeAsync(host.Client, token);
        var handles = host.App.Services.GetRequiredService<MailboxHandles>();
        var alice = new MailboxIdentity("user-a", "alice@example.test", "chatgpt-test");
        var bob = new MailboxIdentity("user-b", "bob@example.test", "chatgpt-test");
        var groupHandle = handles.Issue(alice, "contact-group", "group-1", "group-change");
        var currentMemberHandle = handles.Issue(alice, "contact-group-member",
            "group-1\0member-remove", "group-change");

        var crossMailboxHandle = handles.Issue(bob, "contact-group-member",
            "group-1\0member-remove", "group-change");
        var crossMailbox = await UpdateGroupAsync(groupHandle, ["new@example.test"], [crossMailboxHandle]);
        Expect(IsToolError(crossMailbox.Body) && calls.Count == 0,
            "A contact group member handle from another mailbox reached Exchange.");

        var staleGroupHandle = handles.Issue(alice, "contact-group", "group-1", "old-group-change");
        var staleGroup = await UpdateGroupAsync(staleGroupHandle, ["new@example.test"], [currentMemberHandle]);
        Expect(IsToolError(staleGroup.Body) && calls.Count == 1
            && calls.All(call => call.Operation != "UpdateItem"),
            "A stale contact group handle reached the membership update.");

        calls.Clear();
        var staleMemberHandle = handles.Issue(alice, "contact-group-member",
            "group-1\0member-remove", "old-group-change");
        var staleMember = await UpdateGroupAsync(groupHandle, ["new@example.test"], [staleMemberHandle]);
        Expect(IsToolError(staleMember.Body) && calls.Count == 1
            && calls.All(call => call.Operation != "UpdateItem"),
            "A stale contact group member handle reached Exchange.");

        calls.Clear();
        var otherGroupMember = handles.Issue(alice, "contact-group-member",
            "group-other\0member-remove", "group-change");
        var wrongGroup = await UpdateGroupAsync(groupHandle, ["new@example.test"], [otherGroupMember]);
        Expect(IsToolError(wrongGroup.Body) && calls.Count == 1
            && calls.All(call => call.Operation != "UpdateItem"),
            "A member handle from another contact group reached Exchange.");

        calls.Clear();
        var success = await UpdateGroupAsync(groupHandle, ["new@example.test"], [currentMemberHandle]);
        Expect(!IsToolError(success.Body)
            && calls.Select(call => call.Operation).SequenceEqual(["GetItem", "UpdateItem"])
            && calls.All(call => call.Operation != "CreateItem"),
            "The current group and member handles did not update the existing group.");

        async Task<(HttpStatusCode StatusCode, string Body)> UpdateGroupAsync(string currentGroupHandle,
            string[] additions, string[] removals) =>
            await ToolRequestAsync(host.Client, token, "tools/call", new
            {
                name = "people_update_contact_group",
                arguments = new
                {
                    groupHandle = currentGroupHandle,
                    addMemberEmails = additions,
                    removeMemberHandles = removals
                }
            });
    }

    private sealed class ContactGroupMembershipRecordingHandler(List<CapturedEwsRequest> calls) : HttpMessageHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            var body = await request.Content!.ReadAsStringAsync(cancellationToken);
            var document = XDocument.Parse(body);
            var operation = Operation(document).Name.LocalName;
            var primarySmtpAddress = document.Descendants(XName.Get("PrimarySmtpAddress", TypesNamespace))
                .SingleOrDefault()?.Value;
            calls.Add(new CapturedEwsRequest(operation, body, request.Headers, primarySmtpAddress));
            var result = operation switch
            {
                "GetItem" => "<m:Items>" + GroupXml("group-change") + "</m:Items>",
                "UpdateItem" => "<m:Items><t:DistributionList><t:ItemId Id='group-1' ChangeKey='group-change-2'/></t:DistributionList></m:Items>",
                _ => string.Empty
            };
            return Response(SoapResponse(operation, "NoError", "")
                .Replace($"</m:{operation}Response>", result + $"</m:{operation}Response>", StringComparison.Ordinal));
        }

        private static string GroupXml(string changeKey) =>
            $"<t:DistributionList><t:ItemId Id='group-1' ChangeKey='{changeKey}'/><t:DisplayName>Engineering</t:DisplayName>"
            + "<t:Members>"
            + "<t:Member Key='member-remove'><t:Mailbox><t:Name>Ada Lovelace</t:Name><t:EmailAddress>ada@example.test</t:EmailAddress><t:RoutingType>SMTP</t:RoutingType><t:MailboxType>Mailbox</t:MailboxType><t:ItemId Id='contact-1'/></t:Mailbox></t:Member>"
            + "<t:Member Key='member-keep'><t:Mailbox><t:Name>Nested group</t:Name><t:EmailAddress>nested@example.test</t:EmailAddress><t:RoutingType>SMTP</t:RoutingType><t:MailboxType>PrivateDL</t:MailboxType><t:ItemId Id='group-child'/></t:Mailbox></t:Member>"
            + "</t:Members></t:DistributionList>";
    }
}
