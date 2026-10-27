using System.Net;
using System.Text;
using System.Xml.Linq;
using Company.ExchangeMcp.Exchange;
using Company.ExchangeMcp.Security;
using Microsoft.Extensions.Options;

internal sealed partial class Checks
{
    private async Task DelegatedSenderChecksAsync()
    {
        var delegatedTransport = new DelegatedSenderHandler();
        var access = new MailboxAccess(Options.Create(new ServiceOptions()));
        var client = new EwsClient(
            new HttpClient(delegatedTransport),
            Options.Create(new EwsOptions
            {
                Endpoint = "https://mail.example.test/EWS/Exchange.asmx",
                TimeoutSeconds = 10,
                MaxResponseBytes = 2_097_152
            }),
            access);
        var target = new MailboxIdentity("user-a", "it@example.test", "chatgpt-test", "sender-check",
            "it", "alice@example.test");
        static string? FolderMailbox(string body, string folderId)
        {
            var types = XNamespace.Get("http://schemas.microsoft.com/exchange/services/2006/types");
            var folder = XDocument.Parse(body).Descendants(types + "DistinguishedFolderId")
                .SingleOrDefault(element => (string?)element.Attribute("Id") == folderId);
            return folder?.Element(types + "Mailbox")?.Element(types + "EmailAddress")?.Value;
        }

        using (access.SelectTarget(target))
        {
            var draft = await client.CreateDraftAsync("it@example.test",
                new EwsDraftInput("delegated", "body", ["alice@example.test"], [], []), CancellationToken.None);
            Expect(delegatedTransport.Last("CreateItem").Body.Contains("<t:From>", StringComparison.Ordinal)
                && delegatedTransport.Last("CreateItem").Body.Contains("it@example.test", StringComparison.Ordinal),
                "A delegated draft did not carry the selected mailbox in message:From.");

            await client.UpdateDraftAsync("it@example.test", draft.Id, draft.ChangeKey,
                new EwsDraftInput("edited", "body", ["alice@example.test"], [], []), CancellationToken.None);
            Expect(delegatedTransport.Last("UpdateItem").Body.Contains("message:From", StringComparison.Ordinal)
                && delegatedTransport.Last("UpdateItem").Body.Contains("it@example.test", StringComparison.Ordinal),
                "Editing a delegated draft did not preserve message:From.");

            await client.ForwardDraftAsync("it@example.test", "message-1", "message-change", "forward",
                ["alice@example.test"], [], [], CancellationToken.None);
            Expect(delegatedTransport.Last("UpdateItem").Body.Contains("message:From", StringComparison.Ordinal),
                "A forwarded delegated draft was not assigned its sender after SmartResponse creation.");

            await client.ReplyDraftAsync("it@example.test", "message-1", "message-change", "reply", false,
                CancellationToken.None);
            Expect(delegatedTransport.Last("UpdateItem").Body.Contains("message:From", StringComparison.Ordinal),
                "A replied delegated draft was not assigned its sender after SmartResponse creation.");

            await client.SendDraftAsync("it@example.test", "draft-1", "draft-change", CancellationToken.None);
            var send = delegatedTransport.Last("SendItem").Body;
            Expect(send.Contains("SavedItemFolderId", StringComparison.Ordinal)
                && send.Contains("sentitems", StringComparison.Ordinal)
                && send.Contains("it@example.test", StringComparison.Ordinal),
                "A delegated SendItem did not explicitly save to the target mailbox Sent Items.");

            var message = await client.GetMessageAsync("it@example.test", "message-1", CancellationToken.None);
            Expect(message.Sender == "alice@example.test",
                "message:Sender was not parsed from Exchange metadata.");
        }

        var fallbackTransport = new DelegatedSenderHandler(createContents: false);
        var fallbackAccess = new MailboxAccess(Options.Create(new ServiceOptions()));
        var fallbackClient = new EwsClient(new HttpClient(fallbackTransport), Options.Create(new EwsOptions
        {
            Endpoint = "https://mail.example.test/EWS/Exchange.asmx",
            TimeoutSeconds = 10,
            MaxResponseBytes = 2_097_152
        }), fallbackAccess);
        using (fallbackAccess.SelectTarget(target))
        {
            var draft = await fallbackClient.CreateDraftAsync("it@example.test",
                new EwsDraftInput("fallback", "body", ["alice@example.test"], [], []), CancellationToken.None);
            var create = fallbackTransport.Last("CreateItem");
            Expect(create.Body.Contains("SavedItemFolderId", StringComparison.Ordinal)
                && FolderMailbox(create.Body, "drafts") == "alice@example.test"
                && create.Body.Contains("<t:From>", StringComparison.Ordinal)
                && create.Body.Contains("it@example.test", StringComparison.Ordinal),
                "A target folder without CreateContents did not save the delegated draft in the actor's Drafts while retaining the selected From.");

            await fallbackClient.SendDraftAsync("it@example.test", draft.Id, draft.ChangeKey, CancellationToken.None);
            var send = fallbackTransport.Last("SendItem");
            Expect(FolderMailbox(send.Body, "sentitems") == "alice@example.test"
                && send.PrimarySmtpAddress == "alice@example.test"
                && send.Headers.GetValues("X-AnchorMailbox").Single() == "alice@example.test",
                "A target Sent Items folder without CreateContents did not fall back to actor storage under the actor EWS context.");

            var item = await fallbackClient.GetMessageAsync("it@example.test", draft.Id, CancellationToken.None);
            var getItem = fallbackTransport.Last("GetItem");
            Expect(item.Sender == "alice@example.test"
                && getItem.PrimarySmtpAddress == "alice@example.test"
                && getItem.Headers.GetValues("X-AnchorMailbox").Single() == "alice@example.test"
                && fallbackTransport.Calls.All(call => call.PrimarySmtpAddress == "alice@example.test"
                    && call.Headers.GetValues("X-AnchorMailbox").Single() == "alice@example.test"),
                "Actor-owned draft access changed the EWS ConnectingSID/X-AnchorMailbox or exposed owner-context message content.");
        }

        var ownTransport = new DelegatedSenderHandler();
        var ownClient = new EwsClient(
            new HttpClient(ownTransport),
            Options.Create(new EwsOptions
            {
                Endpoint = "https://mail.example.test/EWS/Exchange.asmx",
                TimeoutSeconds = 10,
                MaxResponseBytes = 2_097_152
            }));
        await ownClient.CreateDraftAsync("alice@example.test",
            new EwsDraftInput("own", "body", ["it@example.test"], [], []), CancellationToken.None);
        Expect(!ownTransport.Last("CreateItem").Body.Contains("<t:From>", StringComparison.Ordinal),
            "An own-mailbox draft changed wire shape by adding a sender.");
        await ownClient.SendDraftAsync("alice@example.test", "draft-1", "draft-change", CancellationToken.None);
        Expect(!ownTransport.Last("SendItem").Body.Contains("SavedItemFolderId", StringComparison.Ordinal),
            "An own-mailbox SendItem changed wire shape by adding a target Sent Items folder.");

        var first = new EwsMessage("id", "key", "subject", "it@example.test",
            Array.Empty<string>(), Array.Empty<string>(), Array.Empty<string>(), Array.Empty<string>(),
            null, false, true, "body", Array.Empty<string>(), "Text");
        var second = first with { Sender = "alice@example.test" };
        Expect(SendGuard.Digest(first) != SendGuard.Digest(second),
            "Send approval digest did not bind the Exchange Sender metadata.");
    }
}

internal sealed class DelegatedSenderHandler(bool createContents = true) : HttpMessageHandler
{
    private static readonly XNamespace Soap = "http://schemas.xmlsoap.org/soap/envelope/";
    private static readonly XNamespace M = "http://schemas.microsoft.com/exchange/services/2006/messages";
    private static readonly XNamespace T = "http://schemas.microsoft.com/exchange/services/2006/types";
    public List<CapturedEwsRequest> Calls { get; } = [];

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var body = await request.Content!.ReadAsStringAsync(cancellationToken);
        var document = XDocument.Parse(body);
        var operation = document.Root!.Element(Soap + "Body")!.Elements().Single();
        Calls.Add(new CapturedEwsRequest(operation.Name.LocalName, body, request.Headers,
            document.Descendants(T + "PrimarySmtpAddress").SingleOrDefault()?.Value));
        var operationName = operation.Name.LocalName;
        var result = operationName switch
        {
            "GetFolder" => "<m:Folders><t:Folder><t:FolderId Id='rights-probe' ChangeKey='rights-change'/>"
                + $"<t:EffectiveRights><t:Read>true</t:Read><t:CreateContents>{createContents.ToString().ToLowerInvariant()}</t:CreateContents>"
                + "<t:Modify>true</t:Modify><t:Delete>false</t:Delete></t:EffectiveRights></t:Folder></m:Folders>",
            "GetItem" => "<m:Items><t:Message><t:ItemId Id='message-1' ChangeKey='message-change'/><t:Subject>item</t:Subject><t:From><t:Mailbox><t:EmailAddress>it@example.test</t:EmailAddress></t:Mailbox></t:From><t:Sender><t:Mailbox><t:EmailAddress>alice@example.test</t:EmailAddress></t:Mailbox></t:Sender><t:IsDraft>true</t:IsDraft><t:Body BodyType='Text'>body</t:Body><t:ToRecipients/><t:CcRecipients/><t:BccRecipients/><t:Attachments/><t:Categories/></t:Message></m:Items>",
            "CreateItem" => "<m:Items><t:Message><t:ItemId Id='draft-1' ChangeKey='draft-change'/></t:Message></m:Items>",
            "UpdateItem" => "<m:Items><t:Message><t:ItemId Id='draft-1' ChangeKey='draft-updated'/></t:Message></m:Items>",
            _ => string.Empty
        };
        var responseBody = operationName == "GetFolder"
            ? $"<m:{operationName}Response><m:ResponseMessages><m:{operationName}ResponseMessage ResponseClass='Success'><m:ResponseCode>NoError</m:ResponseCode>{result}</m:{operationName}ResponseMessage></m:ResponseMessages></m:{operationName}Response>"
            : $"<m:{operationName}Response><m:ResponseMessages><m:{operationName}ResponseMessage ResponseClass='Success'><m:ResponseCode>NoError</m:ResponseCode></m:{operationName}ResponseMessage></m:ResponseMessages>{result}</m:{operationName}Response>";
        var response = $"<s:Envelope xmlns:s='{Soap.NamespaceName}' xmlns:m='{M.NamespaceName}' xmlns:t='{T.NamespaceName}'><s:Body>{responseBody}</s:Body></s:Envelope>";
        return new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(response, Encoding.UTF8, "text/xml")
        };
    }

    public CapturedEwsRequest Last(string operation) => Calls.Last(call => call.Operation == operation);

    private static string? DistinguishedFolderMailbox(string body, string folderId)
    {
        var document = XDocument.Parse(body);
        var folder = document.Descendants(T + "DistinguishedFolderId")
            .SingleOrDefault(element => (string?)element.Attribute("Id") == folderId);
        return folder?.Element(T + "Mailbox")?.Element(T + "EmailAddress")?.Value;
    }
}
