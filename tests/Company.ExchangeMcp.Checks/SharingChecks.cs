using System.Net;
using System.Text;
using System.Xml.Linq;
using System.Xml.Schema;
using Company.ExchangeMcp;
using Company.ExchangeMcp.Exchange;
using Company.ExchangeMcp.Security;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using ModelContextProtocol.AspNetCore;

internal sealed partial class Checks
{
    // Transport-only checks for the Exchange 2019 permission/delegate shapes. Live grants are
    // intentionally exercised by the deployed MCP approval flow, never by this synthetic runner.
    private async Task SharingChecksAsync()
    {
        var calls = new List<string>();
        var responses = new List<string>();
        var folderChangeKey = "calendar-change";
        var client = NewEwsClient(new DelegateHandler(async (request, cancellationToken) =>
        {
            var body = await request.Content!.ReadAsStringAsync(cancellationToken);
            var operation = XDocument.Parse(body).Root!.Element(XName.Get("Body", SoapNamespace))!.Elements().Single().Name.LocalName;
            calls.Add(body);
            if (operation == "UpdateFolder") folderChangeKey = "calendar-change-2";
            var response = operation switch
            {
                "GetFolder" => FolderPermissionsResponse("GetFolder", "calendar-id", folderChangeKey, calendar: true),
                "UpdateFolder" => FolderPermissionsResponse("UpdateFolder", "calendar-id", folderChangeKey, calendar: true),
                "GetDelegate" or "AddDelegate" or "UpdateDelegate" or "RemoveDelegate" => DelegateResponse(operation),
                _ => SoapResponse(operation, "NoError", string.Empty)
            };
            responses.Add(response);
            return Response(response);
        }));

        var snapshot = await client.GetFolderPermissionsAsync("alice@example.test", "calendar", CancellationToken.None);
        Expect(snapshot.IsCalendar && snapshot.FolderClass == "IPF.Appointment" && snapshot.Permissions.Count == 3
            && snapshot.Permissions[0].User.Principal == "alice@example.test"
            && snapshot.Permissions[1].User.Principal == "Default"
            && snapshot.Permissions[2].User.Principal == "Anonymous"
            && snapshot.EffectiveRights?.Read == true,
            "Exchange 2019 calendar permission entries were not parsed safely.");
        Expect(calls[0].Contains("FieldURI=\"folder:PermissionSet\"", StringComparison.Ordinal)
            && calls[0].Contains("FieldURI=\"folder:EffectiveRights\"", StringComparison.Ordinal)
            && calls[0].Contains("FieldURI=\"folder:FolderClass\"", StringComparison.Ordinal)
            && calls[0].Contains("ExchangeImpersonation", StringComparison.Ordinal),
            "Folder permission discovery omitted the permission shape or impersonation header.");

        var custom = new EwsFolderPermission(new EwsSharingUserId("bob@example.test", null, null, null, null),
            true, false, false, true, false, "Owned", "Owned", "TimeOnly", null, "Custom");
        var updated = snapshot with
        {
            Permissions = snapshot.Permissions.Append(custom).ToArray()
        };
        var result = await client.UpdateFolderPermissionsAsync("alice@example.test", "calendar-id", "calendar-change", updated, CancellationToken.None);
        var update = XDocument.Parse(calls[1]);
        var wirePermissions = update.Descendants(XName.Get("CalendarPermission", TypesNamespace)).ToArray();
        var namedWirePermissions = wirePermissions.Where(x => x.Element(XName.Get("CalendarPermissionLevel", TypesNamespace))?.Value != "Custom");
        var customWirePermission = wirePermissions.Single(x => x.Element(XName.Get("CalendarPermissionLevel", TypesNamespace))?.Value == "Custom");
        Expect(result.ChangeKey == "calendar-change-2"
            && wirePermissions.Length == 4
            && namedWirePermissions.All(x => x.Elements().Select(child => child.Name.LocalName)
                .SequenceEqual(["UserId", "CalendarPermissionLevel"]))
            && customWirePermission.Elements().Select(child => child.Name.LocalName)
                .SequenceEqual(["UserId", "CanCreateItems", "CanCreateSubFolders", "IsFolderOwner", "IsFolderVisible",
                    "IsFolderContact", "EditItems", "DeleteItems", "ReadItems", "CalendarPermissionLevel"])
            && customWirePermission.Element(XName.Get("CanCreateItems", TypesNamespace))?.Value == "true"
            && customWirePermission.Element(XName.Get("CanCreateSubFolders", TypesNamespace))?.Value == "false"
            && customWirePermission.Element(XName.Get("ReadItems", TypesNamespace))?.Value == "TimeOnly"
            && update.Descendants(XName.Get("UnknownEntry", TypesNamespace)).Single().Value == "preserve-me"
            && update.Descendants(XName.Get("UnknownEntry", TypesNamespace)).Count() == 1
            && update.Descendants(XName.Get("FolderId", TypesNamespace)).Single().Attribute("ChangeKey")?.Value == "calendar-change"
            && XDocument.Parse(calls[2]).Root!.Element(XName.Get("Body", SoapNamespace))!.Elements().Single().Name.LocalName == "GetFolder",
            "Folder permission replacement did not preserve the complete calendar ACL, current change key, or post-write reread.");

        var ordinaryCalls = new List<string>();
        var ordinaryResponses = new List<string>();
        var ordinaryClient = NewEwsClient(new DelegateHandler(async (request, cancellationToken) =>
        {
            var body = await request.Content!.ReadAsStringAsync(cancellationToken);
            ordinaryCalls.Add(body);
            var operation = XDocument.Parse(body).Root!.Element(XName.Get("Body", SoapNamespace))!.Elements().Single().Name.LocalName;
            var response = FolderPermissionsResponse(operation, "mail-id", "mail-change", calendar: false);
            ordinaryResponses.Add(response);
            return Response(response);
        }));
        var ordinary = await ordinaryClient.GetFolderPermissionsAsync("alice@example.test", "inbox", CancellationToken.None);
        await ordinaryClient.UpdateFolderPermissionsAsync("alice@example.test", "mail-id", "mail-change", ordinary, CancellationToken.None);
        var ordinaryUpdate = XDocument.Parse(ordinaryCalls[1]);
        var ordinaryEntries = ordinaryUpdate.Descendants(XName.Get("Permission", TypesNamespace)).ToArray();
        Expect(ordinary.FolderClass == "IPF.Note" && ordinaryEntries.Length == 2
            && ordinaryEntries.All(x => x.Elements().Select(child => child.Name.LocalName)
                .SequenceEqual(["UserId", "PermissionLevel"]))
            && ordinaryCalls[0].Contains("FieldURI=\"folder:FolderClass\"", StringComparison.Ordinal),
            "Named ordinary-folder levels were mixed with individual flags or omitted the folder class.");

        var delegates = await client.GetDelegatesAsync("alice@example.test", CancellationToken.None);
        Expect(delegates.DeliverMeetingRequests == "DelegatesAndMe" && delegates.Items.Count == 1
            && delegates.Items[0].User.PrimarySmtpAddress == "bob@example.test"
            && delegates.Items[0].ViewPrivateItems == true,
            "Exchange 2019 delegate response was not parsed safely.");

        await client.AddDelegateAsync("alice@example.test",
            new EwsDelegateInput(new EwsSharingUserId("bob@example.test", null, null, null, null),
                "Editor", null, null, null, null, null, false, false), "DelegatesAndMe", CancellationToken.None);
        await client.UpdateDelegateAsync("alice@example.test",
            new EwsDelegateInput(new EwsSharingUserId("bob@example.test", null, null, null, null),
                "Reviewer", null, null, null, null, null, false, false), "DelegatesAndMe", CancellationToken.None);
        await client.RemoveDelegateAsync("alice@example.test", "bob@example.test", CancellationToken.None);
        ValidateSharingSchema(calls.Concat(responses).Concat(ordinaryCalls).Concat(ordinaryResponses));

        var failureClient = NewEwsClient(new DelegateHandler((_, _) => Task.FromResult(
            Response(DelegateChildFailureResponse("AddDelegate")))));
        await AssertThrowsAsync<InvalidOperationException>(
            () => failureClient.AddDelegateAsync("alice@example.test",
                new EwsDelegateInput(new EwsSharingUserId("bob@example.test", null, null, null, null),
                    "Editor", null, null, null, null, null, false, false), null, CancellationToken.None));

        var missingUserClient = NewEwsClient(new DelegateHandler((_, _) => Task.FromResult(
            Response(DelegateMissingUserResponse("GetDelegate")))));
        await AssertThrowsAsync<InvalidOperationException>(
            () => missingUserClient.GetDelegatesAsync("alice@example.test", CancellationToken.None));

        await InternalSharingIdentityChecksAsync();
        await OptionalDelegateResponseCodeChecksAsync();

        var malformedBoolClient = NewEwsClient(new DelegateHandler((_, _) => Task.FromResult(
            Response(MalformedFolderResponse("malformed-bool")))));
        await AssertThrowsAsync<InvalidOperationException>(
            () => malformedBoolClient.GetFolderPermissionsAsync("alice@example.test", "calendar", CancellationToken.None));
        var mixedPermissionClient = NewEwsClient(new DelegateHandler((_, _) => Task.FromResult(
            Response(MalformedFolderResponse("mixed-collections")))));
        await AssertThrowsAsync<InvalidOperationException>(
            () => mixedPermissionClient.GetFolderPermissionsAsync("alice@example.test", "calendar", CancellationToken.None));

        await EffectiveRightsVariantChecksAsync();

    }

    private async Task InternalSharingIdentityChecksAsync()
    {
        const string sid = "S-1-5-21-111-222-333-444";
        const string userId = "<t:UserId><t:SID>" + sid
            + "</t:SID><t:PrimarySmtpAddress>bob@example.test</t:PrimarySmtpAddress>"
            + "<t:DisplayName>Bob</t:DisplayName></t:UserId>";
        var folderCalls = new List<string>();
        var folderResponses = new List<string>();
        var folderClient = NewEwsClient(new DelegateHandler(async (request, cancellationToken) =>
        {
            var body = await request.Content!.ReadAsStringAsync(cancellationToken);
            folderCalls.Add(body);
            var operation = XDocument.Parse(body).Root!.Element(XName.Get("Body", SoapNamespace))!
                .Elements().Single().Name.LocalName;
            var response = FolderIdentityResponse(operation, userId);
            folderResponses.Add(response);
            return Response(response);
        }));
        var snapshot = await folderClient.GetFolderPermissionsAsync("alice@example.test", "calendar", CancellationToken.None);
        Expect(snapshot.Permissions[0].User is
        { PrimarySmtpAddress: "bob@example.test", DisplayName: "Bob", Sid: sid }
            && snapshot.Permissions[0].User.Principal == "bob@example.test",
            "An internal folder principal with SID, SMTP address, and display name was not retained safely.");
        var updated = await folderClient.UpdateFolderPermissionsAsync("alice@example.test", snapshot.Id,
            snapshot.ChangeKey, snapshot, CancellationToken.None);
        var update = XDocument.Parse(folderCalls[1]);
        var preservedUser = update.Descendants(XName.Get("CalendarPermission", TypesNamespace))
            .Select(x => x.Element(XName.Get("UserId", TypesNamespace)))
            .Single(x => x?.Element(XName.Get("PrimarySmtpAddress", TypesNamespace))?.Value == "bob@example.test")!;
        Expect(preservedUser.Elements().Select(x => x.Name.LocalName).SequenceEqual(["PrimarySmtpAddress"])
            && updated.Permissions[0].User is { PrimarySmtpAddress: "bob@example.test", Sid: sid }
            && !folderCalls[1].Contains(sid, StringComparison.Ordinal),
            "A folder ACL write changed the principal or exposed its internal SID on the wire.");

        var delegateResponse = DelegateIdentityResponse(userId);
        var delegateClient = NewEwsClient(new DelegateHandler((_, _) => Task.FromResult(Response(delegateResponse))));
        var delegates = await delegateClient.GetDelegatesAsync("alice@example.test", CancellationToken.None);
        Expect(delegates.Items.Single().User is
        { PrimarySmtpAddress: "bob@example.test", DisplayName: "Bob", Sid: sid }
            && delegates.Items.Single().User.Principal == "bob@example.test",
            "An internal delegate principal with SID, SMTP address, and display name was not retained safely.");

        var malformedUserIds = new[]
        {
            "<t:UserId><t:SID>" + sid + "</t:SID><t:DistinguishedUser>Default</t:DistinguishedUser></t:UserId>",
            "<t:UserId><t:PrimarySmtpAddress>bob@example.test</t:PrimarySmtpAddress>"
                + "<t:ExternalUserIdentity>external</t:ExternalUserIdentity></t:UserId>",
            "<t:UserId><t:SID/><t:PrimarySmtpAddress>bob@example.test</t:PrimarySmtpAddress></t:UserId>",
            "<t:UserId><t:PrimarySmtpAddress> </t:PrimarySmtpAddress></t:UserId>",
            "<t:UserId><t:ExternalUserIdentity/></t:UserId>",
            "<t:UserId><t:DistinguishedUser>Other</t:DistinguishedUser></t:UserId>",
            "<t:UserId><t:DisplayName>Bob</t:DisplayName></t:UserId>",
            "<t:UserId><t:PrimarySmtpAddress>bob@example.test</t:PrimarySmtpAddress>"
                + "<t:PrimarySmtpAddress>bob@example.test</t:PrimarySmtpAddress></t:UserId>"
        };
        foreach (var malformedUserId in malformedUserIds)
        {
            var badFolderClient = NewEwsClient(new DelegateHandler((_, _) => Task.FromResult(Response(
                FolderIdentityResponse("GetFolder", malformedUserId)))));
            await AssertThrowsAsync<InvalidOperationException>(() => badFolderClient.GetFolderPermissionsAsync(
                "alice@example.test", "calendar", CancellationToken.None));
            var badDelegateClient = NewEwsClient(new DelegateHandler((_, _) => Task.FromResult(Response(
                DelegateIdentityResponse(malformedUserId)))));
            await AssertThrowsAsync<InvalidOperationException>(() => badDelegateClient.GetDelegatesAsync(
                "alice@example.test", CancellationToken.None));
        }

        ValidateSharingSchema(folderCalls.Concat(folderResponses).Append(delegateResponse));
    }

    private async Task OptionalDelegateResponseCodeChecksAsync()
    {
        var optionalCodeCases = new (string? Outer, string? Child)[]
        {
            (null, "NoError"), ("NoError", null), (null, null)
        };
        var input = new EwsDelegateInput(new EwsSharingUserId("bob@example.test", null, null, null, null),
            "Editor", null, null, null, null, null, false, false);
        foreach (var operation in new[] { "GetDelegate", "AddDelegate", "UpdateDelegate", "RemoveDelegate" })
            foreach (var (outerCode, childCode) in optionalCodeCases)
            {
                var responses = new List<string>();
                var client = NewEwsClient(new DelegateHandler(async (request, cancellationToken) =>
                {
                    var body = await request.Content!.ReadAsStringAsync(cancellationToken);
                    var actualOperation = XDocument.Parse(body).Root!.Element(XName.Get("Body", SoapNamespace))!
                        .Elements().Single().Name.LocalName;
                    var response = DelegateResponseVariant(actualOperation, outerCode, childCode);
                    responses.Add(response);
                    return Response(response);
                }));

                if (operation == "GetDelegate")
                {
                    var result = await client.GetDelegatesAsync("alice@example.test", CancellationToken.None);
                    Expect(result.Items.Count == 1 && result.DeliverMeetingRequests == "DelegatesAndMe",
                        "A schema-valid GetDelegate response with an omitted optional ResponseCode was rejected or parsed incorrectly.");
                }
                else if (operation == "AddDelegate")
                    await client.AddDelegateAsync("alice@example.test", input, "DelegatesAndMe", CancellationToken.None);
                else if (operation == "UpdateDelegate")
                    await client.UpdateDelegateAsync("alice@example.test", input, "DelegatesAndMe", CancellationToken.None);
                else
                    await client.RemoveDelegateAsync("alice@example.test", "bob@example.test", CancellationToken.None);

                ValidateSharingSchema(responses);
            }

        var metadataResponse = DelegateResponseVariant("GetDelegate", includeOuterMetadata: true);
        var metadataClient = NewEwsClient(new DelegateHandler((_, _) => Task.FromResult(Response(metadataResponse))));
        Expect((await metadataClient.GetDelegatesAsync("alice@example.test", CancellationToken.None)).Items.Count == 1,
            "A successful delegate response with optional base response metadata was rejected.");
        ValidateSharingSchema([metadataResponse]);

        var malformedResponses = new[]
        {
            DelegateResponseVariant("GetDelegate", outerCode: "ErrorInternalServerError"),
            DelegateResponseVariant("GetDelegate", outerClass: null),
            DelegateResponseVariant("GetDelegate", childClass: null),
            DelegateResponseVariant("GetDelegate", outerClass: "Error", outerCode: null),
            DelegateResponseVariant("GetDelegate", childClass: "Error", childCode: null),
            DelegateResponseVariant("GetDelegate", duplicateOuterCodes: true),
            DelegateResponseVariant("GetDelegate", duplicateChildCodes: true),
            DelegateResponseVariant("GetDelegate", emptyMessages: true),
            DelegateResponseVariant("GetDelegate", duplicateResponseMessages: true),
            DelegateResponseVariant("GetDelegate", childClass: "Error", childCode: "ErrorDelegateAlreadyExists")
        };
        foreach (var response in malformedResponses)
        {
            var client = NewEwsClient(new DelegateHandler((_, _) => Task.FromResult(Response(response))));
            await AssertThrowsAsync<InvalidOperationException>(() => client.GetDelegatesAsync(
                "alice@example.test", CancellationToken.None));
        }
    }

    private async Task EffectiveRightsVariantChecksAsync()
    {
        static string Variant(string mode)
        {
            var rights = mode == "absent"
                ? string.Empty
                : $"<t:EffectiveRights><t:Read>{(mode == "true" ? "true" : "false")}</t:Read>"
                    + $"<t:CreateContents>{(mode == "true" ? "true" : "false")}</t:CreateContents>"
                    + $"<t:Modify>{(mode == "true" ? "true" : "false")}</t:Modify>"
                    + $"<t:Delete>{(mode == "true" ? "true" : "false")}</t:Delete></t:EffectiveRights>";
            return $"<s:Envelope xmlns:s='{SoapNamespace}' xmlns:m='{MessagesNamespace}' xmlns:t='{TypesNamespace}'><s:Body>"
                + "<m:GetFolderResponse><m:ResponseMessages><m:GetFolderResponseMessage ResponseClass='Success'>"
                + "<m:ResponseCode>NoError</m:ResponseCode><m:Folders><t:Folder>"
                + "<t:FolderId Id='calendar-id' ChangeKey='calendar-change'/>" + rights
                + "</t:Folder></m:Folders></m:GetFolderResponseMessage></m:ResponseMessages>"
                + "</m:GetFolderResponse></s:Body></s:Envelope>";
        }

        async Task<EwsFolderAccessRights> Read(string mode)
        {
            var client = NewEwsClient(new DelegateHandler((_, _) => Task.FromResult(Response(Variant(mode)))));
            return await client.GetEffectiveRightsAsync("alice@example.test", "calendar", CancellationToken.None);
        }

        var trueRights = await Read("true");
        var falseRights = await Read("false");
        var absentRights = await Read("absent");
        Expect(trueRights is { Read: true, Create: true, Modify: true, Delete: true }
            && falseRights is { Read: false, Create: false, Modify: false, Delete: false }
            && absentRights is { Read: null, Create: null, Modify: null, Delete: null },
            "EffectiveRights metadata did not preserve true, false, and absent Exchange values distinctly.");

        string? permissionMessage = null;
        string? unknownMessage = null;
        foreach (var code in new[] { "ErrorAccessDenied", "ErrorFuturePermissionCode" })
        {
            var client = NewEwsClient(new DelegateHandler((_, _) => Task.FromResult(Response(
                SoapResponse("GetFolder", code, "synthetic-private-error-detail")))));
            Exception? failure = null;
            try { await client.GetEffectiveRightsAsync("alice@example.test", "calendar", CancellationToken.None); }
            catch (Exception exception) { failure = exception; }
            Expect(failure is InvalidOperationException
                && (code == "ErrorAccessDenied" ? failure is EwsPermissionDeniedException : failure is not EwsPermissionDeniedException)
                && !failure.Message.Contains(code, StringComparison.Ordinal)
                && !failure.Message.Contains("synthetic-private-error-detail", StringComparison.Ordinal),
                $"Exchange permission/error code {code} was exposed instead of sanitized.");
            if (code == "ErrorAccessDenied") permissionMessage = failure?.Message;
            else unknownMessage = failure?.Message;
        }
        Expect(!string.IsNullOrWhiteSpace(permissionMessage) && !string.IsNullOrWhiteSpace(unknownMessage)
            && !string.Equals(permissionMessage, unknownMessage, StringComparison.Ordinal),
            "Missing permission and unsupported Exchange responses were not surfaced as distinct safe outcomes.");

        var transportClient = NewEwsClient(new DelegateHandler((_, _) => throw new HttpRequestException("synthetic-private-transport-detail")));
        Exception? transportFailure = null;
        try { await transportClient.GetEffectiveRightsAsync("alice@example.test", "calendar", CancellationToken.None); }
        catch (Exception exception) { transportFailure = exception; }
        Expect(transportFailure is InvalidOperationException
            && !transportFailure.Message.Contains("synthetic-private-transport-detail", StringComparison.Ordinal),
            "An unknown Exchange transport exception was exposed to the mailbox caller.");
    }

    private async Task SharingNativeChecksAsync()
    {
        await AssertInternalSidNotExposedAsync();
        await AssertSharingApprovalCancellationAsync();
        await AssertSharingApprovalBindingAsync();
        await AssertSharingStaleAclAsync();
        await AssertSharingApprovalReplayAsync();
        await AssertSharingPermissionSemanticsAsync();
        await AssertGenericPermissionSemanticsAsync();
        await AssertGenericPermissionWireSemanticsAsync();
        await DelegateNativeChecksAsync();
    }

    private async Task AssertInternalSidNotExposedAsync()
    {
        const string sid = "S-1-5-21-111-222-333-444";
        var exchange = new SharingPolicyRecordingHandler(internalIdentity: true);
        await using var host = await StartSharingHostAsync(exchange, writesEnabled: true, sendEnabled: true);
        await using var client = await CreateNativeClientAsync(host,
            Token("user-a", "mail.read mail.manage", sessionId: "sharing-sid-redaction"),
            new NativeFormResponder(accept: false));
        var profile = await client.Client.CallToolAsync("sharing_get_folder_permissions",
            new Dictionary<string, object?> { ["folder"] = "calendar" });
        var serialized = NativeData(profile).GetRawText();
        Expect(serialized.Contains("alice@example.test", StringComparison.Ordinal)
            && serialized.Contains("Alice", StringComparison.Ordinal)
            && !serialized.Contains(sid, StringComparison.Ordinal),
            "A native folder permission response exposed an internal Exchange SID or lost the public principal.");
    }

    private async Task AssertSharingApprovalCancellationAsync()
    {
        var exchange = new SharingPolicyRecordingHandler();
        await using var host = await StartSharingHostAsync(exchange, writesEnabled: true, sendEnabled: true,
            classicStateful: true);
        var responder = new NativeFormResponder(accept: false);
        await using var client = await CreateNativeClientAsync(host,
            Token("user-a", "mail.read mail.write mail.manage", sessionId: "sharing-cancel"), responder);
        var profile = await client.Client.CallToolAsync("sharing_get_folder_permissions",
            new Dictionary<string, object?> { ["folder"] = "calendar" });
        var handle = NativeData(profile).GetProperty("folderHandle").GetString()!;
        var result = await client.Client.CallToolAsync("sharing_set_folder_permission",
            SharingPermissionArguments(handle));
        var message = responder.LastRequest?.Message ?? string.Empty;
        Expect(result.IsError != true && NativeData(result).GetProperty("status").GetString() == "cancelled"
            && exchange.UpdateCount == 0 && responder.Calls == 1
            && message.Contains("Read access", StringComparison.Ordinal)
            && message.Contains("Create items", StringComparison.Ordinal)
            && message.Contains("Visible", StringComparison.Ordinal)
            && message.Contains("edit", StringComparison.Ordinal)
            && message.Contains("delete", StringComparison.Ordinal),
            "Folder sharing confirmation did not show every ACL field or cancel before EWS.");
    }

    private async Task AssertSharingApprovalBindingAsync()
    {
        var exchange = new SharingPolicyRecordingHandler();
        await using var host = await StartSharingHostAsync(exchange, writesEnabled: true, sendEnabled: true);
        var token = Token("user-a", "mail.read mail.write mail.manage", sessionId: "sharing-bind");
        await InitializeAsync(host.Client, token, elicitation: true);
        var profile = await ToolRequestAsync(host.Client, token, "tools/call", new
        {
            name = "sharing_get_folder_permissions",
            arguments = new { folder = "calendar" }
        }, JulyProtocolVersion, elicitation: true);
        var handle = StructuredProperty(profile.Body, "folderHandle");
        var arguments = SharingPermissionArguments(handle);
        var approval = await ToolRequestAsync(host.Client, token, "tools/call", new
        {
            name = "sharing_set_folder_permission",
            arguments
        }, JulyProtocolVersion, elicitation: true);
        var state = InputRequiredState(approval.Body);
        var alternate = Token("user-a", "mail.read mail.write mail.manage", azp: "chatgpt-alt",
            sessionId: "sharing-bind");
        var alternateRetry = await SharingApprovalResumeAsync(host.Client, alternate, state, arguments);
        var changedSession = Token("user-a", "mail.read mail.write mail.manage", sessionId: "sharing-other");
        var changedRetry = await SharingApprovalResumeAsync(host.Client, changedSession, state, arguments);
        Expect(IsToolError(alternateRetry.Body) && IsToolError(changedRetry.Body) && exchange.UpdateCount == 0,
            "A sharing approval was reusable by another OAuth client or session.");
    }

    private async Task AssertSharingStaleAclAsync()
    {
        var exchange = new SharingPolicyRecordingHandler();
        await using var host = await StartSharingHostAsync(exchange, writesEnabled: true, sendEnabled: true,
            classicStateful: true);
        var responder = new NativeFormResponder(accept: true)
        {
            BeforeResponse = () => exchange.ChangeKey = "changed-after-approval"
        };
        await using var client = await CreateNativeClientAsync(host,
            Token("user-a", "mail.read mail.write mail.manage", sessionId: "sharing-stale"), responder);
        var profile = await client.Client.CallToolAsync("sharing_get_folder_permissions",
            new Dictionary<string, object?> { ["folder"] = "calendar" });
        var handle = NativeData(profile).GetProperty("folderHandle").GetString()!;
        var rejected = await NativeRejectedAsync(client.Client, "sharing_set_folder_permission",
            SharingPermissionArguments(handle));
        Expect(rejected && exchange.UpdateCount == 0,
            "A folder ACL changed while approval was open and was still updated.");
    }

    private async Task AssertSharingApprovalReplayAsync()
    {
        var exchange = new SharingPolicyRecordingHandler();
        await using var host = await StartSharingHostAsync(exchange, writesEnabled: true, sendEnabled: true);
        var token = Token("user-a", "mail.read mail.write mail.manage", sessionId: "sharing-replay");
        await InitializeAsync(host.Client, token, elicitation: true);
        var profile = await ToolRequestAsync(host.Client, token, "tools/call", new
        {
            name = "sharing_get_folder_permissions",
            arguments = new { folder = "calendar" }
        }, JulyProtocolVersion, elicitation: true);
        var handle = StructuredProperty(profile.Body, "folderHandle");
        var arguments = SharingPermissionArguments(handle);
        var approval = await ToolRequestAsync(host.Client, token, "tools/call", new
        {
            name = "sharing_set_folder_permission",
            arguments
        }, JulyProtocolVersion, elicitation: true);
        var state = InputRequiredState(approval.Body);
        var first = await SharingApprovalResumeAsync(host.Client, token, state, arguments);
        var replay = await SharingApprovalResumeAsync(host.Client, token, state, arguments);
        Expect(!IsToolError(first.Body) && IsToolError(replay.Body) && exchange.UpdateCount == 1,
            "A consumed sharing approval was replayed against Exchange.");
    }

    private async Task AssertSharingPermissionSemanticsAsync()
    {
        var exchange = new SharingPolicyRecordingHandler();
        await using var host = await StartSharingHostAsync(exchange, writesEnabled: true, sendEnabled: true,
            classicStateful: true);
        var responder = new NativeFormResponder(accept: false);
        await using var client = await CreateNativeClientAsync(host,
            Token("user-a", "mail.read mail.write mail.manage", sessionId: "sharing-permission-semantics"), responder);
        var profile = await client.Client.CallToolAsync("sharing_get_folder_permissions",
            new Dictionary<string, object?> { ["folder"] = "calendar" });
        var folder = NativeData(profile).GetProperty("folderHandle").GetString()!;
        var named = new Dictionary<string, object?>
        {
            ["folder"] = folder,
            ["principal"] = "bob@example.test",
            ["calendarPermissionLevel"] = "Editor"
        };
        foreach (var (field, value) in new (string, object?)[]
        {
            ("readItems", "FullDetails"), ("calendarReadItems", "TimeOnly"),
            ("editItems", "Owned"), ("deleteItems", "Owned"),
            ("canCreateItems", false), ("canCreateSubFolders", false), ("isFolderVisible", false)
        })
        {
            var arguments = new Dictionary<string, object?>(named) { [field] = value };
            Expect(await NativeRejectedAsync(client.Client, "sharing_set_folder_permission", arguments),
                $"A named permission level was accepted with individual field {field}.");
        }
        var otherNamedField = new Dictionary<string, object?>(named)
        {
            ["calendarPermissionLevel"] = "",
            ["permissionLevel"] = "Editor",
            ["canCreateItems"] = false
        };
        Expect(await NativeRejectedAsync(client.Client, "sharing_set_folder_permission", otherNamedField)
            && exchange.GetCount == 1 && responder.Calls == 0 && exchange.UpdateCount == 0,
            "A named level combined with custom fields reached Exchange or approval.");

        Expect(await NativeRejectedAsync(client.Client, "sharing_set_folder_permission", new Dictionary<string, object?>
        {
            ["folder"] = folder,
            ["principal"] = "bob@example.test",
            ["calendarReadItems"] = "TimeOnly"
        }) && exchange.GetCount == 2 && responder.Calls == 0 && exchange.UpdateCount == 0,
            "A new principal without an explicit permission level reached approval or Exchange write.");

        Expect(await NativeRejectedAsync(client.Client, "sharing_remove_folder_permission", new Dictionary<string, object?>
        {
            ["folder"] = folder,
            ["principal"] = "alice@example.test"
        }) && responder.Calls == 0 && exchange.UpdateCount == 0,
            "The folder owner was offered for removal or removed from Exchange.");

        foreach (var wrongField in new[]
        {
            new Dictionary<string, object?> { ["permissionLevel"] = "Reviewer" },
            new Dictionary<string, object?> { ["readItems"] = "FullDetails" }
        })
        {
            wrongField["folder"] = folder;
            wrongField["principal"] = "bob@example.test";
            Expect(await NativeRejectedAsync(client.Client, "sharing_set_folder_permission", wrongField)
                && responder.Calls == 0 && exchange.UpdateCount == 0,
                "A generic permission field was accepted for a calendar folder.");
        }

        Expect(await NativeRejectedAsync(client.Client, "sharing_set_folder_permission", new Dictionary<string, object?>
        {
            ["folder"] = folder,
            ["principal"] = "alice@example.test",
            ["calendarPermissionLevel"] = "Reviewer"
        }) && responder.Calls == 0 && exchange.UpdateCount == 0,
            "The folder owner was offered a named-level downgrade.");
        var ownerReapply = await client.Client.CallToolAsync("sharing_set_folder_permission", new Dictionary<string, object?>
        {
            ["folder"] = folder,
            ["principal"] = "alice@example.test",
            ["calendarPermissionLevel"] = "Owner"
        });
        Expect(ownerReapply.IsError != true && NativeData(ownerReapply).GetProperty("status").GetString() == "cancelled"
            && responder.Calls == 1 && exchange.UpdateCount == 0,
            "Reapplying the existing folder owner's Owner role was rejected or bypassed confirmation.");

        foreach (var (level, expectedFields) in new (string, string[])[]
        {
            ("Reviewer", ["Read access: FullDetails", "Create items: False; create subfolders: False",
                "Folder owner: False; folder contact: False", "Visible: True; edit: None; delete: None"]),
            ("Editor", ["Read access: FullDetails", "Create items: True; create subfolders: False",
                "Folder owner: False; folder contact: False", "Visible: True; edit: All; delete: All"]),
            ("Owner", ["Read access: FullDetails", "Create items: True; create subfolders: True",
                "Folder owner: True; folder contact: True", "Visible: True; edit: All; delete: All"])
        })
        {
            var preview = await client.Client.CallToolAsync("sharing_set_folder_permission", new Dictionary<string, object?>
            {
                ["folder"] = folder,
                ["principal"] = "bob@example.test",
                ["calendarPermissionLevel"] = level
            });
            var message = responder.LastRequest?.Message ?? string.Empty;
            Expect(preview.IsError != true && NativeData(preview).GetProperty("status").GetString() == "cancelled"
                && message.Contains($"Effective permission: {level}", StringComparison.Ordinal)
                && expectedFields.All(field => message.Contains(field, StringComparison.Ordinal)),
                $"The {level} confirmation preview did not show its documented default permissions.");
        }

        responder.Accept = true;
        var customEdit = await client.Client.CallToolAsync("sharing_set_folder_permission", new Dictionary<string, object?>
        {
            ["folder"] = folder,
            ["principal"] = "Default",
            ["calendarReadItems"] = "FullDetails"
        });
        var wire = XDocument.Parse(exchange.LastUpdateBody!);
        var wirePermissions = wire.Descendants(XName.Get("CalendarPermission", TypesNamespace)).ToArray();
        var customDefault = wirePermissions.Single(x => x.Element(XName.Get("UserId", TypesNamespace))?
            .Element(XName.Get("DistinguishedUser", TypesNamespace))?.Value == "Default");
        var confirmation = responder.LastRequest?.Message ?? string.Empty;
        Expect(customEdit.IsError != true && NativeData(customEdit).GetProperty("status").GetString() == "folder_permissions_updated"
            && exchange.UpdateCount == 1 && customDefault.Element(XName.Get("CalendarPermissionLevel", TypesNamespace))?.Value == "Custom"
            && customDefault.Element(XName.Get("ReadItems", TypesNamespace))?.Value == "FullDetails"
            && customDefault.Element(XName.Get("CanCreateItems", TypesNamespace))?.Value == "false"
            && customDefault.Element(XName.Get("CanCreateSubFolders", TypesNamespace))?.Value == "false"
            && customDefault.Element(XName.Get("IsFolderVisible", TypesNamespace))?.Value == "false"
            && customDefault.Element(XName.Get("EditItems", TypesNamespace))?.Value == "None"
            && customDefault.Element(XName.Get("DeleteItems", TypesNamespace))?.Value == "None"
            && wirePermissions.Where(x => !ReferenceEquals(x, customDefault)).All(x => x.Elements().Select(child => child.Name.LocalName)
                .SequenceEqual(["UserId", "CalendarPermissionLevel"]))
            && confirmation.Contains("Effective permission: Custom", StringComparison.Ordinal)
            && confirmation.Contains("Read access: FullDetails", StringComparison.Ordinal),
            "Editing an existing ACL with individual fields did not preserve omitted custom fields or preview Custom.");
    }

    private async Task AssertGenericPermissionSemanticsAsync()
    {
        var exchange = new SharingPolicyRecordingHandler(calendar: false);
        await using var host = await StartSharingHostAsync(exchange, writesEnabled: true, sendEnabled: true,
            classicStateful: true);
        var responder = new NativeFormResponder(accept: false);
        await using var client = await CreateNativeClientAsync(host,
            Token("user-a", "mail.read mail.write mail.manage", sessionId: "sharing-generic-permissions"), responder);
        var profile = await client.Client.CallToolAsync("sharing_get_folder_permissions",
            new Dictionary<string, object?> { ["folder"] = "inbox" });
        var folder = NativeData(profile).GetProperty("folderHandle").GetString()!;
        foreach (var wrongField in new[]
        {
            new Dictionary<string, object?> { ["calendarPermissionLevel"] = "Reviewer" },
            new Dictionary<string, object?> { ["calendarReadItems"] = "TimeOnly" }
        })
        {
            wrongField["folder"] = folder;
            wrongField["principal"] = "bob@example.test";
            Expect(await NativeRejectedAsync(client.Client, "sharing_set_folder_permission", wrongField)
                && responder.Calls == 0 && exchange.UpdateCount == 0,
                "A calendar permission field was accepted for an ordinary folder.");
        }

        foreach (var (level, expectedFields) in new (string, string[])[]
        {
            ("None", ["Read access: None", "Create items: False; create subfolders: False",
                "Folder owner: False; folder contact: False", "Visible: False; edit: None; delete: None"]),
            ("Reviewer", ["Read access: FullDetails", "Create items: False; create subfolders: False",
                "Folder owner: False; folder contact: False", "Visible: True; edit: None; delete: None"]),
            ("Editor", ["Read access: FullDetails", "Create items: True; create subfolders: False",
                "Folder owner: False; folder contact: False", "Visible: True; edit: All; delete: All"]),
            ("Owner", ["Read access: FullDetails", "Create items: True; create subfolders: True",
                "Folder owner: True; folder contact: True", "Visible: True; edit: All; delete: All"])
        })
        {
            var preview = await client.Client.CallToolAsync("sharing_set_folder_permission", new Dictionary<string, object?>
            {
                ["folder"] = folder,
                ["principal"] = "charlie@example.test",
                ["permissionLevel"] = level
            });
            var message = responder.LastRequest?.Message ?? string.Empty;
            Expect(preview.IsError != true && NativeData(preview).GetProperty("status").GetString() == "cancelled"
                && message.Contains($"Effective permission: {level}", StringComparison.Ordinal)
                && expectedFields.All(field => message.Contains(field, StringComparison.Ordinal)),
                $"The generic-folder {level} preview used the wrong permission defaults.");
        }
        Expect(exchange.UpdateCount == 0 && responder.Calls == 4,
            "Generic folder permission previews changed Exchange ACLs or skipped confirmation.");
    }

    private async Task AssertGenericPermissionWireSemanticsAsync()
    {
        var exchange = new SharingPolicyRecordingHandler(calendar: false);
        await using var host = await StartSharingHostAsync(exchange, writesEnabled: true, sendEnabled: true,
            classicStateful: true);
        var responder = new NativeFormResponder(accept: true);
        await using var client = await CreateNativeClientAsync(host,
            Token("user-a", "mail.read mail.write mail.manage", sessionId: "sharing-generic-wire"), responder);
        var updateBodies = new List<string>();

        async Task Apply(string? level, string? readItems, string expectedRead)
        {
            var profile = await client.Client.CallToolAsync("sharing_get_folder_permissions",
                new Dictionary<string, object?> { ["folder"] = "inbox" });
            var folder = NativeData(profile).GetProperty("folderHandle").GetString()!;
            var arguments = new Dictionary<string, object?>
            {
                ["folder"] = folder,
                ["principal"] = "bob@example.test"
            };
            if (level is not null) arguments["permissionLevel"] = level;
            if (readItems is not null) arguments["readItems"] = readItems;
            var result = await client.Client.CallToolAsync("sharing_set_folder_permission", arguments);
            var message = responder.LastRequest?.Message ?? string.Empty;
            Expect(result.IsError != true
                && NativeData(result).GetProperty("status").GetString() == "folder_permissions_updated"
                && message.Contains("Read access: " + expectedRead, StringComparison.Ordinal)
                && !message.Contains("Read access: All", StringComparison.Ordinal),
                $"Generic permission {level ?? "Custom"} did not confirm its canonical read access.");

            var body = exchange.LastUpdateBody;
            Expect(!string.IsNullOrWhiteSpace(body), "The accepted generic ACL change did not reach Exchange.");
            if (body is not null) updateBodies.Add(body);
            var permission = body is null ? null : XDocument.Parse(body)
                .Descendants(XName.Get("Permission", TypesNamespace))
                .Single(x => x.Element(XName.Get("UserId", TypesNamespace))?
                    .Element(XName.Get("PrimarySmtpAddress", TypesNamespace))?.Value == "bob@example.test");
            var expectedChildren = level is "Reviewer" or "Editor"
                ? new[] { "UserId", "PermissionLevel" }
                : new[] { "UserId", "CanCreateItems", "CanCreateSubFolders", "IsFolderOwner", "IsFolderVisible",
                    "IsFolderContact", "EditItems", "DeleteItems", "ReadItems", "PermissionLevel" };
            Expect(permission is not null
                && permission.Elements().Select(x => x.Name.LocalName).SequenceEqual(expectedChildren)
                && permission.Element(XName.Get("ReadItems", TypesNamespace))?.Value == (level is "Reviewer" or "Editor" ? null : "FullDetails"),
                $"Generic permission {level ?? "Custom"} produced an invalid Exchange ACL shape.");
        }

        await Apply("Reviewer", null, "FullDetails");
        await Apply("Editor", null, "FullDetails");
        await Apply("Custom", "FullDetails", "FullDetails");
        var finalProfile = await client.Client.CallToolAsync("sharing_get_folder_permissions",
            new Dictionary<string, object?> { ["folder"] = "inbox" });
        var finalFolder = NativeData(finalProfile).GetProperty("folderHandle").GetString()!;
        var getsBeforeInvalidValue = exchange.GetCount;
        var invalidReadAccess = await NativeRejectedAsync(client.Client, "sharing_set_folder_permission",
            new Dictionary<string, object?>
            {
                ["folder"] = finalFolder,
                ["principal"] = "bob@example.test",
                ["permissionLevel"] = "Custom",
                ["readItems"] = "All"
            });
        Expect(invalidReadAccess && exchange.GetCount == getsBeforeInvalidValue
            && exchange.UpdateCount == 3 && responder.Calls == 3,
            "The unsupported generic ReadItems value All reached confirmation or Exchange.");
        Expect(exchange.UpdateCount == 3 && responder.Calls == 3,
            "Generic permission writes did not complete their native approval flow.");
        ValidateSharingSchema(updateBodies);
    }

    private static Dictionary<string, object?> SharingPermissionArguments(string handle) => new()
    {
        ["folder"] = handle,
        ["principal"] = "bob@example.test",
        ["calendarPermissionLevel"] = "Custom",
        ["calendarReadItems"] = "TimeOnly",
        ["canCreateItems"] = true,
        ["canCreateSubFolders"] = false,
        ["isFolderVisible"] = true,
        ["editItems"] = "Owned",
        ["deleteItems"] = "Owned"
    };

    private static Task<(HttpStatusCode StatusCode, string Body)> SharingApprovalResumeAsync(
        HttpClient client, string token, string state, IReadOnlyDictionary<string, object?> arguments) =>
        ToolRequestAsync(client, token, "tools/call", new
        {
            name = "sharing_set_folder_permission",
            requestState = state,
            inputResponses = new Dictionary<string, object?>
            {
                ["sharing_confirmation"] = new { action = "accept", content = new { confirm = true } }
            },
            arguments
        }, JulyProtocolVersion, elicitation: true);

    private static string StructuredProperty(string body, string property)
        => ToolStructuredData(body).GetProperty(property).GetString()!;

    private async Task<TestHostContext> StartSharingHostAsync(HttpMessageHandler exchange,
        bool writesEnabled, bool sendEnabled, bool classicStateful = false)
    {
        var passwordPath = Path.Combine(runDirectory, $"sharing-password-{Guid.NewGuid():N}.txt");
        var introspectionSecretPath = Path.Combine(runDirectory, $"sharing-introspection-{Guid.NewGuid():N}.txt");
        var auditPath = Path.Combine(runDirectory, $"sharing-audit-{Guid.NewGuid():N}.jsonl");
        await File.WriteAllTextAsync(passwordPath, "synthetic-password");
        await File.WriteAllTextAsync(introspectionSecretPath, "synthetic-introspection-secret");
        var app = AppHost.Create([], builder =>
        {
            builder.WebHost.UseTestServer();
            if (!classicStateful)
                builder.Services.PostConfigure<HttpServerTransportOptions>(options =>
                    options.SessionMode = HttpServerSessionMode.Stateless);
            builder.Configuration.AddInMemoryCollection(ConfigurationValues(passwordPath, introspectionSecretPath,
                auditPath, writesEnabled, sendEnabled));
            builder.Services.PostConfigure<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme, options =>
            {
                var configuration = new OpenIdConnectConfiguration { Issuer = Authority };
                configuration.SigningKeys.Add(signingKey);
                options.Configuration = configuration;
                options.ConfigurationManager = new StaticConfigurationManager<OpenIdConnectConfiguration>(configuration);
            });
            builder.Services.AddHttpClient<EwsClient>()
                .ConfigurePrimaryHttpMessageHandler(() => exchange);
            builder.Services.AddHttpClient<KeycloakTokenStatus>()
                .ConfigurePrimaryHttpMessageHandler(() => new IntrospectionHandler());
        });
        await app.StartAsync();
        var client = app.GetTestClient();
        client.BaseAddress = new Uri("https://mail.example.test/");
        return new TestHostContext(app, client);
    }

    private static string FolderPermissionsResponse(string operation, string id, string changeKey, bool calendar) =>
        $"<s:Envelope xmlns:s='{SoapNamespace}' xmlns:m='{MessagesNamespace}' xmlns:t='{TypesNamespace}'><s:Body>"
        + $"<m:{operation}Response><m:ResponseMessages><m:{operation}ResponseMessage ResponseClass='Success'><m:ResponseCode>NoError</m:ResponseCode>"
        + (calendar
            ? $"<m:Folders><t:CalendarFolder><t:FolderId Id='{id}' ChangeKey='{changeKey}'/><t:FolderClass>IPF.Appointment</t:FolderClass><t:EffectiveRights><t:CreateAssociated>false</t:CreateAssociated><t:CreateContents>true</t:CreateContents><t:CreateHierarchy>true</t:CreateHierarchy><t:Delete>true</t:Delete><t:Modify>true</t:Modify><t:Read>true</t:Read><t:ViewPrivateItems>true</t:ViewPrivateItems></t:EffectiveRights><t:PermissionSet><t:CalendarPermissions>"
              + "<t:CalendarPermission><t:UserId><t:PrimarySmtpAddress>alice@example.test</t:PrimarySmtpAddress></t:UserId><t:IsFolderOwner>true</t:IsFolderOwner><t:IsFolderVisible>true</t:IsFolderVisible><t:ReadItems>FullDetails</t:ReadItems><t:CalendarPermissionLevel>Owner</t:CalendarPermissionLevel></t:CalendarPermission>"
              + "<t:CalendarPermission><t:UserId><t:DistinguishedUser>Default</t:DistinguishedUser></t:UserId><t:CanCreateItems>false</t:CanCreateItems><t:CanCreateSubFolders>false</t:CanCreateSubFolders><t:IsFolderOwner>false</t:IsFolderOwner><t:IsFolderVisible>false</t:IsFolderVisible><t:IsFolderContact>false</t:IsFolderContact><t:EditItems>None</t:EditItems><t:DeleteItems>None</t:DeleteItems><t:ReadItems>TimeOnly</t:ReadItems><t:CalendarPermissionLevel>FreeBusyTimeOnly</t:CalendarPermissionLevel></t:CalendarPermission>"
              + "<t:CalendarPermission><t:UserId><t:DistinguishedUser>Anonymous</t:DistinguishedUser></t:UserId><t:CanCreateItems>false</t:CanCreateItems><t:CanCreateSubFolders>false</t:CanCreateSubFolders><t:IsFolderOwner>false</t:IsFolderOwner><t:IsFolderVisible>false</t:IsFolderVisible><t:IsFolderContact>false</t:IsFolderContact><t:EditItems>None</t:EditItems><t:DeleteItems>None</t:DeleteItems><t:ReadItems>None</t:ReadItems><t:CalendarPermissionLevel>None</t:CalendarPermissionLevel></t:CalendarPermission>"
              + "</t:CalendarPermissions><t:UnknownEntries><t:UnknownEntry>preserve-me</t:UnknownEntry></t:UnknownEntries></t:PermissionSet></t:CalendarFolder></m:Folders>"
            : $"<m:Folders><t:Folder><t:FolderId Id='{id}' ChangeKey='{changeKey}'/><t:FolderClass>IPF.Note</t:FolderClass><t:PermissionSet><t:Permissions>"
              + "<t:Permission><t:UserId><t:PrimarySmtpAddress>bob@example.test</t:PrimarySmtpAddress></t:UserId><t:CanCreateItems>true</t:CanCreateItems><t:IsFolderVisible>true</t:IsFolderVisible><t:EditItems>All</t:EditItems><t:DeleteItems>All</t:DeleteItems><t:ReadItems>FullDetails</t:ReadItems><t:PermissionLevel>Editor</t:PermissionLevel></t:Permission>"
              + "<t:Permission><t:UserId><t:DistinguishedUser>Default</t:DistinguishedUser></t:UserId><t:PermissionLevel>None</t:PermissionLevel></t:Permission>"
              + "</t:Permissions></t:PermissionSet></t:Folder></m:Folders>")
        + $"</m:{operation}ResponseMessage></m:ResponseMessages></m:{operation}Response></s:Body></s:Envelope>";

    private static string FolderIdentityResponse(string operation, string userId) =>
        FolderPermissionsResponse(operation, "calendar-id", "calendar-change", calendar: true)
            .Replace("<t:UserId><t:PrimarySmtpAddress>alice@example.test</t:PrimarySmtpAddress></t:UserId>",
                userId, StringComparison.Ordinal);

    private static string DelegateResponse(string operation) =>
        $"<s:Envelope xmlns:s='{SoapNamespace}' xmlns:m='{MessagesNamespace}' xmlns:t='{TypesNamespace}'><s:Body>"
        + $"<m:{operation}Response ResponseClass='Success'><m:ResponseCode>NoError</m:ResponseCode><m:ResponseMessages>"
        + (operation == "GetDelegate"
            ? "<m:DelegateUserResponseMessageType ResponseClass='Success'><m:ResponseCode>NoError</m:ResponseCode><m:DelegateUser><t:UserId><t:PrimarySmtpAddress>bob@example.test</t:PrimarySmtpAddress><t:DisplayName>Bob</t:DisplayName></t:UserId><t:DelegatePermissions><t:CalendarFolderPermissionLevel>Editor</t:CalendarFolderPermissionLevel></t:DelegatePermissions><t:ViewPrivateItems>true</t:ViewPrivateItems></m:DelegateUser></m:DelegateUserResponseMessageType>"
            : "<m:DelegateUserResponseMessageType ResponseClass='Success'><m:ResponseCode>NoError</m:ResponseCode></m:DelegateUserResponseMessageType>")
        + $"</m:ResponseMessages>{(operation == "GetDelegate" ? "<m:DeliverMeetingRequests>DelegatesAndMe</m:DeliverMeetingRequests>" : string.Empty)}</m:{operation}Response></s:Body></s:Envelope>";

    private static string DelegateResponseVariant(string operation, string? outerCode = "NoError",
        string? childCode = "NoError", string? outerClass = "Success", string? childClass = "Success",
        bool duplicateOuterCodes = false, bool duplicateChildCodes = false, bool emptyMessages = false,
        bool duplicateResponseMessages = false, bool includeOuterMetadata = false)
    {
        static string ClassAttribute(string? value) => value is null ? string.Empty : $" ResponseClass='{value}'";
        static string Codes(string? value, bool duplicate) => value is null ? string.Empty
            : $"<m:ResponseCode>{value}</m:ResponseCode>" + (duplicate ? $"<m:ResponseCode>{value}</m:ResponseCode>" : string.Empty);

        var child = $"<m:DelegateUserResponseMessageType{ClassAttribute(childClass)}>{Codes(childCode, duplicateChildCodes)}"
            + (operation == "GetDelegate"
                ? "<m:DelegateUser><t:UserId><t:PrimarySmtpAddress>bob@example.test</t:PrimarySmtpAddress></t:UserId></m:DelegateUser>"
                : string.Empty)
            + "</m:DelegateUserResponseMessageType>";
        var messages = emptyMessages ? "<m:ResponseMessages/>"
            : "<m:ResponseMessages>" + child + "</m:ResponseMessages>"
                + (duplicateResponseMessages ? "<m:ResponseMessages>" + child + "</m:ResponseMessages>" : string.Empty);
        var delivery = operation == "GetDelegate" ? "<m:DeliverMeetingRequests>DelegatesAndMe</m:DeliverMeetingRequests>" : string.Empty;
        var metadata = includeOuterMetadata
            ? "<m:MessageText>successful response metadata</m:MessageText>"
                + Codes(outerCode, duplicateOuterCodes)
                + "<m:DescriptiveLinkKey>7</m:DescriptiveLinkKey><m:MessageXml><t:Detail>safe</t:Detail></m:MessageXml>"
            : Codes(outerCode, duplicateOuterCodes);
        return $"<s:Envelope xmlns:s='{SoapNamespace}' xmlns:m='{MessagesNamespace}' xmlns:t='{TypesNamespace}'><s:Body>"
            + $"<m:{operation}Response{ClassAttribute(outerClass)}>{metadata}{messages}{delivery}</m:{operation}Response>"
            + "</s:Body></s:Envelope>";
    }

    private static string DelegateIdentityResponse(string userId) =>
        DelegateResponse("GetDelegate")
            .Replace("<t:UserId><t:PrimarySmtpAddress>bob@example.test</t:PrimarySmtpAddress><t:DisplayName>Bob</t:DisplayName></t:UserId>",
                userId, StringComparison.Ordinal);

    private static string DelegateChildFailureResponse(string operation) =>
        $"<s:Envelope xmlns:s='{SoapNamespace}' xmlns:m='{MessagesNamespace}' xmlns:t='{TypesNamespace}'><s:Body>"
        + $"<m:{operation}Response ResponseClass='Success'><m:ResponseCode>NoError</m:ResponseCode><m:ResponseMessages><m:DelegateUserResponseMessageType ResponseClass='Error'><m:ResponseCode>ErrorDelegateAlreadyExists</m:ResponseCode></m:DelegateUserResponseMessageType></m:ResponseMessages></m:{operation}Response></s:Body></s:Envelope>";

    private static string DelegateMissingUserResponse(string operation) =>
        $"<s:Envelope xmlns:s='{SoapNamespace}' xmlns:m='{MessagesNamespace}' xmlns:t='{TypesNamespace}'><s:Body>"
        + $"<m:{operation}Response ResponseClass='Success'><m:ResponseCode>NoError</m:ResponseCode><m:ResponseMessages><m:DelegateUserResponseMessageType ResponseClass='Success'><m:ResponseCode>NoError</m:ResponseCode></m:DelegateUserResponseMessageType></m:ResponseMessages></m:{operation}Response></s:Body></s:Envelope>";

    private static string MalformedFolderResponse(string mode)
    {
        var permission = mode == "malformed-bool"
            ? "<t:CalendarPermission><t:UserId><t:PrimarySmtpAddress>alice@example.test</t:PrimarySmtpAddress></t:UserId><t:IsFolderVisible>maybe</t:IsFolderVisible><t:ReadItems>FullDetails</t:ReadItems><t:CalendarPermissionLevel>Owner</t:CalendarPermissionLevel></t:CalendarPermission>"
            : "<t:CalendarPermission><t:UserId><t:PrimarySmtpAddress>alice@example.test</t:PrimarySmtpAddress></t:UserId><t:IsFolderVisible>true</t:IsFolderVisible><t:ReadItems>FullDetails</t:ReadItems><t:CalendarPermissionLevel>Owner</t:CalendarPermissionLevel></t:CalendarPermission>";
        var collection = mode == "mixed-collections"
            ? "<t:Permissions><t:Permission><t:UserId><t:PrimarySmtpAddress>bob@example.test</t:PrimarySmtpAddress></t:UserId><t:PermissionLevel>Reviewer</t:PermissionLevel></t:Permission></t:Permissions>"
            : string.Empty;
        return $"<s:Envelope xmlns:s='{SoapNamespace}' xmlns:m='{MessagesNamespace}' xmlns:t='{TypesNamespace}'><s:Body><m:GetFolderResponse><m:ResponseMessages><m:GetFolderResponseMessage ResponseClass='Success'><m:ResponseCode>NoError</m:ResponseCode><m:Folders><t:CalendarFolder><t:FolderId Id='calendar-id' ChangeKey='calendar-change'/><t:FolderClass>IPF.Appointment</t:FolderClass><t:PermissionSet><t:CalendarPermissions>{permission}</t:CalendarPermissions>{collection}</t:PermissionSet></t:CalendarFolder></m:Folders></m:GetFolderResponseMessage></m:ResponseMessages></m:GetFolderResponse></s:Body></s:Envelope>";
    }

    private static void ValidateSharingSchema(IEnumerable<string> bodies)
    {
        var schemas = LoadOptionalExchangeSchemas();
        foreach (var body in bodies)
        {
            var operation = XDocument.Parse(body).Root!.Element(XName.Get("Body", SoapNamespace))!.Elements().Single();
            if (schemas is not null)
                new XDocument(new XElement(operation)).Validate(schemas, (_, error) => throw new InvalidOperationException(
                    $"Sharing operation failed Exchange 2019 schema validation: {error.Message}"));
        }
    }
}

internal sealed class SharingPolicyRecordingHandler(bool calendar = true, bool internalIdentity = false) : HttpMessageHandler
{
    private const string Soap = "http://schemas.xmlsoap.org/soap/envelope/";
    private const string Messages = "http://schemas.microsoft.com/exchange/services/2006/messages";
    private const string Types = "http://schemas.microsoft.com/exchange/services/2006/types";

    public string ChangeKey { get; set; } = "calendar-change";
    public int UpdateCount { get; private set; }
    public int GetCount { get; private set; }
    public string? LastUpdateBody { get; private set; }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        var body = await request.Content!.ReadAsStringAsync(cancellationToken);
        var document = XDocument.Parse(body);
        var operation = document.Root!.Element(XName.Get("Body", Soap))!.Elements().Single().Name.LocalName;
        if (operation == "GetFolder") GetCount++;
        if (operation == "UpdateFolder")
        {
            UpdateCount++;
            LastUpdateBody = body;
            ChangeKey = "calendar-updated-change";
        }
        var response = operation is "GetFolder" or "UpdateFolder"
            ? FolderResponse(operation, ChangeKey, calendar)
            : SimpleResponse(operation);
        if (internalIdentity && calendar)
            response = response.Replace(
                "<t:UserId><t:PrimarySmtpAddress>alice@example.test</t:PrimarySmtpAddress></t:UserId>",
                "<t:UserId><t:SID>S-1-5-21-111-222-333-444</t:SID>"
                    + "<t:PrimarySmtpAddress>alice@example.test</t:PrimarySmtpAddress><t:DisplayName>Alice</t:DisplayName></t:UserId>",
                StringComparison.Ordinal);
        return new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(response, Encoding.UTF8, "text/xml")
        };
    }

    private static string FolderResponse(string operation, string changeKey, bool calendar) =>
        $"<s:Envelope xmlns:s='{Soap}' xmlns:m='{Messages}' xmlns:t='{Types}'><s:Body>"
        + $"<m:{operation}Response><m:ResponseMessages><m:{operation}ResponseMessage ResponseClass='Success'><m:ResponseCode>NoError</m:ResponseCode>"
        + (calendar
            ? $"<m:Folders><t:CalendarFolder><t:FolderId Id='calendar-id' ChangeKey='{changeKey}'/><t:FolderClass>IPF.Appointment</t:FolderClass><t:EffectiveRights><t:CreateAssociated>false</t:CreateAssociated><t:CreateContents>true</t:CreateContents><t:CreateHierarchy>true</t:CreateHierarchy><t:Delete>true</t:Delete><t:Modify>true</t:Modify><t:Read>true</t:Read><t:ViewPrivateItems>true</t:ViewPrivateItems></t:EffectiveRights><t:PermissionSet><t:CalendarPermissions>"
                + "<t:CalendarPermission><t:UserId><t:PrimarySmtpAddress>alice@example.test</t:PrimarySmtpAddress></t:UserId><t:IsFolderOwner>true</t:IsFolderOwner><t:IsFolderVisible>true</t:IsFolderVisible><t:ReadItems>FullDetails</t:ReadItems><t:CalendarPermissionLevel>Owner</t:CalendarPermissionLevel></t:CalendarPermission>"
                + "<t:CalendarPermission><t:UserId><t:DistinguishedUser>Default</t:DistinguishedUser></t:UserId><t:CanCreateItems>false</t:CanCreateItems><t:CanCreateSubFolders>false</t:CanCreateSubFolders><t:IsFolderOwner>false</t:IsFolderOwner><t:IsFolderVisible>false</t:IsFolderVisible><t:IsFolderContact>false</t:IsFolderContact><t:EditItems>None</t:EditItems><t:DeleteItems>None</t:DeleteItems><t:ReadItems>TimeOnly</t:ReadItems><t:CalendarPermissionLevel>FreeBusyTimeOnly</t:CalendarPermissionLevel></t:CalendarPermission>"
                + "<t:CalendarPermission><t:UserId><t:DistinguishedUser>Anonymous</t:DistinguishedUser></t:UserId><t:CanCreateItems>false</t:CanCreateItems><t:CanCreateSubFolders>false</t:CanCreateSubFolders><t:IsFolderOwner>false</t:IsFolderOwner><t:IsFolderVisible>false</t:IsFolderVisible><t:IsFolderContact>false</t:IsFolderContact><t:EditItems>None</t:EditItems><t:DeleteItems>None</t:DeleteItems><t:ReadItems>None</t:ReadItems><t:CalendarPermissionLevel>None</t:CalendarPermissionLevel></t:CalendarPermission>"
                + "</t:CalendarPermissions><t:UnknownEntries><t:UnknownEntry>preserve-me</t:UnknownEntry></t:UnknownEntries></t:PermissionSet></t:CalendarFolder></m:Folders>"
            : $"<m:Folders><t:Folder><t:FolderId Id='inbox-id' ChangeKey='{changeKey}'/><t:FolderClass>IPF.Note</t:FolderClass><t:PermissionSet><t:Permissions>"
                + "<t:Permission><t:UserId><t:PrimarySmtpAddress>bob@example.test</t:PrimarySmtpAddress></t:UserId><t:CanCreateItems>true</t:CanCreateItems><t:IsFolderVisible>true</t:IsFolderVisible><t:EditItems>All</t:EditItems><t:DeleteItems>All</t:DeleteItems><t:ReadItems>FullDetails</t:ReadItems><t:PermissionLevel>Editor</t:PermissionLevel></t:Permission>"
                + "<t:Permission><t:UserId><t:DistinguishedUser>Default</t:DistinguishedUser></t:UserId><t:PermissionLevel>None</t:PermissionLevel></t:Permission>"
                + "</t:Permissions></t:PermissionSet></t:Folder></m:Folders>")
        + $"</m:{operation}ResponseMessage></m:ResponseMessages></m:{operation}Response></s:Body></s:Envelope>";

    private static string SimpleResponse(string operation) =>
        $"<s:Envelope xmlns:s='{Soap}' xmlns:m='{Messages}' xmlns:t='{Types}'><s:Body>"
        + $"<m:{operation}Response><m:ResponseMessages><m:{operation}ResponseMessage ResponseClass='Success'><m:ResponseCode>NoError</m:ResponseCode></m:{operation}ResponseMessage></m:ResponseMessages></m:{operation}Response></s:Body></s:Envelope>";
}
