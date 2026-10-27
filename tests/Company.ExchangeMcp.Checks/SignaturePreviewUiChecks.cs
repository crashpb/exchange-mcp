using System.Text.Json;
using System.Text.Json.Nodes;
using System.Xml.Linq;
using Company.ExchangeMcp;
using Company.ExchangeMcp.Security;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;
using ModelContextProtocol.Protocol;

internal sealed partial class Checks
{
    private async Task SignaturePreviewUiChecksAsync()
    {
        var image = new SignatureImage("logo.png", "image/png", "logo", PngBase64(8));
        const string inlineFormat = "margin-top:3px;margin-bottom:5px;font-family:Aptos;font-size:12pt";
        var profile = new MailSignature("Work", "<p class=\"MsoNormal\" dir=\"rtl\">سلام <img src=\"cid:logo\"/></p>"
            + $"<p class=\"MsoNormal\" style=\"{inlineFormat}\">Explicit formatting</p>", "HTML", [image]);
        var metadata = SignaturePreviewResources.CreateMetadata(profile, "fa",
            new { forNewMessages = "Work", forReplies = (string?)null }, []);
        var preview = metadata["signaturePreview"]?.AsObject()
            ?? throw new InvalidOperationException("Signature preview metadata was missing.");
        var signatureHtml = preview["html"]?.GetValue<string>() ?? string.Empty;
        var dataUri = $"data:image/png;base64,{image.ContentBase64}";
        Expect(signatureHtml.Contains(dataUri, StringComparison.Ordinal),
            "The preview did not embed the exact saved image bytes as a data URI.");
        var paragraphs = XElement.Parse("<root>" + signatureHtml + "</root>").Elements("p").ToArray();
        Expect(paragraphs.Length == 2 && paragraphs[0].Attribute("style") is null
            && paragraphs[1].Attribute("style")?.Value == inlineFormat,
            "The signature preview repaired missing canonical typography or changed explicit inline formatting.");
        var imageSummary = preview["images"]?.AsArray().SingleOrDefault()?.AsObject();
        Expect(imageSummary?["sizeBytes"]?.GetValue<int>() == 8,
            "The preview image summary did not report the stored image size.");

        var result = new CallToolResult
        {
            Content = [new TextContentBlock { Text = "Signature preview ready." }],
            Meta = metadata
        };
        var fallback = string.Join(" ", result.Content.OfType<TextContentBlock>().Select(block => block.Text));
        Expect(result.Meta?["signaturePreview"] is JsonObject && !fallback.Contains(image.ContentBase64, StringComparison.Ordinal),
            "The inline image bytes escaped private preview metadata into model-visible text.");

        var resource = SignaturePreviewResources.Read().Contents.OfType<TextResourceContents>().Single();
        var html = resource.Text;
        Expect(resource.Uri == SignaturePreviewResources.ResourceUri
            && resource.MimeType == SignaturePreviewResources.ResourceMimeType,
            "The signature UI resource URI or MCP Apps MIME type changed.");
        var routes = new[]
        {
            (SignaturePreviewResources.Read(), SignaturePreviewResources.ResourceUri, html),
            (SignaturePreviewResources.ReadRetained(), SignaturePreviewResources.RetainedResourceUri, html),
            (SignaturePreviewResources.ReadPrevious(), SignaturePreviewResources.PreviousResourceUri, html),
            (SignaturePreviewResources.ReadLegacy(), SignaturePreviewResources.LegacyResourceUri, html),
            (MailPreviewResources.Read(), MailPreviewResources.ResourceUri, MailPreviewResources.Read().Contents.OfType<TextResourceContents>().Single().Text),
            (MailPreviewResources.ReadPrior(), MailPreviewResources.PriorResourceUri, MailPreviewResources.Read().Contents.OfType<TextResourceContents>().Single().Text),
            (MailPreviewResources.ReadCached(), MailPreviewResources.CachedResourceUri, MailPreviewResources.Read().Contents.OfType<TextResourceContents>().Single().Text),
            (MailPreviewResources.ReadRetained(), MailPreviewResources.RetainedResourceUri, MailPreviewResources.Read().Contents.OfType<TextResourceContents>().Single().Text),
            (MailPreviewResources.ReadPrevious(), MailPreviewResources.PreviousResourceUri, MailPreviewResources.Read().Contents.OfType<TextResourceContents>().Single().Text),
            (MailPreviewResources.ReadLegacy(), MailPreviewResources.LegacyResourceUri, MailPreviewResources.Read().Contents.OfType<TextResourceContents>().Single().Text)
        };
        foreach (var (read, uri, expectedHtml) in routes)
        {
            var routed = read.Contents.OfType<TextResourceContents>().Single();
            Expect(routed.Uri == uri && routed.Text == expectedHtml
                && routed.MimeType == SignaturePreviewResources.ResourceMimeType,
                "A current or compatibility preview URI returned the wrong URI, document or MCP Apps MIME type.");
        }
        foreach (var card in new[] { html, MailPreviewResources.Read().Contents.OfType<TextResourceContents>().Single().Text })
            Expect(!card.Contains("MsoNormal", StringComparison.Ordinal)
                && card.Contains("background-color:#fff; color:#111;", StringComparison.Ordinal),
                "A preview document supplied missing source typography instead of a neutral canvas.");
        var csp = resource.Meta?["ui"]?["csp"]?.AsObject()
            ?? throw new InvalidOperationException("The UI resource omitted its content-security policy metadata.");
        Expect(csp["connectDomains"]?.AsArray().Count == 0 && csp["resourceDomains"]?.AsArray().Count == 0,
            "The UI resource allowed network connections or remote resources.");

        Expect(html.Contains("بازبینی امضا", StringComparison.Ordinal)
            && html.Contains("Review signature", StringComparison.Ordinal)
            && html.Contains("یک ایمیل آزمایشی فقط به خودتان", StringComparison.Ordinal)
            && html.Contains("ارسال آزمایشی به تأیید جداگانهٔ شما نیاز دارد", StringComparison.Ordinal),
            "The Persian preview did not explain the self-only test-send option and separate approval.");
        Expect(Count(html, "attachShadow({ mode: \"closed\" })") == 1
            && html.Contains("sandbox=\"\"", StringComparison.Ordinal)
            && html.Contains("preview.srcdoc = emailDocument(template.innerHTML, data.language)", StringComparison.Ordinal)
            && !html.Contains("allow-scripts", StringComparison.Ordinal)
            && !html.Contains("allow-same-origin", StringComparison.Ordinal),
            "The signature document was not isolated from widget styles, scripts and origin privileges.");
        Expect(html.Contains("name === \"src\" ? 700000 : 4096", StringComparison.Ordinal)
            && html.Contains("metadata?.signaturePreview", StringComparison.Ordinal)
            && html.Contains("protocolVersion: \"2026-01-26\"", StringComparison.Ordinal),
            "The preview rejected normal image payloads or omitted the standard/direct ChatGPT metadata bridge.");

        var previewRule = html.Split(".preview {", 2, StringSplitOptions.None)[1].Split('}', 2)[0];
        Expect(!previewRule.Contains("img", StringComparison.OrdinalIgnoreCase)
            && !previewRule.Contains("table", StringComparison.OrdinalIgnoreCase)
            && !previewRule.Contains("overflow-wrap", StringComparison.OrdinalIgnoreCase)
            && !html.Contains(".preview img", StringComparison.Ordinal)
            && !html.Contains(".preview table", StringComparison.Ordinal)
            && !html.Contains(".preview a", StringComparison.Ordinal),
            "Preview-shell CSS could override the signature's source layout.");
        Expect(!html.Contains("<script src=", StringComparison.OrdinalIgnoreCase)
            && !html.Contains("<link ", StringComparison.OrdinalIgnoreCase)
            && !html.Contains("fetch(", StringComparison.OrdinalIgnoreCase)
            && !html.Contains("XMLHttpRequest", StringComparison.Ordinal)
            && !html.Contains("WebSocket", StringComparison.Ordinal)
            && !html.Contains("EventSource", StringComparison.Ordinal)
            && !html.Contains("tools/call", StringComparison.OrdinalIgnoreCase)
            && !html.Contains("mail_send_draft", StringComparison.OrdinalIgnoreCase)
            && !html.Contains("<button", StringComparison.OrdinalIgnoreCase),
            "The static preview introduced network access, a tool call or a send control.");
        var classicBindings = new Dictionary<string, string>(StringComparer.Ordinal);
        var classicSchemas = new Dictionary<string, string>(StringComparer.Ordinal);
        var classicPreviewHtml = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var protocol in new[] { ProtocolVersion, JulyProtocolVersion })
        {
            var exchange = new SignatureCaptureFlowHandler(Convert.FromBase64String(image.ContentBase64));
            var seeded = await new SignatureStore().UpdateAsync(NewEwsClient(exchange), "alice@example.test", "new",
                _ => new([], null, null, new("en", "pending")), CancellationToken.None);
            await using var host = await StartHostAsync(exchange, writesEnabled: true, sendEnabled: true,
                configure: builder => builder.Services.AddSingleton<IDataProtectionProvider>(new EphemeralDataProtectionProvider()));
            var token = Token("user-a", "mail.read mail.write mail.manage mail.send", sessionId: "preview-ui-session");
            var resultTypes = new List<string>();
            if (protocol == ProtocolVersion)
                await InitializeAsync(host.Client, token);
            else
            {
                var discoveryResponse = await ToolRequestAsync(host.Client, token, "server/discover", new { }, protocol);
                using var discoveryDocument = ParseJson(discoveryResponse.Body);
                var discovered = discoveryDocument.RootElement.GetProperty("result");
                Expect(discoveryResponse.StatusCode == System.Net.HttpStatusCode.OK
                    && discovered.GetProperty("capabilities").TryGetProperty("resources", out _)
                    && discovered.GetProperty("capabilities").TryGetProperty("tools", out _)
                    && !discovered.TryGetProperty("tools", out _),
                    "Modern discovery omitted resource/tool support or bypassed tools/list with an inline catalog.");
                var type = discovered.TryGetProperty("resultType", out var discoveryType) ? discoveryType.GetString() : "absent";
                Expect(type is "absent" or "complete", "Modern discovery returned an alternate result instead of capabilities.");
                resultTypes.Add("discover=" + type);
            }
            var listedResponse = await ToolRequestAsync(host.Client, token, "resources/list", new { }, protocol);
            using var listedDocument = ParseJson(listedResponse.Body);
            var listed = listedDocument.RootElement.GetProperty("result");
            var listedResources = listed.GetProperty("resources");
            Expect(listedResponse.StatusCode == System.Net.HttpStatusCode.OK && listedResources.GetArrayLength() == routes.Length
                && routes.All(route => listedResources.EnumerateArray().Any(item => item.GetProperty("uri").GetString() == route.Item2
                    && item.GetProperty("mimeType").GetString() == SignaturePreviewResources.ResourceMimeType)),
                "Resource discovery omitted a current/compatibility preview URI or its MCP Apps MIME type.");
            var listType = listed.TryGetProperty("resultType", out var resourceListType) ? resourceListType.GetString() : "absent";
            Expect(listType is "absent" or "complete", "Resource listing returned an alternate result.");
            resultTypes.Add("resources/list=" + listType);
            foreach (var (_, uri, expectedHtml) in routes)
            {
                if (protocol == JulyProtocolVersion && uri == SignaturePreviewResources.ResourceUri)
                {
                    var missingName = await ToolRequestAsync(host.Client, token, "resources/read", new { uri }, protocol);
                    using var missingNameDocument = ParseJson(missingName.Body);
                    var error = missingNameDocument.RootElement.GetProperty("error");
                    Expect(missingName.StatusCode == System.Net.HttpStatusCode.BadRequest
                        && error.GetProperty("code").GetInt32() == -32020
                        && error.GetProperty("message").GetString() == "Missing required Mcp-Name header.",
                        "Modern resource transport did not enforce its required URI routing header.");
                    Console.WriteLine("Preview wire 2026-07-28: missing resources/read Mcp-Name => HTTP400 / -32020; URI header retry follows.");
                }
                // The shared helper currently supplies Mcp-Name only for tools/call.
                if (protocol == JulyProtocolVersion) host.Client.DefaultRequestHeaders.Add("Mcp-Name", uri);
                var response = await ToolRequestAsync(host.Client, token, "resources/read", new { uri }, protocol);
                host.Client.DefaultRequestHeaders.Remove("Mcp-Name");
                using var document = ParseJson(response.Body);
                Expect(response.StatusCode == System.Net.HttpStatusCode.OK && document.RootElement.TryGetProperty("result", out _),
                    $"Preview resource read failed for {protocol} {uri}: HTTP {(int)response.StatusCode}; {response.Body}");
                var read = document.RootElement.GetProperty("result");
                var contents = read.GetProperty("contents");
                var contentCsp = contents[0].GetProperty("_meta").GetProperty("ui").GetProperty("csp");
                var contentDisplay = contents[0].GetProperty("_meta").GetProperty("openai/ui");
                Expect(contentDisplay.GetProperty("preferredDisplayMode").GetString() == "inline"
                    && contentDisplay.GetProperty("availableDisplayModes").EnumerateArray()
                        .Select(mode => mode.GetString()).SequenceEqual(new[] { "inline", "fullscreen" }),
                    "An actual preview resource omitted its inline default or inline/fullscreen display mode declaration.");
                Expect(response.StatusCode == System.Net.HttpStatusCode.OK && contents.GetArrayLength() == 1
                    && contents[0].GetProperty("uri").GetString() == uri
                    && contents[0].GetProperty("mimeType").GetString() == SignaturePreviewResources.ResourceMimeType
                    && contents[0].GetProperty("text").GetString() == expectedHtml
                    && contentCsp.GetProperty("connectDomains").GetArrayLength() == 0
                    && contentCsp.GetProperty("resourceDomains").GetArrayLength() == 0,
                    "An MCP preview resource route changed its URI, MIME type, private UI metadata or current HTML across protocols.");
                var type = read.TryGetProperty("resultType", out var readType) ? readType.GetString() : "absent";
                Expect(type is "absent" or "complete", "Resource reading returned an alternate result.");
                resultTypes.Add("resources/read=" + type);
            }
            var toolsResponse = await ToolRequestAsync(host.Client, token, "tools/list", new { }, protocol);
            using var toolsDocument = ParseJson(toolsResponse.Body);
            var toolList = toolsDocument.RootElement.GetProperty("result");
            var tools = toolList.GetProperty("tools");
            var previewTools = tools.EnumerateArray().Where(tool => tool.GetProperty("name").GetString()
                is "mail_capture_signature" or "mail_preview_signature" or "mail_preview_draft").Where(tool => tool.TryGetProperty("_meta", out var meta)
                && meta.TryGetProperty("ui", out var ui) && ui.TryGetProperty("resourceUri", out _)).ToArray();
            Expect(toolsResponse.StatusCode == System.Net.HttpStatusCode.OK && previewTools.Length == 3,
                "Fresh MCP discovery omitted a signature or mail preview resource selector.");
            var outputSchemas = new Dictionary<string, JsonElement>(StringComparer.Ordinal);
            foreach (var tool in previewTools)
            {
                var name = tool.GetProperty("name").GetString()!;
                var meta = tool.GetProperty("_meta");
                var uri = meta.GetProperty("ui").GetProperty("resourceUri").GetString();
                var expectedUri = name == "mail_preview_draft" ? MailPreviewResources.ResourceUri : SignaturePreviewResources.ResourceUri;
                Expect(name is "mail_capture_signature" or "mail_preview_signature" or "mail_preview_draft"
                    && uri == expectedUri && meta.GetProperty("openai/outputTemplate").GetString() == uri,
                    "Fresh MCP tool metadata selected a stale preview resource or mismatched OpenAI template.");
                Expect(meta.TryGetProperty("openai/ui", out var display)
                    && display.GetProperty("preferredModelDisplayMode").GetString() == "inline",
                    "A preview producer lost its explicit inline display preference on the actual MCP wire.");
                Expect(tool.TryGetProperty("outputSchema", out var schema)
                    && schema.ValueKind == JsonValueKind.Object
                    && schema.GetRawText().Contains("\"status\"", StringComparison.Ordinal)
                    && !new[] { "structuredContent", "_meta", "contentBase64", "signaturePreview", "emailPreview" }
                        .Any(property => schema.GetRawText().Contains("\"" + property + "\"", StringComparison.OrdinalIgnoreCase)),
                    "A preview descriptor omitted its public response schema or advertised the transport/private payload instead.");
                outputSchemas.Add(name, schema);
                if (protocol == ProtocolVersion) classicSchemas.Add(name, schema.GetRawText());
                else Expect(JsonNode.DeepEquals(JsonNode.Parse(classicSchemas[name]), JsonNode.Parse(schema.GetRawText())),
                    "Modern tools/list changed a preview output schema relative to classic discovery.");
                if (protocol == ProtocolVersion) classicBindings.Add(name, meta.ToString());
                else Expect(JsonNode.DeepEquals(JsonNode.Parse(classicBindings[name]), JsonNode.Parse(meta.ToString())),
                    "Modern tools/list changed a preview tool's UI metadata relative to classic discovery.");
            }
            var toolsType = toolList.TryGetProperty("resultType", out var listedToolsType) ? listedToolsType.GetString() : "absent";
            Expect(toolsType is "absent" or "complete", "Tool listing returned an alternate result.");
            resultTypes.Add("tools/list=" + toolsType);

            var identity = new MailboxIdentity("user-a", "alice@example.test", "chatgpt-test", "preview-ui-session");
            var sourceHandle = host.App.Services.GetRequiredService<MailboxHandles>().Issue(identity, "message",
                exchange.SourceId, exchange.SourceChangeKey);
            var captured = await ToolRequestAsync(host.Client, token, "tools/call", new
            {
                name = "mail_capture_signature",
                arguments = new { messageHandle = sourceHandle, name = "Captured" }
            }, protocol);
            var pasted = await ToolRequestAsync(host.Client, token, "tools/call", new
            {
                name = "mail_preview_signature",
                arguments = new { revision = seeded.Revision, name = profile.Name, body = profile.Body, bodyType = "HTML", images = profile.Images }
            }, protocol);
            var mailExchange = new MailPreviewEwsHandler(Convert.FromBase64String(image.ContentBase64));
            await using var mailHost = await StartHostAsync(mailExchange, writesEnabled: true, sendEnabled: true,
                configure: builder => builder.Services.AddSingleton<IDataProtectionProvider>(new EphemeralDataProtectionProvider()));
            if (protocol == ProtocolVersion) await InitializeAsync(mailHost.Client, token);
            var draftHandle = mailHost.App.Services.GetRequiredService<MailboxHandles>().Issue(identity, "message", "draft-1", "draft-current");
            var draftPreview = await ToolRequestAsync(mailHost.Client, token, "tools/call", new
            {
                name = "mail_preview_draft",
                arguments = new { draftHandle }
            }, protocol);
            foreach (var (name, response, metadataKey) in new[]
            {
                ("mail_capture_signature", captured, "signaturePreview"),
                ("mail_preview_signature", pasted, "signaturePreview"),
                ("mail_preview_draft", draftPreview, "emailPreview")
            })
            {
                using var document = ParseJson(response.Body);
                var callResult = document.RootElement.GetProperty("result");
                Expect(response.StatusCode == System.Net.HttpStatusCode.OK && !IsToolError(response.Body)
                    && callResult.GetProperty("_meta").TryGetProperty(metadataKey, out _),
                    "A preview tool omitted its private UI payload on an actual MCP invocation.");
                AssertPreviewOutputSchema(outputSchemas[name], callResult.GetProperty("structuredContent"), name);
                var privateHtml = callResult.GetProperty("_meta").GetProperty(metadataKey).GetProperty("html").GetString()!;
                Expect(privateHtml.Contains(dataUri, StringComparison.Ordinal)
                    && !callResult.GetProperty("content").ToString().Contains(image.ContentBase64, StringComparison.Ordinal)
                    && !callResult.GetProperty("structuredContent").ToString().Contains(image.ContentBase64, StringComparison.Ordinal),
                    "A preview lost its exact inline image or exposed private image bytes in model-facing content.");
                if (name == "mail_preview_signature")
                {
                    var renderedParagraphs = XElement.Parse("<root>" + privateHtml + "</root>").Descendants("p").ToArray();
                    Expect(renderedParagraphs.Length == 2 && renderedParagraphs[0].Attribute("style") is null
                        && renderedParagraphs[1].Attribute("style")?.Value == inlineFormat,
                        "An MCP preview invocation supplied missing typography or changed canonical inline formatting.");
                }
                if (protocol == ProtocolVersion) classicPreviewHtml.Add(name, privateHtml);
                else Expect(classicPreviewHtml[name] == privateHtml, "Modern tools/call changed the private rendered preview HTML.");
                var type = callResult.TryGetProperty("resultType", out var callType) ? callType.GetString() : "absent";
                Expect(type is "absent" or "complete", "A preview invocation returned an alternate result.");
                resultTypes.Add(name + "=" + type);
            }
            var selectionExchange = new SignatureCaptureFlowHandler
            {
                SourceHtml = "<html><body><table><tr><td>First signature</td></tr></table>"
                    + "<table><tr><td>Second signature</td></tr></table></body></html>"
            };
            await using var selectionHost = await StartHostAsync(selectionExchange, writesEnabled: true, sendEnabled: false,
                configure: builder => builder.Services.AddSingleton<IDataProtectionProvider>(new EphemeralDataProtectionProvider()));
            if (protocol == ProtocolVersion) await InitializeAsync(selectionHost.Client, token);
            var selectionHandle = selectionHost.App.Services.GetRequiredService<MailboxHandles>().Issue(identity,
                "message", selectionExchange.SourceId, selectionExchange.SourceChangeKey);
            var selectionResponse = await ToolRequestAsync(selectionHost.Client, token, "tools/call", new
            {
                name = "mail_capture_signature",
                arguments = new { messageHandle = selectionHandle, name = "Selection" }
            }, protocol);
            using var selectionDocument = ParseJson(selectionResponse.Body);
            var selectionResult = selectionDocument.RootElement.GetProperty("result");
            var selectionData = selectionResult.GetProperty("structuredContent");
            Expect(!IsToolError(selectionResponse.Body)
                && selectionData.GetProperty("status").GetString() == "signature_part_selection_required"
                && selectionData.GetProperty("parts").GetArrayLength() == 2
                && (!selectionResult.TryGetProperty("_meta", out var selectionMeta)
                    || !selectionMeta.TryGetProperty("signaturePreview", out _)),
                "The ambiguous source did not produce a selection-only response without a private preview.");
            AssertPreviewOutputSchema(outputSchemas["mail_capture_signature"], selectionData, "capture selection");

            var fallbackExchange = new MailPreviewEwsHandler(Convert.FromBase64String(image.ContentBase64))
            {
                HtmlBody = "<html><body><p>Safe fallback</p><script>untrusted()</script></body></html>"
            };
            await using var fallbackHost = await StartHostAsync(fallbackExchange, writesEnabled: true, sendEnabled: false,
                configure: builder => builder.Services.AddSingleton<IDataProtectionProvider>(new EphemeralDataProtectionProvider()));
            if (protocol == ProtocolVersion) await InitializeAsync(fallbackHost.Client, token);
            var fallbackHandle = fallbackHost.App.Services.GetRequiredService<MailboxHandles>().Issue(identity,
                "message", "draft-1", "draft-current");
            var fallbackResponse = await ToolRequestAsync(fallbackHost.Client, token, "tools/call", new
            {
                name = "mail_preview_draft",
                arguments = new { draftHandle = fallbackHandle }
            }, protocol);
            using var fallbackDocument = ParseJson(fallbackResponse.Body);
            var fallbackResult = fallbackDocument.RootElement.GetProperty("result");
            var fallbackData = fallbackResult.GetProperty("structuredContent");
            Expect(!IsToolError(fallbackResponse.Body) && !fallbackData.GetProperty("editable").GetBoolean()
                && fallbackData.GetProperty("warnings").GetArrayLength() > 0
                && fallbackResult.GetProperty("_meta").TryGetProperty("emailPreview", out _)
                && fallbackExchange.Operations.SequenceEqual(["GetItem", "GetItem"]),
                "The unsafe draft did not return a private, read-only fallback without writes or attachment fetches.");
            AssertPreviewOutputSchema(outputSchemas["mail_preview_draft"], fallbackData, "draft fallback");
            Expect(selectionExchange.ConfigurationWrites == 0 && selectionExchange.DraftCreates == 0
                && selectionExchange.SendItemCalls == 0,
                "The capture selection fixture saved a signature, created a draft or sent mail.");
            Expect(exchange.ConfigurationWrites == 1 && exchange.DraftCreates == 0 && exchange.SendItemCalls == 0,
                "Protocol preview comparison saved a signature, created a draft or sent mail after fixture seeding.");
            Console.WriteLine($"Preview wire {protocol}: resources={routes.Length}; UI bindings=3; private previews=3; output schemas=3; validated success variants=5; {string.Join(", ", resultTypes.Distinct())}.");
        }
    }

    private static void AssertPreviewOutputSchema(JsonElement schema, JsonElement data, string label)
    {
        Expect(data.ValueKind == JsonValueKind.Object && PreviewSchemaMatches(schema, data, schema),
            $"The actual {label} structuredContent did not match its advertised output schema.");
        Expect(!PreviewSchemaMatches(schema, JsonSerializer.SerializeToElement(42), schema),
            $"The {label} output schema accepted a scalar instead of a public response object.");
        var wrongStatus = JsonNode.Parse(data.GetRawText())!.AsObject();
        wrongStatus["status"] = 42;
        Expect(!PreviewSchemaMatches(schema, JsonSerializer.SerializeToElement(wrongStatus), schema),
            $"The {label} output schema accepted a numeric status instead of the public string contract.");
        wrongStatus.Remove("status");
        Expect(!PreviewSchemaMatches(schema, JsonSerializer.SerializeToElement(wrongStatus), schema),
            $"The {label} output schema did not require its public status.");
        var wrongNested = JsonNode.Parse(data.GetRawText())!.AsObject();
        if (wrongNested["parts"] is JsonArray parts) parts[0]!["Id"] = 42;
        else if (wrongNested["signature"] is JsonObject signature) signature["Name"] = 42;
        else if (wrongNested["attachments"] is JsonArray attachments) attachments[0]!["sizeBytes"] = "invalid";
        else wrongNested["images"]![0]!["sizeBytes"] = "invalid";
        Expect(!PreviewSchemaMatches(schema, JsonSerializer.SerializeToElement(wrongNested), schema),
            $"The {label} output schema accepted a mistyped nested public field.");
    }

    // No JSON Schema validator is installed; check every assertion keyword emitted by the SDK and fail closed on new ones.
    private static bool PreviewSchemaMatches(JsonElement schema, JsonElement value, JsonElement root)
    {
        if (schema.ValueKind is JsonValueKind.True or JsonValueKind.False) return schema.GetBoolean();
        var supported = new[] { "$schema", "$defs", "$ref", "description",
            "type", "properties", "required", "additionalProperties", "items", "anyOf", "format" };
        Expect(schema.ValueKind == JsonValueKind.Object && schema.EnumerateObject().All(property => supported.Contains(property.Name)),
            "The SDK emitted a schema keyword that the bounded preview contract checker does not validate.");
        if (schema.TryGetProperty("$ref", out var reference))
        {
            var path = reference.GetString()!;
            Expect(path.StartsWith("#/", StringComparison.Ordinal), "A preview output schema used a nonlocal reference.");
            var target = root;
            foreach (var segment in path[2..].Split('/'))
                target = target.GetProperty(segment.Replace("~1", "/", StringComparison.Ordinal).Replace("~0", "~", StringComparison.Ordinal));
            if (!PreviewSchemaMatches(target, value, root)) return false;
        }
        if (schema.TryGetProperty("anyOf", out var alternatives)
            && !alternatives.EnumerateArray().Any(alternative => PreviewSchemaMatches(alternative, value, root))) return false;
        if (schema.TryGetProperty("format", out var format))
        {
            Expect(format.GetString() == "date-time", "The SDK emitted an unsupported string format.");
            if (value.ValueKind == JsonValueKind.String
                && !DateTimeOffset.TryParse(value.GetString(), System.Globalization.CultureInfo.InvariantCulture,
                    System.Globalization.DateTimeStyles.None, out _)) return false;
        }
        if (schema.TryGetProperty("type", out var type))
        {
            bool MatchesType(string? name) => name switch
            {
                "object" => value.ValueKind == JsonValueKind.Object,
                "array" => value.ValueKind == JsonValueKind.Array,
                "string" => value.ValueKind == JsonValueKind.String,
                "integer" => value.ValueKind == JsonValueKind.Number && value.TryGetInt64(out _),
                "boolean" => value.ValueKind is JsonValueKind.True or JsonValueKind.False,
                "null" => value.ValueKind == JsonValueKind.Null,
                _ => throw new InvalidOperationException("Unknown preview schema type.")
            };
            if (!(type.ValueKind == JsonValueKind.Array ? type.EnumerateArray().Any(item => MatchesType(item.GetString())) : MatchesType(type.GetString())))
                return false;
        }
        if (value.ValueKind == JsonValueKind.Array && schema.TryGetProperty("items", out var items)
            && !value.EnumerateArray().All(item => PreviewSchemaMatches(items, item, root))) return false;
        if (value.ValueKind == JsonValueKind.Object)
        {
            if (schema.TryGetProperty("required", out var required)
                && required.EnumerateArray().Any(property => !value.TryGetProperty(property.GetString()!, out _))) return false;
            var hasProperties = schema.TryGetProperty("properties", out var properties);
            foreach (var property in value.EnumerateObject())
            {
                if (hasProperties && properties.TryGetProperty(property.Name, out var propertySchema))
                {
                    if (!PreviewSchemaMatches(propertySchema, property.Value, root)) return false;
                }
                else if (schema.TryGetProperty("additionalProperties", out var additional)
                    && !PreviewSchemaMatches(additional, property.Value, root)) return false;
            }
        }
        return true;
    }

    private static int Count(string value, string fragment) =>
        value.Split(fragment, StringSplitOptions.None).Length - 1;
}
