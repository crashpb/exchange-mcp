using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Xml.Linq;
using Company.ExchangeMcp.Exchange;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;

namespace Company.ExchangeMcp;

[McpServerResourceType]
public sealed class SignaturePreviewResources
{
    // Hosts cache UI by URI; change this version when preview HTML, JavaScript or CSS changes.
    public const string ResourceUri = "ui://exchange-mcp/signature-preview-v4.html";
    public const string RetainedResourceUri = "ui://exchange-mcp/signature-preview-v3.html";
    public const string PreviousResourceUri = "ui://exchange-mcp/signature-preview-v2.html";
    public const string LegacyResourceUri = "ui://exchange-mcp/signature-preview-v1.html";
    public const string ResourceMimeType = "text/html;profile=mcp-app";

    [McpServerResource(Name = "Exchange MCP signature preview", UriTemplate = ResourceUri, MimeType = ResourceMimeType)]
    public static ReadResourceResult Read() => ReadResource(ResourceUri);

    [McpServerResource(Name = "Exchange MCP signature preview v3 compatibility", UriTemplate = RetainedResourceUri, MimeType = ResourceMimeType)]
    public static ReadResourceResult ReadRetained() => ReadResource(RetainedResourceUri);

    [McpServerResource(Name = "Exchange MCP signature preview v2 compatibility", UriTemplate = PreviousResourceUri, MimeType = ResourceMimeType)]
    public static ReadResourceResult ReadPrevious() => ReadResource(PreviousResourceUri);

    [McpServerResource(Name = "Exchange MCP signature preview compatibility", UriTemplate = LegacyResourceUri, MimeType = ResourceMimeType)]
    public static ReadResourceResult ReadLegacy() => ReadResource(LegacyResourceUri);

    private static ReadResourceResult ReadResource(string uri) => new()
    {
        Contents =
        [
            new TextResourceContents
            {
                Uri = uri,
                MimeType = ResourceMimeType,
                Text = Html,
                Meta = new JsonObject
                {
                    ["openai/ui"] = new JsonObject
                    {
                        ["availableDisplayModes"] = new JsonArray("inline", "fullscreen"),
                        ["preferredDisplayMode"] = "inline"
                    },
                    ["ui"] = new JsonObject
                    {
                        ["prefersBorder"] = true,
                        ["csp"] = new JsonObject
                        {
                            ["connectDomains"] = new JsonArray(),
                            ["resourceDomains"] = new JsonArray()
                        }
                    }
                }
            }
        ]
    };

    public static JsonObject CreateMetadata(MailSignature profile, string? language, object defaults,
        IEnumerable<string> warnings)
    {
        ArgumentNullException.ThrowIfNull(profile);
        ArgumentNullException.ThrowIfNull(defaults);
        ArgumentNullException.ThrowIfNull(warnings);
        SignatureStore.Validate(new([profile], null, null));
        if (language is not null and not ("fa" or "en"))
            throw new ArgumentException("Language must be fa or en.", nameof(language));

        var defaultsNode = JsonSerializer.SerializeToNode(defaults) as JsonObject
            ?? throw new ArgumentException("Defaults must serialize as an object.", nameof(defaults));
        var imageMetadata = profile.Images.Select(image => new
        {
            name = image.Name,
            contentType = image.ContentType,
            sizeBytes = Convert.FromBase64String(image.ContentBase64).Length
        }).ToArray();

        return new JsonObject
        {
            ["signaturePreview"] = new JsonObject
            {
                ["version"] = 1,
                ["html"] = RenderHtml(profile),
                ["language"] = language ?? "en",
                ["signatureName"] = profile.Name,
                ["defaults"] = defaultsNode,
                ["images"] = JsonSerializer.SerializeToNode(imageMetadata) as JsonArray ?? new(),
                ["warnings"] = JsonSerializer.SerializeToNode(warnings.ToArray()) as JsonArray ?? new()
            }
        };
    }

    private static string RenderHtml(MailSignature profile)
    {
        if (profile.BodyType == "Text")
        {
            return WebUtility.HtmlEncode(profile.Body)
                .Replace("\r\n", "<br />", StringComparison.Ordinal)
                .Replace("\n", "<br />", StringComparison.Ordinal)
                .Replace("\r", "<br />", StringComparison.Ordinal);
        }

        var body = RichBody.Validate(profile.Body, "HTML");
        var root = XElement.Parse("<root>" + body + "</root>", LoadOptions.PreserveWhitespace);
        foreach (var image in root.Descendants().Where(element =>
                     element.Name.LocalName.Equals("img", StringComparison.OrdinalIgnoreCase)))
        {
            var source = image.Attributes().Single(attribute =>
                attribute.Name.LocalName.Equals("src", StringComparison.OrdinalIgnoreCase));
            var savedImage = profile.Images.Single(item =>
                string.Equals(item.ContentId, source.Value[4..], StringComparison.OrdinalIgnoreCase));
            source.Value = $"data:{savedImage.ContentType};base64,{savedImage.ContentBase64}";
        }

        return string.Concat(root.Nodes().Select(node => node.ToString(SaveOptions.DisableFormatting)));
    }

    private const string Html = """
        <!doctype html>
        <html lang="en" dir="ltr">
        <head>
          <meta charset="utf-8">
          <meta name="viewport" content="width=device-width, initial-scale=1">
          <meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:; connect-src 'none'; font-src 'none'; media-src 'none'; object-src 'none'; frame-src 'none'; child-src 'none'; base-uri 'none'; form-action 'none'">
          <title>Exchange MCP signature preview</title>
          <style>
            :root { color-scheme: light dark; font-family: system-ui, sans-serif; }
            body { margin:0; color:var(--color-text-primary, light-dark(#202124, #f1f3f4)); background-color:var(--color-background-primary, light-dark(#fff, #202124)); }
          </style>
        </head>
        <body>
          <div id="app"></div>
          <script>
            (() => {
              "use strict";
              const app = document.getElementById("app");
              const shadow = app.attachShadow({ mode: "closed" });
              shadow.innerHTML = `<style>
                :host { display:block; color:inherit; font:inherit; white-space:normal; }
                * { box-sizing:border-box; }
                main { padding:14px; }
                h1 { margin:0 0 4px; font-size:1.05rem; }
                p { margin:6px 0; line-height:1.5; }
                .muted { color:var(--color-text-secondary, light-dark(#606770, #bdc1c6)); font-size:.9rem; }
                .preview { display:block; box-sizing:border-box; width:100%; height:55vh; margin-top:12px; min-height:76px; border:1px solid var(--color-border-primary, light-dark(#d5d8dc, #5f6368)); border-radius:8px; background-color:#fff; color:#111; color-scheme:light; }
                .details { margin-top:10px; display:grid; grid-template-columns:minmax(120px,1fr) minmax(0,2fr); gap:4px 12px; font-size:.9rem; }
                .details dt { color:var(--color-text-secondary, light-dark(#606770, #bdc1c6)); }
                .details dd { margin:0; overflow-wrap:anywhere; }
                .warnings { margin-top:10px; padding-inline-start:1.3em; color:var(--color-text-warning, light-dark(#9a4d00, #fdd663)); }
                .error { padding:12px; border:1px solid var(--color-border-danger, light-dark(#c44, #f28b82)); border-radius:8px; }
                [hidden] { display:none !important; }
              </style>
              <main>
                <h1 id="title"></h1>
                <p id="name" class="muted"></p>
                <p id="note" class="muted"></p>
                <dl id="details" class="details" hidden></dl>
                <ul id="warnings" class="warnings" hidden></ul>
                <iframe id="preview" class="preview" title="Signature content" sandbox="" hidden></iframe>
                <p id="error" class="error" hidden></p>
              </main>`;

              const get = id => shadow.getElementById(id);
              const labels = {
                en: { title: "Review signature", note: "Preview only. Nothing has been saved. After reviewing, ask to save it, edit it, or request one test email addressed only to yourself before saving. The preview sends nothing; a test send needs your separate approval.", unavailable: "Preview data is unavailable. Ask Exchange MCP to prepare the signature preview again.", invalid: "The preview could not be displayed safely. Nothing has been saved.", name: "Signature", newMessages: "New messages", replies: "Replies", noDefault: "No default signature", images: "Inline images" },
                fa: { title: "بازبینی امضا", note: "این فقط پیش‌نمایش است و چیزی ذخیره نشده. پس از بررسی، می‌توانید درخواست ذخیره یا ویرایش بدهید یا بخواهید پیش از ذخیره یک ایمیل آزمایشی فقط به خودتان ارسال شود. پیش‌نمایش ایمیلی نمی‌فرستد؛ ارسال آزمایشی به تأیید جداگانهٔ شما نیاز دارد.", unavailable: "اطلاعات پیش‌نمایش در دسترس نیست. از Exchange MCP بخواهید پیش‌نمایش امضا را دوباره آماده کند.", invalid: "پیش‌نمایش به‌صورت امن نمایش داده نشد. چیزی ذخیره نشده است.", name: "امضا", newMessages: "پیام‌های جدید", replies: "پاسخ‌ها", noDefault: "امضای پیش‌فرض تعیین نشده", images: "تصاویر درون‌خطی" }
              };
              const allowedTags = new Set("a b blockquote br caption code col colgroup del div em h1 h2 h3 h4 h5 h6 hr i img ins li ol p pre s small span strong sub sup table tbody td tfoot th thead tr u ul".split(" "));
              const allowedAttributes = new Set("alt class colspan height id lang rowspan scope src style title width dir href".split(" "));
              const allowedStyles = new Set("background-color border border-bottom border-collapse border-color border-left border-radius border-right border-style border-top border-width color direction font-family font-size font-style font-weight line-height margin margin-bottom margin-left margin-right margin-top padding padding-bottom padding-left padding-right padding-top text-align text-decoration vertical-align white-space width height table-layout border-spacing".split(" "));
              const imagePattern = /^data:image\/(png|jpeg|gif);base64,[A-Za-z0-9+/]*={0,2}$/i;
              const htmlLimit = 4 * 1024 * 1024;

              function showError(message) {
                get("preview").removeAttribute("srcdoc");
                get("preview").hidden = true;
                get("details").hidden = true;
                get("warnings").hidden = true;
                get("error").textContent = message;
                get("error").hidden = false;
              }

              function validStyle(value) {
                if (value.length > 2048 || /[\\<>\u0000-\u001f\u007f]|url\s*\(|expression|javascript|vbscript|data:|@import/i.test(value)) return false;
                return value.split(";").every(item => {
                  if (!item.trim()) return true;
                  const colon = item.indexOf(":");
                  return colon > 0 && allowedStyles.has(item.slice(0, colon).trim().toLowerCase()) && !!item.slice(colon + 1).trim();
                });
              }

              function emailDocument(html, language) {
                return `<!doctype html><html lang="${language}"><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:; connect-src 'none'; font-src 'none'; media-src 'none'; object-src 'none'; frame-src 'none'; base-uri 'none'; form-action 'none'"><style>:root { color-scheme:light; } body { margin:0; padding:14px; background-color:#fff; color:#111; white-space:normal; }</style></head><body>${html}</body></html>`;
              }

              function validateNode(node) {
                if (node.nodeType === Node.TEXT_NODE) return true;
                if (node.nodeType !== Node.ELEMENT_NODE || node.namespaceURI !== "http://www.w3.org/1999/xhtml") return false;
                const tag = node.localName.toLowerCase();
                if (!allowedTags.has(tag)) return false;
                for (const attribute of [...node.attributes]) {
                  const name = attribute.name.toLowerCase();
                  const value = attribute.value;
                  if (!allowedAttributes.has(name) || value.length > (name === "src" ? 700000 : 4096) || /[\u0000-\u001f\u007f]/.test(value)) return false;
                  if (name === "dir" && !["rtl", "ltr", "auto"].includes(value.toLowerCase())) return false;
                  if (name === "style" && !validStyle(value)) return false;
                  if (name === "href") {
                    let url;
                    try { url = new URL(value); } catch { return false; }
                    if (!["http:", "https:", "mailto:"].includes(url.protocol)) return false;
                    node.removeAttribute("href");
                  }
                  if (name === "src" && (tag !== "img" || value.length > 700000 || !imagePattern.test(value))) return false;
                }
                if (tag === "img" && !node.hasAttribute("src")) return false;
                return [...node.childNodes].every(validateNode);
              }

              function render(data) {
                if (!data || data.version !== 1 || typeof data.html !== "string" || data.html.length > htmlLimit
                    || !["fa", "en"].includes(data.language) || typeof data.signatureName !== "string" || data.signatureName.length > 80
                    || !data.defaults || typeof data.defaults !== "object" || Array.isArray(data.defaults)
                    || !Array.isArray(data.warnings) || data.warnings.length > 20
                    || !data.warnings.every(item => typeof item === "string" && item.length <= 2000)
                    || !Array.isArray(data.images) || data.images.length > 8
                    || !data.images.every(image => image && typeof image.name === "string" && image.name.length <= 255
                      && ["image/png", "image/jpeg", "image/gif"].includes(image.contentType)
                      && Number.isInteger(image.sizeBytes) && image.sizeBytes > 0 && image.sizeBytes <= 512 * 1024)
                    || ![data.defaults.forNewMessages, data.defaults.forReplies].every(value => value === null || typeof value === "string" && value.length <= 80)) {
                  showError(labels[data?.language === "fa" ? "fa" : "en"].unavailable);
                  return;
                }
                const language = data.language;
                const text = labels[language];
                document.documentElement.lang = language;
                get("title").textContent = text.title;
                get("name").textContent = `${text.name}: ${data.signatureName}`;
                get("note").textContent = data.reviewState === "saved"
                  ? (language === "fa" ? "این امضای ذخیره‌شدهٔ فعلی شماست. بازکردن این نما امضا، تنظیمات یا پیش‌فرض‌ها را تغییر نمی‌دهد." : "This is your current saved signature. Opening this view does not change the signature, setup or defaults.")
                  : text.note;
                for (const id of ["title", "name", "note", "details", "warnings", "error"])
                  get(id).dir = language === "fa" ? "rtl" : "ltr";
                const details = get("details");
                details.replaceChildren();
                for (const [label, value] of [[text.newMessages, data.defaults.forNewMessages], [text.replies, data.defaults.forReplies], [text.images, String(data.images.length)]]) {
                  const term = document.createElement("dt");
                  term.textContent = label;
                  const description = document.createElement("dd");
                  description.textContent = typeof value === "string" && value ? value : text.noDefault;
                  details.append(term, description);
                }
                details.hidden = false;
                const warningList = get("warnings");
                warningList.replaceChildren();
                for (const warning of data.warnings) {
                  if (typeof warning !== "string") { showError(text.invalid); return; }
                  const item = document.createElement("li");
                  item.textContent = warning;
                  warningList.append(item);
                }
                warningList.hidden = data.warnings.length === 0;
                const template = document.createElement("template");
                template.innerHTML = data.html;
                if (![...template.content.childNodes].every(validateNode)) { showError(text.invalid); return; }
                const preview = get("preview");
                preview.title = text.title;
                preview.srcdoc = emailDocument(template.innerHTML, data.language);
                preview.hidden = false;
                get("error").hidden = true;
              }

              function privatePreview(result) {
                return result?._meta?.signaturePreview;
              }
              function showEmptyReview(result) {
                const data = result?._meta?.signatureReviewBootstrap || result?.signatureReviewBootstrap
                  || result?.call_tool_result?._meta?.signatureReviewBootstrap || result?.mcp_tool_result?._meta?.signatureReviewBootstrap;
                if (!data || data.available !== false) return false;
                showError(typeof data.message === "string" && data.message.length <= 1000 ? data.message : labels.en.unavailable);
                return true;
              }

              function applyHostContext(context) {
                const root = document.documentElement;
                if (["light", "dark"].includes(context?.theme)) {
                  root.dataset.theme = context.theme;
                  root.style.colorScheme = context.theme;
                }
                const variables = context?.styles?.variables;
                for (const name of ["--color-text-primary", "--color-text-secondary", "--color-background-primary", "--color-border-primary", "--color-text-warning", "--color-border-danger"])
                  if (typeof variables?.[name] === "string") root.style.setProperty(name, variables[name]);
              }

              function chatGptPreview() {
                const metadata = window.openai?.toolResponseMetadata;
                return metadata?.signaturePreview || privatePreview(metadata?.call_tool_result) || privatePreview(metadata?.mcp_tool_result)
                  || privatePreview(metadata);
              }

              window.addEventListener("message", event => {
                if (event.source !== window.parent) return;
                const message = event.data;
                if (!message || message.jsonrpc !== "2.0") return;
                if (message.id === 1) {
                  if (message.error) { showError(labels.en.unavailable); return; }
                  applyHostContext(message.result?.hostContext);
                  window.parent.postMessage({ jsonrpc: "2.0", method: "ui/notifications/initialized" }, "*");
                  const initial = chatGptPreview();
                  if (initial) render(initial);
                  else showEmptyReview(window.openai?.toolResponseMetadata);
                  return;
                }
                if (message.method === "ui/notifications/host-context-changed") {
                  applyHostContext(message.params);
                  return;
                }
                if (message.method === "ui/notifications/tool-result") {
                  const result = message.params;
                  if (showEmptyReview(result)) return;
                  const data = privatePreview(result) || chatGptPreview();
                  if (data) render(data);
                  else showError(labels.en.unavailable);
                }
              }, { passive: true });

              window.parent.postMessage({
                jsonrpc: "2.0", id: 1, method: "ui/initialize",
                params: {
                  protocolVersion: "2026-01-26",
                  appInfo: { name: "Exchange MCP signature preview", version: "1.0.0" },
                  appCapabilities: { availableDisplayModes: ["inline", "fullscreen"] }
                }
              }, "*");
              const initial = chatGptPreview();
              if (initial) render(initial);
              else if (!showEmptyReview(window.openai?.toolResponseMetadata)) showError(labels.en.unavailable);
            })();
          </script>
        </body>
        </html>
        """;
}
