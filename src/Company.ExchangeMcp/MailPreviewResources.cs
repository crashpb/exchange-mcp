using System.Text.Json;
using System.Text.Json.Nodes;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;

namespace Company.ExchangeMcp;

[McpServerResourceType]
public sealed class MailPreviewResources
{
    // Hosts cache UI by URI; change this version when preview HTML, JavaScript or CSS changes.
    public const string ResourceUri = "ui://exchange-mcp/email-preview-v6.html";
    public const string PriorResourceUri = "ui://exchange-mcp/email-preview-v5.html";
    public const string CachedResourceUri = "ui://exchange-mcp/email-preview-v4.html";
    public const string RetainedResourceUri = "ui://exchange-mcp/email-preview-v3.html";
    public const string PreviousResourceUri = "ui://exchange-mcp/email-preview-v2.html";
    public const string LegacyResourceUri = "ui://exchange-mcp/email-preview-v1.html";
    public const string ResourceMimeType = "text/html;profile=mcp-app";

    [McpServerResource(Name = "Exchange MCP email preview", UriTemplate = ResourceUri, MimeType = ResourceMimeType)]
    public static ReadResourceResult Read() => ReadResource(ResourceUri);

    [McpServerResource(Name = "Exchange MCP email preview v5 compatibility", UriTemplate = PriorResourceUri, MimeType = ResourceMimeType)]
    public static ReadResourceResult ReadPrior() => ReadResource(PriorResourceUri);

    [McpServerResource(Name = "Exchange MCP email preview v4 compatibility", UriTemplate = CachedResourceUri, MimeType = ResourceMimeType)]
    public static ReadResourceResult ReadCached() => ReadResource(CachedResourceUri);

    [McpServerResource(Name = "Exchange MCP email preview v3 compatibility", UriTemplate = RetainedResourceUri, MimeType = ResourceMimeType)]
    public static ReadResourceResult ReadRetained() => ReadResource(RetainedResourceUri);

    [McpServerResource(Name = "Exchange MCP email preview v2 compatibility", UriTemplate = PreviousResourceUri, MimeType = ResourceMimeType)]
    public static ReadResourceResult ReadPrevious() => ReadResource(PreviousResourceUri);

    [McpServerResource(Name = "Exchange MCP email preview compatibility", UriTemplate = LegacyResourceUri, MimeType = ResourceMimeType)]
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

    public static JsonObject CreateMetadata(string draftHandle, string? mailboxHandle, string? from,
        IReadOnlyList<string> to, IReadOnlyList<string> cc, IReadOnlyList<string> bcc, string subject,
        string bodyType, string body, string html, string bodyText, object attachments,
        IReadOnlyList<string> warnings, string language, bool editable, bool sendable) => new()
        {
            ["emailPreview"] = JsonSerializer.SerializeToNode(new
            {
                version = 1,
                language,
                draftHandle,
                mailboxHandle,
                from,
                to,
                cc,
                bcc,
                subject,
                bodyType,
                body,
                html,
                bodyText,
                attachments,
                warnings,
                editable,
                sendable
            })
        };

    private const string Html = """
        <!doctype html>
        <html lang="en" dir="ltr">
        <head>
          <meta charset="utf-8">
          <meta name="viewport" content="width=device-width, initial-scale=1">
          <meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:; connect-src 'none'; font-src 'none'; media-src 'none'; object-src 'none'; frame-src 'none'; child-src 'none'; base-uri 'none'; form-action 'none'">
          <title>Exchange MCP draft review</title>
          <style>
            :root { color-scheme: light dark; }
            body { color:var(--color-text-primary, light-dark(#202124, #f1f3f4)); background-color:var(--color-background-primary, light-dark(#fff, #202124)); }
          </style>
        </head>
        <body>
          <div id="app"></div>
          <script>
            (() => {
              const host = document.getElementById("app");
              const shell = host.attachShadow({ mode: "closed" });
              shell.innerHTML = `
                <style>
                  :host { color:inherit; font:14px/1.45 system-ui, sans-serif; white-space:normal; }
                  main { display:grid; gap:12px; }
                  h1 { font-size:17px; margin:0; }
                  p { margin:0; }
                  .muted { color:var(--color-text-secondary, light-dark(#606770, #bdc1c6)); }
                  dl { display:grid; grid-template-columns:minmax(64px,auto) 1fr; gap:4px 10px; margin:0; }
                  dt { color:var(--color-text-secondary, light-dark(#606770, #bdc1c6)); }
                  dd { margin:0; overflow-wrap:anywhere; white-space:pre-wrap; }
                  .body { display:block; box-sizing:border-box; width:100%; height:55vh; border:1px solid var(--color-border-primary, light-dark(#d5d8dc, #5f6368)); border-radius:8px; background-color:#fff; color:#111; color-scheme:light; }
                  .attachments, .warnings { margin:0; padding-inline-start:1.4em; }
                  .actions { display:flex; flex-wrap:wrap; gap:8px; }
                  button { border:1px solid var(--color-border-primary, light-dark(#858a91, #9aa0a6)); border-radius:6px; background-color:var(--color-background-secondary, light-dark(#fff, #303134)); color:inherit; padding:7px 12px; cursor:pointer; }
                  button.primary { background:#1558d6; border-color:#1558d6; color:#fff; }
                  button:disabled { opacity:.55; cursor:wait; }
                  .editor { display:grid; gap:8px; max-height:55vh; overflow:auto; }
                  label { display:grid; gap:3px; font-weight:600; }
                  input, textarea { box-sizing:border-box; width:100%; border:1px solid var(--color-border-primary, light-dark(#aab0b7, #9aa0a6)); border-radius:5px; padding:7px; font:13px/1.4 ui-monospace, monospace; background-color:var(--color-background-secondary, light-dark(#fff, #303134)); color:inherit; }
                  textarea { min-height:48px; resize:vertical; }
                  #body { min-height:160px; height:24vh; }
                  .status { min-height:1.4em; }
                  [hidden] { display:none !important; }
                </style>
                <main>
                  <h1 id="title"></h1>
                  <p id="note" class="muted"></p>
                  <dl id="fields"></dl>
                  <ul id="attachments" class="attachments" hidden></ul>
                  <ul id="warnings" class="warnings" hidden></ul>
                  <iframe id="bodyHost" class="body" title="Email content" sandbox=""></iframe>
                  <section id="editor" class="editor" hidden>
                    <label><span id="subjectLabel"></span><input id="subject" maxlength="998"></label>
                    <label><span id="toLabel"></span><textarea id="to" rows="2"></textarea></label>
                    <label><span id="ccLabel"></span><textarea id="cc" rows="2"></textarea></label>
                    <label><span id="bccLabel"></span><textarea id="bcc" rows="2"></textarea></label>
                    <label><span id="bodyLabel"></span><textarea id="body" maxlength="80000"></textarea></label>
                    <p id="editNote" class="muted"></p>
                  </section>
                  <div class="actions">
                    <button id="send" class="primary" type="button"></button>
                    <button id="edit" type="button"></button>
                    <button id="saveEdit" class="primary" type="button" hidden></button>
                    <button id="cancel" type="button"></button>
                  </div>
                  <p id="status" class="status" role="status" aria-live="polite"></p>
                </main>`;

              const get = id => shell.getElementById(id);
              const bodyFrame = get("bodyHost");
              const pending = new Map();
              let nextId = 2;
              let current = null;
              let sendStarted = false;
              let editStarted = false;
              let closed = false;
              let initialized = false;
              let queuedReview = null;
              let reviewGeneration = 0;
              let reviewReference = null;
              const labels = {
                en: {
                  title:"Review email", note:"This is the current draft from Exchange. Nothing has been sent. Send uses Exchange MCP's normal approval. Edit saves the existing draft; Don't send closes this card and leaves the draft unsent.",
                  from:"From", to:"To", cc:"Cc", bcc:"Bcc", subject:"Subject", body:"Message", attachments:"Attachments", noAttachments:"No attachments",
                  send:"Send", edit:"Edit", save:"Save edits", cancel:"Don't send", close:"Close preview", statusSent:"Exchange acknowledged the send request; delivery is not confirmed.",
                  statusCancelled:"Sending was cancelled. The draft remains unchanged.", closed:"Preview closed. No further changes were made.", statusUncertain:"Send result is not confirmed. Check Sent Items before any retry.",
                  statusApprovalRequired:"The MCP client needs your confirmation before it can continue. No email was sent. Complete or decline the approval in the client; this card will not retry. Closing this card leaves the draft unchanged.",
                  statusNotDispatched:"The send request did not reach Exchange. Check the tracking ID and draft before making a new send request.", statusRejected:"Exchange rejected the send request. Check the tracking ID and mailbox status before trying again.",
                  statusEdit:"Saving the draft edits…", statusEditUncertain:"The edit result is unclear. Refresh Drafts before trying again.",
                  statusEdited:"Draft updated. Refreshing its preview…", statusRefreshFailed:"The draft edit succeeded, but its preview could not be refreshed. Ask Exchange MCP to reopen the draft; do not repeat the edit.",
                  editNoteText:"The draft body is editable here. Existing file attachments are preserved. HTML drafts use safe XHTML source; Exchange validates edits before saving.",
                  editNoteFa:"متن پیام را در اینجا ویرایش کنید. فایل‌های پیوست حفظ می‌شوند. بدنهٔ HTML به‌صورت XHTML امن است و Exchange پیش از ذخیره آن را بررسی می‌کند.",
                  invalid:"The preview could not be displayed safely.", loading:"Working…", reviewLoading:"Loading the latest explicitly reviewed draft. Nothing will be sent.", reviewEmpty:"No current draft review is available. Ask Exchange MCP to preview the intended draft, then reopen this view.", reviewFailed:"The draft could not be reloaded. No email was sent. Ask Exchange MCP to preview the intended draft again.", none:"(none)", omitted:"Some inline images were omitted from the preview; the draft is unchanged."
                },
                fa: {
                  title:"بازبینی ایمیل", note:"این پیش‌نویس فعلی Exchange است و هنوز چیزی ارسال نشده. ارسال از تأیید معمول Exchange MCP استفاده می‌کند. ویرایش، پیش‌نویس فعلی را ذخیره می‌کند؛ «ارسال نکن» فقط کارت را می‌بندد و پیش‌نویس را ارسال نمی‌کند.",
                  from:"فرستنده", to:"گیرنده", cc:"رونوشت", bcc:"رونوشت پنهان", subject:"موضوع", body:"متن پیام", attachments:"پیوست‌ها", noAttachments:"بدون پیوست",
                  send:"ارسال", edit:"ویرایش", save:"ذخیرهٔ ویرایش", cancel:"ارسال نکن", close:"بستن پیش‌نمایش", statusSent:"Exchange درخواست ارسال را پذیرفت؛ تحویل پیام تأیید نشده است.",
                  statusCancelled:"ارسال لغو شد. پیش‌نویس تغییر نکرد.", statusUncertain:"نتیجهٔ ارسال تأیید نشده است. پیش از هر تلاش دوباره، پوشهٔ Sent Items را بررسی کنید.",
                  statusApprovalRequired:"برای ادامه، تأیید در MCP لازم است. ایمیلی ارسال نشده است. درخواست را در خود برنامه تأیید یا رد کنید؛ این کارت دوباره تلاش نمی‌کند. بستن کارت پیش‌نویس را تغییر نمی‌دهد.",
                  statusNotDispatched:"درخواست ارسال به Exchange نرسید. شناسهٔ پیگیری و پیش‌نویس را بررسی کنید و سپس یک درخواست ارسال تازه بدهید.", statusRejected:"Exchange درخواست ارسال را رد کرد. پیش از تلاش دوباره، شناسهٔ پیگیری و وضعیت صندوق را بررسی کنید.",
                  statusEdit:"در حال ذخیرهٔ ویرایش‌ها…", statusEditUncertain:"نتیجهٔ ویرایش مشخص نیست. پیش از تلاش دوباره، Drafts را تازه‌سازی کنید.",
                  statusEdited:"پیش‌نویس به‌روزرسانی شد. پیش‌نمایش تازه می‌شود…", statusRefreshFailed:"ویرایش انجام شد، اما پیش‌نمایش تازه نشد. از Exchange MCP بخواهید پیش‌نویس را دوباره باز کند؛ ویرایش را تکرار نکنید.",
                  editNoteText:"متن پیام را در اینجا ویرایش کنید. فایل‌های پیوست حفظ می‌شوند. بدنهٔ HTML به‌صورت XHTML امن است و Exchange پیش از ذخیره آن را بررسی می‌کند.",
                  editNoteFa:"متن پیام را در اینجا ویرایش کنید. فایل‌های پیوست حفظ می‌شوند. بدنهٔ HTML به‌صورت XHTML امن است و Exchange پیش از ذخیره آن را بررسی می‌کند.",
                  invalid:"پیش‌نمایش به‌صورت امن نمایش داده نشد.", loading:"در حال انجام…", reviewLoading:"آخرین پیش‌نویسی که برای بازبینی آماده شده دوباره خوانده می‌شود. ایمیلی ارسال نمی‌شود.", reviewEmpty:"پیش‌نویس فعالی برای بازبینی در دسترس نیست. از Exchange MCP بخواهید پیش‌نویس موردنظر را پیش‌نمایش کند و سپس این نما را دوباره باز کنید.", reviewFailed:"پیش‌نویس دوباره خوانده نشد. ایمیلی ارسال نشده است. از Exchange MCP بخواهید پیش‌نویس موردنظر را دوباره پیش‌نمایش کند.", none:"(ندارد)", closed:"پیش‌نمایش بسته شد؛ تغییر دیگری انجام نشد.", omitted:"بعضی تصاویر درون‌خطی در پیش‌نمایش حذف شدند؛ پیش‌نویس تغییر نکرده است."
                }
              };
              const allowedTags = new Set("a b blockquote br caption code col colgroup del div em h1 h2 h3 h4 h5 h6 hr i img ins li ol p pre s small span strong sub sup table tbody td tfoot th thead tr u ul".split(" "));
              const allowedAttributes = new Set("alt class colspan dir height href id lang rowspan scope src style title width".split(" "));
              const allowedStyles = new Set("background-color border border-bottom border-collapse border-color border-left border-radius border-right border-style border-top border-width color direction font-family font-size font-style font-weight line-height margin margin-bottom margin-left margin-right margin-top padding padding-bottom padding-left padding-right padding-top text-align text-decoration vertical-align white-space width height table-layout border-spacing".split(" "));
              const imagePattern = /^data:image\/(png|jpeg|gif);base64,[A-Za-z0-9+/]*={0,2}$/i;
              const getText = value => Array.isArray(value) ? value.join("\n") : "";
              function applyHostContext(context) {
                const root = document.documentElement;
                if (["light", "dark"].includes(context?.theme)) {
                  root.dataset.theme = context.theme;
                  root.style.colorScheme = context.theme;
                }
                const variables = context?.styles?.variables;
                for (const name of ["--color-text-primary", "--color-text-secondary", "--color-background-primary", "--color-background-secondary", "--color-border-primary"])
                  if (typeof variables?.[name] === "string") root.style.setProperty(name, variables[name]);
              }
              function request(method, params) {
                const id = nextId++;
                return new Promise((resolve, reject) => {
                  pending.set(id, {resolve, reject});
                  window.parent.postMessage({jsonrpc:"2.0", id, method, params}, "*");
                });
              }
              function privatePreview(result) { return result?._meta?.emailPreview; }
              function extractPreview(result) {
                return privatePreview(result) || privatePreview(result?.call_tool_result) || privatePreview(result?.mcp_tool_result)
                  || result?.emailPreview || null;
              }
              function chatGptPreview() {
                const openai = window.openai;
                return extractPreview(openai?.toolOutput) || extractPreview(openai?.toolResponseMetadata)
                  || extractPreview(openai?.toolResponseMetadata?.call_tool_result) || extractPreview(openai?.toolResponseMetadata?.mcp_tool_result);
              }
              function setStatus(message, result = null) {
                const status = get("status");
                status.replaceChildren(document.createTextNode(message));
                const structured = result?.structuredContent?.tracking?.id || result?.tracking?.id;
                const text = (result?.content || []).map(item => item?.text || "").join("\n");
                const match = /\bTracking ID:\s*([0-9a-f]{32})\b/i.exec(text);
                const id = typeof structured === "string" && /^[0-9a-f]{32}$/i.test(structured) ? structured : match?.[1];
                if (id) {
                  const label = document.createElement("span");
                  label.dir = "ltr"; label.textContent = ` Tracking ID: ${id}`;
                  status.append(label);
                }
              }
              function sendOutcome(result) {
                const known = result?.structuredContent?.tracking?.sendStatus;
                if (["not_dispatched", "rejected", "unknown", "acknowledged"].includes(known)) return known;
                const text = (result?.content || []).map(item => item?.text || "").join("\n");
                const match = /Send status:\s*(not_dispatched|rejected|unknown)\b/i.exec(text);
                return match?.[1]?.toLowerCase() || (text.includes("Exchange acknowledged") ? "acknowledged" : "unknown");
              }
              function sendStatusMessage(result, language) {
                const outcome = sendOutcome(result), text = labels[language];
                return outcome === "acknowledged" ? text.statusSent
                  : outcome === "not_dispatched" ? text.statusNotDispatched
                  : outcome === "rejected" ? text.statusRejected : text.statusUncertain;
              }
              function setBusy(value) {
                for (const id of ["send", "edit", "saveEdit", "cancel"]) get(id).disabled = value;
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
                return `<!doctype html><html lang="${language}"><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:; connect-src 'none'; font-src 'none'; media-src 'none'; object-src 'none'; frame-src 'none'; base-uri 'none'; form-action 'none'"><style>:root { color-scheme:light; } body { margin:0; padding:10px; background-color:#fff; color:#111; white-space:normal; }</style></head><body>${html}</body></html>`;
              }
              function validateNode(node) {
                if (node.nodeType === Node.TEXT_NODE) return true;
                if (node.nodeType !== Node.ELEMENT_NODE || node.namespaceURI !== "http://www.w3.org/1999/xhtml") return false;
                const tag = node.localName.toLowerCase();
                if (!allowedTags.has(tag)) return false;
                for (const attribute of [...node.attributes]) {
                  const name = attribute.name.toLowerCase(), value = attribute.value;
                  if (!allowedAttributes.has(name) || value.length > (name === "src" ? 4 * 1024 * 1024 : 4096) || /[\u0000-\u001f\u007f]/.test(value)) return false;
                  if (name === "dir" && !["rtl", "ltr", "auto"].includes(value.toLowerCase())) return false;
                  if (name === "style" && !validStyle(value)) return false;
                  if (name === "href") { let url; try { url = new URL(value); } catch { return false; } if (!["http:", "https:", "mailto:"].includes(url.protocol)) return false; node.removeAttribute("href"); }
                  if (name === "src" && (tag !== "img" || !imagePattern.test(value))) return false;
                }
                if (tag === "img" && !node.hasAttribute("src")) return false;
                return [...node.childNodes].every(validateNode);
              }
              function showPayload(data) {
                if (closed || sendStarted || editStarted) return;
                current = null;
                setBusy(true);
                if (!data || data.version !== 1 || !["fa", "en"].includes(data.language) || typeof data.draftHandle !== "string"
                    || typeof data.subject !== "string" || data.subject.length > 998 || typeof data.body !== "string" || data.body.length > 80000
                    || !["Text", "HTML"].includes(data.bodyType) || typeof data.html !== "string" || data.html.length > 4 * 1024 * 1024
                    || ![data.to, data.cc, data.bcc].every(list => Array.isArray(list) && list.length <= 100 && list.every(item => typeof item === "string" && item.length <= 320))
                    || !Array.isArray(data.attachments) || data.attachments.length > 100 || typeof data.editable !== "boolean"
                    || (data.sendable !== undefined && typeof data.sendable !== "boolean")
                    || !Array.isArray(data.warnings) || data.warnings.length > 20) { setStatus(labels.en.invalid); return; }
                const text = labels[data.language];
                document.documentElement.lang = data.language;
                document.documentElement.dir = data.language === "fa" ? "rtl" : "ltr";
                for (const id of ["title", "note", "fields", "attachments", "warnings", "bodyHost", "editor", "subjectLabel", "toLabel", "ccLabel", "bccLabel", "bodyLabel", "editNote", "status"])
                  get(id).dir = data.language === "fa" ? "rtl" : "ltr";
                get("title").textContent = text.title;
                get("note").textContent = text.note;
                get("send").textContent = text.send;
                get("edit").textContent = text.edit;
                get("saveEdit").textContent = text.save;
                get("cancel").textContent = text.cancel;
                get("subjectLabel").textContent = text.subject;
                get("toLabel").textContent = text.to;
                get("ccLabel").textContent = text.cc;
                get("bccLabel").textContent = text.bcc;
                get("bodyLabel").textContent = data.bodyType === "HTML" ? `${text.body} (HTML)` : text.body;
                get("editNote").textContent = data.language === "fa" ? text.editNoteFa : text.editNoteText;
                const fields = get("fields"); fields.replaceChildren();
                fields.hidden = false;
                for (const [name, value] of [[text.from, data.from], [text.to, getText(data.to)], [text.cc, getText(data.cc)], [text.bcc, getText(data.bcc)], [text.subject, data.subject]]) {
                  if (!value && name !== text.from) continue;
                  const term = document.createElement("dt"); term.textContent = name;
                  const detail = document.createElement("dd"); detail.textContent = value || text.none;
                  fields.append(term, detail);
                }
                const attachments = get("attachments"); attachments.replaceChildren();
                for (const item of data.attachments) {
                  if (!item || typeof item.name !== "string" || item.name.length > 255 || !Number.isInteger(item.sizeBytes) || item.sizeBytes < 0) { setStatus(text.invalid); return; }
                  const li = document.createElement("li");
                  li.textContent = `${item.name} (${item.sizeBytes} bytes${item.isInline ? ", inline" : ""})`;
                  attachments.append(li);
                }
                if (!data.attachments.length) { const li = document.createElement("li"); li.textContent = text.noAttachments; attachments.append(li); }
                attachments.hidden = false;
                const warningList = get("warnings"); warningList.replaceChildren();
                for (const warning of data.warnings) { if (typeof warning !== "string" || warning.length > 2000) { setStatus(text.invalid); return; } const li = document.createElement("li"); li.textContent = warning; warningList.append(li); }
                warningList.hidden = data.warnings.length === 0;
                const template = document.createElement("template"); template.innerHTML = data.html;
                if (![...template.content.childNodes].every(validateNode)) { bodyFrame.removeAttribute("srcdoc"); setStatus(text.invalid); return; }
                current = data;
                bodyFrame.title = text.body;
                bodyFrame.srcdoc = emailDocument(template.innerHTML, data.language);
                bodyFrame.hidden = false;
                get("subject").value = data.subject;
                get("to").value = data.to.join("\n");
                get("cc").value = data.cc.join("\n");
                get("bcc").value = data.bcc.join("\n");
                get("body").value = data.body;
                get("body").dir = data.bodyType === "HTML" ? "ltr" : (data.language === "fa" ? "rtl" : "ltr");
                get("editor").hidden = true;
                get("saveEdit").hidden = true;
                get("edit").hidden = !data.editable;
                get("send").hidden = !(data.sendable ?? data.editable);
                setBusy(false);
                setStatus(data.warnings.length ? text.omitted : "");
              }
              function findData(result) {
                const direct = extractPreview(result);
                if (direct) return direct;
                const content = result?.content || [];
                for (const item of content) if (item && typeof item.text === "string") {
                  try { const parsed = JSON.parse(item.text); const found = extractPreview(parsed); if (found) return found; } catch { }
                }
                return null;
              }
              async function callTool(name, args) {
                const response = await request("tools/call", {name, arguments:args});
                if (response?.isError) throw Object.assign(new Error("The MCP tool returned an error."), {response});
                return response;
              }
              function reviewBootstrap(result) {
                return result?._meta?.emailReviewBootstrap || result?.emailReviewBootstrap
                  || result?.call_tool_result?._meta?.emailReviewBootstrap || result?.mcp_tool_result?._meta?.emailReviewBootstrap || null;
              }
              function clearReview() {
                current = null;
                bodyFrame.removeAttribute("srcdoc");
                bodyFrame.hidden = true;
                for (const id of ["fields", "attachments", "warnings"]) get(id).replaceChildren();
                get("editor").hidden = true;
                get("saveEdit").hidden = true;
                setBusy(true);
              }
              async function openReview(data, source) {
                if (closed || sendStarted || editStarted) return;
                const language = document.documentElement.lang.startsWith("fa") ? "fa" : "en";
                const text = labels[language];
                get("title").textContent = text.title;
                get("note").textContent = text.note;
                get("send").textContent = text.send;
                get("edit").textContent = text.edit;
                get("cancel").textContent = text.cancel;
                if (data.available === false) {
                  reviewGeneration++;
                  clearReview();
                  setStatus(text.reviewEmpty, source);
                  return;
                }
                const validHandle = value => typeof value === "string" && value.length > 0
                  && value.length <= 16384 && !/[\u0000-\u001f\u007f]/.test(value);
                if (data.available !== true || !validHandle(data.draftHandle)
                    || (data.mailboxHandle !== null && data.mailboxHandle !== undefined && !validHandle(data.mailboxHandle))) {
                  reviewGeneration++;
                  clearReview();
                  setStatus(text.invalid, source);
                  return;
                }
                const key = JSON.stringify([data.draftHandle, data.mailboxHandle || null]);
                if (reviewReference === key) return;
                reviewReference = key;
                const generation = ++reviewGeneration;
                clearReview();
                setStatus(text.reviewLoading);
                const args = {draftHandle:data.draftHandle};
                if (data.mailboxHandle) args.mailboxHandle = data.mailboxHandle;
                try {
                  const result = await callTool("mail_preview_draft", args);
                  if (generation !== reviewGeneration || closed || sendStarted || editStarted) return;
                  const preview = findData(result);
                  if (!preview) { setStatus(text.reviewFailed, result); return; }
                  showPayload(preview);
                } catch (error) {
                  if (generation === reviewGeneration) { clearReview(); setStatus(text.reviewFailed, error?.response); }
                }
              }
              function receiveReview(result) {
                const data = reviewBootstrap(result);
                if (!data) return false;
                if (!initialized) queuedReview = {data, source:result};
                else void openReview(data, result);
                return true;
              }
              function isApprovalRequired(value) {
                return value?.resultType === "input_required"
                  || value?.structuredContent?.resultType === "input_required"
                  || value?.rpcData?.resultType === "input_required"
                  || value?.rpcData?.data?.resultType === "input_required"
                  || value?.response?.resultType === "input_required"
                  || value?.response?.error?.data?.resultType === "input_required";
              }
              function showApprovalRequired(result) {
                const text = labels[current.language];
                setBusy(false);
                get("send").disabled = true;
                get("edit").disabled = true;
                get("saveEdit").disabled = true;
                get("cancel").textContent = text.close;
                setStatus(text.statusApprovalRequired, result);
              }
              function selectorArgs() { return current.mailboxHandle ? {mailboxHandle:current.mailboxHandle} : {}; }

              get("send").addEventListener("click", async () => {
                if (!current || sendStarted) return;
                if (!(current.sendable ?? current.editable)) return;
                sendStarted = true; setBusy(true); setStatus(labels[current.language].loading);
                try {
                  const result = await callTool("mail_send_draft", {draftHandle:current.draftHandle, ...selectorArgs()});
                  if (isApprovalRequired(result)) {
                    showApprovalRequired(result);
                  } else if (result?.structuredContent?.status === "cancelled") {
                    sendStarted = false;
                    setBusy(false);
                    setStatus(labels[current.language].statusCancelled, result);
                  } else if (result?.structuredContent?.status === "sent") {
                    setBusy(false); get("send").disabled = true; get("edit").disabled = true;
                    get("cancel").textContent = labels[current.language].close;
                    setStatus(labels[current.language].statusSent, result);
                  } else {
                    setBusy(false); get("send").disabled = true; get("edit").disabled = true; get("saveEdit").disabled = true;
                    get("cancel").textContent = labels[current.language].close;
                    setStatus(sendStatusMessage(result, current.language), result);
                  }
                } catch (error) {
                  if (isApprovalRequired(error)) showApprovalRequired(error.response || error);
                  else {
                    setBusy(false); get("send").disabled = true; get("edit").disabled = true; get("saveEdit").disabled = true;
                    get("cancel").textContent = labels[current.language].close;
                    const result = error?.response;
                    setStatus(sendStatusMessage(result, current.language), result);
                  }
                }
              });
              get("edit").addEventListener("click", () => {
                if (!current || !current.editable) return;
                bodyFrame.hidden = true; get("fields").hidden = true;
                get("editor").hidden = false; get("saveEdit").hidden = false; get("edit").hidden = true; get("send").hidden = true;
                get("subject").focus();
              });
              get("saveEdit").addEventListener("click", async () => {
                if (!current || editStarted) return;
                editStarted = true; setBusy(true); setStatus(labels[current.language].statusEdit);
                const addresses = id => get(id).value.split(/[\n,;]/).map(value => value.trim()).filter(Boolean);
                let updated = false;
                try {
                  const result = await callTool("mail_edit_draft", {
                    draftHandle:current.draftHandle, subject:get("subject").value, body:get("body").value,
                    bodyType:current.bodyType, to:addresses("to"), cc:addresses("cc"), bcc:addresses("bcc"), ...selectorArgs()
                  });
                  const newHandle = result?.structuredContent?.handle;
                  if (result?.structuredContent?.status !== "draft_updated" || typeof newHandle !== "string") throw new Error("Draft update was not confirmed.");
                  updated = true;
                  setStatus(labels[current.language].statusEdited);
                  const refreshed = await callTool("mail_preview_draft", {draftHandle:newHandle, ...selectorArgs()});
                  const data = findData(refreshed);
                  if (!data) throw new Error("Draft preview refresh failed.");
                  editStarted = false;
                  showPayload(data);
                } catch (error) {
                  get("send").disabled = true;
                  get("edit").disabled = true;
                  get("saveEdit").disabled = true;
                  get("cancel").disabled = false;
                  setStatus(updated ? labels[current.language].statusRefreshFailed : labels[current.language].statusEditUncertain, error?.response);
                }
              });
              get("cancel").addEventListener("click", () => {
                if (!current || get("cancel").disabled) return;
                closed = true;
                const text = labels[current.language];
                bodyFrame.removeAttribute("srcdoc");
                get("fields").replaceChildren(); get("attachments").hidden = true; get("warnings").hidden = true;
                get("bodyHost").hidden = true; get("editor").hidden = true;
                get("send").hidden = true; get("edit").hidden = true; get("saveEdit").hidden = true; get("cancel").textContent = text.close; get("cancel").disabled = true;
                setStatus(text.closed);
              });

              window.addEventListener("message", event => {
                if (event.source !== window.parent) return;
                const message = event.data;
                if (!message || message.jsonrpc !== "2.0") return;
                if (message.id !== undefined && pending.has(message.id)) {
                  const item = pending.get(message.id); pending.delete(message.id);
                  if (message.error) {
                    const error = new Error("MCP request failed.");
                    error.rpcCode = message.error.code;
                    error.rpcData = message.error.data;
                    item.reject(error);
                  } else item.resolve(message.result);
                  return;
                }
                if (message.id === 1) {
                  if (message.error) { setStatus(labels.en.invalid); return; }
                  initialized = true;
                  applyHostContext(message.result?.hostContext);
                  window.parent.postMessage({jsonrpc:"2.0", method:"ui/notifications/initialized"}, "*");
                  if (queuedReview) { const queued = queuedReview; queuedReview = null; void openReview(queued.data, queued.source); }
                  if (receiveReview(window.openai?.toolResponseMetadata) || receiveReview(window.openai?.toolOutput)) return;
                  const initial = chatGptPreview();
                  if (initial) showPayload(initial);
                  return;
                }
                if (message.method === "ui/notifications/host-context-changed") {
                  applyHostContext(message.params);
                  return;
                }
                if (message.method === "ui/notifications/tool-result") {
                  if (receiveReview(message.params)) return;
                  const data = findData(message.params);
                  if (data) showPayload(data);
                }
              }, {passive:true});

              window.parent.postMessage({jsonrpc:"2.0", id:1, method:"ui/initialize", params:{
                protocolVersion:"2026-01-26", appInfo:{name:"Exchange MCP email preview",version:"1.0.0"}, appCapabilities:{availableDisplayModes:["inline","fullscreen"]}
              }}, "*");
              setBusy(true);
              if (receiveReview(window.openai?.toolResponseMetadata) || receiveReview(window.openai?.toolOutput)) return;
              const initial = chatGptPreview();
              if (initial) showPayload(initial);
              else setStatus(labels.en.loading);
            })();
          </script>
        </body>
        </html>
        """;
}
