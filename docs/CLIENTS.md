# Connect an MCP client

Connect a client only after the [IdP contract](IDENTITY-PROVIDER.md), [Keycloak configuration](KEYCLOAK.md), and service deployment are ready. `exchange-mcp` is an authenticated Streamable HTTP service for operator-managed Exchange. It is not a built-in Microsoft 365 connector, an Exchange Online OAuth application, or an anonymous mailbox API.

The examples use `https://mail.example.test/mcp`; replace this reserved example hostname. Client UI names and hosted availability change. The linked official OpenAI documentation was checked on 2026-10-28; qualify the actual installed client, workspace policy, and deployment.

## Choose the connection surface

| Surface | Required connection path | What still needs qualification |
| --- | --- | --- |
| Local Codex/desktop runtime | Streamable HTTP URL reachable from that runtime, browser OAuth, approved `azp`, and trusted TLS. | Installed OAuth registration/callback behavior, refresh, UI resources, and form confirmation. |
| Hosted ChatGPT connection | A supported custom-MCP/plugin connection and an MCP/IdP path reachable by the hosted service. | Workspace availability, registration method, actual callback, UI behavior, refresh, and optional events. |
| Application using a remote-MCP API | The application's own OAuth client obtains a valid employee access token and supplies it through the API's supported authorization field. | Token lifecycle, approved client identity, network access from that API, approvals, and data handling. |
| Another MCP HTTP host | Correct transport/authentication and this server's strict token contract. | Each advanced capability independently; basic tool listing does not establish complete compatibility. |

The repository ships the service and its examples. It does not provision a hosted plugin, client account, workspace entitlement, or IdP. No private organization-specific client package is needed or included.

## Network cases

The relevant network is the one used by the MCP runtime. A successful browser visit from Alice's laptop does not establish reachability from a cloud-hosted client.

| Connection case | Network requirements |
| --- | --- |
| Local client on the LAN/VPN | The local runtime resolves and reaches the private MCP URL and IdP token/discovery endpoints. The browser reaches the IdP login URL and the client's actual callback. Trust the relevant CA chains in the runtime and browser. |
| Cloud-hosted client | Its backend must reach MCP metadata/transport and the IdP endpoints used for discovery/token exchange. Use an intentionally published HTTPS endpoint or a host-supported private connectivity mechanism that you have qualified. A laptop-only VPN or private DNS name is not sufficient. |
| Service backend | The container reaches IdP discovery/JWKS and uncached introspection, trusted EWS HTTPS, and LDAPS when configured. This traffic is separate from the client's connection. |
| Mail events | In addition, the service resolves and reaches the host-supplied public HTTPS webhook destination. The event code rejects private/local/test destinations and redirects. |

`Service.Resource` identifies the normal MCP resource. `PublicResource`, if used, adds a second recognized HTTPS authority with the same path. It does not configure ingress. The service selects metadata and the required token audience from the receiving `Host`; preserve that host through the TLS proxy. Tokens used through the public hostname must contain the public resource audience. The introspection response must preserve the entire JWT audience set.

The reference Compose listener binds only to `127.0.0.1:8080`. It needs an operator-managed HTTPS reverse proxy before ordinary client access. Configure only the actual immediate proxy address as trusted, preserve `Host`, and forward the original HTTPS scheme. A reverse proxy in a separate container does not reach the application's host loopback merely by using its own `127.0.0.1`.

`AllowedOrigins` is an exact allowlist for requests that carry an `Origin` header; every supplied origin is checked. An empty list allows requests without `Origin` and rejects requests with one. It is not a substitute for OAuth client approval or a general CORS implementation. Add only an observed, intended HTTPS origin when the chosen host needs it.

## Codex and local desktop clients

The following pre-registered client path uses `exchange-mcp-codex`, matching the release's continuation policy. First have the IdP administrator create that employee-facing OIDC client with Authorization Code + PKCE `S256`, the resource audience, and the approved mailbox scopes. Add its ID to `Service.AllowedClientIds`.

1. Add the remote server with the installed client's supported CLI:

   ```sh
   codex mcp add exchange --url https://mail.example.test/mcp --oauth-client-id exchange-mcp-codex
   ```

2. Copy the complete **OAuth callback URL** printed by the client to the IdP client's valid redirect URI allowlist. Register that exact value; the callback can depend on the server URL, issuer-identification support, installed version, and listener port. Do not invent a callback path, copy one from another server, or use the MCP resource URL as the callback.
3. Start a read-only sign-in:

   ```sh
   codex mcp login exchange --scopes mail.read
   ```

4. Complete the normal browser login and consent. A browser already signed into the IdP may reuse that session; this does not remove the client's OAuth flow.
5. Confirm the server is registered, then inspect the tools in the client:

   ```sh
   codex mcp list
   ```

   A configured entry is not proof of authentication. Run `mail_profile` and a requested mailbox read to verify the identity and EWS path.

Codex can also be configured through its MCP settings UI. The installed client normally manages its own OAuth credentials and callback state. Keep that configuration private. For a confidential client, use the host's secure client-secret setup, not a secret in a shared example or checked-in configuration.

The authoritative client instructions, including fixed/variable loopback port handling and registration choices, are in the [official MCP configuration documentation](https://learn.chatgpt.com/docs/extend/mcp). A preconfigured client ID avoids accidental selection of a different DCR/CIMD identity. If you deliberately change registration mode, inspect the resulting `azp` and approve it explicitly; the server does not trust all clients from a vendor.

If a host lacks a usable loopback callback, use that host's documented supported callback mechanism. Do not expose an ad hoc callback listener or add wildcard IdP redirects to work around it.

## ChatGPT hosted connections

Use the supported **Add custom MCP server** flow, choosing OAuth. Current OpenAI documentation describes the resulting integration as a plugin. Supply the canonical HTTPS MCP URL and the registration/authentication details appropriate to the IdP. Install/enable the resulting integration in the intended workspace and conversation. The server requires authentication for transport initialization and tool listing; choose OAuth rather than anonymous or mixed anonymous discovery. Follow the [official connection procedure](https://developers.openai.com/api/docs/guides/custom-mcp-server).

For a predictable Keycloak baseline, a pre-registered client can be used when the host's setup offers static OAuth credentials. For example, create `company-exchange-chatgpt`, apply the same audience/scopes/identity mapping as the local client, and add that exact ID to the service allowlist. Its secret is a host/client credential, distinct from the service's confidential introspection secret.

For CIMD, all of these must be true:

- The deployed IdP actually fetches and validates Client ID Metadata Documents, validates their redirects, and supports the selected token-endpoint authentication method.
- Its metadata truthfully advertises the supported mechanism. Setting `client_id_metadata_document_supported: true` without implementing the flow breaks authentication.
- The client policy grants the required audience, scopes, and immutable identity claims to the resulting client.
- The service's allowlist contains the actual client ID issued in `azp`.

ChatGPT supports CIMD token exchange with `none` or `private_key_jwt`; match the actual host/IdP intersection. Copy the exact CIMD URL and redirect URI shown on the connection's management page. The stable CIMD ID `https://chatgpt.com/oauth/client.json` is used only in the eligible issuer-bound mode; callback-specific mode has a different ID. Stable callbacks require correct RFC 9207 issuer metadata and a matching `iss` in authorization responses. Do not infer a callback from the CIMD URL. See [OpenAI's authentication requirements](https://developers.openai.com/plugins/build/auth).

CIMD is not implemented by this MCP service, and basic Keycloak OIDC support does not prove that your Keycloak build or installed providers support it. When not demonstrated, use supported pre-registration rather than adding a metadata claim to suggest it does. DCR is another host/IdP mechanism, but every generated `azp` still needs explicit server approval; registration alone does not grant mailbox access.

Once linked, verify the actual profile and permitted mailbox read. Refresh the host's connection/catalog after a server tool or event change. The MCP service cannot force a host catalog refresh, install a plugin in another workspace, or change host-level tool approval settings.

## Applications using the OpenAI remote-MCP API

An application can use the remote MCP integration with `server_url` and its supported `authorization` field. The application must first obtain a valid employee access token through its own approved OAuth client; include that actual client ID in `AllowedClientIds`. The API request does not convert an Exchange password, a Keycloak service-account token, or an arbitrary bearer token into an enrolled employee identity.

Keep access/refresh tokens in the application's protected credential storage, and supply the access token through the documented API field rather than prompt text. The application owns renewal and reauthorization. The [official remote-MCP API guide](https://developers.openai.com/api/docs/guides/tools-connectors-mcp) covers the transport and authorization field. A basic API tool integration does not establish native form elicitation, MCP Apps UI, or event subscriptions; qualify those separately if needed.

## First use and a safe read-only check

With writes and sending still disabled, ask the connected host to:

1. Run `mail_profile` and verify that the displayed own mailbox is Alice's intended mailbox.
2. Read the Inbox or search for a known non-sensitive test message.
3. Show the account's available mailbox targets only if delegated access is in scope. A raw email address is not a delegated authorization handle.
4. Run `mail_onboarding` when first-use guidance is wanted. Language/signature setup is optional and should not block an unrelated requested read.

Successful tool discovery proves a catalog was obtained. `mail_profile` plus the intended read establishes more of the path, but it still does not prove sending, refresh after expiry, every delegated workflow, a preview UI, or event delivery.

Onboarding and signature persistence require write permission for their respective update/commit tools. Do not enable sending just to finish a read-only connection test. Previewing a signature is not the same as saving it, changing defaults, or sending a test message.

## Write actions and human confirmation

There are independent gates: user intent, OAuth scope, server feature switch, recipient/access policy, Exchange rights, and the action's approval protocol. A host's tool annotation or an auto-approve setting cannot bypass the server gates.

| Action/capability | What the host must support |
| --- | --- |
| Mailbox reads | Authenticated Streamable HTTP and ordinary tool results. |
| Mailbox writes | The required `mail.write` or `mail.manage` scope, enabled server writes, and the relevant tool workflow. |
| Normal non-CIMD send approval path | Native form elicitation plus an MRTR or stateful MCP session; continuation must preserve server request state and the human response. |
| Exact stable ChatGPT CIMD send path | The actual `azp` is `https://chatgpt.com/oauth/client.json`; this implementation uses `mail.send` OAuth authorization and the host's normal tool approval, without the per-draft native form. |
| Separately configured standing approval | Only the exact actor/client/mailbox/recipient scope accepted by the server's dedicated configuration and current directory checks. It is disabled by the example configuration. |
| Other protected management actions | Some still require native form confirmation even when the exact ChatGPT send path is used. Qualify the specific tool. |

For the native confirmation path, a text “yes” in chat is not the protocol response. If the client cannot present or complete the required form, the action fails closed. There is no generic fallback that accepts a model-generated approval flag. Use a host that supports the required capability or perform the action through the normal Exchange client.

Changed drafts and repeated send attempts are rejected. If a send has an uncertain result, inspect Sent Items before deciding what to do; never repeat it just to obtain a cleaner success message. Enabling `mail.send` and `SendEnabled` is a real transmission permission and should follow a tested client/approval policy.

## Preview and review UI

The service publishes email and signature preview resources as MCP Apps HTML (`text/html;profile=mcp-app`) with `ui://` resource identifiers. A host must support resource loading, the MCP Apps bridge, the required tool/resource metadata, and its own sandbox/UI policy to show them interactively. Plain tool support does not imply that capability. OpenAI's [MCP server and UI guide](https://developers.openai.com/plugins/build/app-quickstart) describes the host bridge.

`mail_preview_draft` reads the current saved Exchange draft and supplies a refreshed handle plus review content. Hosts without the UI can still receive the structured/plain-text summary. Display failure is not a reason to resend, recreate a draft, or alter a saved signature. The optional `mail_review_email` and `mail_review_signature` views are separate user-requested review surfaces; the server cannot force a particular host panel to open.

UI controls use the ordinary authenticated tools and server guards. Rendering a button does not prove the action is authorized or that the host can complete its confirmation flow. Test a disposable unsent draft, cancellation, stale/changed draft rejection, and the actual host's resource loading before claiming the full review workflow is supported.

## Optional incoming-mail events

Mail notifications are a separate capability from tools and browser SSO. This release exposes `email.received` for the signed-in user's own Inbox, through `events/list`, `events/subscribe`, and `events/unsubscribe`, using MCP protocol `2026-07-28`. It accepts empty event arguments, webhook delivery, and no replay cursor. `mail_event_status` reads subscription state; it does not create a subscription.

Current OpenAI documentation places MCP Events in supported Work/cloud surfaces and dots, subject to workspace controls. The host discovers events, supplies the callback and signing secret, manages renewal, and decides how/when to run the subscribed task. See [OpenAI's MCP Events guide](https://developers.openai.com/plugins/build/mcp-events). Availability in a different desktop/local mode or another host must be demonstrated separately.

The operator and host must qualify:

- A `2026-07-28` discovery response with the events capability and `email.received` in the event catalog.
- Successful authenticated subscription for the own Inbox, callback challenge verification, private persisted state, and outward HTTPS delivery.
- The host-provided callback resolving only to public addresses with a trusted TLS certificate. The server blocks private/local/test addresses, DNS rebinding to non-public addresses, and redirects. The `.example.test` names in these guides cannot be used as real callback destinations.
- Timely renewal: granted subscription lifetime is clamped below the subscribing access token's expiry by five seconds, with at least one minute required to create a subscription. A nominal requested lifetime does not override token expiry.
- Unsubscribe, access revocation, expiration, restart, duplicate/out-of-order events, and expected host batching behavior.

The service maintains Exchange streaming subscriptions and reconciles Inbox state; it does not require periodic Inbox polling by the client. Callback acceptance, host task execution, host awareness, and a visible user notification are different results. A successful callback response does not prove immediate execution or an on-screen alert. Do not resend an already acknowledged event to force another host run.

For a normal employee request, let the host manage its native event workflow. Do not ask the user to invent a callback URL, signing key, command, or schedule. If the host lacks event support, state that limitation; do not claim that `mail_event_status`, an OAuth re-login, or an hourly manual query created an event subscription.

## Refresh and reconnect qualification

The client owns refresh-token storage and renewal. The MCP server receives access tokens and verifies them; it cannot inspect a host credential vault or guarantee silent renewal.

The optional `mail_request_connection_continuation` tool is limited by code to `exchange-mcp-codex` and `https://chatgpt.com/oauth/client.json`. Use it only after the user explicitly asks to stay signed in. It preserves the current mailbox scopes when asking for optional `offline_access`; an unsupported client returns `unsupported_client`. A pre-registered ChatGPT client or another CIMD ID can have working normal OAuth refresh while remaining unsupported by this optional helper.

Verify renewal by allowing the original access token to expire and observing a successful new authenticated request with the correct identity. Check refresh rotation and IdP grant revocation. An `offline_access` claim, a browser cookie, or a configured IdP maximum session length is not proof of host persistence or a fixed multi-day connection. Do not loop sign-ins or delete/recreate a working client registration to try to force refresh.

## Diagnose one layer at a time

| Observation | Meaning / next check |
| --- | --- |
| Local health check succeeds | Process is alive. Continue with external metadata, OAuth, enrollment, then EWS. |
| Browser reaches MCP, hosted connection cannot | Test DNS/TLS/routing from the actual hosted runtime and IdP reachability. |
| Login UI succeeds, MCP returns 401 | Compare issuer, host-specific audience, actual `azp`, token type/expiry, and uncached introspection. |
| 403 | Check scope/enrollment and operation gates; also check an observed `Origin` against the exact origin allowlist. |
| 429 | Respect retry information. Capacity/rate rejection is not a reason to reauthorize. |
| `invalid_client` from the IdP | Check the existing client registration and its current authentication credential. Do not confuse it with access-token expiry. |
| Tools work, UI does not appear | Inspect host MCP Apps capability/resource metadata and refresh its catalog. Do not modify mailbox data to repair UI. |
| Tools work, event catalog missing | Inspect negotiated protocol, host event support, supported connection mode, and host catalog refresh. |
| Subscribed, no visible announcement | Inspect subscription expiry/pending/gap state, callback result, and host task/batching preferences independently. |
| Native confirmation unavailable | Use a capable host or the normal Exchange client; do not weaken the guard as a compatibility workaround. |

Record sanitized timestamps, versions, HTTP/RPC outcomes, and tracking IDs. Do not share access/refresh tokens, client secrets, callback signing secrets, raw mailbox messages, or browser cookies in public issues.

