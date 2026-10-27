# Identity provider, SSO, and authorization contract

`exchange-mcp` requires a properly configured identity provider (IdP). Running the container does not create an IdP, register an OAuth client, connect Active Directory (AD), or enable single sign-on (SSO). Complete this guide before connecting an employee mailbox. For a concrete Keycloak setup, continue with [KEYCLOAK.md](KEYCLOAK.md); for the host connection, use [CLIENTS.md](CLIENTS.md).

The implementation is a protected Streamable HTTP MCP resource server. Its token-status checker is specifically shaped for Keycloak: it constructs a Keycloak introspection URL and checks a strict response contract. An arbitrary OIDC provider is not a drop-in replacement. A different provider needs to satisfy every requirement below, including the endpoint and claim contract, or needs a separately implemented and tested adapter.

This document describes the release source. Provider and hosted-client documentation was checked on 2026-10-28. Examples use reserved `.example.test` names and fictional users Alice and Bob; replace them with operator-owned names. These example DNS names are not usable production endpoints.

## What must already exist

| Requirement | What the operator must establish |
| --- | --- |
| An IdP | A maintained HTTPS OIDC/OAuth service, its canonical issuer, signing keys, browser login policy, approved employees, client registrations, and an administrator who can revoke access. Keycloak is the implementation targeted by this release. |
| A human login flow | Authorization Code with PKCE `S256`, usable discovery metadata, and the actual callback URI supplied by each client. The MCP service has no login page or OAuth callback route. |
| A mailbox identity decision | Either an explicit `sub` to primary SMTP mapping, or automatic enrollment through an immutable AD GUID. A display name or an email claim is not enrollment. |
| Exchange access | A separate EWS service identity, its mounted password file, a trusted HTTPS EWS endpoint, and the Exchange rights required for the approved mailbox scope. An OAuth scope does not grant Exchange rights. |
| AD access when used | Trusted LDAPS on TCP 636, a bounded search base, and directory read permissions. Automatic enrollment requires it; a static own-mailbox pilot can omit it, but directory-dependent delegated features then remain unavailable or unknown. |
| Network and TLS trust | Reachability from the actual MCP client runtime to MCP and the IdP, and from the service to IdP discovery/JWKS/introspection, Exchange, and AD when configured. Browser reachability alone is insufficient. |
| Durable private storage | Persistent audit/state storage and protection keys, restricted secret files, and a backup/restore plan. Enrollment and approval state must not be shared publicly or discarded on a restart. |

The reference configuration starts with mailbox writes and sending disabled. Qualify the identity and read path first; grant additional scopes and enable server-side write switches only for the intended deployment.

## Separate the credential boundaries

There are three independent authentication paths:

1. **Employee to IdP:** the client opens a browser login/consent flow. Keycloak may authenticate with a password, MFA, an existing browser session, or a separately configured Kerberos/SPNEGO flow.
2. **MCP service to IdP:** the service validates the access-token signature and sends the same access token to introspection using a dedicated confidential client's ID and secret.
3. **MCP service to Exchange and AD:** EWS uses `Exchange.Username`, `Exchange.Domain`, and `Exchange.PasswordFile`. The built-in LDAPS reader uses those same configured service credentials for its directory bind. Keycloak's own LDAP federation bind account is a separate Keycloak configuration.

Employee passwords, IdP client secrets, and service passwords do not belong in chat prompts, client manifests, screenshots, or source control. The employee's bearer token is not passed through to EWS. The code does not relay a browser Kerberos ticket, create a Kerberos bridge, or perform Windows constrained delegation on behalf of that browser.

“SSO works” must be qualified: a reused IdP browser session can reduce login prompts, but consent, MFA, browser policy, session expiration, and client refresh support still apply. Integrated Windows login additionally needs working AD Kerberos, the correct HTTP SPN/keytab, the IdP authentication flow, and browser trust. See [Keycloak's Kerberos documentation](https://www.keycloak.org/docs/latest/server_admin/index.html#_kerberos).

## Choose canonical URLs and client identities

A minimal deployment can use:

| Purpose | Example |
| --- | --- |
| `Service.Authority` | `https://identity.example.test/realms/company` |
| `Service.Resource` | `https://mail.example.test/mcp` |
| `Service.IntrospectionClientId` | `https://mail.example.test/mcp` |
| Approved local client | `exchange-mcp-codex` |
| Approved pre-registered hosted client | `company-exchange-chatgpt` |
| Optional public resource | `https://mail-public.example.test/mcp` |

The resource URL is the audience identifier, not the client ID of the human-facing client. The introspection client may use the resource URL as its ID; this is convenient because current Keycloak audience checks then use the same string. The employee client's ID appears in `azp` and belongs in `AllowedClientIds`.

Match issuer, resource, audience, and client ID strings exactly. In particular, adding a trailing slash to an audience changes it. The server explicitly disables trailing-slash normalization for audience validation. Use the exact discovered issuer as `Authority` and issue tokens with that exact `iss` value.

`PublicResource` is optional. If set, it must be HTTPS, have the same absolute path as `Resource`, and use a different authority (hostname/port). Requests received through each configured host must carry that host's resource audience. Adding `PublicResource` configures recognition; it does not publish DNS, TLS, routing, or a firewall rule. See [the network cases in CLIENTS.md](CLIENTS.md#network-cases).

`AllowedClientIds` must be nonempty. It is an exact, case-sensitive allowlist of `azp` values. Keep each approved client explicit. A newly registered DCR client or a different CIMD URL does not become approved automatically.

## Discovery and the OAuth flow

The server exposes these routes:

| Route | Purpose |
| --- | --- |
| `/.well-known/oauth-protected-resource` | Host-specific resource metadata with the configured authority and advertised scopes. |
| `/.well-known/oauth-protected-resource/mcp` | The same protected-resource metadata at the path-specific location. |
| `/mcp` and `/` | Authenticated MCP transports; both require an enrolled identity and `mail.read`. Use the canonical configured resource in clients. |
| `/health/live` | Process liveness only. It does not test login, introspection, AD, or EWS. |

The service does not implement `/authorize`, `/token`, `/register`, `/callback`, a logout endpoint, or an authorization-server metadata proxy. Those functions belong to the IdP or the MCP client. Never add the MCP URL as a redirect URI just because it is the resource URL.

The client discovers the IdP from protected-resource metadata, performs the browser Authorization Code + PKCE flow directly with that IdP, and sends an access token in `Authorization: Bearer <token>`. The IdP must publish its real authorization/token endpoints and PKCE capabilities. Configure its resource/audience handling so a token requested for this service contains the configured resource audience. [MCP's authorization specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization) explains discovery, registration choices, and resource binding.

The implemented unauthenticated challenge points to protected-resource metadata and requests `mail.read`. The metadata advertises `mail.read`, adds `mail.write`/`mail.manage` when writes are enabled, and adds `mail.send` when sending is enabled. This release also advertises `offline_access`; that advertisement does not issue a refresh token or authorize its use by every client.

## Exact access-token requirements

Tokens must be signed JWT access tokens. Opaque tokens, ID tokens, and refresh tokens cannot be used as MCP bearer access tokens.

| Field | Requirement in this implementation |
| --- | --- |
| JWT header `alg` | `RS256`, `RS384`, `RS512`, or `ES256`; unsigned and HMAC tokens are rejected. |
| JWT header `typ` | `JWT` or `at+jwt`. This is distinct from the payload's `typ`. |
| `iss` | Exactly `Service.Authority`; signature keys are obtained through HTTPS authority discovery. |
| `aud` | Contains a configured resource; additionally contains the resource matching the receiving request host. |
| `exp` | Required. Normal JWT lifetime validation allows 30 seconds of clock skew, but introspection additionally requires `exp` strictly later than the current UTC time. Keep clocks synchronized. |
| `sub` | Nonempty stable employee subject. Automatic enrollment further limits it to 256 characters with no control characters. Do not recycle a subject for a different employee. |
| `azp` | Exact approved human-facing OAuth client ID in `AllowedClientIds`. A token with only `client_id` and no `azp` is rejected. |
| Payload `typ` | Exactly the string `Bearer`. A valid JWT with this claim missing is rejected. |
| `scope` | A space-delimited string containing `mail.read` for the MCP transport, plus the scope required by a particular tool. Comparison is case-sensitive. |
| `ad_object_guid` | Required for automatic enrollment: exactly one nonzero, lowercase, hyphenated GUID in canonical `D` form. The claim must come from trusted AD identity data. |
| `sid` | Not a base login requirement, but used to bind session-dependent mailbox handles, previews, and approvals. Qualify these features with a real session-bound token. |

`email`, `preferred_username`, `upn`, and display-name claims are not accepted as an own-mailbox authorization mapping. A user-supplied mailbox name does not replace the enrolled identity. Group/role claims do not replace the four mailbox scopes or live Exchange authorization.

An illustrative payload shape is shown below. It is not a signed token and cannot authenticate:

```json
{
  "iss": "https://identity.example.test/realms/company",
  "sub": "alice-subject",
  "aud": ["https://mail.example.test/mcp"],
  "azp": "exchange-mcp-codex",
  "typ": "Bearer",
  "scope": "openid mail.read",
  "ad_object_guid": "11111111-2222-4333-8444-555555555555",
  "sid": "alice-browser-session",
  "exp": 1893456000
}
```

## Exact introspection requirements

After JWT validation, each authenticated HTTP request performs an uncached check against:

```text
<Service.Authority with trailing slash removed>/protocol/openid-connect/token/introspect
```

The code derives this path; it does not read an arbitrary `introspection_endpoint` from metadata. For the example authority, the resulting endpoint is:

```text
https://identity.example.test/realms/company/protocol/openid-connect/token/introspect
```

The service sends an HTTPS form POST containing `client_id`, `client_secret`, and `token`, with `Accept: application/json`. Its own introspection credentials come from `IntrospectionClientId` and `IntrospectionSecretFile`. It does not obtain a client-credentials access token first. Keycloak documents introspection as a [confidential-client endpoint](https://www.keycloak.org/securing-apps/oidc-layers#introspection-endpoint).

The response must have all of the following:

| Response member | Required comparison |
| --- | --- |
| `active` | JSON boolean `true`. |
| `typ` | String exactly `Bearer`. |
| `sub`, `iss` | Exactly the corresponding validated JWT claims. |
| `aud` | Nonempty string or array of nonempty strings. Its full set must equal the JWT's audience set and overlap configured resources. Extra or missing audiences cause rejection. |
| `azp` and/or `client_id` | At least one must be a string identifying the JWT's `azp`; every one present as a string must match it. |
| `scope` | String whose space-delimited set exactly equals the JWT's scope set, including any OIDC or optional scopes. |
| `exp` | JSON integer exactly equal to the JWT expiry, and still in the future. |
| `ad_object_guid` | If the JWT has the claim, introspection must return the exact same string, and the JWT must contain exactly one valid nonzero GUID. If the JWT has no such claim, introspection must omit it. |

For the preceding illustrative JWT, an acceptable response has this shape:

```json
{
  "active": true,
  "iss": "https://identity.example.test/realms/company",
  "sub": "alice-subject",
  "aud": ["https://mail.example.test/mcp"],
  "azp": "exchange-mcp-codex",
  "client_id": "exchange-mcp-codex",
  "typ": "Bearer",
  "scope": "openid mail.read",
  "ad_object_guid": "11111111-2222-4333-8444-555555555555",
  "exp": 1893456000
}
```

Redirects and cookies are disabled for introspection. The request has a 10-second timeout; oversized tokens or responses above 64 KiB are rejected. A provider failure, non-success response, malformed JSON, unreadable/empty secret, or claim mismatch fails closed. There is no successful-token-status cache to bypass an IdP outage.

Current Keycloak also checks whether the confidential introspecting client's ID appears in the access token audience. Include that client as an audience instead of disabling the audience check. If its ID differs from the MCP resource URL, issue both audiences and preserve the same complete set in the JWT and introspection response. See [Keycloak's audience and introspection rules](https://www.keycloak.org/docs/latest/server_admin/index.html#_audience).

Do not enable lightweight-token policies that remove claims this server needs from the JWT. Returning those claims only through introspection is insufficient: local JWT checks and the equality checks run first or require both copies.

## Enroll the correct mailbox

### Static enrollment for a small pilot

With `AutoEnrollmentEnabled: false`, configure the verified IdP subject explicitly:

```json
{
  "Service": {
    "AutoEnrollmentEnabled": false,
    "Mailboxes": {
      "alice-subject": "alice@example.test"
    }
  }
}
```

This is a partial configuration fragment, not a replacement for the full example file. Obtain `sub` from a verified sign-in to the correct issuer; do not guess it from the username. Ensure the EWS service identity can access the mapped mailbox. Bob remains unenrolled unless his own verified subject is added. Static enrollment does not perform the automatic GUID-to-AD-account check, so the operator owns the correctness and lifecycle of this mapping.

Keep the subject stable across approved clients if the same employee is to share one enrollment. Pairwise subject mappings that change `sub` per client require a deliberate enrollment design; they are not automatically merged by email address.

### Automatic enrollment through AD

With `AutoEnrollmentEnabled: true`, all qualifying MCP authentication attempts with `mail.read` must pass live enrollment checks. An existing static entry does not bypass those checks.

Configure trusted LDAPS (`DirectoryPermissions.Host`, port 636, `BaseDn`) and a nonempty `AllowedRecipientDomains`. The signed GUID claim must uniquely resolve, within that search base, to an AD person/user with:

- The matching binary `objectGUID` and a nonempty distinguished name.
- An enabled normal user account (`userAccountControl` normal-account bit set, disabled bit clear).
- `msExchRecipientTypeDetails` equal to `1`, meaning the supported user-mailbox case.
- Exactly one nonempty `legacyExchangeDN` and `homeMDB`.
- Exactly one uppercase `SMTP:` primary proxy address, valid as an email address and in an allowed domain.

On first enrollment, the service also verifies EWS read rights on that mailbox's Inbox, repeats the AD resolution, rejects conflicting subject/GUID/mailbox bindings, and persists the binding. Later authenticated MCP requests resolve AD again and require the same GUID and primary mailbox. A disabled account, changed GUID, changed primary SMTP address, directory failure, or collision is rejected instead of silently retargeting enrollment. Shared, remote, room, and equipment mailboxes are not auto-enrolled as the employee's own user mailbox by this path.

The private registry is stored at `<AuditPath>.enrollments.json`, bound to the configured issuer. Preserve it with the rest of the service state. It has a maximum of 1,024 records; malformed, wrong-issuer, or incompatible registry contents fail closed. Plan an explicit operator-reviewed migration for mailbox/subject/issuer changes rather than editing claims to impersonate an old identity.

The AD GUID is a security-sensitive identity binding. End users must not be able to edit it through the IdP profile, registration forms, or an untrusted mapper. A hardcoded GUID shared by all users defeats identity isolation.

## Scopes and server switches

| Scope | Meaning and additional gate |
| --- | --- |
| `mail.read` | Required for the MCP transport and read operations, alongside enrollment and Exchange rights. |
| `mail.write` | Tools that create or edit mailbox data; requires `WritesEnabled: true`. |
| `mail.manage` | Management operations selected by the tool; requires `WritesEnabled: true`. |
| `mail.send` | Transmission operations; requires `WritesEnabled: true` and `SendEnabled: true`, recipient policy, Exchange rights, and the implemented approval path. |
| `offline_access` | Optional IdP/host continuation permission. It is not a mailbox permission and does not replace any of the four above. |

Tool metadata and client-side approval settings do not grant server permission. The server rechecks scopes and switches. A delegated mailbox additionally needs current Exchange/AD access evidence and an opaque handle bound to the authenticated actor/client/session; an IdP role or `MailboxTargets` entry is not a shortcut around that authorization.

Sending has a client-specific distinction: the exact client ID `https://chatgpt.com/oauth/client.json` uses the `mail.send` OAuth grant path instead of native per-draft form confirmation. Other clients use the native confirmation path unless the deployment deliberately enables the separate, narrowly scoped configured grant. Do not describe every send as requiring a new native form; review the actual host/client policy before enabling sending. [CLIENTS.md](CLIENTS.md#write-actions-and-human-confirmation) gives the capability requirements.

## Refresh, logout, and revocation

The MCP service validates access tokens; it does not issue, store, or refresh the client's OAuth refresh token. The client and IdP own that lifecycle. A browser cookie, a long IdP session setting, or an `offline_access` claim alone does not prove that a client stores a refresh token, rotates it correctly, or remains connected for a particular number of days.

`mail_request_connection_continuation` is an explicit optional-consent helper. This release allows it only for `exchange-mcp-codex` and `https://chatgpt.com/oauth/client.json`. It preserves currently granted mailbox scopes and asks the host for `offline_access` through the normal OAuth challenge. Other clients return `unsupported_client`; if the scope is already present, the tool reports only that fact. Call it only after the user asks to stay signed in, and do not loop login attempts when the host cannot handle it.

Qualify refresh with the exact client: sign in, allow the original access token to expire, make a new request, and verify that a new valid access token reaches the service without unnecessary user interaction. Test reconnect, refresh-token rotation, consent revocation, and restart separately. Do not weaken IdP session policy merely to make a connection appear permanent.

To revoke access, use the IdP's supported session/consent/token controls and remove enrollment or client approval when appropriate. Test that the IdP reports the old access token inactive and that the next new MCP request returns 401. Disabling a client or logging out a browser is not universal proof that all already-issued access tokens or offline grants were revoked. Offline grants may need their own revocation; follow the provider's policy.

Per-request introspection does not retroactively undo a dispatched EWS operation or cancel every existing long-lived connection. Mail event subscriptions have a separate stored lifecycle, live mailbox checks, and an expiry clamped below the subscribing access token's expiry; the event worker does not repeatedly introspect a stored employee bearer token. Verify unsubscribe, expiry, and revoked mailbox access independently when qualifying events.

## Qualification before wider access

Use a controlled test realm, two fictional/sample employee accounts, and non-sensitive mailboxes. Keep raw token inspection local and restricted; a JWT payload is personal/security data even though decoding it does not require a secret.

1. Check the exact issuer and resource metadata from every configured hostname. Confirm client registration, redirects, PKCE, CA trust, and runtime reachability.
2. Sign in as Alice with only `mail.read`. Verify `mail_profile` resolves Alice's enrolled mailbox and a read returns only approved data.
3. Sign in as unenrolled or IdP-denied Bob. Confirm rejection. Verify Alice cannot select Bob by supplying an email address or reusing Bob's handle.
4. Exercise wrong issuer/audience/client ID, missing `Bearer` payload type, missing `mail.read`, and introspection mismatches in the local test harness or test realm. Each must fail before mailbox work.
5. For automatic enrollment, test a disabled AD account, missing/noncanonical GUID, a conflicting mapping, a changed primary SMTP address, and unavailable LDAPS. Confirm rejection and preserve the existing registry.
6. Revoke the test session/grant, then make a new request with the old token. Record the IdP introspection result and MCP rejection separately from browser logout.
7. Only then qualify write switches, recipient restrictions, native confirmation or the explicit OAuth send-grant path, refresh, delegated features, and optional events.

The included checks use controlled JWT, introspection, LDAP, and EWS fixtures. Passing them does not prove a live IdP, Exchange permission assignment, hosted callback, or browser SSO deployment.

## Troubleshooting without exposing credentials

| Symptom | Check |
| --- | --- |
| Startup rejects Service settings | HTTPS issuer/resource, valid secret file, nonempty approved client list, enrollment settings, audit path, and bounded numeric limits. |
| Browser login succeeds but MCP returns 401 | Verify an access token was sent; inspect `iss`, host-specific `aud`, header/payload types, `azp`, expiry, and the exact introspection comparison. |
| Token works on one hostname only | Compare `Resource`/`PublicResource`, receiving `Host`, proxy-preserved host, and the audience issued for that hostname. |
| 401 after IdP outage or secret rotation | Verify service-to-IdP TLS/connectivity and the mounted introspection secret. The fail-closed check has no successful-status cache. |
| 403 after successful login | Check `mail.read`, enrollment, required operation scope, and server write/send switches. Origin rejection can also return 403. |
| EWS access denied | Check the separate service identity and scoped Exchange rights. Changing browser/IdP credentials does not repair EWS authorization. |
| Automatic enrollment rejected | Check canonical GUID in both token copies, current AD object state, primary SMTP/domain, collision state, LDAPS trust, and first-enrollment Inbox rights. |
| Repeated sign-in or unsupported continuation | Test the actual host's refresh behavior and supported registration method; preserve current credentials instead of repeatedly deleting/recreating the connection. |

For evidence, retain sanitized UTC timestamps, HTTP/RPC outcomes, tracking IDs, and the relevant configuration field names. Do not publish Authorization headers, tokens, passwords, secrets, keytabs, or mailbox contents.

## Implementation references

The enforceable behavior is in [AppHost.cs](../src/Company.ExchangeMcp/AppHost.cs), [ServiceOptions.cs](../src/Company.ExchangeMcp/Security/ServiceOptions.cs), [KeycloakTokenStatus.cs](../src/Company.ExchangeMcp/Security/KeycloakTokenStatus.cs), [MailboxAccess.cs](../src/Company.ExchangeMcp/Security/MailboxAccess.cs), [MailboxEnrollment.cs](../src/Company.ExchangeMcp/Security/MailboxEnrollment.cs), and [ConnectionTools.cs](../src/Company.ExchangeMcp/ConnectionTools.cs). The public [example settings](../appsettings.example.json) contain placeholders, not a ready-to-run identity deployment.
