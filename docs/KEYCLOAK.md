# Keycloak administrator setup

This is the concrete setup path for the Keycloak-shaped authentication implemented by `exchange-mcp`. Read the [identity contract](IDENTITY-PROVIDER.md) first. The application Compose file does not install or configure Keycloak, AD federation, Kerberos, client registrations, or an IdP database.

Use an already operated Keycloak deployment with HTTPS, backups, a known administrator, and an approved employee access policy. Start in a test realm with a read-only pilot. The example realm is `company`, the issuer is `https://identity.example.test/realms/company`, and the MCP resource is `https://mail.example.test/mcp`. Every `.example.test` value is a placeholder.

Before changing a production realm, capture its existing realm/client/mapper settings and a usable database/configuration backup using your established process. Keep the previous client definitions and secret mounts recoverable. Complete the read-only validation at the end before wider access.

## 1. Establish the realm and HTTPS issuer

In the Admin Console, select the intended realm or create `company`. Confirm the discovery document is reachable from both the MCP service and the actual client runtime:

```text
https://identity.example.test/realms/company/.well-known/openid-configuration
```

Its `issuer` must be exactly the value configured in `Service.Authority`. Verify the published authorization, token, and JWKS endpoints use the intended public/canonical HTTPS names and that PKCE `S256` is advertised. Correct Keycloak hostname/proxy settings at the IdP; the MCP service does not rewrite its metadata.

Keep the existing browser authentication/MFA policy. Use persistent employee sessions for the features that need refresh or a session-bound `sid`. A successful discovery request proves metadata delivery only, not employee login or mailbox access.

## 2. Connect the approved AD users when automatic enrollment is wanted

For a static pilot, a verified `sub` to mailbox mapping can be used without automatic AD enrollment. For automatic enrollment, the IdP must issue the employee's trusted, immutable AD GUID, and the MCP service independently verifies that GUID through LDAPS.

In **User federation → Add provider → ldap**, configure the approved AD source. Use these as example field values, not an importable production configuration:

| Field | Example or decision |
| --- | --- |
| Vendor | Active Directory |
| Connection URL | `ldaps://dc.example.test:636` |
| Users DN | `OU=People,DC=example,DC=test`, or your approved bounded search base |
| Bind identity | A dedicated directory-read account managed by the IdP operator |
| Edit mode | `READ_ONLY` |
| Username LDAP attribute | The organization's established login attribute, commonly `sAMAccountName` |
| UUID LDAP attribute | `objectGUID` |
| Search scope/filter | Only the employee population approved to use this service |
| TLS trust | The issuing CA chain for the directory certificate, with hostname validation |

For example, a custom LDAP filter `(memberOf=CN=exchange-mcp-users,OU=Groups,DC=example,DC=test)` restricts direct membership in that example group. It does not itself implement nested-group expansion. Use and test the organization's intended membership rule; do not assume that importing all enabled AD users is authorization for MCP access.

Use **Test connection**, **Test authentication**, and a bounded user sync/search. Prove Alice can authenticate and that an out-of-scope Bob cannot. Do not change AD passwords or broaden an existing federation just to complete this setup. Keycloak's [LDAP federation guide](https://www.keycloak.org/docs/latest/server_admin/index.html#_ldap) documents the provider and mapper controls.

The MCP service's `DirectoryPermissions` section is separate from this federation. Its built-in LDAP reader uses the configured Exchange service identity and password over LDAPS; configuring Keycloak's bind account does not configure the MCP service.

## 3. Map the AD GUID into a trusted token claim

Two mappings are needed: AD to the Keycloak user model, then that user model value to the OIDC access token and introspection response.

In the LDAP provider's **Mappers**, create a **user-attribute-ldap-mapper**:

| Setting | Value |
| --- | --- |
| User Model Attribute | `ad_object_guid` |
| LDAP Attribute | `objectGUID` |
| Read Only | On |
| Always Read Value From LDAP | On |
| Is Mandatory In LDAP | On for the auto-enrollment population |
| Is Binary Attribute | On |
| Decode Binary Attribute As, when available | `uuid` |

Verify the resulting value is one lowercase, hyphenated, nonzero GUID. Existing Keycloak binary mappers may retain base64 decoding after an upgrade; explicitly inspect the mapper instead of relying on a default. The [Keycloak 26.7.2 upgrade notes](https://www.keycloak.org/docs/26.7.2/upgrading/) explain `auto`, `base64`, and `uuid` decoding and the migration behavior. If your version lacks that control, qualify its equivalent mapping before enabling automatic enrollment.

Create an OIDC client scope named `exchange-mcp-identity`, then add a **User Attribute** protocol mapper:

| Setting | Value |
| --- | --- |
| User Attribute | `ad_object_guid` |
| Token Claim Name | `ad_object_guid` |
| Claim JSON Type | `String` |
| Multivalued | Off |
| Add to access token | On |
| Add to token introspection | On |
| Add to ID token / UserInfo | Only if separately needed by your IdP design; MCP authorization does not require them |

Attach this identity scope as a default scope to each approved employee OAuth client. It need not add its own name to the token's `scope` string. Ensure the source user attribute is not editable by end users, registration forms, or untrusted identity brokers. Do not hardcode a shared GUID. Keycloak's [protocol-mapper reference](https://www.keycloak.org/admin-api/protocol-mappers) describes user-attribute and audience mapper fields.

For a static-only pilot, the GUID mapper is optional. If a GUID is included in a JWT, however, introspection must include its exact matching value even in static mode.

## 4. Create the confidential introspection client

In **Clients → Create client**, select **OpenID Connect** and use the exact resource URL as the client ID:

```text
https://mail.example.test/mcp
```

Turn **Client authentication** on. This client authenticates the service's introspection POST; it does not perform employee browser login. Leave Standard Flow, Implicit Flow, Direct Access Grants, and Service Accounts off when they are not otherwise required. No service-account access token is needed for the introspection request.

From the client's **Credentials** tab, save the secret directly to the service's protected secret storage and mount it as `/run/secrets/keycloak_introspection`. Set:

```json
{
  "Service": {
    "IntrospectionClientId": "https://mail.example.test/mcp",
    "IntrospectionSecretFile": "/run/secrets/keycloak_introspection"
  }
}
```

This is a partial fragment. Do not put the literal secret in JSON, a Compose environment variable, a client package, or chat. The mounted file contains the secret value itself. Preserve existing credentials until a controlled rotation has been validated.

Keycloak permits introspection by confidential clients. Its currently documented audience check also requires the introspecting client to be in the access-token audience. This guide makes that client ID equal to the resource URL; the audience mapper in the next step satisfies both checks. A separate introspection client ID is possible, but then both that ID and the resource URL must appear in each relevant token and in the matching introspection response. See [Keycloak's OIDC endpoints](https://www.keycloak.org/securing-apps/oidc-layers#introspection-endpoint) and [audience rules](https://www.keycloak.org/docs/latest/server_admin/index.html#_audience).

## 5. Define mailbox scopes and the resource audience

Create OIDC client scopes named `mail.read`, `mail.write`, `mail.manage`, and `mail.send`. Enable **Include in token scope** for each. The application checks those exact strings in the access token; a realm role with the same display name does not substitute for a scope.

For the pilot employee clients, attach `mail.read` as a default scope. Attach only approved additional mailbox scopes as optional scopes, or according to an explicitly chosen least-privilege client policy. Do not add them as realm-wide defaults for unrelated clients. Creating the scopes does not enable application writes or grant Exchange permissions.

On `exchange-mcp-identity`, or another default scope attached to every approved employee client, add an **Audience** mapper:

| Setting | Value |
| --- | --- |
| Included Client Audience | The confidential client `https://mail.example.test/mcp` |
| Add to access token | On |
| Add to token introspection | On |
| Add to ID token | Off unless separately required |

Use **Evaluate** for each employee client to inspect the effective access-token shape. Confirm `aud` includes the exact resource URL and that the complete audience/scope sets are the same in introspection. Audience additions intended only for introspection will fail this server's equality check.

If using `PublicResource: https://mail-public.example.test/mcp`, add an additional audience mapper with that exact **Included Custom Audience**, again in both access token and introspection. Tokens for that receiving hostname must include its public audience. The private and public resource paths must match. Do not add a broad wildcard audience or disable validation.

## 6. Register the actual employee-facing clients

Keep this registration separate from the confidential introspection client.

### A pre-registered Codex client

Create an OIDC client with ID `exchange-mcp-codex`. For a local public client, set **Client authentication** off, **Standard Flow** on, and require PKCE `S256` in the client's advanced settings. Disable Implicit Flow and Direct Access Grants. Attach the approved scopes, resource audience, and optional GUID mapper from the preceding steps.

Use the client setup procedure in [CLIENTS.md](CLIENTS.md#codex-and-local-desktop-clients) to obtain the actual redirect URI. Paste the exact callback shown by the installed client into **Valid redirect URIs**. It may use a client-specific callback path and a selected loopback port. Do not assume `/callback`, invent a port, use an unrestricted `*`, or substitute the MCP resource URL. Qualify the actual loopback port handling with your installed versions.

Add `exchange-mcp-codex` to the service's `AllowedClientIds`. The `azp` claim must contain that exact ID. If you use another approved client ID, normal access can work, but the release's optional connection-continuation helper has its own fixed client policy.

### ChatGPT or another hosted client

Choose a registration mechanism that the deployed IdP and host actually support:

| Mechanism | Required administrative action |
| --- | --- |
| Pre-registration | Create an OIDC employee client, for example `company-exchange-chatgpt`; supply its ID and, when required by the selected host flow, its secret through the host's supported secure setup. Use the host-displayed redirect and a token authentication method supported by both sides. |
| CIMD | Verify actual IdP support for fetching/validating a Client ID Metadata Document, supported token-endpoint authentication, approved scopes/audiences/mappers, and redirect validation. An advertised metadata flag alone is not an implementation. |
| DCR | Verify and constrain the IdP registration service and each generated client's policy. Arrange explicit approval of every actual generated client ID in `AllowedClientIds`; the MCP server does not auto-enroll OAuth clients. |

Plain OIDC discovery and Keycloak's client-registration endpoint do not, by themselves, prove CIMD support in your deployed Keycloak build. This repository includes no CIMD provider or authorization proxy. Use pre-registration for a predictable baseline when native/installed IdP support has not been demonstrated. Keycloak documents its distinct [client-registration service and policies](https://www.keycloak.org/securing-apps/client-registration).

For ChatGPT, copy both the exact redirect URI and, for CIMD, the exact client-metadata URL from the connection's management page. Issuer-bound and callback-specific modes differ. Add the actual resulting `azp` to `AllowedClientIds`; do not infer it from the product name. The stable ChatGPT CIMD ID `https://chatgpt.com/oauth/client.json` has specific continuation and sending behavior in this release; a pre-registered or callback-specific client does not silently inherit those paths. See [CLIENTS.md](CLIENTS.md#chatgpt-hosted-connections).

## 7. Configure the service and choose enrollment

Merge the following fields into the complete service configuration for an automatic-enrollment, read-only pilot:

```json
{
  "Service": {
    "Authority": "https://identity.example.test/realms/company",
    "Resource": "https://mail.example.test/mcp",
    "PublicResource": "",
    "IntrospectionClientId": "https://mail.example.test/mcp",
    "IntrospectionSecretFile": "/run/secrets/keycloak_introspection",
    "AllowedClientIds": ["exchange-mcp-codex"],
    "AutoEnrollmentEnabled": true,
    "Mailboxes": {},
    "AllowedRecipientDomains": ["example.test"],
    "WritesEnabled": false,
    "SendEnabled": false
  },
  "DirectoryPermissions": {
    "Host": "dc.example.test",
    "Port": 636,
    "BaseDn": "DC=example,DC=test",
    "TimeoutSeconds": 8
  }
}
```

Also configure the existing Exchange service credential, EWS endpoint, audit/state storage, TLS termination, and trusted proxy settings as described by the repository's deployment guidance. The fragment alone cannot start a complete deployment.

For static enrollment instead, set `AutoEnrollmentEnabled` false and add Alice's verified `sub` to `Mailboxes` with `alice@example.test`. A GUID alone does not authorize a static mapping; a username/email claim does not discover a mapping. See the [full enrollment checks](IDENTITY-PROVIDER.md#enroll-the-correct-mailbox).

## 8. Optional integrated Windows browser SSO

LDAP federation is not automatically Kerberos SSO. If integrated Windows login is a deployment requirement, have the AD/IdP administrators:

1. Confirm DNS, AD realm, synchronized clocks, and the actual HTTPS hostname used for browser login.
2. Register the matching `HTTP/identity.example.test` service principal to the intended AD service identity and provision its matching keytab securely to Keycloak. Resolve duplicate SPNs or key/version mismatches first.
3. Configure Kerberos authentication on the LDAP federation provider, including the service principal, realm, and keytab location.
4. Copy the Browser authentication flow, enable its Kerberos execution with the intended fallback/MFA policy, and bind the tested flow to the intended realm/client scope.
5. Configure managed browsers to trust that IdP hostname for integrated authentication. Test a domain-joined browser and a browser without a usable Kerberos ticket separately.
6. Verify actual employee OIDC login, correct token identity, and an authenticated MCP read. An HTTP `Negotiate` challenge alone is not end-to-end SSO proof.

Keep fallback policy deliberate; do not weaken an existing authentication flow to remove prompts. Follow the official [Keycloak Kerberos guide](https://www.keycloak.org/docs/latest/server_admin/index.html#_kerberos) for the deployed version. This browser SSO setup does not replace or forward the MCP service's EWS/LDAPS credentials.

## 9. Optional continuation and session policy

First validate the host's normal access-token refresh behavior. If the organization permits optional offline access, attach `offline_access` only to the intended clients and approve the corresponding user/role/session policy. Inspect client and realm idle/max lifetimes, refresh-token rotation, and offline-grant revocation. Set those values from policy, not from a promised connection duration.

The release exposes `mail_request_connection_continuation` for `exchange-mcp-codex` and the exact stable ChatGPT CIMD client only. It can request normal host consent; it cannot store a host's refresh token or prove persistent sign-in. A pre-registered `company-exchange-chatgpt` client receives `unsupported_client` from that helper even if its ordinary OAuth connection and refresh work.

Test refresh after the original access token expires, then revoke the grant and prove subsequent rejection. Browser logout and offline-grant revocation are separate tests. Do not advertise a fixed multi-day session solely because `offline_access` appears in a token.

## 10. Validate and retain rollback

Use the read-only qualification sequence in [IDENTITY-PROVIDER.md](IDENTITY-PROVIDER.md#qualification-before-wider-access). Record the tested Keycloak/client versions and sanitized UTC times. At minimum verify:

- Exact issuer, PKCE, callback, client ID, resource audience, and matching JWT/introspection scope sets.
- Alice's `mail_profile` and mailbox read; rejection for an unenrolled or IdP-denied Bob.
- For automatic enrollment, the AD GUID, current enabled user-mailbox state, primary SMTP/domain, EWS Inbox rights, persisted enrollment, and restart behavior.
- Revoked/expired token rejection and fail-closed behavior when introspection or LDAPS is unavailable.
- Actual host refresh, UI, confirmation, and event behavior separately when those features are required.

For rollback, restore the prior realm/client/mapper configuration and the matching mounted secret using your established IdP/service process. Keep the service's prior enrollment/state/protection-key data intact. Recheck metadata, the original read path, and revocation. Do not delete users, regenerate all client secrets, or discard the enrollment registry as a troubleshooting shortcut.

No deployment, browser SSO, real mailbox access, hosted refresh, or event callback is established merely by following these examples or passing the local fixture checks. Each is an operator qualification result.
