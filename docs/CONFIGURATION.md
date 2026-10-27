# Configuration reference

Start from [appsettings.example.json](../appsettings.example.json), copy it to the private `appsettings.Local.json`, and replace every placeholder. Follow [DEPLOYMENT.md](DEPLOYMENT.md) for mounts, ownership, TLS, and startup checks. This reference describes the validation in the release source; it does not provision identity, Exchange rights, or network connectivity.

## Loading and change application

The application uses normal ASP.NET Core configuration, explicitly loads optional `appsettings.Local.json` from the application working directory, and reapplies environment variables afterward. The supplied Compose file mounts the local file read-only at `/app/appsettings.Local.json` and uses `/app` as the image's working directory. Environment variables override corresponding local-file values.

Use double underscores for nested environment keys, for example `Service__WritesEnabled=false` or `Exchange__TimeoutSeconds=30`. Do not place credential values in environment variables; configure secret-file paths instead. For arrays/maps, prefer one reviewed local JSON file so an override does not accidentally leave additional configured entries from another provider.

The local file is loaded with `reloadOnChange: false`, and the implementation uses settings captured by services. Treat configuration and secret changes as a controlled restart/recreate operation. Replacing a bind-mounted file atomically on the host may leave a running container bound to the old file inode; recreate the service to confirm it reads the new mount. Never assume a file edit alone activated a policy or rotated a credential.

Startup validates the `Service`, `Exchange`, and `DirectoryPermissions` sections. A syntactically valid Compose file does not establish valid application JSON/settings, a reachable IdP, or valid EWS credentials. Those checks occur at different stages.

## Service identity and ingress

| `Service` key | Shipped example | Validation / behavior |
| --- | --- | --- |
| `Authority` | `https://identity.example.test/realms/company` | Required absolute HTTPS issuer, without user info, query, or fragment. Must exactly match issued `iss`. OIDC discovery/JWKS and fixed-path Keycloak introspection use this authority. |
| `Resource` | `https://mail.example.test/mcp` | Required absolute HTTPS resource/audience. Use the canonical client URL, including its path. |
| `PublicResource` | Empty | Optional second HTTPS resource. Its absolute path must equal `Resource` and its authority must differ. It adds host/audience recognition, not public ingress. |
| `IntrospectionClientId` | `https://mail.example.test/mcp` | Required confidential resource/introspection client ID. Distinct from the employee-facing client's `azp`. Include this ID in audiences when required by Keycloak. |
| `IntrospectionSecretFile` | `/run/secrets/keycloak_introspection` | Required existing file, 1–8,192 bytes at startup. Contains the secret itself, not JSON. Trailing CR/LF are removed when read. |
| `AllowedClientIds` | `exchange-mcp-codex` and the stable ChatGPT CIMD URL | Required nonempty list of nonblank, exact, case-sensitive `azp` values. Remove clients you have not actually approved/configured. DCR/CIMD registration does not add them automatically. |
| `AllowedOrigins` | `[]` | Each entry must be an HTTPS URL; use exact browser origins (`scheme://host[:port]`). Every supplied `Origin` is checked. With an empty list, requests without the header can proceed but requests carrying an origin are rejected. No wildcards or general CORS setup are provided. |
| `TrustedProxyAddresses` | `[]` | Exact literal IP addresses of approved immediate proxies. Enables one hop of `X-Forwarded-For` and `X-Forwarded-Proto` processing. `X-Forwarded-Host` is not consumed: preserve the actual `Host`. No proxy subnet wildcard is configured. |
| `AuditPath` | `/app/audit/operations.jsonl` | Required private writable audit path. Related state paths are derived from it; changing it changes the state namespace. Keep it on the persistent mount. |

The JWT must contain the resource audience selected by the receiving `Host`, as well as pass ordinary configured-audience validation. Unknown hosts are rejected, apart from the bounded loopback case in code. Non-HTTPS requests are rejected except `/health/live`. Do not work around proxy failures by trusting every source or disabling TLS validation. See [the complete token and introspection contract](IDENTITY-PROVIDER.md#exact-access-token-requirements).

The stable ChatGPT CIMD ID is exactly `https://chatgpt.com/oauth/client.json`. It has specific continuation/send behavior in code; a pre-registered ID, another CIMD path, or a vendor display name does not substitute for it.

## Enrollment and recipient policy

| `Service` key | Shipped example | Validation / behavior |
| --- | --- | --- |
| `Mailboxes` | `{"replace-with-alice-sub":"alice@example.test"}` | Map a verified IdP subject to one primary SMTP mailbox. Keys must be nonblank; values must be valid exact mailbox addresses. At least one mapping is required unless automatic enrollment is enabled. The shipped placeholder is not a real enrollment. |
| `AutoEnrollmentEnabled` | `false` | If true, require the trusted canonical `ad_object_guid` claim, configured valid LDAPS, nonempty allowed domains, current supported AD user-mailbox state, collision checks, first-use EWS Inbox read proof, and durable registry persistence. Existing static entries do not bypass this path. |
| `AllowedRecipientDomains` | `[]` | DNS domain strings, without `@`, URLs, or wildcards. Exact domain comparison is case-insensitive; subdomains are not implicitly included. Also bounds primary SMTP domains for automatic enrollment. Required nonempty for automatic enrollment. |
| `AllowExternalRecipients` | `false` | If false, calls using the recipient-policy helper reject addresses outside `AllowedRecipientDomains`. If true, that domain restriction is relaxed, while address validation and all other gates remain. It does not relax automatic-enrollment domain checks. |
| `MailboxTargets` | Omitted | Legacy compatibility field only. Accepted for old configuration parsing; it does not authorize or select delegated mailboxes. Use current permission discovery and returned handles. |

With the unchanged empty recipient-domain list and external recipients disabled, recipient-checked operations can be rejected even while read-only mailbox access works. Configure intended domains deliberately before qualifying meeting/room or mutation workflows that validate participant addresses. Do not enable external recipients as a generic fix.

Automatic enrollment stores `<AuditPath>.enrollments.json`. The binding is issuer/subject/AD-GUID/primary-mailbox specific, with live checks on later authenticated MCP requests. A changed mailbox address or GUID requires an operator-reviewed migration; the service does not silently rebind by email claim. [IDENTITY-PROVIDER.md](IDENTITY-PROVIDER.md#enroll-the-correct-mailbox) specifies the supported AD attributes and checks.

## Write and transmission gates

| `Service` key | Shipped example | Behavior |
| --- | --- | --- |
| `WritesEnabled` | `false` | Required for operations using `mail.write`, `mail.manage`, or `mail.send`. Also gates the optional background task-notice processor. |
| `SendEnabled` | `false` | Additional gate for tools requiring `mail.send`. Can be true only when writes are enabled and either external recipients are permitted or at least one allowed recipient domain exists. |

The employee token must independently contain the operation's scope. The EWS service account's impersonation scope and the employee's target rights are separate gates. A broad service account, an IdP role, or a client-side approval setting does not authorize the employee to use another mailbox.

The exact stable ChatGPT CIMD ID uses the implemented OAuth send-grant path. Other clients normally need native form elicitation on MRTR/stateful MCP, unless the narrowly configured grant below applies. Some protected management actions still need native confirmation. Read [CLIENTS.md](CLIENTS.md#write-actions-and-human-confirmation) before enabling mutable use.

### Optional narrowly configured standing grant

These keys are omitted from the example and disabled by empty defaults. They are not required for ordinary setup:

| `Service` key | Disabled value | Valid enabled configuration |
| --- | --- | --- |
| `SendWithoutNativeConfirmationActor` | Empty string | One mailbox address present exactly once in the static map; automatic enrollment must be enabled. |
| `SendWithoutNativeConfirmationMailboxes` | `[]` | Exactly two distinct valid mailbox addresses, including the actor. |
| `SendWithoutNativeConfirmationClientIds` | `[]` | One or two distinct IDs already present in `AllowedClientIds`. |

The whole set must be disabled together or satisfy that strict combination. The runtime additionally checks the current actor, target, existing rights, recipients all belonging to the configured pair, current draft/revision, and replay protection. This is a prior-authorization policy, not a mailbox grant. Do not enable it merely because a host cannot show a native confirmation form.

## Optional background task-notice processing

The example leaves both settings disabled. This worker is separate from own-Inbox MCP events and their Exchange streaming path.

| `Service` key | Shipped example | Validation / behavior |
| --- | --- | --- |
| `TaskNoticeProcessingAllEnrolledUsers` | `false` | Opts the background task-notice processor into the enrolled-actor set, subject to its bounded discovery and current permission checks. Requires writes enabled to run. |
| `TaskNoticeProcessingActors` | `[]` | At most 16 distinct valid mailbox addresses; each must occur exactly once among static `Mailboxes` values. Enables the named actor set when writes are enabled. |

When enabled, the worker uses a bounded 30-second task-notice processing cadence and private `<AuditPath>.task-notices.json` state. This is not a substitute for `email.received` subscriptions and does not prove host awareness. Review the [task workflow limits](FEATURES-AND-LIMITATIONS.md) before enabling it; do not discard uncertain legacy/processor state to force work to resume.

## Admission and concurrency

These are application limits, distinct from Docker CPU/memory/process limits and external IdP/Exchange limits. They are local to one process, not distributed across replicas.

| `Service` key | Default/example | Accepted range | Purpose |
| --- | --- | --- | --- |
| `RequestsPerMinute` | `60` | 1–1,000 | Per-identity parsed mailbox-operation budget. |
| `ConcurrentRequests` | `8` | 1–64 | Global active mailbox-work budget; also contributes to large-payload work limits. |
| `ConcurrentRequestsPerUser` | `2` | 1–8 | Per-identity active work/payload budget. |
| `TransportRequestsPerMinute` | `600` | 1–10,000 | Per-identity authenticated transport/authentication request rate. |
| `ConcurrentTransports` | `64` | 1–256 | Non-streaming transport and pre-authentication capacity. Streaming and authentication also have separate bounded limits in code. |

The implementation separates transport, authentication, streaming, payload, and operation admission. A long-lived stream should not be interpreted as one available mailbox-operation slot. Rejections carry bounded retry information and tracking metadata. Respect 429/retry responses; do not reconnect OAuth or remove limits to evade them.

The reference Compose file sets a 1 GiB memory limit, 2 CPUs, and 256 PIDs. Those are example resource bounds, not a qualified user count or throughput commitment. Test representative reads, EWS latency, introspection latency, writes, and subscribed Inboxes before expanding enrollment.

## Exchange backend settings

| `Exchange` key | Shipped example | Validation / behavior |
| --- | --- | --- |
| `Endpoint` | `https://exchange.example.test/EWS/Exchange.asmx` | Required absolute HTTPS endpoint without embedded credentials, query, or fragment under startup validation. This service does not run Autodiscover. |
| `Username` | `svc_exchange_mcp` | Required separate service identity. EWS uses configured credentials, not the employee's OAuth token. |
| `Domain` | `EXAMPLE` | Authentication domain; may be empty where the chosen identity format/backend supports it. Do not prepend a second conflicting domain to the username. |
| `PasswordFile` | `/run/secrets/exchange_password` | Required existing 1–8,192-byte secret file at startup. Trailing CR/LF are removed when read; preserve the actual credential value. Also used by the built-in LDAPS bind. |
| `TimeoutSeconds` | `30` | Application startup accepts 1–120 seconds. This is the effective deployment validation boundary. |
| `MaxResponseBytes` | `16777216` | 1,024–16,777,216 bytes. Bounded SOAP response size, not a promise of attachment upload or full-mailbox export capacity. |

The Docker image includes the native GSS-NTLM mechanism needed by its Linux authentication path. Backend certificates remain validated. Supply the relevant operator-approved CA certificates before building when private PKI is used; do not install an accept-all certificate callback or use a leaf certificate as a replacement for the issuing CA trust chain.

The SOAP requests use the `Exchange2016` schema identifier and impersonate the authenticated actor mailbox. Delegated target access is then evaluated separately. A schema identifier or reachable EWS URL is not proof that every native recall/task/meeting workflow works on a particular server build. Qualify the required operations against the actual Exchange environment.

## Directory settings

An entirely empty/default section disables directory lookup. An incomplete section is invalid.

| `DirectoryPermissions` key | Shipped example | Validation / behavior |
| --- | --- | --- |
| `Host` | Empty | When configured, a DNS hostname, trimmed length 1–253, without `/`, `\`, `:`, or control characters. Use the certificate hostname, not an arbitrary IP alias. |
| `Port` | `636` | Exactly 636; the built-in reader uses LDAPS. |
| `BaseDn` | Empty | Required when configured; trimmed nonempty DN, at most 1,024 characters with no control characters. Bound it to the intended directory scope. |
| `TimeoutSeconds` | `8` | 1–30 seconds when configured. The disabled section retains defaults 636/8 with empty host/base. |

The reader uses LDAPv3, TLS certificate/hostname verification, no referral chasing, and a Basic bind over LDAPS using the Exchange service credentials. Configure those credentials and directory rights accordingly. Keycloak's independent LDAP federation account is not read by this service.

Automatic enrollment requires this section. Directory-dependent delegated rights/discovery fail closed or report unknown when it is disabled/unavailable. Current directory data, supported Exchange recipient metadata, effective EWS rights, and separate sender rights all matter; a successful bind is not proof of delegated authorization.

## Paths, persistence, and logs

Keep the entire `state/` mount private and persistent. With the example `AuditPath`, relevant paths include:

| Container path | Purpose |
| --- | --- |
| `/app/audit/operations.jsonl` | Append-only bounded operation/HTTP/resource metadata audit. |
| `/app/audit/operations.jsonl.enrollments.json` | Automatic identity bindings, when enabled. |
| `/app/audit/operations.jsonl.mcp-state/` | Local protection key and durable approval/replay state. |
| `/app/audit/operations.jsonl.mail-events/` | Encrypted event/subscription state and its key. |
| `/app/audit/operations.jsonl.task-notices.json` | Optional task-notice processing state. |

Signatures/onboarding are stored in Exchange UserConfiguration; they are not restored by replacing this directory. Some short-lived handles, preview references, and process caches have their own restart behavior. Read the [deployment restart/restore guidance](DEPLOYMENT.md#persistence-backup-and-restore).

Do not recursively apply group-readable permissions to all state files: protection keys are required to remain private, and an over-broad key mode can cause startup rejection. Preserve generated file modes and owners. Encryption does not protect files from an operator who also has the keys; host and backup access remain a trust boundary.

The supplied Compose log rotation applies to Docker stdout/stderr only (`json-file`, 10 MiB × 3). It does not rotate `operations.jsonl`. Establish a tested audit retention/reopen/rotation process without truncating live replay or state files. Do not log tokens, credential values, email bodies, or arbitrary request payloads at the proxy or framework level for troubleshooting.

## Source references

The settings and gates are implemented in [ServiceOptions.cs](../src/Company.ExchangeMcp/Security/ServiceOptions.cs), [DirectoryPermissionOptions.cs](../src/Company.ExchangeMcp/Security/DirectoryPermissionOptions.cs), [AppHost.cs](../src/Company.ExchangeMcp/AppHost.cs), [RequestAdmission.cs](../src/Company.ExchangeMcp/Security/RequestAdmission.cs), and [EwsOptions.cs](../src/Company.ExchangeMcp/Exchange/EwsOptions.cs). The [IdP guide](IDENTITY-PROVIDER.md) defines the strict claim/introspection contract; [FEATURES-AND-LIMITATIONS.md](FEATURES-AND-LIMITATIONS.md) describes the exposed workflow boundaries.
