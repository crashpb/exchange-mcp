# Linux Docker Compose deployment

This guide deploys one `exchange-mcp` instance from the reviewed source tree. It uses the supplied [compose.yaml](../compose.yaml), whose only service is `mcp`. It does not deploy Keycloak, Exchange, AD, DNS, a reverse proxy, or client accounts. Read [IDENTITY-PROVIDER.md](IDENTITY-PROVIDER.md), [KEYCLOAK.md](KEYCLOAK.md), and [SECURITY.md](../SECURITY.md) before connecting real mail.

Commands below are operator instructions for an explicitly chosen Linux host, not evidence that a deployment has already been performed. Use an isolated read-only pilot first. Keep the deployment in one dedicated directory; the examples use `/srv/exchange-mcp`. All `.example.test` names are placeholders and cannot be used as production DNS/certificate names.

## 1. Confirm the prerequisites and boundaries

| Requirement | Before starting |
| --- | --- |
| Linux host | A maintained Docker Engine installation and Compose v2, enough disk for source/image/private state/backups, and an operator authorized to manage the service. Use Docker's [distribution-specific installation guide](https://docs.docker.com/engine/install/). |
| Source | A reviewed source release and its checksum/provenance. This package does not publish or require a prebuilt container image. |
| IdP | HTTPS issuer, correct metadata/JWKS, employee Authorization Code + PKCE, approved client IDs, scopes/audience, confidential introspection credentials, and tested employee policy. |
| Exchange | Trusted HTTPS EWS endpoint and a dedicated service account. An Exchange administrator must establish the scoped impersonation rights needed for approved actor mailboxes and validate the required operations. Do not use a Domain Admin account. |
| AD when needed | LDAPS hostname/CA trust, TCP 636, bounded search base, and the service account's directory read rights. Automatic enrollment and permission-backed delegated discovery require it. |
| Ingress | Operator-controlled DNS, a trusted HTTPS certificate, and a reverse proxy on the host or another deliberately isolated topology. The reference Compose port is host-loopback only. |
| Outbound network | Container access to IdP discovery/JWKS/introspection, EWS, and LDAPS if configured. Events also require public HTTPS callback egress. Build-time access to the base-image registry, NuGet, and Ubuntu package repositories is separate. |
| Client | A host with compatible Streamable HTTP and OAuth; actual runtime reachability and callback registration. UI/forms/events/refresh must be qualified independently. |
| Rollback | Protected configuration/secrets, durable state with its keys, the previous image, and a tested restore procedure. Wider mutable use must not begin with an untested backup. |

EWS and IdP roles are independent. The code impersonates the authenticated employee actor in EWS and separately checks access to a delegated target. Broad backend rights do not replace those human access checks. A successful TCP/TLS probe, directory bind, or EWS login is not proof of the intended mailbox operation.

Use **one replica and one active signature writer**. The local state, admission limits, preview/session references, and Exchange UserConfiguration update guards do not provide distributed locking. This reference is not an HA design.

## 2. Prepare an empty deployment directory

Unpack the reviewed source so `Dockerfile`, `compose.yaml`, and `appsettings.example.json` are directly in `/srv/exchange-mcp`. Use a clean source export; do not copy a private repository's history, local credentials, logs, or live mailbox evidence. Check the release checksum through your normal trusted channel.

From this point, run Compose commands in that exact directory:

```sh
cd /srv/exchange-mcp
docker --version
docker compose version
```

The reference container runs as numeric UID/GID `1654:1654`, with a read-only root filesystem, dropped capabilities, no-new-privileges, a bounded `/tmp`, and a private persistent state bind mount. Keep those settings while qualifying the pilot. Rootless engines or user-namespace remapping need an explicit host-ID ownership review; the following ownership commands assume a normal rootful Linux Docker deployment.

## 3. Create private configuration, secrets, and state

**The initialization below is for a new installation only.** Confirm `appsettings.Local.json` and both secret files do not already exist. Do not run empty-file initialization over a working installation; reuse its protected files and capture a backup before editing them.

```sh
sudo install -d -m 0700 -o 1654 -g 1654 state secrets
sudo install -m 0640 -o root -g 1654 appsettings.example.json appsettings.Local.json
sudo install -m 0640 -o root -g 1654 /dev/null secrets/keycloak_introspection
sudo install -m 0640 -o root -g 1654 /dev/null secrets/exchange_password
sudoedit appsettings.Local.json secrets/keycloak_introspection secrets/exchange_password
sudo chown root:1654 appsettings.Local.json secrets/keycloak_introspection secrets/exchange_password
sudo chmod 0640 appsettings.Local.json secrets/keycloak_introspection secrets/exchange_password
```

Fill each secret file with only its existing credential value, without JSON wrappers or shell quotes. The application removes trailing CR/LF; preserve other credential characters and spaces. Use your established secret-manager/editor workflow and avoid command-line `echo`, shell history, environment dumps, or chat. Empty files are intentionally invalid and prevent startup.

The Compose mounts are:

| Host path | Container path | Access |
| --- | --- | --- |
| `appsettings.Local.json` | `/app/appsettings.Local.json` | Read-only |
| `secrets/keycloak_introspection` | `/run/secrets/keycloak_introspection` | Read-only |
| `secrets/exchange_password` | `/run/secrets/exchange_password` | Read-only |
| `state/` | `/app/audit` | Writable by `1654:1654` |

Both secret files and the JSON file must be real files before Compose starts. A missing bind source can otherwise become an unintended directory. Check only metadata, without printing values:

```sh
sudo stat -c '%a %u:%g %n' appsettings.Local.json secrets/keycloak_introspection secrets/exchange_password state secrets
sudo test -s secrets/keycloak_introspection
sudo test -s secrets/exchange_password
```

Expected metadata: state/secrets directories `700` and `1654:1654`; config/secret files `640` and `0:1654`. Each `test -s` must exit successfully. Do not recursively apply group-readable permissions to generated state: its protection-key files must remain private.

## 4. Replace all application placeholders

Use [CONFIGURATION.md](CONFIGURATION.md) for the complete field reference. At minimum, configure:

- `Service.Authority`: the exact IdP issuer, such as `https://identity.example.test/realms/company`.
- `Service.Resource`: the canonical HTTPS resource, such as `https://mail.example.test/mcp`; set `PublicResource` only for a deliberately configured second authority with the same path.
- `Service.IntrospectionClientId` and the mounted secret path. The confidential client must be able to introspect tokens issued for this resource.
- `Service.AllowedClientIds`: only the actual employee-facing client IDs you configured and approved. Remove unused examples. The stable ChatGPT CIMD ID is appropriate only when that actual IdP/host flow is qualified.
- Enrollment: for the simplest pilot, leave `AutoEnrollmentEnabled` false and replace `replace-with-alice-sub` with Alice's verified subject and mailbox. For automatic enrollment, follow the GUID/LDAPS/domain setup rather than trusting an email claim.
- `Exchange.Endpoint`, `Username`, `Domain`, and `PasswordFile` for the separately scoped service identity.
- `DirectoryPermissions` when needed: trusted AD hostname, port 636, bounded `BaseDn`, and timeout.
- `Service.TrustedProxyAddresses`: only the immediate proxy address seen by the container, as explained below.
- `AuditPath`: retain `/app/audit/operations.jsonl` so all related private state remains on the persistent mount.

For the first test, retain:

```json
{
  "WritesEnabled": false,
  "SendEnabled": false,
  "AutoEnrollmentEnabled": false,
  "TaskNoticeProcessingAllEnrolledUsers": false,
  "TaskNoticeProcessingActors": [],
  "AllowExternalRecipients": false
}
```

These are fields inside `Service`, not a complete configuration. Do not paste this fragment over the full file. Configure approved recipient domains when the intended workflow needs them; leaving the example list empty is not a working policy for every recipient-checked operation.

The file is loaded without live reload. Apply later JSON/secret changes through a controlled recreate and verify the active behavior. Atomically replacing a host file can leave an existing bind mount referring to the previous inode.

## 5. Add the required CA trust before building

The image uses normal certificate and hostname validation for IdP, EWS, LDAPS, and event callbacks. The public `certs/` directory ships only documentation. If private PKI is needed, place operator-approved **public CA certificates** in PEM `.crt` files there before the build, using distinct generic local filenames. Verify their fingerprints through your established trusted source.

Do not put private keys, keytabs, PFX/P12 bundles, passwords, or an endpoint leaf certificate in that directory as a substitute for the issuing CA chain. The Dockerfile copies `certs/` into the image's CA directory and runs `update-ca-certificates`. Rebuild/recreate after a trust change; editing the source directory does not update a running image. Docker documents the distinction between [host and container CA trust](https://docs.docker.com/engine/network/ca-certs/).

The Docker daemon may separately need trust to pull images through an approved proxy/registry. The MCP client/browser also needs trust for the public MCP and IdP endpoints. Installing a CA in one of those locations does not automatically configure the others. Never use `curl -k`, an accept-all callback, or disabled hostname validation as deployment acceptance.

Keep any operator-specific CA additions out of a redistributed source archive unless you deliberately intend to publish them.

## 6. Validate Compose, build, and start

```sh
docker compose config --quiet
docker compose build --pull mcp
docker compose up -d --no-deps mcp
docker compose ps
docker compose logs --tail 100 --no-color mcp
```

The Dockerfile performs a locked .NET restore and Release publish, and installs the existing native GSS-NTLM/CA/curl runtime packages. The public source release has not runtime-qualified a newly built container or these example settings. A successful image build is not the behavioral check suite; run [BUILD-AND-TEST.md](BUILD-AND-TEST.md) for source verification. A registry/package/audit connectivity failure must be reported as a failed or blocked check, not bypassed by silently changing lockfiles or dependency versions.

The image tag is `exchange-mcp:1.16.8` in the supplied Compose file. It is a local build tag, not a promise of an image at a public registry. Record the resulting image ID/digest for upgrades and rollback.

The health check runs inside the container against loopback. To repeat that bounded check:

```sh
docker compose exec -T mcp curl --fail --silent --show-error --max-time 5 http://127.0.0.1:8080/health/live
```

Expected output is `{"status":"ok"}`. Health is process liveness only. It does not prove IdP, enrollment, EWS, LDAPS, refresh, or event delivery.

If testing the published loopback port from the host, preserve the configured host:

```sh
curl --fail --silent --show-error --max-time 5 --header 'Host: mail.example.test' http://127.0.0.1:8080/health/live
```

A bare host-port request can fail the Host guard depending on Docker's observed peer address. Do not misdiagnose that as EWS failure or broaden accepted hosts.

## 7. Configure HTTPS reverse proxying

Keep `127.0.0.1:8080:8080` private. The example below assumes an already managed **host-native Nginx** terminates TLS on the same Linux host. Adapt to the existing proxy; no proxy package or certificate is installed by this repository.

Before relying on forwarded headers, establish the actual immediate address seen by the application. With a standard rootful Linux Docker bridge and a host proxy, it is commonly the bridge gateway, not `127.0.0.1`. Inspect the reference network as a topology check:

```sh
docker network inspect exchange-mcp_default --format '{{range .IPAM.Config}}{{.Gateway}}{{end}}'
```

Confirm that address matches the intended immediate peer using your normal network diagnostics, then put only the verified address in `TrustedProxyAddresses`. Do not copy an example private IP, trust an entire subnet, or keep adding addresses until the check passes. Rootless Docker, other proxies, and other networks can produce a different peer. The code trusts one hop of forwarded scheme/client IP, and does not consume `X-Forwarded-Host`.

A minimal illustrative Nginx HTTPS server block is:

```nginx
server {
    listen 443 ssl;
    server_name mail.example.test;

    ssl_certificate     /etc/nginx/tls/mail/fullchain.pem;
    ssl_certificate_key /etc/nginx/tls/mail/privkey.pem;

    client_max_body_size 8m;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Host $http_host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header Connection "";
        proxy_buffering off;
        proxy_request_buffering off;
        proxy_read_timeout 3600s;
        proxy_send_timeout 60s;
    }
}
```

Replace the hostname and certificate paths with the intended deployment. Retain the organization's existing TLS policy rather than replacing it with guessed cipher settings. The relevant streaming/buffering/header directives are described in the [Nginx proxy module reference](https://nginx.org/en/docs/http/ngx_http_proxy_module.html).

The proxy must preserve `/mcp`, both protected-resource metadata routes, authentication/challenge headers, response tracking headers, and streaming behavior. Do not insert an interactive reverse-proxy login page in front of MCP discovery/token challenges. Do not log Authorization headers, bodies, or callback secrets. Use a deliberate public route if a hosted client needs it; local browser reachability is insufficient.

Apply the verified proxy address/configuration, recreate the app if its file changed, and validate the existing Nginx configuration before the approved reload:

```sh
docker compose up -d --no-deps --force-recreate mcp
sudo nginx -t
sudo systemctl reload nginx
```

A proxy in another container needs an explicitly reviewed private container-network arrangement; its own loopback is not the application host's loopback. A proxy on another machine cannot reach this host-loopback listener. Do not change the published bind to all interfaces as an unexplained compatibility fix.

## 8. Verify from the intended client path

Run these public, unauthenticated probes from the same network class as the intended client when possible:

```sh
curl --fail --silent --show-error --max-time 10 https://mail.example.test/health/live
curl --fail --silent --show-error --max-time 10 https://mail.example.test/.well-known/oauth-protected-resource
curl --silent --show-error --include --max-time 10 --request POST https://mail.example.test/mcp
```

Expected results are distinct:

| Probe | Expected result / evidence boundary |
| --- | --- |
| HTTPS health | 200 liveness through the intended DNS/TLS/proxy path. |
| Metadata | JSON with the intended `resource`, exact `authorization_servers` issuer, and appropriate advertised scopes. It contains no credentials. |
| Unauthenticated MCP POST | 401 with a Bearer `WWW-Authenticate` challenge pointing at protected-resource metadata and `mail.read`. A JSON-RPC tool result is not expected without authentication. |

Repeat metadata/audience checks for `PublicResource` when configured. A 400 commonly indicates Host or HTTPS-scheme handling; 403 can indicate an Origin check; an authenticated 401 needs token/introspection/enrollment diagnosis. Do not change Exchange permissions to repair a proxy-layer result.

Then use [CLIENTS.md](CLIENTS.md) to register the exact callback, sign in through OAuth, and verify:

1. Alice's `mail_profile` resolves the intended mailbox.
2. A non-sensitive requested Inbox/message read succeeds.
3. Bob, when deliberately not approved/enrolled, is rejected.
4. Wrong issuer/audience/client/type, expired/revoked tokens, and unavailable introspection fail closed in the test environment.
5. Automatic enrollment, if enabled, verifies current AD/GUID/primary-domain/Inbox rights and survives the tested restart with the same binding.

Record the UTC collection time, source/image version, target hostname, client version, probe outcomes, and tracking IDs. Keep raw tokens and mailbox contents private. Do not publish raw configuration/log archives with public issue reports.

Only after the read path is qualified, enable the requested additional scopes and switches in the smallest scope. Test recipient rules and the actual host's approval path before sending. A controlled self-addressed test requires explicit operator/user authorization, and Exchange acknowledgement is not proof of delivery/read. Do not retry an uncertain send.

## 9. Optional host capabilities

Test each capability required by the deployment independently:

| Capability | Qualification |
| --- | --- |
| Refresh | Let the original access token expire; verify a new valid request with the same employee, then test rotation and grant revocation. `offline_access` alone is not proof. |
| Delegated mailbox | Discover a current permission-backed target, use its handle, and verify the required read/write/sender right. Full Access is not automatically Send As or Send on Behalf. |
| Preview UI | Show a disposable unsent draft/signature through the actual host, test cancellation and stale revision rejection. A successful resource fetch is not visible UI proof. |
| Native confirmation | Exercise form elicitation and continuation on the chosen host. The exact stable ChatGPT CIMD send-grant path differs; do not promise a native form for that path. |
| Incoming-mail events | Verify protocol `2026-07-28`, own-Inbox event discovery/subscription, public callback verification, durable state, token-clamped renewal, delivery, actual host response, unsubscribe, and revocation. |
| Background task notices | Review the separate actor scope/processor state and native task workflow before enabling this disabled-by-default worker. |

The service cannot force a host UI mount, refresh a host catalog, install a connection, make a host persist refresh tokens, or promise immediate event-triggered execution. A host callback's 2xx receipt and a visible user notification are separate observations.

## Persistence, backup, and restore

The entire `state/` directory is sensitive operational state. Preserve it, with its generated private permissions and keys, across container replacements. See [the path inventory](CONFIGURATION.md#paths-persistence-and-logs).

- Approval/replay data and the matching `protection.key` prevent reuse of prior uncertain/mutable attempts. The application refuses to replace a missing key when initialized approval state is present.
- Event data and its matching key hold subscription/queue/authorization context. Backup both together; do not restore the encrypted file with an unrelated key.
- Automatic enrollment is bound to issuer, subject, GUID, and primary mailbox. Discarding it is not an identity migration.
- Signature/onboarding settings reside in Exchange UserConfiguration. A local state backup is not an Exchange mailbox backup.
- Ordinary encrypted handles can remain valid only within their own expiry and matching identity/client/session with the same key. In-memory preview/latest-review caches can be lost on restart; re-read/re-preview the exact existing draft rather than creating or sending another one.

Use a short controlled stop for a consistent local snapshot. The following example keeps the archive inside a root-only ignored `backups/` directory. It assumes the reference file names and must be run from `/srv/exchange-mcp`:

```sh
sudo install -d -m 0700 -o root -g root backups
release_stamp=$(date -u +%Y%m%dT%H%M%SZ)
docker image inspect exchange-mcp:1.16.8 --format '{{.Id}}'
docker image tag exchange-mcp:1.16.8 "exchange-mcp:rollback-$release_stamp"
docker compose stop mcp
sudo tar --acls --xattrs --numeric-owner -czf "backups/prechange-$release_stamp.tar.gz" compose.yaml appsettings.Local.json secrets state
sudo chmod 0600 "backups/prechange-$release_stamp.tar.gz"
sudo tar -tzf "backups/prechange-$release_stamp.tar.gz"
docker compose start mcp
```

Check the archive command succeeded before changing code/configuration. If capture fails, retain the previous image/files and resolve backup readiness; do not continue an upgrade on the assumption that a filename is a usable backup. Retain a protected copy of the exact deployed source/Dockerfile or an exported image if the image cannot be rebuilt from trusted inputs. Encrypt/off-host-copy backups through your established backup system; do not leave the only restore copy on the same host.

Listing an archive checks readability and paths, not application recovery. Prove restore on an isolated target without live EWS writes or outward callbacks before declaring rollback ready. Do not allow two restored copies to operate against the same mailboxes, state, or event subscriptions.

For application/configuration rollback:

1. Capture the current failed/new state as a separate protected checkpoint; retain all operation tracking evidence.
2. Stop `mcp`. Restore the previous reviewed configuration/secrets as a matching set, and select the recorded rollback image tag in `compose.yaml`.
3. Retain current durable data if compatibility with that image has been established. If a coordinated older data snapshot is required, preserve the current directory separately and restore the entire selected state/key set, with original owners/modes, under explicit reconciliation of mailbox operations since the snapshot.
4. Start only the selected local image, preventing an unintended rebuild/pull:

   ```sh
   docker compose up -d --no-deps --no-build --pull never mcp
   ```

5. Recheck liveness, metadata, Alice's read path, revocation, state/key readability, and only the affected mutable/host features.

A state restore does not undo Exchange changes or recall messages already delivered. An older approval/replay ledger can forget attempts made after its snapshot. Reconcile Drafts/Sent/Exchange evidence before any retry; do not delete reservation records or regenerate keys to make a send succeed. Use the application's preserved outcomes/tracking IDs and normal Exchange investigation tools.

## Routine operation and updates

Use scoped native commands from the deployment directory:

```sh
docker compose ps
docker compose logs --tail 100 --no-color mcp
docker compose stop mcp
docker compose start mcp
```

`stop` preserves bind-mounted state; it also pauses event/worker activity. The example restart policy does not make stopped/expired subscriptions or an unavailable host healthy. Do not use destructive cleanup, prune commands, or delete `state/` as routine recovery.

Before an upgrade, read the new changelog/configuration contract, record the current image ID and client/IdP setup, take a consistent backup, and run required source checks. Build the intended reviewed version, apply only that service, and repeat the affected validation. Keep the previous image/snapshot until acceptance. Certificate, secret, subject, issuer, resource, client-ID, or state-path changes can alter trust/identity and require their own explicit migration checks.

Monitor disk use, audit write failures, admission rejection/retry rates, EWS and introspection latency, authentication failures, container resource pressure, and optional event expiry/gaps. Docker log rotation is configured, but `operations.jsonl` has no automatic retention/rotation policy supplied here. Establish a tested retention process without truncating active state or losing required incident evidence.

## Common deployment failures

| Failure | Targeted check |
| --- | --- |
| Invalid settings on startup | Replace example subjects/URLs; validate the complete JSON, nonempty approved clients/enrollment, file paths/sizes, and numeric bounds. |
| Secret or config path is a directory | Stop the service; inspect bind-source file types and restore the intended protected file. Do not print secret contents. |
| State permission/key error | Check UID/GID, filesystem ownership support, directory mode, original private key modes, and the matching backup. Do not create a replacement key. |
| HTTPS metadata returns 400 | Check preserved Host, exact configured authority, observed immediate proxy, and trusted forwarded HTTPS scheme. |
| External host cannot connect | Check that runtime's DNS/TLS/network path to MCP and IdP; a local VPN/browser test is insufficient. |
| Authenticated 401 | Check access-token type/issuer/audience/`azp`/expiry, fixed-path introspection and exact claim equality, enrollment, LDAPS when enabled. |
| EWS access denied | Check separate service credentials, scoped actor impersonation, and intended operation/target rights. An IdP relogin does not repair Exchange rights. |
| 429 / busy | Respect bounded retry information and inspect the actual constrained layer. Do not remove guards or repeatedly reconnect. |
| Read succeeds, send/preview/events fail | Inspect that feature's scopes, switches, rights, host capability, and live qualification; do not call the deployment fully validated from a read alone. |

No production environment, live mail, IdP session, client UI, or hosted callback is configured or proven by this source package. Report completed checks separately from skipped checks and unresolved host/Exchange behavior.

