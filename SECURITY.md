# Security and operator responsibilities

This service can read and modify corporate mail. Deploy it only after configuring and testing your identity provider, Exchange service account, TLS trust, scope boundaries and user permissions. Read [identity](docs/IDENTITY-PROVIDER.md), [Keycloak](docs/KEYCLOAK.md) and [deployment](docs/DEPLOYMENT.md) first.

## Trust boundaries

- OAuth identifies the human actor. Signed access-token validation, resource audience, allowed client and current token introspection are checked before mailbox work. An ID token, a decoded JWT, or a browser SSO cookie is not sufficient.
- Exchange uses a separate dedicated EWS account with administrator-configured impersonation scope. An employee OAuth token is not an Exchange/LDAP credential or a forwarded Windows ticket. Do not use Domain Admin credentials for the service.
- Automatic own-mailbox enrollment binds the immutable directory GUID to a currently enabled mailbox and allowed primary domain. Delegated rights are evaluated separately for content, folder access, Send As and Send on Behalf. Unknown/incomplete permission results are not grants. Backend service-account access must cover intended targets without replacing the human permission checks.
- Input validation, safe email composition, quotas, bounded handles, optimistic change keys, approval/replay protection, rate limits and concurrency limits are independent controls. Do not disable them to bypass a failing workflow.
- Message text, attachments, signature HTML and incoming events are untrusted data. They cannot authorize sends, deletion, access changes, URL navigation or execution. Remote images are not automatically fetched for signature capture. Preview rendering is independently sandboxed and sanitized; it does not rewrite saved content simply to make a card appear.

## State and credentials

Use protected mounted files for the EWS password and introspection secret. Do not put secrets in Git, images, command-line arguments, screenshots or issue bodies. Keep the application configuration private too: identity mappings and internal topology can be sensitive even without passwords.

The state directory includes audit records, enrollments, encrypted approvals/replay state, event records and the local protection key. Encryption does not protect against a party with both the key and files. Restrict the directory to the runtime account, encrypt backups, and restore keys and state together. Never replace a missing key to get around startup failure. Signatures and onboarding are stored in the user's Exchange mailbox, not in this source package.

The MCP does not store the user's OAuth refresh token: the client host must keep and renew its grant. Server event state can include encrypted subscription credentials/authorization context; protect it as sensitive operational data. Disabling an employee, revoking an IdP session, stopping a background worker and deleting its subscription are distinct operations; verify the intended effect rather than assuming one implies all the others.

## Network and capacity

Terminate public HTTPS at an approved reverse proxy. Keep the container listener private. Forward the expected Host and HTTPS scheme only through configured trusted proxy addresses, reject unexpected Host values, and do not trust forwarded headers from arbitrary sources. Use valid certificates for the public endpoint, IdP, EWS and LDAPS. Never disable certificate or hostname validation.

Streaming events and webhook callbacks require supported host behavior and public HTTPS callback destinations. The callback validator rejects private/local destinations to prevent server-side request forgery; do not weaken it for a production host. Webhook acceptance is not proof of agent execution or user notification.

Use one application instance with its own durable state. Limits and in-memory sessions are not a distributed coordination system. Load-test a representative mixed workload before expanding enrollment; monitor admission tracking IDs, concurrency, EWS latency, IdP introspection and stream capacity. Do not put multiple replicas behind a load balancer and call it HA without a separately reviewed state/locking/session design.

## Safe incident handling

Capture the tracking ID, UTC time, tool, result stage and outcome. Redact addresses, handles, bodies, cookies and credentials before sharing logs. Do not automatically repeat an uncertain send or mutation. Reconcile the exact draft/Sent/recipient state first. A 429 admission rejection is not a reason to force OAuth reconnection or remove rate limits.

For a suspected vulnerability, use the hosting repository's private vulnerability-reporting channel if enabled. If unavailable, contact the repository owner privately to arrange a secure channel. Do not publish exploit details, real mailbox data or credentials in a public issue. This release does not promise a response SLA or security certification.
