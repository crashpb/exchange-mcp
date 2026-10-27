# Release notes

## 1.16.8 — public source preparation

Initial source-only exchange-mcp package, under Apache-2.0. Provides the existing .NET remote MCP implementation for on-premises Exchange EWS with OAuth/Keycloak validation, directory-aware authorization, mail/groupware/signatures, guarded mutations and host-dependent previews/events.

This packaging separates organization-specific configuration from reusable source. It changes public display/resource branding, uses synthetic fixture identities, removes private schema-directory discovery, adds optional explicit schema qualification, and replaces organization CA/deployment assumptions with operator-managed examples. Tool names, namespace/assembly names and durable cryptographic purposes remain unchanged. No production service is changed by this package.

The repository includes locked dependencies and a 63-group synthetic regression suite. A source build is not proof of Exchange delivery, successful recall, client widget support, long-lived OAuth refresh or a load/HA qualification. See the feature, security, deployment and IdP guides before using it with real mail.

No binary/container release, Exchange schema files, credentials, real mail, private Git history or company configuration is included. A future container distributor must inventory its actual native dependencies and preserve their notices.
