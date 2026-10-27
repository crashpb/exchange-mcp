# Source-release verification

Verification date: 28 October 2026 (Asia/Tehran). Version: 1.16.8. Distribution: source only.

| Check | Result |
| --- | --- |
| Locked restore on .NET SDK 10.0.101 x64 | Passed for server and check projects |
| Release build | Passed; zero warnings, zero errors |
| Baseline synthetic behavior/security suite without private schemas | 63 groups passed, zero failed; schema-only skips explicitly reported |
| Suite using externally supplied Exchange 2019 schemas | 63 groups passed, zero failed; no schemas copied into the package |
| Explicitly missing schema directory | Expected failure verified; no silent fallback |
| Final session-lifetime guidance wording | Rebuilt successfully; affected continuation check passed |
| Whitespace formatting gate | Passed |
| Locked dependency vulnerability audit including transitive packages | No known vulnerabilities reported by the configured NuGet source at verification time |
| Independent source/test review | No blocking finding; production changes limited to public branding and generic session-lifetime wording; test schema portability preserved behavioral assertions |
| Privacy review | Known company names/domains/employees/hosts and secret/certificate patterns absent; 77 standalone Base64 literals checked for private markers |
| Documentation | Relative file links, heading anchors in operator guides, code-fence balance, configuration JSON and six documented JSON examples checked |

The public package contains no production credentials, employee mail, private logs, company certificates, captured Exchange schemas, private Git history, generated binaries or test runtime state. The archive checksum and per-file SHA-256 manifest accompany the release.

These are source and synthetic-test results. No new public Docker image was built/run, and no fresh live IdP, Exchange mailbox, OAuth refresh, recall, host UI, event delivery, load or HA test was performed for this export. Existing implementation history is not a guarantee for a new deployment. Follow the documented read-only pilot and separately authorized acceptance procedure.
