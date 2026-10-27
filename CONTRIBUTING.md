# Contributing

Start with the [build and test guide](docs/BUILD-AND-TEST.md) and the [identity contract](docs/IDENTITY-PROVIDER.md). The project is a .NET 10 application with a separate executable regression-check project. It does not need a frontend package manager or Outlook companion.

Keep changes small and preserve existing callers, tool schemas, authorization checks, durable-state formats and client compatibility. Do not rename cryptographic purpose strings or change token/handle semantics as cosmetic cleanup. Add a focused regression for a changed security, parser, replay or authorization boundary. Reuse existing checks instead of writing mirror tests.

Use synthetic mailbox addresses under example.test, generated test tokens/keys and fake EWS responses. Never commit captured production XML, mail, signatures, certificates, GUIDs, logs, credentials or private deployment state. External Exchange schemas stay outside the repository. Keep dependency lockfiles and source notices intact.

Before a contribution, run locked restore, Release build, all offline checks and package vulnerability review. When EWS serialization changes, also run the external Exchange schema mode and a separately authorized disposable mailbox test. Report what was actually tested, including client UI, delivery and cleanup boundaries. Never claim mailbox delivery from EWS acceptance or recall success from cleanup.

Describe the problem and resulting behavior in the pull request, list relevant checks and remaining limitations. Contributions to project code are under Apache-2.0; third-party notices retain their own terms. Do not add optional frameworks, new production dependencies or deployment automation without a concrete requirement.
