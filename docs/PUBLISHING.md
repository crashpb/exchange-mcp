# Preparing a GitHub publication

This directory is a clean source export, not a clone of a private repository. Do not add the private repository as a remote, copy its .git directory, or publish its history. Do not include local state, configuration, mail, logs, keys, company CA certificates or generated build output.

1. Read README.md, LICENSE, SECURITY.md and THIRD-PARTY-NOTICES.md. Run the build/check steps in docs/BUILD-AND-TEST.md and review every staged path. Keep your release test report honest about external-schema and live-client checks.
2. Create the intended empty repository under your own GitHub account. Choose its visibility deliberately; do not auto-initialize another README/license. The intended public name is exchange-mcp. GitHub publication is a separate action from local preparation.
3. From this clean export, use native Git with your already-authorized GitHub credential:

```sh
git init -b main
git add .
git diff --cached --stat
git diff --cached --check
git status --short
# Review all staged files before committing.
git commit -m "Initial exchange-mcp source release"
git remote add origin https://github.com/YOUR-ACCOUNT/exchange-mcp.git
git push -u origin main
```

Replace YOUR-ACCOUNT; never place a credential in the URL. The commands are documentation and have not been run against GitHub by preparing this export.

4. Enable the repository's security reporting channel, set your maintainer/contact policy, and configure branch/review protections appropriate to your project. Do not copy internal organization access policies blindly.
5. Publish only the reviewed source archive/checksum for this version. If you later distribute binaries or images, add their own dependency/source-license inventory, signing/provenance and platform tests. Version/tag releases from the reviewed public tree, not from a private production checkout.

The intentionally generic Company.ExchangeMcp namespace/assembly and durable protection purposes are retained for compatibility. Display branding is Exchange MCP. Existing deployments must review state/resource/client compatibility before switching to a new distribution; this source package is not an automatic migration.
