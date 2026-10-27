# Build and test

The public `exchange-mcp` tree builds the .NET server and its synthetic check executable. It does not include company secrets, production mail/evidence, a company CA or captured Exchange schemas. Normal checks use generated identities/tokens, in-process HTTP transport and simulated EWS responses; they do not need a live mailbox or identity-provider account.

## Prerequisites and locked build

Use a compatible x64 .NET 10 SDK. `global.json` requests SDK 10.0.101 with `latestFeature` roll-forward. `Directory.Build.props` enables warnings as errors, lockfiles and vulnerability audit for all packages. Restore and package audit require access to the configured NuGet source or a suitable approved cache.

From the repository root:

```powershell
dotnet restore Company.ExchangeMcp.sln --locked-mode --configfile NuGet.Config
dotnet build Company.ExchangeMcp.sln --no-restore -c Release
```

Use `--locked-mode`; do not regenerate lockfiles merely to bypass an unavailable dependency source. A restore/audit network failure is not a passing dependency check. No new system-wide package or deployment is required for source checks.

## Baseline mode: no external XSD files

The entire behavioral/security suite runs when `EXCHANGE_EWS_SCHEMA_DIR` is unset. Each schema validation site prints an explicit XSD-only `SKIP`; the surrounding fixture, SOAP shape, authorization, replay, HTML, quota and protocol assertions remain active.

PowerShell, in the current shell only:

```powershell
Remove-Item Env:\EXCHANGE_EWS_SCHEMA_DIR -ErrorAction SilentlyContinue
Remove-Item Env:\COMPANY_MAIL_CHECK_FILTER -ErrorAction SilentlyContinue
dotnet run --project tests/Company.ExchangeMcp.Checks -c Release --no-build --no-restore
```

POSIX shell:

```sh
unset EXCHANGE_EWS_SCHEMA_DIR COMPANY_MAIL_CHECK_FILTER
dotnet run --project tests/Company.ExchangeMcp.Checks -c Release --no-build --no-restore
```

This snapshot has 63 check groups. A successful baseline run reports zero failures alongside explicit schema SKIPs; that qualifies synthetic behavior without external Exchange XSD validation. It does not qualify actual Exchange, user login, sending/delivery, Outlook processing, host event execution or rendered card appearance. This project uses a console check runner, so `dotnet test` is not the command for these checks.

`COMPANY_MAIL_CHECK_FILTER` can deliberately select groups by name for diagnosis. Leave it unset for a complete run; a filtered passing count is not the full suite. The runner creates synthetic temporary files under `tests/Company.ExchangeMcp.Checks/.local/checks`. Exclude `.local`, bin/obj and logs from a release.

## Optional Exchange 2019 schema mode

An operator may supply an approved external schema directory containing all three files:

- `xml.xsd`
- `types.xsd`
- `messages.xsd`

The schema directory remains outside this public repository and release archive. Obtain it through your organization's authorized Exchange/documentation process; no production credentials, captured traffic or live response bodies are needed by the checks. This source-only release does not redistribute captured vendor schemas or claim redistribution rights for them.

PowerShell, replacing the example with your existing private directory:

```powershell
$env:EXCHANGE_EWS_SCHEMA_DIR = 'C:\private\exchange2019-schema'
Remove-Item Env:\COMPANY_MAIL_CHECK_FILTER -ErrorAction SilentlyContinue
dotnet run --project tests/Company.ExchangeMcp.Checks -c Release --no-build --no-restore
```

POSIX shell:

```sh
unset COMPANY_MAIL_CHECK_FILTER
EXCHANGE_EWS_SCHEMA_DIR=/private/exchange2019-schema dotnet run --project tests/Company.ExchangeMcp.Checks -c Release --no-build --no-restore
```

When supplied, the directory must contain every required file. Missing/incomplete paths, malformed schemas, schema compile errors and schema validation errors fail the affected check and produce a nonzero runner exit. They never silently fall back to baseline mode or search an operator's private project path. An empty/unset variable selects baseline; a nonempty invalid value is an error. XML schema resolution is disabled for external locations.

Schema mode adds validation of the generated SOAP operations/responses covered by each fixture. It does not turn synthetic checks into live Exchange acceptance. Record SDK version, source revision, mode, schema provenance, final count and any skips when reporting results; do not include schema contents or private evidence in a public report.

The existing full-mail group includes regression assertions for unset, explicitly missing and incomplete schema-directory selection. All schema consumers use the same optional loader, preserving consistent failure behavior. Baseline and real external-schema runs should both be checked for release qualification when approved schemas are available.

## Formatting and dependency review

From the repository root:

```powershell
dotnet list Company.ExchangeMcp.sln package --vulnerable --include-transitive
dotnet format src/Company.ExchangeMcp/Company.ExchangeMcp.csproj --no-restore --verify-no-changes
dotnet format tests/Company.ExchangeMcp.Checks/Company.ExchangeMcp.Checks.csproj --no-restore --verify-no-changes
```

Restore already requests all-package audit through project settings; the package-list command provides a reviewable report. Network/source errors must be reported separately from findings. Do not change unrelated dependencies or disable warnings/audit to make a build pass.

## Live probes and deployment

The test executable also contains explicitly selected live diagnostic entrypoints. They are outside normal checks and can contact real infrastructure when given protected configuration. Do not invoke them without authorization for the exact target, inputs and operational scope. Never place service passwords, bearer tokens or raw mailbox evidence in command history, fixtures or this repository.

Building an image, configuring an identity provider, provisioning Exchange rights and deploying a service are separate actions. Follow the public deployment and identity guides with your own environment-specific settings and protected state. A build/test result does not establish production readiness or authorize a deployment.
