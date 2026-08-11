# Contributing to Argus Unified

Argus is an authorization-scoped defensive security platform. Contributions
must not introduce credential theft, uncontrolled scanning, authentication
bypass, stealth, persistence, or collection outside operator-owned scope.

## Development workflow

1. Create a focused branch from `main`.
2. Run `setup/setup.ps1` or `setup/setup.bat` for local Docker configuration.
3. Run `setup/test.ps1 -Install` once, then `setup/test.ps1` for subsequent checks.
4. Add tests for behavioral changes and keep the documentation factual.
5. Open a pull request using the repository template.

The repository uses one canonical `docker/Dockerfile`. Do not add per-module Dockerfiles or
new standalone service stacks when the shared Argus image can run the role.

## Data-handling rule

Never commit real or realistic breach corpora, customer assets, credentials,
provider keys, Telegram sessions, generated reports, or production logs. Use
minimal synthetic fixtures inside tests. Local breach data belongs under the
ignored `data/breach` directory or another path selected with
`BREACH_DATA_PATH`.

## Code expectations

- Fail closed for missing production secrets.
- Validate scope before network activity.
- Use parameterized database queries and argument-vector subprocess calls.
- Bound concurrency, retries, response sizes, graph expansion, and imports.
- Preserve provenance and distinguish candidates from confirmed findings.
- Keep Windows launchers in PowerShell; BAT files are thin wrappers only.
