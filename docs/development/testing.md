# Testing guide

The local quality gate mirrors GitHub Actions:

```powershell
.\setup\test.ps1 -Install  # once per developer machine
.\setup\test.ps1
```

The gate runs backend unit/stateless tests, selected application smoke tests,
Python dependency auditing, frontend lint/build/audit, and Compose validation.

## Focused module commands

```powershell
python -m pytest backend/tests/test_image_intel.py -q
python -m pytest backend/tests/test_telegram_intel.py -q
python -m pytest backend/tests/test_infrastructure.py -q

Set-Location modules-ui
npm run lint
npm run build
```

Tests must use minimal synthetic records. Mark tests requiring live datastores,
provider credentials, or network access clearly and keep them out of the default
stateless gate. Do not make CI success depend on third-party availability.
