param([switch]$Install)

$ErrorActionPreference = 'Stop'
$RepoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$ComposeFile = Join-Path $RepoRoot 'docker\docker-compose.yml'
Set-Location -LiteralPath $RepoRoot

$python = Join-Path $RepoRoot '.venv\Scripts\python.exe'
if ($Install -and -not (Test-Path -LiteralPath $python)) {
    if (Get-Command py -ErrorAction SilentlyContinue) {
        py -3.12 -m venv .venv
    } else {
        $version = python -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"
        if ($version -ne '3.12') {
            throw 'Python 3.12 is required to create the development environment.'
        }
        python -m venv .venv
    }
    if ($LASTEXITCODE -ne 0) { throw 'Could not create .venv.' }
}
if (-not (Test-Path -LiteralPath $python)) {
    throw 'Missing .venv. Run .\setup\test.ps1 -Install once.'
}
if ($Install) {
    & $python -m pip install --upgrade pip
    & $python -m pip install --no-build-isolation -r backend\requirements-dev.txt
    if ($LASTEXITCODE -ne 0) { throw 'Python dependency installation failed.' }
    Push-Location modules-ui
    try {
        npm ci
        if ($LASTEXITCODE -ne 0) { throw 'npm ci failed.' }
    } finally {
        Pop-Location
    }
}

$env:AUTH_DISABLED = 'true'
$env:PYTHONUTF8 = '1'
$env:POSTGRES_PASSWORD = 'test-only-password'
$env:REDIS_PASSWORD = 'test-only-redis-password'
$env:CLICKHOUSE_PASSWORD = 'test-only-clickhouse-password'
$env:JWT_SECRET_KEY = ('a' * 64)
$env:ADMIN_PASSWORD = 'test-only-admin-password'
$env:BREACH_EMAIL_HASH_SALT = ('b' * 64)
$env:BREACH_SEARCH_API_KEY = ('c' * 64)

Write-Host '[1/5] Backend unit and stateless tests'
& $python -m pytest backend\tests -q --ignore=backend\tests\test_api_endpoints.py --ignore=backend\tests\test_integration.py
if ($LASTEXITCODE -ne 0) { throw 'Backend tests failed.' }

Write-Host '[2/5] Application smoke tests'
& $python -m pytest backend\tests\test_integration.py -q -k 'TestAppBoots or TestCORSNotWildcard or TestInputValidation or TestAuthFlows'
if ($LASTEXITCODE -ne 0) { throw 'Application smoke tests failed.' }

Write-Host '[3/5] Python dependency audit'
& $python -m pip_audit -r backend\requirements.txt --timeout 60
if ($LASTEXITCODE -ne 0) { throw 'Python dependency audit failed.' }

Write-Host '[4/5] Modules UI lint, build, and dependency audit'
Push-Location modules-ui
try {
    npm run lint
    if ($LASTEXITCODE -ne 0) { throw 'Frontend lint failed.' }
    npm run build
    if ($LASTEXITCODE -ne 0) { throw 'Frontend build failed.' }
    npm audit --audit-level=low
    if ($LASTEXITCODE -ne 0) { throw 'Frontend dependency audit failed.' }
} finally {
    Pop-Location
}

Write-Host '[5/5] Docker Compose resolution'
docker compose --project-directory $RepoRoot -f $ComposeFile config --quiet
if ($LASTEXITCODE -ne 0) { throw 'Docker Compose configuration failed.' }

Write-Host 'All configured checks passed.'
