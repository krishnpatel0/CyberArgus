$ErrorActionPreference = 'Stop'
$RepoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$EnvFile = Join-Path $RepoRoot '.env'
$ComposeFile = Join-Path $RepoRoot 'docker\docker-compose.yml'
Set-Location -LiteralPath $RepoRoot

if (-not (Test-Path -LiteralPath $EnvFile)) {
    throw 'Missing .env. Run .\setup\setup.ps1 first.'
}

docker compose --project-directory $RepoRoot --env-file $EnvFile -f $ComposeFile --profile '*' stop
if ($LASTEXITCODE -ne 0) { throw 'Docker Compose stop failed.' }
Write-Host 'Argus Unified stopped. Containers, images, and named-volume data were preserved for the next daily start.'
