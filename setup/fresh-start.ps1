$ErrorActionPreference = 'Stop'
$RepoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$EnvFile = Join-Path $RepoRoot '.env'
$ComposeFile = Join-Path $RepoRoot 'docker\docker-compose.yml'
Set-Location -LiteralPath $RepoRoot

Write-Warning 'This permanently deletes all Argus named volumes and their data.'
$confirmation = Read-Host 'Type DELETE ARGUS DATA to continue'
if ($confirmation -cne 'DELETE ARGUS DATA') {
    Write-Host 'Cancelled.'
    exit 0
}

docker compose --project-directory $RepoRoot --env-file $EnvFile -f $ComposeFile down --volumes --remove-orphans
if ($LASTEXITCODE -ne 0) { throw 'Volume removal failed.' }
docker compose --project-directory $RepoRoot --env-file $EnvFile -f $ComposeFile build backend
if ($LASTEXITCODE -ne 0) { throw 'Argus image build failed.' }
docker compose --project-directory $RepoRoot --env-file $EnvFile -f $ComposeFile up -d --no-build --pull never
if ($LASTEXITCODE -ne 0) { throw 'Fresh startup failed.' }
docker compose --project-directory $RepoRoot --env-file $EnvFile -f $ComposeFile ps
