param(
    [switch]$Pull,
    [switch]$AI,
    [switch]$Tor,
    [switch]$Monitoring
)

$ErrorActionPreference = 'Stop'
$RepoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$EnvFile = Join-Path $RepoRoot '.env'
$ComposeFile = Join-Path $RepoRoot 'docker\docker-compose.yml'
Set-Location -LiteralPath $RepoRoot

if (-not (Test-Path -LiteralPath $EnvFile)) {
    throw 'Missing .env. Run .\setup\setup.ps1 first.'
}

docker info | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Docker is not running.' }

$composeArgs = @(
    'compose', '--project-directory', $RepoRoot,
    '--env-file', $EnvFile,
    '-f', $ComposeFile
)
if ($AI) { $composeArgs += @('--profile', 'ai') }
if ($Tor) { $composeArgs += @('--profile', 'tor') }
if ($Monitoring) { $composeArgs += @('--profile', 'monitoring') }

& docker @composeArgs config --quiet
if ($LASTEXITCODE -ne 0) { throw 'Docker Compose configuration is invalid.' }

if ($Pull) {
    Write-Host 'Explicit image update requested. Pulling current infrastructure and build-base images...'
    & docker @composeArgs pull --ignore-buildable --policy always
    if ($LASTEXITCODE -ne 0) { throw 'Infrastructure image update failed.' }
    & docker @composeArgs build --pull backend
} else {
    Write-Host 'Rebuilding Argus from local source with the existing Docker cache...'
    & docker @composeArgs build backend
}
if ($LASTEXITCODE -ne 0) { throw 'Argus image rebuild failed.' }

& docker @composeArgs up -d --no-build --pull never
if ($LASTEXITCODE -ne 0) { throw 'Argus restart after rebuild failed.' }

& docker @composeArgs ps
Write-Host 'Argus was rebuilt and restarted. Named-volume data was preserved.'
