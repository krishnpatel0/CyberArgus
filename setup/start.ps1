param(
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
    throw 'Missing .env. Run .\setup\setup.ps1 first, then review the generated secrets.'
}

New-Item -ItemType Directory -Force -Path (Join-Path $RepoRoot 'data\breach') | Out-Null

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

$requiredImages = @(& docker @composeArgs config --images | Sort-Object -Unique)
if ($LASTEXITCODE -ne 0) { throw 'Could not resolve required Docker images.' }

$missingImages = @()
foreach ($image in $requiredImages) {
    & docker image inspect $image *> $null
    if ($LASTEXITCODE -ne 0) {
        $missingImages += $image
    }
}

if ($missingImages.Count -gt 0) {
    $missingList = $missingImages -join [Environment]::NewLine
    throw "Required images are not installed:`n$missingList`nRun .\setup\setup.ps1 once. Daily start never downloads or builds images."
}

& docker @composeArgs up -d --no-build --pull never
if ($LASTEXITCODE -ne 0) { throw 'Argus startup failed.' }

& docker @composeArgs ps
Write-Host 'Argus Unified is available at http://127.0.0.1:7777'
Write-Host 'Daily start completed without building or downloading images.'
