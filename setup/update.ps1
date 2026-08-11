$ErrorActionPreference = 'Stop'
$RepoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$EnvFile = Join-Path $RepoRoot '.env'
$ComposeFile = Join-Path $RepoRoot 'docker\docker-compose.yml'
$BackendSource = Join-Path $RepoRoot 'backend'
$IntelSource = Join-Path $RepoRoot 'intel-proxy'
$ReconSource = Join-Path $RepoRoot 'recon-engine'
$UiRoot = Join-Path $RepoRoot 'modules-ui'
$UiDist = Join-Path $UiRoot 'dist'
$ViteCommand = Join-Path $UiRoot 'node_modules\.bin\vite.cmd'
Set-Location -LiteralPath $RepoRoot

if (-not (Test-Path -LiteralPath $EnvFile)) {
    throw 'Missing .env. Run .\setup\setup.ps1 first.'
}
if (-not (Test-Path -LiteralPath $ViteCommand)) {
    throw 'Missing frontend development dependencies. Run .\setup\test.ps1 -Install once; update itself never downloads dependencies.'
}

docker info | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Docker is not running.' }

$composeArgs = @(
    'compose', '--project-directory', $RepoRoot,
    '--env-file', $EnvFile,
    '-f', $ComposeFile
)

function Get-RunningServiceContainer([string]$Service) {
    $containerId = (& docker @composeArgs ps --status running -q $Service).Trim()
    if ($LASTEXITCODE -ne 0 -or -not $containerId) {
        throw "Service '$Service' is not running. Run .\setup\start.ps1 first."
    }

    $labelsJson = (& docker inspect --format '{{json .Config.Labels}}' $containerId).Trim()
    if ($LASTEXITCODE -ne 0 -or -not $labelsJson) {
        throw "Could not verify container identity for service '$Service'."
    }
    $labels = $labelsJson | ConvertFrom-Json
    $identity = "$($labels.'com.docker.compose.project')|$($labels.'com.docker.compose.service')"
    if ($LASTEXITCODE -ne 0 -or $identity -ne "argus-unified|$Service") {
        throw "Refusing to update unexpected container identity '$identity'."
    }
    return $containerId
}

function Invoke-ContainerCommand([string]$ContainerId, [string]$Command, [string]$FailureMessage) {
    & docker exec --user root --workdir /tmp $ContainerId sh -c $Command
    if ($LASTEXITCODE -ne 0) { throw $FailureMessage }
}

function Sync-Directory(
    [string]$ContainerId,
    [string]$Source,
    [string]$Target,
    [string]$StageName,
    [switch]$IncludeUi
) {
    $stage = "/tmp/argus-update-$StageName"
    $backup = "$Target.argus-previous"

    Invoke-ContainerCommand $ContainerId "rm -rf '$stage' && mkdir -p '$stage'" "Could not prepare update staging for $Target."
    & docker cp ((Join-Path $Source '.')) "${ContainerId}:$stage"
    if ($LASTEXITCODE -ne 0) { throw "Could not copy $Source into the update staging area." }

    if ($IncludeUi) {
        Invoke-ContainerCommand $ContainerId "mkdir -p '$stage/modules-ui-dist'" 'Could not prepare frontend staging.'
        & docker cp ((Join-Path $UiDist '.')) "${ContainerId}:$stage/modules-ui-dist"
        if ($LASTEXITCODE -ne 0) { throw 'Could not copy the compiled frontend bundle.' }
    }

    $swapCommand = "set -eu; chown -R 10001:10001 '$stage'; rm -rf '$backup'; if [ -e '$Target' ]; then mv '$Target' '$backup'; fi; if mv '$stage' '$Target'; then rm -rf '$backup'; else mv '$backup' '$Target'; exit 1; fi"
    Invoke-ContainerCommand $ContainerId $swapCommand "Could not activate the staged update for $Target."
}

function Wait-ServiceHealth([string[]]$Services, [int]$TimeoutSeconds = 150) {
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        $pending = @()
        foreach ($service in $Services) {
            $containerId = (& docker @composeArgs ps --status running -q $service).Trim()
            if (-not $containerId) {
                $pending += "${service}:not-running"
                continue
            }
            $health = (& docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' $containerId).Trim()
            if ($health -notin @('healthy', 'running')) {
                $pending += "${service}:$health"
            }
        }
        if ($pending.Count -eq 0) { return }
        Start-Sleep -Seconds 2
    } while ((Get-Date) -lt $deadline)

    throw "Updated services did not become healthy: $($pending -join ', ')"
}

$backendServices = @('backend', 'breach-search', 'celery-worker', 'celery-beat')
$allUpdatedServices = @('intel-proxy', 'recon-engine', 'breach-search', 'backend', 'celery-worker', 'celery-beat')
$containers = @{}
foreach ($service in $allUpdatedServices) {
    $containers[$service] = Get-RunningServiceContainer $service
}

$localRequirementsHash = (Get-FileHash -LiteralPath (Join-Path $BackendSource 'requirements.txt') -Algorithm SHA256).Hash.ToLowerInvariant()
$runtimeRequirementsHash = ((& docker exec $containers['backend'] sha256sum /app/backend/requirements.txt) -split '\s+')[0].ToLowerInvariant()
if ($LASTEXITCODE -ne 0 -or $localRequirementsHash -ne $runtimeRequirementsHash) {
    throw 'Python dependencies changed. Fast update cannot install dependencies; use .\setup\rebuild.ps1 instead.'
}

Write-Host '[1/4] Compiling frontend assets locally (no dependency install)'
Push-Location $UiRoot
try {
    npm run build
    if ($LASTEXITCODE -ne 0) { throw 'Frontend build failed.' }
} finally {
    Pop-Location
}
if (-not (Test-Path -LiteralPath (Join-Path $UiDist 'index.html'))) {
    throw 'Frontend build did not produce dist/index.html.'
}

Write-Host '[2/4] Synchronizing backend and module source'
foreach ($service in $backendServices) {
    Sync-Directory $containers[$service] $BackendSource '/app/backend' "backend-$service" -IncludeUi
}
Sync-Directory $containers['intel-proxy'] $IntelSource '/app/intel-proxy' 'intel-proxy'
Sync-Directory $containers['recon-engine'] $ReconSource '/app/recon-engine' 'recon-engine'

Write-Host '[3/4] Restarting application services only'
& docker @composeArgs restart @allUpdatedServices
if ($LASTEXITCODE -ne 0) { throw 'Application service restart failed.' }

Write-Host '[4/4] Waiting for updated services to become healthy'
Wait-ServiceHealth $allUpdatedServices

Write-Host 'Backend and frontend changes are live at http://127.0.0.1:7777'
Write-Host 'No Docker image was built or pulled. Databases and infrastructure services were not restarted.'
