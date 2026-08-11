param(
    [switch]$Force,
    [switch]$AI,
    [switch]$Tor,
    [switch]$Monitoring
)

$ErrorActionPreference = 'Stop'
$RepoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$EnvFile = Join-Path $RepoRoot '.env'
$ComposeFile = Join-Path $RepoRoot 'docker\docker-compose.yml'
Set-Location -LiteralPath $RepoRoot

function New-HexSecret([int]$Bytes = 32) {
    $buffer = New-Object byte[] $Bytes
    $generator = [Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $generator.GetBytes($buffer)
    } finally {
        $generator.Dispose()
    }
    return ([BitConverter]::ToString($buffer) -replace '-', '').ToLowerInvariant()
}

if ((Test-Path -LiteralPath $EnvFile) -and -not $Force) {
    Write-Host 'Existing .env preserved. Use -Force only when intentionally rotating every generated local secret.'
} else {
    if ((Test-Path -LiteralPath $EnvFile) -and $Force) {
        Write-Warning 'Replacing .env changes database, cache, API, and administrator credentials.'
    }

    $content = Get-Content -LiteralPath (Join-Path $RepoRoot '.env.example') -Raw -Encoding UTF8
    $content = $content.Replace('CHANGE_ME_STRONG_DATABASE_PASSWORD', (New-HexSecret 24))
    $content = $content.Replace('CHANGE_ME_STRONG_REDIS_PASSWORD', (New-HexSecret 24))
    $content = $content.Replace('CHANGE_ME_RANDOM_SECRET_AT_LEAST_64_CHARACTERS', (New-HexSecret 48))
    $content = $content.Replace('CHANGE_ME_STRONG_ADMIN_PASSWORD', (New-HexSecret 24))
    $content = $content.Replace('CHANGE_ME_RANDOM_PRIVATE_SALT', (New-HexSecret 32))
    $content = $content.Replace('CHANGE_ME_RANDOM_INTERNAL_BREACH_API_KEY', (New-HexSecret 32))
    $content = $content.Replace('CHANGE_ME_STRONG_CLICKHOUSE_PASSWORD', (New-HexSecret 24))

    [IO.File]::WriteAllText(
        $EnvFile,
        $content,
        (New-Object Text.UTF8Encoding($false))
    )
    Write-Host 'Created .env with cryptographically random local secrets.'
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

Write-Host 'Preparing first-install infrastructure images (missing images only)...'
& docker @composeArgs pull --ignore-buildable --policy missing
if ($LASTEXITCODE -ne 0) { throw 'Infrastructure image preparation failed.' }

Write-Host 'Building the local Argus application image...'
& docker @composeArgs build backend
if ($LASTEXITCODE -ne 0) { throw 'Argus image build failed.' }

Write-Host 'First-time setup is complete. Review .env, then use .\setup\start.ps1 for daily startup.'
