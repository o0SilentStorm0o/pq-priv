# Collect Docker logs for E2E test artifacts
param(
    [string]$topology = "line",
    [string]$composeFile = "docker/e2e/line.yml"
)

Write-Host "=== Collecting logs for $topology topology ===" -ForegroundColor Cyan

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$logDir = "docker/e2e/report/logs_${topology}_${timestamp}"

if (-not (Test-Path $logDir)) {
    New-Item -ItemType Directory -Path $logDir | Out-Null
}

# Get running containers from compose file
$containers = docker compose -f $composeFile ps --format json | ConvertFrom-Json

foreach ($container in $containers) {
    $containerName = $container.Name
    $logFile = "$logDir/${containerName}.log"
    
    Write-Host "Collecting logs from $containerName..." -ForegroundColor Gray
    docker logs $containerName > $logFile 2>&1
}

Write-Host "`n✅ Logs collected in: $logDir" -ForegroundColor Green
Write-Host "   Files: $((Get-ChildItem $logDir).Count)" -ForegroundColor Gray
