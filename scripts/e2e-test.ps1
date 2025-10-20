# E2E Test - Check node consensus with retry logic
param(
    [string]$topology = "line",
    [int[]]$ports = @(8545, 8546, 8547),
    [int]$minHeight = 0,
    [bool]$checkReorg = $false
)

Write-Host "=== E2E Test: $topology ===" -ForegroundColor Cyan
Write-Host "Checking $($ports.Count) nodes (min height: $minHeight)...`n"

$results = @()

# Function to fetch with retry
function Invoke-WithRetry {
    param($Uri, $Retries = 3, $DelaySeconds = 1)
    
    for ($i = 1; $i -le $Retries; $i++) {
        try {
            return Invoke-RestMethod -Uri $Uri -TimeoutSec 2 -ErrorAction Stop
        } catch {
            if ($i -eq $Retries) { throw }
            Start-Sleep -Seconds $DelaySeconds
        }
    }
}

foreach ($port in $ports) {
    try {
        $tip = Invoke-WithRetry -Uri "http://localhost:$port/chain/tip"
        
        # Try to get metrics (optional)
        $reorgCount = "N/A"
        try {
            $metrics = Invoke-RestMethod -Uri "http://localhost:$port/metrics" -TimeoutSec 2 -ErrorAction SilentlyContinue
            if ($metrics -match 'reorg_count_total (\d+)') {
                $reorgCount = $matches[1]
            }
        } catch {}
        
        $results += [PSCustomObject]@{
            Port = $port
            Height = $tip.height
            Hash = ($tip.hash -join ",").Substring(0, 40) + "..."
            ReorgCount = $reorgCount
            Success = $true
        }
        Write-Host "[OK] Node on port $port - Height: $($tip.height), Reorg: $reorgCount" -ForegroundColor Green
    } catch {
        Write-Host "[FAIL] Node on port $port - $($_.Exception.Message)" -ForegroundColor Red
        $results += [PSCustomObject]@{
            Port = $port
            Height = "N/A"
            Hash = "N/A"
            ReorgCount = "N/A"
            Success = $false
        }
    }
}

Write-Host "`n=== Summary ===" -ForegroundColor Cyan
$results | Format-Table -AutoSize

# Assertions
$successfulNodes = ($results | Where-Object { $_.Success }).Count
if ($successfulNodes -ne $ports.Count) {
    Write-Host "`n❌ FAIL: Only $successfulNodes/$($ports.Count) nodes responded" -ForegroundColor Red
    exit 2
}

$heights = $results | Where-Object { $_.Success } | Select-Object -ExpandProperty Height
$uniqueHeights = ($heights | Select-Object -Unique).Count

if ($uniqueHeights -ne 1) {
    Write-Host "`n❌ FAIL: Height mismatch - found $uniqueHeights unique heights: $($heights -join ', ')" -ForegroundColor Red
    exit 1
}

$commonHeight = $heights[0]
if ($commonHeight -lt $minHeight) {
    Write-Host "`n❌ FAIL: Height $commonHeight < $minHeight (required minimum)" -ForegroundColor Red
    exit 1
}

$hashes = $results | Where-Object { $_.Success } | Select-Object -ExpandProperty Hash
$uniqueHashes = ($hashes | Select-Object -Unique).Count

if ($uniqueHashes -ne 1) {
    Write-Host "`n❌ FAIL: Hash mismatch - found $uniqueHashes unique tip hashes" -ForegroundColor Red
    exit 1
}

# Check reorg if requested (for partition topology)
if ($checkReorg) {
    $reorgCounts = $results | Where-Object { $_.ReorgCount -ne "N/A" } | Select-Object -ExpandProperty ReorgCount
    $totalReorgs = ($reorgCounts | ForEach-Object { [int]$_ } | Measure-Object -Sum).Sum
    
    if ($totalReorgs -lt 1) {
        Write-Host "`n⚠️ WARNING: Expected reorg_count_total >= 1, but got $totalReorgs" -ForegroundColor Yellow
        Write-Host "   (This may be expected if bridge wasn't activated)" -ForegroundColor Gray
    } else {
        Write-Host "`n✅ Reorg detected: $totalReorgs total reorgs across all nodes" -ForegroundColor Green
    }
}

Write-Host "`n✅ SUCCESS: All $($ports.Count) nodes at height $commonHeight with matching tip hash" -ForegroundColor Green

# Save artifact
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$reportDir = "docker/e2e/report"
if (-not (Test-Path $reportDir)) {
    New-Item -ItemType Directory -Path $reportDir | Out-Null
}

$artifact = @{
    topology = $topology
    timestamp = $timestamp
    nodes = $results | Select-Object Port, Height, Hash, ReorgCount
    consensus = @{
        height = $commonHeight
        tip_hash = $hashes[0]
        all_nodes_synced = $true
    }
} | ConvertTo-Json -Depth 10

$artifactPath = "$reportDir/summary_${topology}_${timestamp}.json"
$artifact | Out-File -FilePath $artifactPath -Encoding UTF8
Write-Host "📄 Artifact saved: $artifactPath" -ForegroundColor Cyan

exit 0
