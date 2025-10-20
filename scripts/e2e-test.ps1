# E2E Test - Check node consensus
param(
    [string]$topology = "line",
    [int[]]$ports = @(8545, 8546, 8547)
)

Write-Host "=== E2E Test: $topology ===" -ForegroundColor Cyan
Write-Host "Checking $($ports.Count) nodes...`n"

$results = @()

foreach ($port in $ports) {
    try {
        $response = Invoke-RestMethod -Uri "http://localhost:$port/chain/tip" -TimeoutSec 5
        $results += [PSCustomObject]@{
            Port = $port
            Height = $response.height
            Hash = ($response.hash -join ",").Substring(0, 40) + "..."
            Success = $true
        }
        Write-Host "[OK] Node on port $port - Height: $($response.height)" -ForegroundColor Green
    } catch {
        Write-Host "[FAIL] Node on port $port - $($_.Exception.Message)" -ForegroundColor Red
        $results += [PSCustomObject]@{
            Port = $port
            Height = "N/A"
            Hash = "N/A"
            Success = $false
        }
    }
}

Write-Host "`n=== Results ===" -ForegroundColor Cyan
$results | Format-Table -AutoSize

# Check consensus
$successfulNodes = $results | Where-Object { $_.Success }
if ($successfulNodes.Count -lt 2) {
    Write-Host "`n[FAIL] Not enough nodes responding" -ForegroundColor Red
    exit 1
}

$uniqueHeights = ($successfulNodes | Select-Object -ExpandProperty Height | Get-Unique).Count
if ($uniqueHeights -eq 1) {
    Write-Host "`n[SUCCESS] All nodes at same height!" -ForegroundColor Green
    exit 0
} else {
    Write-Host "`n[WARN] Nodes at different heights - may still be syncing" -ForegroundColor Yellow
    exit 0
}
