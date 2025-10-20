# Mine blocks helper - triggers /dev/mine endpoint N times
param(
    [int]$port = 8545,
    [int]$count = 100,
    [int]$delayMs = 100
)

Write-Host "Mining $count blocks on port $port..." -ForegroundColor Cyan

$success = 0
$failed = 0

for ($i = 1; $i -le $count; $i++) {
    try {
        $response = Invoke-RestMethod -Uri "http://localhost:$port/dev/mine" -Method Post -TimeoutSec 5
        $success++
        
        if ($i % 10 -eq 0) {
            Write-Host "  Mined $i blocks..." -ForegroundColor Green
        }
        
        Start-Sleep -Milliseconds $delayMs
    } catch {
        $failed++
        Write-Host "  [WARN] Block $i failed: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

Write-Host "`nMining complete: $success success, $failed failed" -ForegroundColor Cyan

# Check final height
try {
    $tip = Invoke-RestMethod -Uri "http://localhost:$port/chain/tip" -TimeoutSec 5
    Write-Host "Final height: $($tip.height)" -ForegroundColor Green
} catch {
    Write-Host "Could not fetch final height" -ForegroundColor Red
}
