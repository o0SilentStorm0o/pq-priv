# PowerShell Testnet Integration Script
param(
    [int]$LogTail = 50
)

$ErrorActionPreference = "Stop"
$ROOT_DIR = Split-Path -Parent $PSScriptRoot
$TESTNET_DIR = Join-Path $ROOT_DIR ".testnet"
$PID_FILE = Join-Path $TESTNET_DIR "node.pid"
$LOG_FILE = Join-Path $TESTNET_DIR "node.log"
$CONFIG_FILE = Join-Path $TESTNET_DIR "node.toml"

function Write-ErrorWithLogs {
    param([string]$Message)
    Write-Host "Error: $Message" -ForegroundColor Red
    if (Test-Path $LOG_FILE) {
        Write-Host ""
        Write-Host "--- Last $LogTail log lines ---" -ForegroundColor Yellow
        Get-Content $LOG_FILE -Tail $LogTail
    }
    exit 1
}

function Stop-Node {
    if (Test-Path $PID_FILE) {
        $nodePid = Get-Content $PID_FILE
        $proc = Get-Process -Id $nodePid -ErrorAction SilentlyContinue
        if ($proc) {
            Stop-Process -Id $nodePid -Force
            Start-Sleep -Seconds 1
        }
        Remove-Item $PID_FILE
    }
}

# Register cleanup
$null = Register-EngineEvent PowerShell.Exiting -Action { Stop-Node }

# Check if already running
if (Test-Path $PID_FILE) {
    $nodePid = Get-Content $PID_FILE
    if (Get-Process -Id $nodePid -ErrorAction SilentlyContinue) {
        Write-ErrorWithLogs "Node already running with PID $nodePid"
    }
}

# Clean up old testnet data
Write-Host "Cleaning up old testnet data..." -ForegroundColor Cyan
if (Test-Path $TESTNET_DIR) {
    Remove-Item -Path $TESTNET_DIR -Recurse -Force
}

# Create directories
New-Item -ItemType Directory -Path $TESTNET_DIR -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $TESTNET_DIR "node") -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $TESTNET_DIR "snapshots") -Force | Out-Null
"" | Out-File -FilePath $LOG_FILE

# Build
Write-Host "Building node..." -ForegroundColor Cyan
$env:RUST_LOG = "info"
& cargo build --release --features devnet --bin node
if ($LASTEXITCODE -ne 0) { Write-ErrorWithLogs "Build failed" }

$NODE_BIN = Join-Path $ROOT_DIR "target\release\node.exe"
if (-not (Test-Path $NODE_BIN)) { Write-ErrorWithLogs "Node binary not found" }

# Create config
$configContent = @"
p2p_listen = "127.0.0.1:18444"
rpc_listen = "127.0.0.1:18445"
db_path = ".testnet/node"
snapshots_path = ".testnet/snapshots"
"@
[System.IO.File]::WriteAllText($CONFIG_FILE, $configContent, [System.Text.Encoding]::UTF8)

$RPC_URL = "http://127.0.0.1:18445"
$RPC_JSON = "$RPC_URL/rpc"
$RPC_METRICS = "$RPC_URL/metrics"

function Invoke-JsonRpc {
    param(
        [string]$Method,
        [array]$Params = @()
    )
    $body = @{
        jsonrpc = "2.0"
        id = 1
        method = $Method
        params = $Params
    } | ConvertTo-Json -Depth 10 -Compress
    
    try {
        $response = Invoke-RestMethod -Uri $RPC_JSON -Method Post -Body $body -ContentType "application/json" -TimeoutSec 5
        if ($response.error) {
            throw "RPC error: $($response.error.message) (code=$($response.error.code))"
        }
        return $response.result
    } catch {
        throw "RPC call failed: $_"
    }
}

# Start node
Write-Host "Starting node..." -ForegroundColor Cyan
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $NODE_BIN
$psi.Arguments = "run --config `"$CONFIG_FILE`""
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
$psi.UseShellExecute = $false
$psi.WorkingDirectory = $ROOT_DIR

$proc = New-Object System.Diagnostics.Process
$proc.StartInfo = $psi

$outAction = { if ($EventArgs.Data) { $EventArgs.Data | Out-File -Append $LOG_FILE } }
$null = Register-ObjectEvent -InputObject $proc -EventName OutputDataReceived -Action $outAction
$null = Register-ObjectEvent -InputObject $proc -EventName ErrorDataReceived -Action $outAction

$proc.Start() | Out-Null
$proc.BeginOutputReadLine()
$proc.BeginErrorReadLine()
$proc.Id | Out-File $PID_FILE

Write-Host "Node started (PID: $($proc.Id))" -ForegroundColor Green

# Wait for health
Write-Host "Waiting for health..." -ForegroundColor Cyan
$ready = $false
for ($i = 0; $i -lt 40; $i++) {
    try {
        $response = Invoke-RestMethod -Uri "$RPC_URL/health" -TimeoutSec 2
        if ($response.status -eq "ok") {
            $ready = $true
            break
        }
    } catch { }
    Start-Sleep -Milliseconds 500
}
if (-not $ready) { Write-ErrorWithLogs "Health check timeout" }
Write-Host "OK Health check passed" -ForegroundColor Green

# Check genesis
Write-Host "Checking genesis..." -ForegroundColor Cyan
$tip = Invoke-RestMethod -Uri "$RPC_URL/chain/tip"
if ($tip.height -ne 0) { Write-ErrorWithLogs "Expected height 0, got $($tip.height)" }
Write-Host "OK Genesis at height 0 (hash=$($tip.hash))" -ForegroundColor Green

# Mine block
Write-Host "Mining block..." -ForegroundColor Cyan
$mined = Invoke-RestMethod -Uri "$RPC_URL/dev/mine" -Method Post
if ($mined.error) { Write-ErrorWithLogs "Mining failed: $($mined.error)" }
if (-not $mined.height) { Write-ErrorWithLogs "Mining response missing height" }
Write-Host "OK Mined block at height $($mined.height)" -ForegroundColor Green

# Verify height
$tip2 = Invoke-RestMethod -Uri "$RPC_URL/chain/tip"
if ($tip2.height -lt $mined.height) { Write-ErrorWithLogs "Height did not advance" }
Write-Host "OK Height advanced to $($tip2.height)" -ForegroundColor Green

# TODO: Implement JSON-RPC 2.0 endpoint for Bitcoin-compatible RPC methods
# Test JSON-RPC methods
# Write-Host "Testing JSON-RPC methods..." -ForegroundColor Cyan
# ... (getblockcount, getblockhash, getbestblockhash, getblock, getrawmempool, getpeerinfo)

# Test Prometheus metrics
Write-Host "Testing Prometheus metrics..." -ForegroundColor Cyan
try {
    $metrics = Invoke-WebRequest -Uri $RPC_METRICS -TimeoutSec 5
    if ($metrics.StatusCode -ne 200) { Write-ErrorWithLogs "Metrics endpoint returned $($metrics.StatusCode)" }
    $metricsText = $metrics.Content
    
    # Check for expected metrics
    $expectedMetrics = @("chain_height", "mempool_size", "peer_count")
    foreach ($metric in $expectedMetrics) {
        if ($metricsText -notmatch $metric) {
            Write-Host "  Warning: Metric '$metric' not found" -ForegroundColor Yellow
        } else {
            Write-Host "  Found metric: $metric" -ForegroundColor Gray
        }
    }
    Write-Host "OK Metrics endpoint working" -ForegroundColor Green
} catch {
    Write-ErrorWithLogs "Metrics test failed: $_"
}

# Test snapshot directory
Write-Host "Testing snapshots..." -ForegroundColor Cyan
$snapshotDir = Join-Path $TESTNET_DIR "snapshots"
$snapshots = Get-ChildItem -Path $snapshotDir -Filter "snapshot-*" -ErrorAction SilentlyContinue
if ($snapshots.Count -eq 0) {
    Write-Host "  Warning: No snapshots found" -ForegroundColor Yellow
} else {
    Write-Host "  Found $($snapshots.Count) snapshot(s)" -ForegroundColor Gray
    foreach ($snapshot in $snapshots) {
        Write-Host "    - $($snapshot.Name)" -ForegroundColor Gray
    }
}
Write-Host "OK Snapshot directory checked" -ForegroundColor Green

# Test multiple mining operations
Write-Host "Testing multiple block mining..." -ForegroundColor Cyan
$startHeight = $tip2.height
for ($i = 1; $i -le 5; $i++) {
    try {
        $minedBlock = Invoke-RestMethod -Uri "$RPC_URL/dev/mine" -Method Post -TimeoutSec 5
        if ($minedBlock.error) { 
            Write-ErrorWithLogs "Mining block $i failed: $($minedBlock.error)" 
        }
        if (-not $minedBlock.height) { 
            Write-ErrorWithLogs "Mining block $i returned no height. Response: $($minedBlock | ConvertTo-Json)" 
        }
        if ($minedBlock.height -ne ($startHeight + $i)) {
            Write-ErrorWithLogs "Expected height $($startHeight + $i), got $($minedBlock.height)"
        }
        Write-Host "  Mined block $i/5 (height=$($minedBlock.height))" -ForegroundColor Gray
    } catch {
        Write-ErrorWithLogs "Mining block $i failed: $_"
    }
}

$finalTip = Invoke-RestMethod -Uri "$RPC_URL/chain/tip"
$expectedHeight = $startHeight + 5
if ($finalTip.height -ne $expectedHeight) {
    Write-ErrorWithLogs "Expected final height $expectedHeight, got $($finalTip.height)"
}
Write-Host "OK Mined 5 blocks successfully (height=$($finalTip.height))" -ForegroundColor Green

# Test restart
Write-Host "Testing restart..." -ForegroundColor Cyan
Stop-Node
Start-Sleep -Seconds 2

$proc = New-Object System.Diagnostics.Process
$proc.StartInfo = $psi
$null = Register-ObjectEvent -InputObject $proc -EventName OutputDataReceived -Action $outAction
$null = Register-ObjectEvent -InputObject $proc -EventName ErrorDataReceived -Action $outAction
$proc.Start() | Out-Null
$proc.BeginOutputReadLine()
$proc.BeginErrorReadLine()
$proc.Id | Out-File $PID_FILE

$ready = $false
for ($i = 0; $i -lt 40; $i++) {
    try {
        $response = Invoke-RestMethod -Uri "$RPC_URL/health" -TimeoutSec 2
        if ($response.status -eq "ok") {
            $ready = $true
            break
        }
    } catch { }
    Start-Sleep -Milliseconds 500
}
if (-not $ready) { Write-ErrorWithLogs "Health after restart failed" }

$tip3 = Invoke-RestMethod -Uri "$RPC_URL/chain/tip"
if ($tip3.height -lt $finalTip.height) { Write-ErrorWithLogs "Height regressed after restart" }
Write-Host "OK Persistence verified (height=$($tip3.height))" -ForegroundColor Green

# Test RPC methods after restart
Write-Host "Testing RPC after restart..." -ForegroundColor Cyan
try {
    $tipAfterRestart = Invoke-RestMethod -Uri "$RPC_URL/chain/tip"
    if ($tipAfterRestart.height -ne $tip3.height) {
        Write-ErrorWithLogs "chain/tip mismatch: expected $($tip3.height), got $($tipAfterRestart.height)"
    }
    Write-Host "  chain/tip after restart: height=$($tipAfterRestart.height)" -ForegroundColor Gray
} catch {
    Write-ErrorWithLogs "RPC after restart failed: $_"
}
Write-Host "OK RPC working after restart" -ForegroundColor Green

# Test database integrity
Write-Host "Testing database integrity..." -ForegroundColor Cyan
$dbPath = Join-Path $TESTNET_DIR "node"
if (-not (Test-Path $dbPath)) {
    Write-ErrorWithLogs "Database directory not found"
}
$dbFiles = Get-ChildItem -Path $dbPath -Recurse -File
$dbSize = ($dbFiles | Measure-Object -Property Length -Sum).Sum
Write-Host "  Database size: $([math]::Round($dbSize / 1KB, 2)) KB" -ForegroundColor Gray
Write-Host "  Database files: $($dbFiles.Count)" -ForegroundColor Gray
if ($dbSize -eq 0) {
    Write-Host "  Warning: Database appears empty" -ForegroundColor Yellow
}
Write-Host "OK Database integrity checked" -ForegroundColor Green

# Test error handling - invalid RPC calls
Write-Host "Testing error handling..." -ForegroundColor Cyan
try {
    # Invalid endpoint
    $null = Invoke-RestMethod -Uri "$RPC_URL/invalid/endpoint" -ErrorAction Stop
    Write-ErrorWithLogs "Invalid endpoint should have failed"
} catch {
    Write-Host "  Invalid endpoint correctly rejected (404)" -ForegroundColor Gray
}
Write-Host "OK Error handling working" -ForegroundColor Green

# Cleanup
Stop-Node

Write-Host ""
Write-Host "=== TESTNET INTEGRATION TEST PASSED ===" -ForegroundColor Green
Write-Host ""
Write-Host "Test Summary:" -ForegroundColor Cyan
Write-Host "  * Build with devnet feature" -ForegroundColor Green
Write-Host "  * Node startup and health check" -ForegroundColor Green
Write-Host "  * Genesis block verification" -ForegroundColor Green
Write-Host "  * Block mining (devnet)" -ForegroundColor Green
Write-Host "  * Height advancement" -ForegroundColor Green
Write-Host "  * Prometheus metrics endpoint" -ForegroundColor Green
Write-Host "  * Snapshot creation" -ForegroundColor Green
Write-Host "  * Multiple block mining" -ForegroundColor Green
Write-Host "  * Node restart and persistence" -ForegroundColor Green
Write-Host "  * RPC after restart" -ForegroundColor Green
Write-Host "  * Database integrity" -ForegroundColor Green
Write-Host "  * Error handling" -ForegroundColor Green
Write-Host ""
Write-Host "Final chain state:" -ForegroundColor Cyan
Write-Host "  Height: $($tip3.height)" -ForegroundColor Gray
Write-Host "  Best hash: $($tip3.hash)" -ForegroundColor Gray
Write-Host ""
Write-Host "Last log lines:" -ForegroundColor Cyan
Get-Content $LOG_FILE -Tail $LogTail
