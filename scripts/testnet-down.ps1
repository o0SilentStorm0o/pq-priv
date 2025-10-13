# PowerShell version of testnet-down.sh for Windows
$ErrorActionPreference = "Stop"

$ROOT_DIR = Split-Path -Parent $PSScriptRoot
$TESTNET_DIR = Join-Path $ROOT_DIR ".testnet"
$PID_FILE = Join-Path $TESTNET_DIR "node.pid"

function Stop-TestnetNode {
    if (Test-Path $PID_FILE) {
        $pid = Get-Content $PID_FILE -ErrorAction SilentlyContinue
        if ($pid) {
            $process = Get-Process -Id $pid -ErrorAction SilentlyContinue
            if ($process) {
                Write-Host "Stopping testnet node (PID $pid)..." -ForegroundColor Yellow
                Stop-Process -Id $pid -Force -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 1
                
                # Verify stopped
                $stillRunning = Get-Process -Id $pid -ErrorAction SilentlyContinue
                if ($stillRunning) {
                    Write-Host "Warning: Process may still be running" -ForegroundColor Yellow
                } else {
                    Write-Host "Node stopped successfully" -ForegroundColor Green
                }
            } else {
                Write-Host "No running node found with PID $pid" -ForegroundColor Gray
            }
        }
        Remove-Item $PID_FILE -ErrorAction SilentlyContinue
    } else {
        Write-Host "No PID file found - node may not be running" -ForegroundColor Gray
    }
}

Write-Host "Stopping testnet..." -ForegroundColor Cyan
Stop-TestnetNode

# Also check for any orphaned node processes
$orphanedProcesses = Get-Process -Name "node" -ErrorAction SilentlyContinue | Where-Object {
    $_.Path -and $_.Path -like "*pq-priv*"
}

if ($orphanedProcesses) {
    Write-Host "`nFound orphaned node processes:" -ForegroundColor Yellow
    $orphanedProcesses | ForEach-Object {
        Write-Host "  PID $($_.Id): $($_.Path)" -ForegroundColor Gray
        Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
    }
    Write-Host "Orphaned processes stopped" -ForegroundColor Green
}

Write-Host "`nTestnet stopped" -ForegroundColor Green
exit 0
