# Cryptography Integration Test Script
# Tests Dilithium2 implementation in isolated Docker environment

Write-Host "=== PQ-PRIV Cryptography Integration Tests ===" -ForegroundColor Cyan
Write-Host ""

# Clean up any existing containers
Write-Host "[1/5] Cleaning up existing test containers..." -ForegroundColor Yellow
docker-compose -f docker/e2e/crypto-test.yml down -v 2>$null

# Build the Docker image
Write-Host "[2/5] Building Docker image..." -ForegroundColor Yellow
docker-compose -f docker/e2e/crypto-test.yml build

if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Docker build failed!" -ForegroundColor Red
    exit 1
}

# Start the test environment
Write-Host "[3/5] Starting test environment..." -ForegroundColor Yellow
docker-compose -f docker/e2e/crypto-test.yml up -d node_a_dilithium node_b_dilithium

# Wait for nodes to be ready
Write-Host "[4/5] Waiting for nodes to initialize..." -ForegroundColor Yellow
Start-Sleep -Seconds 5

# Run the crypto tester
Write-Host "[5/5] Running cryptography tests..." -ForegroundColor Yellow
Write-Host ""
docker-compose -f docker/e2e/crypto-test.yml run --rm crypto_tester

$testResult = $LASTEXITCODE

# Show logs if tests failed
if ($testResult -ne 0) {
    Write-Host ""
    Write-Host "=== Node A Logs ===" -ForegroundColor Red
    docker-compose -f docker/e2e/crypto-test.yml logs node_a_dilithium
    
    Write-Host ""
    Write-Host "=== Node B Logs ===" -ForegroundColor Red
    docker-compose -f docker/e2e/crypto-test.yml logs node_b_dilithium
}

# Clean up
Write-Host ""
Write-Host "Cleaning up test environment..." -ForegroundColor Yellow
docker-compose -f docker/e2e/crypto-test.yml down -v

Write-Host ""
if ($testResult -eq 0) {
    Write-Host "✓ All cryptography tests PASSED!" -ForegroundColor Green
} else {
    Write-Host "✗ Cryptography tests FAILED!" -ForegroundColor Red
}

Write-Host ""
exit $testResult
