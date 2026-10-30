# run_policy_tests.ps1
# Chay toan bo OPA unit tests cho G0, G1, G2 bang conftest verify.
# Nguoi viet: Hoang Gia Long (Long)

[CmdletBinding()]
param(
    [string]$PolicyDir = "",
    [switch]$Detailed
)

$ErrorActionPreference = "Stop"

if ([string]::IsNullOrEmpty($PolicyDir)) {
    $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
    $PolicyDir = Join-Path (Split-Path -Parent $scriptDir) "policy"
}

Write-Host "Kiem tra conftest trong he thong..." -ForegroundColor Cyan
if (-not (Get-Command conftest -ErrorAction SilentlyContinue)) {
    Write-Error "conftest khong tim thay trong PATH. Cai dat tai https://www.conftest.dev"
    exit 1
}

$ver = conftest --version
Write-Host "Phien ban conftest: $ver" -ForegroundColor Green

$gates = @("g0", "g1", "g2")
$results = @()
$allPassed = $true

foreach ($g in $gates) {
    $targetDir = Join-Path $PolicyDir $g
    if (-not (Test-Path $targetDir)) {
        Write-Warning "Bo qua $g - thu muc khong ton tai: $targetDir"
        continue
    }

    Write-Host "`n=== Kiem thu policy: $($g.ToUpper()) ===" -ForegroundColor Yellow
    $out = conftest verify -p $targetDir 2>&1
    $code = $LASTEXITCODE

    if ($Detailed) {
        $out | ForEach-Object { Write-Host "  $_" }
    }

    $isPass = ($code -eq 0)
    if (-not $isPass) {
        $allPassed = $false
    }

    $statusStr = if ($isPass) { "PASS" } else { "FAIL" }
    $color = if ($isPass) { "Green" } else { "Red" }
    Write-Host "Ket qua $($g.ToUpper()): $statusStr (Exit code: $code)" -ForegroundColor $color

    $results += [PSCustomObject]@{
        Policy   = $g.ToUpper()
        Status   = $statusStr
        ExitCode = $code
    }
}

Write-Host "`n=== BANG TONG HOP KIEM THU OPA / REGOS ===" -ForegroundColor Cyan
$results | Format-Table -AutoSize

# Ghi ket qua JSON
$rootDir = Split-Path -Parent (Split-Path -Parent $PolicyDir)
$metricsDir = Join-Path $PolicyDir "..\tests\results\metrics"
if (Test-Path (Split-Path -Parent $metricsDir)) {
    if (-not (Test-Path $metricsDir)) {
        New-Item -ItemType Directory -Path $metricsDir -Force | Out-Null
    }
    $jsonPath = Join-Path $metricsDir "policy_test_results.json"
    $results | ConvertTo-Json | Set-Content -Path $jsonPath -Encoding UTF8
    Write-Host "Ket qua luu tai: $jsonPath" -ForegroundColor DarkCyan
}

if ($allPassed) {
    Write-Host "`nTat ca policy unit tests deu PASS thanh cong!" -ForegroundColor Green
    exit 0
} else {
    Write-Host "`nCo policy unit test bi FAIL!" -ForegroundColor Red
    exit 1
}
