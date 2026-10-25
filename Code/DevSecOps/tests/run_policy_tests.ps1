# Chay opa test rieng tung thu muc chinh sach.
# Ly do: g0, g1, g2 deu khai bao "package main", chay chung se gop moi luat deny.
$root = Split-Path -Parent $PSScriptRoot
$failed = 0
foreach ($g in "g0", "g1", "g2") {
    Write-Host "== policy/$g =="
    opa test (Join-Path $root "policy\$g") -v
    if ($LASTEXITCODE -ne 0) { $failed++ }
}
if ($failed -gt 0) {
    Write-Host "$failed nhom that bai"
    exit 1
}
Write-Host "Tat ca nhom deu xanh"