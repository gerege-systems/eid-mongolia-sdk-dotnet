# eidpades.dll-ийг Go цөмөөс (eid-mongolia-sdk-go, package capi) build хийнэ.
#   ./build/build-native.ps1 -Arch x64      # windows-latest дээрх MinGW gcc
#   ./build/build-native.ps1 -Arch arm64    # llvm-mingw cross (CI татаж PATH-д нэмнэ)
# Гаралт: native/win-<arch>/eidpades.dll (+ eidpades.h). Цөмийн ref нь build/go-sdk.ref (commit sha) — тогтмол.
param(
    [Parameter(Mandatory = $true)][ValidateSet('x64', 'arm64')][string]$Arch,
    [string]$Ref = (Get-Content (Join-Path $PSScriptRoot 'go-sdk.ref') -Raw).Trim(),
    [string]$Repo = 'https://github.com/gerege-systems/eid-mongolia-sdk-go.git'
)
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$src = Join-Path $root 'artifacts/go-sdk'
$out = Join-Path $root "native/win-$Arch"

if (-not (Test-Path (Join-Path $src '.git'))) {
    git init -q $src
    git -C $src remote add origin $Repo
}
git -C $src fetch -q --depth 1 origin $Ref
if ($LASTEXITCODE -ne 0) { throw "go sdk ref $Ref fetch failed" }
git -C $src checkout -q --detach FETCH_HEAD
$head = (git -C $src rev-parse HEAD).Trim()
Write-Host "go sdk: $head"

New-Item -ItemType Directory -Force $out | Out-Null
$env:CGO_ENABLED = '1'
$env:GOOS = 'windows'
$env:GOARCH = if ($Arch -eq 'x64') { 'amd64' } else { 'arm64' }
if ($Arch -eq 'arm64') { $env:CC = 'aarch64-w64-mingw32-clang' } else { $env:CC = 'gcc' }

Push-Location $src
try {
    go build -buildmode=c-shared -trimpath -ldflags "-s -w -buildid=" -o (Join-Path $out 'eidpades.dll') ./capi
    if ($LASTEXITCODE -ne 0) { throw "go build ($Arch) failed" }
}
finally { Pop-Location }
Set-Content -NoNewline (Join-Path $out 'GO_SDK_COMMIT') $head
Get-ChildItem $out | Format-Table Name, Length
