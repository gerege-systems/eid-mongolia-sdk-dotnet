#!/usr/bin/env bash
# RP SDK-ийн cross-SDK conformance корпусыг (eid-mongolia-sdk-go testdata/conformance, rp-conformance/2)
# build/go-sdk-conformance.ref commit-оос testdata/conformance руу хуулна. pki/keys/ (генераторын хувийн түлхүүр)
# хуулагдахгүй (корпусын README). --check: хуулбар тэр commit-той байт-ижил эсэхийг шалгана (CI).
# Файл бүрийн SHA-256-ийг manifest.json-оор ConformanceTests.Manifest шалгана.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
ref="$(tr -d '[:space:]' < "$root/build/go-sdk-conformance.ref")"
repo="https://github.com/gerege-systems/eid-mongolia-sdk-go.git"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
git -C "$tmp" init -q
git -C "$tmp" remote add origin "$repo"
git -C "$tmp" fetch -q --depth 1 origin "$ref"
git -C "$tmp" checkout -q FETCH_HEAD
src="$tmp/testdata/conformance"
dst="$root/testdata/conformance"
test -f "$src/manifest.json" || { echo "testdata/conformance/manifest.json алга (eid-mongolia-sdk-go@$ref)" >&2; exit 1; }
rm -rf "$src/pki/keys"
if [[ "${1:-}" == "--check" ]]; then
  diff -r "$src" "$dst" && echo "testdata/conformance == eid-mongolia-sdk-go@$ref (pki/keys-гүй)"
  exit
fi
rm -rf "$dst"
mkdir -p "$(dirname "$dst")"
cp -R "$src" "$dst"
echo "synced testdata/conformance from eid-mongolia-sdk-go@$ref"
