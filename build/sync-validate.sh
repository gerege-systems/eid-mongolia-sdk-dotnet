#!/usr/bin/env bash
# ValidatePDF conformance корпусыг (eid-mongolia-sdk-go pades/testdata/validate, pades-validate/1) build/go-sdk-validate.ref
# commit-оос testdata/pades-validate руу хуулна: validate/ (pki/*.key.pem — тестийн хувийн түлхүүр — хуулагдахгүй) ба
# manifest.json-ийн заасан golden/ файлууд (зөвхөн тэдгээр; testdata/golden нь signing-ийн өөр хувилбарт бэхлэгдсэн).
# Замууд Go-ийн pades/testdata-тай ижил харьцангуй. SHA256SUMS — файл бүрийн хэш (ValidatePdfCorpusTests.Manifest шалгана).
# --check: хуулбар тэр commit-той байт-ижил эсэхийг шалгана (CI).
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
ref="$(tr -d '[:space:]' < "$root/build/go-sdk-validate.ref")"
repo="https://github.com/gerege-systems/eid-mongolia-sdk-go.git"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
git -C "$tmp" init -q src
git -C "$tmp/src" remote add origin "$repo"
git -C "$tmp/src" fetch -q --depth 1 origin "$ref"
git -C "$tmp/src" checkout -q FETCH_HEAD
from="$tmp/src/pades/testdata"
stage="$tmp/stage"
dst="$root/testdata/pades-validate"
test -f "$from/validate/manifest.json" || { echo "pades/testdata/validate/manifest.json алга (eid-mongolia-sdk-go@$ref)" >&2; exit 1; }
mkdir -p "$stage"
cp -R "$from/validate" "$stage/validate"
rm -f "$stage"/validate/pki/*.key.pem
grep -o '"golden/[^"]*"' "$stage/validate/manifest.json" | tr -d '"' | LC_ALL=C sort -u | while read -r f; do
  mkdir -p "$stage/$(dirname "$f")"
  cp "$from/$f" "$stage/$f"
done
sum() { if command -v sha256sum >/dev/null; then sha256sum "$@"; else shasum -a 256 "$@"; fi; }
(cd "$stage" && find . -type f | sed 's|^\./||' | LC_ALL=C sort | while read -r f; do sum "$f"; done) > "$tmp/SHA256SUMS"
mv "$tmp/SHA256SUMS" "$stage/SHA256SUMS"
if [[ "${1:-}" == "--check" ]]; then
  diff -r "$stage" "$dst" && echo "testdata/pades-validate == eid-mongolia-sdk-go@$ref pades/testdata/validate (+ golden subset)"
  exit
fi
rm -rf "$dst"
mkdir -p "$(dirname "$dst")"
cp -R "$stage" "$dst"
echo "synced testdata/pades-validate from eid-mongolia-sdk-go@$ref"
