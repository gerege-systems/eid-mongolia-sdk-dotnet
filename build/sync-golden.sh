#!/usr/bin/env bash
# Go reference-ийн golden fixture-ийг (eid-mongolia-sdk-go pades/testdata/golden) build/go-sdk.ref commit-оос
# testdata/golden руу хуулна. --check: хуулбар тэр commit-той яг ижил эсэхийг шалгана (CI).
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
ref="$(tr -d '[:space:]' < "$root/build/go-sdk.ref")"
repo="https://github.com/gerege-systems/eid-mongolia-sdk-go.git"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
git -C "$tmp" init -q
git -C "$tmp" remote add origin "$repo"
git -C "$tmp" fetch -q --depth 1 origin "$ref"
git -C "$tmp" checkout -q FETCH_HEAD
src="$tmp/pades/testdata/golden"
dst="$root/testdata/golden"
if [[ "${1:-}" == "--check" ]]; then
  diff -r "$src" "$dst" && echo "testdata/golden == eid-mongolia-sdk-go@$ref"
  exit
fi
rm -rf "$dst"
mkdir -p "$(dirname "$dst")"
cp -R "$src" "$dst"
echo "synced testdata/golden from eid-mongolia-sdk-go@$ref"
