#!/usr/bin/env bash
# dotnet pack-ийн гаралтыг (lockstep гурван багц) шалгана: яг 3 .nupkg + 3 .snupkg, ижил хувилбар, metadata (authors,
# MIT, README, repository), net8.0 + net10.0 lib, хамаарал: core — package хамааралгүй; Pades ба AspNetCore — core-ийн
# ЯГ тэр хувилбар (TFM бүрд); AspNetCore — Microsoft.AspNetCore.App framework reference.
# Хэрэглээ: build/check-packages.sh <nupkg хавтас> <хувилбар>
set -euo pipefail
dir="${1:?nupkg хавтас}"
ver="${2:?хувилбар}"
core="GeregeSystems.EidMongolia"
fail() {
  echo "::error::$*"
  exit 1
}

n=$(find "$dir" -maxdepth 1 -name '*.nupkg' | wc -l)
[[ $n -eq 3 ]] || fail "$dir: 3 .nupkg хүлээсэн, $n олдсон"
n=$(find "$dir" -maxdepth 1 -name '*.snupkg' | wc -l)
[[ $n -eq 3 ]] || fail "$dir: 3 .snupkg хүлээсэн, $n олдсон"

for id in "$core" "$core.AspNetCore" "$core.Pades"; do
  pkg="$dir/$id.$ver.nupkg"
  [[ -f $pkg ]] || fail "$pkg алга"
  [[ -f $dir/$id.$ver.snupkg ]] || fail "$dir/$id.$ver.snupkg алга"
  nuspec=$(unzip -p "$pkg" "$id.nuspec")
  files=$(unzip -Z1 "$pkg")
  for want in "<id>$id</id>" "<version>$ver</version>" "<authors>Gerege Systems LLC</authors>" \
    '<license type="expression">MIT</license>' "<readme>README.md</readme>" \
    '<repository type="git" url="https://github.com/gerege-systems/eid-mongolia-sdk-dotnet"' \
    "<projectUrl>https://developer.eidmongolia.mn/</projectUrl>"; do
    grep -qF "$want" <<<"$nuspec" || fail "$id: nuspec-д '$want' алга"
  done
  grep -qx 'README.md' <<<"$files" || fail "$id: README.md багцад алга"
  for tfm in net8.0 net10.0; do
    grep -qx "lib/$tfm/$id.dll" <<<"$files" || fail "$id: lib/$tfm/$id.dll алга"
    grep -qx "lib/$tfm/$id.xml" <<<"$files" || fail "$id: lib/$tfm/$id.xml (XML doc) алга"
  done
  deps=$(grep -o '<dependency [^>]*>' <<<"$nuspec" || true)
  case "$id" in
    "$core")
      [[ -z $deps ]] || fail "$id: package хамааралгүй байх ёстой: $deps"
      ;;
    *)
      n=$(grep -cF "id=\"$core\" version=\"$ver\"" <<<"$deps" || true)
      [[ $n -eq 2 ]] || fail "$id: net8.0 ба net10.0-д $core $ver хамаарал хүлээсэн: $deps"
      ;;
  esac
  echo "$id $ver: OK"
done

asp=$(unzip -p "$dir/$core.AspNetCore.$ver.nupkg" "$core.AspNetCore.nuspec")
grep -qF '<frameworkReference name="Microsoft.AspNetCore.App"' <<<"$asp" || fail "AspNetCore: Microsoft.AspNetCore.App framework reference алга"
pades=$(unzip -p "$dir/$core.Pades.$ver.nupkg" "$core.Pades.nuspec")
grep -qF 'id="System.Security.Cryptography.Pkcs"' <<<"$pades" || fail "Pades: System.Security.Cryptography.Pkcs хамаарал алга"
echo "packages OK"
