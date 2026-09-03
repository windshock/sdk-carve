#!/usr/bin/env bash
# Phase B corpus fetcher — retrieves seed samples for static sdk-carve analysis ONLY.
# Samples are NEVER executed. Output dir is git-ignored.
#
# Requires API keys (set as env vars):
#   ANDROZOO_APIKEY   https://androzoo.uni.lu/access   (academic/research registration)
#   MB_APIKEY         https://auth.abuse.ch/            (MalwareBazaar Auth-Key)
#
# Usage:
#   ./fetch.sh                 # dry-run: print what WOULD be fetched (no downloads)
#   ./fetch.sh --go            # actually download (needs keys)
#   ./fetch.sh --go --family Konfety
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SEEDS="$HERE/seeds.csv"
OUT="$HERE/corpus"                 # git-ignored
GO=0; ONLY=""
while [ $# -gt 0 ]; do case "$1" in
  --go) GO=1;; --family) ONLY="$2"; shift;; *) echo "unknown arg $1"; exit 2;; esac; shift; done
mkdir -p "$OUT"

az() {  # androzoo by sha256 -> $OUT/<family>/<sha256>.apk
  local sha="$1" dst="$2"
  [ -n "${ANDROZOO_APIKEY:-}" ] || { echo "  SKIP(no ANDROZOO_APIKEY) $sha"; return 1; }
  curl -fsS -G "https://androzoo.uni.lu/api/download" \
    --data-urlencode "apikey=$ANDROZOO_APIKEY" --data-urlencode "sha256=$sha" \
    -o "$dst" && echo "  androzoo OK  $dst"
}
mb() {  # malwarebazaar by sha256 (returns password-'infected' zip) -> unzip -> apk
  local sha="$1" dst="$2"
  [ -n "${MB_APIKEY:-}" ] || { echo "  SKIP(no MB_APIKEY) $sha"; return 1; }
  local z="${dst%.apk}.zip"
  curl -fsS -H "Auth-Key: $MB_APIKEY" -d "query=get_file&sha256_hash=$sha" \
    https://mb-api.abuse.ch/api/v1/ -o "$z" \
    && 7z x -y -pinfected -o"$(dirname "$dst")" "$z" >/dev/null && rm -f "$z" \
    && echo "  bazaar OK    $(dirname "$dst")"   # MB zips are AES (PK5.1) -> 7z, not unzip
}
ha() {  # hybrid-analysis (Falcon Sandbox) by sha256 -> gzip -> apk; needs auth_level>=100
  local sha="$1" dst="$2"
  [ -n "${HYBRIDANALYSIS_APIKEY:-}" ] || { echo "  SKIP(no HYBRIDANALYSIS_APIKEY) $sha"; return 1; }
  local gz="${dst%.apk}.gz"
  curl -fsS -H "api-key: $HYBRIDANALYSIS_APIKEY" -H "User-Agent: Falcon Sandbox" \
    "https://hybrid-analysis.com/api/v2/overview/$sha/sample" -o "$gz" \
    && gunzip -f "$gz" && mv "${gz%.gz}" "$dst" 2>/dev/null \
    && echo "  HA OK        $dst"
}

tail -n +2 "$SEEDS" | while IFS=, read -r family kind ident htype source conf notes; do
  [ -z "$family" ] && continue
  [ -n "$ONLY" ] && [ "$family" != "$ONLY" ] && continue
  d="$OUT/$family"; mkdir -p "$d"
  if [ "$kind" = "sha256" ]; then
    dst="$d/$ident.apk"
    if [ "$GO" = 0 ]; then echo "WOULD fetch [$family] sha256 $ident ($source)"; continue; fi
    [ -s "$dst" ] && { echo "  have $dst"; continue; }
    # try the seed's preferred source first, then fall back across all providers
    case "$source" in
      malwarebazaar)  mb "$ident" "$dst" || ha "$ident" "$dst" || az "$ident" "$dst" ;;
      hybridanalysis) ha "$ident" "$dst" || mb "$ident" "$dst" || az "$ident" "$dst" ;;
      *)              ha "$ident" "$dst" || mb "$ident" "$dst" || az "$ident" "$dst" ;;
    esac
  elif [ "$kind" = "package" ]; then
    # AndroZoo package -> pick historical versions via the metadata catalogue (manual step);
    # here we only record the intent (infected->clean boundary needs version selection).
    [ "$GO" = 0 ] && echo "WOULD resolve [$family] package $ident via AndroZoo metadata (versions)"
  else
    [ "$GO" = 0 ] && echo "NOTE  [$family] $kind $ident needs a hash-based source ($source)"
  fi
done
echo "done. (dry-run: pass --go to download; corpus/ is git-ignored)"
