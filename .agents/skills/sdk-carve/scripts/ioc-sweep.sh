#!/usr/bin/env bash
# Multi-family IOC + package-anchor + structural-marker sweep over dex2jar JAR(s).
# Families covered: Goldoson, SpinOk, Konfety, MobiDash, Necro/Coral
# (indicators from docs/CROSS_FAMILY_COMPARISON.md, docs/PRE_CARVE.md, docs/ANTI_ANALYSIS.md).
# Usage: ioc-sweep.sh <app-dex2jar.jar> [more.jar ...]   exit 0 = any hit, 1 = clean.
# Hits are *leads* — corroborate with detect.py / behavior-sweep.py / carve (SKILL.md).
set -uo pipefail

# hardcoded C2/ad hosts per family
GOLDSONON_HOSTS="bhuroid\.com|dalefs\.com|discess\.net|fuerob\.com|gadlito\.com|goldoson\.net|hjorsjopa\.com|methinno\.net|necktro\.com|ojiskorp\.net|openwor\.com|phyerh\.net|ridinra\.com|rouperdo\.net|soridok2kpop\.com|sorrowdeepkold\.com|treffaas\.com|visceun\.com|appservice9\.com|trs\.bestsmartshop\.net|retoore\.com|barivemi\.net|huejura\.com|kialant\.com"
SPINOK_HOSTS="d3hdbjtb1686tn\.cloudfront\.net|gpsdk\.html"
KONFETY_HOSTS="jetengine\.be|upyourphone\.me|razkondronging\.com|atswe\.xyz"

# class-path prefixes per family (carve-scope anchors; Necro IOC boundary = com/coral + libcoral.so)
ANCHORS="com/spin/ok:SpinOk com/coral:NecroCoral com/adcommercial:Konfety com/gnet:Konfety com/nextg:Konfety org/lsposed:Konfety com/stwdi:MobiDash"

# structural markers (weak signals — corroborate before claiming anything)
STRUCT="net/sqlcipher:MobiDash packing (SQLCipher module store)
Proxy.NO_PROXY:MobiDash anti-proxy bypass
VirtualDisplay:phantom-viewport candidate (pair with MotionEvent)
MotionEvent:phantom-viewport candidate (pair with VirtualDisplay)
isSimulator:Necro-style env telemetry (generic — corroborate)
isAdb:Necro-style env telemetry (generic — corroborate)"

rc=1
for jar in "$@"; do
  echo "== ioc-sweep $jar =="
  T=$(mktemp)
  unzip -p "$jar" 2>/dev/null | strings -a -n 6 > "$T"
  for fam in "Goldoson:$GOLDSONON_HOSTS" "SpinOk:$SPINOK_HOSTS" "Konfety:$KONFETY_HOSTS"; do
    name="${fam%%:*}"; re="${fam#*:}"
    hits=$(grep -Eio "$re" "$T" | tr 'A-Z' 'a-z' | sort | uniq -c | sort -rn)
    if [ -n "$hits" ]; then echo "  [$name] C2/ad host:"; printf '    %s\n' "$hits"; rc=0
    else echo "  [$name] hosts: none"; fi
  done
  listing=$(unzip -l "$jar" 2>/dev/null | awk '{print $4}')
  anchor_hit=0
  for pair in $ANCHORS; do
    pkg="${pair%%:*}"; fam="${pair#*:}"
    n=$(printf '%s\n' "$listing" | grep -c "^${pkg}/" || true)
    if [ "$n" -gt 0 ]; then echo "  [$fam] package anchor ${pkg}/ — $n classes"; rc=0; anchor_hit=1
    else echo "  [$fam] anchor ${pkg}/: none"; fi
  done
  printf '%s\n' "$STRUCT" | while IFS= read -r line; do
    m="${line%%:*}"; label="${line#*:}"
    c=$(grep -acF -- "$m" "$T" || true)
    if [ "$c" -gt 0 ]; then echo "  [marker] '$m' ×$c — $label"; fi
  done
  vd=$(grep -acF "VirtualDisplay" "$T" || true); me=$(grep -acF "MotionEvent" "$T" || true)
  if [ "$vd" -gt 0 ] && [ "$me" -gt 0 ]; then
    echo "  [marker] VirtualDisplay+MotionEvent both present — check same package for phantom-viewport engine"; rc=0
  fi
  rm -f "$T"
done
exit "$rc"
