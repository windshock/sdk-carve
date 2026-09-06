#!/usr/bin/env bash
# Axis-2: pair-derived scope validation (type-B longitudinal) — generic across families.
# "Did we carve the RIGHT code?" — checks that the carve region is present in the infected build and
# absent from a natural clean counterpart, optionally cross-checked by a carve-INDEPENDENT anchor.
# Type-B => counterfactual scope SUPPORT (scope is infection-associated), NOT scope-completeness.
#
#   usage: scope_validate.sh <infected .apk|.jar> <clean .apk|.jar> <region e.g. com/coral> \
#                            [--native <marker e.g. libcoral.so>] [--anchor "<cmd taking a jar>"]
#
# examples (APK/JAR inputs are provided by the user; this repo never ships samples):
#   Necro/Coral : scope_validate.sh wuta_6.3.2.apk wuta_6.9.8.apk com/coral --native libcoral.so
#   Goldoson    : scope_validate.sh tmap_infected.jar tmap_clean.apk com/smart/sklb
#   Goldoson(R8): scope_validate.sh wc_infected.jar wc_clean.apk com/eltqkdl/sekai/hontoni \
#                     --anchor "python3 research/decrypt_goldoson_blocklist.py"
#
# Provenance: verify infected/clean share a signing identity separately (e.g.
#   research/acquisition/resolve.py --verify-only <apk>). Same signer => no evidence of third-party
#   re-signing / repackaging (it does not, by itself, prove the build was never modified).
# Requires: d2j-dex2jar (for .apk inputs), unzip, python3.
set -uo pipefail
[ $# -ge 3 ] || { grep -E '^#( |$)' "$0" | sed 's/^# \{0,1\}//'; exit 2; }
INF="$1"; CLN="$2"; REGION="$3"; shift 3
NATIVE=""; ANCHOR=""
while [ $# -gt 0 ]; do case "$1" in
  --native) NATIVE="$2"; shift 2;;
  --anchor) ANCHOR="$2"; shift 2;;
  *) echo "unknown arg: $1" >&2; exit 2;;
esac; done
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
tojar(){ case "$1" in
  *.jar) echo "$1";;
  *) d2j-dex2jar "$1" -o "$W/$(basename "$1").jar" -f >/dev/null 2>&1; echo "$W/$(basename "$1").jar";;
esac; }
IJ=$(tojar "$INF"); CJ=$(tojar "$CLN")
# authoritative count: unique .class entries strictly under REGION/ (unzip -Z1 = filenames only)
unzip -Z1 "$IJ" 2>/dev/null | grep -E "^${REGION}/.*\.class$" | sort -u > "$W/i"
unzip -Z1 "$CJ" 2>/dev/null | grep -E "^${REGION}/.*\.class$" | sort -u > "$W/c"
ci=$(wc -l < "$W/i" | tr -d ' '); cc=$(wc -l < "$W/c" | tr -d ' ')
inter=$(comm -12 "$W/i" "$W/c" | wc -l | tr -d ' ')
echo "region=$REGION"
echo "  carve region classes : infected=$ci  clean=$cc   (expect present->absent)"
echo "  carve∩clean          : $inter   (expect 0 => no carved class in the clean counterpart)"
[ -n "$NATIVE" ] && echo "  native marker $NATIVE : infected=$(unzip -l "$INF" 2>/dev/null | grep -c "$NATIVE")  clean=$(unzip -l "$CLN" 2>/dev/null | grep -c "$NATIVE")  (out-of-scope boundary)"
if [ -n "$ANCHOR" ]; then
  ai=$($ANCHOR "$IJ" 2>/dev/null | grep -c .); ac=$($ANCHOR "$CJ" 2>/dev/null | grep -c .)
  echo "  independent anchor   : infected=$ai  clean=$ac   (carve-independent; expect present->absent)"
fi
echo "  reading: type-B pair SUPPORTS the carve scope is infection-associated (not scope-completeness)"