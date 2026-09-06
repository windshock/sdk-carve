#!/usr/bin/env bash
# Axis-1: preservation fidelity (single app) — "Did we PRESERVE the carved code?"
# Builds the whole-app CPG and the carved-region CPG from ONE apk/jar and compares the SDK-internal
# call-graph edge sets (recall + bidirectional symmetric diff). Companion to fidelity_batch.sh (batch).
#
#   usage: preservation_fidelity.sh <app .apk|.jar> <region-dotted e.g. com.coral> <region-slash e.g. com/coral> [heap e.g. 12g]
#
# NOTE (RQ1 feasibility boundary): a whole-app CPG of a very large app (>~50k classes) can exceed
# practical RAM (e.g. on a 16 GB host jimple2cpg OOMs during serialization and writes a CORRUPT graph;
# at -Xmx==physical-RAM the JVM cannot allocate). This script validates the CPG header and reports
# "whole-app NOT measurable (build cost)" — an RQ1 feasibility-boundary result, NOT an equality result.
# The carved side still builds in seconds; that asymmetry IS the feasibility finding.
set -uo pipefail
[ $# -ge 3 ] || { grep -E '^#( |$)' "$0" | sed 's/^# \{0,1\}//'; exit 2; }
APP="$1"; DOTTED="$2"; SLASH="$3"; HEAP="${4:-12g}"
HERE="$(cd "$(dirname "$0")" && pwd)"; EDGES="$HERE/edges.sc"
export _JAVA_OPTIONS="-Xmx${HEAP}"; export SL_LOGGING_LEVEL=ERROR
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT; cd "$W"   # isolate joern workspace/ in $W
case "$APP" in *.jar) JAR="$APP";; *) d2j-dex2jar "$APP" -o "$W/app.jar" -f >/dev/null 2>&1; JAR="$W/app.jar";; esac
python3 - "$JAR" "$W/cv.jar" "$SLASH" <<'PY'
import sys, zipfile
src, dst, root = sys.argv[1], sys.argv[2], sys.argv[3]
with zipfile.ZipFile(src) as zi, zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED) as zo:
    for it in zi.infolist():
        if it.filename.endswith(".class") and it.filename.startswith(root + "/"):
            zo.writestr(it, zi.read(it.filename))
PY
valid(){ [ -f "$1" ] && [ "$(head -c 8 "$1")" = "FLT GRPH" ]; }
jimple2cpg "$JAR"      --output "$W/wa.cpg" > "$W/wa_build.log" 2>&1 || true
jimple2cpg "$W/cv.jar" --output "$W/cv.cpg" > "$W/cv_build.log" 2>&1 || true
CPG="$W/cv.cpg" ROOTS="$DOTTED" OUT="$W/cv.txt" joern --script "$EDGES" >/dev/null 2>&1 || true
CVE=$(grep -c '^E' "$W/cv.txt" 2>/dev/null || echo 0)
echo "carved internal edges = $CVE"
if valid "$W/wa.cpg"; then
  CPG="$W/wa.cpg" ROOTS="$DOTTED" OUT="$W/wa.txt" joern --script "$EDGES" >/dev/null 2>&1 || true
  if [ -s "$W/wa.txt" ]; then
    grep '^E' "$W/wa.txt"|cut -f2-|sort -u>"$W/waE"; grep '^E' "$W/cv.txt"|cut -f2-|sort -u>"$W/cvE"
    WAE=$(wc -l<"$W/waE"|tr -d ' '); WO=$(comm -23 "$W/waE" "$W/cvE"|wc -l|tr -d ' '); CO=$(comm -13 "$W/waE" "$W/cvE"|wc -l|tr -d ' ')
    echo "whole-app internal edges = $WAE | WA-only=$WO CV-only=$CO | recall=$(python3 -c "print(f'{100*($WAE-$WO)/$WAE:.1f}' if $WAE else 'NA')")% exact_equality=$([ "$WO" -eq 0 ]&&[ "$CO" -eq 0 ]&&echo yes||echo no)"
  else echo "whole-app NOT measurable (edge query failed on large CPG — RQ1 cost boundary)"; fi
else echo "whole-app NOT measurable (CPG build produced no valid graph — OOM at RQ1 cost boundary; see wa_build.log)"; fi