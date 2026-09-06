#!/usr/bin/env bash
# External validity (#3, non-gated): fidelity of MULTIPLE benign non-Goldoson SDKs in a benign host
# (DMB-TV). One whole-app CPG, N carves; internal-edge recall carved-vs-whole-app per SDK.
set -uo pipefail
export JAVA_HOME=/Library/Java/JavaVirtualMachines/temurin-17.jdk/Contents/Home
export _JAVA_OPTIONS="-Xmx12g"; export SL_LOGGING_LEVEL=ERROR
cd /Users/1004276/Downloads/goldoson-samples/analysis
APK=general_apps/raw/dmbtv_1.0.8.apk
W=/tmp/dmbev; rm -rf "$W"; mkdir -p "$W"
d2j-dex2jar "$APK" -o "$W/dmb.jar" -f >/dev/null 2>&1
echo "DMB-TV classes: $(unzip -l "$W/dmb.jar"|grep -c '\.class$')"
jimple2cpg "$W/dmb.jar" --output "$W/wa.cpg" >/dev/null 2>&1; echo "whole-app CPG built"
CSV=dmb_extval.csv; echo "sdk,carved_classes,methods_wa,methods_cv,method_wa_only,internal_edges_wa,edge_wa_only,edge_cv_only,exact_edge_equality" > "$CSV"

measure(){ local name="$1" dotted="$2" slash="$3"
  python3 - "$W/dmb.jar" "$W/cv.jar" $slash <<'PY'
import sys,zipfile
src,dst=sys.argv[1],sys.argv[2]; roots=[r for r in sys.argv[3:] if r]
with zipfile.ZipFile(src) as zi, zipfile.ZipFile(dst,"w",zipfile.ZIP_DEFLATED) as zo:
    for it in zi.infolist():
        if it.filename.endswith(".class") and any(it.filename.startswith(r+"/") for r in roots): zo.writestr(it, zi.read(it.filename))
PY
  local cc; cc=$(unzip -l "$W/cv.jar"|grep -c '\.class$')
  jimple2cpg "$W/cv.jar" --output "$W/cv.cpg" >/dev/null 2>&1
  local wm; wm=$(CPG="$W/wa.cpg" ROOTS="$dotted" OUT="$W/wa.txt" joern --script edges.sc 2>/dev/null|grep -oE 'methods=[0-9]+'|grep -oE '[0-9]+')
  local cm; cm=$(CPG="$W/cv.cpg" ROOTS="$dotted" OUT="$W/cv.txt" joern --script edges.sc 2>/dev/null|grep -oE 'methods=[0-9]+'|grep -oE '[0-9]+')
  grep '^E' "$W/wa.txt"|cut -f2-|sort -u>"$W/waE"; grep '^E' "$W/cv.txt"|cut -f2-|sort -u>"$W/cvE"
  local wae; wae=$(wc -l<"$W/waE"|tr -d ' ')
  local wo; wo=$(comm -23 "$W/waE" "$W/cvE"|wc -l|tr -d ' '); local co; co=$(comm -13 "$W/waE" "$W/cvE"|wc -l|tr -d ' ')
  # method-set WA-only (methods present in whole-app but not carved)
  grep '^E' "$W/wa.txt"|cut -f2|sort -u>"$W/waM"; grep '^E' "$W/cv.txt"|cut -f2|sort -u>"$W/cvM"
  local mwo; mwo=$(( wm - cm ))
  local eq="yes"; { [ "$wo" -ne 0 ] || [ "$co" -ne 0 ]; } && eq="no"
  echo "$name,$cc,$wm,$cm,$mwo,$wae,$wo,$co,$eq" >> "$CSV"
  echo "[$name] carved=$cc methods $wm/$cm (WA-only $mwo) | edges WA=$wae WA-only=$wo CV-only=$co exact_equality=$eq"
}

measure okhttp3            okhttp3,okio                    "okhttp3 okio"
measure com.google.android.exoplayer2  com.google.android.exoplayer2   "com/google/android/exoplayer2"
measure com.google.firebase           com.google.firebase             "com/google/firebase"
measure com.google.android.gms        com.google.android.gms          "com/google/android/gms"
measure com.project.onair             com.project.onair               "com/project/onair"
echo "=== DONE_DMB_EXTVAL ==="; column -s, -t "$CSV"; rm -rf "$W"
