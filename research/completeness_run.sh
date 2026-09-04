#!/usr/bin/env bash
# RQ-completeness: does the target SDK survive in the whole-app CPG vs the carved CPG?
# metric = target-root-anchored METHOD count + SDK-own sink call-sites (putCol/getBConfig/getPdata/userJoin).
set -uo pipefail
export JAVA_HOME=/Library/Java/JavaVirtualMachines/temurin-17.jdk/Contents/Home
export _JAVA_OPTIONS="-Xmx12g"
cd /Users/1004276/Downloads/goldoson-samples/analysis
CSV=completeness.csv; rm -f "$CSV"
echo "label,input_classes,wa_td,wa_target_methods,wa_own_sink_cs,cv_td,cv_target_methods,cv_own_sink_cs" > "$CSV"
OWN='putCol|getBConfig|getPdata|userJoin'

query(){ CPG="$1" ROOTS="$2" OWN="$OWN" joern --script cq.sc 2>/dev/null | grep '^QRES' \
         | sed -E 's/.*td=([0-9]+) target_methods=([0-9]+) own_sink_cs=([0-9]+)/\1 \2 \3/'; }

run(){ local label="$1" app="$2" rootsdot="$3"
  local W; W=$(mktemp -d); local ic; ic=$(unzip -l "$app" 2>/dev/null | grep -c '\.class$')
  timeout 600 jimple2cpg "$app" --output "$W/wa.cpg" >/dev/null 2>&1
  read -r wtd wtm wown <<<"$(query "$W/wa.cpg" "$rootsdot")"
  local globs; globs=$(echo "$rootsdot" | tr ',' ' ' | tr '.' '/')
  python3 - "$app" "$W/cv.jar" $globs <<'PY'
import sys,zipfile
src,dst=sys.argv[1],sys.argv[2]; pres=[g.strip() for g in sys.argv[3:] if g.strip()]
with zipfile.ZipFile(src) as zi, zipfile.ZipFile(dst,"w",zipfile.ZIP_DEFLATED) as zo:
    for it in zi.infolist():
        if it.filename.endswith(".class") and any(it.filename.startswith(p+"/") for p in pres):
            zo.writestr(it, zi.read(it.filename))
PY
  timeout 300 jimple2cpg "$W/cv.jar" --output "$W/cv.cpg" >/dev/null 2>&1
  read -r ctd ctm cown <<<"$(query "$W/cv.cpg" "$rootsdot")"
  echo "$label,$ic,${wtd:-NA},${wtm:-NA},${wown:-NA},${ctd:-NA},${ctm:-NA},${cown:-NA}" >> "$CSV"
  echo "[$label] whole-app target-methods=${wtm:-NA} own-sinks=${wown:-NA} | carved target-methods=${ctm:-NA} own-sinks=${cown:-NA}"
  rm -rf "$W"
}

run com.skt.tmap.ku tmap-dex2jar.jar com.smart.sklb,bg,cg,dg
for d in batch/*/; do
  app=$(basename "$d"); [ -f "$d/app.jar" ] && [ -f "$d/scope.txt" ] || continue
  rootsdot=$(tr '\n' ',' < "$d/scope.txt" | tr '/' '.' | sed 's/,$//')
  run "$app" "$d/app.jar" "$rootsdot"
done
echo "=== DONE_COMPLETE ==="; column -s, -t "$CSV"
