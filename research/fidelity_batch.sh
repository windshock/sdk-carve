#!/usr/bin/env bash
# RQ3 semantic fidelity + RQ5 boundary: carved vs (patched, complete) whole-app CPG.
# Per app: build WA + CV CPGs; dump SDK call edges; compute internal-edge recall + boundary split.
set -uo pipefail
export JAVA_HOME=/Library/Java/JavaVirtualMachines/temurin-17.jdk/Contents/Home
export _JAVA_OPTIONS="-Xmx12g"; export SL_LOGGING_LEVEL=ERROR
cd /Users/1004276/Downloads/goldoson-samples/analysis
CSV=fidelity.csv; rm -f "$CSV"
echo "label,sdk_methods_wa,sdk_methods_cv,internal_edges_wa,internal_edges_cv,internal_shared,internal_recall_pct,boundary_wa,boundary_cv,boundary_framework_pct" > "$CSV"
TO=1800

edges(){ CPG="$1" ROOTS="$2" OUT="$3" joern --script edges.sc 2>/dev/null | grep -oE 'methods=[0-9]+ internal_edges=[0-9]+ boundary_edges=[0-9]+'; }

run(){ local label="$1" jar="$2" rootsdot="$3" slash="$4"
  local W; W=$(mktemp -d)
  timeout $TO jimple2cpg "$jar" --output "$W/wa.cpg" >/dev/null 2>&1
  python3 - "$jar" "$W/cv.jar" $slash <<'PY'
import sys,zipfile
src,dst=sys.argv[1],sys.argv[2]; roots=[r for r in sys.argv[3:] if r]
with zipfile.ZipFile(src) as zi, zipfile.ZipFile(dst,"w",zipfile.ZIP_DEFLATED) as zo:
    for it in zi.infolist():
        if it.filename.endswith(".class") and any(it.filename.startswith(r+"/") for r in roots):
            zo.writestr(it, zi.read(it.filename))
PY
  timeout 300 jimple2cpg "$W/cv.jar" --output "$W/cv.cpg" >/dev/null 2>&1
  local wm; wm=$(edges "$W/wa.cpg" "$rootsdot" "$W/wa.txt")
  local cm; cm=$(edges "$W/cv.cpg" "$rootsdot" "$W/cv.txt")
  local wsm=$(echo "$wm"|grep -oE 'methods=[0-9]+'|grep -oE '[0-9]+'); local csm=$(echo "$cm"|grep -oE 'methods=[0-9]+'|grep -oE '[0-9]+')
  grep '^E' "$W/wa.txt" | cut -f2- | sort -u > "$W/waE"; grep '^E' "$W/cv.txt" | cut -f2- | sort -u > "$W/cvE"
  grep '^B' "$W/wa.txt" | cut -f3 | sort -u > "$W/waB"; grep '^B' "$W/cv.txt" | cut -f3 | sort -u > "$W/cvB"
  local wae=$(wc -l <"$W/waE"|tr -d ' '); local cve=$(wc -l <"$W/cvE"|tr -d ' ')
  local shared=$(comm -12 "$W/waE" "$W/cvE" | wc -l | tr -d ' ')
  local recall="NA"; [ "$wae" -gt 0 ] && recall=$(awk "BEGIN{printf \"%.1f\", 100*$shared/$wae}")
  local wab=$(wc -l <"$W/waB"|tr -d ' '); local cvb=$(wc -l <"$W/cvB"|tr -d ' ')
  # boundary framework fraction (callee is android./java./javax./kotlin./androidx.)
  local fw=$(grep -cE '^(android|java|javax|kotlin|androidx|com\.google)\.' "$W/cvB" 2>/dev/null || echo 0)
  local fwpct="NA"; [ "$cvb" -gt 0 ] && fwpct=$(awk "BEGIN{printf \"%.0f\", 100*$fw/$cvb}")
  echo "$label,$wsm,$csm,$wae,$cve,$shared,$recall,$wab,$cvb,$fwpct" >> "$CSV"
  echo "[$label] methods WA=$wsm CV=$csm | internal-edge recall $shared/$wae = ${recall}% | boundary WA=$wab CV=$cvb (fw ${fwpct}%)"
  rm -rf "$W"
}

# fast whole-app builds first, TMAP (slowest) last
order="mafu.driving.free com.appsnine.audiorecorder com.appsnine.compass kr.co.lottecinema.lcm com.wtwoo.girlsinger.worldcup kr.co.psynet com.Monthly23.SwipeBrickBreaker com.megabox.mop com.somcloud.somnote com.gretech.gomplayerko"
for app in $order; do
  d="batch/$app"; [ -f "$d/app.jar" ] && [ -f "$d/scope.txt" ] || continue
  rootsdot=$(tr '\n' ',' < "$d/scope.txt" | tr '/' '.' | sed 's/,$//')
  slash=$(tr '\n' ' ' < "$d/scope.txt")
  run "$app" "$d/app.jar" "$rootsdot" "$slash"
done
run com.skt.tmap.ku tmap-dex2jar.jar com.smart.sklb,bg,cg,dg "com/smart/sklb bg cg dg"
echo "=== DONE_FIDELITY ==="; column -s, -t "$CSV"
