#!/usr/bin/env bash
# CodeQL analyzer-independence — CARVED side across all 11 apps.
# Pipeline per app: carve jar (in-memory) -> jadx decompile -> codeql db (build-mode=none) -> count.
# Carved DB is SDK-only by construction, so src_types/src_methods = the SDK's extracted surface.
set -uo pipefail
export JAVA_HOME=/Library/Java/JavaVirtualMachines/temurin-17.jdk/Contents/Home
export PATH="$JAVA_HOME/bin:$PATH"
cd /Users/1004276/Downloads/goldoson-samples/analysis
CSV=codeql_carved.csv; rm -f "$CSV"
echo "label,carved_cls,decompile_s,dbbuild_s,db_mb,src_types,src_methods" > "$CSV"

carve(){ # <srcjar> <dstjar> <slash-roots...>
  python3 - "$@" <<'PY'
import sys,zipfile
src,dst=sys.argv[1],sys.argv[2]; pres=[g.strip() for g in sys.argv[3:] if g.strip()]
with zipfile.ZipFile(src) as zi, zipfile.ZipFile(dst,"w",zipfile.ZIP_DEFLATED) as zo:
    for it in zi.infolist():
        if it.filename.endswith(".class") and any(it.filename.startswith(p+"/") for p in pres):
            zo.writestr(it, zi.read(it.filename))
PY
}
secs(){ grep -E ' real' "$1" | awk '{print $1}' | tail -1; }

run(){ local label="$1" jar="$2"; shift 2; local roots=("$@")
  local W; W=$(mktemp -d)
  carve "$jar" "$W/cv.jar" "${roots[@]}"
  local cvc; cvc=$(unzip -l "$W/cv.jar" 2>/dev/null | grep -c '\.class$')
  /usr/bin/time -l jadx -d "$W/src" --no-res -q "$W/cv.jar" >/dev/null 2>"$W/jadx.t"
  local ds; ds=$(secs "$W/jadx.t")
  /usr/bin/time -l codeql database create "$W/db" --language=java --build-mode=none \
      --source-root="$W/src" --overwrite >/dev/null 2>"$W/cq.t"
  local bs; bs=$(secs "$W/cq.t"); local dbmb=$(( $(du -sk "$W/db" 2>/dev/null | awk '{print $1}')/1024 ))
  local st sm; read -r st sm <<<"$(codeql query run --database="$W/db" qlqueries/countall.ql 2>/dev/null \
      | grep -E '^\|[0-9 ]+\|' | tr -d ' |' | awk -F'\n' '{print}' | head -1 | sed 's/|/ /g')"
  # robust parse of the result row
  local row; row=$(codeql query run --database="$W/db" qlqueries/countall.ql 2>/dev/null | grep -E '^\| *[0-9]' | head -1 | tr -d ' ' | tr '|' ' ')
  st=$(echo $row | awk '{print $1}'); sm=$(echo $row | awk '{print $2}')
  echo "$label,$cvc,${ds:-NA},${bs:-NA},$dbmb,${st:-NA},${sm:-NA}" >> "$CSV"
  echo "[$label] carved=$cvc cls | decompile ${ds}s | codeql-db ${bs}s ${dbmb}MB | src_types=${st} src_methods=${sm}"
  rm -rf "$W"
}

run com.skt.tmap.ku tmap-dex2jar.jar com/smart/sklb bg cg dg
for d in batch/*/; do
  app=$(basename "$d"); [ -f "$d/app.jar" ] && [ -f "$d/scope.txt" ] || continue
  roots=(); while IFS= read -r line; do [ -n "$line" ] && roots+=("$line"); done < "$d/scope.txt"
  run "$app" "$d/app.jar" "${roots[@]}"
done
echo "=== DONE_CODEQL_CARVED ==="; column -s, -t "$CSV"
