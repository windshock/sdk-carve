#!/usr/bin/env bash
# CodeQL analyzer-independence — WHOLE-APP side, size-bracketed subset (small/med/large).
# Confirms the ~22x carved cost advantage (seen on TMAP) generalizes across app sizes on an
# independent analyzer. Whole-app CodeQL = jadx decompile (mandatory) + codeql build-mode=none.
# Args: list of "label:jar:dottedRoots" (dottedRoots comma-separated). Uses per-app SDK query.
set -uo pipefail
export JAVA_HOME=/Library/Java/JavaVirtualMachines/temurin-17.jdk/Contents/Home
export PATH="$JAVA_HOME/bin:$PATH"
cd /Users/1004276/Downloads/goldoson-samples/analysis
CSV=codeql_wholeapp.csv
[ -f "$CSV" ] || echo "label,input_cls,decompile_s,java_files,dbbuild_s,db_mb,total_src_types,sdk_types,sdk_methods" > "$CSV"
secs(){ grep -E ' real' "$1" | awk '{print $1}' | tail -1; }

genq(){ # <dottedRoots-comma>  -> writes /tmp/sdkq.ql
  local roots="$1"; local pred=""
  IFS=',' read -ra R <<<"$roots"
  for r in "${R[@]}"; do r=$(echo "$r"|tr -d ' '); [ -z "$r" ] && continue
    pred="$pred p = \"$r\" or p.matches(\"$r.%\") or"; done
  pred="${pred% or}"
  cat > qlqueries/sdkq.ql <<QL
import java
predicate sdkPkg(RefType t) { exists(string p | p = t.getPackage().getName() | $pred) }
select count(RefType t | t.fromSource() | t) as total_types,
       count(RefType t | t.fromSource() and sdkPkg(t) | t) as sdk_types,
       count(Method  m | m.fromSource() and sdkPkg(m.getDeclaringType()) | m) as sdk_methods
QL
}

run(){ local label="$1" jar="$2" roots="$3"
  local W; W=$(mktemp -d); local ic; ic=$(unzip -l "$jar" 2>/dev/null | grep -c '\.class$')
  echo "[$label] decompiling whole app ($ic cls)..."
  /usr/bin/time -l jadx -j 6 -d "$W/src" --no-res --no-debug-info -q "$jar" >/dev/null 2>"$W/jadx.t"
  local ds jf; ds=$(secs "$W/jadx.t"); jf=$(find "$W/src" -name '*.java' | wc -l | tr -d ' ')
  echo "[$label] building CodeQL DB..."
  /usr/bin/time -l codeql database create "$W/db" --language=java --build-mode=none \
      --source-root="$W/src" --overwrite >/dev/null 2>"$W/cq.t"
  local bs; bs=$(secs "$W/cq.t"); local dbmb=$(( $(du -sk "$W/db" 2>/dev/null | awk '{print $1}')/1024 ))
  genq "$roots"
  local row; row=$(codeql query run --database="$W/db" qlqueries/sdkq.ql 2>/dev/null | grep -E '^\| *[0-9]' | head -1 | tr -d ' ' | tr '|' ' ')
  local tt st sm; tt=$(echo $row|awk '{print $1}'); st=$(echo $row|awk '{print $2}'); sm=$(echo $row|awk '{print $3}')
  echo "$label,$ic,${ds:-NA},$jf,${bs:-NA},$dbmb,${tt:-NA},${st:-NA},${sm:-NA}" >> "$CSV"
  echo "[$label] DONE: decompile ${ds}s ($jf java) | db ${bs}s ${dbmb}MB | total_types=$tt sdk_types=$st sdk_methods=$sm"
  rm -rf "$W"
}

for spec in "$@"; do
  IFS=':' read -r label jar roots <<<"$spec"
  run "$label" "$jar" "$roots"
done
echo "=== DONE_CODEQL_WHOLEAPP ==="; column -s, -t "$CSV"
