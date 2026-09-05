#!/usr/bin/env bash
# CodeQL corpus sweep (Track 2): carved vs whole-app, all 11 apps, SEQUENTIAL.
# Records 1-min load per app so contaminated timings are detectable. Cleans temp per app.
set -uo pipefail
export JAVA_HOME=/Library/Java/JavaVirtualMachines/temurin-17.jdk/Contents/Home
export PATH="$JAVA_HOME/bin:$PATH"
cd /Users/1004276/Downloads/goldoson-samples/analysis
CSV=codeql_corpus_full.csv; rm -f "$CSV"
echo "label,input_cls,load1,cv_cls,cv_decomp_s,cv_build_s,cv_db_mb,cv_types,cv_methods,wa_decomp_s,wa_java,wa_build_s,wa_db_mb,wa_total_types,wa_sdk_types,wa_sdk_methods" > "$CSV"
CVTO=600; WATO=2400
secs(){ grep -E ' real' "$1" 2>/dev/null | awk '{print $1}' | tail -1; }
dbmb(){ echo $(( $(du -sk "$1" 2>/dev/null | awk '{print $1}')/1024 )); }
load1(){ uptime | sed -E 's/.*load aver[a-z]*: *//' | awk -F',' '{print $1}' | tr -d ' '; }

carve(){ # <srcjar> <dstjar> <dottedRoots-comma>
  local roots; roots=$(echo "$3" | tr ',' ' ' | tr '.' '/')
  python3 - "$1" "$2" $roots <<'PY'
import sys,zipfile
src,dst=sys.argv[1],sys.argv[2]; pres=[g.strip() for g in sys.argv[3:] if g.strip()]
with zipfile.ZipFile(src) as zi, zipfile.ZipFile(dst,"w",zipfile.ZIP_DEFLATED) as zo:
    for it in zi.infolist():
        if it.filename.endswith(".class") and any(it.filename.startswith(p+"/") for p in pres):
            zo.writestr(it, zi.read(it.filename))
PY
}
genq(){ # <dottedRoots-comma> -> qlqueries/sdkq.ql
  local pred=""; IFS=',' read -ra R <<<"$1"
  for r in "${R[@]}"; do r=$(echo "$r"|tr -d ' '); [ -z "$r" ] && continue
    pred="$pred p = \"$r\" or p.matches(\"$r.%\") or"; done
  pred="${pred% or}"
  cat > qlqueries/sdkq.ql <<QL
import java
predicate sdkPkg(RefType t) { exists(string p | p = t.getPackage().getName() | $pred) }
select count(RefType t | t.fromSource() | t), count(RefType t | t.fromSource() and sdkPkg(t) | t),
       count(Method m | m.fromSource() and sdkPkg(m.getDeclaringType()) | m)
QL
}
q2(){ codeql query run --database="$1" "$2" 2>/dev/null | grep -E '^\| *[0-9]' | head -1 | tr -d ' ' | tr '|' ' '; }

run(){ local label="$1" jar="$2" roots="$3"
  local L; L=$(load1); local ic; ic=$(unzip -l "$jar" 2>/dev/null | grep -c '\.class$')
  local W; W=$(mktemp -d)
  # ---- carved ----
  carve "$jar" "$W/cv.jar" "$roots"; local cvc; cvc=$(unzip -l "$W/cv.jar" 2>/dev/null | grep -c '\.class$')
  /usr/bin/time -l jadx -d "$W/cs" --no-res -q "$W/cv.jar" >/dev/null 2>"$W/cjd"
  /usr/bin/time -l timeout "$CVTO" codeql database create "$W/cdb" --language=java --build-mode=none --source-root="$W/cs" --overwrite >/dev/null 2>"$W/cqb"
  local cvt cvm; read -r _ cvt cvm <<<"$(q2 "$W/cdb" qlqueries/countall.ql) 0"; read -r cvt cvm <<<"$(q2 "$W/cdb" qlqueries/countall.ql)"
  local cvdb; cvdb=$(dbmb "$W/cdb")
  # ---- whole-app ----
  /usr/bin/time -l jadx -j 6 -d "$W/ws" --no-res --no-debug-info -q "$jar" >/dev/null 2>"$W/wjd"
  local wjf; wjf=$(find "$W/ws" -name '*.java' | wc -l | tr -d ' ')
  /usr/bin/time -l timeout "$WATO" codeql database create "$W/wdb" --language=java --build-mode=none --source-root="$W/ws" --overwrite >/dev/null 2>"$W/wqb"
  genq "$roots"; local wtt wst wsm; read -r wtt wst wsm <<<"$(q2 "$W/wdb" qlqueries/sdkq.ql)"
  local wdb; wdb=$(dbmb "$W/wdb")
  echo "$label,$ic,$L,$cvc,$(secs "$W/cjd"),$(secs "$W/cqb"),$cvdb,${cvt:-NA},${cvm:-NA},$(secs "$W/wjd"),$wjf,$(secs "$W/wqb"),$wdb,${wtt:-NA},${wst:-NA},${wsm:-NA}" >> "$CSV"
  echo "[$label] load=$L | CV ${cvc}cls db $(secs "$W/cqb")s ${cvdb}MB t=$cvt | WA $wjf java db $(secs "$W/wqb")s ${wdb}MB sdk_t=$wst sdk_m=$wsm"
  rm -rf "$W"
}

# small -> large so quick results land first
run mafu.driving.free                 batch/mafu.driving.free/app.jar                 com.tnrhd.emfkdl.gmdk
run com.appsnine.audiorecorder        batch/com.appsnine.audiorecorder/app.jar        com.enoi.yweoi.nwef
run com.appsnine.compass              batch/com.appsnine.compass/app.jar              com.enoi.yweoi.nwef,s5
run com.Monthly23.SwipeBrickBreaker   batch/com.Monthly23.SwipeBrickBreaker/app.jar   com.tajsl.htmxm.bxkdhqor
run kr.co.lottecinema.lcm             batch/kr.co.lottecinema.lcm/app.jar             com.leri.trub.mwelpk
run com.wtwoo.girlsinger.worldcup     batch/com.wtwoo.girlsinger.worldcup/app.jar     com.eltqkdl.sekai.hontoni,f2
run kr.co.psynet                      batch/kr.co.psynet/app.jar                      com.ldlqm.vfl.szhdj
run com.megabox.mop                   batch/com.megabox.mop/app.jar                   com.mqas.gwey.bcvg
run com.skt.tmap.ku                   tmap-dex2jar.jar                                com.smart.sklb,bg,cg,dg
run com.somcloud.somnote              batch/com.somcloud.somnote/app.jar              com.sshxm.ndos.txm
run com.gretech.gomplayerko           batch/com.gretech.gomplayerko/app.jar           com.gwox.pzkvn.riosk
rm -f qlqueries/sdkq.ql
echo "=== DONE_CODEQL_CORPUS_SWEEP ==="; column -s, -t "$CSV"
