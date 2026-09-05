#!/usr/bin/env bash
# RQ5 boundary decomposition: classify the SDK's boundary callees (the "cut") into
# framework/stdlib | generated-glue | host-app | third-party-lib | unresolved.
# Boundary callees are identical carved==whole-app (measured), so use the fast carved CPG.
set -uo pipefail
export JAVA_HOME=/Library/Java/JavaVirtualMachines/temurin-17.jdk/Contents/Home
export _JAVA_OPTIONS="-Xmx12g"; export SL_LOGGING_LEVEL=ERROR
cd /Users/1004276/Downloads/goldoson-samples/analysis
CSV=boundary_breakdown.csv; rm -f "$CSV"
echo "app,total_boundary,framework,recognized_lib,obfuscated_residue,named_other,unresolved,residue_pct" > "$CSV"

classify(){ python3 - "$1" "$2" <<'PY'
import sys, re
callees=open(sys.argv[1]).read().splitlines()
host=sys.argv[2]
# dedup by CLASS (drop method sig)
def cls(c): return re.sub(r'[:(].*','', c).rsplit('.',1)[0] if '.' in re.sub(r'[:(].*','',c) else c
uniq=sorted(set(cls(c) for c in callees if c.strip()))
FW=("android.","androidx.","java.","javax.","kotlin.","kotlinx.","com.google.","dalvik.","org.json",
    "org.xml","org.w3c","org.apache.","sun.","scala.","junit.","org.junit","com.android.")
LIB=("retrofit2.","okhttp3.","okio.","com.squareup.","com.facebook.","io.reactivex.","com.bumptech.",
     "com.airbnb.","io.netty.","com.fasterxml.","org.chromium.","com.tencent.","com.alibaba.")
def kind(base):
    if base.startswith("<") or "unresolved" in base.lower() or base=="": return "unresolved"
    if any(base.startswith(f) for f in FW): return "framework"
    if (".R"==base[-2:] or ".R$" in base or ".BuildConfig" in base or "databinding" in base
        or ".Manifest" in base): return "framework"       # generated glue folded into framework/noise
    if any(base.startswith(l) for l in LIB): return "recognized_lib"
    # obfuscated residue: every package segment is short (<=3 chars, R8 style) e.g. g4.e, b7.c, bg.a
    segs=base.split(".")
    if all(re.fullmatch(r'[a-z][a-z0-9]{0,2}', s) for s in segs[:-1]) and len(segs)>=1: return "obfuscated_residue"
    return "named_other"   # a real, non-library, human-named package => candidate host-app logic
from collections import Counter
c=Counter(kind(x) for x in uniq)
tot=len(uniq); fw=c["framework"]; lib=c["recognized_lib"]; obf=c["obfuscated_residue"]; no=c["named_other"]; un=c["unresolved"]
residue=obf+no
rp=(100*residue/tot) if tot else 0
print(f"{tot},{fw},{lib},{obf},{no},{un},{rp:.0f}")
PY
}

run(){ local app="$1" jar="$2" rootsdot="$3" slash="$4" host="$5"
  local W; W=$(mktemp -d)
  python3 - "$jar" "$W/cv.jar" $slash <<'PY'
import sys,zipfile
src,dst=sys.argv[1],sys.argv[2]; roots=[r for r in sys.argv[3:] if r]
with zipfile.ZipFile(src) as zi, zipfile.ZipFile(dst,"w",zipfile.ZIP_DEFLATED) as zo:
    for it in zi.infolist():
        if it.filename.endswith(".class") and any(it.filename.startswith(r+"/") for r in roots):
            zo.writestr(it, zi.read(it.filename))
PY
  jimple2cpg "$W/cv.jar" --output "$W/cv.cpg" >/dev/null 2>&1
  CPG="$W/cv.cpg" ROOTS="$rootsdot" OUT="$W/bc.txt" joern --script bcallees.sc >/dev/null 2>&1
  local row; row=$(classify "$W/bc.txt" "$host")
  echo "$app,$row" >> "$CSV"
  echo "[$app] boundary: $row  (host=$host)"
  rm -rf "$W"
}

run com.skt.tmap.ku            tmap-dex2jar.jar                              com.smart.sklb,bg,cg,dg  "com/smart/sklb bg cg dg"  com.skt.tmap
run mafu.driving.free          batch/mafu.driving.free/app.jar              com.tnrhd.emfkdl.gmdk    "com/tnrhd/emfkdl/gmdk"    mafu.driving
run com.appsnine.audiorecorder batch/com.appsnine.audiorecorder/app.jar     com.enoi.yweoi.nwef      "com/enoi/yweoi/nwef"      com.appsnine
run com.appsnine.compass       batch/com.appsnine.compass/app.jar           com.enoi.yweoi.nwef,s5   "com/enoi/yweoi/nwef s5"   com.appsnine
run kr.co.lottecinema.lcm      batch/kr.co.lottecinema.lcm/app.jar          com.leri.trub.mwelpk     "com/leri/trub/mwelpk"     kr.co.lottecinema
run com.wtwoo.girlsinger.worldcup batch/com.wtwoo.girlsinger.worldcup/app.jar com.eltqkdl.sekai.hontoni,f2 "com/eltqkdl/sekai/hontoni f2" com.wtwoo
run kr.co.psynet               batch/kr.co.psynet/app.jar                   com.ldlqm.vfl.szhdj      "com/ldlqm/vfl/szhdj"      kr.co.psynet
run com.Monthly23.SwipeBrickBreaker batch/com.Monthly23.SwipeBrickBreaker/app.jar com.tajsl.htmxm.bxkdhqor "com/tajsl/htmxm/bxkdhqor" com.Monthly23
run com.megabox.mop            batch/com.megabox.mop/app.jar                com.mqas.gwey.bcvg       "com/mqas/gwey/bcvg"       com.megabox
run com.somcloud.somnote       batch/com.somcloud.somnote/app.jar           com.sshxm.ndos.txm       "com/sshxm/ndos/txm"       com.somcloud
run com.gretech.gomplayerko    batch/com.gretech.gomplayerko/app.jar        com.gwox.pzkvn.riosk     "com/gwox/pzkvn/riosk"     com.gretech
echo "=== DONE_BOUNDARY ==="; column -s, -t "$CSV"
