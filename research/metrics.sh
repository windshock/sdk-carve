#!/usr/bin/env bash
# baseline(whole-app) vs carved metrics for one target.  (RQ2/RQ3 evidence)
# usage: bash metrics.sh <label> <app.jar> <out.csv> <carve-glob> [glob ...]
set -uo pipefail
export JAVA_HOME=/Library/Java/JavaVirtualMachines/temurin-17.jdk/Contents/Home
export _JAVA_OPTIONS="${METRICS_HEAP:--Xmx12g}"   # heap; override to model constrained envs
TO=${METRICS_TIMEOUT:-1200}             # per-CPG timeout (s)

LABEL="$1"; APP="$2"; CSV="$3"; shift 3
WORK="$(mktemp -d)"

measure(){ # <jar> <outcpg> <prefix>  -> "status wall_s rss_mb cpg_mb"
  local jar="$1" out="$2" pre="$3" ec
  /usr/bin/time -l timeout "$TO" jimple2cpg "$jar" --output "$out" >"$pre.log" 2>"$pre.err"; ec=$?
  local wall rss
  wall=$(grep -E ' real' "$pre.err" | awk '{print $1}' | tail -1)
  rss=$(grep 'maximum resident set size' "$pre.err" | awk '{print $1}' | tail -1)
  local rssmb=$(( ${rss:-0} / 1048576 ))
  local cpgmb=0; [ -f "$out" ] && cpgmb=$(( $(wc -c <"$out") / 1048576 ))
  local status=ok
  [ $ec -eq 124 ] && status=timeout
  [ $ec -ne 0 ] && [ $ec -ne 124 ] && status="fail$ec"
  echo "$status ${wall:-NA} $rssmb $cpgmb"
}

# --- whole-app baseline ---
WAC=$(unzip -l "$APP" 2>/dev/null | grep -c '\.class$'); WAMB=$(( $(wc -c <"$APP")/1048576 ))
read -r wa_s wa_w wa_r wa_c <<EOF
$(measure "$APP" "$WORK/base.cpg" "$WORK/base")
EOF

# --- carved treatment (scoped jar built in-memory, case-preserving) ---
python3 - "$APP" "$WORK/scoped.jar" "$@" <<'PY'
import sys, zipfile, fnmatch
src, dst = sys.argv[1], sys.argv[2]
globs = [g.strip() for g in sys.argv[3:] if g.strip()]   # tolerate trailing spaces/newlines
def want(n):
    if not n.endswith(".class"): return False
    for g in globs:
        pre=g.rstrip("*").rstrip("/")
        if n.startswith(pre+"/") or fnmatch.fnmatch(n,g): return True
    return False
with zipfile.ZipFile(src) as zi, zipfile.ZipFile(dst,"w",zipfile.ZIP_DEFLATED) as zo:
    for it in zi.infolist():
        if want(it.filename): zo.writestr(it, zi.read(it.filename))
PY
CVC=$(unzip -l "$WORK/scoped.jar" 2>/dev/null | grep -c '\.class$'); CVKB=$(( $(wc -c <"$WORK/scoped.jar")/1024 ))
read -r cv_s cv_w cv_r cv_c <<EOF
$(measure "$WORK/scoped.jar" "$WORK/scoped.cpg" "$WORK/scoped")
EOF

# header once
[ -f "$CSV" ] || echo "label,wa_classes,wa_jar_mb,wa_status,wa_wall_s,wa_rss_mb,wa_cpg_mb,cv_classes,cv_jar_kb,cv_status,cv_wall_s,cv_rss_mb,cv_cpg_mb,globs" > "$CSV"
echo "$LABEL,$WAC,$WAMB,$wa_s,$wa_w,$wa_r,$wa_c,$CVC,$CVKB,$cv_s,$cv_w,$cv_r,$cv_c,$*" >> "$CSV"
echo "[$LABEL] whole-app: $wa_s ${wa_w}s ${wa_r}MB cpg=${wa_c}MB ($WAC cls) | carved: $cv_s ${cv_w}s ${cv_r}MB cpg=${cv_c}MB ($CVC cls)"
rm -rf "$WORK"
