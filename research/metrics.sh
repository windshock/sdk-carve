#!/usr/bin/env bash
# baseline(whole-app) vs carved metrics for one target.  (RQ2/RQ3 evidence)
# usage: bash metrics.sh <label> <app.jar> <out.csv> <carve-glob> [glob ...]
set -uo pipefail
export JAVA_HOME=/Library/Java/JavaVirtualMachines/temurin-17.jdk/Contents/Home
export _JAVA_OPTIONS="${METRICS_HEAP:--Xmx12g}"   # heap; override to model constrained envs
TO=${METRICS_TIMEOUT:-1200}             # per-CPG timeout (s)

LABEL="$1"; APP="$2"; CSV="$3"; shift 3
WORK="$(mktemp -d)"

measure(){ # <jar> <outcpg> <prefix>  -> "status wall_s rss_mb cpg_mb staged warns"
  local jar="$1" out="$2" pre="$3" ec
  # SL_LOGGING_LEVEL=INFO surfaces jimple2cpg's "Loading N program files" staging count,
  # which reveals silent pre-Soot truncation (see docs/METRICS.md root cause). Logs are KEPT.
  SL_LOGGING_LEVEL=${SL_LOGGING_LEVEL:-INFO} \
    /usr/bin/time -l timeout "$TO" jimple2cpg "$jar" --output "$out" >"$pre.log" 2>"$pre.err"; ec=$?
  local wall rss
  wall=$(grep -E ' real' "$pre.err" | awk '{print $1}' | tail -1)
  rss=$(grep 'maximum resident set size' "$pre.err" | awk '{print $1}' | tail -1)
  local rssmb=$(( ${rss:-0} / 1048576 ))
  local cpgmb=0; [ -f "$out" ] && cpgmb=$(( $(wc -c <"$out") / 1048576 ))
  local staged; staged=$(grep -hoE 'Loading [0-9]+ program files' "$pre.log" "$pre.err" 2>/dev/null | grep -oE '[0-9]+' | head -1)
  local warns;  warns=$(grep -hcE ' WARN ' "$pre.log" "$pre.err" 2>/dev/null | awk '{s+=$1}END{print s+0}')
  local status=ok
  [ $ec -eq 124 ] && status=timeout
  [ $ec -ne 0 ] && [ $ec -ne 124 ] && status="fail$ec"
  echo "$status ${wall:-NA} $rssmb $cpgmb ${staged:-NA} ${warns:-0}"
}

# --- whole-app baseline ---
WAC=$(unzip -l "$APP" 2>/dev/null | grep -c '\.class$'); WAMB=$(( $(wc -c <"$APP")/1048576 ))
read -r wa_s wa_w wa_r wa_c wa_staged wa_warn <<EOF
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
read -r cv_s cv_w cv_r cv_c cv_staged cv_warn <<EOF
$(measure "$WORK/scoped.jar" "$WORK/scoped.cpg" "$WORK/scoped")
EOF

# header once. wa_staged = jimple2cpg's "Loading N program files": if wa_staged << wa_classes,
# the whole-app build silently truncated its input (see docs/METRICS.md).
[ -f "$CSV" ] || echo "label,wa_classes,wa_staged,wa_warns,wa_jar_mb,wa_status,wa_wall_s,wa_rss_mb,wa_cpg_mb,cv_classes,cv_staged,cv_status,cv_wall_s,cv_rss_mb,cv_cpg_mb,globs" > "$CSV"
echo "$LABEL,$WAC,$wa_staged,$wa_warn,$WAMB,$wa_s,$wa_w,$wa_r,$wa_c,$CVC,$cv_staged,$cv_s,$cv_w,$cv_r,$cv_c,$*" >> "$CSV"
echo "[$LABEL] whole-app: $wa_s ${wa_w}s ${wa_r}MB cpg=${wa_c}MB (staged ${wa_staged}/${WAC} cls, ${wa_warn} warns) | carved: $cv_s ${cv_w}s ${cv_r}MB cpg=${cv_c}MB (staged ${cv_staged}/${CVC} cls)"
# Preserve logs (the earlier harness deleted them, which hid the staging truncation).
LOGDIR="${METRICS_LOGDIR:-$(dirname "$CSV")/metrics-logs}/$LABEL"; mkdir -p "$LOGDIR"
cp -f "$WORK"/base.log "$WORK"/base.err "$WORK"/scoped.log "$WORK"/scoped.err "$LOGDIR"/ 2>/dev/null
rm -rf "$WORK"
