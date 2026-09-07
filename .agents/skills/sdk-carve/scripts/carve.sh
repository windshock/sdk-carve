#!/usr/bin/env bash
# sdk-carve — extract target packages from an app JAR into a scoped mini-JAR and build a CPG.
#
# Usage:  carve.sh <app-dex2jar.jar> <out-dir> <pkg-glob> [pkg-glob ...]
# Example: carve.sh app.jar out/ 'com/smart/sklb/*' 'bg/*' 'cg/*' 'dg/*'
#
# Requires: JDK 17 (Soot's ASM rejects Java 25 = class major version 69), python3, jimple2cpg.
#
# The mini-JAR is built jar->jar in memory (python zipfile), NOT by extracting to disk. That
# preserves class-name *case* — obfuscated siblings like `j.class` and `J.class` collide on a
# case-insensitive filesystem (macOS/APFS, NTFS) and would silently drop a class or hang
# unzip's overwrite prompt. jimple2cpg reads the jar in-memory, so case-colliding entries
# are fine downstream.
set -euo pipefail

JAR="${1:?usage: carve.sh <app.jar> <out-dir> <pkg-glob> [pkg-glob ...]}"
OUT="${2:?missing <out-dir>}"
shift 2
[ "$#" -ge 1 ] || { echo "give at least one package glob, e.g. 'com/smart/sklb/*'"; exit 1; }
: "${JAVA_HOME:?set JAVA_HOME to a JDK 17 (Soot rejects Java 25 bytecode)}"

JAR="$(cd "$(dirname "$JAR")" && pwd)/$(basename "$JAR")"
mkdir -p "$OUT"; OUT="$(cd "$OUT" && pwd)"

N=$(python3 - "$JAR" "$OUT/scoped.jar" "$@" <<'PY'
import sys, zipfile, fnmatch
src, dst, globs = sys.argv[1], sys.argv[2], sys.argv[3:]
def want(name):
    if not name.endswith(".class"):
        return False
    for g in globs:                        # accept 'pkg/*', 'pkg/', 'pkg' and fnmatch patterns
        pre = g.rstrip("*").rstrip("/")
        if name.startswith(pre + "/") or fnmatch.fnmatch(name, g):
            return True
    return False
n = 0
with zipfile.ZipFile(src) as zi, zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED) as zo:
    for it in zi.infolist():
        if want(it.filename):
            zo.writestr(it, zi.read(it.filename)); n += 1
print(n)
PY
)
[ "$N" -gt 0 ] || { echo "no classes matched those globs in $JAR"; rm -f "$OUT/scoped.jar"; exit 1; }
echo "carved $N classes -> $OUT/scoped.jar"

jimple2cpg "$OUT/scoped.jar" --output "$OUT/cpg.bin"
echo "CPG -> $OUT/cpg.bin"
