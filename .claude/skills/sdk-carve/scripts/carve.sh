#!/usr/bin/env bash
# sdk-carve — extract target packages from an app JAR into a scoped mini-JAR and build a CPG.
#
# Usage:  carve.sh <app-dex2jar.jar> <out-dir> <pkg-glob> [pkg-glob ...]
# Example: carve.sh app.jar out/ 'com/smart/sklb/*' 'bg/*' 'cg/*' 'dg/*'
#
# Requires: JDK 17 (Soot's ASM rejects Java 25 = class major version 69), jar, unzip, jimple2cpg.
set -euo pipefail

JAR="${1:?usage: carve.sh <app.jar> <out-dir> <pkg-glob> [pkg-glob ...]}"
OUT="${2:?missing <out-dir>}"
shift 2
[ "$#" -ge 1 ] || { echo "give at least one package glob, e.g. 'com/smart/sklb/*'"; exit 1; }
: "${JAVA_HOME:?set JAVA_HOME to a JDK 17 (Soot rejects Java 25 bytecode)}"

JAR="$(cd "$(dirname "$JAR")" && pwd)/$(basename "$JAR")"
mkdir -p "$OUT"; OUT="$(cd "$OUT" && pwd)"
WORK="$(mktemp -d)"
( cd "$WORK" && unzip -q "$JAR" "$@" )
N=$(find "$WORK" -name '*.class' | wc -l | tr -d ' ')
[ "$N" -gt 0 ] || { echo "no classes matched those globs in $JAR"; rm -rf "$WORK"; exit 1; }

jar cf "$OUT/scoped.jar" -C "$WORK" .
rm -rf "$WORK"
echo "carved $N classes -> $OUT/scoped.jar"

jimple2cpg "$OUT/scoped.jar" --output "$OUT/cpg.bin"
echo "CPG -> $OUT/cpg.bin"
