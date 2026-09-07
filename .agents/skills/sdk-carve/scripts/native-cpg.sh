#!/usr/bin/env bash
# sdk-carve (native track) — build a CPG from a native binary via Ghidra (ghidra2cpg).
#
# Usage:  native-cpg.sh <binary.so|.dll|.dylib|.exe> <out.cpg>
# Example: native-cpg.sh lib/arm64-v8a/libfoo.so out/libfoo.cpg
#
# JDK NOTE (opposite of the JVM track): Ghidra needs a RECENT JDK (21+). Do NOT pin
# JDK 17 here — that pin is only for jimple2cpg/Soot. Leave JAVA_HOME at the default
# (newest OpenJDK), which is exactly the one that breaks Soot but is required by Ghidra.
set -euo pipefail

BIN="${1:?usage: native-cpg.sh <binary> <out.cpg>}"
OUT="${2:?missing <out.cpg>}"
command -v ghidra2cpg >/dev/null || { echo "ghidra2cpg not found — install Joern + Ghidra"; exit 1; }

# A single library is already a scoped unit (vs the whole app). For a HUGE binary,
# scope further with ghidra2cpg --exclude-regex, or post-filter to the reachable
# subgraph of the exported functions of interest.
ghidra2cpg "$BIN" -o "$OUT"
echo "native CPG -> $OUT"
echo "query with:  CPG=$OUT joern --script native-inventory.sc 2>&1 | grep -a '^MARK'"
