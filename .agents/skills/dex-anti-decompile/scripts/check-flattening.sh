#!/usr/bin/env bash
# check-flattening.sh — post-conversion detector for exception-table flattening / irreducible-flow
# obfuscation (the anti-DECOMPILER technique that has ~no DEX footprint).
#
# The tell: after dex2jar, ONE method's `javap -c` exception table has hundreds/thousands of rows
# (a normal method has single digits) AND every stock decompiler fails on it. Real case: Coocon
# ScriptManager.updateScript = 819-1033 exception-table rows; CFR/jadx/Vineflower/Fernflower all fail.
#
# Usage:
#   check-flattening.sh <Class.class | scoped.jar> [rows_threshold=100]
# Prints methods whose exception-table row count exceeds the threshold.
#
# Defeat: ExFlattenNormalize.java (../../sdk-carve/scripts/) --redundant --split --unify, then CFR.
set -euo pipefail
TARGET="${1:?usage: check-flattening.sh <Class.class|jar> [rows_threshold]}"
THRESH="${2:-100}"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
classes=()
if [[ "$TARGET" == *.jar ]]; then
  (cd "$tmp" && unzip -oq "$TARGET" 2>/dev/null || true)
  while IFS= read -r c; do classes+=("$c"); done < <(find "$tmp" -name '*.class')
else
  classes+=("$TARGET")
fi
hit=0
for c in "${classes[@]}"; do
  # javap -c: a method decl ends with ';' and contains '(' ; its Code has an "Exception table:"
  # block whose rows look like "  12  26  32  Class <type>" (or "any"). Count rows per method.
  # Count real exception-table rows ("N  N  N  Class/any ...") per method. Bytecode lines
  # ("12: invokevirtual") have one number+colon and never match, so no in-block flag is needed.
  javap -p -c "$c" 2>/dev/null | awk -v T="$THRESH" -v F="$c" '
    function flush() { if (meth!="" && rows>T) printf "  [FLAT] exception-table-rows=%d  (>%d)  %s  [%s]\n", rows, T, meth, F }
    /^[[:space:]]+[a-zA-Z].*\(.*\).*;[[:space:]]*$/ { flush(); meth=$0; sub(/^[[:space:]]+/,"",meth); rows=0 }
    /^[[:space:]]+[0-9]+[[:space:]]+[0-9]+[[:space:]]+[0-9]+[[:space:]]+(Class|any)([[:space:]]|$)/ { rows++ }
    END { flush() }
  '
done
echo "(done — any [FLAT] above = likely exception-table flattening; confirm with a decompiler failing on that method,"
echo " then defeat with ExFlattenNormalize.java --redundant --split --unify)"
