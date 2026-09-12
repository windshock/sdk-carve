#!/usr/bin/env bash
# coocon-buildfamily.sh — per-app build-family fingerprint of the Coocon iSAS `sasapi` subtree, to cluster
# L3 carriers into shared builds (turns "N apps carry it" into "which iSAS build propagated where").
#
# Emits per app:  inventory_hash (defined sasapi class-name set)  +  api_shape_hash (+ method/field descriptors).
# Family tiers (do NOT collapse):  same inventory = STRUCTURAL family · same api_shape = SAME-API build (strong)
#                                  · same normalized code_hash = same build · same raw bytes = byte-identical.
# (code_hash is TODO — needs normalized bytecode via `dexdump -d` with pool-index/offset stripping.)
#
# Requires: Android build-tools `dexdump` (set DEXDUMP or it auto-picks the newest under ~/Library/Android/sdk).
# Usage:  coocon-buildfamily.sh <app.apk|app.xapk|app.apks|app.jar> [label]  [... more apps ...]
#         (repeat pairs; or feed one and post-process). Prints:  <label> n=<#classes> inv=<h> api=<h>
set -u
export LC_ALL=C
DEXDUMP="${DEXDUMP:-$(ls -1 "$HOME"/Library/Android/sdk/build-tools/*/dexdump 2>/dev/null | sort -V | tail -1)}"
[ -x "$DEXDUMP" ] || { echo "dexdump not found (set DEXDUMP=/path/to/dexdump)"; exit 2; }

emit() {
  local label="$1" f="$2" tmp i=0; tmp=$(mktemp -d); trap 'rm -rf "$tmp"' RETURN
  case "$f" in
    *.xapk|*.apks|*.zip) unzip -oq "$f" -d "$tmp/c" 2>/dev/null
        while IFS= read -r a; do i=$((i+1)); mkdir -p "$tmp/dex/$i"; unzip -oq "$a" 'classes*.dex' -d "$tmp/dex/$i" 2>/dev/null; done < <(find "$tmp/c" -name '*.apk') ;;
    *.apk) mkdir -p "$tmp/dex/0"; unzip -oq "$f" 'classes*.dex' -d "$tmp/dex/0" 2>/dev/null ;;
    *.jar) cp "$f" "$tmp/x.jar" ;;
    *) echo "$label ? unsupported"; return 2 ;;
  esac
  local inv="$tmp/inv.txt" api="$tmp/api.txt"; : >"$inv"; : >"$api"
  if [ -f "$tmp/x.jar" ]; then          # jar: class-def = .class entry (no bytecode api-shape available)
    unzip -Z1 "$tmp/x.jar" 2>/dev/null | grep -E '^kr/co/coocon/sasapi/.*\.class' | sed 's#\.class$##;s#/#.#g' | sort -u >"$inv"
  else
    for z in $(find "$tmp/dex" -name '*.dex' 2>/dev/null); do
      strings -a "$z" 2>/dev/null | grep -q 'coocon/sasapi' || continue    # cheap pre-filter
      "$DEXDUMP" "$z" 2>/dev/null | awk '
        /Class descriptor/ { cur=($0 ~ /coocon\/sasapi/); if(cur){d=$0; sub(/.*: */,"",d); gsub(/[.'\'' ]/,"",d); print "C "d >> "'"$inv"'"} }
        cur && /^      name/ { nm=$0; sub(/.*: */,"",nm) }
        cur && /^      type/ { tp=$0; sub(/.*: */,"",tp); print "M "nm" "tp >> "'"$api"'" }'
    done
  fi
  sort -u "$inv" -o "$inv"; sort -u "$api" -o "$api"
  local n ih ah; n=$(grep -c . "$inv"); ih=$(shasum -a256 "$inv"|cut -c1-12); ah=$(cat "$inv" "$api"|sort -u|shasum -a256|cut -c1-12)
  printf "%-16s n=%-4s inv=%s api=%s\n" "$label" "$n" "$ih" "$ah"
}

# args: pairs of <apk> [label]; if label omitted, use basename
while [ $# -gt 0 ]; do
  apk="$1"; shift
  if [ $# -gt 0 ] && [ ! -e "$1" ]; then lbl="$1"; shift; else lbl="$(basename "$apk")"; fi
  emit "$lbl" "$apk"
done
# Post-process to cluster:  coocon-buildfamily.sh a.xapk A b.xapk B ... | sort -k3 -t= ; group equal inv=/api=.
