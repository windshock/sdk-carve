#!/usr/bin/env bash
# coocon-fingerprint.sh — classify an APK/XAPK/jar by which Coocon component it bundles, via a fast
# dex-string scan (no full dex2jar). The point: "is a Coocon customer / ships CheckPay" is NOT the same as
# "ships the server-JS-eval channel (sasapi/scriptengine) that is the active-MITM RCE surface".
#
# Usage:  coocon-fingerprint.sh <app.apk | app.xapk | app.jar>  [more ...]
# Exit (last arg): 0 = VULN CHANNEL present (sasapi/scriptengine), 1 = Coocon present (other component),
#                  3 = NEGATIVE (no Coocon, dex readable), 4 = INDETERMINATE (0 markers but packed/stripped —
#                  NOT a negative), 2 = usage/error. Elevate to CONFIRMED only on binary evidence (0/1).
set -u
[ $# -ge 1 ] || { echo "usage: $0 <apk|xapk|jar> [...]"; exit 2; }

fp_one() {
  local in="$1" tmp rc=3
  tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' RETURN
  shopt -s nullglob
  local hay="$tmp/hay.txt" ents="$tmp/ents.txt"; : > "$hay"; : > "$ents"
  # haystack = `strings` of every dex (class descriptors are readable); ents = archive entry names (for .so/packer).
  harvest_dex() { for d in "$@"; do [ -f "$d" ] && strings -a "$d" >> "$hay"; done; }
  case "$in" in
    *.xapk|*.apkm|*.zip) # split bundle: scan EVERY inner apk's dex (SDK often rides a split, not the base)
      unzip -oq "$in" -d "$tmp/xapk" 2>/dev/null
      for a in "$tmp/xapk"/*.apk "$tmp/xapk"/**/*.apk; do
        [ -f "$a" ] && { unzip -Z1 "$a" >> "$ents" 2>/dev/null; unzip -oq "$a" 'classes*.dex' -d "$tmp/d" 2>/dev/null; harvest_dex "$tmp/d"/*.dex; rm -f "$tmp/d"/*.dex; }
      done ;;
    *.apk) unzip -Z1 "$in" >> "$ents" 2>/dev/null; unzip -oq "$in" 'classes*.dex' -d "$tmp" 2>/dev/null; harvest_dex "$tmp"/*.dex ;;
    *.jar) unzip -Z1 "$in" >> "$hay" 2>/dev/null ;;   # jar: match on .class entry names
    *) echo "  ? unsupported: $in"; return 2 ;;
  esac
  [ -s "$hay" ] || { echo "  ? no dex/jar content: $in"; return 2; }
  c() { grep -aoh "$1" "$hay" 2>/dev/null | wc -l | tr -d ' '; }

  local any se v8 sm sas checkpay mydata
  any=$(c 'kr/co/coocon')
  se=$(c 'sasapi/scriptengine/ScriptEngine')
  v8=$(c 'sasapi/scriptengine/V8ScriptEngine')
  sm=$(c 'sasapi/script/ScriptManager')
  sas=$(c 'sasapi/SASManager')
  checkpay=$(c 'com/cp/checkpay'); [ "$checkpay" = 0 ] && checkpay=$(c 'coocon/checkpay')
  mydata=$(c 'mydata'); # coarse; refine per sample

  echo "  file: $(basename "$in")"
  echo "    kr/co/coocon refs=$any | SASManager=$sas | ScriptManager=$sm | ScriptEngine=$se | V8ScriptEngine=$v8 | CheckPay=$checkpay"
  if [ "$se" -gt 0 ] && [ "$sm" -gt 0 ]; then
    echo "    => VULN CHANNEL PRESENT (sasapi/scriptengine server-JS-eval) — the active-MITM RCE surface. deep-confirm next."
    rc=0
  elif [ "$any" -gt 0 ]; then
    echo "    => Coocon PRESENT but no sasapi/scriptengine (likely CheckPay/other component; not the RCE channel)."
    case "$in" in *.apk) echo "       NOTE: single .apk — if this is a split/base, the SDK may ride another split. Prefer the universal/XAPK." ;; esac
    rc=1
  else
    # 0 markers: INDETERMINATE only if the DEX IS ACTUALLY UNREADABLE (stub / string- or whole-dex encryption).
    # A shielder .so alone does NOT imply that — many KR RASPs (AppIron, this xShield variant) leave the dex
    # PLAINTEXT and only do runtime anti-tamper. Decide on readable class-descriptor density, not .so presence.
    local packer classdesc
    packer=$(grep -aoiE 'lib(AppIron|covault|dexhelper|jiagu|shell[a-z]*|secureproxy|secuen|appguard|pairip[a-z]*|DexProtector|whitecryptor|ksetup|mpaas|tup|xg)[^/]*\.so|appsealing|libDexHelper|libexecmain' "$ents" 2>/dev/null | sort -u | tr '\n' ' ')
    classdesc=$(grep -acE 'L[a-z]+/[a-z]+/[A-Za-z0-9/$]+;' "$hay" 2>/dev/null)   # readable class descriptors (strings)
    if [ "${classdesc:-0}" -lt 300 ]; then
      echo "    => INDETERMINATE — dex looks stripped/encrypted (readable class-descriptors=$classdesc${packer:+; shielder=$packer})."
      echo "       Class strings are hidden -> can't call it a negative. Unpack/deobfuscate then re-fingerprint."
      rc=4
    else
      echo "    => NEGATIVE — no Coocon markers; dex is READABLE (class-descriptors=$classdesc)${packer:+ [shielder present but dex plaintext: $packer]} -> genuinely no in-APK iSAS channel."
      rc=3
    fi
  fi
  return $rc
}

last=3
for f in "$@"; do fp_one "$f"; last=$?; done
exit $last

# Deep-confirm (after a VULN-CHANNEL hit) — turns presence into an exploitability verdict:
#   d2j-dex2jar -f -o app.jar app.apk
#   javap -c -p -cp app.jar kr.co.coocon.sasapi.script.ScriptManager   # default iface ver (field b, "02"?),
#                                                                       # no Signature.verify/Mac in updateScript
#   javap -c -p -cp app.jar kr.co.coocon.sasapi.SASManager             # server (isas.coocon.co.kr:443? plain TCP)
#   javap -c -p -cp app.jar kr.co.coocon.sasapi.scriptengine.ScriptEngine | grep -c setClassShutter   # expect 0
#   (then the ByteBuddy MITM lab for a live E2E, if warranted.)
