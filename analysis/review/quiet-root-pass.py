#!/usr/bin/env python3
"""Independent-review pass #3 — surface the behavior-sweep blind spot.

behavior-sweep.py flags roots with collect>=2 + sink>=1 using LITERAL API-name regex.
It cannot see collectors hidden behind reflection / runtime string-decryption (observed
in Adison i/w: dc.Ȍ̔̒˓(...)). This pass finds roots that CAN exfil (network/webview
sink present) but carry hidden-collection machinery (reflection, runtime crypto/base64
decode, dynamic class loading, and NON-ASCII "obfuscated identifiers") while showing
FEW plaintext capability APIs — i.e., exactly what the sweep under-counts.

It does NOT decide maliciousness; it produces a *carve short-list* the sweep misses.
Read-only; does not modify any original report or skill script.

Usage: quiet-root-pass.py <app-dex2jar.jar> [more.jar ...]
"""
from __future__ import annotations
import re, sys, unicodedata, zipfile
from collections import defaultdict

# plaintext capability / sink signals (same literal API names behavior-sweep relies on)
COLLECT = re.compile("|".join(map(re.escape, [
    "requestLocationUpdates","getLastKnownLocation","getCurrentLocation","getDeviceId",
    "getImei","getSubscriberId","getSimSerialNumber","getAndroidId","AdvertisingIdClient",
    "getMacAddress","getScanResults","getBondedDevices","startDiscovery","getAllCellInfo",
    "getInstalledPackages","getInstalledApplications","getRunningTasks","queryIntentActivities",
    "getPrimaryClip","ContactsContract","CallLog","AudioRecord","AccessibilityService"])))
NET  = re.compile("|".join(map(re.escape, ["openConnection","Ljava/net/Socket;","DatagramSocket","Lokhttp3/","Lretrofit2/","Lorg/apache/http/"])))
WEB  = re.compile("|".join(map(re.escape, ["addJavascriptInterface","loadUrl","postUrl","evaluateJavascript","loadDataWithBaseURL"])))
REFL = re.compile("|".join(map(re.escape, ["Ljava/lang/reflect/Method","getDeclaredMethod","getMethod","forName","getDeclaredField",";->invoke"])))
CRYP = re.compile("|".join(map(re.escape, ["Ljavax/crypto/Cipher","Ljavax/crypto/spec/","Landroid/util/Base64","Ljava/util/Base64"])))
DYN  = re.compile("|".join(map(re.escape, ["DexClassLoader","InMemoryDexClassLoader"])))

ORG = ("com","org","net","kr","jp","io","de","uk","cn")
# recognized framework / commercial ad-analytics libs — waved through by behavior-sweep's ~BENIGN;
# a REVIEW tag on anything NOT here = the actionable list (first-party + R8 single-letter roots).
RECOGNIZED = ("kotlin","kotlinx","androidx","android","java","javax","org/jetbrains","io/ktor",
    "okhttp3","okio","retrofit2","org/apache","com/squareup","com/google","org/chromium",
    "com/unity3d","com/unity","com/applovin","com/vungle","com/mopub","com/ironsource","com/mbridge",
    "com/appsflyer","com/adjust","com/facebook","io/branch","com/inmobi","net/pubnative","com/chartboost",
    "com/amazon","com/nps/adiscope","com/smaato","com/fyber","com/pubmatic","com/criteo","com/tapjoy",
    "com/ogury","com/bykv","com/bytedance","com/pgl","io/flutter","com/safedk","com/apm/insight",
    "io/bidmachine","com/kakao","com/naver","com/cauly","com/tnkfactory","com/tencent","com/bumptech",
    "com/byappsoft","com/fsn","com/mbridgex","com/vungle","com/moloco","com/json","com/adcolony")
def recognized(r): return r.startswith(RECOGNIZED)
def root_of(path, depth):
    pkg = path.rsplit("/",1)[0]; parts = pkg.split("/")
    if not parts or pkg == path: return "(default)"
    return "/".join(parts[:depth]) if parts[0] in ORG else parts[0]

# obfuscated-identifier tell: short CONSTANT_Utf8 identifiers containing a non-ASCII
# LETTER/MARK that is NOT Hangul/CJK (i.e. a weird obfuscation alphabet, e.g. Adison's).
_CP_SIZE = {3:4,4:4,5:8,6:8,7:2,8:2,9:4,10:4,11:4,12:4,15:3,16:2,17:4,18:4,19:2,20:2}
def _is_hangul_cjk(ch):
    o = ord(ch)
    return (0xAC00<=o<=0xD7A3) or (0x4E00<=o<=0x9FFF) or (0x3130<=o<=0x318F) or (0x1100<=o<=0x11FF) or (0x3000<=o<=0x303F) or (0xFF00<=o<=0xFFEF)
def obf_ident(b: bytes) -> bool:
    # walk the constant pool; True if any short identifier-shaped Utf8 has a weird non-ASCII letter
    try:
        if b[:4] != b"\xca\xfe\xba\xbe": return False
        n = int.from_bytes(b[8:10],"big"); i = 10; k = 1
        while k < n:
            tag = b[i]; i += 1
            if tag == 1:
                ln = int.from_bytes(b[i:i+2],"big"); i += 2
                raw = b[i:i+ln]; i += ln
                if 1 <= ln <= 12 and b"/" not in raw and b"(" not in raw and b";" not in raw and any(c >= 0x80 for c in raw):
                    try: s = raw.decode("utf-8")
                    except Exception: s = ""
                    for ch in s:
                        if ord(ch) >= 0x80 and not _is_hangul_cjk(ch) and unicodedata.category(ch)[0] in ("L","M","S"):
                            return True
            else:
                i += _CP_SIZE.get(tag, 0)
                if tag in (5,6): k += 1
            k += 1
    except Exception:
        return False
    return False

def sweep(jar):
    R = lambda: {"cls":0,"collect":set(),"net":0,"web":0,"refl":0,"cryp":0,"dyn":0,"obf":0}
    d = defaultdict(R)
    with zipfile.ZipFile(jar) as z:
        for name in z.namelist():
            if not name.endswith(".class"): continue
            b = z.read(name); s = b.decode("latin-1")
            for depth in (3,4):
                r = root_of(name, depth)
                e = d[r]; e["cls"] += 1
                if COLLECT.search(s):
                    for m in set(COLLECT.findall(s)): e["collect"].add(m)
                if NET.search(s):  e["net"]  += 1
                if WEB.search(s):  e["web"]  += 1
                if REFL.search(s): e["refl"] += 1
                if CRYP.search(s): e["cryp"] += 1
                if DYN.search(s):  e["dyn"]  += 1
                if obf_ident(b):   e["obf"]  += 1
    # quiet exfil-capable: has sink, hidden machinery, but <=1 plaintext collect category
    rows = []
    for r,e in d.items():
        if r in ("(default)",) or e["cls"] < 3: continue
        sink = e["net"] + e["web"]
        hidden = e["refl"] + e["cryp"] + e["dyn"] + e["obf"]
        if sink > 0 and hidden >= 3 and len(e["collect"]) <= 1:
            score = hidden + 5*e["obf"] + 3*e["dyn"]
            rows.append((score, r, e, sink, hidden))
    rows.sort(reverse=True)
    print(f"\n===== quiet-root pass: {jar} =====")
    unknown = [x for x in rows if not recognized(x[1])]
    print(f"** UNKNOWN quiet exfil-capable roots (NOT recognized lib/ad — cross-check vs report attributions) — {len(unknown)}:")
    if not unknown: print("   (none — every quiet exfil-capable root is a recognized lib/ad SDK)")
    for score,r,e,sink,hidden in unknown[:25]:
        print(f"   REVIEW {r:<34} cls={e['cls']:<5} net/web={e['net']}/{e['web']} refl={e['refl']} cryp={e['cryp']} dyn={e['dyn']} OBF={e['obf']} plaintext={sorted(e['collect'])}")
    print(f"-- recognized-lib quiet roots (waved through by sweep ~BENIGN; obfuscated+exfil-capable but trusted) — {len(rows)-len(unknown)} (top 8):")
    for score,r,e,sink,hidden in [x for x in rows if recognized(x[1])][:8]:
        print(f"   lib    {r:<34} net/web={e['net']}/{e['web']} refl={e['refl']} cryp={e['cryp']} dyn={e['dyn']} OBF={e['obf']}")
    obf = sorted(((e["obf"],r,e["cls"]) for r,e in d.items() if e["obf"]>0 and not recognized(r)), reverse=True)[:15]
    print(f"** UNKNOWN obfuscated-identifier hotspots (non-ASCII weird-alphabet ids, non-lib) — {len(obf)}:")
    for c,r,ncls in obf: print(f"   {r:<38} OBFident_cls={c}/{ncls}")
    dyn = sorted(((e["dyn"],r) for r,e in d.items() if e["dyn"]>0), reverse=True)[:12]
    print("dynamic-loading roots (DexClassLoader/InMemoryDexClassLoader) [* = non-lib]:")
    for c,r in dyn: print(f"   {'*' if not recognized(r) else ' '} {r:<36} dynload_cls={c}")

for jar in sys.argv[1:]:
    sweep(jar)
