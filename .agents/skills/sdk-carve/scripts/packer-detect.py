#!/usr/bin/env python3
"""sdk-carve pre-carve (stage 0) — identify the packer / app-shielder / obfuscator, and report
what it does to CARVE FIDELITY *before* you carve.

Why this exists (learned from the xShield case):
  `apk-normalize.py` handles a *tampered container* (fake ZIP flags, decoy dex). But a commercial
  app-shielder (NSHC xShield/DxShield, AppSealing, DexGuard, Bangcle, Tencent Legu, …) repackages
  into a PERFECTLY VALID zip — aapt/apktool are happy, classes.dex parses — yet:
    - the app strings are ENCRYPTED (IOC/endpoint sweeps return garbage → false negatives), and/or
    - the real code lives in an ENCRYPTED PAYLOAD DEX decrypted at runtime (classes.dex is a
      stub/loader → a bytecode carve sees ~nothing of the SDK and reports "clean" = silent
      under-scope, the exact failure mode sdk-carve exists to prevent).
  Neither is visible to container normalization. You must first *identify the shielder* and let
  its known behaviour tell you whether a static carve is VALID, DEGRADED, or BLIND.

Signature source: the AWAKE packer catalog (awakewiki.org/packers) + APKiD rule knowledge +
first-party reverse findings (xShield/libdxbase). APKiD, if installed, is run and merged as the
authoritative engine; this script's built-in table is the offline fallback and adds the carve-impact
classification + the Korean-financial shielders (xShield/DxShield, LIAPP, nProtect) the wiki is thin on.

usage:
    packer-detect.py <app.apk>            # human report + exit code
    packer-detect.py --json <app.apk>     # machine-readable
exit code: 0 = static carve valid | 10 = degraded (strings/DEX) | 20 = blind (payload-encrypted DEX)
           30 = UNKNOWN/suspicious packer indicators (possible custom/malware packer)
"""
import sys, os, re, json, math, zipfile, subprocess, collections

# ---------------------------------------------------------------------------------------------------
# Signature table. category: shielder(commercial RASP) | packer(commercial) | malware | obfuscator.
# impact flags describe what the protector does to a *static bytecode carve*:
#   strings  = app strings are encrypted (IOC/endpoint sweep unreliable → run after unpack/dynamic)
#   dex      = real code is in an encrypted/runtime-loaded payload DEX (bytecode carve is BLIND)
#   rasp     = anti-debug/root/emu/frida (a *dynamic* dump needs a bypass; static is unaffected)
# match keys: libs (lib/*/*.so basename regex), assets (zip path regex), pkgs (dex UTF string regex),
#             markers (any zip path regex). A signature fires if ANY of its patterns match.
# ---------------------------------------------------------------------------------------------------
SIGS = [
  # ---- Korean financial / RASP shielders (the class the AWAKE wiki under-covers) ----
  dict(name="NSHC xShield / DxShield", vendor="NSHC", category="shielder",
       libs=[r"libdxbase\.so", r"libnms\.so", r"libeca758\.so"], pkgs=[r"com/xshield/"],
       impact=dict(strings=True, dex=True, rasp=True),
       note="APKiD: libdxbase.so -> DxShield. Financial build likely FxShield. String vault + "
            "encrypted payload DEX + native anti-debug/root/emu/frida. First-party reverse confirms "
            "runtime-decrypt-only payload."),
  dict(name="AppSealing", vendor="INKA Entworks / DoveRunner", category="shielder",
       libs=[r"libcovault-appsec\.so", r"libsecureapp\.so"], assets=[r"assets/AppSealing/"],
       impact=dict(strings=True, dex=True, rasp=True),
       note="AppPealing (Xposed) is the AppSealing-specific one-click dumper (does NOT apply to other "
            "shielders)."),
  dict(name="LIAPP", vendor="Lockin Company", category="shielder",
       pkgs=[r"com/lockincomp/", r"com/liapp/"],
       impact=dict(strings=True, dex=True, rasp=True),
       note="Server-side token/attestation; dynamic bypass often needs server token replay."),
  dict(name="nProtect / AppGuard", vendor="INCA Internet", category="shielder",
       libs=[r"libnprotect.*\.so", r"libAppGuard.*\.so"], pkgs=[r"com/nprotect/", r"com/inca/"],
       impact=dict(strings=True, dex=True, rasp=True), note="Korean RASP; whole-app."),

  # ---- Commercial packers/shielders from the AWAKE catalog ----
  dict(name="360 Jiagu", vendor="Qihoo 360", category="packer",
       libs=[r"libjiagu(_art|_x86|_a64|_x64|_ls)?\.so"], assets=[r"assets/jiagu_data\.bin"],
       impact=dict(strings=False, dex=True, rasp=True),
       note="Memory dump (easy-medium). Real DEX released to memory at runtime."),
  dict(name="Bangcle / SecNeo", vendor="Bangcle", category="packer",
       libs=[r"libsecexe\.so", r"libsecmain\.so", r"libSecShell\.so", r"libDexHelper\.so"],
       assets=[r"assets/secData0\.jar", r"assets/bangcle_classes\.jar"],
       impact=dict(strings=False, dex=True, rasp=True), note="Memory dump."),
  dict(name="Tencent Legu", vendor="Tencent", category="packer",
       libs=[r"libshell[axo]?-?.*\.so", r"libtup\.so", r"libtosprotection.*\.so", r"libBugly\.so"],
       assets=[r"assets/0OO00l111l1l", r"assets/tosversion"],
       impact=dict(strings=False, dex=True, rasp=True), note="Memory dump."),
  dict(name="DexProtector", vendor="Licel", category="shielder",
       libs=[r"libalice\.so", r"libdexprotector.*\.so"], assets=[r"assets/dp\.arm.*", r"\.dp\d*$"],
       impact=dict(strings=True, dex=True, rasp=True),
       note="Class-encryption + string encryption; randomized .dat/.mp3 payloads."),
  dict(name="DexGuard", vendor="Guardsquare", category="shielder",
       pkgs=[r"com/guardsquare/", r"o/aaaa"],  # renamed-so + encrypted class stubs; weak sig
       impact=dict(strings=True, dex=False, rasp=True),
       note="Class-level encrypted stubs + string/reflection obfuscation + renamed .so. Carve sees "
            "code but strings/reflection are obfuscated (DEGRADED, not blind). Confirm via APKiD."),
  dict(name="iJiami", vendor="iJiami", category="packer",
       libs=[r"libexec(main)?\.so", r"libexecmain\.so"], assets=[r"assets/ijiami\.dat", r"ijm_lib/"],
       impact=dict(strings=False, dex=True, rasp=True), note="Memory dump."),
  dict(name="Baidu Reinforcement", vendor="Baidu", category="packer",
       libs=[r"libbaiduprotect\.so"], assets=[r"assets/baiduprotect.*"],
       impact=dict(strings=False, dex=True, rasp=True)),
  dict(name="Naga / Nagain APKProtect", vendor="Nagain", category="packer",
       libs=[r"libnagain.*\.so", r"libAPKProtect\.so"], impact=dict(strings=False, dex=True, rasp=True)),
  dict(name="Kiwisec", vendor="Kiwisec", category="packer",
       libs=[r"libkiwi.*\.so", r"libDexHelper-x86\.so"], impact=dict(strings=False, dex=True, rasp=True)),
  dict(name="zShield", vendor="Zimperium", category="shielder",
       assets=[r"\.szip$"], impact=dict(strings=True, dex=True, rasp=True),
       note="lib<random12>.so + XXTEA-encrypted ELF; randomized names (low-confidence lib sig)."),
  dict(name="Ducex", vendor="unknown (CN)", category="packer",
       libs=[r"libducex\.so"], impact=dict(strings=False, dex=True, rasp=True), note="RC4/SM4."),
  dict(name="Promon SHIELD", vendor="Promon", category="shielder",
       pkgs=[r"no/promon/"], impact=dict(strings=True, dex=False, rasp=True),
       note="RASP, no fixed lib name — low-confidence; confirm dynamically."),
  dict(name="Appdome", vendor="Appdome", category="shielder",
       assets=[r"assets/appdome/"], pkgs=[r"com/appdome/"],
       impact=dict(strings=True, dex=True, rasp=True), note="Outer DEX + native stubs; frida DEX dump."),
  dict(name="Verimatrix XTD (formerly)", vendor="Verimatrix", category="shielder",
       pkgs=[r"com/verimatrix/"], impact=dict(strings=True, dex=False, rasp=True)),
  dict(name="Virbox", vendor="SenseShield", category="shielder",
       assets=[r"assets/virbox.*", r"libsandhook.*\.so"], impact=dict(strings=True, dex=True, rasp=True),
       note="Native VM interpreter; expert-level."),
  # ---- KR commercial (observed 2026-09, cross-checked on real KR finance apps) ----
  dict(name="APKSHIELD", vendor="ahope / Penta Security (ISSAC)", category="packer",
       libs=[r"libahope(_[no])?\.so", r"libIWAndroid\.so", r"libwbaes\.so"],
       pkgs=[r"com/apk_shield/", r"com/goggles/", r"com/ahope/app_shields/"],
       assets=[r"assets/asorg$", r"assets/tables$"],
       impact=dict(strings=False, dex=True, rasp=True),
       note="Whole-app WHITE-BOX-AES packer. Stub loader com.goggles.ApkApp -> Native.c() loadLibrary(wbaes)+"
            "feed assets/tables (WBAES key tables) -> WBAES-decrypt assets/asorg (block-aligned ct) -> "
            "filesDir/asorg.zip -> real dexes -> newApplication(real). Native: libwbaes (decWbAesInit/Update/"
            "DoFinal, BcCreateAndInitWhiteBox), libIWAndroid (Penta ISSAC BCIPHER_Decrypt), libahope_[no] "
            "(apkshield_native/obfuscation.c, RegisterNatives). Self-string 'APKSHIELD_USE_CLASS_LOADER_LIB'. "
            "STATIC UNPACK (DEFEATED, no device/Frida): the white-box only protects KEY DERIVATION, not bulk "
            "crypto. unidbg-load the 4 libs, Native.callMethodV(\"I\") + callMethodW(\"WI\",assets/tables) [wb init], "
            "then direct-symbol call callMethod(\"K\",idx) idx 0..3 -> four 16-byte AES keys; then OFFLINE "
            "AES-128-CBC (asorg = key idx 0, IV = the hardcoded 16-byte string-crypto IV from Native.b) -> PK zip "
            "of the real dexes. Verified: KB Pay com.kbcard.cxh.appcard -> 14 dexes recovered. Harness pattern in "
            "the appshield-unpack skill (AppShieldKeyExtract.java + appshield_unpack.py)."),
  dict(name="AppIron", vendor="SFA (앱아이언)", category="shielder",
       libs=[r"libAppIron-(jni_v[0-9.]+|Suite|RemoteBan-jni_[0-9.]+)\.so"],
       impact=dict(strings=False, dex=False, rasp=True),
       note="RASP / anti-tamper ONLY — leaves the DEX PLAINTEXT (verified on 8 KR finance apps: readable "
            "class-descriptor density 740-865/MB, no encrypted payload). Runtime root/debug/hook/remote-control "
            "block. dex=False -> carve is VALID; do NOT mark INDETERMINATE on this .so alone."),

  # ---- Malware packers / loaders (AWAKE 'malware' + families sdk-carve already handles) ----
  dict(name="Hqwar (malware DEX packer)", vendor="RU underground", category="malware",
       impact=dict(strings=True, dex=True, rasp=False),
       note="Wrapper/loader DEX + encrypted payload. Treat as HOSTILE unpack target."),
  dict(name="Necro (steganographic DEX)", vendor="malware family", category="malware",
       pkgs=[r"com/coral/Coral", r"libcoral\.so"],
       impact=dict(strings=False, dex=True, rasp=False),
       note="Payload DEX hidden in image pixels (steganography). sdk-carve has a carved loader "
            "fingerprint for this family — see analysis/necro."),
  # obfuscators (NOT packers — carve works, but readability degraded)
  dict(name="R8 / ProGuard", vendor="Google", category="obfuscator",
       impact=dict(strings=False, dex=False, rasp=False),
       note="Renaming/shrinking only. Carve is VALID; use detect.py's renamed-root resolver."),
]

# ---------------------------------------------------------------------------------------------------
u = lambda b: b.decode("latin-1", "replace")

def entropy(b):
    if not b: return 0.0
    n = len(b); c = collections.Counter(b)
    return -sum(v/n * math.log2(v/n) for v in c.values())

def collect(apk):
    """Gather zip names, native libs, asset paths, dex sizes, and a UTF-string blob from dex."""
    z = zipfile.ZipFile(apk)
    names = z.namelist()
    libs   = [os.path.basename(n) for n in names if re.match(r"lib/[^/]+/", n) and n.endswith(".so")]
    assets = [n for n in names if n.startswith("assets/")]
    dexes  = [n for n in names if re.match(r"classes\d*\.dex$", n)]
    # size of each dex + entropy of the largest asset (packed-payload heuristic)
    dexinfo = []
    for n in dexes:
        try: dexinfo.append((n, z.getinfo(n).file_size))
        except KeyError: pass
    big_assets = []
    for n in assets:
        try:
            sz = z.getinfo(n).file_size
            if sz > 64*1024:
                with z.open(n) as f: head = f.read(65536)
                big_assets.append((n, sz, entropy(head)))
        except Exception: pass
    # cheap dex string scan for package markers (grep printable com/... paths)
    pkgblob = b""
    for n, _ in sorted(dexinfo, key=lambda x: -x[1])[:2]:
        try:
            with z.open(n) as f: pkgblob += f.read(4*1024*1024)
        except Exception: pass
    # readable-string density (in-dex string-encryption tell): normal apps have thousands of long
    # words + hundreds of type descriptors per MB; a string-encrypted app (e.g. Toss) has ~none.
    mb = max(len(pkgblob) / 1e6, 1e-6)
    readable = dict(
        mb=round(len(pkgblob) / 1e6, 1),
        words_per_mb=round(len(re.findall(rb"[a-z]{5,}", pkgblob)) / mb, 1),
        desc_per_mb=round(len(re.findall(rb"L(?:com|java|android|kotlin|org)/", pkgblob)) / mb, 1),
        http_per_mb=round(len(re.findall(rb"https?://", pkgblob)) / mb, 2))
    return dict(names=names, libs=libs, assets=assets, dexinfo=dexinfo,
                big_assets=big_assets, pkgblob=u(pkgblob), readable=readable)

def match(sig, ctx):
    hits = []
    for pat in sig.get("libs", []):
        for l in ctx["libs"]:
            if re.search(pat, l): hits.append(f"lib:{l}"); break
    for pat in sig.get("assets", []):
        for a in ctx["assets"]:
            if re.search(pat, a): hits.append(f"asset:{a}"); break
    for pat in sig.get("markers", []):
        for a in ctx["names"]:
            if re.search(pat, a): hits.append(f"file:{a}"); break
    for pat in sig.get("pkgs", []):
        if re.search(pat, ctx["pkgblob"]): hits.append(f"pkg:{pat}")
    return hits

def run_apkid(apk):
    try:
        out = subprocess.run(["apkid", "-j", apk], capture_output=True, text=True, timeout=180)
        if out.returncode == 0 and out.stdout.strip():
            return json.loads(out.stdout)
    except Exception:
        return None
    return None

def unknown_indicators(ctx):
    """Heuristics for a custom/unidentified packer when no known signature fired.

    Deliberately CONSERVATIVE — ordinary high-entropy assets (compressed fonts/.woff, Cocos2d
    .png/.jsc/.mp3, ML models, webp) are near-random and are NOT packing. The only reliable
    signature-free tell of a *stub-loader* packer is a genuinely stub-sized classes.dex paired
    with an encrypted payload asset that DWARFS it (payload > loader). A normal app — even a
    heavily-obfuscated one — ships megabytes of real dex, so this cannot fire on legit apps.
    """
    flags = []
    total_dex = sum(s for _, s in ctx["dexinfo"])
    # a real app rarely has < ~500KB of total dex; a packer stub loader is tiny.
    if ctx["dexinfo"] and total_dex < 500*1024:
        payloads = [(n, s, e) for n, s, e in ctx["big_assets"] if e >= 7.9 and s > total_dex]
        if payloads:
            flags.append(f"stub classes.dex ({total_dex//1024}KB) + larger encrypted-looking asset(s) "
                         f"{[(n, round(e,2)) for n,_,e in payloads]} → likely a loader over an encrypted "
                         f"payload (custom/unidentified packer)")
        else:
            flags.append(f"stub-sized classes.dex ({total_dex//1024}KB) with no matching known packer — "
                         f"inspect for a runtime DEX loader")
    return flags

def string_encryption_indicators(ctx):
    """Signature-free tell of an in-house DEX string-encryption obfuscator (e.g. Toss 5.276.0).

    No packer .so / asset marker fires, the dex is a full real-code app (not a stub), yet the readable
    string density is ~0 — class descriptors and long words that every normal (even R8'd) app carries by
    the thousand/MB are absent because the string constants are encrypted in-dex. Calibrated 3 orders of
    magnitude apart: plaintext ~15,000 words/MB & ~1,000 descriptors/MB vs Toss ~9 words/MB & ~0/MB.
    Conservative thresholds (well below any normal app) so this cannot fire on legit/obfuscated apps.
    """
    r = ctx.get("readable") or {}
    total_dex = sum(s for _, s in ctx["dexinfo"])
    if total_dex < 2 * 1024 * 1024 or r.get("mb", 0) < 1:
        return None                      # too small to judge / no dex scanned
    if r["words_per_mb"] < 300 and r["desc_per_mb"] < 100:
        return dict(words_per_mb=r["words_per_mb"], desc_per_mb=r["desc_per_mb"], http_per_mb=r["http_per_mb"],
                    total_dex_mb=round(total_dex / 1e6, 1))
    return None

def main():
    args = [a for a in sys.argv[1:] if a != "--json"]
    as_json = "--json" in sys.argv
    if not args:
        print(__doc__); sys.exit(2)
    apk = args[0]
    ctx = collect(apk)

    found = []
    for sig in SIGS:
        h = match(sig, ctx)
        if h:
            found.append(dict(name=sig["name"], vendor=sig["vendor"], category=sig["category"],
                              impact=sig["impact"], note=sig.get("note",""), evidence=h))
    apkid = run_apkid(apk)
    unknown = unknown_indicators(ctx) if not any(f["category"] in ("shielder","packer","malware") for f in found) else []
    strenc = string_encryption_indicators(ctx)
    if strenc and not any(f["impact"].get("strings") for f in found if f["category"] in ("shielder","packer","malware")):
        found.append(dict(name="In-house DEX string encryption (Toss-class)", vendor="in-house obfuscator",
                          category="shielder", impact=dict(strings=True, dex=False, rasp=False),
                          note=f"No packer .so/asset, full real-code dex ({strenc['total_dex_mb']}MB) but readable "
                               f"strings ~0 ({strenc['words_per_mb']} words/MB, {strenc['desc_per_mb']} descriptors/MB, "
                               f"{strenc['http_per_mb']} url/MB — normal apps carry thousands/MB). String constants are "
                               f"encrypted in-dex: IOC/endpoint '0 hits' is a FALSE NEGATIVE. Structure still carveable; "
                               f"recover strings via the SDK's own decrypt routine or a dynamic dump. Ref case: Toss 5.276.0.",
                          evidence=[f"readable-density: {strenc['words_per_mb']} words/MB (normal ~15000)"]))

    # verdict: worst carve-impact across shielders/packers/malware (obfuscators don't degrade carve)
    prot = [f for f in found if f["category"] in ("shielder","packer","malware")]
    code, verdict = 0, "static carve VALID (no packer/shielder; obfuscation-only at most)"
    if any(f["impact"]["dex"] for f in prot):
        code, verdict = 20, "static carve BLIND — real code is in a runtime-decrypted payload DEX; " \
                             "bytecode carve on classes.dex will silently under-scope"
    elif any(f["impact"]["strings"] for f in prot):
        code, verdict = 10, "static carve DEGRADED — strings encrypted; IOC/endpoint sweep unreliable " \
                            "until unpacked/dynamically dumped (structure still carveable)"
    if not prot and unknown:
        code, verdict = 30, "UNKNOWN/suspicious packer indicators — no known signature but the container " \
                            "looks packed; treat as hostile and identify before carving"

    if as_json:
        print(json.dumps(dict(apk=apk, verdict=verdict, exit=code, detections=found,
                              unknown_indicators=unknown, apkid=apkid,
                              native_libs=sorted(set(ctx["libs"])),
                              dex=ctx["dexinfo"]), indent=2))
        sys.exit(code)

    print(f"# packer-detect — {os.path.basename(apk)}\n")
    print(f"VERDICT: {verdict}\n")
    if found:
        for f in found:
            imp = ",".join(k for k,v in f["impact"].items() if v) or "none"
            print(f"  [{f['category'].upper():9}] {f['name']}  ({f['vendor']})")
            print(f"             carve-impact: {imp}")
            print(f"             evidence: {', '.join(f['evidence']) or '(dex string marker)'}")
            if f["note"]: print(f"             note: {f['note']}")
    else:
        print("  no known packer/shielder/obfuscator signature fired.")
    if unknown:
        print("\n  UNKNOWN-PACKER INDICATORS:")
        for x in unknown: print(f"    - {x}")
    if apkid:
        print("\n  APKiD (authoritative):")
        for fobj in apkid.get("files", []):
            for k, v in (fobj.get("matches") or {}).items():
                print(f"    - {k}: {', '.join(v)}")
    print("\n  next:")
    if code == 0:   print("    -> proceed to carve (detect.py -> carve.sh). Strings/IOC sweep are trustworthy.")
    if code == 10:  print("    -> carve STRUCTURE now; defer IOC/endpoint verdicts until unpack/dynamic dump.")
    if code == 20:  print("    -> DO NOT trust a bytecode carve. Recover the payload DEX first (pre-sealed "
                          "build or sanctioned dynamic dump), then carve THAT. See docs/PACKER_DETECT.md.")
    if code == 30:  print("    -> run apk-normalize.py + APKiD; identify/unpack before any carve verdict.")
    sys.exit(code)

if __name__ == "__main__":
    main()
