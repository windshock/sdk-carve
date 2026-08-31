#!/usr/bin/env python3
"""sdk-carve — auto-locate an R8-renamed SDK root and print carve globs.

Step 0 of the method assumes you can seed the package name from docs. That only holds
when the SDK's package name survives obfuscation. In practice the same SDK is recompiled
per app with a DIFFERENT renamed root (e.g. the Goldoson/SMARTLB SDK appears as
com/smart/sklb/edge in one app but com/enoi/yweoi/nwef, com/gwox/pzkvn/riosk, ... in
others). This script finds the renamed root by anchoring on the SDK's own surviving
method names, guarded so it can't drag in a shaded library that happens to share
framework signatures.

Usage:
    detect.py <app-dex2jar.jar>
    # or, if you already extracted the jar to a tree:
    detect.py --tree <dir>

Env overrides (defaults = Goldoson/SMARTLB worked example):
    CORE_ANCHORS   regex of SDK-UNIQUE method names (the SDK's own, not framework)
    SCAN_ANCHOR    framework API A for the obfuscated-name fallback
    BOND_ANCHOR    framework API B for the obfuscated-name fallback
    GUARD          max classes a root may contain (default 400)

Prints one carve glob per line, e.g.:
    com/enoi/yweoi/nwef/*
Feed straight into scripts/carve.sh.

Why the guards (learned the hard way):
  * Size guard — WiFi/BT-scan framework APIs (getScanResults/getBondedDevices) also live
    in unrelated shaded libs (an 8k-class 'e' package). Anchoring on those without a
    size cap carves a mini-whole-app. A real SDK cluster is ~100-300 classes.
  * Depth guard — a genuine short helper package is shallow (f2/x); a deep hit like
    d/e/a/a/c is a shaded-library substring false positive.
  * Lib denylist — jackson/glide/igaworks/mapps etc. share signatures; skip by name.
  * 4-segment rule — the Goldoson root is consistently com/<a>/<b>/<c>; generalize as
    "for a com/* hit take the first 4 segments" (tune SEGS for other SDKs).
"""
import os, re, sys, subprocess, tempfile, shutil
from collections import defaultdict

CORE  = os.environ.get("CORE_ANCHORS", "getBConfig|getRestEdge|getPdata|putCol")
SCAN  = os.environ.get("SCAN_ANCHOR", "getScanResults")
BOND  = os.environ.get("BOND_ANCHOR", "getBondedDevices")
GUARD = int(os.environ.get("GUARD", "400"))
SEGS  = 4  # Goldoson root depth for com/* clusters

DENY = {
 'com/google','com/fasterxml','com/squareup','com/android','com/facebook','com/bumptech',
 'com/airbnb','com/mapps','com/igaworks','com/mopub','com/applovin','com/unity3d','com/vungle',
 'com/ironsource','com/inmobi','com/kakao','com/naver','com/nhn','com/amazon','com/microsoft',
 'com/adjust','com/appsflyer','com/mixpanel','com/bytedance','com/tnkfactory','com/buzzvil',
 'com/fsn','com/gomtv','com/skplanet','com/jakewharton','io/reactivex','io/grpc',
}

def extract(jar):
    d = tempfile.mkdtemp(prefix="sdkcarve-")
    subprocess.run(["unzip", "-q", jar, "-d", d], check=True)
    return d, True

def all_classes(tree):
    out = []
    for root, _, files in os.walk(tree):
        for f in files:
            if f.endswith(".class"):
                out.append(os.path.relpath(os.path.join(root, f), tree))
    return out

def grep(tree, pattern):
    # -r recursive, -a treat binary as text, -l list files, -E regex
    p = subprocess.run(["grep", "-ralE", pattern, tree],
                       capture_output=True, text=True)
    return [os.path.relpath(l, tree) for l in p.stdout.split("\n") if l.strip()]

def clsize(allcls, prefix):
    p = prefix.rstrip("/") + "/"
    return sum(1 for c in allcls if c.startswith(p))

def root_of(path):
    s = path.split("/")
    if s[0] in ("com", "io", "net", "org") and len(s) >= SEGS:
        return s[0] + "/" + s[1], "/".join(s[:SEGS])
    if len(s) > 3:        # deep non-com hit => shaded-library FP
        return None, None
    return s[0], s[0]     # short, shallow helper package (f2, s5, ...)

def roots_from(allcls, anchors):
    out = set()
    for p in anchors:
        key, root = root_of(p)
        if key is None or key in DENY:
            continue
        sz = clsize(allcls, root)
        if sz == 0 or sz > GUARD:
            continue
        out.add(root)
    return out

def main():
    if len(sys.argv) >= 3 and sys.argv[1] == "--tree":
        tree, tmp = sys.argv[2], False
    elif len(sys.argv) == 2:
        tree, tmp = extract(sys.argv[1])
    else:
        sys.exit(__doc__)
    try:
        allcls = all_classes(tree)
        core = grep(tree, CORE)
        roots = roots_from(allcls, core)
        if not roots:  # method names also obfuscated: structural fallback (scan ∩ bonded)
            sc = roots_from(allcls, grep(tree, SCAN))
            bd = roots_from(allcls, grep(tree, BOND))
            roots = (sc & bd) or sc or bd
        final = [r for r in sorted(roots)
                 if not any(r != o and r.startswith(o + "/") for o in roots)]
        if not final:
            sys.stderr.write("no SDK root found — tune CORE_ANCHORS / SCAN_ANCHOR / BOND_ANCHOR\n")
        for r in final:
            sys.stderr.write(f"# {r}  ({clsize(allcls, r)} classes)\n")
            print(r + "/*")
    finally:
        if tmp:
            shutil.rmtree(tree, ignore_errors=True)

if __name__ == "__main__":
    main()
