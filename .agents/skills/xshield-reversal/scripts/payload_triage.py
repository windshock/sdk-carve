#!/usr/bin/env python3
"""xshield-reversal Phase 0 — payload-asset triage (no decryption needed).

xShield stores the app's real code in a hash-named asset `assets/.<hex>.dex` = a MIXED container
(stub dex + header copy + LCG-encrypted section(s) + PLAINTEXT manifest + OTL). The plaintext manifest
alone yields the supply-chain inventory WITHOUT decrypting anything: engine version, packing system,
the FxShield management server, policys, and the hidden class-map (obfuscated-id -> real class name),
whose distinct package roots ARE the bundled SDK/library inventory.

usage: payload_triage.py <apk-or-xapk-or-dir>   (auto-finds the .<hex>.dex payload asset)
"""
import sys, os, re, math, zipfile, collections, glob

def entropy(b):
    if not b: return 0.0
    c = collections.Counter(b); n = len(b)
    return -sum(v/n*math.log2(v/n) for v in c.values())

def find_asset(path):
    """Return the payload-asset bytes from an apk/xapk/dir; auto-picks the largest .<hex>.dex."""
    apks = []
    if os.path.isdir(path):
        apks = glob.glob(os.path.join(path, '**', '*.apk'), recursive=True)
    elif path.endswith('.xapk') or path.endswith('.apks') or path.endswith('.apk') or path.endswith('.zip'):
        # xapk = zip of apks; recurse one level
        z = zipfile.ZipFile(path)
        inner = [n for n in z.namelist() if n.endswith('.apk')]
        if inner:  # xapk bundle
            import tempfile
            td = tempfile.mkdtemp(prefix='xshtri-')
            for n in inner: z.extract(n, td)
            apks = glob.glob(os.path.join(td, '**', '*.apk'), recursive=True)
        else:
            apks = [path]
    best = None
    for a in apks:
        try:
            za = zipfile.ZipFile(a)
        except Exception:
            continue
        for n in za.namelist():
            if re.match(r'assets/\.?[0-9a-f]{16,}\.dex$', n):
                sz = za.getinfo(n).file_size
                if not best or sz > best[2]:
                    best = (a, n, sz, za.read(n))
    return best

def main():
    if len(sys.argv) < 2:
        print(__doc__); sys.exit(2)
    r = find_asset(sys.argv[1])
    if not r:
        print("no xShield payload asset (assets/.<hex>.dex) found"); sys.exit(1)
    apk, name, sz, d = r
    print(f"=== {os.path.basename(sys.argv[1])} ===")
    print(f"payload asset: {name}  ({sz} B, in {os.path.basename(apk)})  whole-entropy {entropy(d):.2f}")

    # plaintext manifest fields (no decryption)
    def field(pat):
        m = re.search(pat, d)
        if not m: return None
        seg = d[m.start():m.start()+120]
        return ''.join(chr(c) if 32 <= c < 127 else '.' for c in seg)
    for label, pat in [("engine", rb'engine_version=[0-9.]+'), ("packing", rb'packing_system=\w+'),
                       ("policys", rb'policys=[0-9a-fx,]+'), ("fxshield-server", rb'[a-z0-9.]*fxshield[a-z0-9./]*'),
                       ("stamp", rb'system_time=[0-9: -]+')]:
        v = field(pat)
        if v: print(f"  {label:<16}: {v.rstrip('.')}")

    # hidden class-map -> distinct SDK/library package roots (the supply-chain inventory)
    roots = collections.Counter()
    for m in re.finditer(rb'L([a-z][a-z0-9]+(?:/[a-z0-9_]+){1,2})/', d):
        roots[m.group(1).decode()] += 1
    total_cls = len(re.findall(rb'0x[0-9a-f]{8}=L', d))
    print(f"\n  hidden class-map: ~{total_cls} classes; top package roots (bundled SDKs/libs):")
    # flag notable capability libs
    NOTABLE = {'mozilla/javascript': 'Rhino JS engine (server-script surface!)', 'bsh': 'BeanShell (RCE-by-design)',
               'signkorea': 'SignKorea PKI', 'yettiesoft': 'Yettiesoft crypto/PKI', 'adbrix': 'AdBrix attribution',
               'igaworks': 'IGAWorks adtech', 'nshc': 'NSHC (shielder vendor)', 'fairytech': 'Fairytech Moment',
               'adjoe': 'adjoe reward', 'ironsource': 'IronSource', 'tnkfactory': 'TNK offerwall', 'adison': 'Adison offerwall'}
    for rt, c in roots.most_common(25):
        tag = ''
        for k, v in NOTABLE.items():
            if k in rt: tag = '  <<< ' + v; break
        print(f"    {c:>5}  {rt}{tag}")

if __name__ == '__main__':
    main()
