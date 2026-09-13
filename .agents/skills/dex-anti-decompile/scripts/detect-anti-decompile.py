#!/usr/bin/env python3
"""detect-anti-decompile.py — find DEX anti-decompilation / anti-tooling constructs.

Two families this catches, both by parsing the DEX directly (no dex2jar — the point is these
BREAK dex2jar, so you can't rely on it to detect them):

  1) METHOD-DESCRIPTOR BOMB (anti-dex2jar / anti-DEX->.class converter)
     A synthetic method whose proto has an absurd parameter count (e.g. 65,530 params,
     shorty "V"+"L"*65530). Legal in DEX (unbounded type_list) but when a converter rebuilds
     the JVM method descriptor "(L..;L..;..)V" it overflows the class-file CONSTANT_Utf8 64KB
     limit -> dex2jar/jadx-to-jar/enjarify throw "UTF8 string too large" and abort. Runs fine
     on ART. Real-world marker seen: class `STLudc`, method `a_stl_d2j_lock` ("d2j lock").

  2) EXCEPTION-TABLE FLATTENING (anti-decompiler)
     A method with hundreds/thousands of tiny try ranges funnelling into a few shared handler
     stubs (+ irreducible flow). Makes CFR/jadx/Vineflower/Fernflower fail. Detected here as
     methods whose code_item tries_size is absurdly high.

The two attack DIFFERENT stages, so they need different detection:
  - the BOMB breaks the DEX->.class CONVERTER and is reliably visible IN THE DEX (this script);
  - FLATTENING breaks the DECOMPILER AFTER conversion and has almost NO dex footprint
    (real case: updateScript had <13 dalvik tries yet 1033 .class exception-table rows) -> it is
    NOT detectable by DEX try-count; confirm it post-conversion (see check-flattening.sh / SKILL.md).

Usage:
  detect-anti-decompile.py <app.apk|app.xapk|classes.dex|dir> [--shorty-max N]
Exit: 0 = no converter-bomb, 2 = bomb/marker found (does NOT rule out decompiler flattening).

Defeat (see SKILL.md): bomb -> jimple2cpg reads DEX directly (Soot, no 64KB limit) / strip the
STLudc class / direct-dex string scan. Flattening -> ExFlattenNormalize.java (--redundant --split
--unify) then CFR.
"""
import sys, os, struct, zipfile, tempfile, glob, argparse

# --- DEX header field offsets (little-endian u32 pairs of size,off) ---
OFF_STRING_IDS = 0x38   # size@0x38 off@0x3c
OFF_TYPE_IDS   = 0x40
OFF_PROTO_IDS  = 0x48   # proto_id_item = shorty_idx(u32), return_type_idx(u32), parameters_off(u32)
OFF_METHOD_IDS = 0x58   # method_id_item = class_idx(u16), proto_idx(u16), name_idx(u32)
OFF_CLASS_DEFS = 0x60   # class_def_item[8 u32]; [6]=class_data_off

def uleb(b, o):
    r = 0; s = 0
    while True:
        x = b[o]; o += 1; r |= (x & 0x7f) << s
        if not x & 0x80: break
        s += 7
    return r, o

class Dex:
    def __init__(self, b):
        self.b = b
        if b[:4] != b'dex\n':
            raise ValueError("not a dex")
        self.sids_sz, self.sids_off = struct.unpack_from('<II', b, OFF_STRING_IDS)
        self.tids_sz, self.tids_off = struct.unpack_from('<II', b, OFF_TYPE_IDS)
        self.pids_sz, self.pids_off = struct.unpack_from('<II', b, OFF_PROTO_IDS)
        self.mids_sz, self.mids_off = struct.unpack_from('<II', b, OFF_METHOD_IDS)
        self.cdefs_sz, self.cdefs_off = struct.unpack_from('<II', b, OFF_CLASS_DEFS)
    def string(self, idx):
        off, = struct.unpack_from('<I', self.b, self.sids_off + idx * 4)
        _, p = uleb(self.b, off)
        e = self.b.index(b'\x00', p)
        return self.b[p:e]
    def type_str(self, tidx):
        sidx, = struct.unpack_from('<I', self.b, self.tids_off + tidx * 4)
        return self.string(sidx)
    def proto(self, i):
        return struct.unpack_from('<III', self.b, self.pids_off + i * 12)  # shorty, ret, params_off
    def method(self, i):
        return struct.unpack_from('<HHI', self.b, self.mids_off + i * 8)   # class_idx, proto_idx, name_idx

def scan_bombs(dx, shorty_max):
    """proto with shorty length > shorty_max => descriptor bomb. Attribute to class.method."""
    bomb_protos = {}
    for i in range(dx.pids_sz):
        sh, ret, poff = dx.proto(i)
        slen = len(dx.string(sh))
        if slen > shorty_max:
            nparam = 0
            if poff:
                try: nparam, = struct.unpack_from('<I', dx.b, poff)
                except Exception: nparam = -1
            bomb_protos[i] = (slen, nparam)
    hits = []
    if bomb_protos:
        for m in range(dx.mids_sz):
            cidx, pidx, nidx = dx.method(m)
            if pidx in bomb_protos:
                slen, npar = bomb_protos[pidx]
                hits.append((dx.type_str(cidx).decode('latin1'),
                             dx.string(nidx).decode('latin1'), slen, npar))
        if not hits:  # dangling bomb proto not referenced by a real method
            for pidx, (slen, npar) in bomb_protos.items():
                hits.append(("<unreferenced-proto>", f"proto#{pidx}", slen, npar))
    return hits

def iter_dexes(path):
    """yield (label, bytes) for every classes*.dex reachable from path (dex / apk / xapk / dir)."""
    if os.path.isdir(path):
        for f in glob.glob(os.path.join(path, '**', '*.dex'), recursive=True):
            yield f, open(f, 'rb').read()
        return
    if path.endswith('.dex'):
        yield path, open(path, 'rb').read(); return
    # zip container (apk/xapk/apks/zip)
    try:
        z = zipfile.ZipFile(path)
    except Exception:
        yield path, open(path, 'rb').read(); return
    inner_apks = [n for n in z.namelist() if n.endswith('.apk') and 'config.' not in n and not n.startswith('split_')]
    if inner_apks:  # xapk/apks -> pick the base apk(s)
        for ia in inner_apks:
            tmp = tempfile.mkdtemp()
            p = os.path.join(tmp, os.path.basename(ia)); open(p, 'wb').write(z.read(ia))
            yield from iter_dexes(p)
        return
    for n in z.namelist():
        if n.endswith('.dex'):
            yield f"{os.path.basename(path)}!{n}", z.read(n)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target")
    ap.add_argument("--shorty-max", type=int, default=1000, help="proto shorty len > this = bomb (real methods are tiny)")
    a = ap.parse_args()
    MARKERS = (b'a_stl_d2j_lock', b'STLudc', b'_d2j_lock', b'anti_d2j')
    any_hit = False
    for label, data in iter_dexes(a.target):
        try:
            dx = Dex(data)
        except Exception as e:
            print(f"[skip] {label}: {e}"); continue
        bombs = scan_bombs(dx, a.shorty_max)
        marks = sorted({m.decode() for m in MARKERS if m in data})
        if bombs or marks:
            any_hit = True
            print(f"\n### {label}")
            for cls, name, slen, npar in bombs:
                print(f"  [BOMB] descriptor bomb: {cls}.{name}  shorty_len={slen} params={npar} "
                      f"-> breaks DEX->.class converters (dex2jar/jadx-jar/enjarify)")
            if marks:
                print(f"  [MARK] anti-dex2jar name markers: {', '.join(marks)}")
    if any_hit:
        print("\nVERDICT: converter-breaking DEX bomb present.")
        print("  defeat -> carve via jimple2cpg (reads DEX directly, no 64KB limit), or strip the bomb class,")
        print("            or a direct-dex string scan for SDK-root presence.")
        sys.exit(2)
    print("no converter-breaking bomb found.")
    print("NOTE: this does NOT rule out decompiler-level flattening (irreducible flow / exception-table blow-up),")
    print("      which has ~no DEX footprint. Confirm that post-conversion: after dex2jar, a method where")
    print("      `javap -c` shows hundreds+ exception-table rows AND every decompiler fails = flattening.")
    print("      Defeat -> ExFlattenNormalize.java (--redundant --split --unify) then CFR.")
    sys.exit(0)

if __name__ == "__main__":
    main()
