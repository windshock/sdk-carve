#!/usr/bin/env python3
"""sdk-carve pre-carve (payload stage) — recover the hidden second-stage DEX from a
Konfety/CaramelAds APK's packed asset. Worked reference for the *payload-discovery* stage
that follows apk-normalize.py (which flags the packed asset).

Chain (all static, no runtime):
  packed asset  --inflate-->  XOR java.util.Random(seed).nextBytes()  --> inner ZIP --> classes.dex

The XOR keystream is `java.util.Random(seed)`, and across the analysed corpus the seed is
simply **numeric_asset_name + 0xFFFF** (default; verified on 5/5 samples). If a variant
differs, recover `new Random(<seed>)` from the decompiled loader (`svmmk/.../GCw`) and pass
--seed. Generic ZIP-tamper fixes are in apk-normalize.py; this is the family-specific
decrypt kept as a reference for how the payload stage plugs in.

usage: konfety-unpack.py <apk> <out-dir> [--seed N] [--asset assets/NAME]
"""
import struct, sys, zlib, os, argparse, zipfile

class JRandom:                                   # faithful java.util.Random
    M = (1 << 48) - 1
    def __init__(s, seed): s.s = (seed ^ 0x5DEECE66D) & s.M
    def _n(s):
        s.s = (s.s * 0x5DEECE66D + 0xB) & s.M; r = s.s >> 16
        return r - (1 << 32) if r >= (1 << 31) else r
    def nextBytes(s, n):
        o = bytearray(n); i = 0
        while i < n:
            r = s._n()
            for _ in range(min(n - i, 4)): o[i] = r & 0xff; r >>= 8; i += 1
        return bytes(o)

def inflate_asset(d, want):
    i = d.rfind(b"PK\x05\x06"); n = struct.unpack("<H", d[i+10:i+12])[0]; p = struct.unpack("<I", d[i+16:i+20])[0]
    for _ in range(n):
        nlen, elen, clen = struct.unpack("<HHH", d[p+28:p+34]); off = struct.unpack("<I", d[p+42:p+46])[0]
        nm = d[p+46:p+46+nlen].decode("latin-1"); usize = struct.unpack("<I", d[p+24:p+28])[0]
        hit = (nm == want) if want else (nm.startswith("assets/") and usize > 200000 and "/" not in nm[len("assets/"):])
        if hit:
            lnlen, lelen = struct.unpack("<HH", d[off+26:off+30]); ds = off + 30 + lnlen + lelen
            csize = struct.unpack("<I", d[off+18:off+22])[0]
            return nm, zlib.decompressobj(-15).decompress(d[ds:ds+csize])   # fake enc flag ignored
        p += 46 + nlen + elen + clen
    sys.exit("packed asset not found (try --asset)")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("apk"); ap.add_argument("outdir")
    ap.add_argument("--seed", type=int, default=None, help="override; default = asset_name + 0xFFFF")
    ap.add_argument("--asset", default=None)
    a = ap.parse_args()
    d = open(a.apk, "rb").read()
    name, blob = inflate_asset(d, a.asset)
    seed = a.seed if a.seed is not None else int(name.split("/")[1]) + 0xFFFF
    dec = bytes(x ^ y for x, y in zip(blob, JRandom(seed).nextBytes(len(blob))))
    os.makedirs(a.outdir, exist_ok=True)
    zp = os.path.join(a.outdir, "payload.zip"); open(zp, "wb").write(dec)
    if dec[:2] != b"PK": sys.exit(f"decrypt did not yield a ZIP (first4={dec[:4].hex()}) — wrong --seed?")
    with zipfile.ZipFile(zp) as z:
        z.extractall(a.outdir); names = z.namelist()
    print(f"asset={name} -> inner ZIP {names} -> {a.outdir}")

if __name__ == "__main__":
    main()
