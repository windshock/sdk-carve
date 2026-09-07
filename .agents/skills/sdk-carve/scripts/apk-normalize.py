#!/usr/bin/env python3
"""sdk-carve pre-carve — normalize a malformed/evasive APK so the standard bytecode pipeline
(aapt / apktool / dex2jar / jadx) can read it, and flag hidden payloads.

This is the *container-normalization / payload-discovery* stage that belongs BEFORE bytecode
discovery. Some packers (Konfety, SoumniBot, …) tamper the ZIP so Android still installs the
app but static tools choke. Fixes, generically (not family-specific):

  - **fake ZIP 'encrypted' flag** — General Purpose bit 0 set on entries that aren't encrypted
    (blocks unzip/7z). Cleared.
  - **bogus compression method** — e.g. AndroidManifest declared BZIP2 (0x0C) over data that is
    actually STORED AXML, or DEFLATE mislabelled. Re-derived from the bytes.
  - **csize lies** — the real data span is taken from neighbouring local-header offsets, not the
    (lying) size fields.

Every entry is rebuilt as STORE(0) with correct sizes into a clean ZIP that any tool parses.
Reports anomalies (tamper flags, decoy classes.dex, high-entropy assets = likely packed payload).

usage: apk-normalize.py <in.apk> <out.apk>
"""
import struct, sys, zlib, math, collections

u16 = lambda b, o: struct.unpack_from("<H", b, o)[0]
u32 = lambda b, o: struct.unpack_from("<I", b, o)[0]

def entropy(b):
    if not b: return 0.0
    n = len(b); c = collections.Counter(b)
    return -sum(v / n * math.log2(v / n) for v in c.values())

def parse(d):
    i = d.rfind(b"PK\x05\x06")
    n = u16(d, i + 10); cdoff = u32(d, i + 16)
    ents = []; p = cdoff
    for _ in range(n):
        if d[p:p+4] != b"PK\x01\x02": break
        nlen, elen, clen = u16(d, p+28), u16(d, p+30), u16(d, p+32)
        ents.append(dict(gp=u16(d,p+8), method=u16(d,p+10), csize=u32(d,p+20),
                         usize=u32(d,p+24), lfhoff=u32(d,p+42), name=d[p+46:p+46+nlen]))
        p += 46 + nlen + elen + clen
    order = sorted(range(len(ents)), key=lambda k: ents[k]["lfhoff"])
    for idx, k in enumerate(order):
        e = ents[k]; off = e["lfhoff"]
        ds = off + 30 + u16(d, off+26) + u16(d, off+28)
        nxt = ents[order[idx+1]]["lfhoff"] if idx+1 < len(order) else i
        e["ds"], e["true_len"] = ds, nxt - ds
    return ents

def real_data(d, e):
    data = d[e["ds"]:e["ds"] + e["true_len"]]
    try:                                        # DEFLATE (honest or mislabelled)
        r = zlib.decompressobj(-15).decompress(data)
        if r: return r
    except Exception:
        pass
    return data[:e["usize"]] if 0 < e["usize"] <= len(data) else data  # STORED

def build(entries):
    out = bytearray(); cd = bytearray()
    for name, data in entries:
        crc = zlib.crc32(data) & 0xffffffff; off = len(out)
        out += b"PK\x03\x04" + struct.pack("<HHHHHIIIHH", 20,0,0,0,0, crc, len(data), len(data), len(name), 0) + name + data
        cd += b"PK\x01\x02" + struct.pack("<HHHHHHIIIHHHHHII", 20,20,0,0,0,0, crc, len(data), len(data), len(name), 0,0,0,0,0, off) + name
    cdoff = len(out); out += cd
    out += b"PK\x05\x06" + struct.pack("<HHHHIIH", 0,0, len(entries), len(entries), len(cd), cdoff, 0)
    return bytes(out)

def main(inp, outp):
    d = open(inp, "rb").read(); ents = parse(d)
    rebuilt, anom = [], []
    for e in ents:
        nm = e["name"].decode("latin-1", "replace")
        if e["gp"] & 1: anom.append(("fake-enc-flag", nm))
        if e["method"] not in (0, 8): anom.append((f"bogus-method-0x{e['method']:02x}", nm))
        if e["method"] != 8 and e["csize"] != e["true_len"]: anom.append(("csize-lie", nm))
        data = real_data(d, e); rebuilt.append((e["name"], data))
        if nm == "classes.dex" and len(data) < 20000: anom.append(("decoy-classes.dex", f"{len(data)}B"))
        if nm.startswith("assets/") and len(data) > 200000 and entropy(data[:65536]) > 7.5:
            anom.append(("packed-asset?", f"{nm} {len(data)}B ent={entropy(data[:65536]):.2f}"))
    open(outp, "wb").write(build(rebuilt))
    print(f"normalized {len(ents)} entries -> {outp}")
    counts = collections.Counter(a for a, _ in anom)
    print("ANOMALIES:")
    for a in sorted(counts):
        detail = [x for k, x in anom if k == a]
        if counts[a] > 4 and a == "fake-enc-flag":
            print(f"  {a:26} x{counts[a]} (all entries — classic fake-encryption tamper)")
        else:
            print(f"  {a:26} {'; '.join(detail)}")

if __name__ == "__main__":
    if len(sys.argv) != 3: sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2])
