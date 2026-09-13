#!/usr/bin/env python3
"""appshield_unpack.py — Phase 2 of the APKSHIELD static unpack.

Given the AES keys extracted by AppShieldKeyExtract.java (unidbg) + the hardcoded IV (from Native.b), brute
keys x {CBC(hardcoded IV), CBC(zero IV), ECB} on assets/asorg, find the one that yields a ZIP (PK\\x03\\x04),
decrypt the whole payload, strip PKCS7, and unzip the real classes*.dex.

The white-box only guards key derivation; asorg itself is ordinary AES-128-CBC — so this is fast, offline.

Usage:
  appshield_unpack.py --asorg <assets/asorg> --iv <32hex> --keys <hex,hex,...> [--out <dir>]
  (keys = the callMethod("K",n) values from the unidbg harness; iv = the literal in Native.b's IvParameterSpec)

No device, no Frida. Recovered dexes stay local; never commit them.
"""
import argparse, sys, zipfile, io, os
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError:
    sys.exit("pip install cryptography")

ZIP = b"PK\x03\x04"; DEX = b"dex\n"

def dec(data, key, mode):
    d = Cipher(algorithms.AES(key), mode).decryptor()
    return d.update(data) + d.finalize()

def try_head(data, key, mode):
    return dec(data[:64], key, mode)[:4]

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--asorg", required=True)
    ap.add_argument("--iv", required=True, help="hardcoded IV, 32 hex (from Native.b IvParameterSpec)")
    ap.add_argument("--keys", required=True, help="comma-separated hex keys from callMethod('K',n)")
    ap.add_argument("--out", default="real")
    a = ap.parse_args()
    data = open(a.asorg, "rb").read()
    iv = bytes.fromhex(a.iv); iv0 = b"\0"*16
    keys = [bytes.fromhex(k.strip()) for k in a.keys.split(",") if k.strip()]
    cand_modes = lambda: [("CBC-hardcoded", modes.CBC(iv)), ("CBC-zero", modes.CBC(iv0)), ("ECB", modes.ECB())]

    hit = None
    for ki, key in enumerate(keys):
        for mn, mode in cand_modes():
            h = try_head(data, key, mode)
            tag = "ZIP" if h == ZIP else ("DEX" if h == DEX else "")
            print(f"  key[{ki}] {mn:14} head={h.hex()} {tag}")
            if tag and hit is None:
                hit = (ki, key, mn, mode, tag)
    if not hit:
        sys.exit("[!] no key/mode produced a ZIP/DEX header — re-check keys/IV, or bulk may be white-box (rare).")

    ki, key, mn, mode, tag = hit
    print(f"[+] payload cipher: key[{ki}] {mn} -> {tag}")
    pt = dec(data, key, mode)
    if pt and 1 <= pt[-1] <= 16 and pt[-pt[-1]:] == bytes([pt[-1]])*pt[-1]:
        pt = pt[:-pt[-1]]  # strip PKCS7
    os.makedirs(a.out, exist_ok=True)
    if tag == "ZIP":
        zf = zipfile.ZipFile(io.BytesIO(pt))
        dexes = [n for n in zf.namelist() if n.endswith(".dex")]
        zf.extractall(a.out)
        print(f"[+] unzipped {len(zf.namelist())} entries ({len(dexes)} dex) -> {a.out}/")
    else:  # single DEX
        open(os.path.join(a.out, "classes.dex"), "wb").write(pt)
        print(f"[+] wrote {a.out}/classes.dex ({len(pt)} bytes)")
    print("[next] fingerprint the recovered dexes (sdk-carve coocon-fingerprint.sh / class-map.py).")

if __name__ == "__main__":
    main()
