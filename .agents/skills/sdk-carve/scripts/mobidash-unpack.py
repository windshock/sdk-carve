#!/usr/bin/env python3
"""sdk-carve pre-carve (payload stage, MobiDash family) — statically recover MobiDash's
hidden fraud engine from its SQLCipher-encrypted payload. Worked reference for a
multi-layer payload stage (cf. konfety-unpack.py for the single-layer case).

Chain (all static, no runtime):
  APK signing cert --hashCode^const--> SQLCipher passphrase
  assets/jdhcc.db  --SQLCipher(pass)--> table cmnFdTEbL: row1 = bootstrap DEX, rows = XOR'd module jars
  module blob      --XOR(first 10 bytes as key, skip next 8, 64KB-chunked)--> real .jar

Key derivation (loader com...jdhcc.mHwymQ):
  i = 1; for b in cert_der: i = i*31 + b            # Java hashCode over signatures[0].toByteArray()
  passphrase = str( XOR_CONST ^ i )                  # int32, decimal

Requires: `sqlcipher` CLI (brew install sqlcipher) for the DB step; openssl for the cert.
Per-sample constants (XOR_CONST, table/column, db name) come from the loader — defaults match
the analysed sample (c64db66f…). Generic ZIP-tamper fixes are in apk-normalize.py.

usage: mobidash-unpack.py <apk> <out-dir> [--xor-const N] [--db assets/jdhcc.db]
"""
import argparse, os, struct, subprocess, sys, zipfile

def i32(x): return ((x + 0x80000000) & 0xFFFFFFFF) - 0x80000000

def cert_der(apk):
    with zipfile.ZipFile(apk) as z:
        sig = [n for n in z.namelist() if n.upper().startswith("META-INF/") and n.upper().endswith((".RSA", ".EC", ".DSA"))][0]
        pkcs7 = z.read(sig)
    pem = subprocess.run(["openssl", "pkcs7", "-inform", "DER", "-print_certs", "-outform", "PEM"],
                         input=pkcs7, capture_output=True).stdout
    return subprocess.run(["openssl", "x509", "-outform", "DER"], input=pem, capture_output=True).stdout

def passphrase(der, const):
    i = 1
    for b in der:
        i = i32(i * 31 + (b - 256 if b >= 128 else b))
    return str(i32(const ^ i))

def xor_module(blob):                 # key = first 10 bytes, skip next 8, XOR rest in 64KB chunks
    key, body, out = blob[:10], blob[18:], bytearray()
    for off in range(0, len(body), 65536):
        ch = body[off:off + 65536]
        out += bytes(ch[i] ^ key[i % 10] for i in range(len(ch)))
    return bytes(out)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("apk"); ap.add_argument("outdir")
    ap.add_argument("--xor-const", type=int, default=1682213662)
    ap.add_argument("--db", default="assets/jdhcc.db")
    ap.add_argument("--table", default="cmnFdTEbL"); ap.add_argument("--col", default="YhpeCqtoN")
    a = ap.parse_args()
    os.makedirs(a.outdir, exist_ok=True)
    pw = passphrase(cert_der(a.apk), a.xor_const)
    print("SQLCipher passphrase:", pw)
    dbp = os.path.join(a.outdir, "jdhcc.db")
    with zipfile.ZipFile(a.apk) as z: open(dbp, "wb").write(z.read(a.db))
    sql = f"PRAGMA key='{pw}';\n.mode list\nSELECT rowid||'|'||quote({a.col}) FROM {a.table};\n"
    out = subprocess.run(["sqlcipher", dbp], input=sql, capture_output=True, text=True).stdout
    n = 0
    for line in out.splitlines():
        if "|X'" not in line: continue
        rid, hexlit = line.split("|", 1)
        blob = bytes.fromhex(hexlit.strip()[2:-1])
        if blob[:4] == b"dex\n":
            open(os.path.join(a.outdir, f"bootstrap_row{rid}.dex"), "wb").write(blob)
        else:
            jar = xor_module(blob)
            open(os.path.join(a.outdir, f"module_row{rid}.jar"), "wb").write(jar)
        n += 1
    print(f"recovered {n} blobs -> {a.outdir} (bootstrap dex + XOR-decrypted module jars)")

if __name__ == "__main__":
    if len(sys.argv) < 3: sys.exit(__doc__)
    main()
