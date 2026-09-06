#!/usr/bin/env python3
# Recover the AES-encrypted Goldoson anti-analysis packet-capture blocklist from a carved SDK or
# whole-app jar. Extracts base64-ish string constants, tries the shared Goldoson key
# (AES-256/CBC/PKCS5, zero IV), and prints any that decrypt to a plausible package name.
# This is a CARVE-INDEPENDENT lineage/behaviour anchor: the same key+ciphertext+blocklist recur
# byte-identically across the Goldoson family (see docs/ANTI_ANALYSIS.md). Ships in-repo so the
# scope-validation results reproduce; the APK/JAR inputs are NOT redistributed.
#   usage: decrypt_goldoson_blocklist.py <app-or-scoped.jar>
import base64, os, re, shutil, subprocess, sys, tempfile
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

KEY = b"aoKoVu#aiSkjwicO!@)(%^Zdh18zr!Oz"
IV  = b"\x00" * 16
B64 = re.compile(rb"[A-Za-z0-9+/]{16,}={0,2}")

def try_decrypt(tok: bytes):
    if len(tok) % 4:
        return None
    try:
        ct = base64.b64decode(tok, validate=True)
    except Exception:
        return None
    if not ct or len(ct) % 16:
        return None
    try:
        d = Cipher(algorithms.AES(KEY), modes.CBC(IV)).decryptor()
        pt = d.update(ct) + d.finalize()
        pad = pt[-1]
        if not (1 <= pad <= 16) or pt[-pad:] != bytes([pad]) * pad:
            return None
        s = pt[:-pad].decode("utf-8")
    except Exception:
        return None
    if len(s) >= 6 and "." in s and all(32 <= ord(c) < 127 for c in s):
        return s
    return None

def main(jar):
    d = tempfile.mkdtemp()
    subprocess.run(["unzip", "-q", jar, "-d", d], check=False)
    toks = set()
    for root, _, files in os.walk(d):
        for f in files:
            with open(os.path.join(root, f), "rb") as fh:
                for m in B64.findall(fh.read()):
                    toks.add(m)
    shutil.rmtree(d, ignore_errors=True)
    for h in sorted({r for t in toks if (r := try_decrypt(t))}):
        print(h)

if __name__ == "__main__":
    main(sys.argv[1])
