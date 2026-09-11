#!/usr/bin/env python3
"""xShield app string-vault table brute-force decryptor (2026-09-10).

Companion to analysis/PAYLOAD_LOADER_REVERSAL.md UPDATE 2026-09-10 (완결).

Pipeline:
  1. Run tools/unidbg_DxShieldTest.java (unidbg) -> d() returns 13 fields,
     loader installs the bulk vault table at 0x12880000 in emulated memory.
  2. Harness dumps it to app-string-vault-table.bin (1.25MB).
  3. This script decrypts (len,body) at EVERY byte offset with the vault
     decryptor fcn_1eca0 emulated via unicorn:
       length: seeds (DAT_73728, DAT_7372c, DAT_73730)
       body:   REVERSED seed order
       key   = offset of the length field
  4. Output: TSV  offset<TAB>escaped-string  (raw, overlapping hits included).

Usage: python3 vault_table_bruteforce.py
  edit TBL / S1,S2,S3 (session seeds from the [SEEDS] log lines) as needed.
"""
import struct, sys
from unicorn import *
from unicorn.arm64_const import *

SO = sys.argv[1] if len(sys.argv) > 1 else "libdxbase.so"      # usage: vault_table_bruteforce.py <so> <table.bin> [dec_addr]
TBL = sys.argv[2] if len(sys.argv) > 2 else "vault-table.bin"
TBL_ADDR = 0x12880000
DEC = int(sys.argv[3], 0) if len(sys.argv) > 3 else 0x1eca0
STOP = 0x900000
S1, S2, S3 = 0x8bcfa8c8, 0xe40b1d05, 0x76d4f75c   # length decrypt order
C1, C2, C3 = 0x76d4f75c, 0xe40b1d05, 0x8bcfa8c8   # content decrypt order (reversed)

data = open(SO, "rb").read()
tbl = bytearray(open(TBL, "rb").read())

e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
e_phentsize = struct.unpack_from("<H", data, 0x36)[0]
e_phnum = struct.unpack_from("<H", data, 0x38)[0]
segs = []
for i in range(e_phnum):
    off = e_phoff + i * e_phentsize
    p_type, = struct.unpack_from("<I", data, off)
    p_offset, p_vaddr, _, p_filesz, p_memsz = struct.unpack_from("<QQQQQ", data, off + 8)
    if p_type == 1:
        segs.append((p_vaddr, p_filesz, p_memsz, p_offset))

PAGE = 0x1000
al = lambda x: x & ~(PAGE - 1)

mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
for va, fsz, msz, off in segs:
    if not msz: continue
    base = al(va); end = (va + msz + PAGE - 1) & ~(PAGE - 1)
    try: mu.mem_map(base, end - base)
    except Exception: pass
    mu.mem_write(va, data[off:off + fsz])
# table mapping (4KB-aligned chunks)
tbl_size = len(tbl)
mu.mem_map(TBL_ADDR, (tbl_size + PAGE - 1) & ~(PAGE - 1))
mu.mem_write(TBL_ADDR, bytes(tbl))
mu.mem_map(0x400000, 0x40000); mu.reg_write(UC_ARM64_REG_SP, 0x420000)
T = 0x600000; mu.mem_map(T, 0x1000); mu.mem_write(T + 0x28, b'\x11' * 8)
mu.reg_write(UC_ARM64_REG_TPIDR_EL0, T)
mu.hook_add(UC_HOOK_MEM_UNMAPPED, lambda uc, a, ad, sz, v, u: (uc.mem_map(al(ad), PAGE), True)[1])

def decrypt_inplace(buf_addr, length, key, seeds=None):
    s1, s2, s3 = seeds if seeds else (S1, S2, S3)
    for r, v in [(UC_ARM64_REG_X0, s1), (UC_ARM64_REG_X1, s2), (UC_ARM64_REG_X2, s3),
                 (UC_ARM64_REG_X3, buf_addr), (UC_ARM64_REG_X4, length), (UC_ARM64_REG_X5, key),
                 (UC_ARM64_REG_LR, STOP)]:
        mu.reg_write(r, v)
    mu.emu_start(DEC, STOP, count=3_000_000)
    return bytes(mu.mem_read(buf_addr, length))

hits = open('/tmp/xsh_vault_strings.txt', 'w', encoding='utf-8', errors='replace')
total = len(tbl) - 2
try:
    for off in range(0, total):
        orig2 = bytes(tbl[off:off+2])
        addr = TBL_ADDR + off
        mu.mem_write(addr, orig2)
        try:
            pl = decrypt_inplace(addr, 2, off)
            (ln,) = struct.unpack("<H", pl)
        except UcError:
            mu.mem_write(addr, orig2)
            continue
        mu.mem_write(addr, orig2)
        if 1 <= ln <= 2000 and off + 2 + ln <= len(tbl):
            orig_n = bytes(tbl[off+2:off+2+ln])
            mu.mem_write(addr + 2, orig_n)
            try:
                s = decrypt_inplace(addr + 2, ln, off, seeds=(C1, C2, C3))
            except UcError:
                mu.mem_write(addr + 2, orig_n)
                continue
            mu.mem_write(addr + 2, orig_n)
            # accept ASCII-printable OR valid UTF-8 text (Korean etc.)
            try:
                dec = s.decode('utf-8')
                ok = sum(1 for c in dec if c.isprintable() or c in '\n\r\t') >= len(dec) * 0.9 and len(dec) > 0
            except UnicodeDecodeError:
                printable = sum(1 for b in s if 32 <= b < 127 or b in (9, 10, 13))
                ok = printable >= ln * 0.9
            if ok:
                try:
                    txt = s.decode('utf-8')
                except UnicodeDecodeError:
                    txt = s.decode('latin-1')
                esc = txt.replace('\\', '\\\\').replace('\n', '\\n').replace('\r', '\\r').replace('\t', '\\t')
                hits.write(f"{off}\t{esc}\n")
                hits.flush()
        if off % 100000 == 0:
            print(f"... {off}/{total}", flush=True)
finally:
    hits.close()
print("DONE")
