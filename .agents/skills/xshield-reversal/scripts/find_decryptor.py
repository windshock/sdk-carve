#!/usr/bin/env python3
"""xshield-reversal — auto-locate the string decryptor in ANY libdxbase build and dump the vault.

The decrypt function's ADDRESS changes per xShield build (OK Cashbag 0x1eca0, PASS by SKT 0x5c78),
but its ABI + seed constants are STABLE:  fcn(s1=0x86817231, s2=0x86817231, s3=0x11300316, buf, len, key)
with the MBA magic 0x914dbacf (built as `mov #0x914d; movk #0xbacf,lsl16` — an immediate, NOT a data
constant, so byte-grep misses it). This tool finds the decryptor by locating `bl` sites whose preceding
instructions load the seed constant 0x86817231, takes the most-called such target as the decryptor, then
Unicorn-emulates it over every call site (stubbing the memset PLT) to recover the RASP string vault
statically — no device, no Frida, no hardcoded address.

usage: find_decryptor.py <libdxbase.so>
requires: pip install --break-system-packages unicorn capstone lief   (into the running interpreter)
"""
import sys, collections
import lief
from unicorn import *
from unicorn.arm64_const import *
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_OP_IMM, ARM64_OP_REG

S1 = 0x86817231; S3 = 0x11300316          # stable xShield string-decryptor seeds
SO = sys.argv[1] if len(sys.argv) > 1 else "libdxbase.so"
b = lief.parse(SO)
txt = [s for s in b.sections if s.name == '.text'][0]
code = bytes(txt.content); tva = txt.virtual_address
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN); md.detail = True
insns = list(md.disasm(code, tva))

def reg_at(i, span=24):
    """cheap backward reg reconstruction (adrp/add/mov/movk) over `span` insns before index i."""
    reg = {}
    for j in range(max(0, i - span), i):
        ins = insns[j]; ops = ins.operands; m = ins.mnemonic
        try:
            if m == 'adrp': reg[ins.reg_name(ops[0].reg)] = ops[1].imm
            elif m == 'add' and len(ops) == 3 and ops[2].type == ARM64_OP_IMM and ins.reg_name(ops[1].reg) in reg:
                reg[ins.reg_name(ops[0].reg)] = reg[ins.reg_name(ops[1].reg)] + ops[2].imm
            elif m == 'mov' and len(ops) == 2 and ops[1].type == ARM64_OP_IMM:
                reg[ins.reg_name(ops[0].reg)] = ops[1].imm
            elif m == 'movk' and len(ops) == 2 and ops[1].type == ARM64_OP_IMM:
                rd = ins.reg_name(ops[0].reg); reg[rd] = reg.get(rd, 0) | (ops[1].imm << 16)
        except Exception:
            pass
    return reg

# 1) find the decryptor: bl targets whose call site sets a register == S1 (0x86817231)
cand = collections.Counter()
for i, ins in enumerate(insns):
    if ins.mnemonic == 'bl' and ins.operands and ins.operands[0].type == ARM64_OP_IMM:
        reg = reg_at(i, 30)
        if S1 in reg.values():
            cand[ins.operands[0].imm] += 1
if not cand:
    print("no decryptor found (seed 0x86817231 not observed at any call site)"); sys.exit(1)
DEC = cand.most_common(1)[0][0]
print(f"[+] string decryptor @ 0x{DEC:x}  ({cand[DEC]} seed-bearing call sites)  "
      f"[other candidates: {[hex(a) for a,_ in cand.most_common()[1:4]]}]")

# 2) map the .so into Unicorn + stub memset (first bl inside DEC, or any PLT it calls)
PAGE = 0x1000; al = lambda x: x & ~(PAGE - 1)
mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM); SEGS = []
for seg in b.segments:
    if 'LOAD' not in str(seg.type) or not seg.virtual_size: continue
    base = al(seg.virtual_address); end = (seg.virtual_address + seg.virtual_size + PAGE - 1) & ~(PAGE - 1)
    try: mu.mem_map(base, end - base)
    except Exception: pass
    mu.mem_write(seg.virtual_address, bytes(seg.content)); SEGS.append((seg.virtual_address, bytes(seg.content)))
mu.mem_map(0x70000000, 0x100000); mu.mem_map(0x60000000, 0x4000); RET = 0x50000000
# identify the memset PLT that DEC calls (first bl target inside DEC's body)
memset_plt = None
off = DEC - tva
for ins in md.disasm(code[off:off + 400], DEC):
    if ins.mnemonic == 'ret': break
    if ins.mnemonic == 'bl' and ins.operands and ins.operands[0].type == ARM64_OP_IMM:
        memset_plt = ins.operands[0].imm; break
def cb(uc, addr, size, ud):
    if addr == memset_plt:
        x0 = uc.reg_read(UC_ARM64_REG_X0); x1 = uc.reg_read(UC_ARM64_REG_X1) & 0xff; x2 = uc.reg_read(UC_ARM64_REG_X2)
        try: uc.mem_write(x0, bytes([x1]) * min(x2, 0x400))
        except Exception: pass
        uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_LR))
if memset_plt: mu.hook_add(UC_HOOK_CODE, cb, begin=memset_plt, end=memset_plt)

def orig(buf, ln):
    for va, c in SEGS:
        if va <= buf < va + len(c): return c[buf - va: buf - va + ln]
    return None
def decrypt(buf, ln, key):
    ct = orig(buf, ln)
    if ct is None: return None
    mu.mem_write(buf, ct)
    for r, v in [(UC_ARM64_REG_X0, S1), (UC_ARM64_REG_X1, S1), (UC_ARM64_REG_X2, S3),
                 (UC_ARM64_REG_X3, buf), (UC_ARM64_REG_X4, ln), (UC_ARM64_REG_X5, key),
                 (UC_ARM64_REG_SP, 0x70080000), (UC_ARM64_REG_LR, RET), (UC_ARM64_REG_TPIDR_EL0, 0x60000000)]:
        mu.reg_write(r, v)
    try: mu.emu_start(DEC, RET, 0, 0)
    except UcError: return None
    return bytes(mu.mem_read(buf, ln)).split(b'\x00')[0]

# 3) emulate DEC at every call site, reconstructing (buf,len,key)
out = set()
for i, ins in enumerate(insns):
    if ins.mnemonic == 'bl' and ins.operands and ins.operands[0].type == ARM64_OP_IMM and ins.operands[0].imm == DEC:
        reg = reg_at(i, 45)
        buf = reg.get('x3'); ln = reg.get('w4'); key = reg.get('w5')
        if not buf or not ln or ln > 256 or not (tva <= buf < tva + len(code) + 0x40000): continue
        s = decrypt(buf, ln, key)
        if s:
            try: t = s.decode('utf-8')
            except Exception: continue
            if t and sum(32 <= ord(c) < 127 for c in t) >= max(2, len(t) - 1): out.add(t)
out = sorted(out)
print(f"[+] statically decrypted {len(out)} strings via Unicorn:")
for s in out: print("   ", s)
