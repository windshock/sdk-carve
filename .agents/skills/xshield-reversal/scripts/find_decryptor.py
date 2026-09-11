#!/usr/bin/env python3
"""xshield-reversal — auto-locate the string decryptor in ANY libdxbase build and dump the vault.

The decrypt function's ADDRESS changes per xShield build (OK Cashbag 0x1eca0, PASS by SKT 0x5c78),
but its ABI + seed constants are STABLE:  fcn(s1=0x86817231, s2=0x86817231, s3=0x11300316, buf, len, key)
with the MBA magic 0x914dbacf (built as an IMMEDIATE via mov/movk on arm64 or movw/movt on arm32, NOT a
data constant — so byte-grep misses it). This tool finds the decryptor by locating call sites whose
preceding instructions load the seed 0x86817231, takes the most-called such target as the decryptor,
then Unicorn-emulates it over every call site (stubbing memset) to recover the RASP string vault
statically — no device, no Frida, no hardcoded address.

Supports **arm64 (AArch64)** and **armeabi-v7a (ARM/THUMB2)** — the arch is auto-detected. On arm32 the
5th/6th args (len,key) are passed on the stack (AAPCS r0-r3 only), so arg reconstruction also scans
`str rX,[sp,#0|#4]`; the decryptor LOCATION is recovered on both, the string dump is best-effort on arm32.

usage: find_decryptor.py <libdxbase.so>
requires: pip install --break-system-packages unicorn capstone lief   (into the running interpreter)
"""
import sys, struct, collections
import lief

S1 = 0x86817231; S3 = 0x11300316          # stable xShield string-decryptor seeds
SO = sys.argv[1] if len(sys.argv) > 1 else "libdxbase.so"
b = lief.parse(SO)
mach = str(b.header.machine_type)
ARCH = 'arm64' if 'AARCH64' in mach else ('arm' if 'ARM' in mach else None)
if ARCH is None:
    print(f"unsupported arch: {mach}"); sys.exit(1)
txt = [s for s in b.sections if s.name == '.text'][0]
code = bytes(txt.content); tva = txt.virtual_address
print(f"[+] {SO}: {ARCH}, .text @ {hex(tva)} ({len(code)} bytes)")


# ------------------------------------------------------------------ arm64 path
def run_arm64():
    from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE, UcError
    from unicorn.arm64_const import (UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3,
        UC_ARM64_REG_X4, UC_ARM64_REG_X5, UC_ARM64_REG_SP, UC_ARM64_REG_LR, UC_ARM64_REG_PC,
        UC_ARM64_REG_TPIDR_EL0)
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
    from capstone.arm64 import ARM64_OP_IMM
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN); md.detail = True
    insns = list(md.disasm(code, tva))

    def reg_at(i, span=24):
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

    cand = collections.Counter()
    for i, ins in enumerate(insns):
        if ins.mnemonic == 'bl' and ins.operands and ins.operands[0].type == ARM64_OP_IMM:
            if S1 in reg_at(i, 30).values(): cand[ins.operands[0].imm] += 1
    if not cand:
        print("no decryptor found (seed 0x86817231 not observed at any call site)"); return
    DEC = cand.most_common(1)[0][0]
    print(f"[+] string decryptor @ 0x{DEC:x}  ({cand[DEC]} seed-bearing call sites)  "
          f"[other candidates: {[hex(a) for a,_ in cand.most_common()[1:4]]}]")

    PAGE = 0x1000; al = lambda x: x & ~(PAGE - 1)
    mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM); SEGS = []
    for seg in b.segments:
        if 'LOAD' not in str(seg.type) or not seg.virtual_size: continue
        base = al(seg.virtual_address); end = (seg.virtual_address + seg.virtual_size + PAGE - 1) & ~(PAGE - 1)
        try: mu.mem_map(base, end - base)
        except Exception: pass
        mu.mem_write(seg.virtual_address, bytes(seg.content)); SEGS.append((seg.virtual_address, bytes(seg.content)))
    mu.mem_map(0x70000000, 0x100000); mu.mem_map(0x60000000, 0x4000); RET = 0x50000000
    memset_plt = None; off = DEC - tva
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

    out = set()
    for i, ins in enumerate(insns):
        if ins.mnemonic == 'bl' and ins.operands and ins.operands[0].type == ARM64_OP_IMM and ins.operands[0].imm == DEC:
            reg = reg_at(i, 45); buf = reg.get('x3'); ln = reg.get('w4'); key = reg.get('w5')
            if not buf or not ln or ln > 256 or not (tva <= buf < tva + len(code) + 0x40000): continue
            s = decrypt(buf, ln, key)
            if s:
                try: t = s.decode('utf-8')
                except Exception: continue
                if t and sum(32 <= ord(c) < 127 for c in t) >= max(2, len(t) - 1): out.add(t)
    report(sorted(out))


# ---------------------------------------------------------- armeabi-v7a (THUMB)
def run_arm():
    from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE, UcError
    from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
        UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC)
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
    from capstone.arm import ARM_OP_IMM, ARM_OP_REG, ARM_OP_MEM
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB); md.detail = True; md.skipdata = True
    insns = [i for i in md.disasm(code, tva) if i.id != 0]      # drop skipdata (data) pseudo-insns
    idx = {ins.address: k for k, ins in enumerate(insns)}      # addr -> list index
    PCB = lambda a: (a + 4) & ~3                                 # THUMB PC base (word-aligned) for pc-rel

    def upd(reg, ins):
        """apply one THUMB instruction's effect to the reg model (best-effort, immediates + pc-rel)."""
        ops = ins.operands; m = ins.mnemonic
        try:
            rn = lambda k: ins.reg_name(ops[k].reg)
            if m == 'movw' and ops[1].type == ARM_OP_IMM:
                reg[rn(0)] = ops[1].imm & 0xffff
            elif m == 'movt' and ops[1].type == ARM_OP_IMM:
                reg[rn(0)] = (reg.get(rn(0), 0) & 0xffff) | ((ops[1].imm & 0xffff) << 16)
            elif m in ('mov', 'movs', 'mov.w') and ops[1].type == ARM_OP_IMM:
                reg[rn(0)] = ops[1].imm
            elif m in ('mov', 'movs', 'mov.w') and ops[1].type == ARM_OP_REG:
                reg[rn(0)] = reg.get(rn(1))
            elif m == 'adr':
                reg[rn(0)] = PCB(ins.address) + ops[1].imm
            elif m in ('add', 'add.w', 'addw') and len(ops) == 2 and rn(1) == 'pc':      # add rd, pc
                reg[rn(0)] = (reg.get(rn(0)) or 0) + PCB(ins.address)
            elif m in ('add', 'add.w', 'addw') and len(ops) == 3 and ops[2].type == ARM_OP_IMM:
                base = PCB(ins.address) if rn(1) == 'pc' else reg.get(rn(1))
                if base is not None: reg[rn(0)] = base + ops[2].imm
            elif m in ('ldr', 'ldr.w') and ops[1].type == ARM_OP_MEM and ins.reg_name(ops[1].mem.base) == 'pc':
                a = PCB(ins.address) + ops[1].mem.disp; o = a - tva
                if 0 <= o <= len(code) - 4: reg[rn(0)] = struct.unpack('<I', code[o:o + 4])[0]
        except Exception:
            pass

    def reg_at(i, span=40):
        reg = {}
        for j in range(max(0, i - span), i): upd(reg, insns[j])
        return reg

    # reconstruct (ciphertext-source, len, key) at a decrypt call site.
    # arm32 pattern: pc-rel source copied via NEON vld1 into a local buf; len/key pushed via strd/str [sp].
    def args_at(i, span=48):
        reg = {}; src = ln = key = None
        for j in range(max(0, i - span), i):
            ins = insns[j]; ops = ins.operands; m = ins.mnemonic
            # capture the NEON/ldr load SOURCE (base reg value) before updating reg
            try:
                if m.startswith('vld1') or m.startswith('vldr') or (m.startswith('ldr') and ops and ops[-1].type == ARM_OP_MEM):
                    base = ins.reg_name(ops[-1].mem.base)
                    if base not in ('pc',) and reg.get(base) is not None: src = reg[base]
                if m in ('strd',) and len(ops) == 3 and ops[2].type == ARM_OP_MEM and ins.reg_name(ops[2].mem.base) == 'sp':
                    d = ops[2].mem.disp
                    if d == 0: ln = reg.get(ins.reg_name(ops[0].reg)); key = reg.get(ins.reg_name(ops[1].reg))
                elif m in ('str', 'str.w') and len(ops) == 2 and ops[1].type == ARM_OP_MEM and ins.reg_name(ops[1].mem.base) == 'sp':
                    d = ops[1].mem.disp; v = reg.get(ins.reg_name(ops[0].reg))
                    if d == 0: ln = v
                    elif d == 4: key = v
            except Exception:
                pass
            upd(reg, ins)
        return src, ln, key

    cand = collections.Counter()
    for i, ins in enumerate(insns):
        if ins.mnemonic in ('bl', 'blx') and ins.operands and ins.operands[0].type == ARM_OP_IMM:
            if S1 in reg_at(i, 40).values(): cand[ins.operands[0].imm] += 1
    if not cand:
        print("no decryptor found (seed 0x86817231 not observed at any call site)"); return
    DEC = cand.most_common(1)[0][0]
    print(f"[+] string decryptor @ 0x{DEC:x}  ({cand[DEC]} seed-bearing call sites)  "
          f"[other candidates: {[hex(a) for a,_ in cand.most_common()[1:4]]}]")

    PAGE = 0x1000; al = lambda x: x & ~(PAGE - 1)
    mu = Uc(UC_ARCH_ARM, UC_MODE_THUMB); SEGS = []
    for seg in b.segments:
        if 'LOAD' not in str(seg.type) or not seg.virtual_size: continue
        base = al(seg.virtual_address); end = (seg.virtual_address + seg.virtual_size + PAGE - 1) & ~(PAGE - 1)
        try: mu.mem_map(base, end - base)
        except Exception: pass
        mu.mem_write(seg.virtual_address, bytes(seg.content)); SEGS.append((seg.virtual_address, bytes(seg.content)))
    STK = 0x70000000; mu.mem_map(STK, 0x100000); RET = 0x50000000
    # memset PLT = first bl/blx target inside DEC's body
    memset_plt = None; off = (DEC & ~1) - tva
    for ins in md.disasm(code[off:off + 400], DEC & ~1):
        if ins.id == 0: continue
        if ins.mnemonic in ('bx', 'pop') and 'pc' in ins.op_str: break
        if ins.mnemonic in ('bl', 'blx') and ins.operands and ins.operands[0].type == ARM_OP_IMM:
            memset_plt = ins.operands[0].imm; break
    def cb(uc, addr, size, ud):
        if memset_plt is not None and (addr == (memset_plt & ~1)):
            r0 = uc.reg_read(UC_ARM_REG_R0); r1 = uc.reg_read(UC_ARM_REG_R1) & 0xff; r2 = uc.reg_read(UC_ARM_REG_R2)
            try: uc.mem_write(r0, bytes([r1]) * min(r2, 0x400))
            except Exception: pass
            uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))
    if memset_plt is not None:
        mu.hook_add(UC_HOOK_CODE, cb, begin=memset_plt & ~1, end=memset_plt & ~1)

    def orig(buf, ln):
        for va, c in SEGS:
            if va <= buf < va + len(c): return c[buf - va: buf - va + ln]
        return None
    def decrypt_into(buf, ln, key):
        """buf is already filled with `ln` bytes of ciphertext; run DEC in place and read it back."""
        sp = STK + 0x80000
        try:
            mu.mem_write(sp, struct.pack('<II', ln & 0xffffffff, key & 0xffffffff))   # stack args: [sp]=len,[sp+4]=key
        except Exception: pass
        for r, v in [(UC_ARM_REG_R0, S1), (UC_ARM_REG_R1, S1), (UC_ARM_REG_R2, S3),
                     (UC_ARM_REG_R3, buf), (UC_ARM_REG_SP, sp), (UC_ARM_REG_LR, RET)]:
            mu.reg_write(r, v)
        try: mu.emu_start((DEC & ~1) | 1, RET, 0, 0)     # start in THUMB
        except UcError: return None
        return bytes(mu.mem_read(buf, ln)).split(b'\x00')[0]

    SCRATCH = STK + 0x40000                              # scratch buffer for the (copied) ciphertext
    out = set()
    for i, ins in enumerate(insns):
        if ins.mnemonic in ('bl', 'blx') and ins.operands and ins.operands[0].type == ARM_OP_IMM and ins.operands[0].imm == DEC:
            src, ln, key = args_at(i, 48)
            if src is None or ln is None or key is None or ln <= 0 or ln > 256: continue
            ct = orig(src, ln)                            # ciphertext from the pc-relative .text source
            if ct is None: continue
            try:
                mu.mem_write(SCRATCH, ct)
                s = decrypt_into(SCRATCH, ln, key)
            except Exception:
                continue
            if s:
                try: t = s.decode('utf-8')
                except Exception: continue
                if t and sum(32 <= ord(c) < 127 for c in t) >= max(2, len(t) - 1): out.add(t)
    out = sorted(out)
    print(f"[+] statically decrypted {len(out)} strings via Unicorn:")
    for s in out: print("   ", s)
    if not out:
        print("    (0 strings — decryptor LOCATED + len/key recovered, but the ciphertext SOURCE on this")
        print("     v7a build is a function-scoped PIC anchor (`add rX,pc` / `ldr rX,[sp,#..]`) set outside")
        print("     the call-site window, so static source resolution is unreliable. Full arm32 dump needs")
        print("     function-entry emulation; the located address unblocks that / manual work.)")


def report(out):
    print(f"[+] statically decrypted {len(out)} strings via Unicorn:")
    for s in out: print("   ", s)
    if not out:
        print("    (0 strings — decryptor located but arg reconstruction yielded none)")


run_arm64() if ARCH == 'arm64' else run_arm()
