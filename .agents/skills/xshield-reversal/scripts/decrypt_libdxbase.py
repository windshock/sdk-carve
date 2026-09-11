#!/usr/bin/env python3
"""Static string-deobfuscator for xShield/AppSealing libdxbase.so (arm64).

Reverses the native string obfuscation WITHOUT running the app: it emulates ONLY the pure
string-decrypt function fcn@0x1eca0 (unicorn), and reconstructs each call site's 6 args by a
mini register simulator over the preceding instructions (r2 disasm).

Decrypt ABI (recovered):  fcn_0x1eca0(seed1, seed2, seed3, out_ptr, len, key)
  - out_ptr points at the in-place ciphertext (in .data); after the call it holds `len` plaintext bytes.
  - seeds/key select the per-string transform (MBA + NEON tbl substitution).

Requires: pip install unicorn lief ; radare2 (r2) on PATH.
Usage: decrypt_libdxbase.py <libdxbase.so>  [decryptor_vaddr default 0x1eca0]
"""
import sys, subprocess, re, json
import lief
from unicorn import *
from unicorn.arm64_const import *

SO = sys.argv[1] if len(sys.argv) > 1 else "libdxbase.so"
DEC = int(sys.argv[2], 0) if len(sys.argv) > 2 else 0x1eca0
b = lief.parse(SO); PAGE = 0x1000; al = lambda x: x & ~(PAGE-1)

def newmu():
    mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    for seg in b.segments:
        if 'LOAD' not in str(seg.type): continue
        va, msz = seg.virtual_address, seg.virtual_size
        if not msz: continue
        base = al(va); end = (va+msz+PAGE-1) & ~(PAGE-1)
        try: mu.mem_map(base, end-base)
        except Exception: pass
        c = bytes(seg.content)
        if c: mu.mem_write(va, c)
    mu.mem_map(0x400000, 0x40000); mu.reg_write(UC_ARM64_REG_SP, 0x420000)
    T = 0x600000; mu.mem_map(T, 0x1000); mu.mem_write(T+0x28, b'\x11'*8)
    mu.reg_write(UC_ARM64_REG_TPIDR_EL0, T)
    mu.hook_add(UC_HOOK_MEM_UNMAPPED, lambda uc,a,ad,sz,v,u: (uc.mem_map(al(ad), PAGE), True)[1])
    return mu

def decrypt(s1, s2, s3, out_va, length, key):
    if not (0 < length <= 256): return None
    mu = newmu(); STOP = 0x900000
    for r, v in [(UC_ARM64_REG_X0,s1),(UC_ARM64_REG_X1,s2),(UC_ARM64_REG_X2,s3),
                 (UC_ARM64_REG_X3,out_va),(UC_ARM64_REG_X4,length),(UC_ARM64_REG_X5,key),(UC_ARM64_REG_LR,STOP)]:
        mu.reg_write(r, v)
    try: mu.emu_start(DEC, STOP, count=3_000_000)
    except UcError: return None
    return bytes(mu.mem_read(out_va, length))

def regs_at(addr):
    dis = subprocess.run(["r2","-q","-c","pdj 26 @ %d" % (addr-0x60), SO], capture_output=True, text=True).stdout
    try: ins = json.loads(dis)
    except Exception: return None
    R = {}
    for it in ins:
        if it.get("offset", 0) > addr: break
        d = it.get("disasm", "")
        m = re.match(r'mov (w|x)(\d+), (0x[0-9a-f]+|\d+)$', d)
        if m: R[int(m.group(2))] = int(m.group(3),0); continue
        m = re.match(r'movk (w|x)(\d+), (0x[0-9a-f]+|\d+), lsl (\d+)', d)
        if m:
            k=int(m.group(2)); R[k]=(R.get(k,0)&~(0xffff<<int(m.group(4))))|((int(m.group(3),0)&0xffff)<<int(m.group(4))); continue
        m = re.match(r'adrp (w|x)(\d+), (0x[0-9a-f]+)', d)
        if m: R[int(m.group(2))] = int(m.group(3),0); continue
        m = re.match(r'add (w|x)(\d+), (w|x)(\d+), (0x[0-9a-f]+|\d+)', d)
        if m: R[int(m.group(2))] = (R.get(int(m.group(4)),0)+int(m.group(5),0)) & 0xffffffffffffffff; continue
        m = re.match(r'mov (w|x)(\d+), (w|x)(\d+)$', d)
        if m: R[int(m.group(2))] = R.get(int(m.group(4)),0); continue
    return R

xr = subprocess.run(["r2","-q","-c","aa;axtj 0x%x" % DEC, "-e","bin.cache=true", SO], capture_output=True, text=True).stdout
try: sites = sorted({x["from"] for x in json.loads(xr)})
except Exception: sites = sorted({int(a,16) for a in re.findall(r'0x[0-9a-f]+', xr)})
print("# xShield libdxbase.so string decrypt — %d call sites of fcn@0x%x" % (len(sites), DEC))
for s in sites:
    R = regs_at(s)
    if not R or 3 not in R: continue
    pt = decrypt(R.get(0,0)&0xffffffff, R.get(1,0)&0xffffffff, R.get(2,0)&0xffffffff,
                 R[3], R.get(4,0)&0xffff, R.get(5,0)&0xffff)
    if pt is None: continue
    try: txt = pt.decode('utf-8')
    except Exception: txt = repr(pt)
    print("0x%06x  %s" % (s, txt))
