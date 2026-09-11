import pyghidra
pyghidra.start()
import os, sys
from ghidra.app.decompiler import DecompInterface

SO = sys.argv[1] if len(sys.argv) > 1 else "libdxbase.so"   # usage: pyghidra decomp_all.py <so> [out.c]
OUT = sys.argv[2] if len(sys.argv) > 2 else "decomp.c"
with pyghidra.open_program(SO, project_location="/tmp/ghidra_proj2", project_name="dx", analyze=True) as flat:
    prog = flat.getCurrentProgram()
    di = DecompInterface()
    di.openProgram(prog)
    fm = prog.getFunctionManager()
    n = 0
    with open(OUT, "w") as f:
        for fn in fm.getFunctions(True):
            try:
                r = di.decompileFunction(fn, 90, flat.monitor)
                if r.decompileCompleted():
                    f.write("\n/* ===== %s @ %s ===== */\n" % (fn.getName(), fn.getEntryPoint()))
                    f.write(r.getDecompiledFunction().getC())
                    n += 1
            except Exception:
                pass
            if n % 200 == 0: print("...", n, flush=True)
    print("DONE", n)
