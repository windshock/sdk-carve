# Native track — ghidra2cpg (method extension)

Author: AI agent (Claude Opus 4.8, 1M context)
Date: 2026-08-31
Goal: extend sdk-carve past the JVM boundary to native libraries (`.so`/`.dll`/`.exe`)
using Ghidra (`ghidra2cpg`), and prove the pipeline finishes and is queryable.

## Scope note (honesty)

The Goldoson/SMARTLB SDK is **pure Java/Retrofit — it has no native component.** The
34 `.so` files in the sample are the **host app's** (navigation engine, TensorFlow Lite,
Crashlytics, SSO, Tyche, etc.). So this track is a **capability demonstration of the
native method**, not a continuation of the Goldoson analysis. The demo lib
(`libimage_processing_util_jni.so`) is a benign image-processing JNI helper.

## Result

Tooling present: `ghidra2cpg` (Joern 4.0.370 frontend) + Ghidra 12.1.2.

Target: `lib/arm64-v8a/libimage_processing_util_jni.so` — ELF aarch64, **stripped**, 28 KB.

```bash
ghidra2cpg libimage_processing_util_jni.so -o libimg.cpg     # ~6.4 s -> 220 KB
CPG=libimg.cpg joern --script native-inventory.sc 2>&1 | grep -a '^MARK'
```

- CPG built and **finalized in ~6 s (220 KB)**; loads and queries in Joern.
- `methods=97  calls=4832  literals=1746`.
- **Imported API surface** (the native source/sink surface): `ANativeWindow_fromSurface`,
  `ANativeWindow_lock`, `ANativeWindow_setBuffersGeometry`, `ANativeWindow_unlockAndPost`,
  `__android_log_print`, `memcpy`, `memmove`, `malloc`, `free`, `__memcpy_chk`,
  `__stack_chk_fail`, `__cxa_atexit`.
- **Security-relevant calls** matched by the sink regex: `memcpy`, `memmove`, `malloc`,
  `__memcpy_chk` (buffer-copy sinks), `__android_log_print` (logging), ANativeWindow ops.

This is the native analog of the JVM source/sink inventory: for a native binary the
**imported-symbol table is the boundary surface** (libc, Android, JNI, crypto), exactly
where sources and sinks live.

## Method adaptation for native

| JVM track | Native track |
|---|---|
| carve mini-JAR of target packages | one library is already scoped; huge binary → scope by exported fns / reachable subgraph |
| `jimple2cpg` (bytecode) | `ghidra2cpg` (Ghidra decompiles the binary) |
| **pin JDK 17** (Soot's ASM) | **do NOT pin — Ghidra needs a recent JDK (21+)** |
| method names from bytecode | stripped → `FUN_xxxx`; imports keep names |
| `cpg.call.name(...)` source/sink | imported-symbol surface + `Java_*`/`JNI_OnLoad` entry points |

## Gotchas found

- **JDK inversion**: the JVM track pins JDK 17 (Soot rejects Java 25); the native track
  needs the *newest* JDK for Ghidra. Same host, opposite requirement.
- **Output plumbing**: `joern` writes INFO logs to stdout and Ghidra literals contain NUL
  bytes, so plain `grep` treats the stream as binary and prints nothing. Prefix results
  with a marker and extract with `grep -a '^MARK'`.
- **pcode "Unable to disassemble EXTERNAL block"** warnings are benign (PLT stubs).

## Limits

Stripped binaries lose symbol names; there are no source-level types; string extraction
needs a dedicated pass (the default `literal` nodes here are numeric operands/addresses).
Confirm findings against the disassembly and cross-verify, as in the JVM track.

Scripts: `.claude/skills/sdk-carve/scripts/native-cpg.sh`, `native-inventory.sc`.
