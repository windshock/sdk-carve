---
name: sdk-carve
description: >-
  Carve one embedded SDK/library out of a huge, decompiler-damaged Android/JVM app and
  analyze it with scoped, tool-verified static analysis — a scoped Joern CPG
  (jimple2cpg over bytecode) plus a scoped CodeQL database (build-mode=none), and a
  native track via ghidra2cpg for `.so`/`.dll`/`.exe` — when whole-app CPG/CodeQL
  fails on scale or on decompiled/obfuscated syntax. Use for:
  embedded third-party SDK/adware/spyware analysis, isolating a small target inside a
  huge codebase, decompiled or obfuscated JVM bytecode, and source→sink / reachability
  / capability questions. Triggers — "analyze this SDK embedded in the app", "scope a
  target out of a huge decompiled app", "whole-app CPG/CodeQL OOMed / never finalized /
  2GB cpg.bin.tmp", "build a scoped CPG", "jimple2cpg / build-mode=none", "decompiled
  Android static analysis", "which data does this SDK collect and where does it send it".
---

# sdk-carve

A repeatable method to analyze one embedded component inside a large decompiled JVM app
when whole-application CPG/CodeQL does not finish. The core move: **scope to a
self-contained subgraph, feed bytecode (not damaged source), stub the framework
boundary, and cross-verify** — then prove the scope was complete.

## When to use

- A big Android/JVM app (~10k+ classes, GB-scale, `??` / `Method not decompiled` stubs).
- The interesting logic is one SDK/library with an identifiable package root.
- Whole-app attempts stall (2 GB CPG that never finalizes; CodeQL DB that never builds).

## Do NOT assume this works for

- **Native code** (`.so`/`.dll`/`.exe`): the JVM frontend does not apply — use the
  **native track (ghidra2cpg)** below.
- **Heavy reflection / dynamic class loading**: static call edges are missing, so the
  scope-closure proof (step 5) can silently under-scope. Re-check per target.
- Targets with **no clean package boundary**.
- Targets that share framework signatures with **shaded libraries** in the same app
  (WiFi/BT scanning, HTTP, crypto): anchor-based root detection can *over*-scope — always
  size/depth-guard the detection (step 0) and re-check the closure (step 5).
- **Malformed / packed APKs** (Konfety, SoumniBot, DCL packers): the real SDK isn't in the
  primary `classes.dex` — it's a decoy, and the payload is a tampered/encrypted asset. Run
  the **pre-carve** stage first (see below); a bytecode carve on the raw APK finds only the
  decoy.

## Pre-carve (stage 0 — container normalization & payload discovery)

If `aapt`/`apktool` say the manifest is "corrupt", or `classes.dex` is tiny/decoy, the APK
container is tampered. `scripts/apk-normalize.py` generically repairs the ZIP (fake
encryption flag, bogus compression method, size lies) so standard tools parse it, and flags
high-entropy `assets/*` as candidate packed payloads. Then recover the hidden DEX (e.g.
`scripts/konfety-unpack.py` for the Konfety family) and carve *that*. Full worked example:
[`docs/PRE_CARVE.md`](../../../docs/PRE_CARVE.md).

## Method

### 0. Establish the target root
Identify the SDK's own package(s) and any obfuscated helper packages it references
(single/two-letter packages are common after R8). Seed from docs/known research, then
confirm by reading imports/usages. You will *prove* completeness in step 5.

**When the package name is itself R8-renamed** (the common case — the same SDK ships as
`com/smart/sklb/edge` in one app but `com/enoi/yweoi/nwef`, `com/gwox/pzkvn/riosk`, … in
others), you cannot seed from docs. Auto-locate the renamed root by anchoring on the
SDK's *own* surviving method names:

```bash
scripts/detect.py app-dex2jar.jar        # prints carve globs, e.g. com/enoi/yweoi/nwef/*
```

`detect.py` greps for the SDK-unique method names (the same names you put in
`source-sink.sc`), maps each hit to its package root, and applies three guards so it
cannot drag in a shaded library that merely shares a signature:

- **size guard** — framework scan APIs (`getScanResults`/`getBondedDevices`) also live in
  unrelated shaded libs (e.g. an 8k-class package); a real SDK cluster is ~100–300
  classes, so roots larger than `GUARD` (400) are rejected. *Without this the carve
  balloons to a mini-whole-app — the #1 way to under-scope by over-scoping.*
- **depth guard** — a genuine short helper is shallow (`f2/x`); a deep hit (`d/e/a/a/c`)
  is a shaded-library substring FP and is dropped.
- **lib denylist + a 4-segment `com/<a>/<b>/<c>` rule** — across the Goldoson family the
  root is consistently four segments; jackson/glide/igaworks/mapps and friends are
  skipped by name (tune `DENY` / `SEGS` for your SDK).

If the SDK's *method* names are obfuscated too, `detect.py` falls back to a structural
anchor — classes that call **both** framework `getScanResults` and `getBondedDevices`
(a WiFi-scan ∩ BT-bonded collector triad no benign single-purpose lib exhibits).

### 1. Carve a scoped mini-JAR from bytecode
Extract only the target packages' classes from the app's dex2jar JAR and re-jar them.
This is 100–200 classes instead of ~50k, and bytecode is immune to decompiler-damaged
Java syntax.

```bash
export JAVA_HOME=<jdk17>   # REQUIRED: Soot's ASM rejects Java 25 (major 69) bytecode
scripts/carve.sh app-dex2jar.jar out/ 'com/smart/sklb/*' 'bg/*' 'cg/*' 'dg/*'
# -> out/scoped.jar  and  out/cpg.bin (jimple2cpg)
```

`scripts/carve.sh` takes the app JAR, an output dir, then one or more package globs.
It builds the mini-JAR and runs `jimple2cpg` → `out/cpg.bin`.

### 2. Query the scoped CPG (Joern)
Enumerate sources/sinks and prove entry→sink reachability. Edit the source/sink method
names in the script for your target.

```bash
CPG=out/cpg.bin joern --script scripts/source-sink.sc
```

> If the SDK's own method names are R8-renamed (not just its package), name-matching
> under-reports — the sink inventory collapses to framework names only
> (`loadUrl`/`loadData`). Recover the real surface with the structural anchors from step 0
> (framework APIs cannot be renamed), or map the renamed names by call structure.

### 3. Scoped CodeQL (independent second tool)
Copy only the target `.java` into a clean source root and build with **no compilation**:

```bash
codeql database create out/db --language=java --build-mode=none --source-root=src-scoped
codeql pack install queries
codeql query run --database=out/db queries/flows.ql   # match by method NAME (externals unresolved)
```

### 4. Cross-verify
Reconcile three independent results: your manual read, the Joern/bytecode CPG, and the
CodeQL/source DB. Agreement → high confidence. Disagreement is signal — e.g. a bytecode
CPG resolves external API calls (GPS, ad-ID) that a source-only DB leaves unresolved.

### 5. Prove the scope is complete (reverse-trace closure)
Show the SDK calls nothing outside scope except libraries/compiler synthetics:

```bash
CPG=out/cpg.bin joern --script scripts/scope-closure.sc
```

Everything left after filtering libs + in-scope should be framework or R8 synthetic
`StringBuilder` helpers — not missed SDK logic. If a real out-of-scope package appears,
add it to the scope (step 1) and repeat.

### 6. State limits honestly
- Fine-grained taint (`reachableByFlows` / CodeQL path) often returns 0 because data
  crosses `SharedPreferences` / DTO constructors. That is a **framework-boundary** limit
  (present even whole-app), not a scoping artifact; recover full paths with flow
  models/semantics. Reachability + source/sink inventory already establish the capability.
- Static ≠ runtime. Label findings `binary-confirmed` vs `runtime-confirmed`.

## Native track (ghidra2cpg)

For native libraries (`.so`/`.dll`/`.dylib`/`.exe`) the JVM frontend does not apply;
use Ghidra via `ghidra2cpg`. Same shape — scope, lift, inventory, verify — with these
differences:

- **Scope**: one library is already a scoped unit. For a huge binary, scope by exported
  functions and their reachable subgraph (`ghidra2cpg --exclude-regex`, or post-filter).
- **Lift**: `scripts/native-cpg.sh <binary> <out.cpg>` (wraps `ghidra2cpg`). Works on
  stripped binaries (functions become `FUN_xxxx`).
- **JDK inversion**: Ghidra needs a *recent* JDK (21+). Do **not** pin JDK 17 here — that
  pin is only for jimple2cpg/Soot. Leave `JAVA_HOME` at the default.
- **Inventory**: `CPG=out.cpg joern --script scripts/native-inventory.sc 2>&1 | grep -a '^MARK'`.
  The imported-symbol surface *is* the source/sink surface (libc, `__android_log_print`,
  `socket`/`open`, crypto, JNI env calls); `Java_*` / `JNI_OnLoad` are entry points.
- **Output plumbing**: joern logs to stdout and Ghidra literals contain NUL bytes — hence
  the `MARK` prefix + `grep -a`.
- **Limits**: stripped → no symbol names; no source-level types; strings need a dedicated
  pass. Confirm against the disassembly and cross-verify, like the JVM track.

## Files

- `scripts/apk-normalize.py` — pre-carve: repair a tampered/evasive APK ZIP (fake enc flag,
  bogus method, size lies) so tools parse it; flags decoy dex + packed assets
- `scripts/konfety-unpack.py` — pre-carve payload stage (Konfety family): inflate + XOR
  (`java.util.Random`, seed = asset-name + 0xFFFF) → inner ZIP → real `classes.dex`
- `scripts/mobidash-unpack.py` — pre-carve payload stage (MobiDash family): signing-cert →
  SQLCipher passphrase → bootstrap DEX + XOR-decrypted module jars (multi-layer example)
- `scripts/detect.py` — auto-locate an R8-renamed SDK root (method-name anchors +
  size/depth/denylist guards + structural fallback); prints carve globs
- `scripts/carve.sh` — mini-JAR + `jimple2cpg` (parameterized by package globs); builds the
  jar in-memory so obfuscated `j.class`/`J.class` siblings survive a case-insensitive FS
- `scripts/source-sink.sc` — Joern source/sink inventory + entry→sink reachability
- `scripts/scope-closure.sc` — reverse dependency trace / scope-completeness proof
- `queries/flows.ql` — CodeQL source/sink template (name-matched, `build-mode=none`-friendly)
- `scripts/native-cpg.sh` — native binary → CPG via `ghidra2cpg` (native track)
- `scripts/native-inventory.sc` — imported-API surface + native sinks + JNI entry points

Edit the `EDIT:`-marked lines (package prefixes, source/sink method names, entry points)
for your target. The Goldoson/SMARTLB defaults are left in as a worked example.
