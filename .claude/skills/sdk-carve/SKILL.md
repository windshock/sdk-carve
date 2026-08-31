---
name: sdk-carve
description: >-
  Carve one embedded SDK/library out of a huge, decompiler-damaged Android/JVM app and
  analyze it with scoped, tool-verified static analysis — a scoped Joern CPG
  (jimple2cpg over bytecode) plus a scoped CodeQL database (build-mode=none) — when
  whole-app CPG/CodeQL fails on scale or on decompiled/obfuscated syntax. Use for:
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

- **Native code** (`.so`, C/C++): `jimple2cpg` is JVM-only — swap in a binary/IR frontend.
- **Heavy reflection / dynamic class loading**: static call edges are missing, so the
  scope-closure proof (step 5) can silently under-scope. Re-check per target.
- Targets with **no clean package boundary**.

## Method

### 0. Establish the target root
Identify the SDK's own package(s) and any obfuscated helper packages it references
(single/two-letter packages are common after R8). Seed from docs/known research, then
confirm by reading imports/usages. You will *prove* completeness in step 5.

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

## Files

- `scripts/carve.sh` — mini-JAR + `jimple2cpg` (parameterized by package globs)
- `scripts/source-sink.sc` — Joern source/sink inventory + entry→sink reachability
- `scripts/scope-closure.sc` — reverse dependency trace / scope-completeness proof
- `queries/flows.ql` — CodeQL source/sink template (name-matched, `build-mode=none`-friendly)

Edit the `EDIT:`-marked lines (package prefixes, source/sink method names, entry points)
for your target. The Goldoson/SMARTLB defaults are left in as a worked example.
