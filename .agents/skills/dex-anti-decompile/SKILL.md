---
name: dex-anti-decompile
description: >-
  Identify and defeat DEX anti-decompilation / anti-reversing constructs that break Android
  static-analysis toolchains — deliberately crafted, runtime-legal DEX that crashes or defeats
  dex2jar / jadx / CFR / Vineflower while running fine on ART. Two families: (1) method-descriptor
  "bombs" (a synthetic method with ~65,530 parameters, e.g. `STLudc.a_stl_d2j_lock`) that break the
  DEX->.class CONVERTER (dex2jar/jadx-to-jar/enjarify) via the class-file 64 KB CONSTANT_Utf8 limit;
  (2) exception-table flattening + irreducible control flow that break the DECOMPILER after conversion
  (CFR ConfusedCFRException, Vineflower/Fernflower FinallyProcessor IOOBE, jadx "Method not decompiled").
  Use when dex2jar emits a 0-byte / silently-incomplete jar, when a specific method makes every
  decompiler fail, when "UTF8 string too large" appears, or to detect these before trusting a carve.
  Triggers — "dex2jar failed / 0-byte jar / UTF8 string too large", "jadx can't decompile this method",
  "anti-decompilation", "anti-dex2jar", "decompiler bomb", "why does every decompiler crash on one method".
---

# dex-anti-decompile

Anti-decompilation = **obfuscation aimed at the analysis TOOL, not (only) at a human reader.** The DEX is
crafted so it runs on ART but a specific tool cannot process it. Two distinct families seen in KR banking/
fintech apps (2026-09). **They attack different stages, so they need different detection AND different
defeat** — do not conflate them.

| # | family | breaks | DEX footprint | detect | defeat |
|---|---|---|---|---|---|
| 1 | **method-descriptor bomb** | the **converter** (dex2jar / jadx-to-jar / enjarify) | **large & obvious** (a proto with a huge shorty/param count) | `detect-anti-decompile.py` (parses DEX) | **jimple2cpg reads DEX directly** (Soot, no 64 KB limit) / strip the bomb class / direct-dex string scan |
| 2 | **exception-table flattening + irreducible flow** | the **decompiler** (CFR/jadx/Vineflower/Fernflower) | **almost none** (few dalvik tries) | `check-flattening.sh` (post-conversion, `javap`) | **`ExFlattenNormalize.java`** (`--redundant --split --unify`) then CFR |

## Family 1 — method-descriptor bomb (anti-converter)
**What:** a synthetic method whose proto has an absurd parameter count — real case: class `STLudc`, method
**`a_stl_d2j_lock`** ("d2j lock"), a proto with **65,530 parameters** (shorty `V` + `L`×65530). DEX stores
parameters in an **unbounded `type_list`**, so this is legal and ART runs it. But a DEX→`.class` converter must
rebuild the JVM **method descriptor** `(L…;L…;… ×65530)V`, which overflows the class-file **`CONSTANT_Utf8`
65535-byte limit** → ASM `IllegalArgumentException: UTF8 string too large` (stack:
`collectBasicMethodInfo→visitMethod→MethodWriter.<init>→addConstantUtf8→putUTF8`).

**Two failure modes — the second is dangerous:**
- whole-apk `dex2jar` → the exception propagates → **hard 0-byte jar** (obvious).
- per-dex `dex2jar` on a bombed dex → **exits 0 but silently drops** that dex's classes → a jar that *looks*
  complete but is **missing packages**. **A converter exiting 0 ≠ a complete jar — always cross-check the
  output class count against the source dex.** (Real case: a per-dex "recovery" jar had 34154 classes yet 0
  `com.infinigru`, because infinigru's dexes were the bombed ones.)

**Two variants observed in the wild (fleet sweep, 9/88 KR apps, 2026-09), each attributed by its product .so:**
- **Variant A — STEALIEN AppSuit:** native `libAppSuit.so` + `APPSUIT`/`AppSuit` strings + `STL*` classes; bomb
  `STLudc.a_stl_d2j_lock`, 65,530 params. Seen: 신한 슈퍼SOL은행, 하나원큐, 삼성 모니모.
- **Variant B — EverSafe (Everspin):** native `libeversafe.so` + `libeversafe-loader.so` (present in all 6
  Variant-B apps, absent in A/clean = clean discriminator); bomb `L<realclass>$$0;.a`, **65,534** params, no name
  marker. Seen: 부산은행, NH올원/스마트/콕/기업, 우리WON.
`detect-anti-decompile.py` catches both via the shorty-length rule (markers only add names for A).

**Precise mechanism (DEX↔JVM representational mismatch, not just "a big string"):** DEX proto params live in a
`type_list` whose `.size` is a **uint32** → far larger than JVM allows. JVM has *two* limits: method descriptor
**≤255 params** (JVMS) and `CONSTANT_Utf8` **≤65535 B** (16-bit length); dex2jar/ASM crashes on the latter but the
root is the mismatch. And the bombed method is **not callable** — DEX `invoke-*/range` arg count is 8-bit (≤255) —
so it never runs; it exists only to be walked by the converter = an **analyzer landmine / tool bomb**. (Say "ART
runs the app", not "ART invokes the 65530-param method".) See the workspace `~/Downloads/dex-anti-decompilation/`
(prior-art-and-taxonomy.md) for the broader 6–8-family taxonomy, the "Cross-IR Differential Anti-Analysis" framing,
and prior art (Balachandran 2016 CFF; Mauthe 2023 decompiler-failure study; Yang 2016 RAPID direct-DEX; OBAD).

**Do NOT mis-diagnose it as "a >64 KB string constant/embedded blob."** Verify the *actual* cause: parse the
DEX string table — if no string exceeds 65535 B, it is the descriptor bomb, not a data string. (Lesson: don't
trust an exception message's *implied* cause; measure it.)

**Detect:**
```
scripts/detect-anti-decompile.py <app.apk|app.xapk|classes.dex|dir>
#   [BOMB] descriptor bomb: <class>.<method> shorty_len=… params=…    (exit 2)
#   [MARK] anti-dex2jar name markers: a_stl_d2j_lock, STLudc, …
```
It parses proto_ids/method_ids directly (works even though dex2jar can't) and attributes the bomb to its class.

**Defeat (in order):**
1. **`jimple2cpg` reads DEX/APK directly** (Soot dexpler — no 64 KB descriptor limit). Wrap a bombed
   `classesN.dex` as a minimal apk (`zip mini.apk classes.dex`) and `jimple2cpg mini.apk --output cpg.bin`,
   or point it at the whole apk. This is the clean carve path; use the sdk-carve queries on the CPG.
2. **direct-dex presence scan** — raw `grep` of `classesN.dex` for SDK package roots / hosts. Reliable for
   the inventory question ("which SDKs ship") without any conversion.
3. **strip the bomb** — remove the `STLudc`/`a_stl_d2j_lock` class from the dex, then dex2jar the remainder.

## Family 2 — exception-table flattening + irreducible flow (anti-decompiler)
**What:** the method's dalvik has few tries, but its control flow is **irreducible** (backward GOTOs into
finally-ladders = fake do-loops) with catches structured so that after `dex2jar` the `.class` exception table
**explodes to hundreds/thousands of rows** funnelling into a few shared `ASTORE;GOTO` handler stubs, many
guarding non-throwing code. `dex2jar` *succeeds*; the **decompilers** then fail: CFR `ConfusedCFRException
TRYBLOCK`, Vineflower/Fernflower `FinallyProcessor` IOOBE, jadx "Method not decompiled", Corpseflower
`--deobfuscate` fails. Real case: Coocon `ScriptManager.updateScript` — **<13 dalvik tries but 819–1033 .class
exception-table rows.**

**Detect (post-conversion — it has almost no DEX footprint, so DEX try-count is the WRONG signal):**
```
scripts/check-flattening.sh <Class.class | scoped.jar> [rows_threshold=100]
#   [FLAT] exception-table-rows=819  ...  updateScript(...)
```
Authoritative signal = **one method with hundreds+ `javap` exception-table rows AND every stock decompiler
fails on it** (a normal method has single digits). Confirm by actually running a decompiler and watching it
fail on exactly that method.

**Defeat:** `../sdk-carve/scripts/ExFlattenNormalize.java` (ASM) — passes `--redundant` (drop traps that
can't throw), `--split` (node-split terminal cleanup blocks reached by backward GOTOs → CFG reducible),
`--unify` (collapse handlers onto one try + multi-catch); strip Java-6 frames + `COMPUTE_MAXS`. Then
`cfr.jar Class_norm.class` decompiles clean (0 failures). Add flags incrementally and watch the CFR error
evolve `TRYBLOCK→UNCONDITIONALDOLOOP→DOLOOP→success`. Always cross-check recovered source vs raw `javap -c`.

## Key insight — the DEX↔JVM impedance mismatch
Both families exploit **places where DEX is more permissive than the JVM class file**: DEX has an unbounded
parameter `type_list` (→ descriptor bomb) and a more flexible try/handler + control-flow model (→ flattening
that only detonates on `.class` reconstruction). So the robust move is to **avoid the round-trip through
`.class`**: **Soot-based `jimple2cpg` parses dalvik directly and is immune to both** (proven — it carved a
bombed dex and CPG'd a flattened method where dex2jar/CFR failed). Prefer it whenever these constructs appear.

## Detection is tool-specific → diversify tools
These tricks target *named* tools (`a_stl_d2j_lock` literally names dex2jar). A construct that defeats one tool
often passes another. Always keep an independent second path (dex2jar ↔ jimple2cpg-direct; CFR ↔ jadx ↔
Vineflower) and treat a single tool's failure/exit-0 as a lead, not a verdict.

## Files
- `scripts/detect-anti-decompile.py` — DEX parser: finds descriptor bombs (huge-shorty protos) + anti-d2j name
  markers, attributes each to its class.method. Handles apk/xapk/dex/dir. Exit 2 on hit.
- `scripts/check-flattening.sh` — post-conversion: `javap` per-method exception-table row count on a
  `.class`/jar; flags methods over a threshold (= flattening candidates; confirm with a failing decompiler).
- Defeat tools live in the sibling **sdk-carve** skill: `ExFlattenNormalize.java` (flattening) and the
  `carve.sh` / `jimple2cpg` path (bomb). This skill is the *identify + route to the right defeat* layer.

## Worked example (2026-09, KR banking fleet)
- 슈퍼SOL은행 (`com.shinhan.sbanking`): descriptor bomb `STLudc.a_stl_d2j_lock` in 11/19 dexes → `detect-anti-
  decompile.py` = 19 BOMB hits; dex2jar 0-byte / per-dex silently drops → carve via jimple2cpg-direct.
- 신한투자증권 / 신한 SOL저축은행 (Coocon `sasapi`): `updateScript` flattening → `check-flattening.sh` = 819 / 1033
  rows → defeated with `ExFlattenNormalize` → CFR clean; protocol recovered at source level.
- See `analysis/reports/SHINHAN_SDK_CARVE.md` (ROADMAP G-9) for the full trail.
