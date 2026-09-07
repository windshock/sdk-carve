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
  / capability questions, AND for the upstream triage of a whole host app: "does this
  app contain a malicious SDK", "is this app infected / does it phone home", "find and
  behavior-analyze embedded spyware/adware SDKs in <app> — family-agnostic, or against
  known families (Goldoson, SpinOk, Konfety, MobiDash)", "acquire an APK
  and verify its signer for analysis". Triggers — "analyze this SDK embedded in the app", "scope a
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

## Triage a new host app (acquire → generic sweep → carve decision)

For "does app X have a malicious SDK, and what does it do" the carve is the *deep* pass
that produces the behavior verdict. The sweep steps only decide WHERE to carve; they are
family-agnostic until a family is actually identified.

1. **Acquire + verify.** `python3 research/acquisition/resolve.py <package>
   [--allow-download]` — the `apkeep`/APKPure adapter is the tested path; it emits a
   normalized record with sha256 + signer SHA-256. Compare the signer against the app's
   other versions (mismatch = repackaged mirror). Downloads are auth-gated: never pass
   `--allow-download` without the user's OK; a user-supplied official-channel APK beats
   a mirror.
2. **Generic behavior sweep (no family knowledge needed).** `d2j-dex2jar app.apk` then
   `scripts/behavior-sweep.py app-dex2jar.jar` — clusters un-renameable capability-API
   hits per package root and flags collector+sink shapes. Known ad/analytics SDKs are
   annotated `~`; sharp small roots (1–2 packages, 4+ categories) are usually
   R8-scattered pieces of ONE SDK — reassemble them with step 3's structural detection.
3. **Known-family checks (one signal, not the answer).** `scripts/ioc-sweep.sh` (hardcoded
   Goldoson C2 hosts across the whole bytecode) + `scripts/detect.py` (exact renamed
   Goldoson root, with a structural WiFi∩BT fallback). If the container looks packed
   (`aapt` says "corrupt", tiny decoy dex), run the pre-carve stage below FIRST.
4. **Carve every non-`~` flagged root and run the FULL Method below — no tiering.**
   "It's an identified commercial SDK" is NOT a reason to skip analyzers: every carve
   gets Joern inventory + entry→sink reachability, CodeQL source DB, Semgrep, and
   scope-closure. The behavior report MUST contain a cross-verification table
   (analyzer × root) and the closure result. Slow steps (reachability on big CPGs,
   CodeQL DB) run in background — a report issued before they finish is *provisional*
   and must say so, then be amended. Never call an app "clean" from the sweeps alone:
   the sweeps find collection/exfil *shapes*; a negative means "no flagged shape", and
   the report must say so under the evidence rules.

Example: OK캐시백 `com.skmc.okcashbag.home_google` (7.1.9), 시럽
`com.skt.skaf.OA00026910` (5.8.16_M) — both acquired + fully analyzed 2026-09
(see `analysis/reports/OKCASHBAG_SDK_TRIAGE.md`, `SYRUP_SDK_TRIAGE.md`).

### Field notes (validated on a 104k-class KR commercial app, 2026-09)

- **dex2jar OOMs at default heap on big apps** → `_JAVA_OPTIONS=-Xmx6g d2j-dex2jar …`.
- **apkeep**: probe `apkeep --list-versions -a <pkg>` BEFORE downloading; KR-only apps
  often have zero versions on APKPure/Uptodown/apkcombo — don't rabbit-hole, ask the
  user for an official-channel APK into `research/acquisition/corpus/targets/`.
- **Fast deep pass first, but never last**: after carve, `scripts/class-map.py` maps
  per-class APIs+endpoints in seconds — use it to steer, not to conclude. The FULL
  analyzer set (Joern + CodeQL + Semgrep + scope-closure) is mandatory per carve; see
  triage step 4.
- **Joern**: run each carve's `joern --script` from THAT carve's directory — concurrent
  runs sharing a cwd collide on the workspace project name and cross-load CPGs.
  `repeat(_.callee)` reachability on a ~4k-method CPG can take 10+ min → background it.
- **CodeQL**: decompile the scoped JAR directly (`jadx --no-res -d src scoped.jar`);
  qlpack.yml needs modern syntax `dependencies: { codeql/java-all: ^9.x }` (version via
  `codeql resolve packs`); `codeql query run` prints a TABLE — match `\| SRC`/`\| SINK`,
  not `^(SRC|SINK)`.
- **Semgrep scoped works** on jadx output (it was whole-tree scans that historically
  broke on decompiler syntax). Regex rules see through runtime string decryption that
  name-matching analyzers miss — treat analyzer disagreement as a lead, root-cause it.
- **Custom string encryption evades packer-detect** (Toss 5.276.0, 2026-09): valid dex
  magic + no known-packager signature, yet per-10MB-dex `Lcom/` descriptor counts of
  1–10 (normal: tens of thousands) and a near-empty AndroidManifest string pool = full
  DEX+manifest string encryption by an in-house obfuscator. Before trusting a "0 hits"
  IOC sweep, ALWAYS run a positive control (grep `androidx`/`Landroid`/the host's own
  name) on the exact artifacts you scanned. When dex is void, fall back to surfaces
  string-encryption doesn't cover: `resources.arsc` (SDK resource-name prefixes are
  mandatory for library SDKs — a positive control there, e.g. the host's own strings,
  makes a zero-hit for the target SDK's prefix strong negative evidence) and confirm
  with the vendor's docs what components/resources an integration must ship.

### Vendor attribution & server-script triage (validated on GPA GAD/BeanShell in Syrup 5.8.16, 2026-09)

1. **Attribute the vendor before judging behavior** — "obfuscated KR adtech" is not an
   identity. Chain: log tags / resource prefixes (`GPADEV`, `gad_sdk_*`) → host-app
   Gradle coordinates (`libs.versions.toml`, private forks: `com.github.<org>:<repo>:<tag>`)
   → GitHub orgs (vendor may keep TWO orgs: one for JitPack deploy, one for samples/docs) →
   **JitPack leaks**: `https://jitpack.io/api/builds/com.github.<org>/<repo>` lists every
   built tag publicly, and `.aar` + `build.log` stay downloadable for tags built while the
   repo was public — even after the repo went private (GitHub 404). The AAR gives
   pre-host-R8 code with real names; **base URLs usually live in string resources**
   (`res/values/values.xml`: `…_url_live`/`…_url_dev`), not class constants. POM = declared
   deps (e.g. `org.beanshell:bsh:2.0b5`); build.log = internal publication coords + R8 mode.
2. **Cross-check binary ↔ public spec 1:1** (docs site, sample repo's `api-doc.md`):
   Retrofit paths, param names, identifier collection (widevine/android_id/imei), and note
   version skew (app pins v3.x line, docs describe v5). Separate same-function SDKs by
   **cross-reference counts** (com/gad ↔ adison hosts: 0 refs = different vendors); a
   copy-pasted comment in host code (`PREF_GAD_UID // Adison UID`) is red herring, not lineage.
3. **Server-controlled script channels: capture → dedupe → replay.** With explicit user OK
   (AGENTS.md domain rule): GET-only documented read endpoints, app/media key only (no
   uid/adid/identifiers), no state-changing POST/DELETE, cap retries. Dedupe by sha256
   (848 → 38 here) — replay output is a pure function of script content, so cluster
   representatives are full coverage; prove it once with a 3-member dup-check. Capture
   provenance (dates, request counts, codes, no-identifier pledge) in a corpus README.
   Expect undeliberated surprises: multi-tenant script channels (other client apps'
   package names in comments), undocumented enum values, shipped dev-tunnel URLs.
4. **Dynamic replay without an emulator** — `analysis/bsh-sandbox/`: JDK 17 only
   (SecurityManager is dead in 24) + the SDK's OWN interpreter artifact (match the APK's
   class count to the Maven jar) + real-package stub classes that log every call.
   Order matters: `eval(script)` THEN bind (top-level typed declarations like
   `Context cat;` reset variables — the SDK sources first, sets after), then invoke the
   observed hooks; rewrite captured domains `.invalid`. Record NET/EXEC/EXIT/FILE-W/
   LINK denies + `checkPackageAccess` + SM-tamper + stub-call events as JSON; keep
   rawlogs (bsh EvalError messages are truncated — stack traces go in the rawlog).
   Reusable beyond BeanShell for any server-supplied script channel.
5. **"Vulnerable version pinned" ≠ "reachable".** For CVEs on embedded libs
   (CVE-2016-2510 / bsh ≤2.0b5), verify attack preconditions across the WHOLE app:
   deserialization sinks (XStream/XMLDecoder/Kryo/ScriptEngineManager/Jackson
   defaultTyping), known gadget-chain libraries, external refs to the gadget class.
   All-zero → report as hygiene/latent-amplifier, and state the direct path separately
   (a server-driven eval channel IS arbitrary-exec-by-design; its risk framing is
   vendor-backend integrity, not the CVE).


## Pre-carve (stage 0 — packer ID, container normalization & payload discovery)

**First, identify the protector — a bytecode carve on a packed/shielded app silently
under-scopes.** `scripts/packer-detect.py <app.apk>` fingerprints the packer / app-shielder /
obfuscator (native `.so` names, asset paths, dex package markers; merges APKiD if installed)
against a catalog derived from [awakewiki.org/packers](https://awakewiki.org/packers/) + APKiD
+ first-party reverse findings, and — crucially — reports the **carve-impact**:

- exit `0`  — no packer / obfuscation-only → **carve is VALID** (proceed).
- exit `10` — strings encrypted (e.g. DexGuard) → carve **structure** now; IOC/endpoint sweep is
  **unreliable** until unpacked/dynamically dumped.
- exit `20` — real code is in a runtime-decrypted **payload DEX** (e.g. NSHC xShield/DxShield,
  AppSealing, 360 Jiagu, Bangcle, Tencent Legu) → a bytecode carve of `classes.dex` is **BLIND**;
  recover the payload first (pre-sealed build or sanctioned dynamic dump), then carve *that*.
- exit `30` — **UNKNOWN/suspicious** packer indicators (stub dex over an encrypted payload) → a
  custom/malware packer; identify + unpack before trusting any verdict.

This closes the gap `apk-normalize.py` can't see: a commercial shielder repackages into a *valid*
ZIP (aapt/apktool are happy) yet encrypts strings and/or hides the real code in a runtime DEX —
so the app looks carveable but the carve is a false negative. Worked example: OK Cashbag /
xShield in [`docs/PACKER_DETECT.md`](../../../docs/PACKER_DETECT.md).

Then, if `aapt`/`apktool` say the manifest is "corrupt", or `classes.dex` is tiny/decoy, the APK
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

- `scripts/packer-detect.py` — pre-carve stage 0: identify the packer/app-shielder/obfuscator
  (AWAKE catalog + APKiD + first-party sigs) and report carve-impact (VALID / strings-encrypted /
  payload-DEX-blind / unknown-packer); gates whether a bytecode carve can be trusted
- `scripts/apk-normalize.py` — pre-carve: repair a tampered/evasive APK ZIP (fake enc flag,
  bogus method, size lies) so tools parse it; flags decoy dex + packed assets
- `scripts/konfety-unpack.py` — pre-carve payload stage (Konfety family): inflate + XOR
  (`java.util.Random`, seed = asset-name + 0xFFFF) → inner ZIP → real `classes.dex`
- `scripts/mobidash-unpack.py` — pre-carve payload stage (MobiDash family): signing-cert →
  SQLCipher passphrase → bootstrap DEX + XOR-decrypted module jars (multi-layer example)
- `scripts/detect.py` — auto-locate an R8-renamed SDK root (method-name anchors +
  size/depth/denylist guards + structural fallback); prints carve globs
- `scripts/behavior-sweep.py` — family-agnostic triage: capability-API clusters per
  package root, flags spyware-shaped collector+sink roots; `~` = known ad/analytics prefix
- `scripts/ioc-sweep.sh` — multi-family sweep (Goldoson/SpinOk/Konfety/MobiDash/
  NecroCoral): C2 hosts + package anchors + structural markers (known-family signal)
- `scripts/class-map.py` — per-class capability-API + endpoint mapping on a carved
  mini-JAR (seconds; the fast deep pass before Joern/CodeQL)
- `analysis/bsh-sandbox/` (workspace) — JVM replay harness for captured server-side
  BeanShell/scripts: JDK 17 + SecurityManager (NET/EXEC/EXIT/FILE-W deny + class-load
  log) + real-package stub classes; `eval → bind → hook replay` in the SDK's own bsh
  version, domains rewritten `.invalid`. Run: `java -cp classes:bsh-<ver>.jar
  BshSandbox <script.bsh> <out.json>`. See analysis/reports/GAD_BSH_SANDBOX_RUN.md
- `scripts/carve.sh` — mini-JAR + `jimple2cpg` (parameterized by package globs); builds the
  jar in-memory so obfuscated `j.class`/`J.class` siblings survive a case-insensitive FS
- `scripts/source-sink.sc` — Joern source/sink inventory + entry→sink reachability
- `scripts/scope-closure.sc` — reverse dependency trace / scope-completeness proof
- `queries/flows.ql` — CodeQL source/sink template (name-matched, `build-mode=none`-friendly)
- `scripts/native-cpg.sh` — native binary → CPG via `ghidra2cpg` (native track)
- `scripts/native-inventory.sc` — imported-API surface + native sinks + JNI entry points

Edit the `EDIT:`-marked lines (package prefixes, source/sink method names, entry points)
for your target. The Goldoson/SMARTLB defaults are left in as a worked example.
