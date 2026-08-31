# Goldoson/SMARTLB re-analysis plan

Author: AI agent (Claude Opus 4.8, 1M context)
Date: 2026-08-31
Status: Plan only — not yet executed. Review before running any track.

This plan supersedes the "whole-application static analysis" approach that failed
historically. It does not delete or modify any prior evidence. All new outputs go
under `analysis/reports/` and `analysis/<tool>/scripts/` per `AGENTS.md`.

---

## 1. Analysis question (unchanged)

What does the embedded Goldoson/SMARTLB SDK (`com.smart.sklb.edge` + obfuscated
`bg`/`cg`/`dg`) collect, how does it transform it, and where does it send it —
including the background-service hidden-WebView path — with each material claim
labeled `binary-confirmed` / `runtime-confirmed` / `not-confirmed` and anchored to
`docs/EVIDENCE_MAP.md`.

## 2. Why the historical whole-app approach failed

Confirmed from the surviving artifacts and `docs/ANALYSIS_STATUS.md`:

| Failure | Root cause |
|---|---|
| Joern `dex2jar-incomplete` = 2.0 GB `cpg.bin.tmp`, never finalized | Whole 53 MB / ~50k-class JAR ingested at once → unbounded CPG |
| CodeQL databases (3) never finalized | Java extractor required a build; decompiled deps + invalid methods never compiled; Android SDK polluted baseline; one baseline had 0 LOC |
| Semgrep whole-tree scan failed | Decompiler-damaged Java syntax (`??`, `Method not decompiled`) breaks source parsers across the tree |

Two structural causes:

1. **Scale** — the target was the whole app: 26,980 Java files / 50,893 classes / 4.9 GB. Source-based static-analysis frontends cannot swallow that whole.
2. **Damaged source syntax** — decompiled Java contains `??` placeholders and `Method not decompiled` stubs, which choke source parsers and any compile step.

A third, non-tool cause: at the time, the AI could not author reliable CodeQL/Joern
queries or hold the target in context.

## 3. What is different now (verified 2026-08-31)

| Fact | Consequence |
|---|---|
| Target is tiny: `com.smart.sklb.edge` = **49 files / 5,158 LOC**, only **2** files with `Method not decompiled`; plus `bg`(7)/`cg`(2)/`dg`(1) ≈ **59 files, <6k LOC** | The analysis question is answerable from a small, already-mapped subgraph. No whole-app pass is needed. |
| Bytecode evidence present: `artifacts/derived/tmap-dex2jar.jar` (53 MB) contains **112** `com/smart/sklb/edge` classes | Bytecode stays syntactically valid where decompiled Java is damaged. |
| Tooling is current: `joern` + **`jimple2cpg`**, **CodeQL 2.26.3** (supports `--build-mode=none`), `semgrep`, `jadx` 1.5.2, JDK 17 | `jimple2cpg` (bytecode→CPG) sidesteps damaged syntax; CodeQL `build-mode=none` removes the compile requirement. Both historical failure causes are addressable at the tool level. |
| Agent context window = 1M tokens | The full <6k-LOC target subgraph fits in context for direct, precise dataflow tracing. |

**Reframe:** the CPG/CodeQL failures were a *scale + damaged-source* problem on the
whole app. Scope hard to the mapped subgraph, use **bytecode** where source is
damaged, and treat CPG/CodeQL as **verification** of an AI-built dataflow model
rather than the primary discovery engine.

## 4. Plan — three tracks

### Track 1 — Scoped CPG via bytecode (`jimple2cpg`)  [direct rebuttal of the past failure]

Goal: prove a CPG now *finalizes* and produces taint paths.

1. Build a mini-JAR from `tmap-dex2jar.jar` containing only `com/smart/sklb/**`,
   `bg/`, `cg/`, `dg/`, and the Retrofit/OkHttp interface classes they reference.
2. Run `jimple2cpg mini.jar -o analysis/joern/projects/edge-scoped/cpg.bin`.
   Bytecode input → immune to `??` / `Method not decompiled`; ~112 classes → seconds
   and MBs, not a 2 GB stall.
3. Joern queries:
   - Sources: advertising ID, Android ID, `getInstalledApplications`, `WifiInfo`,
     `BluetoothAdapter`, telephony/carrier, battery/timezone.
   - Sinks: Retrofit `@POST`/`putCol()`, OkHttp calls, `WebView.load*`.
   - Reachability + taint from each source class to each sink.
4. Output: `analysis/joern/scripts/edge-taint.sc` + results note in `analysis/reports/`.

Success criterion: a finalized `cpg.bin` (not `.tmp`) plus at least the known
identifier→Retrofit and remote-HTML→WebView flows recovered.

### Track 2 — Scoped CodeQL (`--build-mode=none`)  [reproducible, defensible artifact]

1. Copy only target-package `.java` into a clean `analysis/codeql/src-scoped/`
   (exclude Android SDK; stub or omit the 2 damaged edge files).
2. `codeql database create --language=java --build-mode=none` on that scoped tree —
   no Gradle/JDK build.
3. Author taint-tracking queries (sources/sinks per Track 1) under
   `analysis/codeql/queries/`; optionally run the standard Java security pack scoped
   to this DB.
4. Output: finalized scoped DB + `.ql` queries + CWE-mapped findings.

Success criterion: a DB that finalizes (unlike the 3 historical ones) and answers
the source→sink queries. Run only if a reproducible/defensible artifact is wanted.

### Track 3 — AI-native dataflow model  [fastest, tool-independent; the newly-possible path]

1. Read the full ~59-file subgraph; resolve obfuscated names (`bg`/`cg`/`dg`,
   `nepkt_*`, `wepkr_*`) into a named component/dataflow model.
2. Trace source → transform (compress/hash) → sink → trust boundary by hand,
   following `docs/EVIDENCE_MAP.md` anchors.
3. For the 2 `Method not decompiled` edge methods (and any ambiguous reflection),
   cross-check against the JAR via `javap` disassembly.
4. Output: evidence-cited flow report in `analysis/reports/`, every claim labeled
   `binary-confirmed` / `not-confirmed`.

### Convergence / verification

Cross-check Track 3 (AI model) against Track 1/2 (tool taint). Agreement → high
confidence. Tool-blind spots (reflection, obfuscation, WebView JS bridge) are filled
by AI + bytecode. Semgrep targeted taint (`analysis/semgrep/`, already parse-clean on
the 49-file set) as a cheap third cross-check.

### Track 4 (optional, gated) — dynamic validation

Only on explicit authorization: isolated emulator + sinkhole/mock endpoints, never
contacting `bhuroid.com` / `kialant.com`. Converts key `not-confirmed` flags to
`runtime-confirmed`. Per `AGENTS.md` safety rules.

## 5. Recommended sequence

1. Track 3 → fast answer + a checklist of flows to verify.
2. Track 1 → prove the CPG finalizes and confirm taint paths.
3. Track 2 → only if a reproducible query artifact / CWE mapping is needed.
4. Track 4 → only if runtime confirmation is authorized.

## 6. Guardrails

- Treat `artifacts/`, `corpus/`, and historical `analysis/` results as read-only.
- Do not delete or overwrite failed/partial results; archive under `legacy/` if
  superseded.
- New scoped JAR/CPG/DB are *derived* artifacts — label as such; do not present them
  as original evidence.
- Do not contact embedded domains or run the sample dynamically without explicit
  authorization and an isolated test plan.
