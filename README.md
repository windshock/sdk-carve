# sdk-carve

**Carve one embedded SDK out of a huge, decompiler-damaged Android app and analyze it
with scoped, tool-verified static analysis — where whole-app CPG/CodeQL fails.**

This repo is a *method* plus a fully worked *case study* (the Goldoson/SMARTLB
advertising/spyware SDK). It shows that the classic "Joern CPG and CodeQL are
impossible on decompiled Android at this scale" outcome was never a tool limitation —
it was a **methodology** problem: running whole-application analysis over tens of
thousands of damaged decompiled files. Scope to the target subgraph and the same tools
finish in seconds.

## The problem

A large Android app decompiles to ~27k Java files / ~50k classes / several GB, with
`??` placeholders and `Method not decompiled` stubs scattered through it. Point Joern
or CodeQL at the whole thing and:

- Joern's whole-JAR CPG grows to ~2 GB and never finalizes.
- CodeQL (old Java extractor) requires a build; decompiled, dependency-less, damaged
  code never compiles → the database never finalizes.
- Source parsers (Semgrep, source-based CPG) choke on the damaged syntax.

## The method (sdk-carve)

1. **Scope to a self-contained subgraph.** Find the target's own packages plus its
   non-library dependencies by *reference closure*, and cut at the library/framework
   boundary. Don't analyze the whole app.
2. **Match the frontend to the least-damaged representation.** Decompiled / obfuscated
   / no-source → use **bytecode** (`jimple2cpg`), not source. Damaged Java syntax is
   irrelevant because the bytecode is intact.
3. **Treat framework/library calls as boundary stubs**, and place sources/sinks there.
4. **Cross-verify with independent methods** — manual read + bytecode CPG (Joern) +
   source DB (CodeQL). Agreement = confidence; disagreement = signal.
5. **Prove scope completeness** with a reverse dependency trace (closure), so "nothing
   was missed" is demonstrable, not assumed.
6. **State the limits honestly** — flow *through* a stub needs models; static ≠ runtime.

## Results on the case study (Goldoson/SMARTLB)

Target scoped from **50,157 classes → 117** (the SDK's `com.smart.sklb.edge` +
obfuscated `bg`/`cg`/`dg`, = 59 `.java`):

| | Whole-app (historical) | Scoped (this method) |
|---|---|---|
| Joern CPG (`jimple2cpg`) | 2.0 GB tmp, never finalized | **538 KB, finalized in ~2.2 s** (893 methods) |
| CodeQL DB | 3 databases, none finalized | **finalized, 4,825 LOC** (`--build-mode=none`) |
| Query | — | source/sink inventory in **0.66 s** (21 sources, 9 sinks) |
| Reachability | — | `onStartJob` → every network + WebView sink |

Three independent methods (manual, Joern/bytecode, CodeQL/source) recover the same
source/sink set. Where they differ is instructive: the bytecode CPG resolved GPS and
advertising-ID external calls that the source-only DB left unresolved — so the tracks
are complementary.

### What the SDK does (all `binary-confirmed`)

A persistent, reboot-surviving background `JobService` pulls server-controlled config
from `bhuroid.com` and, when server flags allow, collects **ad ID, Android-ID-derived
UUID, HmacMD5 of Wi‑Fi/P2P MAC, installed-app list (with add/delete diff), precise
GPS, connected + nearby Wi‑Fi, bonded + nearby Bluetooth, carrier, and device state**,
uploading them via `putCol` to `bhuroid.com`. It also fetches ad HTML and executes it
in a JavaScript-enabled WebView created off-screen from the background service. A guard
**aborts collection when a packet-capture / network-analysis app is installed** (SSL
Capture, tPacketCapture, IP Tools, Network Scanner, Net Utils) — deliberate
anti-analysis. See [`analysis/reports/`](analysis/reports/) for the full,
evidence-cited trace.

## Repo layout

```
README.md                       this file
REPRODUCE.md                    regenerate everything from the public sample
AGENTS.md                       analysis conventions + evidence-labeling discipline
docs/                           case-study knowledge (overview, evidence map, status)
analysis/reports/               the deliverables:
  ANALYSIS_PLAN.md              the 3-track plan + why the old approach failed
  TRACK3_DATAFLOW.md            manual AI dataflow model (sources→sinks, guard decrypt)
  TRACK1_CPG.md                 scoped jimple2cpg CPG + reachability
  TRACK2_CODEQL.md              scoped CodeQL build-mode=none + query
  SCOPE_VERIFICATION.md         reverse-trace proof the 59-file scope is complete
  TRACK_NATIVE.md               native track (ghidra2cpg) — method extension demo
  SUMMARY.md                    one-page summary
analysis/joern/scripts/         edge-taint.sc, scope-check.sc, scope-detail.sc
analysis/codeql/queries/        edge_flows.ql (+ qlpack.yml)
analysis/codeql/results/        edge_flows.csv (findings)
```

Derived/large artifacts (the decompiled corpus, the mini-JAR, the CPG, the CodeQL DB)
are **not tracked** — they are regenerated from the sample. See **[REPRODUCE.md](REPRODUCE.md)**.

## Sample

The Goldoson sample is available separately (e.g.
<https://github.com/IHbib/goldoson-samples>). This repo intentionally does not include
the app corpus; `file:line` citations in the reports resolve against a JADX export of
the sample (see REPRODUCE.md).

## When it applies / where it breaks

Works well for: embedded SDKs/libraries inside big apps, a small target inside a huge
codebase, decompiled/obfuscated JVM bytecode, and source→sink / reachability /
capability questions.

Extends to **native code** (`.so`/`.dll`/`.exe`) via the ghidra2cpg native track — same
shape (scope → lift → inventory → verify), different frontend; see
[`analysis/reports/TRACK_NATIVE.md`](analysis/reports/TRACK_NATIVE.md).

Needs adaptation or breaks for: **reflection / dynamic loading** (defeats static closure —
the completeness proof must be re-checked per target), targets with **no clean package
boundary**, **framework-mediated dataflow** (always needs models), and anything that is
truly a **runtime** question.

## Credits

Goldoson was originally documented by McAfee Labs. This repo is defensive
security-research analysis; behavior here is static (`binary-confirmed`) unless a
controlled runtime test is stated.
