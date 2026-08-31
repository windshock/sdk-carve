# Goldoson/SMARTLB re-analysis — summary of the 3-track run

Author: AI agent (Claude Opus 4.8, 1M context)
Date: 2026-08-31
Plan: `analysis/reports/ANALYSIS_PLAN.md`. Tracks executed in order 3 → 1 → 2.

## Outcome in one line

The analyses that "failed" years ago (Joern CPG, CodeQL) now **succeed** — because the
failure was never really about the tools, it was about running whole-application
static analysis over 27k damaged decompiled files. Scoped to the ~59-file target and
run with modern frontends (jimple2cpg over bytecode, CodeQL `build-mode=none`), both
finalize in seconds, and a modern-LLM read of the same subgraph produces a precise,
tool-cross-verified dataflow model.

## What was produced

| Track | Deliverable | Result |
|---|---|---|
| **3 — AI dataflow** | `TRACK3_DATAFLOW.md` | Full source→transform→sink model with `file:line` evidence; decrypted the 5 anti-analysis guard packages; bytecode-confirmed the 2 undecompilable methods |
| **1 — Scoped CPG** | `TRACK1_CPG.md`, `analysis/joern/projects/edge-scoped/cpg.bin`, `analysis/joern/scripts/edge-taint.sc` | CPG **finalized in ~2.2 s / 538 KB** (vs. historical 2 GB never-finished); `onStartJob` → every network + WebView sink is call-graph reachable |
| **2 — Scoped CodeQL** | `TRACK2_CODEQL.md`, `analysis/codeql/databases/edge-scoped/`, `analysis/codeql/queries/edge_flows.ql`, `analysis/codeql/results/edge_flows.csv` | DB **finalized (4,825 LOC)** (vs. 3 historical incomplete DBs); query recovers 21 source + 9 sink calls in 0.66 s |

## The core finding (all `binary-confirmed`)

A persistent, reboot-surviving background `JobService` (`wepkr_luhFzJx`, job `159294`,
process `:smartlbp_dv`) pulls **server-controlled config** from `bhuroid.com` and, when
the server flags allow, collects **ad ID, Android-ID-derived UUID, HmacMD5 of Wi‑Fi/P2P
MAC, installed-app list (with add/delete diff), precise GPS, connected+nearby Wi‑Fi,
bonded+nearby Bluetooth, carrier, and device state**, then uploads them via `putCol` to
`bhuroid.com`. It also fetches ad HTML via `getPdata` and **executes it in a
JavaScript-enabled WebView created off-screen from the background service**. A guard
**aborts collection when a packet-capture/network-analysis app is installed**
(`app.greyshirts.sslcapture`, `com.ddm.iptools`, `com.myprog.netscan`,
`com.myprog.netutils`, `jp.co.taosoftware.android.packetcapture`).

## Why it works now (and didn't before)

1. **Scope, don't boil the ocean.** The answer lives in ~59 files / <6k LOC already
   mapped in `docs/EVIDENCE_MAP.md`. Feeding the whole app was the root cause of both
   the 2 GB CPG and the never-finalizing CodeQL DBs.
2. **Use bytecode where source is damaged.** `jimple2cpg` reads the JAR/class bytecode,
   so `??` / `Method not decompiled` are irrelevant; the two undecompilable methods are
   fully present and queryable.
3. **Modern frontends removed the old blockers.** CodeQL `build-mode=none` drops the
   compile requirement that killed every historical DB.
4. **A 1M-context LLM can read the whole target** and drive the tools + queries — the
   thing that wasn't possible at the time.

## Cross-verification (three independent methods agree)

Track 3 (manual), Track 1 (Joern/bytecode), and Track 2 (CodeQL/source) independently
recover the same source and sink set. Where they differ is instructive: Joern's
bytecode CPG additionally resolved GPS and advertising-ID external calls that CodeQL's
source-only DB left unresolved — so the two tool tracks are complementary, and the
combination is what gives high confidence.

## Known limits / optional follow-ups

- Byte-precise source→sink taint returns 0 in both tools because data crosses
  `SharedPreferences` and DTO constructors; recovering full paths needs explicit flow
  **models/semantics** (CodeQL taint steps or a Joern `semantics` file).
- `runtime-confirmed` behavior (does the live backend return active collect/ads
  payloads or non-empty ad HTML) needs **Track 4**: isolated emulator + sinkhole, never
  contacting the embedded domains — gated on explicit authorization per `AGENTS.md`.

## Environment note

Homebrew's `joern`/`jimple2cpg` launcher defaults `JAVA_HOME` to the newest OpenJDK
(Java 25 = class major 69), which Soot's ASM rejects. Pin `JAVA_HOME` to JDK 17
(Temurin 17 present) for both jimple2cpg and CodeQL runs.
