# Baseline (whole-app) vs carved — metrics (issue #5 RQ1/RQ2/RQ3 + completeness)

Empirical support for the R-Droid distinction (`docs/RELATED_WORK.md` §B1). Harness:
`research/metrics.sh` (timing/RAM), `research/completeness_run.sh` + `research/cq.sc`
(jimple2cpg target-presence), and `research/completeness.ql` (CodeQL target-presence),
whole-app vs in-memory case-preserving carve. **Setup:** Apple Silicon, 16 GB, JDK 17;
**two analyzers** — Joern jimple2cpg (11 apps, TMAP + 10 Goldoson batch, 7.7k–59.7k classes)
and CodeQL 2.26.3 `build-mode=none` (TMAP cross-check).

## Headline — whole-app CPG is silently *incomplete* (completeness)

The most important result. A whole-app CPG that **builds fine** does not mean the target is
in it. jimple2cpg retains a **bounded ~9–16k typeDecls regardless of input size** (12,778 for
a 50k-class app), keeping mostly heavily-referenced libraries and **silently dropping the
rest — including, on most apps, the entire target SDK.** No error/warning is emitted;
`--full-resolver` does not change it.

Target-SDK methods present in the CPG (whole-app vs carved), and SDK-own sink call-sites
(`putCol`/`getBConfig`/`getPdata`/`userJoin`):

| app | input cls | whole-app SDK methods | whole-app own-sinks | carved SDK methods | carved own-sinks |
|---|--:|--:|--:|--:|--:|
| com.skt.tmap.ku | 50157 | **0** (0%) | **0** | 557 | 6 |
| com.Monthly23.SwipeBrickBreaker | 13974 | **0** | **0** | 895 | 8 |
| com.gretech.gomplayerko | 59668 | **23** (2%) | **0** | 1349 | 9 |
| com.megabox.mop | 42702 | **0** | **0** | 1457 | 9 |
| com.somcloud.somnote | 58431 | **0** | **0** | 909 | 8 |
| kr.co.lottecinema.lcm | 16620 | **0** | 0\* | 1230 | 0\* |
| kr.co.psynet | 33786 | **0** | **0** | 910 | 8 |
| com.appsnine.audiorecorder | 11677 | 551 (96%) | 9 | 574 | 6 |
| com.appsnine.compass | 12385 | 726 (97%) | 9 | 749 | 6 |
| com.wtwoo.girlsinger.worldcup | 25137 | 757 (100%) | 8 | 757 | 8 |
| mafu.driving.free | 7783 | 695 (100%) | 8 | 695 | 8 |

**On 7 of 11 apps the target SDK is effectively absent from the whole-app CPG** (0–2% of its
methods; **0 SDK sinks → detection returns nothing, a false negative**). On 4/11 it survives.
**The carved CPG contains 100% of the SDK on all 11** (by construction) → detection always
works. (\*lottecinema renamed the SDK's own method names, so own-sinks=0 even carved; the
method-count metric still shows 0 vs 1230.)

Verified end-to-end on TMAP: the whole-app CPG (built at 12 GB) runs the detection script in
60 s and reports **0 sources / 0 sinks / 0 flows**; a direct probe confirms `smart.sklb`,
`SMARTLB`, `wepkr`, `nepkt_hrn`, `bhuroid` are **all absent** (not renamed — dropped).

### Root cause (confirmed): a silent, order-dependent ~12.8k-class cap in jimple2cpg

Controlled test — the **same 30,117-class jar**, only the entry **order** changed:

| SDK classes written | typeDecls | SDK methods in CPG |
|---|--:|--:|
| **first** | 12,761 | **557 (present)** |
| **last** | 12,778 | **0 (dropped)** |

Identical input, opposite result → jimple2cpg silently retains ~the **first ~12,800 classes** it
processes and drops the rest, with **no error/warning**. It is **not** memory (12 GB heap, ~3.8 GB
used; the cap is heap-independent), **not** `--full-resolver`-fixable, **not** obfuscation, **not**
the carve. SDK-inclusive subsets confirm scale/order dependence: at 5k/15k/30k/40k input with the
SDK written *first*, all 557 SDK methods survive; the SDK drops only when it falls past the ~12.8k
processing boundary (as in the real 50k-class app, where its classes sort late).

### Analyzer independence — CodeQL cross-check (RESOLVES the load-bearing caveat)

The completeness finding above is a *jimple2cpg* cap, so we cross-checked an **independent
analyzer, CodeQL 2.26.3** (`build-mode=none`) on the same TMAP app. Result: **the silent
incompleteness is jimple2cpg-specific — CodeQL is complete but expensive.**

| stage | whole-app | carved | ratio |
|---|--:|--:|--:|
| decompile to source (jadx, **mandatory** — CodeQL can't read `.class`/dex) | 50 s, 4.9 GB, 26,954 `.java` (2.68M LOC) | ~2 s, 117 `.java` (4.8k LOC) | — |
| CodeQL DB build (`build-mode=none`) | **542 s (9 min)**, 4.1 GB, 2.5 GB DB | 25 s, 2.1 GB, ~11 MB DB | **~22× faster** |
| **SDK in DB** (types / methods / own-sinks) | **117 / 395 / 5 — COMPLETE** | 117 / 395 / 5 | identical |
| detection run (`flows.ql`) | 22 s, **864 name-matched hits** (SDK's 32 buried inside) | 4 s, **30 hits = exactly the SDK** | **28× less noise** |

Two independent facts fall out:

1. **CodeQL ingests all 66,665 source types incl. the full SDK** (117/117) → *whole-app
   incompleteness is not fundamental; it is a jimple2cpg limitation.* This is the honest
   answer to "is silent-incompleteness general?" — **no, it's frontend-specific.**
2. **But CodeQL pays dearly for completeness:** a mandatory decompilation gate (bytecode →
   source) plus a ~9-min, 2.5 GB DB build, then 28× detection noise from name-matching across
   66k types. Carving makes it **~22× cheaper to build, tiny on disk, and noise-free.**

**Net:** carving helps *both* frontends, for *different* reasons — for jimple2cpg it is a
**correctness fix** (recovers the silently-dropped SDK; 0→557 methods, 0→6 sinks), for CodeQL a
**cost + precision fix** (22× faster, 555× less code, 28× less triage). Whichever analyzer you
pick, carve-then-analyze is cheaper *and* at least as complete.

## RQ1 — feasibility (heap `-Xmx1g`, timeout 150 s; laptop/CI budget)

Even where the whole-app CPG *would* be complete, it can't be built under a realistic budget:

| app | whole-app | carved |
|---|---|---|
| TMAP / gomplayerko / somnote (50–60k) | **timeout, no CPG** | ✅ 3–4 s |
| com.megabox.mop / mafu (43k / 7.7k) | **OOM, no CPG** | ✅ 2–4 s |

At 1 GB, whole-app jimple2cpg **fails 5/5** (timeout/OOM, incl. the smallest 7.7k-class app),
producing no CPG; carved **succeeds 5/5** in 2–4 s.

## RQ2 — reduction (heap `-Xmx12g`, where whole-app *does* build)

54–429× fewer classes (**median 143×**), **8–15× faster**, **6–10× less peak RAM**, ~40–70×
smaller CPG; carved CPG builds in **2–4 s** everywhere. (e.g. TMAP 50157→117 classes,
33→2.3 s, 3.8 GB→386 MB, 42 MB→<1 MB CPG.)

## RQ3 — fidelity

Carved CPGs recover the SDK's source/sink/reachability surface established in the deep-dive
(`docs/CROSS_APP_VALIDATION.md`, `analysis/reports/`), modulo the documented static-reference
boundary (reflection / dynamic loading / native — `docs/PRE_CARVE.md`).

## Honest caveats

- **The completeness result is the strongest and the most surprising:** the whole-app CPG
  *builds* (12 GB, ~30 s, 42 MB) yet silently omits the target on 7/11 apps. The mechanism
  is now characterized (above): a silent, **order-dependent ~12.8k-class retention cap in
  jimple2cpg**, proven by the same-jar order test.
- **Scoping honesty — the silent cap is jimple2cpg-specific (now cross-checked).** The CodeQL
  run above **resolves** this: CodeQL extracts all 66,665 types incl. the full SDK, so
  whole-app incompleteness is *not* fundamental — it is jimple2cpg's silent ~12.8k-class cap.
  The value of carving therefore does **not** rest on that one tool's bug: it is a correctness
  fix for jimple2cpg *and* an independent 22×-cost / 28×-noise fix for a complete-but-expensive
  frontend (CodeQL). RQ1's 1 GB failures and RQ2's cost are likewise not caused by the cap.
- Two analyzers now (`jimple2cpg` + CodeQL), one machine, one deep-dive app (TMAP) for the
  cross-check. **Next:** extend the CodeQL completeness/cost pass across the full 11-app corpus
  (only TMAP done end-to-end on CodeQL), then unrelated non-Goldoson SDKs (issue #5 Phase 1).
- Reproduce: `bash research/completeness_run.sh` and `bash research/metrics.sh …`
  (`METRICS_HEAP=-Xmx1g` for the constrained run).
