# Baseline (whole-app) vs carved — metrics (issue #5 RQ1/RQ2/RQ3 + completeness)

Empirical support for the R-Droid distinction (`docs/RELATED_WORK.md` §B1). Harness:
`research/metrics.sh` (timing/RAM) and `research/completeness_run.sh` + `research/cq.sc`
(target-presence), whole-app jar vs in-memory case-preserving carve, same analyzer
(`jimple2cpg`). **Setup:** Apple Silicon, 16 GB, JDK 17, Joern jimple2cpg; 11 apps
(TMAP + 10 Goldoson batch), 7.7k–59.7k classes.

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
  *builds* (12 GB, ~30 s, 42 MB) yet silently omits the target on 7/11 apps. The exact
  class-selection mechanism of jimple2cpg on large jars is not fully characterized here
  (it retains a bounded typeDecl set dominated by heavily-referenced libraries; the
  manifest-registered SDK's survival is app-dependent) — but the *effect* (false-negative
  detection) is reproduced across the corpus.
- One machine, one analyzer (`jimple2cpg`). **Next:** repeat completeness + RQ1/RQ2 on
  **CodeQL** (analyzer independence), and on unrelated non-Goldoson SDKs (issue #5 Phase 1).
- Reproduce: `bash research/completeness_run.sh` and `bash research/metrics.sh …`
  (`METRICS_HEAP=-Xmx1g` for the constrained run).
