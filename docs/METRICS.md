# Baseline (whole-app) vs carved — metrics (issue #5 RQ1/RQ2/RQ3)

Empirical support for the R-Droid distinction (`docs/RELATED_WORK.md` §B1). Harness:
`research/metrics.sh` (timing/RAM), `research/completeness_run.sh` + `research/cq.sc`
(jimple2cpg target-presence), and `research/completeness.ql` (CodeQL target-presence),
whole-app vs in-memory case-preserving carve. **Setup:** Apple Silicon, 16 GB, JDK 17;
**two analyzers** — Joern jimple2cpg (11 apps: TMAP + 10 Goldoson batch, 7.7k–59.7k classes)
and CodeQL 2.26.3 `build-mode=none` (TMAP cross-check).

> **Important — baseline is the *patched* frontend.** The RQ1/RQ2/RQ3 numbers below use a
> jimple2cpg with [joernio/joern#6257](https://github.com/joernio/joern/pull/6257) applied, so the
> whole-app baseline actually processes **all** classes. Numbers reported here supersede an earlier
> draft whose whole-app baseline was silently truncated to ~10,122 classes (see the case study at
> the end); those old figures under-counted the baseline's true cost.
> Data: `research/remeasure_12g_patched.csv` (RQ2), `research/remeasure_1g_patched.csv` (RQ1).

## Headline — carving is 1–2 orders of magnitude cheaper, and enables analysis that is otherwise infeasible

For a *specific* embedded SDK, analyzing the carved program (117–295 classes) instead of the whole
app (7.7k–59.7k classes) is **10–324× faster (median 44×)**, uses **~10× less peak RAM**, produces
a **sub-1 MB CPG vs 35–261 MB**, and — critically — **builds under a laptop/CI budget where the
whole-app build does not build at all**. This holds on the fixed frontend (it is not an artifact of
the bug in the case study), and is corroborated on a second analyzer (CodeQL, ~22× cheaper). The
carved analysis contains **100 % of the target SDK's method surface** (RQ3), so the cost is not paid
in fidelity.

## RQ1 — feasibility (heap `-Xmx1g`, timeout 180 s; laptop/CI budget)

The whole-app CPG cannot be built under a realistic budget:

| whole-app @ 1 GB | outcome |
|---|---|
| tmap, SwipeBrickBreaker, audiorecorder, compass, megabox, somnote | **timeout, no CPG** |
| gomplayerko, **mafu (smallest, 7.7k)** | **OOM, no CPG** |

**Whole-app jimple2cpg fails on all 8 apps measured at 1 GB** (timeout/OOM) — spanning the smallest
(mafu 7.7k, which OOMs in 22 s) to the largest (somnote/gomplayerko ~59k). The remaining 3 apps
(lottecinema 16k, worldcup 25k, psynet 34k) were not separately re-run — they fall *between*
measured failures at both smaller and larger sizes, so success is not expected, but this is stated as
8/11 measured, not 11/11. Several large apps GC-thrash for many minutes before dying (megabox spun
~35 min under `SIGTERM` pressure before the JVM released). **Carved succeeds 11/11** in **2.2–4.3 s**
with the full SDK. So carving is not merely faster here; it is the difference between *an answer* and
*no answer* on commodity hardware.

## RQ2 — reduction (heap `-Xmx12g`, where the whole-app build *does* complete)

Per-app, whole-app (WA) vs carved (CV), patched frontend:

| app | input cls | WA wall | CV wall | speedup | WA RAM | CV RAM | WA CPG | CV CPG |
|---|--:|--:|--:|--:|--:|--:|--:|--:|
| com.Monthly23.SwipeBrickBreaker | 13,974 | 772 s | 2.4 s | **324×** | 5.8 GB | 0.57 GB | 49 MB | <1 MB |
| com.skt.tmap.ku | 50,157 | 518 s | 2.3 s | **230×** | 4.2 GB | 0.39 GB | 218 MB | <1 MB |
| com.somcloud.somnote | 58,431 | 371 s | 2.6 s | 145× | 5.3 GB | 0.54 GB | 252 MB | <1 MB |
| com.gretech.gomplayerko | 59,668 | 359 s | 3.8 s | 95× | 5.2 GB | 0.79 GB | 261 MB | 1 MB |
| com.megabox.mop | 42,702 | 170 s | 3.4 s | 50× | 5.4 GB | 0.83 GB | 166 MB | 1 MB |
| kr.co.psynet | 33,786 | 120 s | 2.7 s | 44× | 5.1 GB | 0.55 GB | 157 MB | <1 MB |
| com.wtwoo.girlsinger.worldcup | 25,137 | 54 s | 2.3 s | 23× | 6.1 GB | 0.54 GB | 96 MB | <1 MB |
| kr.co.lottecinema.lcm | 16,620 | 47 s | 3.2 s | 15× | 5.5 GB | 0.72 GB | 78 MB | 1 MB |
| com.appsnine.compass | 12,385 | 32 s | 2.9 s | 11× | 5.3 GB | 0.52 GB | 60 MB | <1 MB |
| com.appsnine.audiorecorder | 11,677 | 28 s | 2.5 s | 11× | 5.3 GB | 0.49 GB | 49 MB | <1 MB |
| mafu.driving.free | 7,783 | 23 s | 2.2 s | 10× | 5.1 GB | 0.50 GB | 35 MB | <1 MB |

**Summary:** **54–429× fewer classes (median 143×)**, **10–324× faster (median 44×)**,
**~6.6–11.3× less peak RAM (median ~10×)**, CPG **sub-1 MB vs 35–261 MB**. Carved builds are
**flat and cheap** (2.2–4.3 s, ≤0.83 GB) regardless of app size; whole-app cost is large **and
content-sensitive** (SwipeBrickBreaker at 14k classes is the slowest at 772 s — its ~5.2k
`gms.internal.ads` classes stress Soot type-propagation — while the 50k-class TMAP takes 518 s).
Predictable cheap cost vs unpredictable expensive cost is itself a reason to carve.

## RQ3 — fidelity

With the frontend fixed, the whole-app CPG is now complete, so fidelity can be checked **directly**:
the target-SDK method surface in the carved CPG vs the whole-app CPG.

**On all 11 apps the carved SDK method count equals the whole-app SDK method count exactly:**
tmap 557=557, SwipeBrickBreaker 895=895, audiorecorder 574=574, compass 749=749, gomplayerko
1349=1349, megabox 1457=1457, somnote 909=909, worldcup 757=757, lottecinema 1230=1230, psynet
910=910, mafu 695=695. Carving preserves the SDK's full statically-reachable method/source/sink
surface (deep-dive in `docs/CROSS_APP_VALIDATION.md`), modulo the documented static-reference
boundary — reflection / dynamic loading / native (`docs/PRE_CARVE.md`). (Whole-app *name-matched*
sink counts are sometimes higher than carved, but that is cross-app noise from unrelated code that
happens to share a method name, not extra SDK fidelity — see the CodeQL 28× noise result below.)

## Analyzer independence — CodeQL cross-check

Cost/feasibility is not a jimple2cpg artifact. An **independent analyzer, CodeQL 2.26.3**
(`build-mode=none`) on TMAP:

| stage | whole-app | carved | ratio |
|---|--:|--:|--:|
| decompile to source (jadx, **mandatory** — CodeQL can't read `.class`/dex) | 50 s, 4.9 GB, 26,954 `.java` (2.68M LOC) | ~2 s, 117 `.java` (4.8k LOC) | — |
| CodeQL DB build (`build-mode=none`) | **542 s (9 min)**, 4.1 GB, 2.5 GB DB | 25 s, 2.1 GB, ~11 MB DB | **~22× faster** |
| SDK in DB (types / methods / own-sinks) | 117 / 395 / 5 | 117 / 395 / 5 | identical |
| detection run (`flows.ql`) | 22 s, **864 name-matched hits** (SDK's 32 buried inside) | 4 s, **30 hits = exactly the SDK** | **28× less noise** |

CodeQL ingests all 66,665 source types (it has no jimple2cpg-style truncation), but pays a
mandatory decompilation gate + a ~9-min / 2.5 GB DB build, then 28× detection noise from
name-matching across the whole app. **Carving is ~22× cheaper to build and noise-free** — an
advantage entirely independent of the jimple2cpg bug below.

**Corpus generalization.** Carved CodeQL was run on **all 11 apps**
(`research/codeql_carved_corpus.csv`): each builds in **21–29 s** into a **7–11 MB DB** containing
**100 % of the SDK** — source-type count ≈ carved class count on 11/11 (tmap 117/117, SBB 201/201,
gomplayerko 295/295, megabox 271/271, lottecinema 273/273, worldcup 176/176, … mafu 145/144). Carved
CodeQL is uniformly cheap and complete regardless of app size. Whole-app CodeQL was measured on the
two apps for which the **original APK** is available (`research/codeql_wholeapp.csv`): tmap
(542 s build / 2.5 GB DB) and worldcup (220 s / 207 MB) → carved is **~9–22× faster to build and
~30–280× smaller on disk**, consistent with the 54–429× input reduction (§RQ2).

*Honest limit — whole-app CodeQL beyond 2 apps.* The other 9 apps have only their dex2jar
`app.jar` (not the original APK). Decompiling that with jadx yields source damaged enough that
CodeQL's `build-mode=none` silently drops most of it — e.g. mafu: 1,554 of ~5,286 files extracted,
SDK 0. That is a **decompilation-quality** confound, *not* a CodeQL property, so those whole-app
runs are not reported. It is, however, itself an argument for the bytecode carve: source-based
whole-app analysis of repackaged/obfuscated apps is gated on decompilation fidelity, which the
carve (bytecode → `jimple2cpg`, or a small clean decompile → CodeQL) sidesteps. (An earlier batch
also showed this machine's background load can inflate CodeQL build timings ~40×; the numbers here
are from clean, low-load, sequential runs.)

## Case study — a silent toolchain failure, caught by carve-vs-whole-app validation

While establishing the baseline we compared carved vs whole-app CPGs and found the whole-app CPG
**silently missing the target SDK on 7/11 apps**. Root-causing it led to a real, shipped bug in
Joern and an upstream fix. This is a **bonus** result — a case of differential validation being
useful — not the project's central claim.

**Pre-fix behaviour (jimple2cpg as shipped, ≤ v4.0.370).** The whole-app CPG *built fine* yet
silently dropped classes; the target SDK was effectively absent on most apps:

| app | pre-fix WA SDK methods | post-fix WA SDK methods | carved SDK methods |
|---|--:|--:|--:|
| tmap / SwipeBrickBreaker / megabox / somnote / lottecinema / psynet | **0** | = carved | 557 / 895 / 1457 / 909 / 1230 / 910 |
| gomplayerko | **23 (2%)** | 1349 | 1349 |
| audiorecorder / compass | 551 (96%) / 726 (97%) | 574 / 749 | 574 / 749 |
| worldcup / mafu | 757 / 695 (100%) | 757 / 695 | 695 / 757 |

**Root cause (confirmed, then fixed — [joernio/joern#6257](https://github.com/joernio/joern/pull/6257)).**
`FileUtil.unzipTo` registers every per-entry `getInputStream`/`newOutputStream` with a single
`Using.Manager` scoped to the **whole** archive, so no per-entry resource is released until
extraction finishes; and the `Using.Manager` result `Try` is **discarded**, with `destination`
returned unconditionally. So per-entry resource accumulation drives an **environment-specific
resource exhaustion/failure part-way through, which is then swallowed and a partially-extracted
directory returned as success.** jimple2cpg then stages only the first N entries (`Loading N program
files` pinned to ~10,122 across apps; controlled proof: survivors = exactly the first 10,122 zip
entries, 0 outside). The exact resource limit that triggers at ~10,122 is **not** pinned down
(shell `ulimit -n` was 1,048,576 and `kern.maxfilesperproc` 61,440, both far above); recorded
*observation*: process open-FD count climbed to ~10k during extraction.

**Ruled out** en route: memory/OOM (3.7 of 12 GB used), case-insensitive path collisions (0; raw
`unzip` lands all 13,974), obfuscated SDK bytecode (the same classes carve fine → context/order
dependent), concurrency (3 runs byte-identical), per-class Soot/AST failures (those log a WARN;
none seen).

**Fix + verification.** Close each entry's streams immediately (nested `Using.resource`), which
also restores failure propagation. Rebuilt frontend: staging **10,122 → 50,157** (TMAP) and
**→ 13,974** (SBB); SBB whole-app SDK **0 → 895 methods / 0 → 8 sinks**. The post-fix column above
(WA = carved on 11/11) is this patched frontend.

**Relationship to carving.** Carving did **not** fix this bug — the fix is the `unzipTo` patch.
Carving's small input **avoided** the failure surface, and comparing carved vs whole-app **exposed**
it. One instance shows differential validation *can* surface silent toolchain failures; it is not
(yet) evidence that carving is a general analyzer-bug oracle — that would require defined invariants
(target class/method/sink surface) checked systematically across analyzers.

## Honest caveats

- **What is durable vs what was a bug.** The durable, frontend-agnostic results are **cost/
  feasibility (RQ1/RQ2)** and **fidelity (RQ3)**; CodeQL corroborates the cost gap independently.
  The dramatic *completeness* gap (0% SDK on 7/11) was a **fixable jimple2cpg bug**, now upstreamed
  (#6257) — it is presented as a case study, not as a standing property of whole-app analysis.
- **Baseline honesty.** All whole-app numbers here are on the **patched** frontend (it does the full
  work), so RQ1/RQ2 reflect the true baseline cost — larger than the earlier draft's, which compared
  against a silently-truncated baseline.
- **Scope.** One machine; jimple2cpg on 11 apps (clean); **carved CodeQL on all 11** (clean); whole-app
  CodeQL on the 2 apps with an original APK (TMAP, worldcup). Whole-app CodeQL on the other 9 is
  blocked by decompilation-quality confound (only dex2jar `app.jar` available — see the CodeQL
  section), not by CodeQL itself. **Next:** original APKs for a wider whole-app CodeQL set, and
  unrelated non-Goldoson SDKs (issue #5 Phase 1).
- **Reproduce:** `bash research/metrics.sh …` (`METRICS_HEAP=-Xmx1g` for the RQ1 run;
  default 12g for RQ2). The harness records the staging count (`wa_staged` = jimple2cpg's
  `Loading N program files`) and **keeps the raw logs** under `research/metrics-logs/<label>/` — an
  earlier version deleted them, which is why the silent truncation went unnoticed at first. Direct
  check: `SL_LOGGING_LEVEL=INFO jimple2cpg <app>.jar --output /tmp/x.cpg 2>&1 | grep 'program files'`.
