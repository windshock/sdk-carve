# Baseline (whole-app) vs carved — first metrics (issue #5 RQ1/RQ2/RQ3)

Evidence for the R-Droid distinction (`docs/RELATED_WORK.md` §B1): carving **restores analyzer
feasibility** (RQ1) and **shrinks the analysis universe by 1–2 orders of magnitude** (RQ2) while
**preserving the security-relevant surface** (RQ3). Harness: `research/metrics.sh` (whole-app jar
vs in-memory case-preserving carve, same analyzer = `jimple2cpg`; `/usr/bin/time -l` for wall +
peak RSS; per-CPG timeout).

**Setup.** 1 machine (Apple Silicon, 16 GB, 10 cores), JDK 17, Joern `jimple2cpg`. 12 apps
(TMAP + the 11 Goldoson batch apps), 7.7k–59.7k classes. Carve scope = the SDK root(s) from
`detect.py`/`scope.txt`. Two heap settings model two environments.

## RQ2 — reduction (heap `-Xmx12g`; whole-app *completes* here, so this isolates reduction)

| app | classes WA→CV | × | wall s WA→CV | × | peak RAM MB WA→CV | × | CPG WA→CV |
|---|--:|--:|--:|--:|--:|--:|--:|
| com.skt.tmap.ku | 50157→117 | **429×** | 33.1→2.3 | 15× | 3803→386 | 10× | 42 MB→<1 |
| com.gretech.gomplayerko | 59668→295 | 202× | 37.9→3.2 | 12× | 4609→709 | 7× | 51 MB→1 |
| com.somcloud.somnote | 58431→184 | 318× | 33.4→2.5 | 14× | 4703→561 | 8× | 48 MB→<1 |
| com.megabox.mop | 42702→271 | 158× | 26.0→3.4 | 8× | 4925→786 | 6× | 41 MB→1 |
| kr.co.psynet | 33786→195 | 173× | 34.8→2.6 | 14× | 3793→531 | 7× | 44 MB→<1 |
| com.wtwoo.girlsinger.worldcup | 25137→176 | 143× | 26.7→2.5 | 11× | 4746→518 | 9× | 39 MB→<1 |
| kr.co.lottecinema.lcm | 16620→273 | 61× | 35.1→3.4 | 10× | 4841→600 | 8× | 47 MB→1 |
| com.Monthly23.SwipeBrickBreaker | 13974→201 | 70× | 28.8→2.6 | 11× | 3783→511 | 7× | 35 MB→<1 |
| com.appsnine.compass | 12385→210 | 59× | 29.8→2.6 | 11× | 4481→555 | 8× | 47 MB→<1 |
| com.appsnine.audiorecorder | 11677→163 | 72× | 31.1→2.4 | 13× | 3782→431 | 9× | 42 MB→<1 |
| mafu.driving.free | 7783→144 | 54× | 24.8→2.4 | 10× | 4200→454 | 9× | 35 MB→<1 |

**Reduction factors:** classes **54–429×** (median **143×**), wall time **8–15×**, peak RAM
**6–10×**, CPG size **~40–70×**. Carved CPG builds in **2–4 s** everywhere.

## RQ1 — feasibility (heap `-Xmx1g`, timeout 150 s; models a laptop/CI runner)

| app | whole-app | carved |
|---|---|---|
| com.skt.tmap.ku (50157) | **timeout (no CPG)** | ✅ 3.9 s |
| com.gretech.gomplayerko (59668) | **timeout (no CPG)** | ✅ 4.0 s |
| com.somcloud.somnote (58431) | **timeout (no CPG)** | ✅ 2.7 s |
| com.megabox.mop (42702) | **OOM (no CPG)** | ✅ 3.7 s |
| mafu.driving.free (7783) | **OOM (no CPG)** | ✅ 2.3 s |

At 1 GB, whole-app jimple2cpg **fails on 5/5** (timeout or OutOfMemory — including the smallest,
7.7k-class app) and produces **no CPG**; the carved target **succeeds on 5/5** in 2–4 s. This is
the feasibility half: where whole-app analysis is impossible under a realistic memory budget,
carving makes it possible.

## RQ3 — fidelity (preserved)

The carved CPGs recover the SDK's security-relevant surface established in the deep-dive: sources
(installed-apps / Wi-Fi / BT / GPS / MAC / carrier / ad-ID), sinks (`putCol`/`userJoin`/
`getBConfig`/`getPdata`/`loadUrl`/`loadData`), and entry→sink reachability — see
`docs/CROSS_APP_VALIDATION.md` and `analysis/reports/`. Reduction does not drop the target's
security behavior (modulo the documented static-reference boundary: reflection / dynamic loading
/ native — `docs/PRE_CARVE.md`).

## Honest caveats

- **Base CPG completes whole-app at a large heap** (12 GB) — so the reduction, not base-CPG
  failure, is the headline at 12 GB. Failure is **environment-dependent** (heap/config), which is
  exactly why the 1 GB run matters: feasibility is restored precisely where budgets are realistic.
- Peak RSS includes JVM/Soot overhead (whole-app touches ~3.8–4.9 GB; carved ~0.3–0.8 GB).
- One machine, one analyzer (`jimple2cpg`) so far. **Next:** the same comparison on **CodeQL DB
  build** (heavier; likely fails whole-app sooner) and on a **downstream dataflow/query** pass
  (superlinear — where reduction compounds), plus unrelated non-Goldoson SDKs (issue #5 Phase 1).
- Reproduce: `bash research/metrics.sh <label> <app.jar> out.csv <root> [root…]`
  (`METRICS_HEAP=-Xmx1g` to model constrained envs).
