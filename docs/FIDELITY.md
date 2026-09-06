# Structural (static-analysis surface) fidelity & failure boundary — carved vs whole-app CPG (RQ3 / RQ5)

*Answers the reviewer question "method present ≠ analysis meaning preserved."* Compares the **carved**
CPG against the **complete whole-app** CPG (jimple2cpg patched with
[joernio/joern#6257](https://github.com/joernio/joern/pull/6257), so the whole-app graph actually
contains the SDK) — beyond method-count, at the **call-graph** level.

**Scope of the claim (deliberately precise).** What is demonstrated is *structural* fidelity of the
static-analysis surface, not *semantic* (taint/dataflow) equivalence:

```
Method set                     = exact (9/11)
SDK-internal call graph        = exact, 0 divergence (9/11)
Boundary call-sites            = exact (9/11)
Source/sink surface            = exact (2 apps)
Call-graph reachability        = exact where the path stays SDK-internal (by construction)
Taint/dataflow semantic equiv. = NOT yet demonstrated (needs dataflow semantics models — future work)
```

So the finding is: **for the measured SDKs, no host-app code was required to preserve the SDK-internal
static call graph and source/sink surface; fidelity loss begins at explicitly-modeled boundaries** —
*not* "app context can be zero."

## Two independent evaluation axes (kept separate on purpose)

Target-centric carving is evaluated along **two orthogonal questions**. They use different baselines
and must never be conflated:

| Axis | Question | Baseline | Metric | Status |
|---|---|---|---|---|
| **1. Preservation fidelity** | *Did we preserve the carved code?* | **whole-app CPG of the same APK** (patched-complete) | SDK-internal call-graph / boundary / source-sink **set equality** | measured — §Result below |
| **2. Pair-derived scope validation** | *Did we carve the right code?* | **a natural counterpart APK** (infected↔clean / decoy↔twin / original↔patched) | **counterfactual scope agreement** — carve scope vs pair-supported malicious region | pilot (Necro/Wuta) done — §Pair-derived scope validation |

Axis 1 lives **inside one APK**; axis 2 lives **across a pair**. Axis 2 does **not** reuse axis-1's
edge-recall pipeline — the counterpart APK does not contain the SDK, so there is nothing to recall.
This document covers axis 1 first (the sections through *Boundary decomposition*), then axis 2.

## What target-centric carving preserves — and where fidelity can be lost

```text
                    Host application
          ┌────────────────────────────────┐
          │ host code / other SDKs / JNI    │
          │ reflection / dynamic loading    │   ← intentionally removed
          └───────────────┬─────────────────┘
                          │
                 explicit boundary
            fidelity may be lost here
                          │
                          ▼
        ┌──────────────────────────────────┐
        │          Target SDK carve         │
        │                                   │
        │ Method set           exact        │
        │ Internal call graph  exact (9/9)  │
        │ Boundary call-sites  exact (9/9)  │
        │ Source/sink surface  exact (2/2)  │
        │                                   │
        │ Dataflow equivalence:             │
        │   NOT yet positively demonstrated │
        └───────────────────────────────────┘

          54–429× smaller analysis universe
          10–324× cheaper CPG construction
```

*(9/9 = of 9 apps measured; 2/2 = of 2 apps measured for the source/sink surface. Both CPGs use the
identical, complete SDK bytecode; the "exact" rows are equalities between the carved and the
patched-complete whole-app graph, not approximations.)*

## What is measured (`research/edges.sc`, `research/fidelity_batch.sh`)

For the target SDK's methods, every call site is classified:
- **internal edge** — SDK method → SDK method (both ends inside the carved scope).
- **boundary edge** — SDK method → non-SDK callee (host app / framework / library).

Then, carved vs whole-app:
- **Internal-edge recall** = |edges in *both*| / |edges in whole-app|. This is the core fidelity
  number: does the carve reproduce the SDK's *own* call graph?
- **Boundary call-sites** = distinct external targets the SDK calls, with the fraction that are
  framework/library (`android.`/`java.`/`javax.`/`kotlin.`/`androidx.`/`com.google.`). This is the
  **cut**: in the carved graph these callees are stubs; in the whole-app graph they resolve to bodies.

## Result — the SDK's internal call graph is preserved *exactly*

| app | SDK methods (WA=CV) | internal edges (WA=CV) | internal-edge recall | boundary targets (WA=CV) | boundary framework % |
|---|--:|--:|--:|--:|--:|
| mafu.driving.free | 695 | 671 | **100.0 %** | 318 | 55 % |
| com.appsnine.audiorecorder | 574 | 235 | **100.0 %** | 498 | 64 % |
| com.appsnine.compass | 749 | 736 | **100.0 %** | 627 | 81 % |
| kr.co.lottecinema.lcm | 1230 | 2023 | **100.0 %** | 602 | 92 % |
| com.wtwoo.girlsinger.worldcup | 757 | 845 | **100.0 %** | 363 | 75 % |
| kr.co.psynet | 910 | 1348 | **100.0 %** | 404 | 91 % |
| com.Monthly23.SwipeBrickBreaker | 895 | 1299 | **100.0 %** | 433 | 90 % |
| com.megabox.mop | 1457 | 1556 | **100.0 %** | 619 | 81 % |
| com.somcloud.somnote | 909 | 1182 | **100.0 %** | 373 | 90 % |

**9/11 measured, 9/9 exact — every measured app has 100 % internal-edge recall with 0 divergence**
(no carved-only or whole-app-only internal edge), across the full size range **7.7k–58k input
classes**. The boundary count is **identical (WA=CV) on every measured app**, 55–92 % of it
framework/stdlib. The two largest apps (gomplayerko 59.7k, TMAP 50k) were **not measured** — their
*whole-app* CPG edge-dump exceeds practical joern time/memory on this machine (the carved side dumps
in seconds — the same cost asymmetry as §RQ2). We do not claim a result for them.

**External validity — structural fidelity beyond Goldoson.** Internal call-graph edge sets, carved vs
whole-app, measured **bidirectionally** (WA-only *and* CV-only — set equality, not just recall):

| host (source) | target | edges (WA=CV) | edge WA-only / CV-only | method set |
|---|---|--:|--:|---|
| DMB-TV `com.project.onair` (in-hand) | okhttp3+okio | 3314 | **0 / 0** | 2295=2295 exact |
| DMB-TV | com.google.android.exoplayer2 | 14733 | **0 / 0** | 10262/10256 (**+6 WA**) |
| DMB-TV | com.google.firebase | 2761 | **0 / 0** | 2760/2758 (**+2 WA**) |
| DMB-TV | com.google.android.gms | 15002 | **0 / 0** | 8779=8779 exact |
| DMB-TV | com.project.onair (host's *own* code, **not** an embedded SDK) | 1338 | **0 / 0** | 1137=1137 exact |
| **NewPipe** (**downloaded**, F-Droid) | okhttp3+okio | 1754 | **0 / 0** | 1418=1418 exact |

**Internal call-graph edge sets are exactly equal (0 divergence *both directions*) in every case.**
Method sets are exact **except** exoplayer2 (+6) and firebase (+2) present only in whole-app — and
those extras are **framework-inherited / interface method entries**, root-caused:
`PlayerView.{getLayoutParams,getVisibility,setLayoutParams,setSystemUiVisibility}` = `android.view.View.*`;
`SimpleExoPlayer.stop` = `Player.stop` (interface); `FirebaseMessagingService.{onCreate,onDestroy}` =
`android.app.Service` lifecycle. Whole-app materializes them on the SDK subclass (full class hierarchy
present); the carve resolves them to the framework superclass stub. They carry **no SDK-internal
edges** (hence edge-set still exact) and **no SDK-defined method body is lost** (CV-only method = 0).
So this is a **framework-hierarchy attribution effect at the boundary, not lost SDK logic** — and it
is exactly the case **adaptive context expansion** would pull in (add the framework hierarchy, which
you stub anyway). Under the letter of the preservation contract (method set), these two are *not*
byte-exact; we say so rather than round it to "negligible."

*Two separate claims, kept apart:*
- **Structural fidelity (measured, carved-vs-whole-app):** exact internal-CG preservation on Goldoson
  (9 hosts) + benign libraries okhttp3 (**two** unrelated hosts, one downloaded), exoplayer2, firebase,
  gms, and the host's own `com.project.onair` code — internal-edge set equal in all.
- **Broader applicability (a *different*, weaker claim):** sdk-carve has been *applied* to 5 malware
  families (Goldoson/SpinOk/Konfety/MobiDash/Necro) — i.e. the method *runs* on them — which is **not**
  the same as verifying the preservation contract against whole-app on each. NewPipe's okhttp3 is a
  **second host of the same library**, not a new family; `com.project.onair` is **host code**, not an
  embedded third-party SDK. (Verified on `research/dmb_extval.csv` + edge symmetric-diff.)

**Finding (RQ3).** Across every app measured, the carved CPG reproduces the SDK's **internal
static call graph with 0 divergence** — same method set, same internal call edges (recall 100 %, no
carved-only or whole-app-only internal edges). Within the SDK scope, the carved graph is *structurally
identical* to what the complete whole-app analysis sees; no host-app code was needed to reconstruct
it. (This is a statement about the static call graph, not about taint/dataflow — see the scope box.)

**Finding (RQ5 — the boundary is the cut, and it is mostly framework).** The only difference is at
**boundary edges** (SDK → non-SDK). The carved graph keeps the *call site* but the callee is a stub;
the whole-app graph resolves the callee body. Of these boundary targets, **55–92 % are framework /
standard library** (`android.*`, `java.*`, …) — which are **stubs in the whole-app graph too**
(neither includes `android.jar`), so they are *not* lost context. The genuinely-lost context is only
the **non-framework (host-app) fraction** of boundary calls — and this is exactly the documented,
intentional reduction: flow *through* host-app code is not followed (see `docs/PRE_CARVE.md` for the
reflection / dynamic-loading / native caveats that also break the closure).

## Source→sink surface (RQ3 deeper — ②; `research/paths.sc`)

Beyond the call graph: the SDK's sensitive-**source** call-sites (`getInstalledApplications`,
`getHardwareAddress`, `getBSSID`, GPS, IMEI, …) and **sink** call-sites (`loadUrl`/`loadData`,
`openConnection`/`exec`, SDK-own `putCol`/`getPdata`/`userJoin`/`getBConfig`) — the dataflow-relevant
surface — carved vs whole-app:

| app | source-sites | sink-sites | source-methods | sink-methods | src/sink method divergence |
|---|--:|--:|--:|--:|--:|
| com.wtwoo.girlsinger.worldcup | 33 | 16 | 15 | 15 | **0 (WA=CV)** |
| com.appsnine.audiorecorder | 16 | 7 | 6 | 7 | **0 (WA=CV)** |

Every source/sink call-site and its containing method is **identical carved-vs-whole-app**. Combined
with the 100 % internal call graph, source→sink **call-graph reachability is preserved by
construction** (same graph, same endpoints). *Honest caveat:* joern's default **taint-flow**
(`reachableBy`) reports **0 flows in both** carved and whole-app — the SDK's collect→upload path runs
through `Bundle`/field/serialization that joern doesn't track without dataflow **semantics models**;
this is an identical analyzer limitation, **not** a carving fidelity gap (a **negative control**:
carving didn't break dataflow — nothing to break).

*Positive-taint attempt (documented, `research/qlqueries/dataflow.ql`).* We also ran **CodeQL
`TaintTracking`** (mature built-in flow models) with **three added within-SDK steps** (method
arg/qualifier→return, field store→read, and collector-mutation arg→qualifier) — still **0
source→sink flows on the carved DB**.
**Observed modeling barrier** (a hypothesis consistent with the data, not a proven root cause): the
SDK appears to collect into **fields of a collector object** and pass that *object* to the sink
(`putCol(collector)`), and a tainted *field* does not taint the *container argument* under general
static taint — compounded by obfuscated serialization. What is *measured*: **0 flows on two analyzers
(joern + CodeQL)** with reasonable models, orthogonal to carving (a negative control). Positive
**semantic** (dataflow) equivalence therefore needs **per-SDK content/field-object models** — deferred
as its own subproject. This section claims **structural** (surface) fidelity only, **not semantic
(dataflow) equivalence** — the figure keeps that cell explicitly blank.

## Boundary decomposition — what *kind* of context is cut (RQ5, #2; `research/boundary_classify.sh`)

The boundary (SDK → non-SDK) is the only place fidelity is lost. Deduped by **class** and classified
(boundary callees are identical carved=whole-app, so the fast carved CPG is used):

| app | boundary classes | framework/stdlib | recognized lib | obfuscated residue | **named non-lib pkg** | residue % |
|---|--:|--:|--:|--:|--:|--:|
| kr.co.lottecinema.lcm | 167 | 156 | 10 | 0 | **0** | 0 % |
| kr.co.psynet | 122 | 115 | 6 | 0 | **0** | 0 % |
| com.Monthly23.SwipeBrickBreaker | 128 | 120 | 7 | 0 | **0** | 0 % |
| com.somcloud.somnote | 111 | 104 | 6 | 0 | **0** | 0 % |
| com.gretech.gomplayerko | 169 | 158 | 10 | 0 | **0** | 0 % |
| com.skt.tmap.ku | 115 | 101 | 8 | 5 | **0** | 4 % |
| com.megabox.mop | 182 | 159 | 10 | 12 | **0** | 7 % |
| com.wtwoo.girlsinger.worldcup | 112 | 95 | 6 | 10 | **0** | 9 % |
| com.appsnine.compass | 214 | 152 | 3 | 58 | **0** | 27 % |
| mafu.driving.free | 86 | 58 | 0 | 27 | **0** | 31 % |
| com.appsnine.audiorecorder | 178 | 104 | 0 | 73 | **0** | 41 % |

**Finding (stated at the strength the measurement supports).** On all 11 apps, **no direct static
boundary call targets an identifiable host-app namespace**: the classifier checks each app's own
package prefix (e.g. `com.skt.tmap`, `com.wtwoo`) *and* finds zero human-named non-library callees at
all (`named non-lib pkg = 0`). The SDK's identifiable external surface is **framework/stdlib +
recognized libraries** (retrofit2/okhttp3/picasso/gson — network/image/serialization, the deps you'd
stub or model). **We do not claim the SDK never touches host code**, because an **R8-obfuscated
residue** remains (short renamed classes like `g4`,`b7`): **0 % on 5/11 apps, up to 41 %** elsewhere.
By name that residue cannot be attributed to host-app vs bundled-library vs *missed-SDK-scope*, so it
**could** contain obfuscated host code. Attributing it (per-class) is future work and directly
motivates **adaptive context expansion** (pull the residue's closure in and re-check). *(Answer to
"how much app context is needed": none of the host's **identifiable** code; an unresolved obfuscated
residue of 0–41 % remains to be attributed.)*

---

# Axis 2 — Pair-derived scope validation: *"Did we carve the right code?"* (`analysis/necro_fidelity.sh` + pilot)

Preservation fidelity (axis 1, above) shows the carve **faithfully preserves whatever it selected**.
It says nothing about whether the *selection itself* — the target scope — corresponds to the real
malicious component. A **natural counterfactual** (a real, in-the-wild APK that differs from the
infected one by the presence/absence of the malicious component) gives an **independent** check on the
scope decision: if the carved scope lines up with what actually differs between the pair, we carved the
right code.

**Pair taxonomy — the counterfactual is not the same kind of evidence for every family.**

| Type | Relation | What it can establish | Families |
|---|---|---|---|
| **A. Strong / base-matched** | same base APK with the malicious component directly added/removed (repackage, evil-twin) | same-base APK delta = independent scope ground truth → scope **precision / recall (/completeness)** | MobiDash (original↔patched), Konfety (decoy↔evil-twin) — *when the matched relation is established* |
| **B. Longitudinal** | same app lineage, different versions; component present then gone | raw version delta is **NOT** ground truth (host/lib/feature churn + R8 rename noise) — anchor on **published IOC region**; yields **counterfactual scope support** (scope is infection-associated), **not** scope-completeness | Goldoson (infected↔later-clean), SpinOk (infected↔removed), Necro/Wuta (infected↔later-clean) |

For type-B pairs we **do not** call the raw `infected − clean` class diff "malicious". We define the
malicious region from **published IOC markers** (package / class / native marker), verify that region
is **present in infected and absent in clean** (the pair *supports* the marker), then measure how the
sdk-carve scope agrees with that pair-supported region.

## Metric — counterfactual scope support (umbrella: *pair-derived scope validation*)
**What each pair type can establish is deliberately different — do not generalize "scope-completeness"
to type-B:**
- **Type B (longitudinal)** provides **counterfactual scope support / scope validity** only: it can
  *support* that the selected scope is **infection-associated** (present in the infected build, absent
  in the clean counterpart). It **cannot** establish scope *completeness* — because the two APKs are
  different versions, not the same base binary, a type-B pair cannot prove that all infection-added
  code is known, that no infection-related code exists outside the IOC region, or that every carved
  class was added *solely* by the injection.
- **Type A (base-matched)** can go further: an original↔patched delta on the **same base** is an
  independent scope ground truth, enabling scope **precision / recall (/completeness)** of the carve.

Measured quantities (for the carve scope *C*, the clean counterpart, and — type-A only — an
independent infection delta *D*):
- **Pair support** — |IOC region in infected| vs |in clean|: supports that the region is
  infection-associated, not pre-existing host code (independent of the carve).
- **Carve∩clean** — carved classes also observed in the clean counterpart (a low count supports that
  the carve is infection-associated; it does **not** prove classes were added *solely* by injection).
- **Carve within IOC region** — are all carved classes inside the published IOC region observed as
  infected-present / clean-absent? (type-B: a *support* check, not a completeness proof.)
- **Scope precision/recall vs *D*** — **type-A only**, when a same-base infection delta is available.
- **Out-of-scope boundary** — injected components that are real but outside the bytecode-carve model
  (native `.so`), recorded as a documented boundary, **not** a scope miss.

## Necro/Coral pilot — Wuta 6.3.2 infected ↔ 6.9.8.161 clean *(both in hand; type-B longitudinal)*
IOC-anchored region *R* = `com.coral.*` (`CoralSdk`, `com.coral.vmout`, `com.coral.imp.*`); native
marker `libcoral.so`.

| measurement | value | reading |
|---|--:|---|
| **Pair support** — `com.coral.*` classes infected / clean | **660 / 0** | the IOC region is **observed in the infected build and absent from the clean counterpart** — observed **independently** of the carve |
| **Carve∩clean** — carved classes also in clean | **0** | **no carved class is observed in the clean counterpart** |
| **Carve within IOC region** — carved classes inside `com.coral.*` | 660 / 660 | **all carved Java classes fall within the IOC-anchored region** observed infected-present / clean-absent |
| **Other stable IOC markers** infected-only besides `com.coral` | none | no stable coral-adjacent Java marker observed outside the carve |
| **Out-of-scope boundary** — `libcoral.so` infected / clean | **2 / 0** | native 2nd-stage is observed infected-present / clean-absent but **outside bytecode-carve scope** — documented boundary, not a Java-scope miss |

**Reading (calibrated to what a type-B pair supports).** *All carved Java classes fall within the
IOC-anchored `com.coral.*` region observed in the infected build and absent from the clean counterpart;
no carved class is observed in the clean counterpart.* Therefore: **the longitudinal pair independently
supports that the selected carve scope is infection-associated** — a **counterfactual scope
support / scope-validity** result, *not* a scope-completeness ground truth. Because Wuta 6.3.2 and
6.9.8.161 are **different versions, not the same base binary**, this pair does **not** establish that
all infection-added code is known, that no infection-related code exists outside `com.coral`, or that
every carved class was added *solely* by the injection. The native second stage (`libcoral.so`) is
observed as an injected artifact but is explicitly out of bytecode-carve scope.

**Necro axis-1 (preservation fidelity) is host-limited — and that is itself the RQ1 point.** The
carved `com.coral` CPG builds in seconds (660 classes → 2,208 methods, 1,536 internal edges — a
complete SDK-internal call graph by construction). The **whole-app** baseline needed to cross-check it
is **not buildable on this 16 GB machine**: Wuta 6.3.2 is ~56k classes, and its whole-app CPG **OOMs
during serialization at 12g (writes a corrupt graph) and cannot allocate at 16g**. So Necro is a
concrete instance of the feasibility transformation (RQ1) — whole-app analysis is infeasible-at-budget
while the carve analyzes fine. **This is recorded as a feasibility-boundary result, not a
preservation-equality result:** the carved-vs-whole-app *fidelity equality* cross-check for Necro is
**deferred until a larger-RAM host is available**, not claimed. The axis-1 equality result already
stands on 9 Goldoson hosts + 5 benign libraries (above); Necro contributes an axis-2 scope-support
result plus an RQ1 feasibility-boundary data point, not another axis-1 equality point.

**Honest limitation (type-B).** A longitudinal pair cannot rule out injected malicious **Java outside
`com.coral`**, because the raw name-delta is dominated by R8 rebuild-renaming between 6.3.x and 6.9.8
(56,416 vs 69,499 classes, mostly renamed) — so we anchor on the published `com.coral` IOC rather than
the version diff. A **type-A** pair (e.g. MobiDash original↔patched) would let the APK delta itself
serve as the scope ground truth, closing this gap. This is exactly why the two pair types are kept
distinct.

## Goldoson pilot — TMAP lineage: infected 9.16.0.291767 ↔ clean 9.21.7.291923 *(type-B longitudinal)*
Flagship-family reproduction of the same type-B methodology. Infected `com.skt.tmap.ku` v9.16.0.291767
(versionCode 1400) is in hand; the clean successor v9.21.7.291923 (versionCode 1469, July 2023 —
post-McAfee-disclosure) was fetched via **apkeep / APKPure** (the mirror adapter that works on this
host — apkmirror is Cloudflare-blocked, apkcombo's tool is stale). IOC-anchored region *R* =
`com.smart.sklb`, the identified **non-R8-renamed** Goldoson SDK package for TMAP.

| measurement | value | reading |
|---|--:|---|
| **Provenance** — signer_sha256 infected / clean | `90351f2e…cf0f8e2` = same | **same SKT signing key** → genuine same-lineage successor, **not repackaged** (the mirror-repackaging check) |
| **Pair support** — `com.smart.sklb` classes infected / clean | **113 / 0** | the region is observed infected-present / clean-absent — independently of the carve |
| **Carve∩clean** — carved classes also in clean | **0** | no carved class is observed in the clean counterpart |
| clean total classes | 50,911 | comparable-scale successor (infected ~50k) |

**Reading (same calibration as Necro).** *All carved `com.smart.sklb` classes are observed in the
infected build and absent from the clean counterpart; no carved class is observed in the clean
counterpart.* → **the longitudinal pair independently supports that the carve scope is
infection-associated** (counterfactual scope support), **not** scope-completeness (9.16.0 and 9.21.7
are different versions, not the same base binary). Provenance is verified by signer-cert equality, so
the clean side is a genuine SKT successor rather than a repackage. Harness: `analysis/goldoson_scopeval.sh`;
provenance record `research/scope_validation.csv`.

## Pair feasibility / acquisition status

| family | distribution model | pair type | counterfactual | status |
|---|---|---|---|---|
| **Necro/Coral** | trojanized app build | B (longitudinal) | Wuta 6.3.2 infected ↔ 6.9.8.161 clean | ✅ **in hand — pilot done** |
| **Goldoson** | dev-included supply-chain SDK | B (longitudinal) | TMAP 9.16.0.291767 ↔ 9.21.7.291923 (same app) | ✅ **done — TMAP lineage** (apkeep/APKPure, signer-verified) |
| **SpinOk** | marketing SDK | B (longitudinal) | infected ↔ SpinOk-removed version (e.g. Zapya) | ⛔ acquisition — infected/removed pair needed |
| **Konfety** | Play decoy + evil-twin | A (base-matched) | Play decoy ↔ evil-twin | ⛔ acquisition + **matching identification** (twin ↔ decoy) |
| **MobiDash** | parasite repackaging | A (base-matched) | original legit APK ↔ MobiDash-patched | ⛔ acquisition + **original identification** (which app was repackaged) |

**Termination (snapshot).** Define each family's distribution model + natural-counterfactual type up
front; run pair-derived scope validation on **every family where a provenance-compatible counterpart
can actually be obtained**; for families where it cannot, record the reason as an **evaluation
limitation / acquisition gap** (*not* as an RQ4 result). **Report the two counts separately:**
#families sdk-carve was *applied* to vs #families with a *pair-validated* scope — **currently applied 5
/ pair-validated 2** (Necro/Coral, Goldoson/TMAP).

---

## Preservation contract (what "correct enough" means, made explicit)

A carve is faithful when, for the target SDK: **(1) the method set, (2) the internal call graph, and
(3) the boundary call-sites are preserved** — which we measure to be exact here. What is *deliberately
not* preserved: **callee bodies across the boundary** (host-app methods the SDK calls), and flows that
leave and re-enter through **reflection / dynamic loading / JNI / framework-mediated** paths. Those are
the stated limits, not silent losses.
