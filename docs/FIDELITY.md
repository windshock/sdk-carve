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

**External validity (benign, non-Goldoson SDK + non-Goldoson host).** The same exact preservation
holds outside the Goldoson family: carving **okhttp3 + okio** (a well-known benign library, 249 classes)
from **DMB-TV** (`com.project.onair`, a benign streaming app) vs its whole-app CPG → **2295 = 2295
methods, 3314/3314 internal edges shared (0 divergence, 100 % recall), boundary identical**. So the
structural-fidelity result is not a property of Goldoson or of malware — it holds for an arbitrary
embedded SDK in an unrelated host. *(No download needed — DMB-TV was already in hand.)*

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
Root cause: the SDK collects into **fields of a collector object** and passes that *object* to the
sink (`putCol(collector)`); a tainted *field* does not taint the *container argument* in general
static taint, and the SDK's serialization is obfuscated. So **0 flows is confirmed on two analyzers
(joern + CodeQL)**, orthogonal to carving. Positive **semantic** (dataflow) equivalence therefore
needs **per-SDK content/field-object models** (reverse-engineering the collector) — deferred as its
own subproject. Until then this section claims **structural** (surface) fidelity, not **semantic**
(dataflow) equivalence; the box in the figure keeps that cell explicitly blank.

## Boundary decomposition — what *kind* of context is cut (RQ5, #2; `research/boundary_classify.sh`)

The boundary (SDK → non-SDK) is the only place fidelity is lost. Deduped by **class** and classified
(boundary callees are identical carved=whole-app, so the fast carved CPG is used):

| app | boundary classes | framework/stdlib | recognized lib | obfuscated residue | **named host-app pkg** | residue % |
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

**Finding.** On **all 11 apps, zero boundary calls target a human-named host-app package**
(`named host-app pkg = 0`) — the SDK does not call the host application's business logic; its external
surface is **framework/stdlib + recognized libraries** (retrofit2/okhttp3/picasso/gson — network/
image/serialization, exactly the deps you'd stub or model). The only ambiguous cut is an
**R8-obfuscated residue** (short renamed classes like `g4`,`b7`): **0 % on 5/11**, up to 41 %. By name
it cannot be attributed to host-app vs bundled-library vs *missed-SDK-scope* — but the total absence
of human-named host packages makes host **business logic** an unlikely component of it. Attributing
the residue (per-class) is future work and directly motivates **adaptive context expansion** (pull the
residue's closure into the carve and re-check). *(Answer to "how much app context is needed":
none of the host's *named* code; at most a small obfuscated residue whose nature is TBD.)*

## Preservation contract (what "correct enough" means, made explicit)

A carve is faithful when, for the target SDK: **(1) the method set, (2) the internal call graph, and
(3) the boundary call-sites are preserved** — which we measure to be exact here. What is *deliberately
not* preserved: **callee bodies across the boundary** (host-app methods the SDK calls), and flows that
leave and re-enter through **reflection / dynamic loading / JNI / framework-mediated** paths. Those are
the stated limits, not silent losses.
