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
carving didn't break dataflow — nothing to break). The *positive* evidence — carved and whole-app
producing the **same non-zero** taint flows — is **not yet demonstrated** and is the clear next step:
add dataflow **semantics models** for the `Bundle`/serialization sinks, then compare flow sets. Until
then this section claims **structural** (surface) fidelity, not **semantic** (dataflow) equivalence.

## Preservation contract (what "correct enough" means, made explicit)

A carve is faithful when, for the target SDK: **(1) the method set, (2) the internal call graph, and
(3) the boundary call-sites are preserved** — which we measure to be exact here. What is *deliberately
not* preserved: **callee bodies across the boundary** (host-app methods the SDK calls), and flows that
leave and re-enter through **reflection / dynamic loading / JNI / framework-mediated** paths. Those are
the stated limits, not silent losses.
