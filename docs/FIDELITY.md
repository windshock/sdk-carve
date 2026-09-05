# Semantic fidelity & failure boundary — carved vs whole-app CPG (RQ3 / RQ5)

*Answers the reviewer question "method present ≠ analysis meaning preserved."* Compares the **carved**
CPG against the **complete whole-app** CPG (jimple2cpg patched with
[joernio/joern#6257](https://github.com/joernio/joern/pull/6257), so the whole-app graph actually
contains the SDK) — beyond method-count, at the **call-graph** level.

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
| _(SwipeBrickBreaker / megabox / somnote / gomplayerko / psynet / TMAP — batch completing; large whole-app builds. All apps measured so far = exact 100 %.)_ | | | | | |

**Finding (RQ3).** Across every app measured, the carved CPG reproduces the SDK's **internal
call graph with 0 divergence** — same method set, same internal call edges (recall 100 %, no
carved-only or whole-app-only internal edges). Carving is not a lossy approximation of the SDK's
own semantics; within the scope it is *identical* to what the whole-app analysis sees.

**Finding (RQ5 — the boundary is the cut, and it is mostly framework).** The only difference is at
**boundary edges** (SDK → non-SDK). The carved graph keeps the *call site* but the callee is a stub;
the whole-app graph resolves the callee body. Of these boundary targets, **55–92 % are framework /
standard library** (`android.*`, `java.*`, …) — which are **stubs in the whole-app graph too**
(neither includes `android.jar`), so they are *not* lost context. The genuinely-lost context is only
the **non-framework (host-app) fraction** of boundary calls — and this is exactly the documented,
intentional reduction: flow *through* host-app code is not followed (see `docs/PRE_CARVE.md` for the
reflection / dynamic-loading / native caveats that also break the closure).

## Preservation contract (what "correct enough" means, made explicit)

A carve is faithful when, for the target SDK: **(1) the method set, (2) the internal call graph, and
(3) the boundary call-sites are preserved** — which we measure to be exact here. What is *deliberately
not* preserved: **callee bodies across the boundary** (host-app methods the SDK calls), and flows that
leave and re-enter through **reflection / dynamic loading / JNI / framework-mediated** paths. Those are
the stated limits, not silent losses.
