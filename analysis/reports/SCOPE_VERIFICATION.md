# Scope verification — is the 59-file target complete?

Author: AI agent (Claude Opus 4.8, 1M context)
Date: 2026-08-31
Question: does the SMARTLB/Goldoson flow call any **SDK-logic class outside** the
chosen scope (`com/smart/sklb/edge/**` + `bg`/`cg`/`dg`, 59 `.java`) that was excluded?

## Method

Reverse dependency trace from the SDK bytecode (authoritative), plus a source-level
import cross-check:

1. **Callee owners from the scoped CPG** — every method the SDK invokes:
   `cpg.call.methodFullName` → 213 distinct owner types
   (`analysis/joern/scripts/scope-check.sc`).
2. Filter out standard library/framework/bundled-lib and in-scope packages.
3. Inspect every remaining owner and every out-of-scope source `import`.

## Result

After removing libs (java/android/androidx/GMS/retrofit/okhttp/gson/picasso/apache/
coremedia/mixpanel) and the in-scope packages, the SDK's **method calls** reach only
**5 external owners** — all identical between `jdeps` and the CPG:

`b7.c`, `g4.e`, `g4.i`, `i1.b`, `w1.i`

Each is a **R8 compiler synthetic class** (`/* compiled from: R8$$SyntheticClass */`)
whose only method is a shared `StringBuilder.append(...)` helper, and each is called
**only from `toString()`** of the SDK's own DTOs (`nepkt_*`, `bg.*`). These are
compiler-generated string builders, **not SDK logic**.

The source-level import scan surfaces a few more out-of-scope names — all are either
**dead imports** (R8 constant-pool merging makes jadx emit an import that the readable
body never uses) or **static constant field reads**, never calls:

| Out-of-scope name | How the SDK uses it | Verdict |
|---|---|---|
| `b7.c`,`g4.e`,`g4.i`,`i1.b`,`w1.i` | `StringBuilder.append` in `toString()` | R8 synthetic, not logic |
| `ke.e.Q` / `ke.e.R` | carrier-name string constants in `c/i.g()` | constant read |
| `TmapMciOtpFragment.f26649l` | default `service_wait_time` (long) | constant read |
| `RGConstant...NONE` | `"0"` hex-padding in `c/i.d()` | constant read |
| `AiConstant.f31028d0` | string compared in a DTO `equals` | constant read |
| `com.skt.aicloud.sdk.BuildConfig` | SDK version string in `c/a` ad request | constant read |
| `com.naver.gfpsdk.*`, `com.skt.aicloud.*contacts/*database`, `com.skt.moment.*`, `com.skt.tmap.activity.a`, `com.tmapmobility.*`, `ym.l`, `sc.d`, `je.h`, `ib.a`, `x9.a` | import present, no body reference | dead import (R8 artifact) |

(Note: the FQN source-grep under-counts short-named constant use — e.g.
`BuildConfig.MIN_TYCHE_VERSION` is used but reads as `BuildConfig.…`. The **bytecode
call analysis is authoritative** and shows only the 5 R8 synthetics as external calls.)

## Conclusion

**No SDK-logic class was missed.** Every behavior (method call/instantiation) either
stays inside the 59-file scope or targets a standard library/framework API or a
compiler-generated string helper. Out-of-scope references are limited to R8 synthetics,
borrowed static constants, and dead imports — none carry SDK behavior. The scope chosen
per `AGENTS.md`/`ANALYSIS_STATUS.md` (start at `com.smart.sklb.edge`, plus referenced
`bg`/`cg`/`dg`) is therefore **complete and self-contained** for analyzing the SDK.

Scripts: `analysis/joern/scripts/scope-check.sc`, `scope-detail.sc`.
