# Track 2 — Scoped CodeQL (build-mode=none) result

Author: AI agent (Claude Opus 4.8, 1M context)
Date: 2026-08-31
Goal: produce a **reproducible, defensible** CodeQL database that *finalizes* on this
target (unlike the 3 historical DBs) and answers the source/sink question with a
query artifact. Tools: CodeQL 2.26.3.

## What changed vs. the historical attempts

| | Historical (3 DBs) | Track 2 (`edge-scoped`) |
|---|---|---|
| Source root | whole JADX tree / reconstructed app / empty | scoped 59-file copy (`analysis/codeql/src-scoped/`) |
| Build | required a Java build (Gradle/JDK) → failed | **`--build-mode=none`** — no build |
| Baseline | one had **0 LOC**; others polluted by Android SDK | **4,825 LOC**, target only |
| Outcome | never finalized | **"Successfully created database"** in ~48 s |

The two decisive changes: **scope the source root** and **`--build-mode=none`**
(CodeQL ≥2.16, fully supported in 2.26.3), which extracts Java without compiling —
so decompiled dependencies and the two `Method not decompiled` stubs no longer block
database creation. The scoped target also has **zero `??` syntax placeholders**, so
extraction is clean.

## Reproduce

```bash
export JAVA_HOME=/Library/Java/JavaVirtualMachines/temurin-17.jdk/Contents/Home
codeql database create analysis/codeql/databases/edge-scoped \
  --language=java --build-mode=none --source-root=analysis/codeql/src-scoped
codeql pack install analysis/codeql/queries
codeql query run --database=analysis/codeql/databases/edge-scoped \
  analysis/codeql/queries/edge_flows.ql
```

Artifacts: DB `analysis/codeql/databases/edge-scoped/` (finalized,
`codeql-database.yml` present), query `analysis/codeql/queries/edge_flows.ql`,
results `analysis/codeql/results/edge_flows.csv`.

## Query result

`edge_flows.ql` (matches by method name, since `build-mode=none` leaves external
types unresolved) evaluated in ~0.66 s → **30 rows: 21 source calls, 9 sink calls**.

Sinks recovered (all `binary-confirmed`):
`putCol` ×2 (`wepkr_luhFzJx$l.run`, `$m.run`), `getPdata` (`.c0`), `userJoin` (`.G`),
`getBConfig` (`.H`), `isRunable` (`$g.run`), `loadData` (`c.k.b`),
`loadUrl` ×2 (`c.k$c`, `c.k.a`).

Sources recovered: installed-apps (`getInstalledApplications`), MAC
(`getHardwareAddress`), Bluetooth (`getBondedDevices`, `getAddress`), Wi‑Fi
(`getConnectionInfo`, `getBSSID`, `getSSID`, `getScanResults`), carrier
(`getNetworkOperatorName`).

## Cross-verification finding (why the tracks are complementary)

The source-only DB (no Android/GMS/Retrofit dependencies) did **not** name-resolve a
few external-call sources that **Joern's bytecode CPG did** catch:

| Source | Joern (bytecode CPG) | CodeQL (source, build-mode=none) |
|---|---|---|
| `getInstalledApplications`, `getHardwareAddress`, Wi‑Fi, Bluetooth, carrier | ✅ | ✅ |
| `getAdvertisingIdInfo` (advertising ID) | ✅ | ❌ not resolved |
| `getLastLocation` / `getLatitude` / `getLongitude` (GPS) | ✅ | ❌ not resolved |

`build-mode=none` does best-effort extraction; without the GMS/Android jars it can
leave some external calls unresolved. **Joern over bytecode is more complete for
external API sinks/sources; CodeQL over source is more reproducible and portable.**
Using both is what closes the gap — the exact opposite of the historical situation
where neither finalized.

## Taint boundary (same as Track 1)

Byte-precise source→sink paths are blocked by the same structure in both tools: data
flows **source → `SharedPreferences.putString` → `getString` → SDK constructors →
Retrofit interface call**. Recovering full paths requires explicit flow models
(CodeQL `additional taint steps` / a Joern `semantics` file) for `SharedPreferences`
and the SDK's DTO constructors. The call-graph reachability (Track 1: `onStartJob` →
every sink) plus the source/sink inventory here is sufficient to establish the
capability; byte-precise taint modeling is an optional follow-up.

## Status

Track 2 goal met: a scoped CodeQL DB that **finalizes** (the historical blocker),
plus a reproducible `.ql` + CSV artifact that recovers the source/sink inventory and,
by comparison with Track 1, demonstrates why bytecode+source cross-verification is the
right modern approach.
