# Analysis status

Last workspace audit: 2026-08-31

> **2026-08-31 update — scoped re-analysis succeeded.** The historical whole-app
> failures below are preserved as evidence. A new scoped run (target = ~59 files of
> `com.smart.sklb.edge` + `bg`/`cg`/`dg`) now completes on all three tracks. See
> `analysis/reports/SUMMARY.md` and `analysis/reports/ANALYSIS_PLAN.md`.
>
> | New (scoped) artifact | State |
> |---|---|
> | `analysis/joern/projects/edge-scoped/cpg.bin` | **Finalized** via `jimple2cpg` on a 117-class mini-JAR (~2.2 s, 538 KB) |
> | `analysis/codeql/databases/edge-scoped/` | **Finalized** via `--build-mode=none` (4,825 LOC baseline) |
> | `analysis/joern/scripts/edge-taint.sc`, `analysis/codeql/queries/edge_flows.ql` | Query artifacts; recover the source/sink inventory |
> | Reports | `analysis/reports/TRACK1_CPG.md`, `TRACK2_CODEQL.md`, `TRACK3_DATAFLOW.md` |
>
> Run frontends with `JAVA_HOME` pinned to JDK 17 (the Homebrew launcher otherwise
> selects Java 25, which Soot rejects).

## Artifact inventory

| Artifact | State |
|---|---|
| `artifacts/derived/tmap-dex2jar.jar` | Present; SHA-256 `5525576e129c71174f986a25588aa71331f6ff62a245a85aca5d236ffb31d50b` |
| Original APK | Missing |
| Canonical JADX export | Present: 26,980 Java files and 6,300 resource files |
| Extracted class tree | Present: 50,893 class files |
| Native libraries | Present: 34 `.so` files for ARM64/ARMv7 |

## Decompiler quality

- 1,407 Java files contain at least one `Method not decompiled` marker.
- Those files contain 2,067 unsupported-method stubs in total.
- 105 Java files contain `??` syntax placeholders.
- Important high-level Goldoson paths are readable, but whole-application Java
  compilation and parser-based analysis are unreliable.

## Tool results

| Tool | Location | Status |
|---|---|---|
| Semgrep | `analysis/semgrep/` | Historical whole-tree run failed; the new targeted 49-file run completes with 6 Retrofit endpoint candidates and no parse errors |
| CodeQL | `analysis/codeql/databases/root-jadx-incomplete/` | Not finalized; Gradle/JDK and extractor failures |
| CodeQL | `analysis/codeql/databases/reconstructed-app-incomplete/` | Not finalized; included copied Android SDK content in baseline |
| CodeQL | `analysis/codeql/databases/empty-source-incomplete/` | Not finalized; zero baseline LOC |
| Joern | `analysis/joern/projects/reconstructed-app/` | Completed `cpg.bin` and `cpg.bin.zip` are present |
| Joern | `analysis/joern/projects/dex2jar-incomplete/` | Incomplete; only a 2 GB `cpg.bin.tmp` remains |

Historical CodeQL and Joern metadata contains the old absolute workspace paths.
Treat it as preserved evidence, not a relocatable project configuration.

The successful targeted Semgrep result is stored at
`analysis/semgrep/results/targeted-scan.json`. It is candidate collection only,
not a completed source-to-sink trace.

## Build state

- The reconstructed Android project has manifest/resource merge output but no APK.
- Its Gradle file says target SDK 31 while the extracted manifest says target SDK 33.
- Decompiled dependencies and invalid methods make a clean rebuild unlikely without
  substantial repair.
- `experiments/gradle-harness/` is a historical JAR-loading experiment, not a test
  suite for the host application.

## Recommended next analysis sequence

1. Work only in `com.smart.sklb.edge`, plus directly referenced `bg`, `cg`, and `dg` classes.
2. Use the canonical JADX source for readability and JAR/class evidence for ambiguous methods.
3. Rebuild a small source/sink model around identifiers, installed apps, Wi-Fi,
   Bluetooth, Retrofit requests, and WebView HTML.
4. If runtime validation is authorized, use an isolated emulator and sinkhole/mock
   endpoints rather than contacting embedded domains.
