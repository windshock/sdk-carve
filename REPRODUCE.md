# Reproduce

Regenerate the derived artifacts (corpus, mini-JAR, CPG, CodeQL DB, query results)
from the sample. Nothing derived is tracked in this repo.

## Prerequisites

- JDK **17** (see the JAVA_HOME note below), plus `jar`/`unzip`
- [JADX](https://github.com/skylot/jadx) (also provides dex→jar), or `dex-tools`
- [Joern](https://joern.io) (bundles `jimple2cpg`)
- [CodeQL CLI](https://github.com/github/codeql-cli-binaries) 2.16+ (tested on 2.26.3)

> **JAVA_HOME gotcha:** the Homebrew `joern`/`jimple2cpg` launcher defaults `JAVA_HOME`
> to the newest OpenJDK (Java 25 = class major 69), which Soot's ASM rejects
> (`Unsupported class file major version 69`). Pin JDK 17 for both jimple2cpg and CodeQL:
> `export JAVA_HOME=<path-to-jdk-17>`

## 0. Get the sample

Obtain the Goldoson APK (`com.skt.tmap.ku`, SMARTLB 5.4.1), e.g. from
<https://github.com/IHbib/goldoson-samples>. Then:

```bash
jadx -d corpus/decompiled/jadx sample.apk        # readable source (for citations)
# and a dex2jar-style JAR of the same app, e.g. via d2j-dex2jar:
d2j-dex2jar sample.apk -o app-dex2jar.jar
```

## 1. Scope → mini-JAR (the carve)

```bash
WORK=$(mktemp -d)
(cd "$WORK" && unzip -q "$OLDPWD/app-dex2jar.jar" 'com/smart/sklb/*' 'bg/*' 'cg/*' 'dg/*')
mkdir -p analysis/joern/projects/edge-scoped
jar cf analysis/joern/projects/edge-scoped/edge-scoped.jar -C "$WORK" .
# ~117 classes, ~113 KB
```

## 2. Scoped CPG (Track 1)

```bash
export JAVA_HOME=<jdk17>
cd analysis/joern/projects/edge-scoped
jimple2cpg edge-scoped.jar --output cpg.bin      # ~2.2 s, ~538 KB
cd ../../scripts
joern --script edge-taint.sc                     # sources/sinks + reachability
joern --script scope-check.sc                    # reverse-trace / scope completeness
```

## 3. Scoped CodeQL (Track 2)

```bash
export JAVA_HOME=<jdk17>
# copy only the target packages' .java into a clean source root:
mkdir -p analysis/codeql/src-scoped
rsync -aR --include='*/' \
  --include='com/smart/sklb/***' --include='bg/***' --include='cg/***' --include='dg/***' \
  --exclude='*' corpus/decompiled/jadx/sources/./ analysis/codeql/src-scoped/

codeql database create analysis/codeql/databases/edge-scoped \
  --language=java --build-mode=none --source-root=analysis/codeql/src-scoped
codeql pack install analysis/codeql/queries
codeql query run --database=analysis/codeql/databases/edge-scoped \
  analysis/codeql/queries/edge_flows.ql
```

## Notes

- `file:line` citations in `analysis/reports/` are relative to the JADX export in
  step 0; exact line numbers depend on the JADX version.
- Fine-grained taint (`reachableByFlows` / CodeQL path) returns 0 by default: data
  crosses `SharedPreferences` and DTO constructors, which need explicit flow models.
  Call-graph reachability + the source/sink inventory establish the capability; see
  `analysis/reports/TRACK1_CPG.md` and `TRACK2_CODEQL.md`.
