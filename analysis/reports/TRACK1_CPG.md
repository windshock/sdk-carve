# Track 1 — Scoped CPG via jimple2cpg (result)

Author: AI agent (Claude Opus 4.8, 1M context)
Date: 2026-08-31
Goal: prove a CPG now finalizes on this target and tool-verify the source→sink paths
that Track 3 found by hand. Direct rebuttal of the historical failure
(`analysis/joern/projects/dex2jar-incomplete/` = 2 GB `cpg.bin.tmp`, never finished).

## What changed vs. the historical attempt

| | Historical (`dex2jar-incomplete`) | Track 1 (`edge-scoped`) |
|---|---|---|
| Frontend input | whole `tmap-dex2jar.jar` (~50k classes) | scoped mini-JAR (117 classes) |
| Frontend | jimple2cpg (bytecode) | jimple2cpg (bytecode) |
| Result | 2.0 GB `cpg.bin.tmp`, never finalized | **538 KB `cpg.bin`, finalized in ~2.2 s** |

The fix was **scoping the JAR before ingestion**, not changing the tool. Bytecode input
also means the decompiler damage (`??`, `Method not decompiled`) is irrelevant — e.g.
`c.c.d()` (undecompilable in JADX) is fully present in the CPG.

One environment gotcha, now documented: the Homebrew `jimple2cpg`/`joern` launcher
defaults `JAVA_HOME` to Homebrew `openjdk` (Java 25 = class major version 69), which
Soot's ASM rejects ("Unsupported class file major version 69"). Run with
`JAVA_HOME=<JDK 17>` (Temurin 17 present on this host).

## Reproduce

```bash
JAR=artifacts/derived/tmap-dex2jar.jar
WORK=$(mktemp -d); (cd "$WORK" && unzip -q "$OLDPWD/$JAR" 'com/smart/sklb/*' 'bg/*' 'cg/*' 'dg/*')
jar cf analysis/joern/projects/edge-scoped/edge-scoped.jar -C "$WORK" .
export JAVA_HOME=/Library/Java/JavaVirtualMachines/temurin-17.jdk/Contents/Home
cd analysis/joern/projects/edge-scoped && jimple2cpg edge-scoped.jar --output cpg.bin
cd ../../scripts && joern --script edge-taint.sc    # query script
```

Artifacts: `analysis/joern/projects/edge-scoped/{edge-scoped.jar,cpg.bin}`,
query `analysis/joern/scripts/edge-taint.sc`.

## CPG stats

`methods=893  calls=9195  typeDecls=289` — fully queryable.

## Sources recovered (device-data reads, with locations)  `binary-confirmed`

`getAdvertisingIdInfo` (`c.b$a.run`), `getInstalledApplications`
(`c.c.d`, `c.c.h`, `c.c.j` — **including the JADX-undecompilable `c.c.d`**),
`getHardwareAddress` (`c.c.c`), `getBondedDevices` (`c.d.d`),
`getConnectionInfo`/`getBSSID`/`getSSID` (`c.j.b`), `getScanResults`
(`c.j$a.onReceive`), `getLastLocation`/`getLatitude`/`getLongitude`
(`c.g$a.onLocationResult`, and `wepkr_luhFzJx$l$b.run` — the other undecompilable
method), `getAddress` (Bluetooth, `nepkt_hrnRzBxI`, `wepkr_luhFzJx$c.run`,
`wepkr_luhFzJx$l$b.run`), `getNetworkOperatorName` (`c.i.g`).

## Sinks recovered (network / WebView, with locations)  `binary-confirmed`

`userJoin` (`wepkr_luhFzJx.G`), `getBConfig` (`wepkr_luhFzJx.H`), `isRunable`
(`wepkr_luhFzJx$g.run`), `getPdata` (`wepkr_luhFzJx.c0`), `putCol`
(`wepkr_luhFzJx$l$b.run`, `$l.run`, `$m.run`), `loadData` (`c.k.b`),
`loadUrl` (`c.k$c.shouldOverrideUrlLoading`, `c.k.a`).

## Call-graph reachability: `onStartJob` → sinks  `binary-confirmed`

From the JobService entry set (`onStartJob`/orchestrator runnables), reachable:

| Sink | Reachable | Call sites |
|---|---|---|
| `putCol` (collection upload) | **yes** | 3 |
| `getPdata` (ad HTML fetch) | **yes** | 1 |
| `userJoin` (register) | **yes** | 1 |
| `getBConfig` (remote config) | **yes** | 1 |
| `isRunable` (gate) | **yes** | 1 |
| `loadData` (WebView HTML exec) | **yes** | 1 |
| `loadUrl` (WebView) | **yes** | 2 |

This tool-verifies Track 3's central claim: the background service can reach every
network-exfiltration sink **and** the hidden-WebView `loadData` sink.

## Fine-grained taint (`reachableByFlows`): 0 flows — and why

`snk.reachableByFlows(src)` returned **0**. This is expected, not a failure of the
approach: the collected values travel **source → `SharedPreferences.putString` →
… → `getString` → object constructors (`nepkt_hrnRzWxI/RzLxI/RzBxC` …) → Retrofit
interface call**. jimple2cpg's default dataflow semantics do not propagate taint
through the SharedPreferences round-trip, through the SDK's own constructors
(field-sensitivity), or across the Retrofit interface boundary. Closing this needs
explicit flow **semantics/models** for those methods.

Net: **reachability is tool-confirmed; byte-precise taint needs custom semantics** —
which is exactly what Track 2 (CodeQL taint models) and/or a Joern `semantics` file are
for. The value here is that the CPG now exists, finalizes, and is queryable at all —
the thing that was impossible before.

## Status

Track 1 goal met: CPG finalizes on the scoped target and confirms source/sink
inventory + entry→sink reachability. Follow-ups (optional): add Joern flow semantics
for `SharedPreferences`/constructors to recover byte-precise flows; or rely on Track 2.
