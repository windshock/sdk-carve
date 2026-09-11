# Issue #5 — does target-aware carving generalize beyond Goldoson? (evidence synthesis)

**RQ (GitHub issue #5 / PLAN Track 2):** target-aware SDK carving was developed on the Goldoson family.
Does it generalize to *unrelated* SDK families across RQ4's stress axes (different families, versions,
hosts, R8/renames, damaged/packed decompilation, big apps, lib-dependent SDKs)? This report synthesizes
the carves accumulated across the offerwall + KR-RASP work as generalization evidence. It does **not**
re-run them — it maps existing per-SDK triage results onto the RQ4 axes.

## Evidence set — unrelated SDK families carved target-aware + analyzed
| SDK family (target root) | host / artifact | carve size | analyzer | RQ4 axis stressed | outcome |
|---|---|---|---|---|---|
| **GAD / BeanShell** (`com.gpakorea…`) | Syrup app | behavior-sweep + carve | bsh sandbox + JS replay | server-script channel; big app | server BeanShell eval channel found |
| **Syrup host `ob`** (R8 modules) | Syrup app (104,029 cls) | 109 cls | carve + API map | **R8-renamed** modules; big app | first-party telemetry → nxt.syrup.co.kr |
| **SK Planet proximity `bb8`** (`com/skplanet/sdk/proximity`) | Syrup app | 449 cls | carve | unrelated family (proximity, not adtech) | WiFi/BLE/location/applist survey SDK |
| **TNK rwd** (`com/tnkfactory/ad`) | AAR ×2 (v7.31.3, v8.09.32) | 331 / **664** cls | jimple2cpg → joern `reachableByFlows` | **multi-version + obfuscation variance** (v7 string-encrypted, v8 plaintext) | custom-ObjectInput deser surface |
| **Tyrads** (`com/tyrads/sdk`) | OK캐시락커 (bundled) | 89 cls | jimple2cpg → joern | **bundled-in-host**, consent-gated | usage-stats consent flow; `queryUsageStats` call = 0 in CPG (vaulted) |
| **Adison** (`co.adison.offerwall`) | Syrup-bundled AAR (628 cls) | 628 cls | jimple2cpg → joern | real-name pkg + **embedded 3rd-party** (exp4j) | webview navigation bridge surface |
| **Coocon SASAPI** (`kr/co/coocon`) | M-STOCK (xShield payload) | **865 cls → 7,877 methods** | jimple2cpg → joern | **damaged/packed decompilation** (decrypt→carve); big financial app | server-JS (Rhino/V8) scraping channel |
| **(negative) Toss-obfuscated dex** | Toss-bundled | — | — | **dex-encryption** | carve blocked; documented LIMIT (packer-detect → arsc fallback) |

## What the set demonstrates (against RQ4)
- **Unrelated families (≥6):** adtech offerwall (GAD/TNK/Tyrads/Adison), proximity (bb8), first-party
  telemetry (Syrup `ob`), financial scraping (Coocon). The method is not offerwall- or Goldoson-specific.
- **Multiple versions / obfuscation variance:** TNK v7 (string-encrypted, 331 cls) vs v8 (plaintext, 664
  cls) carved the same root under different protection policies.
- **Hosts:** standalone AARs, a bundled locker app, a big Syrup app (104k cls), and a packed brokerage app.
- **R8 / renames:** Syrup `ob` modules carved despite R8 renaming; real-name roots (Adison/TNK/Coocon) trivial.
- **Damaged/packed decompilation:** Coocon was reached only after `xshield-reversal` decrypted the payload
  (packed → plaintext → carve) — the pre-carve stage composes with the carve to reach otherwise-inert code.
- **Big apps:** 104k-class Syrup and multi-dex M-STOCK both carved to a small target root without whole-app CPG.
- **Lib-dependent SDKs:** Adison embeds exp4j; Coocon embeds Rhino + V8 — carved with their embedded deps.
- **Analyzer-agnostic:** carves fed **both** jimple2cpg→joern (TNK/Tyrads/Adison/Coocon) **and** CodeQL
  `--build-mode=none` (Track 2 edge-scoped DB, TRACK2_CODEQL.md). The carve output is not tied to one engine.

## Honest limits (defensibility — "what's preserved vs lost")
- **Carve finds the class, not always the behavior:** Tyrads' `queryUsageStats`/`UsageStatsManager` call
  is **0 in the CPG** — capability is indicated by class-name + requested permission, but the actual
  collection call sits behind a vault/payload not present in the carved bytecode. Carving preserves
  reachable structure; runtime-vaulted behavior needs the payload/dynamic stage.
- **Auto-dataflow under-stitches:** recurring `0 flows` across socket/collection/coroutine hops (Coocon
  net→eval, TNK reachability) — a joern stitching limit, not a carve defect; structural call-graph evidence
  remained conclusive.
- **Packing can block carve entirely:** Toss dex-encryption defeated `packer-detect` (arsc fallback) — a
  documented negative that bounds the claim to "carve generalizes *once code is recoverable*".

## Bottom line for issue #5
Target-aware carving **generalized across every unrelated family attempted where the code was recoverable**,
spanning version/obfuscation/host/size/lib-dependency variance, and its output drove two independent
analyzers. The failure mode is not the carve but *code recoverability* (packing) and *behavior residency*
(runtime vaults) — both handled by composing the pre-carve (xshield-reversal / unpackers) and payload/
dynamic stages. → Recommend citing this set as the RQ4 diversity evidence in the issue #5 writeup, and
closing the "generalizes-beyond-Goldoson" claim as **supported, with the two bounded limits above stated**.

Evidence pointers: `GAD_*`, `SYRUP_SDK_TRIAGE`, `TNK_FULLPASS`/`TNK_SDK_TRIAGE`, `TYRADS_SDK_TRIAGE`,
`ADISON_SDK_TRIAGE`, `COOCON_SASAPI_TRIAGE`, `TRACK2_CODEQL`, `XSHIELD_FLEET_SURVEY` (all in this dir).
