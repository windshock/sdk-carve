# Cross-app validation — the method across all 11 Goldoson samples

Author: AI agent (Claude Opus 4.8, 1M context)
Date: 2026-08-31
Question: does the sdk-carve method generalize beyond the single TMAP worked example,
and does the SDK-root auto-detection (`scripts/detect.py`) hold up across obfuscation
variants?

The TMAP deep-dive (`docs/`, `analysis/reports/`) proves the method on one app with a
surviving package name (`com.smart.sklb.edge`). This note applies the same pipeline to
the other 10 apps in the Goldoson sample set, where the SDK package — and in one case the
SDK's own method names — are R8-renamed per app.

## Method (per app, scripted)

1. `d2j-dex2jar` the APK.
2. `scripts/detect.py app-dex2jar.jar` → carve globs (anchors on the SDK-unique method
   names, size/depth/denylist guards, 4-segment `com/*` rule, WiFi-scan ∩ BT-bonded
   structural fallback).
3. `scripts/carve.sh` → scoped mini-JAR + CPG.
4. `scripts/source-sink.sc` → sources / sinks / entry→sink reachability.
5. `scripts/scope-closure.sc` → external-owner closure (scope-completeness).
6. Grep the carved bytecode for hardcoded C2/ad hosts.

## Result

Every app carries the same Goldoson/SMARTLB SDK, recompiled under a renamed root. All
sinks present are reachable from the JobService/thread entry, and every app hardcodes at
least one C2 domain from the McAfee/Goldoson IOC list.

| App | app classes | carved | Goldoson root(s) | README C2 hit |
|---|--:|--:|---|---|
| com.skt.tmap.ku (TMAP, deep-dive) | 50157 | 117 | `com/smart/sklb/edge` +bg/cg/dg | bhuroid.com |
| com.Monthly23.SwipeBrickBreaker | 13974 | 201 | `com/tajsl/htmxm/bxkdhqor` | rouperdo.net, visceun.com |
| com.appsnine.audiorecorder | 11677 | 163 | `com/enoi/yweoi/nwef` | ojiskorp.net, openwor.com |
| com.appsnine.compass | 12385 | 210 | `com/enoi/yweoi/nwef` +s5 | ojiskorp.net, openwor.com |
| com.gretech.gomplayerko | 59668 | 295 | `com/gwox/pzkvn/riosk` | methinno.net, phyerh.net, ridinra.com |
| com.megabox.mop | 42702 | 271 | `com/mqas/gwey/bcvg` | soridok2kpop.com, sorrowdeepkold.com |
| com.somcloud.somnote | 58431 | 184 | `com/sshxm/ndos/txm` | discess.net |
| com.wtwoo.girlsinger.worldcup | 25137 | 176 | `com/eltqkdl/sekai/hontoni` +f2 | **goldoson.net**, necktro.com |
| kr.co.lottecinema.lcm | 16620 | 273 | `com/leri/trub/mwelpk` | treffaas.com |
| kr.co.psynet (LIVE Score) | 33786 | 195 | `com/ldlqm/vfl/szhdj` | dalefs.com, fuerob.com |
| mafu.driving.free | 7783 | 144 | `com/tnrhd/emfkdl/gmdk` | gadlito.com, hjorsjopa.com |

## What generalizes

- **Root shape is a stable fingerprint.** Every Goldoson root is a 4-segment
  `com/<a>/<b>/<c>` package (matching `com/smart/sklb/edge`), plus occasional short helper
  packages (`f2`, `s5`). This is what `detect.py`'s `SEGS=4` rule keys on.
- **Anchor on the SDK's own names, guard against shaded libs.** Naïvely anchoring on
  framework scan APIs over-scopes: `getScanResults`/`getBondedDevices` also live in an
  8k-class shaded library (`e`/`d`) in several apps. The size guard (≤400) and depth guard
  reject those; the lib denylist rejects jackson/glide/igaworks/mapps.
- **Structural fallback when method names are gone.** `kr.co.lottecinema.lcm` renamed the
  SDK's *own* method names, so name-matching found 0 core anchors. The WiFi-scan ∩
  BT-bonded collector-triad fallback located `com/leri/trub/mwelpk`. Its name-matched sink
  count is low (2 — only framework `loadUrl`/`loadData` survive) precisely because the SDK
  method names are renamed; the sources (framework APIs) still match (11).
- **Honest scope boundaries.** `com.appsnine.audiorecorder` shows only 1 in-scope source
  because that build delegates BT/Wi-Fi scanning to a shaded library (`e.d.a`), left out of
  scope on purpose by the size guard — a boundary, not a miss. `scope-closure` external
  owners for most apps are a handful of R8-renamed libraries (okhttp/okio/gson/glide →
  short names), not missed SDK logic.

## Incidental IOCs

- **README/McAfee domains hit across the batch (17 distinct):** bhuroid.com, dalefs.com,
  discess.net, fuerob.com, gadlito.com, goldoson.net, hjorsjopa.com, methinno.net,
  necktro.com, ojiskorp.net, openwor.com, phyerh.net, ridinra.com, rouperdo.net,
  soridok2kpop.com, sorrowdeepkold.com, treffaas.com, visceun.com.
- **Ad/config hosts not in the McAfee README list** (observed in carved bytecode):
  appservice9.com, trs.bestsmartshop.net, retoore.com, barivemi.net, huejura.com.
- `com.appsnine.audiorecorder` and `com.appsnine.compass` share the exact SDK root
  (`com/enoi/yweoi/nwef`) and server set — same developer build.

## Limits

Static, binary-confirmed, name-matched. Fine-grained taint was not run in the batch (the
framework-boundary limit from the TMAP deep-dive applies: data crosses SQLite/DTO/Retrofit
boundaries). Which C2 is actually contacted, and the collection cadence, are gated at
runtime by the SDK's remote-config (`getBConfig`/`isRunable`).
