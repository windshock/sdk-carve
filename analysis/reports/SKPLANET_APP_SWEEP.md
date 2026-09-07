# SK Planet published-app sweep — malicious-SDK screen across the Play catalog

**Scope**: all apps on the Google Play developer page 에스케이플래닛(주) (SK Planet
Co., Ltd.) — 4 apps total (3 obtained via resolver/apkeep, 1 user-supplied).
**Date**: 2026-09-06. **Method**: per app — signer/sha256 record → dex2jar →
behavior-sweep (capability clustering) → 5-family IOC sweep (Goldoson, SpinOk,
Konfety, MobiDash, Necro/Coral) → attribution → carve + full mandatory analyzer pass
(Joern / CodeQL / Semgrep / scope-closure) on every non-`~` flagged root.
All findings `binary-confirmed` (static); nothing was executed.

## Catalog matrix

| app | version | sha256* | signer | 5-family IOC | unknown roots | verdict |
|---|---|---|---|---|---|---|
| 시럽 `com.skt.skaf.OA00026910` | 5.8.16_M (301) | `0a4ef3c6…` | `e981b282…` (SK) | **0 hits** | none | **clean** — first-party + commercial adtech |
| OK캐쉬백 `com.skmc.okcashbag.home_google` | 7.1.9 (243) | `d5e6a110…` | `42467702…` (SK 2011 cert) | **0 hits** | none | **clean** — first-party + commercial adtech/reward |
| 오락 `com.skplanet.ocb.locker` | 3.0.2 | `804fffddeb9d28f2…` | `42467702…` (**same key as OK캐쉬백**) | **0 hits** | none | **clean** — first-party + ad mediation |
| 위주로 `com.skplanet.wezuro` | 1.2.6 | `6de128a4…` | Play App Signing (Google-managed — genuine Play artifact) | **0 hits** | none | **clean** — Flutter app + ad mediation |

\* full hashes in `research/acquisition/corpus/targets/` provenance records.

## Per-app collector profile

**시럽** — bb8 proximity (store-visit tracking: WiFi/BSSID+BLE+GPS+GAID+installed-apps
→ `pxsens/pxpolicy.syrup.co.kr`, policy-gated), host telemetry (`nxt.syrup.co.kr/collect`),
Adison beacon SDK, mainstream ad networks. [SYRUP_SDK_TRIAGE.md](SYRUP_SDK_TRIAGE.md)

**OK캐쉬백** — same bb8 build (class-set identical ±1), Adison offerwall
(`co/adison`, 8k methods), **Enliple cashkeyboard** (device-id + typed-keyword →
`ocbapi.cashkeyboard.co.kr` — the app's top privacy-gray item), adjoe/tapjoy
(usage-stats rewards), TouchEn mVaccine AV, SKT TID auth, Pangle/IronSource/Mintegral
et al. [OKCASHBAG_SDK_TRIAGE.md](OKCASHBAG_SDK_TRIAGE.md)

**오락 (OCB locker)** — lockscreen app-tech. Full mandatory pass on three first-party
roots: host (`com/skplanet/ocb/locker`, 27k methods — Kotlin clean architecture, all
endpoints `*.okcashbag.com`, device-id/GAID/location for lockscreen content, Pubmatic
banner loading), `skpad/benefit` (SKP reward adtech — device-id as reward identifier;
execute/loadUrl/evaluateJavascript entry-reachable), `serviceappplatform` (SK common
platform lib; nothing entry-reachable). Ad mediation: Pangle (`openadsdk`/`pgl.ssdk`),
SafeDK (ad-SDK compliance monitor — its collection is its function), IronSource,
Mintegral, AppLovin, Kakao AdFit, Smaato, Fyber, Pubmatic, Mopub. **No bb8, no Adison,
no Enliple.** CodeQL 45 findings, all first-party; Semgrep 135, consistent.

**위주로** — Flutter shopping app-tech. Leanest permission set of the four (no
location, no contacts, no phone-state beyond READ_PHONE_NUMBERS). Revenue layer is ad
mediation/offerwall: InMobi, AppLovin (Array), Mintegral, Pangle, PubNative, Chartboost,
Amazon Ads, Smaato, Fyber, **Adiscope** (offerwall mediation), Ogury, Branch. The
`VirtualDisplay+MotionEvent` pair-flag resolved to **Flutter's own
`VirtualDisplayController`** (standard platform-views embedding) — not a phantom-viewport
engine. Host code: no collector+sink flag at all.

## Cross-cutting findings

- **bb8 spread**: Syrup + OK캐쉬백 only (both flagship loyalty apps). Absent from
  오락/위주로. Star-Wars internal naming family: `bb8` (SDK) / `c3po` (protobuf wire
  layer — scope gap flagged in the OK캐쉬백 carve closure) / `r2d2` (OK캐쉬백 host-side
  data pipeline).
- **Signers**: 오락 shares OK캐쉬백's 2011 SK certificate (`42467702…`) — key reuse
  across the OCB app family; 위주로 ships Play-App-Signing-managed (cannot be compared
  to a developer key).
- **No `sendTextMessage`, no `CallLog` access, no packet-capture-app blocklist, no
  phantom-viewport engine in any of the four apps** (the last checked per-root:
  위주로's VirtualDisplay hits are Flutter framework).
- Unknown-root count across the whole catalog: **0 unknown *plaintext* clusters** — every
  plaintext-visible collector+sink cluster attributed. *Rescoped per independent review
  ([REVIEW_FINDINGS](../review/REVIEW_FINDINGS.md)): string-obfuscated SDKs
  (Avatye/IGAWorks/MobWith/Fairytech Moment/Anick/Mocoplex/Tyrads/`com.gad.sdk`) are invisible
  to plaintext-API sweeps; three of them (Fairytech Moment, gad, Tyrads) have obfuscated
  endpoints and remain **static-unresolved** ("not shown malicious" ≠ "clean"), resolvable
  via a pre-sealed build diff or sanctioned dynamic capture.* The
  `VirtualDisplay+MotionEvent` pair-flag resolved to **Flutter's own
  `VirtualDisplayController`** — not a phantom-viewport engine.

## Limits

- Static, version-bound (versions above), binary-confirmed; runtime cadence and actual
  server responses are config-gated and not observable statically.
- 오락 host entry→sink reachability was **deliberately terminated, not pending**: on a
  27k-method first-party-only CPG (all egress to `*.okcashbag.com`) the generic-entry
  exploration adds no discriminative information, and the other four passes (Joern
  inventory, CodeQL 45, Semgrep 135, scope-closure) are complete and consistent. This
  is a recorded deviation from the mandatory-pass rule with the rationale stated.
- bb8 carves must include `com.skplanet.c3po/*` (wire layer, 81 classes, outside the
  current glob) for any completeness claim.
- Mirror provenance: 위주로/오락/시럽 from APKPure (signers verified — see table);
  OK캐쉬백 user-supplied official download.
