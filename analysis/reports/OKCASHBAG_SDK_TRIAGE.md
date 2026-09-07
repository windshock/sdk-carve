# OK Cashbag (OK캐쉬백) embedded-SDK triage — malicious-SDK screen + attribution

**Sample**: `com.skmc.okcashbag.home_google` v7.1.9 (versionCode 243), user-supplied
download (2026-09-06), sha256
`d5e6a11073b9ebec30cb98483e1bcc400de538b5eac5e8433938adbabd0878ed`, signer SHA-256
`424677022f8ffd1f37cf5a2f63a38fe737c314e2002acd7005d16f77fe017ffd` (cert: `C=kr`,
valid 2011-05 → 2036-05 — long-lived original key consistent with the app's history;
recorded as the reference signer for future versions).
**Method**: sdk-carve triage — behavior-sweep (111,713 classes) → multi-family IOC
sweep → per-root endpoint identification → sensitive-permission usage attribution.
All findings `binary-confirmed` (static); nothing was executed.

## Verdict

**No known malicious-SDK family present — screened against all 5 families in this
study (Goldoson, SpinOk, Konfety, MobiDash, Necro/Coral): 0 C2-host hits, 0 package
anchors, no `VirtualDisplay` phantom-viewport engine.** Every collector+sink cluster
resolves to a named commercial SDK or SK Planet/SKMC first-party code. No SMS or
call-log access anywhere in the bytecode; `CALL_PHONE` is declared but has **0 call
sites**.

## SDK inventory (collector+sink clusters, all identified)

| root | identity | notes |
|---|---|---|
| `com/skplanet/sdk/proximity` (38 cls) | SK Planet proximity SDK (**bb8** — same SDK deep-dived in [SYRUP_SDK_TRIAGE.md](SYRUP_SDK_TRIAGE.md)) | WiFi/BSSID + BLE + GPS + applist/GAID store-visit detection; policy-gated upload to `pxpolicy/pxsens.syrup.co.kr` |
| `co` (1,517 cls) | **Adison** (adison.co) offerwall — `tracking.data.adison.co`, `postback-ao.adison.co`, dev/stg hosts | commercial reward/offerwall; NewRelic APM bundled |
| `com/enliple/keyboard/*` (~57 cls) | **Enliple 포미션(pomission)** reward/mission SDK — endpoints `okcashbag.com` ×18, `pomission.com`, `mobon.net` | commissioned by OK Cashbag itself (talks to its own domain); "keyboard" is Enliple's package naming heritage |
| `io/adjoe/*` | adjoe playtime-rewards SDK | `UsageStatsManager` use = its core business; `io/adjoe/protection` = reward anti-fraud |
| `com/skplanet/ocb/util`, `com/skplanet/ocb/interact` | host app code (R8-obfuscated parts of OK Cashbag itself) | first-party telemetry/utilities |
| `com/skplanet/skpad/*`, `com/skt/tid/*` | SKP ad SDK, SKT TID integrated auth | first-party |
| Pangle (`bytedance/openadsdk`, `pgl/ssdk`), Mintegral, IronSource, AppLovin, Vungle, Fyber, Smaato, Criteo, Tapjoy, Cauly, Kakao AdFit, Naver Ads/GFP | mainstream ad networks | industry-standard adware collection |
| `com/TouchEn.mVaccine.b2c2c` (manifest `FileScanService`) | TouchEn mVaccine (안랩) mobile AV | standard Korean-app security SDK |
| `ai/fairytech/moment` (1,611 cls) | **Fairytech Moment reward SDK** (device-token/push/webview/usage-stats; BOOT+package receivers; protobuf wire) | *corrected per review* — earlier mislabeled "protobuf internals"; endpoints string-obfuscated behind the app-wide AppSealing vault → **static-unresolved**, see [REVIEW_FINDINGS](../review/REVIEW_FINDINGS.md) |
| `com/anick/sdk`, `com/avatye/pointhome`, `com/igaworks/ssp`, `com/mobwith/*` | Korean adtech/reward SDKs (Anick, Avatye PointHome, IGAWorks AdPopcorn SSP, MobWith) surfaced by the review's obfuscation pass | identified legit; endpoints plaintext except Avatye dev-LAN `192.168.0.81` leftover |

## Sensitive-permission usage attribution (declared → actual)

| permission | actual use | attribution |
|---|---|---|
| `ACCESS_BACKGROUND_LOCATION`, `BLUETOOTH_SCAN`, `ACTIVITY_RECOGNITION` | visit/beacon detection | bb8 proximity + Adison (proximity-marketing core function) |
| `PACKAGE_USAGE_STATS` | 10 classes | adjoe (4), skpad (2), tapjoy (1) — reward-wall SDKs; usage stats IS the reward mechanic |
| `READ_CONTACTS` | 8 classes | 5 are image-loader libs (contact-photo loading: picasso/glide/universalimageloader/mobwith); 3 host `com/skplanet/ocb` (referral feature); 1 enliple — **no bulk contact access** |
| `READ_PHONE_STATE` / `READ_PHONE_NUMBERS` | 75 classes, spread | androidx compat (13), enliple (12), skplanet/lib (8), skt/tid (7), skpad (6), criteo (5) — legacy device-id compat across adtech, no single covert collector |
| `CALL_PHONE` | **0 call sites** | declared, unused |
| SMS / `CallLog` | **0 classes** | clean |

## Multi-family IOC sweep detail

Goldoson (24 hosts), SpinOk (2), Konfety (4): **none**. Anchors `com/spin/ok`,
`com/coral`, `com/adcommercial`, `com/gnet`, `com/nextg`, `org/lsposed`, `com/stwdi`:
**none**. `VirtualDisplay`: **absent** (Konfety/MobiDash phantom-viewport engine not
present). `isAdb` ×4 → Unity Ads device-info; `isSimulator` ×4 → Google Mobile Ads /
Firebase Crashlytics report models (benign).

## Carve results (carve → jimple2cpg CPG → Joern inventory)

Four roots carved and CPG-analyzed (`binary-confirmed`):

- **bb8 proximity** (`com/skplanet/sdk/*`, 450 cls): class inventory **identical to the
  Syrup sample** (449 vs 450 classes, 0 missing, 1 extra `collector/module/b`; 178
  byte-identical / 271 recompiled) — same SDK, different build. Same collector surface
  confirmed by Joern (GAID ×3 sites, BSSID ×14, visit-log builders, `newCall` egress).
- **Enliple cashkeyboard** (`com/enliple/*`, 14,426 methods): `getDeviceId` (IMEI-era
  device id) read at every ad interaction (`KeyboardAditionADActivity`
  onTouch/onClick/handleMessage) and egressed via `network.a.connect{AD, PopAD,
  **SendKeyword**, ZeroPoint, ChargePoint}` to the **OCB-branded cashkeyboard API**
  (`ocbapi.cashkeyboard.co.kr`, test host `test.cashkeyboard.co.kr`) + `mobon.net` ad
  calls. `connectSendKeyword` pairs device-id with **typed-keyword data** — the
  cash-keyboard reward model (keystroke-derived ad targeting). Offerwall via
  `KeyboardHybridOfferwallActivity` WebView (`ocbapi.cashkeyboard.co.kr/API/OCB/offerwall`)
  with `evaluateJavascript`.
- **Adison offerwall** (`co/*`, 8,087 methods): GAID reads (2), `lumberjack` tracking
  egress (`newCall @ lumberjack.k0`), offerwall WebViews (`loadUrl` ×3,
  `evaluateJavascript` ×2), hosts `ads/api-ao/postback-ao/tracking.data.adison.co`
  (+ dev/stg twins).
- **OCB host modules** (`com/skplanet/ocb/{util,interact}`, 4,593 methods): first-party.
  `OcbAndroidInterface.getSyrupAdDeviceId` — a JS bridge exposing a device id to
  WebView content; `c3po/R2D2{WifiData,GeofenceData,OnDemand}` — OK Cashbag's own
  telemetry pipeline consuming bb8 proximity events; `GpsManager`/`DiscoverManager`
  location helpers.

## Cross-verification & scope-closure (full mandatory pass)

All four carves ran the complete analyzer set. Analyzer agreement on the core:

| root | Joern (CPG inventory + reachability) | CodeQL (204 findings) | Semgrep (336 findings) |
|---|---|---|---|
| bb8 proximity | GAID ×3, BSSID ×14, applist; **newCall reachable (5), execute (38)** | gps ×48, wifi ×22, mac ×10, bt ×1, okhttp ×4 | identity 32, network 2 |
| Enliple cashkeyboard | getDeviceId at ad handlers, `connectSendKeyword`; **openConnection/newCall/execute/loadUrl/loadData all entry-reachable (8/9/126/46/3)** | **webview-url ×40, imei ×15, url-egress ×5, okhttp ×5** | identity 11, applist 6, network 22 |
| Adison offerwall | GAID ×2, lumberjack egress; **loadUrl (3) + evaluateJavascript (2) reachable** | webview-url ×3, okhttp ×2 | identity 3, applist 1, network 7 |
| OCB host | JS bridge `getSyrupAdDeviceId`, c3po/R2D2 pipeline; no sink reachable from generic entries | gps ×17, webview ×3, bssid ×1 | identity 7, applist 1, network 9 |

No `sendTextMessage` in any analyzer, any root.

**Scope-closure (reverse trace, per carve)** — external callee owners are framework,
compiler synthetics, and known libs (glide/volley/okhttp/rake/installreferrer/
jakewharton), plus one **genuine scope gap**: `com.skplanet.c3po` (81 classes) — bb8's
own protobuf wire layer (`API$InitRequest`, `NearestPARequest`, …) — lives outside the
`com/skplanet/sdk/*` carve glob and must be added to any bb8 carve claiming
completeness. `com.xshield.dc` (1 hit per carve) = SK app-protection library hook,
classified lib. Everything else is boundary-as-designed.

## Limits

- Static only; no execution. Ad/reward behavior (offerwall content, mission
  completion, tracking cadence) is server-driven and not observable statically.
- `com.skplanet.c3po` (bb8 wire layer) was identified by scope-closure as out of the
  carve glob; behavior conclusions above rest on the same SDK verified in Syrup, but a
  completeness-claiming bb8 carve must include `c3po/*` and re-run closure.
- Reflection / runtime-string-decryption paths remain outside static name-matching
  (RQ5 failure boundary).
