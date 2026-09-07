# Syrup (시럽) embedded-SDK triage — malicious-SDK screen + behavior deep-dive

**Sample**: `com.skt.skaf.OA00026910` v5.8.16_M (versionCode 301), APKPure mirror
sha256 `0a4ef3c6380139c6e92d6f5c954646d76fe996dd0f662634fee9ad140166a12e`,
signer SHA-256 `e981b282ec9663ddaaed9e863cf499ebc03a76b358722fc021645bb37ca33146`
(repackage check pending comparison against an official-channel copy).
**Date**: 2026-09-06. **Method**: sdk-carve triage — behavior-sweep (capability-API
clustering over 104,029 classes) → IOC sweep → carve (449/74/109 cls) → per-class
API/endpoint mapping on the carved bytecode. All findings `binary-confirmed` (static);
runtime contact targets are server-gated and were NOT executed.

## Verdict

**No known malicious-SDK family present — screened against all 5 families in this
study (Goldoson, SpinOk, Konfety, MobiDash, Necro/Coral).** Multi-family IOC sweep
(`scripts/ioc-sweep.sh`): hardcoded C2/ad hosts — Goldoson 24, SpinOk 2, Konfety 4
indicators: **0 hits** in 104,029 classes; family package anchors (`com/spin/ok`,
`com/coral`, `com/adcommercial`, `com/gnet`, `com/nextg`, `org/lsposed`, `com/stwdi`):
**0 hits**. Structural markers: no `VirtualDisplay` (Konfety/MobiDash phantom-viewport
engine absent); `isAdb` ×4 attributes to Unity Ads device-info, `isSimulator` ×4 to
Google Mobile Ads / Firebase Crashlytics report models — benign context. No unknown
spyware-shaped root: every collector+sink cluster resolves to a named commercial ad
SDK or SK Planet first-party code. No SMS/contacts/call-log/READ_PHONE_STATE permission.

## What the app embeds (collector+sink clusters)

| root | identity | shape |
|---|---|---|
| `com/skplanet/sdk/proximity` (449 cls) | SK Planet proximity/visit SDK, internal name **bb8** | WiFi-survey + location + BLE + applist + persist + network |
| `ob` (109 cls) | Syrup host modules (R8) | first-party telemetry → `nxt.syrup.co.kr/collect`, WebView |
| `i` (74 cls) | **Adison** (adison.co) offerwall SDK — 공식 문서 확인: [docs.adison.co/offerwall](https://docs.adison.co/offerwall) (애디슨, 연락처 dev.team@adison.co) | GAID + prefs + network |
| Pangle (`com/bytedance/sdk/openadsdk`, `com/pgl/ssdk`), Mintegral, IronSource, AppLovin, Vungle, Fyber, PubMatic, Kakao AdFit, Cauly | mainstream ad SDKs | industry-standard adware collection |
| `com/initech/fido` | FIDO auth (benign identity use) | identity + network |
| `bsh/` (174 cls) | **BeanShell** Java script interpreter — embedded `eval` engine | *confirmed per review + trace + 벤더 문서*: **서버 응답 → eval 체인 완전 매핑** — `GadService.setup(media)`/`prepare2(media)`/`script/entry(id)`가 `ScriptResponse{script}`를 반환 → `GadScript.run()` → `bsh.Interpreter.eval()`. **Syrup 전용**, 유일 임베더 = `com.gad.sdk` v0.8.0 (GPA KOREA의 GAD 오퍼월 — 아래 딥다이브 참조). 스크립트 내용은 서버 제어(동적 캡처 필요)이나 벤더·제품·엔드포인트 체계는 공개 문서로 확인 완료 |
| `com/avatye/pointhome`, `com/igaworks/ssp`, `com/mobwith/*`, `kr/co/touchad`, `com/gad/sdk` | Korean adtech/reward SDKs (Avatye PointHome, IGAWorks AdPopcorn SSP, MobWith, TouchAd, gad) surfaced by the review's obfuscation pass | identified legit; **gad = `com.github.koreagpa-dev:gad:syrup-0.8.0-rc.12`** — GPA KOREA(도메인 `gpakorea.com`)의 **GAD 오퍼월** 상용 제품. 공개 증거: GitHub org [`koreagpa-dev`](https://github.com/koreagpa-dev) (JitPack) + [`GPA-KOREA`](https://github.com/GPA-KOREA) (샘플·iOS·웹뷰 SDK), 샘플 레포 [gad-sample-android](https://github.com/GPA-KOREA/gad-sample-android) README/api-doc. 5.8.14 기본브랜치엔 없어 5.8.15/16에 새로 추가된 연동. **Adison(애디슨)과는 별개 벤더** (바이너리 상호 참조 0건) |

## Deep-dive: `com.skplanet.sdk.proximity` (bb8)

A store-visit detection / proximity-marketing platform. Per-class evidence (carved
bytecode, `binary-confirmed`):

- **Collectors**: `module/scanner/{WifiScanner,BLEScanner,GeolocationScanner}`
  (WiFi `getScanResults`, BLE `startLeScan`, `requestLocationUpdates`);
  `collector/module/DeviceCollector` (WiFi+lat/lon);
  `DeviceUtils` (BSSID/SSID/**getBondedDevices**/GAID);
  `collector/module/installation/AppInstallationWithGAIDCollector`
  (**installed-app list + GAID**, uploads via okhttp `newCall`).
- **Event records** in Room DB: `ServiceEventLog`/`StorePlaceEventLog`
  (BSSID+SSID+lat/lon+MAC), `LocationEventLog`, `BLERegionEventLog` — i.e. visit
  history tied to store regions (`StoreRegion`/`VisitRegion` builders).
- **Persistence**: `RecoveryReceiver` + `CollectorRecoveryReceiver` (recovery/boot
  path), JobService (`BIND_JOB_SERVICE`), `ProximityRoomDatabase`, SharedPreferences.
- **Network**: `pxpolicy.syrup.co.kr/v{1,3}/policy/use?tid=` (server policy gate),
  `pxsens.syrup.co.kr/api/v1/data/nearest/pa`, `/api/v2/auth`; BSSID→place map
  `bssidmap_v12.sqlite` from `skpis.cache.scs.skcdn.co.kr` (on-device WiFi
  positioning).
- **Assessment**: first-party (all endpoints syrup.co.kr/skcdn.co.kr), collection is
  policy-gated by its own backend — architecturally similar to a *benign* version of
  the Goldoson pattern (survey → config gate → upload). The privacy-gray element is
  installed-app enumeration + GAID + store-visit history; disclosed purpose is
  proximity marketing. No evasion (no emulator/pcap/xposed checks) observed in scope.

## Deep-dive: Adison (`i/*`) and host modules (`ob/*`)

- **Adison**: GAID read (`i/w$a`), SharedPreferences, prod/stg/dev endpoints
  `ao.adison.co`, `api-ao-*.adison.co`. 공식 문서 ([docs.adison.co/offerwall](https://docs.adison.co/offerwall)) 와 대조:
  문서는 Android SDK v5.0.0 라인을 다루며(네이티브 SDK + 웹뷰 JS SDK, uid 바인딩, v3→v5
  마이그레이션 안내 포함) 본 앱은 v3.x 계열인 `co.adison:adison-offerwall-sdk:3.16.4` 사용.
  웹뷰 JS SDK 패턴(네이티브 SDK 필수 + JS 콜백)은 앱의 `showAdisonOfferwall` 월렛 브리지
  (successCallbackJS/failCallbackJS)와 일치 — 문서화된 표준 연동 형태. bsh를 호출하는
  `com.gad.sdk`와는 무관 (상호 참조 0건, 별개 벤더).
- **`ob/e1`**: JS-enabled WebView (`loadUrl`/`setJavaScriptEnabled`) to
  `dev-mt.syrup.co.kr` + `nxt.syrup.co.kr/collect` — first-party telemetry with a
  WebView path; `ob/o` uses raw `openConnection`.

## Deep-dive: gad (`com.gad.sdk` — GPA KOREA GAD 오퍼월)

벤더 확인 경로 (모두 공개 소스, `binary-confirmed` + 공개 문서 대조):

- **벤더**: GPA KOREA — 도메인 `gpakorea.com`, GitHub org `koreagpa-dev`(SDK 배포
  JitPack) + `GPA-KOREA`(샘플/iOS/웹뷰 SDK 4레포). SDK 내부 로그 태그 `GPADEV`,
  리소스 `gad_sdk_avd_gpa`와 일치.
- **샘플 문서와 바이너리 1:1 대응**: README의 `Gad.init(mediaKey, userId)` /
  `setUserInfo(sex, age)` / `showAdList` / `getAdListFragment` / `join(adKey)` — 바이너리
  API 면과 동일. api-doc의 식별자 수집 지침 — **udid=widevine ID(권장), android_id(선택),
  imei(선택), adid** — 도 바이너리에서 그대로 관측: `util/b`(MediaDrm WIDEVINE UUID),
  `module/NetworkModule`(Settings.Secure android_id).
- **백엔드**: api-doc 문서화 도메인 `https://gad.api.gpakorea.com/campaign/*`
  (list/join/status/complete). 바이너리 `GadService`의 Retrofit 경로가 동일
  `campaign/*` 네임스페이스 사용 — 문서 미수록 내부 경로 다수 포함
  (get/join/list/media/list/mission/list/reward/list/inquiry(2)/histories/history/
  log/{id}/shown/prepare2/setup/action/script/entry).
- **bsh 체인의 엔드포인트 매핑 (바이너리 확정)**: `campaign/setup(media)` →
  `ScriptResponse`, `campaign/prepare2(media)` → `ScriptResponse` (부트스트랩),
  `campaign/script/entry(id)` → 스크립트 본문 → `GadScript.run()` →
  `bsh.Interpreter.eval()`. api-doc이 "문서에 정의되지 않은 필드… 정의된 필드만 사용
  바랍니다" + join 응답 "SDK 예약 필드"라고 경고하는 것이 바로 이 서버 주도 스크립트
  체계(미션형 캠페인용 원격 로직)에 해당 — **문서화된 제품 설계**로 판명.
- **호스트 밀착 통합 (소스 확정 — 내부 레포 `develope/5.8.16`, HEAD 커밋이 PR #651
  "[SYRUPPROD-2560] gad = \"syrup-0.8.0-rc.12\" 적용")**: 이 포크는 파라미터명 상수로
  시럽 자체 클래스 `com.skt.skaf.syrup.web.JavaScriptInterface.UID`를 직접 import.
  앱 측 연동 `ad/offerwall/GadSdk.kt` — **`GAD_MEDIA_KEY = "7fce4262-8654-4117-b100-0117f8e74857"`
  하드코딩**. uid는 기기 식별자가 아니라 **시럽 백엔드가 발급하는 파트너 user key**:
  실행정보 동기(5658)의 서버 플래그 `adSdkSyncYn` 게이트 → `request5420(PARTNER_SERVICE_GAD)`
  → `partnerUserKey` → `PREF_GAD_UID` → `Gad.init`. Adison(5640→uid), PAD(5697)도
  동일 패턴. 월렛 브리지 `showGadOfferwall`(JavaScriptInterface.kt:1559, uid 없으면
  failCallback) + `attachOfwBridge`가 공통 웹뷰 2곳(CommonMobileWebActivity/WebFragment)에
  `GadOfwBridge` 부착. SWConst 주석이 `PREF_GAD_UID // Adison UID`로 복붙된 흔적 —
  개발 단계에서도 두 SDK가 동일 코드 경로의 형제 연동임을 방증.
- **잔여 미확정**: (1) 시럽 빌드의 실제 베이스 URL — 문자열이 AppSealing 볼트 뒤
  (`GadScript.destroy()`도 `dc.m31294(int)` 호출; 공개 문서는 `gad.api.gpakorea.com`이나
  시럽 포크가 다른 프록시 도메인을 가리킬 가능성은 봉인 전 빌드 diff로만 확인 가능),
  (2) 스크립트의 실제 내용 — 서버 제어라 동적 캡처 필요.
- **평가**: 미확인 벤더의 기묘한 eval이 아니라, **식별된 상용 오퍼월의 설계된 원격
  로직 체계**. 다만 bsh 스크립트가 샌드박스 없이 시럽 앱 권한으로 실행되는 구조 자체는
  유효한 공급망 리스크 항목 — GPA 백엔드(및 시럽 빌드가 가리키는 최종 베이스 URL)의
  무결성에 의존. 악성 SDK 계열 시그니처(5-family IOC)와는 무관.

## Cross-verification (3 analyzers, per the sdk-carve method)

Same carved scopes, three independent frontends: **Joern** (jimple2cpg bytecode CPG,
`scripts/source-sink` inventory), **CodeQL** (jadx source DB, `build-mode=none`,
name-matched `flows-syrup.ql`), **Semgrep** 1.78 (regex rules on the same sources),
plus the per-class bytecode string mapping. Agreement on the core:

- **Collectors concentrate in `com.skplanet.sdk.proximity`**: CodeQL 97 findings —
  gps-lat/lon ×48, wifi-ssid ×13, wifi-bssid ×8, mac ×10, bt-bonded ×1 (all proximity),
  with 4 okhttp-egress sinks incl. `AppInstallationWithGAIDCollector` (applist+GAID
  upload). Joern's source inventory on the same CPG matches (GAID/BSSID/bonded/
  installed-apps/location; sink `newCall @ NetworkManager`). Semgrep: 32 identity-files
  + 2 network-files in the same package.
- **`ob`** (host): CodeQL + Joern both see the WebView sink (`loadUrl @ ob.e1.b0`) and
  raw egress (`openConnection @ ob.o.t`); applist hits are `queryIntentActivities`/
  `getRunningTasks` (pattern-list coverage differs per tool).
- **`i`** (Adison): sinks `evaluateJavascript @ i.c0.m` (Joern: **reachable from
  entry**). **Disagreement = signal**: Semgrep + raw strings see `getAdvertisingIdInfo`
  in `i/w`, but Joern/CodeQL name-matching does not — root-caused to **runtime string
  decryption** (`dc.Ȍ̔̒˓(1244803385)`, unicode-obfuscated decryptor) wrapping the GAID
  read. Documented as obfuscation hygiene; no family IOC correlates.
- No `sendTextMessage` (SMS) sink in any analyzer; no collector/sink shape anywhere
  outside the three scoped components + known commercial ad SDKs.

## Limits

- Static only; no execution (AGENTS.md gate). Server policy gates decide what is
  actually collected at runtime.
- Joern entry→sink reachability: **`newCall` (okhttp egress) reachable from entry
  methods in proximity — 5 call-sites** (incl. the GAID-collector upload path); no
  WebView/SMS sink reachable there. Adison: `evaluateJavascript` reachable. `ob`:
  sinks present, not entry-reachable from the generic entry set.
- Scope-closure (step 5) not yet run on the three carves; helper packages outside the
  globs (e.g. shared R8 utils) are out of scope by construction.
- Reflection / runtime-string-decryption paths (seen in Adison `i/w`) are outside
  static name-matching — the known RQ5 failure boundary of the carve method.

## OK Cashbag

`com.skmc.okcashbag.home_google` **pending** — not hosted on APKPure/Uptodown/
apkcombo (KR-only app). Awaiting an official-channel APK in
`research/acquisition/corpus/targets/`; same pipeline runs on arrival.
