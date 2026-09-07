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
| `bsh/` (174 cls) | **BeanShell** Java script interpreter — embedded `eval` engine | *confirmed*: 서버 응답 → eval 체인 **완전 매핑 + 콘텐츠까지 런타임 확보** — `campaign/setup`·`prepare2`·`script/entry`가 Java 소스 문자열을 내려주고 SDK 객체가 주입된 채 `bsh.Interpreter.eval()`로 실행 ([GAD_API_RUNTIME_CAPTURE](GAD_API_RUNTIME_CAPTURE.md)). **Syrup 전용**, 유일 임베더 = `com.gad.sdk` (GPA KOREA GAD 오퍼월 — 아래 딥다이브). 관측 콘텐츠 양성, 채널은 설계된 원격 행위 시스템 |
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
- **AAR 원본 확보 — 볼트 질문 종결** (`binary-confirmed`, 신규 증거):
  `research/acquisition/corpus/dependencies/gad/` — JitPack이 **시럽이 쓰는 정확한 태그**
  `syrup-0.8.0-rc.12` AAR을 공개 서빙 (sha256 `c432f7a8…`), 공개 라인 0.7.7도 확보
  (sha256 `3374f8a7…`). AAR의 문자열 리소스: `gad_sdk_gad_url_live =
  https://gad.api.gpakorea.com/` (라이브), `gad_sdk_gad_url_dev = https://gpa.jp.ngrok.io/`
  (개발 터널), `gad_sdk_powered_by = "GPA KOREA"`. AAR BuildConfig `BUILD_TYPE=release` →
  시럽 빌드가 소비한 기본 베이스 URL = **라이브 `gad.api.gpakorea.com`**. AppSealing 볼트가
  가리던 값이 바로 이것 — 시럽 앱 코드에는 URL 오버라이드 경로가 없으므로(`GadSdk.kt`에
  init/showAdList/attachOfwBridge 뿐) 베이스 URL 미확정 항목은 **아티팩트 수준에서 해소**.
  두 태그 모두 `campaign/setup`·`prepare2`·`script/entry` + `GadScript`→bsh 보유 —
  스크립트 체계는 시럽 전용 추가가 아니라 **공개 제품 라인의 설계**.
  소스 JAR은 미발행(JitPack 파일 목록: aar/module/pom만 존재; Android SDK 레포
  `koreagpa-dev/gad`는 비공개 404 — sample/iOS/webview만 공개). 단, 공개
  `build.log`가 빌드 수준 정보를 추가 확정: 내부 publication 좌표
  `com.gad.sdk:gad-sdk:0.8.0`, SDK는 **순수 Java**(`compileJavaWithJavac`, Kotlin
  컴파일 태스크 없음), 레포 구조 = `:app`(샘플)+`:gad`(본체), 빌드 경고로
  `META-INF/services/javax.script.ScriptEngineFactory`(bsh의 JSR-223 서비스 등록)가
  리소스에 병합됨까지 확인 — GPA가 **AAR에 자체 R8(full mode)**을 적용해 배포함
  (Gradle 8.11.1 / AGP·빌드도구 35 / 빌드일 2026-07-13, 커밋 `90013b1` "백스택
  리스너 미해제 크래시 수정").
- **부수 소견 (위생/품질 — 악성 시그니처 아님)**: (a) 개발 터널 URL이 출하 리소스에
  잔존하고 `ui/fragment/e`에 "offer URL이 `gpa.jp.ngrok.io`로 시작하면 라이브 호스트로
  리라이트"하는 유산 로직 존재 — dev→prod 방향이라 위험은 아니고 정리 안 된 흔적.
  (b) SDK 내장 **에뮬레이터 감지** (`com.nekolaboratory.EmulatorDetector` →
  `NetworkModule.mIsEmulator`) — CPI 리워드망의 표준 어뷰징 방지 기능이나, 앞선
  행위-스윝의 evade 카테고리와 매칭되므로 명시 기록. (c) 도움말(Q&A) URL이
  **IGAWorks adPOPcorn의 S3 버킷**(`contents.igaworks.com/adPOPcorn/faq.html`)을
  가리킴 — 템플릿 재사용/방치 흔적으로 보이며, SDK 도움말 웹뷰가 제3자 콘텐츠를
  로드하는 셈. (d) POM에 `org.beanshell:bsh:2.0b5`가 **런타임 의존성으로 선언** —
  시럽 APK의 `bsh/` 174클래스 출처가 여기로 완전히 닫힘.
- **런타임 캡처 — 스크립트 내용 확보 (`runtime-confirmed`, 사용자 명시 요청 + GET 한정
  격리 계획; 전문은 [GAD_API_RUNTIME_CAPTURE.md](GAD_API_RUNTIME_CAPTURE.md))**:
  식별자 없이 media key만으로 문서화된 GET 4건. **BeanShell에 내려오는 것은
  값이 아니라 완전한 Java 소스 문자열** — 두 계층: (a) 매체 스코프 부트스트랩
  `setup`/`prepare2` (SDK 객체가 변수로 주입됨: `action`=`AppCompatActivity`,
  `flag`=`GadAdListFragment`, `medal`=`GadViewModel`, `hold`=`Handler`, `ball`=바인딩),
  (b) 캠페인 스코프 `script/entry?id=` = **웹뷰 라이프사이클 훅 집합**
  (`shouldOverrideUrlLoading`/`onPageStarted`/`onPageFinished`/`onPageLoaded`/
  `checkValid`/`prepare` — 반환값으로 URL 로드 차단권 보유). 관측된 내용은 전부
  양성(UI 라벨 세팅, 다이얼로그 헬퍼, 에러 폴백). 부수 확정: setup 주석에 타 매체
  앱(`com.reward.cashmong`, `com.rainbow.albamong`) — **다중테넌트 원격 제어층**;
  폴백 주석이 **"트래픽 SDK"**(형제 제품, `abortSession` CPI 검증) 공유 언급;
  `campaign/list` = 현재 라이브 848건, **문서 없는 type=5가 385건으로 최다**
  (prepare2의 TYPE_CPS="쇼핑적립"과 일치).
- **외부 참고 분석 대조** (사용자 제공 자료 — 본 워크스페이스 미재검증 항목은 표기):
  (a) bsh **2.0b5 고정**은 POM으로 재확인 — CVE-2016-2510(≤2.0b5 역직렬화 RCE,
  2.0b6서 수정) 대상 버전. **도달성까지 검증 완료** (스윕 리포트 §3.2): `bsh.This`
  Serializable/XThis 존재 등 취약 클래스는 배포됐으나, XStream·XMLDecoder·Kryo·
  ScriptEngineManager·Jackson defaultTyping·가젯체인 라이브러리가 전부 0개,
  `bsh.This` 외부 참조 0개 — 역직렬화 인스턴스화 경로 부재로 **도달 불가**. 그래도
  CVE보다 본질 리스크는 "설계된 원격 스크립팅"이며 bsh 갱신은 벤더 정리 항목.
  (b) NetworkModule: `debug ? url_dev(ngrok) : url_live` — **dev 터널은 디버그
  빌드에서만 선택 가능**, 릴리즈는 무조건 라이브. (c) AAR 전체에서
  IMEI/getDeviceId/READ_PHONE_STATE **0건** — 참고자료가 인용한 2019 정책상 IMEI
  수집은 현 아티팩트에 부재(android_id+widevine+adid만). (d) 2017년 GPA 제안서의
  "자동 광고참여 자체기술" 문구, mission.html URL 내 email+tracking_id 색인 사례는
  벤더 측 역사적/웹 인프라 소견으로 참고만 (미재검증, 앱 바이너리와 직접 결정 안
  함). IGAWorks adPOPcorn FAQ 잔존은 "계보 단서"로 유지 (관계 미확정).
- **동적 리플레이 (`runtime-confirmed`, [GAD_BSH_SANDBOX_RUN](GAD_BSH_SANDBOX_RUN.md))**:
  유니크 40종 전부를 JVM(bsh 2.0b5 동일 버전 + SecurityManager 감시 + 스텁 주입)에서
  실제 실행 — **eval 40/40, 위험 시도(NET/EXEC/EXIT/FILE-W/LINK/SM-TAMPER) 0건**.
  실관측 행위: `javascript:` 페이로드로 광고 페이지 DOM을 XPath 스크래핑해 참여
  검증(네이버 이웃추가 셀렉터 등), postDelayed 폴링, blur 연출, prefs 읽기, 라벨 세팅.
  정적 결론(악성 0건)을 행위 수준에서 재확인 — 재사용 가능한 하니스는
  `analysis/bsh-sandbox/`에 등록(스킬에도 반영).
- **잔여 미확정**: 없음 (gad 한정). **캠페인 전수 스윕까지 완료**
  ([GAD_CAMPAIGN_SWEEP](GAD_CAMPAIGN_SWEEP.md), 2026-09-07 시점): 스크립트 848개
  전수 수집 → 유니크 38종(91%는 동일 에러 폴백 1종) 전부 검증 — 위험 API 13
  카테고리 전부 0건, 전부 참여-미션 UI 오케스트레이션 템플릿. 광고 URL 41종 전부
  메인스트림 도메인, 설치형 7건 전부 공식 마켓 경유. 악성 스크립트 0건.
  트래픽 SDK(형제 제품)만 미표본.
- **평가**: 미확인 벤더의 기묘한 eval이 아니라, **식별된 상용 오퍼월의 설계된 원격
  행위 시스템**(AAR로 벤더·엔드포인트·베이스 URL까지, 런타임 캡처로 스크립트
  콘텐츠까지 검증). 관측 콘텐츠는 양성이나, 채널 자체가 서버에 앱 프로세스 내 임의
  Java 실행 권한을 주는 구조 — bsh 2.0b5 고정(CVE-2016-2510 대상 버전)과 함께
  GPA 백엔드 무결성에 의존하는 공급망 리스크 항목으로 유지. 악성 SDK 계열
  시그니처(5-family IOC)와는 무관.

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
