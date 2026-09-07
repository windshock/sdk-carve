# Adison Offerwall SDK 트리아지 — AAR 원본 분석 (시럽 동일 버전)

- **일시**: 2026-09-07 · 계기: 오퍼월 3사(GAD·TNK·Tyrads)에 이은 마지막 미분석 SDK
- **등급**: 벤더 아티팩트 분석 + **CPG source/sink 패스**(2026-09-07 상향; jimple2cpg→joern, §3.1)

## 1. 벤더·제품·아티팩트

- **벤더**: Adison (애디슨) — 공식 문서 docs.adison.co, 문의 dev.team@adison.co
- **좌표**: `co.adison:adison-offerwall-sdk` — **자체 Nexus**
  `https://repo.nbt.com/repository/adison-ads-android`(공개 서빙). Maven Central 부재.
- **분석 아티팩트**: **3.16.4 — 시럽이 쓰는 정확히 동일 버전**(sha256 `1340220e…`,
  1,162,938B, 628클래스, 실명 패키지 `co.adison.offerwall.*` + 내장 `com.nbt.oss.exp4j`).
  최신 라인은 5.4.0(문서도 5.0.0 기준, v3→v5 마이그레이션 안내 존재 — 시럽은 구버전
  유지 중).

## 2. 엔드포인트 (전부 평문, 전부 회사 도메인)

prod `ao.adison.co`(웹뷰) · `api-ao.adison.co`(API) · `api-ao-list.adison.co` ·
`api-points.adison.co`(포인트) · `postback-ao.adison.co`(S2S 포스트백) ·
`tracking.data.adison.co` — 각각 dev/stg 트윈이 출하물에 함께 존재.
**위생 항목**: `private-4bc62-adisonofw.apiary-mock.com` — **Apiary 목서버 URL이
출하물에 잔존**(GAD의 ngrok, TNK의 adiscope-dev와 같은 부류).

## 3. 위험 API 스캔 (13 카테고리)

| 카테고리 | 결과 |
|---|---|
| 스크립트엔진(bsh/Rhino/JSR-223) | **0** — GAD와의 핵심 차이 |
| 동적로드 / 역직렬화(loadClass·forName·newInstance 포함) | **0** — TNK의 자체 ObjectInput면도 없음 |
| 파일 / 식별자(IMEI·android_id) / 앱목록 / 위치 / 루팅·에뮬감지 | **0** |
| exec 히트 1건 | **오탐** — `LruBitmapCache`: `Runtime.getRuntime().maxMemory()` 캐시 크기 산정 |
| 광고ID | 1클래스(`AdisonParameters$GetAdvertisingId`) — 문서화된 표준 수집 |

### 3.1 CPG 콜그래프 확인 (2026-09-07 상향 — regex를 넘어선 재검증)

`classes.jar` → `jimple2cpg` → `joern`(`analysis/joern/scripts/adison-audit.sc`). 정규식이 아니라
콜그래프 기준:

| 카테고리 | CPG |
|---|---|
| EXEC / 스크립트엔진 / 동적로드(loadClass·DexClassLoader·System.load) / 역직렬화 | **전부 0** — **자체 `ObjectInput`면도 없음**(TNK와의 차이) |
| DEVICE-ID | **0** |
| `Class.forName`(2) / `newInstance`(19) | **표준 UI/프레임워크 팩토리** — `init`/`onCreate`/`showNetworkErrorView`/`replaceWebFragment` 등의 뷰·프래그먼트 생성; **서버 통제 클래스명 아님**(TNK식 wire→loadClass 채널 부재) |
| NET | okhttp `newCall` + TLS12 소켓 — 표준 |

→ **실행/역직렬화/동적로드 프리미티브 부재가 콜그래프로 확정.** 서버가 내리는 exp4j 식은 산술·논리
double 평가라 문법상 실행 불가(§5). (`forName/newInstance` 19건은 서버 미통제 프레임워크 reflection —
미래 리뷰어의 TNK식 재의심 방지용으로 명기.)

## 4. 웹뷰 브리지 — 전량 문서화된 JS SDK 표면

`AdisonWebViewJsInterface`의 `@JavascriptInterface` 메서드 12개:
`clearCache, setUid, setUserProfile, showOfferwall×3, showHelp, impression,
showNativeAd, availableReward, getSdkVersion, loadAds` — 문서의 웹뷰 JS SDK가
정의하는 그것 그대로(단일 진입점 `postMessage` 방식인 Tyrads와 달리 named-method
방식이나, 전부 제품 기능). 임의 실행·파일·식별자 메서드 없음.

## 5. exp4j 내장 수식 평가기 — GAD bsh의 "설계상 샌드박스" 버전

- `utils/ExpressionUtils.eval(String)` = `ExpressionBuilder(expr).operator(LogicOperators)` —
  **연산자 9종만 등록된 산술·논리 평가기**(`! != && < <= == > >= ||`).
- 용도 추정: 서버 배포 타겟팅 규칙 평가(문서의 "성별 연령 타겟팅" 페이지와 정합).
- exp4j의 문법은 수치·논리 연산만 허용 — **메서드 호출·객체 접근이 문법적으로
  불가능**하므로, "서버가 로직을 내려보낸다"는 점에서 GAD의 bsh와 동일 카테고리의
  채널이지만 **설계상 샌드박스**. 임의 실행 경로 아님.

## 6. 판정

- **판정**: 식별된 상용 오퍼월, 문서화된 표준 연동, 위험 API 전무, 수집은 광고ID
  문서화 항목뿐. 오퍼월 3사 비교에서 **가장 깨끗한 표면** — GAD(bsh 원격 실행 채널)
  / TNK(잠복 자체 역직렬화면)와 달리 실행 프리미티브 자체가 없음(**§3.1 CPG 확정**).
- **위생**: Apiary 목서버 잔존, dev/stg 엔드포인트 전면 출하, 시럽의 v3.16.4는
  문서 기준 구버전(5.4.0) — 벤더에 버전 업그레이드 검토 권고 가능.
- **한계**: 1차 패스(AAR 정적). 시럽 번들에서는 R8으로 `i/`(74클래스)로 변형돼
  식별됐었고 AAR 실명 628클래스와 동일 제품(버전 일치)으로 확인. 전체 카브 패스는
  히트 전무로 미수행.

## 7. 사용자 식별자 — SugarToken (기록, 미완료 확인)

- **운영 정보(매체 연동 문서 인용)**: 사용자 식별자는 **Session > SugarToken 사용
  (사용자마다 Unique)**. 관련 문서 섹션: Native Ads 가이드
  ([docs.adison.co/ofw-native-ads](https://docs.adison.co/ofw-native-ads) ·
  [iOS](https://docs.adison.co/ofw-native-ads/ios-native-ads-1)) + 웹뷰 SDK
  ([offerwall-webview](https://docs.adison.co/offerwall-webview/oofkW8Cq1tIbXXBXtSIi)).
- **v5 설정 API 예시**(매체 문서 인용): `AdisonConfig()` — `prepareViewHidden`,
  `offerwallListTitle`, `navigationHelpButtonType`, `listType`,
  `enablePopupBannerExtension` 등. v5 스타일 API이며 **시럽이 쓰는 3.16.4에는
  없는 인터페이스**.
- **바이너리 확인**: `SugarToken` 문자열은 3.16.4와 5.4.0 AAR 양쪽 모두 0건 —
  SDK 클래스가 아니라 **서버 세션 개념**이거나 Native Ads 전용 아티팩트(미분석)의
  요소로 추정. 확정하려면 ofw-native-ads 문서/SDK 별도 확인 필요 → **미완료로 기록**.
- **v3(시럽) 식별자 흐름은 문서로 확정됨**: `Adison.setUid(...)` — UID는 사용자마다
  고유·불변(재설치/기기 변경/재로그인 불변), 80자 한도, 매체사가 생성하는 비개인정보
  난수(생성 로직을 애디슨에 설명하지 않는 것이 문서 요건). 시럽 구현과 정확히 일치:
  5640 API `uid` → `PREF_ADISON_UID` → `AdisonSdk.setUid()`.
