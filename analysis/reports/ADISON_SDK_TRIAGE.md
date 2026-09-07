# Adison Offerwall SDK 트리아지 — AAR 원본 분석 (시럽 동일 버전)

- **일시**: 2026-09-07 · 계기: 오퍼월 3사(GAD·TNK·Tyrads)에 이은 마지막 미분석 SDK
- **등급**: 1차 패스(벤더 아티팩트 정적 분석 + 브리지/수식 엔진 감사)

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
  / TNK(잠복 자체 역직렬화면)와 달리 실행 프리미티브 자체가 없음.
- **위생**: Apiary 목서버 잔존, dev/stg 엔드포인트 전면 출하, 시럽의 v3.16.4는
  문서 기준 구버전(5.4.0) — 벤더에 버전 업그레이드 검토 권고 가능.
- **한계**: 1차 패스(AAR 정적). 시럽 번들에서는 R8으로 `i/`(74클래스)로 변형돼
  식별됐었고 AAR 실명 628클래스와 동일 제품(버전 일치)으로 확인. 전체 카브 패스는
  히트 전무로 미수행.
