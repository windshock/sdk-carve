# Tyrads SDK 트리아지 — OK캐시락커 번들 분석 (GAD 플레이북 적용)

- **일시**: 2026-09-07 · 계기: 독립 검토의 static-unresolved 3개 중 잔여 항목
- **대상**: OK캐시락커 `com.skplanet.ocb.locker.apk` 내 `com/tyrads/sdk/*`
- **등급**: 번들 카브 1차 패스 (Joern/CodeQL 전체 패스 미수행 — 위험 히트 전무)

## 1. 벤더·제품 확정

- **벤더**: Tyrads (TyrAds 리워드/오퍼월 플랫폼, docs.tyrads.com — 플랫폼 API 문서는
  공개, **모바일 SDK 자체는 공개 배포되지 않음**: Maven Central `com/tyrads` 404,
  GitHub에 SDK 레포 없음)
- **제품**: Tyrads SDK (`com.tyrads.sdk`, 내부 코드명 **"Acmo"** — AcmoApp/
  AcmoEndpointNames/AcmoTrackingRepository 등), `tyrads_sdk_release` 변형
- **호스트 연동**: `com.skplanet.ocb.locker.presentation.framework`의 `TyradsAdapter`·
  `TyradsLinkRestriction` + 라우트 `/contents/game/offerwall/tyrads` — 락커
  게임/오퍼월 탭에서 Tyrads로 진입하는 구조

## 2. 엔드포인트 (볼트 뒤지만 일부 평문 생존)

- **`https://api.tyrads.com/v3.0/translations/version`** — 번들에서 평문으로 관측된
  유일한 전체 URL(번역 리소스 버전 체크). 베이스 호스트 = **api.tyrads.com** 확정
- 나머지 API 경로는 **AppSealing 문자열 볼트 뒤** — SDK 전체가 `com.xshield.dc`를
  import(NetworkCommons 등)해서 호출 시점에 복호화
- 인증 모델: **apiKey + apiSecret**(prefs `acmo_tyrads_sdk_api_key/secret`) +
  **Play Integrity 어트리스테이션 토큰**(`acmo_tyrads_sdk_play_integrity_token`) —
  무결성 어트리스테이션 도입은 이 카테고리에서 긍정적 신호

## 3. 수집 표면

| 항목 | 내용 | 평가 |
|---|---|---|
| 디바이스 프로파일 | brand/model/manufacturer/tablet 여부/기기 사용기간 + 볼트화된 `Settings.Secure` 문자열(android_id 추정) | 카테고리 표준 |
| **사용 통계** | `AcmoUsageStatsController` + 전용 동의 액티비티 **`AcmoUsagePermissionActivity`**(modules/legal) — PACKAGE_USAGE_STATS 특수 권한을 사용자에게 **요청하는 동의 플로우 존재** | consent 게이트 존재 — 무동의 수집 아님. CPA 설치 검증용으로 보임. 용도·범위는 벤더 확인 권장 |
| 광고ID | 1클래스 | 표준 |
| 웹뷰 브리지 | `WebAppInterface` — **`postMessage(String)` 단일 진입** | GAD의 다중 브리지보다 좁음 |

- `safedk_Context_startActivity_*` 래퍼 — SDK가 **SafeDK** 처리를 거친 흔적(서드파티
  SDK 거버넌스 도구) — 공급망 위생 관점 긍정적

## 4. 위험 API 스캔 (카브 89클래스, 10 카테고리)

동적로드 / exec / 역직렬화 / 스크립트엔진 / 리플렉션 / 식별자(IMEI류) / 앱목록 /
위치 — **전부 0**. 광고ID 1건뿐.
단, 볼트화 문자열은 정규식에 비가시이므로 위 스캔은 "평문 표면 0건"이며,
UsageStats 내용 등은 구조 참조로만 확인(위 표).

## 5. 판정 및 잔여

- **판정**: 식별된 상용 리워드 오퍼월, 수집이 카테고리 표준 + 사용통계는 동의
  게이트 존재 + Play Integrity 도입. 원격 코드 실행 채널 없음. GAD 때와 달리
  **남는 것은 정확한 API 경로 목록뿐**(볼트 뒤) — 이는 (a) 벤더에 SDK 아티팩트/문서
  요청, (b) OKC 봉인 전 빌드 diff 중 하나로 닫힘. 악성 시그니처와는 무관.
- **GAD 케이스와의 차이**: GAD는 JitPack에 아티팩트가 공개돼 있어 볼트 값을
  아티팩트로 복원했지만, Tyrads SDK는 비공개 배포라 그 경로가 없음 —
  "호스트 번들 = 유일한 1차 증거" 상태.
