# TNK 리워드 SDK (tnk_sdk_rwd_br) 1차 트리아지 — 토스 번들 대조 포함

- **일시**: 2026-09-07 · 계기: 토스 5.276.0에서 TNK 오퍼월 리소스 확인 ([TOSS_GAD_CHECK](TOSS_GAD_CHECK.md))
- **등급**: 1차 패스(벤더 아티팩트 정적 분석) — Joern/CodeQL 전체 카브 패스는 미수행(아래 한계)

## 1. 벤더·제품 확정

- **벤더**: TNK Factory (tnkfactory.com, 문의 platform@tnkfactory.com)
- **제품**: TnkAd SDK Rwd — 오퍼월 + 전면광고 + 분석도구
- **좌표**: `com.tnkfactory:rwd` — Maven Central(7.31.3까지) + 자체 Nexus
  `https://repository.tnkad.net:8443/repository/public/`(8.x 전용)
- **분석 아티팩트**(로컬 /tmp/tnk-sdk, provenance):
  - `rwd-8.09.32.aar` (2,052,662B, sha256 `760098ae…`) — 최신(2026-08-24), 664 클래스, 평문 문자열
  - `rwd-7.31.3.aar` (664,817B, sha256 `d74e6d54…`) — 331 클래스, **문자열 암호화**(URL 0건 → 버전대별 보호 정책 차이)
- 레포 자체는 샘플앱(`com.tnkfactory.tnkofferer`)+가이드+Unity 플러그인 — SDK 본체는 Maven/Nexus 배포

## 2. 엔드포인트·연동 구조 (8.09.32 평문 기준)

- 백엔드: **`https://api3.tnkfactory.com`** — 오퍼월 웹 엔트리
  `/tnk/offerwall.web.main?md_user_nm={매체유저ID}` (GAD의 media/uid와 동일 역할)
- 제3자 연동이 AAR에 내장:
  - `https://reward-channel-webview.reward.tenqube.com` — **Tenqube** 리워드 채널 웹뷰
  - `https://tnk-ads-analytics-dev.adiscope.com` — **Adiscope** 분석(개발) 엔드포인트가
    출하물에 잔존 — 정리 항목(GAD의 ngrok 잔존과 같은 부류)
  - `https://www.tnpick.com` — TNK 자사 제품
- UI: `AdWallActivity` 등 컴포넌트 + 웹뷰 오퍼월(TnkWebEventActivity, HelpDeskWebView)

## 3. 위험 API 스캔 (13 카테고리)

| 카테고리 | 결과 |
|---|---|
| 동적로드 / 역직렬화 / 스크립트엔진(bsh·Rhino·JSR-223) / 리플렉션 | **전부 0** |
| 클립보드 / 앱목록 / 위치 | **0** |
| 광고ID | 28클래스 — 카테고리 표준 |
| 기기식별자 | `getDeviceId` 3클래스 (`TnkCore`, `data/SessionInfo`, `PacketService`) — 구형 IMEI 계열 유산 호출(현대 Android에선 null/예외). privacy-gray 유산 항목 |
| "exec" 히트 1건 | **오탐** — 실체는 `checkRooted`(`/system/bin/su` 등 su 경로 + `test-keys` 검사). 리워드 어뷰징 방지 표준(GAD의 EmulatorDetector와 동류) |

**핵심 차이(GAD 대비): 서버 주도 스크립트 채널이 없다.** BeanShell 같은 원격 로직
체계·비문서 필드 경고가 없고, 동작은 웹뷰 오퍼울 + 자체 UI로 수렴. 즉 "서버가
앱 프로세스에 임의 실행 권한을 갖는" 구조적 리스크가 이 SDK에는 관측되지 않음.

## 4. 토스 번들 대조

- 토스 `resources.arsc`의 `com_tnk_*` 254개 ↔ AAR의 `com_tnk_*` 231개 —
  **14개 정확 일치**(`com_tnk_offerwall_cps_search_with_filter*`,
  `com_tnk_offerwall_curation_control_cps_primary`, `com_tnk_offerwall_header*` 등).
  불일치 다수는 토스 쪽 버전 차이 + 리소스 셰이킹으로 설명되는 범위.
- → 토스에 들어있는 오퍼월이 TNK 제품군임을 아티팩트 수준에서 교차 확인.
  (GAD/gpakorea/adison는 토스에서 0건 — [TOSS_GAD_CHECK](TOSS_GAD_CHECK.md))

## 5. 판정 및 한계

- **판정**: 식별된 상용 오퍼월, 행위 표면은 카테고리 표준(ADID + 유산 getDeviceId +
  루팅 검사 + 웹뷰 오퍼월). 원격 코드 실행 채널 없음 → GAD 대비 구조적 리스크 낮음.
  위생 항목: `getDeviceId` 유산 호출, Adiscope **dev** 엔드포인트 잔존, v7 문자열
  암호화(v8은 평문 — 배포물 보호 정책 일관성).
- **한계(1차 패스)**: 본 분석은 AAR 정적 표면 스캔. 스킬 기준의 전체 패스(Joern
  entry→sink 도달성, CodeQL, scope-closure)는 미수행 — 히트가 전무해 우선순위 낮다고
  판단했으나, 토스 실번들 대상 감사가 필요하면 해당 버전 AAR로 카브+전체 패스 수행.

## 6. 검증 보충 — 자체 ObjectInput 역직렬화면 (풀패스 보정에 대한 2차 검증, 2026-09-07)

타 세션 풀패스의 보정("deserialization 0은 오탐 — 자체 ObjectInput `e.f`가
서버 스트림 클래스명을 `loadClass().newInstance()`")을 바이트코드로 재검증:

- **확인**: `com.tnkfactory.ad.e.f extends DataInputStream implements ObjectInput` —
  `readObject()` case 10에서 스트림의 className으로 `loadClass(str).newInstance()`.
- **보강(풀패스가 언급 안 한 게이트)**: 인스턴스화 직후 **`instanceof Externalizable`
  검사** — 통과 못 하면 IOException으로 폐기. AAR 664클래스 전체에서 Externalizable
  구현은 **`e.f`(자신)와 `e.g`(자사 패킷) 단 2개**.
- **공격 가능성 평가**:
  - 제3자 공격자: 스트림은 api3.tnkfactory.com TLS(서버가 HSTS max-age 발행)라
    MITM에 신뢰 CA 필요 → **사실상 불가**.
  - TNK 백엔드 신뢰 상실 시나리오: (a) 성공 경로 = 자사 패킷 2클래스의 readExternal
    필드값 조작 — "백엔드가 응답 내용을 정하는" 정상 동작과 동일 신뢰등급, 새 권한
    아님. (b) 폐기 경로 = 임의 클래스의 no-arg 생성자·정적 초기화 트리거 — 코드
    실행 아님, 이상 상태 유발 수준. (c) 재귀 파싱(중첩 배열) 스택오버플로·과다
    할당 — 자기 백엔드가 자기 앱을 DoS하는 시나리오만 성립.
  - 결론: **CVE-2016-2510류 가젯 구조가 성립 불가**(임의 타입 필드 주입도, 임의
    readObject 콜백도 없음). "잠복·낮음" 평가가 맞고 Externalizable 게이트로
    실질 표면은 자사 패킷 2클래스.
- **권고**: TNK에 className 화이트리스트(PacketTypes 등록 클래스 한정) 요청 시
    이면 완전히 닫힘 — 정리 항목 수준.
