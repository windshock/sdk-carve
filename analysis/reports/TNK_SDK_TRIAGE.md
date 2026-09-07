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

## 6. 검증 보충 — 자체 ObjectInput 역직렬화면 (풀패스 보정에 대한 2차·3차 검증, 2026-09-07)

타 세션 풀패스의 보정("deserialization 0은 오탐 — 자체 ObjectInput `e.f`가
서버 스트림 클래스명을 `loadClass(str).newInstance()`")을 바이트코드로 재검증:

- **확인**: `com.tnkfactory.ad.e.f extends DataInputStream implements ObjectInput` —
  `readObject()` case 10에서 스트림의 className으로 `loadClass(str).newInstance()`,
  직후 **`instanceof Externalizable` 검사**, 통과 시 `readExternal(this)` 호출.
- **스코프 정정(3차 검증, 사용자 지적)**: 공격면은 AAR이 아니라 `f.class.getClassLoader()`
  = **앱 전체 클래스패스**. 정확한 classfile 파서(초기 파서의 cp 슬롯 버그 수정)로
  재측정한 Externalizable 구현 클래스:

| 클래스패스 | classes | implements Externalizable | 성격 |
|---|---|---|---|
| Android framework (android-33) | 전체 | **0** (참조 자체 0) | — |
| TNK AAR | 664 | **0** (초기 "2개"는 instanceof 참조를 구현으로 오인한 crude 오탐) | — |
| OK Cashbag | 111,713 | **8** | kotlin SerializedCollection/SerializedMap, ktor, threetenbp, kotlin.time/uuid |
| Syrup | 104,029 | **18** | 위 + **INITECH AriaKey/DESKey**, R8-renamed 다수 |
| OKC Locker | 92,120 | **8** | 위 + **SafeDK PersistableBase** |

  (instanceof는 서브클래스도 만족하므로 실제 후보는 구현자+그 서브클래스)

- **공격 가능성 재평가**: 후보가 "0개"가 아니라 **8~18개+서브클래스**라는 것이
  정확한 그림. 다만 가젯 성립에는 다음 관문이 남는다:
  1. 후보의 `readExternal()`이 위험한 부작용(임의 클래스 로드, exec, 타입 컨퓨전)
     를 가져야 함 — 현재 후보들은 kotlin/ktor/threetenbp/키 컨테이너류
     **데이터 채움형**으로 알려진 가젯 없음 (AOSP 가젯 연구에서도 Externalizable
     가젯은 Serializable 대비 극소)
  2. readExternal이 반환한 객체는 TNK 파서의 메시지 슬롯으로 들어감 — 이질 타입은
     TNK 코드의 타입 기대와 어긋나 ClassCastException/무시로 귀결
  3. 도달성: 스트림 = api3.tnkfactory.com TLS(서버 HSTS 발행) — 제3자는 신뢰 CA
     확보 전까지 도달 불가
- **결론(정정)**: 이전 "구조적으로 불가"는 과소 서술. 정확한 표현은
  **"후보 8~18개+서브클래스의 readExternal 전수 감사 결과에 종속 — 알려진 가젯은
  없으며 데이터 채움형이라 실행 프리미티브로 이어지는 경로가 관측되지 않음.
  도달성은 백엔드/TLS 신뢰에 묶임"**. 잔여 작업: 후보 18개(Syrup 기준) readExternal
  감사 — 수작업 1시간 내 완료 가능한 규모.
- **권고**: TNK에 className 화이트리스트(PacketTypes 등록 클래스 한정) 요청 시
  이면 완전히 닫힘 — 정리 항목 수준.
