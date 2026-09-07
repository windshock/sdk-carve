# bsh-sandbox 리플레이 — GAD 서버 스크립트 동적 캐퍼빌리티 분석

- **일시**: 2026-09-07 ([전수 스윕](GAD_CAMPAIGN_SWEEP.md) 직후, 같은 캡처 코퍼스 사용)
- **목적**: 서버가 내려보낸 BeanShell 스크립트를 에뮬레이터 없이 JVM에서
  **실제로 실행**해 어떤 동작을 시도하는지 관측(참고 분석이 제안한 2-tier 중 Level 1).
- **증거 등급**: `runtime-confirmed` (격리 JVM, 도메인 .invalid 치환, SM 차단 하 replay)

## 1. 구성

| 항목 | 값 |
|---|---|
| 하니스 | `analysis/bsh-sandbox/scripts/BshSandbox.java` (~200줄) |
| 스텁 클래스 | `analysis/bsh-sandbox/scripts/stubs-src/` — **실제 패키지명** 그대로 22종 (android.content.Context/Intent/Uri, android.webkit.WebView, androidx.appcompat.app.AlertDialog, com.gad.sdk.{model,ui.fragment,viewmodel,util,databinding} 등, 모든 호출을 이벤트로 기록) |
| 인터프리터 | **bsh 2.0b5** (Maven Central 공식, sha256 `62321995…`, 163클래스 — APK 내 `bsh/` 163클래스와 개수 일치 = SDK가 실은 동일 아티팩트) |
| JDK | 17.0.7 Temurin (SecurityManager 동작 마지막 라인 — JDK 24부턴 완전 비활성) |
| 차단 정책 | NET(connect/resolve)·EXEC·EXIT·LINK·FILE-WRITE = **기록 후 SecurityException**, FILE-READ = 카운트만, `checkPackageAccess` = 기록만(클래스로드 신호), `setSecurityManager` bsh 경유 조작 = SM-TAMPER로 기록+거부 |
| 리플레이 절차 | `eval(스크립트)` → **바인딩은 eval 후**(스크립트 상단 타입 선언이 변수를 리셋하므로 SDK와 동일 순서; flag는 스크립트별로 GadPerformFragment/GadAdListFragment 이원이라 후보 바인딩) → 관측된 훅 13종 재호출(prepare/setup/checkValid/shouldOverrideUrlLoading/onPage*/onPageLoaded/checkParticipation/isValidUrl/destroy — URL 인자는 실관측 mission.html 형태 재현, 도메인만 `.invalid`) |

## 2. 코퍼스와 결과

- 대상: 캠페인 유니크 38종 + 부트스트랩 2종(setup/prepare2) = **40종**
  (848건 = 38 sha256 클러스터 + 부트스트랩. 리플레이 결과는 스크립트 내용의
  순수 함수이므로 클러스터 대표 실행으로 전수 커버 — 동일 클러스터 소속
  캠페인 3개의 리플레이 출력이 filename 제외 비트 동일함을 검증:
  `runs/dup-check/`)
- **eval 성공 40/40** (R8 전 원본과 동일한 환경에서 전부 파싱·정의·호출됨)
- **위험 시도 총합 0**: NET-DENY 0, EXEC-DENY 0, EXIT-DENY 0,
  FILE-WRITE-DENY 0, LINK-DENY 0, SM-TAMPER 0 (SM 조작 시도조차 없음)
- 클래스 접근: android*/java*/com.gad/androidx/bsh 범위 전부 — 유일한
  `java.lang.reflect` 접근은 부트스트랩 prepare2의 `getDeclaredField("TYPE_CPS")`
  (정적 분석과 일치). 전화/식별자/파일 관련 패키지 접근 없음
- 이벤트 총계: CLASS 815, STUB 254, HOOK-ERR 19(스텁 미완 메서드 갭 — 문서화), LOG 18

## 3. 동적 리플레이가 밝혀낸 실제 동작 (정적 분석의 확인 + 심화)

1. **참여 검증 = 웹뷰 DOM XPath 스크래핑**: 스크립트가 `wind.loadUrl("javascript: …")`
   로 페이지 스크립트를 주입해 광고 페이지의 DOM을 검사한다. 실제 포착된 페이로드:
   - 네이버 블로그 이웃추가 검증:
     `getElementsByXpath('//a[@ng-click="blogHomeCtrl.addBothBuddy()"]|…[text()="이웃"]')`
   - `GAD.log("checkParticipation " + node)` → `GAD.recursiveScript('setParticipation(true/false)')`
   - 검증 대기: `handler.postDelayed(delay=2000)` 폴링
   - UI 조작: `document.getElementById('ct').setAttribute("style","filter:blur(2px);")`
2. **서버 라벨 세팅 재현**: prepare2 replay에서 스텁 `Utils.Names` 정적 필드가
   실제로 `참여형/경험하기/쇼핑적립` 으로 세팅됨 (정적 관측과 일치하는 동적 확인)
3. **prefs 접근**: `getSharedPreferences("com.gad.sdk")` 읽기 — 참여 상태 기록용
   (쓰기 시도는 FILE-WRITE DENY로 잡히는데 0건 — 스텁은 메모리만 사용)
4. **토스트 문구 포착**: "적립 확인 페이지로 이동합니다. 이동 후 다시 시도해 주세요."
   등 UX 흐름 전체가 스크립트 주도임을 확인

## 4. 판정 및 한계

- **판정**: 전수 40종의 동적 리플레이가 정적 분석 결론(§악성 0건)을 **행위 수준에서
  재확인**. 시스템의 실 능력은 "웹뷰 제어 + DOM 스크래핑 기반 참여 검증 + UI 연출"
  이며, 기기식별자·실행·외부 통신·파일시스템 표면은 관측되지 않음. 구조적 리스크
  평가(서버가 프로세스 내 임의 Java 실행 가능 + bsh 2.0b5 고정)는 유지.
- **한계**: (1) Level 1만 수행 — Robolectric 2차 계층 불요 판단(스텁으로 전 훅 도달).
  (2) 스텁은 SDK 클래스의 관측된 부분집합 — 미구현 메서드 호출 19건은 HOOK-ERR로
  기록(원문 rawlog 보존). (3) 2026-09-07 스냅샷 — 서버 스크립트는 시점별 갱신 가능.
  (4) 네트워크는 설계상 전면 DENY라 "실연 안 함"과 동일.
- **재사용**: 신규 캡처 스크립트는 `java -cp classes:bsh-2.0b5.jar BshSandbox
  <script.bsh> <out.json>` 한 줄로 동일 분석 가능 (bsh 버전만 SDK 의존성과 일치시킬 것).
