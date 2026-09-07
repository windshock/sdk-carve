# bsh-sandbox — 서버 제공 BeanShell 스크립트 JVM 리플레이 하니스

에뮬레이터 없이 캡처한 `.bsh` 스크립트를 JDK 17 위에서 실제 실행해
캐퍼빌리티 시도를 JSON으로 기록한다. GPA GAD 분석을 위해 만들어졌으나
일반 목적(모든 BeanShell 서버 스크립트 트리이지)으로 재사용 가능.

## 구성

- `scripts/BshSandbox.java` — 하니스 본체 (SM 감시 + 바인딩 + 훅 리플레이 + JSON 출력)
- `scripts/stubs-src/` — 실제 패키지명의 최소 스텁 22종
  (`android.*`, `androidx.appcompat.app.AlertDialog`, `com.gad.sdk.*`, `sbx.Log`)
  모든 스텁 메서드는 `[STUB]` 이벤트를 남긴다
- `lib/bsh-2.0b5.jar` — Maven Central 공식 (sha256 `6232199563807354b3bcb5aceb3dc136502f022c6b0ef743987a83f66fee5a5c`)
  — **리플레이 대상 SDK가 선언한 bsh 버전과 일치시킬 것** (버전별 동작 차이 제거)
- `runs/` — 실행 결과 (2026-09-07: 40종 JSON + summary + dup-check)

## 빌드/실행

```bash
J17=$(/usr/libexec/java_home -v 17)   # JDK 17 필수 (JDK 24부턴 SecurityManager 비활성)
cd analysis/bsh-sandbox
"$J17/bin/javac" -cp lib/bsh-2.0b5.jar -d classes \
  $(find scripts/stubs-src -name "*.java") scripts/BshSandbox.java
"$J17/bin/java" -cp classes:lib/bsh-2.0b5.jar BshSandbox <script.bsh> <out.json>
```

## 동작 원리

1. `eval(스크립트)` — 스크립트의 타입 선언은 실제 스텁 클래스로 해석됨
2. **바인딩은 eval 이후** — 스크립트 상단의 타입 선언(`Context cat;` 등)이 변수를
   리셋하므로, SDK처럼 소스 로드 후 객체를 주입해야 함. `flag`처럼 스크립트별
   선언 타입이 다른 변수는 `safeSet` 후보 바인딩 사용
3. 관측된 훅 재호출 — `prepare/setup/checkValid/shouldOverrideUrlLoading/
   onPageStarted/onLoadResource/onPageFinished/onPageLoaded/checkParticipation/
   isValidUrl/destroy` (+URL 인자는 실관측 형태, **도메인 `.invalid` 치환**)
4. SecurityManager: NET/EXEC/EXIT/LINK/FILE-WRITE = 기록 후 차단,
   FILE-READ = 카운트만, `checkPackageAccess` = 기록(클래스로드 신호),
   bsh 경유 `setSecurityManager` = SM-TAMPER로 기록+거부

## 커버리지 원칙

리플레이 결과는 **스크립트 내용의 순수 함수** (바인딩·인자·정책 동일).
대상 코퍼스를 sha256 클러스터링해 유니크 대표만 돌리면 전수 커버리지.
동일성 검증 예: `runs/dup-check/` — 동일 클러스터 소속 캠페인 3개의
출력이 filename 필드 제외하고 비트 단위 동일.

## 결과 리포트

- `analysis/reports/GAD_BSH_SANDBOX_RUN.md` — GPA GAD 40종 리플레이 결과
- `analysis/reports/GAD_CAMPAIGN_SWEEP.md` §3 — 정적 심화(리플렉션/CVE 도달성)
- 원본 스크립트 코퍼스:
  `research/acquisition/corpus/dependencies/gad/runtime-capture-2026-09-07/`
