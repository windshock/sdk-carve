# GAD BeanShell — Level-2: injected-JavaScript replay (WebView layer)

- **일시**: 2026-09-07 (Level-1 [bsh-sandbox](GAD_BSH_SANDBOX_RUN.md)의 후속; 같은 캡처 코퍼스)
- **동기**: Level-1(`BshSandbox.java`)은 BeanShell 계층만 replay하고 stub WebView는 `loadUrl()`을
  로깅만 함. 스크립트가 **주입하는 JavaScript**(`wind.loadUrl("javascript:…")`) — 실제 기기의
  진짜 WebView에서 `GAD` JS 브리지와 함께 광고주 페이지 위에서 도는 그 계층 — 은 Level-1에서
  실행되지 않았음(리뷰 지적사항). 본 단계가 그 갭을 닫는다.
- **방법**: `analysis/bsh-sandbox/scripts/JsReplay.js` — 캡처된 .bsh에서 주입 JS 블롭을 추출해
  Node `vm` 컨텍스트에서 **실행**. mock DOM(`document.evaluate`/`getElementById`/노드) + `GAD`
  브리지를 제공하고, **모든 위험 전역을 trap**(fetch/XMLHttpRequest/WebSocket/EventSource/
  navigator/location/document.cookie/localStorage/sessionStorage/indexedDB/eval/Function/Image)
  + 노드 메서드(`click`/`dispatchEvent`/`submit`/`innerHTML`)를 trap. **라이브 사이트 접촉 0**
  (전부 mock). 위험 이벤트는 `!!` 접두로 기록.
- **증거 등급**: `runtime-confirmed` (격리 JS VM, 실 사이트 미접촉).

## 결과 (유니크 38 + 부트스트랩 2 = 40종, JS 주입 34종 / JS 블롭 183개)

| 관측 | 수치 |
|---|---|
| XPath 읽기(`document.evaluate`) | 130 |
| DOM 주석/연출(`setAttribute` style: blur/border) | 68 |
| GAD 브리지 콜백 | `log` 73, `recursiveScript` 35, `setValid` 42 |
| 네비게이션 호스트 | `accounts.google.com` 4, `m.youtube.com` 1, `my.musinsa.com` 1 (나머지는 `apple.getUrl()` 런타임값) |
| **위험 이벤트(네트워크/exec/쿠키/합성클릭/폼전송/exfil)** | **0 (전무)** |

동적 결과를 **원문 정적 grep으로 교차확인** — `.click(`·`dispatchEvent`·`fetch(`·`XMLHttpRequest`·
`document.cookie`·`.submit(`·`localStorage`·`sessionStorage`·`new Image`·`navigator.`·`eval(`·
`.innerHTML` = **전 카테고리 0 files**. 동적·정적 일치.

## 해석

- **주입 JS 계층도 관측 전용(observe-only)**: 패턴은 일관되게 `document.evaluate(XPath)`로 참여
  완료 신호(찜 개수/버디 노드/로그인 상태)를 **읽고** → `GAD.recursiveScript('setParticipation(...)')`
  /`setValid(...)`로 boolean 보고 → 실제 버튼을 `border:solid red`로 강조하거나 `filter:blur`로
  연출. **합성 클릭·이벤트 디스패치·폼 전송·DOM 주입·쿠키/세션 접근·외부 통신은 한 건도 없음.**
- **미묘점(무해 확인)**: Band 초대(`cmtm2j58…`)는 `button.onclick = function(){ GAD.recursiveScript
  ('setInvited()'); }` — **사용자 본인의 클릭을 관측**해 보고할 뿐 클릭을 대신 실행하지 않음
  (클릭 사기 아님). YouTube-like(`cmths7i6i…`) 1종만 숨김 웹뷰로 **실 `accounts.google.com`
  로그인**을 로드 — 폼 값은 안 읽고 URL 패턴으로 흐름만 추적하나, "리워드 미션 맥락의 SDK 제어
  웹뷰 내 구글 로그인"이라는 UX 그레이존은 기록(악성 아님).
- **리뷰 갭 종결**: 이제 두 계층(BeanShell = Level-1, 주입 JavaScript = Level-2)이 모두 동적으로
  양성 확인됨. 잔여 리스크는 **콘텐츠가 아니라 채널** — 서버가 임의 bsh/JS를 앱 프로세스+웹뷰
  브리지 권한으로 언제든 교체 투입 가능하다는 설계상 사실 — 로 변함없음(커밋 044f950의 프레이밍과 동일).

## 한계

- 주입 JS를 **트리거하는 훅/인자 집합은 관측된 것으로 한정**(Level-1과 동일 제약). mock DOM은
  `evaluate`가 항상 "발견(count=1/node 존재)"을 반환하도록 세팅해 "완료" 분기를 실행 — "미완료"
  분기도 동일 관측(추가 XPath 없음).
- 2026-09-07 스냅샷. 서버 스크립트는 시점별 갱신 가능 — 신규 캡처는 동일 하네스로 재실행
  (`node JsReplay.js <dir-of-bsh>`).
- JS 브리지(`GAD.*`)의 **네이티브 측 구현**은 여기 범위가 아님(bsh→네이티브 재진입은 Level-1이 커버).
