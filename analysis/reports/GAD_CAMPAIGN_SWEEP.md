# GAD 캠페인 전수 스윕 — 848건 스크립트·메타데이터 악성 행위 분석

- **일시**: 2026-09-07 (직전 [런타임 캡처](GAD_API_RUNTIME_CAPTURE.md)와 같은 날 연속 수행)
- **근거**: 사용자 명시 요청("캠페인하는걸 모두 내려받아서 악성 행위를 하는게 있는지
  분석") — AGENTS.md 도메인 접촉 예외. 격리 계획 사전 고지.
- **요청량**: `GET /campaign/list` 1건 + `GET /campaign/script/entry?id=…` 848건 =
  총 849건, 동시 3커넥션, 식별자 전송 0건, 상태 변경(POST/DELETE) 0건.
  응답코드 **848/848 전부 200 OK**.
- **원본 보존**:
  `research/acquisition/corpus/dependencies/gad/runtime-capture-2026-09-07/`
  (스크립트 848개 원문 + list.json + 분석 산출물).
- **증거 등급**: `runtime-confirmed`.

## 1. 스크립트 코퍼스 — 848개 → 유니크 38종

sha256 클러스터링 결과:

| 군 | 캠페인 수 | 내용 |
|---|---|---|
| 에러 폴백 (동일 1종) | 774 | "모듈 로드 실패 시 서버가 대신 전달하는 에러용 스크립트" — `prepare()`→`flag.quit()` 등 정리 루틴 |
| 미션 컨트롤러 템플릿군 | 74 | 아래 상세. 캠페인별 소폭 변형 37종 |

즉 **전체의 91%가 같은 에러 폴백 1종**이고, 나머지도 단일 템플릿의 캠페인별 변형
37종 — 인간 검토 가능한 크기로 수렴하며, 38종 전부 육안 검증 완료.

### 미션 컨트롤러 템플릿의 구조

SDK가 주입하는 변수 (스크립트 선언부가 그대로 노출):

```java
Context cat;  WebView wind;  WebView hawaii;  Handler hold;
Advertisement apple;  GadPerformViewModel vibe;  GadPerformFragment flag;
AlertDialog mDialog;  SharedPreferences mPref;   // + isAdded, isSignInRequested 등 상태
```

(변수명 전체가 cat/wind/hawaii/apple/vibe/flag/hold 식의 장난스러운 난독화.)

정의 함수 (캠페인별 부분 변형): `prepare, shouldOverrideUrlLoading,
onPageStarted, onLoadResource, onPageFinished, checkValid, destroy, execute,
isValidUrl, checkParticipation, setParticipation, popupGuide, toast, blur,
drawRect, fadeOut, onClick, cancelPost, signIn, goYoutube, checkLogin, setLogin,
isHome, isInviteUrl, observeInvite, start, setInvited, run`

역할: 광고 참여 플로우의 **서버 정의 UI 오케스트레이션** — 이중 웹뷰 제어
(`wind`=숨김 검증용, `hawaii`=표시 안내용), 참여 검증 도메인 도달 확인,
가이드 팝업/블러 이펙트, 참여 상태를 SDK 자체 prefs
(`cat.getSharedPreferences("com.gad.sdk")`)에 기록, 완료 버튼 표시 제어.

### YouTube 좋아요(YTL) 계열의 구글 로그인 플로우 (7종, 주요 관찰)

```java
wind.loadUrl("https://accounts.google.com/signin/v2/identifier?continue=" + apple.getUrl());
hawaii.loadUrl("https://gad.api.gpakorea.com/page/youtube_webview.html?type=YTL&gad_tracking_id=…");
```

숨김 웹뷰로 **실제 accounts.google.com**을 로드해 구글 로그인을 유도하고 URL 상태로
진행을 추적. 참고분석의 "URL 내 email+gad_tracking_id" 지적과 연결되는 지점 —
단, 본 스크립트들은 폼 값을 읽지 않고(키로깅/입력 가로챔 없음) URL 패턴 매칭으로만
흐름을 제어하며, 로그인 페이지는 스푸핑 없이 구글 원본. 그래도 "리워드 미션
맥락에서 SDK 제어 웹뷰 안의 구글 로그인"이라는 UX 그레이 존 자체는 기록 가치 있음.

### 위험 API 스캔 (13 카테고리 × 848개)

| 카테고리 | 결과 |
|---|---|
| Runtime.exec / ProcessBuilder / 쉘 | **0건** |
| 리플렉션 / Class.forName | **0건** |
| DexClassLoader / System.load | **0건** |
| 직접 네트워크(URL/HttpURLConnection/Socket/okhttp) | **0건** |
| 기기식별자(IMEI/ANDROID_ID/TelephonyManager/MediaDrm) | **0건** |
| SMS/전화 / 위치 / 클립보드 / 앱목록 / 연락처 | **0건** |
| 역직렬화(ObjectInputStream/XStream/XMLDecoder) | **0건** |
| 암호화(Cipher/crypto/Base64) | **0건** |
| 파일시스템 입출력 | **0건** |
| SharedPreferences | 참여 상태 기록(위 참조) — 유일 적중, 범위 내 |

import는 전부 `android.*`/`java.*`/`com.gad.sdk.*`/`androidx.*` — 특이 외부
import 없음 (1종이 `java.util.HashMap` 세션용).

## 2. 캠페인 메타데이터 (방문 없이 문자열만 분석)

- **광고 URL 호스트 41종, 전부 메인스트림**: play.google.com(29), m.youtube.com(25),
  cafe.naver.com(22), smartstore.naver.com(16), 29cm, threads, instagram,
  daangn, coupang 등. **단축URL/IP리터럴/.apk직접경로/퓨니코드 플래그 0건.**
  653건은 url 필드 없음 — 이 중 385건이 type=5(CPS), 나머지는 폴백 상태 캠페인.
- **설치형(type=1) 7건 — 전부 공식 마켓 경유**(play.google.com / onestore.co.kr).
  인벤토리 성상 메모: 경기똑D·서울시청소년몽땅 등 공공 앱과 함께
  `com.ggnsqy.trxgame`(랜덤 패키지명 게임, 카피캣 의심), 성인용품·데이팅 앱 등
  저품질 CPI 혼재 — **SDK의 악성이 아니라 인벤토리 품질 문제**.
- **type=5 (api-doc 미문서) 385건 = CPS 쇼핑 카탈로그**: mission="구매",
  적립 최대 93,307점, 상품 이미지 CDN이 `i.imgur.com` (제3자 무료 CDN 사용 —
  위생 메모), `pub.offer="IVE"`, `pub.class=3`. prepare2 부트스트랩의
  TYPE_CPS="쇼핑적립"과 정합 — **문서 미갱신 신규 타입**.
- **개인정보 요구 키워드**: 적중 6건 전부 맥락상 무해 — 제품 요약문(빗썸·보안플러스·
  KB펫보험 설명) 또는 리브 미션의 입력 폼 라벨(`detail.data1="비밀번호"` =
  리뷰 작성 확인용). SDK가 자발적으로 PII를 요구하는 구성 아님.

## 3. 심화 재검증 — 리플렉션 / CVE-2016-2510 (사용자 지적 대응)

### 3.1 스크립트 리플렉션 심화 스캔 (848개, 확장 패턴)

1차 스캔에서 빠졌던 `getDeclaredField` 등을 포함해 8패턴으로 재스캔:
getDeclaredField/Method/Constructor, newInstance/forName, getClass() 체인,
bsh 명령(source/eval/reflect/Interpreter), bsh 내부(this.caller/namespace/global),
역직렬화 트리거, 런타임 실행, 동적클래스로드 — **전부 0건**.
(예외: 매체 부트스트랩 `campaign/prepare2`의
`Utils$Names.class.getDeclaredField("TYPE_CPS")` 1건 — 신형 필드 존재 확인용으로
이미 문서화. UI 라벨 외 용도 없음.)

### 3.2 CVE-2016-2510 (BeanShell ≤2.0b5 역직렬화 RCE) 도달성 검증

| CVE 조건 | APK 상태 | 판정 |
|---|---|---|
| bsh ≤2.0b5 classpath 존재 | `bsh/` 163클래스, Interpreter 버전 문자열 **2.0b5** | **충족** |
| 가젯 대상 `bsh.This` 직렬화 가능 | `This` implements **Serializable** (readObject 가드 없음 — b6 수정분 부재), `XThis`도 존재 | **충족** |
| 공격자 제어 데이터를 임의 클래스로 역직렬화하는 경로 | XStream **0**, XMLDecoder **0**, Kryo **0**, ScriptEngineManager(JSR-223) **0** — 즉 bsh의 서비스 등록 파일은 사실상 사물(dead weight), Jackson defaultTyping **0** | **부재** |
| 알려진 가젯 체인 라이브러리 | commons-collections(-4)·beanutils·io·groovy·spring **전부 0클래스** | **부재** |
| `bsh.This` 타입 외부 참조 | 비-bsh 클래스 중 **0개** | **부재** |

ObjectInputStream 실호출 후보 98개(com/google 66=protobuf 내부 직렬화 호환,
naver 광고 비디오 19, datastore 등 벤더 프레임워크) 중 비벤더 3개를 육안 분류:
`c5/a`(Kotlin Queue 구현체의 자기상태 직렬화), `gf/p`(날짜 값 클래스),
`com/skt/.../network/h`(시럽 자체 Serializable DTO, 자체 readObject) — **전부
자기 클래스 상태의 직렬화 라운드트립**이며 공격자 데이터를 임의 타입으로
인스턴스화하는 구조 아님.

**판정**: 취약 버전 클래스는 배포되지만, CVE-2016-2510의 공격 전제(신뢰할 수 없는
데이터의 클래스 인스턴스화 역직렬화)가 앱 어디에도 존재하지 않아 **도달 불가**.
다만 "취약 라이브러리 고정" 자체는 GPA에 갱신(bsh 2.0b6+) 요청 가능한 정리 항목.

## 4. 판정

1. **악성 행위 스크립트: 0건** — 848개 전수에서 임의 실행/식별자 접근/은닉 통신/
   동적 로드/역직렬화 계열은 한 건도 없음. 스크립트 시스템의 실 용도는
   "참여형 미션의 서버 주도 UI 오케스트레이션+검증"으로 수렴.
2. **구조적 리스크는 유지** — 스크립트 채널 자체는 서버가 앱 프로세스 내 임의
   Java 실행 권한을 가진다는 점(지금까지의 평가와 동일). 현재 콘텐츠가 양성이라는
   것과 채널의 권한 설계는 별개. bsh 2.0b5 고정(CVE-2016-2510 대상 버전)도 유지.
3. **품질/위생 소견**: 저품질 CPI 인벤토리 혼재, imgur 이미지 CDN, 문서 미갱신
   type=5, 출하물 내 dev URL 잔존 — GPA 벤더에 통보 가능한 정리 항목.
4. 남는 미표본: 스크립트는 시점별로 서버에서 갱신 가능 — 본 스윕은 2026-09-07
   시점 스냅샷임.
