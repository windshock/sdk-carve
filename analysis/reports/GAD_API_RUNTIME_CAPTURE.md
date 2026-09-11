# GAD API 런타임 캡처 — BeanShell 스크립트 콘텐츠 확보

- **일시**: 2026-09-07T05:20:34Z ~ 05:22:29Z (UTC)
- **근거**: 사용자가 명시적으로 요청("gad.api.gpakorea.com을 규격에 맞게 호출해서
  beanshell에 어떤 값을 내려주는지 확인") — AGENTS.md의 도메인 접촉 금지 조항의
  명시적 요청 예외 적용. 격리 테스트 계획 사전 고지 후 실행.
- **범위 준수**: **GET 4건 한정**(문서화된 읽기 엔드포인트만), 상태 변경
  (join/action/complete/inquiry/mission/log/shown/history 등 POST·DELETE) 0건,
  재시도 0건. 파라미터는 앱 소스에 하드코딩된 공개 media key
  `7fce4262-8654-4117-b100-0117f8e74857`(Syrup) 하나 — **uid/adid/android_id/
  widevine/IMEI 등 식별자 전송 0건**.
- **증거 등급**: `runtime-confirmed` (제어된 단발 요청, 원문 보존)
- **요청 소스**: analysis 작업 머신의 curl (앱 실행 아님). 응답 원문은 본 문서에
  전문 수록.

## 요청 1 — `GET /campaign/setup?media=7fce4262-…` → 200 OK (1,627 B)

매체(앱) 스코프의 부트스트랩 스크립트. BeanShell로 eval되며, SDK가 살아있는 객체를
주입한다는 사실을 스크립트 변수 선언이 그대로 보여줌:

```json
{"code":0,"message":"OK","script":"import android.content.DialogInterface;\nimport android.widget.Toast;\nimport android.util.Log;\nimport android.os.Handler;\nimport androidx.appcompat.app.AlertDialog;\nimport androidx.appcompat.app.AppCompatActivity;\nimport com.gad.sdk.viewmodel.GadViewModel;\n\n    AppCompatActivity action;\n    Handler hold;\n    GadViewModel medal;\n\n    private void execute(Runnable runnable) {\n        hold.post(runnable);\n    }\n\n    public void destroy() {\n        action = null;\n        if (hold != null) {\n            hold.removeCallbacksAndMessages(null);\n        }\n        hold = null;\n    }\n\n    public void setup() {\n//        if (\"com.reward.cashmong\".equals(action.getPackageName()) || \"com.rainbow.albamong\".equals(action.getPackageName())) {\n//            // 공지\n//            buildDialog(\"[서버점검안내]\", \"15:00에 서버점검을 진행합니다.\\n약 20분간 서비스 이용이 불가능합니다.\",\n//                    new DialogInterface.OnClickListener() {\n//                        public void onClick(DialogInterface dialog, int which) {\n//                        }\n//                    })\n//                    .show();\n//        }\n    }\n\n    public AlertDialog.Builder buildDialog(String title, String message, DialogInterface.OnClickListener listener) {\n        AlertDialog.Builder builder = new AlertDialog.Builder(action);\n        builder.setTitle(title);\n        builder.setMessage(message);\n        builder.setPositiveButton(\"확인\", listener);\n        builder.setCancelable(false);\n        return builder;\n    }"}
```

관찰:

- 주입 변수: `action`=`AppCompatActivity`(호출 액티비티), `hold`=`Handler`(메인
  스레드), `medal`=`GadViewModel` — **스크립트가 SDK/앱 객체에 풀 액세스**.
  `GadScript.set(...)`으로 바인딩 후 eval하는 구조와 정확히 일치.
- 주석 처리된 예시 코드가 `com.reward.cashmong`(캐시몽), `com.rainbow.albamong`
  (알바몽)을 참조 — **동일 스크립트 채널이 여러 매체 앱에 공통 서비스되는
  다중테넌트 구조**의 직접 증거.

## 요청 2 — `GET /campaign/prepare2?media=7fce4262-…` → 200 OK (1,084 B)

오퍼월 목록 화면 준비 훅. 서버가 **SDK UI 라벨을 원격으로 세팅**한다:

```json
{"code":0,"message":"OK","script":"import android.os.Handler;\nimport android.util.Log;\nimport com.gad.sdk.databinding.GadFragmentAdListInnerBinding;\nimport com.gad.sdk.ui.fragment.GadAdListFragment;\nimport com.gad.sdk.util.Utils$Names;\nimport com.gad.sdk.viewmodel.GadViewModel;\n\n    GadAdListFragment flag;\n    Utils$Names name;\n    GadFragmentAdListInnerBinding ball;\n    Handler hold;\n    GadViewModel medal;\n\n    public boolean prepare() {\n        flag.hideProgress();\n        name.TYPE_PARTICIPATION = \"참여형\";\n        name.TYPE_INSTALL = \"경험하기\";\n        name.TYPE_LAUNCH = \"경험하기\";\n        name.TYPE_MISSION = \"미션형\";\n        name.TYPE_ACTION = \"액션형\";\n        try {\n            Utils$Names.class.getDeclaredField(\"TYPE_CPS\");\n            name.TYPE_CPS = \"쇼핑적립\";\n        } catch (Exception e) {\n            //\n        }\n        return true;\n    }\n\n    public void destroy() {\n        if (hold != null) {\n            hold.removeCallbacksAndMessages(null);\n        }\n        hold = null;\n    }"}
```

관찰: `flag`=`GadAdListFragment`, `ball`=데이터바인딩 객체까지 주입.
`Utils$Names` 정적 필드를 서버가 바꾸는 것 = 원격 UI 동작 제어의 실례.
TYPE_CPS 존재를 리플렉션으로 확인 — 문서에 없는 신형(CPS 쇼핑적립) 대응.

## 요청 3 — `GET /campaign/list?media=7fce4262-…` → 200 OK

- **현재 라이브 캠페인 848건** (Syrup media key 기준).
- type 분포: `{0(참여형): 340, 3(미션형): 113, 4(액션형): 3, 1(설치형): 7,
  5(미문서화): 385}` — **api-doc에 없는 type=5가 최다 차지(385건)**. prepare2의
  TYPE_CPS("쇼핑적립")와 시의성 일치.
- 응답 키 전체: `id, key, type, subtype, title, url, point, icon, mission,
  platform, app{market,package,scheme}, detail{require,summary,description,
  image1..4}, target{sex,age_from,age_to}, pub{class,offer,order,platform,shown,
  valid,start_date,end_date}, created_at, unit, size`.
- 표본 관찰(비평 아님, 인벤토리 성상 기록): 미션형 표본 1건은 bit.ly 링크의
  전자책 유도형 소셜 액션 광고 — 저품질 CPA 인벤토리 혼재.

## 요청 4 — `GET /campaign/script/entry?id=cmtqmllw7006qx1f0eewidjvg` → 200 OK (1,318 B)

`GadPerformFragment`가 `getScriptEntry(advertisement.getId())`로 호출하는
**캠페인 스코프 스크립트**. 표본 캠페인은 "모듈 로드 실패" 상태여서 서버가
에러 폴백 스크립트를 내려줬는데, 그 **한국어 주석이 스크립트 시스템 전체를
자기설명**한다:

```java
/** 모듈 로드 실패 시 서버가 대신 전달하는 에러용 스크립트
 *  - 트래픽 SDK: onPageLoaded → abortSession → 로컬 완료 + 종료 + 재참여 차단
 *  - 오퍼월 SDK: prepare → flag.quit() 즉시 종료
 *  - 빈 텍스트 응답으로 인한 BeanShell 로드 실패/크래시 방지용 */

// ── 트래픽 SDK 진입점 ──
void onPageLoaded(String url) {
    abortSession("error", "module_not_found");
}

// ── 오퍼월 SDK 진입점 ──
//   flag(GadPerformFragment) 주입돼 있으면 오퍼월 SDK 로 판정 → 메인 스레드에서 quit()
//   prepare() == true 반환 → SDK 가 advertisement.url 로드하지 않도록 차단
boolean prepare() {
    try {
        if (flag != null && hold != null) {
            hold.post(new Runnable() {
                public void run() {
                    try { flag.quit(); } catch (Exception e) {}
                }
            });
            return true;
        }
    } catch (Exception e) {}
    return false;
}

// ── 오퍼월 SDK 라이프사이클 no-op (Command not found 노이즈 차단) ──
boolean shouldOverrideUrlLoading(String url) { return false; }
void onPageStarted(String url) {}
void onLoadResource(String url) {}
Object onPageFinished(String url) { return null; }
void checkValid() {}
```

관찰 (구조 확정):

1. **스크립트 = 웹뷰 라이프사이클 훅 집합**. SDK는 광고 웹뷰의 각 이벤트 지점에서
   인터프리터에 등록된 같은 이름의 BeanShell 함수를 호출한다:
   `shouldOverrideUrlLoading / onPageStarted / onLoadResource / onPageFinished /
   onPageLoaded / checkValid / prepare`. 즉 "서버가 SDK 동작을 script로 지시하는
   architecture" 가설이 그대로 참.
2. **반환값으로 네비게이션 거부권 보유** — `prepare()`가 true면 SDK가
   `advertisement.url` 로드를 차단. `shouldOverrideUrlLoading`도 boolean 반환.
3. **"트래픽 SDK"라는 형제 제품**이 동일 메커니즘 공유 — `abortSession(reason,
   code)` 호출로 "로컬 완료 + 종료 + 재참여 차단"(CPI 검증/어뷰징 제어). GAD는
   GPA의 오퍼월 SDK이고, 트래픽 SDK는 별도 제품으로 추정(본 APK에는 미확인).
4. 폴백조차 SDK 객체(`flag`, `hold`)를 조건 검사하고 종료를 트리거 — **에러 경로에도
   원격 제어가 작동**.

## 종합 판정

- 사용자 질문에 대한 답: **BeanShell에 내려오는 값은 "값"이 아니라 완전한 Java
  소스 문자열**이다. setup/prepare2(매체 스코프 부트스트랩)와 script/entry(캠페인
  스코프 라이프사이클 훅) 두 계층이며, eval 전에 SDK 살아있는 객체가 변수로 주입된다.
- 관측된 실제 콘텐츠는 전부 양성(UI 라벨, 다이얼로그 헬퍼, 에러 폴백) — 그러나
  채널 자체는 **서버가 앱 프로세스 안에서 임의 Java 코드를 실행할 수 있는
  설계된 원격 행위 시스템**. 서버 무결성(또는 중간자)이 곧 앱 코드 실행 권한.
- 본 캡처만으로 악성 판단 소재는 없음. 리스크는 "설계"에 대한 것 (아래 리포트 참조).

## 공개 소스 (2026-09-07 기록 — 미대조, 후속용)

GPA KOREA는 GitHub org를 2개 운영(스킬 vendor-attribution 노트의 "2-org" 패턴 확인):
- **`koreagpa-dev`** — JitPack 배포용(= gradle 좌표 `com.github.koreagpa-dev:gad`가 가리킴)
- **`GPA-KOREA`** — 샘플/문서용

- **AOS**: `implementation 'com.github.koreagpa-dev:gad:syrup-0.8.0-rc.4'` (repo `jitpack.io`),
  가이드 `https://github.com/GPA-KOREA/gad-sample-android/tree/syrup`
- **iOS SDK 존재(크로스플랫폼)**: `https://github.com/GPA-KOREA/gad-ios-sdk-syrup`,
  CocoaPods `pod 'GadSDK', '~> 0.1.3'` / SPM. (iOS 측 BeanShell/스크립트 채널 유무 미확인.)
- **버전 skew**: 통합 스니펫 = `syrup-0.8.0-rc.4` vs 본 분석 AAR/런타임 캡처 = `rc.12`
  — triage에 핀된 RC 명확화 필요(동일 라인이나 RC별 엔드포인트/스크립트 차이 가능).

## 공개 문서 1:1 대조 (2026-09-11 완료 — ROADMAP C-P1)

`gad-sample-android@syrup`의 공개 문서 3종(README.md / api-doc.md / guide_cpa.md)을 본 캡처와 대조했다.

**공개 문서가 명시하는 것 (정상 오퍼월 CRUD):**
- 호스트 `https://gad.api.gpakorea.com` — 캡처 호스트와 **일치**.
- 엔드포인트: `/campaign/{list, join, status, complete}`, 레거시 `/advertisement`, `/advertisement/comp`.
- `type` 파라미터 = **0~4만 문서화** (0 참여/1 설치/2 실행/3 미션/4 액션).
- 파라미터: media/adKey/uid/adid/adid/udid/android_id/imei 등. **헤더 문서화 없음.**
- 버전: README = `syrup-0.8.0-rc.12` → **본 분석 런타임 캡처(rc.12)와 일치** (rc.4 skew는 통합 스니펫의 구버전 표기였을 뿐, 샘플 repo 기준은 rc.12로 종결).

**공개 문서 어디에도 없는 것 (= 캡처된 은닉 채널 표면):**
- 엔드포인트 `/campaign/setup`, `/campaign/prepare2`, `/campaign/script/entry` — 미문서.
- `type=5` (CPS) — 미문서 (문서는 0~4까지만).
- `x-tdi-client-secret` 헤더 — 미문서.
- **BeanShell / script / eval / 서버구동 코드 채널** — 3종 문서 전부 **0회 언급**.

**결론(공개 문서로 종결):** 개발자 대상 공개 API는 표준 오퍼월 CRUD(list/join/status/complete, type 0~4)에
불과하다. 런타임에서 관측된 `setup/prepare2/script/entry` 라이프사이클 + `type=5` + `x-tdi-client-secret`
+ BeanShell eval 채널은 **통합사(매체)에게 전혀 공개되지 않은 내부 표면**이다. 즉 "볼트 뒤 정확한 API 경로"
미결은 봉인 전 diff 없이 **공개 문서 부재로 확정**된다 — 문서화된 표면과 실제 표면의 격차 자체가 은닉 채널이다.

**남은 후속**: iOS SDK(`gad-ios-sdk-syrup`, `GadSDK ~>0.1.3`)의 BeanShell/스크립트 채널 유무(크로스플랫폼 대칭성 확인용).

## 공개 소스 (2026-09-07 기록)

GPA KOREA는 GitHub org를 2개 운영(스킬 vendor-attribution 노트의 "2-org" 패턴 확인):
- **`koreagpa-dev`** — JitPack 배포용(= gradle 좌표 `com.github.koreagpa-dev:gad`가 가리킴)
- **`GPA-KOREA`** — 샘플/문서용
- **AOS**: `com.github.koreagpa-dev:gad:syrup-0.8.0-rc.12` (repo `jitpack.io`), 가이드 `GPA-KOREA/gad-sample-android/tree/syrup`
- **iOS**: `GPA-KOREA/gad-ios-sdk-syrup`, CocoaPods `pod 'GadSDK', '~> 0.1.3'` / SPM.
