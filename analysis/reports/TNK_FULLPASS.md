# TNK rwd — full-pass elevation (CPG source→sink) of the first-pass triage

Elevates [`TNK_SDK_TRIAGE.md`](TNK_SDK_TRIAGE.md) §5 (1차 패스, "Joern/CodeQL 미수행") to a
CPG-level source/sink pass per the skill standard.

- **일시**: 2026-09-07 · **대상**: `com.tnkfactory:rwd` **8.09.32** AAR
  (sha256 `760098aebf1b23604d8b3c764e25442e13f6b4ab63f505dbc4726d7d8d0b968f`, Nexus
  `repository.tnkad.net:8443/public`; = triage와 동일 아티팩트) · 7.31.3도 재확보(`d74e6d54…`, Maven Central).
- **파이프라인**: AAR → `classes.jar`(664 클래스, root `com/tnkfactory/ad/*`, JNI 없음) →
  `jimple2cpg`(Soot, JDK17) → `joern` inventory + `reachableByFlows`.
- **증거 등급**: `cpg-confirmed`(정적) — 실행/네트워크 없음.

## 1. 싱크·소스 인벤토리 (CPG call-site 기준)

| 카테고리 | 콜사이트 | 판정 |
|---|---|---|
| **EXEC** (Runtime.exec/ProcessBuilder) | **0** | 없음 (triage 확인) |
| **SCRIPT-ENGINE** (bsh/ScriptEngine/Interpreter.eval) | **0** | **없음 — GAD와의 결정적 차이 CPG로 확정** |
| **DYNAMIC-LOAD** (loadClass/DexClassLoader/System.load) | 2 | `Utils.checkVM`(에뮬레이터 클래스 존재검사, 양성) + `e.f.readObject`(아래 §2) |
| **REFLECTION** | 2 | `AdPlacementView.initView`의 `Class.getConstructor`/`newInstance` — 클래스명으로 placement 뷰 생성하는 UI 팩토리(양성) |
| **DESERIALIZATION** (java.io.ObjectInputStream.readObject) | 0 | 표준 패턴 0 — 단, §2의 **자체 ObjectInput 구현은 이 패턴을 우회**(triage 보정) |
| **NET** (HttpURLConnection/URLConnection/SSLSocket) | 65 | `PacketService.a`, `VideoCache/InterstitialCache`, `AdiscopeReport.postData`, `SSLFactory` — 표준 광고 SDK 네트워킹 |
| **DEVICE-ID** (getDeviceId/AdvertisingId) | 45 | `SessionInfo.getDeviceId()` + `AdidManager.getAdvertisingId*`, ServiceTask 전 API에 확산 |
| **LOCATION** | 0 | 없음 |

## 2. 보정 필요 — triage의 "deserialization 0"은 false negative

CPG가 잡아낸 **`com.tnkfactory.ad.e.f`** 는 표준 `java.io.ObjectInputStream`이 아니라
**자체 구현 `DataInputStream implements java.io.ObjectInput`**(TNK 자체 바이너리 프로토콜 리더).
그 `readObject()` 바이트코드:

```
484: invokevirtual java/lang/ClassLoader.loadClass:(String)Class
487: invokevirtual java/lang/Class.newInstance:()Object     // 스트림에서 읽은 클래스명을 인스턴스화
```

즉 **서버 응답 스트림에 담긴 클래스명을 `loadClass().newInstance()` 로 인스턴스화**한다.
triage의 위험스캔은 `ObjectInputStream.readObject` 시그니처만 봐서 이 자체 ObjectInput을
놓쳤음 → **"deserialization 0"을 "custom deserialization surface 존재"로 보정.**

- **리스크 등급: 잠복(낮음).** `newInstance()`는 **무인자 생성자**만 호출 → 임의 코드 실행이
  아니라 classpath 상 로드 가능한 클래스의 기본 생성자 인스턴스화에 국한(가젯 체인 라이브러리
  부재는 CVE 절과 동일 조건). 입력은 `api3.tnkfactory.com` 응답(HttpsURLConnection/SSLFactory =
  TLS) → **전제조건은 백엔드/TLS 무결성**. GAD BeanShell 채널과 **같은 위협 클래스(서버신뢰=인프로세스
  행위)이나 훨씬 좁음**(코드 eval 아님, 무인자 생성자 인스턴스화만).
- **정밀화(2026-09-07 바이트코드 검증; zcode `80ce9ef` 반영):** `newInstance()`(offset 487) 직후
  **`instanceof java/io/Externalizable` 게이트**(501)가 있어 데이터 구동 `readExternal(ObjectInput)`
  (513)은 Externalizable 구현체에만 실행됨. **AAR 664클래스 중 Externalizable 구현체는 0개**
  — `e.f`/`e.g`는 Externalizable을 *구현*하는 게 아니라 각각 `DataInputStream implements ObjectInput`
  / `DataOutputStream implements ObjectOutput` 리더·라이터로 이 게이트를 **참조**할 뿐(= zcode의
  "e.f/e.g가 Externalizable 구현" 표현은 "구현 0, 게이트 참조 2"로 보정).
- **재보정(2026-09-07, Externalizable 취약점 레퍼런스 반영 — "in-package dead / nil"은 과소평가):**
  바이트코드 추가 확인 결과 표면은 TNK AAR이 아니라 **앱 런타임 classpath 전체**다.
  (1) 인스턴스화할 **클래스명은 스트림에서 읽은 `PacketTypes$Traits.className`**(서버 통제) —
  `462 length/465 ifne`의 **비어있지 않음 검사만, 화이트리스트/프리픽스 필터 없음**;
  (2) 로더는 `478 ldc e.f.class → 480 getClassLoader` = **앱 클래스로더** → 프레임워크+호스트앱+
  번들된 모든 SDK 클래스를 로드 가능(TNK 패키지 한정 아님);
  (3) `487 newInstance`가 **게이트(501) 이전**에 실행 → 임의 앱-classpath 클래스의 무인자 생성자/
  정적초기화가 무조건 실행;
  (4) e.f는 **표준 `ObjectInputStream`이 아닌 자체 `ObjectInput`** → **JEP-290 `ObjectInputFilter`가
  이 경로를 보호하지 못함**(플랫폼 역직렬화 필터 우회). 따라서 `readExternal` 가젯 표면 =
  **피해 앱 classpath 상의 Externalizable+악용가능 readExternal 구현체 집합**(TNK AAR=0이 상한이 아님;
  레퍼런스 §2/§3의 앱·3rd-party readExternal 가젯 지점과 동일). 표준 Intent/Bundle/ObjectInputStream
  진입점(CVE-2014-7911/2015-3825)은 **미해당**(데이터는 api3 HTTP 프로토콜로 유입) — 원리만 동일.
  - **판정 재조정: nil 아님 → 실사용 "낮음"(설계결함은 "중").** 실 익스플로잇은
    (a) HSTS api3 **TLS MITM/백엔드 침해** 전제 + (b) 앱 classpath 내 악용가능 readExternal 가젯 필요
    (2025 arXiv: AOSP엔 심각 가젯 희소 → 앱·SDK 의존)로 게이트되어 낮음. 다만 **화이트리스트 부재 +
    자체 ObjectInput(JEP-290 우회) + 앱 로더 + 서버 통제 클래스명**은 실질 역직렬화 설계결함 →
    **TNK 하드닝 요청: (i) loadClass 전 클래스명 allow-list(자사 패킷 클래스), (ii) 자체 ObjectInput
    폐기하고 타입안전 포맷(protobuf 등), (iii) 서버 응답 무결성(cert pinning) 확인.**

## 3. 식별자 텔레메트리 — 구조적 exfil 경로 확정

`PacketService.a(String,String,Object[],Map)` 한 메서드에 **`SessionInfo` 36회 + `getDeviceId` +
`openConnection` + `getOutputStream` + `HttpURLConnection` 4회가 공존**. 즉 세션/기기 식별자를
담은 요청을 만들어 커넥션 OutputStream으로 전송 → **adid + (레거시) getDeviceId 가 백엔드로 전송**됨
(표준 광고 adid 텔레메트리; `getDeviceId`는 구형 IMEI 계열 45개 소스 중 하나).

- **자동 dataflow(`reachableByFlows`) = 0 flows**: 이는 "미전송"이 **아니라** Joern 기본 데이터플로가
  Kotlin 코루틴 상태머신(`invokeSuspend`)·`SessionInfo` 필드·`Map`/`OutputStream.write` 직렬화 홉을
  스티칭 못 한 **엔진 한계**. 동일 메서드 내 소스·싱크 공존으로 **구조적 확정**(기계증명은 미완).

## 4. 판정 (elevation)

- **triage 핵심 결론 유지·강화**: **원격 코드 실행 채널 없음**(EXEC 0 · SCRIPT-ENGINE 0 CPG 확정) —
  GAD BeanShell과 근본적으로 다름. 행위는 웹뷰 오퍼월 + 표준 광고 API로 수렴.
- **보정 1건**: "deserialization 0" → **자체 `ObjectInput`(`e.f`)의 loadClass+newInstance 잠복면
  존재** → **재보정(§2)**: `instanceof Externalizable` 게이트는 있으나 클래스명 화이트리스트 없음 +
  **앱 클래스로더**(런타임 classpath 전체) + 자체 ObjectInput(**JEP-290 필터 우회**) → 표면은
  AAR(구현체 0)이 아니라 **피해 앱 classpath 전체**. 실사용 **낮음**(TLS-MITM/백엔드 + 가젯 가용 전제),
  **설계결함 "중" → TNK 하드닝 요청**(allow-list / 타입안전 포맷 / cert pinning).
- **프라이버시**: adid + 레거시 `getDeviceId`(3+) 가 `api3.tnkfactory.com`으로 전송(구조 확정),
  Adiscope(dev 엔드포인트 잔존)/Tenqube 3자 연동 — triage §2·§3와 일치.
- **위생 항목(유지)**: v7 문자열 암호화 vs v8 평문, Adiscope **dev** URL 잔존, 레거시 IMEI 호출.

## 4.1 cert-pinning decider — 확정 (2026-09-11, ROADMAP C-P1)

§2/§4의 역직렬화 가젯면(`api3.tnkfactory.com` 응답 → 화이트리스트 없는 자체 `ObjectInput`)의 심각도는
"서버 응답이 pinning으로 무결성 보장되는가"로 low↔medium이 갈렸다. `com.tnkfactory.ad.rwd.SSLFactory`
+ 실제 전송 클래스(`PacketService`/`VideoCache`/`InterstitialCache`)를 디컴파일해 확정:

- `SSLFactory()` = `SSLContext.getInstance("TLS")` + `init(null, null, null)` → **플랫폼 기본 TrustManager
  (시스템 CA 스토어)**. trust-all도 아니고 **pinning도 아님**. `a(Socket)`은 활성 프로토콜을 TLS 계열로만
  제한(하드닝) — pinning 아님.
- `PacketService`(API 본선): `new URL(...).openConnection()` → `if (instanceof HttpsURLConnection)
  setSSLSocketFactory(new SSLFactory())`, 그리고 `http://`를 `https://`로 강제 승격. **`setHostnameVerifier`
  호출 없음** → 기본 호스트명 검증 적용. `VideoCache`도 동일(`setSSLSocketFactory(new SSLFactory())` ×2).
- **trust-all `TnkAssert$NullHostNameVerifier.verify()`는 무조건 `return true`** 지만 **`TnkAssert`
  자가진단 클래스 안에만** 존재 — `setDefaultHostnameVerifier`/`setHostnameVerifier`로 전역·본선에 설치되지
  않음(프로덕션 미배선). 잠복 위험(향후 배선 시 즉시 MITM 홀)이라 하드닝 목록에 명시.

**결론:** API 전송은 **cert pinning 부재** — 무결성은 오직 단말 CA 스토어에 의존. 개방망 수동 MITM은
표준 TLS로 차단되나(=trivially exploitable 아님, high 아님), **단말 신뢰 CA를 얻은 공격자**(오발급/침해 CA,
기업 MITM 프록시, 루팅 단말의 사용자 CA)는 응답을 치환해 화이트리스트 없는 deser 가젯에 도달 가능.
→ **decider = medium 확정**(low로 하향 불가): "unpinned + 화이트리스트 없는 자체 ObjectInput". §4 하드닝
요청(allow-list / 타입안전 포맷 / **cert pinning**)은 이제 증거 기반이며 pinning이 실제 결여됨을 확인.

## 5. 한계

- 자동 reachability 미스티칭(§3) — 정밀 증명 필요 시 소스/싱크를 `SessionInfo` 필드·
  `URLConnection.getOutputStream().write`까지 확장한 커스텀 flow 또는 수동 슬라이스 필요.
- **버전**: 분석 아티팩트 = 8.09.32(평문). **토스 실번들 버전은 dex 암호화로 미확정**(리소스 14개
  교차일치만) — 토스 정번들 감사가 목적이면 해당 버전 AAR로 동일 파이프라인 재실행.
- JNI 없음(순수 Java/Kotlin) — 네이티브 트랙 불요.

## 재현
```bash
# AAR -> classes.jar -> CPG
unzip -o rwd-8.09.32.aar classes.jar -d x && jimple2cpg x/classes.jar -o tnk.cpg
# joern inventory + reachability
joern --script analysis/joern/scripts/tnk-audit.sc
```
CPG/AAR는 `research/acquisition/corpus/dependencies/tnk/`(gitignore) 로컬 보존.
