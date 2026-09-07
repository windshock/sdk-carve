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
  존재**(백엔드 무결성 의존, 무인자 생성자 한정 → 낮음).
- **프라이버시**: adid + 레거시 `getDeviceId`(3+) 가 `api3.tnkfactory.com`으로 전송(구조 확정),
  Adiscope(dev 엔드포인트 잔존)/Tenqube 3자 연동 — triage §2·§3와 일치.
- **위생 항목(유지)**: v7 문자열 암호화 vs v8 평문, Adiscope **dev** URL 잔존, 레거시 IMEI 호출.

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
