# exp4j 엔진 기술 분석 — Adison SDK 내장 수식 평가기

- **일시**: 2026-09-07 · 대상: Adison 3.16.4 AAR 내 `com.nbt.oss.exp4j` (재배포 네임스페이스)
- **등급**: `binary-confirmed`(바이트코드) + `runtime-confirmed`(JVM 격리 실증)

## 1. 계보·구성

- upstream: **fasseg/exp4j**(MIT) — Java용 경량 수식 평가기. 클래스 구성이 upstream
  구조와 정확히 일치(ArrayStack 존재로 보아 구버전 계열 포크), NBT(애디슨 인프라
  도메인 repo.nbt.com의 운영 주체)가 `com.nbt.oss`로 리로케이션해 내장.
- 구성: 코어 4(`Expression`, `ExpressionBuilder`, `ValidationResult`, `ArrayStack`) +
  `shuntingyard/ShuntingYard` + `tokenizer/*` 9종(Token 8종 + 예외) +
  `operator/*` 10종(Operator + 내장 8) + `function/*` 33종(Function + 내장 31).

## 2. 아키텍처 (3단계, 전부 반복 구조)

```text
중위식 문자열 ──Tokenizer──▶ 토큰 스트림
             ──ShuntingYard──▶ RPN(후위) 큐     (Dijkstra, 스택 기반·반복)
             ──Expression.evaluate──▶ 값 스택 계산 (RPN, 반복)
```

재귀가 **전혀 없어** 깊은 중첩도 콜스택을 소모하지 않음(아래 실증: 10만 중첩 18ms).

## 3. 능력 폐쇄성 (보안 핵심 — 바이트코드 검증)

평가기의 우주는 **double 값 + 등록된 Operator/Function 객체**뿐. 패키지 전체에서
`java.lang.reflect` / `java.io`(File·Stream·Reader) / `java.net` / `java.lang.Runtime`
/ `Serializable` 참조가 **전부 0** — 표현식이 할 수 있는 것은 "등록된 연산·함수로
숫자를 조합하는 것"으로 물리적으로 한정. 임의 메서드 호출·필드 접근·클래스 로드는
문법적으로 존재하지 않음. 미지 심볼은 `UnknownFunctionOrVariableException`으로
**fail-closed**.

## 4. Adison 통합 방식

- `LogicOperators`: 연산자 9종(`< <= > >= == != ! && ||`)을 double 위의 부 논리로
  등록(TRUE=1.0, FALSE=0.0, 우선순위 500, 좌결합).
- `ExpressionUtils.eval(String)`: `ExpressionBuilder(expr).operator(LogicOperators).build().evaluate()`.
- **유일 호출부** `Ad.isPassedTargetPackages()`: 서버가 캠페인 필터로
  `{패키지명}` 플레이스홀더 논리식을 내려보내면 → 각 패키지를 `isInstalled()`
  개별 조회(대량 나열 아님; 현대 Android에선 manifest `<queries>` 선언 필요) →
  `1.0/0.0` 치환 → eval → `== 1.0`이면 캠페인 노출 통과.
- 개인정보 뉘앙스: 설치 조회는 **서버가 지정한 패키지 이름에 한정**된 쿼리 방식이며
  설치 목록 덤프가 아님.

## 5. 실증 테스트 (JDK 17, -Xmx512m, AAR 원본 클래스, 격리 실행)

| 공격 케이스 | 결과 |
|---|---|
| sanity `1+1` | 2.0 (15ms) |
| 논리 `1 && 0 \|\| !(1 > 0)` | 0.0 — 등록 연산자 정상 |
| 실 타겟팅 원형(치환 전 `{pkg}`) | `UnknownFunctionOrVariableException` — **fail-closed** |
| `1/0`, `0/0` | `ArithmeticException: Division by zero!` — Infinity로 흐르지 않고 예외 |
| `2^1000000`, `9e2147483647` | Infinity, 0ms — 유한 비용 |
| 괄호 10만 중첩 | 18ms — **스택오버플로 없음**(반복 파서/평가기) |
| 1MB 산술식(`1+`×50만) | 123ms — 선형, 알고리즘적 폭주 없음 |
| 불완전 괄호 | `IllegalArgumentException` — fail-closed |

## 6. 결론 및 노트

- **결론**: exp4j는 GAD의 BeanShell과 같은 "서버가 로직을 내려보내는" 채널이되,
  **문법이 산술·논리로 닫혀 있어 코드 실행 탈출 경로가 없는 설계형 샌드박스**.
  임의 실행·수집·파일·네트워크 표면 전무(바이트코드+실증 이중 확인). 서버 신뢰
  전제의 리스크도 "식이 이상한 타겟팅 규칙" 수준으로 한정.
- **견고성 노트(보안 경계 아님)**: 서버가 정규식 `\{[a-zA-Z0-9_.]+\}` 밖의
  플레이스홀더를 담은 필터를 보내면 치환 누락 → eval 예외가 `isPassedTargetPackages`
  밖으로 전파(해당 메서드의 try는 치환 루프만 커버). fail-closed지만 처리되지 않은
  예외로 오퍼월 렌더 경로가 흔들릴 여지 — 서버 데이터 검증은 벤더 측 책임 영역.
- **권고**: 없음(설계 양호). 참고로 upstream exp4j도 동일 아키텍처 — 커스텀
  Operator/Function을 등록하는 호스트 코드가 능력 경계를 정한다는 원칙 확인.
