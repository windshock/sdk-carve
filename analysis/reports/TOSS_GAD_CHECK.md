# Toss 5.276.0 — GAD(`com.gad.sdk`/GPA) 사용 여부 확인

- **일시**: 2026-09-07 · 획득: APKPure, `viva.republica.toss@5.276.0.xapk` (216MB,
  base + config split) · 로컬: `research/acquisition/corpus/targets/toss-5.276.0/`
- **질문**: GPA KOREA GAD 오퍼월(시럽에서 확인된 `com.github.koreagpa-dev:gad`)을
  토스도 쓰는가?

## 결론: GAD 표지 없음 (리소스 표면 기준, 높은 신뢰) — 토스의 오퍼월은 TNK Factory

| 표면 | 상태 | GAD 표지 |
|---|---|---|
| dex 30개 (~310MB) | **문자열 전면 암호화** (Toss 자체 보호기법) | 판정 불가 |
| AndroidManifest.xml | 문자열 풀 비가독 (0개 가독 문자열) | 판정 불가 |
| **resources.arsc (22.7MB)** | **평문** — 양성 대조군 통과 (`toss` 8,749회, `viva` 72회) | `gad_sdk_*` 0, `gpakorea` 0, `adison` 0 |

- GAD는 라이브러리 SDK로 `gad_sdk_*` 접두 리소스(drawable/layout/string 수십 개)와
  매니페스트 activity(`GadActivity`, `GadWebOfferwallActivity`)가 번들에 **반드시**
  포함돼야 함. 리소스 테이블이 평문인 상태에서 둘 다 부재 → **강한 부정 증거**.
- dex 기반 IOC 스캔은 무효: 30개 dex 모두 `Lcom/` 디스크립터 dex당 1~10개
  (정상 10MB dex는 수만 개) — 런타임 복호화형 자체 난독화. `packer-detect`가
  "no known packer"를 반환한 것은 시그니처 카탈로그에 이 커스텀 기법이 없기
  때문 — **양성 대조군 없는 0건은 증거가 아님**(스킬 Field notes에 반영).
- 참고: 토스의 오퍼월 인프라는 **TNK Factory**(`com_tnk_offerwall_*` 리소스 다수,
  CPS 검색 필터 UI 포함) — 오퍼월 자체는 있되 GPA GAD와는 무관한 벤더.
- 코드 레벨 확정이 필요하면 시럽 AppSealing과 동일하게 런타임 덤프 또는 봉인 전
  빌드가 필요하나, 리소스 표면의 음성으로 실무적 판단은 가능.
