---
name: xshield-reversal
description: NSHC xShield/DxShield(및 유사 상용 Android RASP·패커)로 봉인된 APK를 기기·Frida 없이 분석하는 통합 방법론. 정적 단계(문자열 볼트/페이로드 섹션 암호 크랙, 매니페스트·클래스맵 파싱)와 unidbg 에뮬레이션 단계(JNI_OnLoad→d() 13필드→p() 문자열 볼트 전수 복호화)를 아우른다. 앱 프로텍터 공급망 평가, 숨겨진 컴포넌트·엔드포인트 회수, 봉인 APK의 네이티브 에뮬레이션에 사용. Use when reversing a sealed/protected Android APK (xShield, DxShield, or similar commercial packer/RASP), recovering hidden components and endpoints, or emulating protector natives end-to-end in unidbg.
---

# xShield/DxShield 봉인 APK 리버설 — 정적 + unidbg 통합 방법론

**검증된 실적 (2앱 교차검증)**:
- **OK Cashbag 7.1.9** (com.skmc.okcashbag.home_google) — 섹션 암호 크랙, 컴포넌트 jar 복호화(기기
  아티팩트와 바이트 일치), d() 13필드 완전 성공, 앱 문자열 볼트 51,783개 전수 복호화. 상세:
  `analysis/PAYLOAD_LOADER_REVERSAL.md`, 교훈: `analysis/LESSONS_LEARNED.md`.
- **PASS by SKT 3.12.8** (com.sktelecom.tauth) — **동일 방법론이 다른 빌드에 그대로 일반화**됨(2026-09):
  페이로드 컴포넌트 dex를 밑바닥부터 정적 복호 → **ground truth md5 일치**, RASP 볼트 40+ 정적 복호
  (frida/magisk/proc/emulator 탐지). 문자열 복호기는 0x1eca0이 아니라 **0x5c78**였을 뿐 동일 MBA
  알고리즘. → 아래 **[Cross-build 주소 재특정]** 참조.
전 과정 기기 0회, Frida 0회, 순수 정적/에뮬.

## 전제 조건

- Python3 + `unicorn` + `capstone` (`pip install --user --break-system-packages unicorn capstone`)
- JDK 17+(실측 25 사용), Maven, unidbg 클론 (`git clone https://github.com/zhkl0228/unidbg /tmp/unidbg`)
- Ghidra + pyghidra (구조 파악용, 일괄 디컴파일: `tools/decomp_all.py`), radare2(선택)
- 스킬 내장 도구: **`scripts/find_decryptor.py`**(빌드 무관 문자열 복호기 자동 특정 + 정적 볼트 덤프).
- 분석 워크스페이스 도구(무거운 것): `~/Downloads/xshield/tools/` — `decrypt_libdxbase.py`(볼트, 주소 인자),
  `unidbg_DxShieldTest.java`(전체 로더 에뮬 하니스), `vault_table_bruteforce.py`, `jarsolve.c`,
  `decomp_all.py`(pyghidra). 다른 타깃엔 이들 + 타깃 `.so`를 함께 가져갈 것.
- Sibling 스킬 **`sdk-carve`**: `scripts/packer-detect.py`(stage-0 프로텍터 식별), carve/CPG source→sink.

## 대상 지문 (xShield 판별)

- Java: `com.xshield.*` (da=native 브릿지, dc=문자열 접근자, 난독화된 유니코드 필드명)
- Native: `libdxbase.so` (JNI_OnLoad@@LIBJNI, 심볼 스트립, `Java_*` 익스포트 없음)
- Asset: `.4ee57bec*.dex`류 해시명 에셋 = [스텁 dex][섹션들][평문 매니페스트][OTL]
- **주의**: 루트 `classes*.dex`가 평문이어도 봉인일 수 있다 — 문자열 상수가 재암호화되고
  런타임에 p() 볼트로 복호된다(이번 사례). "dex가 평문이니 봉인 아님" 판단 금지.

## 워크플로

### Phase 0 — 트리아지 (정적)
1. **`scripts/packer-detect.py <apk>`**(sibling sdk-carve 스킬) 먼저 — NSHC xShield 식별 + carve-impact
   (payload-DEX BLIND) 판정. APKiD 병행, 네이티브 sha256 기록(공급망 베이스라인).
2. APK CD 전수 열거: `classes*.dex` 개수/크기, 대형 에셋, lib/ — 엔트리 수를 기억
   (로더가 CD를 전수 순회하며, 이후 교차 검증에 쓰임).
3. **페이로드 에셋 엔트로피 재측정 필수** — "통째 암호화(7.9x)"로 단정 금지. 256KB→그 이하 윈도우로
   엔트로피 맵 그리면 **혼합 컨테이너**가 드러난다: `[스텁][헤더사본][암호섹션][평문 매니페스트
   (engine_version/policys/classes 맵)][OTL]`. 평문 매니페스트만으로 클래스 인벤토리 전량 확보.
   (OK캐시백에서 "7.96 통째암호화"는 오측정이었고 실제 7.10 혼합 — 재측정 1회로 뒤집힘.)

### Phase 1 — 정적 크랙 (먼저 시도. 여기서 끝나는 경우가 많다)
1. **라이브러리 구조화**: Ghidra로 디컴파일 일괄 생성 (`tools/decomp_all.py`).
2. **문자열 볼트 크랙**: 볼트 복호 순수함수를 unicorn 단독 에뮬 → ABI `(s1,s2,s3,buf,len,key)`,
   상수 **s1=s2=0x86817231, s3=0x11300316**(빌드 불변). 함수 **주소는 빌드별로 다름**
   (OK캐시백 `0x1eca0`, PASS `0x5c78`) → 아래 **[Cross-build 주소 재특정]**으로 먼저 특정.
   호출부 직전 레지스터에서 인자 재구성해 전량 복호 (`tools/decrypt_libdxbase.py <so> <addr>`).
3. **페이로드 에셋 해부**: 스텁 dex → 헤더 사본(file_size 힌트) → 섹션 길이/본문 →
   평문 매니페스트(engine_version/policys/classes 맵) → OTL.
4. **섹션 LCG 암호**: `s = s*0x343FD + 0x269EC3` (MSVC rand), 키바이트 = `s>>16`.
   - S1은 CD 엔트리 누적(`acc ^= crc32 ^ usize`)에서 유도, 섹션 시드는 로직 복원 or
     known-plaintext 브루트포스(zip `PK\x03\x04`/dex 매직 오라클, `tools/jarsolve.c`류).
   - **오라클-우선 권장(S1 불필요, 앱 간 이식성 높음)**: 섹션0(설정)은 **패키지명**을 known-plaintext로
     (`com.<pkg>` 오라클 @0x234, 앞 16B는 raw 키블록), 섹션1(jar)은 **`PK\x03\x04`** 오라클로 시드
     직접 재발견. 섹션1 오프셋이 애매하면 소범위 오프셋 스캔 + zip-EOCD 검증으로 확정(PASS 실측:
     `S1 길이체인 모델이 안 맞아도 오라클로 우회` → 시드 0x977225 재발견, md5 일치).
   - 결과는 **기기/기존 산출물과 크기·바이트(md5) 대조**로 검증 (OK캐시백 L1=163,098, PASS md5 일치).
5. 이 단계에서 막히면(런타임 상태 의존) Phase 2로.

### Phase 2 — unidbg 전체 파이프라인 에뮬레이션
하니스 뼈대: `tools/unidbg_DxShieldTest.java` (그대로 복사해 타깃 경로만 교체).
핵심 구성: AndroidEmulator(64bit) + DVM + IO 리졸버(**반드시 SimpleFileIO** —
ByteArrayFileIO는 readlinkat에서 AbstractMethodError로 로더가 도중 사망) +
JNI_OnLoad → 등록 네이티브 관찰(RegisterNatives 주소 기록) → 21인자 `d()` 호출.

**환경 완성 체크리스트** — 에뮬레이션이 자기종료/정지하면 아래 순서로 소거:
1. 종료/스핀 지점 특정: 전역 코드 훅(pc 링 버퍼 3000개, 주기적 파일 덤프) +
   게이트 분기마다 케이스 훅. jstack/sample은 호스트 블로킹 구분용.
2. `__system_property_get`: `SystemPropertyHook` + `SystemPropertyProvider`로
   필요 프로퍼티 공급(삼성 Knox 검사: `ro.build.version.sdk`≠0, `ro.build.selinux`==1).
   볼트 복호기로 검사 대상 프로퍼티명을 먼저 알아낸다.
3. 워커 스레드 폴링: unidbg는 스레드를 실행 못 하므로 pthread_create 직후
   결과 구조체에 "정상 기기 결과"(status=0, count≥1)를 주입.
4. pthread 계열 데드락(bionic futex 재시도 스핀): `pthread_create@plt`를
   `mov w0,#0; ret`로 패치, dlsym'd 뮤텍스 fn-ptr도 같은 스텁으로 리다이렉트 —
   **JNI_OnLoad 이후에** (dlsym이 덮어쓴다).
5. VFS 완성: 로더가 검증하는 실제 경로 채우기 — `/data/app/…/lib/arm64`에
   실제 .so들(644 권한!), files/ 디렉터리. 실행 간 상태 오염 주의(rootfs 마커 파일 삭제).
6. 디버그 출력: mvn `-Dmaven.test.skip=false -Dtest=…` (루트 pom이 skip=true 기본값).

성공 판정: `d()`가 13필드 CSV 반환 (Application/Entrypoint 클래스, jar 경로/파일명,
**세션 잠금 키[6번 필드 hex]**, 에셋명, 엔진 버전, policys, 브릿지 클래스). 오류 시
"-N" 코드 문자열 → 로더 반환값 `-N-100` 프로토콜로 원인 역추적.

### Phase 3 — 잠금 해제 채널 + 볼트 전수 복호화
1. `o(i^key, j)` / `p(i^key, j[i2<4])` / `q(ctx, id, str)` 을 DvmClass로 직접 호출
   (key=6번 필드). q는 커맨드 채널 — 응답하는 id 목록이 Java 호출부와 일치하는지 확인.
2. p() 디컴필에서 **볼트 테이블 포인터 전역**을 찾아 덤프 (d() 성공 후 활성).
   벌크 암호 영역 = 이 테이블일 가능성이 높다(로더는 복호 없이 적재만 함).
3. 테이블 전체를 파일로 덤프(청크 mem_read) → `tools/vault_table_bruteforce.py`로
   모든 오프셋에서 (u16 길이, 본문) 복호. **길이와 본문의 시드 순서가 서로 다를 수
   있음**(본문은 역순 — p() 디컴필의 두 FUN 호출 인자 순서를 확인할 것).
   필터는 ASCII가 아니라 UTF-8 유효성 기준(한글 등 멀티바이트 보존).
4. 산출물: 고유 문자열 사전(엔드포인트/헤더/행위 지표) → 평가 보고서 소재.

## Cross-build 주소 재특정 (핵심 — OK Cashbag ↔ PASS by SKT 검증)

xShield는 앱/버전마다 **다른 `libdxbase` 빌드** → 주소는 전부 다르다. 단 **알고리즘·상수·ABI는 안정**:
- 문자열 복호기 ABI `fcn(s1,s2,s3, buf, len, key)`, 상수 **s1=s2=0x86817231 / s3=0x11300316**,
  MBA 매직 **0x914dbacf** — **`mov #0x914d; movk #0xbacf,lsl#16` 즉치로 생성**(데이터 상수 아님).
  **파일 바이트 `grep 0x914dbacf`는 0 나온다 → 반드시 디스어셈에서 확인.** (이걸로 "다른 cipher"라 2회 오판함.)
- 페이로드 섹션 = MSVC-LCG `s*0x343FD+0x269EC3`, 키=`s>>16` (앱 불변).

**새 빌드에서 문자열 복호기 자동 특정 + 볼트 덤프**: **`scripts/find_decryptor.py <libdxbase.so>`** — 아래
1~3을 자동 수행(검증: PASS→0x5c78, OK캐시백→0x1eca0을 하드코딩 0으로 각각 탐지). 원리:
1. **seed 상수 0x86817231을 인자로 세팅하는 `bl` 사이트들** 집계 → 최다 타깃 = 복호기(콜트리 불필요).
   (보강: `.init_array`는 정적 0x0 → RELA addend에서 실제 ctor; strcpy는 seed 안 넘겨 자동 배제됨.)
2. 세그먼트 매핑 → 복호기 첫 `bl`(=memset@plt) **스텁**(코드훅 PC=LR).
3. 모든 `bl dec` 사이트에서 (buf=adrp+add, len=w4, key=w5) 역산 → `x0..x5=(s1,s2,s3,buf,len,key)` →
   `emu_start(dec,RET)` → buf 평문. **한계**: buf/len/key를 동적으로 받는 사이트는 정적 역산 불가 →
   정적으론 RASP 정적-버퍼 세트만(수십 개). 앱 문자열 볼트 전량은 Phase 2/3(unidbg d() 후 테이블 덤프).

**정적 복호기 특정이 어려우면 "정적=에뮬 포함"으로 우회 후 되먹임**: unidbg로 `.so` JNI_OnLoad 완주 →
libdxbase 메모리 스캔으로 자기복호된 문자열 덤프 → (평문 vaddr) ↔ 정적 `.so`(암호문 vaddr) known-plaintext
쌍으로 복호기 위치/ABI 검증. (PASS: 에뮬로 798개 먼저 회수 → 그걸로 0x5c78 특정 → 정적 40개 복호.)

**Portable vs per-build (2앱 검증):**
| 레이어 | 이식성 |
|---|---|
| packer-detect(stage0)·페이로드 LCG/오라클 복호·SDK triage·CPG source→sink | **직접 이식**(다른 앱·다른 시드도 byte-match) |
| 네이티브 문자열 복호기(Unicorn)·unidbg 로더/게이트 오프셋 | **주소만 per-build 재특정**(알고리즘·ABI 동일) |

## 자주 하는 실못 (실측 교훈)

- **"다른 cipher다 / 이식 안 된다" 성급한 단정 금지 (최다 실수)** — PASS에서 NEON tbl 없음·매직 바이트 0으로
  "다른 알고리즘"이라 2회 오판했으나 실제는 **동일 MBA 복호기(주소만 다름, 매직은 즉치)**. 차이/네거티브
  판정 전에 **불변 상수(0x86817231/0x11300316/0x914dbacf-immediate)로 재확인**. "불가/다름"은 결론이
  아니라 반증할 가설.
- **툴 마찰은 벽이 아님(즉시 우회)**: `lief`는 **실행 인터프리터에** 설치(`python3 -m pip install
  --break-system-packages lief`) · JDK17 `Module` 모호성 → **FQN**(`com.github.unidbg.Module`) ·
  unidbg write-hook은 상당수 write 누락 → **code-hook 또는 `.init_array` 정적분석** · Unicorn
  `UC_ERR_EXCEPTION` → **PLT(memset) 스텁**.
- "런타임 생성 코드" 가설 → 실제로는 다른 모듈(libc) 주소를 lib 기준 오프셋으로 착각.
  모듈 base 목록을 먼저 출력해 좌표계를 확정할 것.
- 폴링 루프 = q() 대기로 오판 → 실제론 `usleep` 폴링. dlsym fn-ptr 전역은 반드시
  실체 확인(dlsym 인자 문자열을 볼트 복호기로 복호).
- 커버리지 계측 사각으로 "더미 데이터" 오판 → 철회 사례 1회. 네거티브 판정은
  2개 이상 독립 근거 없으면 보류.
- 정적 분석의 "스텁 dex"와 APK 루트 dex를 혼동하지 말 것 (Phase 0-3이 방지책).
- 상태 전역(시드/플래그)은 d() 성공 후에만 채워진다 — 실패 경로에서 덤프해 판단 금지.

## 산출물 규약

`analysis/decrypted/` 밑에: 복호화 산출물·실행 로그(핵심 지표 요약본)·덤프 바이너리.
리버싱 문서는 `analysis/*.md`에 결정론적 사실+근거+재현 명령으로 기록. 네거티브
판정·정정 이력은 삭제하지 말고 부록으로 남긴다.
