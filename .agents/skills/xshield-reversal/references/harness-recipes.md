# unidbg 하니스 레시피 — 환경 완성 주입 카탈로그

> xShield 6.9.13.22 (libdxbase.so arm64) 실측 레시피. **어드레스는 빌드별로 다르다** —
> 값 자체보다 "어떻게 찾는지" 절차를 따를 것. 전체 실동작 하니스:
> `tools/unidbg_DxShieldTest.java`.

## 0. 하니스 뼈대

```java
AndroidEmulator emulator = AndroidEmulatorBuilder.for64Bit()
        .setProcessName("<pkg>").build();
Memory memory = emulator.getMemory();
memory.setLibraryResolver(new AndroidResolver(23));

// IO 리졸버 — 반드시 SimpleFileIO (ByteArrayFileIO는 readlinkat에서
// AbstractMethodError -> 로더 도중 사망 -> d() null 반환)
emulator.getSyscallHandler().addIOResolver((emu, path, oflags) -> {
    if (path.contains("base.apk")) {
        return FileResult.<AndroidFileIO>success(
            new SimpleFileIO(oflags, new File(APK), path));
    }
    return null;
});

VM vm = emulator.createDalvikVM(new File(APK));
DalvikModule dm = vm.loadLibrary(new File(SO), false);
dm.callJNI_OnLoad(emulator);           // RegisterNatives 주소가 stdout에 기록됨
```

실행: `cd /tmp/unidbg && ./mvnw -q -pl unidbg-android test -Dtest=DxShieldTest \
  -DskipTests=false -Dmaven.test.skip=false -DfailIfNoTests=false`
(루트 pom `maven.test.skip=true` 기본값 — 플래그 빠지면 조용히 스킵된다.)

## 1. 관측 인프라 (먼저 깔 것)

전역 코드 훅 하나로 pc 링 버퍼 + 게이트 케이스 스위치 + 와치독:

```java
final Deque<Long> pcRing = new ArrayDeque<>();
final long[] watchdog = {0};
emulator.getBackend().hook_add_new(new CodeHook() {
    public void hook(Backend backend, long address, int size, Object user) {
        long off = address - base;
        if (pcRing.size() > 3000) pcRing.poll();
        pcRing.add(off);
        switch ((int) off) {
            case 0x21a84: /* 게이트 분기 — x0/전역 덤프 */ break;
            // ... 관심 분기마다 case 추가
        }
        if ((++watchdog[0] & 0xFFFF) == 0) { /* pc tail -> 파일 덤프 (정지 후 검시용) */ }
    }
    public void onAttach(UnHook u) {} public void detach() {}
}, base + 0x10000, base + 0x70000, null);
```

- 정지가 libdxbase 밖(libc 스핀)이면 범위를 `1L, 0xfffffffffffffffL`로 넓혀 재실행.
- **모듈 좌표계 먼저 확인**: `memory.getLoadedModules()`로 base/size 출력 —
  "lib 기준 오프셋 0x22xxxx"가 사실은 libc+0x68xxx였던 사례가 있었다.
- 에뮬레이션이 CPU를 쓰는데 pc 훅이 안 찍히면 libc 내부 루프(futex 스핀) 의심.

## 2. 자기종료 게이트 해부 절차 (이 사례: 0x21a10 게이트)

1. termination 헬퍼를 objdump로 역추적 (`bl kill@plt` / `blr` 우회 호출 주의 —
   kill/exit은 dlsym fn-ptr로도 불린다: `[0x73628]`, `[0x73620]`).
2. 헬퍼가 검사하는 조건을 디스어셈에서 나열 → 각 조건의 전역/인자 식별.
3. 하니스에 조건별 덤프 케이스 추가 → 실행 → **어떤 조건이 실패했는지 1개로 수렴**.
4. 이 사례의 조건: `[x24]`(nativeLibraryDir)에 ':' 포함 또는 int인자∈[90000,100000)
   또는 SDK 전역<17 → 통과. 아니면 `FUN_26128(0)∈{0,9}` + 타이밍 플래그 0 + bit29=0.
5. 실패 시 odex 마커 기록 후 termination(-2/-3): 볼트 시드로 3글자 복호("x86")와
   아치 전역 비교 — **"dex"가 아니라 에뮬레이터 감지용 아치 문자열이었다.**

## 3. FUN_26128 환경 프로브 (ret 0/9=통과, 3=워커 타임아웃, 10=삼성 실패)

- **프로퍼티 공급** (삼성 기기 재현):

```java
SystemPropertyHook hook = new SystemPropertyHook(emulator);
hook.setPropertyProvider(new SystemPropertyProvider() {
    public String getProperty(String key) {
        if ("ro.build.version.sdk".equals(key)) return "33";
        if ("ro.build.selinux".equals(key)) return "1";
        return null;   // null -> 실제 dlsym 경로
    }
});
memory.addHookListener(hook);   // loadLibrary 전에
```

  검사 대상 프로퍼티명은 볼트 복호기로 먼저 알아낸다 (`decrypt_libdxbase.py`에
  VA/길이/키를 넘기면 됨: 이 사례 `ro.build.version.sdk`(0x70198,0x14,0x21b8),
  `ro.build.selinux`(0x701ad,0x10,0x21cd)).

- **워커 스레드 결과 주입**: unidbg는 pthread_create 후 스레드를 실행 못 한다 →
  64×usleep(1ms) 폴링이 타임아웃. pthread_create **직후 명령어**에 케이스 훅을 달고
  스택상 결과 구조체에 정상 기기 값을 쓴다 (이 사례: `[sp+0x3028]=0 status, [sp+0x302c]=1 count`).
  - 구조체 위치 찾기: `pthread_create` 호출 직전 `str xzr,[sp,#N]` (0 초기화)과
    폴링 루프의 `ldr w8,[sp,#N+4]; cmp #0` 를 objdump에서 대조.

## 4. pthread 데드락 제거 (MAIN PATH 이후 무한 스핀)

증상: CPU 100%, pc 훅 라이브러리 범위 밖, sampler로 보면 libc `uc_emu_start` 점유.
원인: bionic `pthread_mutex_lock`의 futex 재시도 루프 (unidbg futex 한계).

```java
// pthread_create@plt (0x627a0) -> "mov w0,#0; ret"
emulator.getBackend().mem_write(base + 0x627a0,
    new byte[]{(byte)0xe0,0x03,0x1f,0x2a,(byte)0xc0,0x03,0x5f,(byte)0xd6});

// !!! JNI_OnLoad "이후에" — dlsym 스톰이 fn-ptr 전역을 덮어쓴다 (실측으로 확인한 순서)
long noRet = base + 0x627a0;
byte[] ptr = /* noRet를 LE 8바이트로 */;
emulator.getBackend().mem_write(base + 0x735e8, ptr);  // pthread_mutex_lock
emulator.getBackend().mem_write(base + 0x73618, ptr);  // pthread_mutex_unlock
```

dlsym 타깃 이름 확인법: 디컴필에서 `DAT_x = dlsym(uVar7,&DAT_y)` 직전 볼트 복호
호출(FUN_1eca0)의 (VA,len,key)를 복호기에 넣는다 → "pthread_mutex_lock" 등.

## 5. VFS 완성

```bash
R=/tmp/unidbg/unidbg-android/target/rootfs/default
mkdir -p "$R/data/app/~~XXXX/<pkg>-YYYY/lib/arm64"
cp native/arm64-v8a/*.so "$R/data/app/…/lib/arm64/"
chmod 644 "$R/data/app/…/lib/arm64/"*.so      # 444면 SimpleFileIO rw-open이 Permission denied
rm -rf "$R/data/user/0/<pkg>"                  # 실행 간 마커/odex 상태 오염 제거 (매 실행)
```

## 6. d() 21인자 호출 + 결과

```java
DvmClass da = vm.resolveClass("com/xshield/da");
StringObject ret = da.callStaticJniMethodObject(emulator,
    "d(Ljava/lang/String;×11…IIIIIIII)Ljava/lang/String;",
    pkg, filesDir, sourceDir, dataDir, nativeLibDir,
    "arm64-v8a:armeabi-v7a:armeabi",       // ← ABIs는 ':' join (게이트의 ':' 검사 대상일 수 있음)
    Build.MANUFACTURER, Build.MODEL, Build.FINGERPRINT,   // FINGERPRINT에 ':' 포함
    "1.8.0_332", versionName,
    versionCode, targetSdk, sdkInt, timeCounter, launchCount, appFlags, uid, 4400);
```

- 성공: 13필드 CSV. **fields[6] = 세션 잠금 키(매 실행 변함)**.
- 실패: "-N" 코드 → FUN_29d70 반환값 = 섹션결과-100 프로토콜. 로더 진입(0x29d70류)
  에 엔트리 훅을 달아 param_2/호출 횟수부터 확인.

## 7. 잠금 해제 채널 (d() 성공 직후, 같은 emulator 인스턴스)

```java
int key = Integer.parseInt(fields[6].trim(), 16);          // _p/_o 의 XOR 키
// p: i2<4면 i^key 후 호출. 반환은 StringObject (callStaticJniMethodObject 사용 —
//    callStaticJniMethodString은 이 버전에 없다)
StringObject so = da.callStaticJniMethodObject(emulator, "p(II)Ljava/lang/String;", a1, i2);
// o: callStaticJniMethodInt(emulator, "o(II)I", i^key, j)
// q: 컨텍스트는 vm.resolveClass("android/content/Context").newObject(null)
```

- p() 디컴필에서 볼트 테이블 포인터/카테고리 키/시드 전역을 확인하고
  `[SEEDS]` 덤프에 추가 (d() 성공 후 0이 아니면 볼트 활성).

## 8. 볼트 테이블 덤프 + 전수 복호화

```java
long tbl = rd64(backend, base + 0x71f80);        // 테이블 포인터 전역
for (long got = 0; got < 1_500_000; got += 65536) {
    try { fos.write(backend.mem_read(tbl + got, 65536)); }
    catch (Throwable t2) { break; }               // 매핑 끝
}
```

오프라인: `tools/vault_table_bruteforce.py` — 모든 바이트 오프셋에서
`(u16 길이, 본문)` 복호. 주의:
- **길이 복호와 본문 복호의 시드 순서가 다를 수 있다** (p() 디컴필의 FUN_1eca0 두 호출
  인자 순서 비교 — 이 사례는 본문이 역순). 틀리면 전부 노이즈만 나온다.
- 필터는 UTF-8 유효성 기준(ASCII 90%면 한글이 탈락한다).
- 산출은 겹침 히트 TSV → 접미사/토큰 기준 클린 dedup → 엔드포인트/헤더/행위 지표 추출.

## 9. 검증 규약 (결과 신뢰성)

- 에뮬레이션 산출물은 정적 분석 결과(또는 기기 아티팩트)와 **MD5/바이트 대조**로 교차 검증.
- 정적만으로 얻은 결론은 "에뮬레이션 재현 성공"을, 에뮬레이션 결론은 "정적 근거"를
  서로 대조 — 한쪽만의 결론을 최종판으로 쓰지 않는다.
- 네거티브 판정("더미", "안 쓰임")은 커버리지 사각/좌표 혼동 사례가 있었으므로
  2개 이상 독립 근거 없이는 확정하지 않는다.

## 10. Phase-3 재현 레시피 (unidbg 풀 볼트 덤프 + static 대조)

**클래스패스(.m2, JDK17)** — 별도 unidbg 체크아웃 없이 로컬 maven 저장소 jar만으로 컴파일/실행:
```bash
CP=$(find ~/.m2/repository \( -path '*com/github/zhkl0228/*' -o -path '*net/java/dev/jna/*' \
     -o -path '*junit/*' -o -path '*org/slf4j/*' -o -path '*log4j*' -o -path '*dongliu/apk-parser*' \
     -o -path '*org/apache/commons*' \) -name '*.jar' ! -name '*sources*' ! -name '*javadoc*' | tr '\n' ':')
javac -cp "$CP" -d out scripts/unidbg_DxShieldTest.java   # 패키지 com.github.unidbg.android
java  -cp "$CP:out" com.github.unidbg.android.DxShieldTest
```
검증: zhkl0228 unidbg **0.9.10-SNAPSHOT** 로 클린 컴파일(2026-09-11). 하네스 SO 경로만 대상 빌드로 교체.

**static(find_decryptor) vs dynamic(unidbg d()/p()) — 완전성 대조:**
- `find_decryptor.py`(정적)는 콜사이트에서 인자가 정적 역산되는 항목만 → 빌드당 **개별 문자열 21~104개**
  (arm64; 안티분석 IOC 핵심은 회수). 동적 주소·런타임 앵커 항목은 누락.
- unidbg **Phase 3**는 `d()`/`p()`를 볼트 테이블 전역에 에뮬 → **볼트 전량**(루팅/frida/xposed 경로,
  원격제어 앱 목록(teamviewer/anydesk/rsupport…), `[STAGE x/3] Hacking was successful` 등 전부).
- 규약(§9): 두 산출을 교차 대조 — static은 "동적 재현 성공"을, dynamic은 "정적 근거"를 서로 확인.
  본 사례 실측 아티팩트는 로컬 SKP 워크스페이스(`~/Downloads/xshield/analysis/xshield-vault-decrypted.txt`,
  샘플 파생물이라 미커밋). arm32(v7a) 풀 덤프는 정적 소스 앵커 한계로 이 Phase-3(동적) 경로가 정석.
