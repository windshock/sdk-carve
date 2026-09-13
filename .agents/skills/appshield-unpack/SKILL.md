---
name: appshield-unpack
description: Statically unpack APKSHIELD-protected Android apps (ahope / Penta Security ISSAC; loader com.goggles + libahope_*/libIWAndroid/libwbaes, white-box AES over assets/asorg+assets/tables) without a device or Frida. Key insight — the white-box only protects KEY DERIVATION, not bulk crypto: extract the AES keys via unidbg (callMethod("K",n)), then decrypt assets/asorg OFFLINE with standard AES-128-CBC to recover the real DEXes. Use when packer-detect flags APKSHIELD / a com.goggles stub loader / assets/asorg+tables, or when a KR finance app shows a stub classes.dex + libahope_*.so and you need the real code (e.g. to fingerprint a bundled SDK).
---
# APKSHIELD static unpack — white-box-AES packer, no device / no Frida

**Proven (2026-09-13):** KB Pay `com.kbcard.cxh.appcard` — full static unpack of a 60 MB white-box-AES payload
→ 14 real dexes (149 MB, 143,339 class-descriptors), then fingerprinted (0 iSAS markers → NEGATIVE). Sibling of
[[xshield-reversal]] (same static+unidbg philosophy; different packer). packer-detect (sdk-carve) IDs it.

## Fingerprint (is it APKSHIELD?)
- **Loader (plaintext stub dex):** `com.goggles.*` (`ApkApp` = Application, `MultiDexExtractor`, `Native`,
  `NativeCaller`, `ZipUtil`), `com.apk_shield.{skdb,ServiceAhope}`, `com.ahope.app_shields.PureAppClient`.
- **Natives:** `libahope_n.so` (apkshield_native.c, RegisterNatives), `libahope_o.so` (apkshield_obfuscation.c,
  `Java_com_goggles_Native_callMethod__Ljava_lang_String_2I`), `libwbaes.so` (WBAES.c/dec_wbaes.c,
  `decWbAesInit/Update/DoFinal`, `BcCreateAndInitWhiteBox`, `AES_TB_TYPE1/2/3`), `libIWAndroid.so` (Penta
  Security ISSAC: `IW_Decrypt`, `BCIPHER_Decrypt`, `com.penta.issacweb`).
- **Payload:** `assets/asorg` (AES-block-aligned ciphertext) + `assets/tables` (white-box key tables).
- **Self-string:** `APKSHIELD_USE_CLASS_LOADER_LIB`. Stub `classes.dex` is tiny (~100–130 KB); real code is in `asorg`.

## Why it's tractable (the crux)
The stub `Native.b()` sets up **standard** `Cipher.getInstance("AES/CBC/PKCS5Padding")` with a **hardcoded IV**
(`new IvParameterSpec(Native.d("<32 hex>"))`) and a key = `Native.d(callMethod("K", n))`. The white-box
(`libwbaes` + `tables`) only guards the **key derivation** call `callMethod("K", n)` — the bulk `asorg`
decryption is ordinary AES-128-CBC. So you never emulate WBAES over the whole 60 MB: **extract the keys, then
decrypt offline.** (`callMethod("W", bytes)` is just the same standard AES exposed as a byte[] API.)

## Recipe
### Phase 0 — identify + stage (static)
```
packer-detect.py <apk|xapk>            # -> APKSHIELD, carve BLIND
# get the base apk (xapk: inner non-config apk). Extract:
unzip base.apk 'classes*.dex'          # stub loader -> dex2jar + CFR/jadx to READ com.goggles.ApkApp/Native
unzip base.apk assets/asorg assets/tables
unzip config.<abi>.apk 'lib/<abi>/lib{IWAndroid,ahope_n,ahope_o,ahope,wbaes}.so'   # natives live in the abi split
# read Native.b() for the hardcoded IV (hex) and which key index / cipher mode asorg uses.
```
### Phase 1 — extract keys (unidbg; small, fast)
`scripts/AppShieldKeyExtract.java` — loads the 4 libs, runs `Native.callMethodV("I")` +
`Native.callMethodW("WI", assets/tables)` (white-box init), then calls `callMethod("K", idx)` for idx 0..N via
**direct symbol** (`Java_com_goggles_Native_callMethod__Ljava_lang_String_2I`; unidbg's overload resolver fails,
so resolve `Module.findSymbolByName` and `sym.call(env, jclass, jstring, jint)`). Prints the hex keys.
```
mvn -q dependency:build-classpath -Dmdep.outputFile=/tmp/ucp.txt      # in /tmp/unidbg/unidbg-android (once)
UJAR=.../unidbg-android-*.jar; CORE=.../unidbg-api-*.jar; CP="$UJAR:$CORE:$(cat /tmp/ucp.txt)"
javac -cp "$CP" -d out scripts/AppShieldKeyExtract.java
java -cp "out:$CP" -Dappdir=<workdir> AppShieldKeyExtract      # workdir has base.apk, native/*.so, tables
```
Gotchas: `callMethodV`/`callMethodW` resolve fine via `DvmClass.callStaticJniMethod`; the OVERLOADED
`callMethod(...)` variants do NOT (use direct symbol). Feed the FULL `tables` file (all AES_TB_TYPE tables
concatenated). Provide `base.apk` to `createDalvikVM` (the loader touches assets/resources).
### Phase 2 — decrypt offline + fingerprint
`scripts/appshield_unpack.py <appdir>` — brute the extracted keys × {CBC(hardcoded IV), CBC(0), ECB} on
`asorg`; the one that yields `PK\x03\x04` is the payload key/mode; decrypt the whole file, strip PKCS7, unzip →
real `classes*.dex`. Then run sdk-carve `coocon-fingerprint.sh` / `class-map.py` on the recovered dexes.

## Discipline
- **No device, no Frida** — pure static + unidbg emulation of the key-derivation only.
- Keep it honest: a recovered-dex "0 markers" is a real NEGATIVE only after ALL secondary dexes are unzipped and
  the dex is the real app (sanity-check: app package refs present, class-descriptor count in the tens of thousands).
- **Never commit** samples, recovered dexes, the unidbg harness output, or the per-build AES keys — those stay
  local (`~/Downloads/AppShield/<app>/`). Commit only methodology + the generalized scripts.
- If a future APKSHIELD build white-box-encrypts the BULK (not just the key), fall back to unidbg-emulating
  `decWbAesInit_/Update/DoFinal` directly over `asorg` (slower; xShield Phase-2 style) — not needed on samples seen.
