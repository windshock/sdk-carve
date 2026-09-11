# NSHC xShield/DxShield — fleet survey (KR apps, 2026-09)

Applied the `xshield-reversal` + `sdk-carve` skills to a set of KR Android apps to (a) confirm xShield,
(b) recover the mgmt-server + supply-chain inventory, (c) auto-locate the native string decryptor.
Pipeline per app: `packer-detect` (stage 0) → `payload_triage.py` (plaintext manifest, no decrypt) →
`payload_decrypt.py` (section0 config **server** + app-dex SDK inventory) → `find_decryptor.py` (arm64)
→ (deep) `sdk-carve` CPG source→sink.

Method notes: engine/policys/class-map come from the payload asset's PLAINTEXT manifest (no crypto). The
mgmt **server** is in the encrypted section0 config, recovered by `payload_decrypt.py` via a package-name
known-plaintext oracle (2^24-bounded LCG-seed brute). **Key structural fact: under this xShield variant
the app's REAL classes*.dex stay PLAINTEXT in the base apk** — only a small loader component + the config
are encrypted in the payload asset. So the bundled-SDK inventory is read directly from the base apk dexes
(no decryption). The native string decryptor address differs per build; `find_decryptor.py` auto-locates
it via the stable seed constant 0x86817231. Samples/decrypted artifacts kept local per app dir, never committed.

## Confirmed xShield (14 apps) + 1 negative

Server + inventory columns below are from `payload_decrypt.py` (mgmt server = recovered section0 config;
SDK inventory = plaintext base-apk dex scan). `×N` = string-ref count (proxy for how embedded the SDK is).

| App | package | engine | packing | mgmt server | Coocon/Rhino | other notable SDKs | decryptor |
|---|---|---|---|---|---|---|---|
| OK Cashbag | com.skmc.okcashbag.home_google | 6.9.13.22 | — | fxshield.co.kr | — | Fairytech/adjoe/Adison/IronSource/Unity (adtech) | 0x1eca0 |
| PASS by SKT | com.sktelecom.tauth | 6.9.x | — | fxshield.co.kr | — | net.nshc.droidx3 (AV/root scan) | 0x5c78 |
| Mirae M-STOCK | com.miraeasset.trade | 6.9.19.30 | windows | **dxshield.com** | **Coocon×997 / Rhino×817** | AhnLab AV, SignKorea+Yettiesoft+Raon PKI, AdBrix, IGAWorks, drfn/chart, Sentry | (v7a) |
| IBK i-ONE 기업 | com.ibk.scbs | 6.3.8.97 | linux | **dxshield.com** | **Coocon×1384 / Rhino×707** | **AhnLab AV×463**, Raon+SignKorea+INITECH PKI, everspin, Kakao, ZXing | 0x5dfc |
| 신한 SOL저축은행 | com.shinhan.spbs | 6.9.11.19 | windows | fxshield.co.kr | **Coocon×1081 / Rhino×698** | **AhnLab AV×594**, WIZVERA+SpongyCastle PKI, AppsFlyer, unboundid LDAP | (v7a) |
| 현대해상 Hi | m.hi.co.kr | 6.9.13.22 | linux | fxshield.co.kr | **Coocon×1074 / Rhino×767** | WIZVERA×3868 PKI, Raon, AhnLab AV, SignKorea, INITECH | (v7a) |
| Kia | com.kia.oneapp.kr | 6.9.20.31 | linux | fxshield.co.kr | — | HMG platform, **Mapbox×9103, Datadog, Sentry, Airbridge, Salesforce MC** | (v7a) |
| MyHyundai | com.hyundai.oneapp.kr | 6.9.20.31 | linux | fxshield.co.kr | — | HMG platform (byte-≈ Kia): Mapbox/Datadog/Airbridge/Salesforce | 0x24124 |
| 빗썸 Bithumb | com.btckorea.bithumb | 6.9.2.8 | windows | fxshield.co.kr | — | Raon×1199, AppsFlyer, AhnLab AV, Braze, SciChart, IronSource | 0x1eadc |
| L.POINT 모아락 | com.lpoint.moalock | 6.9.4.11 | windows | fxshield.co.kr | — | **Buzzvil + Avatye + IGAWorks (lockscreen ads)**, Unity | 0x1eab0 |
| 현대캐피탈 | com.hyundai.capital | 6.9.2.8 | windows | fxshield.co.kr | — | Raon×1248, AppsFlyer, NSHC nFilter, SignKorea, INITECH, secuchart | (v7a) |
| 우리WON카 | com.woorifcapital.m.woncar | (native) | — | fxshield.co.kr | — | DreamSecurity PKI, AdBrix, IGAWorks, adjust, NSHC nFilter, KFTC | 0xd868 |
| SK증권 주파수3 | com.sks.android.neojoopasoo | 6.5.1.2 | windows | (old framing†) | Coocon×10 (stub) | DreamSecurity+Yettiesoft+SignKorea PKI, mVigs chart engine | (v7a) |
| NIGHT CROWS | com.wemade.nightcrowsglobal | 6.3.1.85 | windows | (old framing†) | — | Wemade WMSDK, Unreal, Facebook, Kakao, adjust, IronSource (game) | (v7a) |
| **부국증권 BEST-M** | com.bookook.mtsplus | — | — | — | — | **NOT xShield** (no known packer, no libdxbase) | — |

† SK증권 (6.5.1.2) and NIGHT CROWS (6.3.1.85) are the two oldest engines; their section0 keyblock/offset
framing differs so `payload_decrypt` didn't recover the server (xShield still confirmed by packer-detect +
inventory). Engine versions span **6.3.1.85 → 6.9.20.31**; `find_decryptor.py` auto-located the decryptor at
a DIFFERENT address in every arm64 build (0x1eca0/0x5c78/0x1eadc/0x1eab0/0x5dfc/0x24124/0xd868), zero hardcoding.

## Cross-app patterns
- **Coocon SASAPI server-driven JS scraping — CHANNEL confirmed in 4 financial apps** (M-STOCK, IBK, 신한,
  현대해상). Not just the package: all four carry a byte-identical `sasapi/scriptengine/{ScriptEngine,
  V8ScriptEngine}` + `sasapi/script/ScriptManager` + network-fetch exceptions — the `updateScript`→
  `loadScript`→JS `eval` channel, runnable on **Rhino or V8**. RCE-by-design class (cf. GAD BeanShell).
  SK증권 has only a 10-ref Coocon stub. See [`COOCON_SASAPI_TRIAGE.md`](COOCON_SASAPI_TRIAGE.md). Fleet's
  most significant shared surface.
- **On-device AV** — AhnLab V3 (`com.ahnlab.enginesdk`) in the 4 Coocon apps + Bithumb; NSHC DroidX3 in PASS.
- **PKI diversity** — WIZVERA+SpongyCastle (신한, 현대해상), SignKorea+Yettiesoft (M-STOCK, SK증권),
  DreamSecurity (우리, SK증권), RaonSecure (most), INITECH (IBK, 현대캐피탈), NSHC nFilter keypad (우리, 현대캐피탈).
- **adtech-heavy** — L.POINT (Buzzvil/Avatye/IGAWorks lockscreen), 우리WON카 (AdBrix/IGAWorks/adjust),
  Bithumb (Braze/AppsFlyer/IronSource), OK Cashbag (Fairytech/adjoe/Adison).
- **Shared platform** — Kia and MyHyundai carry a byte-≈ identical `com.hmg.*` HMG codebase (Mapbox/Datadog/
  Airbridge/Salesforce), no Coocon/Rhino — automotive telemetry, not financial scraping.
- **Two mgmt servers (CORRECTED)** — `-c{server}`: **`xo.dxshield.com` = the Coocon-heavy brokers
  (Mirae, IBK)**; **`xo.fxshield.co.kr` = everyone else** (신한, HMG apps, Bithumb, L.POINT, 현대캐피탈/해상,
  우리, SKP apps). fxshield.co.kr is the shared default — *not* SKP-exclusive as first thought.
- **xShield ≠ full packer here** — the app's real dexes are plaintext; only a loader + config are encrypted.
  RASP value is runtime anti-debug/root/hook + the string vault, not code confidentiality.
- **Verified the customer-list claims** — 현대캐피탈/현대해상/우리WON카 are APK-confirmed xShield; only 부국증권 negative.

## Provenance
Downloaded via apkeep/APKPure into per-app dirs under `~/Downloads/`. KR financial apps are often
armeabi-v7a-only (find_decryptor is arm64 — v7a builds need a 32-bit port, noted). Confirmations are
`packer-detect` + plaintext-manifest engine strings; server via `payload_decrypt.py` section0 oracle;
inventory via base-apk dex scan (byte-level string counts); deep results are byte/CPG-verified where decrypted.
