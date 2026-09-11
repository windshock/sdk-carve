# NSHC xShield/DxShield — fleet survey (KR apps, 2026-09)

Applied the `xshield-reversal` + `sdk-carve` skills to a set of KR Android apps to (a) confirm xShield,
(b) recover the supply-chain inventory without decryption, (c) auto-locate the native string decryptor.
Pipeline per app: `packer-detect` (stage 0) → `payload_triage.py` (plaintext manifest, no decrypt) →
`find_decryptor.py` (arm64) → (deep) `xshield-reversal` payload decrypt → `sdk-carve` CPG source→sink.

Method notes: engine/server/class-map come from the payload asset's PLAINTEXT manifest (no crypto needed).
The native string decryptor address differs per build; `find_decryptor.py` auto-locates it via the stable
seed constant 0x86817231 (see the skill). Samples/decrypted artifacts kept local per app dir, never committed.

## Confirmed xShield (14 apps) + 1 negative

| App | package | engine | packing | DxShield server | notable bundled SDKs | decryptor addr |
|---|---|---|---|---|---|---|
| OK Cashbag | com.skmc.okcashbag.home_google | 6.9.13.22 | — | xo.fxshield.co.kr | Fairytech/adjoe/Adison/IronSource/Unity | 0x1eca0 |
| PASS by SKT | com.sktelecom.tauth | 6.9.x | — | xo.fxshield.co.kr | net.nshc.droidx3 (AV/root scan) | 0x5c78 |
| Mirae Asset M-STOCK | com.miraeasset.trade | 6.9.19.30 | windows | **xo.dxshield.com** | **Coocon SASAPI (Rhino JS scraping)**, SignKorea+Yettiesoft PKI, AdBrix, IGAWorks, drfn/chart | (v7a) |
| Kia App | com.kia.oneapp.kr | 6.9.20.31 | linux | — | HMG(자체), Datadog, Sentry, Salesforce MC, Airbridge, Mapbox | (v7a) |
| MyHyundai | com.hyundai.oneapp.kr | 6.9.20.31 | linux | — | HMG platform (= Kia) | 0x24124 |
| 빗썸 Bithumb | com.btckorea.bithumb | 6.9.2.8 | windows | — | (universal apk: arm64+v7a) | 0x1eadc |
| L.POINT 모아락 | com.lpoint.moalock | 6.9.4.11 | windows | — | — | 0x1eab0 |
| IBK i-ONE 기업 | com.ibk.scbs | 6.3.8.97 | linux | — | **AhnLab V3 AV** | 0x5dfc |
| 현대캐피탈 | com.hyundai.capital | 6.9.2.8 | windows | — | — | (v7a) |
| 현대해상 | m.hi.co.kr | 6.9.13.22 | linux | — | **Rhino JS engine** | (v7a) |
| 우리WON카 | com.woorifcapital.m.woncar | (native) | — | — | — | 0xd868 |
| 신한 SOL저축은행 | com.shinhan.spbs | 6.9.11.19 | windows | — | **AhnLab V3 AV**, WIZVERA PKI, SpongyCastle, AppsFlyer, **Rhino JS** | (v7a) |
| SK증권 주파수3 | com.sks.android.neojoopasoo | 6.5.1.2 | windows | — | (framework-heavy; MQTT) | (v7a) |
| NIGHT CROWS | com.wemade.nightcrowsglobal | 6.3.1.85 | windows | — | Unreal wrapper (dex 34 cls), Firebase/Facebook | (v7a) |
| **부국증권 BEST-M** | com.bookook.mtsplus | — | — | — | **NOT xShield** (no known packer, no libdxbase) | — |

Engine versions span **6.3.1.85 → 6.9.20.31**; `find_decryptor.py` auto-located the decryptor at a
DIFFERENT address in every build (0x1eca0/0x5c78/0x1eadc/0x1eab0/0x5dfc/0x24124/0xd868), zero hardcoding.

## Cross-app patterns
- **Server-driven JS execution surface** — `org/mozilla/javascript` (Rhino) bundled in **3 financial apps**
  (M-STOCK, Shinhan, Hyundai Marine). In M-STOCK it is **Coocon SASAPI** — a server-fed JS scraping engine
  (RCE-by-design threat class, cf. GAD BeanShell). See [`COOCON_SASAPI_TRIAGE.md`](COOCON_SASAPI_TRIAGE.md).
- **On-device AV** — AhnLab V3 (`com.ahnlab.enginesdk`) in Shinhan + IBK; NSHC DroidX3 in PASS.
- **PKI stacks** — SignKorea+Yettiesoft (M-STOCK), WIZVERA+SpongyCastle (Shinhan).
- **Shared platform** — Kia and MyHyundai carry the same `com.hmg.*` HMG codebase.
- **Per-customer mgmt server** — `-c{server}` differs: SKP apps `xo.fxshield.co.kr`, M-STOCK `xo.dxshield.com`.
- **Verified the customer-list claims** — the three "customer-relationship only" candidates (현대캐피탈,
  현대해상, 우리WON카) are APK-confirmed xShield; only 부국증권 was negative.

## Provenance
Downloaded via apkeep/APKPure into per-app dirs under `~/Downloads/`. KR financial apps are often
armeabi-v7a-only (find_decryptor is arm64 — v7a builds need a 32-bit port, noted). Confirmations are
`packer-detect` + plaintext-manifest engine strings; deep results are byte/CPG-verified where decrypted.
