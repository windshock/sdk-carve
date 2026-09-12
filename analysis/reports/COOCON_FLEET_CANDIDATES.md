# Coocon fleet — candidate corpus (expansion beyond the confirmed 4)

Finding apps that ship a Coocon client library so we can binary-confirm which carry the **active-MITM RCE
surface** (`kr.co.coocon.sasapi.scriptengine` server-JS-eval channel — see COOCON_SASAPI_TRIAGE.md). Discovery
is OSINT; **confirmation is binary.** Disciplines:

1. **Public evidence ≠ binary confirmation** — separate columns; `CONFIRMED` only on an in-APK hit.
2. **"Coocon present" ≠ "vulnerable channel present"** — `sasapi/scriptengine` (RCE surface) ≠ CheckPay(PG) / MyData Plug-In.
3. **0 markers ≠ negative when PACKED** — a shielder (AppIron, …) hides class strings → report **INDETERMINATE**, unpack, re-scan.
4. **Do not collapse the evidence levels (below)** — "carrier identity" is not "exploit-proven."

## What the SDK is: Coocon **iSAS** (smart-scraping), binary-grounded
`sasapi` = client SDK for Coocon **iSAS / Smart-Scraping** (reg `COOCON iSAS`, C-2017-021779). Binary basis: a
class literally named **`kr.co.coocon.sasapi.pkcs.iSASXecure`**, `iSAS` strings in `ScriptEngine`/`V8ScriptEngine`,
the `isas.coocon.co.kr` host, and the `SAS*` family (`SASManager`/`SASEnvironment`/`SASAlgorithm`/`SAS_AL_000…`).
⇒ strong signal = **iSAS/smart-scraping supply history**, not "MyData customer." Coocon also sells server-side
**Cloud Scraping / ASP** (separate SW). **⚠️ The rule "cloud/ASP wording ⇒ server-side ⇒ no device `sasapi`" is
DEPRECATED** — OSB was tagged "정부24 클라우드스크래핑" yet the APK carries the device-side iSAS lib. Such wording is a
**priority hint only; L3 APK fingerprint is the sole truth.** (Product history, per Coocon filings — *timeline only,
no code-lineage claim*: `2007 client scraping iBASE 2.0 → 2013 server/cloud iBASE 3.0 → 2015 smart scraping i-SAS 2.0`.)

## Evidence levels (claim each separately)
| Lvl | Claim | How established |
|---|---|---|
| L0 | public Coocon customer | OSINT (weak) |
| L1 | scraping/iSAS supply evidence | OSINT press/위탁현황 (medium) |
| L2 | source-level SDK use (`SASManager`/`sasapi`/`iSAS`) | dev blog / public code |
| **L3** | **APK carrier** — `sasapi`+`ScriptEngine`+`isas` in the shipped APK | `coocon-fingerprint.sh` (binary) |
| **L4** | **exact dangerous config** — `b="02"`, 0 sig/MAC, 0 `ClassShutter` | `javap` deep-confirm (binary) |
| **L5** | **controlled E2E** — full network→eval→RCE | ByteBuddy MITM lab |

**Scoping (do NOT over-claim):** carrier identity / vulnerable-channel-present = **L3: 22 apps**. Exact dangerous
config = **L4: 6** (M-STOCK/신한/IBK/현대해상 + 체크페이 + BNK경남). E2E exploitability = **L5: 4** (M-STOCK/신한/IBK/현대해상).
The other 16 carriers are L3 (real surface), pending L4/L5.

## How to confirm (one step per APK)
```
.agents/skills/sdk-carve/scripts/coocon-fingerprint.sh app.xapk   # scan universal/XAPK (SDK often on a split)
#   exit 0 = vuln channel · 1 = coocon-other · 3 = NEGATIVE(readable) · 4 = INDETERMINATE(packed)
d2j-dex2jar -f -o app.jar app.apk    # then javap deep-confirm (b=="02"? / 0 sig / 0 setClassShutter)
```
Acquisition: `research/acquisition/resolve.py <pkg> --allow-download` (apkeep/APKPure). One folder per app under
`~/Downloads/<app>/`; **samples never committed.**

## CARRIERS (L3) — `sasapi/scriptengine` in the shipped APK, all → `isas.coocon.co.kr:443:80`  · **22 apps**
| App | package | refs | max level | note |
|---|---|---|---|---|
| 미래에셋 M-STOCK | `com.miraeasset.trade` | 896 | **L5 live-E2E** | broker |
| 신한 SOL저축은행 | `com.shinhan.spbs` | — | **L5 live-E2E** | 저축은행 (2016 smart-scraping supplyee) |
| IBK 증권 | `com.ibk.scbs` | 1281 | **L5 live-E2E** | broker |
| 현대해상 | `m.hi.co.kr` | 971 | **L5 live-E2E** | insurer |
| 체크페이 (CheckPay) | `com.cp.checkpay` | 890 | **L4** | Coocon's own app |
| BNK경남은행 | `com.knb.psb` | 1001 | **L4** | MyData Plug-In |
| BNK부산은행 | `kr.co.busanbank.mbp` | 1027 | L3 (+server) | 2016 supplyee |
| TRIP+ (Bizplay) | `com.nextbiz.hdexpense.aos` | 981 | L3 (+server) | |
| 한국투자저축 KEY뱅크 | `com.koreainvestment.android.keybank` | 1001 | L3 (+server) | 2016 supplyee |
| 우리WON뱅킹 (우리은행) | `com.wooribank.smart.npib` | 996 | L3 (+server) | supplyee |
| NH스마트뱅킹 (농협) | `nh.smart.banking` | 1013 | L3 (+server) | supplyee |
| 보맵 | `com.rv2.bomapp` | 728 | L3 (+server) | 레드벨벳벤처스 MOU |
| IBK저축은행 i-Bank | `kr.co.ibksb.ibank` | 977 | L3 (+server) | 쿠콘 ARS·스크래핑 |
| 우리WON저축은행 | `com.woorifsb.woorifsbapp` | 893 | L3 (+server) | 쿠콘 스크래핑 |
| 다올디지털뱅크 Fi | `com.eugene.eugenebank` | 894 | L3 (+server) | 2026-07 쿠콘 방화벽 공지 |
| OK저축은행 | `com.cabsoft.oksavingbank` | — | L3 (+server) | 쿠콘 ARS·스크래핑 |
| 신협 온뱅크 | `kr.co.cu.onbank` | — | L3 (+server) | 중앙회 위탁: 쿠콘 스크래핑 |
| OSB저축은행 | `co.osb.banking` | — | L3 (+server) | **guessed cloud/server-side but APK carries device iSAS** |
| 핀다 (finda) | `kr.co.finda.finda` | — | L3 (+server) | 위탁: ㈜쿠콘 스크래핑; 2018 스크래핑 솔루션+API 공급 |
| 세모장부 (웹케시) | `com.webcash.semo` | — | L3 (+server) | 정책: 정보 스크래핑 + 증빙 데이터 제공 |
| 모바일 경리나라 (웹케시) | `com.webcash.serp3_0` | — | L3 (+server) | 전은행 잔액/거래 실시간 조회 |
| 비즈플레이 | `com.bizcard.bizplay` | 888 | L3 (+server) | dev-family reuse (TRIP+ 동일 개발사) |

## NEGATIVE (L3-neg) — public "Coocon integration" but NO in-APK lib (readable dex; server-side/ASP/cloud)  · 8
| App | package | androidx | why negative |
|---|---|---|---|
| 테이블링 | `com.mealant.tabling` | 682 | CheckPay PG not an in-APK SDK |
| 밀리패스 | `kr.or.zeropay.mlps` | 9029 | Coocon named in policy but processing server-side |
| 한화생명 | `com.hanwhalife.hiw` | 10163 | MyData "adopter" ≠ in-APK lib |
| 캐시워크 | `com.cashwalk.cashwalk` | 42905 | |
| 삼성카드/모니모 | `net.ib.android.smcard` | 51129 | |
| 씨티모바일 | `kr.co.citibank.citimobile` | 8326 | 2016 supplyee, none in current build |
| 디지털페퍼 (페퍼저축) | `kr.pepperbank.digital` | 10759 | 위탁: 스크래핑 **ASP** (server-side) |
| HB저축은행 | `kr.co.essb.esbank` | 6286 | scraping supply is server-side here |
> "readable" rules out packing, not DexGuard-style selective string encryption → "no in-APK lib in *this build*."

## INDETERMINATE — 0 markers but PACKED (unpack, then re-fingerprint)  · 3
| App | package | packer |
|---|---|---|
| 롯데캐피탈 | `com.lottecap.finance` | AppIron (`libAppIron-jni_v2.*`) — 업무위탁 lists 쿠콘-스크래핑 → likely carrier |
| 수협 | `com.suhyup.psmb` | AppIron (`libAppIron-jni_v2.13.28`) |
| 흥국화재 | `kr.co.hkfire.cyber` | AppIron (`libAppIron-RemoteBan` + `libAppIron-jni_v2.13.18`) — 위탁: 쿠콘 스크래핑 → likely carrier |

## PENDING acquisition (zero versions on APKPure / apkmirror unconfigured — need official-channel APK)  · 6
| App | package | note |
|---|---|---|
| 메디팜핏 | `com.aromit.hmds_app_normal` | **P0, L2** — dev blog shows `SASManager.run()` + MethodChannel `*.coocon`; strongest un-scanned candidate |
| 세모리포트 (웹케시) | `com.webcash.semor` | L1 — same 쿠콘 스크래핑 위탁 문구; PC-collect + mobile-view possible (rank below 세모장부) |
| 신협 ON뱅크 기업 | `kr.co.cu.bizonbank` | sibling of 신협 온뱅크 (carrier) |
| ACT 액트 | `com.conduit.act` | KIND filing: 체크페이→자산관리→COOCON |
| BNK캐피탈 | `com.bnkfg.bnkcapital` | Plug-In + We-Check |
| 보맵플래너 | `kr.co.bomapp.planner` | 보맵 sibling |

## Next-batch strategy — 비즈플레이 developer family (both TRIP+ AND 비즈플레이 = carriers ⇒ shared module)
Enumerate the 비즈플레이(주) Play developer account and fingerprint the lot (need package IDs): 현대카드/우리카드/삼성카드
비즈플레이, IBK 법인카드, BZPEXPENSE. Also worth: other 웹케시 apps (경리나라 계열). Same one-folder-per-app → fingerprint flow.

## Tally & lessons
- **22 carriers (L3)** · 8 negatives · 3 indeterminate (packed) · 6 pending. 33 APKs fingerprinted.
  New this batch (웹케시/핀다/비즈플레이 생태계): 핀다, 세모장부, 모바일 경리나라, 비즈플레이 — all carriers.
- **iSAS/smart-scraping supply = strong predictor**; every *readable* smart-scraping supplyee scanned is a carrier
  (신한저축·부산·한투저축·우리·NH·IBK저축·우리저축·다올·OK저축·신협·OSB). **MyData-customer / ASP / cloud-scraping = weak/negative**
  (한화생명·밀리패스·페퍼-ASP·HB). Binary overrode OSINT twice: TRIP+ (guessed server-only) = carrier; OSB (guessed cloud) = carrier.
- Wording is a **priority hint, not a rule**: "ASP"/"클라우드스크래핑" *leans* server-side, "장비/방화벽 영향에 스크래핑"
  *leans* device iSAS — but **OSB (tagged cloud) is a carrier**, so never conclude from wording; only L3 decides.
- Always packing-check (AppIron on 롯데캐피탈/수협/흥국화재 = false-negative trap).
- Samples live in `~/Downloads/<app>/`, never committed; this file = packages + evidence + verdicts only.
