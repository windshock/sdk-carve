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

**Scoping (do NOT over-claim):** carrier identity / vulnerable-channel-present = **L3: 37 apps**. Exact dangerous
config = **L4: 6** (M-STOCK/신한/IBK/현대해상 + 체크페이 + BNK경남). E2E exploitability = **L5: 4** (M-STOCK/신한/IBK/현대해상).
The other 31 carriers are L3 (real surface), pending L4/L5.

## Candidate generation — VT domain pivot (now the primary method)
Reversing from the binary beats OSINT guessing: pull **VirusTotal relations for `isas.coocon.co.kr`** (the iSAS
server) → the APKs VT associates with that host are direct candidates → verify each with a **current official-APK
L3 fingerprint**. Discipline: a VT relation is a *lead, not a verdict* — its meaning depends on the relation type
(APK string/DEX reference vs a domain merely *contacted at runtime*, e.g. via WebView), so never call carrier from
VT alone; confirm at L3 on the shipping APK. (Also: VT lists must be normalized — drop bare DEX fragments,
multi-version dups, and the **Windows iSAS** artifacts `NXISAS`/`nxisas.exe`/`iSASNXWS.exe` — those are
product-family attribution for iSAS on Windows, **not** part of the Android `sasapi` mobile-vuln claim.)

## Verticals — iSAS is not finance-only
Coocon's official case studies place iSAS/healthcare-package beyond banking: **[인바디]** and **[GC케어]** are
published Coocon customer cases ("헬스케어 패키지…맞춤형 건강관리"). Coocon's personal-data product also brokers
건강보험공단/국민연금/국세청 data (income/proof). So the SDK surface plausibly spans **finance · corporate-expense ·
healthcare · public/transit** — verify each vertical at L3 rather than assuming.

## How to confirm (one step per APK)
```
.agents/skills/sdk-carve/scripts/coocon-fingerprint.sh app.xapk   # scan universal/XAPK (SDK often on a split)
#   exit 0 = vuln channel · 1 = coocon-other · 3 = NEGATIVE(readable) · 4 = INDETERMINATE(packed)
d2j-dex2jar -f -o app.jar app.apk    # then javap deep-confirm (b=="02"? / 0 sig / 0 setClassShutter)
```
Acquisition: `research/acquisition/resolve.py <pkg> --allow-download` (apkeep/APKPure). One folder per app under
`~/Downloads/<app>/`; **samples never committed.**

## CARRIERS (L3) — `sasapi/scriptengine` in the shipped APK, all → `isas.coocon.co.kr:443:80`  · **37 apps**
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
| BZPEXPENSE | `com.nextbiz.bzpexpense.aos` | 981 | L3 (+server) | com.nextbiz.* — identical refcount to TRIP+ |
| 현대카드 비즈플레이 | `com.bizplay.hyundai` | 888 | L3 (+server) | white-label (888-cluster) |
| 우리카드 비즈플레이 | `com.bizplay.woori` | 888 | L3 (+server) | white-label (888-cluster) |
| 삼성카드 비즈플레이 | `com.bizplay.samsung` | 888 | L3 (+server) | white-label (888-cluster) |
| 비즈플레이 On-Premise | `com.bizcard.bizplayPPPEnt` | 888 | L3 (+server) | On-Prem fork (888-cluster) |
| 창원 누비전 (지역화폐) | `com.bizplay.bizzeropay.changwon` | 725 | L3 (+server) | bizzeropay line; 개인계좌 자동출금 |
| KB스타뱅킹 | `com.kbstar.kbbank` | 1006 | L3 (+server) | **VT-derived**; major bank |
| KB저축은행 키위뱅크 | `com.kbsavings.android` | 979 | L3 (+server) | VT-derived |
| NH콕뱅크 | `nh.smart.nhcok` | 1023 | L3 (+server) | VT-derived; NH family (w/ NH스마트뱅킹) |
| InBody | `com.inbody2014.inbody` | 976 | L3 (+server) | **VT-derived · HEALTHCARE** (Coocon 공식 고객사례) |
| 어떠케어 (GC케어) | `com.gchc.combination` | 1012 | L3 (+server) | **VT-derived · HEALTHCARE** (Coocon 공식 고객사례) |
| 웰체크 (WellCheck) | `biz.mcircle.cdpc` | 1005 | L3 (+server) | **VT-derived · HEALTHCARE** |
| 셔클 (현대차 모빌리티) | `com.hyundai.airlab.shucle` | 985 | L3 (+server) | **VT-derived · MOBILITY** (no prior OSINT — binary found it) |
| 똑타 (경기교통公 GMaaS) | `com.hyundai.shucle.gmaas` | 985 | L3 (+server) | **VT-derived · MOBILITY** (985 = 셔클, same code line) |
| NAVER | `com.nhn.android.search` | 1001 | L3 (+server) | **VT-derived · PORTAL/super-app** — relation-nature VERIFIED: class descriptors (incl. `iSASXecure`) **compiled into base-apk dex** (classes7/14) + `isas.coocon.co.kr` string (also `:80:443` variant); NOT a runtime WebView contact. v12.23.50 |

## SDK propagation tree — 비즈플레이/nextbiz dev-family (fingerprint ref-count clusters)
The `kr/co/coocon` ref count is a build-lineage signature: apps sharing a code line carry the *same* count.
Three clusters in the 비즈플레이(주) family, each a distinct integration of the same iSAS SDK:
```
981-cluster  com.nextbiz.*         TRIP+ (hdexpense) 981 · BZPEXPENSE (bzpexpense) 981         [expense line]
888-cluster  com.bizcard.* /       비즈플레이 888 · On-Premise(bizplayPPPEnt) 888 ·               [corp-card / white-label]
             com.bizplay.<card>    현대 888 · 우리 888 · 삼성 888
725-cluster  com.bizplay.bizzeropay.* 창원 누비전 725                                             [지역화폐 line]

985-cluster  com.hyundai.shucle.*  셔클(airlab.shucle) 985 · 똑타(shucle.gmaas) 985             [mobility/GMaaS — 현대차 AirLab]
```
Read-out: within 비즈플레이(주) the iSAS channel propagated across **all three** product lines (expense,
corporate-card white-labels, 지역화폐) — carrier status tracks the code line, not the customer brand; card
white-labels are byte-family (all 888). A separate same-code-line cluster shows up in 현대차 AirLab mobility
(셔클/똑타 = 985). Same-vendor apps still packed (AppIron) can't be counted yet (see INDETERMINATE).

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

## INDETERMINATE — 0 markers but PACKED (unpack, then re-fingerprint)  · 8
| App | package | packer |
|---|---|---|
| 롯데캐피탈 | `com.lottecap.finance` | AppIron (`libAppIron-jni_v2.*`) — 업무위탁 lists 쿠콘-스크래핑 → likely carrier |
| 수협 | `com.suhyup.psmb` | AppIron (`libAppIron-jni_v2.13.28`) |
| 흥국화재 | `kr.co.hkfire.cyber` | AppIron (`libAppIron-RemoteBan` + `libAppIron-jni_v2.13.18`) — 위탁: 쿠콘 스크래핑 → likely carrier |
| IBK 법인카드 | `com.ibk.bizcard` | AppIron (`libAppIron-Suite`) — 비즈플레이 family → likely carrier |
| 비플법인카드 On-Premise | `com.bizplay.ippp.bizcard.aos` | AppIron (`libAppIron-Suite`) — 비즈플레이 family → likely carrier |
| 춘천사랑상품권 | `com.bizplay.bizzeropay.chuncheon` | AppIron (`libAppIron-jni_v2.12.3`) — bizzeropay line (창원=carrier) |
| 강원상품권 | `com.bizplay.bizzeropay.kangwon` | AppIron (`libAppIron-Suite`) — bizzeropay line |
| 경남지역상품권 | `com.bizplay.bizzeropay.gyeongnam` | AppIron (`libAppIron-jni_v2.12.3`) — bizzeropay line |

## PENDING acquisition (zero versions on APKPure / apkmirror unconfigured — need official-channel APK)  · 6
| App | package | note |
|---|---|---|
| 메디팜핏 | `com.aromit.hmds_app_normal` | **P0, L2** — dev blog shows `SASManager.run()` + MethodChannel `*.coocon`; strongest un-scanned candidate |
| 세모리포트 (웹케시) | `com.webcash.semor` | L1 — same 쿠콘 스크래핑 위탁 문구; PC-collect + mobile-view possible (rank below 세모장부) |
| 신협 ON뱅크 기업 | `kr.co.cu.bizonbank` | sibling of 신협 온뱅크 (carrier) |
| ACT 액트 | `com.conduit.act` | KIND filing: 체크페이→자산관리→COOCON |
| BNK캐피탈 | `com.bnkfg.bnkcapital` | Plug-In + We-Check |
| 보맵플래너 | `kr.co.bomapp.planner` | 보맵 sibling |
| 비씨카드 비즈플레이 | `com.bizplay.bccard` | white-label; 0 versions on APKPure |
| 서울Pay+ | `com.bizplay.seoul.pay` | bizzeropay/pay line; 0 versions on APKPure |
| 제주 탐나는전 | `com.bizplay.g2c.jeju` | 지역화폐; 0 versions on APKPure |

## Next-batch strategy — 비즈플레이 developer family (both TRIP+ AND 비즈플레이 = carriers ⇒ shared module)
Enumerate the 비즈플레이(주) Play developer account and fingerprint the lot (need package IDs): 현대카드/우리카드/삼성카드
비즈플레이, IBK 법인카드, BZPEXPENSE. Also worth: other 웹케시 apps (경리나라 계열). Same one-folder-per-app → fingerprint flow.

## Tally & lessons
- **37 carriers (L3)** · 8 negatives · 8 indeterminate (AppIron-packed) · 9 pending. 53 APKs fingerprinted.
  VT batch = 9/9 fingerprinted are carriers: KB스타뱅킹, KB저축, NH콕뱅크, **InBody, GC케어, 웰체크 (healthcare)**,
  **셔클, 똑타 (mobility)**, **NAVER (portal super-app — relation-nature verified: iSAS compiled into base-apk dex,
  incl. `iSASXecure`; not a runtime contact)**.
- **VT domain pivot >> OSINT guessing** (8/8 hit). And **iSAS is not finance-only** — proven at L3 in healthcare
  (InBody/GC케어/웰체크) and mobility (셔클/똑타). New verticals to sweep, not just banks.
- **Code-lineage (ref-count) as a search axis**: propagation clusters 981/888/725 (비즈플레이) and 985 (현대 AirLab
  mobility). Carrier tracks the code line, not the brand.
- Next levers: **AppIron unpacking** (8 packed → L3) and **more VT-relation pivots** per newly-found vertical.
- **iSAS/smart-scraping supply = strong predictor**; every *readable* smart-scraping supplyee scanned is a carrier
  (신한저축·부산·한투저축·우리·NH·IBK저축·우리저축·다올·OK저축·신협·OSB). **MyData-customer / ASP / cloud-scraping = weak/negative**
  (한화생명·밀리패스·페퍼-ASP·HB). Binary overrode OSINT twice: TRIP+ (guessed server-only) = carrier; OSB (guessed cloud) = carrier.
- Wording is a **priority hint, not a rule**: "ASP"/"클라우드스크래핑" *leans* server-side, "장비/방화벽 영향에 스크래핑"
  *leans* device iSAS — but **OSB (tagged cloud) is a carrier**, so never conclude from wording; only L3 decides.
- Always packing-check (AppIron on 롯데캐피탈/수협/흥국화재 = false-negative trap).
- Samples live in `~/Downloads/<app>/`, never committed; this file = packages + evidence + verdicts only.
