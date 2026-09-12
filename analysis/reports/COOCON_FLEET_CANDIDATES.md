# Coocon fleet — candidate corpus (expansion beyond the confirmed 4)

Finding apps that ship a Coocon client library so we can binary-confirm which carry the **active-MITM RCE
surface** (`kr.co.coocon.sasapi.scriptengine` server-JS-eval channel — see COOCON_SASAPI_TRIAGE.md). Discovery
is OSINT; **confirmation is binary.** Disciplines:

1. **Public evidence ≠ binary confirmation** — separate columns; `CONFIRMED` only on an in-APK hit.
2. **"Coocon present" ≠ "vulnerable channel present"** — `sasapi/scriptengine` (the RCE surface) is distinct
   from CheckPay (PG) / MyData Plug-In.
3. **0 markers ≠ negative when the app is PACKED** — a shielder (AppIron, AppSealing, DexProtector, …) hides
   class strings. Report **INDETERMINATE**, not NEGATIVE, and unpack before concluding.

## What the SDK is: Coocon **iSAS** (smart-scraping), binary-grounded
`sasapi` is the client SDK for Coocon's **iSAS / Smart-Scraping** product (reg. `COOCON iSAS`, C-2017-021779).
Binary basis (not just the server name): a class literally named **`kr.co.coocon.sasapi.pkcs.iSASXecure`**,
`iSAS` strings inside `ScriptEngine`/`V8ScriptEngine`, the `isas.coocon.co.kr` host (isas = iSAS), and the whole
`SAS*` family (`SASManager`/`SASEnvironment`/`SASAlgorithm`/`SAS_AL_000…`). ⇒ the strong candidate signal is
**"Coocon iSAS / smart-scraping supply history,"** not "Coocon MyData customer" (validated: BNK부산은행 was a 2016
smart-scraping supplyee → binary positive). Selection funnel, weak→strong:
`Coocon customer → MyData Plug-In customer → iSAS/smart-scraping supply evidence → APK carries sasapi+ScriptEngine+isas → BINARY CONFIRMED`.

## How to confirm (one step per APK)
```
# Tier-1 presence (fast, no dex2jar) — scan the UNIVERSAL/XAPK (SDK often rides a split, not base):
.agents/skills/sdk-carve/scripts/coocon-fingerprint.sh app.xapk
#   exit 0 = vuln channel · 1 = coocon-other · 3 = NEGATIVE (dex readable) · 4 = INDETERMINATE (packed)
# Tier-2 exploitability deep-confirm (after a Tier-1 vuln hit):
d2j-dex2jar -f -o app.jar app.apk
javap -c -p -cp app.jar kr.co.coocon.sasapi.script.ScriptManager        # default iface ver (b=="02"?), no sig/MAC
javap -c -p -cp app.jar kr.co.coocon.sasapi.SASManager                  # server (isas.coocon.co.kr:443 plain TCP?)
javap    -p -cp app.jar kr.co.coocon.sasapi.scriptengine.ScriptEngine | grep -c setClassShutter   # expect 0
```
> Acquisition: `research/acquisition/resolve.py <pkg> --allow-download` (apkeep/APKPure works; apkmirror/apkcombo
> need `APKMD_CLI`). One folder per app under `~/Downloads/<app>/`. Samples never committed.

## CARRIERS — binary-confirmed `sasapi/scriptengine` (the RCE channel). All → `isas.coocon.co.kr:443:80`.
**12 apps.** "live E2E" = full network→eval→RCE reproduced in the ByteBuddy lab; "deep-confirm" = b/sig/ClassShutter via javap.
| App | package | evidence class | status |
|---|---|---|---|
| 미래에셋 M-STOCK | `com.miraeasset.trade` | broker MyData | ✅ **live E2E RCE** |
| 신한 SOL저축은행 | `com.shinhan.spbs` | 저축은행 smart-scraping supplyee (2016) | ✅ **live E2E RCE** |
| IBK (증권) | `com.ibk.scbs` | broker | ✅ **live E2E RCE** |
| 현대해상 | `m.hi.co.kr` | insurer | ✅ **live E2E RCE** |
| 체크페이 (CheckPay) | `com.cp.checkpay` | Coocon's own app | ✅ deep-confirm (b=02/0-sig/0-shutter) |
| BNK경남은행 | `com.knb.psb` | MyData Plug-In | ✅ deep-confirm (b=02/0-sig/0-shutter) |
| BNK부산은행 | `kr.co.busanbank.mbp` | smart-scraping supplyee (2016) | ✅ channel+server (javap pending; dex2jar crash) |
| TRIP+ (Bizplay) | `com.nextbiz.hdexpense.aos` | Bizplay–Coocon linkage | ✅ channel+server (javap pending) |
| 한국투자저축은행 KEY뱅크 | `com.koreainvestment.android.keybank` | 저축은행 smart-scraping supplyee (2016) | ✅ channel+server |
| 우리WON뱅킹 (우리은행) | `com.wooribank.smart.npib` | smart-scraping supplyee | ✅ channel+server |
| NH스마트뱅킹 (농협) | `nh.smart.banking` | smart-scraping supplyee | ✅ channel+server |
| 보맵 | `com.rv2.bomapp` | 레드벨벳벤처스 smart-scraping MOU | ✅ channel+server |

## NEGATIVE — public "Coocon integration" but NO in-APK library (dex readable, no packer)
Coocon used **server-side / via redirect**, not an embedded lib. (androidx ref count shown = dex is genuinely readable.)
| App | package | androidx | note |
|---|---|---|---|
| 테이블링 | `com.mealant.tabling` | 682 | CheckPay PG not an in-APK SDK here |
| 밀리패스 | `kr.or.zeropay.mlps` | 9029 | privacy policy names Coocon, but processing is server-side |
| 한화생명 | `com.hanwhalife.hiw` | 10163 | MyData Plug-In "adopter" ≠ in-APK lib |
| 캐시워크 | `com.cashwalk.cashwalk` | 42905 | — |
| 삼성카드/모니모 | `net.ib.android.smcard` | 51129 | — |
| 씨티모바일 | `kr.co.citibank.citimobile` | 8326 | 2016 supplyee, but no in-APK lib in the current build |
> Caveat: "readable" rules out packing, not necessarily DexGuard-style selective string encryption. Treat as
> "no in-APK Coocon lib in *this build*," not "never integrated."

## INDETERMINATE — 0 markers but PACKED (cannot conclude; unpack then re-fingerprint)
| App | package | packer | note |
|---|---|---|---|
| 롯데캐피탈 | `com.lottecap.finance` | **AppIron** (`libAppIron-jni_v2.*`) | current 업무위탁현황 lists "㈜쿠콘-스크래핑" → likely carrier, hidden by the packer |
| 수협 | `com.suhyup.psmb` | **AppIron** (`libAppIron-jni_v2.13.28`) | earlier mislabeled negative — corrected to INDETERMINATE |

## PENDING acquisition (zero versions on APKPure; need official-channel APK or `APKMD_CLI`)
| App | package | note |
|---|---|---|
| ACT 액트 | `com.conduit.act` | KIND filing: 체크페이→자산관리→COOCON flow |
| BNK캐피탈 | `com.bnkfg.bnkcapital` | Plug-In + We-Check |
| 보맵플래너 | `kr.co.bomapp.planner` | 보맵 sibling; derivative check |

## Tally & lessons
- **12 carriers** (4 live-E2E + 8 channel-confirmed) · **6 negatives** · **2 indeterminate (packed)** · **3 pending**.
- The **iSAS/smart-scraping supply signal is strong**: every 2016 smart-scraping supplyee we could read is a
  carrier (신한저축·부산·한투저축·우리·NH). MyData-customer alone is weak (한화생명/밀리패스= no in-APK lib).
- Tier guesses are hints only: 한화생명 (①) = none in-APK; TRIP+ (guessed ③) = carrier.
- Packers matter: AppIron on 롯데캐피탈/수협 turns a naive scan into a false negative — always packing-check.
- Samples in `~/Downloads/<app>/`, never committed; this file = packages + evidence + verdicts only.
