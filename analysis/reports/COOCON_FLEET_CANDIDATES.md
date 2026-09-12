# Coocon fleet — candidate corpus (expansion beyond the confirmed 4)

Working list for finding more apps that ship a Coocon client library, so we can binary-confirm which ones carry
the **active-MITM RCE surface** (`kr.co.coocon.sasapi.scriptengine` server-JS-eval channel — see
COOCON_SASAPI_TRIAGE.md). Candidate discovery is OSINT; **confirmation is binary.** Two disciplines:

1. **Public-source evidence ≠ binary confirmation.** They are separate columns. A row is only `CONFIRMED`
   once the Coocon library is seen *in the APK*.
2. **"Coocon present" ≠ "vulnerable channel present."** Coocon ships several products:
   - **`sasapi/scriptengine` (SAS scraping / MyData)** — the server-JavaScript `eval` channel = **the RCE
     surface we proved.** Marker: `kr/co/coocon/sasapi/scriptengine/ScriptEngine` (+`V8ScriptEngine`) +
     `sasapi/script/ScriptManager`.
   - **CheckPay (payment PG)** and **MyData Plug-In (Infrastructure+App+ScreenView)** — may bundle a client
     lib that may *or may not* include `sasapi/scriptengine`. Must be checked per sample, not assumed.

## How to confirm (one step when an APK lands)
```
# Tier-1 presence (fast, no dex2jar):  prefer the UNIVERSAL/XAPK — the SDK often rides a split, NOT the base
.agents/skills/sdk-carve/scripts/coocon-fingerprint.sh app.xapk        # exit 0 = vuln channel, 1 = coocon-other, 3 = none
# Tier-2 exploitability deep-confirm (only after a Tier-1 vuln hit):
d2j-dex2jar -f -o app.jar app.apk
javap -c -p -cp app.jar kr.co.coocon.sasapi.script.ScriptManager        # default iface ver (field b == "02"?), no sig/MAC in updateScript
javap -c -p -cp app.jar kr.co.coocon.sasapi.SASManager                  # server (isas.coocon.co.kr:443 plain TCP?)
javap    -p -cp app.jar kr.co.coocon.sasapi.scriptengine.ScriptEngine | grep -c setClassShutter   # expect 0
# (optional) ByteBuddy MITM lab for a live E2E, if warranted.
```
> **Acquisition tip:** grab the **universal APK / XAPK** (or all splits). For M-STOCK the `base` split had ~1
> Coocon ref while the universal apk had **896 + `scriptengine`** — a base-only scan would false-negative.

## Confirmed (binary + live)
| App | package | public evidence | binary (fingerprint) | RCE channel (`scriptengine`) | status |
|---|---|---|---|---|---|
| 미래에셋 M-STOCK | `com.miraeasset.trade` | broker MyData/scraping | ✅ 896 refs, SE+V8+SM | ✅ yes | **CONFIRMED — live E2E RCE** |
| 신한 | `com.shinhan.spbs` | broker | ✅ SE+V8+SM | ✅ yes | **CONFIRMED — live E2E RCE** |
| IBK | `com.ibk.scbs` | broker | ✅ 1281 refs, SE+V8+SM | ✅ yes | **CONFIRMED — live E2E RCE** |
| 현대해상 | `m.hi.co.kr` | insurer | ✅ SE+V8+SM | ✅ yes | **CONFIRMED — live E2E RCE** |
| SK증권 주파수3 | (broker) | broker | ⚠️ ~10-ref Coocon **stub** | ❌ interface stub, not full engine | present-but-not-the-engine |

## Candidates — public evidence gathered, **APK not yet acquired (binary = PENDING)**
Tiers by likelihood the Coocon lib is *in the APK*: **① Plug-In/CheckPay lineage** (ships Infrastructure+App+UI →
most likely in-APK) · **② app-integrated We-Check/payment** · **③ server-API-only** (least likely to bundle a lib).

| Pri | App | package | tier | public-source evidence | binary status |
|---|---|---|---|---|---|
| 0 | 체크페이 (CheckPay) | `com.cp.checkpay` | ① | Coocon's own app — reference/base | ⏳ PENDING (baseline) |
| 1 | ACT 액트 | `com.conduit.act` | ① | in-app 체크페이(Coocon) 통합자산관리; KIND filing shows flow 체크페이→자산관리→COOCON | ⏳ PENDING |
| 2 | 테이블링 | `com.mealant.tabling` | ①/② | official help: CheckPay = Coocon PG for pay/auth/account-register/charge/withdraw; Coocon case study "테이블링페이" | ⏳ PENDING |
| 3 | 밀리패스 | `kr.or.zeropay.mlps` | ① | privacy policy names **Coocon** as processor for "MyData 현역/증명 정보 송수신 + infra 설치·유지보수" | ⏳ PENDING (newly found) |
| 4 | BNK부산은행 | `kr.co.busanbank.mbp` | ① | Coocon **MyData Plug-In** adopter (Coocon IR/사업보고서) | ⏳ PENDING |
| 5 | BNK경남은행 | `com.knb.psb` | ① | Coocon MyData Plug-In adopter | ⏳ PENDING |
| 6 | BNK캐피탈 | `com.bnkfg.bnkcapital` | ① | Coocon MyData Plug-In + We-Check | ⏳ PENDING |
| 7 | 한화생명 | `com.hanwhalife.hiw` | ① | Coocon MyData Plug-In adopter | ⏳ PENDING |
| 8 | 캐시워크 | `com.cashwalk.cashwalk` | ① | Coocon MyData Plug-In adopter (notable: non-financial) | ⏳ PENDING |
| 9 | 삼성카드/모니모 | `net.ib.android.smcard` | ②/③ | past Plug-In adopter; current APK residency unverified | ⏳ PENDING |
| 10 | 수협 | `com.suhyup.psmb` | ③ | appears in past Coocon MyData material | ⏳ PENDING |
| 11 | TRIP+ | `com.nextbiz.hdexpense.aos` | ③ | Bizplay–Coocon data linkage + in-app MyData | ⏳ PENDING |

**Note on Plug-In vs plain API:** Coocon's MyData Plug-In is documented as **Infrastructure + App + Screen
View(UI)** (not "server-side API only"), so the ① adopters are the group most likely to carry an in-APK Coocon
lib — the right first targets for the fingerprint. Server-API-only integrations (③) may show no client library.

## Method / provenance
Fingerprint: `coocon-fingerprint.sh` (validated: 4/4 confirmed apps → exit 0; 부국증권 negative → exit 3).
Samples are acquired from official channels and **never committed** (this file tracks packages + evidence +
verdicts only). Elevate a candidate to CONFIRMED only after a Tier-1 binary hit; add "live E2E" only after the lab.
