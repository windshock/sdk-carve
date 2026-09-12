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

## Binary fingerprint results — 12 candidates acquired & scanned (2026-09-12)
Acquired via `research/acquisition/resolve.py` (apkeep/APKPure), one folder per app under `~/Downloads/<app>/`,
scanned with `coocon-fingerprint.sh` on the universal/XAPK. **OSINT vs binary diverged sharply: 6 of 10 scanned
"Coocon customers" carry NO in-APK Coocon library.**

### NEW — binary-confirmed carriers of the vulnerable channel (`sasapi/scriptengine`)
All point at the same `isas.coocon.co.kr:443:80` server (dex-string verified).
| App | package | fingerprint | deep-confirm (b / sig / ClassShutter) | verdict |
|---|---|---|---|---|
| 체크페이 (CheckPay) | `com.cp.checkpay` | 890 refs, SE+V8+SM, CheckPay=63 | **b="02", 0 sig/MAC, 0 ClassShutter** | ✅ **EXPLOITABLE-config confirmed** (Coocon's own app) |
| BNK경남은행 | `com.knb.psb` | 1001 refs, SE+V8+SM | **b="02", 0 sig/MAC, 0 ClassShutter** | ✅ **EXPLOITABLE-config confirmed** |
| BNK부산은행 | `kr.co.busanbank.mbp` | 1027 refs, SE+V8+SM | dex2jar crashed → javap pending | ✅ VULN CHANNEL + same server (deep-confirm pending) |
| TRIP+ (Bizplay) | `com.nextbiz.hdexpense.aos` | 981 refs, SE+V8+SM | dex2jar crashed → javap pending | ✅ VULN CHANNEL + same server (was guessed tier③ — wrong; it bundles the lib) |

→ **Fleet total: 8 binary-confirmed carriers** (original 4 live-E2E: M-STOCK/신한/IBK/현대해상 + these 4). checkpay
& 경남은행 additionally match the exploitable config 1:1; 부산은행 & TRIP+ have the channel + server, deep-confirm
only blocked by a dex2jar crash (retry with a different converter).

### NEGATIVE — public "Coocon integration" but NO in-APK library (this build)
The two-column discipline earning its keep — these use Coocon **server-side / via redirect**, not an embedded lib.
| App | package | fingerprint | note |
|---|---|---|---|
| 테이블링 | `com.mealant.tabling` | 0 coocon / 0 checkpay (base-apk hand-verified) | CheckPay PG here is not an in-APK SDK |
| 밀리패스 | `kr.or.zeropay.mlps` | 0 coocon | privacy policy names Coocon, but the processing is server-side |
| 한화생명 | `com.hanwhalife.hiw` | 0 coocon | MyData Plug-In "adopter" ≠ in-APK lib |
| 캐시워크 | `com.cashwalk.cashwalk` | 0 coocon | — |
| 삼성카드/모니모 | `net.ib.android.smcard` | 0 coocon | — |
| 수협 | `com.suhyup.psmb` | 0 coocon | — |
> Caveat: "0 markers" = no *plaintext* Coocon class strings in any dex; a packed/string-encrypted build could
> hide them (none tripped the packer heuristic, but note it before calling a hard negative).

### PENDING acquisition (zero versions on APKPure; apkmirror backend unconfigured — need official-channel APK)
| App | package | note |
|---|---|---|
| ACT 액트 | `com.conduit.act` | KIND filing shows 체크페이→자산관리→COOCON flow |
| BNK캐피탈 | `com.bnkfg.bnkcapital` | Plug-In + We-Check adopter |

**Tier heuristic vs reality:** ① Plug-In/CheckPay-lineage mostly held (checkpay/부산/경남 = carriers) but is **not**
reliable alone — 한화생명 (①) carries nothing in-APK, while TRIP+ (guessed ③) does. Only the binary settles it.

## Method / provenance
Fingerprint: `coocon-fingerprint.sh` (validated: 4/4 confirmed apps → exit 0; 부국증권 negative → exit 3).
Samples are acquired from official channels and **never committed** (this file tracks packages + evidence +
verdicts only). Elevate a candidate to CONFIRMED only after a Tier-1 binary hit; add "live E2E" only after the lab.
