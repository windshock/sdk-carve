# 신한(Shinhan) app family — full sdk-carve pass (2026-09-13)

Scope: **all Shinhan-related Android apps acquired** — run the full sdk-carve methodology (packer-detect →
static carve → per-app SDK/security-stack inventory → Coocon-channel deep-confirm on carriers), not just the
Coocon-only fingerprint. Samples live in `~/Downloads/<app>/`; **never committed** (methodology + verdicts only).

## Result — 5 apps: 2 carriers, 3 negatives, 0 packed
| App | package | ver | packer | Coocon iSAS | verdict |
|---|---|---|---|---|---|
| 신한 SOL저축은행 | `com.shinhan.spbs` | 2.2.9 | none (carve VALID) | **carrier** (951 cls) | **L5** live-E2E (re-confirmed on 2.2.9) |
| 신한투자증권 SOL증권 | `com.shinhaninvest.nsmts` | — | none (carve VALID) | **carrier** (714 cls, `iSASXecure`) | **L4** deep-confirmed (this pass) |
| 신한 슈퍼SOL (신한은행) | `com.shinhan.sbanking` | — | none (carve VALID) | none (readable) | **NEGATIVE** |
| 신한생명 SOL라이프 | `com.AFSSHLife` | — | none (carve VALID) | none (readable) | **NEGATIVE** |
| 신한카드 신한SOL페이 | `com.shcard.smartpay` | — | none (carve VALID) | none (readable) | **NEGATIVE** (new — acquired this pass) |

**All 5 static-carve VALID** — no whole-app packer/shielder (packer-detect). Where an xShield RASP string appears
(저축/증권/생명) the dex is still plaintext, so it does not block carve (RASP-only, consistent with the fleet finding).

## Per-app SDK / security-stack inventory (base-dex marker counts)
| App | Coocon | WIZVERA | Raon/TouchEn | INITECH/INISAFE | SignKorea | AhnLab(V3) | xShield(str) |
|---|---|---|---|---|---|---|---|
| 신한저축 (carrier) | ✓ 951 carved | **1079** | – | – | 1 | **525** | 22 |
| 신한증권 (carrier) | ✓ 714, `iSASXecure` | – | 39/15 | 97/34 | 19 | 27 (+mvaccine) | 15 |
| 슈퍼SOL 은행 (neg) | – | – | **644/24** | **256/58** | 13 | – | – |
| 신한생명 (neg) | – | – | 120/12 | **1610/58** | 15 | 11 | 24 |
| 신한카드 (neg) | – | **3936** | 642/3 | – | 1 | **535** | – |

Read-out: two integration lineages inside the Shinhan family — **저축·카드 lean WIZVERA + AhnLab V3**; **은행·생명·증권
lean INITECH INISAFE + RaonSecure/TouchEn**. The Coocon device-side iSAS channel rides only on the two
data-aggregation products (savings-bank + brokerage), not on the flagship bank / life / card apps.

## Carrier deep-confirm (carve → exploitability preconditions)
`d2j-dex2jar` the base APK, carve `kr/co/coocon/**`, inspect the three preconditions that make the
`ScriptManager.updateScript` server-JS-eval channel an active-MITM RCE surface (see COOCON_SASAPI_TRIAGE.md):

| precondition | 신한저축 v2.2.9 | 신한증권 |
|---|---|---|
| coocon classes carved | 951 (incl. `CloneSASManager` variant) | 714 |
| `iSASXecure` (binary iSAS proof) | present | present |
| **ClassShutter** (Rhino sandbox) | **0 — no sandbox** | **0 — no sandbox** |
| pushed-script **Signature/verify/SHA256withRSA** | **0 — none** | **0 — none** |
| `isas.coocon.co.kr` endpoint | ✓ (`CloneSASManager`) | ✓ (`SASManager`) |
| Rhino `ScriptEngine` + `V8ScriptEngine` | both | both |
| protocol constants `01`/`02`/`0001`/`0000` | present | present |
| `c`-field default `127.0.0.1:1024:1025` | present | present |

Both carry the identical dangerous configuration: **default interface version `02` (JSON+AES) path available, no
signature/MAC on the pushed script, no Rhino `ClassShutter` sandbox** → a MITM on the plain-TCP
`isas.coocon.co.kr:443:80` channel can push script that the engine evaluates.

- **신한저축**: previously proven end-to-end in the ByteBuddy MITM lab (**L5**); this pass re-confirms the channel
  is intact in the current store build **v2.2.9** (a `CloneSASManager` variant is additionally present).
- **신한증권**: was L3 (fingerprint only). This pass carves + `javap`-confirms all L4 preconditions → **promoted L3→L4**.
  Not yet live-run, but structurally identical to the four L5 apps.

## Carved artifacts (local only)
`~/Downloads/coocon/carve_shinhansec_kr/` · `~/Downloads/coocon/carve_shinhanjeohuk_kr/` (kr/co/coocon class trees).
Not committed.

## Notes / gaps
- Other Shinhan-brand apps not in this pass (would extend coverage): 신한 SOL페이(모바일 결제) beyond the card app,
  any 신한 계열 sub-brands. 신한카드 신한SOL페이 (`com.shcard.smartpay`) is the card flagship and is NEGATIVE.
- 신한저축 base-dex raw-string count for `kr/co/coocon` (23) undercounts vs the 951 carved classes / 978 type-descriptor
  refs — the carve (dex2jar class tree) is authoritative, not the raw-string grep.
