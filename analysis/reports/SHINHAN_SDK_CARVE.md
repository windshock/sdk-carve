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

## Obfuscation — present (packer absent ≠ obfuscation absent)
`packer-detect: VALID (obfuscation-only at most)` means **no packer / no runtime dex encryption** — it does NOT
mean the code is un-obfuscated. Two obfuscation layers are present:

1. **Host-app identifier renaming (R8/ProGuard), selective.** Short (1–2 char) class names are present in every
   app — full-dex ratio ≈ **신한저축 2% · 신한증권 4%** of all descriptors. The ratio is modest because these apps
   *keep* the names of bundled libraries/SDKs (Coocon `kr/co/coocon`, PKI vendors, AhnLab, androidx, kotlin) and
   rename mainly their own business logic. The 3 negatives are R8-renamed the same way (app logic renamed, libs kept).
   → **This is why fingerprinting/carve works at all: the Coocon package names are preserved** (951 / 714 classes).
2. **Method-level control-flow obfuscation on the Coocon SDK's sensitive method — DEFEATED this pass.**
   `ScriptManager.updateScript` is exception-table-flattened: **신한저축 = 1033 exception-table rows / 2240 instrs;
   신한증권 = 819 rows / 1466 instrs** (a normal method has single digits). This defeats every stock decompiler
   (CFR/jadx/Vineflower/Fernflower/Corpseflower). We did **not** leave it there — ran the `ExFlattenNormalize`
   (`CooconDeobf`) ASM normalizer (`--redundant --split --unify`) on both Shinhan builds:
   - 신한증권: exception-table `819→39` (−217 redundant), gotos `48→11`, node-split `+37` → **CFR clean, 0 errors**.
   - 신한저축 v2.2.9: `1033→40` (−295), gotos `39→8`, split `+31` → **CFR clean, 0 errors** — pass counts match the
     reference build exactly (same SDK build).

   The recovered source confirms the protocol **1:1 at source level** in both:
   `getInterfaceVersion()` branch `"01"`(plaintext GZip) / `"02"`(JSON+AES); `SecureRandom.nextBytes(seed)` →
   `MessageDigest(SHA-256).digest()` = key; IV = `Bytes.bytesToHexString(key).substring(0,16)`;
   `new Socket()`→`InetSocketAddress(this.q,this.r[i])`; response `GZip.unzip(AESCipher.decrypt(..))` →
   `JSONObject.parse` → `.get(o/n/p)` = ResultCode/ScriptVersion/Script; `"0000"` store / `"0001"` up-to-date.
   **Grep for `Signature`/`verify`/`RSA`/`MAC` in the recovered `updateScript` = 0** in both → no integrity gate,
   confirming the L4 finding at *source* level (not just javap-structural). Recovered source local only, not committed.

Net: **not un-obfuscated** — R8 on the host app + heavy CFO on the Coocon channel (now decompiled); only the
*packer* is absent.

## CPG (Joern) — source→sink, run on the two carriers this pass
Ran `jimple2cpg` (`-Xmx6g`) on the carved `kr/co/coocon` jars (798 / 1048 classes) and queried the channel.
**Identical result on both carriers** (and matches the M-STOCK reference chain):

| CPG signal | 신한증권 | 신한저축 v2.2.9 |
|---|---|---|
| `evaluateString` (Rhino eval) sink | 1 | 1 |
| eval-wrapper method | `avoid(String)` (obf-renamed `ScriptEngine.a`) | `avoid(String)` |
| `updateScript` sensitive callees | `connect·getInputStream·getOutputStream·decrypt·unzip·parse·toJSONString` | *(same)* |
| `setClassShutter` (Rhino sandbox) | **0** | **0** |
| FLOW eval-param → `evaluateString` (intra-proc taint) | **3 paths** | **3 paths** |
| FLOW socket-read/decrypt → `evaluateString` (cross-method) | 0 | 0 |

Read-out: CPG independently confirms the **source side** (`updateScript` pulls bytes off a socket → AES-decrypt →
GZip-unzip → JSON-parse) and the **sink side** (a Rhino `evaluateString` with **no `ClassShutter`** anywhere), and
taint-proves the last hop (wrapper param → eval). The socket→eval auto-flow is **0 only because the hop is
field-mediated across classes** (`updateScript` stores the script, `ScriptEngine` loads it later) — Joern's default
taint doesn't stitch field-store→field-load across classes; the same 0 was seen on M-STOCK. The structural + javap +
intra-proc-taint evidence together is conclusive; a full cross-class flow would need a custom field-store→load rule.

CPGs (local only): `/tmp/cpg_sec.bin` · `/tmp/cpg_jeohuk.bin` (not committed).

### Did deobfuscating updateScript change the CPG? No — verified, not assumed
The first CPG was built on the **obfuscated** `ScriptManager` (819/1033 exception rows). To check whether Soot
mis-modeled the flattened method, we swapped the `ExFlattenNormalize`-normalized `ScriptManager` into the jar and
**re-parsed + re-queried**. Intra-`updateScript` dataflow (scoped to the method) came out **identical**:

| intra-`updateScript` flow | 증권 obf → norm | 저축 obf → norm |
|---|---|---|
| AST nodes in updateScript | 2814 → **1732** | 3792 → **1601** |
| `read/getInputStream` → `decrypt` | 1 → 1 | 1 → 1 |
| `decrypt` → `parse` | 0 → 0 | 2 → 2 |
| `parse` → `get(Script)` | 6 → 6 | 6 → 6 |
| `SecureRandom/digest` → `setKey/encrypt` | 2 → 2 | 2 → 2 |

Only the AST node count shrank (~40%, the removed synthetic exception scaffolding) — **every dataflow count is
unchanged.** Reason: the exception-table-flattening / irreducible-flow obfuscation defeats *decompilers* (they need
a reducible CFG to emit Java), but **Soot/`jimple2cpg` builds the CPG from raw Jimple IR and tolerates arbitrary
(irreducible) CFGs**, so the taint model was already sound. ⇒ **CPG did not need the deobfuscation**; the normalizer
was necessary only for human-readable source recovery (the L4 *source-level* confirmation + reading the crypto), not
for the graph/dataflow. (Consistency notes: `decrypt→parse`=0 on 증권 is a Joern tracking gap through the
`new String(GZip.unzip(..))` wrapper — present in *both* CPGs, not an obfuscation artifact; the cross-class
socket→eval hop is still field-mediated and unchanged by normalization.)

## FULL analyzer set (SKILL.md Method steps 2–5 — completing the mandated pass)
The first write-up stopped at carve + javap + a partial CPG. Per sdk-carve the FULL Method requires, *per carve*:
class-map → Joern source/sink **+ entry→sink reachability** → **scoped CodeQL** → **Semgrep** → **scope-closure**,
with a **cross-verification table (analyzer × root)** and the closure result. Ran the lot on the Coocon carve of
both carriers (`kr/co/coocon`, 714 / 951 classes). Tools: joern 4.0.370, codeql (build-mode=none), semgrep, jadx.

**class-map.py** (fast deep pass): `DeviceInfo`/`CertImplements` → `getMacAddress`/`getHardwareAddress` (device-id
collectors); `SASManager`/`HttpManager` → `isas.coocon.co.kr` / `coocon.co.kr` (endpoints).
**behavior-sweep.py**: 1 flagged root `kr/co/coocon` = 3-category `[collect.identity · dyn.load · sink.network]`
(collector+sink shape).

### Cross-verification table (analyzer × the Coocon channel, 신한증권; 신한저축 identical)
| signal | manual/CFR | Joern (bytecode CPG) | CodeQL (source DB) | Semgrep (regex/source) |
|---|---|---|---|---|
| Rhino eval sink (RCE) | ✅ `ScriptEngine.a` | ✅ `evaluateString @ a` | ✅ `rhino-eval @ ScriptEngine.a` | ✅ `rhino-eval-server-script` |
| no `ClassShutter` sandbox | ✅ (0 in source) | ✅ `setClassShutter=0` | — | ✅ `no-classshutter-sandbox` |
| net-in source | ✅ Socket read | ✅ `getInputStream @ updateScript/SASEngineTask.run` | ✅ `getInputStream @ SASEngineTask.run` | — |
| decrypt source | ✅ `AESCipher.decrypt` | ✅ `decrypt @ updateScript/AESCipher` | ✅ `decrypt @ AESCipher/ARIACipher/CustomCipher` | — |
| device-id source | ✅ `DeviceInfo` | ✅ `getMacAddress` | ✅ `getMacAddress @ CertImplements.MoaSign` | — |
| net-out sink | ✅ Socket write | ✅ `getOutputStream @ updateScript/ASTXComm.trx` | ✅ `getOutputStream @ ASTXComm.trx` (+crypto FPs) | — |
| `Runtime.exec` | ✅ (V8 lib chmod) | ✅ `exec @ chmod` | — | ✅ `runtime-exec @ v8/LibraryLoader` |

Three independent tools agree on the core chain. **CodeQL name-match caveat (honest):** its `getOutputStream`
"net-out" hits include ~15 `spongycastle`/PKCS12 `ByteArrayOutputStream` writes that are **crypto, not network** —
a build-mode=none name-matching limitation, not real exfil; the real net-out is `ASTXComm.trx`/`SASEngineTask.run`.

### Entry→sink reachability (the step the first pass lacked) — capability PROVEN
Joern `repeat(_.callee)` from entries `{updateScript, runScript, run, initInstance}`, maxDepth 6:
| sink | 신한증권 | 신한저축 |
|---|---|---|
| `evaluateString` (Rhino eval / RCE) | **reachable=true** (1 site) | **reachable=true** (1 site) |
| `getOutputStream` (net-out) | true (16) | true (14) |
| `exec` (Runtime.exec) | true (1) | true (2) |
| `toJSONString` | true (11) | true (15) |
| methods reachable ≤6 | 649 | 804 |

The Rhino eval sink **is reachable from the update/run entry points** — the call-graph path exists (stronger than
the earlier field-mediated auto-taint=0; that limit is about *value* flow across a field, not call reachability).

### Scope-closure (step 5 — carve completeness PROVEN)
| app | distinct callee owners | external (non-lib, non-scope) | what's external |
|---|---|---|---|
| 신한증권 | 854 | 7 | all `com.sun.net.httpserver.*` (JDK) |
| 신한저축 | 1073 | 9 | `com.sun.net.httpserver.*` + `com.xshield.dc` (RASP) + `kr.co.useb.AES256$$ExternalSynthetic…` (R8 synthetic) |

Everything the carve calls outside `kr.co.coocon` is **framework / the xShield RASP class / an R8 synthetic** — **no
missed Coocon SDK logic**, so the carve scope is complete.

### Item 1 — the bundled local HTTPS server (iSASService / SAS-proxy)
The `com.sun.net.httpserver` external owner led to `sasapi/engine/listener/HttpListener` + `engine/task/HttpTask`:
- **`HttpListener` is a standalone local HTTPS server** ("iSASService", default port **35751**, tunable via system
  props `debug.port`/`http.mode`). `run()` stands up an `HttpsServer` and `createContext("/", new HttpTask())`.
- **`HttpTask implements HttpHandler`** and its `handle()` calls `ScriptEngine.contextEnter()` → the local server
  **exposes the same server-JS-eval engine over local HTTPS**.
- Its TLS keystore is fetched over the **unauthenticated `updateScript("sas/SASKey")` channel** and loaded as a JKS
  with hardcoded password **`webcash123`** (webcash = Coocon's affiliate). Startup failure logs *"방화벽을 확인 하시기
  바랍니다"* — the exact "check your firewall" wording seen in customer scraping notices.
- **On Android it is bundled but NOT started**: the only caller of `new HttpListener(...).start()` is
  `HttpListener.main()` (a standalone-JVM entry). The on-device path is `SASManager.initInstance()` → connect **out**
  to `isas.coocon.co.kr:443:80` (client mode; hardcoded default appId `"PUSANAPP"`, plus an HTTP `Proxy` setup). The
  `c="127.0.0.1:1024:1025"` field is the **dormant** legacy local-proxy default.

⇒ So this is the desktop/PC **iSASService** code shipped inside the mobile artifact. It does **not** add mobile
attack surface (not invoked on-device) — but it documents the SAS-proxy design and a second place the same
no-signature `updateScript` channel delivers security material (a TLS private key). *Caveat:* verified within the
Coocon carve only; the **whole-app** grep (does any `com.shinhan*`/`com.shinhaninvest*` host code call `HttpListener`?)
is the G-8 whole-app pass — pending.

**Artifacts (local only):** CPGs `/tmp/cpg_{sec,jeohuk}.bin`; CodeQL DB `/tmp/db_sec`; jadx src `/tmp/src_sec`;
adapted scripts `/tmp/coocon_{ss,sinks,reach,sc}.sc`, `/tmp/qlpack/flows.ql`, `/tmp/coocon_semgrep.yml`. Not committed.

### Still not done (honest scope of THIS pass)
- Full analyzer set was run on the **Coocon carve** (the security-relevant target) of the **two carriers** only.
  Not run: whole-app `behavior-sweep.py` on all 5 apps to carve the *other* bundled SDKs (PKI/AV/adtech) — those
  were only string-counted in the inventory table, not carved+analyzed. The 3 negatives got fingerprint+inventory,
  not a full per-SDK carve (no Coocon target in them).

## Whole-app sdk-carve (G-8) — ALL bundled SDKs, not just Coocon
Per SKILL.md triage: dex2jar the whole app → `behavior-sweep.py` (family-agnostic capability-cluster) → carve every
non-`~` flagged root. dex2jar succeeded on 신한저축/증권/생명 (149/40/80 MB jars, 24928/33520/64262 classes); the two
**flagship apps 슈퍼SOL은행 + 카드 hard-fail dex2jar** (`Dex2jar.doTranslate` error → 0-byte jar, even per-dex + `-Xmx6g`)
— for those the SDK set was recovered by a **direct-dex package-root scan** (works without dex2jar).

### Per-app SDK matrix (✓ = package root present in the shipped APK)
| SDK (vendor / purpose) | 저축 | 증권 | 슈퍼SOL은행 | 생명 | 카드 |
|---|:--:|:--:|:--:|:--:|:--:|
| **Coocon iSAS** (scraping / server-JS-eval channel) | ✓ | ✓ | | | |
| **infinigru PhishingEyes** (anti-phishing: installed-app list + **APK-file upload** → `pelib.phishingeyes.com`) | ✓ | | ✓ | | ✓ |
| **interezen IPInside** (real-IP / device fingerprint: MAC/conn/applist → openConnection) | ✓ | | | | |
| **Insider** (`useinsider` martech / engagement) | | ✓ | | | |
| **Airbridge** (`ab180` attribution) | | ✓ | | | |
| **Hackle** (`io.hackle` A/B + analytics) | | | | ✓ | |
| **AppsFlyer** (attribution) | ✓ | | | | |
| **drfn / dooriworld** (chart SDK — **plain-HTTP bare-IP** `218.38.18.171/smartPhone/{dnload,uploads}`) | | ✓ | | | |
| AhnLab V3 (AV) | ✓ | ✓ | | ✓ | ✓ |
| RaonSecure (TouchEn/OnePass keypad/FIDO) | ✓ | ✓ | ✓ | ✓ | ✓ |
| WIZVERA Delfino (PKI) | ✓ | | | | ✓ |
| INITECH (PKI/SSO) | | ✓ | ✓ | ✓ | |
| nProtect seculog / secuchart | | ✓ | | ✓(secuchart) | |

Read-out: **carrier status (Coocon) is orthogonal to the rest of the stack** — every Shinhan app carries a
RaonSecure keypad + a PKI vendor + (usually) AhnLab AV; on top of that each app bundles *different* data SDKs.
The **notable non-Coocon collectors** the whole-app pass surfaced (would have been missed by a Coocon-only carve):

- **infinigru PhishingEyes (4 of 5 apps).** `PeBackgroundService`/`PeJobService` + `ReportTargetWorker` →
  `getInstalledPackages`; `SendApkFileWorker` + `ApiRequestService.sendApkFileByRequest`/`send_large_apk` →
  **uploads installed APK files (chunked) to `https://pelib.phishingeyes.com/v1`**. Legitimate anti-fraud purpose,
  but a high-privacy capability (full installed-app inventory + APK bytes leave the device). Behavior-sweep flagged
  it 6-cat incl. `evade`+`persist`+`dyn.load`.
- **interezen IPInside (저축).** `info/*` → `getHardwareAddress`/`getMacAddress`/`getConnectionInfo`/
  `getInstalledPackages` → `openConnection`. Client device/network fingerprint agent.
- **drfn/dooriworld chart (증권).** Chart data over **plain HTTP to a bare IP** (`218.38.18.171/smartPhone/*`) —
  same hygiene flag found earlier in M-STOCK; cross-app confirmed.
- Martech/attribution (Insider, Airbridge, Hackle, AppsFlyer) — expected analytics, listed for completeness.

**iSASService (G-7) whole-app closure:** grep of the full 저축/증권 jars shows **no host code
(`com.shinhan*`/`com.shinhaninvest*`) references `HttpListener`** — only Coocon's own package does → the bundled
local HTTPS server is confirmed **not started on-device**.

### Honest scope of the analyzer depth (do not over-claim)
- **Coocon carve** got the FULL mandated set (class-map + Joern source/sink + reachability + CodeQL + Semgrep +
  scope-closure + cross-verify) on both carriers.
- **Other flagged roots** got behavior-sweep + carve + `class-map.py` + endpoint identification (the fast deep pass
  that yields the SDK verdict). A full per-root Joern/CodeQL/scope-closure pass was **not** run on every root
  (~15 roots × up to 5 apps). Remaining mandated work (flagged): full CPG source→sink on the two high-privacy
  collectors **infinigru** (APK-upload path) and **interezen** (fingerprint→network).
- dex2jar hard-failed on 슈퍼SOL은행 + 카드 → their inventory is from the direct-dex root scan (presence-level), not a
  carved CPG. Alternate converter (e.g. `enjarify`/jadx-jar) is the follow-on to carve those two.

## Carved artifacts (local only)
`~/Downloads/coocon/carve_shinhansec_kr/` · `~/Downloads/coocon/carve_shinhanjeohuk_kr/` (kr/co/coocon class trees).
Not committed.

## Notes / gaps
- Other Shinhan-brand apps not in this pass (would extend coverage): 신한 SOL페이(모바일 결제) beyond the card app,
  any 신한 계열 sub-brands. 신한카드 신한SOL페이 (`com.shcard.smartpay`) is the card flagship and is NEGATIVE.
- 신한저축 base-dex raw-string count for `kr/co/coocon` (23) undercounts vs the 951 carved classes / 978 type-descriptor
  refs — the carve (dex2jar class tree) is authoritative, not the raw-string grep.
