# Analysis backlog / roadmap (KR RASP supply-chain + offerwall)

Living actionable list for the analysis work (distinct from `PLAN.md`, which tracks the sdk-carve
method/tooling). Priority: **P1** = high value + low cost, **P2** = high value, needs setup, **P3** = later.
Status: `[ ]` todo · `[~]` in progress · `[x]` done · `[-]` dropped/blocked. Keep newest evidence inline.

---

## Execution sequence (gap-free, all remaining items) — set 2026-09-11
All P1 + the recommended-next-3 are done. Remaining P2/P3 are sequenced below so nothing is dropped;
executing top-down, recommendation-first. `[x]`=done this session.
1. [x] **C** — Adison SugarToken + allowlist → **C** vendor hardening docs (GAD/TNK/Adison) → **C** issue #5 writeup.
2. [x] **B** — [x] Coocon version diff (4 apps) → [x] `updateScript` server endpoint/protocol → [x] drfn
   plain-HTTP → [x] **(9/12 deep-dive)** impact = in-process RCE → **live E2E RCE PoC reproduced on all 4 apps**
   → decompiler-resistance root-caused + custom ASM deobf → recovered `updateScript` pseudocode + 4 new protocol
   findings. Only **B-P3 (dynamic: what server JS collects/exfils)** remains, parked on runtime/server capture.
3. [x] **A/D** — [x] find_decryptor 32-bit + arg-recon (arm64 6.9.20.x 0→104 str; arm32 locates+len/key)
   → [x] app string vault (Phase 3, reproducible unidbg recipe) → [x] packer-detect Toss string-enc heuristic.
4. [x] **E/F** — [x] consolidated KR-RASP memo (+ GAD iOS symmetry) → [x] vendor notification drafts →
   [x] Goldoson-TDI notii service/view carve. **All ROADMAP items complete.**
> Blocked-on-dynamic (parked, needs runtime/server JS): B "what scraping scripts collect/exfil"; outbound
> vendor *sends* need explicit user auth (drafts only).

---

## A. xShield fleet — deepen  (survey done: XSHIELD_FLEET_SURVEY.md, 14 apps)
> **Re-prioritized after the fleet run:** `payload_decrypt.py` already recovers the mgmt server +
> full SDK inventory *without* the native vault (app dexes are plaintext), so the native-decryptor
> items drop from P1→P2 — they now only add native-side string IOCs (extra anti-analysis constants,
> any native-embedded URLs), not the primary supply-chain picture.
- [x] **P2 — 32-bit ARM (armeabi-v7a) port of `find_decryptor.py`.** DONE. Auto-detects arm64 vs
  arm/THUMB2; the ARM32 path locates the decryptor via the same seed (movw/movt) — validated M-STOCK v7a
  → 0x14a00 (308 sites) + len/key recovered. arm64 path regression-clean (bithumb 0x1eadc/21 str, IBK
  0x5dfc/34 str). **Honest limit**: arm32 ciphertext source is a function-scoped PIC anchor (`add rX,pc`/
  `ldr [sp]`) set outside the call-site window → full v7a string dump needs function-entry emulation
  (future); the decryptor *address* (the per-build unknown) + len/key are recovered. Documented in SKILL.md.
- [x] **P2 — fix `find_decryptor.py` arg reconstruction on newer engines.** DONE. Root cause: 6.9.20.x
  copies ciphertext from an `adrp+add` source via `ldr q,[xN]` into a stack buffer (x3=stack), so the old
  "buf=x3 in .text" path found nothing. Added source-candidate reconstruction (last `ldr [xN]` before the
  call) + scratch-buffer emulation. **MyHyundai 0x24124: 0 → 104 strings** (real RASP IOCs: /sbin/magisk,
  /topjohnwu/magisk, su paths, OAT/dalvik-cache, /proc/self probes). bithumb/IBK regression-clean.
- [x] **P2 — full payload decrypt + inventory across the fleet.** `payload_decrypt.py` run on all 12
  downloaded apps: mgmt server recovered 10/12 (2 oldest engines have different section0 framing) +
  plaintext base-apk SDK inventory for all 12. Results folded into XSHIELD_FLEET_SURVEY.md. Two
  corrections: (1) fxshield.co.kr is the shared default, dxshield.com = Mirae+IBK; (2) the app's real
  dexes are PLAINTEXT under this xShield variant (only loader+config encrypted). *Remaining sub-item:
  deep `sdk-carve` source→sink on the non-M-STOCK Coocon apps (IBK/신한/현대해상) — see B.*
- [x] **P2 — app string vault (Phase 3) on one representative app** — DONE/demonstrated. unidbg harness
  (`unidbg_DxShieldTest.java`, `[PHASE3]` via `d()`/`p()`) compiles clean against `.m2` (zhkl0228 unidbg
  0.9.10) — reproducible; prior full-vault artifact exists (`~/Downloads/xshield/analysis/
  xshield-vault-decrypted.txt`, local/uncommitted). Reproducible classpath recipe + the static-vs-dynamic
  completeness comparison (find_decryptor 21–104 discrete strings vs unidbg full-vault) added to
  references/harness-recipes.md §10. This is also the correct route for arm32 v7a full dumps.

## B. Coocon SASAPI — server-script channel  (found: COOCON_SASAPI_TRIAGE.md)
- [x] **P1 — Coocon presence across the Rhino-bearing apps.** Confirmed: same `kr.co.coocon` engine in
  **M-STOCK, IBK, 신한, 현대해상** (~700–1400 refs each) + a 10-ref stub in SK증권. Table in
  COOCON_SASAPI_TRIAGE.md.
- [x] **P1 — confirm the `updateScript`→Rhino `eval` CHANNEL (not just the package) on IBK/신한/현대해상.**
  DONE. Carved `kr/co/coocon` from the plaintext base apks: all 4 apps have byte-identical
  `sasapi/scriptengine/{ScriptEngine,V8ScriptEngine}` + `sasapi/script/ScriptManager` +
  `ConnectionFailed/ScriptNotFound` exceptions + matching updateScript/loadScript/evaluateString/Socket
  counts. Channel present + identical in all 4 (M-STOCK also CPG-flow-verified). New detail: Coocon runs
  scripts on **Rhino OR V8**. Written up in COOCON_SASAPI_TRIAGE.md.
- [x] **P2 — recover Coocon `updateScript` server endpoint + protocol** — DONE. Server `isas.coocon.co.kr:443:80`
  (svc `PUSANAPP`/type `A`), devel fallback `183.111.160.145` via `devel.mode`/`local.ip` system-property
  override (script-source redirect knob), auth-txn `http://59.6.190.44:8900/cgi/sidea.authtr.cgi` (plain HTTP),
  local proxy `127.0.0.1:1024/1025`. Protocol: HTTP GET/POST, `+`-joined script names + 10-digit versions,
  SEED-decrypted JS → Rhino/V8. No pin observed. Folded into COOCON_SASAPI_TRIAGE.md.
- [x] **P1 — impact of the channel (answering "is only JS executed?")** — DONE (2026-09-12). The engine sets
  `initSafeStandardObjects` but **no `setClassShutter`**, so a server script escapes to **arbitrary in-process
  Java** via `getClass().forName('java.lang.Runtime')…`. Not "just JS" — full in-process code exec (and via the
  app's own injected `com.miraeasset.main.dc` it bridges to the app's secure-key crypto). Written up in
  COOCON_SASAPI_TRIAGE.md §Sandbox strength + IMPACT analysis.
- [x] **P1 — LIVE end-to-end active-MITM RCE PoC — reproduced on ALL 4 apps** — DONE (2026-09-12). ByteBuddy MITM
  lab drives each app's own dex2jar'd `ScriptManager.updateScript` + `ScriptEngine` vs a localhost mock: MITM reads
  the cleartext request seed → `key=SHA-256(seed)[0:16]` → forges `[6-len]["02"][seed][AES(GZip(JSON))]` → real
  `AESCipher.decrypt`+`GZip.unzip`+`JSONParser` accept it → script **stored** → real `ScriptEngine.a()` Rhino
  `evaluateString` → `Runtime.exec` (proof file). **M-STOCK / 신한(com.shinhan.spbs) / IBK(com.ibk.scbs) /
  현대해상(m.hi.co.kr) = 4/4 `store=1 eval=1 RCE=YES`.** All identical preconditions (default iface `"02"`, same
  `isas.coocon.co.kr:443` plain TCP, no signature/MAC, no `ClassShutter`); 신한 & 현대해상 needed `android.jar`
  only for their request-build device-info (emulation-env gap, not a control). Lab/proof local, uncommitted.
- [x] **P2 — defeat `updateScript` decompiler-resistance + recover source** — DONE (2026-09-12). All 5 decompilers
  (CFR/Vineflower/Fernflower/Corpseflower/jadx) fail; root cause = 2-layer obfuscation (exception-table flattening:
  1033 entries/225 ranges/~40 shared `ASTORE;GOTO` stubs/295 non-throwing traps + irreducible flow via
  backward-GOTO finally-ladders). Built reusable ASM normalizer (`.agents/skills/sdk-carve/scripts/
  ExFlattenNormalize.java`: `--redundant`/`--split`/`--unify`) → CFR decompiles clean. Recovered source confirms
  the reversed protocol 1:1 (key=SHA-256(seed)[0:16] at source level) + **4 new findings**: legacy `"01"` arm =
  plaintext GZip (no AES, even easier to forge); `"02"` client ignores response `[0:22]` (key from request seed
  only); `"0001"`=delta/up-to-date + no version-monotonicity check → MITM `"0000"`+malicious forces store
  regardless of cached version (downgrade). Folded into COOCON_SASAPI_TRIAGE.md + SKILL.md.
- [-] **P3 — what the scraping scripts collect/exfil** — **PARKED (not now, per 2026-09-12 decision).** Needs the
  server-supplied JS (dynamic run or live server capture); the design-level risk is already fully established.
  Same "server code channel" framing as GAD BeanShell. Re-open only if a runtime/server capture becomes available.
- [x] **P3 — drfn/chart plain-HTTP (218.38.18.171/smartPhone/*.php)** — DONE. `upload.php` multipart sends
  the chart image + `userId`/`userIp`/`deviceID` + charted `symbol`/`codeName`/`lcode` + `title`/`detail`
  memo; `delete.php` sends `deviceID` in the query. Cleartext HTTP to a hardcoded 3rd-party IP inside a
  brokerage app. Not creds/orders (it's the 공유차트 share feature) but identifiers+watchlist in plaintext
  = confirmed privacy/hygiene flag. Written up in COOCON_SASAPI_TRIAGE.md.

## C. Offerwall — resume (xShield deobf gate now cleared; skp-xshield-assessment is a separate session)
- [x] **P1 — GAD api-doc ↔ capture cross-check** (`GPA-KOREA/gad-sample-android@syrup`). DONE. Public
  README/api-doc/guide_cpa document only the standard offerwall CRUD (`/campaign/{list,join,status,
  complete}` + `/advertisement`, type **0–4**, no headers). The captured `setup`/`prepare2`/`script/entry`
  lifecycle, `type=5` CPS, `x-tdi-client-secret`, and the BeanShell/eval channel are **absent from all
  public docs** → the covert channel is undocumented-to-integrators; item closed by public-doc absence.
  Bonus: README pins `syrup-0.8.0-rc.12` = my runtime capture → rc.4/rc.12 skew resolved.
  *(iOS SDK script-channel symmetry check — DONE, see E: v0.1.9 XCFramework is asymmetric, no interpreter.)*
- [x] **P1 — TNK `SSLFactory` cert-pinning check** — DONE. `SSLFactory` = `SSLContext.init(null,null,
  null)` (default system-CA trust, TLS-only, forced https) with NO pinning; `PacketService`/`VideoCache`
  wire it via `setSSLSocketFactory` and set no HostnameVerifier. The trust-all `NullHostNameVerifier` is
  confined to `TnkAssert` self-test (not wired to production). Verdict: **unpinned → deser decider =
  medium confirmed** (not trivially MITM-able, but no pinning defense-in-depth). Written up in
  TNK_FULLPASS.md §4.1. Pinning is now an evidence-backed line in the hardening ask.
- [x] **P2 — Adison SugarToken confirm + `open/openExternal` allowlist** — DONE. SugarToken = server-session
  term for the `setUid` uid (0 binary refs / not in SDK docs / not on web) → no client artifact. Bridge
  re-decompiled: corrected two triage overstatements — web bridge is ~9 methods (not 3), and URL handling
  is structured scheme-dispatch (adison-scheme host-gated), NOT blind loadUrl. Real residual surface =
  `intent:` `Intent.parseUri` redirection + web-specified packageName + no http/inappbrowser domain
  allowlist. Folded into ADISON_SDK_TRIAGE.md §7/§9; hardening asks feed the next item.
- [x] **P2 — vendor hardening request docs** — DONE. Consolidated `VENDOR_HARDENING_REQUESTS.md` with
  evidence-backed asks per vendor: GPA GAD (disclose+constrain the BeanShell channel, pin/sign scripts),
  TNK (class allow-list / type-safe format / cert pinning / drop NullHostNameVerifier), Adison (domain
  allowlist / constrain intent: scheme / validate packageName / drop dev+apiary-mock), Coocon+banks
  (script signing + endpoint pinning + govern as supply-chain code channel). Includes an outreach-priority
  table. Sends remain gated on explicit auth (E-P3).
- [x] **P2 — issue #5 (method generalization) writeup** — DONE. `ISSUE5_GENERALIZATION.md` maps the
  accumulated carves (GAD/Syrup-ob/SK-Planet-bb8/TNK×2/Tyrads/Adison/Coocon + Toss negative) onto RQ4's
  axes (unrelated families, multi-version, R8/renames, packed/damaged decompilation, big apps, lib-dep,
  analyzer-agnostic). Verdict: generalizes wherever code is recoverable; the two honest limits (carve
  finds class not always behavior; packing can block carve) stated. → PLAN Track 2.

## D. Skill / tooling improvements  (`.agents/skills/`)
- [x] **P1 — generalize the payload section-decrypt into a tool** (`scripts/payload_decrypt.py`). Built:
  finds asset → section0 package-oracle (config/server) + section1 PK-oracle+offset-scan+zip-EOCD →
  component classes.dex → SDK-root inventory + Rhino/Coocon/AV/PKI auto-flags. Compiles a throwaway C
  brute for the 2^32 seed. Complements payload_triage (no-decrypt) with the actual decrypt.
- [ ] **P1 — find_decryptor 32-bit + arg-recon** (see A). 
- [x] **P2 — packer-detect: add the Toss in-house obfuscator case** — DONE. Added a signature-free
  readable-string-density heuristic (`string_encryption_indicators`): large real-code dex + near-zero
  readable strings (words/desc per-MB ~50× below normal) → verdict DEGRADED (exit 10), "In-house DEX
  string encryption (Toss-class)". Validated: Toss 5.276.0 → flagged (7.9 words/MB, 313MB dex); plaintext
  control not false-positived (50× margin). In packer-detect.py + SKILL.md field note.
- [x] **P2 — reusable exception-flattening deobfuscator** (`scripts/ExFlattenNormalize.java`) — DONE (2026-09-12).
  ASM normalizer for methods that defeat all decompilers via exception-table flattening + irreducible flow:
  `--redundant` (drop non-throwing traps) / `--split` (node-split terminal blocks → reducible) / `--unify`
  (handlers → one try+multi-catch); strips Java-6 frames, `COMPUTE_MAXS`. Cracked Coocon `updateScript`
  (CFR 0 failures after). Methodology bullet + error-evolution signal in SKILL.md.

## E. Reporting / outbound
- [x] **P2 — consolidated KR-RASP supply-chain memo** — DONE. `KR_RASP_SUPPLY_CHAIN_MEMO.md` synthesizes
  the fleet + the two server-code channels (Coocon JS / GAD BeanShell) + AV/PKI/adtech/drfn patterns +
  actions. Includes the **GAD iOS symmetry** resolution: iOS SDK (v0.1.9 XCFramework) is asymmetric — shares
  API host + TDI but ships no script interpreter (WKWebView evaluateJavaScript only, no JSContext/BeanShell)
  → the RCE-by-design channel is Android-only. Folded into GAD_API_RUNTIME_CAPTURE.md too.
- [-] **P3 — vendor notifications SEND** — **PARKED (not now, per 2026-09-12 decision).** Drafts DONE
  (`VENDOR_NOTIFICATION_DRAFTS.md`, ready-to-send for NSHC, Coocon+host banks, drfn+Mirae, GPA GAD, TNK/Adison).
  Actual sending stays gated on explicit user sign-off (recipient/channel/timeline); no samples in first contact.

## F. Low
- [x] **P3 — Goldoson-TDI notii** service/view behavior + `tdi9.com` endpoint carve — DONE (local
  workspace `goldoson-samples/analysis/TDI_NOTII_FINDING.md §8`). notii = full geo-targeted push/overlay
  ad engine: `NotiIForegroundService` (foreground svc + location) + `view/` (push/overlay via
  SYSTEM_ALERT_WINDOW, consent, weather cover) + network (Campaign/Impression/Adx) → /config→/campaign→
  /impression on tdi9.com/notii.net/appservice9.com. Bundled under the Goldoson root; behavior = ad
  delivery, not Goldoson-core C2. (Local finding — samples never committed.)

## G. Coocon fleet expansion + iSAS carrier corpus  (COOCON_FLEET_CANDIDATES.md)  — ACTIVE
Reframed from "Coocon customer" OSINT to **iSAS/smart-scraping supply history + code-lineage (dev-family)**;
`sasapi==Coocon iSAS` closed in binary (`iSASXecure` class). Acquire→`coocon-fingerprint.sh`→deep-confirm.
- [x] **fingerprint tool + candidate tracker** — `scripts/coocon-fingerprint.sh` (exit 0/1/3/4; packing-aware),
  `COOCON_FLEET_CANDIDATES.md` with the L0–L5 evidence framework and strict claim scoping.
- [~] **fleet sweep (53 APKs fingerprinted, 6 batches incl. VT domain-pivot)** — **37 L3 carriers** (all →
  `isas.coocon.co.kr:443:80`) across **finance / expense / 지역화폐 / healthcare / mobility / portal(NAVER)**; 8
  negatives (server-side/ASP), 8 INDETERMINATE (AppIron-packed), 9 pending. Scoping honest: **37 L3 / 6 L4 / 4 L5.**
  Method ranking (evidence): VT-domain pivot (9/9 observed) > dev-family > supplier OSINT.
- [~] **G-3 build-family (subtree-hash) — the highest-leverage item** — method VALIDATED: identical sasapi
  class-inventory clusters cross-industry+cross-vendor (**M-STOCK≡CheckPay≡OSB** =105-class build; **IBK≡현대해상**
  =108; 신한=112; 창원=97). Turns "37 apps" into a few shared iSAS builds = supply-chain result. **Blocker:** quick
  extractor reads jars/plain-APK only (returns 0 on XAPK) → needs a robust dex class-def parser (dexdump/dex2jar).
- [ ] **G-1 AppIron unpacking** — 8 INDETERMINATE staged at `~/Downloads/AppIron/` (`UNPACK_PLAN.md`). Goal =
  recover runtime L3 evidence (any of `sasapi.*`/`SASManager`/`iSASXecure`/`isas.coocon.co.kr` in loaded code),
  NOT a generic unpacker. Approach: frida-dexdump / unidbg emul of `libAppIron-jni`. **PREPARED, not started.**
- [ ] **G-2 acquire the pending-9** (official-channel APK / `APKMD_CLI`): 메디팜핏 (P0, L2), 세모리포트, 신협기업,
  ACT, BNK캐피탈, 보맵플래너, 비씨카드 비즈플레이, 서울Pay+, 제주 탐나는전.
- [ ] **G-4 L3→L4** on one representative app per build-family (javap b/sig/ClassShutter) → then **G-5 vendor
  disclosure** scoped by build-family representative. (Growing 37→50 < proving how few builds they collapse into.)

---

### Status (2026-09-12) — tracks A–F CLOSED; track G ACTIVE
**A–F done.** The Coocon deep-dive went beyond scope: impact = in-process RCE, **live E2E RCE on all 4 original
apps**, decompiler-resistance defeated (reusable ASM deobfuscator), `updateScript` source recovered.

**Then the fleet expanded into a corpus effort (track G, ACTIVE):** 28 iSAS carriers confirmed at L3; the next
lever is **G-1 AppIron unpacking** (8 packed candidates staged, not started).

**Parked (external gate):** B-P3 (server-JS exfil — needs runtime/server capture); E-P3 (vendor-notification
send — needs explicit sign-off).
