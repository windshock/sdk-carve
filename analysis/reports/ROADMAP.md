# Analysis backlog / roadmap (KR RASP supply-chain + offerwall)

Living actionable list for the analysis work (distinct from `PLAN.md`, which tracks the sdk-carve
method/tooling). Priority: **P1** = high value + low cost, **P2** = high value, needs setup, **P3** = later.
Status: `[ ]` todo · `[~]` in progress · `[x]` done · `[-]` dropped/blocked. Keep newest evidence inline.

---

## Execution sequence (gap-free, all remaining items) — set 2026-09-11
All P1 + the recommended-next-3 are done. Remaining P2/P3 are sequenced below so nothing is dropped;
executing top-down, recommendation-first. `[x]`=done this session.
1. [x] **C** — Adison SugarToken + allowlist → **C** vendor hardening docs (GAD/TNK/Adison) → **C** issue #5 writeup.
2. [~] **B** — [x] Coocon version diff (4 apps) → [ ] Coocon `updateScript` server endpoint/protocol → [ ] drfn plain-HTTP payload.
3. [ ] **A/D** — find_decryptor 32-bit + arg-recon → app string vault (Phase 3) → packer-detect Toss case.
4. [ ] **E/F** — consolidated KR-RASP memo (+ GAD iOS symmetry) → draft vendor notifications → Goldoson-TDI.
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
- [~] **P2 — fix `find_decryptor.py` arg reconstruction on newer engines.** Partly folded into the arm32
  work (reg-sim widened: movw/movt/add-pc/addw/ldr-lit/strd). MyHyundai (arm64 6.9.20.31, 0x24124) 0-string
  case still to retest with the widened arm64 reg-sim; deferred as a small follow-up.
- [x] **P2 — full payload decrypt + inventory across the fleet.** `payload_decrypt.py` run on all 12
  downloaded apps: mgmt server recovered 10/12 (2 oldest engines have different section0 framing) +
  plaintext base-apk SDK inventory for all 12. Results folded into XSHIELD_FLEET_SURVEY.md. Two
  corrections: (1) fxshield.co.kr is the shared default, dxshield.com = Mirae+IBK; (2) the app's real
  dexes are PLAINTEXT under this xShield variant (only loader+config encrypted). *Remaining sub-item:
  deep `sdk-carve` source→sink on the non-M-STOCK Coocon apps (IBK/신한/현대해상) — see B.*
- [ ] **P2 — app string vault (Phase 3) on one representative app** via unidbg d() → table dump →
  `vault_table_bruteforce.py` (build-specific offsets/seeds).

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
- [ ] **P3 — what the scraping scripts collect/exfil** — needs the server-supplied JS (dynamic run or
  captured module). Same "server code channel" risk framing as GAD BeanShell.
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
  *Remaining: iOS SDK (`gad-ios-sdk-syrup`) script-channel symmetry check.*
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
- [ ] **P2 — packer-detect: add the Toss in-house obfuscator case** (packer-detect blind → arsc fallback;
  already noted in sdk-carve SKILL field notes, wire a signature/heuristic).

## E. Reporting / outbound
- [ ] **P2 — consolidated KR-RASP supply-chain memo** (fleet + Coocon + AV/PKI patterns). Note: the SKP
  xShield 공급망 평가 proper is a **separate session** (`~/Downloads/xshield/`).
- [ ] **P3 — vendor notifications**: NSHC (xShield), Coocon (server-code channel govern), drfn (plain-HTTP).

## F. Low
- [ ] **P3 — Goldoson-TDI notii** service/view behavior + `tdi9.com` endpoint carve.

---

### Recommended next 3 (P1, cheap, high-leverage) — updated after channel confirmation
1. ~~Confirm the Coocon channel on IBK/신한/현대해상~~ **DONE** (channel present + identical in all 4).
2. **GAD api-doc cross-check** (C) → closes a long-standing vaulted-endpoint item with zero new setup.
3. **TNK cert-pinning check** (C) → the low↔medium decider for the deser surface.

*(Old "32-bit find_decryptor port" demoted to P2 — payload_decrypt already covers server+inventory.)*
