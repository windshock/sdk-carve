# Analysis backlog / roadmap (KR RASP supply-chain + offerwall)

Living actionable list for the analysis work (distinct from `PLAN.md`, which tracks the sdk-carve
method/tooling). Priority: **P1** = high value + low cost, **P2** = high value, needs setup, **P3** = later.
Status: `[ ]` todo · `[~]` in progress · `[x]` done · `[-]` dropped/blocked. Keep newest evidence inline.

---

## A. xShield fleet — deepen  (survey done: XSHIELD_FLEET_SURVEY.md, 14 apps)
> **Re-prioritized after the fleet run:** `payload_decrypt.py` already recovers the mgmt server +
> full SDK inventory *without* the native vault (app dexes are plaintext), so the native-decryptor
> items drop from P1→P2 — they now only add native-side string IOCs (extra anti-analysis constants,
> any native-embedded URLs), not the primary supply-chain picture.
- [ ] **P2 — 32-bit ARM (armeabi-v7a) port of `find_decryptor.py`.** Many KR financial apps ship v7a-only.
  Same MBA decryptor + ABI, just ARM32 regs (r0–r5) + capstone/unicorn ARM mode. Native string-vault only.
- [ ] **P2 — fix `find_decryptor.py` arg reconstruction on newer engines.** MyHyundai (6.9.20.31) auto-found
  the decryptor addr (0x24124) but reconstructed 0 static-buffer sites → 0 strings. Widen reg-sim / handle
  the 6.9.20.x call-site pattern.
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
- [ ] **P2 — recover Coocon `updateScript` server endpoint + protocol** (SEED-encrypted; behind config).
- [ ] **P3 — what the scraping scripts collect/exfil** — needs the server-supplied JS (dynamic run or
  captured module). Same "server code channel" risk framing as GAD BeanShell.
- [ ] **P3 — drfn/chart plain-HTTP (218.38.18.171/smartPhone/*.php)** — confirm payload of upload.php
  (chart data only vs account context); hygiene flag → vendor.

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
- [ ] **P2 — Adison SugarToken confirm** (Native-Ads SDK/docs) + `open/openExternal` domain allowlist
  request (TYRADS/ADISON triage §9).
- [ ] **P2 — vendor hardening request docs**: GPA(bsh 2.0b6+/channel integrity), TNK(loadClass allow-list /
  type-safe format / pinning), Adison(open/openExternal allowlist / v5 / drop dev+apiary-mock).
- [ ] **P2 — issue #5 (method generalization) writeup** — the 4 non-Goldoson offerwalls carved+CPG'd are
  the evidence. → PLAN.md Track 2.

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
