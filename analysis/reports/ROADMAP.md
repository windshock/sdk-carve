# Analysis backlog / roadmap (KR RASP supply-chain + offerwall)

Living actionable list for the analysis work (distinct from `PLAN.md`, which tracks the sdk-carve
method/tooling). Priority: **P1** = high value + low cost, **P2** = high value, needs setup, **P3** = later.
Status: `[ ]` todo · `[~]` in progress · `[x]` done · `[-]` dropped/blocked. Keep newest evidence inline.

---

## A. xShield fleet — deepen  (survey done: XSHIELD_FLEET_SURVEY.md, 14 apps)
- [ ] **P1 — 32-bit ARM (armeabi-v7a) port of `find_decryptor.py`.** Many KR financial apps ship v7a-only
  (M-STOCK, Kia, 신한, 현대캐피탈, 현대해상, SK증권). Same MBA decryptor + ABI, just ARM32 regs (r0–r5) +
  capstone/unicorn ARM mode. Unblocks native string-vault on ~half the fleet.
- [ ] **P1 — fix `find_decryptor.py` arg reconstruction on newer engines.** MyHyundai (6.9.20.31) auto-found
  the decryptor addr (0x24124) but reconstructed 0 static-buffer sites → 0 strings. Widen reg-sim / handle
  the 6.9.20.x call-site pattern.
- [ ] **P2 — full payload decrypt + sdk-carve on the rest.** Only M-STOCK deep-dived. Prioritize the
  Rhino-bearing (신한, 현대해상) and AhnLab-bearing (IBK, 신한). Reuse the oracle decrypt (→ see D).
- [ ] **P2 — app string vault (Phase 3) on one representative app** via unidbg d() → table dump →
  `vault_table_bruteforce.py` (build-specific offsets/seeds).

## B. Coocon SASAPI — server-script channel  (found: COOCON_SASAPI_TRIAGE.md)
- [ ] **P1 — Coocon presence/version across the Rhino-bearing apps** (신한, 현대해상): is it the same
  `kr.co.coocon.sasapi` engine + `updateScript` channel? cheap (grep decrypted dex / class-map).
- [ ] **P2 — recover Coocon `updateScript` server endpoint + protocol** (SEED-encrypted; behind config).
- [ ] **P3 — what the scraping scripts collect/exfil** — needs the server-supplied JS (dynamic run or
  captured module). Same "server code channel" risk framing as GAD BeanShell.
- [ ] **P3 — drfn/chart plain-HTTP (218.38.18.171/smartPhone/*.php)** — confirm payload of upload.php
  (chart data only vs account context); hygiene flag → vendor.

## C. Offerwall — resume (xShield deobf gate now cleared; skp-xshield-assessment is a separate session)
- [ ] **P1 — GAD api-doc ↔ capture cross-check** (`GPA-KOREA/gad-sample-android@syrup`): closes the
  vaulted-endpoint item without a pre-seal diff. (See GAD_API_RUNTIME_CAPTURE.md §공개 소스.)
- [ ] **P1 — TNK `SSLFactory` cert-pinning check** — the low↔medium decider for the deser surface
  (TNK_FULLPASS.md §5). HSTS ≠ pinning.
- [ ] **P2 — Adison SugarToken confirm** (Native-Ads SDK/docs) + `open/openExternal` domain allowlist
  request (TYRADS/ADISON triage §9).
- [ ] **P2 — vendor hardening request docs**: GPA(bsh 2.0b6+/channel integrity), TNK(loadClass allow-list /
  type-safe format / pinning), Adison(open/openExternal allowlist / v5 / drop dev+apiary-mock).
- [ ] **P2 — issue #5 (method generalization) writeup** — the 4 non-Goldoson offerwalls carved+CPG'd are
  the evidence. → PLAN.md Track 2.

## D. Skill / tooling improvements  (`.agents/skills/`)
- [ ] **P1 — generalize the payload section-decrypt into a tool** (`scripts/payload_decrypt.py`). Hand-wrote
  the oracle-brute C for OKC/PASS/M-STOCK each time; make it: find asset → section0 (package oracle) +
  section1 (PK oracle + offset scan + zip-EOCD) → classes.dex → SDK inventory. (Complements payload_triage.)
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

### Recommended next 3 (P1, cheap, high-leverage)
1. **32-bit ARM port of find_decryptor** → unlocks native vault on the v7a fleet half.
2. **Coocon presence/version across 신한·현대해상** (grep) → confirms the channel is a cross-app pattern.
3. **GAD api-doc cross-check** → closes a long-standing vaulted-endpoint item with zero new setup.
