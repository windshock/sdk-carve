# Project Plan & Roadmap

**Living status tracker + next actions for the whole project.** Two tracks: the
**sdk-carve method/skill** (largely shipped) and the **Goldoson anti-analysis research**
(the forward frontier). This file records where we are and what to do next; it does not
restate the reference docs.

**Inputs**
- Method (how we carve/verify one SDK): [`.claude/skills/sdk-carve/SKILL.md`](.claude/skills/sdk-carve/SKILL.md)
- TMAP worked example (n=1 deep-dive): [`analysis/reports/`](analysis/reports/), esp. `TRACK3_DATAFLOW.md` §9
- Cross-app validation (n=11): [`docs/CROSS_APP_VALIDATION.md`](docs/CROSS_APP_VALIDATION.md)
- Lineage / corpus recipes: [`research/goldoson-like-android-ad-sdk-malware-lineage.md`](research/goldoson-like-android-ad-sdk-malware-lineage.md)
- Corpus availability + acquisition roadmap: [`research/goldoson-like-android-ad-sdk-malware-corpus-and-lineage.md`](research/goldoson-like-android-ad-sdk-malware-corpus-and-lineage.md)

> **Local workspace note.** The 11-sample Goldoson carve lives in a separate, uncommitted
> corpus workspace (`goldoson-samples/analysis/` — the McAfee sample set), not in this repo.
> Artifacts referenced below (`BATCH_REPORT.md`, `batch/<app>/out/`, `detect.py`) are there.

The single research question (reference docs §20 / "Final research priorities"):

> **Was Goldoson's installed packet-capture / traffic-analysis app detection an isolated
> implementation, or part of a reusable SDK/code lineage traceable before or after 2023?**

---

## Track 0 — sdk-carve method & skill  *(shipped; maintenance only)*

- [x] Scoped bytecode CPG + CodeQL (build-mode=none) method — TMAP deep-dive
- [x] Native track (`ghidra2cpg`) for `.so`/`.dll`/`.exe`
- [x] **`detect.py`** — auto-locate R8-renamed SDK roots (anchors + size/depth/denylist
  guards + structural fallback), validated on all 11 samples *(merged, PR #1)*
- [x] **Pre-carve stage** — `apk-normalize.py` (generic ZIP-tamper repair + payload flagging)
  and `konfety-unpack.py` (payload decrypt); handles Konfety/SoumniBot malformed/packed APKs
  that defeat bytecode discovery → [`docs/PRE_CARVE.md`](docs/PRE_CARVE.md)
- [x] SKILL.md: Step-0 auto-detect, over-scoping gotcha, obfuscated-method-name fallback, pre-carve stage
- [ ] Optional: fold the batch drivers (`detect_all.sh`/`carve_all.sh`/`batch.sc`) into the
  skill as a `scripts/batch.sh` once a second corpus (Phase B) exercises them

---

## Current status snapshot (evidence-labeled)

| # | Result | Confidence | Where |
|---|---|---|---|
| S1 | sdk-carve works on 1 huge app (TMAP, 50k→117 classes) | binary-confirmed | `analysis/reports/`, `docs/` |
| S2 | Generalizes to all 11 samples; per-app **R8-renamed 4-seg `com/a/b/c`** root; `detect.py` auto-locates it | binary-confirmed | `docs/CROSS_APP_VALIDATION.md` |
| S3 | Every app hardcodes ≥1 McAfee C2 domain (17 distinct) | binary-confirmed | `docs/CROSS_APP_VALIDATION.md` |
| S4 | 5 **new** candidate domains beyond McAfee's 27 (`appservice9.com`, `trs.bestsmartshop.net`, `retoore.com`, `barivemi.net`, `huejura.com`) | binary-derived candidate IOC; **infra correlation pending** | research lineage doc §"Your five candidate indicators" |
| S5 | Anti-analysis guard = AES-256/CBC (key `aoKoVu…`, zero IV) decrypt of 5 packet-capture app names → abort collection if installed | binary-confirmed (TMAP) | `analysis/reports/TRACK3_DATAFLOW.md` §9 |
| S6 | **Same hardcoded AES key + guard class in 9/11 apps** (absent in carved scope of `com.appsnine.audiorecorder`, `mafu.driving.free`); blocklist always encrypted | binary-confirmed (this run) | `goldoson-samples/analysis/` guard probe |

**The 5 blocklisted apps (TMAP, decrypted):** `app.greyshirts.sslcapture`,
`com.ddm.iptools`, `com.myprog.netscan`, `com.myprog.netutils`,
`jp.co.taosoftware.android.packetcapture`.

---

## Phase A — Goldoson anti-analysis deep characterization  ✅ *done → [`docs/ANTI_ANALYSIS.md`](docs/ANTI_ANALYSIS.md)*

- [x] **A1 — Decrypt the blocklist across all 11 apps.** **11/11 identical**: same AES-256
  key, same ciphertext, same 5 packet-capture apps (`app.greyshirts.sslcapture`,
  `com.ddm.iptools`, `com.myprog.netscan`, `com.myprog.netutils`,
  `jp.co.taosoftware.android.packetcapture`). Byte-identical → single shared SDK source.
- [x] **A2 — Guard in the 2 outliers.** Present in `audiorecorder`/`mafu` too, but in the
  shaded-lib package (`e/…`, `d/e/a/a/…`) the carve's size/depth guard excludes — confirmed
  from the full app jar. Scope boundary, not absence.
- [x] **A3 — Guard implementation extracted** (`c/c.l()` Gson-JSON → `e.a()` AES → `f()`
  isInstalled → short-circuit). Documented.
- [x] **A4 — Hunt YARA shipped** (AES key + identical ciphertext fragments + JSON marker).
- [x] **A5 — Candidate domains classified.** 4/5 are backends of **sibling bundled ad
  modules** (notii push, S_MALL shopping), not Goldoson C2; only `barivemi.net` is Goldoson
  core (edge endpoint). Corrects "5 new C2" → "1 edge + 4 sibling-module backends."

---

## Phase B — Corpus acquisition  *(AUTHORIZATION-GATED — do not auto-run)*

Fetching samples/hashes from AndroZoo / MalwareBazaar / Koodous / Triage is outward-facing
and gated by `AGENTS.md`. **Each fetch needs explicit per-step user OK.** Order by seed
quality (corpus doc §16–17).

Kit: [`research/acquisition/`](research/acquisition/) (`seeds.csv` + `fetch.sh`, tries
HA → MalwareBazaar → AndroZoo). Keys loaded: `MB_APIKEY`, `HYBRIDANALYSIS_APIKEY`
(auth_level 100 = downloadable). AndroZoo still pending (academic-gated).

- [ ] **B1 — Goldoson historical (P0-A, the novel part).** McAfee packages → AndroZoo →
  **infected→clean version boundary** → when the blocklist and the 5 domains first appear.
  *(Final priority #1.)* **Blocked on `ANDROZOO_APIKEY`.**
- [x] **B2 — SpinOk (P0-B).** `3745e0fb…` (MalwareBazaar) carved: SDK has **no packet-capture
  guard**, AES/GCM (vs Goldoson AES/CBC); sensor/emulator anti-analysis is in co-bundled ad SDKs.
- [x] **B3 — Konfety (P0-E).** 5 samples via **Hybrid Analysis** (sha256-verified). Distinct
  packaging-layer branch — **fully unpacked statically** via the new pre-carve stage: ZIP
  tamper (fake enc flag + fake `0x0C` method) repaired, asset XOR-decrypted
  (`Random(asset+0xFFFF)`) → identical 6,777-class payload (InMobi + com.adcommercial/gnet/
  nextg, install-referrer gating, C2 api.jetengine.be/one.upyourphone.me). →
  [`docs/PRE_CARVE.md`](docs/PRE_CARVE.md), [`docs/CROSS_FAMILY_COMPARISON.md`](docs/CROSS_FAMILY_COMPARISON.md).
- [ ] **B4 — MobiDash (P0-H).** Jamf hashes not on MalwareBazaar/HA → AndroZoo.
- [ ] **B5 — SlopAds / Trapdoor (P0-G/I).** App-ID → AndroZoo from official HUMAN lists.
- [ ] **B6 — Invisible Adware / Necro (P0-C/D).** Not on MalwareBazaar/HA → AndroZoo (Necro md5→sha256 first).

---

## Phase C — Cross-family sdk-carve + normalized dataset

- [ ] **C1** Run sdk-carve (`detect.py`→carve→CPG→source/sink→closure; native track for packed `.so`) per family.
- [ ] **C2** Populate the normalized schema (corpus doc §18): `family, sha256, host_package,
  sdk_package, sdk_entrypoint, remote_config, c2, installed_apps, location, wifi, bluetooth,
  hidden_webview, ad_click, dynamic_loader, proxy, anti_debug, anti_emulator, anti_proxy,
  anti_root, **anti_analysis_apps**, …`.
- [ ] **C3** Anti-analysis evolution comparison: Goldoson pkg-detection → SpinOk sensor →
  Necro isAdb/isProxy → SlopAds debug/emulator/root → MobiDash `Proxy.NO_PROXY`.

---

## Phase D — Infrastructure correlation  *(evidence-gated)*

- [ ] **D1** Retain only evidence-backed infra artifacts (C2, Firebase IDs, TLS certs, pDNS,
  ASN, first/last-seen). No shared-operator inference from shared hosting/CDN. Candidate
  domains stay "correlation pending" until pDNS/cert evidence exists.

---

## Authorization gates (explicit)

| Action | Gate |
|---|---|
| Phase A (local carved samples we already hold) | ✅ no gate — proceed |
| Any sample/hash fetch from AndroZoo/MalwareBazaar/Koodous/Triage/VT (Phase B) | ⛔ explicit per-step user OK |
| Any network call to a candidate/known C2 domain | ⛔ explicit OK + isolated env (`AGENTS.md`) |
| Committing/pushing research to the public repo | ⛔ explicit OK |

---

## Immediate next action

Phase A is complete ([`docs/ANTI_ANALYSIS.md`](docs/ANTI_ANALYSIS.md)). **Decision point:
Phase B go/no-go.** Phase B (corpus acquisition) is authorization-gated — it fetches
malware samples/hashes from AndroZoo/MalwareBazaar/etc. Await explicit user OK before B1.
Cheapest first novel step once approved: **B1** (Goldoson historical infected→clean
boundary via AndroZoo) to date when the blocklist + domains first appear.
