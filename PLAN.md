# Project Plan & Roadmap

**Living status tracker + next actions.** Three tracks:
- **Track 0 — Method & skill** (the `sdk-carve` tooling; largely shipped).
- **Track 1 — Threat-intel: Goldoson-model lineage** (the `research/` study; ad-fraud SDK families 2023–2026).
- **Track 2 — Method-generalization study** (GitHub **issue #5**: does target-aware carving generalize across *unrelated* SDKs?).

**Inputs**
- Method: [`.claude/skills/sdk-carve/SKILL.md`](.claude/skills/sdk-carve/SKILL.md)
- TMAP deep-dive (n=1): [`analysis/reports/`](analysis/reports/); cross-app (n=11): [`docs/CROSS_APP_VALIDATION.md`](docs/CROSS_APP_VALIDATION.md)
- Anti-analysis: [`docs/ANTI_ANALYSIS.md`](docs/ANTI_ANALYSIS.md); pre-carve: [`docs/PRE_CARVE.md`](docs/PRE_CARVE.md); cross-family: [`docs/CROSS_FAMILY_COMPARISON.md`](docs/CROSS_FAMILY_COMPARISON.md)
- Lineage / corpus: [`research/`](research/); acquisition kit: [`research/acquisition/`](research/acquisition/)
- GitHub issue [#5](https://github.com/windshock/sdk-carve/issues/5)

> **Local workspace note.** Sample carves live in an uncommitted workspace
> (`goldoson-samples/analysis/`, `.../analysis/{konfety,mobidash}`). Samples are never committed.

---

## Track 0 — Method & skill  *(shipped; maintenance)*

- [x] Scoped bytecode CPG + CodeQL (`build-mode=none`) — TMAP deep-dive; native track (`ghidra2cpg`)
- [x] `detect.py` — auto-locate R8-renamed SDK roots (anchors + size/depth/denylist + structural fallback)
- [x] `carve.sh` — in-memory, **case-preserving** mini-JAR (survives `j.class`/`J.class` on case-insensitive FS)
- [x] **Pre-carve stage** (stage 0): `apk-normalize.py` (generic ZIP-tamper repair + payload flagging),
  `konfety-unpack.py` (XOR-asset), `mobidash-unpack.py` (SQLCipher + XOR modules) → [`docs/PRE_CARVE.md`](docs/PRE_CARVE.md)
- [x] SKILL.md: auto-detect, over-scoping gotcha, obfuscated-name fallback, pre-carve stage
- [ ] **Generalize the pre-carve payload stage** (Track 2 dependency): confirm Konfety seed rule / MobiDash
  XOR-const across more samples; factor shared bits out of the family-specific unpackers
- [ ] Machine-readable metrics output from carve + scope-closure (needed by Track 2)

---

## Track 1 — Threat-intel: Goldoson-model lineage

### Status snapshot (evidence-labeled)

| # | Result | Where |
|---|---|---|
| S1–S3 | sdk-carve on 11 Goldoson apps; R8-renamed 4-seg roots; every app ≥1 McAfee C2 | `CROSS_APP_VALIDATION.md` |
| S4 | 5 candidate domains → 1 Goldoson edge + 4 sibling-module backends | `ANTI_ANALYSIS.md` |
| S5–S6 | Goldoson guard = AES packet-capture blocklist, **identical 11/11** (same key) | `ANTI_ANALYSIS.md` |
| S7 | **SpinOk** carved: no packet-capture guard, AES/GCM; anti-analysis in bundled ad SDKs | `CROSS_FAMILY_COMPARISON.md` |
| S8 | **Konfety** (5): ZIP-tamper + decoy dex + XOR asset → **fully unpacked** → phantom-viewport engine | `PRE_CARVE.md` |
| S9 | **MobiDash** (Jamf c64db66f): SQLCipher(cert-key)+XOR modules → **fully unpacked** → same phantom-viewport engine | `CROSS_FAMILY_COMPARISON.md` |
| S10 | **Necro/Coral** acquired: 8 infected hosts (Wuta 6.3.2/4/5/6, Spotify 18.9.40.5, Max Browser 1.2.2–4; `libcoral.so`/`fkgh` confirmed) + clean Wuta 6.9.8.161 (version spread + infected→clean boundary); carve pending | `analysis/necro/` (local) |

**Finding:** Goldoson's packet-capture blocklist is unique; Konfety & MobiDash converge on
phantom-viewport + synthetic-touch click fraud via different packing (both statically recoverable).

### Phases
- [x] **A — Goldoson anti-analysis** (blocklist decrypt 11/11, domain reclassification, YARA)
- [~] **B — corpus acquisition** *(authorization-gated; kit `research/acquisition/`)*
  - [x] SpinOk (MalwareBazaar), Konfety ×5 (Hybrid Analysis), MobiDash (Triage)
  - [x] **Necro/Coral** — 8 infected + 1 clean via APKPure/apkfiles by hash (S10); Coral SDK carve pending
  - [ ] **Invisible Adware** — DMB TV (`com.project.onair`) sourced but turned out **benign ≠ IOC**; real
    `com.dmb.media`/`dmb.onair.media`/`band.kr.com`/`easy.kr` need VT/Koodous/AndroZoo (**droppable** — 5 families suffice)
  - [ ] SlopAds / Trapdoor (App-ID → AndroZoo) — **need `ANDROZOO_APIKEY`**
  - [ ] Goldoson historical infected→clean boundary (AndroZoo) — *research Final-priority #1*
- [x] **C — cross-family comparison** (4 families; anti-analysis + fraud-engine matrix) — Necro = 5th, carve pending
- [ ] **D — infrastructure correlation** (evidence-gated; C2/pDNS/cert — only with cited evidence)
- [ ] Konfety↔MobiDash **phantom-viewport code diff** (both engines now recovered — direct compare)
- [ ] Sample-generalize the unpackers across a Konfety/MobiDash version spread

---

## Track 2 — Method-generalization empirical study  *(GitHub issue #5)*

The academic question: does target-aware carving **generalize across unrelated SDKs** and
materially change deep-analysis feasibility? Distinct from Track 1 (which is one SDK-model family).

### Research questions
- **RQ1 Feasibility** — does carving let analyzers process targets that time out / OOM whole-app?
- **RQ2 Reduction** — classes / methods / size / CPG-DB size / time / peak memory (whole-app vs carved).
- **RQ3 Fidelity** — sources, sinks, entry→sink reachability, endpoints, sensitive APIs preserved?
- **RQ4 Generalizability** — unrelated families, multiple versions, hosts, R8/ProGuard, renames, damaged decompilation, big apps, lib-dependent SDKs.
- **RQ5 Boundaries** — reflection, dynamic class loading, JNI/native, framework-mediated flow, no clean boundary, shaded deps.

### Corpus
- **Phase 1 (diversity):** ~10 **unrelated** SDK families × ~10 apps ≈ 100 APKs — mix of ad / analytics /
  privacy-sensitive / malicious / heavily-obfuscated / old+modern. Per sample: sha256, package, version,
  source, date, family, SDK-version evidence, obfuscation traits. *(Do not redistribute APKs.)*
  - first benign general-SDK sample in hand: **DMB TV `com.project.onair`** ×5 (ExoPlayer/Firebase/
    YouTube-player/okhttp/ButterKnife) — `analysis/general_apps/` — good non-adfraud carve target.
- **Phase 2 (scale):** 20–30 families, several hundred APKs (AndroZoo useful, not required) — only if Phase 1 pays off.

### Experimental design (per target: baseline whole-app **vs** treatment carved)
Record: classes, methods, input size, analysis-completed?, runtime, peak memory, CPG/DB size, sources,
sinks, reachability. **Failures are data** (timeout / OOM / parser / extractor / incomplete graph / excessive runtime).

### Analyzer independence (claim must not depend on one engine)
- [ ] Joern / bytecode CPG (have) · [ ] CodeQL (have) · [ ] optional FlowDroid/Soot track

### Scope-completeness (per carved target)
- [ ] external-owner closure · record excluded libs · reverse-trace unresolved · boundary-vs-missed-logic ·
  manual subset inspection · **report known unsoundness** (reflection/dynamic loading break closure).

### Related-work matrix *(each answers a reviewer question)*
- [ ] **A. TPL detection** — LibScout (CCS'16), LibPecker (SANER'18), LibID (ISSTA'19), AndroLibZoo (MSR'24) →
  *"which library is present"* ≠ *"what analyzable subprogram should the analyzer see"*.
- [ ] **B. Slicing / static analysis** — **R-Droid (AsiaCCS'16, high-priority)**, FlowDroid (PLDI'14), CPG (S&P'14) →
  point/sink-driven slice vs reusable target-centered closure. *R-Droid is the key comparison — read + diff first.*
- [ ] **C. Context-aware narrowing** — DamFlow (TOSEM'25), TaskFlow (TOSEM'26), Alecci PhD'26, REPROCESS →
  pre-analysis universe reduction vs post-analysis result relevance.
- [ ] **D. Payload localization** — MalLoc (ICSME'25), RAML (ASE'25) → *rank suspicious code* vs *build the analysis universe* (complementary: localize → seed, carve → surround).
- [ ] **E. Corpus** — AndroZoo (MSR'24).

### Reviewer questions to answer with data
not-TPL-detector · not-just-slicing (R-Droid) · not-localization · analyzer-agnostic-feasibility · what's-preserved-vs-lost · generalizes-beyond-Goldoson.

### Immediate next steps (from issue #5)
- [x] Read + summarize **R-Droid**; document exact overlap/differences → [`docs/RELATED_WORK.md`](docs/RELATED_WORK.md) §B1
- [x] Build the related-work matrix (13/14 refs; TaskFlow PDF pending) → [`docs/RELATED_WORK.md`](docs/RELATED_WORK.md)
- [ ] Select 10 **unrelated** SDK families + define corpus metadata schema
- [x] Automate APK → detect → carve → analyze → **metrics** pipeline + whole-app baseline runner
  → [`research/metrics.sh`](research/metrics.sh), [`research/completeness_run.sh`](research/completeness_run.sh);
  results [`docs/METRICS.md`](docs/METRICS.md):
  - **COMPLETENESS (headline):** whole-app CPG *builds* but silently **omits the target SDK on 7/11 apps**
    (0–2% of its methods; 0 SDK sinks → false-negative detection); carved = **100%** on all 11.
  - RQ1 feasibility (patched frontend, 1 GB heap): whole-app **fails on all 8 apps measured**
    (timeout/OOM; smallest mafu 7.7k OOMs in 22 s, largest ~59k too; other 3 not re-run);
    carved succeeds 11/11 in 2.2–4.3 s.
  - RQ2 reduction (patched frontend, 12 GB): **54–429× fewer classes** (median 143×),
    **10–324× faster** (median 44×), **~10× less RAM**, CPG sub-1 MB vs 35–261 MB.
  - RQ3 fidelity: carved SDK method surface == whole-app SDK method surface **exactly, 11/11**.
- [~] Extend CodeQL cost/completeness cross-check across the corpus — **carved: all 11 apps**
  (21–29 s, 7–11 MB DB, 100 % SDK each; `research/codeql_carved_corpus.csv`). Whole-app: 2 apps
  with original APK (TMAP 542 s/2.5 GB, worldcup 220 s/207 MB) → carved ~9–22× faster, ~30–280×
  smaller. Whole-app on other 9 blocked by dex2jar→jadx source-damage confound (need original APKs).
  **Non-Goldoson generality done:** carved 4 benign SDKs (retrofit2/okhttp3/firebase/reactivex)
  from TMAP → 2–9 s (56–232× vs whole-app), method captured (`research/nongoldoson_carve.csv`).
  Remaining: original APKs for wider whole-app CodeQL set.
- [ ] Consistent timeout/OOM/failure recording; machine-readable scope-completeness output
- [ ] Generalize SDK-root detection beyond Goldoson-specific anchors
- [ ] Run Phase 1 (~100 APKs); analyze failures; **reassess the novelty claim**; decide on Phase 2

**Target claim (reframed after fixing joernio/joern#6257):**
> *Target-aware carving reduces the analysis universe and downstream cost/noise while preserving the
> selected SDK's security-relevant surface; paired whole-app vs carved validation can additionally
> expose silent toolchain failures, as demonstrated by joernio/joern#6257.*

The first clause is the project body (durable, frontend-agnostic): on the **fixed** frontend, carving
is 10–324× faster (median 44×), ~10× less RAM, and feasible at 1 GB where whole-app fails 11/11,
while preserving 100 % of the SDK method surface (RQ3); CodeQL corroborates the cost gap (~22×,
independent of the bug). The second clause is a **bonus case study**: comparing carved vs whole-app
surfaced a shipped silent-truncation bug in jimple2cpg (`FileUtil.unzipTo`), which we root-caused and
fixed upstream. *Not* elevated to a general "carving is an analyzer-bug oracle" thesis (one instance).
The earlier "whole-app is silently incomplete" headline is **demoted to that case study** — it was a
fixable bug, not a standing property.
Evidence: [`docs/METRICS.md`](docs/METRICS.md) (RQ1 1 GB fails 8/8 measured; RQ2 10–324×; RQ3 11/11 exact; case study #6257).

---

## Authorization gates

| Action | Gate |
|---|---|
| Local carves of samples already held | ✅ proceed |
| Sample/hash fetch (AndroZoo/MalwareBazaar/Hybrid Analysis/Triage/VT) | ⛔ per-step user OK (standing OK for Track 1 Phase B) |
| Network call to a candidate/known C2 | ⛔ explicit OK + isolated env (`AGENTS.md`) |
| Commit/push to the public repo | ⛔ explicit OK |

---

## Immediate next actions (consolidated — pick one)

1. **[done] Metrics pipeline** — completeness + RQ1 + RQ2 on the 11 Goldoson apps ([`docs/METRICS.md`](docs/METRICS.md)).
   **Next (recommended): analyzer independence — repeat completeness + RQ1/RQ2 on CodeQL** (whole-app CodeQL DB
   on 50k classes likely fails harder; confirms the claim isn't jimple2cpg-specific). Then extend to the other
   families in hand (SpinOk/Konfety/MobiDash/Necro/DMB-TV) and unrelated SDKs.
2. **Track 1:** Necro/Coral carve (anti-analysis `isAdb/isProxy/isSimulator/isDebug` + infected→clean diff);
   Konfety↔MobiDash phantom-viewport code diff — no new samples.
3. **Track 2 desk:** [done] R-Droid diff + related-work matrix (`docs/RELATED_WORK.md`); next = corpus schema + 10 families.
4. **Blocked on `ANDROZOO_APIKEY`:** SlopAds/Trapdoor + Goldoson historical + Phase-1 unrelated-family corpus
   (Invisible Adware also needs VT/Koodous — droppable).
