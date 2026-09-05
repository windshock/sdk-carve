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
| S10 | **Necro/Coral** carved: IOC boundary confirmed (`com/coral/Coral`+`libcoral.so` in Wuta 6.3.2–6.3.6 / Spotify / Max Browser; **absent in clean Wuta 6.9.8.161**; gbwhatsapp = not-Necro). Java loader carved (660 cls, CPG 3.3 s): obfuscated + **runtime string encryption**; `com.coral.vmout.CoNativ.load(…File…)` native second-stage + `URL.openConnection` + AES `Cipher.doFinal` + reflective `Method.invoke` + `ProcessBuilder.start` | `CROSS_FAMILY_COMPARISON.md`; `analysis/necro/` (local) |

**Finding:** Goldoson's packet-capture blocklist is unique; Konfety & MobiDash converge on
phantom-viewport + synthetic-touch click fraud via different packing (both statically recoverable).

### Phases
- [x] **A — Goldoson anti-analysis** (blocklist decrypt 11/11, domain reclassification, YARA)
- [~] **B — corpus acquisition** *(authorization-gated; kit `research/acquisition/`)*
  - [x] SpinOk (MalwareBazaar), Konfety ×5 (Hybrid Analysis), MobiDash (Triage)
  - [x] **Necro/Coral** — 8 infected + 1 clean via APKPure/apkfiles by hash (S10); **Coral Java loader carved** (660 cls; behavior fingerprint recovered — see S10 / `CROSS_FAMILY_COMPARISON.md`)
  - [ ] **Invisible Adware** — DMB TV (`com.project.onair`) sourced but turned out **benign ≠ IOC**; real
    `com.dmb.media`/`dmb.onair.media`/`band.kr.com`/`easy.kr` need VT/Koodous/AndroZoo (**droppable** — 5 families suffice)
  - [ ] SlopAds / Trapdoor (App-ID → **resolver**: mirror history / AndroZoo) — no longer AndroZoo-only;
    standalone-flagged variants may still need MalwareBazaar/Triage/VT
  - [ ] Goldoson historical infected→clean boundary — via **resolver** (mirror version history), same
    pattern as Necro/DMB-TV; AndroZoo optional for citable metadata — *research Final-priority #1*
- [x] **C — cross-family comparison** (**5 families**; anti-analysis + fraud-engine matrix) — Necro/Coral carved (native-second-stage loader branch)
- [ ] **D — infrastructure correlation** (evidence-gated; C2/pDNS/cert — only with cited evidence)
- [x] Konfety↔MobiDash **phantom-viewport code diff** — direct class-level compare: Konfety
  `com.adcommercial.utils.xOnUc` (1 class) vs MobiDash `com.stwdi…jdhcc.jdhcc.{HqJz25,…}` (5 classes),
  different packages/scale → **technique lineage, not shared code** (`CROSS_FAMILY_COMPARISON.md`)
- [ ] Sample-generalize the unpackers across a Konfety/MobiDash version spread

---

## Track 2 — Resource-bounded, target-centric analysis of embedded SDKs  *(GitHub issue #5)*

**Positioning (converged).** Not "SDK carving is a new algorithm" (it isn't — cf. slicing / R-Droid).
The paper-worthy question is:

> **How much application context is actually necessary to *faithfully* analyze a third-party SDK
> embedded in an Android app, and where does target-centric reduction stop being faithful?**

Framing that dodges the "this is just slicing" attack:
- **Supply-chain unit of analysis.** The target is not the app — it is a component **repeated across
  many host apps** (Goldoson/SpinOk/Konfety/MobiDash/Necro). Re-running whole-app analysis per host
  is wasteful **in aggregate**; the natural unit is the SDK. (Tension we *observed and turn into a
  finding:* SDKs are **re-obfuscated per host** — Goldoson per-app R8 renames, Necro per-build name
  randomization — so it's carve-**and-reanalyze per host**; carving is what makes that tractable *at
  scale*, which also answers the "just add heap" rebuttal — individual builds may run at 12 GB, but
  triaging one SDK across thousands of hosts is infeasible whole-app in aggregate.)
- **Feasibility transformation, not speed optimization.** The headline is RQ1 (1 GB: whole-app 11/11
  fail → carve 11/11 succeed), i.e. moving the *feasibility boundary*, not a 44× speedup.
- **The Joern bug is a cautionary case study**, not the thesis: a production analyzer had a
  resource-sensitive silent failure on large/adversarial Android input, and the carve-vs-whole-app
  *differential* surfaced it (joernio/joern#6257) — motivation, not claim.

**The real bottleneck is definitional, not corpus size:** we must **define what must be preserved for
a carve to be "correct enough"** (the *preservation contract*). With that definition, ~100 APKs are
evidence; without it, 1,000 APKs still only show "smaller ⇒ faster." This is the priority, and it is
**not AndroZoo-gated** — it can be built now on the samples in hand.

### Research questions
- **RQ1 Feasibility (headline)** — does carving move the *feasibility boundary*: analyze targets that
  are impossible whole-app under a realistic/at-scale budget? *(1 GB: whole-app fails 11/11, carve
  succeeds 11/11.)*
- **RQ2 Reduction** — classes / methods / size / CPG-DB size / time / peak memory (whole-app vs carved).
- **RQ3 Semantic fidelity (the core, was under-specified)** — beyond method-presence: **call-graph
  edges, source→sink reachability *paths*, dataflow findings, manifest/resource/entry-point deps**
  preserved carved-vs-(complete)-whole-app. Method-count alone is *not* fidelity.
- **RQ4 Generalizability** — unrelated families, multiple versions, hosts, R8/ProGuard, renames, damaged decompilation, big apps, lib-dependent SDKs.
- **RQ5 Failure boundary (co-core with RQ3)** — where carve stops being faithful: reflection, dynamic
  class loading, JNI/native, shared host utilities, resource lookup, manifest components, inter-SDK
  deps, shaded deps. Must be **shown explicitly**, not hand-waved.

### Corpus
- **Phase 1 (diversity):** ~10 **unrelated** SDK families × ~10 apps ≈ 100 APKs — mix of ad / analytics /
  privacy-sensitive / malicious / heavily-obfuscated / old+modern. Per sample: sha256, package, version,
  source, date, family, SDK-version evidence, obfuscation traits. *(Do not redistribute APKs.)*
  - first benign general-SDK sample in hand: **DMB TV `com.project.onair`** ×5 (ExoPlayer/Firebase/
    YouTube-player/okhttp/ButterKnife) — `analysis/general_apps/` — good non-adfraud carve target.
- **Phase 2 (scale):** 20–30 families, several hundred APKs (AndroZoo useful, not required) — only if Phase 1 pays off.

### Corpus acquisition — **NOT AndroZoo-gated** (revised)
`package + historical version → APK` is already solved by many tools; don't build a downloader, build
a **resolver** over them. (This is exactly how the Necro hosts + DMB-TV versions were already
obtained — via APKPure/apkfiles by hash, no AndroZoo.)
- [ ] **Multi-source resolver** `resolve(package, version?)` with fallback chain →
  `local · AndroZoo · APKMirror (apkmirror-downloader) · APKCombo · APKPure (py) · Play (gpapi/Aurora) · Uptodown`,
  emitting a **normalized record** `{package, version_name, version_code, sha256, signer_sha256, source, source_url, split, retrieved_at}`.
- **Fit for *our* threat model:** malicious SDKs ride in **real host apps** (Goldoson=Play apps,
  Necro=Wuta/Spotify mods) with an **infected→clean version boundary** → historical-version mirrors are
  the *right* tool and already worked for us. **Caveats:** (a) *standalone flagged* malware is taken
  down from mirrors/Play → still via MalwareBazaar/Triage/VT (already used); (b) mirror APKs can be
  **repackaged** → the resolver **must verify `signer_sha256` + `sha256`** (also our SDK-provenance
  check); (c) AndroZoo stays valuable for **reproducibility/metadata** (citable hashes, dex-date, VT
  count) but is **optional, not a gate**; (d) respect ToS + the authorization gate (below).
- **Consequence:** RQ4 generality is now an **engineering task (the resolver)**, not an external gate.
  The intellectual bottleneck remains the **preservation contract** (★ PRIORITY), not sample access.

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
  - RQ3 **method-presence only** (NOT yet semantic fidelity): carved SDK method surface == whole-app
    exactly, 11/11. ⚠️ Reviewer: "method present ≠ analysis meaning preserved" — semantic fidelity
    (call-graph edges / source→sink paths / dataflow) is the **pending core**, see priority block below.
- [~] Extend CodeQL cost/completeness cross-check across the corpus — **carved: all 11 apps**
  (21–29 s, 7–11 MB DB, 100 % SDK each; `research/codeql_carved_corpus.csv`). Whole-app: 2 apps
  with original APK (TMAP 542 s/2.5 GB, worldcup 220 s/207 MB) → carved ~9–22× faster, ~30–280×
  smaller. Whole-app on other 9 blocked by dex2jar→jadx source-damage confound (need original APKs).
  **Non-Goldoson generality done:** carved 4 benign SDKs (retrofit2/okhttp3/firebase/reactivex)
  from TMAP → 2–9 s (56–232× vs whole-app), method captured (`research/nongoldoson_carve.csv`).
  Remaining: original APKs for wider whole-app CodeQL set.
- [ ] Consistent timeout/OOM/failure recording; machine-readable scope-completeness output
- [ ] Generalize SDK-root detection beyond Goldoson-specific anchors
- [ ] Run Phase 1 (~100 APKs) — **generality evidence, AndroZoo-gated, but NOT the bottleneck**
  (see priority block); analyze failures; **reassess novelty**; decide on Phase 2

### ★ PRIORITY (non-gated, the intellectual core) — define + measure the preservation contract
The bottleneck is *definitional*, not corpus size. Do this now on samples in hand (11 Goldoson +
Necro; whole-app CPG is complete post-#6257 so carved-vs-whole-app is a fair comparison):
- [x] **Define the preservation contract** — method set + internal call graph + boundary call-sites
  preserved; deliberately-cut = callee bodies across the boundary + reflection/dynamic/JNI paths →
  [`docs/FIDELITY.md`](docs/FIDELITY.md).
- [x] **RQ3 semantic fidelity (call-graph)** — carved vs complete-whole-app CPG: **internal-edge recall
  = 100.0 %, 0 divergence on 9/11 apps** (7.7k–58k classes; 2 largest not re-run — whole-app edge-dump
  impractical, within covered range, deterministic same). `docs/FIDELITY.md`, `research/edges.sc`.
- [ ] **RQ3 deeper (②)** — source→sink *path* recall + dataflow-finding agreement (carved vs whole-app).
- [~] **RQ5 failure boundary (measure explicitly)** — boundary edges (SDK→non-SDK) are the cut; **55–92 %
  are framework/stdlib** (stubs in whole-app too → not lost), only the non-framework host-app fraction is
  genuinely dropped. Still to enumerate: reflection / dynamic loading / JNI / manifest-component paths.
- [ ] Only then: Phase-1 corpus (via the **multi-source resolver**, AndroZoo optional) turns the
  *defined* contract into generality evidence.

**Target claim (converged framing — feasibility + fidelity, supply-chain unit):**
> *For a third-party SDK embedded across many Android host apps, whole-app analysis is the wrong
> default unit: target-centric carving **moves the feasibility boundary** (analyzes SDKs that are
> impossible whole-app under realistic/at-scale budgets) at 1–2 orders less cost, **while preserving
> the SDK's security-relevant semantics** — and we characterize exactly **where that preservation
> stops holding**. The carve-vs-whole-app differential additionally surfaced a real production-analyzer
> failure (joernio/joern#6257).*

- **Headline = feasibility transformation** (RQ1: 1 GB whole-app 8/8 measured fail → carve 11/11 ok),
  not the 10–324× speedup (RQ2), which is expected. The "just add heap" rebuttal is answered by the
  **supply-chain-at-scale** unit (triage one SDK across thousands of hosts is infeasible whole-app in
  aggregate) — reinforced by our finding that SDKs are **re-obfuscated per host** (carve+reanalyze
  per host is unavoidable, and carving is what makes it tractable).
- **Core still open = semantic fidelity (RQ3, not method-count) + failure boundary (RQ5).** These are
  the paper-defining deliverables and are **not corpus-gated** — see the ★ PRIORITY block.
- **Joern #6257 = cautionary case study / motivation**, not the thesis. Earlier "whole-app is silently
  incomplete" headline demoted (it was a fixable bug).
- **Honest venue:** solid empirical / SE-security (measurement + systematization), *not* a novel-algorithm
  paper — and that's fine; the contribution is the *preservation-contract definition + feasibility/
  fidelity/boundary characterization for supply-chain SDK analysis*.
Evidence: [`docs/METRICS.md`](docs/METRICS.md) (RQ1 1 GB fails 8/8 measured; RQ2 10–324×; RQ3 method-presence 11/11 — semantic fidelity pending; case study #6257).

---

## Authorization gates

| Action | Gate |
|---|---|
| Local carves of samples already held | ✅ proceed |
| Sample/hash fetch (AndroZoo/MalwareBazaar/Hybrid Analysis/Triage/VT) | ⛔ per-step user OK (standing OK for Track 1 Phase B) |
| APK fetch via mirror resolver (APKMirror/APKCombo/APKPure/Play/Uptodown) | ⛔ per-step user OK; **respect each source's ToS/anti-bot**; **verify signer+hash** (mirror APKs may be repackaged) |
| Network call to a candidate/known C2 | ⛔ explicit OK + isolated env (`AGENTS.md`) |
| Commit/push to the public repo | ⛔ explicit OK |

---

## Immediate next actions (consolidated — priority order)

1. **★ Semantic-fidelity + failure-boundary study (RQ3/RQ5) — the paper-defining, non-gated core.**
   Define the **preservation contract**, then measure carved-vs-(complete)-whole-app: CG-edge recall,
   source→sink path recall, dataflow-finding agreement, and *where carve breaks*. On 11 Goldoson +
   Necro, now — no new samples needed.
2. **Build the multi-source APK resolver** (`resolve(package, version?)`, normalized record, signer+hash
   verify) → unblocks RQ4 generality without AndroZoo as a gate. Then Phase-1 corpus.
3. **Track 1 (done this pass):** Necro/Coral carved + Konfety↔MobiDash diff + cross-host build compare.
   Remaining is gated (native ghidra track; Phase-D infra correlation needs external evidence).
4. **Wrap the sure wins:** land Joern #6257 merge; publish threat-intel as a report/blog; ship the tool.
5. **Track 2 desk (done):** R-Droid diff + related-work matrix (`docs/RELATED_WORK.md`).
