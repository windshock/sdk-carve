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

**Finding:** Goldoson's packet-capture blocklist is unique; Konfety & MobiDash converge on
phantom-viewport + synthetic-touch click fraud via different packing (both statically recoverable).

### Phases
- [x] **A — Goldoson anti-analysis** (blocklist decrypt 11/11, domain reclassification, YARA)
- [~] **B — corpus acquisition** *(authorization-gated; kit `research/acquisition/`)*
  - [x] SpinOk (MalwareBazaar), Konfety ×5 (Hybrid Analysis), MobiDash (Triage)
  - [ ] SlopAds / Trapdoor (App-ID → AndroZoo), Invisible Adware / Necro (→ AndroZoo) — **need `ANDROZOO_APIKEY`**
  - [ ] Goldoson historical infected→clean boundary (AndroZoo) — *research Final-priority #1*
- [x] **C — cross-family comparison** (4 families; anti-analysis + fraud-engine matrix)
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
- [ ] Read + summarize **R-Droid**; document exact overlap/differences
- [ ] Build the related-work matrix (the 14 refs above)
- [ ] Select 10 **unrelated** SDK families + define corpus metadata schema
- [ ] Automate APK → detect → carve → analyze → **metrics** pipeline + whole-app baseline runner
- [ ] Consistent timeout/OOM/failure recording; machine-readable scope-completeness output
- [ ] Generalize SDK-root detection beyond Goldoson-specific anchors
- [ ] Run Phase 1 (~100 APKs); analyze failures; **reassess the novelty claim**; decide on Phase 2

**Target claim (if evidence supports):** *target-aware carving turns large decompiled Android apps
that are impractical for heavyweight static analysis into substantially smaller, statically
dependency-closed targets that preserve enough security-relevant behavior for meaningful downstream
analysis* — scoped to static references (no universal soundness).

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

1. **Track 1:** Konfety↔MobiDash phantom-viewport **code diff** (both engines recovered) — no new samples.
2. **Track 2 kickoff:** read/diff **R-Droid** + build the related-work matrix (pure desk work, high leverage for novelty).
3. **Track 2 pipeline:** automate baseline-vs-carved **metrics** on the samples in hand (Goldoson×11 + SpinOk + Konfety + MobiDash) — first RQ2/RQ3 data.
4. **Blocked on `ANDROZOO_APIKEY`:** SlopAds/Trapdoor/Invisible/Necro + Goldoson historical + Phase-1 unrelated-family corpus.
