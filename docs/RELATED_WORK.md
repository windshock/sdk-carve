# Related work & positioning (GitHub issue #5)

Each group answers a specific reviewer question. The recurring distinction:

> Prior work asks **"which library is present"** (detection), **"which flows/statements matter for
> this sink"** (slicing), or **"which code is malicious"** (localization). sdk-carve asks a
> different, earlier question: **given a target SDK/root, what statically dependency-closed
> subprogram should conventional analyzers receive so that deep analysis becomes *feasible* on an
> app that is otherwise too large/obfuscated to process?**

Claim scope: static references only — reflection / dynamic class loading / native transitions can
invalidate closure (documented, not hidden). See `docs/PRE_CARVE.md` for the dynamic-loading cases
we handle by *unpacking to bytecode first*, which is exactly where a purely-static slicer stalls.

---

## B1. R-Droid — the key comparison  (Backes et al., AsiaCCS'16)

**What it does (from the paper).** R-Droid takes a set of **points of interest** (sinks, as method
signatures) — i.e. the analysis question is fixed up front — enhances the app bytecode, and uses
**JOANA** to build an object-, context- and field-sensitive **System Dependence Graph (SDG)** on top
of a precise lifecycle model. It then runs **backward data-dependence slicing** from the points of
interest and a def-use **slice-optimization** post-pass, yielding semantically-equivalent slices
**~49% smaller** than standard slices, plus **string re-targeting** to recover concrete values and
cut false positives. Output = optimized **slices** to ease analyst review; evaluated as a
data-leak study over 22,700 Google-Play apps. Reflection is only partially handled; native code is
not (paper's own capability table).

**Why sdk-carve is not R-Droid** (the distinction to defend empirically):

| Axis | R-Droid | sdk-carve |
|---|---|---|
| Seed / criterion | **sinks / points of interest** — question fixed first | a **target SDK/package root** — question *not* fixed |
| Direction | **backward** data-dependence from sinks | **forward closure** from the target root + reverse-trace for completeness |
| What's produced | optimized **slices** (statement-level) for one question | a reusable **mini-JAR / mini-program** (bytecode) |
| Reusability | per sink-set / per analysis | analyzer- and question-agnostic (one carve → Joern **and** CodeQL **and** …) |
| Granularity | statements (data-dependence) | whole classes/methods (downstream tools rebuild AST/CFG/PDG/CPG) |
| Engine | **JOANA SDG over the whole app** (heavyweight pass required to *produce* the slice) | frontend-agnostic; no whole-app graph needed before carving |
| Primary claim | smaller analyst-visible output | **restores analyzer feasibility** when whole-app CPG/CodeQL OOMs / never finalizes |

**The load-bearing difference:** R-Droid still runs a heavyweight whole-application analysis (WALA +
JOANA) to *build the SDG it slices* — it shrinks the **analyst-visible output**, not the
**analyzer's input universe**. sdk-carve shrinks the **input program before any heavyweight analyzer
runs**, so an analyzer that cannot finish on the whole app (our motivating failure: 2 GB CPG that
never finalizes) can run at all. If experiments show a downstream analyzer succeeds on the carved
target where it fails whole-app — across *multiple* analyzers — the novelty holds. If R-Droid-style
slicing alone already restores feasibility for the same targets, the claim must be revised.
*(Complementary framing: localization/slicing could seed the target; sdk-carve builds the analyzable
program around it.)*

---

## Matrix

### A. Third-party-library identification — *"which library is present?"*
| Ref | Contribution | sdk-carve distinction |
|---|---|---|
| **LibScout** (Backes, CCS'16) | obfuscation-resilient TPL detection + version/vuln attribution via profiles | detection ≠ analyzable subprogram; LibScout could be an **input** (find the root), not the output |
| **LibPecker** (Zhang, SANER'18) | signature-matching TPL detection, adaptive class-similarity, obfuscation-resilient | same: identifies presence/similarity, not a dependency-closed carve for downstream analysis |
| **LibID** (Zhang, ISSTA'19) | version-precise ID under code-shrinking/package-mod via binary-integer-programming | version ID is orthogonal; sdk-carve targets a root and *closes* it for analyzers |
| **AndroLibZoo** (Samhi, MSR'24) | up-to-date library dataset; argues large TPL footprints hurt static-analysis scalability/precision | **motivates** sdk-carve (TPL bloat is the problem); provides allow/deny signal for scope/denylist |

### B. Program reduction / slicing / static analysis — *"why not just slicing / improve one analyzer?"*
| Ref | Contribution | sdk-carve distinction |
|---|---|---|
| **R-Droid** (AsiaCCS'16) | sink-driven backward slicing on JOANA SDG; 49%-smaller optimized slices; string re-targeting | see §B1 — target-driven **structural closure** vs sink-driven slice; **feasibility** vs output-size |
| **FlowDroid** (Arzt, PLDI'14) | canonical precise Android taint analysis + DroidBench | a candidate **downstream analyzer** for analyzer-independence (does carving help it too?) |
| **CPG / Joern** (Yamaguchi, S&P'14) | code property graph (AST+CFG+PDG) for querying vulnerabilities | rationale for preserving whole-method structure in the carve so a CPG can be rebuilt |

### C. Context-aware narrowing / LLM specs — *"is this just result-filtering?"*
| Ref | Contribution | sdk-carve distinction |
|---|---|---|
| **DamFlow** (Alecci, TOSEM'25) | context-aware anomaly detection to cut irrelevant **result** flows | post-analysis **result relevance** vs pre-analysis **program-universe** reduction |
| **TaskFlow** (Alecci, TOSEM'26)* | LLM-generated task-specific source/sink lists | *what to look for* vs sdk-carve's *what code to see* (PDF not held; from abstract) |
| **LLM-Enhanced Taint** (Miazzo/Alecci, arXiv'26) | LLMs to enhance Android taint analysis | orthogonal spec/analysis layer; could ride on a carved target |
| Alecci PhD'26 · REPROCESS (uni.lu) | umbrella: pre/post-processing to make Android static analysis practical | sdk-carve = a concrete **pre-processing** instance under this framing |

### D. Malicious-payload localization — *"is this just malware localization?"*
| Ref | Contribution | sdk-carve distinction |
|---|---|---|
| **MalLoc** (Sun, ASE'25 NIER) | LLM two-phase fine-grained payload localization on Smali | ranks/finds suspicious code; sdk-carve **constructs the analysis universe** around a target |
| **RAML** (Sun, ASE'25 NIER) | RAG + LLM class/method-level payload localization | complementary: localize → seed root; carve → dependency-closed program |

### E. Corpus / reproducibility
| Ref | Contribution | Use here |
|---|---|---|
| **AndroZoo retrospective** (Alecci, MSR'24) | ~24M-APK dataset; `uploadDate` metadata fixes 1980/1981 dex_date issue | cross-SDK corpus + reliable versioning for the Track-2 study (useful, not a hard dependency) |

\* TaskFlow PDF not obtained (ACM-only); summarized from the abstract — low-priority contrast.

---

## Reviewer questions → our answer
1. **Not a TPL detector** — output is an analyzable program, shown via downstream results; detection is at most an input.
2. **Not just slicing (R-Droid)** — target-driven structural closure, reusable across analyzers, and the claim is *feasibility restoration* (§B1), not smaller slices.
3. **Not malware localization** — localization ranks code; carving builds the code universe (they compose: localize→seed, carve→surround).
4. **Not "just improve one analyzer"** — analyzer-agnostic preprocessing; benefit demonstrated on ≥2 engines (Joern + CodeQL, optional FlowDroid).
5. **Preserved vs lost** — quantify sources/sinks/reachability fidelity; document reflection/dynamic-loading/native/shaded boundaries (`PRE_CARVE.md` shows unpacking dynamic loaders back into carve-able bytecode).
6. **Generalizes beyond Goldoson** — the empirical gap Track 2 (issue #5 Phase 1, ~100 APKs / 10 unrelated families) is built to close.
