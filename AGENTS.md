# Workspace instructions for AI agents

## Objective

Analyze the Goldoson/SMARTLB SDK embedded in the decompiled TMAP Android package.
Keep claims tied to local evidence and clearly separate static observations from
runtime-confirmed behavior.

## Source of truth

- Canonical decompiled source: `corpus/decompiled/jadx/sources/`
- Canonical extracted manifest/resources: `corpus/decompiled/jadx/resources/`
- Derived JAR: `artifacts/derived/tmap-dex2jar.jar`
- Reconstructed Android project: `corpus/reconstructed/android-gradle/`
  - This is a duplicate working view, not original source.
  - Do not cite it when the same file exists in the canonical JADX tree.
- Start Goldoson review at `corpus/decompiled/jadx/sources/com/smart/sklb/edge/`.

## Evidence rules

- Use `binary-confirmed` for behavior visible in DEX/JAR-derived code.
- Use `runtime-confirmed` only when a controlled runtime test actually observed it.
- Use `not-confirmed` for inferred paths blocked by decompiler damage or missing artifacts.
- Do not imply that current Play Store releases contain this SDK. This workspace is
  tied only to the extracted version shown in the manifest.
- The original APK is absent. The JAR is derived evidence and cannot be re-anchored
  to an original APK hash from this workspace alone.

## Search strategy

- Prefer targeted `rg` searches under the canonical source tree.
- Avoid broad searches in `generated/`, `environments/`, CodeQL databases, or the
  extracted class tree unless a task specifically needs them.
- Expect obfuscated package names such as `bg`, `cg`, and `dg` to participate in the
  SMARTLB flow.
- Check `docs/EVIDENCE_MAP.md` before starting a new trace.

## Tool state

- Semgrep historical whole-tree scans were disrupted by invalid decompiler syntax.
- CodeQL databases are incomplete and must not be treated as successful results.
- `analysis/joern/projects/reconstructed-app/` contains a completed CPG, while
  `analysis/joern/projects/dex2jar-incomplete/` contains an unfinished 2 GB CPG.
- The reconstructed Android project has no successfully produced APK.
- See `docs/ANALYSIS_STATUS.md` for details.

## Safety and preservation

- Treat `artifacts/`, `corpus/`, and historical analysis results as read-only evidence.
- Put new reports under `analysis/reports/` and new scripts under the relevant
  `analysis/<tool>/scripts/` directory.
- Do not contact embedded domains or run the sample dynamically unless the user
  explicitly requests it and an isolated test plan is in scope.
- Do not delete failed or partial results; move superseded material under a clearly
  named `legacy/` or `archive/` directory.
