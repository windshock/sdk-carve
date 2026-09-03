# Phase B — corpus acquisition kit

Operationalizes the retrieval recipes in the research docs. Samples are fetched **only for
static `sdk-carve` analysis** and are never executed. Downloads land in `corpus/`
(git-ignored). See [`../../PLAN.md`](../../PLAN.md) Phase B for the plan and gates.

## Prerequisites (API keys — this is the blocker)

| Var | Get it | Used for |
|---|---|---|
| `HYBRIDANALYSIS_APIKEY` | https://hybrid-analysis.com (Falcon Sandbox; `auth_level>=100` "default" can download) | samples by sha256 (gzip) |
| `MB_APIKEY` | https://auth.abuse.ch/ (MalwareBazaar Auth-Key) | family-tagged samples by sha256 (AES zip) |
| `ANDROZOO_APIKEY` | https://androzoo.uni.lu/access (academic/research only) | historical APKs by sha256 / package |

`fetch.sh` tries HA → MalwareBazaar → AndroZoo. Which repo has which sample varies:
SpinOk was on MalwareBazaar only; Konfety on Hybrid Analysis only. Availability is a
per-hash lookup (`search/hash` on HA, `get_info` on MB) — many hashes are on neither, and
those (MobiDash, Invisible Adware, Necro, Goldoson-historical) need AndroZoo.

## Usage

```bash
./fetch.sh                      # dry-run: list what would be fetched (safe, no keys needed)
export ANDROZOO_APIKEY=...      # and/or  export MB_APIKEY=...
./fetch.sh --go                 # download all seeds
./fetch.sh --go --family MobiDash
```

Then carve each: `detect.py <apk-dex2jar>.jar` → `carve.sh` → the usual pipeline, and
record rows in the normalized schema (PLAN Phase C).

## Files
- `seeds.csv` — machine-readable seed list (family, kind, identifier, source, confidence).
  `sha256` rows are directly fetchable; `package` rows need AndroZoo version selection
  (infected→clean boundary) and `md5` rows need a hash→sha256 pivot first.
- `fetch.sh` — parameterized fetcher (AndroZoo + MalwareBazaar), dry-run by default.

## Safety
- Static analysis only; do not install/run APKs.
- `corpus/` is git-ignored; never commit samples (see repo `.gitignore`).
