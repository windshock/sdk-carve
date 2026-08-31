# Workspace migration map

Historical logs contain paths from the original flat workspace. Use this table to
translate them to the organized layout.

| Old path | New path |
|---|---|
| `com.skt.tmap.ku/` | `corpus/decompiled/jadx/` |
| `com.skt.tmap.ku-dex2jar.jar` | `artifacts/derived/tmap-dex2jar.jar` |
| `com.skt.tmap.ku-dex2jar.jar.out/` | `artifacts/extracted/dex2jar-classes/` |
| `com.skt.tmap.ku-jadx/` | `corpus/reconstructed/android-gradle/` |
| `com.skt.tmap.ku-jadx/tmap_android/` | `analysis/codeql/databases/reconstructed-app-incomplete/` |
| `com.skt.tmap.ku-jadx/workspace/tmap_android/` | `analysis/joern/projects/reconstructed-app/` |
| `com.skt.tmap.ku-jadx/~/Library/Android/sdk/` | `generated/android-sdk/legacy-snapshot/` |
| `com.skt.tmap.ku-jadx/app/build/` | `generated/builds/reconstructed-app/` |
| `tmap_android/` | `analysis/codeql/databases/root-jadx-incomplete/` |
| `tmap_android_db/` | `analysis/codeql/databases/empty-source-incomplete/` |
| `workspace/tmap_android/` | `analysis/joern/projects/dex2jar-incomplete/` |
| `goldoson/` virtual environment | `environments/semgrep-py312/` |
| Root Semgrep scripts/rules/results | `analysis/semgrep/` |
| Root Gradle wrapper and tests | `experiments/gradle-harness/` |

No evidence artifact was deleted during the migration. Generated caches and empty
markers were retained under `generated/`.
