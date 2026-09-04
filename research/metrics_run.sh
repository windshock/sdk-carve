#!/usr/bin/env bash
# Drive baseline-vs-carved metrics across TMAP + all batch Goldoson apps.
set -uo pipefail
cd /Users/1004276/Downloads/goldoson-samples/analysis
CSV=metrics.csv; rm -f "$CSV"
export METRICS_TIMEOUT=1800

echo ">>> TMAP"
bash metrics.sh com.skt.tmap.ku tmap-dex2jar.jar "$CSV" com/smart/sklb bg cg dg

for d in batch/*/; do
  app=$(basename "$d"); jar="$d/app.jar"; sc="$d/scope.txt"
  [ -f "$jar" ] && [ -f "$sc" ] || { echo "skip $app"; continue; }
  roots=$(tr '\n' ' ' < "$sc")
  echo ">>> $app  roots=[$roots]"
  bash metrics.sh "$app" "$jar" "$CSV" $roots
done
echo "=== DONE ==="; column -s, -t "$CSV"
