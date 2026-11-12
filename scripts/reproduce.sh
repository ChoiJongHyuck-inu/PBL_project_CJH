#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

echo "=================================="
echo " PBL Security Detection Pipeline"
echo "=================================="

echo "[1/5] Parsing and normalization"

python3 - <<'PY'
import sys
sys.path.insert(0, "src")

from pathlib import Path
from parser import process_scenario
from normalizer import normalize
from ablation import SCENARIOS

for name in SCENARIOS:
    path = Path(f"results/raw/{name}.jsonl")
    if not path.is_file():
        raise SystemExit(f"Missing raw log: {path}")

for name in SCENARIOS:
    process_scenario(name)
    normalize(name)
PY

echo "[2/5] Original scenario evaluation"
python3 src/evaluate.py

echo "[3/5] Ablation study"
python3 src/ablation.py

echo "[4/5] Scenario visualizations"
python3 src/visualize.py

echo "[5/5] Ablation visualization"
python3 src/plot_ablation.py

echo
echo "=================================="
echo " Pipeline completed successfully"
echo "=================================="

echo
echo "Generated figures:"
ls -lh results/figures/*.png

echo
echo "Generated CSV files:"
ls -lh results/*.csv
