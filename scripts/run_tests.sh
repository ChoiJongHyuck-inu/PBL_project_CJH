#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

echo "================================"
echo " PBL Automated Test Suite"
echo "================================"

echo
echo "[1/4] Unit Tests"
python3 -m unittest discover -s tests -v

echo
echo "[2/4] Generate Synthetic Hubble Logs"
python3 scripts/generate_fixtures.py

echo
echo "[3/4] Validate Hubble JSONL"
python3 scripts/validate_logs.py tests/fixtures/*.jsonl

echo
echo "[4/4] End-to-End Pipeline Test"
python3 scripts/smoke_test.py

echo
echo "================================"
echo " ALL TESTS PASSED"
echo "================================"
