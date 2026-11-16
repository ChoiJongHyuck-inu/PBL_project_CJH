#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

usage() {
    echo "Usage: $0 <scenario_name>"
    echo
    echo "Examples:"
    echo "  $0 normal"
    echo "  $0 abnormal_1"
    echo "  $0 abnormal_shortscan"
    echo
    echo "Requires Hubble Relay port-forward."
}

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    usage
    exit 0
fi

if [[ $# -ne 1 ]]; then
    usage
    exit 1
fi

SCENARIO="$1"

if [[ ! "$SCENARIO" =~ ^[a-zA-Z0-9_-]+$ ]]; then
    echo "ERROR: Invalid scenario name."
    exit 1
fi

if ! command -v hubble >/dev/null 2>&1; then
    echo "ERROR: Hubble CLI is not installed."
    exit 1
fi

if ! hubble status >/dev/null 2>&1; then
    echo "ERROR: Cannot connect to Hubble Relay."
    echo "Run in another terminal:"
    echo "  cilium hubble port-forward"
    exit 1
fi

mkdir -p results/raw

OUTPUT="results/raw/${SCENARIO}.jsonl"

if [[ -e "$OUTPUT" ]]; then
    echo "ERROR: File already exists: $OUTPUT"
    echo "Existing logs will not be overwritten."
    exit 1
fi

echo "===================================="
echo " Hubble Network Flow Collection"
echo "===================================="
echo "Scenario : $SCENARIO"
echo "Namespace: pbl-security"
echo "Output   : $OUTPUT"
echo
echo "Run the scenario in another terminal."
echo "Press Ctrl+C after the scenario finishes."
echo

hubble observe \
    --namespace pbl-security \
    --follow \
    --output json > "$OUTPUT"
