# System Architecture

## 1. Overview

This project analyzes Kubernetes network traffic using Cilium Hubble.
It uses an offline, rule-based detection pipeline.

## 2. Processing Pipeline

Kubernetes Pods
  -> Cilium NetworkPolicy Enforcement
  -> Hubble JSONL Collection
  -> Parser
  -> Normalizer
  -> Detector (R1 / R2 / R3)
  -> Evaluation and Visualization

## 3. Components

### Hubble Collection
- Script: scripts/collect_hubble.sh
- Collects network flow events from Hubble Relay.
- Saves JSONL files under results/raw/.

### Parser
- File: src/parser.py
- Extracts timestamps, Pod names, IPs, ports, protocols, and verdicts.
- Saves structured events under results/parsed/.

### Normalizer
- File: src/normalizer.py
- Extracts TCP connection-attempt candidates.
- Groups repeated events using TCP 5-tuple and a 10-second interval.
- Saves normalized events under results/normalized/.

### Detector
- File: src/detector.py
- Uses a 180-second sliding window.
- R1: Unauthorized Egress.
- R2: Destination Fan-out.
- R3: Multi-Port Scanning.

### Evaluation
- evaluate.py: Scenario evaluation.
- ablation.py: Rule contribution comparison.
- visualize.py: Scenario and window figures.
- plot_ablation.py: Ablation figures.

## 4. Reproduction

Run unit tests:
python3 -m unittest discover -s tests -v

Run synthetic pipeline test:
python3 scripts/smoke_test.py

Run evaluation with collected logs:
bash scripts/reproduce.sh

The full evaluation requires seven original Hubble JSONL files.

## 5. Data Policy

Original Hubble logs are excluded from the public repository.
Synthetic test data is available under tests/fixtures/.
