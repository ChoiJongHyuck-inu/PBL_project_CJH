# Experiments and Results

## 1. Experimental Environment

- Kubernetes: kind, 3 nodes
- Network: Cilium / Hubble 1.16.3
- Namespace: pbl-security
- Workloads: Frontend, Backend, DB
- Service communication: TCP port 80
- Detection method: Offline rule-based classification
- Default sliding window: 180 seconds

The DB workload is a demonstration HTTP service.

## 2. Experimental Scenarios

Seven traffic scenarios were analyzed.

1. Normal: Frontend to Backend and Backend to DB.
2. Abnormal 1: Unauthorized Frontend to DB access.
3. Abnormal 2: Multiple destination IPs.
4. Abnormal 3: Multiple destination IP and port combinations.
5. Normal Repeat: Normal traffic repeated five times.
6. Short Scan: Five ports on one destination.
7. Slow Scan: Four ports accessed at 45-second intervals.

The three basic abnormal scenarios follow the
instructor-provided Category 2 scripts.

## 3. Collected Data

Scenario | Raw Events | DROPPED | Attempts
--- | ---: | ---: | ---:
Normal | 754 | 0 | 9
Abnormal 1 | 382 | 6 | 1
Abnormal 2 | 384 | 11 | 10
Abnormal 3 | 973 | 84 | 42
Normal Repeat | 1262 | 0 | 45
Short Scan | 233 | 10 | 5
Slow Scan | 2229 | 8 | 4
Total | 6217 | 119 | 116

Raw events include background Kubernetes traffic.
Attempts are normalized TCP connection-attempt candidates.

## 4. Final Scenario Classification

Scenario | Predicted Class
--- | ---
Normal | NORMAL
Abnormal 1 | UNAUTHORIZED_EGRESS
Abnormal 2 | DESTINATION_FANOUT
Abnormal 3 | MULTI_PORT_SCAN
Normal Repeat | NORMAL
Short Scan | MULTI_PORT_SCAN
Slow Scan | MULTI_PORT_SCAN

All seven development scenarios matched their labels.

## 5. Sliding Window Comparison

Window | Exact Type Accuracy
--- | ---
60 seconds | 6/7 (85.7%)
120 seconds | 6/7 (85.7%)
180 seconds | 7/7 (100%)
240 seconds | 7/7 (100%)

At 120 seconds, Slow Scan was classified as
UNAUTHORIZED_EGRESS.

At 180 seconds, the four accessed ports were
included in the window, activating MULTI_PORT_SCAN.

The default window was set to 180 seconds.

## 6. Ablation Study

Enabled Rules | Exact Type Accuracy | Binary F1
--- | --- | ---
R1 | 3/7 (42.9%) | 1.000
R1 + R2 | 4/7 (57.1%) | 1.000
R1 + R2 + R3 | 7/7 (100%) | 1.000

R1 detects the presence of blocked unauthorized traffic.
R2 separates destination fan-out behavior.
R3 separates multi-port scan behavior.

R2 and R3 improved attack-type classification
in these scenarios. Binary detection F1 remained unchanged.

## 7. Evaluation Scope

The evaluation unit is one scenario log file.

- Normal scenarios: 2
- Abnormal scenarios: 5
- True positives: 5
- True negatives: 2
- False positives: 0
- False negatives: 0

Detection thresholds and window size were adjusted
using the same seven scenario logs.

Results therefore describe development-scenario
classification rather than independent test performance.

## 8. Reproduction

Run automatic unit tests:
python3 -m unittest discover -s tests -v

Generate synthetic data:
python3 scripts/generate_fixtures.py

Validate synthetic JSONL logs:
python3 scripts/validate_logs.py tests/fixtures/*.jsonl

Run the synthetic end-to-end pipeline:
python3 scripts/smoke_test.py

Reproduce the original evaluation:
bash scripts/reproduce.sh

The original evaluation requires the seven collected
Hubble JSONL files, which are not published in the repository.

The synthetic fixtures are intended for functionality
testing and are not included in the reported evaluation scores.
