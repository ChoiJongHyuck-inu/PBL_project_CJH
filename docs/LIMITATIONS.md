# Limitations and Future Work

## 1. Scope

This project provides offline, rule-based classification
of Kubernetes network behavior using Cilium Hubble logs.

The evaluation uses seven traffic scenarios collected
from a single kind-based Kubernetes environment.

## 2. Dependence on Policy Denials

The detection rules rely heavily on DROPPED events.

Examples of behavior outside the current coverage:
- Malicious requests over permitted service paths
- Application-layer attacks using allowed HTTP traffic
- Suspicious activity without policy-denied connections

Future work:
- Add flow frequency and byte-count features
- Analyze permitted traffic patterns
- Consider application-layer observations

## 3. Manually Configured Service Paths

Expected service relationships are defined manually
in the detector's ALLOWED_EDGES configuration.

Changes in Pod roles or application topology
may require corresponding configuration changes.

Future work:
- Parse Kubernetes NetworkPolicy resources
- Update allowed communication relationships automatically

## 4. Approximate TCP Deduplication

The Normalizer uses TCP connection information
and a 10-second deduplication interval.

This method approximates connection attempts.
It does not reconstruct complete TCP sessions.

Future work:
- Evaluate retransmission handling
- Compare normalized attempts against packet traces
- Test connections with repeated TCP 5-tuples

## 5. Limited Evaluation Data

The evaluation contains:
- Two normal scenario logs
- Five abnormal scenario logs
- Seven scenario files in total

Detection thresholds and the 180-second window
were selected using these development scenarios.

The reported 7/7 classification result therefore
describes the available development data.

Future work:
- Collect independent evaluation scenarios
- Test more normal traffic variations
- Evaluate false alarms in larger environments
- Compare performance under different workloads

## 6. Offline Processing

The current pipeline analyzes stored Hubble JSONL files.

Future work:
- Stream Hubble events into the detector
- Measure detection latency
- Monitor CPU and memory usage
- Evaluate alert generation under continuous traffic

## 7. Deployment Considerations

Before operational deployment, additional testing
would be needed for:
- Different Kubernetes cluster configurations
- Dynamic Pod creation and deletion
- Multiple namespaces and services
- NetworkPolicy changes during execution

The current implementation is intended for
educational experimentation and reproducible analysis.
