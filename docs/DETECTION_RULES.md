# Detection Rules

## 1. Overview

The detector analyzes normalized TCP connection attempts.
Events are grouped by source Pod using a 180-second
sliding window.

Three rules classify suspicious network behavior.

## 2. R1 - Unauthorized Egress

Purpose: Detect blocked connections outside normal paths.

Allowed application paths:
- Frontend -> Backend:80
- Backend -> DB:80

Conditions:
- Verdict is DROPPED.
- Source, destination role, and port are not in ALLOWED_EDGES.

Example: Frontend -> DB:80 (DROPPED)

Output: UNAUTHORIZED_EGRESS

## 3. R2 - Destination Fan-out

Purpose: Detect connections to multiple destination IPs.

Conditions within 180 seconds:
- Unique destination IPs >= 3
- Unique blocked destination IPs >= 2

Output: DESTINATION_FANOUT

## 4. R3 - Multi-Port Scan

Purpose: Detect access attempts across multiple ports.

Conditions within 180 seconds:
- Unique destination ports >= 4
- Unique destination IP:port pairs >= 4
- Unique blocked destination ports >= 4

Output: MULTI_PORT_SCAN

## 5. Classification Priority

When multiple rules trigger, the priority is:

1. R3 - MULTI_PORT_SCAN
2. R2 - DESTINATION_FANOUT
3. R1 - UNAUTHORIZED_EGRESS
4. NORMAL

All triggered rules are also recorded.

## 6. Sliding Window Comparison

Window | Exact classification
60s    | 6/7
120s   | 6/7
180s   | 7/7
240s   | 7/7

The default is 180 seconds.

## 7. Evaluation Scope

The thresholds were adjusted using seven collected
development scenarios. The reported results describe
these scenarios rather than independent generalization.

The detector uses blocked flows and manually configured
application paths. NetworkPolicy rules are not parsed
automatically.
