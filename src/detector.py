import json
from collections import defaultdict, deque
from datetime import datetime
from pathlib import Path

DATA_DIR = Path("results/normalized")
SCENARIOS = (
    "normal",
    "abnormal_1",
    "abnormal_2",
    "abnormal_3",
)

WINDOW_SECONDS = 180

# Current workload's expected application traffic.
ALLOWED_EDGES = {
    ("frontend", "backend", 80),
    ("backend", "db", 80),
}


def pod_role(pod_name):
    if not isinstance(pod_name, str):
        return None

    for role in ("frontend", "backend", "db"):
        if pod_name == role or pod_name.startswith(role + "-"):
            return role

    return None


def timestamp_seconds(value):
    try:
        return datetime.fromisoformat(
            value.replace("Z", "+00:00")
        ).timestamp()
    except (AttributeError, ValueError):
        return None


def load_attempts(path):
    valid = []
    skipped = 0

    with path.open(encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue

            item = json.loads(line)

            src_role = pod_role(item.get("source_pod"))
            dst_role = pod_role(item.get("destination_pod"))
            timestamp = timestamp_seconds(item.get("timestamp"))

            try:
                port = int(item.get("destination_port"))
            except (TypeError, ValueError):
                port = 0

            source_ip = item.get("source_ip")
            destination_ip = item.get("destination_ip")

            if (
                not src_role
                or timestamp is None
                or port <= 0
                or item.get("protocol") != "TCP"
                or port == 53
                or item.get("source_namespace")
                   not in (None, "pbl-security")
                or (source_ip and source_ip == destination_ip)
            ):
                skipped += 1
                continue

            item["_time"] = timestamp
            item["_src_role"] = src_role
            item["_dst_role"] = dst_role
            item["_port"] = port

            valid.append(item)

    return valid, skipped


def window_features(events):
    destinations = {
        e["destination_ip"]
        for e in events
        if e.get("destination_ip")
    }

    ports = {e["_port"] for e in events}

    pairs = {
        (e["destination_ip"], e["_port"])
        for e in events
    }

    blocked_dest = {
        e["destination_ip"]
        for e in events
        if e["verdict"] == "DROPPED"
    }

    violations = [
        e for e in events
        if e["verdict"] == "DROPPED"
        and (
            e["_src_role"],
            e["_dst_role"],
            e["_port"]
        ) not in ALLOWED_EDGES
    ]

    rules = set()

    if violations:
        rules.add("R1_UNAUTHORIZED_EGRESS")

    if (
        len(destinations) >= 3
        and len(blocked_dest) >= 2
    ):
        rules.add("R2_DESTINATION_FANOUT")

    blocked_ports = {
        e["_port"] for e in events
        if e["verdict"] == "DROPPED"
    }

    if (
        len(ports) >= 4
        and len(pairs) >= 4
        and len(blocked_ports) >= 4
    ):
        rules.add("R3_MULTI_PORT_SCAN")

    return {
        "destinations": len(destinations),
        "blocked_destinations": len(blocked_dest),
        "ports": len(ports),
        "pairs": len(pairs),
        "rules": rules,
    }


def analyze(attempts):
    groups = defaultdict(list)

    for item in attempts:
        groups[item["source_pod"]].append(item)

    triggered = set()
    snapshots = []

    for source, items in groups.items():
        window = deque()

        for item in sorted(items, key=lambda x: x["_time"]):
            window.append(item)

            while (
                window
                and item["_time"] - window[0]["_time"]
                > WINDOW_SECONDS
            ):
                window.popleft()

            features = window_features(window)
            features["source"] = source

            triggered.update(features["rules"])
            snapshots.append(features)

    best = max(
        snapshots,
        key=lambda x: (
            x["pairs"],
            x["destinations"],
            x["ports"]
        ),
        default=None,
    )

    if "R3_MULTI_PORT_SCAN" in triggered:
        decision = "MULTI_PORT_SCAN"
    elif "R2_DESTINATION_FANOUT" in triggered:
        decision = "DESTINATION_FANOUT"
    elif "R1_UNAUTHORIZED_EGRESS" in triggered:
        decision = "UNAUTHORIZED_EGRESS"
    else:
        decision = "NORMAL"

    return decision, triggered, best


def main():
    for name in SCENARIOS:
        path = DATA_DIR / f"{name}.jsonl"

        if not path.exists():
            print(f"[{name}] FILE NOT FOUND: {path}")
            continue

        attempts, skipped = load_attempts(path)
        decision, rules, best = analyze(attempts)

        print(f"\n=== {name} ===")
        print(f"Attempts={len(attempts)}  Skipped={skipped}")
        print(f"Decision={decision}")
        print(f"Rules={sorted(rules)}")

        if best:
            print(f"Source={best['source']}")
            print(
                f"Window={WINDOW_SECONDS}s  "
                f"DstIP={best['destinations']}  "
                f"BlockedDstIP={best['blocked_destinations']}  "
                f"Ports={best['ports']}  "
                f"IP:Port={best['pairs']}"
            )


if __name__ == "__main__":
    main()
