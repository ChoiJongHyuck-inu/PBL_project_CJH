import json
from datetime import datetime
from pathlib import Path
from collections import Counter

INPUT_DIR = Path("results/parsed")
OUTPUT_DIR = Path("results/normalized")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

SCENARIOS = [
    "normal",
    "abnormal_1",
    "abnormal_2",
    "abnormal_3",
]

NAMESPACE = "pbl-security"
RETRANSMIT_WINDOW = 10.0


def parse_timestamp(value):
    if not isinstance(value, str):
        return None

    try:
        return datetime.fromisoformat(
            value.replace("Z", "+00:00")
        ).timestamp()
    except ValueError:
        return None


def has_flag(flags, name):
    if isinstance(flags, dict):
        value = flags.get(
            name, flags.get(name.lower(), False)
        )
        return value is True or value == 1

    if isinstance(flags, list):
        return name in flags

    if isinstance(flags, str):
        return name in flags.upper()

    return False


def is_connection_attempt(event):
    if event.get("protocol") != "TCP":
        return False

    if event.get("verdict") not in (
        "FORWARDED", "DROPPED"
    ):
        return False

    source_pod = event.get("source_pod")
    source_namespace = event.get("source_namespace")

    # Host-originated health checks are excluded.
    if not source_pod:
        return False

    if source_namespace and source_namespace != NAMESPACE:
        return False

    required = [
        "source_ip",
        "destination_ip",
        "source_port",
        "destination_port",
    ]

    if any(event.get(field) is None for field in required):
        return False

    flags = event.get("tcp_flags")

    syn = has_flag(flags, "SYN")
    ack = has_flag(flags, "ACK")

    if event["verdict"] == "DROPPED":
        # Keep blocked attempts. Exclude obvious replies.
        return not (ack and not syn)

    # A forwarded connection begins with SYN without ACK.
    return syn and not ack


def connection_key(event):
    return (
        event["source_ip"],
        event["source_port"],
        event["destination_ip"],
        event["destination_port"],
        event["protocol"],
    )


def normalize(name):
    input_path = INPUT_DIR / f"{name}.jsonl"
    output_path = OUTPUT_DIR / f"{name}.jsonl"

    events = []

    with input_path.open(encoding="utf-8") as f:
        for line in f:
            if line.strip():
                event = json.loads(line)
                if is_connection_attempt(event):
                    events.append(event)

    events.sort(
        key=lambda e: (
            parse_timestamp(e.get("timestamp"))
            if parse_timestamp(e.get("timestamp")) is not None
            else float("inf")
        )
    )

    attempts = []
    active = {}

    for event in events:
        key = connection_key(event)
        timestamp = parse_timestamp(event.get("timestamp"))

        previous = active.get(key)

        if previous is not None:
            last = previous["_last_seconds"]

            if (
                timestamp is not None
                and last is not None
                and 0 <= timestamp - last <= RETRANSMIT_WINDOW
            ):
                previous["observed_events"] += 1
                previous["last_timestamp"] = event["timestamp"]
                previous["_last_seconds"] = timestamp

                if event["verdict"] == "DROPPED":
                    previous["verdict"] = "DROPPED"
                    previous["drop_reason"] = event.get(
                        "drop_reason"
                    )

                continue

        attempt = {
            "timestamp": event["timestamp"],
            "last_timestamp": event["timestamp"],
            "source_pod": event["source_pod"],
            "source_namespace": event["source_namespace"],
            "source_ip": event["source_ip"],
            "source_port": event["source_port"],
            "destination_pod": event["destination_pod"],
            "destination_namespace": event["destination_namespace"],
            "destination_ip": event["destination_ip"],
            "destination_port": event["destination_port"],
            "protocol": event["protocol"],
            "verdict": event["verdict"],
            "drop_reason": event["drop_reason"],
            "observed_events": 1,
            "_last_seconds": timestamp,
        }

        attempts.append(attempt)
        active[key] = attempt

    with output_path.open("w", encoding="utf-8") as f:
        for attempt in attempts:
            output = {
                k: v
                for k, v in attempt.items()
                if not k.startswith("_")
            }

            f.write(json.dumps(output, ensure_ascii=False) + "\n")

    verdicts = Counter(
        attempt["verdict"] for attempt in attempts
    )

    blocked_pairs = {
        (
            attempt["destination_ip"],
            attempt["destination_port"]
        )
        for attempt in attempts
        if attempt["verdict"] == "DROPPED"
    }

    print(f"\n=== {name} ===")
    print(f"Candidate events  : {len(events)}")
    print(f"Connection attempts: {len(attempts)}")
    print(f"Deduplicated events: {len(events) - len(attempts)}")
    print(f"Verdicts          : {dict(verdicts)}")
    print(f"Blocked IP:port   : {len(blocked_pairs)}")
    print(f"Output            : {output_path}")


if __name__ == "__main__":
    for scenario in SCENARIOS:
        normalize(scenario)
