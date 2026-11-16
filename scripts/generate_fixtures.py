import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

OUTPUT = Path(__file__).resolve().parents[1] / "tests/fixtures"
OUTPUT.mkdir(parents=True, exist_ok=True)

BASE = datetime(2026, 11, 16, tzinfo=timezone.utc)

PODS = {
    "frontend": ("frontend-demo", "10.244.0.10"),
    "backend": ("backend-demo", "10.244.0.20"),
    "db": ("db-demo", "10.244.0.30"),
    "api": (None, "10.96.0.1"),
}


def make_flow(
    second,
    source,
    destination,
    port,
    verdict,
    source_port=None,
):
    src_name, src_ip = PODS[source]
    dst_name, dst_ip = PODS[destination]

    if source_port is None:
        source_port = 41000 + second

    timestamp = (
        BASE + timedelta(seconds=second)
    ).isoformat().replace("+00:00", "Z")

    return {
        "flow": {
            "time": timestamp,
            "source": {
                "pod_name": src_name,
                "namespace": "pbl-security",
            },
            "destination": {
                "pod_name": dst_name,
                "namespace": (
                    "pbl-security" if dst_name else None
                ),
            },
            "IP": {
                "source": src_ip,
                "destination": dst_ip,
            },
            "l4": {
                "TCP": {
                    "source_port": source_port,
                    "destination_port": port,
                    "flags": {
                        "SYN": True,
                        "ACK": False,
                    },
                }
            },
            "verdict": verdict,
            "drop_reason_desc": (
                "POLICY_DENIED"
                if verdict == "DROPPED" else None
            ),
        }
    }


SCENARIOS = {
    "normal": [
        make_flow(0, "frontend", "backend", 80, "FORWARDED"),
        make_flow(1, "backend", "db", 80, "FORWARDED"),
    ],

    "unauthorized": [
        make_flow(
            0, "frontend", "db", 80,
            "DROPPED", source_port=41000
        ),
        make_flow(
            2, "frontend", "db", 80,
            "DROPPED", source_port=41000
        ),
    ],

    "fanout": [
        make_flow(0, "frontend", "backend", 80, "FORWARDED"),
        make_flow(1, "frontend", "db", 80, "DROPPED"),
        make_flow(2, "frontend", "api", 80, "DROPPED"),
    ],

    "portscan": [
        make_flow(
            i, "frontend", "backend", port, "DROPPED"
        )
        for i, port in enumerate([22, 443, 3306, 6379])
    ],
}


def main():
    for name, records in SCENARIOS.items():
        path = OUTPUT / f"{name}.jsonl"

        with path.open("w", encoding="utf-8") as f:
            for record in records:
                f.write(
                    json.dumps(record, ensure_ascii=False) + "\n"
                )

        print(f"Created: {path.name} ({len(records)} events)")

    print("\nAll synthetic fixtures generated.")


if __name__ == "__main__":
    main()
