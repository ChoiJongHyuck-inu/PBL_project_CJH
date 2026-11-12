import json
from collections import Counter
from pathlib import Path

RAW_DIR = Path("results/raw")
OUT_DIR = Path("results/parsed")
OUT_DIR.mkdir(parents=True, exist_ok=True)

SCENARIOS = [
    "normal",
    "abnormal_1",
    "abnormal_2",
    "abnormal_3",
]


def parse_flow(record):
    flow = record.get("flow") or record

    source = flow.get("source") or {}
    destination = flow.get("destination") or {}
    ip = flow.get("IP") or flow.get("ip") or {}
    l4 = flow.get("l4") or {}

    tcp = l4.get("TCP") or {}
    udp = l4.get("UDP") or {}

    transport = tcp or udp
    protocol = "TCP" if tcp else "UDP" if udp else "OTHER"

    return {
        "timestamp": flow.get("time") or record.get("time"),
        "source_pod": source.get("pod_name"),
        "source_namespace": source.get("namespace"),
        "source_ip": ip.get("source"),
        "destination_pod": destination.get("pod_name"),
        "destination_namespace": destination.get("namespace"),
        "destination_ip": ip.get("destination"),
        "source_port": transport.get("source_port"),
        "destination_port": transport.get("destination_port"),
        "protocol": protocol,
        "verdict": flow.get("verdict"),
        "drop_reason": flow.get("drop_reason_desc"),
        "tcp_flags": tcp.get("flags") if tcp else None,
    }


def process_scenario(name):
    input_path = RAW_DIR / f"{name}.jsonl"
    output_path = OUT_DIR / f"{name}.jsonl"

    verdicts = Counter()
    blocked_pairs = set()
    errors = 0
    total = 0

    with input_path.open(encoding="utf-8") as source, \
         output_path.open("w", encoding="utf-8") as target:

        for line in source:
            if not line.strip():
                continue

            try:
                record = json.loads(line)
                event = parse_flow(record)
            except (ValueError, TypeError, AttributeError):
                errors += 1
                continue

            json.dump(event, target, ensure_ascii=False)
            target.write("\n")

            total += 1
            verdicts[event["verdict"]] += 1

            if event["verdict"] == "DROPPED":
                blocked_pairs.add((
                    event["source_pod"],
                    event["destination_ip"],
                    event["destination_port"],
                ))

    print(f"\n[{name}]")
    print(f"  Events       : {total}")
    print(f"  Verdicts     : {dict(verdicts)}")
    print(f"  Parse errors : {errors}")
    print(f"  Blocked pairs: {len(blocked_pairs)}")
    print(f"  Output       : {output_path}")


if __name__ == "__main__":
    for scenario in SCENARIOS:
        process_scenario(scenario)
