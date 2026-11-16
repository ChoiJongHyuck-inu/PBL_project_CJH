import argparse
import json
from collections import Counter
from pathlib import Path


def validate_file(path):
    counts = Counter()
    errors = []
    total = 0

    with path.open(encoding="utf-8") as f:
        for line_no, line in enumerate(f, 1):
            if not line.strip():
                continue

            total += 1

            try:
                record = json.loads(line)
            except json.JSONDecodeError as e:
                errors.append(f"Line {line_no}: Invalid JSON ({e.msg})")
                continue

            if not isinstance(record, dict):
                errors.append(f"Line {line_no}: Expected JSON object")
                continue

            flow = record.get("flow", record)

            if not isinstance(flow, dict):
                errors.append(f"Line {line_no}: Invalid flow object")
                continue

            timestamp = flow.get("time") or record.get("time")
            verdict = flow.get("verdict")

            ip = flow.get("IP") or flow.get("ip") or {}
            l4 = flow.get("l4") or {}

            if not timestamp:
                errors.append(f"Line {line_no}: Missing timestamp")

            if not verdict:
                errors.append(f"Line {line_no}: Missing verdict")
            else:
                counts[verdict] += 1

            if not isinstance(ip, dict) or not (
                ip.get("source") and ip.get("destination")
            ):
                errors.append(f"Line {line_no}: Missing source/destination IP")

            if not isinstance(l4, dict):
                errors.append(f"Line {line_no}: Invalid L4 data")
                continue

            tcp = l4.get("TCP") or {}
            udp = l4.get("UDP") or {}
            transport = tcp or udp

            if transport:
                port = transport.get("destination_port")
                try:
                    valid_port = 1 <= int(port) <= 65535
                except (TypeError, ValueError):
                    valid_port = False

                if not valid_port:
                    errors.append(f"Line {line_no}: Invalid destination port")

    print(f"\n=== {path.name} ===")
    print("Events :", total)
    print("Verdicts:", dict(counts))
    print("Errors :", len(errors))

    for error in errors[:5]:
        print(" -", error)

    if len(errors) > 5:
        print(f" ... {len(errors) - 5} more errors")

    if total == 0:
        print("ERROR: Empty log file")
        return False

    return not errors


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="+", type=Path)
    args = ap.parse_args()

    passed = 0

    for path in args.files:
        if not path.is_file():
            print(f"ERROR: File not found: {path}")
            continue

        if validate_file(path):
            passed += 1

    print(f"\nValidation: {passed}/{len(args.files)} files passed")

    if passed != len(args.files):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
