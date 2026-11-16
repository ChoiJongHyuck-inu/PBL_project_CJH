import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import parser
import normalizer
import detector

FIXTURES = ROOT / "tests" / "fixtures"

EXPECTED = {
    "normal": "NORMAL",
    "unauthorized": "UNAUTHORIZED_EGRESS",
    "fanout": "DESTINATION_FANOUT",
    "portscan": "MULTI_PORT_SCAN",
}


def main():
    print("=== Synthetic Hubble Pipeline Test ===")

    passed = 0

    with tempfile.TemporaryDirectory() as tmp:
        temp = Path(tmp)

        parsed = temp / "parsed"
        normalized = temp / "normalized"

        parsed.mkdir()
        normalized.mkdir()

        for name, expected in EXPECTED.items():

            print(f"\n--- {name} ---")

            # Step 1: Parse raw Hubble JSONL
            with patch.object(parser, "RAW_DIR", FIXTURES), \
                 patch.object(parser, "OUT_DIR", parsed):
                parser.process_scenario(name)

            # Step 2: Normalize TCP events
            with patch.object(normalizer, "INPUT_DIR", parsed), \
                 patch.object(normalizer, "OUTPUT_DIR", normalized):
                normalizer.normalize(name)

            # Step 3: Apply detector
            path = normalized / f"{name}.jsonl"

            attempts, skipped = detector.load_attempts(path)
            prediction, rules, _ = detector.analyze(attempts)

            correct = prediction == expected
            passed += int(correct)

            print("Expected :", expected)
            print("Predicted:", prediction)
            print("Attempts :", len(attempts))
            print("Rules    :", sorted(rules))
            print("Result   :", "PASS" if correct else "FAIL")

    print("\n=== Final Result ===")
    print(f"Passed: {passed}/{len(EXPECTED)}")

    if passed != len(EXPECTED):
        raise SystemExit("SMOKE TEST FAILED")

    print("ALL PIPELINE TESTS PASSED")


if __name__ == "__main__":
    main()
