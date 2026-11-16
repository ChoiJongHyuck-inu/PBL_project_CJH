import json
import sys
import tempfile
import unittest

from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import parser
import normalizer


class TestProcessing(unittest.TestCase):

    def make_event(self, seconds=0, port=80):
        return {
            "timestamp": (
                f"2026-11-16T00:00:{seconds:02d}+00:00"
            ),
            "source_pod": "frontend-1",
            "source_namespace": "pbl-security",
            "source_ip": "10.244.0.10",
            "source_port": 40000,
            "destination_pod": "db-1",
            "destination_namespace": "pbl-security",
            "destination_ip": "10.244.0.30",
            "destination_port": port,
            "protocol": "TCP",
            "verdict": "DROPPED",
            "drop_reason": "POLICY_DENIED",
            "tcp_flags": {"SYN": True, "ACK": False},
        }

    def test_01_parse_tcp(self):
        raw = {
            "flow": {
                "time": "2026-11-16T00:00:00Z",
                "source": {
                    "pod_name": "frontend-1",
                    "namespace": "pbl-security"
                },
                "destination": {"pod_name": "db-1"},
                "IP": {
                    "source": "10.244.0.10",
                    "destination": "10.244.0.30"
                },
                "l4": {
                    "TCP": {
                        "source_port": 40000,
                        "destination_port": 80
                    }
                },
                "verdict": "DROPPED",
                "drop_reason_desc": "POLICY_DENIED"
            }
        }

        result = parser.parse_flow(raw)

        self.assertEqual(result["protocol"], "TCP")
        self.assertEqual(result["source_pod"], "frontend-1")
        self.assertEqual(result["destination_pod"], "db-1")
        self.assertEqual(result["destination_port"], 80)
        self.assertEqual(result["verdict"], "DROPPED")
        self.assertEqual(result["drop_reason"], "POLICY_DENIED")

    def test_02_parse_udp(self):
        raw = {
            "flow": {
                "l4": {
                    "UDP": {
                        "source_port": 50000,
                        "destination_port": 53
                    }
                },
                "verdict": "FORWARDED"
            }
        }

        result = parser.parse_flow(raw)

        self.assertEqual(result["protocol"], "UDP")
        self.assertEqual(result["destination_port"], 53)

    def test_03_forwarded_syn_filter(self):
        event = self.make_event()
        event["verdict"] = "FORWARDED"

        # TCP connection-start packet
        self.assertTrue(
            normalizer.is_connection_attempt(event)
        )

        # TCP reply packet
        event["tcp_flags"] = {
            "SYN": True,
            "ACK": True
        }

        self.assertFalse(
            normalizer.is_connection_attempt(event)
        )

    def test_04_healthcheck_filter(self):
        event = self.make_event()
        event["source_pod"] = None

        self.assertFalse(
            normalizer.is_connection_attempt(event)
        )

    def test_05_deduplication(self):
        with tempfile.TemporaryDirectory() as tmp:
            input_dir = Path(tmp) / "parsed"
            output_dir = Path(tmp) / "normalized"

            input_dir.mkdir()
            output_dir.mkdir()

            events = [
                self.make_event(0),
                self.make_event(2),
                self.make_event(13)
            ]

            input_file = input_dir / "sample.jsonl"

            with input_file.open("w") as f:
                for event in events:
                    f.write(json.dumps(event) + "\n")

            with patch.object(
                normalizer, "INPUT_DIR", input_dir
            ), patch.object(
                normalizer, "OUTPUT_DIR", output_dir
            ):
                normalizer.normalize("sample")

            output_file = output_dir / "sample.jsonl"

            with output_file.open() as f:
                attempts = [
                    json.loads(line)
                    for line in f if line.strip()
                ]

            # 0s and 2s are grouped.
            # 13s is a separate attempt.
            self.assertEqual(len(attempts), 2)

            self.assertEqual(
                attempts[0]["observed_events"], 2
            )

            self.assertEqual(
                attempts[1]["observed_events"], 1
            )


if __name__ == "__main__":
    unittest.main()
