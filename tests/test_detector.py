import json
import sys
import tempfile
import unittest

from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import detector


class TestDetector(unittest.TestCase):

    def make_event(
        self, seconds, ip, port,
        verdict="DROPPED", dst="backend-1"
    ):
        timestamp = (
            datetime(2026, 11, 16, tzinfo=timezone.utc)
            + timedelta(seconds=seconds)
        ).isoformat()

        return {
            "timestamp": timestamp,
            "source_pod": "frontend-1",
            "source_namespace": "pbl-security",
            "source_ip": "10.244.0.10",
            "source_port": 40000 + seconds,
            "destination_pod": dst,
            "destination_ip": ip,
            "destination_port": port,
            "protocol": "TCP",
            "verdict": verdict,
            "drop_reason": (
                "POLICY_DENIED"
                if verdict == "DROPPED" else None
            ),
        }

    def predict(self, events, window=180):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "test.jsonl"

            with path.open("w") as f:
                for event in events:
                    f.write(json.dumps(event) + "\n")

            attempts, skipped = detector.load_attempts(path)

            with patch.object(detector, "WINDOW_SECONDS", window):
                decision, rules, _ = detector.analyze(attempts)

            return decision, rules

    def test_01_normal(self):
        events = [
            self.make_event(
                0, "10.244.0.20", 80,
                "FORWARDED", "backend-1"
            )
        ]
        decision, rules = self.predict(events)
        self.assertEqual(decision, "NORMAL")
        self.assertEqual(rules, set())

    def test_02_unauthorized_egress(self):
        events = [
            self.make_event(0, "10.244.0.30", 80, dst="db-1")
        ]
        decision, rules = self.predict(events)
        self.assertEqual(decision, "UNAUTHORIZED_EGRESS")
        self.assertIn("R1_UNAUTHORIZED_EGRESS", rules)

    def test_03_destination_fanout(self):
        events = [
            self.make_event(
                0, "10.244.0.20", 80,
                "FORWARDED", "backend-1"
            ),
            self.make_event(1, "10.244.0.30", 80, dst="db-1"),
            self.make_event(2, "10.96.0.1", 80, dst=None),
        ]
        decision, rules = self.predict(events)
        self.assertEqual(decision, "DESTINATION_FANOUT")
        self.assertIn("R2_DESTINATION_FANOUT", rules)

    def test_04_multi_port_scan(self):
        ports = [22, 443, 3306, 6379]
        events = [
            self.make_event(i, "10.244.0.20", port)
            for i, port in enumerate(ports)
        ]
        decision, rules = self.predict(events)
        self.assertEqual(decision, "MULTI_PORT_SCAN")
        self.assertIn("R3_MULTI_PORT_SCAN", rules)

    def test_05_below_port_threshold(self):
        ports = [22, 443, 3306]
        events = [
            self.make_event(i, "10.244.0.20", port)
            for i, port in enumerate(ports)
        ]
        decision, rules = self.predict(events)
        self.assertEqual(decision, "UNAUTHORIZED_EGRESS")
        self.assertNotIn("R3_MULTI_PORT_SCAN", rules)

    def test_06_slow_scan_window(self):
        ports = [22, 443, 3306, 6379]
        events = [
            self.make_event(i * 45, "10.244.0.20", port)
            for i, port in enumerate(ports)
        ]

        short_decision, _ = self.predict(events, window=120)
        long_decision, _ = self.predict(events, window=180)

        self.assertEqual(short_decision, "UNAUTHORIZED_EGRESS")
        self.assertEqual(long_decision, "MULTI_PORT_SCAN")

    def test_07_forwarded_ports(self):
        ports = [22, 443, 3306, 6379]
        events = [
            self.make_event(
                i, "10.244.0.20", port, "FORWARDED"
            )
            for i, port in enumerate(ports)
        ]
        decision, rules = self.predict(events)
        self.assertEqual(decision, "NORMAL")
        self.assertNotIn("R3_MULTI_PORT_SCAN", rules)


if __name__ == "__main__":
    unittest.main()
