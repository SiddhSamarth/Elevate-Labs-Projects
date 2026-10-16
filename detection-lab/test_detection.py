#!/usr/bin/env python3
"""Dependency-free tests for the failed-logon detection lab."""
import json
import unittest
from pathlib import Path

from detect_failed_logons import detect, read_events

HERE = Path(__file__).resolve().parent


class FailedLogonDetectionTests(unittest.TestCase):
    def setUp(self):
        self.events = read_events(HERE / "sample_windows_auth_events.jsonl")

    def test_sample_matches_expected_alerts(self):
        alerts = detect(self.events, threshold=5, window_minutes=10)
        expected = json.loads((HERE / "expected_alerts.json").read_text(encoding="utf-8"))
        self.assertEqual(alerts, expected)

    def test_only_two_groups_cross_threshold(self):
        alerts = detect(self.events, threshold=5, window_minutes=10)
        self.assertEqual(len(alerts), 2)
        self.assertEqual({row["IpAddress"] for row in alerts}, {"198.51.100.25", "203.0.113.77"})

    def test_successful_logon_is_not_counted(self):
        alerts = detect(self.events, threshold=5, window_minutes=10)
        attack_burst = next(row for row in alerts if row["IpAddress"] == "198.51.100.25")
        self.assertEqual(attack_burst["FailureCount"], 5)
        self.assertEqual(attack_burst["DistinctAccounts"], 5)

    def test_higher_threshold_reduces_alerts(self):
        alerts = detect(self.events, threshold=6, window_minutes=10)
        self.assertEqual(alerts, [])


if __name__ == "__main__":
    unittest.main()
