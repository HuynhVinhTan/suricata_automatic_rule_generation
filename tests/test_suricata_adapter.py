import math
import unittest

import pandas as pd

from netids.adapters.suricata import (
    suricata_eve_to_features,
    FEATURE_NAMES,
)

from netids.features.schema import validate_feature_matrix


class TestSuricataAdapter(unittest.TestCase):

    def make_tcp_event(self):
        return {
            "event_type": "flow",
            "proto": "TCP",
            "flow": {
                "start": "2026-10-29T12:00:00+07:00",
                "end": "2026-10-29T12:00:00.049435+07:00",
                "age": 0,
                "pkts_toserver": 2,
                "pkts_toclient": 1,
                "bytes_toserver": 182,
                "bytes_toclient": 154,
                "state": "new",
                "reason": "timeout",
            },
        }

    def make_udp_event(self):
        return {
            "event_type": "flow",
            "proto": "UDP",
            "flow": {
                "start": "2026-10-29T12:00:00+07:00",
                "end": "2026-10-29T12:00:00.430434+07:00",
                "age": 1,
                "pkts_toserver": 4,
                "pkts_toclient": 0,
                "bytes_toserver": 344,
                "bytes_toclient": 0,
                "state": "new",
                "reason": "timeout",
            },
        }

    def test_tcp_features(self):
        features = suricata_eve_to_features(
            self.make_tcp_event()
        )

        self.assertEqual(
            tuple(features.keys()),
            FEATURE_NAMES,
        )

        self.assertEqual(features["protocol_tcp"], 1)

        self.assertAlmostEqual(
            features["duration_log"],
            math.log1p(0.049435),
            places=12,
        )

        self.assertAlmostEqual(
            features["packets_log"],
            math.log1p(3),
            places=12,
        )

        self.assertAlmostEqual(
            features["bytes_log"],
            math.log1p(336),
            places=12,
        )

    def test_udp_uses_timestamp_duration(self):
        features = suricata_eve_to_features(
            self.make_udp_event()
        )

        self.assertEqual(features["protocol_tcp"], 0)

        self.assertAlmostEqual(
            features["duration_log"],
            math.log1p(0.430434),
            places=12,
        )

        self.assertAlmostEqual(
            features["packets_log"],
            math.log1p(4),
            places=12,
        )

        self.assertAlmostEqual(
            features["bytes_log"],
            math.log1p(344),
            places=12,
        )

    def test_feature_schema_compatible(self):
        features = suricata_eve_to_features(
            self.make_tcp_event()
        )

        frame = pd.DataFrame([features])

        validated = validate_feature_matrix(frame)

        self.assertEqual(validated.shape, (1, 4))

    def test_non_flow_event_rejected(self):
        event = self.make_tcp_event()
        event["event_type"] = "alert"

        with self.assertRaises(ValueError):
            suricata_eve_to_features(event)

    def test_unsupported_protocol_rejected(self):
        event = self.make_tcp_event()
        event["proto"] = "ICMP"

        with self.assertRaises(ValueError):
            suricata_eve_to_features(event)

    def test_missing_counter_rejected(self):
        event = self.make_tcp_event()
        del event["flow"]["bytes_toclient"]

        with self.assertRaises(ValueError):
            suricata_eve_to_features(event)

    def test_negative_counter_rejected(self):
        event = self.make_tcp_event()
        event["flow"]["pkts_toserver"] = -1

        with self.assertRaises(ValueError):
            suricata_eve_to_features(event)

    def test_invalid_duration_rejected(self):
        event = self.make_tcp_event()

        event["flow"]["end"] = (
            "2026-10-29T11:59:59+07:00"
        )

        with self.assertRaises(ValueError):
            suricata_eve_to_features(event)

    def test_timezone_required(self):
        event = self.make_tcp_event()

        event["flow"]["start"] = (
            "2026-10-29T12:00:00"
        )

        with self.assertRaises(ValueError):
            suricata_eve_to_features(event)


if __name__ == "__main__":
    unittest.main()