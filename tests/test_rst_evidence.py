"""Unit tests for independent TCP RST evidence."""

import math

import pytest

from netids.rst_evidence import correlate_rst_events


def test_rst_ack_matches_server_reverse_direction():
    result = correlate_rst_events([
        (1.0, (40000, 18100), "client", 100, 0, 0x02, 0),
        (1.01, (40000, 18100), "server", 200, 101, 0x14, 0),
    ])
    assert result["rst_count"] == 1
    assert result["rst_ack_count"] == 1
    assert result["rst_ratio"] == 1.0
    assert result["filtered_no_response_count"] == 0


def test_retransmitted_syn_and_rst_are_counted_once():
    event = (1.0, (40000, 18100), "client", 100, 0, 0x02, 0)
    rst = (1.01, (40000, 18100), "server", 200, 101, 0x14, 0)
    result = correlate_rst_events([event, event, rst, rst])
    assert result["initial_syn_packets"] == 1
    assert result["rst_count"] == 1


def test_repeated_legitimate_closed_port_responses_remain_distinct_flows():
    events = []
    for index in range(3):
        port = 18100 + index
        events.extend([
            (float(index), (40000 + index, port), "client", 100 + index, 0, 0x02, 0),
            (float(index) + 0.01, (40000 + index, port), "server", 200 + index, 101 + index, 0x14, 0),
        ])
    result = correlate_rst_events(events)
    assert result["initial_syn_packets"] == 3
    assert result["rst_count"] == 3
    assert result["rst_flows"] == 3
    assert result["handshake_success_count"] == 0


def test_incomplete_capture_is_not_called_closed():
    result = correlate_rst_events([(1.0, (40000, 18100), "client", 100, 0, 0x02, 0)])
    assert result["rst_count"] == 0
    assert result["filtered_no_response_count"] == 1
    assert result["capture_integrity"]["capture_complete"] is None


def test_mixed_open_and_closed_ports_preserves_each_outcome():
    result = correlate_rst_events([
        (1.0, (40000, 18100), "client", 100, 0, 0x02, 0),
        (1.01, (40000, 18100), "server", 200, 101, 0x12, 0),
        (1.02, (40000, 18100), "client", 101, 201, 0x10, 0),
        (1.03, (40000, 18100), "client", 101, 201, 0x18, 5),
        (1.04, (40000, 18100), "server", 201, 106, 0x18, 5),
        (3.0, (40001, 18101), "client", 300, 0, 0x02, 0),
        (3.01, (40001, 18101), "server", 400, 301, 0x14, 0),
    ])
    assert result["initial_syn_packets"] == 2
    assert result["rst_count"] == 1
    assert result["handshake_success_count"] == 1
    assert result["bidirectional_payload_count"] == 1
    assert result["failed_connection_count"] == 1


def test_zero_syn_packets_has_zero_ratios():
    result = correlate_rst_events([])
    assert result["initial_syn_packets"] == 0
    assert result["rst_ratio"] == 0.0
    assert result["handshake_success_ratio"] == 0.0


def test_invalid_timestamp_is_rejected():
    with pytest.raises(ValueError):
        correlate_rst_events([(math.nan, (40000, 18100), "client", 1, 0, 2, 0)])


def test_rst_ack_must_match_syn_sequence_plus_one_with_wraparound():
    result = correlate_rst_events([
        (1.0, (40000, 18100), "client", 0xFFFFFFFF, 0, 0x02, 0),
        (1.01, (40000, 18100), "server", 200, 7, 0x14, 0),
    ])
    assert result["rst_count"] == 0


def test_rst_ack_wraparound_valid_ack_is_correlated():
    result = correlate_rst_events([
        (1.0, (40000, 18100), "client", 0xFFFFFFFF, 0, 0x02, 0),
        (1.01, (40000, 18100), "server", 200, 0, 0x14, 0),
    ])
    assert result["rst_ack_count"] == 1
    assert result["rst_count"] == 1


def test_rst_window_and_integrity_metadata_are_conservative():
    events = [
        (1.0, (40000, 18100), "client", 100, 0, 0x02, 0),
        (62.0, (40000, 18100), "server", 200, 101, 0x14, 0),
    ]
    outside = correlate_rst_events(events, window_seconds=60)
    assert outside["rst_count"] == 0
    unknown = correlate_rst_events(events, capture_metadata={})
    assert unknown["capture_integrity"]["capture_complete"] is None
    incomplete = correlate_rst_events(
        events,
        capture_metadata={"packet_records_complete": False, "snaplen_truncated": False, "capture_drops": False},
    )
    assert incomplete["capture_integrity"]["capture_complete"] is False
