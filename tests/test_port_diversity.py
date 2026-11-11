import pytest

from netids.port_diversity import (
    SynEvent,
    analyze_port_diversity,
)


def syn(t, port, src="192.0.2.10", dst="198.51.100.10"):
    return SynEvent(float(t), src, dst, port)


def test_repeated_ports_not_double_counted():
    events = [syn(i, 80) for i in range(20)]

    finding, = analyze_port_diversity(
        events, min_distinct_ports=2
    )

    assert finding.total_syn == 20
    assert finding.total_distinct_ports == 1
    assert finding.max_window_distinct_ports == 1
    assert not finding.triggered


def test_sliding_window_expiry_at_exact_boundary():
    finding, = analyze_port_diversity(
        [syn(0, 80), syn(60, 81)],
        min_distinct_ports=2,
    )

    assert finding.max_window_distinct_ports == 1
    assert not finding.triggered

    finding, = analyze_port_diversity(
        [syn(59.999, 81), syn(0, 80)],
        min_distinct_ports=2,
    )

    assert finding.max_window_distinct_ports == 2
    assert finding.triggered
    assert finding.first_trigger_timestamp == 59.999


def test_per_pair_isolation():
    events = [
        syn(0, 20),
        syn(1, 21),
        syn(2, 22, src="192.0.2.11"),
    ]

    findings = analyze_port_diversity(
        events, min_distinct_ports=3
    )

    assert len(findings) == 2
    assert not any(f.triggered for f in findings)


def test_attack_like_and_normal_like():
    attack = [syn(i * 2, 1000 + i) for i in range(26)]

    normal = [
        syn(i * 11, [80, 22][i % 2])
        for i in range(32)
    ]

    attack_finding, = analyze_port_diversity(attack)
    normal_finding, = analyze_port_diversity(normal)

    assert attack_finding.max_window_distinct_ports == 26
    assert attack_finding.triggered

    assert normal_finding.max_window_distinct_ports == 2
    assert not normal_finding.triggered


def test_whole_capture_distinct_ports_are_not_used_as_window_peak():
    finding, = analyze_port_diversity(
        [syn(0, 1000), syn(1, 1001), syn(61, 1002), syn(62, 1003)],
        min_distinct_ports=2,
    )
    assert finding.total_distinct_ports == 4
    assert finding.max_window_distinct_ports == 2
    assert finding.triggered is True


def test_invalid_threshold_rejected():
    with pytest.raises(ValueError):
        analyze_port_diversity([], min_distinct_ports=0)

    with pytest.raises(ValueError):
        analyze_port_diversity([], window_seconds=0)
