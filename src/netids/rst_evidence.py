"""Offline TCP RST correlation evidence for review-only experiments."""

from collections import defaultdict
import math

from netids.tcp_handshake import _tcp_events


def _validate_events(events):
    normalized = []
    for event in events:
        if not isinstance(event, (tuple, list)) or len(event) != 7:
            raise ValueError("TCP event must contain seven fields")
        timestamp, pair, direction, seq, ack, flags, payload = event
        if not isinstance(timestamp, (int, float)) or not math.isfinite(timestamp):
            raise ValueError("TCP event timestamp must be finite")
        if timestamp < 0:
            raise ValueError("TCP event timestamp cannot be negative")
        if (
            not isinstance(pair, (tuple, list))
            or len(pair) != 2
            or any(type(port) is not int or not 1 <= port <= 65535 for port in pair)
        ):
            raise ValueError("TCP event port pair is invalid")
        if direction not in {"client", "server"}:
            raise ValueError("TCP event direction is invalid")
        if any(type(value) is not int or value < 0 for value in (seq, ack, flags, payload)):
            raise ValueError("TCP event numeric fields are invalid")
        normalized.append((float(timestamp), tuple(pair), direction, seq, ack, flags, payload))
    return sorted(normalized, key=lambda event: event[0])


def correlate_rst_events(events, *, window_seconds=60):
    """Correlate directed TCP events without counting retransmissions twice.

    The returned values are protocol evidence only. A server-direction RST or
    RST-ACK is associated with a preceding client SYN on the same normalized
    client-port/destination-port pair. No-response traffic is retained as
    filtered/unknown evidence and is never classified as a closed port.
    """
    if type(window_seconds) is not int or window_seconds <= 0:
        raise ValueError("window_seconds must be a positive integer")
    events = _validate_events(events)
    unique = list(dict.fromkeys(events))
    syns = {}
    rsts = {}
    handshakes = defaultdict(lambda: {"synack": False, "ack": False, "client_payload": False, "server_payload": False})

    for timestamp, pair, direction, seq, ack, flags, payload in unique:
        state = handshakes[pair]
        if direction == "client" and flags & 0x02 and not flags & 0x10:
            syns.setdefault((pair, seq), timestamp)
        if direction == "server" and flags & 0x02 and flags & 0x10:
            state["synack"] = True
        if direction == "client" and flags & 0x10 and not flags & 0x02:
            state["ack"] = True
        if payload > 0:
            state[f"{direction}_payload"] = True
        if direction == "server" and flags & 0x04 and any(key[0] == pair and value <= timestamp for key, value in syns.items()):
            rsts.setdefault((pair, seq, ack, flags, payload), timestamp)

    pair_syn_times = defaultdict(list)
    for (pair, _seq), timestamp in syns.items():
        pair_syn_times[pair].append(timestamp)
    pairs = set(pair for pair, _seq in syns)
    rst_pairs = {event[0] for event in rsts}
    handshake_pairs = {
        pair for pair, state in handshakes.items()
        if pair in pairs and state["synack"] and state["ack"]
    }
    payload_pairs = {
        pair for pair, state in handshakes.items()
        if pair in pairs and state["client_payload"] and state["server_payload"]
    }
    first_syn = min(syns.values()) if syns else None
    windows = []
    if first_syn is not None:
        counts = defaultdict(int)
        for timestamp in rsts.values():
            counts[int((timestamp - first_syn) // window_seconds)] += 1
        windows = [counts[index] for index in sorted(counts)]

    syn_count = len(syns)
    rst_count = len(rsts)
    return {
        "method": "offline_tcp_rst_correlation",
        "evidence_type": "protocol_heuristic_not_ml",
        "window_seconds": window_seconds,
        "initial_syn_packets": syn_count,
        "unique_destination_ports": len({pair[1] for pair in pairs}),
        "rst_count": rst_count,
        "rst_ack_count": sum(bool(flags & 0x10) for _pair, _seq, _ack, flags, _payload in rsts),
        "rst_ratio": rst_count / syn_count if syn_count else 0.0,
        "rst_flows": len(rst_pairs),
        "handshake_success_count": len(handshake_pairs),
        "handshake_success_ratio": len(handshake_pairs) / syn_count if syn_count else 0.0,
        "bidirectional_payload_count": len(payload_pairs),
        "bidirectional_payload_ratio": len(payload_pairs) / syn_count if syn_count else 0.0,
        "failed_connection_count": max(0, syn_count - len(handshake_pairs)),
        "filtered_no_response_count": max(0, syn_count - len(handshake_pairs) - len(rst_pairs)),
        "rst_counts_by_window": windows,
        "max_rst_count_per_window": max(windows, default=0),
        "capture_complete": True,
    }


def analyze_rst_evidence(pcap, *, source_ip, destination_ip, window_seconds=60):
    """Read an Ethernet PCAP and return RST correlation evidence."""
    events = _tcp_events(pcap, source_ip, destination_ip)
    evidence = correlate_rst_events(events, window_seconds=window_seconds)
    evidence["source_pcap"] = str(pcap)
    return evidence
