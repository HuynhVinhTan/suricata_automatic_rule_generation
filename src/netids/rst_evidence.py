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


def _capture_integrity(capture_metadata):
    """Return conservative completeness evidence; unknown remains ``None``."""
    metadata = capture_metadata if isinstance(capture_metadata, dict) else {}
    packet_records_complete = metadata.get("packet_records_complete")
    snaplen_truncated = metadata.get("snaplen_truncated")
    capture_drops = metadata.get("capture_drops")
    if any(value is not None and type(value) is not bool for value in (
        packet_records_complete, snaplen_truncated, capture_drops
    )):
        raise ValueError("Capture integrity fields must be boolean or unknown")
    if packet_records_complete is False or snaplen_truncated is True or capture_drops is True:
        complete = False
    elif packet_records_complete is True and snaplen_truncated is False and capture_drops is False:
        complete = True
    else:
        complete = None
    return {
        "packet_records_complete": packet_records_complete,
        "snaplen_truncated": snaplen_truncated,
        "capture_drops": capture_drops,
        "capture_complete": complete,
    }


def _nearest_syn(syns, pair, timestamp, window_seconds):
    candidates = [
        (syn_timestamp, seq)
        for syn_timestamp, seq in syns.get(pair, [])
        if syn_timestamp <= timestamp <= syn_timestamp + window_seconds
    ]
    return max(candidates, default=None)


def correlate_rst_events(events, *, window_seconds=60, capture_metadata=None):
    """Correlate server RST/RST-ACK packets with preceding client SYNs.

    Correlation uses the normalized client-port/destination-port pair, a
    preceding SYN time window, and (for RST-ACK) ``ack == syn_seq + 1`` with
    32-bit wraparound. Retransmissions are de-duplicated by packet identity,
    not timestamp. No-response traffic remains filtered/unknown evidence.
    """
    if type(window_seconds) is not int or window_seconds <= 0:
        raise ValueError("window_seconds must be a positive integer")
    events = _validate_events(events)
    deduplicated = []
    seen = set()
    for event in events:
        timestamp, pair, direction, seq, ack, flags, payload = event
        identity = (pair, direction, seq, ack, flags, payload)
        if identity in seen:
            continue
        seen.add(identity)
        deduplicated.append(event)

    syns = defaultdict(list)
    rst_packets = []
    handshakes = defaultdict(lambda: {
        "syn_seq": None,
        "server_seq": None,
        "synack": False,
        "ack": False,
        "client_payload": False,
        "server_payload": False,
    })

    for timestamp, pair, direction, seq, ack, flags, payload in deduplicated:
        state = handshakes[pair]
        if direction == "client" and flags & 0x02 and not flags & 0x10:
            if not any(existing_seq == seq for _time, existing_seq in syns[pair]):
                syns[pair].append((timestamp, seq))
                if state["syn_seq"] is None:
                    state["syn_seq"] = seq
        if direction == "server" and flags & 0x04:
            matched = _nearest_syn(syns, pair, timestamp, window_seconds)
            if matched is not None:
                _syn_timestamp, syn_seq = matched
                if not flags & 0x10 or ack == (syn_seq + 1) % (2 ** 32):
                    rst_packets.append((timestamp, pair, seq, ack, flags, payload))
        if direction == "server" and flags & 0x02 and flags & 0x10:
            matched = _nearest_syn(syns, pair, timestamp, window_seconds)
            if matched is not None and ack == (matched[1] + 1) % (2 ** 32):
                state["syn_seq"] = matched[1]
                state["server_seq"] = seq
                state["synack"] = True
        if direction == "client" and flags & 0x10 and not flags & 0x02:
            if (
                state["synack"]
                and state["syn_seq"] is not None
                and state["server_seq"] is not None
                and seq == (state["syn_seq"] + 1) % (2 ** 32)
                and ack == (state["server_seq"] + 1) % (2 ** 32)
            ):
                state["ack"] = True
        if payload > 0:
            state[f"{direction}_payload"] = True

    rst_packets = list(dict.fromkeys(rst_packets))
    pairs = set(syns)
    rst_pairs = {pair for _time, pair, _seq, _ack, _flags, _payload in rst_packets}
    handshake_pairs = {
        pair for pair, state in handshakes.items()
        if pair in pairs and state["synack"] and state["ack"]
    }
    payload_pairs = {
        pair for pair, state in handshakes.items()
        if pair in pairs and state["client_payload"] and state["server_payload"]
    }
    first_syn = min((timestamp for values in syns.values() for timestamp, _seq in values), default=None)
    windows = []
    if first_syn is not None:
        counts = defaultdict(int)
        for timestamp, _pair, _seq, _ack, _flags, _payload in rst_packets:
            counts[int((timestamp - first_syn) // window_seconds)] += 1
        windows = [counts[index] for index in sorted(counts)]

    syn_count = sum(len(values) for values in syns.values())
    rst_count = len(rst_packets)
    integrity = _capture_integrity(capture_metadata)
    return {
        "method": "offline_tcp_rst_correlation",
        "evidence_type": "protocol_heuristic_not_ml",
        "window_seconds": window_seconds,
        "initial_syn_packets": syn_count,
        "unique_destination_ports": len({pair[1] for pair in pairs}),
        "rst_count": rst_count,
        "rst_ack_count": sum(bool(flags & 0x10) for _time, _pair, _seq, _ack, flags, _payload in rst_packets),
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
        "capture_integrity": integrity,
    }


def analyze_rst_evidence(pcap, *, source_ip, destination_ip, window_seconds=60, capture_metadata=None):
    """Read an Ethernet PCAP and return RST correlation evidence."""
    evidence = correlate_rst_events(
        _tcp_events(pcap, source_ip, destination_ip),
        window_seconds=window_seconds,
        capture_metadata=capture_metadata,
    )
    evidence["source_pcap"] = str(pcap)
    return evidence
