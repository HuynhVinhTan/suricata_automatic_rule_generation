"""Synthetic packet-level tests for TCP handshake evidence."""

import struct

import pytest

from netids.tcp_handshake import summarize_tcp_handshake


SRC = bytes([192, 0, 2, 10])
DST = bytes([198, 51, 100, 20])


def packet(direction, flags, seq, ack, payload=b"", port=80):
    if direction == "client":
        source, destination = SRC, DST
        sport, dport = 40000, port
    else:
        source, destination = DST, SRC
        sport, dport = port, 40000

    tcp = struct.pack(
        "!HHIIHHHH",
        sport,
        dport,
        seq,
        ack,
        (5 << 12) | flags,
        8192,
        0,
        0,
    ) + payload

    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(tcp),
        0,
        0,
        64,
        6,
        0,
        source,
        destination,
    )

    return b"\x00" * 12 + b"\x08\x00" + ip + tcp


def make_pcap(tmp_path, frames):
    path = tmp_path / "test.pcap"

    content = (
        b"\xd4\xc3\xb2\xa1"
        + struct.pack("<HHIIII", 2, 4, 0, 0, 96, 1)
    )

    for index, frame in enumerate(frames):
        content += struct.pack(
            "<IIII", index, 0, len(frame), len(frame)
        ) + frame

    path.write_bytes(content)
    return path


def summary(tmp_path, frames):
    path = make_pcap(tmp_path, frames)

    return summarize_tcp_handshake(
        path,
        source_ip="192.0.2.10",
        destination_ip="198.51.100.20",
    )


def test_completed_handshake_and_data(tmp_path):
    result = summary(tmp_path, [
        packet("client", 0x02, 100, 0),
        packet("server", 0x12, 500, 101),
        packet("client", 0x10, 101, 501),
        packet("client", 0x18, 101, 501, b"GET"),
        packet("server", 0x18, 501, 104, b"OK"),
    ])

    assert result["initial_syn_packets"] == 1
    assert result["flows_with_valid_synack"] == 1
    assert result["flows_with_confirmed_handshake"] == 1
    assert result["flows_with_bidirectional_payload"] == 1
    assert result["ports_with_confirmed_handshake"] == 1


def test_syn_scan_without_handshake(tmp_path):
    result = summary(tmp_path, [
        packet("client", 0x02, 100, 0),
        packet("server", 0x14, 500, 101),
    ])

    assert result["initial_syn_packets"] == 1
    assert result["flows_with_valid_synack"] == 0
    assert result["flows_with_confirmed_handshake"] == 0
    assert result["flows_with_rst"] == 1


def test_synack_requires_correct_ack_number(tmp_path):
    result = summary(tmp_path, [
        packet("client", 0x02, 100, 0),
        packet("server", 0x12, 500, 999),
        packet("client", 0x10, 101, 501),
    ])

    assert result["flows_with_valid_synack"] == 0
    assert result["flows_with_confirmed_handshake"] == 0


def test_final_ack_requires_correct_sequence(tmp_path):
    result = summary(tmp_path, [
        packet("client", 0x02, 100, 0),
        packet("server", 0x12, 500, 101),
        packet("client", 0x10, 999, 501),
    ])

    assert result["flows_with_valid_synack"] == 1
    assert result["flows_with_confirmed_handshake"] == 0


def test_retransmitted_syn_not_another_flow(tmp_path):
    result = summary(tmp_path, [
        packet("client", 0x02, 100, 0),
        packet("client", 0x02, 100, 0),
        packet("server", 0x12, 500, 101),
        packet("client", 0x10, 101, 501),
    ])

    assert result["initial_syn_packets"] == 2
    assert result["syn_flows"] == 1
    assert result["flows_with_confirmed_handshake"] == 1


def test_reject_truncated_pcap(tmp_path):
    path = tmp_path / "broken.pcap"
    path.write_bytes(b"\xd4\xc3\xb2\xa1")

    with pytest.raises(ValueError):
        summarize_tcp_handshake(
            path,
            source_ip="192.0.2.10",
            destination_ip="198.51.100.20",
        )
