"""Offline TCP handshake evidence, not an attack classifier."""

from collections import defaultdict
from ipaddress import IPv4Address
from pathlib import Path
import struct


def _tcp_events(path, source_ip, destination_ip):
    source = IPv4Address(source_ip).packed
    destination = IPv4Address(destination_ip).packed

    formats = {
        b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
        b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
        b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
        b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
    }

    events = []

    with Path(path).open("rb") as stream:
        header = stream.read(24)

        if len(header) != 24 or header[:4] not in formats:
            raise ValueError("Expected classic PCAP")

        endian, resolution = formats[header[:4]]
        linktype = struct.unpack(endian + "I", header[20:24])[0]

        if linktype != 1:
            raise ValueError("Only Ethernet PCAP supported")

        while True:
            record = stream.read(16)

            if not record:
                break

            if len(record) != 16:
                raise ValueError("Truncated PCAP record")

            sec, frac, caplen, _ = struct.unpack(
                endian + "IIII", record
            )

            frame = stream.read(caplen)

            if len(frame) != caplen:
                raise ValueError("Truncated PCAP frame")

            if len(frame) < 14:
                continue

            ethertype = int.from_bytes(frame[12:14], "big")
            offset = 14

            while ethertype in (0x8100, 0x88A8):
                if len(frame) < offset + 4:
                    break

                ethertype = int.from_bytes(
                    frame[offset + 2:offset + 4], "big"
                )
                offset += 4

            if ethertype != 0x0800:
                continue

            ip = frame[offset:]

            if len(ip) < 20 or ip[0] >> 4 != 4:
                continue

            ihl = (ip[0] & 15) * 4

            if ihl < 20 or len(ip) < ihl + 20:
                continue

            if ip[9] != 6:
                continue

            if int.from_bytes(ip[6:8], "big") & 0x1FFF:
                continue

            if ip[12:16] == source and ip[16:20] == destination:
                direction = "client"
            elif ip[12:16] == destination and ip[16:20] == source:
                direction = "server"
            else:
                continue

            tcp = ip[ihl:]
            tcp_len = (tcp[12] >> 4) * 4

            if tcp_len < 20 or len(tcp) < tcp_len:
                continue

            sport = int.from_bytes(tcp[0:2], "big")
            dport = int.from_bytes(tcp[2:4], "big")

            pair = (
                (sport, dport)
                if direction == "client"
                else (dport, sport)
            )

            seq = int.from_bytes(tcp[4:8], "big")
            ack = int.from_bytes(tcp[8:12], "big")
            flags = tcp[13]

            total_len = int.from_bytes(ip[2:4], "big")
            payload_len = max(0, total_len - ihl - tcp_len)

            events.append((
                sec + frac / resolution,
                pair,
                direction,
                seq,
                ack,
                flags,
                payload_len,
            ))

    return sorted(events, key=lambda event: event[0])


def summarize_tcp_handshake(
    pcap, *, source_ip, destination_ip
):
    """Summarize observed TCP evidence for one directed IP pair.

    A confirmed handshake requires a client SYN, a server
    SYN-ACK acknowledging that SYN, and a client ACK
    acknowledging the matching server SYN.

    This is offline evidence only. It does not establish
    whether traffic is malicious or benign.
    """
    states = defaultdict(lambda: {
        "syn_packets": 0,
        "client_isn": None,
        "server_isn": None,
        "valid_synack": False,
        "handshake": False,
        "client_payload": False,
        "server_payload": False,
        "rst": False,
    })

    events = _tcp_events(
        pcap, source_ip, destination_ip
    )

    for _, pair, direction, seq, ack, flags, payload in events:
        state = states[pair]

        syn = bool(flags & 0x02)
        ack_flag = bool(flags & 0x10)

        if flags & 0x04:
            state["rst"] = True

        if direction == "client":
            if syn and not ack_flag:
                state["syn_packets"] += 1

                if state["client_isn"] is None:
                    state["client_isn"] = seq

            if (
                ack_flag
                and not syn
                and state["valid_synack"]
                and state["client_isn"] is not None
                and state["server_isn"] is not None
                and seq == (
                    state["client_isn"] + 1
                ) % (2 ** 32)
                and ack == (
                    state["server_isn"] + 1
                ) % (2 ** 32)
            ):
                state["handshake"] = True

            if payload > 0:
                state["client_payload"] = True

        else:
            if (
                syn and ack_flag
                and state["client_isn"] is not None
                and ack == (
                    state["client_isn"] + 1
                ) % (2 ** 32)
            ):
                state["server_isn"] = seq
                state["valid_synack"] = True

            if payload > 0:
                state["server_payload"] = True

    observed = {
        pair: state
        for pair, state in states.items()
        if state["syn_packets"] > 0
    }

    return {
        "method": "offline_tcp_three_way_handshake_evidence",
        "evidence_type": "protocol_heuristic_not_ml",
        "initial_syn_packets": sum(
            state["syn_packets"]
            for state in observed.values()
        ),
        "syn_flows": len(observed),
        "distinct_destination_ports": len({
            pair[1] for pair in observed
        }),
        "flows_with_valid_synack": sum(
            state["valid_synack"]
            for state in observed.values()
        ),
        "flows_with_confirmed_handshake": sum(
            state["handshake"]
            for state in observed.values()
        ),
        "flows_with_server_payload": sum(
            state["server_payload"]
            for state in observed.values()
        ),
        "flows_with_bidirectional_payload": sum(
            state["client_payload"] and state["server_payload"]
            for state in observed.values()
        ),
        "flows_with_rst": sum(
            state["rst"]
            for state in observed.values()
        ),
        "ports_with_confirmed_handshake": len({
            pair[1]
            for pair, state in observed.items()
            if state["handshake"]
        }),
        "ports_with_server_payload": len({
            pair[1]
            for pair, state in observed.items()
            if state["server_payload"]
        }),
    }
