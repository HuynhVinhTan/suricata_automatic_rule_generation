"""Offline SYN port-diversity evidence; not a Suricata rule."""

from collections import Counter, deque
from dataclasses import dataclass
from ipaddress import IPv4Address
from pathlib import Path
import math
import struct


@dataclass(frozen=True)
class SynEvent:
    timestamp: float
    src_ip: str
    dst_ip: str
    dst_port: int


@dataclass(frozen=True)
class PairFinding:
    src_ip: str
    dst_ip: str
    total_syn: int
    total_distinct_ports: int
    max_window_distinct_ports: int
    triggered: bool
    first_trigger_timestamp: float | None


def read_pcap_syn(path):
    """Read initial IPv4 TCP SYN packets from classic Ethernet PCAP."""
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
            raise ValueError("Expected classic PCAP, not PCAPNG")

        endian, resolution = formats[header[:4]]
        linktype = struct.unpack(endian + "I", header[20:24])[0]

        if linktype != 1:
            raise ValueError("Only Ethernet PCAP is supported")

        while True:
            record = stream.read(16)

            if not record:
                break

            if len(record) != 16:
                raise ValueError("Truncated PCAP record")

            sec, frac, caplen, _ = struct.unpack(
                endian + "IIII", record
            )

            packet = stream.read(caplen)

            if len(packet) != caplen:
                raise ValueError("Truncated PCAP packet")

            if len(packet) < 14:
                continue

            ethertype = int.from_bytes(packet[12:14], "big")
            offset = 14

            while ethertype in (0x8100, 0x88A8):
                if len(packet) < offset + 4:
                    break

                ethertype = int.from_bytes(
                    packet[offset + 2:offset + 4], "big"
                )
                offset += 4

            if ethertype != 0x0800:
                continue

            ip = packet[offset:]

            if len(ip) < 20 or ip[0] >> 4 != 4:
                continue

            ihl = (ip[0] & 15) * 4

            if ihl < 20 or len(ip) < ihl + 14:
                continue

            if ip[9] != 6:
                continue

            if int.from_bytes(ip[6:8], "big") & 0x1FFF:
                continue

            tcp = ip[ihl:]
            flags = tcp[13]

            if not flags & 0x02 or flags & 0x10:
                continue

            events.append(
                SynEvent(
                    timestamp=sec + frac / resolution,
                    src_ip=str(IPv4Address(ip[12:16])),
                    dst_ip=str(IPv4Address(ip[16:20])),
                    dst_port=int.from_bytes(tcp[2:4], "big"),
                )
            )

    return sorted(events, key=lambda item: item.timestamp)


def analyze_port_diversity(
    events, *, window_seconds=60, min_distinct_ports=8
):
    """Count distinct ports in (t - window_seconds, t] per IP pair."""
    if (
        not isinstance(window_seconds, (int, float))
        or not math.isfinite(window_seconds)
        or window_seconds <= 0
    ):
        raise ValueError("Invalid window_seconds")

    if (
        type(min_distinct_ports) is not int
        or min_distinct_ports < 1
    ):
        raise ValueError("Invalid min_distinct_ports")

    states = {}

    for event in sorted(events, key=lambda item: item.timestamp):
        if not math.isfinite(event.timestamp):
            raise ValueError("Invalid event timestamp")

        if (
            type(event.dst_port) is not int
            or not 1 <= event.dst_port <= 65535
        ):
            raise ValueError("Invalid destination port")

        pair = (event.src_ip, event.dst_ip)

        if pair not in states:
            states[pair] = {
                "queue": deque(),
                "counts": Counter(),
                "all_ports": set(),
                "total": 0,
                "peak": 0,
                "first": None,
            }

        state = states[pair]
        queue = state["queue"]
        counts = state["counts"]

        while (
            queue
            and event.timestamp - queue[0][0] >= window_seconds
        ):
            _, old_port = queue.popleft()
            counts[old_port] -= 1

            if counts[old_port] == 0:
                del counts[old_port]

        queue.append((event.timestamp, event.dst_port))
        counts[event.dst_port] += 1

        state["all_ports"].add(event.dst_port)
        state["total"] += 1
        state["peak"] = max(state["peak"], len(counts))

        if (
            state["first"] is None
            and len(counts) >= min_distinct_ports
        ):
            state["first"] = event.timestamp

    return [
        PairFinding(
            src_ip=src,
            dst_ip=dst,
            total_syn=state["total"],
            total_distinct_ports=len(state["all_ports"]),
            max_window_distinct_ports=state["peak"],
            triggered=state["first"] is not None,
            first_trigger_timestamp=state["first"],
        )
        for (src, dst), state in sorted(states.items())
    ]
