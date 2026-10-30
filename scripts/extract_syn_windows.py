"""Extract TCP SYN behavior features from classic Ethernet PCAP."""

import argparse
import csv
import hashlib
import ipaddress
import statistics
import struct
from collections import defaultdict
from pathlib import Path

MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("<", 1000000),
    b"\xa1\xb2\xc3\xd4": (">", 1000000),
    b"\x4d\x3c\xb2\xa1": ("<", 1000000000),
    b"\xa1\xb2\x3c\x4d": (">", 1000000000),
}


def read_syn_events(pcap, src, dst):
    events = []

    with pcap.open("rb") as f:
        header = f.read(24)

        if len(header) != 24 or header[:4] not in MAGIC:
            raise ValueError("Only classic PCAP is supported")

        endian, units = MAGIC[header[:4]]

        major, minor, _, _, _, network = struct.unpack(
            endian + "HHIIII", header[4:]
        )

        if (network & 0xffff) != 1:
            raise ValueError("Only Ethernet PCAP is supported")

        while True:
            record = f.read(16)

            if not record:
                break

            if len(record) != 16:
                raise ValueError("Truncated PCAP record")

            sec, fraction, captured, original = struct.unpack(
                endian + "IIII", record
            )

            if captured > 10000000:
                raise ValueError("Invalid PCAP record length")

            packet = f.read(captured)

            if len(packet) != captured:
                raise ValueError("Truncated packet")

            if len(packet) < 14:
                continue

            offset = 14
            ethertype = struct.unpack("!H", packet[12:14])[0]

            for _ in range(2):
                if ethertype not in (0x8100, 0x88a8, 0x9100):
                    break
                if len(packet) < offset + 4:
                    break
                ethertype = struct.unpack(
                    "!H", packet[offset + 2:offset + 4]
                )[0]
                offset += 4

            if ethertype != 0x0800 or len(packet) < offset + 20:
                continue

            ip = packet[offset:]

            if ip[0] >> 4 != 4:
                continue

            ihl = (ip[0] & 15) * 4

            if ihl < 20 or len(ip) < ihl + 14:
                continue

            if ip[9] != 6:
                continue

            if struct.unpack("!H", ip[6:8])[0] & 0x1fff:
                continue

            if ip[12:16] != src or ip[16:20] != dst:
                continue

            tcp = ip[ihl:]

            # SYN set, ACK not set
            if (tcp[13] & 0x12) != 0x02:
                continue

            port = struct.unpack("!H", tcp[2:4])[0]
            timestamp = sec + fraction / units

            events.append((timestamp, port))

    return sorted(events)


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument("--pcap", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--src", required=True)
    parser.add_argument("--dst", required=True)
    parser.add_argument(
        "--label", choices=["NORMAL", "ATTACK", "UNLABELED"], required=True
    )
    parser.add_argument("--window-seconds", type=int, default=60)

    args = parser.parse_args()

    if args.window_seconds < 1:
        parser.error("Window size must be positive")

    h = hashlib.sha256()

    with args.pcap.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)

    if h.hexdigest() != args.expected_sha256.lower():
        raise SystemExit("ERROR: PCAP SHA256 mismatch")

    source = ipaddress.IPv4Address(args.src).packed
    destination = ipaddress.IPv4Address(args.dst).packed

    events = read_syn_events(args.pcap, source, destination)

    if not events:
        raise SystemExit("ERROR: No matching SYN packets")

    first_timestamp = events[0][0]
    windows = defaultdict(list)

    # Windows are anchored at the first SYN of each session.
    for timestamp, port in events:
        index = int(
            (timestamp - first_timestamp) // args.window_seconds
        )
        windows[index].append((timestamp, port))

    rows = []

    for index, probes in sorted(windows.items()):
        timestamps = [item[0] for item in probes]
        unique_ports = {item[1] for item in probes}

        gaps = [
            b - a
            for a, b in zip(timestamps, timestamps[1:])
        ]

        rows.append({
            "label": args.label,
            "window_index": index,
            "window_seconds": args.window_seconds,
            "syn_count": len(probes),
            "unique_dst_ports": len(unique_ports),
            "repeated_probes": len(probes) - len(unique_ports),
            "median_inter_syn_seconds": (
                round(statistics.median(gaps), 6)
                if gaps else 0.0
            ),
            "syn_rate_per_second": round(
                len(probes) / args.window_seconds, 6
            ),
        })

    if args.out.exists():
        raise SystemExit("ERROR: Output already exists")

    args.out.parent.mkdir(parents=True, exist_ok=True)

    with args.out.open("x", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f, fieldnames=list(rows[0].keys())
        )
        writer.writeheader()
        writer.writerows(rows)

    print("=== REAL PCAP SYN FEATURE EXTRACTION ===")
    print("PCAP SHA256: PASS")
    print("Label:", args.label)
    print("SYN packets:", len(events))
    print(
        "Unique destination ports:",
        len({port for _, port in events})
    )
    print(
        "Observed SYN span (seconds):",
        round(events[-1][0] - first_timestamp, 3)
    )
    print("Window seconds:", args.window_seconds)
    print("Feature rows:", len(rows))
    print("First window SYN count:", rows[0]["syn_count"])
    print(
        "First window unique ports:",
        rows[0]["unique_dst_ports"]
    )
    print("Private output:", args.out)
    print("No IPs or port numbers exported.")
    print("PASS: SYN FEATURES EXTRACTED")


if __name__ == "__main__":
    main()