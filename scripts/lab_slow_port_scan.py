"""Deterministic, private-lab-only slow TCP connection probe generator."""

import argparse
from datetime import datetime, timezone
import ipaddress
import json
import random
import socket
import time


LAB_NETWORK = ipaddress.ip_network("192.168.10.0/24")


def _lab_ip(value):
    address = ipaddress.ip_address(value)
    if address.version != 4 or address not in LAB_NETWORK:
        raise ValueError("target must be an IPv4 address in 192.168.10.0/24")
    return str(address)


def _ports(value):
    ports = [int(item) for item in value.split(",") if item.strip()]
    if len(ports) != 24 or len(set(ports)) != 24 or any(not 1 <= port <= 65535 for port in ports):
        raise ValueError("exactly 24 unique TCP ports are required")
    return ports


def _utc():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def run(*, run_id, target, ports, interval_seconds=2.0, timeout_seconds=1.0, seed=0, source_ip=None):
    target = _lab_ip(target)
    ports = _ports(",".join(str(port) for port in ports))
    if not isinstance(run_id, str) or not run_id:
        raise ValueError("run_id is required")
    if interval_seconds <= 0 or timeout_seconds <= 0:
        raise ValueError("interval and timeout must be positive")
    if source_ip is not None:
        source_ip = _lab_ip(source_ip)
    order = list(ports)
    random.Random(seed).shuffle(order)
    attempts = []
    started_at = _utc()
    schedule = time.monotonic()
    for port in order:
        now = time.monotonic()
        if now < schedule:
            time.sleep(schedule - now)
        attempt_started = _utc()
        started_monotonic = time.monotonic()
        result = "error"
        error = None
        source_port = None
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.settimeout(timeout_seconds)
            if source_ip:
                sock.bind((source_ip, 0))
            source_port = sock.getsockname()[1]
            code = sock.connect_ex((target, port))
            if code == 0:
                result = "connected_unexpected"
            elif code in {111, 61, 10061}:
                result = "rst_refused"
            elif code in {110, 60, 10060}:
                result = "timeout_filtered"
            else:
                result = "connect_error"
            error = code
        except socket.timeout:
            result = "timeout_filtered"
            error = "timeout"
        except OSError as exc:
            error = f"{type(exc).__name__}:{exc.errno}"
        finally:
            sock.close()
        attempt_ended = _utc()
        attempts.append({
            "attempt_id": f"{run_id}-{len(attempts) + 1:03d}",
            "timestamp_utc": attempt_started,
            "attempt_end_utc": attempt_ended,
            "source_ip": source_ip or "0.0.0.0",
            "source_port": source_port,
            "target_ip": target,
            "destination_ip": target,
            "destination_port": port,
            "protocol": "TCP",
            "result": result,
            "error": error,
            "elapsed_seconds": round(time.monotonic() - started_monotonic, 6),
        })
        schedule += interval_seconds
    return {
        "schema_version": "lab_slow_port_scan_v1",
        "run_id": run_id,
        "scenario": "ATTACK",
        "ground_truth": "CONTROLLED_SLOW_TCP_PORT_SCAN",
        "started_at_utc": started_at,
        "ended_at_utc": _utc(),
        "target_ip": target,
        "source_ip": source_ip,
        "interval_seconds": interval_seconds,
        "timeout_seconds": timeout_seconds,
        "seed": seed,
        "attempt_count": len(attempts),
        "attempts": attempts,
        "rst_refused_count": sum(item["result"] == "rst_refused" for item in attempts),
        "timeout_filtered_count": sum(item["result"] == "timeout_filtered" for item in attempts),
        "connected_unexpected_count": sum(item["result"] == "connected_unexpected" for item in attempts),
        "capture_completeness": "UNKNOWN_UNTIL_PCAP_VERIFIED",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--ports", required=True, help="24 comma-separated closed-port candidates")
    parser.add_argument("--source-ip")
    parser.add_argument("--interval", type=float, default=2.0)
    parser.add_argument("--timeout", type=float, default=1.0)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    result = run(
        run_id=args.run_id,
        target=args.target,
        ports=_ports(args.ports),
        interval_seconds=args.interval,
        timeout_seconds=args.timeout,
        seed=args.seed,
        source_ip=args.source_ip,
    )
    with open(args.out, "w", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2)
        stream.write("\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
