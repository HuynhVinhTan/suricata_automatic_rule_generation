"""Deterministic private-lab Normal HTTP service-access generator."""

import argparse
from datetime import datetime, timezone
import ipaddress
import json
import socket
import time


LAB_NETWORK = ipaddress.ip_network("192.168.10.0/24")


def _lab_ip(value):
    address = ipaddress.ip_address(value)
    if address.version != 4 or address not in LAB_NETWORK:
        raise ValueError("target must be an IPv4 address in 192.168.10.0/24")
    return str(address)


def _utc():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def run(*, run_id, target, open_port, closed_ports, interval_seconds=2.0, timeout_seconds=1.0, source_ip=None):
    target = _lab_ip(target)
    if type(open_port) is not int or not 1 <= open_port <= 65535:
        raise ValueError("open_port is invalid")
    if len(closed_ports) > 2 or len(set(closed_ports)) != len(closed_ports):
        raise ValueError("at most two unique closed ports are allowed")
    if any(type(port) is not int or not 1 <= port <= 65535 for port in closed_ports):
        raise ValueError("closed port is invalid")
    if source_ip is not None:
        source_ip = _lab_ip(source_ip)
    plan = [(open_port, "/health") for _ in range(22)]
    plan.extend((port, None) for port in closed_ports)
    if len(plan) != 24:
        raise ValueError("Normal plan must contain exactly 24 attempts")
    attempts = []
    started_at = _utc()
    schedule = time.monotonic()
    for port, path in plan:
        now = time.monotonic()
        if now < schedule:
            time.sleep(schedule - now)
        attempt_started = _utc()
        started_monotonic = time.monotonic()
        result = "error"
        status = None
        error = None
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.settimeout(timeout_seconds)
            if source_ip:
                sock.bind((source_ip, 0))
            code = sock.connect_ex((target, port))
            if code != 0:
                result = "rst_refused" if code in {111, 61, 10061} else "connect_error"
                error = code
            elif path is None:
                result = "connected_unexpected"
            else:
                request = f"GET {path} HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n".encode()
                sock.sendall(request)
                response = sock.recv(4096)
                status = int(response.split(b" ", 2)[1]) if response.startswith(b"HTTP/") else None
                result = "http_200" if status == 200 else "http_non_200"
        except socket.timeout:
            result = "timeout_filtered"
            error = "timeout"
        except (OSError, ValueError) as exc:
            error = f"{type(exc).__name__}:{getattr(exc, 'errno', None)}"
        finally:
            sock.close()
        attempts.append({
            "timestamp_utc": attempt_started,
            "target_ip": target,
            "destination_port": port,
            "path": path,
            "result": result,
            "http_status": status,
            "error": error,
            "elapsed_seconds": round(time.monotonic() - started_monotonic, 6),
        })
        schedule += interval_seconds
    return {
        "schema_version": "lab_normal_service_access_v1",
        "run_id": run_id,
        "scenario": "NORMAL",
        "ground_truth": "LEGITIMATE_HTTP_SERVICE_ACCESS",
        "started_at_utc": started_at,
        "ended_at_utc": _utc(),
        "target_ip": target,
        "source_ip": source_ip,
        "interval_seconds": interval_seconds,
        "timeout_seconds": timeout_seconds,
        "attempt_count": len(attempts),
        "attempts": attempts,
        "http_200_count": sum(item["result"] == "http_200" for item in attempts),
        "rst_refused_count": sum(item["result"] == "rst_refused" for item in attempts),
        "capture_completeness": "UNKNOWN_UNTIL_PCAP_VERIFIED",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--open-port", type=int, required=True)
    parser.add_argument("--closed-ports", default="")
    parser.add_argument("--source-ip")
    parser.add_argument("--interval", type=float, default=2.0)
    parser.add_argument("--timeout", type=float, default=1.0)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    closed = [int(item) for item in args.closed_ports.split(",") if item.strip()]
    result = run(
        run_id=args.run_id,
        target=args.target,
        open_port=args.open_port,
        closed_ports=closed,
        interval_seconds=args.interval,
        timeout_seconds=args.timeout,
        source_ip=args.source_ip,
    )
    with open(args.out, "w", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2)
        stream.write("\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
