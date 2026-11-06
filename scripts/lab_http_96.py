"""Authorized three-VM lab HTTP scenario: exact 96-request completion gate.

This client sends only benign GETs to the pre-approved VM1 synthetic services
on 192.168.10.10:18100-18111. It does not scan external networks, change a
live IDS rule, or manipulate the capture process.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import ProxyHandler, Request, build_opener

HOST = "192.168.10.10"
PORTS = tuple(range(18100, 18112))
PATHS = ("/version", "/status", "/metrics", "/admin")
SCENARIOS = ("recon-v03", "matched12-v02")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def plan(scenario: str) -> list[tuple[int, str]]:
    if scenario == "recon-v03":
        # 2 of each path per port, same explicit request order as Recon V02.
        result = [(port, path) for _ in range(2)
                  for path in PATHS for port in PORTS]
    elif scenario == "matched12-v02":
        # Matched 96 connections and 12 destination ports, benign /health only.
        result = [(port, "/health") for _ in range(8) for port in PORTS]
    else:
        raise ValueError("Unsupported authorized scenario")
    assert len(result) == 96
    return result


def execute(scenario: str, *, opener=None, sleep=time.sleep,
            interval: float = 0.6) -> dict:
    if interval < 0 or interval > 10:
        raise ValueError("Unsupported pacing interval")
    opener = opener or build_opener(ProxyHandler({}))
    requests = plan(scenario)
    by_port: Counter[int] = Counter()
    by_path: Counter[str] = Counter()
    errors = []
    started_at = utc_now()
    print(f"SCENARIO={scenario} EXPECTED=96 START_UTC={started_at}", flush=True)

    for index, (port, path) in enumerate(requests):
        url = f"http://{HOST}:{port}{path}"
        try:
            request = Request(url, headers={"Connection": "close"})
            with opener.open(request, timeout=5) as response:
                body = response.read().decode("utf-8", errors="replace")
                if (response.status != 200
                    or "SYNTHETIC LAB SERVICE" not in body
                    or f"SERVICE_PORT={port}" not in body
                    or f"REQUESTED_PATH={path}" not in body):
                    errors.append({"request": index + 1, "type": "response_mismatch"})
                else:
                    by_port[port] += 1
                    by_path[path] += 1
        except Exception as exc:
            errors.append({"request": index + 1, "type": type(exc).__name__})
        if (index + 1) % 12 == 0:
            print(f"PROGRESS={index+1}/96 HTTP_SUCCESS={sum(by_port.values())}",
                  flush=True)
        if index < len(requests) - 1:
            sleep(interval)

    success = sum(by_port.values())
    result = {
        "schema_version": "lab_96_http_v0_1",
        "scenario": scenario,
        "source_vm": "Kali_VM2_192.168.10.20",
        "destination_ipv4": HOST,
        "ports": list(PORTS),
        "requests_planned": len(requests),
        "http_success": success,
        "http_failures": len(errors),
        "success_by_port": dict(sorted(by_port.items())),
        "success_by_path": dict(sorted(by_path.items())),
        "error_types": errors[:10],
        "start_utc": started_at,
        "end_utc": utc_now(),
        "status": "PASS" if success == 96 and not errors else "FAIL",
    }
    print(json.dumps(result, ensure_ascii=False, sort_keys=True), flush=True)
    if result["status"] == "PASS":
        print("SAFE_TO_STOP_CAPTURE: YES (Kali completed all 96 GET)", flush=True)
    else:
        print("SAFE_TO_STOP_CAPTURE: NO (scenario incomplete)", flush=True)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario", choices=SCENARIOS)
    parser.add_argument("--result-file", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.result_file.is_symlink() or args.result_file.exists():
        parser.error("Evidence file exists: refusing overwrite")
    if not args.result_file.parent.is_dir():
        parser.error("Result directory must already exist")
    result = execute(args.scenario)
    with args.result_file.open("x", encoding="utf-8") as file:
        json.dump(result, file, indent=2, sort_keys=True)
        file.write("\n")
    args.result_file.chmod(0o600)
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
