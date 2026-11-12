"""Offline paired baseline/augmented Suricata comparison harness.

Each case is a PCAP replay into a separate output directory.  Detection is
defined by an explicit reconnaissance SID/signature allow-list supplied by the
operator; generic ET informational alerts are reported but never counted as
reconnaissance detection by default.
"""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import subprocess


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def parse_eve(path: Path, recon_sids: set[int], recon_signatures: set[str]) -> dict:
    total = 0
    alerts = Counter()
    recon = 0
    if path.exists():
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if not line.strip():
                continue
            event = json.loads(line)
            if event.get("event_type") != "alert":
                continue
            total += 1
            alert = event.get("alert") or {}
            sid = int(alert.get("signature_id", -1))
            signature = str(alert.get("signature", ""))
            alerts[f"{sid}:{signature}"] += 1
            if sid in recon_sids or signature in recon_signatures:
                recon += 1
    return {"alert_events": total, "reconnaissance_alert_events": recon, "signatures": dict(alerts)}


def replay(suricata: str, config: Path, rules: Path, pcap: Path, output: Path) -> dict:
    output.mkdir(parents=True, exist_ok=True)
    eve = output / "eve.json"
    command = [suricata, "-c", str(config), "-S", str(rules), "-r", str(pcap), "-l", str(output), "--runmode", "single"]
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    return {
        "command": command,
        "returncode": completed.returncode,
        "stdout_sha256": hashlib.sha256(completed.stdout.encode()).hexdigest(),
        "stderr_sha256": hashlib.sha256(completed.stderr.encode()).hexdigest(),
        "eve_path": str(eve),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--suricata", default="suricata")
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--baseline-rules", type=Path, required=True)
    parser.add_argument("--augmented-rules", type=Path, required=True)
    parser.add_argument("--case", action="append", nargs=2, metavar=("LABEL", "PCAP"), required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--recon-sid", action="append", type=int, default=[])
    parser.add_argument("--recon-signature", action="append", default=[])
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    recon_sids = set(args.recon_sid)
    recon_signatures = set(args.recon_signature)
    results = []
    for label, pcap_value in args.case:
        pcap = Path(pcap_value)
        row = {"label": label, "pcap": str(pcap), "pcap_sha256": _sha256(pcap)}
        for name, rules in (("baseline", args.baseline_rules), ("augmented", args.augmented_rules)):
            run = replay(args.suricata, args.config, rules, pcap, args.output_root / label / name)
            run["rules_sha256"] = _sha256(rules)
            run["evidence"] = parse_eve(Path(run["eve_path"]), recon_sids, recon_signatures)
            row[name] = run
        results.append(row)
    report = {
        "schema_version": "suricata_baseline_comparison_v1",
        "definition": {
            "reconnaissance_detected": "at least one alert whose SID or exact signature is explicitly included in the supplied reconnaissance allow-list",
            "generic_alerts_are_not_reconnaissance": True,
        },
        "config_sha256": _sha256(args.config),
        "reconnaissance_sids": sorted(recon_sids),
        "reconnaissance_signatures": sorted(recon_signatures),
        "cases": results,
    }
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    return 0 if all(row[name]["returncode"] == 0 for row in results for name in ("baseline", "augmented")) else 1


if __name__ == "__main__":
    raise SystemExit(main())
