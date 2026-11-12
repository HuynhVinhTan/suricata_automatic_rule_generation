"""Inventory a Suricata rules directory without changing the installation.

This is intentionally a local/offline utility.  Copying files from a VM is a
separate operator action; the script never invokes sudo, systemctl or reload.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re


SID_RE = re.compile(r"\bsid\s*:\s*(\d+)\s*;", re.IGNORECASE)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def classify(path: Path) -> str:
    lower = path.name.lower()
    if "emerging" in lower or lower in {"suricata.rules", "suricata.rules.gz"}:
        return "emerging_threats_or_aggregated"
    if "local" in lower or "custom" in lower:
        return "custom_or_local"
    return "other"


def inventory(root: Path, config: Path | None = None) -> dict:
    files = []
    for path in sorted(root.rglob("*.rules")):
        text = path.read_text(encoding="utf-8", errors="replace")
        sids = sorted({int(value) for value in SID_RE.findall(text)})
        files.append({
            "path": str(path),
            "classification": classify(path),
            "size_bytes": path.stat().st_size,
            "sha256": sha256(path),
            "rule_lines": sum(1 for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")),
            "sid_count": len(sids),
            "sid_min": min(sids) if sids else None,
            "sid_max": max(sids) if sids else None,
        })
    result = {
        "schema_version": "suricata_rules_inventory_v1",
        "rules_root": str(root),
        "files": files,
        "total_files": len(files),
        "total_rule_lines": sum(item["rule_lines"] for item in files),
        "total_sid_count": sum(item["sid_count"] for item in files),
    }
    if config is not None:
        result["config"] = {"path": str(config), "sha256": sha256(config), "size_bytes": config.stat().st_size}
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("rules_root", type=Path)
    parser.add_argument("--config", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = inventory(args.rules_root, args.config)
    payload = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(payload, encoding="utf-8", newline="\n")
    else:
        print(payload, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
