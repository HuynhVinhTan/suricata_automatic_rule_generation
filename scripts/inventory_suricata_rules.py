"""Read-only inventory of a copied Suricata ruleset.

The tool does not infer Emerging Threats provenance from filenames. Source
origin, effective enablement and historical identity are separate facts and
must be supplied or verified from the YAML/rule-manager record.
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


def inventory(root: Path, config: Path | None = None, *, source_label: str = "UNKNOWN") -> dict:
    files = []
    all_sids: set[int] = set()
    for path in sorted(root.rglob("*.rules")):
        text = path.read_text(encoding="utf-8", errors="strict")
        active_sids = set()
        active_lines = 0
        for line in text.splitlines():
            if line.strip() and not line.lstrip().startswith("#"):
                active_lines += 1
                match = SID_RE.search(line)
                if match:
                    active_sids.add(int(match.group(1)))
        all_sids.update(active_sids)
        files.append({
            "path": str(path),
            "source_attribution": source_label,
            "size_bytes": path.stat().st_size,
            "sha256": sha256(path),
            "active_rule_lines": active_lines,
            "active_unique_sid_count": len(active_sids),
            "active_sids_sha256": hashlib.sha256(",".join(map(str, sorted(active_sids))).encode()).hexdigest(),
        })
    result = {
        "schema_version": "suricata_rules_inventory_v2",
        "rules_root": str(root),
        "source_attribution": source_label,
        "historical_identity": "NOT_ESTABLISHED",
        "files": files,
        "total_files": len(files),
        "total_active_rule_lines": sum(item["active_rule_lines"] for item in files),
        "total_active_unique_sid_count": len(all_sids),
        "active_sids_sha256": hashlib.sha256(",".join(map(str, sorted(all_sids))).encode()).hexdigest(),
    }
    if config is not None:
        result["config"] = {"path": str(config), "sha256": sha256(config), "size_bytes": config.stat().st_size}
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("rules_root", type=Path)
    parser.add_argument("--config", type=Path)
    parser.add_argument("--source-label", default="UNKNOWN")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = inventory(args.rules_root, args.config, source_label=args.source_label)
    payload = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(payload, encoding="utf-8", newline="\n")
    else:
        print(payload, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
