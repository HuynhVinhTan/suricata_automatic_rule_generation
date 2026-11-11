"""Safe, review-only Suricata rule proposal generation."""

import hashlib
import re
from ipaddress import ip_address, ip_network
from pathlib import Path

# Documentation-only IPv4 networks (RFC 5737).
TEST_NETWORKS = (
    ip_network("192.0.2.0/24"),
    ip_network("198.51.100.0/24"),
    ip_network("203.0.113.0/24"),
)

REJECTED_SIDS = frozenset({9102001, 9102002})
ML_SID_START = 9103000
_SID_PATTERN = re.compile(r"\bsid\s*:\s*(\d+)\s*;")
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


def _test_ip(value):
    if not isinstance(value, str):
        raise ValueError("IP address must be a string")

    address = ip_address(value)

    if address.version != 4:
        raise ValueError("Only IPv4 is supported in this prototype")

    if not any(address in network for network in TEST_NETWORKS):
        raise ValueError(
            "Prototype accepts documentation-only IP addresses"
        )

    return str(address)


def _port(value):
    if type(value) is not int or not 1 <= value <= 65535:
        raise ValueError("Port must be an integer from 1 to 65535")
    return value


def _validate_sha256(value, field_name):
    if (
        not isinstance(value, str)
        or not _SHA256_PATTERN.fullmatch(value.lower())
    ):
        raise ValueError(f"{field_name} must be a SHA256 hex string")
    return value.lower()


def _validate_counts(values, field_name):
    if not isinstance(values, (list, tuple)) or not values:
        raise ValueError(f"{field_name} must contain at least one count")
    if any(type(value) is not int or value < 0 for value in values):
        raise ValueError(f"{field_name} must contain non-negative integers")
    return list(values)


def collect_sids(rule_texts):
    """Return all integer SIDs found in existing rule text."""
    sids = set()
    for text in rule_texts:
        if not isinstance(text, str):
            raise ValueError("Existing rules must be strings")
        sids.update(int(match) for match in _SID_PATTERN.findall(text))
    return sids


def allocate_sid(existing_sids=(), *, start=ML_SID_START):
    """Allocate a deterministic fresh local SID, excluding rejected SIDs."""
    if type(start) is not int or not 1 <= start <= 4294967295:
        raise ValueError("Invalid SID allocation start")

    used = set()
    for sid in existing_sids:
        if type(sid) is not int or not 1 <= sid <= 4294967295:
            raise ValueError("Existing SIDs must be valid integers")
        used.add(sid)

    for candidate in range(start, 4294967296):
        if candidate not in used and candidate not in REJECTED_SIDS:
            return candidate
    raise ValueError("No unused SID is available")


def _build_ml_syn_rule(*, destination_ip, threshold, window_seconds, sid):
    address = ip_address(destination_ip)
    if address.version != 4:
        raise ValueError("ML rule generation requires IPv4")
    if type(threshold) is not int or threshold < 1:
        raise ValueError("Invalid SYN threshold")
    if type(window_seconds) is not int or window_seconds <= 0:
        raise ValueError("Invalid rule window")
    if type(sid) is not int or not 1 <= sid <= 4294967295:
        raise ValueError("Invalid SID")
    if sid in REJECTED_SIDS:
        raise ValueError("Rejected historical SID cannot be reused")

    # detection_filter counts SYN packets per source. It does not count
    # unique destination ports; port diversity remains separate evidence.
    return (
        f"alert tcp any any -> {address} any "
        '(msg:"ML REVIEW - SYN packet burst"; '
        f"flow:stateless; flags:S; detection_filter:track by_src,"
        f"count {threshold},seconds {window_seconds}; "
        f"classtype:attempted-recon; sid:{sid}; rev:1;)"
    )


def generate_ml_rule(
    *,
    run_id,
    pcap_sha256,
    model_sha256,
    destination_ip,
    normal_train_syn_counts,
    normal_cal_syn_counts,
    normal_test_syn_counts,
    attack_syn_counts,
    existing_sids=(),
    window_seconds=10,
):
    """Generate a provenance-bound rule only when evidence clears all gates.

    Normal train/calibration data selects the first unseen packet-count
    threshold. Normal validation data is a hard false-positive gate. Attack
    evidence must exceed that threshold. A returned candidate is still
    ``needs_review`` and is never deployable by this function.
    """
    if (
        not isinstance(run_id, str)
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", run_id)
    ):
        raise ValueError("Invalid run ID")
    pcap_sha256 = _validate_sha256(pcap_sha256, "pcap_sha256")
    model_sha256 = _validate_sha256(model_sha256, "model_sha256")
    normal_train = _validate_counts(normal_train_syn_counts, "normal_train_syn_counts")
    normal_cal = _validate_counts(normal_cal_syn_counts, "normal_cal_syn_counts")
    normal_test = _validate_counts(normal_test_syn_counts, "normal_test_syn_counts")
    attack = _validate_counts(attack_syn_counts, "attack_syn_counts")

    normal_baseline = normal_train + normal_cal
    threshold = max(normal_baseline) + 1
    metadata = {
        "schema_version": "ml_rule_metadata_v1",
        "run_id": run_id,
        "pcap_sha256": pcap_sha256,
        "model_sha256": model_sha256,
        "window_seconds": window_seconds,
        "threshold_method": "max_normal_train_and_calibration_plus_one",
        "normal_train_max_syn": max(normal_train),
        "normal_cal_max_syn": max(normal_cal),
        "normal_validation_max_syn": max(normal_test),
        "attack_max_syn": max(attack),
        "deployable": False,
        "deployed": False,
        "approved": False,
        "rule_sha256": None,
    }

    if any(count >= threshold for count in normal_test):
        return {
            "status": "rejected_validation_failure",
            "rejection_reason": "normal_validation_false_positive",
            "sid": None,
            "threshold": threshold,
            "rule": None,
            "metadata": metadata,
        }
    if max(attack) < threshold:
        return {
            "status": "rejected_validation_failure",
            "rejection_reason": "insufficient_attack_evidence",
            "sid": None,
            "threshold": threshold,
            "rule": None,
            "metadata": metadata,
        }

    sid = allocate_sid(existing_sids)
    rule = _build_ml_syn_rule(
        destination_ip=destination_ip,
        threshold=threshold,
        window_seconds=window_seconds,
        sid=sid,
    )
    metadata["rule_sha256"] = hashlib.sha256(rule.encode("utf-8")).hexdigest()
    return {
        "status": "needs_review",
        "rejection_reason": None,
        "sid": sid,
        "threshold": threshold,
        "rule": rule,
        "metadata": metadata,
    }


def write_ml_rule_artifacts(output_dir, result):
    """Write exclusive review artifacts; never overwrite a prior run."""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    metadata = dict(result["metadata"])
    metadata["status"] = result["status"]
    metadata["rejection_reason"] = result.get("rejection_reason")
    with (output_dir / "ml-generated.metadata.json").open(
        "x", encoding="utf-8"
    ) as stream:
        import json

        json.dump(metadata, stream, indent=2, ensure_ascii=False)
        stream.write("\n")
    if result["rule"] is not None:
        with (output_dir / "ml-generated.rules").open(
            "x", encoding="utf-8"
        ) as stream:
            stream.write(result["rule"] + "\n")


def build_test_alert_rule(
    *,
    protocol,
    source_ip,
    source_port,
    destination_ip,
    destination_port,
    sid,
):
    if not isinstance(protocol, str):
        raise ValueError("Invalid protocol")

    protocol = protocol.lower()

    if protocol not in {"tcp", "udp"}:
        raise ValueError("Only TCP/UDP are supported")

    src = _test_ip(source_ip)
    dst = _test_ip(destination_ip)
    sport = _port(source_port)
    dport = _port(destination_port)

    if type(sid) is not int or not 1 <= sid <= 4294967295:
        raise ValueError("Invalid SID")

    return (
        f"alert {protocol} {src} {sport} -> {dst} {dport} "
        f'(msg:"LOCAL TEST CANDIDATE - NOT VERIFIED ATTACK"; '
        f"sid:{sid}; rev:1;)"
    )

def build_syn_burst_review_rule(
    *, destination_ip, normal_max_syn, window_seconds=10, sid=9102001
):
    """Review-only SYN packet-count proxy, not a learned model rule."""
    address = ip_address(destination_ip)

    if address.version != 4:
        raise ValueError("IPv4 required")
    if type(normal_max_syn) is not int or normal_max_syn < 0:
        raise ValueError("Invalid Normal maximum")
    if type(window_seconds) is not int or window_seconds != 10:
        raise ValueError("Window contract mismatch")
    if type(sid) is not int or not 1 <= sid <= 4294967295:
        raise ValueError("Invalid SID")

    count = max(3, normal_max_syn + 1)

    return (
        f"alert tcp any any -> {address} any "
        '(msg:"LAB AI REVIEW SYN burst proxy"; '
        "flow:stateless; tcp.flags:S,CE; "
        "threshold:type threshold,track by_both,"
        f"count {count},seconds {window_seconds}; "
        f"classtype:attempted-recon; sid:{sid}; rev:1;)"
    )
