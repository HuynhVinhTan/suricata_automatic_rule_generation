"""Calibrated, review-only hybrid reconnaissance evidence."""


def _complete(evidence):
    integrity = evidence.get("capture_integrity", {})
    return integrity.get("capture_complete") is True


def _int(evidence, name):
    value = evidence.get(name)
    if type(value) is not int or value < 0:
        raise ValueError(f"Invalid hybrid evidence: {name}")
    return value


def calibrate_hybrid_thresholds(normal_evidence):
    """Derive conservative thresholds from complete Normal references only."""
    if not normal_evidence:
        raise ValueError("Normal calibration evidence is required")

    for evidence in normal_evidence:
        if not isinstance(evidence, dict) or not _complete(evidence):
            raise ValueError("Normal calibration evidence must be complete")
        syns = _int(evidence, "initial_syn_packets")
        handshakes = _int(evidence, "handshake_success_count")
        if syns < 1 or handshakes > syns:
            raise ValueError("Invalid Normal handshake evidence")
        _int(evidence, "unique_destination_ports")
        _int(evidence, "max_rst_count_per_window")

    return {
        "min_unique_destination_ports": max(
            evidence["unique_destination_ports"]
            for evidence in normal_evidence
        ) + 1,
        "min_rst_count_per_window": max(
            evidence["max_rst_count_per_window"]
            for evidence in normal_evidence
        ) + 1,
        "max_handshake_failure_count": max(
            evidence["initial_syn_packets"]
            - evidence["handshake_success_count"]
            for evidence in normal_evidence
        ),
    }


def evaluate_hybrid(
    *, ml_consensus, rst_evidence, port_evidence,
    handshake_evidence, thresholds,
):
    """Classify evidence without approving or deploying a rule."""
    if type(ml_consensus) is not bool:
        raise ValueError("ml_consensus must be boolean")
    required_thresholds = {
        "min_unique_destination_ports",
        "min_rst_count_per_window",
        "max_handshake_failure_count",
    }
    if not required_thresholds.issubset(thresholds):
        raise ValueError("Incomplete hybrid thresholds")

    complete = _complete(rst_evidence)
    syns = _int(handshake_evidence, "initial_syn_packets")
    handshakes = _int(handshake_evidence, "flows_with_confirmed_handshake")
    payloads = _int(handshake_evidence, "flows_with_bidirectional_payload")
    if syns < 1 or handshakes > syns or payloads > handshakes:
        raise ValueError("Invalid hybrid handshake evidence")

    conditions = {
        "capture_complete": complete,
        "ml_consensus": ml_consensus,
        "rst_threshold": (
            _int(rst_evidence, "max_rst_count_per_window")
            >= thresholds["min_rst_count_per_window"]
        ),
        "port_diversity": (
            _int(port_evidence, "max_window_distinct_ports")
            >= thresholds["min_unique_destination_ports"]
        ),
        "handshake_failure_exceeds_normal": (
            syns - handshakes
            > thresholds["max_handshake_failure_count"]
        ),
        "no_successful_handshake": handshakes == 0,
        "no_bidirectional_payload": payloads == 0,
    }

    if not complete:
        classification = "ambiguous_incomplete_capture"
    elif all(conditions.values()):
        classification = "reconnaissance_consistent"
    elif ml_consensus:
        classification = "anomalous_not_reconnaissance"
    else:
        classification = "normal_or_insufficient_evidence"

    return {
        "schema_version": "hybrid_review_v1",
        "classification": classification,
        "conditions": conditions,
        "thresholds": dict(thresholds),
        "requires_manual_review": True,
        "approved": False,
        "deployable": False,
        "deployed": False,
        "explanation": {
            name: "passed" if passed else "failed"
            for name, passed in conditions.items()
        },
    }
