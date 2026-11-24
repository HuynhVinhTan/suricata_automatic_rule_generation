# G4 RST candidate evidence lifecycle

The `rst_response_v1` family is an evidence-gated, review-only Suricata
signature. It is a bounded laboratory detection signature for repeated TCP RST
responses under the frozen development distribution. It is not a complete
equivalent of the Python Hybrid detector, and it must not be represented as
one.

## Generation contract

The worker may generate `ml-generated-rst.rules` and
`ml-generated-rst.metadata.json` only when all of these are present and
consistent:

- `G4_DEVELOPMENT_ONLY` provenance with complete independent Normal calibration
  captures, `native_replay_tested=false`, and
  `independent_final_acceptance=false`;
- accepted calibration provenance frozen before holdout exposure;
- a complete, independent Normal validation capture and RST count series;
- complete candidate capture integrity;
- ML consensus and independent port-diversity evidence; and
- an attack RST count above the threshold derived from Normal calibration.

The pipeline reads the development-only sidecars from the private worker root:

```text
lab-rule-candidates/rst_response_v1/development-evidence.json
lab-rule-candidates/rst_response_v1/normal-validation-rst.json
```

The Normal validation sidecar must use scope
`G4_DEVELOPMENT_VALIDATION_ONLY`, contain its own PCAP SHA256, complete capture
integrity, and `final_acceptance=false`. Holdout evidence is never accepted as
generation or calibration input. SID allocation skips the permanently
quarantined SYN-only family, including SID9103000 and equivalent historical
SIDs.

## Frozen SID9103005 verification

`scripts/verify_frozen_rst_candidate.py` verifies the owner-produced freeze,
development evidence, rule and metadata bytes, cohort plan/results, worker
receipts, and native holdout report. It is read-only and does not approve,
deploy, activate, or rewrite SID9103005.

The supplied native result is therefore represented as evidence only:
three Attack detections, zero Normal detections, TP=3/FN=0/FP=0/TN=3,
approval=false, deployment=false. A failed hash, duplicate case, incomplete
capture, inconsistent receipt, or holdout overlap fails closed.

## G5 interface

`build_g5_acceptance_request()` creates a candidate-bound
`g5_candidate_acceptance_request_v1` record with status
`awaiting_owner_runtime`. It requires separate owner authorization, isolated
candidate-only activation, independent Normal and negative-control replay, an
Attack replay, and a visible rollback/post-rollback check. It always returns
`approved=false`, `deployed=false`, and `production_activation=false`.

Legitimate repeated RST traffic outside the tested Normal distribution remains
an explicit residual risk. Regression coverage confirms that the candidate can
be reviewable while still declaring `hybrid_equivalent=false`; G5 must test that
boundary in an owner-controlled isolated runtime.
