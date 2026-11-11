# Unresolved requirements

## Blocking

1. Milestone 6 event-level correlation remains unproven. The production EVE
   documents and AI summaries have no verified shared run ID or hash, and the
   production Filebeat input must not be changed solely to add one.
2. The validated SID 9103003 is a review-only RST telemetry proxy. The Python
   hybrid remains authoritative and is not equivalent to a single Suricata
   signature.

## Scientific scope

- Only six independent holdout sessions were evaluated: three Attack and
  three challenging Normal sessions.
- All evidence is from a controlled lab; production accuracy and generalization
  are not established.
- Frozen IF/AE remains non-discriminating in this evaluation:
  `TP=3, FP=3, FN=0, TN=0, FPR=1.0`.
- The Python hybrid separated the bounded holdouts:
  `TP=3, FP=0, FN=0, TN=3`, observed `FPR=0.0`.

## Smallest defensible next step

Keep the Python hybrid as a review-only worker layer and collect a larger,
owner-authorized, independently manifested lab corpus before making any
production or executable-signature claim. Any future signature work requires
an explicitly stateful architecture or telemetry/proxy component approved by
the owner; an RST-only approximation is not acceptable.
