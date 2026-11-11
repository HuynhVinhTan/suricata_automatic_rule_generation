# Unresolved requirements

## Blocking

1. Milestone 6 is accepted for the six verified lab experiments. The six
   derived summaries are present in `suricata-ai-summary` with exact read-back,
   while the four historical documents remain preserved. This does not claim
   live production EVE correlation by run ID.
2. The validated SID 9103003 is a review-only RST telemetry proxy. The Python
   hybrid remains authoritative and is not equivalent to a single Suricata
   signature.
3. CIC-IDS2017 remains unsuitable for model training until duplicate headers,
   non-finite rates and label policy receive a separately reviewed adapter
   experiment. CTU's largest duplicate/contradiction audit needs more
   temporary disk; no result is inferred.
4. Active isolated-lab rule installation remains pending explicit owner
   approval. The lifecycle implementation is dry-run and fail-closed.

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
