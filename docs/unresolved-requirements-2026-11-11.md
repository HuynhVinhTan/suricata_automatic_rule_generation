# Unresolved requirements

## Blocking

1. The owner must remove and verify the temporary VM1 tcpdump file capability.
   The current read-only audit still reports `/usr/bin/tcpdump cap_net_raw=ep`.
   This audit did not alter privileges. The owner should diagnose the same
   interactive `sudo -i` context and then verify `getcap -v /usr/bin/tcpdump`
   returns no capability.
2. A safe executable Suricata rule remains unavailable. The Python hybrid is a
   review-only decision and is not equivalent to a single Suricata signature.
3. Baseline-versus-augmented Suricata improvement is not demonstrated because
   no candidate survived the false-positive and semantic-equivalence gates.

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
