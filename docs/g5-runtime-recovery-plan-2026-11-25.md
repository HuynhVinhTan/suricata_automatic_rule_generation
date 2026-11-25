# G5 runtime failure recovery plan

The authorized G5 experiment remains a failed experiment. It is not runtime
acceptance evidence, and this plan does not authorize a retry.

## Preserved original evidence

Retain the original failure JSON, signed authorization, audit ledger, audit
hash chain, and native daemon logs exactly as produced by the failed attempt.
The supplied failure JSON SHA-256 is
`44baca73ab8a25d287bd343f103107ffd01fd24e8d492911dd454271baec0177`.
The supplied audit ledger SHA-256 is
`5b6b90da08efd9088c1bb5bd6a266e8c0a60fa64c7642d3786e99e2edd6fcb7b`.

The previous authorization nonce is consumed. Its audit record must remain in
the persistent hash chain; it must not be removed, rewritten, or replayed.

## Fail-closed recovery sequence

1. Classify the original attempt as `FAILED`. Do not convert it into accepted
   activation, rollback, or production-unchanged evidence.
2. Perform readiness validation without VM access or live operation: verify the
   Suricata 8.0.3 configuration contract, AF_PACKET loopback-only scope,
   attempt-specific UNIX socket, isolated `active.rules` path, six pinned PCAP
   hashes, frozen replay signature, trust anchors, and the existing deadline
   and rollback gates. If native `suricata -T` is unavailable, record that gap;
   offline tests are not a native verification substitute.
3. After a separately reviewed owner decision, issue a new authorization with a
   new nonce. The old authorization is never reused. No code path performs an
   automatic retry.
4. Allocate a new attempt-specific evidence directory and diagnostic log. Keep
   the persistent audit ledger as the source of truth and append through its
   existing hash-chain writer; never reset it. Failure and signed-success
   outputs are exclusive-create artifacts and must not overwrite the originals.
5. Run only the isolated AF_PACKET/`lo` runtime. The daemon configuration
   names the isolated `active.rules` file and UNIX socket; no production rules,
   configuration, interface, or socket may be opened.
6. Accept a new runtime result only if startup, candidate load count, active
   probes, mandatory rollback, post-rollback probes, child cleanup, deadline,
   production before/after equality, and audit-chain verification all pass.
   Otherwise write a separate unsigned failure report containing the failure
   phase, native diagnostics hash, cleanup result, rollback result, production
   state (`unchanged`, `changed`, or `not_verified`), and persistent audit hash.

The existing `.runtime-staging/`, frozen candidate, thresholds, PCAPs, signed
replay, trust anchors, and model artifacts are inputs to this procedure and
must not be modified.
