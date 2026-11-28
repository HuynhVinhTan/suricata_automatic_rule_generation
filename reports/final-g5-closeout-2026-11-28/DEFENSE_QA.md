# Defense questions and answers

### What problem does the project address?

It studies how frozen ML output and protocol evidence can add context to manually maintained Suricata signatures while keeping generated rules under human review.

### Is the system automatically blocking production traffic?

No. Candidates remain review-only. Production deployment and live G5 acceptance are not claimed.

### Did the standalone anomaly models separate Attack and Normal traffic?

Not in the reported six-session holdout. The existing report gives TP=3, FP=3, FN=0, TN=0 for IF/AE consensus. The Python Hybrid layer reported TP=3, FP=0, FN=0, TN=3 on that bounded lab cohort.

### Does the result generalize to production?

No. It is a small controlled laboratory result, not an estimate of production accuracy.

### What is candidate SID 9103005?

It is a frozen RST-response candidate bound to development, cohort, holdout, and baseline evidence. Its candidate and replay signatures verify locally; its approval and deployment flags remain false.

### Why did G5R4 fail?

The historical run is terminal FAILED. Its supplied evidence says the expected flow events were emitted with shutdown reason, so they did not establish per-probe observation while the engine was active. No active Attack probe completed. Do not reframe this as a passing activation.

### What changed in the observer?

The generated isolated config enables EVE alerts, flow events, and stats, and caps TCP state timeouts at five seconds. The observer requires exact probe-flow tuple/ID evidence, candidate alert correlation, stats liveness, and bounded deadlines. Production settings and candidate rules are untouched.

### Has the correction been validated on Suricata 8.0.3 with the original PCAPs?

Not in this closeout. The offline tests pass, but VM1 native syntax validation and in-window flow evidence from the actual PCAPs remain blocked.

### Why not rerun G5R4?

G5R4 is terminal FAILED and its nonce is consumed. A future attempt requires independent readiness, a new unused attempt namespace, and a separate Owner authorization with a fresh nonce.

### What does the latency table show?

It separates historical within-process pipeline measurements and a same-host 607-record EVE-to-ledger distribution from activation, rollback, and other stages that remain `NOT_MEASURED`.

### Is EVE continuously driving ML inference?

No. Existing EVE-to-ELK visibility is documented; continuous EVE-driven ML inference is not implemented.

### What is the project's main limitation?

The evidence is bounded to the tested lab and data. Dataset gaps, standalone model false positives, absent live G5 acceptance, and incomplete end-to-end latency limit operational claims.
