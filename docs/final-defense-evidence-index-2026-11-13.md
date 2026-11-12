# Final defense evidence index

This index is sanitized: raw PCAPs, raw EVE payloads, model binaries,
credentials and private keys are excluded from Git. Private evidence is
available to the authorized reviewer under
`data/private/sid-9103012-validation-20261113-p3/`.

| Requirement | Evidence | SHA256 / run | Result | Limitation |
|---|---|---|---|---|
| Candidate provenance | `data/private/isolated-candidate-9103012-20261112/candidate.json` | `2bb34edcf09ee1474b3a4f1568b6b49273a37ed325674272ac49dd2c5d5114dd` | PASS, review-only | Candidate remains `PROPOSED` |
| Approved independent cohort | `configs/suricata/isolated-candidate-9103012-independent-cases.json` | `57aa92f0a63bd2f8fe037904d0aecb2e2414031d5b9af8f08e5c9bbf73eddeba` | PASS | Discovery Attack-01 excluded |
| Deployment provenance | `configs/suricata/isolated-candidate-9103012-deployment-manifest.json` | manifest SHA `4e9849f85c097f2a2b6d228b3f9044e5fd034014fb6437789f38b04bbe35b0dc`; signer/runtime `e278b50369c3947dcbacc5e324faba3276cc48d9` | PASS | Candidate generation source remains `65a197e0df95f0f96e3cb41b4870d96c1d53659a` |
| Suricata syntax | Private `syntax-stdout.txt`, `syntax-metadata.tsv` | `syntax-20261113-02`; config SHA `a341e5a1dd7e09c5f3440584147665506038f6f54e383254d72e94145e91c203` | PASS | Syntax does not prove safety |
| Independent replay | `data/private/sid-9103012-validation-20261113-p3/summary.tsv` | `replay-20261113-04`; summary SHA `62401b8428675c645097840e7a413cf189844a2efa9bb962924ee67623975f9a` | Executed | Candidate gate failed |
| Candidate metrics | `docs/sid-9103012-validation-summary-2026-11-13.md` | TP=2, FN=0, FP=3, TN=0 | FAIL / REJECTED | FPR=1.0000 |
| Fresh EVE evidence | Five private `*.eve.json` files | Hashes listed in the validation summary | PASS as evidence | Raw payloads remain private |
| Historical SID 9103003 | `docs/documented-rule-recovery-2026-11-12.md` and historical private evidence | Separate historical run | PASS where documented | Historical ET snapshot/metadata not recovered |
| Baseline comparison | `docs/baseline-comparison-evidence-2026-11-12.md` | New copied VM1 ruleset | PASS as NEW baseline | Not the unavailable historical snapshot |
| Review-only lifecycle | `src/netids/candidate_record.py`, `scripts/operate_isolated_once.py` | Focused security tests | PASS for fail-closed code | No live activation or rollback |
| CI and source | PR #3 branch | Commit `68faf5989f974105c8b9f65e9f1017507092ed08`; [Actions run 43281660270](https://github.com/HuynhVinhTan/suricata_automatic_rule_generation/actions/runs/43281660270) | PASS: dataset-and-lifecycle and unit-handoff succeeded | CI is not VM1 runtime evidence |

## Reproduction

Use the approved manifest, candidate record and exact source/runtime commit
from PR #3. Resolve manifest paths only beneath the approved VM1 holdout root,
verify every PCAP hash, run Suricata 8.0.3 `-T`, then replay each of the five
cases into a fresh exclusive directory. Parse fresh EVE and compute metrics at
session level. A normal-session candidate alert is a rejection; do not sign,
approve, activate or deploy the candidate after that result.
