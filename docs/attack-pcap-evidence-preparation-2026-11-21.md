# P1.1 Attack PCAP evidence preparation (2026-11-21)

## Scope and verdict

This note records repository implementation and offline validation only. No VM,
SSH session, tcpdump process, attack generator, Suricata EVE file, or raw PCAP
was accessed or created for this task.

**P1.1_PREPARED — WAITING_FOR_OWNER_APPROVAL**

The implementation is deliberately stopped before live capture approval. It does
not perform Hybrid signing, candidate generation, rule activation, or any
production Suricata/Filebeat/EVE/ELK change.

## Historical evidence preserved

The previously verified Normal-only PCAP remains historical evidence and is not
reclassified:

| Item | Observed/documented value |
| --- | --- |
| Path | `/home/kali/suricata-ai-showcase/evidence/labcap-20261113T100057Z.pcap` |
| SHA256 | `b0f9459ffa2280bad876302bba66f480d0c372a928d12e806cf6b3adaf54e528` |
| Contents | 228 packets; 22 Normal HTTP SYN attempts; two Normal RST controls on 18100 and 18101 |
| Classification | Normal-only; not Attack evidence |

No new Attack PCAP or EVE evidence was observed in this repository-only task.

## Prepared workflow

`scripts/demo/vm2-capture-session.sh` is an owner-invoked VM2 workflow. It
verifies `eth1` and `192.168.10.20`, refuses overwrite, starts interactive
`sudo tcpdump` with snaplen 96, a 5,000 packet limit, a 120 second timer, and a
bidirectional allowlist for VM2/VM1 and TCP ports 18100–18123. It waits for the
`listening on eth1` readiness line before launching the unprivileged 24-probe
generator. Partial PCAP, tcpdump log, and metadata are retained on failure;
successful output is moved atomically and hashed.

`scripts/verify_attack_evidence.py` is read-only. It parses classic Ethernet
PCAP, checks hash/link type/snaplen/timestamps/scope, matches actual manifest
five-tuples and inbound RSTs, reports retransmissions, and correlates optional
EVE JSONL records. A generator result of `24/24 rst_refused` is never treated as
capture proof. Missing or incomplete EVE correlation is `PARTIAL` or `BLOCKED`.

## Remaining gates

- Live capture requires a separate owner authorization naming the exact VM2 host,
  command, and scope.
- A future runtime result must independently show 24 destination ports, 24
  manifest-matched SYN five-tuples, 24 inbound RST responses, correct timing,
  no out-of-scope traffic, and documented drop statistics.
- Independent holdout evidence remains missing and no frozen model, threshold, or
  historical evaluation dataset was changed.
