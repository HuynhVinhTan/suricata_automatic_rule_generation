# Milestones 4 5 and 6 Evidence Record

Collected from the authorized lab on 2026-11-11 UTC.

## Services

```text
VM1 2026-11-11T17:34:31+00:00
suricata active
filebeat active
/usr/bin/tcpdump

VM3 2026-11-11T17:34:32+00:00
Elasticsearch yellow, one data node
Kibana HTTP 200
Beats listener 192.168.10.30:5044
```

## Elasticsearch

```text
suricata-eve-2026.11.11  7674 documents
suricata-ai-summary         4 documents
```

## Rule

```text
alert tcp 192.168.10.10 any -> 192.168.10.20 any (msg:"ML REVIEW - repeated TCP RST responses"; flow:stateless; flags:R+; threshold:type threshold,track by_dst,count 3,seconds 60; classtype:attempted-recon; sid:9103003; rev:1;)
rule_sha256=7182bb328ce4ed1230c6de9b20c825d458b8c224a494d6b2a60063cca5ec21df
suricata=8.0.3
syntax=PASS
attack_sessions=3/3
normal_sessions=0/3
approved=false
deployable=false
deployed=false
```

Raw private PCAPs and replay logs remain outside this artifact and outside Git.
