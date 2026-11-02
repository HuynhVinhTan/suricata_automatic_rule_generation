# Suricata IDS Infrastructure

## 1. Overview

Suricata is the Network Intrusion Detection System (IDS)
used in the Suricata AI Project.

It runs on VM1 and monitors network traffic in the lab.

## 2. Environment

VM: VM1 - Ubuntu Suricata IDS
IP: 192.168.10.10
Network: VMware VMnet2
Network range: 192.168.10.0/24

## 3. Responsibilities

Suricata is responsible for:

- Monitoring network traffic.
- Analyzing supported network protocols.
- Detecting suspicious traffic using IDS rules.
- Generating network security events.
- Writing events to EVE JSON logs.

Suricata does not train ML or DL models.

## 4. Important Files

Main configuration:

    /etc/suricata/suricata.yaml

EVE JSON output:

    /var/log/suricata/eve.json

Rules directory:

    /etc/suricata/rules/

The actual active rules must be verified from
the rule-files configuration.

## 5. Data Pipeline

Kali Linux (VM2)
    |
    v
Suricata IDS (VM1)
    |
    v
/var/log/suricata/eve.json
    |
    v
Filebeat (VM1)
    |
    v
Logstash (VM3)
    |
    v
Elasticsearch (VM3)
    |
    v
Kibana (VM3)

## 6. Useful Commands

Check service status:

    sudo systemctl status suricata --no-pager

Check configuration:

    sudo suricata -T -c /etc/suricata/suricata.yaml -v

View recent EVE logs:

    sudo tail -n 20 /var/log/suricata/eve.json

View IDS alerts:

    sudo tail -f /var/log/suricata/fast.log

Check Suricata version:

    suricata --build-info

## 7. Rule Management

Custom project rules are stored in:

    infrastructure/suricata/rules/

Do not directly modify the generated suricata.rules file.

The project rules in this repository are not
automatically active on VM1.

Before activating rules:

1. Verify the current rule-files configuration.
2. Copy the selected custom rules to VM1.
3. Add the rule path if required.
4. Test the complete Suricata configuration.
5. Reload or restart Suricata in a controlled test.

## 8. Deployment Notes

The production configuration must be copied from VM1.

Do not replace the working VM1 configuration with
a template without reviewing its differences.

Never commit passwords, tokens, private keys,
or sensitive network information.

## 9. Project Status

Phase 03 infrastructure has been deployed.

Custom rule activation:
NOT VERIFIED / NOT DEPLOYED FROM THIS REPOSITORY.

ML/DL integration:
Planned for Phase 05-06.