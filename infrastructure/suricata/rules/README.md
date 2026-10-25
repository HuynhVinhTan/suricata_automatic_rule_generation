# Suricata Custom Rules

## Purpose

This directory contains IDS rules developed specifically
for the Suricata AI Project.

These rules are separate from third-party rulesets
managed by Suricata or suricata-update.

## Files

local.rules

Contains a simple ICMP detection rule for testing
Suricata in the isolated VMware lab.

## Rule Naming Convention

Use descriptive names when adding more rules:

- local.rules
- lab-http.rules
- lab-icmp.rules
- lab-scan.rules

These additional files should only be created
when the corresponding detection requirement exists.

## Rule SID Convention

Project example rules may use locally allocated SIDs
such as 1000001, 1000002, etc.

Every rule must have a unique SID.

Check for conflicts before enabling new rules.

## Deployment

Example destination on VM1:

    /etc/suricata/rules/local.rules

Example configuration entry:

    /etc/suricata/rules/local.rules

This path must be included in the active
rule-files configuration before the file is loaded.

Do not assume that placing a file in this directory
automatically enables it.

## Testing

Validate Suricata after adding a rule:

    sudo suricata -T -c /etc/suricata/suricata.yaml -v

Do not restart the service if validation fails.

## Important

The local.rules file in this repository is a lab example.

It is not evidence that this rule is currently
enabled on VM1.

Do not modify the generated ruleset maintained
by suricata-update.