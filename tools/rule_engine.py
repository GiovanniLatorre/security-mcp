"""Detection rule suggestion engine.

Generates Wazuh and Falco rules based on security findings.
The AI calls this to get actionable rule templates.
"""

from __future__ import annotations

import json
import textwrap


def suggest_wazuh_rule(
    finding_type: str,
    description: str,
    field_name: str = "",
    field_value: str = "",
    severity: int = 10,
) -> dict:
    """Generate a Wazuh rule XML based on a finding.

    Args:
        finding_type: Category (e.g. 'brute_force', 'anomalous_dns', 'privilege_escalation',
                      'unauthorized_access', 'data_exfiltration', 'malware', 'policy_violation')
        description: Human description of what to detect
        field_name: Wazuh decoded field to match (e.g. 'srcip', 'data.aws.eventName')
        field_value: Expected value or regex pattern
        severity: Wazuh rule level (1-15)
    """
    rule_id = 100_000 + hash(description) % 10_000

    templates = {
        "brute_force": textwrap.dedent(f"""\
            <group name="custom,authentication_failures,">
              <rule id="{rule_id}" level="{severity}">
                <if_matched_sid>5710</if_matched_sid>
                <frequency>10</frequency>
                <timeframe>120</timeframe>
                <description>{description}</description>
                <group>authentication_failures,pci_dss_10.2.4,pci_dss_10.2.5,</group>
              </rule>
            </group>"""),

        "anomalous_dns": textwrap.dedent(f"""\
            <group name="custom,dns_anomaly,">
              <rule id="{rule_id}" level="{severity}">
                <field name="query_name">{field_value or 'REGEX_PATTERN_HERE'}</field>
                <description>{description}</description>
                <group>dns_anomaly,threat_intel,</group>
              </rule>
            </group>"""),

        "privilege_escalation": textwrap.dedent(f"""\
            <group name="custom,privilege_escalation,">
              <rule id="{rule_id}" level="{severity}">
                <field name="{field_name or 'data.aws.eventName'}">{field_value or 'AttachRolePolicy|PutUserPolicy'}</field>
                <description>{description}</description>
                <group>privilege_escalation,pci_dss_10.2.2,</group>
              </rule>
            </group>"""),

        "unauthorized_access": textwrap.dedent(f"""\
            <group name="custom,unauthorized_access,">
              <rule id="{rule_id}" level="{severity}">
                <field name="{field_name or 'srcip'}">{field_value or 'IP_OR_PATTERN'}</field>
                <description>{description}</description>
                <group>unauthorized_access,gdpr_IV_35.7.d,</group>
              </rule>
            </group>"""),

        "data_exfiltration": textwrap.dedent(f"""\
            <group name="custom,data_exfiltration,">
              <rule id="{rule_id}" level="{severity}">
                <field name="{field_name or 'data.aws.eventName'}">{field_value or 'GetObject'}</field>
                <frequency>50</frequency>
                <timeframe>300</timeframe>
                <description>{description}</description>
                <group>data_exfiltration,pci_dss_10.6.1,</group>
              </rule>
            </group>"""),

        "policy_violation": textwrap.dedent(f"""\
            <group name="custom,policy_violation,">
              <rule id="{rule_id}" level="{severity}">
                <field name="{field_name or 'data.aws.eventName'}">{field_value or 'EVENT_NAME'}</field>
                <description>{description}</description>
                <group>policy_violation,hipaa_164.312.b,</group>
              </rule>
            </group>"""),
    }

    generic = textwrap.dedent(f"""\
        <group name="custom,{finding_type},">
          <rule id="{rule_id}" level="{severity}">
            <field name="{field_name or 'FIELD'}">{field_value or 'VALUE'}</field>
            <description>{description}</description>
            <group>{finding_type},</group>
          </rule>
        </group>""")

    return {
        "engine": "wazuh",
        "rule_id": rule_id,
        "level": severity,
        "xml": templates.get(finding_type, generic),
        "deploy_path": "/var/ossec/etc/rules/local_rules.xml",
        "restart_cmd": "systemctl restart wazuh-manager",
        "test_cmd": f"/var/ossec/bin/wazuh-logtest",
    }


def suggest_falco_rule(
    finding_type: str,
    description: str,
    condition: str = "",
    output_fields: str = "",
    severity: str = "WARNING",
) -> dict:
    """Generate a Falco YAML rule based on a finding.

    Args:
        finding_type: Category (same as Wazuh)
        description: Human description
        condition: Falco condition expression (if known)
        output_fields: Fields to include in output
        severity: Falco priority (EMERGENCY, ALERT, CRITICAL, ERROR, WARNING, NOTICE, INFO, DEBUG)
    """
    templates = {
        "privilege_escalation": {
            "rule": description,
            "desc": f"Detects {finding_type}: {description}",
            "condition": condition or "spawned_process and proc.name in (sudo, su, pkexec) and not proc.pname in (cron, sshd)",
            "output": output_fields or "Privilege escalation detected (user=%user.name command=%proc.cmdline parent=%proc.pname container=%container.id)",
            "priority": severity,
            "tags": ["host", "privilege_escalation", "T1548"],
        },
        "unauthorized_access": {
            "rule": description,
            "desc": f"Detects {finding_type}: {description}",
            "condition": condition or "inbound_outbound and fd.sport in (22, 3306, 5432, 6379) and not fd.sip in (rfc_1918_addresses)",
            "output": output_fields or "Unexpected network connection (proc=%proc.name ip=%fd.sip port=%fd.sport container=%container.id)",
            "priority": severity,
            "tags": ["network", "unauthorized_access", "T1071"],
        },
        "data_exfiltration": {
            "rule": description,
            "desc": f"Detects {finding_type}: {description}",
            "condition": condition or "evt.type in (sendto, connect) and fd.net != '127.0.0.0/8' and proc.name in (curl, wget, nc, ncat)",
            "output": output_fields or "Potential data exfiltration (proc=%proc.name dest=%fd.sip:%fd.sport user=%user.name container=%container.id)",
            "priority": severity,
            "tags": ["network", "data_exfiltration", "T1048"],
        },
        "malware": {
            "rule": description,
            "desc": f"Detects {finding_type}: {description}",
            "condition": condition or "spawned_process and (proc.name in (cryptominer, xmrig) or proc.args contains 'stratum+tcp')",
            "output": output_fields or "Suspected malware (proc=%proc.name args=%proc.args user=%user.name container=%container.id)",
            "priority": "CRITICAL",
            "tags": ["host", "malware", "T1496"],
        },
    }

    generic = {
        "rule": description,
        "desc": f"Custom detection: {description}",
        "condition": condition or "# TODO: define condition",
        "output": output_fields or f"Detection triggered (proc=%proc.name user=%user.name container=%container.id)",
        "priority": severity,
        "tags": [finding_type],
    }

    rule = templates.get(finding_type, generic)

    yaml_output = (
        f"- rule: {rule['rule']}\n"
        f"  desc: {rule['desc']}\n"
        f"  condition: {rule['condition']}\n"
        f"  output: \"{rule['output']}\"\n"
        f"  priority: {rule['priority']}\n"
        f"  tags: {json.dumps(rule['tags'])}\n"
    )

    return {
        "engine": "falco",
        "yaml": yaml_output,
        "deploy_path": "/etc/falco/rules.d/custom_rules.yaml",
        "restart_cmd": "systemctl restart falco",
        "test_cmd": "falco --dry-run -r /etc/falco/rules.d/custom_rules.yaml",
    }


def suggest_rules(
    finding_type: str,
    description: str,
    field_name: str = "",
    field_value: str = "",
    severity: int = 10,
    falco_condition: str = "",
) -> dict:
    """Generate both Wazuh and Falco rules for a finding."""
    falco_priority_map = {
        range(1, 5): "NOTICE",
        range(5, 8): "WARNING",
        range(8, 11): "ERROR",
        range(11, 13): "CRITICAL",
        range(13, 16): "ALERT",
    }
    falco_prio = "WARNING"
    for r, p in falco_priority_map.items():
        if severity in r:
            falco_prio = p
            break

    return {
        "wazuh": suggest_wazuh_rule(finding_type, description, field_name, field_value, severity),
        "falco": suggest_falco_rule(finding_type, description, falco_condition, severity=falco_prio),
    }
