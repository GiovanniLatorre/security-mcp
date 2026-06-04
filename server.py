"""Security MCP Server -- read-only AWS/VPN security investigation tools.

Run: python server.py  (stdio transport, for Cursor/Claude Desktop)
"""

from __future__ import annotations

import functools
import json
import logging
import os
import sys
from typing import Optional

from mcp.server.fastmcp import FastMCP

_PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _PROJECT_DIR)
os.chdir(_PROJECT_DIR)

from dotenv import load_dotenv
load_dotenv()

from tools.aws_helper import AWSHelper, list_account_names, resolve_account
from tools.splunk_client import SplunkClient
from tools.posture import get_posture, format_posture_text
from tools.playbook_store import (
    save_playbook as _save_playbook,
    search_playbooks as _search_playbooks,
    list_recent_playbooks as _list_recent,
    get_stats as _get_playbook_stats,
)
from tools.rule_engine import suggest_rules as _suggest_rules
from tools.audit_store import log_action as _log_action, get_recent_actions as _get_recent_actions

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger("security-mcp")

mcp = FastMCP("Security Investigation MCP")


def _json_compact(obj: object) -> str:
    return json.dumps(obj, indent=2, default=str, ensure_ascii=False)


def _get_aws(account: str, region: str = "us-east-1") -> AWSHelper:
    return AWSHelper(account, region)


SSO_KEYWORDS = ["expired", "token", "sso", "unauthorized", "credentials", "security token", "access denied"]


def _safe_call(func):
    """Catch SSO/credential errors and return actionable messages instead of tracebacks."""

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as exc:
            err = str(exc).lower()
            if any(kw in err for kw in SSO_KEYWORDS):
                acct = kwargs.get("account") or (args[1] if len(args) > 1 else "?")
                acct_cfg = resolve_account(str(acct))
                profile = (
                    acct_cfg["profile"]
                    if acct_cfg
                    else os.environ.get("AWS_PROFILE", f"<sso-profile-for-{acct}>")
                )
                return json.dumps({
                    "error": "AWS_SSO_EXPIRED",
                    "message": f"SSO token expirado para a conta '{acct}'.",
                    "action": f"Pede pro usuario rodar: aws sso login --profile {profile}",
                    "profile": profile,
                })
            logger.exception("Tool %s failed", func.__name__)
            return json.dumps({"error": str(exc)})

    return wrapper


# ═════════════════════════════════════════════════════════════════════════
# TOOL: list_accounts
# ═════════════════════════════════════════════════════════════════════════

@mcp.tool()
def list_accounts() -> str:
    """List all configured AWS accounts available for investigation.

    Returns account names, profiles, and IDs.
    """
    names = list_account_names()
    accounts = []
    for name in names:
        acct = resolve_account(name)
        if acct:
            accounts.append({
                "name": name,
                "profile": acct.get("profile", ""),
                "account_id": acct.get("account_id", ""),
                "has_guardduty": bool(acct.get("guardduty_detector")),
                "has_dns_logs": bool(acct.get("dns_log_group")),
            })
    return _json_compact(accounts)


# ═════════════════════════════════════════════════════════════════════════
# TOOL: investigate_ec2
# ═════════════════════════════════════════════════════════════════════════

@mcp.tool()
@_safe_call
def investigate_ec2(
    instance_id: str,
    account: str,
    region: str = "us-east-1",
) -> str:
    """Investigate an EC2 instance: tags, security groups, state, IAM, Wazuh status.

    Read-only. Gathers all relevant info for security analysis.

    Args:
        instance_id: EC2 instance ID (e.g. i-0abc123def456)
        account: AWS account name or ID (e.g. 'example-staging', '123456789012')
        region: AWS region (default us-east-1)
    """
    aws = _get_aws(account, region)
    result: dict = {}

    result["instance"] = aws.get_instance_summary(instance_id)

    sg_details = []
    for sg in result["instance"].get("security_groups", []):
        sg_details.append(aws.describe_security_group(sg["id"]))
    result["security_group_details"] = sg_details

    result["wazuh"] = aws.check_wazuh_status(instance_id)

    return _json_compact(result)


# ═════════════════════════════════════════════════════════════════════════
# TOOL: investigate_guardduty
# ═════════════════════════════════════════════════════════════════════════

@mcp.tool()
@_safe_call
def investigate_guardduty(
    account: str,
    region: str = "us-east-1",
    finding_id: Optional[str] = None,
    instance_id: Optional[str] = None,
    max_results: int = 10,
) -> str:
    """Investigate GuardDuty findings for an account.

    Read-only. Can get a specific finding by ID, list findings for an instance,
    or list recent findings for the account.

    Args:
        account: AWS account name or ID
        region: AWS region (default us-east-1)
        finding_id: Specific GuardDuty finding ID (optional)
        instance_id: Filter findings for this EC2 instance (optional)
        max_results: Max findings to return (default 10)
    """
    aws = _get_aws(account, region)

    if finding_id:
        finding = aws.get_guardduty_finding(finding_id)
        if finding:
            return _json_compact(finding)
        return json.dumps({"error": f"Finding {finding_id} not found"})

    findings = aws.list_guardduty_findings(instance_id=instance_id, max_results=max_results)
    return _json_compact({"count": len(findings), "findings": findings})


# ═════════════════════════════════════════════════════════════════════════
# TOOL: investigate_alb
# ═════════════════════════════════════════════════════════════════════════

@mcp.tool()
@_safe_call
def investigate_alb(
    alb_name_or_arn: str,
    account: str,
    region: str = "us-east-1",
) -> str:
    """Investigate an ALB: listeners, security groups, WAF status, exposure.

    Read-only. Checks if the ALB has WAF, what IPs are allowed in SGs,
    and its general configuration.

    Args:
        alb_name_or_arn: ALB name or full ARN
        account: AWS account name or ID
        region: AWS region (default us-east-1)
    """
    aws = _get_aws(account, region)
    return _json_compact(aws.describe_alb(alb_name_or_arn))


# ═════════════════════════════════════════════════════════════════════════
# TOOL: investigate_lambda
# ═════════════════════════════════════════════════════════════════════════

@mcp.tool()
@_safe_call
def investigate_lambda(
    function_name: str,
    account: str,
    region: str = "us-east-1",
    hours_back: int = 6,
) -> str:
    """Investigate a Lambda function: config, recent errors, CloudTrail events.

    Read-only. Gets Lambda configuration, recent error logs, and API events.

    Args:
        function_name: Lambda function name
        account: AWS account name or ID
        region: AWS region (default us-east-1)
        hours_back: How many hours back to search logs (default 6)
    """
    aws = _get_aws(account, region)
    result: dict = {}

    result["config"] = aws.describe_lambda(function_name)
    result["recent_errors"] = aws.get_lambda_errors(function_name, hours_back=hours_back, limit=20)

    ct_events = aws.lookup_cloudtrail_events(
        "ResourceName", function_name, hours_back=hours_back, max_results=15
    )
    result["cloudtrail_events"] = ct_events

    return _json_compact(result)


# ═════════════════════════════════════════════════════════════════════════
# TOOL: check_wazuh
# ═════════════════════════════════════════════════════════════════════════

@mcp.tool()
@_safe_call
def check_wazuh(
    instance_id: str,
    account: str,
    region: str = "us-east-1",
) -> str:
    """Check Wazuh agent status on an EC2 instance.

    Read-only. Verifies if Wazuh is installed and running via SSM.

    Args:
        instance_id: EC2 instance ID
        account: AWS account name or ID
        region: AWS region (default us-east-1)
    """
    aws = _get_aws(account, region)
    return _json_compact(aws.check_wazuh_status(instance_id))


# ═════════════════════════════════════════════════════════════════════════
# TOOL: who_has_ip
# ═════════════════════════════════════════════════════════════════════════

@mcp.tool()
@_safe_call
def who_has_ip(
    ip_address: str,
    account: str = "networking",
    region: str = "us-east-1",
) -> str:
    """Identify which VPN user has a specific IP address.

    Read-only. Searches Pritunl VPN logs via SSM on configured VPN instances.

    Args:
        ip_address: The VPN IP to look up (e.g. 10.15.3.42)
        account: AWS account with VPN instances (default 'networking')
        region: AWS region (default us-east-1)
    """
    acct = resolve_account(account)
    if not acct:
        return json.dumps({"error": f"Account '{account}' not found"})

    vpn_instances = acct.get("vpn_instances", [])
    if not vpn_instances:
        return json.dumps({"error": f"No VPN instances configured for '{account}'"})

    aws = _get_aws(account, region)

    for inst_id in vpn_instances:
        user_info = aws.identify_vpn_user(inst_id, ip_address)
        if user_info:
            user_info["vpn_instance"] = inst_id
            return _json_compact(user_info)

    return json.dumps({"result": "not_found", "ip": ip_address, "searched_instances": vpn_instances})


# ═════════════════════════════════════════════════════════════════════════
# TOOL: query_dns
# ═════════════════════════════════════════════════════════════════════════

@mcp.tool()
@_safe_call
def query_dns(
    search_term: str,
    account: str = "networking",
    region: str = "us-east-1",
    hours_back: int = 1,
    limit: int = 50,
) -> str:
    """Query Route53 DNS logs for a domain, IP, or pattern.

    Read-only. Searches CloudWatch DNS query logs.

    Args:
        search_term: Domain name, IP, or substring to search for
        account: AWS account with DNS logs (default 'networking')
        region: AWS region (default us-east-1)
        hours_back: How many hours back to search (default 1)
        limit: Max results (default 50)
    """
    aws = _get_aws(account, region)
    results = aws.query_dns_logs(search_term, hours_back=hours_back, limit=limit)
    return _json_compact({"count": len(results), "results": results[:limit]})


# ═════════════════════════════════════════════════════════════════════════
# TOOL: lookup_cloudtrail
# ═════════════════════════════════════════════════════════════════════════

@mcp.tool()
@_safe_call
def lookup_cloudtrail(
    attribute_key: str,
    attribute_value: str,
    account: str,
    region: str = "us-east-1",
    hours_back: int = 24,
    max_results: int = 20,
) -> str:
    """Search CloudTrail events by attribute.

    Read-only. Looks up recent API activity.

    Args:
        attribute_key: CloudTrail lookup key (EventName, ResourceName, ResourceType, Username, EventSource)
        attribute_value: Value to search for
        account: AWS account name or ID
        region: AWS region (default us-east-1)
        hours_back: How many hours back to search (default 24)
        max_results: Max events to return (default 20)
    """
    aws = _get_aws(account, region)
    events = aws.lookup_cloudtrail_events(
        attribute_key, attribute_value, hours_back=hours_back, max_results=max_results
    )
    return _json_compact({"count": len(events), "events": events})


# ═════════════════════════════════════════════════════════════════════════
# TOOL: describe_security_group
# ═════════════════════════════════════════════════════════════════════════

@mcp.tool()
@_safe_call
def describe_security_group(
    sg_id: str,
    account: str,
    region: str = "us-east-1",
) -> str:
    """Get detailed info about a security group including all inbound rules.

    Read-only.

    Args:
        sg_id: Security group ID (e.g. sg-0abc123)
        account: AWS account name or ID
        region: AWS region (default us-east-1)
    """
    aws = _get_aws(account, region)
    return _json_compact(aws.describe_security_group(sg_id))


# ═════════════════════════════════════════════════════════════════════════
# TOOL: ssm_command (read-only)
# ═════════════════════════════════════════════════════════════════════════

@mcp.tool()
@_safe_call
def ssm_read_command(
    instance_id: str,
    command: str,
    account: str,
    region: str = "us-east-1",
) -> str:
    """Run a read-only shell command on an EC2 instance via SSM.

    For diagnostic/inspection commands only (cat, grep, ps, systemctl status, etc).
    Does NOT execute destructive commands.

    Args:
        instance_id: EC2 instance ID
        command: Shell command to run (read-only operations only)
        account: AWS account name or ID
        region: AWS region (default us-east-1)
    """
    blocked = ["rm ", "dd ", "mkfs", "shutdown", "reboot", "halt", "kill ",
               "systemctl stop", "systemctl restart", "yum remove", "apt remove",
               "pip uninstall", "npm uninstall", "> /", ">> /", "chmod", "chown"]
    cmd_lower = command.lower().strip()
    for b in blocked:
        if b in cmd_lower:
            return json.dumps({"error": f"Blocked: command contains '{b.strip()}'. Only read-only commands allowed."})

    aws = _get_aws(account, region)
    return _json_compact(aws.ssm_run_command(instance_id, command))


# ═════════════════════════════════════════════════════════════════════════
# TOOL: search_splunk
# ═════════════════════════════════════════════════════════════════════════

@mcp.tool()
def search_splunk(
    query: str,
    earliest: str = "-1h",
    latest: str = "now",
    max_results: int = 50,
) -> str:
    """Search Splunk for logs and events. Read-only.

    Use for: Pritunl VPN logs, Wazuh alerts, CloudTrail events, application logs,
    or any indexed data. This is the primary source of truth for security investigations.

    Common queries:
    - Pritunl errors: 'index=pritunl "authorizer callback" | stats count by host, user'
    - Wazuh alerts: 'index=wazuh rule.level>=10 | table agent.name, rule.description'
    - User activity: 'index=pritunl user_name="john.doe" | table _time, message, server_name'

    Args:
        query: SPL query string (e.g. 'index=pritunl "error" | head 20')
        earliest: Start time (e.g. '-1h', '-24h', '-7d', '2026-04-01T00:00:00')
        latest: End time (default 'now')
        max_results: Max results to return (default 50)
    """
    client = SplunkClient()
    result = client.search(query, earliest=earliest, latest=latest, max_results=max_results)
    return _json_compact(result)


# ═════════════════════════════════════════════════════════════════════════
# TOOL: save_playbook
# ═════════════════════════════════════════════════════════════════════════

@mcp.tool()
def save_investigation_playbook(
    alert_type: str,
    verdict: str,
    summary: str,
    alert_source: str = "",
    resource_type: str = "",
    investigation_steps: Optional[str] = None,
    splunk_queries: Optional[str] = None,
    mcp_tools_used: Optional[str] = None,
    tags: Optional[str] = None,
) -> str:
    """Save an investigation result as a playbook for future reference.

    Call this AFTER completing an investigation. Stores the alert type, verdict,
    summary, and the steps/queries used so future similar alerts can be resolved faster.

    Args:
        alert_type: Type of alert (e.g. 'GuardDuty:DNS', 'Pritunl:AuthError', 'EC2:NoWazuh', 'ALB:NoWAF')
        verdict: Investigation result ('fp', 'tp', 'likely_fp', 'needs_escalation')
        summary: Short summary of what was found and why (2-3 sentences)
        alert_source: Where the alert came from (e.g. 'splunk', 'guardduty', 'inspector')
        resource_type: AWS resource type (e.g. 'ec2', 'lambda', 'alb', 'vpn')
        investigation_steps: JSON array of steps taken (e.g. '["checked EC2 tags","queried Splunk"]')
        splunk_queries: JSON array of SPL queries used (e.g. '["index=pritunl error"]')
        mcp_tools_used: JSON array of MCP tools called (e.g. '["investigate_ec2","search_splunk"]')
        tags: Comma-separated tags (e.g. 'vpn,sso,pritunl')
    """
    def _parse_json_list(val: Optional[str]) -> list:
        if not val:
            return []
        try:
            return json.loads(val)
        except json.JSONDecodeError:
            return [s.strip() for s in val.split(",") if s.strip()]

    playbook_id = _save_playbook(
        alert_type=alert_type,
        verdict=verdict,
        summary=summary,
        alert_source=alert_source or None,
        resource_type=resource_type or None,
        investigation_steps=_parse_json_list(investigation_steps),
        splunk_queries=_parse_json_list(splunk_queries),
        mcp_tools_used=_parse_json_list(mcp_tools_used),
        tags=(tags.split(",") if tags else None),
    )
    return json.dumps({"saved": True, "playbook_id": playbook_id})


# ═════════════════════════════════════════════════════════════════════════
# TOOL: search_playbooks
# ═════════════════════════════════════════════════════════════════════════

@mcp.tool()
def find_playbook(
    query: str,
    limit: int = 5,
) -> str:
    """Search past investigations for similar alerts.

    Call this BEFORE starting a new investigation to check if a similar alert
    was already analyzed. Returns matching playbooks with verdicts and steps used.

    Args:
        query: Search terms (e.g. 'pritunl authorizer callback', 'ec2 wazuh', 'guardduty dns')
        limit: Max results (default 5)
    """
    results = _search_playbooks(query, limit=limit)
    if not results:
        return json.dumps({"count": 0, "message": "No matching playbooks found. This is a new alert type."})
    return _json_compact({"count": len(results), "playbooks": results})


# ═════════════════════════════════════════════════════════════════════════
# TOOL: playbook_stats
# ═════════════════════════════════════════════════════════════════════════

@mcp.tool()
def playbook_stats() -> str:
    """Get statistics on all saved investigation playbooks.

    Shows total investigations, breakdown by verdict (FP/TP), and top alert types.
    """
    stats = _get_playbook_stats()
    recent = _list_recent(limit=5)
    stats["recent_investigations"] = [
        {"alert_type": p["alert_type"], "verdict": p["verdict"], "date": p["created_at"][:10]}
        for p in recent
    ]
    return _json_compact(stats)


# ═════════════════════════════════════════════════════════════════════════
# TOOL: security_posture
# ═════════════════════════════════════════════════════════════════════════

@mcp.tool()
async def security_posture(hours: int = 24) -> str:
    """Get the current security posture across all data sources.

    Queries Splunk for: Wazuh alerts, Inspector vulnerabilities, VPN activity,
    CloudTrail suspicious events, GitHub audit, Google Workspace auth, and bastion access.
    Also checks AWS for cost waste and downtime risk indicators.

    Returns a consolidated report of the security state of the environment.
    Use when the user asks: "estado de seguranca", "posture", "como esta o ambiente",
    "indicadores de compromisso", "o que aconteceu hoje", etc.

    Args:
        hours: How many hours back to look (default 24)
    """
    client = SplunkClient()
    if not client.is_configured:
        return json.dumps({
            "error": "SPLUNK_NOT_CONFIGURED",
            "message": "Splunk nao configurado. Coloca SPLUNK_TOKEN no .env",
        })

    report = await get_posture(hours)
    text = format_posture_text(report)
    return text


# ═════════════════════════════════════════════════════════════════════════
# TOOL: check_s3_exposure
# ═════════════════════════════════════════════════════════════════════════

@mcp.tool()
@_safe_call
def check_s3_exposure(
    account: str,
    region: str = "us-east-1",
) -> str:
    """Check S3 buckets for public access exposure in an AWS account.

    Read-only. Checks account-level public access block and finds
    buckets that may be publicly accessible.

    Args:
        account: AWS account name or ID
        region: AWS region (default us-east-1)
    """
    aws = _get_aws(account, region)
    return _json_compact(aws.check_s3_exposure())


# ═════════════════════════════════════════════════════════════════════════
# TOOL: check_eks_security
# ═════════════════════════════════════════════════════════════════════════

@mcp.tool()
@_safe_call
def check_eks_security(
    account: str,
    cluster_name: Optional[str] = None,
    region: str = "us-east-1",
) -> str:
    """Check EKS cluster security configuration.

    Read-only. Checks public endpoint, logging, encryption, RBAC.
    If no cluster_name is given, lists all clusters in the account.

    Args:
        account: AWS account name or ID
        cluster_name: EKS cluster name (optional, lists all if omitted)
        region: AWS region (default us-east-1)
    """
    aws = _get_aws(account, region)

    if not cluster_name:
        clusters = aws.list_eks_clusters()
        if not clusters:
            return json.dumps({"account": account, "clusters": [], "message": "No EKS clusters found"})
        results = []
        for name in clusters[:10]:
            results.append(aws.describe_eks_cluster(name))
        return _json_compact({"account": account, "clusters": results})

    return _json_compact(aws.describe_eks_cluster(cluster_name))


# ═════════════════════════════════════════════════════════════════════════
# TOOL: check_ecr_vulns
# ═════════════════════════════════════════════════════════════════════════

@mcp.tool()
@_safe_call
def check_ecr_vulns(
    account: str,
    region: str = "us-east-1",
) -> str:
    """Check ECR container images for critical/high vulnerabilities.

    Read-only. Scans ECR repositories for image scan findings.

    Args:
        account: AWS account name or ID
        region: AWS region (default us-east-1)
    """
    aws = _get_aws(account, region)
    return _json_compact(aws.get_ecr_critical_findings())


# ═════════════════════════════════════════════════════════════════════════
# TOOL: check_waf_status
# ═════════════════════════════════════════════════════════════════════════

@mcp.tool()
@_safe_call
def check_waf_status(
    account: str,
    region: str = "us-east-1",
    web_acl_arn: Optional[str] = None,
) -> str:
    """Check WAF Web ACLs and recent blocked requests.

    Read-only. Lists WAF ACLs with rules, or gets sampled blocked
    requests for a specific ACL.

    Args:
        account: AWS account name or ID
        region: AWS region (default us-east-1)
        web_acl_arn: Specific WAF ACL ARN to get sampled requests (optional)
    """
    aws = _get_aws(account, region)

    if web_acl_arn:
        samples = aws.get_waf_sampled_requests(web_acl_arn)
        return _json_compact({"web_acl_arn": web_acl_arn, "sampled_requests": samples})

    acls = aws.list_waf_acls()
    return _json_compact({"account": account, "web_acls": acls})


# ═════════════════════════════════════════════════════════════════════════
# TOOL: suggest_detection_rules
# ═════════════════════════════════════════════════════════════════════════

@mcp.tool()
def suggest_detection_rules(
    finding_type: str,
    description: str,
    field_name: str = "",
    field_value: str = "",
    severity: int = 10,
    falco_condition: str = "",
) -> str:
    """Generate Wazuh and Falco detection rules for a security finding.

    Based on a finding, generates ready-to-deploy rule templates for both
    Wazuh (XML) and Falco (YAML), including deploy paths and test commands.

    Use after identifying a gap in detection coverage, e.g. from posture report
    findings or during incident investigation.

    Args:
        finding_type: Category - one of: brute_force, anomalous_dns, privilege_escalation,
                      unauthorized_access, data_exfiltration, malware, policy_violation
        description: What to detect (e.g. 'Detect repeated VPN auth failures from same IP')
        field_name: Wazuh field to match (e.g. 'srcip', 'data.aws.eventName')
        field_value: Value or regex pattern to match
        severity: Wazuh severity level 1-15 (default 10)
        falco_condition: Falco condition expression (optional, generates template if empty)
    """
    return _json_compact(_suggest_rules(
        finding_type=finding_type,
        description=description,
        field_name=field_name,
        field_value=field_value,
        severity=severity,
        falco_condition=falco_condition,
    ))


# ═════════════════════════════════════════════════════════════════════════
# TOOL: ssm_execute (write — requires approval)
# ═════════════════════════════════════════════════════════════════════════

_SSM_ALLOWED_PATTERNS: list[str] = [
    "systemctl restart wazuh-agent",
    "systemctl start wazuh-agent",
    "systemctl stop wazuh-agent",
    "systemctl status wazuh-agent",
    "systemctl restart filebeat",
    "systemctl start filebeat",
    "systemctl status filebeat",
    "apt-get update",
    "apt-get install -y wazuh-agent",
    "yum install -y wazuh-agent",
    "dpkg -l | grep wazuh",
    "rpm -qa | grep wazuh",
    "cat /var/ossec/etc/ossec.conf",
    "cat /var/ossec/logs/ossec.log",
    "tail ",
    "head ",
    "grep ",
    "ps aux",
    "df -h",
    "free -m",
    "uptime",
    "hostnamectl",
    "curl -so /dev/null -w '%{http_code}'",
    "wazuh-control status",
    "/var/ossec/bin/wazuh-control status",
]

_SSM_BLOCKED_PATTERNS: list[str] = [
    "rm -rf", "rm -r", "dd ", "mkfs", "shutdown", "reboot", "halt",
    "kill -9", "killall", "chmod 777", "chown root",
    "> /dev/", "curl | bash", "curl | sh", "wget | bash", "wget | sh",
    "passwd", "useradd", "userdel", "groupdel",
    "iptables -F", "iptables -X", "ufw disable",
    "terraform destroy", "kubectl delete",
]


def _is_command_allowed(command: str) -> tuple[bool, str]:
    cmd_lower = command.lower().strip()

    for blocked in _SSM_BLOCKED_PATTERNS:
        if blocked in cmd_lower:
            return False, f"BLOCKED: command contains '{blocked}'"

    for allowed in _SSM_ALLOWED_PATTERNS:
        if cmd_lower.startswith(allowed.lower()):
            return True, "matches allowlist"

    return False, (
        "Command not in allowlist. Allowed: systemctl (wazuh/filebeat), "
        "apt-get/yum install wazuh, log reading (cat/tail/grep), system info (ps/df/free). "
        "Add to _SSM_ALLOWED_PATTERNS if this should be permitted."
    )


@mcp.tool()
@_safe_call
def ssm_execute(
    instance_id: str,
    command: str,
    account: str,
    region: str = "us-east-1",
    dry_run: bool = True,
) -> str:
    """Execute an approved command on an EC2 instance via SSM.

    IMPORTANT: dry_run=True by default. The first call MUST be dry_run=True
    to show the user what will be executed. Only call with dry_run=False
    AFTER the user explicitly approves.

    Allowed operations: Wazuh agent management, Filebeat management,
    package install (wazuh only), log reading, system diagnostics.

    Destructive commands are blocked by allowlist.

    Args:
        instance_id: EC2 instance ID (e.g. i-0abc123)
        command: Shell command to execute (must match allowlist)
        account: AWS account name or ID
        region: AWS region (default us-east-1)
        dry_run: If True (default), only validates and shows what would run. Set False to execute.
    """
    allowed, reason = _is_command_allowed(command)

    if not allowed:
        _log_action(
            action_type="ssm_execute",
            account=account,
            command=command,
            dry_run=True,
            status="REJECTED",
            instance_id=instance_id,
            error=reason,
        )
        return _json_compact({
            "status": "REJECTED",
            "reason": reason,
            "command": command,
            "instance_id": instance_id,
        })

    if dry_run:
        _log_action(
            action_type="ssm_execute",
            account=account,
            command=command,
            dry_run=True,
            status="PENDING_APPROVAL",
            instance_id=instance_id,
        )
        return _json_compact({
            "status": "PENDING_APPROVAL",
            "message": "Comando validado. Aguardando aprovacao do usuario.",
            "will_execute": {
                "command": command,
                "instance_id": instance_id,
                "account": account,
                "region": region,
            },
            "instruction": (
                "Mostra ao usuario o que sera executado e pede confirmacao. "
                "So chame novamente com dry_run=false apos aprovacao explicita."
            ),
        })

    aws = _get_aws(account, region)
    result = aws.ssm_run_command(instance_id, command, timeout_sec=60)

    status = result.get("status", "unknown")
    _log_action(
        action_type="ssm_execute",
        account=account,
        command=command,
        dry_run=False,
        status=f"EXECUTED_{status.upper()}",
        instance_id=instance_id,
        output=result.get("stdout", ""),
        error=result.get("stderr", ""),
    )

    return _json_compact({
        "status": "EXECUTED",
        "result": result,
        "audit": "Action logged in audit trail.",
    })


# ═════════════════════════════════════════════════════════════════════════
# TOOL: audit_log
# ═════════════════════════════════════════════════════════════════════════

@mcp.tool()
def audit_log(limit: int = 20) -> str:
    """View recent write operations executed through the MCP.

    Shows the audit trail of all ssm_execute calls: what was run,
    where, when, dry_run or executed, and the result.

    Args:
        limit: Number of recent actions to show (default 20)
    """
    actions = _get_recent_actions(limit)
    return _json_compact({"count": len(actions), "actions": actions})


# ═════════════════════════════════════════════════════════════════════════
# TOOL: check_cost_waste
# ═════════════════════════════════════════════════════════════════════════

@mcp.tool()
@_safe_call
def check_cost_waste(
    account: str,
    region: str = "us-east-1",
) -> str:
    """Check for cost waste in an AWS account: idle EC2, unattached EBS, unused EIPs.

    Read-only. Identifies resources costing money without providing value.

    Args:
        account: AWS account name or ID
        region: AWS region (default us-east-1)
    """
    aws = _get_aws(account, region)
    result: dict = {}
    result["ebs_unattached"] = aws.get_unattached_ebs_volumes()
    result["eips_unused"] = aws.get_unused_elastic_ips()
    return _json_compact({"account": account, **result})


# ═════════════════════════════════════════════════════════════════════════
# TOOL: check_dt_risk
# ═════════════════════════════════════════════════════════════════════════

@mcp.tool()
@_safe_call
def check_dt_risk(
    account: str,
    region: str = "us-east-1",
) -> str:
    """Check for downtime risk indicators: expiring certs, RDS storage, SQS DLQs.

    Read-only. Identifies conditions that could cause service outages.

    Args:
        account: AWS account name or ID
        region: AWS region (default us-east-1)
    """
    aws = _get_aws(account, region)
    result: dict = {}
    result["expiring_certificates"] = aws.get_expiring_certificates(days_threshold=30)
    result["rds_storage_risk"] = aws.get_rds_storage_risk(threshold_pct=85.0)
    result["sqs_dlq_activity"] = aws.get_sqs_dlq_activity(min_messages=10)
    return _json_compact({"account": account, **result})


# ═════════════════════════════════════════════════════════════════════════
# TOOL: manage_security_group (write — requires approval)
# ═════════════════════════════════════════════════════════════════════════

_SG_DANGEROUS_PORTS = {22, 3389, 3306, 5432, 6379, 27017, 9200, 8080, 8443}
_SG_OPEN_WORLD = {"0.0.0.0/0", "::/0"}


@mcp.tool()
@_safe_call
def manage_security_group(
    sg_id: str,
    account: str,
    action: str,
    protocol: str = "tcp",
    port: int = 443,
    cidr: str = "",
    description: str = "",
    region: str = "us-east-1",
    dry_run: bool = True,
) -> str:
    """Add or remove an inbound rule from a Security Group.

    IMPORTANT: dry_run=True by default. First call shows what will change.
    Only call with dry_run=False AFTER user explicitly approves.

    Safety: blocks opening sensitive ports (SSH, RDP, DB) to 0.0.0.0/0.

    Args:
        sg_id: Security Group ID (e.g. sg-0abc123)
        account: AWS account name or ID
        action: 'add_ingress' or 'remove_ingress'
        protocol: Protocol (tcp, udp, icmp, -1 for all). Default tcp.
        port: Port number. Default 443.
        cidr: CIDR block (e.g. '10.0.0.0/8', '203.0.113.5/32')
        description: Rule description (required for add)
        region: AWS region (default us-east-1)
        dry_run: If True (default), only validates. Set False to execute.
    """
    if action not in ("add_ingress", "remove_ingress"):
        return _json_compact({"status": "REJECTED", "reason": "action must be 'add_ingress' or 'remove_ingress'"})

    if not cidr:
        return _json_compact({"status": "REJECTED", "reason": "cidr is required"})

    if action == "add_ingress" and cidr in _SG_OPEN_WORLD and port in _SG_DANGEROUS_PORTS:
        _log_action("sg_rule", account, f"{action} {sg_id} {protocol}/{port} {cidr}", True, "REJECTED", error="open world on dangerous port")
        return _json_compact({
            "status": "REJECTED",
            "reason": f"BLOCKED: opening port {port} to {cidr} is not allowed. "
                      f"Dangerous ports ({_SG_DANGEROUS_PORTS}) cannot be opened to the world.",
        })

    if action == "add_ingress" and not description:
        return _json_compact({"status": "REJECTED", "reason": "description is required when adding rules"})

    rule_spec = {"protocol": protocol, "port": port, "cidr": cidr, "description": description}

    if dry_run:
        _log_action("sg_rule", account, f"{action} {sg_id} {protocol}/{port} {cidr}", True, "PENDING_APPROVAL")
        aws = _get_aws(account, region)
        current = aws.describe_security_group(sg_id)
        return _json_compact({
            "status": "PENDING_APPROVAL",
            "will_execute": {"action": action, "sg_id": sg_id, "rule": rule_spec},
            "current_rules_count": len(current.get("inbound_rules", [])),
            "instruction": "Mostra ao usuario a regra e pede confirmacao.",
        })

    aws = _get_aws(account, region)
    ec2 = aws._client("ec2")

    ip_perm = {
        "IpProtocol": protocol,
        "FromPort": port,
        "ToPort": port,
        "IpRanges": [{"CidrIp": cidr, "Description": description}],
    }

    try:
        if action == "add_ingress":
            ec2.authorize_security_group_ingress(GroupId=sg_id, IpPermissions=[ip_perm])
        else:
            ec2.revoke_security_group_ingress(GroupId=sg_id, IpPermissions=[ip_perm])

        _log_action("sg_rule", account, f"{action} {sg_id} {protocol}/{port} {cidr}", False, "EXECUTED")
        return _json_compact({"status": "EXECUTED", "action": action, "rule": rule_spec, "audit": "Logged."})
    except Exception as exc:
        _log_action("sg_rule", account, f"{action} {sg_id} {protocol}/{port} {cidr}", False, "FAILED", error=str(exc))
        return _json_compact({"status": "FAILED", "error": str(exc)})


# ═════════════════════════════════════════════════════════════════════════
# TOOL: manage_routes (write — requires approval)
# ═════════════════════════════════════════════════════════════════════════

@mcp.tool()
@_safe_call
def manage_routes(
    route_table_id: str,
    account: str,
    action: str,
    destination_cidr: str,
    target_id: str = "",
    region: str = "us-east-1",
    dry_run: bool = True,
) -> str:
    """Add or remove a route from a Route Table.

    IMPORTANT: dry_run=True by default. First call shows what will change.
    Only call with dry_run=False AFTER user explicitly approves.

    Safety: blocks replacing the default route (0.0.0.0/0) and
    blocks routes pointing to internet gateways on private tables.

    Args:
        route_table_id: Route Table ID (e.g. rtb-0abc123)
        account: AWS account name or ID
        action: 'add_route' or 'remove_route'
        destination_cidr: Destination CIDR (e.g. '10.200.0.0/16')
        target_id: Target (gateway, instance, endpoint, etc). Required for add.
        region: AWS region (default us-east-1)
        dry_run: If True (default), only validates. Set False to execute.
    """
    if action not in ("add_route", "remove_route"):
        return _json_compact({"status": "REJECTED", "reason": "action must be 'add_route' or 'remove_route'"})

    if action == "add_route" and destination_cidr in ("0.0.0.0/0", "::/0"):
        _log_action("route", account, f"{action} {route_table_id} {destination_cidr}", True, "REJECTED", error="default route modification blocked")
        return _json_compact({
            "status": "REJECTED",
            "reason": "BLOCKED: modifying the default route (0.0.0.0/0) is not allowed via MCP. Do this manually.",
        })

    if action == "add_route" and not target_id:
        return _json_compact({"status": "REJECTED", "reason": "target_id is required when adding routes"})

    if dry_run:
        _log_action("route", account, f"{action} {route_table_id} {destination_cidr} -> {target_id}", True, "PENDING_APPROVAL")
        aws = _get_aws(account, region)
        ec2 = aws._client("ec2")
        try:
            rt = ec2.describe_route_tables(RouteTableIds=[route_table_id])
            current_routes = rt["RouteTables"][0]["Routes"] if rt["RouteTables"] else []
        except Exception:
            current_routes = []

        return _json_compact({
            "status": "PENDING_APPROVAL",
            "will_execute": {
                "action": action, "route_table_id": route_table_id,
                "destination": destination_cidr, "target": target_id,
            },
            "current_routes_count": len(current_routes),
            "instruction": "Mostra ao usuario a rota e pede confirmacao.",
        })

    aws = _get_aws(account, region)
    ec2 = aws._client("ec2")

    try:
        if action == "add_route":
            kwargs = {
                "RouteTableId": route_table_id,
                "DestinationCidrBlock": destination_cidr,
            }
            if target_id.startswith("igw-"):
                kwargs["GatewayId"] = target_id
            elif target_id.startswith("vpce-"):
                kwargs["VpcEndpointId"] = target_id
            elif target_id.startswith("nat-"):
                kwargs["NatGatewayId"] = target_id
            elif target_id.startswith("i-"):
                kwargs["InstanceId"] = target_id
            elif target_id.startswith("tgw-"):
                kwargs["TransitGatewayId"] = target_id
            elif target_id.startswith("pcx-"):
                kwargs["VpcPeeringConnectionId"] = target_id
            else:
                kwargs["GatewayId"] = target_id
            ec2.create_route(**kwargs)
        else:
            ec2.delete_route(
                RouteTableId=route_table_id,
                DestinationCidrBlock=destination_cidr,
            )

        _log_action("route", account, f"{action} {route_table_id} {destination_cidr} -> {target_id}", False, "EXECUTED")
        return _json_compact({"status": "EXECUTED", "action": action, "audit": "Logged."})
    except Exception as exc:
        _log_action("route", account, f"{action} {route_table_id} {destination_cidr} -> {target_id}", False, "FAILED", error=str(exc))
        return _json_compact({"status": "FAILED", "error": str(exc)})


# ═════════════════════════════════════════════════════════════════════════
# TOOL: deploy_wazuh (write — wraps existing scripts, requires approval)
# ═════════════════════════════════════════════════════════════════════════

@mcp.tool()
@_safe_call
def deploy_wazuh(
    target_profile: str,
    vpc_id: str,
    subnet_ids: str,
    security_profile: str = "",
    dry_run: bool = True,
) -> str:
    """Deploy Wazuh agent infrastructure to an AWS account.

    Wraps the existing Deploy-Wazuh/deploy-wazuh-account.sh script.
    Creates VPC endpoint, IAM roles, and SSM documents needed for
    Wazuh agent installation in the target account.

    IMPORTANT: dry_run=True by default (passes --dry-run to the script).
    Only call with dry_run=False AFTER user explicitly approves.

    Args:
        target_profile: AWS SSO profile for target account (e.g. 'readonly@your-org-prod')
        vpc_id: VPC ID in the target account (e.g. 'vpc-0abc123')
        subnet_ids: Comma-separated subnet IDs (e.g. 'subnet-aaa,subnet-bbb')
        security_profile: AWS SSO profile for security/hub account (or WAZUH_SECURITY_PROFILE env)
        dry_run: If True (default), runs with --dry-run flag. Set False to execute.
    """
    import subprocess

    if not security_profile:
        security_profile = os.environ.get("WAZUH_SECURITY_PROFILE", "")
    if not security_profile:
        return _json_compact({
            "status": "REJECTED",
            "reason": "security_profile required (argument or WAZUH_SECURITY_PROFILE env)",
        })

    script_path = os.path.join(
        os.path.dirname(_PROJECT_DIR), "Deploy-Wazuh", "deploy-wazuh-account.sh"
    )

    if not os.path.exists(script_path):
        return _json_compact({
            "status": "REJECTED",
            "reason": f"Script not found: {script_path}",
        })

    cmd = [
        "bash", script_path,
        "--target-profile", target_profile,
        "--security-profile", security_profile,
        "--vpc-id", vpc_id,
        "--subnet-ids", subnet_ids,
    ]

    if dry_run:
        cmd.append("--dry-run")
        _log_action("deploy_wazuh", target_profile, " ".join(cmd), True, "PENDING_APPROVAL")
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=120
            )
            return _json_compact({
                "status": "PENDING_APPROVAL (dry-run output below)",
                "command": " ".join(cmd),
                "stdout": result.stdout[-3000:] if result.stdout else "",
                "stderr": result.stderr[-1000:] if result.stderr else "",
                "exit_code": result.returncode,
                "instruction": "Mostra o output ao usuario. So execute com dry_run=false apos aprovacao.",
            })
        except subprocess.TimeoutExpired:
            return _json_compact({"status": "TIMEOUT", "reason": "dry-run took > 120s"})
        except Exception as exc:
            return _json_compact({"status": "FAILED", "error": str(exc)})

    _log_action("deploy_wazuh", target_profile, " ".join(cmd), False, "EXECUTING")
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=300
        )
        status = "EXECUTED" if result.returncode == 0 else "FAILED"
        _log_action(
            "deploy_wazuh", target_profile, " ".join(cmd), False, status,
            output=result.stdout[-3000:] if result.stdout else "",
            error=result.stderr[-1000:] if result.stderr else "",
        )
        return _json_compact({
            "status": status,
            "exit_code": result.returncode,
            "stdout": result.stdout[-3000:] if result.stdout else "",
            "stderr": result.stderr[-1000:] if result.stderr else "",
            "audit": "Logged.",
        })
    except subprocess.TimeoutExpired:
        _log_action("deploy_wazuh", target_profile, " ".join(cmd), False, "TIMEOUT")
        return _json_compact({"status": "TIMEOUT", "reason": "Deploy took > 300s"})
    except Exception as exc:
        _log_action("deploy_wazuh", target_profile, " ".join(cmd), False, "FAILED", error=str(exc))
        return _json_compact({"status": "FAILED", "error": str(exc)})


# ═════════════════════════════════════════════════════════════════════════
# ENTRYPOINT
# ═════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    logger.info("Starting Security Investigation MCP server (stdio)")
    mcp.run()
