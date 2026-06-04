"""Security Posture: 3 pillars of value.

  1. "Estou comprometido?" (Security) — IOCs, threats, suspicious behavior
  2. "Estou desperdicando dinheiro?" (Cost) — CloudTrail waste, idle resources
  3. "Algo pode causar downtime?" (Availability) — expiring certs, full disks, DLQs

If it doesn't answer one of these 3 questions, it doesn't belong here.
"""

from __future__ import annotations

import asyncio
import logging
import time
from concurrent.futures import ThreadPoolExecutor

from tools.splunk_client import SplunkClient
from tools.posture_store import save_snapshot, get_previous_snapshot, compute_delta
from tools.playbook_store import search_playbooks
from tools.aws_helper import load_accounts_config

logger = logging.getLogger(__name__)


def _account_id_to_name(account_id: str) -> str:
    """Resolve AWS account ID to friendly name from accounts.yaml."""
    try:
        cfg = load_accounts_config()
        for name, acct in cfg.get("accounts", {}).items():
            if acct.get("account_id") == account_id:
                return name
    except Exception:
        pass
    return account_id


_SSO_KEYWORDS = [
    "expired", "token", "sso", "unauthorized",
    "credentials", "security token", "access denied",
]

# Service accounts / bots to exclude from anomaly detection.
# These are expected to run 24/7 and should not appear in off-hours alerts.
_SERVICE_ACCOUNTS = [
    "circleci",
    "github-actions",
    "deploy",
    "bot",
    "automation",
    "jenkins",
    "terraform",
    "datadog",
]


def _match_playbooks(findings: list[dict], description_key: str = "rule.description") -> dict[str, dict]:
    """Cross-reference findings with saved playbooks.

    Returns a dict mapping description -> playbook summary for matches found.
    """
    matches: dict[str, dict] = {}
    for finding in findings:
        desc = finding.get(description_key, "")
        if not desc:
            continue
        words = desc.split()
        query_terms = " OR ".join(
            w for w in words if len(w) > 3 and w.isalpha()
        )
        if not query_terms:
            continue
        try:
            hits = search_playbooks(query_terms, limit=1)
            if hits:
                pb = hits[0]
                matches[desc] = {
                    "verdict": pb.get("verdict", "?"),
                    "summary": pb.get("summary", ""),
                    "alert_type": pb.get("alert_type", ""),
                    "created_at": pb.get("created_at", ""),
                }
        except Exception:
            continue
    return matches


def _splunk() -> SplunkClient:
    return SplunkClient()


def _search(query: str, earliest: str = "-24h", max_results: int = 50, timeout: int = 45) -> list[dict]:
    client = _splunk()
    result = client.search(query, earliest=earliest, max_results=max_results, timeout=timeout)
    if "error" in result:
        logger.warning("Splunk query failed: %s", result["error"])
        return []
    return result.get("results", [])


# ═══════════════════════════════════════════════════════════════════════
# AWS COVERAGE: SCP-aware S3 + EKS checks
# ═══════════════════════════════════════════════════════════════════════

def _check_org_scp_s3_block() -> bool:
    """Check if the Organization has an SCP blocking public S3 access.

    Returns True if an SCP exists that denies public S3 operations,
    meaning per-account S3 Public Access Block is redundant.
    """
    from tools.aws_helper import resolve_account

    org_account = None
    from tools.aws_helper import load_accounts_config
    cfg = load_accounts_config()
    for name, acct in cfg.get("accounts", {}).items():
        if acct.get("is_org_master"):
            org_account = acct
            break

    if not org_account:
        return False

    import boto3
    try:
        session = boto3.Session(
            profile_name=org_account["profile"], region_name="us-east-1"
        )
        org_client = session.client("organizations")
        paginator = org_client.get_paginator("list_policies")
        for page in paginator.paginate(Filter="SERVICE_CONTROL_POLICY"):
            for policy in page.get("Policies", []):
                if policy["AwsManaged"]:
                    continue
                detail = org_client.describe_policy(PolicyId=policy["Id"])
                content = detail.get("Policy", {}).get("Content", "")
                content_lower = content.lower()
                if "s3" in content_lower and (
                    "putbucketpolicy" in content_lower
                    or "putpublicaccessblock" in content_lower
                    or "putbucketacl" in content_lower
                    or "publicaccessblock" in content_lower
                ):
                    return True
    except Exception as exc:
        logger.warning("SCP check failed: %s", exc)

    return False


def _check_aws_coverage() -> dict:
    """Check real exposure: S3 (SCP-aware) + EKS public endpoints.

    SSO is already validated by _sso_preflight() before this runs.
    Individual account role failures are tracked but don't block other accounts.
    """
    import boto3
    from tools.aws_helper import AWSHelper, list_account_names, resolve_account

    result: dict = {
        "s3_exposure": [],
        "eks_issues": [],
        "accounts_checked": [],
        "accounts_failed": [],
        "s3_scp_protected": False,
    }

    accounts_to_check: list[tuple[str, dict]] = []
    for acct_name in list_account_names():
        acct = resolve_account(acct_name)
        if not acct or not acct.get("account_id"):
            continue
        if acct.get("is_org_master"):
            continue
        accounts_to_check.append((acct_name, acct))

    if not accounts_to_check:
        return result

    scp_blocks_s3 = _check_org_scp_s3_block()
    result["s3_scp_protected"] = scp_blocks_s3

    for acct_name, acct in accounts_to_check:
        try:
            s = boto3.Session(
                profile_name=acct["profile"], region_name="us-east-1"
            )
            s.client("sts").get_caller_identity()
        except Exception:
            result["accounts_failed"].append(acct_name)
            continue

        result["accounts_checked"].append(acct_name)

        try:
            aws = AWSHelper(acct_name)
        except Exception:
            continue

        if not scp_blocks_s3:
            try:
                s3ctrl = aws._client("s3control")
                try:
                    pab = s3ctrl.get_public_access_block(AccountId=acct["account_id"])
                    cfg = pab.get("PublicAccessBlockConfiguration", {})
                    all_blocked = all([
                        cfg.get("BlockPublicAcls", False),
                        cfg.get("IgnorePublicAcls", False),
                        cfg.get("BlockPublicPolicy", False),
                        cfg.get("RestrictPublicBuckets", False),
                    ])
                    if not all_blocked:
                        result["s3_exposure"].append({
                            "account": acct_name,
                            "issue": "no account-level S3 block + no SCP protection",
                        })
                except Exception as e:
                    if "NoSuchPublicAccessBlockConfiguration" in str(e):
                        result["s3_exposure"].append({
                            "account": acct_name,
                            "issue": "no S3 public access block + no SCP protection",
                        })
            except Exception:
                pass

        for cluster_name in acct.get("eks_clusters", []):
            try:
                eks_info = aws.describe_eks_cluster(cluster_name)
                if eks_info.get("error"):
                    continue
                issues: list[str] = []
                cidrs = eks_info.get("public_access_cidrs", [])
                if eks_info.get("endpoint_public") and "0.0.0.0/0" in cidrs:
                    issues.append("public endpoint open to 0.0.0.0/0")
                missing = eks_info.get("logging_missing", [])
                if "audit" in missing:
                    issues.append("audit logging disabled")
                if issues:
                    result["eks_issues"].append({
                        "account": acct_name,
                        "cluster": cluster_name,
                        "version": eks_info.get("version"),
                        "issues": issues,
                    })
            except Exception:
                pass

    return result


# ═══════════════════════════════════════════════════════════════════════
# POSTURE: collect indicators
# ═══════════════════════════════════════════════════════════════════════

def _sso_preflight() -> dict | None:
    """Quick SSO pre-flight. Returns login instructions if expired, else None.

    All AWS profiles share the same sso_session (access-session).
    One login refreshes credentials for every account.
    """
    import boto3
    import configparser
    import os
    from tools.aws_helper import list_account_names, resolve_account

    accounts_to_check: list[tuple[str, dict]] = []
    for acct_name in list_account_names():
        acct = resolve_account(acct_name)
        if not acct or not acct.get("account_id"):
            continue
        if acct.get("is_org_master"):
            continue
        accounts_to_check.append((acct_name, acct))

    if not accounts_to_check:
        return None

    first_name, first_acct = accounts_to_check[0]
    try:
        session = boto3.Session(
            profile_name=first_acct["profile"], region_name="us-east-1"
        )
        session.client("sts").get_caller_identity()
        return None
    except Exception:
        pass

    sso_session_name = None
    aws_config_path = os.path.expanduser("~/.aws/config")
    try:
        cfg = configparser.ConfigParser()
        cfg.read(aws_config_path)
        profile_section = f"profile {first_acct['profile']}"
        if cfg.has_section(profile_section):
            sso_session_name = cfg.get(profile_section, "sso_session", fallback=None)
    except Exception:
        pass

    if sso_session_name:
        login_cmd = f'aws sso login --sso-session {sso_session_name}'
    else:
        login_cmd = f'aws sso login --profile "{first_acct["profile"]}"'

    total_accounts = len(accounts_to_check)
    return {
        "sso_expired": True,
        "message": (
            f"SSO expirado. As {total_accounts} contas compartilham a mesma "
            f"sessao SSO ({sso_session_name or 'shared'}).\n"
            f"Um unico login renova o acesso a todas:"
        ),
        "login_cmd": login_cmd,
    }


async def get_posture(hours: int = 24) -> dict:
    """Build security posture focused on IOC + exposure.

    All Splunk queries and AWS API calls run in parallel via asyncio
    to avoid MCP stdio timeout (~30-60s).
    """

    _start_time = time.monotonic()

    # ── SSO PRE-FLIGHT: check BEFORE any heavy queries ──────────────
    sso_check = _sso_preflight()
    if sso_check:
        return {
            "sso_blocked": True,
            "sso_info": sso_check,
        }

    earliest = f"-{hours}h"
    report: dict = {}
    loop = asyncio.get_event_loop()
    pool = ThreadPoolExecutor(max_workers=24)

    def _t(fn, *args, **kwargs):
        """Wrap a blocking call for use with asyncio."""
        return loop.run_in_executor(pool, lambda: fn(*args, **kwargs))

    svc_filter = " ".join(
        f'user_name!="{sa}*"' for sa in _SERVICE_ACCOUNTS
    )

    # ── Define AWS async tasks (will run in parallel with Splunk) ─────
    async def _aws_coverage_async():
        try:
            return await _t(_check_aws_coverage)
        except Exception as exc:
            logger.warning("AWS coverage check failed: %s", exc)
            return {"error": str(exc)}

    _POSTURE_ACCOUNTS = [
        "linkedstore", "staging", "networking", "bi",
        "nuvem-envio", "security", "mkt-automation",
    ]

    async def _cost_and_dt_async():
        from tools.aws_helper import AWSHelper, resolve_account as _ra
        cost_data: dict = {}
        dt_data: dict = {}

        def _check_account(acct_name):
            results = {"cost": {}, "dt": {}}
            acct = _ra(acct_name)
            if not acct or not acct.get("account_id"):
                return results
            try:
                aws = AWSHelper(acct_name)
            except Exception:
                return results
            try:
                ebs = aws.get_unattached_ebs_volumes()
                if ebs and not (len(ebs) == 1 and "error" in ebs[0]):
                    results["cost"]["ebs"] = [{**v, "account": acct_name} for v in ebs]
            except Exception:
                pass
            try:
                eips = aws.get_unused_elastic_ips()
                if eips and not (len(eips) == 1 and "error" in eips[0]):
                    results["cost"]["eips"] = [{**e, "account": acct_name} for e in eips]
            except Exception:
                pass
            try:
                certs = aws.get_expiring_certificates(days_threshold=30)
                if certs and not (len(certs) == 1 and "error" in certs[0]):
                    results["dt"]["certs"] = [{**c, "account": acct_name} for c in certs]
            except Exception:
                pass
            try:
                rds = aws.get_rds_storage_risk(threshold_pct=85.0)
                if rds and not (len(rds) == 1 and "error" in rds[0]):
                    results["dt"]["rds"] = [{**r, "account": acct_name} for r in rds]
            except Exception:
                pass
            try:
                dlqs = aws.get_sqs_dlq_activity(min_messages=10)
                if dlqs and not (len(dlqs) == 1 and "error" in dlqs[0]):
                    results["dt"]["dlqs"] = [{**d, "account": acct_name} for d in dlqs]
            except Exception:
                pass
            return results

        tasks = [_t(_check_account, name) for name in _POSTURE_ACCOUNTS]
        results_list = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results_list:
            if isinstance(r, dict):
                for v in r.get("cost", {}).get("ebs", []):
                    cost_data.setdefault("ebs_unattached", []).append(v)
                for v in r.get("cost", {}).get("eips", []):
                    cost_data.setdefault("eips_unused", []).append(v)
                for v in r.get("dt", {}).get("certs", []):
                    dt_data.setdefault("expiring_certs", []).append(v)
                for v in r.get("dt", {}).get("rds", []):
                    dt_data.setdefault("rds_storage_risk", []).append(v)
                for v in r.get("dt", {}).get("dlqs", []):
                    dt_data.setdefault("sqs_dlq", []).append(v)
        return cost_data, dt_data

    # CloudTrail fallback queries (only used if summary index empty)
    async def _ct_fallback_real():
        return await _t(_search,
            'index=aws_cloudtrail errorCode!="" errorCode!="success" '
            'errorCode!="AccessDenied" '
            'errorCode!="Client.UnauthorizedAccess" '
            '| stats count by eventName, errorCode, '
            'userIdentity.arn, recipientAccountId '
            '| where count >= 1000 '
            '| sort -count '
            '| head 10',
            earliest=earliest, max_results=10, timeout=60)

    async def _ct_fallback_volume():
        return await _t(_search,
            'index=aws_cloudtrail errorCode="success" '
            '| stats count by eventName, '
            'userIdentity.arn, recipientAccountId '
            '| where count >= 100000 '
            '| sort -count '
            '| head 10',
            earliest=earliest, max_results=10, timeout=60)

    # ── Launch EVERYTHING in parallel (Splunk + AWS + fallbacks) ──────
    (
        wazuh_behavior,
        wazuh_summary,
        inspector_exploitable,
        inspector_coverage,
        vpn_failures,
        vpn_offhours,
        vpn_host_health,
        vpn_host_errors,
        ct_iam_changes,
        ct_dangerous,
        ct_console_logins,
        ct_real_errors_summary,
        ct_high_volume_summary,
        ct_fallback_real_errors,
        ct_fallback_high_volume,
        splunk_ingestion,
        github_overrides,
        gws_suspicious,
        gws_login_failures,
        aws_cov,
        cost_dt_result,
    ) = await asyncio.gather(
        # Wazuh
        _t(_search,
            'index=wazuh rule.level>=10 '
            'NOT rule.description="CVE-*" '
            'NOT rule.group="vulnerability-detector" '
            '| stats count, dc(agent.name) as agents, max(rule.level) as level, '
            'values(agent.name) as affected_hosts '
            'by rule.description '
            '| sort -level -count '
            '| head 10',
            earliest=earliest, max_results=10),
        _t(_search,
            'index=wazuh rule.level>=10 '
            'NOT rule.description="CVE-*" '
            'NOT rule.group="vulnerability-detector" '
            '| stats count as total_alerts, dc(agent.name) as agents_affected, '
            'max(rule.level) as max_severity',
            earliest=earliest, max_results=1),
        # Inspector
        _t(_search,
            'index=aws_inspector (severity="CRITICAL" OR severity="HIGH") '
            'exploitAvailable="YES" '
            '| stats count, dc(dest) as instances, dc(awsAccountId) as accounts '
            'by title, severity '
            '| sort -severity -count '
            '| head 10',
            earliest=earliest, max_results=10),
        _t(_search,
            'index=aws_inspector '
            '| stats dc(awsAccountId) as accounts_with_inspector, '
            'dc(dest) as total_instances, '
            'values(awsAccountId) as account_ids '
            '| appendcols [search index=wazuh '
            '| stats dc(agent.name) as wazuh_agents]',
            earliest=earliest, max_results=1),
        # VPN
        _t(_search,
            'index=pritunl sourcetype="pritunl:journal" event="*failure*" OR event="*fail*" '
            '| stats count, dc(remote_address) as distinct_ips, '
            'values(remote_address) as ips by user_name '
            '| where count >= 5 '
            '| eval classification=if(distinct_ips>2, "INVESTIGATE - multiple source IPs", '
            '"SUSPECT - likely misconfigured client") '
            '| sort -distinct_ips -count '
            '| head 10',
            earliest=earliest, max_results=10),
        _t(_search,
            f'index=pritunl sourcetype="pritunl:journal" user_name!="" {svc_filter} '
            '| eval hour=strftime(_time, "%H") '
            '| where hour>=0 AND hour<=5 '
            '| stats count, dc(event) as event_types by user_name '
            '| where count >= 10 '
            '| sort -count '
            '| head 5',
            earliest=earliest, max_results=5),
        _t(_search,
            'index=wazuh agent.name="pritunl*" OR agent.name="vpn*" '
            '| stats count as alerts, max(rule.level) as max_level, '
            'latest(rule.description) as last_alert by agent.name '
            '| where max_level >= 7',
            earliest=earliest, max_results=5),
        _t(_search,
            'index=pritunl sourcetype="pritunl" '
            '(error OR critical OR "disk" OR "memory" OR "restart") '
            '| stats count by host, _raw '
            '| where count >= 3 '
            '| sort -count '
            '| head 5',
            earliest=earliest, max_results=5),
        # CloudTrail security (timeout=60s — scan full index)
        _t(_search,
            'index=aws_cloudtrail '
            '(eventName="CreateUser" OR eventName="CreateAccessKey" '
            'OR eventName="AttachUserPolicy" OR eventName="PutUserPolicy" '
            'OR eventName="CreateLoginProfile" OR eventName="AddUserToGroup") '
            'NOT userIdentity.invokedBy="*amazonaws.com" '
            '| stats count by eventName, userIdentity.arn, sourceIPAddress '
            '| sort -count',
            earliest=earliest, max_results=10, timeout=60),
        _t(_search,
            'index=aws_cloudtrail '
            '(eventName="StopLogging" OR eventName="DeleteTrail" '
            'OR eventName="DisableGuardDuty" OR eventName="DeleteDetector" '
            'OR eventName="DisableKey" OR eventName="ScheduleKeyDeletion" '
            'OR eventName="PutBucketPublicAccessBlock" '
            'OR eventName="DeleteBucketPolicy") '
            '| stats count by eventName, userIdentity.arn, sourceIPAddress '
            '| sort -count',
            earliest=earliest, max_results=10, timeout=60),
        _t(_search,
            'index=aws_cloudtrail eventName="ConsoleLogin" '
            'errorMessage="Failed authentication" '
            '| stats count by userIdentity.arn, sourceIPAddress '
            '| where count >= 3 '
            '| sort -count',
            earliest=earliest, max_results=5, timeout=60),
        # CloudTrail cost — from summary index (fast)
        _t(_search,
            'index=security_mcp source=cloudtrail_api_errors '
            '| where errorCode!="success" '
            '| sort -count '
            '| head 10',
            earliest="-25h", max_results=10),
        _t(_search,
            'index=security_mcp source=cloudtrail_api_errors '
            '| where errorCode="success" '
            '| sort -count '
            '| head 10',
            earliest="-25h", max_results=10),
        # CloudTrail fallbacks (run in parallel; used only if summary empty)
        _ct_fallback_real(),
        _ct_fallback_volume(),
        # Splunk ingestion
        _t(_search,
            'index=_internal source=*license_usage.log type=Usage '
            '| stats sum(b) as bytes by idx '
            '| eval GB=round(bytes/1024/1024/1024,2) '
            '| where GB > 0.1 '
            '| sort -GB '
            '| head 10',
            earliest=earliest, max_results=10),
        # GitHub
        _t(_search,
            'index=github_auditlog '
            '(action="protected_branch.policy_override" '
            'OR action="protected_branch.destroy" '
            'OR action="repo.destroy" '
            'OR action="repo.change_visibility") '
            '| stats count by action, actor, repo '
            '| sort -count',
            earliest=earliest, max_results=10),
        # Google Workspace
        _t(_search,
            'index=google_workspace '
            '(event.name="suspicious_login" '
            'OR event.name="account_disabled_password_leak" '
            'OR event.name="gov_attack_warning") '
            '| stats count by event.name, actor.email, ipAddress '
            '| sort -count',
            earliest=earliest, max_results=10),
        _t(_search,
            'index=google_workspace event.name="login_failure" '
            '| stats count, dc(ipAddress) as distinct_ips, '
            'values(ipAddress) as ips by actor.email '
            '| where count >= 10 '
            '| eval classification=if(distinct_ips>2, '
            '"INVESTIGATE - multiple source IPs", '
            '"SUSPECT - single origin, possibly legitimate") '
            '| sort -distinct_ips -count '
            '| head 5',
            earliest=earliest, max_results=5),
        # AWS checks (run in parallel with Splunk!)
        _aws_coverage_async(),
        _cost_and_dt_async(),
    )

    # Use summary data if available, otherwise use pre-fetched fallbacks
    ct_real_errors = ct_real_errors_summary if ct_real_errors_summary else ct_fallback_real_errors
    ct_high_volume = ct_high_volume_summary if ct_high_volume_summary else ct_fallback_high_volume

    # Unpack cost + DT
    cost_data, dt_data = cost_dt_result if isinstance(cost_dt_result, tuple) else ({}, {})

    # ── Assemble results ──────────────────────────────────────────────
    playbook_matches = _match_playbooks(wazuh_behavior)

    report["wazuh"] = {
        "summary": wazuh_summary[0] if wazuh_summary else {},
        "top_rules": wazuh_behavior,
        "playbook_matches": playbook_matches,
    }
    report["inspector"] = {
        "exploitable": inspector_exploitable,
        "coverage": inspector_coverage[0] if inspector_coverage else {},
    }
    report["vpn"] = {
        "connection_failures": vpn_failures,
        "off_hours": vpn_offhours,
        "host_health": vpn_host_health,
        "host_errors": vpn_host_errors,
    }
    report["cloudtrail"] = {
        "iam_changes": ct_iam_changes,
        "dangerous_actions": ct_dangerous,
        "failed_console_logins": ct_console_logins,
        "real_errors": ct_real_errors,
        "high_volume": ct_high_volume,
    }
    report["splunk_ingestion"] = splunk_ingestion
    report["github"] = {"security_events": github_overrides}
    report["google_workspace"] = {
        "suspicious_auth": gws_suspicious,
        "login_failures": gws_login_failures,
    }
    report["aws_coverage"] = aws_cov if isinstance(aws_cov, dict) else {"error": str(aws_cov)}
    report["cost"] = cost_data
    report["dt_risk"] = dt_data

    # ── Delta vs previous snapshot ────────────────────────────────────
    previous = get_previous_snapshot()
    if previous:
        report["_delta"] = compute_delta(report, previous)
    else:
        report["_delta"] = None

    save_snapshot(report, hours)
    pool.shutdown(wait=False)

    report["_elapsed_seconds"] = round(time.monotonic() - _start_time, 1)

    return report


# ═══════════════════════════════════════════════════════════════════════
# FORMAT: concise, actionable output
# ═══════════════════════════════════════════════════════════════════════

def format_posture_text(report: dict) -> str:
    """Format posture as concise, actionable text."""
    lines: list[str] = []

    if report.get("sso_blocked"):
        info = report.get("sso_info", {})
        lines.append("=== AWS SSO EXPIRADO ===\n")
        lines.append(info.get("message", "SSO expirado."))
        lines.append(f"\n  {info.get('login_cmd', '')}")
        lines.append(
            "\nDepois de logar, pede o posture de novo. "
            "Um login cobre todas as contas (sessao SSO compartilhada)."
        )
        return "\n".join(lines)

    lines.append("=== SECURITY POSTURE (IOC + EXPOSURE) ===\n")

    # Wazuh behavior threats (CVEs excluded — Inspector handles those)
    ws = report.get("wazuh", {}).get("summary", {})
    total = int(ws.get("total_alerts", 0))
    if total > 0:
        lines.append("## THREATS (Wazuh behavior, excl. CVEs)")
        lines.append(
            f"  {total} alerts | {ws.get('agents_affected', 0)} agents | "
            f"max severity {ws.get('max_severity', '?')}"
        )
        pb_matches = report.get("wazuh", {}).get("playbook_matches", {})
        for r in report.get("wazuh", {}).get("top_rules", [])[:5]:
            desc = r.get("rule.description", "?")
            hosts_raw = r.get("affected_hosts", "")
            if isinstance(hosts_raw, list):
                hosts_str = ", ".join(hosts_raw[:5])
                if len(hosts_raw) > 5:
                    hosts_str += f" (+{len(hosts_raw) - 5} more)"
            else:
                hosts_str = str(hosts_raw)[:120] if hosts_raw else "?"
            lines.append(
                f"  - [level {r.get('level', '?')}] {desc} "
                f"({r.get('count', 0)}x, {r.get('agents', 0)} agents)"
            )
            lines.append(f"    hosts: {hosts_str}")
            if desc in pb_matches:
                pb = pb_matches[desc]
                verdict = pb["verdict"].upper()
                lines.append(
                    f"    >> PLAYBOOK: ja investigado — veredicto: {verdict}. "
                    f"{pb['summary'][:100]}"
                )
        if pb_matches:
            unmatched = sum(
                1 for r in report.get("wazuh", {}).get("top_rules", [])[:5]
                if r.get("rule.description", "") not in pb_matches
            )
            if unmatched:
                lines.append(
                    f"  ({unmatched} alerta(s) sem playbook — investigue para criar memoria)"
                )
    else:
        lines.append("## THREATS (Wazuh): Nenhum alerta comportamental nivel >= 10.")

    # Inspector exploitable + coverage gap
    expl = report.get("inspector", {}).get("exploitable", [])
    cov_data = report.get("inspector", {}).get("coverage", {})
    insp_accounts = int(cov_data.get("accounts_with_inspector", 0))
    insp_instances = int(cov_data.get("total_instances", 0))
    wazuh_agents = int(cov_data.get("wazuh_agents", 0))
    insp_account_ids = cov_data.get("account_ids", "")

    if expl:
        lines.append(f"\n## EXPLOITABLE VULNS ({len(expl)} findings)")
        for e in expl[:5]:
            lines.append(
                f"  - [{e.get('severity', '?')}] {e.get('title', '?')} "
                f"({e.get('count', 1)}x, {e.get('instances', '?')} instances, "
                f"{e.get('accounts', '?')} accounts)"
            )

    from tools.aws_helper import list_account_names
    total_configured = len(list_account_names())
    if insp_accounts < total_configured:
        lines.append(
            f"  COVERAGE GAP: Inspector ativo em {insp_accounts} de "
            f"{total_configured} contas ({insp_instances} instances). "
            f"{total_configured - insp_accounts} contas SEM vulnerability scanning."
        )
        if insp_account_ids:
            lines.append(f"    Contas com Inspector: {insp_account_ids}")

    # VPN anomalies + host health
    failures = report.get("vpn", {}).get("connection_failures", [])
    offhours = report.get("vpn", {}).get("off_hours", [])
    host_health = report.get("vpn", {}).get("host_health", [])
    host_errors = report.get("vpn", {}).get("host_errors", [])
    if failures or offhours or host_health or host_errors:
        lines.append(f"\n## VPN")
        if failures:
            lines.append(f"  Auth failures (>= 5x):")
            for f in failures[:5]:
                classification = f.get("classification", "SUSPECT")
                distinct = f.get("distinct_ips", 1)
                lines.append(
                    f"    - {f.get('user_name', '?')} ({f.get('count', 0)}x, "
                    f"{distinct} IPs) [{classification}]"
                )
        if offhours:
            lines.append(f"  Off-hours humans (00h-05h, >= 10 events):")
            for o in offhours[:3]:
                lines.append(f"    - {o.get('user_name', '?')} ({o.get('count', 0)} events)")
        if host_health:
            lines.append(f"  Host health alerts:")
            for h in host_health[:3]:
                lines.append(
                    f"    - {h.get('agent.name', '?')}: {h.get('last_alert', '?')} "
                    f"(level {h.get('max_level', '?')})"
                )
        if host_errors:
            lines.append(f"  Pritunl server errors:")
            for e in host_errors[:3]:
                lines.append(f"    - [{e.get('host', '?')}] (x{e.get('count', 1)})")

    # CloudTrail security events
    iam = report.get("cloudtrail", {}).get("iam_changes", [])
    dangerous = report.get("cloudtrail", {}).get("dangerous_actions", [])
    failed_logins = report.get("cloudtrail", {}).get("failed_console_logins", [])
    if iam or dangerous or failed_logins:
        lines.append(f"\n## CLOUD SECURITY (CloudTrail)")
        if dangerous:
            lines.append(f"  DANGEROUS ACTIONS:")
            for d in dangerous[:5]:
                lines.append(
                    f"    - {d.get('eventName', '?')} by {d.get('userIdentity.arn', '?')}"
                )
        if iam:
            lines.append(f"  IAM changes (manual, non-automated):")
            for i in iam[:5]:
                lines.append(
                    f"    - {i.get('eventName', '?')} by {i.get('userIdentity.arn', '?')} "
                    f"from {i.get('sourceIPAddress', '?')}"
                )
        if failed_logins:
            lines.append(f"  Console login failures (>= 3x — investigate):")
            for login in failed_logins[:3]:
                lines.append(
                    f"    - {login.get('userIdentity.arn', '?')} from {login.get('sourceIPAddress', '?')} "
                    f"({login.get('count', 0)}x)"
                )

    # CloudTrail REAL errors (broken automations)
    real_errors = report.get("cloudtrail", {}).get("real_errors", [])
    if real_errors:
        total_errs = sum(int(e.get("count", 0)) for e in real_errors)
        lines.append(
            f"\n## BROKEN AUTOMATIONS (CloudTrail — {total_errs:,} real errors)"
        )
        lines.append(
            "  Actual API errors (not success). Broken references, "
            "missing resources, misconfigs."
        )
        for e in real_errors[:7]:
            count = int(e.get("count", 0))
            acct_id = e.get("recipientAccountId", "?")
            acct_name = _account_id_to_name(acct_id)
            lines.append(
                f"    - {e.get('eventName', '?')} [{e.get('errorCode', '?')}] "
                f"({count:,}x) by {e.get('userIdentity.arn', '?')[:60]} "
                f"in {acct_name} ({acct_id})"
            )

    # CloudTrail high-volume legitimate calls (logging cost)
    high_volume = report.get("cloudtrail", {}).get("high_volume", [])
    if high_volume:
        total_vol = sum(int(e.get("count", 0)) for e in high_volume)
        lines.append(
            f"\n## HIGH-VOLUME LOGGING (CloudTrail — {total_vol:,} calls)"
        )
        lines.append(
            "  Legitimate operations generating excessive CloudTrail/Splunk "
            "volume. Not errors — logging cost."
        )
        for e in high_volume[:5]:
            count = int(e.get("count", 0))
            acct_id = e.get("recipientAccountId", "?")
            acct_name = _account_id_to_name(acct_id)
            error_code = e.get("errorCode", "success")
            lines.append(
                f"    - {e.get('eventName', '?')} "
                f"({count:,}x) by {e.get('userIdentity.arn', '?')[:60]} "
                f"in {acct_name} ({acct_id})"
            )

    # GitHub
    gh = report.get("github", {}).get("security_events", [])
    if gh:
        lines.append(f"\n## CODE (GitHub)")
        for g in gh[:5]:
            lines.append(
                f"  - {g.get('action', '?')} by {g.get('actor', '?')} "
                f"on {g.get('repo', '?')}"
            )

    # Google Workspace
    gws = report.get("google_workspace", {}).get("suspicious_auth", [])
    gws_failures = report.get("google_workspace", {}).get("login_failures", [])
    if gws or gws_failures:
        lines.append(f"\n## IDENTITY (Google Workspace)")
        for g in gws[:3]:
            lines.append(
                f"  - {g.get('event.name', '?')}: {g.get('actor.email', '?')} "
                f"from {g.get('ipAddress', '?')}"
            )
        if gws_failures:
            lines.append(f"  Repeated login failures (>= 10x — investigate):")
            for b in gws_failures[:3]:
                classification = b.get("classification", "SUSPECT")
                distinct = b.get("distinct_ips", 1)
                lines.append(
                    f"    - {b.get('actor.email', '?')} ({b.get('count', 0)}x, "
                    f"{distinct} IPs) [{classification}]"
                )

    # AWS Coverage (SSO already validated in pre-flight)
    cov = report.get("aws_coverage", {})
    if isinstance(cov, dict) and not cov.get("error"):
        s3 = cov.get("s3_exposure", [])
        eks = cov.get("eks_issues", [])
        scp = cov.get("s3_scp_protected", False)
        checked = cov.get("accounts_checked", [])
        failed = cov.get("accounts_failed", [])

        if s3 or eks:
            lines.append(f"\n## AWS EXPOSURE")
            if s3:
                for item in s3:
                    lines.append(f"  - S3 [{item['account']}]: {item['issue']}")
            if eks:
                for item in eks:
                    lines.append(
                        f"  - EKS [{item['account']}] {item['cluster']}: "
                        f"{'; '.join(item.get('issues', []))}"
                    )
        else:
            note = " (S3 protegido por SCP)" if scp else ""
            lines.append(
                f"\n## AWS EXPOSURE: {len(checked)} contas verificadas — "
                f"sem exposicao encontrada{note}"
            )
        if failed:
            lines.append(
                f"  Contas sem acesso (role issue): {', '.join(failed)}"
            )

    # Splunk ingestion (cost visibility)
    ingestion = report.get("splunk_ingestion", [])
    if ingestion:
        total_gb = sum(float(i.get("GB", 0)) for i in ingestion)
        lines.append(f"\n## SPLUNK INGESTION ({total_gb:.1f} GB/dia)")
        for i in ingestion[:5]:
            gb = float(i.get("GB", 0))
            if gb >= 1.0:
                lines.append(f"    - {i.get('idx', '?')}: {gb:.1f} GB")

    # Cost indicators
    cost = report.get("cost", {})
    ebs = cost.get("ebs_unattached", [])
    eips = cost.get("eips_unused", [])
    if ebs or eips:
        lines.append(f"\n## COST WASTE (recursos ociosos)")
        if ebs:
            total_ebs_gb = sum(v.get("size_gb", 0) for v in ebs)
            lines.append(
                f"  EBS volumes sem instancia: {len(ebs)} "
                f"({total_ebs_gb} GB total)"
            )
            for v in ebs[:5]:
                lines.append(
                    f"    - {v.get('volume_id', '?')} ({v.get('size_gb', 0)} GB "
                    f"{v.get('volume_type', '')}) [{v.get('account', '?')}]"
                )
            if len(ebs) > 5:
                lines.append(f"    (+{len(ebs) - 5} mais)")
        if eips:
            lines.append(
                f"  Elastic IPs sem uso: {len(eips)} "
                f"(~${len(eips) * 3.65:.0f}/mes)"
            )
            from collections import Counter
            eip_by_acct = Counter(e.get("account", "?") for e in eips)
            lines.append("    Breakdown por conta:")
            for acct, cnt in eip_by_acct.most_common():
                lines.append(f"    - {acct}: {cnt} EIPs (~${cnt * 3.65:.0f}/mes)")

    # DT risk indicators
    dt = report.get("dt_risk", {})
    certs = dt.get("expiring_certs", [])
    rds = dt.get("rds_storage_risk", [])
    dlqs = dt.get("sqs_dlq", [])
    if certs or rds or dlqs:
        lines.append(f"\n## DOWNTIME RISK")
        if certs:
            lines.append(f"  Certificados expirando (<= 30 dias):")
            for c in certs[:5]:
                lines.append(
                    f"    - {c.get('domain', '?')} ({c.get('days_left', '?')} dias) "
                    f"[{c.get('account', '?')}]"
                )
        if rds:
            lines.append(f"  RDS storage critico (>= 85%):")
            for r in rds[:5]:
                lines.append(
                    f"    - {r.get('db_identifier', '?')} ({r.get('used_pct', '?')}% "
                    f"de {r.get('allocated_gb', '?')} GB) [{r.get('account', '?')}]"
                )
        if dlqs:
            lines.append(f"  SQS dead letter queues com mensagens:")
            for d in dlqs[:5]:
                lines.append(
                    f"    - {d.get('queue_name', '?')} ({d.get('messages', 0)} msgs) "
                    f"[{d.get('account', '?')}]"
                )

    # Delta
    delta = report.get("_delta")
    if delta and delta.get("has_changes"):
        lines.append(f"\n## DELTA (vs ultima execucao)")
        wd = delta.get("wazuh", {})
        if wd.get("alert_delta", 0) != 0:
            sign = "+" if wd["alert_delta"] > 0 else ""
            lines.append(f"  Wazuh: {sign}{wd['alert_delta']} alertas")
        for r in wd.get("new_rules", [])[:3]:
            lines.append(f"    [NOVO] {r}")
        for r in wd.get("resolved_rules", [])[:3]:
            lines.append(f"    [RESOLVIDO] {r}")
        for c in delta.get("inspector", {}).get("new_exploitable", [])[:3]:
            lines.append(f"  [NOVA VULN EXPLORAVEL] {c}")
        for f in delta.get("vpn", {}).get("new_failure_patterns", [])[:3]:
            lines.append(f"  [NOVA FALHA VPN] {f}")
        for e in delta.get("cloudtrail", {}).get("new_error_patterns", [])[:3]:
            lines.append(f"  [NOVO CloudTrail] {e}")
        for e in delta.get("github", {}).get("new_events", [])[:3]:
            lines.append(f"  [NOVO GitHub] {e}")
    elif delta is None:
        lines.append(f"\n## DELTA: Primeira execucao -- sem baseline.")
    else:
        lines.append(f"\n## DELTA: Sem mudancas.")

    elapsed = report.get("_elapsed_seconds")
    if elapsed is not None:
        lines.append(f"\n## PERFORMANCE: Relatorio gerado em {elapsed}s")

    return "\n".join(lines)
