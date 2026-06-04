"""AWS helper: thin boto3 wrapper scoped to one account via SSO profile.

Reuses patterns from security-n1-bot/playbooks/base.py and
vpn-monitor/collectors/aws_client.py but standalone for MCP use.
"""

from __future__ import annotations

import json
import logging
import os
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import boto3
import yaml

logger = logging.getLogger(__name__)

_CONFIG_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "config", "accounts.yaml")


def load_accounts_config() -> dict:
    with open(_CONFIG_PATH, "r") as fh:
        return yaml.safe_load(fh)


def resolve_account(account_name: str) -> Optional[dict]:
    cfg = load_accounts_config()
    accounts = cfg.get("accounts", {})
    if account_name in accounts:
        acct = dict(accounts[account_name])
        acct.setdefault("name", account_name)
        return acct
    for name, acct in accounts.items():
        if acct.get("account_id") == account_name:
            acct = dict(acct)
            acct.setdefault("name", name)
            return acct
    return None


def list_account_names() -> list[str]:
    cfg = load_accounts_config()
    return list(cfg.get("accounts", {}).keys())


class AWSHelper:
    """Read-only (mostly) boto3 helper scoped to one account + region."""

    def __init__(self, account_name: str, region: str = "us-east-1"):
        acct = resolve_account(account_name)
        if not acct:
            raise ValueError(f"Account '{account_name}' not in config. Available: {list_account_names()}")
        self.account_config = acct
        self.account_name = acct.get("name", account_name)
        self.profile = acct["profile"]
        self.region = region
        self._session = boto3.Session(profile_name=self.profile, region_name=region)
        self._clients: dict[str, Any] = {}

    def _client(self, service: str):
        if service not in self._clients:
            self._clients[service] = self._session.client(service)
        return self._clients[service]

    # ── EC2 ──────────────────────────────────────────────────────────────

    def describe_instance(self, instance_id: str) -> Optional[dict]:
        try:
            resp = self._client("ec2").describe_instances(InstanceIds=[instance_id])
            reservations = resp.get("Reservations", [])
            if reservations and reservations[0].get("Instances"):
                return reservations[0]["Instances"][0]
        except Exception as exc:
            logger.warning("describe_instance %s: %s", instance_id, exc)
        return None

    def get_instance_summary(self, instance_id: str) -> dict:
        inst = self.describe_instance(instance_id)
        if not inst:
            return {"error": f"Instance {instance_id} not found or not accessible"}

        tags = {t["Key"]: t["Value"] for t in inst.get("Tags", [])}
        sgs = [
            {"id": sg["GroupId"], "name": sg["GroupName"]}
            for sg in inst.get("SecurityGroups", [])
        ]
        return {
            "instance_id": instance_id,
            "name": tags.get("Name", ""),
            "state": inst.get("State", {}).get("Name", ""),
            "type": inst.get("InstanceType", ""),
            "platform": inst.get("PlatformDetails", ""),
            "ami": inst.get("ImageId", ""),
            "private_ip": inst.get("PrivateIpAddress", ""),
            "public_ip": inst.get("PublicIpAddress"),
            "vpc_id": inst.get("VpcId", ""),
            "subnet_id": inst.get("SubnetId", ""),
            "iam_profile": inst.get("IamInstanceProfile", {}).get("Arn", ""),
            "launch_time": str(inst.get("LaunchTime", "")),
            "tags": tags,
            "security_groups": sgs,
            "account": self.account_name,
            "region": self.region,
        }

    def describe_security_group(self, sg_id: str) -> dict:
        try:
            resp = self._client("ec2").describe_security_groups(GroupIds=[sg_id])
            groups = resp.get("SecurityGroups", [])
            if not groups:
                return {"error": f"SG {sg_id} not found"}
            sg = groups[0]
            return {
                "group_id": sg["GroupId"],
                "group_name": sg["GroupName"],
                "description": sg.get("Description", ""),
                "vpc_id": sg.get("VpcId", ""),
                "inbound_rules": [
                    {
                        "protocol": r.get("IpProtocol", ""),
                        "from_port": r.get("FromPort"),
                        "to_port": r.get("ToPort"),
                        "sources": [
                            ip.get("CidrIp") or ip.get("Description", "")
                            for ip in r.get("IpRanges", [])
                        ] + [
                            ip.get("CidrIpv6") or ip.get("Description", "")
                            for ip in r.get("Ipv6Ranges", [])
                        ] + [
                            p.get("GroupId", "")
                            for p in r.get("UserIdGroupPairs", [])
                        ],
                    }
                    for r in sg.get("IpPermissions", [])
                ],
            }
        except Exception as exc:
            return {"error": str(exc)}

    # ── GuardDuty ────────────────────────────────────────────────────────

    def get_guardduty_finding(self, finding_id: str) -> Optional[dict]:
        detector_id = self.account_config.get("guardduty_detector")
        if not detector_id:
            return None
        resp = self._client("guardduty").get_findings(
            DetectorId=detector_id, FindingIds=[finding_id]
        )
        findings = resp.get("Findings", [])
        return findings[0] if findings else None

    def list_guardduty_findings(
        self,
        instance_id: Optional[str] = None,
        max_results: int = 20,
    ) -> list[dict]:
        detector_id = self.account_config.get("guardduty_detector")
        if not detector_id:
            return []
        gd = self._client("guardduty")
        criterion: dict = {}
        if instance_id:
            criterion["resource.instanceDetails.instanceId"] = {"Eq": [instance_id]}

        resp = gd.list_findings(
            DetectorId=detector_id,
            FindingCriteria={"Criterion": criterion} if criterion else {},
            SortCriteria={"AttributeName": "updatedAt", "OrderBy": "DESC"},
            MaxResults=max_results,
        )
        finding_ids = resp.get("FindingIds", [])
        if not finding_ids:
            return []
        resp2 = gd.get_findings(DetectorId=detector_id, FindingIds=finding_ids)
        findings = resp2.get("Findings", [])

        return [
            {
                "finding_id": f["Id"],
                "type": f["Type"],
                "severity": f["Severity"],
                "title": f.get("Title", ""),
                "description": f.get("Description", ""),
                "first_seen": f.get("Service", {}).get("EventFirstSeen", ""),
                "last_seen": f.get("Service", {}).get("EventLastSeen", ""),
                "count": f.get("Service", {}).get("Count", 1),
                "resource": _extract_resource_info(f),
                "action": _extract_action_info(f),
            }
            for f in findings
        ]

    # ── CloudWatch Logs ──────────────────────────────────────────────────

    def query_cloudwatch_logs(
        self,
        log_group: str,
        filter_pattern: str,
        hours_back: int = 1,
        limit: int = 50,
    ) -> list[str]:
        now = datetime.now(timezone.utc)
        start_ms = int((now - timedelta(hours=hours_back)).timestamp() * 1000)
        end_ms = int(now.timestamp() * 1000)
        try:
            resp = self._client("logs").filter_log_events(
                logGroupName=log_group,
                startTime=start_ms,
                endTime=end_ms,
                filterPattern=filter_pattern,
                limit=limit,
            )
            return [e.get("message", "") for e in resp.get("events", [])]
        except Exception as exc:
            return [f"Error querying {log_group}: {exc}"]

    def get_lambda_errors(
        self,
        function_name: str,
        hours_back: int = 6,
        limit: int = 30,
    ) -> list[str]:
        log_group = f"/aws/lambda/{function_name}"
        return self.query_cloudwatch_logs(log_group, "ERROR", hours_back, limit)

    # ── DNS Logs (Route53) ───────────────────────────────────────────────

    def query_dns_logs(
        self,
        filter_pattern: str,
        hours_back: int = 1,
        limit: int = 100,
    ) -> list[dict]:
        log_group = self.account_config.get("dns_log_group")
        if not log_group:
            return []
        now = datetime.now(timezone.utc)
        start_ms = int((now - timedelta(hours=hours_back)).timestamp() * 1000)
        end_ms = int(now.timestamp() * 1000)
        try:
            resp = self._client("logs").filter_log_events(
                logGroupName=log_group,
                startTime=start_ms,
                endTime=end_ms,
                filterPattern=filter_pattern,
                limit=limit,
            )
            results = []
            for event in resp.get("events", []):
                try:
                    results.append(json.loads(event["message"]))
                except json.JSONDecodeError:
                    results.append({"raw": event["message"]})
            return results
        except Exception as exc:
            return [{"error": str(exc)}]

    # ── SSM ──────────────────────────────────────────────────────────────

    def ssm_run_command(
        self,
        instance_id: str,
        command: str,
        timeout_sec: int = 30,
    ) -> dict:
        try:
            ssm = self._client("ssm")
            resp = ssm.send_command(
                InstanceIds=[instance_id],
                DocumentName="AWS-RunShellScript",
                Parameters={"commands": [command]},
            )
            command_id = resp["Command"]["CommandId"]

            elapsed = 0
            poll_interval = 3
            result = None
            while elapsed < timeout_sec:
                time.sleep(poll_interval)
                elapsed += poll_interval
                result = ssm.get_command_invocation(
                    CommandId=command_id, InstanceId=instance_id
                )
                if result["Status"] in ("Success", "Failed", "Cancelled", "TimedOut"):
                    break

            if result is None:
                return {"status": "error", "output": "No response from SSM"}

            return {
                "status": result["Status"].lower(),
                "output": result.get("StandardOutputContent", ""),
                "stderr": result.get("StandardErrorContent", ""),
            }
        except Exception as exc:
            return {"status": "error", "output": str(exc)}

    def check_wazuh_status(self, instance_id: str) -> dict:
        result = self.ssm_run_command(
            instance_id,
            "/var/ossec/bin/wazuh-control status 2>/dev/null || echo 'NOT_INSTALLED'",
        )
        if result["status"] != "success":
            return {"installed": False, "running": False, "error": result.get("output", "")}

        output = result["output"]
        installed = "NOT_INSTALLED" not in output
        running = "wazuh-agentd is running" in output

        return {
            "installed": installed,
            "running": running,
            "details": output.strip(),
        }

    def identify_vpn_user(self, instance_id: str, client_ip: str) -> Optional[dict]:
        result = self.ssm_run_command(
            instance_id,
            f'grep -r "{client_ip}" /var/log/pritunl_journal.log* 2>/dev/null | grep user_connect | tail -5',
        )
        if result["status"] != "success" or not result["output"].strip():
            subnet = ".".join(client_ip.split(".")[:3])
            result = self.ssm_run_command(
                instance_id,
                f'grep -r "{subnet}" /var/log/pritunl_journal.log* 2>/dev/null | grep user_connect | tail -20',
            )
            if result["status"] != "success" or not result["output"].strip():
                return None

        for line in result["output"].strip().split("\n"):
            if client_ip not in line:
                continue
            try:
                json_start = line.index("{")
                data = json.loads(line[json_start:])
                return {
                    "user_name": data.get("user_name"),
                    "user_email": data.get("user_email", data.get("user_name")),
                    "platform": data.get("platform"),
                    "device_name": data.get("device_name"),
                    "real_address": data.get("real_address"),
                    "virt_address": data.get("virt_address"),
                    "server_name": data.get("server_name"),
                }
            except (json.JSONDecodeError, ValueError):
                continue
        return None

    # ── CloudTrail ───────────────────────────────────────────────────────

    def lookup_cloudtrail_events(
        self,
        attribute_key: str,
        attribute_value: str,
        hours_back: int = 24,
        max_results: int = 20,
    ) -> list[dict]:
        now = datetime.now(timezone.utc)
        start = now - timedelta(hours=hours_back)
        try:
            resp = self._client("cloudtrail").lookup_events(
                LookupAttributes=[
                    {"AttributeKey": attribute_key, "AttributeValue": attribute_value}
                ],
                StartTime=start,
                EndTime=now,
                MaxResults=max_results,
            )
            results = []
            for event in resp.get("Events", []):
                detail = json.loads(event.get("CloudTrailEvent", "{}"))
                results.append({
                    "time": str(event.get("EventTime", "")),
                    "name": event.get("EventName", ""),
                    "username": event.get("Username", ""),
                    "source_ip": detail.get("sourceIPAddress", ""),
                    "user_agent": detail.get("userAgent", ""),
                    "error": detail.get("errorCode", ""),
                })
            return results
        except Exception as exc:
            return [{"error": str(exc)}]

    # ── S3 Exposure ─────────────────────────────────────────────────────

    def check_s3_exposure(self) -> dict:
        """Check account-level S3 public access block + find exposed buckets."""
        account_id = self.account_config.get("account_id")
        result: dict = {"account": self.account_name, "buckets_checked": 0}

        if account_id:
            try:
                s3ctrl = self._client("s3control")
                pab = s3ctrl.get_public_access_block(AccountId=account_id)
                cfg = pab.get("PublicAccessBlockConfiguration", {})
                result["account_level_block"] = {
                    "block_public_acls": cfg.get("BlockPublicAcls", False),
                    "ignore_public_acls": cfg.get("IgnorePublicAcls", False),
                    "block_public_policy": cfg.get("BlockPublicPolicy", False),
                    "restrict_public_buckets": cfg.get("RestrictPublicBuckets", False),
                }
                all_blocked = all(result["account_level_block"].values())
                result["account_fully_blocked"] = all_blocked
                if all_blocked:
                    return result
            except Exception as exc:
                result["account_level_block"] = {"error": str(exc)}

        s3 = self._client("s3")
        try:
            buckets = s3.list_buckets().get("Buckets", [])
        except Exception as exc:
            result["error"] = str(exc)
            return result

        exposed: list[dict] = []
        for bucket in buckets[:100]:
            name = bucket["Name"]
            result["buckets_checked"] += 1
            try:
                pab_resp = s3.get_public_access_block(Bucket=name)
                cfg = pab_resp.get("PublicAccessBlockConfiguration", {})
                if all([
                    cfg.get("BlockPublicAcls", False),
                    cfg.get("IgnorePublicAcls", False),
                    cfg.get("BlockPublicPolicy", False),
                    cfg.get("RestrictPublicBuckets", False),
                ]):
                    continue
            except s3.exceptions.ClientError as e:
                if "NoSuchPublicAccessBlockConfiguration" not in str(e):
                    continue

            is_public = False
            try:
                status = s3.get_bucket_policy_status(Bucket=name)
                is_public = status.get("PolicyStatus", {}).get("IsPublic", False)
            except Exception:
                pass

            exposed.append({
                "bucket": name,
                "is_public_policy": is_public,
            })

        result["exposed_buckets"] = exposed
        return result

    # ── EKS ──────────────────────────────────────────────────────────────

    def describe_eks_cluster(self, cluster_name: str) -> dict:
        """Get EKS cluster security-relevant info."""
        try:
            eks = self._client("eks")
            cluster = eks.describe_cluster(name=cluster_name).get("cluster", {})
            vpc_cfg = cluster.get("resourcesVpcConfig", {})
            logging_types = []
            for log in cluster.get("logging", {}).get("clusterLogging", []):
                if log.get("enabled"):
                    logging_types.extend(log.get("types", []))

            return {
                "name": cluster.get("name"),
                "version": cluster.get("version"),
                "status": cluster.get("status"),
                "endpoint_public": vpc_cfg.get("endpointPublicAccess"),
                "endpoint_private": vpc_cfg.get("endpointPrivateAccess"),
                "public_access_cidrs": vpc_cfg.get("publicAccessCidrs", []),
                "security_groups": vpc_cfg.get("securityGroupIds", []),
                "logging_enabled": logging_types,
                "logging_missing": [
                    t for t in ["api", "audit", "authenticator", "controllerManager", "scheduler"]
                    if t not in logging_types
                ],
                "encryption": bool(cluster.get("encryptionConfig")),
                "platform_version": cluster.get("platformVersion"),
                "account": self.account_name,
                "region": self.region,
            }
        except Exception as exc:
            return {"error": str(exc)}

    def list_eks_clusters(self) -> list[str]:
        """List EKS cluster names in the account."""
        try:
            return self._client("eks").list_clusters().get("clusters", [])
        except Exception as exc:
            logger.warning("list_eks_clusters: %s", exc)
            return []

    # ── ECR ──────────────────────────────────────────────────────────────

    def get_ecr_critical_findings(self, max_repos: int = 30) -> dict:
        """Get critical/high ECR image scan findings."""
        ecr = self._client("ecr")
        result: dict = {"account": self.account_name, "repos_checked": 0, "vulnerable_images": []}

        try:
            repos = ecr.describe_repositories(maxResults=max_repos).get("repositories", [])
        except Exception as exc:
            result["error"] = str(exc)
            return result

        for repo in repos:
            repo_name = repo["repositoryName"]
            result["repos_checked"] += 1
            try:
                images = ecr.describe_images(
                    repositoryName=repo_name,
                    filter={"tagStatus": "TAGGED"},
                    maxResults=5,
                ).get("imageDetails", [])

                for img in images:
                    scan = img.get("imageScanFindingsSummary", {})
                    counts = scan.get("findingSeverityCounts", {})
                    crit = counts.get("CRITICAL", 0)
                    high = counts.get("HIGH", 0)
                    if crit > 0 or high > 0:
                        tags = img.get("imageTags", ["untagged"])
                        result["vulnerable_images"].append({
                            "repo": repo_name,
                            "tag": tags[0] if tags else "untagged",
                            "critical": crit,
                            "high": high,
                            "medium": counts.get("MEDIUM", 0),
                            "scan_date": str(scan.get("imageScanCompletedAt", "")),
                        })
            except Exception:
                continue

        return result

    # ── WAF ──────────────────────────────────────────────────────────────

    def list_waf_acls(self) -> list[dict]:
        """List WAFv2 Web ACLs."""
        waf = self._session.client("wafv2", region_name=self.region)
        acls: list[dict] = []
        try:
            resp = waf.list_web_acls(Scope="REGIONAL")
            for acl in resp.get("WebACLs", []):
                detail = waf.get_web_acl(
                    Name=acl["Name"], Scope="REGIONAL", Id=acl["Id"]
                ).get("WebACL", {})
                rules = [r.get("Name", "") for r in detail.get("Rules", [])]
                acls.append({
                    "name": acl["Name"],
                    "id": acl["Id"],
                    "rules_count": len(rules),
                    "rules": rules[:10],
                    "default_action": list(detail.get("DefaultAction", {}).keys()),
                })
        except Exception as exc:
            return [{"error": str(exc)}]
        return acls

    def get_waf_sampled_requests(self, web_acl_arn: str, max_items: int = 20) -> list[dict]:
        """Get recent sampled requests from a WAF ACL (blocked requests)."""
        waf = self._session.client("wafv2", region_name=self.region)
        from datetime import datetime, timedelta, timezone as tz
        now = datetime.now(tz.utc)
        start = now - timedelta(hours=3)

        try:
            resp = waf.get_sampled_requests(
                WebAclArn=web_acl_arn,
                RuleMetricName="ALL",
                Scope="REGIONAL",
                TimeWindow={"StartTime": start, "EndTime": now},
                MaxItems=max_items,
            )
            samples: list[dict] = []
            for req in resp.get("SampledRequests", []):
                r = req.get("Request", {})
                samples.append({
                    "timestamp": str(req.get("Timestamp", "")),
                    "action": req.get("Action", ""),
                    "source_ip": r.get("ClientIP", ""),
                    "country": r.get("Country", ""),
                    "uri": r.get("URI", ""),
                    "method": r.get("Method", ""),
                    "rule": req.get("RuleNameWithinRuleGroup", ""),
                })
            return samples
        except Exception as exc:
            return [{"error": str(exc)}]

    # ── ELBv2 (ALB) ─────────────────────────────────────────────────────

    def describe_alb(self, alb_arn_or_name: str) -> dict:
        try:
            elbv2 = self._client("elbv2")
            if alb_arn_or_name.startswith("arn:"):
                resp = elbv2.describe_load_balancers(LoadBalancerArns=[alb_arn_or_name])
            else:
                resp = elbv2.describe_load_balancers(Names=[alb_arn_or_name])
            lbs = resp.get("LoadBalancers", [])
            if not lbs:
                return {"error": f"ALB '{alb_arn_or_name}' not found"}

            lb = lbs[0]
            arn = lb["LoadBalancerArn"]

            listeners_resp = elbv2.describe_listeners(LoadBalancerArn=arn)
            listeners = [
                {
                    "port": l["Port"],
                    "protocol": l["Protocol"],
                    "default_action": l["DefaultActions"][0]["Type"] if l.get("DefaultActions") else "",
                }
                for l in listeners_resp.get("Listeners", [])
            ]

            sg_ids = lb.get("SecurityGroups", [])
            sg_details = []
            if sg_ids:
                sg_resp = self._client("ec2").describe_security_groups(GroupIds=sg_ids)
                for sg in sg_resp.get("SecurityGroups", []):
                    sources = []
                    for rule in sg.get("IpPermissions", []):
                        for ip_range in rule.get("IpRanges", []):
                            sources.append(ip_range.get("CidrIp", ""))
                    sg_details.append({
                        "id": sg["GroupId"],
                        "name": sg["GroupName"],
                        "inbound_sources": sources,
                    })

            waf_arn = None
            try:
                waf = self._session.client("wafv2", region_name=self.region)
                waf_resp = waf.get_web_acl_for_resource(ResourceArn=arn)
                waf_arn = waf_resp.get("WebACL", {}).get("ARN")
            except Exception:
                pass

            return {
                "name": lb["LoadBalancerName"],
                "arn": arn,
                "scheme": lb.get("Scheme", ""),
                "type": lb.get("Type", ""),
                "state": lb.get("State", {}).get("Code", ""),
                "dns_name": lb.get("DNSName", ""),
                "vpc_id": lb.get("VpcId", ""),
                "availability_zones": [
                    az.get("ZoneName", "") for az in lb.get("AvailabilityZones", [])
                ],
                "security_groups": sg_details,
                "listeners": listeners,
                "waf_arn": waf_arn,
                "has_waf": waf_arn is not None,
                "account": self.account_name,
                "region": self.region,
            }
        except Exception as exc:
            return {"error": str(exc)}

    # ── Lambda ───────────────────────────────────────────────────────────

    def describe_lambda(self, function_name: str) -> dict:
        try:
            resp = self._client("lambda").get_function(FunctionName=function_name)
            config = resp.get("Configuration", {})
            return {
                "function_name": config.get("FunctionName", ""),
                "runtime": config.get("Runtime", ""),
                "handler": config.get("Handler", ""),
                "role": config.get("Role", ""),
                "memory": config.get("MemorySize"),
                "timeout": config.get("Timeout"),
                "last_modified": config.get("LastModified", ""),
                "state": config.get("State", ""),
                "description": config.get("Description", ""),
                "layers": [
                    layer["Arn"] for layer in config.get("Layers", [])
                ],
            }
        except Exception as exc:
            return {"error": str(exc)}

    # ── Cost indicators (Phase 3.2) ─────────────────────────────────────

    def get_idle_ec2_instances(self, cpu_threshold: float = 5.0, days: int = 7) -> list[dict]:
        """Find EC2 instances with avg CPU below threshold over N days."""
        try:
            ec2 = self._client("ec2")
            cw = self._client("cloudwatch")
            instances = []
            paginator = ec2.get_paginator("describe_instances")
            for page in paginator.paginate(Filters=[{"Name": "instance-state-name", "Values": ["running"]}]):
                for res in page.get("Reservations", []):
                    for inst in res.get("Instances", []):
                        instances.append(inst)

            idle = []
            now = datetime.now(timezone.utc)
            start = now - timedelta(days=days)

            for inst in instances[:100]:  # cap to avoid API throttling
                inst_id = inst["InstanceId"]
                try:
                    resp = cw.get_metric_statistics(
                        Namespace="AWS/EC2",
                        MetricName="CPUUtilization",
                        Dimensions=[{"Name": "InstanceId", "Value": inst_id}],
                        StartTime=start,
                        EndTime=now,
                        Period=86400,
                        Statistics=["Average"],
                    )
                    datapoints = resp.get("Datapoints", [])
                    if datapoints:
                        avg_cpu = sum(d["Average"] for d in datapoints) / len(datapoints)
                        if avg_cpu < cpu_threshold:
                            name = ""
                            for tag in inst.get("Tags", []):
                                if tag["Key"] == "Name":
                                    name = tag["Value"]
                            idle.append({
                                "instance_id": inst_id,
                                "name": name,
                                "type": inst.get("InstanceType", ""),
                                "avg_cpu": round(avg_cpu, 2),
                                "days_checked": days,
                            })
                except Exception:
                    continue
            return idle
        except Exception as exc:
            return [{"error": str(exc)}]

    def get_unattached_ebs_volumes(self) -> list[dict]:
        """Find EBS volumes not attached to any instance."""
        try:
            ec2 = self._client("ec2")
            volumes = []
            paginator = ec2.get_paginator("describe_volumes")
            for page in paginator.paginate(Filters=[{"Name": "status", "Values": ["available"]}]):
                for vol in page.get("Volumes", []):
                    name = ""
                    for tag in vol.get("Tags", []):
                        if tag["Key"] == "Name":
                            name = tag["Value"]
                    volumes.append({
                        "volume_id": vol["VolumeId"],
                        "name": name,
                        "size_gb": vol.get("Size", 0),
                        "volume_type": vol.get("VolumeType", ""),
                        "created": str(vol.get("CreateTime", "")),
                    })
            return volumes
        except Exception as exc:
            return [{"error": str(exc)}]

    def get_unused_elastic_ips(self) -> list[dict]:
        """Find Elastic IPs not associated to any resource (cost: ~$3.65/month each).

        An EIP is unused if it has no AssociationId — meaning it's not attached
        to any instance, NAT Gateway, NLB, or network interface.
        """
        try:
            ec2 = self._client("ec2")
            resp = ec2.describe_addresses()
            unused = []
            for addr in resp.get("Addresses", []):
                if not addr.get("AssociationId"):
                    unused.append({
                        "public_ip": addr.get("PublicIp", ""),
                        "allocation_id": addr.get("AllocationId", ""),
                        "domain": addr.get("Domain", ""),
                    })
            return unused
        except Exception as exc:
            return [{"error": str(exc)}]

    # ── Downtime risk indicators (Phase 3.3) ───────────────────────────

    def get_expiring_certificates(self, days_threshold: int = 30) -> list[dict]:
        """Find ACM certificates expiring within N days."""
        try:
            acm = self._client("acm")
            certs = []
            paginator = acm.get_paginator("list_certificates")
            now = datetime.now(timezone.utc)
            for page in paginator.paginate(CertificateStatuses=["ISSUED"]):
                for cert in page.get("CertificateSummaryList", []):
                    not_after = cert.get("NotAfter")
                    if not_after:
                        days_left = (not_after - now).days
                        if days_left <= days_threshold:
                            certs.append({
                                "domain": cert.get("DomainName", ""),
                                "arn": cert.get("CertificateArn", ""),
                                "expires": str(not_after),
                                "days_left": days_left,
                                "type": cert.get("Type", ""),
                            })
            return sorted(certs, key=lambda c: c["days_left"])
        except Exception as exc:
            return [{"error": str(exc)}]

    def get_rds_storage_risk(self, threshold_pct: float = 85.0) -> list[dict]:
        """Find RDS instances with storage usage above threshold."""
        try:
            rds = self._client("rds")
            cw = self._client("cloudwatch")
            at_risk = []
            paginator = rds.get_paginator("describe_db_instances")
            for page in paginator.paginate():
                for db in page.get("DBInstances", []):
                    db_id = db["DBInstanceIdentifier"]
                    allocated = db.get("AllocatedStorage", 0)
                    if allocated == 0:
                        continue
                    try:
                        resp = cw.get_metric_statistics(
                            Namespace="AWS/RDS",
                            MetricName="FreeStorageSpace",
                            Dimensions=[{"Name": "DBInstanceIdentifier", "Value": db_id}],
                            StartTime=datetime.now(timezone.utc) - timedelta(hours=6),
                            EndTime=datetime.now(timezone.utc),
                            Period=3600,
                            Statistics=["Average"],
                        )
                        datapoints = resp.get("Datapoints", [])
                        if datapoints:
                            free_bytes = datapoints[-1]["Average"]
                            free_gb = free_bytes / (1024**3)
                            used_pct = round((1 - free_gb / allocated) * 100, 1)
                            if used_pct >= threshold_pct:
                                at_risk.append({
                                    "db_identifier": db_id,
                                    "engine": db.get("Engine", ""),
                                    "allocated_gb": allocated,
                                    "used_pct": used_pct,
                                    "free_gb": round(free_gb, 2),
                                    "status": db.get("DBInstanceStatus", ""),
                                })
                    except Exception:
                        continue
            return sorted(at_risk, key=lambda d: d["used_pct"], reverse=True)
        except Exception as exc:
            return [{"error": str(exc)}]

    def get_sqs_dlq_activity(self, min_messages: int = 10) -> list[dict]:
        """Find SQS dead letter queues with messages (failed processing)."""
        try:
            sqs = self._client("sqs")
            resp = sqs.list_queues()
            dlqs = []
            for url in resp.get("QueueUrls", []):
                if "dlq" in url.lower() or "dead" in url.lower():
                    try:
                        attrs = sqs.get_queue_attributes(
                            QueueUrl=url,
                            AttributeNames=["ApproximateNumberOfMessages", "QueueArn"],
                        ).get("Attributes", {})
                        msg_count = int(attrs.get("ApproximateNumberOfMessages", 0))
                        if msg_count >= min_messages:
                            dlqs.append({
                                "queue_url": url,
                                "queue_name": url.split("/")[-1],
                                "messages": msg_count,
                                "arn": attrs.get("QueueArn", ""),
                            })
                    except Exception:
                        continue
            return sorted(dlqs, key=lambda d: d["messages"], reverse=True)
        except Exception as exc:
            return [{"error": str(exc)}]


def _extract_resource_info(finding: dict) -> dict:
    resource = finding.get("Resource", {})
    result: dict = {"type": resource.get("ResourceType", "")}
    instance = resource.get("InstanceDetails", {})
    if instance:
        tags = {t["Key"]: t["Value"] for t in instance.get("Tags", [])}
        result["instance_id"] = instance.get("InstanceId", "")
        result["instance_name"] = tags.get("Name", "")
        result["instance_type"] = instance.get("InstanceType", "")
    return result


def _extract_action_info(finding: dict) -> dict:
    service = finding.get("Service", {})
    action = service.get("Action", {})
    action_type = action.get("ActionType", "")
    result: dict = {"type": action_type}

    if action_type == "DNS_REQUEST":
        dns = action.get("DnsRequestAction", {})
        result["domain"] = dns.get("Domain", "")
        result["protocol"] = dns.get("Protocol", "")

    elif action_type == "NETWORK_CONNECTION":
        conn = action.get("NetworkConnectionAction", {})
        result["direction"] = conn.get("ConnectionDirection", "")
        remote = conn.get("RemoteIpDetails", {})
        result["remote_ip"] = remote.get("IpAddressV4", "")
        result["remote_org"] = remote.get("Organization", {}).get("Org", "")

    return result
