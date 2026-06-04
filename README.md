# Security MCP

> MCP server for security investigation, daily posture, and operational intelligence in Cursor.

| | |
|---|---|
| **Stack** | Python 3.11+, boto3, Splunk REST, SQLite, MCP |
| **Visibility** | Public |
| **Type** | Security automation / IDE integration |

## Overview

Local [Model Context Protocol](https://modelcontextprotocol.io) server that connects Cursor to AWS (via SSO profiles), Splunk Cloud, and on-disk knowledge bases. Supports read-heavy investigation workflows and guarded write operations (dry-run by default).

**Value pillars:** security (threats, IOCs), cost (CloudTrail noise, idle resources, Splunk volume), availability (certs, storage, broken automations).

## Features

- **Investigation** — EC2, GuardDuty, IP, Splunk search, S3/EKS/ECR/WAF checks
- **Posture** — consolidated daily report with delta vs previous run
- **Playbooks** — save and search investigation patterns (FTS5)
- **Detection helpers** — Wazuh/Falco rule templates
- **Controlled writes** — SSM (allowlisted), security groups, routes, Wazuh deploy (`dry_run=true` default)
- **Audit trail** — all write attempts logged to `data/audit.db`

## Architecture

```
Cursor IDE <--stdio--> server.py (MCP) <--> AWS APIs (boto3 / SSO)
                                       <--> Splunk Cloud (REST)
                                       <--> SQLite (playbooks, posture, audit)
```

## Prerequisites

- Python 3.11+
- AWS CLI with SSO profiles in `~/.aws/config`
- Splunk Cloud API token (or service account)
- Cursor with MCP support

## Quick start

```bash
cd security-mcp
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt

cp .env.example .env          # SPLUNK_BASE_URL + SPLUNK_TOKEN
cp config/accounts.yaml.example config/accounts.yaml
```

Add to `~/.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "security": {
      "command": "/absolute/path/to/security-mcp/venv/bin/python",
      "args": ["server.py"],
      "cwd": "/absolute/path/to/security-mcp"
    }
  }
}
```

Reload Cursor, then log in to AWS SSO before using AWS tools:

```bash
aws sso login --profile <your-profile>
```

## Configuration

| File | Purpose |
|------|---------|
| `.env` | Splunk URL/token, optional Slack webhook |
| `config/accounts.yaml` | Account aliases, SSO profiles, account IDs (local only) |
| `config/saved_searches.yaml` | Splunk saved-search templates for summary index |
| `data/*.db` | Playbooks, posture snapshots, audit log (gitignored) |

Optional scheduled posture + Slack:

```bash
python orchestrator.py --slack --hours 24
```

## MCP tools (summary)

| Category | Examples |
|----------|----------|
| Investigation | `security_posture`, `investigate_instance`, `investigate_guardduty`, `search_splunk` |
| Exposure | `check_s3_exposure`, `check_eks_security`, `check_ecr_vulns`, `check_waf_status` |
| Cost / risk | `check_cost_waste`, `check_dt_risk` |
| Knowledge | `save_investigation_playbook`, `find_playbook`, `suggest_detection_rules` |
| Write (guarded) | `ssm_execute`, `manage_security_group`, `deploy_wazuh` |

See tool docstrings in `server.py` for full list.

## Project layout

```
security-mcp/
├── server.py              # MCP entrypoint
├── orchestrator.py        # Scheduled posture + Slack
├── config/
├── tools/                 # AWS, Splunk, posture, stores
├── data/                  # Local DBs (gitignored)
├── SECURITY.md
└── requirements.txt
```

## Security & data handling

- Never commit `.env`, `config/accounts.yaml`, or `data/`.
- Write tools default to **dry-run**; destructive shell patterns are blocked.
- See [SECURITY.md](SECURITY.md).

## Related projects

- [ec2-credential-boundary](https://github.com/GiovanniLatorre/ec2-credential-boundary) — AWS credential boundary pilot (SCP, private)
- [aws-credential-posture](https://github.com/GiovanniLatorre/aws-credential-posture) — org-wide EC2-trust inventory (private)
- [giovanni-portfolio](https://github.com/GiovanniLatorre/giovanni-portfolio) — project index

## License

MIT License — see [LICENSE](LICENSE).
