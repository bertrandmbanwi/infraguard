# infraguard

[![CI](https://github.com/bertrandmbanwi/infraguard/actions/workflows/ci.yml/badge.svg)](https://github.com/bertrandmbanwi/infraguard/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**Infrastructure guardrails for teams that ship fast.**

Three tools in one CLI — score Terraform plan risk, audit AWS resource tags, and analyze IAM policies for least-privilege violations. Zero-config defaults, CI-ready exit codes, and multiple output formats.

```
infraguard
├── plan-risk    Terraform plan blast radius scorer
├── tag-audit    AWS resource tag compliance checker
└── iam-check    IAM policy least-privilege analyzer
```

## Install

```bash
pip install infraguard

# With AWS support (boto3) for live scanning:
pip install 'infraguard[aws]'
```

## Quick Start

### Score a Terraform plan

```bash
# Generate plan JSON, then score it
terraform plan -out=tfplan && terraform show -json tfplan > plan.json

# Score the plan — block if risk exceeds threshold
infraguard plan-risk -f plan.json --threshold 50
```

```
╭────────────────────────────╮
│ Terraform Plan Risk Report │
╰────────────────────────────╯

  Resource                          Action    Criticality  Score
  aws_db_instance.prod_main         delete    CRITICAL       100
  aws_ecs_service.api               replace   HIGH            28
  aws_security_group.web            update    MEDIUM           8
  aws_cloudwatch_log_group.app      create    LOW              2

  Total Risk Score: 138
  Highest Risk: aws_db_instance.prod_main (delete CRITICAL resource)
  Verdict: BLOCK — score 138 exceeds threshold (50)
```

### Audit AWS resource tags

```bash
# Live scan (uses AWS credentials from environment)
infraguard tag-audit --services ec2,rds,s3 --profile production

# Offline mode with custom tag policy
infraguard tag-audit -f resources.json --rules tag_policy.yaml --min-compliance 95
```

### Analyze IAM policies

```bash
# Check a policy file for least-privilege violations
infraguard iam-check -f policy.json

# Gate CI on severity thresholds
infraguard iam-check -f policy.json --max-findings critical:0,high:3
```

## How It Works

### plan-risk — Scoring Model

Each Terraform resource change is scored by:

```
risk_score = action_weight × resource_criticality × environment_multiplier
```

| Factor | Values |
|--------|--------|
| **Action** | delete (5), replace (4), update (2), create (1) |
| **Criticality** | CRITICAL (10), HIGH (7), MEDIUM (4), LOW (2), INFO (1) |
| **Environment** | prod (2.0x), staging (1.5x), dev/test (1.0x) |

Resource types are pre-classified: databases and IAM roles are CRITICAL, load balancers and clusters are HIGH, compute instances are MEDIUM. Environment is auto-detected from resource addresses (e.g. `aws_db_instance.prod_main` → 2.0x multiplier).

### tag-audit — Compliance Checks

Evaluates resources against configurable tag policies:

- **Required tags** — flag missing tags (e.g. Environment, Team, Service)
- **Allowed values** — enforce valid values (e.g. Environment must be production|staging|development)
- **Pattern matching** — validate tag formats (e.g. CostCenter must match `^CC-\d{4}$`)
- **Naming conventions** — catch prohibited prefixes (`aws:`, `temp_`) and empty values
- **Resource overrides** — require extra tags per resource type (e.g. S3 buckets need DataClassification)

### iam-check — Security Checks

Evaluates IAM policies for common least-privilege violations:

| Check | Severity | Example |
|-------|----------|---------|
| Full admin access (`*:*`) | CRITICAL | `{"Action": "*", "Resource": "*"}` |
| Wildcard service actions | HIGH/MEDIUM | `"Action": "s3:*"` |
| Dangerous individual actions | HIGH | `iam:AttachRolePolicy`, `cloudtrail:DeleteTrail` |
| Wildcard resources on sensitive actions | HIGH | `sts:AssumeRole` on `Resource: *` |
| Missing Condition constraints | MEDIUM | Sensitive actions without IP/org restrictions |
| Cross-account access without conditions | HIGH | `Principal: *` with no Condition |

## Output Formats

All modules support four output formats:

```bash
--format table      # Rich terminal output (default)
--format json       # Machine-readable JSON
--format markdown   # PR comment / documentation
--format sarif      # GitHub Code Scanning integration
```

## CI Integration

### GitHub Actions Example

```yaml
- name: Score Terraform plan risk
  run: |
    pip install infraguard
    terraform show -json tfplan > plan.json
    infraguard plan-risk -f plan.json --threshold 50

- name: Check IAM policies
  run: |
    infraguard iam-check -f policies/ --max-findings critical:0,high:3 --format sarif > results.sarif

- name: Upload SARIF results
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

### Exit Codes

| Code | Meaning |
|------|---------|
| `0` | All checks passed / within threshold |
| `1` | Threshold exceeded (CI should block) |
| `2` | Input error (bad file, parse failure) |

## Configuration

All modules work zero-config with sensible defaults. Override with custom YAML rules:

```bash
infraguard plan-risk -f plan.json --rules custom_rules.yaml
infraguard tag-audit -f resources.json --rules tag_policy.yaml
```

See [`examples/`](examples/) for sample rule files and demo data.

## Project Structure

```
src/infraguard/
├── cli.py              Main entry point
├── common/             Shared severity model, reporter, config loader
├── plan_risk/          Terraform plan parser, scorer, rules
├── tag_audit/          AWS resource scanner, tag evaluator, rules
└── iam_check/          IAM policy analyzer, checks, rules
```

## Development

```bash
git clone https://github.com/bertrandmbanwi/infraguard.git
cd infraguard
pip install -e '.[dev]'
pytest                   # 58 tests
ruff check src/ tests/   # lint
```

## License

[MIT](LICENSE)
