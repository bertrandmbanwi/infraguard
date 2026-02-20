# Changelog

## 0.1.0 (2026-02-20)

### Added
- `plan-risk` — Terraform plan blast radius scorer with configurable resource criticality, action weights, and environment detection
- `tag-audit` — AWS resource tag compliance checker with required tags, allowed values, pattern matching, and resource-type overrides; supports live AWS scanning and offline JSON mode
- `iam-check` — IAM policy least-privilege analyzer with checks for admin access, wildcard actions/resources, dangerous permissions, missing conditions, and cross-account access
- Four output formats: table (Rich), JSON, markdown, SARIF
- CI-ready exit codes and threshold enforcement across all modules
- 58 tests covering parser, scorer, evaluator, analyzer, and individual checks
