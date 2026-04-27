# Security Group Audit

A Python tool that audits EC2 Security Groups for overly permissive inbound rules and risky management ports. Built for GRC engineers, compliance analysts, and assessors working in FedRAMP High and CJIS v6.0 environments where exposed boundary controls represent immediate audit findings.

## Compliance Controls Addressed

| NIST 800-53 Rev 5 | FedRAMP High | CJIS v6.0 | Validation Method |
|--------------------|:------------:|:---------:|-------------------|
| SC-7 Boundary Protection | Yes | Policy Area 13 | Detects `0.0.0.0/0` ingress on any inbound rule |
| SC-7(3) Access Points | Yes | — | Limits attack surface by enumerating risky ports |
| SC-7(4) External Telecommunications Services | Yes | — | Enforces cloud network boundary at security-group layer |
| AC-3 Access Enforcement | Yes | — | Network-layer access control at the SG |
| AC-4 Information Flow Enforcement | Yes | — | Ingress flow control (egress on roadmap) |
| CM-7 Least Functionality | Yes | — | Flags risky management ports (SSH, RDP, DB ports) |
| AU-12 Audit Record Generation | Yes | — | Every audit run produces compliance evidence |

## Overview

Two scripts:

1. **`sg_audit.py`** — Audits security groups for open internet access and risky ports.
2. **`deploy_test_sgs.py`** — Creates test security groups with various configurations to exercise the audit script.

## Requirements

- Python 3.x
- `boto3` library
- AWS CLI configured with credentials (`aws configure`)

### Install dependencies

```bash
pip install boto3
```

## Usage

### Run the audit

```bash
python sg_audit.py
```

**Sample output:**

```
Checking: test-open-ssh (sg-07c07ec3b75a2aa62)
    [FAIL] Port 22 is open to the Internet!

Checking: test-open-rdp (sg-01d01d1b156373a84)
    [FAIL] Port 3389 is open to the Internet!

Checking: test-secure (sg-0f8c1c9faa58e4c1d)

Checking: default (sg-0ecc91801d95742d6)

Checking: test-open-https (sg-02e918fc9b1fa60f1)
    [WARN] Open to internet on port 443.

========================================
Total security groups: 5
Groups with open rules: 3
Critical findings (risky ports): 2
```

### Deploy test security groups (optional)

```bash
python deploy_test_sgs.py
```

Creates 4 security groups with different configurations:

| Security Group | Rule | Expected Result |
|----------------|------|-----------------|
| `test-open-ssh` | Port 22 → 0.0.0.0/0 | FAIL |
| `test-open-rdp` | Port 3389 → 0.0.0.0/0 | FAIL |
| `test-open-https` | Port 443 → 0.0.0.0/0 | WARN |
| `test-secure` | No rules | Clean |

## Compliance Checks

### 1. Open to Internet (SC-7, AC-3, AC-4)

Checks if any inbound rule allows traffic from `0.0.0.0/0`. Open ingress on any port is a boundary protection finding under SC-7; non-risky ports drop to `WARN` because some workloads (e.g., public-facing web servers on 443) legitimately require it, while risky ports stay `FAIL`.

### 2. Risky Ports (CM-7, SC-7(3))

Flags critical findings if these management / database ports are open to the internet:

| Port | Service |
|------|---------|
| 22 | SSH |
| 3389 | RDP |
| 3306 | MySQL |
| 5432 | PostgreSQL |
| 1433 | MSSQL |
| 27017 | MongoDB |

## Output Legend

| Status | Meaning |
|--------|---------|
| `[FAIL]` | Risky port open to internet |
| `[WARN]` | Non-risky port open to internet |
| (no output) | No open rules |

## How an Auditor Uses This Output

An assessor reviewing a FedRAMP High or CJIS v6.0 authorization package can use this script across the in-scope account to verify SC-7 (Boundary Protection) and CM-7 (Least Functionality) implementation. `FAIL` findings on risky ports map directly to the assessor's adequacy determination as control deficiencies; `WARN` findings on non-risky ports surface design questions ("why is this open?") that the system owner must justify. Combined with `cloudtrail-audit` (event monitoring) and `evidence-logger` (timestamped evidence packaging), the SG audit completes the network-boundary picture the assessor needs for an SC-7 walkthrough.

## FedRAMP 20x Alignment

This script supports FedRAMP 20x compliance-as-code by producing deterministic, automatable, and re-runnable boundary-control validation output. The findings can be transformed into OSCAL Assessment Results entries for machine-readable compliance reporting, and the SG state at run time becomes a KSI metric data point for continuous monitoring. Future iterations will emit JSON output (see Future Enhancements) to feed compliance-trestle and OSCAL pipelines directly.

## CJIS v6.0 Relevance

CJIS v6.0 became the audit standard on April 1, 2026 and aligns with NIST 800-53 Rev 5 as of December 2024. SC-7 falls under **Policy Area 13: System and Communications Protection**, which governs how Criminal Justice Information (CJI) crosses network boundaries. Open security groups on networks handling CJI are a near-immediate audit finding because they undermine the boundary controls that the rest of the policy depends on. A future enhancement to this script will add a `--cjis-mode` flag that demotes any `0.0.0.0/0` rule (risky port or not) to `FAIL` for security groups attached to CJI-tagged ENIs.

## Cleanup

Delete test security groups when done:

```bash
aws ec2 delete-security-group --group-name test-open-ssh
aws ec2 delete-security-group --group-name test-open-rdp
aws ec2 delete-security-group --group-name test-open-https
aws ec2 delete-security-group --group-name test-secure
```

## Future Enhancements

- Export results to CSV / JSON for downstream OSCAL pipelines
- Check IPv6 ranges (`::/0`)
- Audit egress (outbound) rules — AC-4 information flow
- Filter by VPC or tags (in-scope CJI vs general-purpose)
- `--cjis-mode` flag for stricter findings on CJI-tagged resources
- Auto-remediation hooks (revoke risky ingress)
- SNS / email alerts for findings

## Framework Reference

Control family mappings and AWS implementation details are documented in [nist-800-53-rev-5-to-aws-mapping](https://github.com/0xBahalaNa/nist-800-53-rev-5-to-aws-mapping).

## License

MIT
