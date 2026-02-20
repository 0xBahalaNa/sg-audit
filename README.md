# Security Group Audit

A Python tool that audits EC2 Security Groups for overly permissive inbound rules.

## Overview

This repository contains two scripts:
1. **sg_audit.py** - Audits security groups for open internet access and risky ports
2. **deploy_test_sgs.py** - Creates test security groups with various configurations

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

### 1. Open to Internet (0.0.0.0/0)

Checks if any inbound rule allows traffic from all IP addresses.

### 2. Risky Ports

Flags critical findings if these ports are open to the internet:

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

## Cleanup

Delete test security groups when done:

```bash
aws ec2 delete-security-group --group-name test-open-ssh
aws ec2 delete-security-group --group-name test-open-rdp
aws ec2 delete-security-group --group-name test-open-https
aws ec2 delete-security-group --group-name test-secure
```

## Key Concepts Learned

| Concept | Description |
|---------|-------------|
| `ec2.describe_security_groups()` | List all security groups |
| `ec2.create_security_group()` | Create new security group |
| `ec2.authorize_security_group_ingress()` | Add inbound rules |
| Nested loops | Navigate complex data structures |
| Sets | Fast membership checking |

## GRC Application

This tool supports:
- **CIS AWS Benchmark** - 5.2, 5.3 (No unrestricted SSH/RDP access)
- **SOC 2** - CC6.6 (Boundary Protection)
- **NIST 800-53** - SC-7 (Boundary Protection)
- **PCI DSS** - 1.2.1 (Restrict inbound/outbound traffic)

## Future Enhancements

- Check IPv6 ranges (`::/0`)
- Audit outbound rules
- Export results to CSV/JSON
- Filter by VPC or tags
- Auto-remediation (remove risky rules)
- Email alerts for findings

