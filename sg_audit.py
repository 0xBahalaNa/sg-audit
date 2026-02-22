"""
sg_audit.py

Audits all EC2 Security Groups in your AWS account for overly permissive inbound rules.

Checks performed:
    1. Open to Internet - Is 0.0.0.0/0 in any inbound rule?
    2. Risky Ports - Are sensitive ports (SSH, RDP, databases) open to the world?

Output:
    [FAIL] - Risky port open to internet (critical security issue)
    [WARN] - Non-risky port open to internet (review recommended)

Risky Ports:
    22    - SSH (remote shell access)
    3389  - RDP (Windows remote desktop)
    3306  - MySQL database
    5432  - PostgreSQL database
    1433  - MSSQL database
    27017 - MongoDB database

Usage:
    python sg_audit.py

Requirements:
    - boto3 installed (pip install boto3)
    - AWS credentials configured (aws configure)
"""

import boto3

# ---------------------------------------------------------------------------
# Configuration: Define risky ports to flag as critical
# ---------------------------------------------------------------------------

# Set of ports that should never be open to the internet
RISKY_PORTS = {22, 3389, 3306, 5432, 1433, 27017}

# ---------------------------------------------------------------------------
# Setup: Create EC2 client and get all security groups
# ---------------------------------------------------------------------------

# Create EC2 client to interact with AWS EC2 service
ec2 = boto3.client('ec2')

# Get all security groups in the account
security_groups = ec2.describe_security_groups()
security_groups_list = security_groups['SecurityGroups']

# ---------------------------------------------------------------------------
# Counters: Track audit findings
# ---------------------------------------------------------------------------

total_groups = len(security_groups_list)
open_groups = 0          # Groups with any open rule (0.0.0.0/0)
critical_findings = 0    # Rules with risky ports open

# ---------------------------------------------------------------------------
# Main Loop: Check each security group
# ---------------------------------------------------------------------------

for sg in security_groups_list:
    sg_name = sg['GroupName']
    sg_id = sg['GroupId']
    has_open_rule = False
    
    print(f"\nChecking: {sg_name} ({sg_id})")

    # Get inbound rules for the security group
    # IpPermissions = inbound rules, IpPermissionsEgress = outbound rules
    inbound_rules = sg['IpPermissions']

    # Loop through each inbound rule
    for rule in inbound_rules:
        # Get port range (some rules like ICMP don't have ports)
        from_port = rule.get('FromPort', 'All')
        to_port = rule.get('ToPort', 'All')

        # Check each IP range in this rule
        # A rule can allow multiple CIDR blocks
        for ip_range in rule['IpRanges']:
            cidr_ip = ip_range['CidrIp']
            
            # Check if open to entire internet
            if cidr_ip == '0.0.0.0/0':
                has_open_rule = True
                
                # Check if it's a risky port
                if from_port in RISKY_PORTS:
                    print(f"    [FAIL] Port {from_port} is open to the Internet!")
                    critical_findings += 1
                else:
                    print(f"    [WARN] Open to internet on port {from_port}.")
    
    # Count groups with any open rule (after checking all rules)
    if has_open_rule:
        open_groups += 1

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

print("\n" + "=" * 40)
print(f"Total security groups: {total_groups}")
print(f"Groups with open rules: {open_groups}")
print(f"Critical findings (risky ports): {critical_findings}")
