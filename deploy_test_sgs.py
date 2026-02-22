"""
deploy_test_sgs.py

Creates test security groups with various configurations to test sg_audit.py.

Security Groups Created:
    1. test-open-ssh   - SSH (22) open to internet → should trigger FAIL
    2. test-open-rdp   - RDP (3389) open to internet → should trigger FAIL
    3. test-open-https - HTTPS (443) open to internet → should trigger WARN
    4. test-secure     - No open rules → should pass clean

Usage:
    python deploy_test_sgs.py

Cleanup:
    aws ec2 delete-security-group --group-name test-open-ssh
    aws ec2 delete-security-group --group-name test-open-rdp
    aws ec2 delete-security-group --group-name test-open-https
    aws ec2 delete-security-group --group-name test-secure

Requirements:
    - boto3 installed (pip install boto3)
    - AWS credentials configured (aws configure)
"""

import boto3

# ---------------------------------------------------------------------------
# Setup: Create EC2 client and get VPC ID
# ---------------------------------------------------------------------------

# Create EC2 client
ec2 = boto3.client('ec2')

# Get the default VPC ID (security groups must be associated with a VPC)
vpcs = ec2.describe_vpcs(Filters=[{'Name': 'is-default', 'Values': ['true']}])
vpc_id = vpcs['Vpcs'][0]['VpcId']
print(f"Using VPC: {vpc_id}")

# ---------------------------------------------------------------------------
# Configuration: Define test security groups to create
# ---------------------------------------------------------------------------

# List of dictionaries - each defines one security group and its rules
test_sgs = [
    {
        "name": "test-open-ssh",
        "description": "SSH open to internet (should FAIL)",
        "rules": [{"port": 22, "cidr": "0.0.0.0/0"}]
    },
    {
        "name": "test-open-rdp",
        "description": "RDP open to internet (should FAIL)",
        "rules": [{"port": 3389, "cidr": "0.0.0.0/0"}]
    },
    {
        "name": "test-open-https",
        "description": "HTTPS open to internet (should WARN)",
        "rules": [{"port": 443, "cidr": "0.0.0.0/0"}]
    },
    {
        "name": "test-secure",
        "description": "No open rules (should PASS)",
        "rules": []  # Empty list = no inbound rules
    }
]

print(f"Will create {len(test_sgs)} test security groups.")

# ---------------------------------------------------------------------------
# Main Loop: Create each security group and add rules
# ---------------------------------------------------------------------------

for sg_config in test_sgs:
    sg_name = sg_config["name"]
    sg_desc = sg_config["description"]
    
    # --- Step 1: Create the security group ---
    try:
        response = ec2.create_security_group(
            GroupName=sg_name,
            Description=sg_desc,
            VpcId=vpc_id
        )
        sg_id = response['GroupId']
        print(f"Created: {sg_name} ({sg_id})")
    except ec2.exceptions.ClientError as e:
        # Handle "already exists" error gracefully
        if 'InvalidGroup.Duplicate' in str(e):
            print(f"Already exists: {sg_name}")
            # Get existing group ID so we can still add rules
            existing = ec2.describe_security_groups(GroupNames=[sg_name])
            sg_id = existing['SecurityGroups'][0]['GroupId']
        else:
            raise e
    
    # --- Step 2: Add inbound rules ---
    for rule in sg_config["rules"]:
        try:
            ec2.authorize_security_group_ingress(
                GroupId=sg_id,
                IpProtocol='tcp',
                FromPort=rule["port"],
                ToPort=rule["port"],
                CidrIp=rule["cidr"]
            )
            print(f"    → Added rule: port {rule['port']} from {rule['cidr']}")
        except ec2.exceptions.ClientError as e:
            # Handle "rule already exists" error gracefully
            if 'InvalidPermission.Duplicate' in str(e):
                print(f"    → Rule already exists: port {rule['port']}")
            else:
                raise e

print("\nDone! Run sg_audit.py to test these security groups.")
