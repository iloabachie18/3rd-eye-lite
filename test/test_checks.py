"""
Tests for every 3RD EYE check.

Each check gets two kinds of test, just like the practice houses:
  - MESSY: plant the mistake -> the check MUST catch it
  - CLEAN: do it right       -> the check must NOT raise a false alarm
Run with:  python -m pytest -v
"""

import json

from check_s3_public import find_public_buckets
from check_ssh_open import find_open_ssh
from check_mfa import find_users_without_mfa
from check_ebs_encryption import find_unencrypted_disks
from check_password_policy import find_password_weaknesses
from scan import score_and_grade


# ---------- Check #1: public S3 buckets ----------

def test_public_bucket_is_caught(aws):
    s3 = aws.client("s3")
    s3.create_bucket(Bucket="planted-public")
    s3.put_bucket_policy(Bucket="planted-public", Policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": "*",
                       "Action": "s3:GetObject",
                       "Resource": "arn:aws:s3:::planted-public/*"}],
    }))
    _, findings = find_public_buckets(aws)
    assert [f["resource"] for f in findings] == ["planted-public"]
    assert findings[0]["risk"] == "CRITICAL"


def test_private_bucket_passes(aws):
    aws.client("s3").create_bucket(Bucket="private-bucket")
    _, findings = find_public_buckets(aws)
    assert findings == []


# ---------- Check #2: SSH open to the internet ----------

def _new_group_with_ssh(aws, name, cidr):
    ec2 = aws.client("ec2")
    vpc_id = ec2.describe_vpcs()["Vpcs"][0]["VpcId"]
    group_id = ec2.create_security_group(
        GroupName=name, Description="test", VpcId=vpc_id)["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=group_id, IpPermissions=[{
        "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
        "IpRanges": [{"CidrIp": cidr}]}])


def test_ssh_open_to_internet_is_caught(aws):
    _new_group_with_ssh(aws, "planted-open", "0.0.0.0/0")
    _, findings = find_open_ssh(aws)
    assert len(findings) == 1
    assert "planted-open" in findings[0]["resource"]


def test_ssh_from_private_network_passes(aws):
    _new_group_with_ssh(aws, "private-only", "172.31.0.0/16")
    _, findings = find_open_ssh(aws)
    assert findings == []


# ---------- Check #3: console users without MFA ----------

def test_console_user_without_mfa_is_caught(aws):
    iam = aws.client("iam")
    iam.create_user(UserName="planted-no-mfa")
    iam.create_login_profile(UserName="planted-no-mfa", Password="Test-Password-123!")
    _, findings = find_users_without_mfa(aws)
    assert [f["resource"] for f in findings] == ["planted-no-mfa"]


def test_user_without_console_password_passes(aws):
    aws.client("iam").create_user(UserName="no-console-access")
    _, findings = find_users_without_mfa(aws)
    assert findings == []


def test_no_users_passes(aws):
    checked, findings = find_users_without_mfa(aws)
    assert checked == 0 and findings == []


# ---------- Check #4: EBS encryption ----------

def test_unencrypted_volume_and_default_off_are_caught(aws):
    aws.client("ec2").create_volume(AvailabilityZone="us-east-1a", Size=1, Encrypted=False)
    _, findings = find_unencrypted_disks(aws)
    checks = sorted(f["check"] for f in findings)
    assert checks == ["EBS default encryption is off", "Unencrypted EBS volume"]


def test_encrypted_volume_with_default_on_passes(aws):
    ec2 = aws.client("ec2")
    ec2.enable_ebs_encryption_by_default()
    ec2.create_volume(AvailabilityZone="us-east-1a", Size=1, Encrypted=True)
    _, findings = find_unencrypted_disks(aws)
    assert findings == []


# ---------- Check #5: password policy ----------

def test_missing_password_policy_is_caught(aws):
    findings = find_password_weaknesses(aws)
    assert findings[0]["check"] == "No password policy"


def test_weak_password_policy_is_caught(aws):
    aws.client("iam").update_account_password_policy(MinimumPasswordLength=6)
    findings = find_password_weaknesses(aws)
    assert findings[0]["check"] == "Weak password policy"
    assert "minimum length is 6" in findings[0]["resource"]


def test_strong_password_policy_passes(aws):
    aws.client("iam").update_account_password_policy(
        MinimumPasswordLength=14, RequireSymbols=True, RequireNumbers=True,
        RequireUppercaseCharacters=True, RequireLowercaseCharacters=True,
        PasswordReusePrevention=24)
    assert find_password_weaknesses(aws) == []


# ---------- The report card score ----------

def test_perfect_account_scores_100():
    assert score_and_grade([]) == (100, "A")


def test_messy_house_scores_30():
    risks = ["CRITICAL", "HIGH", "HIGH", "MEDIUM", "MEDIUM", "MEDIUM"]
    assert score_and_grade([{"risk": r} for r in risks]) == (30, "F")