"""
3RD EYE - Check #4: Are storage disks (EBS volumes) encrypted?

Two questions:
  1. Is account-wide "encrypt new disks by default" switched on?
  2. Is any existing disk unencrypted?
Usage:  python scanner/check_ebs_encryption.py messy
"""

import sys

import boto3


def find_unencrypted_disks(session):
    """Return (number of disks checked, list of findings)."""
    ec2 = session.client("ec2")
    findings = []

    # Question 1: the account-wide safety net
    if not ec2.get_ebs_encryption_by_default()["EbsEncryptionByDefault"]:
        findings.append({
            "check": "EBS default encryption is off",
            "resource": f"account setting (region {session.region_name})",
            "risk": "MEDIUM",
            "fix": "Turn on 'Always encrypt new EBS volumes' in EC2 settings for this region.",
        })

    # Question 2: every existing disk
    checked = 0
    for page in ec2.get_paginator("describe_volumes").paginate():
        for volume in page["Volumes"]:
            checked += 1
            if not volume["Encrypted"]:
                findings.append({
                    "check": "Unencrypted EBS volume",
                    "resource": f"{volume['VolumeId']} ({volume['Size']} GB, {volume['State']})",
                    "risk": "MEDIUM",
                    "fix": "Copy a snapshot of the volume with encryption on, restore from it, then delete the old volume.",
                })

    return checked, findings


def main():
    profile = sys.argv[1] if len(sys.argv) > 1 else "messy"
    session = boto3.Session(profile_name=profile)

    print(f"\n3RD EYE scan - account profile: {profile} (region: {session.region_name})")
    print("Check: Are storage disks encrypted?\n")

    checked, findings = find_unencrypted_disks(session)
    print(f"EBS volumes checked: {checked}")

    if not findings:
        print("PASS - default encryption is on and every disk is encrypted.\n")
        return 0

    for f in findings:
        print(f"[{f['risk']}] {f['check']}: {f['resource']}")
        print(f"   Fix: {f['fix']}")
    print(f"\nFAIL - {len(findings)} encryption problem(s) found.\n")
    return 1


if __name__ == "__main__":
    sys.exit(main())