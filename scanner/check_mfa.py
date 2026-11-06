"""
3RD EYE - Check #3: Can any IAM user log into the console WITHOUT MFA?

Looks at every IAM user. If a user has a console password (login profile)
but no MFA device, anyone who steals or guesses that password gets in.
Usage:  python scanner/check_mfa.py messy
"""

import sys

import boto3
from botocore.exceptions import ClientError


def has_console_password(iam, user_name):
    """True if the user can log into the AWS console with a password."""
    try:
        iam.get_login_profile(UserName=user_name)
        return True
    except ClientError as error:
        # "NoSuchEntity" means this user has no console password at all
        if error.response["Error"]["Code"] == "NoSuchEntity":
            return False
        raise


def has_mfa(iam, user_name):
    """True if the user has at least one MFA device."""
    devices = iam.list_mfa_devices(UserName=user_name)["MFADevices"]
    return len(devices) > 0


def find_users_without_mfa(session):
    """Return (number of users checked, list of findings)."""
    iam = session.client("iam")
    findings = []
    checked = 0

    for page in iam.get_paginator("list_users").paginate():
        for user in page["Users"]:
            checked += 1
            name = user["UserName"]
            if has_console_password(iam, name) and not has_mfa(iam, name):
                findings.append({
                    "check": "Console user without MFA",
                    "resource": name,
                    "risk": "HIGH",
                    "fix": "Turn on MFA for this user, or remove their console password if they don't need it.",
                })

    return checked, findings


def main():
    profile = sys.argv[1] if len(sys.argv) > 1 else "messy"
    session = boto3.Session(profile_name=profile)

    print(f"\n3RD EYE scan - account profile: {profile}")
    print("Check: Can any IAM user log in without MFA?\n")

    checked, findings = find_users_without_mfa(session)
    print(f"IAM users checked: {checked}")

    if not findings:
        print("PASS - every console user has MFA (or there are no console users).\n")
        return 0

    for f in findings:
        print(f"[{f['risk']}] {f['check']}: {f['resource']}")
        print(f"   Fix: {f['fix']}")
    print(f"\nFAIL - {len(findings)} user(s) can log in without MFA.\n")
    return 1


if __name__ == "__main__":
    sys.exit(main())