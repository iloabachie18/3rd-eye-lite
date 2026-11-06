"""
3RD EYE - Check #5: Is the account password policy strong enough?

Compares the account's password rules against CIS AWS Foundations
Benchmark guidance: at least 14 characters and no reuse of the last
24 passwords, plus character-complexity rules.
Usage:  python scanner/check_password_policy.py messy
"""

import sys

import boto3
from botocore.exceptions import ClientError

MIN_LENGTH = 14   # CIS recommendation
MIN_REUSE = 24    # remember the last 24 passwords
COMPLEXITY_RULES = {
    "RequireUppercaseCharacters": "uppercase letters",
    "RequireLowercaseCharacters": "lowercase letters",
    "RequireNumbers": "numbers",
    "RequireSymbols": "symbols",
}


def find_password_weaknesses(session):
    """Return a list of findings (empty list = the policy is strong)."""
    iam = session.client("iam")

    try:
        policy = iam.get_account_password_policy()["PasswordPolicy"]
    except ClientError as error:
        # "NoSuchEntity" means the account has no password policy at all
        if error.response["Error"]["Code"] == "NoSuchEntity":
            return [{
                "check": "No password policy",
                "resource": "account password policy",
                "risk": "MEDIUM",
                "fix": f"Create a password policy: {MIN_LENGTH}+ characters, complexity, reuse prevention of {MIN_REUSE}.",
            }]
        raise

    weaknesses = []
    length = policy.get("MinimumPasswordLength", 0)
    if length < MIN_LENGTH:
        weaknesses.append(f"minimum length is {length} (should be {MIN_LENGTH}+)")

    reuse = policy.get("PasswordReusePrevention", 0)
    if reuse < MIN_REUSE:
        weaknesses.append(f"remembers {reuse} old passwords (should be {MIN_REUSE})")

    missing = [label for key, label in COMPLEXITY_RULES.items() if not policy.get(key, False)]
    if missing:
        weaknesses.append("does not require " + ", ".join(missing))

    if not weaknesses:
        return []

    return [{
        "check": "Weak password policy",
        "resource": "account password policy: " + "; ".join(weaknesses),
        "risk": "MEDIUM",
        "fix": f"Update the policy: {MIN_LENGTH}+ characters, all complexity rules, reuse prevention of {MIN_REUSE}.",
    }]


def main():
    profile = sys.argv[1] if len(sys.argv) > 1 else "messy"
    session = boto3.Session(profile_name=profile)

    print(f"\n3RD EYE scan - account profile: {profile}")
    print("Check: Is the password policy strong enough?\n")

    findings = find_password_weaknesses(session)

    if not findings:
        print("PASS - the password policy meets CIS guidance.\n")
        return 0

    for f in findings:
        print(f"[{f['risk']}] {f['check']}: {f['resource']}")
        print(f"   Fix: {f['fix']}")
    print("\nFAIL - the password policy needs strengthening.\n")
    return 1


if __name__ == "__main__":
    sys.exit(main())