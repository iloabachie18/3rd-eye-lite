"""
3RD EYE Lite - Full scan and report card.

Runs every check against one AWS account and prints a single report:
findings sorted by risk (CRITICAL first) and a security score out of 100.
Usage:  python scanner/scan.py <aws-profile>
"""

import sys
from datetime import datetime

import boto3

from check_s3_public import find_public_buckets
from check_ssh_open import find_open_ssh
from check_mfa import find_users_without_mfa
from check_ebs_encryption import find_unencrypted_disks
from check_password_policy import find_password_weaknesses

# Points taken off the score for each finding, by risk level
PENALTY = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 5, "LOW": 2}
RISK_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]


def run_all_checks(session):
    """Run every check. Returns (findings, list of check results for the summary)."""
    checks = [
        ("Public S3 buckets", lambda: find_public_buckets(session)[1]),
        ("SSH open to the internet", lambda: find_open_ssh(session)[1]),
        ("Console users without MFA", lambda: find_users_without_mfa(session)[1]),
        ("EBS encryption", lambda: find_unencrypted_disks(session)[1]),
        ("Password policy", lambda: find_password_weaknesses(session)),
    ]
    findings, summary = [], []

    for name, run in checks:
        try:
            results = run()
            findings.extend(results)
            summary.append((name, "PASS" if not results else f"FAIL ({len(results)})"))
        except Exception as error:  # one broken check must not stop the whole scan
            summary.append((name, f"ERROR - {type(error).__name__}"))

    return findings, summary


def score_and_grade(findings):
    """Start at 100 and subtract points for each finding."""
    score = max(0, 100 - sum(PENALTY.get(f["risk"], 0) for f in findings))
    for minimum, grade in [(90, "A"), (75, "B"), (60, "C"), (40, "D")]:
        if score >= minimum:
            return score, grade
    return score, "F"


def main():
    profile = sys.argv[1] if len(sys.argv) > 1 else "default"
    session = boto3.Session(profile_name=profile)

    findings, summary = run_all_checks(session)
    findings.sort(key=lambda f: RISK_ORDER.index(f["risk"]))
    score, grade = score_and_grade(findings)

    line = "=" * 64
    print(f"\n{line}")
    print("  3RD EYE LITE - SECURITY REPORT CARD")
    print(f"  Account profile: {profile}   Region: {session.region_name}")
    print(f"  Scanned: {datetime.now():%Y-%m-%d %H:%M}")
    print(line)
    print(f"\n  SECURITY SCORE: {score}/100   GRADE: {grade}\n")

    print("  Checks run:")
    for name, result in summary:
        print(f"    {result:<12} {name}")

    if findings:
        print(f"\n  Findings ({len(findings)}), most serious first:")
        for number, f in enumerate(findings, start=1):
            print(f"\n  {number}. [{f['risk']}] {f['check']}")
            print(f"     Resource: {f['resource']}")
            print(f"     Fix:      {f['fix']}")
    else:
        print("\n  No findings - excellent work!")

    print(f"\n{line}\n")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())