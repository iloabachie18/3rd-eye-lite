"""
3RD EYE - Check #1: Is any S3 bucket public?

Asks AWS about every bucket in the account and reports the ones
that anyone on the internet can read.
Usage:  python scanner/check_s3_public.py messy
"""

import sys

import boto3
from botocore.exceptions import ClientError


def find_public_buckets(session):
    """Return (all bucket names, list of findings for public buckets)."""
    s3 = session.client("s3")
    bucket_names = [b["Name"] for b in s3.list_buckets().get("Buckets", [])]
    findings = []

    for name in bucket_names:
        try:
            status = s3.get_bucket_policy_status(Bucket=name)
            is_public = status["PolicyStatus"]["IsPublic"]
        except ClientError as error:
            # A bucket with no policy at all cannot be public through a policy
            if error.response["Error"]["Code"] == "NoSuchBucketPolicy":
                is_public = False
            else:
                raise

        if is_public:
            findings.append({
                "check": "S3 bucket is public",
                "resource": name,
                "risk": "CRITICAL",
                "fix": "Turn on Block Public Access and remove the public bucket policy.",
            })

    return bucket_names, findings


def main():
    profile = sys.argv[1] if len(sys.argv) > 1 else "messy"
    session = boto3.Session(profile_name=profile)

    print(f"\n3RD EYE scan - account profile: {profile}")
    print("Check: Is any S3 bucket public?\n")

    bucket_names, findings = find_public_buckets(session)
    print(f"Buckets checked: {len(bucket_names)}")

    if not findings:
        print("PASS - no public buckets found.\n")
        return 0

    for f in findings:
        print(f"[{f['risk']}] {f['check']}: {f['resource']}")
        print(f"   Fix: {f['fix']}")
    print(f"\nFAIL - {len(findings)} public bucket(s) found.\n")
    return 1


if __name__ == "__main__":
    sys.exit(main())