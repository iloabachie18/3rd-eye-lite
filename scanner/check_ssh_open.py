"""
3RD EYE - Check #2: Is SSH (port 22) open to the whole internet?

Looks at every security group (firewall) in the account's region and
reports any rule that lets the entire internet reach port 22.
Usage:  python scanner/check_ssh_open.py messy
"""

import sys

import boto3

SSH_PORT = 22
WHOLE_INTERNET = {"0.0.0.0/0", "::/0"}  # IPv4 and IPv6 "everyone"


def rule_covers_ssh(rule):
    """True if this firewall rule includes port 22."""
    if rule.get("IpProtocol") == "-1":  # "-1" means ALL traffic, all ports
        return True
    from_port = rule.get("FromPort")
    to_port = rule.get("ToPort")
    if from_port is None or to_port is None:
        return False
    return from_port <= SSH_PORT <= to_port


def rule_open_to_internet(rule):
    """True if this rule allows traffic from anywhere on the internet."""
    ipv4 = {r.get("CidrIp") for r in rule.get("IpRanges", [])}
    ipv6 = {r.get("CidrIpv6") for r in rule.get("Ipv6Ranges", [])}
    return bool((ipv4 | ipv6) & WHOLE_INTERNET)


def find_open_ssh(session):
    """Return (number of security groups checked, list of findings)."""
    ec2 = session.client("ec2")
    findings = []
    checked = 0

    for page in ec2.get_paginator("describe_security_groups").paginate():
        for group in page["SecurityGroups"]:
            checked += 1
            for rule in group.get("IpPermissions", []):
                if rule_covers_ssh(rule) and rule_open_to_internet(rule):
                    findings.append({
                        "check": "SSH open to the internet",
                        "resource": f"{group['GroupId']} ({group['GroupName']})",
                        "risk": "HIGH",
                        "fix": "Limit port 22 to trusted IP ranges, or use AWS Systems Manager Session Manager instead of SSH.",
                    })
                    break  # one finding per security group is enough

    return checked, findings


def main():
    profile = sys.argv[1] if len(sys.argv) > 1 else "messy"
    session = boto3.Session(profile_name=profile)

    print(f"\n3RD EYE scan - account profile: {profile} (region: {session.region_name})")
    print("Check: Is SSH open to the whole internet?\n")

    checked, findings = find_open_ssh(session)
    print(f"Security groups checked: {checked}")

    if not findings:
        print("PASS - no security groups allow SSH from the internet.\n")
        return 0

    for f in findings:
        print(f"[{f['risk']}] {f['check']}: {f['resource']}")
        print(f"   Fix: {f['fix']}")
    print(f"\nFAIL - {len(findings)} security group(s) with SSH open to the internet.\n")
    return 1


if __name__ == "__main__":
    sys.exit(main())