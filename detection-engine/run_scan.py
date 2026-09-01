import json
from connector import AWSConnector
from rules.s3_rules import evaluate_s3_public_access
from rules.encryption_rules import evaluate_s3_encryption
from rules.iam_rules import evaluate_iam_wildcard_policy, evaluate_iam_root_mfa, evaluate_iam_user_no_mfa
from rules.sg_rules import evaluate_sg_open_to_world
from rules.cloudtrail_rules import evaluate_cloudtrail_status

def main():
    print("Initializing AWS connector...")
    connector = AWSConnector()
    all_findings = []

    print("Evaluating S3 (Public Access & Encryption)...")
    s3_data = connector.get_s3_buckets_config()
    all_findings.extend(evaluate_s3_public_access(s3_data))
    all_findings.extend(evaluate_s3_encryption(s3_data))

    print("Evaluating IAM (Wildcards, Root MFA, User MFA)...")
    iam_data = connector.get_iam_config()
    all_findings.extend(evaluate_iam_wildcard_policy(iam_data))
    all_findings.extend(evaluate_iam_root_mfa(iam_data))
    all_findings.extend(evaluate_iam_user_no_mfa(iam_data))

    print("Evaluating Security Groups (0.0.0.0/0 exposure)...")
    sg_data = connector.get_security_groups_config()
    all_findings.extend(evaluate_sg_open_to_world(sg_data))

    print("Evaluating CloudTrail status...")
    trail_data = connector.get_cloudtrail_config()
    all_findings.extend(evaluate_cloudtrail_status(trail_data))

    # Output full findings list to scan_output.json
    with open("scan_output.json", "w") as f:
        json.dump(all_findings, f, indent=4)

    print(f"\nScan complete! Generated {len(all_findings)} raw findings matching finding_schema.json.")
    print("Output saved to scan_output.json")

if __name__ == "__main__":
    main()