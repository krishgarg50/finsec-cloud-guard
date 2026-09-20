import json
import uuid
from connector import AWSConnector

from rules.s3_rules import evaluate_s3_public_access, evaluate_s3_no_versioning
from rules.encryption_rules import (
    evaluate_s3_encryption,
    evaluate_ebs_not_encrypted,
    evaluate_rds_not_encrypted,
    evaluate_rds_publicly_accessible,
)
from rules.iam_rules import (
    evaluate_iam_wildcard_policy,
    evaluate_iam_root_mfa,
    evaluate_iam_user_no_mfa,
    evaluate_iam_unused_access_key,
)
from rules.sg_rules import evaluate_sg_open_to_world
from rules.cloudtrail_rules import evaluate_cloudtrail_status


def main():
    print("Initializing AWS connector...")
    connector = AWSConnector()

    scan_id = f"scan-{uuid.uuid4()}"
    account_id = connector.get_account_id()
    print(f"Scan ID: {scan_id}  |  Account: {account_id}")

    all_findings = []

    print("Evaluating S3 (Public Access, Encryption, Versioning)...")
    s3_data = connector.get_s3_buckets_config()
    all_findings.extend(evaluate_s3_public_access(s3_data, scan_id))
    all_findings.extend(evaluate_s3_encryption(s3_data, scan_id))
    all_findings.extend(evaluate_s3_no_versioning(s3_data, scan_id))

    print("Evaluating IAM (Wildcards, Root MFA, User MFA, Unused Keys)...")
    iam_data = connector.get_iam_config()
    all_findings.extend(evaluate_iam_wildcard_policy(iam_data, scan_id))
    all_findings.extend(evaluate_iam_root_mfa(iam_data, scan_id, account_id))
    all_findings.extend(evaluate_iam_user_no_mfa(iam_data, scan_id))
    all_findings.extend(evaluate_iam_unused_access_key(iam_data, scan_id))

    print("Evaluating Security Groups (0.0.0.0/0 exposure)...")
    sg_data = connector.get_security_groups_config()
    all_findings.extend(evaluate_sg_open_to_world(sg_data, scan_id))

    print("Evaluating CloudTrail status...")
    trail_data = connector.get_cloudtrail_config()
    all_findings.extend(evaluate_cloudtrail_status(trail_data, scan_id, account_id))

    print("Evaluating EBS (Encryption)...")
    ebs_data = connector.get_ebs_volumes_config()
    all_findings.extend(evaluate_ebs_not_encrypted(ebs_data, scan_id))

    print("Evaluating RDS (Encryption, Public Access)...")
    rds_data = connector.get_rds_instances_config()
    all_findings.extend(evaluate_rds_not_encrypted(rds_data, scan_id))
    all_findings.extend(evaluate_rds_publicly_accessible(rds_data, scan_id))

    with open("scan_output.json", "w") as f:
        json.dump(all_findings, f, indent=4)

    print(f"\nScan complete! Generated {len(all_findings)} raw findings matching shared/raw_finding_schema.json.")
    print("Output saved to scan_output.json")


if __name__ == "__main__":
    main()
