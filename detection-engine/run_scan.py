import json
from connector import AWSConnector
from rules.s3_rules import evaluate_s3_public_access
from rules.iam_rules import evaluate_iam_wildcard_policy, evaluate_iam_root_mfa

def main():
    print("Starting AWS scan...")
    connector = AWSConnector()
    all_findings = []

    print("Pulling S3 configuration...")
    s3_data = connector.get_s3_buckets_config()
    all_findings.extend(evaluate_s3_public_access(s3_data))

    print("Pulling IAM configuration...")
    iam_data = connector.get_iam_config()
    all_findings.extend(evaluate_iam_wildcard_policy(iam_data))
    all_findings.extend(evaluate_iam_root_mfa(iam_data))

    print(f"Scan complete. Found {len(all_findings)} raw findings matching finding_schema.json.")
    
    with open("week1_output.json", "w") as f:
        json.dump(all_findings, f, indent=4)
        
    print("Results saved to week1_output.json")

if __name__ == "__main__":
    main()