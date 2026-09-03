def evaluate_s3_encryption(bucket_data):
    findings = []
    for b in bucket_data:
        if not b.get("encryption"):
            findings.append({
                "rule_id": "S3_NO_ENCRYPTION",
                "severity_raw": "HIGH",
                "resource": {
                    "type": "AWS::S3::Bucket",
                    "id": b["name"],
                    "arn": f"arn:aws:s3:::{b['name']}"
                },
                "status": "FAIL",
                "risk_score": 0,
                "score_breakdown": [],
                "explanation": "",
                "compliance_mappings": []
            })
    return findings