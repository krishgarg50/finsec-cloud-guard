def evaluate_s3_public_access(bucket_data):
    findings = []
    for b in bucket_data:
        pab = b.get("public_access_block", {})
        # Check if all four Public Access Block settings are enabled
        is_pab_enabled = (
            pab.get("BlockPublicAcls", False) and
            pab.get("IgnorePublicAcls", False) and
            pab.get("BlockPublicPolicy", False) and
            pab.get("RestrictPublicBuckets", False)
        )

        if not is_pab_enabled:
            # Output conforms exactly to shared/finding_schema.json
            findings.append({
                "rule_id": "S3_PUBLIC_ACCESS",
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