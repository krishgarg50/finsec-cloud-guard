from datetime import datetime, timezone

def evaluate_s3_no_versioning(bucket_data):
    findings = []
    for b in bucket_data:
        if b.get("versioning") != "Enabled":
            findings.append({
                "rule_id": "S3_NO_VERSIONING",
                "severity_raw": "LOW",
                "resource": {
                    "type": "AWS::S3::Bucket",
                    "id": b["name"],
                    "arn": f"arn:aws:s3:::{b['name']}"
                },
                "status": "FAIL", "risk_score": 0, "score_breakdown": [], "explanation": "", "compliance_mappings": []
            })
    return findings

def evaluate_iam_unused_access_key(iam_data):
    findings = []
    now = datetime.now(timezone.utc)
    for user in iam_data.get("users", []):
        for key in user.get("access_keys", []):
            last_used = key.get("last_used_date")
            if last_used:
                days_unused = (now - last_used).days
                if days_unused > 90:
                    findings.append({
                        "rule_id": "IAM_UNUSED_ACCESS_KEY",
                        "severity_raw": "MEDIUM",
                        "resource": {
                            "type": "AWS::IAM::AccessKey",
                            "id": key["key_id"],
                            "arn": user["arn"]
                        },
                        "status": "FAIL", "risk_score": 0, "score_breakdown": [], "explanation": "", "compliance_mappings": []
                    })
    return findings

def evaluate_ebs_not_encrypted(ebs_data):
    findings = []
    for vol in ebs_data:
        if not vol.get("Encrypted", False):
            findings.append({
                "rule_id": "EBS_NOT_ENCRYPTED",
                "severity_raw": "HIGH",
                "resource": {
                    "type": "AWS::EC2::Volume",
                    "id": vol["VolumeId"],
                    "arn": f"arn:aws:ec2:::volume/{vol['VolumeId']}"
                },
                "status": "FAIL", "risk_score": 0, "score_breakdown": [], "explanation": "", "compliance_mappings": []
            })
    return findings

def evaluate_rds_not_encrypted(rds_data):
    findings = []
    for db in rds_data:
        if not db.get("StorageEncrypted", False):
            findings.append({
                "rule_id": "RDS_NOT_ENCRYPTED",
                "severity_raw": "HIGH",
                "resource": {
                    "type": "AWS::RDS::DBInstance",
                    "id": db["DBInstanceIdentifier"],
                    "arn": db.get("DBInstanceArn", f"arn:aws:rds:::db:{db['DBInstanceIdentifier']}")
                },
                "status": "FAIL", "risk_score": 0, "score_breakdown": [], "explanation": "", "compliance_mappings": []
            })
    return findings

def evaluate_rds_publicly_accessible(rds_data):
    findings = []
    for db in rds_data:
        if db.get("PubliclyAccessible", False):
            findings.append({
                "rule_id": "RDS_PUBLICLY_ACCESSIBLE",
                "severity_raw": "HIGH",
                "resource": {
                    "type": "AWS::RDS::DBInstance",
                    "id": db["DBInstanceIdentifier"],
                    "arn": db.get("DBInstanceArn", f"arn:aws:rds:::db:{db['DBInstanceIdentifier']}")
                },
                "status": "FAIL", "risk_score": 0, "score_breakdown": [], "explanation": "", "compliance_mappings": []
            })
    return findings