def evaluate_cloudtrail_status(trail_data):
    findings = []
    # If no trails exist or none are currently actively logging
    active_trails = [t for t in trail_data if t.get("is_logging", False)]
    
    if not active_trails:
        findings.append({
            "rule_id": "CLOUDTRAIL_DISABLED",
            "severity_raw": "CRITICAL",
            "resource": {
                "type": "AWS::CloudTrail::Trail",
                "id": "global-trail",
                "arn": "arn:aws:cloudtrail:::trail/global-trail"
            },
            "status": "FAIL",
            "risk_score": 0,
            "score_breakdown": [],
            "explanation": "",
            "compliance_mappings": []
        })
    return findings