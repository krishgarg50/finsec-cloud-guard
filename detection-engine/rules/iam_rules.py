def evaluate_iam_wildcard_policy(iam_data):
    findings = []
    for user in iam_data.get("users", []):
        for pol in user.get("policies", []):
            doc = pol.get("document", {})
            statements = doc.get("Statement", [])
            if isinstance(statements, dict):
                statements = [statements]

            for stmt in statements:
                if stmt.get("Effect") == "Allow":
                    action = stmt.get("Action", "")
                    resource = stmt.get("Resource", "")
                    # Check for permissive wildcard policies
                    if (action == "*" or (isinstance(action, list) and "*" in action)) and \
                       (resource == "*" or (isinstance(resource, list) and "*" in resource)):
                        findings.append({
                            "rule_id": "IAM_WILDCARD_POLICY",
                            "severity_raw": "CRITICAL",
                            "resource": {
                                "type": "AWS::IAM::User",
                                "id": user["user_name"],
                                "arn": user["arn"]
                            },
                            "status": "FAIL",
                            "risk_score": 0,
                            "score_breakdown": [],
                            "explanation": "",
                            "compliance_mappings": []
                        })
    return findings

def evaluate_iam_root_mfa(iam_data):
    findings = []
    account_summary = iam_data.get("account_summary", {})
    root_mfa_active = account_summary.get("AccountMFAEnabled", 0)

    if root_mfa_active == 0:
        findings.append({
            "rule_id": "IAM_ROOT_NO_MFA",
            "severity_raw": "CRITICAL",
            "resource": {
                "type": "AWS::IAM::RootAccount",
                "id": "root",
                "arn": "arn:aws:iam::root"
            },
            "status": "FAIL",
            "risk_score": 0,
            "score_breakdown": [],
            "explanation": "",
            "compliance_mappings": []
        })
    return findings