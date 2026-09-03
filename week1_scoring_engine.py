from __future__ import annotations
from typing import Any

BASE_SCORE_BY_SEVERITY = {
    "high": 75,
    "medium": 50,
    "low": 25,
}

RULE_SEVERITY = {
    "S3_PUBLIC_ACCESS": "high",
    "S3_NO_ENCRYPTION": "medium",
    "S3_NO_VERSIONING": "low",
    "IAM_WILDCARD_POLICY": "high",
    "IAM_ROOT_NO_MFA": "high",
    "IAM_USER_NO_MFA": "medium",
    "IAM_UNUSED_ACCESS_KEY": "low",
    "SG_OPEN_TO_WORLD": "high",
    "EBS_NOT_ENCRYPTED": "medium",
    "RDS_NOT_ENCRYPTED": "medium",
    "RDS_PUBLICLY_ACCESSIBLE": "high",
    "CLOUDTRAIL_DISABLED": "high",
}

SENSITIVE_NAME_KEYWORDS = (
    "customer", "statement", "transaction", "payment", "card",
    "ssn", "account", "financial", "billing", "pii",
)

PROD_NAME_KEYWORDS = ("prod", "production")


def _sensitive_name_factor(resource: dict) -> dict | None:
    name = resource.get("name", "").lower()
    if any(k in name for k in SENSITIVE_NAME_KEYWORDS):
        return {
            "factor": "sensitive_data_likely",
            "weight": 20,
            "description": f"Resource name '{resource.get('name')}' suggests sensitive/financial data (inferred from naming, not verified against content).",
        }
    return None


def _prod_name_factor(resource: dict) -> dict | None:
    name = resource.get("name", "").lower()
    if any(k in name for k in PROD_NAME_KEYWORDS):
        return {
            "factor": "attached_to_prod_resource",
            "weight": 10,
            "description": f"Resource name '{resource.get('name')}' suggests a production resource (inferred from naming).",
        }
    return None


def _rule_specific_factors(rule_id: str, raw_finding: dict) -> list[dict]:
    resource = raw_finding.get("resource", {})
    factors: list[dict] = []

    if rule_id == "S3_PUBLIC_ACCESS":
        factors.append({
            "factor": "public_read_access",
            "weight": 15,
            "description": "S3_PUBLIC_ACCESS rule fired: bucket ACL/policy grants public access.",
        })
        f = _sensitive_name_factor(resource)
        if f:
            factors.append(f)

    elif rule_id == "IAM_WILDCARD_POLICY":
        factors.append({
            "factor": "wildcard_action_resource",
            "weight": 15,
            "description": "IAM_WILDCARD_POLICY rule fired: policy grants Action:'*' and/or Resource:'*'.",
        })

    elif rule_id == "IAM_ROOT_NO_MFA":
        factors.append({
            "factor": "root_account_no_mfa",
            "weight": 15,
            "description": "Root account has no MFA -- highest-privilege identity in the account.",
        })

    elif rule_id == "SG_OPEN_TO_WORLD":
        factors.append({
            "factor": "open_to_world",
            "weight": 15,
            "description": "Security group allows inbound 0.0.0.0/0 on a sensitive port.",
        })
        f = _prod_name_factor(resource)
        if f:
            factors.append(f)

    elif rule_id == "RDS_PUBLICLY_ACCESSIBLE":
        factors.append({
            "factor": "publicly_accessible",
            "weight": 15,
            "description": "RDS instance is flagged as publicly accessible.",
        })
        f = _sensitive_name_factor(resource)
        if f:
            factors.append(f)

    elif rule_id == "CLOUDTRAIL_DISABLED":
        factors.append({
            "factor": "no_audit_trail",
            "weight": 15,
            "description": "No active multi-region CloudTrail trail for this account.",
        })

    elif rule_id in ("S3_NO_ENCRYPTION", "EBS_NOT_ENCRYPTED", "RDS_NOT_ENCRYPTED"):
        factors.append({
            "factor": "no_encryption_at_rest",
            "weight": 12,
            "description": f"{rule_id} rule fired: encryption at rest is disabled.",
        })
        f = _sensitive_name_factor(resource)
        if f:
            factors.append(f)

    elif rule_id == "IAM_USER_NO_MFA":
        factors.append({
            "factor": "console_access_no_mfa",
            "weight": 12,
            "description": "IAM user has console password access without MFA enabled.",
        })

    elif rule_id == "S3_NO_VERSIONING":
        factors.append({
            "factor": "no_versioning",
            "weight": 8,
            "description": "Bucket versioning is not enabled (no recovery from accidental delete/overwrite).",
        })

    elif rule_id == "IAM_UNUSED_ACCESS_KEY":
        factors.append({
            "factor": "unused_key_90_days",
            "weight": 10,
            "description": "Access key has not been used in 90+ days.",
        })

    return factors


def compute_score(raw_finding: dict[str, Any]) -> dict[str, Any]:
    rule_id = raw_finding["rule_id"]
    severity = raw_finding.get("severity_raw") or RULE_SEVERITY.get(rule_id)

    if severity not in BASE_SCORE_BY_SEVERITY:
        raise ValueError(f"Unknown severity '{severity}' for rule_id '{rule_id}'")

    base = BASE_SCORE_BY_SEVERITY[severity]

    score_breakdown = [{
        "factor": f"base_severity_{severity}",
        "weight": base,
        "description": f"Base score for {severity}-severity rule '{rule_id}', per shared/detection_rules.md.",
    }]

    score_breakdown.extend(_rule_specific_factors(rule_id, raw_finding))

    total = sum(f["weight"] for f in score_breakdown)
    risk_score = max(0, min(100, round(total)))

    enriched = dict(raw_finding)
    enriched["severity_raw"] = severity
    enriched["score_breakdown"] = score_breakdown
    enriched["risk_score"] = risk_score

    return enriched


def strip_to_raw(finding: dict[str, Any]) -> dict[str, Any]:
    raw = dict(finding)
    raw["score_breakdown"] = []
    raw["risk_score"] = 0
    return raw


if __name__ == "__main__":
    import json
    from pathlib import Path

    mock_path = Path(__file__).resolve().parent.parent / "shared" / "mock_findings.json"
    mock_findings = json.loads(mock_path.read_text())

    print(f"{'rule_id':<26} {'mock_score':>10} {'computed_score':>15}")

    for f in mock_findings:
        raw = strip_to_raw(f)
        enriched = compute_score(raw)
        print(f"{f['rule_id']:<26} {f['risk_score']:>10} {enriched['risk_score']:>15}")
