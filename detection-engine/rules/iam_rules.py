from datetime import datetime, timezone
from .common import new_finding


def evaluate_iam_wildcard_policy(iam_data, scan_id):
    """IAM_WILDCARD_POLICY.

    CHANGED FROM ORIGINAL: the contract's resource type for this rule is
    `iam_policy`, not `iam_user` -- a wildcard policy is one finding per
    policy, not one per (user, policy) pair. This version aggregates across
    all users to compute `attached_user_count` correctly, instead of
    reporting the same policy once per attached user with no count at all.

    `attached_role_count` is omitted -- the connector does not currently
    fetch role policy attachments (only user attachments), so there's no
    evidence to report. This is a real, open gap (see
    docs/INTEGRATION_CONTRACT.md item 5) worth closing later.
    """
    policy_map = {}  # policy_arn -> {name, wildcard_action, wildcard_resource, users:set}

    for user in iam_data.get("users", []):
        user_name = user["user_name"]
        for pol in user.get("policies", []):
            doc = pol.get("document", {})
            statements = doc.get("Statement", [])
            if isinstance(statements, dict):
                statements = [statements]

            wildcard_action = False
            wildcard_resource = False
            for stmt in statements:
                if stmt.get("Effect") == "Allow":
                    action = stmt.get("Action", "")
                    resource = stmt.get("Resource", "")
                    if action == "*" or (isinstance(action, list) and "*" in action):
                        wildcard_action = True
                    if resource == "*" or (isinstance(resource, list) and "*" in resource):
                        wildcard_resource = True

            if wildcard_action or wildcard_resource:
                pol_arn = pol.get("arn") or pol["name"]
                entry = policy_map.setdefault(pol_arn, {
                    "name": pol["name"],
                    "wildcard_action": False,
                    "wildcard_resource": False,
                    "users": set(),
                })
                entry["wildcard_action"] = entry["wildcard_action"] or wildcard_action
                entry["wildcard_resource"] = entry["wildcard_resource"] or wildcard_resource
                entry["users"].add(user_name)

    findings = []
    for pol_arn, info in policy_map.items():
        findings.append(new_finding(
            rule_id="IAM_WILDCARD_POLICY",
            scan_id=scan_id,
            severity_raw="high",
            resource_type="iam_policy",
            resource_id=pol_arn,
            resource_name=info["name"],
            region="global",
            context={
                "wildcard_action": info["wildcard_action"],
                "wildcard_resource": info["wildcard_resource"],
                "attached_user_count": len(info["users"]),
                # "attached_role_count" intentionally omitted -- see docstring
            },
        ))
    return findings


def evaluate_iam_root_mfa(iam_data, scan_id, account_id):
    """IAM_ROOT_NO_MFA.

    CHANGED FROM ORIGINAL: resource id now uses the real account id
    (fetched via STS) instead of a placeholder "root" ARN, so the finding
    is a genuinely resolvable ARN.
    """
    findings = []
    account_summary = iam_data.get("account_summary", {})
    mfa_enabled = bool(account_summary.get("AccountMFAEnabled", 0))

    if not mfa_enabled:
        findings.append(new_finding(
            rule_id="IAM_ROOT_NO_MFA",
            scan_id=scan_id,
            severity_raw="high",
            resource_type="iam_user",
            resource_id=f"arn:aws:iam::{account_id}:root",
            resource_name="root",
            region="global",
            context={
                "is_root": True,
                "mfa_enabled": mfa_enabled,
            },
        ))
    return findings


def evaluate_iam_user_no_mfa(iam_data, scan_id):
    """IAM_USER_NO_MFA.

    CHANGED FROM ORIGINAL: now reports `has_console_access` and
    `in_elevated_group` (both newly collected by connector.py) alongside
    `mfa_enabled`, instead of just severity/resource with no context at
    all. Firing condition (no MFA) is unchanged from the original rule --
    P2's scoring factors decide what these facts are worth, P1 just
    reports what it observed.
    """
    findings = []
    for user in iam_data.get("users", []):
        mfa_enabled = bool(user.get("mfa_active", False))
        if not mfa_enabled:
            findings.append(new_finding(
                rule_id="IAM_USER_NO_MFA",
                scan_id=scan_id,
                severity_raw="medium",
                resource_type="iam_user",
                resource_id=user["arn"],
                resource_name=user["user_name"],
                region="global",
                context={
                    "has_console_access": bool(user.get("has_console_access", False)),
                    "mfa_enabled": mfa_enabled,
                    "in_elevated_group": bool(user.get("in_elevated_group", False)),
                },
            ))
    return findings


def evaluate_iam_unused_access_key(iam_data, scan_id):
    """IAM_UNUSED_ACCESS_KEY.

    Resource type is `iam_user` per the contract. Finding granularity stays
    per-key (a user can have two keys, one stale and one active), so the
    resource id includes the key id suffix to keep finding_id stable and
    unique per key rather than colliding across a user's multiple keys.
    """
    findings = []
    now = datetime.now(timezone.utc)
    for user in iam_data.get("users", []):
        for key in user.get("access_keys", []):
            last_used = key.get("last_used_date")
            if last_used:
                days_unused = (now - last_used).days
                if days_unused > 90:
                    key_id = key["key_id"]
                    findings.append(new_finding(
                        rule_id="IAM_UNUSED_ACCESS_KEY",
                        scan_id=scan_id,
                        severity_raw="low",
                        resource_type="iam_user",
                        resource_id=f"{user['arn']}#{key_id}",
                        resource_name=user["user_name"],
                        region="global",
                        context={"unused_days": days_unused},
                    ))
    return findings
