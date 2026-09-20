from .common import new_finding


def evaluate_cloudtrail_status(trail_data, scan_id, account_id):
    """CLOUDTRAIL_DISABLED.

    CHANGED FROM ORIGINAL: resource id now uses the real account id, and
    `active_trail_count` / `has_log_history` are real observed facts
    instead of an empty context. `has_log_history` is inferred as "true
    when at least one trail is actively logging" -- a reasonable proxy
    since confirming actual log file delivery would need a
    lookup_events/S3 check this connector doesn't perform.
    """
    active_trails = [t for t in trail_data if t.get("is_logging", False)]
    active_trail_count = len(active_trails)
    multi_region_trail = any(t.get("is_multi_region", False) for t in active_trails)

    findings = []
    if active_trail_count == 0:
        findings.append(new_finding(
            rule_id="CLOUDTRAIL_DISABLED",
            scan_id=scan_id,
            severity_raw="high",
            resource_type="account",
            resource_id=f"arn:aws:cloudtrail::{account_id}:trail/none",
            resource_name=f"account-{account_id}",
            region="global",
            context={
                "active_trail_count": active_trail_count,
                "has_log_history": active_trail_count > 0,  # proxy, see docstring
                "multi_region_trail": multi_region_trail,   # unscored today, sent for visibility
            },
        ))
    return findings
