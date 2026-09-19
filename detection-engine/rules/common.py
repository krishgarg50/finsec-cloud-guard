"""Shared helpers for building raw findings that conform to
shared/raw_finding_schema.json (P1 -> P2 contract).

Every rule module builds its findings through `new_finding()` so the
top-level shape (finding_id, scan_id, timestamps, detection_source,
status) is generated in exactly one place instead of being duplicated
-- and possibly drifting -- in every rule file.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Mapping

# Name substrings that suggest a resource is production-facing. Used for the
# SG_OPEN_TO_WORLD rule's `attached_to_prod` context key. This is a naming
# heuristic on the security group's own name/description, since correlating
# to an actual attached instance's tags would require an extra
# describe_instances call this connector does not currently make.
PROD_NAME_HINTS = ("prod", "production")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def new_finding(
    *,
    rule_id: str,
    scan_id: str,
    severity_raw: str,
    resource_type: str,
    resource_id: str,
    resource_name: str,
    region: str,
    context: Mapping[str, Any],
) -> dict:
    """Build one raw finding conforming to shared/raw_finding_schema.json.

    `finding_id` is derived deterministically from (rule_id, resource_id)
    rather than a fresh random UUID per scan. Per
    docs/INTEGRATION_CONTRACT.md item 3: finding_id is P3's upsert key, so a
    changing id would make every scan look like a fresh set of findings and
    break the dashboard's trend/reopen tracking. Using a stable UUIDv5
    (namespace + rule_id + resource_id) means the same misconfiguration on
    the same resource produces the same finding_id on every scan, while
    still being a valid, opaque UUID string.
    """
    stable_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"finsec:{rule_id}:{resource_id}"))
    timestamp = now_iso()

    return {
        "finding_id": stable_id,
        "rule_id": rule_id,
        "scan_id": scan_id,
        "resource": {
            "type": resource_type,
            "id": resource_id,
            "name": resource_name,
            "region": region,
        },
        "detection_source": "rule_engine",
        "severity_raw": severity_raw,
        "context": dict(context),
        "detected_at": timestamp,
        "last_seen_at": timestamp,
        "status": "open",
    }
