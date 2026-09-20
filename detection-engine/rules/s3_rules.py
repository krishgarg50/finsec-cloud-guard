from .common import new_finding


def evaluate_s3_public_access(bucket_data, scan_id):
    """S3_PUBLIC_ACCESS.

    KNOWN LIMITATION: the connector currently checks the bucket's Public
    Access Block (PAB) configuration, not the bucket ACL/policy grants
    directly. `public_read_access` is therefore an approximation: "PAB is
    not fully enabled" is treated as "public read may be possible", which
    is the same trigger condition the original (pre-fix) rule used. This is
    a reasonable proxy for a demo but is not the same as confirming an
    actual public grant via GetBucketAcl/GetBucketPolicyStatus -- flag to
    the team if a stricter check is wanted before the real demo.
    `public_write_access` has no data source at all yet, so it is omitted
    (treated as "unknown" by P2, not "false") rather than guessed.
    """
    findings = []
    for b in bucket_data:
        pab = b.get("public_access_block", {})
        is_pab_enabled = (
            pab.get("BlockPublicAcls", False) and
            pab.get("IgnorePublicAcls", False) and
            pab.get("BlockPublicPolicy", False) and
            pab.get("RestrictPublicBuckets", False)
        )

        if not is_pab_enabled:
            name = b["name"]
            findings.append(new_finding(
                rule_id="S3_PUBLIC_ACCESS",
                scan_id=scan_id,
                severity_raw="high",
                resource_type="s3_bucket",
                resource_id=f"arn:aws:s3:::{name}",
                resource_name=name,
                region="global",
                context={
                    "public_read_access": True,     # see docstring: PAB-based proxy
                    "encryption_enabled": bool(b.get("encryption")),
                    "block_public_access": is_pab_enabled,  # unscored today, sent for visibility
                    # "public_write_access" intentionally omitted -- no evidence collected
                },
            ))
    return findings


def evaluate_s3_no_versioning(bucket_data, scan_id):
    """S3_NO_VERSIONING.

    `backup_configured` has no data source (no separate backup/AWS Backup
    check implemented) so it is omitted rather than guessed.
    """
    findings = []
    for b in bucket_data:
        name = b["name"]
        versioning_enabled = b.get("versioning") == "Enabled"
        if not versioning_enabled:
            findings.append(new_finding(
                rule_id="S3_NO_VERSIONING",
                scan_id=scan_id,
                severity_raw="low",
                resource_type="s3_bucket",
                resource_id=f"arn:aws:s3:::{name}",
                resource_name=name,
                region="global",
                context={
                    "versioning_enabled": versioning_enabled,
                    # "backup_configured" intentionally omitted -- no evidence collected
                },
            ))
    return findings
