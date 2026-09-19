from .common import new_finding


def evaluate_s3_encryption(bucket_data, scan_id):
    """S3_NO_ENCRYPTION."""
    findings = []
    for b in bucket_data:
        encryption_enabled = bool(b.get("encryption"))
        if not encryption_enabled:
            name = b["name"]
            findings.append(new_finding(
                rule_id="S3_NO_ENCRYPTION",
                scan_id=scan_id,
                severity_raw="medium",
                resource_type="s3_bucket",
                resource_id=f"arn:aws:s3:::{name}",
                resource_name=name,
                region="global",
                context={"encryption_enabled": encryption_enabled},
            ))
    return findings


def evaluate_ebs_not_encrypted(ebs_data, scan_id):
    """EBS_NOT_ENCRYPTED.

    `snapshot_count` is deliberately not fetched (would require an extra
    describe_snapshots call per volume) since it is an unscored context key
    per docs/INTEGRATION_CONTRACT.md -- populating it would not change the
    risk score.
    """
    findings = []
    for vol in ebs_data:
        encryption_enabled = bool(vol.get("Encrypted", False))
        if not encryption_enabled:
            vol_id = vol["VolumeId"]
            attachments = vol.get("Attachments", [])
            attached_to_instance = any(a.get("State") == "attached" for a in attachments)
            findings.append(new_finding(
                rule_id="EBS_NOT_ENCRYPTED",
                scan_id=scan_id,
                severity_raw="medium",
                resource_type="ebs_volume",
                resource_id=f"arn:aws:ec2:::volume/{vol_id}",
                resource_name=vol_id,
                region=vol.get("AvailabilityZone", "unknown")[:-1] if vol.get("AvailabilityZone") else "unknown",
                context={
                    "encryption_enabled": encryption_enabled,
                    "attached_to_instance": attached_to_instance,
                    # "snapshot_count" intentionally omitted -- unscored, not worth an extra API call
                },
            ))
    return findings


def evaluate_rds_not_encrypted(rds_data, scan_id):
    """RDS_NOT_ENCRYPTED."""
    findings = []
    for db in rds_data:
        storage_encrypted = bool(db.get("StorageEncrypted", False))
        if not storage_encrypted:
            db_id = db["DBInstanceIdentifier"]
            findings.append(new_finding(
                rule_id="RDS_NOT_ENCRYPTED",
                scan_id=scan_id,
                severity_raw="medium",
                resource_type="rds_instance",
                resource_id=db.get("DBInstanceArn", f"arn:aws:rds:::db:{db_id}"),
                resource_name=db_id,
                region=db.get("AvailabilityZone", "unknown")[:-1] if db.get("AvailabilityZone") else "unknown",
                context={"storage_encrypted": storage_encrypted},
            ))
    return findings


def evaluate_rds_publicly_accessible(rds_data, scan_id):
    """RDS_PUBLICLY_ACCESSIBLE.

    `engine_version_supported` needs an external reference (AWS's published
    end-of-life engine version list) to determine reliably -- omitted
    rather than guessed. It's a real gap worth closing later, since the
    contract lists it as a live-scored factor (12 pts), not an unscored one.
    """
    findings = []
    for db in rds_data:
        publicly_accessible = bool(db.get("PubliclyAccessible", False))
        if publicly_accessible:
            db_id = db["DBInstanceIdentifier"]
            findings.append(new_finding(
                rule_id="RDS_PUBLICLY_ACCESSIBLE",
                scan_id=scan_id,
                severity_raw="high",
                resource_type="rds_instance",
                resource_id=db.get("DBInstanceArn", f"arn:aws:rds:::db:{db_id}"),
                resource_name=db_id,
                region=db.get("AvailabilityZone", "unknown")[:-1] if db.get("AvailabilityZone") else "unknown",
                context={
                    "publicly_accessible": publicly_accessible,
                    "storage_encrypted": bool(db.get("StorageEncrypted", False)),
                    # "engine_version_supported" intentionally omitted -- see docstring
                },
            ))
    return findings
