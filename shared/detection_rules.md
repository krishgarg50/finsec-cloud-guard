# Detection Rule List (Draft — v1)

This is the shared build checklist for P1 (detection engine) and reference for P2 (scoring/compliance).
Each rule below needs sign-off from P2 before Week 1 starts, since severity feeds directly into scoring weights.

| # | Rule ID | Resource Type | Check | AWS API / Data Source | Severity |
|---|---------|---------------|-------|------------------------|----------|
| 1 | S3_PUBLIC_ACCESS | s3_bucket | Bucket ACL or bucket policy allows public read/write | `s3:GetBucketAcl`, `s3:GetBucketPolicy`, `s3:GetPublicAccessBlock` | High |
| 2 | S3_NO_ENCRYPTION | s3_bucket | Bucket does not have default encryption (SSE) enabled | `s3:GetBucketEncryption` | Medium |
| 3 | S3_NO_VERSIONING | s3_bucket | Bucket does not have versioning enabled (helps ransomware/accidental-delete recovery) | `s3:GetBucketVersioning` | Low |
| 4 | IAM_WILDCARD_POLICY | iam_policy | Policy grants `"Action": "*"` and/or `"Resource": "*"` | `iam:GetPolicy`, `iam:GetPolicyVersion` | High |
| 5 | IAM_ROOT_NO_MFA | iam_user (root) | Root account does not have MFA enabled | `iam:GetAccountSummary` / `iam:GetCredentialReport` | High |
| 6 | IAM_USER_NO_MFA | iam_user | IAM user with console access does not have MFA enabled | `iam:GetCredentialReport` | Medium |
| 7 | IAM_UNUSED_ACCESS_KEY | iam_user | Access key unused for 90+ days (stale credential risk) | `iam:GetCredentialReport`, `iam:GetAccessKeyLastUsed` | Low |
| 8 | SG_OPEN_TO_WORLD | security_group | Inbound rule allows `0.0.0.0/0` on sensitive ports (22, 3389, 3306, 5432, etc.) | `ec2:DescribeSecurityGroups` | High |
| 9 | EBS_NOT_ENCRYPTED | ebs_volume | EBS volume does not have encryption enabled | `ec2:DescribeVolumes` | Medium |
| 10 | RDS_NOT_ENCRYPTED | rds_instance | RDS instance storage encryption disabled | `rds:DescribeDBInstances` | Medium |
| 11 | RDS_PUBLICLY_ACCESSIBLE | rds_instance | RDS instance flagged as publicly accessible | `rds:DescribeDBInstances` | High |
| 12 | CLOUDTRAIL_DISABLED | account/global | CloudTrail logging not enabled, or not multi-region | `cloudtrail:DescribeTrails`, `cloudtrail:GetTrailStatus` | High |

## Notes
- Severity here is the **base/raw severity** per rule — actual `risk_score` is computed later by P2's scoring engine, which may weight the same rule differently based on context (e.g. resource sensitivity, exposure combination with other findings).
- Rules 1–8 should be the priority build order for P1 in Week 1–2 (core AWS services: S3, IAM, EC2/SG). Rules 9–12 (EBS, RDS, CloudTrail) follow in Week 2–3.
- This list is intentionally kept to ~12 rules for the 8-week scope — expand later only if time allows, don't let this list grow before the demo is stable.
- P2: please confirm severity levels and flag any rule you think needs re-weighting before Week 1 starts.
