# Integration contract

> **Generated file -- do not edit by hand.**
> Regenerate with `python scripts/generate_contract_doc.py`;
> `--check` fails the build when it is stale.

This is the agreement between the three workstreams. It is derived from
`p2_scoring/rules.py`, `p2_scoring/compliance.py` and
`p2_scoring/enrich.py`, so it cannot describe a system that does not exist.

## The pipeline

```
  P1  AWS connector
      |  raw finding JSON        (schema/raw_finding_schema.json)
      v
  P2  enrich_findings()
      |  + risk_score, score_breakdown, explanation, compliance_mappings
      v
  P3  POST /scan  ->  SQLite  ->  dashboard
```

P2 is a pure function over P1's output: no network, no database, no AWS
credentials. That is why both sides can be built and tested in parallel
against `data/mock_findings.raw.json` before either is finished.

## What P1 must emit (raw finding)

| field | | meaning |
|---|---|---|
| `finding_id` | required | Stable id for this finding. Must be stable across scans -- it is the primary key P3 upserts on, so a changing id re-alerts a finding every scan. |
| `rule_id` | required | One of the rule ids in the table below. An unknown id is rejected, not ignored (see 'Failure policy'). |
| `scan_id` | required | Identifier of the scan run that produced this finding. |
| `resource` | required | ``{type, id, name, region}``. ``name`` is used by P2 to derive sensitivity, so a name like ``customer-statements-backup`` scores higher than ``test-bucket`` on the same rule. |
| `detection_source` | required | ``rule_engine`` or ``anomaly_detection``. |
| `severity_raw` | required | P1's own severity. Kept for display; it does **not** feed the risk score. |
| `context` | required | The observed facts. This is the whole reason the pipeline can explain itself -- see per-rule keys below. |
| `detected_at` | required | ISO-8601 UTC, when the misconfiguration was first observed in the environment. |
| `last_seen_at` | required | ISO-8601 UTC, most recent observation. |
| `status` | optional | Defaults to ``open``. P3 owns the lifecycle after that. |

Authoritative schema: `schema/raw_finding_schema.json`.

P1 does not compute a score, a band, an explanation or a compliance
mapping. Those are P2's, and duplicating them is how two teams end up
disagreeing about the same number.

## Per-rule context the scorer reads

A factor only counts when the keys in its **requires** column are present
and non-null. A missing key means *unknown*, never *safe* and never *bad*:
the factor is skipped, and the finding scores lower with the gap reported.
That is deliberate -- scoring `{}` as if it said `active_trail_count: 0`
manufactures a critical finding out of data nobody sent.

`(derived)` marks a factor driven by the resource name, which is always
present, so it needs no context key.

### `S3_PUBLIC_ACCESS` -- S3 bucket is publicly accessible

- **Resource types:** `s3_bucket`
- **P1's severity:** `high`
- **Maximum score:** 117 (capped at 100 overall)
- **Score after remediation:** 15 -- Fixing the ACL removes the exposure, but the bucket name and data classification keep a residual 'sensitive data at rest' risk that a future policy change could re-expose.
- **Frameworks:** PCI-DSS, SOC2

**Context keys for this rule**

- `public_read_access` -- scores `public_read_access`
- `public_write_access` -- scores `public_write_access`
- `encryption_enabled` -- scores `no_encryption`
- `block_public_access` -- **not scored.** No factor reads this today; sending
  it will not change the risk score. Listed so the gap is visible.

**Scoring factors**

| factor | points | fires when | requires |
|---|---|---|---|
| `public_read_access` | 40 | Bucket ACL grants public read access | `public_read_access` |
| `public_write_access` | 25 | Bucket ACL grants public write access to anyone | `public_write_access` |
| `sensitive_data_likely` | 30 | Bucket name suggests customer financial data | _(derived)_ |
| `no_encryption` | 22 | Default encryption is not enabled | `encryption_enabled` |

### `S3_NO_ENCRYPTION` -- S3 bucket has no default encryption

- **Resource types:** `s3_bucket`
- **P1's severity:** `medium`
- **Maximum score:** 70 (capped at 100 overall)
- **Score after remediation:** 20 -- Enabling SSE-KMS closes the finding; residual reflects key-rotation and access-policy drift on the newly created key.
- **Frameworks:** PCI-DSS, SOC2, GLBA

**Context keys for this rule**

- `encryption_enabled` -- scores `no_encryption`

**Scoring factors**

| factor | points | fires when | requires |
|---|---|---|---|
| `no_encryption` | 40 | Bucket does not have default encryption (SSE) enabled | `encryption_enabled` |
| `sensitive_data_likely` | 30 | Bucket name suggests customer financial data | _(derived)_ |

### `S3_NO_VERSIONING` -- S3 bucket versioning is disabled

- **Resource types:** `s3_bucket`
- **P1's severity:** `low`
- **Maximum score:** 28 (capped at 100 overall)
- **Score after remediation:** 8 -- Versioning restores recoverability; the small remainder covers the storage-cost and lifecycle-policy follow-up work.
- **Frameworks:** SOC2

**Context keys for this rule**

- `versioning_enabled` -- scores `no_versioning`
- `backup_configured` -- scores `no_recovery_mechanism`

**Scoring factors**

| factor | points | fires when | requires |
|---|---|---|---|
| `no_versioning` | 18 | Bucket versioning is not enabled | `versioning_enabled` |
| `no_recovery_mechanism` | 10 | No backup mechanism identified for this bucket | `backup_configured` |

### `IAM_WILDCARD_POLICY` -- IAM policy grants wildcard action/resource

- **Resource types:** `iam_policy`
- **P1's severity:** `high`
- **Maximum score:** 88 (capped at 100 overall)
- **Score after remediation:** 20 -- A scoped policy removes the wildcard, but replacing an in-use admin policy carries breakage risk that keeps the finding on the audit list until the migration is fully verified.
- **Frameworks:** PCI-DSS, SOC2

**Context keys for this rule**

- `wildcard_action` -- scores `wildcard_action`
- `wildcard_resource` -- scores `wildcard_resource`
- `attached_user_count` -- scores `attached_to_multiple_users`
- `attached_role_count` -- **not scored.** No factor reads this today; sending
  it will not change the risk score. Listed so the gap is visible.

**Scoring factors**

| factor | points | fires when | requires |
|---|---|---|---|
| `wildcard_action` | 35 | Policy grants Action: '*' across all services | `wildcard_action` |
| `wildcard_resource` | 35 | Policy grants Resource: '*' | `wildcard_resource` |
| `attached_to_multiple_users` | 18 | Policy is attached to {user_count} IAM users | `attached_user_count` |

### `IAM_ROOT_NO_MFA` -- Root account has no MFA

- **Resource types:** `iam_user`, `account`
- **P1's severity:** `high`
- **Maximum score:** 85 (capped at 100 overall)
- **Score after remediation:** 10 -- Enrolling MFA resolves it, but the root account always retains unrestricted capability and cannot be eliminated entirely.
- **Frameworks:** PCI-DSS, SOC2

**Context keys for this rule**

- `is_root` -- scores `root_account`
- `mfa_enabled` -- scores `no_mfa`

**Scoring factors**

| factor | points | fires when | requires |
|---|---|---|---|
| `root_account` | 45 | Finding applies to the root account, which has unrestricted access | `is_root` |
| `no_mfa` | 40 | Multi-factor authentication is not enabled | `mfa_enabled` |

### `IAM_USER_NO_MFA` -- IAM user with console access has no MFA

- **Resource types:** `iam_user`
- **P1's severity:** `medium`
- **Maximum score:** 55 (capped at 100 overall)
- **Score after remediation:** 20 -- MFA enrollment closes the technical gap; residual covers the behavioural risk of a user who was previously phishable.
- **Frameworks:** PCI-DSS

**Context keys for this rule**

- `has_console_access` -- scores `console_access_no_mfa`
- `mfa_enabled` -- scores `console_access_no_mfa`, `elevated_access_without_mfa`
- `in_elevated_group` -- scores `has_elevated_permissions`, `elevated_access_without_mfa`

**Scoring factors**

| factor | points | fires when | requires |
|---|---|---|---|
| `console_access_no_mfa` | 35 | User has console password access without MFA enabled | `has_console_access`, `mfa_enabled` |
| `has_elevated_permissions` | 15 | User is a member of a group with elevated permissions | `in_elevated_group` |
| `elevated_access_without_mfa` | 5 | Elevated permissions protected only by a phishable password | `in_elevated_group`, `mfa_enabled` |

### `IAM_UNUSED_ACCESS_KEY` -- IAM access key unused for 90+ days

- **Resource types:** `iam_user`
- **P1's severity:** `low`
- **Maximum score:** 35 (capped at 100 overall)
- **Score after remediation:** 5 -- Deactivating the key removes the credential; a 5-point floor remains because the account itself may still exist.
- **Frameworks:** SOC2

**Context keys for this rule**

- `unused_days` -- scores `unused_key_90_days`

**Scoring factors**

| factor | points | fires when | requires |
|---|---|---|---|
| `unused_key_90_days` | 25 | Access key has not been used in over {days} days | `unused_days` |
| `user_likely_inactive` | 10 | Username suggests a former contractor account | _(derived)_ |

### `SG_OPEN_TO_WORLD` -- Security group open to 0.0.0.0/0

- **Resource types:** `security_group`
- **P1's severity:** `high`
- **Maximum score:** 80 (capped at 100 overall)
- **Score after remediation:** 18 -- Restricting the CIDR range closes the finding, but the group stays production-attached, so it remains worth re-checking each scan.
- **Frameworks:** PCI-DSS, SOC2

**Context keys for this rule**

- `open_cidrs` -- scores `open_to_world`, `sensitive_port`
- `exposed_ports` -- scores `sensitive_port`
- `attached_to_prod` -- scores `attached_to_prod_instance`

**Scoring factors**

| factor | points | fires when | requires |
|---|---|---|---|
| `open_to_world` | 40 | Inbound rule allows 0.0.0.0/0 | `open_cidrs` |
| `sensitive_port` | 30 | Port {first_sensitive_port} ({first_sensitive_service}) is exposed to the internet | `open_cidrs`, `exposed_ports` |
| `attached_to_prod_instance` | 10 | Security group is attached to a production-tagged instance | `attached_to_prod` |

### `EBS_NOT_ENCRYPTED` -- EBS volume is not encrypted

- **Resource types:** `ebs_volume`
- **P1's severity:** `medium`
- **Maximum score:** 70 (capped at 100 overall)
- **Score after remediation:** 22 -- EBS encryption cannot be toggled in place; residual reflects the snapshot-and-recreate migration window.
- **Frameworks:** PCI-DSS, GLBA

**Context keys for this rule**

- `encryption_enabled` -- scores `no_storage_encryption`
- `attached_to_instance` -- scores `attached_to_running_instance`
- `snapshot_count` -- **not scored.** No factor reads this today; sending
  it will not change the risk score. Listed so the gap is visible.

**Scoring factors**

| factor | points | fires when | requires |
|---|---|---|---|
| `no_storage_encryption` | 40 | EBS volume does not have encryption enabled | `encryption_enabled` |
| `attached_to_running_instance` | 15 | Volume is attached to a running instance | `attached_to_instance` |
| `sensitive_data_likely` | 15 | Volume name or tags suggest it holds sensitive data | _(derived)_ |

### `RDS_NOT_ENCRYPTED` -- RDS instance storage is not encrypted

- **Resource types:** `rds_instance`
- **P1's severity:** `medium`
- **Maximum score:** 62 (capped at 100 overall)
- **Score after remediation:** 25 -- RDS cannot encrypt in place, so the reading stays elevated until the migrated instance is cut over and the original is destroyed.
- **Frameworks:** PCI-DSS, GLBA

**Context keys for this rule**

- `storage_encrypted` -- scores `no_storage_encryption`

**Scoring factors**

| factor | points | fires when | requires |
|---|---|---|---|
| `no_storage_encryption` | 40 | Storage encryption is disabled on this instance | `storage_encrypted` |
| `sensitive_data_likely` | 22 | Database name suggests financial transaction data | _(derived)_ |

### `RDS_PUBLICLY_ACCESSIBLE` -- RDS instance is publicly accessible

- **Resource types:** `rds_instance`
- **P1's severity:** `high`
- **Maximum score:** 90 (capped at 100 overall)
- **Score after remediation:** 20 -- Moving the instance into a private subnet closes the finding; residual covers the subnet-routing review and any lingering security-group path to it.
- **Frameworks:** PCI-DSS, GLBA

**Context keys for this rule**

- `publicly_accessible` -- scores `publicly_accessible`, `public_exposure_without_encryption`
- `storage_encrypted` -- scores `no_encryption`, `public_exposure_without_encryption`
- `engine_version_supported` -- scores `outdated_engine_version`

**Scoring factors**

| factor | points | fires when | requires |
|---|---|---|---|
| `publicly_accessible` | 45 | Instance is flagged as publicly accessible | `publicly_accessible` |
| `no_encryption` | 25 | Storage encryption is also disabled on this instance | `storage_encrypted` |
| `outdated_engine_version` | 12 | Database engine version is past its support window | `engine_version_supported` |
| `public_exposure_without_encryption` | 8 | Public reachability combined with unencrypted storage compounds exposure | `publicly_accessible`, `storage_encrypted` |

### `CLOUDTRAIL_DISABLED` -- CloudTrail logging is not enabled

- **Resource types:** `account`
- **P1's severity:** `high`
- **Maximum score:** 78 (capped at 100 overall)
- **Score after remediation:** 12 -- Enabling a multi-region trail fixes it going forward, but activity before the change is permanently unrecorded.
- **Frameworks:** PCI-DSS, SOC2

**Context keys for this rule**

- `active_trail_count` -- scores `no_active_trail`
- `multi_region_trail` -- **not scored.** No factor reads this today; sending
  it will not change the risk score. Listed so the gap is visible.
- `has_log_history` -- scores `no_audit_log_history`

**Scoring factors**

| factor | points | fires when | requires |
|---|---|---|---|
| `no_active_trail` | 45 | No active CloudTrail trail found for this account | `active_trail_count` |
| `no_audit_log_history` | 33 | No API activity history available for investigation | `has_log_history` |

## What P2 emits (enriched finding)

Fields, in the order `enrich.py` writes them:

- `finding_id`
- `rule_id`
- `scan_id`
- `resource`
- `detection_source`
- `severity_raw`
- `risk_score`
- `score_breakdown`
- `compliance_mappings`
- `explanation`
- `status`
- `detected_at`
- `last_seen_at`
- `context`

Authoritative schema: `schema/finding_schema.json`.

Note `context` is carried through to the output. It is an **additive**
extension permitted by the schema, and it is what lets the dashboard show
`observed facts -> factors -> score` as one traceable chain.

### The arithmetic guarantee

```
risk_score == min(100, sum(f.weight for f in score_breakdown))
```

`score_breakdown` is not a summary of the score; it *is* the score. When
the raw factor total would exceed 100, a single negative
`score_cap_adjustment` entry is appended so the sum still reconciles.
`tests/test_scoring.py` asserts this for every rule, and
`tests/test_seed_reconciliation.py` asserts it against the hand-authored
seed findings.

### Risk bands

Bands are computed from the score, never stored in the finding document:

| band | score |
|---|---|
| `critical` | 80-100 |
| `high` | 60-79 |
| `medium` | 40-59 |
| `low` | 0-39 |

## What P3 adds

P3 stores the enriched document verbatim alongside denormalised columns
for filtering and aggregation, and owns the fields P2 does not:

- `status` -- `open`, `acknowledged`, `remediated`, `false_positive`
- `reopen_count` -- incremented when a `remediated` finding reappears
- `first_seen_at` -- when this system first stored the finding

`remediated` is **not permanent**: if a later scan sees the same
`finding_id` again, the finding reopens and `reopen_count` increments. A
fix that did not stick has to surface, not quietly disappear.
`acknowledged` and `false_positive` are never overridden by a scan. In both
cases a human already made the call, and a scanner that re-flags the same
misconfiguration every night would make them re-decide it every night --
which is the workflow the human statuses exist to prevent.

## Open items needing a human decision

### Compliance mappings awaiting sign-off

These rules had no precedent in the Week-0 mock findings. Their
mappings are proposed, not agreed, and a compliance mapping is a claim
about a regulation rather than a code comment:

- `EBS_NOT_ENCRYPTED` -> PCI-DSS 3.4, GLBA Safeguards Rule
- `S3_NO_ENCRYPTION` -> PCI-DSS 3.4, SOC2 CC6.1, GLBA Safeguards Rule

### Contract questions for P1

1. **Context completeness.** Can the connector populate every key in the
   per-rule tables above? Anything it cannot should be named now, so the
   affected factors can be redesigned rather than scoring 0 in silence.
2. **`resource.type: "account"`.** Account-level rules such as
   `CLOUDTRAIL_DISABLED` have no resource ARN. The agreed vocabulary did
   not list `account`, so it was added to the schema description -- confirm
   that is the value the connector will send.
3. **`finding_id` stability.** It is P3's primary key. If the connector
   derives it from anything that changes between scans (a timestamp, a
   run counter), every scan will look like a fresh set of findings and the
   dashboard's trend line will be meaningless.
4. **Two spellings of storage encryption.** Confirmed with the connector:

   | rule | key it reads |
   |---|---|
   | `S3_PUBLIC_ACCESS` | `encryption_enabled` |
   | `S3_NO_ENCRYPTION` | `encryption_enabled` |
   | `EBS_NOT_ENCRYPTED` | `encryption_enabled` |
   | `RDS_NOT_ENCRYPTED` | `storage_encrypted` |
   | `RDS_PUBLICLY_ACCESSIBLE` | `storage_encrypted` |

   Both spellings came from the agreed mock findings, so both are
   faithfully implemented -- but they are one concept, and a connector that
   sends `storage_encrypted` on an S3 bucket will have that factor scored
   as *missing evidence* rather than as encryption status. Pick one spelling
   per concept (or send both) before integration.

5. **Context keys that are collected but not scored.** These are declared by
   a rule and sent by the connector, but no scoring factor reads them, so
   populating them changes no risk score:

   | rule | key |
   |---|---|
   | `S3_PUBLIC_ACCESS` | `block_public_access` |
   | `IAM_WILDCARD_POLICY` | `attached_role_count` |
   | `EBS_NOT_ENCRYPTED` | `snapshot_count` |
   | `CLOUDTRAIL_DISABLED` | `multi_region_trail` |

   Nothing is broken -- the scores are correct, they simply ignore these
   fields. The question for the review is whether each *should* score, and
   the answer is not obvious from the code:

   - `block_public_access` (S3) is the account-level control that would
     have prevented the public ACL the rule already scores 40 + 25 for.
     Scoring it would charge twice for one exposure, so leaving it out may
     be right -- but then it does not need to be in the contract.
   - `attached_role_count` (IAM) is unscored while `attached_user_count` is
     worth 18. Broad attachment is the risk either way, so the asymmetry
     looks like an omission rather than a decision.
   - `snapshot_count` (EBS) and `multi_region_trail` (CloudTrail) have no
     factor at all.

   Either add a factor or drop the key from `context_keys`. Until one of
   those happens the key sits in `UNSCORED_CONTEXT_KEYS`, which
   `tests/test_rule_table.py` keeps honest in both directions.

