# P2 Decisions Log -- Week 5

Resolves the "Open items needing a human decision" section of
`docs/INTEGRATION_CONTRACT.md` against P1's actual (rewritten) connector
code and a real scan run against a live AWS test account
(`scan_output.json`, scan-91bb53f1-a656-41ca-8132-48ad4c8ac9c3,
2026-09-19). Nothing below is speculative -- each item was checked against
either the real code or the real scan output before being marked resolved.

## Compliance mappings awaiting sign-off

`S3_NO_ENCRYPTION` -> PCI-DSS 3.4, SOC2 CC6.1, GLBA Safeguards Rule
`EBS_NOT_ENCRYPTED` -> PCI-DSS 3.4, GLBA Safeguards Rule

**Status: reviewed, recommended for confirmation, not yet formally closed.**
Both mappings are factually reasonable -- PCI-DSS 3.4 and the GLBA
Safeguards Rule both concern rendering stored data unreadable/protected,
which is exactly what these two rules check. P2 recommends confirming
these at the Week 7 sync so `PROPOSED_MAPPINGS` in `compliance.py` can be
cleared; a full sign-off needs the whole team's agreement, not just P2's
review, since a compliance mapping is a claim about a regulation.

## Contract questions for P1

### 1. Context completeness
**Status: mostly resolved, one new gap found.**

P1's rewritten connector explicitly documents (via code comments) that it
cannot currently populate: `public_write_access`, `attached_role_count`,
`snapshot_count`, `engine_version_supported`. These were already known and
are correctly listed in `UNSCORED_CONTEXT_KEYS` or absent from context
entirely -- no silent gap.

**New gap found from the real scan** (not previously documented): for
`SG_OPEN_TO_WORLD`, real security groups configured to allow all traffic
(rather than a specific port range) produce an empty `exposed_ports: []`
list. AWS omits `FromPort`/`ToPort` entirely for "all traffic" rules, and
the connector's port-range logic only populates `exposed_ports` when both
are present. Effect: the `sensitive_port` scoring factor cannot fire on
these findings, even though an all-traffic-open security group is at least
as severe as one open on a single sensitive port. Confirmed against real
data: `demo-open-sg-576c93` and `cspm-open-test` both scored only 40
(missing the sensitive-port bonus) when a genuinely fully-open security
group arguably deserves more. **Action: flag to P1 for Week 6** -- either
populate `exposed_ports` with the full sensitive-port list whenever the
rule allows all traffic (protocol `-1`), or explicitly send a distinct
signal (e.g. `all_traffic_open: true`) P2 can score directly.

### 2. `resource.type: "account"`
**Status: resolved.** Confirmed in the real scan: `CLOUDTRAIL_DISABLED`
sends `"resource": {"type": "account", ...}` exactly as the contract
describes. No action needed.

### 3. `finding_id` stability
**Status: resolved by design, recommend one more empirical check.**
P1's connector derives `finding_id` as a UUIDv5 of `(rule_id, resource_id)`,
which is deterministic -- the same misconfiguration on the same resource
produces the same ID on every scan, by construction, not by luck. This is
correct per the contract's requirement. Recommend P1 run two back-to-back
scans against the same demo resources before the actual review and confirm
the `finding_id` values are byte-for-byte identical across both runs, as a
belt-and-braces check before relying on it for the dashboard's reopen/trend
tracking.

### 4. Two spellings of storage encryption
**Status: resolved.** Confirmed against P1's actual rule files: `encryption_enabled`
is used for `S3_PUBLIC_ACCESS`, `S3_NO_ENCRYPTION`, and `EBS_NOT_ENCRYPTED`;
`storage_encrypted` is used for `RDS_NOT_ENCRYPTED` and
`RDS_PUBLICLY_ACCESSIBLE` -- matching the contract's table exactly, with no
mixing. No action needed.

### 5. Context keys that are collected but not scored
**Status: partially closed this week.**

- **`multi_region_trail` (CLOUDTRAIL_DISABLED): now scored.** Real data
  confirms P1 sends this key (`"multi_region_trail": false` in the real
  scan). A new factor, `single_region_trail_only` (10 pts), was added this
  week: it fires only when a trail exists but isn't multi-region, avoiding
  double-charging the same underlying gap that `no_active_trail` (45 pts)
  already covers when no trail exists at all. Removed from
  `UNSCORED_CONTEXT_KEYS`. All 232 tests pass after this change (one
  existing test's expected `missing_evidence` set was updated to reflect
  the new required key).
- **`block_public_access` (S3_PUBLIC_ACCESS): remains unscored, by
  decision, not by gap.** The contract's own reasoning holds: this is the
  account-level control that would have prevented the public ACL already
  being scored 40+25 points. Scoring it too would charge twice for one
  exposure. Decision: leave unscored, and this reasoning is now recorded
  here so a future reader does not mistake it for an oversight.
- **`attached_role_count` (IAM_WILDCARD_POLICY) and `snapshot_count`
  (EBS_NOT_ENCRYPTED): remain unscored, genuinely blocked on P1.** Neither
  has a data source yet -- P1's connector does not fetch role policy
  attachments or EBS snapshot counts. This is not a P2 decision to make;
  it requires P1 to add the underlying AWS API calls first. Left in
  `UNSCORED_CONTEXT_KEYS` until that happens.

## Summary for the team

Of 5 open items: 3 fully resolved (account type, finding_id design,
encryption spelling), 1 newly and properly scored (multi_region_trail), 1
compliance sign-off recommended but pending team confirmation, and 1 new
gap discovered from real data (SG_OPEN_TO_WORLD's empty exposed_ports on
all-traffic rules) that needs P1's attention before the review demo, since
it currently makes a fully-open security group score no higher than a
single-port exposure.
