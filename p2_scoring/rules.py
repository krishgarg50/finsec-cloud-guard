"""Scoring rule definitions for P2.

This module is the single source of truth for *how a raw finding becomes a
risk score*. It is deliberately dependency-free (stdlib only) so P2's owner can
run and test it without installing anything, and so P1 can import it to learn
which `context` keys a rule expects.

Design
------
Every rule declares an ordered list of `Factor`s. Each factor has:

  * `key`      - stable identifier, appears verbatim in `score_breakdown[].factor`
  * `points`   - how many points it contributes to the risk score
  * `template` - human-readable justification, `.format()`-ed against the signals
  * `applies`  - predicate over the observed signals; the factor only counts if True
  * `requires` - the `context` keys that must actually be present for this factor
                 to be evaluable at all (see "Evidence" below)

The engine (see ``scoring.py``) computes::

    risk_score = min(100, sum(f.points for f in factors if f.applies(signals)))

That identity is the whole point of the project: **the breakdown an auditor
reads is literally the arithmetic that produced the score**. There is no hidden
term. ``tests/test_scoring.py`` asserts this invariant for every rule.

Evidence (and why `requires` exists)
------------------------------------
A missing context key is not the same as a negative observation.

  * ``{"active_trail_count": 0}``  -> P1 looked, found no trail. Genuine finding.
  * ``{}``                          -> P1 said nothing. We do not know.

Without `requires`, a factor like "no active trail" evaluates as ``count == 0``
and fires on the *unknown* case too, scoring a resource 78/100 on the strength
of data nobody supplied. Every ``_no(...)``-style factor is a false-positive
generator under that rule, so each one names the keys it needs and is skipped
entirely when they are absent. Explicit ``null`` counts as absent.

The consequence is visible in the pipeline: a rule that fires with no usable
evidence scores 0 and ``enrich.py`` reports it as a likely P1 contract gap,
instead of the dashboard showing a confident 78.

Synergy factors
---------------
Two rules carry an extra factor that only fires when two lower-level factors
co-occur (`public_exposure_without_encryption`, `elevated_access_without_mfa`).
This is intentional and matches the note in ``detection_rules.md`` that scoring
"may weight the same rule differently based on context (e.g. resource
sensitivity, exposure combination with other findings)". Exposure that compounds
is worth more than the sum of its parts, and the score card says so explicitly
rather than burying it in a multiplier.

Adding a rule
-------------
1. Add a ``DetectionRule`` to ``RULES``.
2. Add matching entries in ``compliance.py`` and ``explanations.py``.
3. Regenerate the contract P1 reads: ``python scripts/generate_contract_doc.py``.

``tests/test_rule_table.py`` fails if any of the three registries disagree or if
a declared ``context_key`` is unreadable, so a rule cannot be half-added by
accident. The contract document is generated rather than edited, because a
hand-maintained restatement of the table below is guaranteed to drift, and a
drifted contract is worse than none: P1 would populate keys nobody reads while
the keys that actually drive scores stay empty.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Mapping

# --------------------------------------------------------------------------
# Derived-signal heuristics
# --------------------------------------------------------------------------
# These let P2 squeeze context out of data P1 already sends (the resource name)
# instead of demanding an extra API call for every nuance. Factors driven purely
# by these need no `requires`, because the resource name is always present.

SENSITIVE_NAME_HINTS: tuple[str, ...] = (
    "customer",
    "statement",
    "transaction",
    "payment",
    "card",
    "billing",
    "invoice",
    "payroll",
    "ledger",
    "account",
    "finance",
    "financial",
    "kyc",
    "fraud",
    "loan",
    "credit",
    "bank",
    "personal",
    "pii",
    "patient",
    "userdata",
    "user-data",
    "backup",
)

INACTIVE_USER_HINTS: tuple[str, ...] = (
    "former",
    "contractor",
    "temp",
    "intern",
    "vendor",
    "external",
    "legacy",
    "old",
    "departed",
    "offboard",
)

#: Ports that should essentially never be reachable from 0.0.0.0/0.
SENSITIVE_PORTS: Mapping[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    1433: "MSSQL",
    1521: "Oracle DB",
    2375: "Docker daemon",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    9200: "Elasticsearch",
    11211: "Memcached",
    27017: "MongoDB",
    27018: "MongoDB",
}

#: Score bands used by the dashboard for colouring/grouping. The schema's
#: `risk_score` is a bare 0-100 number; bands are a presentation concern layered
#: on top, and are computed by P3 rather than persisted into the finding doc.
SEVERITY_BANDS: tuple[tuple[int, str], ...] = (
    (80, "critical"),
    (60, "high"),
    (40, "medium"),
    (0, "low"),
)


def risk_band(risk_score: float) -> str:
    """Map a 0-100 risk score onto a presentation band."""
    for threshold, band in SEVERITY_BANDS:
        if risk_score >= threshold:
            return band
    return "low"


#: Context keys a rule declares in ``context_keys`` that **no factor reads**.
#:
#: These are not a bug in themselves -- P1 already collects them, and the
#: contract document is more useful showing what arrives than pretending the
#: field does not exist. But they must be named here, because the alternative is
#: a declaration that is silently dead: `docs/INTEGRATION_CONTRACT.md` tells P1
#: to send them, and a reader reasonably assumes a factor consumes each one.
#:
#: ``test_rule_table.py`` requires every declared key to be either read by a
#: factor, consumed by ``signals.derive_signals``, or listed here. So this set is
#: a ledger of accepted gaps -- adding to it is a deliberate act, and a typo'd
#: ``requires=`` (``attached_role_counts`` vs the declared ``attached_role_count``)
#: cannot hide inside it. Each entry is surfaced to a human in the generated
#: contract's open-items section rather than left as a footnote.
UNSCORED_CONTEXT_KEYS: frozenset[str] = frozenset(
    {
        "block_public_access",  # S3_PUBLIC_ACCESS
        "attached_role_count",  # IAM_WILDCARD_POLICY
        "snapshot_count",  # EBS_NOT_ENCRYPTED
        "multi_region_trail",  # CLOUDTRAIL_DISABLED
    }
)


@dataclass(frozen=True)
class Factor:
    """One contributing reason a finding is risky."""

    key: str
    points: int
    template: str
    applies: Callable[[Mapping[str, Any]], bool]
    #: Context keys that must be present (and non-null) for this factor to count.
    #: Empty means the factor depends only on derived signals (e.g. the resource
    #: name), which are always available.
    requires: tuple[str, ...] = ()

    def describe(self, signals: Mapping[str, Any]) -> str:
        return self.template.format(**signals)


@dataclass(frozen=True)
class DetectionRule:
    """A detection rule plus the scoring metadata P2 attaches to it."""

    rule_id: str
    title: str
    base_severity: str
    resource_types: tuple[str, ...]
    factors: tuple[Factor, ...]
    residual_score: int
    residual_rationale: str
    #: `context` keys P1 is expected to populate, documented for the contract.
    context_keys: tuple[str, ...] = field(default=())

    @property
    def max_score(self) -> int:
        """Highest score this rule can produce (before the 100 cap)."""
        return sum(f.points for f in self.factors)


# --------------------------------------------------------------------------
# Predicate shorthands (kept tiny so the rule table below reads as a spec)
# --------------------------------------------------------------------------

def _yes(key: str) -> Callable[[Mapping[str, Any]], bool]:
    """True when the key is present and truthy. Absent keys never fire."""
    return lambda s: bool(s.get(key))


def _absent_or_false(key: str) -> Callable[[Mapping[str, Any]], bool]:
    """True when a key is present and falsy.

    Always paired with `requires=(key,)`, which drops the factor entirely when
    the key is absent -- otherwise "we were not told" would read as "confirmed
    bad". ``scoring.py`` enforces the pairing; ``test_rule_table.py`` checks it.
    """
    return lambda s: not s.get(key)


def _at_least(key: str, n: int) -> Callable[[Mapping[str, Any]], bool]:
    """True when a numeric key is present and >= n. Absent keys never fire."""

    def predicate(s: Mapping[str, Any]) -> bool:
        value = s.get(key)
        return isinstance(value, (int, float)) and value >= n

    return predicate


def _world_open(s: Mapping[str, Any]) -> bool:
    """True when a security group actually admits traffic from anywhere.

    Shared by ``SG_OPEN_TO_WORLD``'s two exposure factors so they cannot drift:
    awarding points for an exposed port while the supplied CIDRs say the group is
    private-only would be scoring against the evidence rather than from it.
    """
    return "0.0.0.0/0" in (s.get("open_cidrs") or [])


# --------------------------------------------------------------------------
# The rule table
# --------------------------------------------------------------------------

RULES: tuple[DetectionRule, ...] = (
    DetectionRule(
        rule_id="S3_PUBLIC_ACCESS",
        title="S3 bucket is publicly accessible",
        base_severity="high",
        resource_types=("s3_bucket",),
        context_keys=(
            "public_read_access",
            "public_write_access",
            "encryption_enabled",
            "block_public_access",
        ),
        factors=(
            Factor(
                "public_read_access",
                40,
                "Bucket ACL grants public read access",
                _yes("public_read_access"),
                requires=("public_read_access",),
            ),
            Factor(
                "public_write_access",
                25,
                "Bucket ACL grants public write access to anyone",
                _yes("public_write_access"),
                requires=("public_write_access",),
            ),
            Factor(
                "sensitive_data_likely",
                30,
                "Bucket name suggests customer financial data",
                _yes("sensitive_data_likely"),
            ),
            Factor(
                "no_encryption",
                22,
                "Default encryption is not enabled",
                _absent_or_false("encryption_enabled"),
                requires=("encryption_enabled",),
            ),
        ),
        residual_score=15,
        residual_rationale=(
            "Fixing the ACL removes the exposure, but the bucket name and data "
            "classification keep a residual 'sensitive data at rest' risk that a "
            "future policy change could re-expose."
        ),
    ),
    DetectionRule(
        rule_id="S3_NO_ENCRYPTION",
        title="S3 bucket has no default encryption",
        base_severity="medium",
        resource_types=("s3_bucket",),
        context_keys=("encryption_enabled",),
        factors=(
            Factor(
                "no_encryption",
                40,
                "Bucket does not have default encryption (SSE) enabled",
                _absent_or_false("encryption_enabled"),
                requires=("encryption_enabled",),
            ),
            Factor(
                "sensitive_data_likely",
                30,
                "Bucket name suggests customer financial data",
                _yes("sensitive_data_likely"),
            ),
        ),
        residual_score=20,
        residual_rationale=(
            "Enabling SSE-KMS closes the finding; residual reflects key-rotation "
            "and access-policy drift on the newly created key."
        ),
    ),
    DetectionRule(
        rule_id="S3_NO_VERSIONING",
        title="S3 bucket versioning is disabled",
        base_severity="low",
        resource_types=("s3_bucket",),
        context_keys=("versioning_enabled", "backup_configured"),
        factors=(
            Factor(
                "no_versioning",
                18,
                "Bucket versioning is not enabled",
                _absent_or_false("versioning_enabled"),
                requires=("versioning_enabled",),
            ),
            Factor(
                "no_recovery_mechanism",
                10,
                "No backup mechanism identified for this bucket",
                _absent_or_false("backup_configured"),
                requires=("backup_configured",),
            ),
        ),
        residual_score=8,
        residual_rationale=(
            "Versioning restores recoverability; the small remainder covers the "
            "storage-cost and lifecycle-policy follow-up work."
        ),
    ),
    DetectionRule(
        rule_id="IAM_WILDCARD_POLICY",
        title="IAM policy grants wildcard action/resource",
        base_severity="high",
        resource_types=("iam_policy",),
        context_keys=(
            "wildcard_action",
            "wildcard_resource",
            "attached_user_count",
            "attached_role_count",
        ),
        factors=(
            Factor(
                "wildcard_action",
                35,
                "Policy grants Action: '*' across all services",
                _yes("wildcard_action"),
                requires=("wildcard_action",),
            ),
            Factor(
                "wildcard_resource",
                35,
                "Policy grants Resource: '*'",
                _yes("wildcard_resource"),
                requires=("wildcard_resource",),
            ),
            Factor(
                "attached_to_multiple_users",
                18,
                "Policy is attached to {user_count} IAM users",
                _at_least("attached_user_count", 2),
                requires=("attached_user_count",),
            ),
        ),
        residual_score=20,
        residual_rationale=(
            "A scoped policy removes the wildcard, but replacing an in-use "
            "admin policy carries breakage risk that keeps the finding on the "
            "audit list until the migration is fully verified."
        ),
    ),
    DetectionRule(
        rule_id="IAM_ROOT_NO_MFA",
        title="Root account has no MFA",
        base_severity="high",
        resource_types=("iam_user", "account"),
        context_keys=("is_root", "mfa_enabled"),
        factors=(
            Factor(
                "root_account",
                45,
                "Finding applies to the root account, which has unrestricted access",
                _yes("is_root"),
                requires=("is_root",),
            ),
            Factor(
                "no_mfa",
                40,
                "Multi-factor authentication is not enabled",
                _absent_or_false("mfa_enabled"),
                requires=("mfa_enabled",),
            ),
        ),
        residual_score=10,
        residual_rationale=(
            "Enrolling MFA resolves it, but the root account always retains "
            "unrestricted capability and cannot be eliminated entirely."
        ),
    ),
    DetectionRule(
        rule_id="IAM_USER_NO_MFA",
        title="IAM user with console access has no MFA",
        base_severity="medium",
        resource_types=("iam_user",),
        context_keys=("has_console_access", "mfa_enabled", "in_elevated_group"),
        factors=(
            Factor(
                "console_access_no_mfa",
                35,
                "User has console password access without MFA enabled",
                lambda s: bool(s.get("has_console_access")) and not s.get("mfa_enabled"),
                requires=("has_console_access", "mfa_enabled"),
            ),
            Factor(
                "has_elevated_permissions",
                15,
                "User is a member of a group with elevated permissions",
                _yes("in_elevated_group"),
                requires=("in_elevated_group",),
            ),
            Factor(
                "elevated_access_without_mfa",
                5,
                "Elevated permissions protected only by a phishable password",
                lambda s: bool(s.get("in_elevated_group")) and not s.get("mfa_enabled"),
                requires=("in_elevated_group", "mfa_enabled"),
            ),
        ),
        residual_score=20,
        residual_rationale=(
            "MFA enrollment closes the technical gap; residual covers the "
            "behavioural risk of a user who was previously phishable."
        ),
    ),
    DetectionRule(
        rule_id="IAM_UNUSED_ACCESS_KEY",
        title="IAM access key unused for 90+ days",
        base_severity="low",
        resource_types=("iam_user",),
        context_keys=("unused_days",),
        factors=(
            Factor(
                "unused_key_90_days",
                25,
                "Access key has not been used in over {days} days",
                _at_least("unused_days", 90),
                requires=("unused_days",),
            ),
            Factor(
                "user_likely_inactive",
                10,
                "Username suggests a former contractor account",
                _yes("user_likely_inactive"),
            ),
        ),
        residual_score=5,
        residual_rationale=(
            "Deactivating the key removes the credential; a 5-point floor "
            "remains because the account itself may still exist."
        ),
    ),
    DetectionRule(
        rule_id="SG_OPEN_TO_WORLD",
        title="Security group open to 0.0.0.0/0",
        base_severity="high",
        resource_types=("security_group",),
        context_keys=("open_cidrs", "exposed_ports", "attached_to_prod"),
        factors=(
            Factor(
                "open_to_world",
                40,
                "Inbound rule allows 0.0.0.0/0",
                _world_open,
                requires=("open_cidrs",),
            ),
            Factor(
                "sensitive_port",
                30,
                "Port {first_sensitive_port} ({first_sensitive_service}) is exposed to the internet",
                # Gated on the group actually being world-open: a private-only
                # CIDR is positive evidence the port is NOT reachable, and a
                # supplied negative must not be overridden by a supplied port list.
                lambda s: _world_open(s) and bool(s.get("sensitive_ports_found")),
                requires=("open_cidrs", "exposed_ports"),
            ),
            Factor(
                "attached_to_prod_instance",
                10,
                "Security group is attached to a production-tagged instance",
                _yes("attached_to_prod"),
                requires=("attached_to_prod",),
            ),
        ),
        residual_score=18,
        residual_rationale=(
            "Restricting the CIDR range closes the finding, but the group stays "
            "production-attached, so it remains worth re-checking each scan."
        ),
    ),
    DetectionRule(
        rule_id="EBS_NOT_ENCRYPTED",
        title="EBS volume is not encrypted",
        base_severity="medium",
        resource_types=("ebs_volume",),
        context_keys=("encryption_enabled", "attached_to_instance", "snapshot_count"),
        factors=(
            Factor(
                "no_storage_encryption",
                40,
                "EBS volume does not have encryption enabled",
                _absent_or_false("encryption_enabled"),
                requires=("encryption_enabled",),
            ),
            Factor(
                "attached_to_running_instance",
                15,
                "Volume is attached to a running instance",
                _yes("attached_to_instance"),
                requires=("attached_to_instance",),
            ),
            Factor(
                "sensitive_data_likely",
                15,
                "Volume name or tags suggest it holds sensitive data",
                _yes("sensitive_data_likely"),
            ),
        ),
        residual_score=22,
        residual_rationale=(
            "EBS encryption cannot be toggled in place; residual reflects the "
            "snapshot-and-recreate migration window."
        ),
    ),
    DetectionRule(
        rule_id="RDS_NOT_ENCRYPTED",
        title="RDS instance storage is not encrypted",
        base_severity="medium",
        resource_types=("rds_instance",),
        context_keys=("storage_encrypted",),
        factors=(
            Factor(
                "no_storage_encryption",
                40,
                "Storage encryption is disabled on this instance",
                _absent_or_false("storage_encrypted"),
                requires=("storage_encrypted",),
            ),
            Factor(
                "sensitive_data_likely",
                22,
                "Database name suggests financial transaction data",
                _yes("sensitive_data_likely"),
            ),
        ),
        residual_score=25,
        residual_rationale=(
            "RDS cannot encrypt in place, so the reading stays elevated until "
            "the migrated instance is cut over and the original is destroyed."
        ),
    ),
    DetectionRule(
        rule_id="RDS_PUBLICLY_ACCESSIBLE",
        title="RDS instance is publicly accessible",
        base_severity="high",
        resource_types=("rds_instance",),
        context_keys=(
            "publicly_accessible",
            "storage_encrypted",
            "engine_version_supported",
        ),
        factors=(
            Factor(
                "publicly_accessible",
                45,
                "Instance is flagged as publicly accessible",
                _yes("publicly_accessible"),
                requires=("publicly_accessible",),
            ),
            Factor(
                "no_encryption",
                25,
                "Storage encryption is also disabled on this instance",
                _absent_or_false("storage_encrypted"),
                requires=("storage_encrypted",),
            ),
            Factor(
                "outdated_engine_version",
                12,
                "Database engine version is past its support window",
                _absent_or_false("engine_version_supported"),
                requires=("engine_version_supported",),
            ),
            Factor(
                "public_exposure_without_encryption",
                8,
                "Public reachability combined with unencrypted storage compounds exposure",
                lambda s: bool(s.get("publicly_accessible")) and not s.get("storage_encrypted"),
                requires=("publicly_accessible", "storage_encrypted"),
            ),
        ),
        residual_score=20,
        residual_rationale=(
            "Moving the instance into a private subnet closes the finding; "
            "residual covers the subnet-routing review and any lingering "
            "security-group path to it."
        ),
    ),
    DetectionRule(
        rule_id="CLOUDTRAIL_DISABLED",
        title="CloudTrail logging is not enabled",
        base_severity="high",
        resource_types=("account",),
        context_keys=("active_trail_count", "multi_region_trail", "has_log_history"),
        factors=(
            Factor(
                "no_active_trail",
                45,
                "No active CloudTrail trail found for this account",
                lambda s: (s.get("active_trail_count") or 0) == 0,
                requires=("active_trail_count",),
            ),
            Factor(
                "no_audit_log_history",
                33,
                "No API activity history available for investigation",
                _absent_or_false("has_log_history"),
                requires=("has_log_history",),
            ),
        ),
        residual_score=12,
        residual_rationale=(
            "Enabling a multi-region trail fixes it going forward, but activity "
            "before the change is permanently unrecorded."
        ),
    ),
)

RULES_BY_ID: Mapping[str, DetectionRule] = {r.rule_id: r for r in RULES}


class UnknownRuleError(KeyError):
    """Raised when a raw finding cites a rule_id P2 has no definition for.

    Deliberately loud: an unrecognised rule silently scoring 0 would hide a
    real misconfiguration behind a clean-looking dashboard.
    """

    def __init__(self, rule_id: str) -> None:
        super().__init__(rule_id)
        self.rule_id = rule_id

    def __str__(self) -> str:  # pragma: no cover - trivial
        known = ", ".join(sorted(RULES_BY_ID))
        return (
            f"Unknown rule_id {self.rule_id!r}. P2 has no scoring definition for it. "
            f"Known rules: {known}"
        )


def get_rule(rule_id: str) -> DetectionRule:
    try:
        return RULES_BY_ID[rule_id]
    except KeyError:
        raise UnknownRuleError(rule_id) from None
