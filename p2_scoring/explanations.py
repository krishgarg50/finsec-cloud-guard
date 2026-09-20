"""Explanation card generation: the plain-English half of the product.

Everything here is templated rather than LLM-authored, for three reasons that
matter in a regulated setting:

  1. **Determinism.** The same finding always produces the same wording, so a
     card shown to an auditor in March still reads the same in June.
  2. **No hallucination surface.** An LLM that invents a remediation step for a
     compliance finding is a liability, not a feature.
  3. **Auditability.** Every sentence traces to a template plus observed
     signals, which is exactly the rule-trace story the project claims.

The templates are parameterised on the same signals the scoring engine uses, so
the card's narrative and its arithmetic can never disagree about the facts.

Wording can be conditional (`consequence` for S3_PUBLIC_ACCESS reads differently
for a bucket of customer statements than for a scratch bucket). That is done
with a callable rather than a second template, to keep the nuance in one place.

Later, if an LLM layer is added (the Week-5/6 side track), it should *polish*
these sentences -- not replace them. Keep the templated version as the fallback
so the pipeline degrades gracefully.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping

from .rules import UnknownRuleError, get_rule

Renderer = str | Callable[[Mapping[str, Any]], str]


@dataclass(frozen=True)
class ExplanationTemplate:
    issue: Renderer
    consequence: Renderer
    fix: Renderer

    def render(self, signals: Mapping[str, Any]) -> dict[str, str]:
        def one(value: Renderer) -> str:
            return value(signals) if callable(value) else value.format(**signals)

        return {"issue": one(self.issue), "consequence": one(self.consequence), "fix": one(self.fix)}


# --------------------------------------------------------------------------
# Conditionals reused across templates
# --------------------------------------------------------------------------

def _public_s3_consequence(s: Mapping[str, Any]) -> str:
    if s.get("sensitive_data_likely"):
        return (
            "Sensitive customer financial data could be viewed, downloaded, or leaked by "
            "unauthorized parties, potentially triggering regulatory penalties and breach "
            "disclosure obligations."
        )
    return (
        "Anyone on the internet could read or modify the objects in this bucket, and it "
        "could be used to host or distribute malicious content under your organisation's "
        "domain."
    )


def _no_mfa_consequence(s: Mapping[str, Any]) -> str:
    base = (
        "If this user's password is compromised through phishing or credential reuse, an "
        "attacker could gain access to systems this user can reach."
    )
    if s.get("in_elevated_group"):
        base += (
            " Because the account also holds elevated permissions, that access would extend "
            "well beyond everyday operational scope."
        )
    return base


def _public_rds_consequence(s: Mapping[str, Any]) -> str:
    base = (
        "This significantly increases the attack surface for one of the most sensitive "
        "components in the environment"
    )
    if not s.get("storage_encrypted"):
        base += (
            ", and combined with disabled encryption, exposes data both in transit exposure "
            "risk and at rest"
        )
    return base + "."


def _sg_issue(s: Mapping[str, Any]) -> str:
    name = s.get("name") or "This security group"
    port = s.get("first_sensitive_port")
    service = s.get("first_sensitive_service")
    if port and service:
        return (
            f"The security group '{name}' allows inbound traffic from the entire internet on "
            f"port {port} ({service}), rather than being restricted to trusted sources."
        )
    if port:
        return (
            f"The security group '{name}' allows inbound traffic from the entire internet on "
            f"port {port}, rather than being restricted to trusted sources."
        )
    return (
        f"The security group '{name}' allows inbound traffic from the entire internet, "
        f"rather than being restricted to trusted sources."
    )


TEMPLATES: Mapping[str, ExplanationTemplate] = {
    "S3_PUBLIC_ACCESS": ExplanationTemplate(
        issue=(
            "The storage bucket '{name}' is accessible to anyone on the internet, not just "
            "authorized systems."
        ),
        consequence=_public_s3_consequence,
        fix=(
            "Enable S3 Block Public Access at the bucket and account level, and remove any "
            "public grants from the bucket ACL and bucket policy."
        ),
    ),
    "S3_NO_ENCRYPTION": ExplanationTemplate(
        issue=(
            "The bucket '{name}' does not have default encryption enabled, so objects written "
            "to it are stored unencrypted."
        ),
        consequence=(
            "Anyone who obtains the underlying objects -- through a misconfigured ACL, a "
            "shared snapshot, or a support access path -- reads them in plain form."
        ),
        fix=(
            "Enable default bucket encryption with SSE-KMS using a customer-managed key, and "
            "add a bucket policy that denies unencrypted PUT requests."
        ),
    ),
    "S3_NO_VERSIONING": ExplanationTemplate(
        issue=(
            "The bucket '{name}' does not keep previous versions of files when they are "
            "changed or deleted."
        ),
        consequence=(
            "Accidental deletion, overwriting, or a ransomware-style attack could result in "
            "permanent, unrecoverable data loss."
        ),
        fix="Enable versioning on the bucket so that previous versions of objects can be restored if needed.",
    ),
    "IAM_WILDCARD_POLICY": ExplanationTemplate(
        issue=(
            "The permission policy '{name}' grants full administrative access to every AWS "
            "service and resource, with no restrictions."
        ),
        consequence=(
            "Any account using this policy could modify, delete, or exfiltrate data across "
            "the entire cloud environment, and a single compromised credential could lead to "
            "a full account takeover."
        ),
        fix=(
            "Replace the wildcard policy with scoped permissions limited to only the specific "
            "actions and resources each user actually needs."
        ),
    ),
    "IAM_ROOT_NO_MFA": ExplanationTemplate(
        issue=(
            "The root account, which has unrestricted control over the entire cloud "
            "environment, does not have multi-factor authentication enabled."
        ),
        consequence=(
            "If the root password is ever compromised, an attacker would gain complete, "
            "unrestricted control of the account with no second layer of protection."
        ),
        fix=(
            "Enable a hardware or virtual MFA device on the root account immediately, and "
            "avoid using the root account for day-to-day operations."
        ),
    ),
    "IAM_USER_NO_MFA": ExplanationTemplate(
        issue=(
            "The user '{name}' can log into the AWS console with just a password, without a "
            "second authentication factor."
        ),
        consequence=_no_mfa_consequence,
        fix=(
            "Require MFA enrollment for this user before their next login, and consider "
            "enforcing an account-wide MFA policy."
        ),
    ),
    "IAM_UNUSED_ACCESS_KEY": ExplanationTemplate(
        issue=(
            "The user '{name}' has an access key that has not been used in over {days} days, "
            "suggesting the account may no longer be needed."
        ),
        consequence=(
            "Stale, unmonitored credentials are a common target for attackers since their "
            "compromise is less likely to be noticed quickly."
        ),
        fix=(
            "Confirm whether this user still requires access; if not, deactivate the access "
            "key and disable or delete the account."
        ),
    ),
    "SG_OPEN_TO_WORLD": ExplanationTemplate(
        issue=_sg_issue,
        consequence=(
            "Attackers can directly attempt to connect to this port from anywhere in the "
            "world, making it a prime target for brute-force attacks and exploitation."
        ),
        fix=(
            "Restrict the inbound rule to specific trusted IP ranges or internal security "
            "groups only, and remove the 0.0.0.0/0 entry."
        ),
    ),
    "EBS_NOT_ENCRYPTED": ExplanationTemplate(
        issue="The EBS volume '{name}' does not encrypt data at rest.",
        consequence=(
            "If a snapshot of this volume is shared, or the underlying storage is accessed "
            "without authorization, the data would be readable in plain form."
        ),
        fix=(
            "Create an encrypted snapshot of the volume, restore it as a new encrypted "
            "volume, then detach the original and replace it."
        ),
    ),
    "RDS_NOT_ENCRYPTED": ExplanationTemplate(
        issue=(
            "The database '{name}' does not encrypt data at rest, meaning stored data is not "
            "protected if the underlying storage is ever accessed without authorization."
        ),
        consequence=(
            "In the event of physical media theft, storage misconfiguration, or unauthorized "
            "snapshot access, transaction data would be readable in plain form."
        ),
        fix=(
            "Enable storage encryption on a new encrypted instance and migrate data, since "
            "encryption cannot be enabled on an existing unencrypted RDS instance directly."
        ),
    ),
    "RDS_PUBLICLY_ACCESSIBLE": ExplanationTemplate(
        issue=(
            "The database '{name}' is directly reachable from the public internet rather than "
            "being restricted to internal systems."
        ),
        consequence=_public_rds_consequence,
        fix=(
            "Disable public accessibility on the instance, place it in a private subnet, and "
            "enable storage encryption on a migrated, encrypted instance."
        ),
    ),
    "CLOUDTRAIL_DISABLED": ExplanationTemplate(
        issue=(
            "Account-level activity logging is not enabled, so there is no record of who did "
            "what across the cloud environment."
        ),
        consequence=(
            "In the event of a security incident, there would be no audit trail available to "
            "investigate what happened, when, or who was responsible -- this also fails "
            "standard regulatory audit requirements."
        ),
        fix=(
            "Enable a multi-region CloudTrail trail with log file validation, and route logs "
            "to a dedicated, access-restricted S3 bucket."
        ),
    ),
}


def explanation_for(signals: Mapping[str, Any], rule_id: str) -> dict[str, Any]:
    """Build the schema-shaped `explanation` object for one finding.

    `projected_score_after_fix` comes from the rule's declared residual rather
    than being computed from the factor list. It is an *estimate* of post-fix
    risk, and is declared explicitly with a rationale (see
    ``DetectionRule.residual_rationale``) because the honest answer to "what will
    this score afterwards?" depends on judgement -- migration windows, data
    classification, blast radius -- not just on which factors disappear.
    """
    try:
        template = TEMPLATES[rule_id]
    except KeyError:
        raise UnknownRuleError(rule_id) from None

    rule = get_rule(rule_id)
    card = template.render(signals)
    return {
        "issue": card["issue"],
        "consequence": card["consequence"],
        "fix": card["fix"],
        "projected_score_after_fix": rule.residual_score,
    }
