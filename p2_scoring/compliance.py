"""Compliance mapping lookup table: rule_id -> framework clauses.

This is the bridge between "a technical thing is wrong" and "here is the
regulation that says so". For a regulated buyer that link is the product -- a
finding that cannot be traced to an obligation is just an alert.

Ordering
--------
Clauses are listed in a canonical framework order (PCI-DSS, SOC2, GLBA) so the
dashboard renders the same framework first everywhere, rather than in whatever
order a rule author happened to type them.

Status of the mappings
----------------------
The ten rules covered by the Week-0 mock findings reproduce those mappings
exactly (``tests/test_compliance.py`` asserts it). Two rules -- S3_NO_ENCRYPTION
and EBS_NOT_ENCRYPTED -- had no mock precedent, so theirs are **proposed** and
listed in ``PROPOSED_MAPPINGS`` awaiting sign-off. Treat a mapping as a
compliance claim, not a code comment: it should be reviewed by whoever owns the
framework relationship before it goes in front of an auditor.

Known wart: the hand-authored mocks describe GLBA's Safeguards Rule two
different ways ("Encrypt customer information at rest" for RDS_NOT_ENCRYPTED,
"Restrict access to customer information systems" for RDS_PUBLICLY_ACCESSIBLE).
Both are faithfully preserved here. GLBA's Safeguards Rule is not clause-
numbered the way PCI is, so the description carries the real meaning -- worth
normalising to a single canonical phrasing in a later pass.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping

#: Framework display order, most-specific-to-financial-services first.
FRAMEWORK_ORDER: tuple[str, ...] = ("PCI-DSS", "SOC2", "GLBA", "ISO27001")


@dataclass(frozen=True)
class ClauseRef:
    framework: str
    clause: str
    clause_description: str

    def to_dict(self) -> dict[str, str]:
        return {
            "framework": self.framework,
            "clause": self.clause,
            "clause_description": self.clause_description,
        }


# --------------------------------------------------------------------------
# Reusable clause definitions (many rules cite the same clause verbatim)
# --------------------------------------------------------------------------

# PCI-DSS
PCI_1_2_1 = ClauseRef("PCI-DSS", "1.2.1", "Restrict inbound and outbound traffic to that which is necessary")
PCI_1_3_4 = ClauseRef(
    "PCI-DSS",
    "1.3.4",
    "Prohibit direct public access between the internet and any system component in the cardholder data environment",
)
PCI_3_4 = ClauseRef("PCI-DSS", "3.4", "Render cardholder data unreadable anywhere it is stored")
PCI_7_1_2 = ClauseRef("PCI-DSS", "7.1.2", "Restrict access to privileged user IDs to least privileges necessary")
PCI_8_3_1 = ClauseRef(
    "PCI-DSS",
    "8.3.1",
    "Incorporate multi-factor authentication for all access into the cardholder data environment",
)
PCI_10_1 = ClauseRef(
    "PCI-DSS",
    "10.1",
    "Implement audit trails to link access to system components to each individual user",
)

# SOC 2 (Trust Services Criteria)
SOC2_CC6_1 = ClauseRef("SOC2", "CC6.1", "Logical access controls restrict access to authorized users")
SOC2_CC6_2 = ClauseRef("SOC2", "CC6.2", "User access is removed in a timely manner when no longer required")
SOC2_CC6_3 = ClauseRef("SOC2", "CC6.3", "Access is granted based on least privilege principle")
SOC2_CC6_6 = ClauseRef("SOC2", "CC6.6", "System boundaries are protected from unauthorized network access")
SOC2_CC7_2 = ClauseRef("SOC2", "CC7.2", "System activity is monitored to detect anomalies")
SOC2_A1_2 = ClauseRef("SOC2", "A1.2", "System components are recoverable in the event of data loss")

# GLBA (Safeguards Rule -- not clause-numbered the way PCI is)
GLBA_ENCRYPT_AT_REST = ClauseRef("GLBA", "Safeguards Rule", "Encrypt customer information at rest")
GLBA_RESTRICT_ACCESS = ClauseRef("GLBA", "Safeguards Rule", "Restrict access to customer information systems")


RULE_COMPLIANCE: Mapping[str, tuple[ClauseRef, ...]] = {
    "S3_PUBLIC_ACCESS": (PCI_1_3_4, SOC2_CC6_1),
    "S3_NO_ENCRYPTION": (PCI_3_4, SOC2_CC6_1, GLBA_ENCRYPT_AT_REST),
    "S3_NO_VERSIONING": (SOC2_A1_2,),
    "IAM_WILDCARD_POLICY": (PCI_7_1_2, SOC2_CC6_3),
    "IAM_ROOT_NO_MFA": (PCI_8_3_1, SOC2_CC6_1),
    "IAM_USER_NO_MFA": (PCI_8_3_1,),
    "IAM_UNUSED_ACCESS_KEY": (SOC2_CC6_2,),
    "SG_OPEN_TO_WORLD": (PCI_1_2_1, SOC2_CC6_6),
    "EBS_NOT_ENCRYPTED": (PCI_3_4, GLBA_ENCRYPT_AT_REST),
    "RDS_NOT_ENCRYPTED": (PCI_3_4, GLBA_ENCRYPT_AT_REST),
    "RDS_PUBLICLY_ACCESSIBLE": (PCI_1_3_4, GLBA_RESTRICT_ACCESS),
    "CLOUDTRAIL_DISABLED": (PCI_10_1, SOC2_CC7_2),
}

#: Rules whose mappings had no mock precedent and need a human sign-off.
PROPOSED_MAPPINGS: frozenset[str] = frozenset({"S3_NO_ENCRYPTION", "EBS_NOT_ENCRYPTED"})


class UnknownComplianceRuleError(KeyError):
    """Raised when a rule has no compliance mapping entry."""

    def __init__(self, rule_id: str) -> None:
        super().__init__(rule_id)
        self.rule_id = rule_id

    def __str__(self) -> str:  # pragma: no cover - trivial
        return (
            f"No compliance mapping for rule_id {self.rule_id!r}. Every rule must map to at "
            f"least one framework clause -- see compliance.py."
        )


def _ordered(refs: Iterable[ClauseRef]) -> tuple[ClauseRef, ...]:
    """Sort clauses into canonical framework order, preserving within-framework order."""
    return tuple(sorted(refs, key=lambda r: FRAMEWORK_ORDER.index(r.framework)))


def clauses_for(rule_id: str) -> list[dict[str, str]]:
    """Return the schema-shaped `compliance_mappings` list for a rule."""
    try:
        refs = RULE_COMPLIANCE[rule_id]
    except KeyError:
        raise UnknownComplianceRuleError(rule_id) from None
    return [ref.to_dict() for ref in _ordered(refs)]


def frameworks_for(rule_id: str) -> list[str]:
    """Distinct frameworks a rule touches, in canonical order."""
    return [ref.framework for ref in _ordered(RULE_COMPLIANCE.get(rule_id, ()))]


def summarise_by_framework(findings: Iterable[Mapping[str, Any]]) -> dict[str, dict[str, Any]]:
    """Aggregate findings per framework.

    Powers the dashboard's compliance view: "how many open PCI-DSS findings do
    we have, and which clauses drive them?"
    """
    summary: dict[str, dict[str, Any]] = {}
    for finding in findings:
        # A finding counts once per framework, even if it cites several clauses
        # in that framework -- otherwise a rule mapped to two PCI clauses would
        # inflate the PCI count.
        counted_frameworks: set[str] = set()
        for mapping in finding.get("compliance_mappings", ()):
            framework = mapping["framework"]
            bucket = summary.setdefault(
                framework,
                {"framework": framework, "finding_count": 0, "open_count": 0, "clauses": {}},
            )
            if framework not in counted_frameworks:
                bucket["finding_count"] += 1
                if finding.get("status") == "open":
                    bucket["open_count"] += 1
                counted_frameworks.add(framework)
            clause = bucket["clauses"].setdefault(
                # Keyed by (clause, description), not by clause alone. GLBA's
                # Safeguards Rule is not clause-numbered, so two genuinely
                # different requirements -- "Encrypt customer information at
                # rest" and "Restrict access to customer information systems" --
                # share the clause string "Safeguards Rule". Keying on the clause
                # alone merges them into a single row whose description is
                # whichever finding happened to be iterated first, silently
                # dropping the other requirement. `repository.compliance_summary`
                # groups by the same pair, so both paths answer alike.
                (mapping["clause"], mapping["clause_description"]),
                {
                    "clause": mapping["clause"],
                    "clause_description": mapping["clause_description"],
                    "finding_count": 0,
                },
            )
            clause["finding_count"] += 1
    return summary
