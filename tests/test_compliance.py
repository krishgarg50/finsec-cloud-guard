"""Compliance mapping table: coverage, fidelity to the mocks, and shape."""

from __future__ import annotations

import pytest

from p2_scoring.compliance import (
    FRAMEWORK_ORDER,
    PROPOSED_MAPPINGS,
    RULE_COMPLIANCE,
    UnknownComplianceRuleError,
    clauses_for,
    summarise_by_framework,
)
from p2_scoring.rules import RULES


def test_every_rule_maps_to_at_least_one_clause():
    """A finding that cannot be traced to an obligation is just an alert."""
    unmapped = [r.rule_id for r in RULES if not RULE_COMPLIANCE.get(r.rule_id)]
    assert not unmapped, f"rules with no compliance mapping: {unmapped}"


def test_mapping_table_has_no_orphan_entries():
    """Catch a renamed rule leaving a stale row behind."""
    known = {r.rule_id for r in RULES}
    orphans = set(RULE_COMPLIANCE) - known
    assert not orphans, f"compliance entries for unknown rules: {orphans}"


@pytest.mark.parametrize("rule_id", sorted(RULE_COMPLIANCE))
def test_clauses_use_known_frameworks(rule_id):
    for ref in RULE_COMPLIANCE[rule_id]:
        assert ref.framework in FRAMEWORK_ORDER, f"{rule_id}: unknown framework {ref.framework}"
        assert ref.clause and ref.clause_description


def test_clauses_render_in_canonical_framework_order():
    """PCI-DSS before SOC2 before GLBA, everywhere, regardless of authoring order."""
    for rule_id in RULE_COMPLIANCE:
        frameworks = [m["framework"] for m in clauses_for(rule_id)]
        positions = [FRAMEWORK_ORDER.index(f) for f in frameworks]
        assert positions == sorted(positions), f"{rule_id}: {frameworks}"


def test_clauses_for_reproduces_the_handcrafted_mappings(handcrafted_by_id, raws_by_id):
    """Engine mappings must match the agreed ones exactly, clause for clause."""
    from p2_scoring import enrich_finding

    for finding_id, handcrafted in handcrafted_by_id.items():
        enriched = enrich_finding(raws_by_id[finding_id])
        engine = {(m["framework"], m["clause"]) for m in enriched["compliance_mappings"]}
        agreed = {(m["framework"], m["clause"]) for m in handcrafted["compliance_mappings"]}
        assert engine == agreed, f"{finding_id}: engine={engine} agreed={agreed}"


def test_unknown_rule_raises():
    with pytest.raises(UnknownComplianceRuleError):
        clauses_for("NOT_A_REAL_RULE")


def test_proposed_mappings_are_still_flagged():
    """The two rules with no mock precedent need a human sign-off.

    If someone reviews and blesses them, delete this test deliberately rather
    than letting the flag rot.
    """
    assert PROPOSED_MAPPINGS == {"S3_NO_ENCRYPTION", "EBS_NOT_ENCRYPTED"}
    assert PROPOSED_MAPPINGS <= set(RULE_COMPLIANCE)


class TestFrameworkSummary:
    def test_counts_findings_and_open_items_per_framework(self, raw_mocks):
        from p2_scoring import enrich_findings

        summary = summarise_by_framework(enrich_findings(raw_mocks).findings)

        assert "PCI-DSS" in summary and "SOC2" in summary
        pci = summary["PCI-DSS"]
        assert pci["finding_count"] >= pci["open_count"]
        assert pci["open_count"] > 0
        assert all(clause["finding_count"] > 0 for clause in pci["clauses"].values())

    def test_a_finding_citing_two_clauses_in_one_framework_counts_once(self):
        findings = [
            {
                "status": "open",
                "compliance_mappings": [
                    {"framework": "PCI-DSS", "clause": "3.4", "clause_description": "a"},
                    {"framework": "PCI-DSS", "clause": "3.5", "clause_description": "b"},
                ],
            }
        ]
        summary = summarise_by_framework(findings)
        assert summary["PCI-DSS"]["finding_count"] == 1
        assert len(summary["PCI-DSS"]["clauses"]) == 2

    def test_two_glba_phrasings_stay_distinct(self):
        """GLBA is not clause-numbered, so both requirements share a clause id.

        Keying the clause buckets on the clause string alone collapses them: the
        dashboard would show one "Safeguards Rule" row carrying whichever
        description was iterated first, and the other requirement would vanish.
        Both are real obligations, so both must survive.
        """
        findings = [
            {
                "status": "open",
                "compliance_mappings": [
                    {
                        "framework": "GLBA",
                        "clause": "Safeguards Rule",
                        "clause_description": "Encrypt customer information at rest",
                    },
                    {
                        "framework": "GLBA",
                        "clause": "Safeguards Rule",
                        "clause_description": "Restrict access to customer information systems",
                    },
                ],
            }
        ]
        glba = summarise_by_framework(findings)["GLBA"]

        assert glba["finding_count"] == 1  # one finding, two obligations
        assert len(glba["clauses"]) == 2
        descriptions = {c["clause_description"] for c in glba["clauses"].values()}
        assert descriptions == {
            "Encrypt customer information at rest",
            "Restrict access to customer information systems",
        }
