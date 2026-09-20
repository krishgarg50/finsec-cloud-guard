"""Explanation card generation.

The bar these tests hold the templates to: every rule produces readable prose
with no unrendered placeholders and no leaked Python `None`, and the wording
actually responds to the observed facts rather than being a fixed string.
"""

from __future__ import annotations

import pytest

from p2_scoring.explanations import TEMPLATES, explanation_for
from p2_scoring.rules import RULES


def _signals_for(rule_id: str, raw_mocks):
    """Derive signals for a rule from whichever seed finding exercises it."""
    from p2_scoring.signals import derive_signals

    for raw in raw_mocks:
        if raw["rule_id"] == rule_id:
            return derive_signals(raw)
    pytest.skip(f"no seed finding exercises {rule_id}")


@pytest.fixture(scope="module")
def sample_signals(raw_mocks):
    return {rule.rule_id: _signals_for(rule.rule_id, raw_mocks) for rule in RULES}


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.rule_id)
def test_every_rule_has_a_template(rule):
    assert rule.rule_id in TEMPLATES


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.rule_id)
def test_card_renders_cleanly(rule, sample_signals):
    """No unrendered `{placeholder}` and no leaked `None` for an absent value."""
    card = explanation_for(sample_signals[rule.rule_id], rule.rule_id)

    for field in ("issue", "consequence", "fix"):
        text = card[field]
        assert text and text.strip(), f"{rule.rule_id}.{field} is empty"
        assert "{" not in text and "}" not in text, f"{rule.rule_id}.{field} has an unrendered placeholder: {text!r}"
        assert "None" not in text, f"{rule.rule_id}.{field} leaked None: {text!r}"

    assert card["projected_score_after_fix"] == rule.residual_score


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.rule_id)
def test_card_survives_an_empty_context(rule):
    """A rule that fires with no context must still produce a sentence, not a crash."""
    from p2_scoring.signals import derive_signals

    signals = derive_signals(
        {
            "finding_id": "t",
            "rule_id": rule.rule_id,
            "scan_id": "scan-test",
            "resource": {
                "type": "unknown",
                "id": "arn:x",
                "name": "unknown-resource",
                "region": "us-east-1",
            },
            "detection_source": "rule_engine",
            "severity_raw": "low",
            "context": {},
            "detected_at": "2026-01-01T00:00:00Z",
            "last_seen_at": "2026-01-01T00:00:00Z",
        }
    )
    card = explanation_for(signals, rule.rule_id)

    for field in ("issue", "consequence", "fix"):
        assert card[field].strip()
        assert "{" not in card[field] and "}" not in card[field]
        assert "None" not in card[field], f"{rule.rule_id}.{field} leaked None: {card[field]!r}"


def test_unknown_rule_raises():
    from p2_scoring.rules import UnknownRuleError

    with pytest.raises(UnknownRuleError):
        explanation_for({}, "TOTALLY_MADE_UP")


class TestWordingAdaptsToFacts:
    """The card must not read the same for a scratch bucket and a PII bucket."""

    def test_s3_public_access_escalates_for_sensitive_data(self):
        sensitive = explanation_for(
            {"name": "customer-statements-backup", "sensitive_data_likely": True}, "S3_PUBLIC_ACCESS"
        )
        scratch = explanation_for(
            {"name": "build-artifacts", "sensitive_data_likely": False}, "S3_PUBLIC_ACCESS"
        )

        assert "customer financial data" in sensitive["consequence"]
        assert "customer financial data" not in scratch["consequence"]
        assert "host or distribute malicious content" in scratch["consequence"]

    def test_mfa_card_escalates_when_permissions_are_elevated(self):
        elevated = explanation_for(
            {"name": "j.patel", "in_elevated_group": True}, "IAM_USER_NO_MFA"
        )
        plain = explanation_for({"name": "j.patel", "in_elevated_group": False}, "IAM_USER_NO_MFA")

        assert "elevated permissions" in elevated["consequence"]
        assert "elevated permissions" not in plain["consequence"]

    def test_rds_card_mentions_encryption_only_when_it_is_also_off(self):
        unencrypted = explanation_for(
            {"name": "db", "storage_encrypted": False}, "RDS_PUBLICLY_ACCESSIBLE"
        )
        encrypted = explanation_for(
            {"name": "db", "storage_encrypted": True}, "RDS_PUBLICLY_ACCESSIBLE"
        )

        assert "disabled encryption" in unencrypted["consequence"]
        assert "disabled encryption" not in encrypted["consequence"]

    def test_security_group_card_names_the_exposed_port(self):
        card = explanation_for(
            {"name": "db-server-sg", "first_sensitive_port": 3306, "first_sensitive_service": "MySQL"},
            "SG_OPEN_TO_WORLD",
        )
        assert "3306" in card["issue"] and "MySQL" in card["issue"]
        assert "db-server-sg" in card["issue"]

    def test_cards_name_the_offending_resource(self):
        """A card that does not say *which* resource is wrong is not actionable."""
        for rule_id in ("S3_PUBLIC_ACCESS", "RDS_NOT_ENCRYPTED", "IAM_WILDCARD_POLICY"):
            card = explanation_for({"name": "my-resource"}, rule_id)
            assert "my-resource" in card["issue"], rule_id
