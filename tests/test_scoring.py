"""The scoring engine's own guarantees, independent of any seed data."""

from __future__ import annotations

import pytest

from p2_scoring.rules import RULES, RULES_BY_ID, risk_band
from p2_scoring.scoring import CAP_FACTOR_KEY, MAX_SCORE, score_finding
from p2_scoring.signals import DERIVED_KEYS, derive_signals

EMPTY_CONTEXT_RESOURCE_NAME = "thing"  # matches no sensitivity heuristic


def _raw(rule_id: str, name: str = EMPTY_CONTEXT_RESOURCE_NAME, **context):
    return {
        "finding_id": "test-1",
        "rule_id": rule_id,
        "scan_id": "scan-test",
        "resource": {"type": "s3_bucket", "id": "arn:x", "name": name, "region": "us-east-1"},
        "detection_source": "rule_engine",
        "severity_raw": "high",
        "context": context,
        "detected_at": "2026-01-01T00:00:00Z",
        "last_seen_at": "2026-01-01T00:00:00Z",
    }


def _seed_finding(rule_id: str, raw_mocks):
    for raw in raw_mocks:
        if raw["rule_id"] == rule_id:
            return raw
    pytest.skip(f"no seed finding exercises {rule_id}")


# --------------------------------------------------------------------------
# The central invariant
# --------------------------------------------------------------------------

@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.rule_id)
def test_breakdown_sums_to_risk_score(rule, raw_mocks):
    """The card an auditor reads IS the arithmetic. Checked on realistic data."""
    result = score_finding(_seed_finding(rule.rule_id, raw_mocks))
    assert sum(f["weight"] for f in result.score_breakdown) == result.risk_score
    assert 0 <= result.risk_score <= MAX_SCORE


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.rule_id)
def test_every_rule_is_actually_exercised_by_the_seed_data(rule, raw_mocks):
    """Guard against seed data that silently stops testing a rule."""
    result = score_finding(_seed_finding(rule.rule_id, raw_mocks))
    assert result.substantiated, f"{rule.rule_id} scores 0 on its own seed finding"
    assert result.risk_score > 0


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.rule_id)
def test_no_factor_key_collides_with_the_cap_entry(rule):
    """A real factor must never be named like the synthetic cap correction."""
    assert CAP_FACTOR_KEY not in {f.key for f in rule.factors}


def test_cap_is_explicit_and_keeps_the_sum_honest():
    """S3_PUBLIC_ACCESS with every factor on totals 117 -- over the 100 cap.

    The engine must show the correction rather than quietly truncating, so the
    breakdown still sums to the reported score.
    """
    result = score_finding(
        _raw(
            "S3_PUBLIC_ACCESS",
            name="customer-statements-backup",  # triggers the sensitivity factor
            public_read_access=True,
            public_write_access=True,
            encryption_enabled=False,
            block_public_access=False,
        )
    )

    assert result.raw_total == 40 + 25 + 30 + 22  # 117
    assert result.capped is True
    assert result.risk_score == MAX_SCORE
    assert result.score_breakdown[-1]["factor"] == CAP_FACTOR_KEY
    assert result.score_breakdown[-1]["weight"] == MAX_SCORE - 117  # negative correction
    assert sum(f["weight"] for f in result.score_breakdown) == result.risk_score


def test_scores_are_deterministic():
    """Same input, same output -- the property that makes a card auditable."""
    raw = _raw("SG_OPEN_TO_WORLD", open_cidrs=["0.0.0.0/0"], exposed_ports=[22], attached_to_prod=True)
    assert score_finding(raw).score_breakdown == score_finding(raw).score_breakdown


# --------------------------------------------------------------------------
# The evidence gate
# --------------------------------------------------------------------------

@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.rule_id)
def test_empty_context_scores_zero(rule):
    """'We were not told' must never be read as 'confirmed bad'.

    Before the evidence gate existed, CLOUDTRAIL_DISABLED scored 78/100 on a raw
    finding carrying no context at all, because `active_trail_count` defaulted
    to 0 and 0 == 'no trail found'.
    """
    result = score_finding(_raw(rule.rule_id))

    assert result.risk_score == 0
    assert result.score_breakdown == []
    assert not result.substantiated


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.rule_id)
def test_every_factor_that_fires_on_absent_evidence_declares_what_it_needs(rule):
    """The pairing `scoring.py` relies on, asserted at the predicate level.

    `_absent_or_false(key)` returns True when the key is absent -- "not
    encryption_enabled" is true of a context that says nothing about encryption.
    That is deliberate, and it is safe only because the factor names the key in
    `requires` so the engine's evidence gate drops it first.

    So the invariant is not "no predicate fires on an empty context" (several
    legitimately do); it is "no predicate fires on an empty context without
    declaring the evidence it would need". A factor that reads a key but forgets
    to declare it would score points the data does not support -- the exact
    false-positive class the gate exists to prevent.
    """
    signals = derive_signals(_raw(rule.rule_id))
    for factor in rule.factors:
        if factor.applies(signals) and not factor.requires:
            raise AssertionError(
                f"{rule.rule_id}.{factor.key} fires on a context that supplies no "
                f"evidence, but declares no `requires`. Either it reads only derived "
                f"signals (in which case it should not fire on name "
                f"{EMPTY_CONTEXT_RESOURCE_NAME!r}), or it needs the keys it reads "
                f"named in `requires`."
            )


def test_explicit_null_counts_as_absent():
    """P1 sending a key with a null value is not evidence of a misconfiguration."""
    result = score_finding(_raw("CLOUDTRAIL_DISABLED", active_trail_count=None, has_log_history=None))
    assert result.risk_score == 0
    assert set(result.missing_evidence) == {"active_trail_count", "has_log_history"}


def test_missing_evidence_is_reported_for_diagnosis():
    """The integration aid: name the keys P1 failed to send."""
    result = score_finding(_raw("SG_OPEN_TO_WORLD", exposed_ports=[3306]))
    assert "open_cidrs" in result.missing_evidence
    assert "attached_to_prod" in result.missing_evidence
    # the one key that WAS supplied is not reported as missing
    assert "exposed_ports" not in result.missing_evidence


def test_partial_evidence_scores_only_the_supplied_factors():
    """A partially-populated context yields a partial, honest score."""
    result = score_finding(_raw("SG_OPEN_TO_WORLD", open_cidrs=["0.0.0.0/0"]))
    assert result.risk_score == 40  # open_to_world only
    assert [f["factor"] for f in result.score_breakdown] == ["open_to_world"]
    assert set(result.missing_evidence) == {"exposed_ports", "attached_to_prod"}


def test_present_but_false_evidence_does_not_earn_points():
    """The flip side: a supplied 'false' is real evidence and must be respected."""
    result = score_finding(
        _raw("S3_NO_VERSIONING", versioning_enabled=True, backup_configured=True)
    )
    assert result.risk_score == 0
    assert result.missing_evidence == ()  # nothing missing -- just genuinely fine


# --------------------------------------------------------------------------
# Guard rails
# --------------------------------------------------------------------------

def test_unknown_rule_raises_rather_than_scoring_zero():
    """A rule P2 does not know must not become a silent, clean-looking finding."""
    from p2_scoring.rules import UnknownRuleError

    with pytest.raises(UnknownRuleError) as excinfo:
        score_finding(_raw("S3_BUCKET_MADE_UP"))

    assert "S3_BUCKET_MADE_UP" in str(excinfo.value)


def test_context_cannot_shadow_a_derived_signal():
    """P1 sending a reserved key is a real bug -- fail loudly, don't let it win."""
    with pytest.raises(ValueError, match="reserved key"):
        derive_signals(_raw("S3_PUBLIC_ACCESS", sensitive_data_likely=True))


def test_derived_signals_are_disjoint_from_context_namespace():
    """Guard the guard: DERIVED_KEYS must actually contain what we claim."""
    assert {"sensitive_data_likely", "user_likely_inactive"} <= DERIVED_KEYS


def test_rule_table_covers_every_seeded_rule(raw_mocks):
    """Seed data must not reference a rule the engine has no definition for."""
    assert {r["rule_id"] for r in raw_mocks} <= set(RULES_BY_ID)


# --------------------------------------------------------------------------
# Presentation helper
# --------------------------------------------------------------------------

class TestRiskBands:
    @pytest.mark.parametrize(
        ("score", "expected"),
        [
            (100, "critical"),
            (80, "critical"),
            (79, "high"),
            (60, "high"),
            (59, "medium"),
            (40, "medium"),
            (39, "low"),
            (0, "low"),
        ],
    )
    def test_boundaries(self, score, expected):
        assert risk_band(score) == expected


class TestSecurityGroupSignals:
    def test_picks_the_lowest_sensitive_port(self):
        result = score_finding(
            _raw("SG_OPEN_TO_WORLD", open_cidrs=["0.0.0.0/0"], exposed_ports=[8080, 5432, 22])
        )
        sensitive = next(f for f in result.score_breakdown if f["factor"] == "sensitive_port")
        assert "22" in sensitive["description"] and "SSH" in sensitive["description"]

    def test_non_sensitive_port_earns_no_sensitive_port_factor(self):
        result = score_finding(_raw("SG_OPEN_TO_WORLD", open_cidrs=["0.0.0.0/0"], exposed_ports=[8080]))
        assert "sensitive_port" not in {f["factor"] for f in result.score_breakdown}

    def test_private_cidr_only_scores_nothing(self):
        """A supplied negative outranks a supplied port list.

        `exposed_ports` says port 22 is open, but `open_cidrs` says the group
        only admits a private range. Scoring 30 for "port 22 is exposed" would be
        awarding points *against* evidence P1 actually sent -- worse than the
        missing-key case the evidence gate already covers.
        """
        result = score_finding(_raw("SG_OPEN_TO_WORLD", open_cidrs=["10.0.0.0/8"], exposed_ports=[22]))
        assert result.risk_score == 0
        # The two keys that decide exposure were supplied and read as negative,
        # so neither is reported as a gap. `attached_to_prod` genuinely was not
        # sent, and still is -- the point is that its absence costs nothing here.
        assert set(result.missing_evidence) == {"attached_to_prod"}
        assert "open_cidrs" not in result.missing_evidence
        assert "exposed_ports" not in result.missing_evidence

    def test_sensitive_port_still_fires_on_a_genuinely_public_group(self):
        """The gate must not over-suppress: a world-open group with a sensitive
        port still carries both factors."""
        result = score_finding(
            _raw("SG_OPEN_TO_WORLD", open_cidrs=["0.0.0.0/0"], exposed_ports=[5432])
        )
        assert result.risk_score == 70  # open_to_world + sensitive_port
        assert [f["factor"] for f in result.score_breakdown] == ["open_to_world", "sensitive_port"]

    def test_sensitive_port_factor_never_fires_without_a_cidr_list(self):
        """Absent `open_cidrs` must skip the factor, not assume exposure."""
        result = score_finding(_raw("SG_OPEN_TO_WORLD", exposed_ports=[5432]))
        assert result.risk_score == 0
        assert "open_cidrs" in result.missing_evidence
