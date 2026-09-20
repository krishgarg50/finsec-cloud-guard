"""Structural invariants of the rule table.

A rule is defined across three registries -- scoring factors (`rules.py`),
compliance clauses (`compliance.py`) and explanation templates
(`explanations.py`). These tests make a half-added rule impossible: forget one
registry and the suite fails, rather than the pipeline discovering it at runtime
in front of an audience.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from p2_scoring.compliance import RULE_COMPLIANCE
from p2_scoring.explanations import TEMPLATES
from p2_scoring.rules import RULES, RULES_BY_ID, UNSCORED_CONTEXT_KEYS, DetectionRule
from p2_scoring.signals import CONTEXT_KEYS_CONSUMED, DERIVED_KEYS

SCHEMA_PATH = Path(__file__).resolve().parent.parent / "schema" / "finding_schema.json"


def test_rule_ids_are_unique():
    assert len(RULES_BY_ID) == len(RULES)


def test_the_three_registries_agree():
    """Every rule must be fully defined, or not defined at all."""
    scoring = set(RULES_BY_ID)
    compliance = set(RULE_COMPLIANCE)
    explanations = set(TEMPLATES)

    assert scoring == compliance, (
        f"missing compliance mapping for {scoring - compliance}; "
        f"stale entries for {compliance - scoring}"
    )
    assert scoring == explanations, (
        f"missing explanation template for {scoring - explanations}; "
        f"stale entries for {explanations - scoring}"
    )


def test_expected_rule_count():
    """The detection-rules doc scopes this iteration to ~12 rules."""
    assert len(RULES) == 12, f"rule table has {len(RULES)} rules; detection_rules.md scopes 12"


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.rule_id)
def test_rule_is_well_formed(rule: DetectionRule):
    assert rule.rule_id.isupper()
    assert rule.title.strip()
    assert rule.base_severity in {"high", "medium", "low"}
    assert rule.resource_types, f"{rule.rule_id} declares no resource types"
    assert rule.context_keys, f"{rule.rule_id} declares no context keys for P1"
    assert 0 <= rule.residual_score < rule.max_score, (
        f"{rule.rule_id}: residual {rule.residual_score} must be below the rule's max {rule.max_score}"
    )
    assert rule.residual_rationale.strip(), f"{rule.rule_id} has no residual rationale"


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.rule_id)
def test_factor_keys_are_unique_and_positive(rule: DetectionRule):
    keys = [f.key for f in rule.factors]
    assert len(keys) == len(set(keys)), f"{rule.rule_id} has duplicate factor keys"
    for factor in rule.factors:
        assert factor.points > 0, f"{rule.rule_id}.{factor.key} has non-positive points"
        assert factor.template.strip()


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.rule_id)
def test_factor_evidence_keys_are_declared_in_the_contract(rule: DetectionRule):
    """A factor may only demand evidence the rule tells P1 to send.

    Otherwise the contract doc would under-report what P1 must supply, and the
    factor would silently never fire.
    """
    declared = set(rule.context_keys)
    for factor in rule.factors:
        undeclared = set(factor.requires) - declared
        assert not undeclared, (
            f"{rule.rule_id}.{factor.key} requires {sorted(undeclared)}, which is not in "
            f"the rule's context_keys {sorted(declared)}"
        )


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.rule_id)
def test_context_keys_do_not_collide_with_derived_signals(rule: DetectionRule):
    """P1 can only send keys P2 does not compute itself."""
    overlap = set(rule.context_keys) & DERIVED_KEYS
    assert not overlap, f"{rule.rule_id} declares derived key(s) as context: {sorted(overlap)}"


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.rule_id)
def test_resource_types_are_valid_per_the_schema(rule: DetectionRule):
    """Resource types should stay within the vocabulary the schema documents."""
    with SCHEMA_PATH.open(encoding="utf-8") as handle:
        schema = json.load(handle)
    documented = schema["properties"]["resource"]["properties"]["type"]["description"]
    for resource_type in rule.resource_types:
        assert resource_type in documented, (
            f"{rule.rule_id}: resource type {resource_type!r} is not in the schema's documented "
            f"vocabulary. Add it to schema/finding_schema.json too."
        )


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.rule_id)
def test_every_declared_context_key_is_actually_read(rule: DetectionRule):
    """No dead contract entries -- P1 should not be asked for facts nobody uses.

    A key is live if a factor demands it, or if ``derive_signals`` consumes it and
    exposes a derived signal instead. Anything else must be a deliberate entry in
    ``UNSCORED_CONTEXT_KEYS``.

    This is deliberately not a source grep. The obvious version -- search
    ``rules.py`` for the key as a string literal -- can never fail, because the
    key *is* a string literal in the very ``context_keys`` tuple being checked.
    An earlier version of this test did exactly that and reported a clean bill of
    health for four keys nothing reads.
    """
    read_by_a_factor = {key for factor in rule.factors for key in factor.requires}
    live = read_by_a_factor | CONTEXT_KEYS_CONSUMED | UNSCORED_CONTEXT_KEYS

    dead = set(rule.context_keys) - live
    assert not dead, (
        f"{rule.rule_id} declares {sorted(dead)} in context_keys, but no factor "
        f"requires it, derive_signals does not consume it, and it is not listed in "
        f"UNSCORED_CONTEXT_KEYS. Either score it, drop it from context_keys, or add "
        f"it to UNSCORED_CONTEXT_KEYS to record that the gap is accepted."
    )


def test_the_unscored_key_ledger_has_no_stale_entries():
    """A ledger of accepted gaps must shrink when a gap closes.

    Without this, scoring a key that used to be unscored would leave it declared
    here forever, and the next person would read the entry as "still not scored".
    """
    declared = {key for rule in RULES for key in rule.context_keys}
    read_by_a_factor = {key for rule in RULES for factor in rule.factors for key in factor.requires}

    stale = UNSCORED_CONTEXT_KEYS - declared
    assert not stale, f"UNSCORED_CONTEXT_KEYS lists keys no rule declares: {sorted(stale)}"

    now_scored = UNSCORED_CONTEXT_KEYS & (read_by_a_factor | CONTEXT_KEYS_CONSUMED)
    assert not now_scored, (
        f"{sorted(now_scored)} is listed in UNSCORED_CONTEXT_KEYS but is now read -- "
        f"remove it from the ledger"
    )
