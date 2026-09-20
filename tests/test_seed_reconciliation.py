"""Reconcile P2's engine against the Week-0 hand-authored mock findings.

`data/seed/mock_findings.handcrafted.json` is the artifact the team agreed on
before any code existed. It is the closest thing this project has to a
specification, so the engine is held to it: run the raw equivalent of each
hand-authored finding through `enrich_finding` and the numbers must come out the
same.

Two findings in that file did not add up -- their `score_breakdown` summed to
less than their `risk_score` (82 vs 90, and 50 vs 55). Rather than fudge the
totals or quietly ignore the gap, the engine models the difference as an
explicit named *synergy* factor, which is what the detection-rules doc already
anticipated ("exposure combination with other findings"). The result reconciles
exactly AND the breakdown still sums to the score.

`test_only_the_expected_findings_gained_a_synergy_factor` pins that exception so
it cannot silently spread to other rules.
"""

from __future__ import annotations

import pytest

from p2_scoring import enrich_finding

#: Findings whose hand-authored breakdown omitted a synergy term. Keys are
#: finding_id; values are the factor the engine added to close the gap.
EXPECTED_SYNERGY_UPLIFTS = {
    "f1a1b111-0009-4a1a-9a11-000000000009": "public_exposure_without_encryption",
    "f1a1b111-0010-4a1a-9a11-000000000010": "elevated_access_without_mfa",
}


@pytest.fixture(scope="module")
def reconciled(handcrafted_findings, raws_by_id):
    """Enrich each hand-authored finding's raw counterpart."""
    out = {}
    for handcrafted in handcrafted_findings:
        finding_id = handcrafted["finding_id"]
        raw = raws_by_id.get(finding_id)
        if raw is None:
            pytest.skip(f"no raw counterpart for {finding_id}")
        out[finding_id] = (handcrafted, enrich_finding(raw))
    return out


def test_every_handcrafted_finding_has_a_raw_counterpart(handcrafted_findings, raws_by_id):
    """The raw fixture must cover the whole hand-authored set."""
    missing = [f["finding_id"] for f in handcrafted_findings if f["finding_id"] not in raws_by_id]
    assert not missing, f"raw mock file is missing counterparts for: {missing}"


def test_risk_scores_match_the_handcrafted_file(reconciled):
    """The headline claim: P2 computes the same score a human did, from raw facts."""
    mismatches = [
        (fid, handcrafted["risk_score"], enriched["risk_score"])
        for fid, (handcrafted, enriched) in reconciled.items()
        if handcrafted["risk_score"] != enriched["risk_score"]
    ]
    assert not mismatches, f"score drift (finding_id, handcrafted, engine): {mismatches}"


def test_engine_never_disagrees_with_a_handauthored_factor_weight(reconciled):
    """Every factor the human listed must appear with the identical weight.

    The engine is allowed to *add* a factor (the synergy cases) but never to
    silently re-price one that was already agreed.
    """
    problems = []
    for finding_id, (handcrafted, enriched) in reconciled.items():
        engine = {f["factor"]: f["weight"] for f in enriched["score_breakdown"]}
        for factor in handcrafted["score_breakdown"]:
            if engine.get(factor["factor"]) != factor["weight"]:
                problems.append(
                    f"{finding_id}: {factor['factor']} handcrafted={factor['weight']} engine={engine.get(factor['factor'])}"
                )
    assert not problems, problems


def test_breakdown_sums_to_the_score_for_every_reconciled_finding(reconciled):
    """The invariant must survive contact with the real seed data."""
    for finding_id, (_handcrafted, enriched) in reconciled.items():
        total = sum(f["weight"] for f in enriched["score_breakdown"])
        assert total == enriched["risk_score"], f"{finding_id}: {total} != {enriched['risk_score']}"


def test_only_the_expected_findings_gained_a_synergy_factor(reconciled):
    """Confine the documented exception to exactly two findings.

    If a future edit makes the engine disagree with the hand-authored file
    somewhere new, this fails and names the finding, instead of the change
    sliding through as 'just a weight tweak'.
    """
    actual = {}
    for finding_id, (handcrafted, enriched) in reconciled.items():
        handcrafted_factors = {f["factor"] for f in handcrafted["score_breakdown"]}
        added = {f["factor"] for f in enriched["score_breakdown"]} - handcrafted_factors
        if added:
            actual[finding_id] = added

    assert set(actual) == set(EXPECTED_SYNERGY_UPLIFTS), (
        f"unexpected synergy drift. Unexpected: "
        f"{ {k: v for k, v in actual.items() if k not in EXPECTED_SYNERGY_UPLIFTS} }. "
        f"Missing: {set(EXPECTED_SYNERGY_UPLIFTS) - set(actual)}"
    )

    for finding_id, expected_factor in EXPECTED_SYNERGY_UPLIFTS.items():
        assert actual[finding_id] == {expected_factor}


def test_projected_scores_match_the_handcrafted_file(reconciled):
    mismatches = [
        (fid, handcrafted["explanation"]["projected_score_after_fix"], enriched["explanation"]["projected_score_after_fix"])
        for fid, (handcrafted, enriched) in reconciled.items()
        if handcrafted["explanation"]["projected_score_after_fix"]
        != enriched["explanation"]["projected_score_after_fix"]
    ]
    assert not mismatches, f"projected_score_after_fix drift: {mismatches}"


def test_projected_score_is_always_below_the_current_score(reconciled):
    """A 'fix' that does not reduce risk is not a fix."""
    for finding_id, (_handcrafted, enriched) in reconciled.items():
        assert enriched["explanation"]["projected_score_after_fix"] < enriched["risk_score"], finding_id


def test_enriched_output_matches_the_agreed_schema(handcrafted_findings, raws_by_id):
    """Every enriched finding validates against schema/finding_schema.json."""
    from p2_scoring import validate_findings

    enriched = [enrich_finding(raws_by_id[f["finding_id"]]) for f in handcrafted_findings]
    problems = validate_findings(enriched)
    assert not problems, "\n".join(problems)


def test_enriching_the_whole_raw_fixture_produces_no_warnings(raw_mocks):
    """The 12-entry raw fixture should enrich cleanly -- no zero scores, no skips."""
    from p2_scoring import enrich_findings

    report = enrich_findings(raw_mocks)
    assert not report.skipped
    assert not report.warnings, report.warnings
    assert len(report.findings) == len(raw_mocks)


def test_results_are_sorted_by_descending_risk(raw_mocks):
    from p2_scoring import enrich_findings

    scores = [f["risk_score"] for f in enrich_findings(raw_mocks).findings]
    assert scores == sorted(scores, reverse=True)
