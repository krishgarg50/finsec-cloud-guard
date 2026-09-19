"""The scoring engine: raw finding -> risk score + transparent breakdown.

The contract this module guarantees, and that ``tests/test_scoring.py``
enforces on every rule:

    risk_score == min(100, sum(f.weight for f in score_breakdown))

When the raw total exceeds 100 the engine appends an explicit negative
``score_cap_adjustment`` entry rather than silently truncating. That keeps the
"the card adds up to the score" property true even at the ceiling, which is the
property an auditor actually checks.

Evidence gate
-------------
A factor only counts when the context keys it names in ``Factor.requires`` were
actually supplied. Absent (or explicitly null) keys drop the factor instead of
being read as a negative observation -- otherwise a raw finding with no context
at all would score as though every check had failed. See the module docstring
in ``rules.py`` for why that distinction matters.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from .rules import DetectionRule, Factor, UnknownRuleError, get_rule, risk_band
from .signals import derive_signals

#: The cap the finding schema places on `risk_score`.
MAX_SCORE = 100

#: Factor key used when the raw sum is clipped to MAX_SCORE.
CAP_FACTOR_KEY = "score_cap_adjustment"


@dataclass(frozen=True)
class ScoreResult:
    """Everything the engine concluded about one raw finding."""

    rule: DetectionRule
    signals: dict[str, Any]
    risk_score: int
    score_breakdown: list[dict[str, Any]]
    raw_total: int
    capped: bool
    #: Context keys some factor needed but P1 never sent. Non-empty means the
    #: score is built from partial evidence -- see `substantiated`.
    missing_evidence: tuple[str, ...] = ()

    @property
    def band(self) -> str:
        return risk_band(self.risk_score)

    @property
    def substantiated(self) -> bool:
        """True when at least one factor actually fired.

        A rule can fire while every factor predicate is False -- typically
        because P1 did not populate ``context``. That is a pipeline bug, not a
        clean resource, so callers surface it instead of reporting 'risk 0'.
        """
        return self.raw_total > 0


def _evidence_present(signals: Mapping[str, Any], factor: Factor) -> bool:
    """Whether every context key this factor needs was actually supplied.

    An explicit ``null`` counts as absent: P1 saying "here is a key, value
    unknown" is not evidence that the resource is misconfigured.
    """
    return all(signals.get(key) is not None for key in factor.requires)


def score_finding(raw: Mapping[str, Any]) -> ScoreResult:
    """Score one raw finding.

    Raises:
        UnknownRuleError: the finding cites a rule_id with no P2 definition.
        ValueError: the finding's context reuses a reserved derived key.
    """
    rule = get_rule(str(raw.get("rule_id", "")))
    signals = derive_signals(raw)

    breakdown: list[dict[str, Any]] = []
    total = 0
    missing_evidence: list[str] = []

    for factor in rule.factors:
        if not _evidence_present(signals, factor):
            missing_evidence.extend(k for k in factor.requires if signals.get(k) is None)
            continue
        if not factor.applies(signals):
            continue
        breakdown.append(
            {
                "factor": factor.key,
                "weight": factor.points,
                "description": factor.describe(signals),
            }
        )
        total += factor.points

    capped = total > MAX_SCORE
    risk_score = min(total, MAX_SCORE)

    if capped:
        # Keep the breakdown honest: show the correction that produced the score.
        breakdown.append(
            {
                "factor": CAP_FACTOR_KEY,
                "weight": MAX_SCORE - total,  # negative
                "description": (
                    f"Raw factor total of {total} exceeds the {MAX_SCORE}-point "
                    f"scale and is capped"
                ),
            }
        )

    return ScoreResult(
        rule=rule,
        signals=signals,
        risk_score=risk_score,
        score_breakdown=breakdown,
        raw_total=total,
        capped=capped,
        missing_evidence=tuple(sorted(set(missing_evidence))),
    )


__all__ = [
    "CAP_FACTOR_KEY",
    "MAX_SCORE",
    "ScoreResult",
    "UnknownRuleError",
    "score_finding",
]
