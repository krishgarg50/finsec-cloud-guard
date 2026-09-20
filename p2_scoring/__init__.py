"""P2: scoring, explainability and compliance enrichment.

Public surface::

    from p2_scoring import enrich_findings, score_finding, clauses_for, explanation_for

See ``docs/P2_SCORING_SPEC.md`` for the scoring model and
``docs/INTEGRATION_CONTRACT.md`` for what P1 must send.
"""

from .compliance import (
    FRAMEWORK_ORDER,
    PROPOSED_MAPPINGS,
    RULE_COMPLIANCE,
    UnknownComplianceRuleError,
    clauses_for,
    frameworks_for,
    summarise_by_framework,
)
from .enrich import (
    EnrichmentReport,
    EnrichmentError,
    enrich_finding,
    enrich_findings,
    validate_findings,
)
from .explanations import TEMPLATES, ExplanationTemplate, explanation_for
from .rules import RULES, RULES_BY_ID, DetectionRule, Factor, UnknownRuleError, get_rule, risk_band
from .scoring import MAX_SCORE, ScoreResult, score_finding
from .signals import derive_signals

__all__ = [
    "RULES",
    "RULES_BY_ID",
    "RULE_COMPLIANCE",
    "FRAMEWORK_ORDER",
    "PROPOSED_MAPPINGS",
    "TEMPLATES",
    "MAX_SCORE",
    "DetectionRule",
    "EnrichmentError",
    "EnrichmentReport",
    "ExplanationTemplate",
    "Factor",
    "ScoreResult",
    "UnknownComplianceRuleError",
    "UnknownRuleError",
    "clauses_for",
    "derive_signals",
    "enrich_finding",
    "enrich_findings",
    "explanation_for",
    "frameworks_for",
    "get_rule",
    "risk_band",
    "score_finding",
    "summarise_by_framework",
    "validate_findings",
]
