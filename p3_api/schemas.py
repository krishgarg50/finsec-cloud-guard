"""Pydantic models for the P3 HTTP surface.

These describe the *transport* shape only. The finding document itself is served
straight from storage as P2 produced it -- deliberately not round-tripped through
a partial model, which is how fields silently disappear from an API.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

FindingStatus = Literal["open", "acknowledged", "remediated", "false_positive"]


class Resource(BaseModel):
    type: str
    id: str
    name: str
    region: str


class ScoreFactor(BaseModel):
    factor: str
    weight: float
    description: str


class ComplianceMapping(BaseModel):
    framework: str
    clause: str
    clause_description: str


class Explanation(BaseModel):
    issue: str
    consequence: str
    fix: str
    projected_score_after_fix: float


class Finding(BaseModel):
    """A fully enriched finding -- the agreed schema, validated on the way out."""

    finding_id: str
    rule_id: str
    scan_id: str
    resource: Resource
    detection_source: Literal["rule_engine", "anomaly_detection"]
    severity_raw: Literal["high", "medium", "low"]
    risk_score: float
    score_breakdown: list[ScoreFactor]
    compliance_mappings: list[ComplianceMapping]
    explanation: Explanation
    status: FindingStatus
    #: P3-owned. How many times a `remediated` finding has come back. Without it
    #: on the response, a fix that did not stick reopens silently: the scan
    #: response reports `reopened: 1` once and the finding then looks like any
    #: other open item. This is the field that makes the regression visible.
    reopen_count: int = 0
    detected_at: str
    last_seen_at: str
    #: Additive extension (permitted by the schema): the observed facts behind
    #: the score, so a card can be traced back to raw evidence in the UI.
    context: dict[str, Any] = Field(default_factory=dict)


class FindingList(BaseModel):
    items: list[Finding]
    total: int
    limit: int
    offset: int


class StatusUpdate(BaseModel):
    status: FindingStatus


class ScanRequest(BaseModel):
    """`POST /scan` accepts either a bare array or {"findings": [...]}."""

    findings: list[dict[str, Any]]


class ScanResponse(BaseModel):
    scan_id: str | None
    finding_count: int
    outcome: dict[str, int]
    band_counts: dict[str, int]
    warnings: list[str]
    skipped: list[dict[str, str]]
    average_score: float


class GroupCount(BaseModel):
    label: str
    count: int
    avg_score: float
    max_score: float


class SummaryStats(BaseModel):
    total: int
    open: int
    acknowledged: int
    remediated: int
    false_positive: int
    critical: int
    anomaly_findings: int
    average_score: float
    average_open_score: float
    scan_count: int
    last_scan_at: str | None


class ClauseCount(BaseModel):
    clause: str
    clause_description: str
    count: int


class FrameworkSummary(BaseModel):
    framework: str
    finding_count: int
    open_count: int
    critical_count: int
    average_score: float
    clauses: list[ClauseCount]


class TrendPoint(BaseModel):
    date: str
    count: int
    avg_score: float
    critical: int
    #: Counted alongside `critical` so the chart can show the two worst bands
    #: without a second request. FastAPI drops fields the model does not
    #: declare, so anything added to `repository.trend()` must be added here too.
    high: int


class ScanRecord(BaseModel):
    scan_id: str
    ingested_at: str
    finding_count: int
    new_count: int
    reopened_count: int
    skipped_count: int
    avg_score: float


class TrendResponse(BaseModel):
    by_day: list[TrendPoint]
    by_scan: list[dict[str, Any]]


class RuleInfo(BaseModel):
    """One entry in the detection-rule catalogue, served from P2's table.

    The dashboard uses this to label rules in the UI and to show what a rule
    looks for, so the two halves of the product cannot drift apart.
    """

    rule_id: str
    title: str
    base_severity: str
    resource_types: list[str]
    context_keys: list[str]
    max_score: int
    projected_score_after_fix: int
    frameworks: list[str]
    factors: list[dict[str, Any]]


class HealthResponse(BaseModel):
    status: str
    finding_count: int
    rule_count: int
