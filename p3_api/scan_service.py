"""Scan ingest: the seam where P1's output meets P2's enrichment and P3's store.

P3 does not re-implement any scoring. It calls P2's ``enrich_findings`` and
persists the result. That keeps one implementation of the scoring rules in the
codebase, which is the entire reason P2 and P3 are separable at all.

Called by ``POST /scan``. Also importable, so the CLI and the tests can seed
the database without going through HTTP.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

from p2_scoring import EnrichmentError, enrich_findings
from p2_scoring.rules import UnknownRuleError

from . import repository


@dataclass
class ScanReport:
    """The outcome of ingesting one batch of raw findings."""

    scan_id: str | None = None
    finding_count: int = 0
    outcome: dict[str, int] = field(default_factory=dict)
    band_counts: dict[str, int] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    skipped: list[dict[str, str]] = field(default_factory=list)
    average_score: float = 0.0

    def as_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "finding_count": self.finding_count,
            "outcome": self.outcome,
            "band_counts": self.band_counts,
            "warnings": self.warnings,
            "skipped": self.skipped,
            "average_score": self.average_score,
        }


class ScanIngestError(Exception):
    """Raised when the batch cannot be ingested at all."""

    def __init__(self, message: str, *, detail: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.detail = detail


def run_scan(
    connection: sqlite3.Connection,
    raw_findings: Sequence[Mapping[str, Any]],
    *,
    strict_unknown_rules: bool = False,
) -> ScanReport:
    """Enrich a batch of raw findings and store them.

    ``strict_unknown_rules`` defaults to False here (unlike P2's CLI default),
    because this runs behind an HTTP endpoint: one rule P1 shipped ahead of P2
    should not 500 the whole scan. Skipped findings are reported in the response
    so they cannot pass unnoticed.

    Raises:
        ScanIngestError: the batch is malformed or enrichment failed outright.
    """
    if not raw_findings:
        raise ScanIngestError("no findings supplied")

    try:
        report = enrich_findings(raw_findings, strict_unknown_rules=strict_unknown_rules)
    except UnknownRuleError as exc:
        raise ScanIngestError(
            "a finding cites a rule P2 does not know",
            detail=str(exc),
        ) from exc
    except EnrichmentError as exc:
        raise ScanIngestError("a raw finding is malformed", detail=str(exc)) from exc

    if not report.findings:
        raise ScanIngestError(
            "no findings could be enriched",
            detail="; ".join(report.warnings) or "every finding was skipped",
        )

    outcome, scan_id = repository.ingest(
        connection, report.findings, skipped_count=len(report.skipped)
    )

    scores = [f["risk_score"] for f in report.findings]
    return ScanReport(
        scan_id=scan_id,
        finding_count=len(report.findings),
        outcome=outcome.as_dict(),
        band_counts=report.band_counts(),
        warnings=report.warnings,
        skipped=report.skipped,
        average_score=round(sum(scores) / len(scores), 1) if scores else 0.0,
    )


def seed_from_file(
    connection: sqlite3.Connection, path: str, *, strict_unknown_rules: bool = False
) -> ScanReport:
    """Convenience wrapper for the dev CLI: ingest a raw findings JSON file."""
    import json
    from pathlib import Path

    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(payload, Mapping):
        payload = [payload]
    return run_scan(connection, payload, strict_unknown_rules=strict_unknown_rules)
