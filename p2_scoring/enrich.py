"""P2 orchestrator: raw finding JSON in, enriched finding JSON out.

This is the module boundary P1 and P3 both talk to. P1 hands it raw findings
(``schema/raw_finding_schema.json``); it hands back findings conforming to the
agreed ``schema/finding_schema.json`` -- with `risk_score`, `score_breakdown`,
`compliance_mappings` and `explanation` populated.

CLI
---
    python -m p2_scoring.enrich --in data/mock_findings.raw.json --out data/mock_findings.json

Also reads/writes ``-`` for stdin/stdout, so it drops into a shell pipeline::

    p1_scan | python -m p2_scoring.enrich --in - --out - | p3_ingest

Failure policy
--------------
An unrecognised ``rule_id`` **aborts the run by default**. Dropping a finding
because its rule is unknown would turn a genuine misconfiguration into a clean
dashboard -- the worst possible failure mode for this product. Pass
``--skip-unknown-rules`` when you are deliberately integrating a new P1 rule and
want the rest of the scan to land; every skip is reported.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from .compliance import clauses_for
from .explanations import explanation_for
from .rules import UnknownRuleError, risk_band
from .scoring import ScoreResult, score_finding

#: Fields the enriched output carries, in a stable order.
OUTPUT_FIELD_ORDER: tuple[str, ...] = (
    "finding_id",
    "rule_id",
    "scan_id",
    "resource",
    "detection_source",
    "severity_raw",
    "risk_score",
    "score_breakdown",
    "compliance_mappings",
    "explanation",
    "status",
    "detected_at",
    "last_seen_at",
    # --- additive extension, permitted by the schema ---
    # Retained so a card can be traced all the way back to the observed facts:
    # context -> factors -> score. Purely additive; P1's schema does not forbid it.
    "context",
)

DEFAULT_STATUS = "open"


class EnrichmentError(ValueError):
    """A raw finding could not be enriched."""


@dataclass
class EnrichmentReport:
    """Bookkeeping for one enrichment run."""

    findings: list[dict[str, Any]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    skipped: list[dict[str, str]] = field(default_factory=list)

    def add_warning(self, message: str) -> None:
        self.warnings.append(message)

    def band_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for finding in self.findings:
            band = risk_band(finding["risk_score"])
            counts[band] = counts.get(band, 0) + 1
        return counts


def _require(raw: Mapping[str, Any], key: str, where: str) -> Any:
    if key not in raw or raw[key] in (None, ""):
        raise EnrichmentError(f"{where}: required field {key!r} is missing")
    return raw[key]


def enrich_finding(raw: Mapping[str, Any], report: EnrichmentReport | None = None) -> dict[str, Any]:
    """Enrich one raw finding into a schema-conformant finding.

    Raises:
        EnrichmentError: a required field is missing, or the rule is unknown.
        UnknownRuleError: (a subclass of KeyError) unknown rule_id.
    """
    where = f"finding {raw.get('finding_id') or '<no id>'}"

    finding_id = _require(raw, "finding_id", where)
    rule_id = str(_require(raw, "rule_id", where))
    where = f"finding {finding_id} ({rule_id})"

    score: ScoreResult = score_finding(raw)

    if score.rule.resource_types and score.signals["resource_type"] not in score.rule.resource_types:
        if report is not None:
            report.add_warning(
                f"{where}: rule expects resource type(s) "
                f"{list(score.rule.resource_types)}, got {score.signals['resource_type']!r}"
            )

    if not score.substantiated:
        # The rule fired but no factor could be evaluated. Almost always means
        # P1 did not populate `context` for this rule, not that the resource is safe.
        if report is not None:
            report.add_warning(
                f"{where}: scored 0 -- no scoring factor was substantiated. "
                f"P1 most likely did not populate `context` (expected keys: "
                f"{list(score.rule.context_keys)})."
            )

    explanation = explanation_for(score.signals, rule_id)

    finding: dict[str, Any] = {
        "finding_id": finding_id,
        "rule_id": rule_id,
        "scan_id": _require(raw, "scan_id", where),
        "resource": dict(_require(raw, "resource", where)),
        "detection_source": raw.get("detection_source", "rule_engine"),
        "severity_raw": raw.get("severity_raw", score.rule.base_severity),
        "risk_score": score.risk_score,
        "score_breakdown": score.score_breakdown,
        "compliance_mappings": clauses_for(rule_id),
        "explanation": explanation,
        "status": raw.get("status", DEFAULT_STATUS),
        "detected_at": _require(raw, "detected_at", where),
        "last_seen_at": _require(raw, "last_seen_at", where),
        "context": dict(raw.get("context") or {}),
    }
    return {key: finding[key] for key in OUTPUT_FIELD_ORDER}


def enrich_findings(
    raws: Iterable[Mapping[str, Any]],
    *,
    strict_unknown_rules: bool = True,
    report: EnrichmentReport | None = None,
) -> EnrichmentReport:
    """Enrich a batch of raw findings.

    With ``strict_unknown_rules=False`` a finding citing an unknown rule is
    skipped and recorded in ``report.skipped`` instead of aborting the run.
    """
    report = report or EnrichmentReport()

    for raw in raws:
        try:
            report.findings.append(enrich_finding(raw, report))
        except UnknownRuleError as exc:
            if strict_unknown_rules:
                raise
            report.skipped.append(
                {
                    "finding_id": str(raw.get("finding_id", "<no id>")),
                    "rule_id": str(raw.get("rule_id", "<no rule>")),
                    "reason": str(exc).split(".")[0],
                }
            )
            report.add_warning(f"Skipped finding {raw.get('finding_id')}: unknown rule {exc.rule_id}")

    report.findings.sort(key=lambda f: (-f["risk_score"], f["finding_id"]))
    return report


# --------------------------------------------------------------------------
# Schema validation (optional -- jsonschema is not a hard dependency of P2)
# --------------------------------------------------------------------------

def schema_path() -> Path:
    return Path(__file__).resolve().parent.parent / "schema" / "finding_schema.json"


def validate_findings(findings: Sequence[Mapping[str, Any]]) -> list[str]:
    """Validate findings against the agreed schema.

    Returns a list of human-readable problems (empty means clean). If
    ``jsonschema`` is not installed, returns a single explanatory message rather
    than pretending the data is valid.
    """
    try:
        import jsonschema  # type: ignore[import-not-found]
    except ImportError:  # pragma: no cover - depends on environment
        return ["jsonschema is not installed; schema validation skipped"]

    with schema_path().open(encoding="utf-8") as handle:
        schema = json.load(handle)

    validator = jsonschema.Draft7Validator(schema)
    problems: list[str] = []
    for finding in findings:
        for error in sorted(validator.iter_errors(finding), key=lambda e: list(e.path)):
            location = "/".join(str(p) for p in error.path) or "<root>"
            problems.append(f"{finding.get('finding_id', '?')}: {location}: {error.message}")
    return problems


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def _read_json(path: str) -> Any:
    if path == "-":
        return json.load(sys.stdin)
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def _write_json(payload: Any, path: str) -> None:
    text = json.dumps(payload, indent=2, ensure_ascii=False) + "\n"
    if path == "-":
        sys.stdout.write(text)
    else:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(text, encoding="utf-8")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m p2_scoring.enrich",
        description="Enrich raw detection findings with risk score, explanation and compliance mappings.",
    )
    parser.add_argument("--in", dest="infile", required=True, help="Raw findings JSON ('-' for stdin)")
    parser.add_argument("--out", dest="outfile", default="-", help="Enriched findings JSON ('-' for stdout)")
    parser.add_argument(
        "--skip-unknown-rules",
        action="store_true",
        help="Skip findings whose rule_id P2 does not know, instead of aborting the run.",
    )
    parser.add_argument("--validate", action="store_true", help="Validate output against schema/finding_schema.json")
    parser.add_argument("--quiet", action="store_true", help="Suppress the summary report on stderr")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    payload = _read_json(args.infile)
    if isinstance(payload, Mapping):
        payload = [payload]
    if not isinstance(payload, list):
        print("error: input must be a JSON array of raw findings", file=sys.stderr)
        return 2

    try:
        report = enrich_findings(payload, strict_unknown_rules=not args.skip_unknown_rules)
    except UnknownRuleError as exc:
        print(f"error: {exc}", file=sys.stderr)
        print("hint: pass --skip-unknown-rules to continue and report the skip.", file=sys.stderr)
        return 1
    except EnrichmentError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    _write_json(report.findings, args.outfile)

    if args.validate:
        problems = validate_findings(report.findings)
        report.warnings.extend(f"schema: {p}" for p in problems)

    if not args.quiet:
        label = args.infile if args.infile != "-" else "<stdin>"
        print(f"enriched {len(report.findings)} finding(s) from {label}", file=sys.stderr)
        for band, count in sorted(report.band_counts().items()):
            print(f"  {band:<9} {count}", file=sys.stderr)
        if report.skipped:
            print(f"  skipped   {len(report.skipped)} unknown-rule finding(s)", file=sys.stderr)
        for warning in report.warnings:
            print(f"  warning: {warning}", file=sys.stderr)

    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
