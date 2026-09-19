"""Data access for P3: upsert findings, query them, aggregate for the dashboard.

All SQL lives here. The API layer (`app.py`) does HTTP concerns only, so the
query behaviour can be tested without going through FastAPI.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping, Sequence

from p2_scoring.rules import risk_band

#: Statuses a human sets deliberately. A re-scan must not quietly undo these.
HUMAN_SET_STATUSES = frozenset({"acknowledged", "remediated", "false_positive"})

#: The one human status a re-scan is allowed to override.
#:
#: `remediated` means "we fixed this", so seeing it again is a *regression* --
#: that is news, and it should reopen. `false_positive` means "this was never a
#: real problem", and the scanner will go on re-detecting the same
#: misconfiguration on every single run; reopening it each time would force the
#: analyst to re-mark it forever, which is exactly the workflow the human
#: statuses exist to prevent. So it is preserved like `acknowledged`.
REOPENABLE_STATUSES = frozenset({"remediated"})

SORTABLE_COLUMNS = {
    "risk_score": "risk_score",
    "detected_at": "detected_at",
    "last_seen_at": "last_seen_at",
    "first_seen_at": "first_seen_at",
    "resource_name": "resource_name",
    "rule_id": "rule_id",
    "status": "status",
}


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class UpsertOutcome:
    """What happened to one finding during ingest."""

    new: int = 0
    updated: int = 0
    reopened: int = 0
    unchanged: int = 0

    def as_dict(self) -> dict[str, int]:
        return {
            "new": self.new,
            "updated": self.updated,
            "reopened": self.reopened,
            "unchanged": self.unchanged,
        }


def _row_columns(finding: Mapping[str, Any]) -> dict[str, Any]:
    """Derive the indexed columns for a finding document."""
    resource = finding.get("resource") or {}
    score = int(finding.get("risk_score") or 0)
    frameworks = sorted(
        {m["framework"] for m in finding.get("compliance_mappings", ())},
    )
    return {
        "finding_id": finding["finding_id"],
        "scan_id": finding["scan_id"],
        "rule_id": finding["rule_id"],
        "resource_type": resource.get("type", ""),
        "resource_id": resource.get("id", ""),
        "resource_name": resource.get("name", ""),
        "resource_region": resource.get("region", ""),
        "detection_source": finding.get("detection_source", "rule_engine"),
        "severity_raw": finding.get("severity_raw", ""),
        "risk_score": score,
        "risk_band": risk_band(score),
        "status": finding.get("status", "open"),
        "frameworks": ",".join(frameworks),
        "detected_at": finding.get("detected_at", ""),
        "last_seen_at": finding.get("last_seen_at", ""),
    }


def upsert_finding(connection: sqlite3.Connection, finding: Mapping[str, Any]) -> str:
    """Insert or update one enriched finding.

    Returns one of ``new`` / ``updated`` / ``reopened`` / ``unchanged``.

    Status handling on re-detection is the interesting part. A finding that a
    human marked `remediated` and that shows up again in a new scan is a
    **regression**, so it reopens and `reopen_count` increments -- that counter
    is how a compliance team notices a fix that did not stick. A finding marked
    `acknowledged` or `false_positive` keeps its status: in both cases the human
    already made the call, and a nightly scan that reset them would mean
    re-deciding the same finding every night. See `REOPENABLE_STATUSES`.
    """
    columns = _row_columns(finding)
    now = _now()

    existing = connection.execute(
        "SELECT status, risk_score, reopen_count FROM findings WHERE finding_id = ?",
        (finding["finding_id"],),
    ).fetchone()

    if existing is None:
        connection.execute(
            """
            INSERT INTO findings (
                finding_id, scan_id, rule_id, resource_type, resource_id, resource_name,
                resource_region, detection_source, severity_raw, risk_score, risk_band,
                status, frameworks, detected_at, last_seen_at, first_seen_at, updated_at,
                reopen_count, document
            ) VALUES (
                :finding_id, :scan_id, :rule_id, :resource_type, :resource_id, :resource_name,
                :resource_region, :detection_source, :severity_raw, :risk_score, :risk_band,
                :status, :frameworks, :detected_at, :last_seen_at, :first_seen_at, :updated_at,
                0, :document
            )
            """,
            {
                **columns,
                "first_seen_at": now,
                "updated_at": now,
                # P3-owned fields go in the document as well as the columns --
                # the document is what every read path serves. See the UPDATE
                # path below for why that matters.
                "document": json.dumps(
                    {**finding, "status": columns["status"], "reopen_count": 0},
                    ensure_ascii=False,
                ),
            },
        )
        return "new"

    previous_status = existing["status"]
    status = columns["status"]
    reopened = previous_status in REOPENABLE_STATUSES and status == "open"

    if reopened:
        # clear the remediated state so the finding is visibly actionable again
        status = "open"
    elif previous_status in HUMAN_SET_STATUSES:
        # preserve the human decision rather than letting the scan clobber it
        status = previous_status

    columns["status"] = status
    reopen_delta = 1 if reopened else 0

    # The columns are derived; the *document* is what `find_findings` and
    # `get_finding` return, and therefore what the dashboard renders. Writing the
    # incoming document verbatim would store a document saying status="open"
    # beside a status column saying "acknowledged": the human's decision would be
    # preserved in the table and silently discarded on the way to the screen. The
    # effective status (and the reopen counter) must be written into the document
    # to be preserved at all.
    document = json.dumps(
        {
            **finding,
            "status": status,
            "reopen_count": existing["reopen_count"] + reopen_delta,
        },
        ensure_ascii=False,
    )

    connection.execute(
        """
        UPDATE findings SET
            scan_id = :scan_id, rule_id = :rule_id, resource_type = :resource_type,
            resource_id = :resource_id, resource_name = :resource_name,
            resource_region = :resource_region, detection_source = :detection_source,
            severity_raw = :severity_raw, risk_score = :risk_score, risk_band = :risk_band,
            status = :status, frameworks = :frameworks, detected_at = :detected_at,
            last_seen_at = :last_seen_at, updated_at = :updated_at,
            reopen_count = reopen_count + :reopen_delta, document = :document
        WHERE finding_id = :finding_id
        """,
        {
            **columns,
            "updated_at": now,
            "reopen_delta": reopen_delta,
            "document": document,
        },
    )

    if reopened:
        return "reopened"
    if existing["risk_score"] != columns["risk_score"] or previous_status != status:
        return "updated"
    return "unchanged"


def ingest(
    connection: sqlite3.Connection,
    findings: Sequence[Mapping[str, Any]],
    *,
    skipped_count: int = 0,
) -> tuple[UpsertOutcome, str | None]:
    """Store a batch of enriched findings and record the scan(s).

    Returns the outcome tally and the batch's dominant ``scan_id`` (None when the
    batch is empty) -- "dominant" meaning the one most of the batch belongs to,
    which is what a caller reports as *the* scan.

    A batch may span more than one ``scan_id`` (the seed data does). Each gets
    its own row, because ``/trend``'s per-scan view is read as a history of scan
    runs: recording only the dominant one would drop a run from that history and
    show a single point where the data describes two.
    """
    outcome = UpsertOutcome()
    results_by_scan: dict[str, list[str]] = {}
    findings_by_scan: dict[str, list[Mapping[str, Any]]] = {}

    for finding in findings:
        result = upsert_finding(connection, finding)
        setattr(outcome, result, getattr(outcome, result) + 1)
        scan_id = str(finding.get("scan_id", ""))
        results_by_scan.setdefault(scan_id, []).append(result)
        findings_by_scan.setdefault(scan_id, []).append(finding)

    if not findings:
        connection.commit()
        return outcome, None

    dominant = max(findings_by_scan, key=lambda s: len(findings_by_scan[s]))

    for scan_id, batch in findings_by_scan.items():
        results = results_by_scan[scan_id]
        scores = [int(f.get("risk_score") or 0) for f in batch]
        connection.execute(
            """
            INSERT INTO scans (scan_id, ingested_at, finding_count, new_count,
                               updated_count, reopened_count, skipped_count, avg_score)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(scan_id) DO UPDATE SET
                ingested_at    = excluded.ingested_at,
                finding_count  = excluded.finding_count,
                new_count      = excluded.new_count,
                updated_count  = excluded.updated_count,
                reopened_count = excluded.reopened_count,
                skipped_count  = excluded.skipped_count,
                avg_score      = excluded.avg_score
            """,
            (
                scan_id,
                _now(),
                len(batch),
                results.count("new"),
                results.count("updated"),
                results.count("reopened"),
                # Skips carry no scan_id, so they are attributed to the dominant
                # scan rather than smeared across every row in the batch.
                skipped_count if scan_id == dominant else 0,
                round(sum(scores) / len(scores), 1) if scores else 0.0,
            ),
        )

    connection.commit()
    return outcome, dominant


# --------------------------------------------------------------------------
# Queries
# --------------------------------------------------------------------------

@dataclass
class FindingQuery:
    """Filters for the findings list. Mirrors the dashboard's filter bar."""

    band: Sequence[str] = ()
    status: Sequence[str] = ()
    rule_id: Sequence[str] = ()
    resource_type: Sequence[str] = ()
    framework: Sequence[str] = ()
    detection_source: Sequence[str] = ()
    scan_id: str | None = None
    min_score: int | None = None
    search: str | None = None
    sort: str = "risk_score"
    order: str = "desc"
    limit: int = 100
    offset: int = 0


def _build_where(query: FindingQuery) -> tuple[str, list[Any]]:
    clauses: list[str] = []
    params: list[Any] = []

    def any_of(column: str, values: Sequence[str]) -> None:
        if not values:
            return
        clauses.append(f"{column} IN ({','.join('?' * len(values))})")
        params.extend(values)

    any_of("risk_band", query.band)
    any_of("status", query.status)
    any_of("rule_id", query.rule_id)
    any_of("resource_type", query.resource_type)
    any_of("detection_source", query.detection_source)

    if query.framework:
        # `frameworks` is a comma list; match on delimited membership so
        # 'SOC2' cannot match a hypothetical 'SOC20'.
        framework_clauses = []
        for framework in query.framework:
            framework_clauses.append("(',' || frameworks || ',') LIKE ?")
            params.append(f"%,{framework},%")
        clauses.append("(" + " OR ".join(framework_clauses) + ")")

    if query.scan_id:
        clauses.append("scan_id = ?")
        params.append(query.scan_id)

    if query.min_score is not None:
        clauses.append("risk_score >= ?")
        params.append(query.min_score)

    if query.search:
        clauses.append(
            "(resource_name LIKE ? OR rule_id LIKE ? OR finding_id LIKE ? OR resource_id LIKE ?)"
        )
        needle = f"%{query.search}%"
        params.extend([needle] * 4)

    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    return where, params


def find_findings(connection: sqlite3.Connection, query: FindingQuery) -> tuple[list[dict], int]:
    """Return (findings, total_matching) for a filter set.

    The full document is returned rather than the denormalised columns, so the
    API always serves exactly what P2 produced.
    """
    where, params = _build_where(query)

    total = connection.execute(
        f"SELECT COUNT(*) AS n FROM findings {where}", params
    ).fetchone()["n"]

    sort_column = SORTABLE_COLUMNS.get(query.sort, "risk_score")
    direction = "ASC" if query.order.lower() == "asc" else "DESC"

    rows = connection.execute(
        f"""
        SELECT document FROM findings {where}
        ORDER BY {sort_column} {direction}, finding_id ASC
        LIMIT ? OFFSET ?
        """,
        [*params, query.limit, query.offset],
    ).fetchall()

    return [json.loads(row["document"]) for row in rows], total


def get_finding(connection: sqlite3.Connection, finding_id: str) -> dict | None:
    row = connection.execute(
        "SELECT document FROM findings WHERE finding_id = ?", (finding_id,)
    ).fetchone()
    return json.loads(row["document"]) if row else None


def update_status(connection: sqlite3.Connection, finding_id: str, status: str) -> dict | None:
    """Set a finding's workflow status. Returns the updated document, or None."""
    row = connection.execute(
        "SELECT document FROM findings WHERE finding_id = ?", (finding_id,)
    ).fetchone()
    if row is None:
        return None

    document = json.loads(row["document"])
    document["status"] = status
    connection.execute(
        "UPDATE findings SET status = ?, document = ?, updated_at = ? WHERE finding_id = ?",
        (status, json.dumps(document, ensure_ascii=False), _now(), finding_id),
    )
    connection.commit()
    return document


def delete_findings(connection: sqlite3.Connection, finding_ids: Iterable[str]) -> int:
    ids = list(finding_ids)
    if not ids:
        return 0
    cursor = connection.execute(
        f"DELETE FROM findings WHERE finding_id IN ({','.join('?' * len(ids))})", ids
    )
    connection.commit()
    return cursor.rowcount


def clear(connection: sqlite3.Connection) -> None:
    """Wipe findings and scans. Used by tests and the `--reset` dev flag."""
    connection.executescript("DELETE FROM findings; DELETE FROM scans;")
    connection.commit()


# --------------------------------------------------------------------------
# Aggregations for the dashboard
# --------------------------------------------------------------------------

def summary_stats(connection: sqlite3.Connection) -> dict[str, Any]:
    """Headline numbers for the dashboard tiles."""
    row = connection.execute(
        """
        SELECT
            COUNT(*)                                        AS total,
            COALESCE(SUM(status = 'open'), 0)               AS open_count,
            COALESCE(SUM(status = 'acknowledged'), 0)       AS acknowledged_count,
            COALESCE(SUM(status = 'remediated'), 0)         AS remediated_count,
            COALESCE(SUM(status = 'false_positive'), 0)     AS false_positive_count,
            COALESCE(SUM(risk_band = 'critical'), 0)        AS critical_count,
            COALESCE(SUM(detection_source = 'anomaly_detection'), 0) AS anomaly_count,
            COALESCE(AVG(risk_score), 0)                    AS avg_score
        FROM findings
        """
    ).fetchone()

    open_row = connection.execute(
        "SELECT COALESCE(AVG(risk_score), 0) AS a FROM findings WHERE status = 'open'"
    ).fetchone()

    scans = connection.execute(
        "SELECT COUNT(*) AS n, MAX(ingested_at) AS last FROM scans"
    ).fetchone()

    return {
        "total": row["total"],
        "open": row["open_count"],
        "acknowledged": row["acknowledged_count"],
        "remediated": row["remediated_count"],
        "false_positive": row["false_positive_count"],
        "critical": row["critical_count"],
        "anomaly_findings": row["anomaly_count"],
        "average_score": round(row["avg_score"], 1),
        "average_open_score": round(open_row["a"], 1),
        "scan_count": scans["n"],
        "last_scan_at": scans["last"],
    }


def _grouped(
    connection: sqlite3.Connection, column: str, *, open_only: bool = False
) -> list[dict[str, Any]]:
    where = "WHERE status = 'open'" if open_only else ""
    rows = connection.execute(
        f"""
        SELECT {column} AS label,
               COUNT(*) AS count,
               COALESCE(AVG(risk_score), 0) AS avg_score,
               COALESCE(MAX(risk_score), 0) AS max_score
        FROM findings {where}
        GROUP BY {column}
        ORDER BY count DESC, label ASC
        """
    ).fetchall()
    return [
        {
            "label": row["label"],
            "count": row["count"],
            "avg_score": round(row["avg_score"], 1),
            "max_score": row["max_score"],
        }
        for row in rows
    ]


def by_band(connection: sqlite3.Connection) -> list[dict[str, Any]]:
    """Severity distribution. Ordered worst-first, which is how it reads on a chart."""
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    rows = _grouped(connection, "risk_band")
    return sorted(rows, key=lambda r: order.get(r["label"], 99))


def by_service(connection: sqlite3.Connection) -> list[dict[str, Any]]:
    """Findings per AWS service (derived from the resource type)."""
    return _grouped(connection, "resource_type")


def by_rule(connection: sqlite3.Connection) -> list[dict[str, Any]]:
    return _grouped(connection, "rule_id")


def by_status(connection: sqlite3.Connection) -> list[dict[str, Any]]:
    return _grouped(connection, "status")


def compliance_summary(connection: sqlite3.Connection) -> list[dict[str, Any]]:
    """Per-framework counts plus the clauses driving them."""
    frameworks = connection.execute(
        "SELECT DISTINCT frameworks FROM findings WHERE frameworks <> ''"
    ).fetchall()

    seen: list[str] = []
    for row in frameworks:
        for framework in row["frameworks"].split(","):
            if framework and framework not in seen:
                seen.append(framework)

    results: list[dict[str, Any]] = []
    for framework in seen:
        # match on delimited membership so SOC2 cannot match SOC20
        like = f"%,{framework},%"
        totals = connection.execute(
            """
            SELECT COUNT(*) AS n,
                   COALESCE(SUM(status = 'open'), 0) AS open_count,
                   COALESCE(SUM(risk_band = 'critical'), 0) AS critical_count,
                   COALESCE(AVG(risk_score), 0) AS avg_score
            FROM findings WHERE (',' || frameworks || ',') LIKE ?
            """,
            (like,),
        ).fetchone()

        clause_rows = connection.execute(
            """
            SELECT json_extract(mapping.value, '$.clause')             AS clause,
                   json_extract(mapping.value, '$.clause_description') AS clause_description,
                   COUNT(*) AS count
            FROM findings,
                 json_each(json_extract(document, '$.compliance_mappings')) AS mapping
            WHERE json_extract(mapping.value, '$.framework') = ?
            GROUP BY clause, clause_description
            ORDER BY count DESC, clause ASC
            """,
            (framework,),
        ).fetchall()

        results.append(
            {
                "framework": framework,
                "finding_count": totals["n"],
                "open_count": totals["open_count"],
                "critical_count": totals["critical_count"],
                "average_score": round(totals["avg_score"], 1),
                "clauses": [dict(row) for row in clause_rows],
            }
        )

    return results


def trend(connection: sqlite3.Connection) -> dict[str, list[dict[str, Any]]]:
    """New findings over time, for the trend chart.

    Two cuts, because they answer different questions: ``by_day`` shows whether
    the environment is getting better or worse over calendar time, and
    ``by_scan`` shows it per scan run, which is what a live demo steps through.

    ``by_day`` buckets on ``detected_at`` -- when the misconfiguration first
    existed in AWS -- not ``first_seen_at`` (when this system stored it). They
    differ whenever a scan backfills history, and ``detected_at`` is the one
    that describes the environment rather than the pipeline.
    """
    by_day = connection.execute(
        """
        SELECT substr(detected_at, 1, 10) AS date,
               COUNT(*) AS count,
               COALESCE(AVG(risk_score), 0) AS avg_score,
               COALESCE(SUM(risk_band = 'critical'), 0) AS critical,
               COALESCE(SUM(risk_band = 'high'), 0) AS high
        FROM findings
        WHERE detected_at <> ''
        GROUP BY date
        ORDER BY date ASC
        """
    ).fetchall()

    by_scan = connection.execute(
        """
        SELECT scan_id, ingested_at, finding_count, new_count, reopened_count,
               skipped_count, avg_score
        FROM scans
        -- scan_id breaks ties: a single batch spanning several scans stamps them
        -- all with the same ingest time, and an unstable order would draw the
        -- per-scan line in an arbitrary sequence.
        ORDER BY ingested_at ASC, scan_id ASC
        """
    ).fetchall()

    return {
        "by_day": [
            {
                "date": row["date"],
                "count": row["count"],
                "avg_score": round(row["avg_score"], 1),
                "critical": row["critical"],
                "high": row["high"],
            }
            for row in by_day
        ],
        "by_scan": [dict(row) for row in by_scan],
    }


def filter_options(connection: sqlite3.Connection) -> dict[str, list[str]]:
    """Distinct values to populate the dashboard's filter dropdowns.

    Keys match the ``GET /findings`` query parameters they populate, so a
    control's filter key is also its options key. ``risk_band`` is the column,
    but the parameter that filters on it is ``band`` -- returning the column name
    here would leave the severity control silently empty.
    """

    def distinct(column: str) -> list[str]:
        rows = connection.execute(
            f"SELECT DISTINCT {column} AS v FROM findings WHERE {column} <> '' ORDER BY v"
        ).fetchall()
        return [row["v"] for row in rows]

    frameworks: set[str] = set()
    for row in connection.execute("SELECT frameworks FROM findings WHERE frameworks <> ''"):
        frameworks.update(f for f in row["frameworks"].split(",") if f)

    from p2_scoring.compliance import FRAMEWORK_ORDER

    return {
        "rule_id": distinct("rule_id"),
        "resource_type": distinct("resource_type"),
        "status": distinct("status"),
        "band": distinct("risk_band"),
        "scan_id": distinct("scan_id"),
        "detection_source": distinct("detection_source"),
        "framework": sorted(frameworks, key=lambda f: (FRAMEWORK_ORDER.index(f) if f in FRAMEWORK_ORDER else 99, f)),
    }


def scans(connection: sqlite3.Connection) -> list[dict[str, Any]]:
    rows = connection.execute(
        # scan_id breaks the tie for scans ingested in the same second, which is
        # every scan in a batch that spans more than one.
        "SELECT * FROM scans ORDER BY ingested_at DESC, scan_id DESC"
    ).fetchall()
    return [dict(row) for row in rows]
