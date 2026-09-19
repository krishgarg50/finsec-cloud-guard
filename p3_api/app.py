"""P3 HTTP API.

Endpoints
---------
    GET    /health                 liveness + row counts
    POST   /scan                   ingest raw findings (P1 shape) -> enrich -> store
    GET    /findings               filtered/sorted/paged list
    GET    /findings/{id}          one finding
    PATCH  /findings/{id}          set workflow status
    GET    /stats                  dashboard aggregates in one round trip
    GET    /compliance             per-framework summary + clause breakdown
    GET    /trend                  new findings by day and by scan
    GET    /rules                  detection-rule catalogue (from P2)
    GET    /filter-options         distinct values for the filter dropdowns
    GET    /scans                  scan history
    GET    /                       the dashboard

Run it::

    python -m p3_api.app                     # http://127.0.0.1:8000
    uvicorn p3_api.app:app --reload

Data comes from P1 via ``POST /scan``. To populate a demo database from a file::

    python -m p3_api.cli seed data/mock_findings.raw.json
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from fastapi import Body, Depends, FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from p2_scoring import RULES, clauses_for, frameworks_for

from . import repository
from .db import DEFAULT_DB_PATH, session
from .scan_service import ScanIngestError, run_scan
from .schemas import (
    Finding,
    FindingList,
    FrameworkSummary,
    HealthResponse,
    RuleInfo,
    ScanRequest,
    ScanResponse,
    StatusUpdate,
    SummaryStats,
    TrendResponse,
)

STATIC_DIR = Path(__file__).resolve().parent / "static"

DESCRIPTION = """
Explainable cloud misconfiguration detection -- API for the dashboard.

Findings arrive raw from the detection engine via `POST /scan`; this service
enriches them (risk score, explanation card, compliance mappings) and stores
them. The dashboard reads everything else from here.
"""


def create_app(db_path: Path | str | None = None) -> FastAPI:
    """Build the app. Takes a db path so tests can use a throwaway database."""
    resolved_db = db_path or os.environ.get("CSPM_DB_PATH") or DEFAULT_DB_PATH

    app = FastAPI(
        title="Explainable CSPM API",
        description=DESCRIPTION,
        version="0.1.0",
    )

    # Exposed for tests and for ops ("which database is this process actually
    # serving?"), since the path can come from an argument or the environment.
    app.state.db_path = Path(resolved_db)

    # The dashboard is served from this same app, so it does not need CORS.
    # These origins are for a separately-hosted dev frontend, and are limited to
    # loopback: this API returns a full inventory of an account's
    # misconfigurations, so it should never be reachable cross-origin from a
    # real hostname.
    app.add_middleware(
        CORSMiddleware,
        allow_origin_regex=r"http://(localhost|127\.0\.0\.1)(:\d+)?",
        allow_methods=["*"],
        allow_headers=["*"],
    )

    def get_db():
        with session(resolved_db) as connection:
            yield connection

    # ---------------------------------------------------------------- health

    @app.get("/health", response_model=HealthResponse, tags=["meta"])
    def health(connection=Depends(get_db)) -> dict[str, Any]:
        stats = repository.summary_stats(connection)
        return {"status": "ok", "finding_count": stats["total"], "rule_count": len(RULES)}

    # ------------------------------------------------------------------ scan

    @app.post("/scan", response_model=ScanResponse, tags=["scan"])
    def scan(
        payload: list[dict[str, Any]] | ScanRequest = Body(...),
        connection=Depends(get_db),
    ) -> dict[str, Any]:
        """Enrich and store a batch of raw findings.

        Accepts either a bare JSON array or ``{"findings": [...]}``, so P1 can
        post its output directly without wrapping it.
        """
        raw = payload if isinstance(payload, list) else payload.findings
        try:
            report = run_scan(connection, raw)
        except ScanIngestError as exc:
            raise HTTPException(
                status_code=422,
                detail={"message": exc.message, "detail": exc.detail},
            ) from exc
        return report.as_dict()

    # -------------------------------------------------------------- findings

    @app.get("/findings", response_model=FindingList, tags=["findings"])
    def list_findings(
        connection=Depends(get_db),
        band: list[str] | None = Query(None, description="risk band, repeatable"),
        status: list[str] | None = Query(None, description="workflow status, repeatable"),
        rule_id: list[str] | None = Query(None),
        resource_type: list[str] | None = Query(None),
        framework: list[str] | None = Query(None, description="e.g. PCI-DSS, SOC2, GLBA"),
        detection_source: list[str] | None = Query(None),
        scan_id: str | None = Query(None),
        min_score: int | None = Query(None, ge=0, le=100),
        q: str | None = Query(None, description="free-text search over resource, rule and id"),
        sort: str = Query("risk_score"),
        order: str = Query("desc", pattern="^(asc|desc)$"),
        limit: int = Query(100, ge=1, le=500),
        offset: int = Query(0, ge=0),
    ) -> dict[str, Any]:
        query = repository.FindingQuery(
            band=band or (),
            status=status or (),
            rule_id=rule_id or (),
            resource_type=resource_type or (),
            framework=framework or (),
            detection_source=detection_source or (),
            scan_id=scan_id,
            min_score=min_score,
            search=q,
            sort=sort,
            order=order,
            limit=limit,
            offset=offset,
        )
        items, total = repository.find_findings(connection, query)
        return {"items": items, "total": total, "limit": limit, "offset": offset}

    @app.get("/findings/{finding_id}", response_model=Finding, tags=["findings"])
    def get_finding(finding_id: str, connection=Depends(get_db)) -> dict[str, Any]:
        finding = repository.get_finding(connection, finding_id)
        if finding is None:
            raise HTTPException(status_code=404, detail=f"no finding with id {finding_id!r}")
        return finding

    @app.patch("/findings/{finding_id}", response_model=Finding, tags=["findings"])
    def set_status(
        finding_id: str, update: StatusUpdate, connection=Depends(get_db)
    ) -> dict[str, Any]:
        """Set the workflow status.

        `remediated` is the only status a later scan may override: if the same
        finding is detected again, ingest reopens it and increments its reopen
        count, so a fix that did not stick surfaces instead of disappearing.
        `acknowledged` and `false_positive` are preserved -- a human made that
        call, and re-flagging the same misconfiguration every night would make
        them re-make it every night.
        """
        finding = repository.update_status(connection, finding_id, update.status)
        if finding is None:
            raise HTTPException(status_code=404, detail=f"no finding with id {finding_id!r}")
        return finding

    # ------------------------------------------------------------ aggregates

    @app.get("/stats", tags=["aggregates"])
    def stats(connection=Depends(get_db)) -> dict[str, Any]:
        """Everything the dashboard tiles and charts need, in one request."""
        return {
            "summary": repository.summary_stats(connection),
            "by_band": repository.by_band(connection),
            "by_service": repository.by_service(connection),
            "by_rule": repository.by_rule(connection),
            "by_status": repository.by_status(connection),
        }

    @app.get("/compliance", response_model=list[FrameworkSummary], tags=["aggregates"])
    def compliance(connection=Depends(get_db)) -> list[dict[str, Any]]:
        return repository.compliance_summary(connection)

    @app.get("/trend", response_model=TrendResponse, tags=["aggregates"])
    def trend(connection=Depends(get_db)) -> dict[str, Any]:
        return repository.trend(connection)

    @app.get("/filter-options", tags=["aggregates"])
    def filter_options(connection=Depends(get_db)) -> dict[str, list[str]]:
        return repository.filter_options(connection)

    @app.get("/scans", tags=["aggregates"])
    def scans(connection=Depends(get_db)) -> list[dict[str, Any]]:
        return repository.scans(connection)

    # ----------------------------------------------------------------- rules

    @app.get("/rules", response_model=list[RuleInfo], tags=["meta"])
    def rules() -> list[dict[str, Any]]:
        """The detection-rule catalogue, straight from P2's rule table.

        Served from the same objects the scorer uses, so the explanation shown
        in the UI cannot drift from the logic that produced the score.
        """
        return [
            {
                "rule_id": rule.rule_id,
                "title": rule.title,
                "base_severity": rule.base_severity,
                "resource_types": list(rule.resource_types),
                "context_keys": list(rule.context_keys),
                "max_score": rule.max_score,
                "projected_score_after_fix": rule.residual_score,
                "frameworks": frameworks_for(rule.rule_id),
                "factors": [
                    {"factor": f.key, "points": f.points, "requires": list(f.requires)}
                    for f in rule.factors
                ],
            }
            for rule in RULES
        ]

    @app.get("/rules/{rule_id}/clauses", tags=["meta"])
    def rule_clauses(rule_id: str) -> list[dict[str, str]]:
        try:
            return clauses_for(rule_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    # ------------------------------------------------------------- dashboard

    @app.get("/", include_in_schema=False)
    def dashboard() -> FileResponse:
        index = STATIC_DIR / "index.html"
        if not index.exists():  # pragma: no cover - only if static files are missing
            raise HTTPException(status_code=500, detail="dashboard assets are missing")
        return FileResponse(index)

    if STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    @app.exception_handler(ValueError)
    async def value_error_handler(_request: Request, exc: ValueError) -> JSONResponse:
        # P2 raises ValueError for contract violations (e.g. a finding reusing a
        # reserved context key). Surface it as a client error, not a 500.
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    return app


app = create_app()


def main() -> None:  # pragma: no cover - process entry point
    import uvicorn

    uvicorn.run(
        "p3_api.app:app",
        host="127.0.0.1",
        port=int(os.environ.get("PORT", "8000")),
        reload=os.environ.get("CSPM_RELOAD") == "1",
    )


if __name__ == "__main__":  # pragma: no cover
    main()
