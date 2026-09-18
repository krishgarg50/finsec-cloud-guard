"""P3 API tests.

These run the real app against a throwaway SQLite file in ``tmp_path`` -- no
mocks of the storage layer, because the storage layer is ours and the bugs we
care about (status transitions, aggregation arithmetic, filter construction) only
appear against a real database.

The seed data is the same P1-shaped raw file the demo uses, so a passing run here
means the demo path works.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("fastapi", reason="P3 needs fastapi installed")

from fastapi.testclient import TestClient  # noqa: E402

from p3_api.app import create_app  # noqa: E402


@pytest.fixture
def client(tmp_path: Path) -> TestClient:
    app = create_app(db_path=tmp_path / "test.db")
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def seeded(client: TestClient, raw_mocks: list[dict[str, Any]]) -> TestClient:
    """A client whose database already holds the 12 mock findings."""
    response = client.post("/scan", json=raw_mocks)
    assert response.status_code == 200, response.text
    return client


def _first_finding(client: TestClient, **params: Any) -> dict[str, Any]:
    response = client.get("/findings", params=params)
    assert response.status_code == 200, response.text
    items = response.json()["items"]
    assert items, f"no findings matched {params}"
    return items[0]


# --------------------------------------------------------------------- meta


def test_health_on_an_empty_database(client: TestClient) -> None:
    body = client.get("/health").json()
    assert body["status"] == "ok"
    assert body["finding_count"] == 0
    assert body["rule_count"] == 12


def test_dashboard_is_served(client: TestClient) -> None:
    response = client.get("/")
    assert response.status_code == 200
    assert "Cloud Misconfiguration Risk" in response.text


def test_static_assets_are_served(client: TestClient) -> None:
    for asset in ("/static/app.js", "/static/styles.css"):
        assert client.get(asset).status_code == 200, asset


def test_rules_catalogue_matches_the_scorer(client: TestClient) -> None:
    from p2_scoring import RULES

    rules = client.get("/rules").json()
    assert len(rules) == len(RULES)
    by_id = {rule["rule_id"]: rule for rule in rules}

    for rule in RULES:
        entry = by_id[rule.rule_id]
        assert entry["title"] == rule.title
        assert entry["max_score"] == rule.max_score
        assert entry["projected_score_after_fix"] == rule.residual_score
        # every factor the scorer can apply must be visible in the UI's model
        assert {f["factor"] for f in entry["factors"]} == {f.key for f in rule.factors}


def test_unknown_rule_clauses_are_a_404(client: TestClient) -> None:
    assert client.get("/rules/NOT_A_RULE/clauses").status_code == 404


def test_known_rule_clauses_are_returned(client: TestClient) -> None:
    clauses = client.get("/rules/S3_PUBLIC_ACCESS/clauses").json()
    assert clauses
    assert all("framework" in c and "clause" in c for c in clauses)


# --------------------------------------------------------------------- scan


def test_scan_ingests_every_mock_finding(seeded: TestClient) -> None:
    body = seeded.get("/health").json()
    assert body["finding_count"] == 12


def test_scan_accepts_a_wrapped_payload(client: TestClient, raw_mocks) -> None:
    response = client.post("/scan", json={"findings": raw_mocks})
    assert response.status_code == 200
    assert response.json()["finding_count"] == 12


def test_scan_reports_the_outcome_tally(seeded: TestClient, raw_mocks) -> None:
    # re-scanning the identical batch must not create duplicates
    report = seeded.post("/scan", json=raw_mocks).json()
    assert report["outcome"]["new"] == 0
    assert report["outcome"]["unchanged"] == 12
    assert seeded.get("/health").json()["finding_count"] == 12


def test_scan_rejects_an_empty_batch(client: TestClient) -> None:
    assert client.post("/scan", json=[]).status_code == 422


def test_scan_rejects_a_malformed_finding(client: TestClient) -> None:
    response = client.post("/scan", json=[{"rule_id": "S3_PUBLIC_ACCESS"}])
    assert response.status_code == 422
    assert "malformed" in json.dumps(response.json()).lower()


def test_scan_skips_an_unknown_rule_instead_of_failing_the_batch(
    client: TestClient, raw_mocks
) -> None:
    """One rule shipped ahead of P2 must not lose the other 12 findings."""
    batch = [*raw_mocks, {**raw_mocks[0], "finding_id": "brand-new-rule-0001",
                          "rule_id": "S3_OBJECT_LOCK_MISSING"}]
    report = client.post("/scan", json=batch).json()

    assert report["finding_count"] == 12
    assert len(report["skipped"]) == 1
    assert report["skipped"][0]["rule_id"] == "S3_OBJECT_LOCK_MISSING"
    # the skip is reported, not silent
    assert any("S3_OBJECT_LOCK_MISSING" in w for w in report["warnings"])


def test_scan_persists_enriched_fields(seeded: TestClient) -> None:
    finding = _first_finding(seeded)
    assert finding["risk_score"] > 0
    assert finding["explanation"]["issue"]
    assert finding["compliance_mappings"]
    assert finding["score_breakdown"]


def test_stored_score_equals_the_sum_of_its_breakdown(seeded: TestClient) -> None:
    """The project's central invariant, asserted through the HTTP surface."""
    items = seeded.get("/findings", params={"limit": 100}).json()["items"]
    for finding in items:
        total = sum(f["weight"] for f in finding["score_breakdown"])
        assert total == pytest.approx(finding["risk_score"]), finding["finding_id"]


# ----------------------------------------------------------------- findings


def test_findings_are_ordered_worst_first(seeded: TestClient) -> None:
    items = seeded.get("/findings").json()["items"]
    scores = [f["risk_score"] for f in items]
    assert scores == sorted(scores, reverse=True)


def test_finding_detail_matches_the_list_entry(seeded: TestClient) -> None:
    listed = _first_finding(seeded)
    detail = seeded.get(f"/findings/{listed['finding_id']}").json()
    assert detail == listed


def test_missing_finding_is_a_404(seeded: TestClient) -> None:
    assert seeded.get("/findings/does-not-exist").status_code == 404


def test_pagination_reports_the_true_total(seeded: TestClient) -> None:
    page = seeded.get("/findings", params={"limit": 5}).json()
    assert len(page["items"]) == 5
    assert page["total"] == 12
    assert page["limit"] == 5


def test_filter_by_band(seeded: TestClient) -> None:
    items = seeded.get("/findings", params={"band": "critical"}).json()["items"]
    assert items
    assert all(f["risk_score"] >= 80 for f in items)


def test_filter_by_min_score(seeded: TestClient) -> None:
    items = seeded.get("/findings", params={"min_score": 70}).json()["items"]
    assert items
    assert all(f["risk_score"] >= 70 for f in items)


def test_repeated_filters_are_a_union(seeded: TestClient) -> None:
    params = [("band", "critical"), ("band", "low")]
    items = seeded.get("/findings", params=params).json()["items"]
    assert items
    assert all(f["risk_score"] >= 80 or f["risk_score"] < 40 for f in items)


def test_filter_by_resource_type(seeded: TestClient) -> None:
    items = seeded.get("/findings", params={"resource_type": "s3_bucket"}).json()["items"]
    assert items
    assert all(f["resource"]["type"] == "s3_bucket" for f in items)


def test_filter_by_framework_uses_delimited_membership(seeded: TestClient) -> None:
    items = seeded.get("/findings", params={"framework": "PCI-DSS"}).json()["items"]
    assert items
    assert all(
        any(m["framework"] == "PCI-DSS" for m in f["compliance_mappings"]) for f in items
    )


def test_search_matches_resource_name_and_id(seeded: TestClient) -> None:
    by_name = seeded.get("/findings", params={"q": "customer-statements"}).json()
    assert by_name["total"] >= 1

    known = _first_finding(seeded)
    by_id = seeded.get("/findings", params={"q": known["finding_id"]}).json()
    assert by_id["total"] == 1


def test_search_with_no_match_returns_an_empty_page(seeded: TestClient) -> None:
    body = seeded.get("/findings", params={"q": "zzzz-no-such-resource"}).json()
    assert body["total"] == 0
    assert body["items"] == []


def test_sort_ascending_reverses_the_order(seeded: TestClient) -> None:
    items = seeded.get(
        "/findings", params={"sort": "risk_score", "order": "asc"}
    ).json()["items"]
    scores = [f["risk_score"] for f in items]
    assert scores == sorted(scores)


def test_unknown_sort_column_falls_back_instead_of_erroring(seeded: TestClient) -> None:
    """A bad sort key must not be interpolated into SQL, nor 500."""
    response = seeded.get("/findings", params={"sort": "'; DROP TABLE findings; --"})
    assert response.status_code == 200
    assert seeded.get("/health").json()["finding_count"] == 12


def test_bad_order_direction_is_rejected(seeded: TestClient) -> None:
    assert seeded.get("/findings", params={"order": "sideways"}).status_code == 422


# ------------------------------------------------------------------- status


def test_status_update_round_trips(seeded: TestClient) -> None:
    finding_id = _first_finding(seeded)["finding_id"]
    updated = seeded.patch(f"/findings/{finding_id}", json={"status": "acknowledged"}).json()
    assert updated["status"] == "acknowledged"
    assert seeded.get(f"/findings/{finding_id}").json()["status"] == "acknowledged"


def test_invalid_status_is_rejected(seeded: TestClient) -> None:
    finding_id = _first_finding(seeded)["finding_id"]
    response = seeded.patch(f"/findings/{finding_id}", json={"status": "banana"})
    assert response.status_code == 422


def test_status_update_on_a_missing_finding_is_a_404(seeded: TestClient) -> None:
    assert seeded.patch("/findings/nope", json={"status": "open"}).status_code == 404


def test_a_rescan_does_not_undo_a_human_decision(
    seeded: TestClient, raw_mocks: list[dict[str, Any]]
) -> None:
    """The behaviour a compliance team will actually notice.

    `acknowledged` and `false_positive` are decisions a person made. A nightly
    scan that silently reset them to `open` would make the workflow useless.
    """
    finding_id = _first_finding(seeded)["finding_id"]

    for status in ("acknowledged", "false_positive"):
        seeded.patch(f"/findings/{finding_id}", json={"status": status})
        seeded.post("/scan", json=raw_mocks)
        assert seeded.get(f"/findings/{finding_id}").json()["status"] == status, status


def test_a_remediated_finding_that_comes_back_reopens(
    seeded: TestClient, raw_mocks: list[dict[str, Any]]
) -> None:
    """A fix that did not stick must surface, not disappear.

    This is the one status a re-scan is allowed to override, because seeing a
    'fixed' misconfiguration again is a regression -- and `reopen_count` is how
    that becomes visible instead of being silently re-alerted.
    """
    finding_id = _first_finding(seeded)["finding_id"]
    seeded.patch(f"/findings/{finding_id}", json={"status": "remediated"})

    report = seeded.post("/scan", json=raw_mocks).json()
    assert report["outcome"]["reopened"] == 1

    finding = seeded.get(f"/findings/{finding_id}").json()
    assert finding["status"] == "open"


def test_a_false_positive_is_not_treated_as_a_regression(
    seeded: TestClient, raw_mocks: list[dict[str, Any]]
) -> None:
    """`remediated` reopens; `false_positive` must not.

    A finding a human marked `false_positive` is, by definition, one the scanner
    will keep re-detecting. If a re-scan reopened it, the analyst would have to
    re-mark it on every run -- and the `reopened` tally, which exists to make a
    genuine regression visible, would be noise instead of signal.
    """
    finding_id = _first_finding(seeded)["finding_id"]
    seeded.patch(f"/findings/{finding_id}", json={"status": "false_positive"})

    report = seeded.post("/scan", json=raw_mocks).json()
    assert report["outcome"]["reopened"] == 0

    finding = seeded.get(f"/findings/{finding_id}").json()
    assert finding["status"] == "false_positive"


def test_the_status_column_and_the_document_agree(
    seeded: TestClient, raw_mocks: list[dict[str, Any]]
) -> None:
    """The regression behind `acknowledged` silently reading back as `open`.

    Storage keeps a `status` column for filtering *and* a JSON document that is
    what `GET /findings` actually serves. Ingest preserved the column but wrote
    the incoming document verbatim, so a re-scan stored a document saying
    `open` beside a column saying `acknowledged`. Everything that reads the table
    saw the human's decision; everything that reads the API -- which is the whole
    dashboard -- saw the scan's. The two must not be allowed to disagree, because
    only one of them is visible.
    """
    from p3_api.db import session as db_session

    finding_id = _first_finding(seeded)["finding_id"]
    seeded.patch(f"/findings/{finding_id}", json={"status": "acknowledged"})
    seeded.post("/scan", json=raw_mocks)

    with db_session(seeded.app.state.db_path) as connection:
        row = connection.execute(
            "SELECT status, document FROM findings WHERE finding_id = ?", (finding_id,)
        ).fetchone()

    assert row["status"] == "acknowledged"
    assert json.loads(row["document"])["status"] == "acknowledged"
    # and the served document is the stored one, not a reassembly that drifted
    assert seeded.get(f"/findings/{finding_id}").json()["status"] == "acknowledged"


def test_a_reopened_finding_reports_its_reopen_count(
    seeded: TestClient, raw_mocks: list[dict[str, Any]]
) -> None:
    """The counter has to be readable, or a stuck fix reopens silently.

    `POST /scan` reports `reopened: 1` once and that response is gone. Without
    the count on the finding itself, the regression is indistinguishable from any
    other open item the next time anyone looks.
    """
    finding_id = _first_finding(seeded)["finding_id"]
    assert seeded.get(f"/findings/{finding_id}").json()["reopen_count"] == 0

    seeded.patch(f"/findings/{finding_id}", json={"status": "remediated"})
    seeded.post("/scan", json=raw_mocks)

    finding = seeded.get(f"/findings/{finding_id}").json()
    assert finding["status"] == "open"
    assert finding["reopen_count"] == 1

    # a second regression increments rather than resetting
    seeded.patch(f"/findings/{finding_id}", json={"status": "remediated"})
    seeded.post("/scan", json=raw_mocks)
    assert seeded.get(f"/findings/{finding_id}").json()["reopen_count"] == 2

    # an unrelated re-scan of a still-open finding does not inflate it
    seeded.post("/scan", json=raw_mocks)
    assert seeded.get(f"/findings/{finding_id}").json()["reopen_count"] == 2


def test_open_findings_stay_open_across_scans(
    seeded: TestClient, raw_mocks: list[dict[str, Any]]
) -> None:
    """A re-scan is not a refresh: it must not move any finding's status.

    Asserted as *invariance* rather than against a literal count. The seed itself
    carries `acknowledged` and `remediated` findings, so "12 open" would be wrong
    before a rescan ever happened -- and a hard-coded number would have to be
    updated every time the seed changes, which is how a test stops testing
    anything. What matters is that every finding's status is identical either
    side of the scan.
    """
    def statuses() -> dict[str, str]:
        items = seeded.get("/findings", params={"limit": 500}).json()["items"]
        return {f["finding_id"]: f["status"] for f in items}

    before = statuses()
    assert len(before) == 12, "the seed should have been ingested in full"
    assert any(s == "open" for s in before.values())
    # the seed is why this test cannot use a literal count
    assert any(s != "open" for s in before.values()), (
        "seed no longer carries non-open findings -- the invariance check below "
        "would pass even if a re-scan flattened everything to `open`"
    )

    seeded.post("/scan", json=raw_mocks)
    assert statuses() == before


# --------------------------------------------------------------- aggregates


def test_stats_counts_match_the_findings_list(seeded: TestClient) -> None:
    stats = seeded.get("/stats").json()
    total = seeded.get("/findings", params={"limit": 500}).json()["total"]

    assert stats["summary"]["total"] == total
    assert sum(row["count"] for row in stats["by_band"]) == total
    assert sum(row["count"] for row in stats["by_service"]) == total


def test_bands_are_ordered_worst_first(seeded: TestClient) -> None:
    labels = [row["label"] for row in seeded.get("/stats").json()["by_band"]]
    assert labels == sorted(labels, key=lambda l: ["critical", "high", "medium", "low"].index(l))


def test_stats_on_an_empty_database_are_zero_not_null(client: TestClient) -> None:
    """A fresh install must render zeroes, not a broken dashboard."""
    summary = client.get("/stats").json()["summary"]
    assert summary["total"] == 0
    assert summary["average_score"] == 0
    assert summary["last_scan_at"] is None


def test_compliance_summary_matches_a_filtered_listing(seeded: TestClient) -> None:
    """The framework counts must agree with what the list view shows for the
    same filter -- two independent code paths answering one question."""
    for summary in seeded.get("/compliance").json():
        assert summary["finding_count"] > 0
        assert summary["open_count"] <= summary["finding_count"]
        assert summary["critical_count"] <= summary["finding_count"]

        listed = seeded.get(
            "/findings", params={"framework": summary["framework"], "limit": 500}
        ).json()
        assert listed["total"] == summary["finding_count"], summary["framework"]


def test_compliance_clause_counts_sum_to_at_least_the_finding_count(seeded: TestClient) -> None:
    """A finding can breach several clauses of one framework, so the clause
    counts may exceed the finding count -- but never fall short of it."""
    for summary in seeded.get("/compliance").json():
        assert sum(c["count"] for c in summary["clauses"]) >= summary["finding_count"]


def test_a_finding_citing_two_clauses_of_one_framework_counts_once(
    seeded: TestClient,
) -> None:
    """The double-count regression, pinned.

    No seeded rule cites two clauses in the same framework, so this inserts one
    that does. Counting mapping rows instead of distinct findings would report
    this single finding as two PCI findings -- inflating exactly the number a
    compliance officer reads off the dashboard.
    """
    from p3_api import repository
    from p3_api.db import session

    template = _first_finding(seeded, framework="PCI-DSS")
    doubled = json.loads(json.dumps(template))
    doubled["finding_id"] = "synthetic-double-clause"
    doubled["compliance_mappings"] = [
        {"framework": "PCI-DSS", "clause": "1.2.1", "clause_description": "one"},
        {"framework": "PCI-DSS", "clause": "1.3.4", "clause_description": "two"},
    ]

    before = seeded.get(
        "/findings", params={"framework": "PCI-DSS", "limit": 500}
    ).json()["total"]

    with session(seeded.app.state.db_path) as connection:
        repository.upsert_finding(connection, doubled)

    after = seeded.get(
        "/findings", params={"framework": "PCI-DSS", "limit": 500}
    ).json()["total"]
    assert after == before + 1

    pci = next(row for row in seeded.get("/compliance").json() if row["framework"] == "PCI-DSS")
    assert pci["finding_count"] == after
    assert sum(c["count"] for c in pci["clauses"]) == after + 1


def test_all_three_frameworks_are_represented(seeded: TestClient) -> None:
    frameworks = {row["framework"] for row in seeded.get("/compliance").json()}
    assert {"PCI-DSS", "SOC2", "GLBA"} <= frameworks


def test_trend_buckets_on_detected_at(seeded: TestClient) -> None:
    """The seed data spans several detection dates, so the chart has a shape."""
    by_day = seeded.get("/trend").json()["by_day"]
    assert len(by_day) > 1
    dates = [point["date"] for point in by_day]
    assert dates == sorted(dates)
    assert all(len(d) == 10 and d[4] == "-" for d in dates)


def test_trend_does_not_drop_the_high_band(seeded: TestClient) -> None:
    """FastAPI filters response fields to the declared model."""
    by_day = seeded.get("/trend").json()["by_day"]
    assert all("high" in point for point in by_day)


def test_trend_records_every_scan_in_the_batch(seeded: TestClient) -> None:
    """The seed spans two scan_ids, so /trend must show two runs.

    Recording only the batch's dominant scan_id would draw a single point where
    the data describes two, and the per-scan view exists precisely to be stepped
    through during a demo.
    """
    by_scan = seeded.get("/trend").json()["by_scan"]
    assert [row["scan_id"] for row in by_scan] == ["scan-0001", "scan-0002"]
    assert sum(row["finding_count"] for row in by_scan) == 12
    # the runs are a partition of the batch, not overlapping slices of it
    assert [row["finding_count"] for row in by_scan] == [10, 2]


def test_filter_options_cover_the_seeded_values(seeded: TestClient) -> None:
    options = seeded.get("/filter-options").json()
    assert len(options["rule_id"]) == 12
    assert "s3_bucket" in options["resource_type"]
    assert "open" in options["status"]
    assert set(options["band"]) <= {"critical", "high", "medium", "low"}


def test_filter_option_keys_match_the_query_parameters(seeded: TestClient) -> None:
    """Each options key must be a parameter `GET /findings` actually filters on.

    The severity list is keyed `band`, not `risk_band` (the column name). Getting
    this wrong leaves the dashboard's severity control permanently empty, and an
    empty dropdown looks like a data problem rather than a naming one.

    A status-code check would not catch it: FastAPI ignores query parameters it
    does not declare, so an unknown key returns the unfiltered list with a 200.
    The discriminating test is that a *bogus* value of a real filter matches
    nothing.
    """
    options = seeded.get("/filter-options").json()
    for key, values in options.items():
        if not values:
            continue
        matching = seeded.get("/findings", params={key: values[0]}).json()["total"]
        bogus = seeded.get("/findings", params={key: "zzz-no-such-value"}).json()["total"]

        assert matching > 0, f"{key}={values[0]!r} matched nothing"
        assert bogus == 0, (
            f"{key!r} is not a real filter parameter -- a value nothing matches "
            f"still returned {bogus} findings, so the parameter is being ignored"
        )


def test_filter_options_are_empty_on_a_fresh_database(client: TestClient) -> None:
    options = client.get("/filter-options").json()
    assert options["rule_id"] == []
    assert options["resource_type"] == []


def test_scans_endpoint_lists_the_batch(seeded: TestClient) -> None:
    scans = seeded.get("/scans").json()
    assert {row["scan_id"] for row in scans} == {"scan-0001", "scan-0002"}
    assert sum(row["finding_count"] for row in scans) == 12
    assert sum(row["new_count"] for row in scans) == 12
    assert all(row["ingested_at"] for row in scans)


def test_a_rescan_updates_the_existing_scan_row(seeded: TestClient, raw_mocks) -> None:
    """Re-ingesting the same batch must not accumulate duplicate scan rows."""
    before = len(seeded.get("/scans").json())
    report = seeded.post("/scan", json=raw_mocks).json()
    after = seeded.get("/scans").json()

    assert len(after) == before
    assert report["outcome"]["unchanged"] == 12
    assert sum(row["finding_count"] for row in after) == 12
