# P3 — API and dashboard specification

P3 is the read side of the product: an HTTP API over the enriched findings, and a
dashboard with two views of the same data — one for the engineer who has to fix
things, one for the compliance officer who has to explain them.

## Running it

```bash
pip install -e .                       # fastapi, uvicorn, pydantic
python -m p3_api.cli seed data/mock_findings.raw.json
python -m p3_api.cli serve             # http://127.0.0.1:8000
```

`seed` takes **raw** findings — P1's shape — and runs the full enrich-and-store
path. Seeding the demo exercises exactly the code a real scan does, so a bug in
the ingest path cannot hide behind a fixture.

Other commands:

```bash
python -m p3_api.cli stats             # print the database summary
python -m p3_api.cli reset --yes       # wipe findings and scans
```

Interactive API docs are at `/docs` (FastAPI's OpenAPI UI).

## Endpoints

### Meta

| method | path | purpose |
|---|---|---|
| `GET` | `/health` | liveness plus finding and rule counts |
| `GET` | `/rules` | the detection-rule catalogue, served from P2's table |
| `GET` | `/rules/{rule_id}/clauses` | the compliance clauses one rule maps to |

`/rules` is generated from the same `DetectionRule` objects the scorer uses, so
the explanation the UI renders cannot drift from the logic that produced the
score. It exposes each rule's title, factors with their point values and required
context keys, the maximum score, and the post-remediation estimate — which is
what lets the dashboard explain a rule the user has never seen before.

### Ingest

| method | path | purpose |
|---|---|---|
| `POST` | `/scan` | enrich and store a batch of raw findings |

Accepts either a bare JSON array or `{"findings": [...]}`, so P1 can post its
output directly without wrapping it. Response:

```json
{
  "scan_id": "...",
  "finding_count": 12,
  "outcome": {"new": 12, "updated": 0, "reopened": 0, "unchanged": 0},
  "band_counts": {"critical": 5, "high": 4, "medium": 3},
  "warnings": [],
  "skipped": [],
  "average_score": 71.6
}
```

P3 does not score anything. It calls P2's `enrich_findings()` and persists the
result, so there is exactly one implementation of the scoring rules in the
codebase — which is the entire reason P2 and P3 are separable.

`strict_unknown_rules` defaults to **False** here, unlike P2's own CLI default.
Behind an HTTP endpoint, one rule P1 shipped ahead of P2 must not reject the
whole scan; the skipped finding is reported in `skipped` and a warning names it,
so it cannot pass unnoticed. P2's CLI default stays strict because a batch job
that silently drops findings is a worse failure than one that stops.

Failures return `422` with a `detail` naming the offending finding — malformed
input, an empty batch, or a context key colliding with P2's reserved derived
namespace.

### Findings

| method | path | purpose |
|---|---|---|
| `GET` | `/findings` | filtered, sorted, paged list |
| `GET` | `/findings/{finding_id}` | one finding |
| `PATCH` | `/findings/{finding_id}` | set workflow status |

`GET /findings` query parameters — all filters repeatable, combined as a union
within a parameter and an intersection across parameters:

| parameter | meaning |
|---|---|
| `band` | `critical` / `high` / `medium` / `low` |
| `status` | `open` / `acknowledged` / `remediated` / `false_positive` |
| `rule_id` | detection rule |
| `resource_type` | `s3_bucket`, `iam_user`, … |
| `framework` | `PCI-DSS` / `SOC2` / `GLBA` |
| `detection_source` | `rule_engine` / `anomaly_detection` |
| `scan_id` | findings from one scan run |
| `min_score` | risk score floor, 0–100 |
| `q` | free text over resource name, resource id, rule id and finding id |
| `sort` | `risk_score` (default), `detected_at`, `last_seen_at`, `first_seen_at`, `resource_name`, `rule_id`, `status` |
| `order` | `asc` / `desc`, default `desc` |
| `limit` / `offset` | page size (1–500, default 100) and offset |

`sort` is looked up in a whitelist (`repository.SORTABLE_COLUMNS`) and falls back
to `risk_score` for anything unrecognised — the value is never interpolated into
SQL. `order` is validated by the query layer with a regex, so a bad direction is a
422 rather than a syntax error.

The list returns the **full stored document** for each finding, not a summary
projection. The dashboard's detail drawer opens without a second request, and
there is no second definition of what a finding contains that could drift from
P2's output.

### Aggregates

| method | path | purpose |
|---|---|---|
| `GET` | `/stats` | everything the tiles and charts need, in one round trip |
| `GET` | `/compliance` | per-framework summary plus the clauses driving it |
| `GET` | `/trend` | new findings by day and by scan |
| `GET` | `/filter-options` | distinct values for the filter controls |
| `GET` | `/scans` | scan history |

`/stats` returns `summary`, `by_band`, `by_service`, `by_rule` and `by_status`
together. The dashboard issues one request on load instead of five, which is the
difference between a dashboard that feels instant and one that paints in pieces.

`/compliance` counts **distinct findings per framework**: a finding citing two
PCI clauses is one PCI finding, not two. Counting mapping rows instead is the
obvious implementation and inflates precisely the number a compliance officer
reads off the screen. `clauses[].count` does count citations, so the two numbers
differ by design — clause counts may exceed the finding count.

`/trend` buckets `by_day` on `detected_at` — when the misconfiguration first
existed in the environment — not `first_seen_at` (when this system stored it).
The two differ whenever a scan backfills history, and `detected_at` is the one
that describes the environment rather than the pipeline. A freshly seeded demo
spanning several detection dates therefore renders a real trend line instead of a
single point.

## Finding lifecycle

P3 owns the fields P2 does not:

| field | meaning |
|---|---|
| `status` | `open` / `acknowledged` / `remediated` / `false_positive` |
| `reopen_count` | incremented when a `remediated` finding reappears |
| `first_seen_at` | when this system first stored the finding |

Re-detection behaviour is the interesting part, and it is where a naive upsert
gets the product wrong:

| status before rescan | status after | why |
|---|---|---|
| `open` | `open` | still a problem |
| `acknowledged` | `acknowledged` | a human already accepted this risk; a nightly scan must not keep re-alerting |
| `remediated` | **`open`**, `reopen_count += 1` | seeing a "fixed" misconfiguration again is a regression, and it has to surface |
| `false_positive` | `false_positive` | a human decided this; re-alerting on every scan is how a queue becomes noise |

`remediated` is the only status a scan may override, and only in the direction of
reopening. `reopen_count` is how a fix that did not stick becomes visible instead
of being silently re-alerted forever.

## Storage

SQLite, plain `sqlite3`, WAL mode, one connection per request.

The full enriched finding is stored as a JSON document — the source of truth,
exactly as P2 produced it — **plus** denormalised columns for everything the UI
filters, sorts or aggregates on (`risk_score`, `risk_band`, `status`,
`resource_type`, `frameworks`, the three timestamps). That gives one writer, no
marshalling bugs, and a schema that tolerates P2 adding fields without a
migration — while keeping the list view off a full-table JSON scan.

The columns are derived, never authored. If they ever disagree with the document,
the document wins: `repository.find_findings()` reads the document back out
verbatim rather than reassembling it from columns.

Chosen over an ORM because the schema is one table plus a scan index, the filters
are dynamic, and a demo that needs no migrations and no database server is worth
more here than an abstraction layer. Chosen over Postgres for the same reason —
the deployment target is a demo on a laptop, and requiring a database server
would be the single most likely reason the demo fails.

`frameworks` is stored as a canonical-order comma list (`'PCI-DSS,SOC2'`) and
matched with delimited membership (`(',' || frameworks || ',') LIKE '%,SOC2,%'`)
so `SOC2` cannot match a hypothetical `SOC20`.

## Dashboard

Two views over one dataset, because the same findings answer two different
questions.

**Technical view** — for whoever has to fix it: summary tiles, findings by
severity (donut) and by service (bars), a filter bar, and the findings list.

**Compliance view** — for whoever has to explain it: framework exposure cards,
per-clause tables, risk over time, and a remediation queue ordered worst-first.

Opening a finding shows the detail drawer: the explanation card (issue,
consequence, recommended fix, and the projected score after remediation), the
score breakdown, the compliance mappings, the detection source, the observed
context as a key/value table, and the timeline. The context table is what closes
the loop — `observed facts → factors → score` in one place.

### Constraints

**No build step and no CDN.** `index.html`, `styles.css` and `app.js` are served
as-is. Charts are hand-drawn SVG (donut via `stroke-dasharray`, bars, trend
polyline). No framework, no bundler, no npm. A live demo cannot fail because the
conference wifi dropped, and there is nothing to reinstall on the demo laptop.

**Everything interpolated is escaped.** Resource names, ARNs and context values
come from a cloud account and are not ours to trust. `app.js` has one `esc()`
helper and every AWS-supplied string goes through it — a bucket named
`<img src=x onerror=…>` must render as text, not execute. That is a real attack
path for a security tool: it reads hostile-ish data by definition.

**Light and dark**, following `prefers-color-scheme`, all through CSS custom
properties.

**Risk bands are coloured, but `low` is blue rather than green.** A
misconfiguration is never "good"; it is only less urgent. Green would tell a
dashboard reader that something is fine when the correct reading is that it is
still wrong.

**CORS is restricted to loopback.** This API returns a complete inventory of an
account's misconfigurations; it must not be reachable cross-origin from a real
hostname. The dashboard is served from the same app and needs no CORS at all — the
permissive rule exists only for a separately hosted dev frontend.

## Tests

`tests/test_api.py` runs the real app against a throwaway SQLite file via
FastAPI's `TestClient` — no mocked storage layer, because the bugs worth catching
here (status transitions, aggregation arithmetic, filter construction) only
appear against a real database. The seed data is the same P1-shaped file the demo
uses, so a green run means the demo path works.
