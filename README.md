# Explainable cloud misconfiguration detection

A CSPM for regulated industries where the hard part is not *detecting* a
misconfiguration but **justifying** it — to an engineer deciding what to fix
first, and to an auditor asking which regulation it breaches.

Conventional scanners tell you a bucket is public and label it "critical". This
one shows you the arithmetic: an ordered list of named factors, each with a point
value and a sentence explaining why it applies, that sums to exactly the score on
the card. Then it names the PCI-DSS or SOC 2 clause the finding bears on.

## What is actually different

**The score breakdown is the score.** Not a summary of it, not an approximation
of it.

```
risk_score == min(100, sum(f.weight for f in score_breakdown))
```

The brief suggested SHAP or LIME for explainability. Those explain a *model* by
approximating it. This is not a model — it is declared weights over observed
facts, so an approximation would be strictly worse than showing the computation.
An auditor can add up the card and get the number.

**Missing evidence is not a negative observation.** A context key P1 did not send
means *unknown*, so the factor is skipped rather than firing. During development
the naive version scored a CloudTrail finding **78/100 on an empty context** — a
confident critical finding built from data nobody supplied. This is the defect
that would have made the whole product untrustworthy, and it is pinned by tests.

**Findings are traceable to a regulation.** Every rule maps to PCI-DSS, SOC 2 or
GLBA clauses, and the dashboard's compliance view counts exposure per framework
and per clause.

## Layout

```
p2_scoring/          P2 — enrichment. stdlib only, no install needed.
  rules.py             the rule table: factors, weights, required evidence
  scoring.py           the engine; the sum-to-score invariant
  signals.py           derived signals (sensitivity from resource name, …)
  compliance.py        rule -> framework clause mappings
  explanations.py      issue / consequence / fix prose per rule
  enrich.py            the P1-facing entry point + CLI

p3_api/              P3 — HTTP API, storage, dashboard.
  app.py               FastAPI endpoints
  db.py                SQLite schema
  repository.py        all SQL
  scan_service.py      the seam between P2's output and storage
  static/              the dashboard (no build step, no CDN)

schema/              the agreed finding schemas (raw + enriched)
data/                mock findings; the demo database lives here
docs/                scoring spec, compliance mapping, API spec, contract
scripts/             contract-doc generator
tests/               P2 unit + reconciliation tests, P3 API tests
```

## Running it

```bash
pip install -e ".[dev]"

python -m p3_api.cli seed data/mock_findings.raw.json
python -m p3_api.cli serve          # http://127.0.0.1:8000
```

P2 alone needs nothing installed:

```bash
python -m p2_scoring.enrich --in data/mock_findings.raw.json --out /tmp/enriched.json
pytest tests/test_scoring.py tests/test_seed_reconciliation.py
```

## The data contract

```
P1 AWS connector
  |  raw finding JSON          schema/raw_finding_schema.json
  v
P2 enrich_findings()
  |  + risk_score, score_breakdown, explanation, compliance_mappings
  v
P3 POST /scan -> SQLite -> dashboard
```

`docs/INTEGRATION_CONTRACT.md` is **generated** from the rule table by
`scripts/generate_contract_doc.py`, and `--check` fails the build when it is
stale. A hand-maintained contract drifts, and a drifted contract is worse than
none: P1 would populate keys nobody reads while the keys that drive scores stay
empty.

## Tests

```bash
pytest
```

- `test_seed_reconciliation.py` — the ten hand-authored Week-0 findings must
  reproduce their `risk_score` and their original `score_breakdown` exactly.
  This is the regression that matters most: the seed data is the agreed
  specification, and it is where the synergy-factor defect was found.
- `test_scoring.py` — the sum-to-score invariant and the evidence gate.
- `test_compliance.py`, `test_explanations.py`, `test_rule_table.py` — the three
  registries stay in agreement; a rule cannot be half-added.
- `test_api.py` — the real app against a real (throwaway) database.

## Status

This is the P2 and P3 halves, built and independently testable against mock
findings. The P1 AWS connector is **not** included — findings arrive via
`POST /scan` or a seed file. See "Open items" in
`docs/INTEGRATION_CONTRACT.md` for what P1 needs to confirm before integration.
