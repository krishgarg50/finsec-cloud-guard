# finsec-cloud-guard -- Setup Guide

An explainable cloud misconfiguration detection system for financial
institutions. This guide gets you from a fresh clone to a running
dashboard with real findings on screen.

## 1. Requirements

- Python 3.10+
- An AWS account (only needed if you want to run a live scan; the steps
  below work fully offline using included sample data)

## 2. Install

From the repository root:

```bash
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -e .
pip install fastapi uvicorn jsonschema pytest httpx
```

## 3. Run the automated test suite (optional, but recommended first)

```bash
python -m pytest -q
```
Expect all tests to pass with no failures. If anything fails here, stop
and fix it before continuing -- the steps below assume a working install.

## 4. Load findings into the dashboard

You have two options.

### Option A -- Use the included sample data (fastest, no AWS needed)
```bash
python -m p3_api.cli seed data/mock_findings.raw.json
```

### Option B -- Run a real AWS scan first, then load its output
```bash
cd detection-engine
python run_scan.py
cd ..
python -m p3_api.cli seed detection-engine/scan_output.json
```
This requires AWS credentials configured in a `.env` file at the repo
root (see `.env.example` for the expected variables) for a read-only IAM
user. See `docs/aws_setup.md` for how to set that up from scratch.

Either option prints a short summary, for example:
```
scan scan-91bb53f1-...: 8 finding(s) ingested
  new=8 updated=0 reopened=0 unchanged=0
  average score: 44.9
  critical  1
  high      1
  low       2
  medium    4
```

## 5. Start the server

```bash
python -m p3_api.cli serve
```

## 6. Open the dashboard

Visit **http://127.0.0.1:8000/** in a browser. You should see:
- A **Technical view**: sortable/filterable list of findings, a score
  badge per row, and a detail drawer (click any row) showing the full
  risk-score breakdown and recommended fix.
- A **Compliance view**: findings grouped by framework (PCI-DSS, SOC2,
  GLBA) with clause references.
- Summary tiles and a trend chart at the top of both views.

## 7. Re-scanning and the reopen workflow

Findings can be marked `acknowledged`, `remediated`, or `false_positive`
via the detail drawer, or directly through the API:
```bash
curl -X PATCH http://127.0.0.1:8000/findings/<finding_id> \
  -H "Content-Type: application/json" \
  -d '{"status": "remediated"}'
```

If a finding marked `remediated` is still present in the AWS environment
on a later scan, it is automatically **reopened** -- its status returns
to `open` and `reopen_count` increments by one. This was verified
end-to-end for this guide: marking a finding remediated, re-running the
same scan, and confirming the API correctly reported
`"reopened": 1` and the finding's own record showed
`"status": "open", "reopen_count": 1`.

## 8. Troubleshooting

- **`ModuleNotFoundError: p3_api`** -- you likely skipped `pip install -e .`
  from step 2, or are running commands from the wrong directory. Run
  commands from the repository root.
- **Dashboard loads but shows "No findings"** -- you haven't run step 4
  yet, or seeded into a different database file than the server is
  reading. Both `cli seed` and `cli serve` use the same default DB path
  (`data/findings.db`) unless overridden.
- **`jsonschema` import errors when validating** -- run
  `pip install jsonschema` (not always installed by `pip install -e .`
  alone, depending on your environment).
- **Port 8000 already in use** -- another process is already using it;
  stop it, or run `python -m p3_api.cli serve --port 8001` and adjust the
  URL in step 6 accordingly (check `python -m p3_api.cli serve --help`
  for the exact flag name in your checkout).

## 9. Project layout

```
detection-engine/   P1 -- AWS connector + 12 detection rules
p2_scoring/          P2 -- risk scoring, explanations, compliance mapping
p3_api/               P3 -- FastAPI backend + dashboard (this component)
schema/                Shared JSON schemas (the contract between all three)
data/                   Sample/mock findings for offline development
tests/                  Automated tests for all three components
docs/                   Setup guides, specs, and the integration contract
```
