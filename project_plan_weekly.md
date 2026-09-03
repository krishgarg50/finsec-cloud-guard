# [PROJECT NAME] — Fixed 8-Week Implementation Plan

This document is the single source of truth for what each person builds, week by week.
Do not reinterpret or re-derive this plan — follow it exactly as written. If something is unclear, ask the team, don't guess a different version.

Roles:
- **P1** = Detection Engine (AWS connector + rule engine)
- **P2** = Scoring, Explainability, Compliance Mapping (+ optional ML layer)
- **P3** = Backend API + Dashboard

Shared files everyone depends on (already created in Week 0):
- `shared/finding_schema.json` — the Finding contract, do not modify without team agreement
- `shared/mock_findings.json` — sample data for parallel development
- `shared/detection_rules.md` — the 12 rules with severity levels
- `docs/aws_setup.md`, `docs/tech_stack.md`, `.env.example`, `.gitignore`, `requirements.txt`

---

## PERSON 1 (P1) — Detection Engine

### Goal of P1's role
Build the component that connects to AWS, reads real configuration state, evaluates it against the 12 rules in `shared/detection_rules.md`, and outputs raw findings that conform exactly to `shared/finding_schema.json` (with `score_breakdown`, `explanation`, and `compliance_mappings` left as empty arrays/placeholder — those get filled in by P2 later).

### Week 1
**Goal:** AWS connector working for S3 and IAM; can pull raw config data.
**Build:**
1. Set up `detection-engine/` folder with `connector.py` and `rules/` subfolder.
2. Write AWS connection setup using `boto3`, reading credentials from `.env` (never hardcode keys).
3. Write functions to pull: all S3 buckets + their ACLs/policies/encryption status; all IAM users + policies + MFA status (via `iam:GetCredentialReport`).
4. Implement rules #1 (S3_PUBLIC_ACCESS), #4 (IAM_WILDCARD_POLICY), #5 (IAM_ROOT_NO_MFA) from `detection_rules.md`.
5. Output findings as JSON objects matching `finding_schema.json` — leave `score_breakdown: []`, `compliance_mappings: []`, and `explanation` fields as empty strings/0 for now.
**Git commits this week:**
- `detection-engine/connector.py` (AWS connection logic)
- `detection-engine/rules/s3_rules.py`, `detection-engine/rules/iam_rules.py`
- Commit message format: `P1: add AWS connector + S3/IAM public access and wildcard policy rules`

### Week 2
**Goal:** Expand connector to Security Groups, encryption checks, MFA, CloudTrail. 6-8 rules working end-to-end against the real test AWS account.
**Build:**
1. Add EC2 Security Group pulling (`ec2:DescribeSecurityGroups`).
2. Implement rule #8 (SG_OPEN_TO_WORLD), #2 (S3_NO_ENCRYPTION), #6 (IAM_USER_NO_MFA), #12 (CLOUDTRAIL_DISABLED).
3. Test all rules against the real AWS test account — manually create one test S3 bucket, one open security group, confirm the rules correctly flag them.
4. Write a `run_scan.py` script that runs all rules and outputs a full findings list as a single JSON file (`scan_output.json`).
**Git commits this week:**
- `detection-engine/rules/sg_rules.py`, `detection-engine/rules/encryption_rules.py`, `detection-engine/rules/cloudtrail_rules.py`
- `detection-engine/run_scan.py`
- Commit message format: `P1: add SG/encryption/MFA/CloudTrail rules, add run_scan entrypoint`

### Week 3
**Goal:** All 12 rules implemented, edge cases handled, rules documented.
**Build:**
1. Implement remaining rules: #3 (S3_NO_VERSIONING), #7 (IAM_UNUSED_ACCESS_KEY), #9 (EBS_NOT_ENCRYPTED), #10 (RDS_NOT_ENCRYPTED), #11 (RDS_PUBLICLY_ACCESSIBLE).
2. Handle edge cases: what happens if a bucket has no policy at all (not an error, just "no public access" = pass); what happens if AWS API rate-limits you (add retry logic with backoff); what happens if a service has zero resources (return empty list, not a crash).
3. Write `detection-engine/README.md` documenting each rule, what it checks, and how to run the scanner.
**Git commits this week:**
- `detection-engine/rules/remaining_rules.py` (or split into individual files matching pattern above)
- `detection-engine/README.md`
- Commit message format: `P1: complete all 12 detection rules, add edge case handling and docs`

### Week 4 — Integration Checkpoint (all 3 together)
**Goal:** P1's real scan output flows into P2's scoring and P3's dashboard without errors.
**Build:**
1. Run `run_scan.py` against the real AWS test account, produce real `scan_output.json`.
2. Hand this off to P2 to run through their scoring engine.
3. Fix any schema mismatches found (e.g., missing fields, wrong types) — this is expected, budget real time for it.
**Git commits this week:**
- Any bugfix commits: `P1: fix schema mismatch in [specific field] found during integration`

### Week 5
**Goal:** Support role. Fix any remaining rule bugs. Start building demo misconfigured resources.
**Build:**
1. Fix bugs surfaced by P2/P3 during integration.
2. Using the separate write-access IAM user (`csmp-demo-resources`, NOT the scanning user), create 3-4 deliberately misconfigured AWS resources for the live demo (e.g., one public S3 bucket named clearly like `demo-public-bucket`, one open security group, one unencrypted RDS instance if budget/time allows).
3. Tag all demo resources with `Project: CSPM-Demo` for easy cleanup later.
**Git commits this week:**
- `detection-engine/demo_setup.py` (script to create/teardown demo resources, so it's reproducible, not manual clicking)
- Commit message format: `P1: add demo resource setup/teardown script`

### Week 6
**Goal:** Support role. Help wire demo scenarios into full pipeline.
**Build:**
1. Run full scan against demo resources, confirm all planted misconfigurations are correctly detected.
2. Any final rule accuracy fixes.
**Git commits this week:**
- Bugfix commits as needed.

### Week 7 — Integration Checkpoint 2 + Demo Prep (all 3 together)
**Goal:** Full pipeline runs end-to-end reliably for the live demo.
**Build:**
1. Run the full scan-to-dashboard pipeline multiple times, confirm consistency.
2. Help rehearse the demo walkthrough script.
**Git commits this week:**
- Final polish commits only.

### Week 8 — Buffer
**Goal:** No new features. Only fix what's broken.
**Build:** Bug fixes only, based on final rehearsal issues.
**Git commits this week:** Bugfix commits only, e.g. `P1: fix intermittent rate-limit error in S3 scan`

---

## PERSON 2 (P2) — Scoring, Explainability, Compliance Mapping (+ optional ML)

### Goal of P2's role
Take raw findings (from P1, or from `shared/mock_findings.json` before P1's output is ready) and enrich them with: a computed `risk_score`, a transparent `score_breakdown`, a plain-English `explanation` (issue/consequence/fix/projected_score_after_fix), and `compliance_mappings` to PCI-DSS and SOC2. All output must conform to `shared/finding_schema.json`. This role never has to wait on P1 — it can and should be built entirely against `mock_findings.json` first.

### Week 1
**Goal:** Scoring engine v1 built and tested against mock data.
**Build:**
1. Set up `scoring-explainability/` folder.
2. Read `shared/mock_findings.json`, write `scoring_engine.py` that takes a raw finding (rule_id + resource info) and computes `risk_score` using additive weighted factors — reference the severity levels in `detection_rules.md` as your starting weights (high severity rules start around 70-90 base points, medium 40-60, low 15-35, then add/subtract based on specific factors like "sensitive data" or "attached to production").
3. Output the `score_breakdown` array showing each factor and its weight, exactly matching the schema structure.
4. Validate your output against `shared/finding_schema.json` using Python's `jsonschema` library — write a small `validate.py` test script.
**Git commits this week:**
- `scoring-explainability/scoring_engine.py`
- `scoring-explainability/validate.py`
- Commit message format: `P2: add scoring engine v1 with weighted factor logic, validated against schema`

### Week 2
**Goal:** Explanation card generator + first compliance mapping table.
**Build:**
1. Write `explanation_generator.py` — for each rule_id, generate templated but rule-specific text for `issue`, `consequence`, `fix`, and compute `projected_score_after_fix` (generally: high-severity findings should project down to 10-25 after fix, medium to 15-30, low to 5-15).
2. Build `compliance_mapping.py` — a lookup table mapping each of the 12 rule_ids to relevant PCI-DSS and SOC2 clauses (use the mappings already drafted in `mock_findings.json` as your starting reference, expand/verify them).
3. Test both modules against all findings in `mock_findings.json`.
**Git commits this week:**
- `scoring-explainability/explanation_generator.py`
- `scoring-explainability/compliance_mapping.py`
- Commit message format: `P2: add explanation card generator and compliance mapping table`

### Week 3
**Goal:** Polish explanation quality, cover all 12 rules, begin ML groundwork (non-blocking side track).
**Build:**
1. Ensure explanation text and compliance mappings exist for all 12 rules from `detection_rules.md`, not just the ones in mock data.
2. Write `enrich_findings.py` — the main entrypoint that takes P1's raw `scan_output.json`, runs it through scoring + explanation + compliance mapping, and outputs a fully enriched findings list.
3. **ML side track (does not block anything else):** decide model approach (isolation forest recommended for IAM permission anomaly detection — simplest to implement and interpret). Start collecting/synthesizing training data — this can be synthetic data you generate by randomly combining IAM permission patterns, labeled as normal/anomalous based on rules of thumb (e.g., wildcard + attached to many users + created recently = higher anomaly likelihood).
**Git commits this week:**
- `scoring-explainability/enrich_findings.py`
- `scoring-explainability/ml/data_synthesis.py` (if ML track proceeding)
- Commit message format: `P2: add main enrichment pipeline; start ML anomaly data synthesis`

### Week 4 — Integration Checkpoint (all 3 together)
**Goal:** P1's real output runs through P2's enrichment without errors, output validates against schema.
**Build:**
1. Run `enrich_findings.py` on P1's real `scan_output.json`.
2. Fix any bugs — missing fields, unexpected rule_ids not in the compliance mapping table, etc.
3. Hand off enriched output to P3 for dashboard integration.
**Git commits this week:**
- Bugfix commits: `P2: handle missing rule_id case in compliance mapping`

### Week 5
**Goal:** ML layer build (go/no-go checkpoint at end of this week).
**Build:**
1. Train the anomaly detection model (isolation forest or one-class SVM) on synthesized/labeled data.
2. Validate: inject known-anomalous test cases, measure precision/recall — write this evaluation as a script with printed metrics, not just eyeballing results.
3. **Decision point at end of week:** if precision/recall are reasonable (aim for >70% on your test set) and you're not spending excessive time debugging — continue to Week 6 integration. If it's not working well or eating too much time — STOP here, pivot Week 6 to strengthening explanations/compliance mapping instead. This is not a failure, it's the planned safety valve.
**Git commits this week:**
- `scoring-explainability/ml/train_model.py`, `scoring-explainability/ml/evaluate.py`
- Commit message format: `P2: train anomaly detection model, add evaluation script with precision/recall metrics`

### Week 6
**Goal (if ML proceeding):** Integrate anomaly findings into pipeline, marked with `detection_source: anomaly_detection`.
**Goal (if ML cut):** Strengthen explanation quality, add a 3rd compliance framework (GLBA) as extra depth.
**Build (ML path):**
1. Wire anomaly detection into `enrich_findings.py` — anomaly findings get their own explanation framing ("flagged by anomaly detection, not a static rule") and a distinct `detection_source` value.
**Build (non-ML path):**
1. Add GLBA compliance mappings alongside PCI-DSS/SOC2.
2. Improve explanation text specificity (e.g., reference actual resource names/values in generated text, not just generic templates).
**Git commits this week:**
- Commit message format: `P2: integrate ML anomaly findings into pipeline` OR `P2: add GLBA compliance mapping, improve explanation specificity`

### Week 7 — Integration Checkpoint 2 + Demo Prep (all 3 together)
**Goal:** Full enrichment pipeline runs reliably end-to-end on demo data.
**Build:**
1. Run full pipeline on P1's demo resource scan, confirm scores/explanations/compliance mappings all look correct and compelling for the live demo.
2. Help rehearse demo walkthrough.
**Git commits this week:** Final polish commits only.

### Week 8 — Buffer
**Goal:** No new features. Only fix what's broken.
**Build:** Bug fixes only.
**Git commits this week:** Bugfix commits only.

---

## PERSON 3 (P3) — Backend API + Dashboard

### Goal of P3's role
Build the API layer that serves findings data, and the dashboard that presents it in two views: technical (DevOps/security — raw findings, severity, fix steps) and compliance (risk/audit — explanation cards, compliance mapping, trends). This role never has to wait on P1/P2 — build entirely against `shared/mock_findings.json` first, swap in real pipeline output at integration checkpoints.

### Week 1
**Goal:** API skeleton + dashboard shell, both rendering mock data.
**Build:**
1. Set up `backend-api/` folder with FastAPI app (`main.py`).
2. Implement endpoints: `GET /findings` (returns list from `mock_findings.json` initially), `GET /findings/{finding_id}` (single finding detail).
3. Set up `dashboard/` folder with React app (via `create-react-app` or `vite`).
4. Build basic routing: two pages/routes — `/technical` and `/compliance` — both currently just fetching and displaying raw JSON from the API (styling comes later).
**Git commits this week:**
- `backend-api/main.py`
- `dashboard/src/App.jsx`, `dashboard/src/pages/TechnicalView.jsx`, `dashboard/src/pages/ComplianceView.jsx`
- Commit message format: `P3: add API skeleton with /findings endpoints, dashboard shell with two routes`

### Week 2
**Goal:** Persistence layer + functional technical view.
**Build:**
1. Add SQLite database via SQLAlchemy — table matching `finding_schema.json` structure (nested fields like `score_breakdown` and `explanation` can be stored as JSON columns).
2. Write a script to load `mock_findings.json` into the database, update `/findings` endpoint to read from DB instead of static file.
3. Build out Technical View: table/list of findings, sortable by `risk_score` and `severity_raw`, filterable by `resource.type` and `status`.
**Git commits this week:**
- `backend-api/database.py`, `backend-api/load_mock_data.py`
- `dashboard/src/pages/TechnicalView.jsx` (updated with sort/filter)
- Commit message format: `P3: add SQLite persistence, build functional technical view with sort/filter`

### Week 3
**Goal:** Compliance view functional with explanation cards and charts.
**Build:**
1. Build Compliance View: renders `explanation` fields as readable cards (issue/consequence/fix/projected score), displays `compliance_mappings` per finding grouped by framework.
2. Add basic charts using Recharts: findings count by severity, findings count by resource type (bar charts are enough, don't over-engineer).
**Git commits this week:**
- `dashboard/src/pages/ComplianceView.jsx`
- `dashboard/src/components/ExplanationCard.jsx`, `dashboard/src/components/SeverityChart.jsx`
- Commit message format: `P3: build compliance view with explanation cards and severity charts`

### Week 4 — Integration Checkpoint (all 3 together)
**Goal:** Dashboard displays P2's real enriched findings (from P1's real scan) instead of mock data.
**Build:**
1. Replace mock data loading with P2's `enrich_findings.py` output — write a script to load enriched findings into the database.
2. Add a `POST /scan` endpoint that triggers P1's scan + P2's enrichment pipeline and stores results (can be synchronous/blocking for now, doesn't need to be async/background for this scope).
3. Fix any rendering bugs caused by real data differing from mock data assumptions.
**Git commits this week:**
- `backend-api/scan_trigger.py`
- Bugfix commits: `P3: fix rendering issue with real data edge case`

### Week 5
**Goal:** Dashboard polish — trends, better filtering, UI cleanup.
**Build:**
1. Add a trend view: findings count over time (using `scan_id`/`detected_at` fields) — even a simple line chart showing scan-over-scan finding counts is enough.
2. Improve filtering: by compliance framework, by date range.
3. UI cleanup: consistent styling, loading states while data fetches, empty states when no findings match filters.
**Git commits this week:**
- `dashboard/src/pages/TrendsView.jsx`
- Commit message format: `P3: add trends view, improve filtering, polish UI states`

### Week 6
**Goal (if P2's ML proceeding):** Display anomaly-detected findings with distinct visual treatment.
**Goal (if ML cut):** Continue polish — error handling, edge cases, responsive layout.
**Build (ML path):**
1. Add visual distinction (badge/icon) for findings where `detection_source: anomaly_detection`, with a tooltip explaining what that means.
**Build (non-ML path):**
1. Handle error states (API down, no findings, malformed data) gracefully in UI.
2. Basic responsive layout check (dashboard usable on a laptop screen at minimum, doesn't need full mobile support).
**Git commits this week:**
- Commit message format: `P3: add anomaly finding visual treatment` OR `P3: add error handling and responsive layout polish`

### Week 7 — Integration Checkpoint 2 + Demo Prep (all 3 together)
**Goal:** Full pipeline (scan → enrich → store → dashboard) runs reliably for live demo.
**Build:**
1. Run full pipeline against P1's demo resources multiple times, confirm dashboard updates correctly each time.
2. Write `docs/README.md` — setup instructions so anyone (professor/evaluator) can run the project from scratch.
3. Help rehearse demo walkthrough — decide what gets clicked through live vs. pre-loaded.
**Git commits this week:**
- `docs/README.md`
- Final polish commits.

### Week 8 — Buffer
**Goal:** No new features. Only fix what's broken.
**Build:** Bug fixes only, based on final rehearsal issues.
**Git commits this week:** Bugfix commits only.

---

## Git Workflow Rules (all 3 people, every week)

1. **Branch naming:** `p1/week-N-short-description`, `p2/week-N-short-description`, `p3/week-N-short-description` (e.g. `p1/week-2-security-groups`).
2. **Commit frequency:** commit at the end of each working session, not just once at the end of the week — small, working increments are easier to debug than one giant commit.
3. **Commit message format:** always start with your role tag, e.g. `P1: add SG rules`, `P2: fix scoring bug`, `P3: add trend chart`.
4. **Never commit:** `.env`, any `.csv` credential files, `node_modules/`, `__pycache__/`, database files (`.db`) — all already covered by `.gitignore`.
5. **Pull before you push, every time** — with 3 people touching `shared/` files occasionally, merge conflicts on the schema file are the most likely source of pain; always confirm with the team before editing anything in `shared/`.
6. **At every Integration Checkpoint (Week 4, Week 7):** merge all branches into `main` (or `dev`), do not leave integration merges for later — this is the entire point of those weeks.
