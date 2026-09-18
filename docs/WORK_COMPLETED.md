# Work completed — P2 and P3, week by week

**Date:** 2026-09-19
**Scope:** Person 2 (scoring, explainability, compliance) and Person 3 (API, storage, dashboard), built up to but **not including** the Week-4 P1→P2→P3 integration.
**Explicitly not included:** any P1 work. No AWS connector, no boto3, no live account access, no polling loop. Findings enter the system as raw JSON via `POST /scan` or a seed file.

Read §5 before treating anything here as working. The suite runs and is **not green**: the last run was **279 passed, 3 failed**, and one of those three is a real behavioural bug that is not yet root-caused.

---

## Week 0 — Foundation

| Task | State |
|---|---|
| Finalize the Finding JSON schema | **Done** — `schema/finding_schema.json` (enriched shape) and `schema/raw_finding_schema.json` (P1's output shape). Added `'account'` to the documented `resource.type` vocabulary, which the mock findings already used. |
| Commit 8–10 mock findings | **Done** — `data/seed/mock_findings.handcrafted.json`, 10 hand-authored enriched findings, frozen as the regression fixture. `data/mock_findings.raw.json`, 12 P1-shaped findings covering all 12 rules, spanning 12 detection dates and 2 scan ids. |
| Repository / branch structure | **Outstanding** — the git root still sits at `C:\Users\Krish Garg` with no commits, so the project has no repository of its own. |
| AWS test account | P1's task — untouched. |

## Week 1 — Scoring engine and API skeleton

**P2 — scoring engine v1. Done.**

| File | What it does |
|---|---|
| `p2_scoring/rules.py` | The rule table: 12 rules, each with ordered factors, point weights, and the `context` keys each factor requires. Also `UnknownRuleError`. |
| `p2_scoring/scoring.py` | The engine: applies factors whose required evidence is present, caps at 100 with an explicit `score_cap_adjustment` ledger entry, assigns the risk band. |
| `p2_scoring/signals.py` | Signals derived from the finding rather than supplied by P1 — data sensitivity from the resource name, inactive-user detection, sensitive-port classification. |

**P3 — API skeleton and dashboard shell. Done.** `p3_api/app.py`, `p3_api/schemas.py`, `p3_api/static/index.html`, `app.js`, `styles.css`.

## Week 2 — Explanation, compliance, persistence, technical view

**P2 — explanation cards and compliance table v1. Done.**

| File | What it does |
|---|---|
| `p2_scoring/explanations.py` | Per-rule issue / consequence / fix prose, with wording that adapts to the facts (names the exposed port, escalates when permissions are elevated, mentions RDS encryption only when it is also off). |
| `p2_scoring/compliance.py` | Rule → framework-clause mappings for PCI-DSS, SOC 2 and GLBA, clause reference text, and `PROPOSED_MAPPINGS`. |
| `p2_scoring/enrich.py` | The P1-facing entry point, `enrich_findings()`, plus a CLI (`--in` / `--out`). The one function P1 needs to call. |
| `p2_scoring/__init__.py` | Public surface; documents why P2 carries no dependencies. |

**P3 — persistence and the technical view. Done.**

| File | What it does |
|---|---|
| `p3_api/db.py` | SQLite schema — `findings` and `scans` — WAL mode, connection-per-request `session()`. |
| `p3_api/repository.py` | All SQL: upsert, filtering, sorting, pagination, aggregation, trend bucketing, filter options. |
| `p3_api/scan_service.py` | The seam between P2's enriched output and storage: validate → enrich → upsert → build the scan report. |
| `p3_api/cli.py` | `seed`, `stats`, `reset --yes`, `serve`. `seed` takes **raw** findings, so seeding a demo exercises the same path a real scan does. |

## Week 3 — All 12 rules, compliance view, hardening

**P2 — polish to all 12 rules. Done.** Every rule has factors, a compliance mapping and an explanation template; `tests/test_rule_table.py` fails if the three registries disagree. ML groundwork deferred (the project plan marks it cuttable).

**P3 — compliance view. Done.** Framework/clause view plus hand-rolled SVG charts (donut, bars, trend) — no build step and no CDN, so an offline demo cannot fail on network. XSS escaping via an `esc()` helper on every AWS-supplied string.

**Docs and tooling. Done.** `docs/P2_SCORING_SPEC.md`, `docs/P2_COMPLIANCE_MAPPING.md`, `docs/P3_API_SPEC.md`, `README.md`, `pyproject.toml`, `.gitignore`, `scripts/generate_contract_doc.py`.

**Tests.** `conftest.py` plus `tests/` for seed reconciliation, scoring, compliance, explanations, rule table, and the API against a real throwaway database.

## Week 4 — Integration

**Not started**, as scoped. The prerequisite is `docs/INTEGRATION_CONTRACT.md`, which does not exist yet (§5).

---

## Decisions worth knowing about

**The score breakdown *is* the score.** The invariant is `risk_score == min(100, sum(f.weight for f in score_breakdown))`. SHAP and LIME were considered and rejected: they explain a *model* by approximating it, and this is declared weights over observed facts, so an approximation would be strictly worse than showing the computation.

**Missing evidence is not a negative observation.** A `context` key P1 did not send means *unknown*, so the factor is skipped rather than firing. The naive version scored a CloudTrail finding **78/100 on an empty context** — a confident critical finding built from data nobody supplied.

**Synergy factors close arithmetic gaps honestly.** Two hand-authored findings had breakdowns summing below their stated score. Rather than inflating a weight or hiding a multiplier, two named factors were added — `public_exposure_without_encryption` (8 pts) and `elevated_access_without_mfa` (5 pts) — so the card still adds up and each point has a sentence.

**A supplied negative outranks a supplied positive.** `SG_OPEN_TO_WORLD`'s `sensitive_port` factor is gated on the group actually being world-open, so a private-only CIDR does not earn points for "port 3306 is exposed to the internet."

---

## Defects found and fixed

Each is now pinned by a test.

| Defect | Effect if shipped |
|---|---|
| `sensitive_port` fired on `exposed_ports` alone | A security group with a private-only CIDR still earned 30 points for internet exposure — points awarded *against* evidence P1 had supplied. |
| Missing `high` on `TrendPoint` | FastAPI filters response fields to the declared model, so the high-band count was computed and then silently dropped from `/trend`. |
| `[hidden]` lost to `.view { display: flex }` | An author rule outranks the user-agent `[hidden]` rule, so both the technical and compliance views rendered at once. |
| Multiselect CSS used child selectors (`> summary`) | The control nests `<summary>` inside a `<details>`, so no selector matched and the entire filter control was unstyled. |
| Multiselect re-rendered the whole control on each checkbox click | Tore down the `<details>` the user was clicking inside, slamming the popover shut — selecting two values meant reopening it twice. |
| `/filter-options` returned `risk_band`, the filter is `band` | The severity control read `state.options['band']`, found nothing, and stayed permanently empty — which looks like a data problem, not a naming one. |
| Trend chart used `preserveAspectRatio="none"` with a fixed height | Stretched the axis labels along with the geometry. |
| `ingest()` recorded only the batch's dominant `scan_id` | The per-scan trend view drew one point where the data described two. Now one row per distinct scan, with `scan_id` ORDER BY tiebreakers. |
| Contract generator asserted the wrong thing | Checked `factor.key not in rule.context_keys`, which wrongly fails for factors like `no_encryption`. Now checks `set(factor.requires) - declared`. |
| `false_positive` was treated as reopenable | `TERMINAL_STATUSES` lumped it with `remediated`, so every re-scan reopened it and bumped `reopen_count`. A scanner re-detects a false positive on *every* run, so an analyst would have re-marked it nightly and the `reopened` tally — the thing that makes a real regression visible — would have been noise. Split into `REOPENABLE_STATUSES = {"remediated"}`. |
| `test_every_declared_context_key_is_actually_read` was circular | It grepped `rules.py` for each key as a string literal — but every key in `context_keys` *is* a string literal in `rules.py`, so it could never fail. It was reporting a clean bill of health for **four context keys nothing reads**: `block_public_access`, `attached_role_count`, `snapshot_count`, `multi_region_trail`. Rewritten to be structural, with `UNSCORED_CONTEXT_KEYS` as an explicit ledger so a dead entry is a deliberate act rather than an accident. |
| `summarise_by_framework` keyed clause buckets on `clause` alone | GLBA's Safeguards Rule is not clause-numbered, so two different requirements share the clause string. They merged into one row carrying whichever description was iterated first; the other requirement vanished. Now keyed on `(clause, description)`, matching `repository.compliance_summary`, so both paths give the same answer. |
| `filterwarnings = ["error::DeprecationWarning"]` | Promoted a third-party import-time warning (starlette's `TestClient` importing an anyio alias) into a collection error, making **all of `tests/test_api.py` unrunnable**. Scoped to this project's own modules. |
| `test_private_cidr_only_scores_nothing` asserted the wrong thing | Claimed no missing evidence while supplying only two of the rule's three `context` keys. `attached_to_prod` genuinely was not sent. |

---

## Verification status — read this before trusting the above

| Item | State |
|---|---|
| Authoring of P2 and P3 | Done |
| Full test suite | **Run.** Last result: **279 passed, 3 failed** — up from a stale cache of 161 passed / 14 failed that predated the fixes. |
| `docs/INTEGRATION_CONTRACT.md` | **Does not exist.** The generator is written and complete but has never been executed, so the file is not on disk. `README.md` and several docstrings reference it. This is the Week-4 prerequisite. |
| End-to-end demo path | **Not run.** The database has not been seeded from `data/mock_findings.raw.json`; the server has not been started; the dashboard has never been rendered in a browser. |
| Project `git init` | **Outstanding.** |

### The three open failures

1. **`test_a_rescan_does_not_undo_a_human_decision` — real bug, reproduced.** After `PATCH {"status": "acknowledged"}`, a re-scan returns the finding to `open`. `upsert_finding` **in isolation preserves it correctly** (returns `unchanged`, column stays `acknowledged`), so the clobber is somewhere in the HTTP path rather than in the upsert logic. Root cause not identified.
2. **`test_a_false_positive_is_not_treated_as_a_regression`** — same area, same symptom.
3. **`test_open_findings_stay_open_across_scans`** — asserts 12 open, gets 10. The seed itself carries `acknowledged` and `remediated` findings (observed statuses: `acknowledged`, `open`, `remediated`), so this expectation looks wrong rather than the code. Worth confirming, not assuming.

To close the rest out:

```bash
python -m pytest
python scripts/generate_contract_doc.py
python -m p3_api.cli seed data/mock_findings.raw.json
python -m p3_api.cli serve        # then open http://127.0.0.1:8000
```

---

## Open items needing a decision

These need a person, not more code.

**For P1** — to answer before Week 4:

1. Can the connector populate **every per-rule `context` key**? Any key it cannot supply is a factor that will never fire.
2. Four declared keys are **collected but not scored** — no factor reads them, so populating them changes no risk score: `block_public_access` (S3), `attached_role_count` (IAM), `snapshot_count` (EBS), `multi_region_trail` (CloudTrail). Either add a factor or drop the key from the contract. Note `attached_role_count` is unscored while `attached_user_count` is worth 18 points, which reads as an omission rather than a decision.
3. Confirm `resource.type: "account"` for account-level rules such as `CLOUDTRAIL_DISABLED`.
4. Confirm `finding_id` is **stable across scans**. The whole lifecycle model depends on it — a regenerated id makes every re-scan look like a brand-new finding and silently breaks reopen detection.
5. Storage encryption is spelled two ways — `encryption_enabled` (S3, EBS) and `storage_encrypted` (RDS). A connector sending the wrong one gets that factor scored as *missing evidence* rather than as encryption status. Pick one, or send both.

**For compliance sign-off:**

- `S3_NO_ENCRYPTION` and `EBS_NOT_ENCRYPTED` are in `PROPOSED_MAPPINGS` — mapped by us, not yet confirmed by whoever owns the compliance relationship. They need review before they appear in front of an auditor.
- GLBA is cited under two phrasings in the reference material. Both are recorded rather than normalised, since which is correct is a compliance question, not a code one.

**For the team:**

- Week 0 repository setup: this project needs its own `git init` and the branch layout the project plan describes.
