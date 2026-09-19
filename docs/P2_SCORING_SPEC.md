# P2 — scoring specification

How a raw detection becomes a number a risk committee will accept.

## The guarantee

```
risk_score == min(100, sum(f.weight for f in score_breakdown))
```

This is the whole product. A conventional CSPM computes a score inside a
function and prints a label; the reasoning is not recoverable, so a finding that
says "critical" cannot be argued with, and a finding that says "low" cannot be
justified to an auditor. Here the breakdown the analyst reads **is** the
arithmetic that produced the score. There is no hidden multiplier, no severity
matrix applied afterwards, no model.

The invariant is asserted for every rule by `tests/test_scoring.py`, and against
the hand-authored Week-0 findings by `tests/test_seed_reconciliation.py`.

### Why rule-trace and not SHAP/LIME

The project brief suggested SHAP or LIME for explainability. Those techniques
explain a *model* by perturbing inputs and observing output changes. This system
is not a model — it is a rule engine with declared weights. Running a surrogate
explainer over it would produce an approximation of a computation we can simply
show, and an approximation of deterministic arithmetic is strictly worse than the
arithmetic itself: it can be wrong, and when it disagrees with the score nobody
can say which one to trust.

`score_breakdown` is the exact decomposition. The "explanation" the UI renders is
that decomposition stated in English. See `p2_scoring/explanations.py`.

## Evidence gating

The single most important correctness property in P2.

```
{"active_trail_count": 0}   ->  P1 looked. There is no trail. Real finding.
{}                          ->  P1 said nothing. We do not know.
```

A naive `not context.get("active_trail_count")` treats both as "no trail" and
scores the second as a confirmed problem. During development that produced a
`CLOUDTRAIL_DISABLED` finding scoring **78/100 on an empty context** — a
confident critical finding manufactured entirely from data nobody supplied.

Every `Factor` therefore declares `requires`: the context keys that must be
present for it to be evaluable at all. `scoring._evidence_present()` drops any
factor whose keys are missing, and explicit `null` counts as missing — P1 sending
`{"encryption_enabled": null}` is "value unknown", not "encryption is off".

Consequences:

- A rule that fires with no usable evidence scores **0**, and `enrich.py` emits a
  warning naming the expected keys. The pipeline reports a contract gap instead of
  the dashboard showing a number nobody can defend.
- `ScoreResult.missing_evidence` lists exactly which keys were needed and absent,
  so an integration bug is diagnosable from the output alone.
- Partial evidence scores partially: the factors that *are* substantiated count,
  the rest are skipped. This is what lets P1 ship context incrementally without
  invalidating the whole score.

`tests/test_scoring.py::test_a_factor_requiring_evidence_never_fires_without_it`
pins this; `test_explicit_null_counts_as_absent` pins the null case.

### The one predicate that cannot be gated

Factors driven by the resource *name* (`sensitive_data_likely`) need no
`requires`, because the name is a required field on every raw finding. A rule
cannot fire without one. Those factors are marked `_(derived)_` in the generated
contract.

## Synergy factors

Two rules carry a factor that fires only when two lower-level factors co-occur:

| rule | factor | points | fires when |
|---|---|---|---|
| `RDS_PUBLICLY_ACCESSIBLE` | `public_exposure_without_encryption` | 8 | publicly accessible **and** unencrypted |
| `IAM_USER_NO_MFA` | `elevated_access_without_mfa` | 5 | console access without MFA **and** elevated permissions |

This exists because of a real defect found during seed reconciliation. Two of the
ten hand-authored Week-0 findings had a `score_breakdown` that summed to *less*
than their stated `risk_score`:

| finding | stated score | breakdown summed to | gap |
|---|---|---|---|
| publicly-accessible RDS, unencrypted | 90 | 82 | 8 |
| IAM user, console access, no MFA, elevated | 55 | 50 | 5 |

The gap was not random — it appeared exactly where two bad properties compounded.
The detection-rules document anticipates this: scoring "may weight the same rule
differently based on context (e.g. resource sensitivity, **exposure combination
with other findings**)".

There were three ways to close the gap, and the choice matters:

1. **Inflate a constituent factor** so the arithmetic lands on 90. Rejected: it
   would misstate what that factor is worth, and the same factor is shared with
   other findings where the total is already right.
2. **Add a hidden multiplier.** Rejected outright — it breaks the invariant that
   makes the system auditable at all.
3. **Name the compounding.** Chosen. Combined exposure is genuinely worth more
   than the sum of its parts, and saying so explicitly means the score card shows
   *why*, in a line a reviewer can read and either accept or challenge.

After this change all ten hand-authored findings reconcile exactly, and the
synergy is a first-class line item rather than a rounding artefact.
`tests/test_seed_reconciliation.py::EXPECTED_SYNERGY_UPLIFTS` asserts that these
two findings — and only these two — gain a synergy factor.

## The 100-point cap

Factor totals can exceed 100 (an S3 bucket that is public, writable, sensitive
*and* unencrypted totals 117). Rather than truncating silently, the engine
appends an explicit negative entry:

```json
{"factor": "score_cap_adjustment", "weight": -17,
 "description": "Raw factor total of 117 exceeds the 100-point scale and is capped"}
```

The sum still equals the score, so the card still reconciles. A reviewer sees the
score was clipped rather than wondering why the numbers do not add up.

## Risk bands

| band | score range |
|---|---|
| `critical` | 80–100 |
| `high` | 60–79 |
| `medium` | 40–59 |
| `low` | 0–39 |

Bands are computed from the score (`rules.risk_band()`) and never stored in the
finding document — the schema's `risk_score` is a bare number, and a band is a
presentation concern P3 layers on top. Keeping it out of the document means a
band threshold can be retuned without rewriting stored findings.

Note that `low` renders blue, not green. A misconfiguration is never *good*; it
is only less urgent.

## Derived signals

`signals.derive_signals()` merges the raw `context` with values P2 computes, so
the engine can use context P1 already sends rather than demanding a new API call
per nuance:

| signal | source |
|---|---|
| `name`, `name_lower` | `resource.name` |
| `sensitive_data_likely` | substring match against `SENSITIVE_NAME_HINTS` |
| `user_likely_inactive` | substring match against `INACTIVE_USER_HINTS` |
| `sensitive_ports_found`, `first_sensitive_port` | `open_ports` ∩ `SENSITIVE_PORTS` |
| `port_services` | port → service name, for readable prose |
| `days`, `user_count` | aliases for the rule's own threshold |

`DERIVED_KEYS` is a reserved namespace. A raw finding whose `context` collides
with one of those names raises `ValueError` rather than silently letting P1
override a derived value — the API surfaces that as a 422.

The `days` alias defaults to 90 rather than 0 for a readability reason: the
`IAM_UNUSED_ACCESS_KEY` template reads "key unused for {days} days", and 0 would
render "unused for 0 days" on a finding that is by definition about a key unused
for at least 90.

## Score after remediation

Each rule declares a `residual_score` — what the finding is estimated to fall to
once fixed — with a written rationale. There is no arithmetic that derives these
from the ten mock values, so they are declared per rule and labelled in the UI as
**an estimate for prioritisation, not a re-scan result**. It answers "is this
worth doing this week", which is the question a remediation queue exists to
answer, and it must not be presented as a measurement.

## Adding a rule

1. Add a `DetectionRule` to `RULES` in `p2_scoring/rules.py`.
2. Add an entry in `p2_scoring/compliance.py` and a template in
   `p2_scoring/explanations.py`.
3. Regenerate `docs/INTEGRATION_CONTRACT.md` and tell P1 which `context` keys the
   rule reads.

`tests/test_rule_table.py` fails if those registries disagree, so a rule cannot be
half-added. `scripts/generate_contract_doc.py --check` fails if the contract
document is stale.
