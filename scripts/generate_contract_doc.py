#!/usr/bin/env python
"""Generate ``docs/INTEGRATION_CONTRACT.md`` from the code.

The contract between P1, P2 and P3 is defined by ``p2_scoring/rules.py``: which
``context`` keys each rule reads, and what each is worth. Hand-maintaining a
document that restates that table guarantees it drifts, and a drifted contract
is worse than none -- P1 would populate keys nobody reads while the keys that
actually drive scores stay empty.

So the document is generated. Run::

    python scripts/generate_contract_doc.py            # write the file
    python scripts/generate_contract_doc.py --check     # fail if it is stale

``--check`` is what CI should run, so a rule change that forgets to regenerate
the doc breaks the build instead of a downstream team's week.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from p2_scoring.compliance import (  # noqa: E402
    FRAMEWORK_ORDER,
    PROPOSED_MAPPINGS,
    RULE_COMPLIANCE,
)
from p2_scoring.enrich import OUTPUT_FIELD_ORDER  # noqa: E402
from p2_scoring.rules import RULES, SEVERITY_BANDS, UNSCORED_CONTEXT_KEYS  # noqa: E402
from p2_scoring.signals import CONTEXT_KEYS_CONSUMED  # noqa: E402

OUTPUT_PATH = ROOT / "docs" / "INTEGRATION_CONTRACT.md"

#: Raw-finding fields P1 must supply, and whether P2 can proceed without them.
RAW_FIELDS: tuple[tuple[str, str, str], ...] = (
    ("finding_id", "required", "Stable id for this finding. Must be stable across scans -- it is the primary key P3 upserts on, so a changing id re-alerts a finding every scan."),
    ("rule_id", "required", "One of the rule ids in the table below. An unknown id is rejected, not ignored (see 'Failure policy')."),
    ("scan_id", "required", "Identifier of the scan run that produced this finding."),
    ("resource", "required", "``{type, id, name, region}``. ``name`` is used by P2 to derive sensitivity, so a name like ``customer-statements-backup`` scores higher than ``test-bucket`` on the same rule."),
    ("detection_source", "required", "``rule_engine`` or ``anomaly_detection``."),
    ("severity_raw", "required", "P1's own severity. Kept for display; it does **not** feed the risk score."),
    ("context", "required", "The observed facts. This is the whole reason the pipeline can explain itself -- see per-rule keys below."),
    ("detected_at", "required", "ISO-8601 UTC, when the misconfiguration was first observed in the environment."),
    ("last_seen_at", "required", "ISO-8601 UTC, most recent observation."),
    ("status", "optional", "Defaults to ``open``. P3 owns the lifecycle after that."),
)

#: Guards against the doc quietly describing a rule that is half-defined.
def _assert_contract_is_complete() -> None:
    missing = [r.rule_id for r in RULES if r.rule_id not in RULE_COMPLIANCE]
    if missing:
        raise SystemExit(f"rules with no compliance mapping: {missing}")
    for rule in RULES:
        declared = set(rule.context_keys)
        for factor in rule.factors:
            undeclared = set(factor.requires) - declared
            if undeclared:
                raise SystemExit(
                    f"{rule.rule_id}: factor {factor.key!r} requires {sorted(undeclared)}, "
                    f"which context_keys does not declare. context_keys is what this "
                    f"document tells P1 to send."
                )
        # Mirrors test_rule_table.py, because the failure mode is a *document*
        # that asks P1 for facts nothing reads -- which only this script emits.
        dead = declared - UNSCORED_CONTEXT_KEYS
        for factor in rule.factors:
            dead -= set(factor.requires)
        dead -= CONTEXT_KEYS_CONSUMED
        if dead:
            raise SystemExit(
                f"{rule.rule_id}: context_keys declares {sorted(dead)}, which no factor "
                f"requires and derive_signals does not consume. Scoring a key that is "
                f"unread would have this document instruct P1 to send it for nothing; "
                f"either score it, drop it, or list it in UNSCORED_CONTEXT_KEYS."
            )


def _render() -> str:
    lines: list[str] = []
    add = lines.append

    add("# Integration contract")
    add("")
    add("> **Generated file -- do not edit by hand.**")
    add("> Regenerate with `python scripts/generate_contract_doc.py`;")
    add("> `--check` fails the build when it is stale.")
    add("")
    add("This is the agreement between the three workstreams. It is derived from")
    add("`p2_scoring/rules.py`, `p2_scoring/compliance.py` and")
    add("`p2_scoring/enrich.py`, so it cannot describe a system that does not exist.")
    add("")

    add("## The pipeline")
    add("")
    add("```")
    add("  P1  AWS connector")
    add("      |  raw finding JSON        (schema/raw_finding_schema.json)")
    add("      v")
    add("  P2  enrich_findings()")
    add("      |  + risk_score, score_breakdown, explanation, compliance_mappings")
    add("      v")
    add("  P3  POST /scan  ->  SQLite  ->  dashboard")
    add("```")
    add("")
    add("P2 is a pure function over P1's output: no network, no database, no AWS")
    add("credentials. That is why both sides can be built and tested in parallel")
    add("against `data/mock_findings.raw.json` before either is finished.")
    add("")

    # ------------------------------------------------------------------ raw
    add("## What P1 must emit (raw finding)")
    add("")
    add("| field | | meaning |")
    add("|---|---|---|")
    for name, requirement, meaning in RAW_FIELDS:
        add(f"| `{name}` | {requirement} | {meaning} |")
    add("")
    add("Authoritative schema: `schema/raw_finding_schema.json`.")
    add("")
    add("P1 does not compute a score, a band, an explanation or a compliance")
    add("mapping. Those are P2's, and duplicating them is how two teams end up")
    add("disagreeing about the same number.")
    add("")

    # --------------------------------------------------------------- rules
    add("## Per-rule context the scorer reads")
    add("")
    add("A factor only counts when the keys in its **requires** column are present")
    add("and non-null. A missing key means *unknown*, never *safe* and never *bad*:")
    add("the factor is skipped, and the finding scores lower with the gap reported.")
    add("That is deliberate -- scoring `{}` as if it said `active_trail_count: 0`")
    add("manufactures a critical finding out of data nobody sent.")
    add("")
    add("`(derived)` marks a factor driven by the resource name, which is always")
    add("present, so it needs no context key.")
    add("")

    for rule in RULES:
        frameworks = sorted(
            {ref.framework for ref in RULE_COMPLIANCE[rule.rule_id]},
            key=FRAMEWORK_ORDER.index,
        )
        add(f"### `{rule.rule_id}` -- {rule.title}")
        add("")
        add(f"- **Resource types:** {', '.join(f'`{t}`' for t in rule.resource_types)}")
        add(f"- **P1's severity:** `{rule.base_severity}`")
        add(f"- **Maximum score:** {rule.max_score} (capped at 100 overall)")
        add(f"- **Score after remediation:** {rule.residual_score} -- {rule.residual_rationale}")
        add(f"- **Frameworks:** {', '.join(frameworks)}")
        add("")
        add("**Context keys for this rule**")
        add("")
        for key in rule.context_keys:
            if key in UNSCORED_CONTEXT_KEYS:
                add(f"- `{key}` -- **not scored.** No factor reads this today; sending")
                add("  it will not change the risk score. Listed so the gap is visible.")
                continue
            readers = [f.key for f in rule.factors if key in f.requires]
            if readers:
                add(f"- `{key}` -- scores {', '.join(f'`{r}`' for r in readers)}")
            else:
                # consumed by derive_signals rather than named by a factor
                add(f"- `{key}` -- consumed by `derive_signals`")
        add("")
        add("**Scoring factors**")
        add("")
        add("| factor | points | fires when | requires |")
        add("|---|---|---|---|")
        for factor in rule.factors:
            requires = ", ".join(f"`{k}`" for k in factor.requires) or "_(derived)_"
            # a template containing a pipe would silently break the table
            fires_when = factor.template.replace("|", "\\|")
            add(f"| `{factor.key}` | {factor.points} | {fires_when} | {requires} |")
        add("")

    # -------------------------------------------------------------- output
    add("## What P2 emits (enriched finding)")
    add("")
    add("Fields, in the order `enrich.py` writes them:")
    add("")
    for name in OUTPUT_FIELD_ORDER:
        add(f"- `{name}`")
    add("")
    add("Authoritative schema: `schema/finding_schema.json`.")
    add("")
    add("Note `context` is carried through to the output. It is an **additive**")
    add("extension permitted by the schema, and it is what lets the dashboard show")
    add("`observed facts -> factors -> score` as one traceable chain.")
    add("")
    add("### The arithmetic guarantee")
    add("")
    add("```")
    add("risk_score == min(100, sum(f.weight for f in score_breakdown))")
    add("```")
    add("")
    add("`score_breakdown` is not a summary of the score; it *is* the score. When")
    add("the raw factor total would exceed 100, a single negative")
    add("`score_cap_adjustment` entry is appended so the sum still reconciles.")
    add("`tests/test_scoring.py` asserts this for every rule, and")
    add("`tests/test_seed_reconciliation.py` asserts it against the hand-authored")
    add("seed findings.")
    add("")
    add("### Risk bands")
    add("")
    add("Bands are computed from the score, never stored in the finding document:")
    add("")
    add("| band | score |")
    add("|---|---|")
    upper = 100
    for threshold, band in SEVERITY_BANDS:
        add(f"| `{band}` | {threshold}-{upper} |")
        upper = threshold - 1
    add("")

    # ---------------------------------------------------------------- p3
    add("## What P3 adds")
    add("")
    add("P3 stores the enriched document verbatim alongside denormalised columns")
    add("for filtering and aggregation, and owns the fields P2 does not:")
    add("")
    add("- `status` -- `open`, `acknowledged`, `remediated`, `false_positive`")
    add("- `reopen_count` -- incremented when a `remediated` finding reappears")
    add("- `first_seen_at` -- when this system first stored the finding")
    add("")
    add("`remediated` is **not permanent**: if a later scan sees the same")
    add("`finding_id` again, the finding reopens and `reopen_count` increments. A")
    add("fix that did not stick has to surface, not quietly disappear.")
    add("`acknowledged` and `false_positive` are never overridden by a scan. In both")
    add("cases a human already made the call, and a scanner that re-flags the same")
    add("misconfiguration every night would make them re-decide it every night --")
    add("which is the workflow the human statuses exist to prevent.")
    add("")

    # ------------------------------------------------------------ open items
    add("## Open items needing a human decision")
    add("")
    add("### Compliance mappings awaiting sign-off")
    add("")
    if PROPOSED_MAPPINGS:
        add("These rules had no precedent in the Week-0 mock findings. Their")
        add("mappings are proposed, not agreed, and a compliance mapping is a claim")
        add("about a regulation rather than a code comment:")
        add("")
        for rule_id in sorted(PROPOSED_MAPPINGS):
            clauses = ", ".join(
                f"{ref.framework} {ref.clause}" for ref in RULE_COMPLIANCE[rule_id]
            )
            add(f"- `{rule_id}` -> {clauses}")
    else:  # pragma: no cover - only once every mapping is signed off
        add("None -- every mapping has a precedent in the agreed mock findings.")
    add("")
    add("### Contract questions for P1")
    add("")
    add("1. **Context completeness.** Can the connector populate every key in the")
    add("   per-rule tables above? Anything it cannot should be named now, so the")
    add("   affected factors can be redesigned rather than scoring 0 in silence.")
    add("2. **`resource.type: \"account\"`.** Account-level rules such as")
    add("   `CLOUDTRAIL_DISABLED` have no resource ARN. The agreed vocabulary did")
    add("   not list `account`, so it was added to the schema description -- confirm")
    add("   that is the value the connector will send.")
    add("3. **`finding_id` stability.** It is P3's primary key. If the connector")
    add("   derives it from anything that changes between scans (a timestamp, a")
    add("   run counter), every scan will look like a fresh set of findings and the")
    add("   dashboard's trend line will be meaningless.")
    add("4. **Two spellings of storage encryption.** Confirmed with the connector:")
    add("")
    add("   | rule | key it reads |")
    add("   |---|---|")
    for rule_id, key in _encryption_key_usage():
        add(f"   | `{rule_id}` | `{key}` |")
    add("")
    add("   Both spellings came from the agreed mock findings, so both are")
    add("   faithfully implemented -- but they are one concept, and a connector that")
    add("   sends `storage_encrypted` on an S3 bucket will have that factor scored")
    add("   as *missing evidence* rather than as encryption status. Pick one spelling")
    add("   per concept (or send both) before integration.")
    add("")
    add("5. **Context keys that are collected but not scored.** These are declared by")
    add("   a rule and sent by the connector, but no scoring factor reads them, so")
    add("   populating them changes no risk score:")
    add("")
    add("   | rule | key |")
    add("   |---|---|")
    for rule_id, key in _unscored_key_usage():
        add(f"   | `{rule_id}` | `{key}` |")
    add("")
    add("   Nothing is broken -- the scores are correct, they simply ignore these")
    add("   fields. The question for the review is whether each *should* score, and")
    add("   the answer is not obvious from the code:")
    add("")
    add("   - `block_public_access` (S3) is the account-level control that would")
    add("     have prevented the public ACL the rule already scores 40 + 25 for.")
    add("     Scoring it would charge twice for one exposure, so leaving it out may")
    add("     be right -- but then it does not need to be in the contract.")
    add("   - `attached_role_count` (IAM) is unscored while `attached_user_count` is")
    add("     worth 18. Broad attachment is the risk either way, so the asymmetry")
    add("     looks like an omission rather than a decision.")
    add("   - `snapshot_count` (EBS) and `multi_region_trail` (CloudTrail) have no")
    add("     factor at all.")
    add("")
    add("   Either add a factor or drop the key from `context_keys`. Until one of")
    add("   those happens the key sits in `UNSCORED_CONTEXT_KEYS`, which")
    add("   `tests/test_rule_table.py` keeps honest in both directions.")
    add("")
    return "\n".join(lines) + "\n"


#: Keys different rules use to mean "is storage encrypted".
ENCRYPTION_KEY_ALIASES: tuple[str, ...] = ("encryption_enabled", "storage_encrypted")


def _encryption_key_usage() -> list[tuple[str, str]]:
    """Rules that read an encryption flag, and which spelling each one reads."""
    usage: list[tuple[str, str]] = []
    for rule in RULES:
        for key in ENCRYPTION_KEY_ALIASES:
            if key in rule.context_keys:
                usage.append((rule.rule_id, key))
    return usage


def _unscored_key_usage() -> list[tuple[str, str]]:
    """Rules declaring a context key that no factor scores, and the key."""
    return [
        (rule.rule_id, key)
        for rule in RULES
        for key in rule.context_keys
        if key in UNSCORED_CONTEXT_KEYS
    ]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="exit non-zero if the file on disk differs from the generated text",
    )
    parser.add_argument("--out", default=str(OUTPUT_PATH), help="output path")
    args = parser.parse_args(argv)

    _assert_contract_is_complete()
    rendered = _render()
    target = Path(args.out)

    if args.check:
        if not target.exists():
            print(f"error: {target} does not exist; run without --check", file=sys.stderr)
            return 1
        if target.read_text(encoding="utf-8") != rendered:
            print(
                f"error: {target} is stale. "
                f"Regenerate with `python scripts/generate_contract_doc.py`.",
                file=sys.stderr,
            )
            return 1
        print(f"{target} is up to date")
        return 0

    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(rendered, encoding="utf-8")
    print(f"wrote {target} ({len(rendered.splitlines())} lines)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
