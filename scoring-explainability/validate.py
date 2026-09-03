import json
import sys
from pathlib import Path

try:
    import jsonschema
    from jsonschema import Draft7Validator
except ImportError:
    print(
        "ERROR: the 'jsonschema' package is not installed.\n"
        "Run: pip install jsonschema --break-system-packages\n"
        "(and confirm it's listed in shared/requirements.txt for the team)."
    )
    sys.exit(1)

REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_PATH = REPO_ROOT / "shared" / "finding_schema.json"


def validate_findings(findings: list[dict], schema: dict) -> tuple[int, int]:
    validator = Draft7Validator(schema)
    ok_count = 0
    fail_count = 0

    for finding in findings:
        errors = sorted(
            validator.iter_errors(finding),
            key=lambda e: e.path
        )

        finding_id = finding.get("finding_id", "<missing finding_id>")

        if not errors:
            ok_count += 1
            continue

        fail_count += 1

        print(f"\nFAIL  {finding_id}  (rule_id={finding.get('rule_id')})")

        for err in errors:
            location = "/".join(str(p) for p in err.path) or "<root>"
            print(f"   - {location}: {err.message}")

    return ok_count, fail_count


def main():
    target = (
        Path(sys.argv[1])
        if len(sys.argv) > 1
        else REPO_ROOT / "shared" / "mock_findings.json"
    )

    schema = json.loads(SCHEMA_PATH.read_text())
    findings = json.loads(target.read_text())

    if isinstance(findings, dict):
        findings = [findings]

    ok, fail = validate_findings(findings, schema)
    total = ok + fail

    print(f"\n{ok}/{total} findings valid against {SCHEMA_PATH.name}")

    if fail:
        sys.exit(1)


if __name__ == "__main__":
    main()
