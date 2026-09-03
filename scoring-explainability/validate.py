import json
import sys
from pathlib import Path

from jsonschema import validate
from jsonschema.exceptions import ValidationError


ROOT = Path(__file__).resolve().parent.parent
SCHEMA_PATH = ROOT / "shared" / "finding_schema.json"
DEFAULT_FINDINGS_PATH = ROOT / "shared" / "mock_findings.json"


def main():
    findings_path = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_FINDINGS_PATH

    with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
        schema = json.load(f)

    with open(findings_path, "r", encoding="utf-8") as f:
        findings = json.load(f)

    if not isinstance(findings, list):
        findings = [findings]

    for index, finding in enumerate(findings, start=1):
        try:
            validate(instance=finding, schema=schema)
        except ValidationError as e:
            print(f"INVALID: finding #{index}")
            print(e.message)
            sys.exit(1)

    print(f"VALID: {len(findings)} findings")


if __name__ == "__main__":
    main()
