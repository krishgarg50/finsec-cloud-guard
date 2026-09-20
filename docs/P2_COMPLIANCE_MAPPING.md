# P2 — compliance mapping

The bridge from "a technical thing is wrong" to "here is the regulation that says
so". For a regulated buyer that link is the product: a finding that cannot be
traced to an obligation is just an alert, and a queue of alerts is what they
already ignore.

## Frameworks

| framework | what it is | why it is in scope |
|---|---|---|
| **PCI-DSS** | Payment Card Industry Data Security Standard | Cardholder data in AWS is the assumed context for a financial institution. Clause-numbered, so the mapping is precise. |
| **SOC 2 (TSC)** | AICPA Trust Services Criteria | The assurance report a fintech's enterprise customers ask for. Mapped at criterion level (`CC6.1`). |
| **GLBA** | Gramm-Leach-Bliley Act, Safeguards Rule | The US financial-privacy regime. Not clause-numbered — see the wart below. |
| **ISO 27001** | Information security management | Listed in the canonical framework order for future mappings. **No rule currently maps to it.** |

Canonical order is `FRAMEWORK_ORDER` in `p2_scoring/compliance.py`
(PCI-DSS, SOC2, GLBA, ISO27001). Clauses are sorted into that order before they
are written to a finding, so the dashboard shows the same framework first
everywhere instead of whichever one a rule author happened to type first.

## The mapping table

`RULE_COMPLIANCE` is the source of truth; this table is a transcription of it.
`tests/test_compliance.py` asserts the ten rules with mock precedent reproduce
the hand-authored mappings exactly.

| rule | clauses |
|---|---|
| `S3_PUBLIC_ACCESS` | PCI-DSS 1.3.4, SOC2 CC6.1 |
| `S3_NO_ENCRYPTION` | PCI-DSS 3.4, SOC2 CC6.1, GLBA *(proposed)* |
| `S3_NO_VERSIONING` | SOC2 A1.2 |
| `IAM_WILDCARD_POLICY` | PCI-DSS 7.1.2, SOC2 CC6.3 |
| `IAM_ROOT_NO_MFA` | PCI-DSS 8.3.1, SOC2 CC6.1 |
| `IAM_USER_NO_MFA` | PCI-DSS 8.3.1 |
| `IAM_UNUSED_ACCESS_KEY` | SOC2 CC6.2 |
| `SG_OPEN_TO_WORLD` | PCI-DSS 1.2.1, SOC2 CC6.6 |
| `EBS_NOT_ENCRYPTED` | PCI-DSS 3.4, GLBA *(proposed)* |
| `RDS_NOT_ENCRYPTED` | PCI-DSS 3.4, GLBA Safeguards Rule — encrypt at rest |
| `RDS_PUBLICLY_ACCESSIBLE` | PCI-DSS 1.3.4, GLBA Safeguards Rule — restrict access |
| `CLOUDTRAIL_DISABLED` | PCI-DSS 10.1, SOC2 CC7.2 |

## Clause reference

| clause | requirement |
|---|---|
| PCI-DSS 1.2.1 | Restrict inbound and outbound traffic to that which is necessary |
| PCI-DSS 1.3.4 | Prohibit direct public access between the internet and any system component in the cardholder data environment |
| PCI-DSS 3.4 | Render cardholder data unreadable anywhere it is stored |
| PCI-DSS 7.1.2 | Restrict access to privileged user IDs to least privileges necessary |
| PCI-DSS 8.3.1 | Incorporate multi-factor authentication for all access into the cardholder data environment |
| PCI-DSS 10.1 | Implement audit trails to link access to system components to each individual user |
| SOC2 CC6.1 | Logical access controls restrict access to authorized users |
| SOC2 CC6.2 | User access is removed in a timely manner when no longer required |
| SOC2 CC6.3 | Access is granted based on least privilege principle |
| SOC2 CC6.6 | System boundaries are protected from unauthorized network access |
| SOC2 CC7.2 | System activity is monitored to detect anomalies |
| SOC2 A1.2 | System components are recoverable in the event of data loss |
| GLBA Safeguards Rule | Encrypt customer information at rest |
| GLBA Safeguards Rule | Restrict access to customer information systems |

## Mappings awaiting sign-off

`PROPOSED_MAPPINGS` marks the rules whose mappings had **no precedent** in the
Week-0 mock findings:

- `S3_NO_ENCRYPTION` → PCI-DSS 3.4, SOC2 CC6.1, GLBA
- `EBS_NOT_ENCRYPTED` → PCI-DSS 3.4, GLBA

The other ten rules reproduce mappings a human already wrote. These two were
inferred by analogy with `RDS_NOT_ENCRYPTED` (same clause, same control
objective, different storage service), which is a reasonable inference but not an
agreement.

**A compliance mapping is a claim about a regulation, not a code comment.** It
should be reviewed by whoever owns the framework relationship before it goes in
front of an auditor. The set exists so that review is a one-line change rather
than an archaeology exercise, and so nobody mistakes an inference for a decision.

## Known wart: GLBA is described two ways

The hand-authored mocks describe the GLBA Safeguards Rule inconsistently:

- `RDS_NOT_ENCRYPTED` says *"Encrypt customer information at rest"*
- `RDS_PUBLICLY_ACCESSIBLE` says *"Restrict access to customer information systems"*

Both are faithfully preserved. GLBA's Safeguards Rule is not clause-numbered the
way PCI is, so the description carries the entire meaning of the mapping — which
makes an inconsistent description a real defect rather than a cosmetic one. Two
findings citing "GLBA Safeguards Rule" will render as two different obligations,
and a reader cannot tell whether that reflects two distinct requirements or two
phrasings of one.

This is deliberately **not** silently normalised: the mock findings are the
agreed specification, and quietly rewriting them would hide a disagreement rather
than surface it. Normalising to a single canonical phrasing per requirement is a
small change to make once someone with the framework knowledge confirms which
reading is right.

## What a mapping does and does not claim

A mapping says: *this misconfiguration is evidence that the control this clause
requires is not being met.*

It does not claim:

- that the organisation is non-compliant — one finding is not an audit result,
  and a control can be met by compensating measures elsewhere;
- that this is the only clause involved — the table lists the clauses a rule
  clearly bears on, not every clause an auditor might raise;
- anything about scope — whether the resource is actually in the cardholder data
  environment is a question the mapping does not answer, and `RDS_NOT_ENCRYPTED`
  and `S3_NO_ENCRYPTION` cite PCI clauses regardless.

The dashboard's compliance view counts findings per framework and per clause.
Those counts are an **exposure indicator** — where to look first — not a
compliance status. The UI labels them that way and does not render a pass/fail.
