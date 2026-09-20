# Detection Engine (Person 1)

This module connects to AWS, retrieves configuration data, and evaluates it against 12 security rules. Outputs are formatted to match `shared/finding_schema.json`.

## How to Run
1. Ensure AWS credentials are set in the `.env` file (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_DEFAULT_REGION`).
2. Run the scanner: `python run_scan.py`
3. Results are saved to `scan_output.json`.

## Implemented Rules
1. **S3_PUBLIC_ACCESS**: Checks if S3 buckets lack public access blocks.
2. **S3_NO_ENCRYPTION**: Checks if S3 buckets lack default server-side encryption.
3. **S3_NO_VERSIONING**: Checks if S3 versioning is not explicitly enabled.
4. **IAM_WILDCARD_POLICY**: Flags IAM policies using `*` (wildcard) for actions or resources.
5. **IAM_ROOT_NO_MFA**: Checks if the root AWS account lacks MFA.
6. **IAM_USER_NO_MFA**: Checks if IAM users lack active MFA devices.
7. **IAM_UNUSED_ACCESS_KEY**: Flags access keys unused for > 90 days.
8. **SG_OPEN_TO_WORLD**: Flags Security Groups with ingress open to `0.0.0.0/0` or `::/0`.
9. **EBS_NOT_ENCRYPTED**: Checks for unencrypted Elastic Block Store volumes.
10. **RDS_NOT_ENCRYPTED**: Checks for unencrypted RDS instances.
11. **RDS_PUBLICLY_ACCESSIBLE**: Flags RDS instances that are publicly accessible.
12. **CLOUDTRAIL_DISABLED**: Checks if AWS CloudTrail logging is missing or disabled.

## Edge Case Handling
* **Rate Limiting**: Boto3 client calls are wrapped in a custom `@retry_with_backoff` decorator to handle API throttling.
* **Empty Resources**: Environments returning zero resources naturally bypass loops and return empty lists without crashing.
* **Missing Configurations**: Managed via `try/except` blocks (e.g., S3 buckets without explicit public access blocks pass without causing a crash).