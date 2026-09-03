# AWS Test Account Setup

## 1. Account
- Use a dedicated AWS account for this project — NOT anyone's personal or work account.
- Free Tier is sufficient for the entire project scope.

## 0. Root vs IAM login — read this first
- **Root user is used exactly once**, right after account creation, to set up IAM users. Enable MFA on root, then do not log in as root again unless changing billing/account-level settings.
- **Every day-to-day login goes through an IAM user** — never root. This applies to console logins AND to any credentials used in code (`.env`, `aws configure`).
- Create one IAM user per teammate for console access (`p1-dev`, `p2-dev`, `p3-dev`), each with `SecurityAudit` + `ViewOnlyAccess`, console password, and MFA enabled.
- Create a separate IAM user for the scanner itself (`csmp-scanner-readonly`, CLI access keys only, no console password needed) — see below.
- Login URL for IAM users: `https://<account-id-or-alias>.signin.aws.amazon.com/console` (find this on the IAM dashboard after setup).

## 2. IAM user for scanning (read-only)
- Create IAM user: `csmp-scanner-readonly`
- Attach managed policy: `SecurityAudit` (covers S3, IAM, EC2, RDS, CloudTrail read access — purpose-built for security scanning tools)
- Generate CLI access keys for this user (Security credentials → Create access key → CLI use case)
- Download the CSV immediately — the secret key is only shown once

## 3. Local setup (each team member running the scanner)
```bash
pip install awscli boto3
aws configure
# AWS Access Key ID: <from CSV>
# AWS Secret Access Key: <from CSV>
# Default region: us-east-1
# Default output format: json
```

## 4. Credential safety rules (all team members)
- NEVER commit access keys to the repo, in any file, any commit, any branch.
- Use `.env` for local secrets (see `.env.example` in repo root) — `.env` is gitignored.
- If a key is ever accidentally committed: rotate it immediately in IAM (deactivate old key, create new one), then scrub git history if needed.

## 5. Demo/write-access user (Week 5-6 only, P1)
- Separate IAM user: `csmp-demo-resources`
- Scoped write access limited to S3, EC2 (Security Groups), IAM (for creating deliberately misconfigured demo resources)
- Do NOT use this user for the scanning/detection engine — keep scan and write credentials separate at all times.

## 6. Resource cleanup
- Tag every resource created for testing/demo with `Project: CSPM-Demo` so it's easy to find and delete everything before the account is closed or at project end (avoid surprise billing).
