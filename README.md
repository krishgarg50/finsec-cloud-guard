\# FinSec Cloud Guard



FinSec Cloud Guard is a Cloud Security Posture Management (CSPM) prototype for detecting AWS security misconfigurations, scoring risks, mapping findings to compliance frameworks, and displaying results through a web dashboard.



\## Project Structure



\- `p3\_api/` - FastAPI backend and dashboard

\- `p2\_scoring/` - Risk scoring and compliance logic

\- `docs/` - API documentation

\- `tests/` - Automated tests



\## Features



\- AWS security finding ingestion

\- Risk scoring and severity classification

\- Rule-based explanations

\- Compliance mapping

\- Technical security dashboard

\- Compliance dashboard

\- Finding details and status management

\- Scan and findings API endpoints

\- Loading and error handling



\## Running the Backend



From the project root:



```powershell

python -m uvicorn p3\_api.app:app --reload

