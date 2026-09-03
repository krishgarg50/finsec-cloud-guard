# Tech Stack Decisions

Locked for the 8-week build. Change only with team agreement — mid-project stack changes cost more time than they save.

| Layer | Choice | Owner | Why |
|---|---|---|---|
| Detection engine | Python + boto3 | P1 | Native AWS SDK, fastest path to working scanner |
| Scoring/Explainability | Python | P2 | Same language as P1's output, simplifies integration; scikit-learn added Week 5+ only if ML layer proceeds |
| Backend API | FastAPI | P3 | Auto-generated docs, async support, fast to build |
| Database | SQLite (dev) | P3 | Zero setup, sufficient for prototype scale; note Postgres as the production path in docs, no need to actually set it up |
| Frontend | React (plain, no Next.js) | P3 | Simple, avoids over-engineering for the timeline |
| Charts | Recharts | P3 | Lightweight, fast to integrate with React |
| Package mgmt | requirements.txt / package.json | All | Standard, no extra tooling overhead |

## Environment setup (all team members)
```bash
git clone <repo-url>
cd <repo>
python3 -m venv venv
source venv/bin/activate    # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env        # then fill in your own values, never commit this
```
