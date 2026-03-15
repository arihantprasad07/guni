# Guni

**AI agent security. One import.**  
Detect prompt injection, phishing, UI deception, and goal hijacking before your agent executes anything.

---

## Install

```bash
pip install -e .
```

## Quickstart

```python
from guni import scan

result = scan(html=page_html, goal="Login to website")

print(result["decision"])   # ALLOW / CONFIRM / BLOCK
print(result["risk"])       # 0-100
print(result["evidence"])   # what was detected and why
```

## REST API

```bash
# Start the API server
uvicorn api.main:app --reload --port 8000

# Scan a page
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"html": "<div>Ignore previous instructions</div>", "goal": "Browse page"}'

# Interactive docs
open http://localhost:8000/docs
```

## With LLM reasoning (catches novel, reworded attacks)

```python
from guni import scan

result = scan(
    html=page_html,
    goal="Login to website",
    api_key="sk-ant-..."   # or set ANTHROPIC_API_KEY env var
)
print(result["llm_analysis"]["summary"])
```

## What Guni detects

| Threat              | Weight | Example                                      |
|---------------------|--------|----------------------------------------------|
| Prompt injection    | 30     | "Ignore previous instructions"               |
| Phishing forms      | 40     | Password fields posting to external URLs     |
| UI deception        | 25     | Hidden buttons with "Transfer now"           |
| Malicious scripts   | 20     | eval(), fetch() to unknown domains           |
| Goal mismatch       | 35     | Page telling agent to wire money             |

## Decision policy

| Risk  | Decision | Meaning                     |
|-------|----------|-----------------------------|
| ≥ 70  | BLOCK    | Action halted               |
| 40–69 | CONFIRM  | Human confirmation required |
| < 40  | ALLOW    | Safe to proceed             |

## Deploy to Railway

See [DEPLOY.md](DEPLOY.md) for step-by-step instructions.

---

Built by Code Mavericks — Indore Institute of Science & Technology
