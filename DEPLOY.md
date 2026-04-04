# Deployment Guide

This guide is for taking Guni from local development to a production-style Railway deployment with healthier defaults for customer use.

## Current deployment shape

Guni is a FastAPI application served through Gunicorn/Uvicorn.

Important runtime behavior:

- the API serves static dashboard pages from `dashboard/`
- runtime state should live in a writable data directory
- the app exposes `/health` for healthchecks
- every GitHub push can redeploy Railway automatically

## Recommended production environment variables

Set these in Railway:

| Variable | Recommended value |
|---|---|
| `PORT` | Railway-provided |
| `GUNI_DATA_DIR` | `/data/guni` or Railway volume path for logs/non-DB state |
| `GUNI_MONGO_URI` | MongoDB connection string |
| `GUNI_MONGO_DB_NAME` | `guni` or your preferred database name |
| `GUNI_RATE_LIMIT` | `60` or your preferred limit |
| `GUNI_APP_BASE_URL` | Public base URL such as `https://guni.example.com` |
| `GUNI_CORS_ORIGINS` | Comma-separated allowed browser origins for cross-origin API calls |
| `GUNI_TRUSTED_HOSTS` | Comma-separated hostnames the app should serve |
| `GUNI_API_KEYS` | Comma-separated production keys if using protected mode |
| `GUNI_SESSION_SECRET` | Long random secret |
| `GUNI_LLM_API_KEY` | Optional default API key for hosted LLM reasoning |
| `GUNI_LLM_PROVIDER` | Optional default provider: `anthropic`, `openai`, `gemini`, or `openai_compatible` |
| `GUNI_LLM_MODEL` | Optional default model name |
| `GUNI_LLM_BASE_URL` | Optional default base URL for OpenAI-compatible providers |
| `ANTHROPIC_API_KEY` | Legacy fallback for Anthropic |
| `RAZORPAY_KEY_ID` | Required for hosted checkout creation |
| `RAZORPAY_KEY_SECRET` | Required for hosted checkout creation |
| `RAZORPAY_WEBHOOK_SECRET` | Required for webhook verification |
| `BREVO_API_KEY` | Required for transactional email delivery |
| `GUNI_EMAIL_FROM` | Verified sender for transactional emails |

Optional overrides:

- `GUNI_DB_PATH`
- `GUNI_LOG_PATH`
- `GUNI_KEYS_PATH`
- `GUNI_WAITLIST_PATH`
- `GUNI_EVENT_LOG_PATH`

## Railway checklist

1. Push the repo to GitHub.
2. Create a Railway project from the repo.
3. Keep the included `Dockerfile` and `railway.toml`.
4. Provision MongoDB and set `GUNI_MONGO_URI`.
5. Mount persistent storage if you want durable logs or waitlist files.
6. Set the environment variables above.
7. Verify `/health`, `/dashboard`, and `/enterprise` after deploy.

## Verify the deploy

```bash
curl https://YOUR_URL/health
curl https://YOUR_URL/waitlist/count
```

For Docker Compose users, the included healthcheck now uses Python's standard library instead of `curl`, so it works with the shipped slim image without extra packages.

Scan smoke test:

```bash
curl -X POST https://YOUR_URL/scan \
  -H "X-API-Key: guni_live_..." \
  -H "Content-Type: application/json" \
  -d "{\"html\":\"<html><body><h1>hello</h1></body></html>\",\"goal\":\"Read page\"}"
```

If you intentionally want unauthenticated demo scans, you must explicitly set `GUNI_ALLOW_OPEN_MODE=true`. Do not enable that in production.

## Recommended customer-facing setup

For pilots:

- use the hosted API
- keep open mode only for demos
- share the dashboard and enterprise page during sales

For production customers:

- require `X-API-Key`
- use a durable MongoDB deployment for application data
- store runtime logs on a persistent volume if you want filesystem durability
- rotate keys deliberately
- set a strong `GUNI_SESSION_SECRET`
- set `RAZORPAY_KEY_ID`, `RAZORPAY_KEY_SECRET`, and `RAZORPAY_WEBHOOK_SECRET` if you want in-product checkout
- decide whether the customer uses managed API or self-hosted mode

## CI recommendation

GitHub Actions CI is included in `.github/workflows/ci.yml`.

Before treating a branch as deployable, make sure:

- CI passes
- `pytest -q test_api.py` passes locally
- `/health` returns `ok` after deploy
