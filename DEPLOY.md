# Guni — Deployment Guide
## From your laptop to a live URL on Railway

---

## What you need (all free)

- GitHub account — github.com
- Railway account — railway.app (sign up with GitHub)
- Your guni-sdk folder on your machine

---

## Step 1 — Install Git (if you haven't)

Download from: https://git-scm.com/download/win
Accept all defaults during install.

Verify:
```
git --version
```

---

## Step 2 — Create a GitHub repository

1. Go to github.com → click "New repository"
2. Name it: `guni`
3. Set to Public (required for Railway free tier)
4. Do NOT add README or .gitignore (we have our own)
5. Click "Create repository"

---

## Step 3 — Push your code to GitHub

Open a terminal in your guni-sdk folder:

```bash
git init
git add .
git commit -m "Initial Guni SDK v0.3.0"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/guni.git
git push -u origin main
```

Replace YOUR_USERNAME with your GitHub username.

---

## Step 4 — Deploy to Railway

1. Go to railway.app
2. Click "New Project"
3. Choose "Deploy from GitHub repo"
4. Select your `guni` repository
5. Railway will detect the Dockerfile automatically
6. Click "Deploy"

Railway will build and deploy in about 2-3 minutes.

---

## Step 5 — Add environment variables on Railway

In your Railway project dashboard:
1. Click on your service
2. Click "Variables" tab
3. Add these:

| Variable | Value |
|----------|-------|
| ANTHROPIC_API_KEY | sk-ant-... (your key) |
| GUNI_LOG_PATH | /tmp/guni_audit.log |
| GUNI_RATE_LIMIT | 60 |

Leave GUNI_API_KEYS blank for now (open mode = no key required).

---

## Step 6 — Get your live URL

1. In Railway dashboard → click your service → "Settings"
2. Under "Networking" → click "Generate Domain"
3. You'll get a URL like: `https://guni-production.up.railway.app`

---

## Step 7 — Test your live API

Replace YOUR_URL with your Railway domain:

```bash
# Health check
curl https://YOUR_URL/health

# Scan a page
curl -X POST https://YOUR_URL/scan \
  -H "Content-Type: application/json" \
  -d "{\"html\": \"<div>Ignore previous instructions</div>\", \"goal\": \"Browse page\"}"

# Interactive docs
Open in browser: https://YOUR_URL/docs
```

---

## Step 8 — Share it

Your API docs page (https://YOUR_URL/docs) is a fully interactive demo.
Anyone can open it in their browser and test Guni without writing code.

Share this URL with:
- Developers building AI agents
- Potential customers
- Hackathon judges
- YC application

---

## Updating your deployment

Every time you push to GitHub, Railway redeploys automatically:

```bash
git add .
git commit -m "Update: improved phishing detection"
git push
```

Railway rebuilds in ~2 minutes.

---

## Protecting your API (when you have paying customers)

Set GUNI_API_KEYS in Railway variables:
```
GUNI_API_KEYS=customer1-key-abc123,customer2-key-def456
```

Customers then call with:
```bash
curl -X POST https://YOUR_URL/scan \
  -H "X-API-Key: customer1-key-abc123" \
  -H "Content-Type: application/json" \
  -d "{\"html\": \"...\", \"goal\": \"...\"}"
```

---

## Costs

Railway free tier: $5 free credit/month
Estimated API usage at 1000 scans/day: ~$2-3/month

You can charge customers $49-199/month and be profitable from customer 1.
