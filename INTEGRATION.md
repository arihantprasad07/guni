# Guni Client Integration Guide

Guide for integrating Guni into browser agents, web automations, and agent-backed products.

## Core model

Before your agent acts on a page, scan the HTML and enforce the returned decision:

```text
ALLOW   -> proceed
CONFIRM -> warn, log, or require user approval
BLOCK   -> stop the action
```

## Install

```bash
git clone https://github.com/arihantprasad07/guni.git
cd guni
pip install -r requirements.txt
pip install -e .
```

## Option 1: Python SDK

```python
from guni import scan

result = scan(
    html=page_html,
    goal="Book a flight",
)

if result["decision"] == "BLOCK":
    raise RuntimeError(f"Threat detected: {result['evidence']}")

if result["decision"] == "CONFIRM":
    print(f"Warning: risk {result['risk']}/100")
```

Typical result fields:

```python
{
  "risk": 85,
  "decision": "BLOCK",
  "breakdown": {"injection": 30, "phishing": 40},
  "evidence": {"injection": ["Hidden instruction override"]},
  "heuristic_risk": 70,
  "heuristic_latency": 0.001,
  "total_latency": 0.004,
  "goal": "Book a flight",
  "url": "https://example.com",
  "llm_analysis": None,
}
```

Optional semantic reasoning:

```python
result = scan(
    html=page_html,
    goal="Login to website",
    llm=True,
    llm_api_key="your-provider-key",
    llm_provider="openai",
    llm_model="gpt-4.1-mini",
)
```

## Option 2: Playwright

```python
from playwright.sync_api import sync_playwright
from guni import GuniScanner

scanner = GuniScanner(goal="Book a train ticket")

def safe_goto(page, url: str) -> bool:
    page.goto(url)
    result = scanner.scan(html=page.content(), url=url)

    if result["decision"] == "BLOCK":
        print(f"[GUNI] BLOCKED {url} - Risk {result['risk']}/100")
        page.go_back()
        return False

    if result["decision"] == "CONFIRM":
        print(f"[GUNI] WARNING {url} - Risk {result['risk']}/100")

    return True

with sync_playwright() as p:
    browser = p.chromium.launch(headless=False)
    page = browser.new_page()

    if safe_goto(page, "https://example.com"):
        page.click("button")
```

## Option 3: browser-use

Use the maintained example in [examples/browser_use_integration.py](./examples/browser_use_integration.py).

Minimal pre-scan flow:

```python
from examples.browser_use_integration import pre_scan_url

safe = await pre_scan_url("https://target.com", goal="Login")
if safe:
    await page.goto("https://target.com")
```

## Option 4: LangChain

```python
from examples.langchain_integration import SecureBrowserTool

tool = SecureBrowserTool(goal="Find product prices", api_key="guni_live_...")
```

## Option 5: Hosted or self-hosted REST API

Run locally:

```bash
uvicorn api.main:app --reload --port 8000
```

Protected mode request:

```bash
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -H "X-API-Key: guni_live_..." \
  -d "{\"html\":\"<html>...</html>\",\"goal\":\"Login\"}"
```

Open demo mode is available only when `GUNI_ALLOW_OPEN_MODE=true` is explicitly enabled.

Python client:

```python
import requests

def scan_page(html: str, goal: str, api_key: str) -> dict:
    response = requests.post(
        "https://guni.up.railway.app/scan",
        json={"html": html, "goal": goal},
        headers={"X-API-Key": api_key},
        timeout=10,
    )
    payload = response.json()
    return payload["data"]

result = scan_page(page_html, "Login to website", "guni_live_...")
if result["decision"] == "BLOCK":
    raise RuntimeError("Threat detected")
```

JavaScript client:

```javascript
async function scanPage(html, goal, apiKey) {
  const res = await fetch("https://guni.up.railway.app/scan", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-API-Key": apiKey,
    },
    body: JSON.stringify({ html, goal }),
  });

  const payload = await res.json();
  return payload.data;
}

const result = await scanPage(pageHTML, "Book a flight", "guni_live_...");
if (result.decision === "BLOCK") {
  throw new Error("Threat detected");
}
```

## Option 6: WebSocket real-time

The WebSocket endpoint requires authentication.

```python
import asyncio
import json
import websockets

async def secure_agent():
    uri = "wss://guni.up.railway.app/ws/scan?api_key=guni_live_...&goal=Book+a+flight"

    async with websockets.connect(uri) as ws:
        async def check_page(html: str, url: str) -> dict:
            await ws.send(json.dumps({"html": html, "url": url}))
            message = json.loads(await ws.recv())

            while message.get("type") in {"connected", "scanning"}:
                message = json.loads(await ws.recv())

            return message

        result = await check_page(page_html, current_url)
        if result.get("decision") == "BLOCK":
            print(f"BLOCKED: {current_url}")

asyncio.run(secure_agent())
```

## Hosted product flow

For the hosted product:

1. Create an account in the app.
2. Verify your email if prompted.
3. Sign in to the portal.
4. Generate or retrieve your API key from the product.
5. Use that key with the hosted API or WebSocket endpoints.

For self-hosting, you can run the API directly and manage keys yourself.
