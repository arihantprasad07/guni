# Guni — Client Integration Guide

Complete guide for integrating Guni into your AI browser agent.

---

## How it works in 30 seconds

Your agent visits pages. Before it acts on any page, Guni scans the HTML
and returns one of three decisions:

```
ALLOW   → safe, agent proceeds normally
CONFIRM → suspicious, proceed with caution or ask user
BLOCK   → threat detected, stop agent, don't execute
```

That's it. You add 3 lines of code around your existing agent logic.

---

## Installation

```bash
pip install -e git+https://github.com/arihantprasad07/guni.git#egg=guni
# or clone and install locally:
git clone https://github.com/arihantprasad07/guni.git
cd guni
pip install -e .
```

---

## Option 1 — Python SDK (recommended)

The fastest way. Works with any agent framework.

### Basic usage

```python
from guni import scan

# Before your agent acts on any page:
result = scan(
    html=page_html,        # raw HTML from the page
    goal="Book a flight"   # your agent's declared objective
)

if result["decision"] == "BLOCK":
    # Don't proceed — threat detected
    raise SecurityError(f"Threat detected: {result['evidence']}")

if result["decision"] == "CONFIRM":
    # Log and proceed carefully
    print(f"Warning: Risk {result['risk']}/100")

# ALLOW — safe to proceed with agent logic
```

### Full result structure

```python
{
  "decision":  "BLOCK",        # ALLOW / CONFIRM / BLOCK
  "risk":      85,             # 0-100 overall score
  "breakdown": {               # per-category scores
    "injection":     30,
    "phishing":      40,
    "goal_mismatch": 35,
    "clickjacking":  0,
    "csrf":          0,
    "redirect":      0,
    "deception":     0,
    "scripts":       0,
  },
  "evidence": {                # what was found
    "injection": ["Hidden CSS element: 'ignore previous instructions'"],
    "phishing":  ["Form posts to external URL: 'http://evil.com'"],
  },
  "total_latency": 0.0009,     # seconds
  "vectors_checked": 8,
}
```

---

## Option 2 — Playwright integration

Drop Guni into any Playwright agent with one wrapper function.

```python
from playwright.sync_api import sync_playwright
from guni import GuniScanner

# Create scanner once, reuse across pages
scanner = GuniScanner(goal="Book a train ticket from Delhi to Mumbai")

def safe_goto(page, url: str) -> bool:
    """Navigate to URL safely. Returns False if blocked."""
    page.goto(url)
    result = scanner.scan(html=page.content(), url=url)

    if result["decision"] == "BLOCK":
        print(f"[GUNI] BLOCKED {url} — Risk {result['risk']}/100")
        for cat, items in result["evidence"].items():
            for item in items:
                print(f"  [{cat}] {item}")
        page.go_back()
        return False

    if result["decision"] == "CONFIRM":
        print(f"[GUNI] WARNING {url} — Risk {result['risk']}/100")

    return True


# Use in your agent:
with sync_playwright() as p:
    browser = p.chromium.launch(headless=False)
    page    = browser.new_page()

    # Every navigation through safe_goto
    if safe_goto(page, "https://irctc.co.in/book"):
        page.fill("#from-station", "Delhi")
        page.fill("#to-station", "Mumbai")
        page.click("#search")
```

---

## Option 3 — browser-use integration

```python
from guni import GuniScanner

scanner = GuniScanner(goal="Find best laptop deals")

async def secure_task(task: str):
    from browser_use import Agent
    from langchain_anthropic import ChatAnthropic

    llm   = ChatAnthropic(model="claude-3-5-sonnet-20241022")
    agent = Agent(task=task, llm=llm)

    # Hook into agent's page handling
    original_step = agent.step

    async def secure_step(*args, **kwargs):
        # Scan current page before agent acts
        if hasattr(agent, 'browser') and agent.browser:
            page   = await agent.browser.get_current_page()
            html   = await page.content()
            url    = page.url
            result = scanner.scan(html=html, url=url)

            if result["decision"] == "BLOCK":
                return f"Page blocked by Guni security: {url}"

        return await original_step(*args, **kwargs)

    agent.step = secure_step
    return await agent.run()
```

---

## Option 4 — LangChain integration

```python
from langchain.tools import BaseTool
from guni import GuniScanner

class SecureBrowserTool(BaseTool):
    name = "secure_browser"
    description = "Browse URLs securely with Guni threat detection"

    def __init__(self, goal: str):
        super().__init__()
        self._scanner = GuniScanner(goal=goal)

    def _run(self, url: str) -> str:
        from playwright.sync_api import sync_playwright
        from bs4 import BeautifulSoup

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page    = browser.new_page()
            page.goto(url, timeout=15000)
            html    = page.content()
            browser.close()

        result = self._scanner.scan(html=html, url=url)

        if result["decision"] == "BLOCK":
            return (
                f"[BLOCKED] Risk {result['risk']}/100 — "
                f"This page contains threats. Do not proceed. "
                f"Threats: {list(result['evidence'].keys())}"
            )

        return BeautifulSoup(html, 'lxml').get_text()[:3000]

    async def _arun(self, url: str) -> str:
        return self._run(url)


# Use in your chain:
from langchain.agents import initialize_agent, AgentType
from langchain_anthropic import ChatAnthropic

llm   = ChatAnthropic(model="claude-3-5-sonnet-20241022")
tools = [SecureBrowserTool(goal="Book cheapest flight Delhi to Mumbai")]
agent = initialize_agent(tools, llm, agent=AgentType.ZERO_SHOT_REACT_DESCRIPTION)
agent.run("Find and book the cheapest flight from Delhi to Mumbai next Friday")
```

---

## Option 5 — REST API (any language)

Use Guni as a hosted service. Works with Python, Node.js, Go, anything.

```bash
# Hosted endpoint
POST https://guni.up.railway.app/scan
Headers: X-API-Key: guni_live_...
Body: {"html": "<page html>", "goal": "your agent goal"}
```

### Python (requests)

```python
import requests

def scan_page(html: str, goal: str, api_key: str) -> dict:
    r = requests.post(
        "https://guni.up.railway.app/scan",
        json={"html": html, "goal": goal},
        headers={"X-API-Key": api_key},
        timeout=10,
    )
    return r.json()

result = scan_page(page_html, "Login to website", "guni_live_...")
if result["decision"] == "BLOCK":
    raise Exception("Threat detected")
```

### JavaScript/Node.js

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
  return res.json();
}

const result = await scanPage(pageHTML, "Book a flight", "guni_live_...");
if (result.decision === "BLOCK") {
  throw new Error(`Threat detected: ${JSON.stringify(result.evidence)}`);
}
```

---

## Option 6 — WebSocket real-time

Best for high-frequency agents that visit many pages per second.

```python
import asyncio
import json
import websockets

async def secure_agent():
    uri = "wss://guni.up.railway.app/ws/scan?goal=Book+a+flight"

    async with websockets.connect(uri) as ws:
        # Send pages as agent browses
        async def check_page(html: str, url: str) -> dict:
            await ws.send(json.dumps({"html": html, "url": url}))
            response = json.loads(await ws.recv())

            while response.get("type") == "scanning":
                response = json.loads(await ws.recv())

            return response

        # In your agent loop:
        result = await check_page(page_html, current_url)
        if result.get("decision") == "BLOCK":
            print(f"BLOCKED: {current_url}")
            return

asyncio.run(secure_agent())
```

---

## Getting your API key

1. Go to **guni.up.railway.app**
2. Join the waitlist
3. You'll receive your `guni_live_...` key within 48 hours
4. Use it in any integration above via the `api_key` parameter

Or run Guni self-hosted (free, open source):
```bash
git clone https://github.com/arihantprasad07/guni
cd guni
pip install -e .
uvicorn api.main:app --port 8000
```

---

## Run the demo

See Guni protecting a real agent against 6 attack scenarios:

```bash
# Quick demo (no browser needed)
python examples/agent_demo.py

# With real Playwright browser
python examples/agent_demo.py --browser

# See integration template
python examples/agent_demo.py --template
```

---

## Decision policy

| Risk score | Decision | What to do in your agent |
|------------|----------|--------------------------|
| ≥ 70 | **BLOCK** | Stop. Don't execute. Go back or abort task. |
| 40–69 | **CONFIRM** | Log the warning. Proceed carefully. Notify user. |
| < 40 | **ALLOW** | Safe to proceed with planned action. |

---

## Support

- **Docs**: guni.up.railway.app/docs
- **GitHub**: github.com/arihantprasad07/guni
- **Email**: hello@guni.dev
- **Issues**: github.com/arihantprasad07/guni/issues
