"""
Guni + LangChain Integration Example
Adds security scanning to any LangChain browser agent.

Install:
    pip install guni langchain langchain-community playwright
    playwright install
"""

from guni import GuniScanner

# ── Option 1: Simple wrapper around any LangChain tool ────────────────────────

from langchain.tools import BaseTool
from typing import Optional
from pydantic import Field


class SecureBrowserTool(BaseTool):
    """
    A LangChain tool wrapper that scans pages with Guni before returning content.
    Drop-in replacement for any browser tool.
    """

    name:        str = "secure_browser"
    description: str = (
        "Browse a URL securely. Automatically scans for prompt injection, "
        "phishing, and goal hijacking before returning page content."
    )
    agent_goal:  str = Field(default="browse website")
    api_key:     Optional[str] = Field(default=None)
    _scanner:    Optional[GuniScanner] = None

    def __init__(self, goal: str = "browse website", api_key: str = None, **kwargs):
        super().__init__(**kwargs)
        self.agent_goal = goal
        self.api_key    = api_key
        self._scanner   = GuniScanner(goal=goal, api_key=api_key or "")

    def _run(self, url: str) -> str:
        from playwright.sync_api import sync_playwright

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page    = browser.new_page()
            page.goto(url, timeout=15000)
            html = page.content()
            browser.close()

        result = self._scanner.scan(html=html, url=url)

        if result["decision"] == "BLOCK":
            return (
                f"[GUNI SECURITY] Page blocked — Risk: {result['risk']}/100\n"
                f"Threats: {list(result['evidence'].keys())}\n"
                f"This page appears to contain adversarial content. "
                f"Do not proceed."
            )

        if result["decision"] == "CONFIRM":
            return (
                f"[GUNI WARNING] Page flagged — Risk: {result['risk']}/100\n"
                f"Proceeding with caution. Evidence: "
                f"{[v[0] for v in result['evidence'].values() if v]}\n\n"
                + self._get_page_text(html)
            )

        return self._get_page_text(html)

    def _get_page_text(self, html: str) -> str:
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(html, "lxml")
        return soup.get_text()[:3000]

    async def _arun(self, url: str) -> str:
        return self._run(url)


# ── Option 2: Middleware callback for existing chains ─────────────────────────

from langchain.callbacks.base import BaseCallbackHandler


class GuniSecurityCallback(BaseCallbackHandler):
    """
    LangChain callback that intercepts tool outputs and scans them.
    Add to any chain via callbacks=[GuniSecurityCallback(goal="...")]
    """

    def __init__(self, goal: str = "browse website", api_key: str = None):
        self.scanner = GuniScanner(goal=goal, api_key=api_key or "")
        self.blocked_urls = []

    def on_tool_end(self, output: str, **kwargs) -> None:
        """Scan tool output for threats."""
        if len(output) < 100:
            return  # Too short to be a full page

        result = self.scanner.scan(html=output, url="tool_output")

        if result["decision"] == "BLOCK":
            self.blocked_urls.append(result.get("url", "unknown"))
            raise ValueError(
                f"[Guni] Blocked — Risk {result['risk']}/100. "
                f"Threats: {[k for k,v in result['evidence'].items() if v]}"
            )

        if result["decision"] == "CONFIRM" and result["risk"] > 50:
            print(f"[Guni] Warning — Risk {result['risk']}/100 on tool output")


# ── Usage examples ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("Guni + LangChain Integration\n")

    # Example 1: Use SecureBrowserTool in an agent
    tool = SecureBrowserTool(
        goal="Find the price of MacBook Pro",
        api_key=None,  # Set to your Guni API key for LLM layer
    )

    print("Example 1: Direct tool use")
    result = tool._run("https://example.com")
    print(result[:200])

    # Example 2: Scan directly before using any tool
    from guni import scan

    html = "<html><body><p>Safe page content</p></body></html>"
    security_check = scan(html=html, goal="Browse product page")

    print(f"\nExample 2: Direct scan")
    print(f"Decision: {security_check['decision']}")
    print(f"Risk:     {security_check['risk']}/100")
    print(f"Latency:  {security_check['total_latency']*1000:.1f}ms")
