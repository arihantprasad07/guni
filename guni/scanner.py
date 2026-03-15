"""
Guni Scanner
Two-layer threat detection pipeline:
  Layer 1 — Fast heuristic detectors (~0.001s, no API cost)
  Layer 2 — LLM semantic reasoning (only when needed, catches novel attacks)
"""

import time
import os
from guni.core.dom_parser import parse_dom
from guni.core.risk_engine import calculate_risk
from guni.core.mediator import decide_action
from guni.core.logger import GuniLogger
from guni.detectors.injection import detect_injection
from guni.detectors.phishing import detect_phishing
from guni.detectors.deception import detect_ui_deception
from guni.detectors.scripts import detect_dynamic_scripts
from guni.detectors.goal import detect_goal_mismatch


def scan(
    html:    str,
    goal:    str = "browse website",
    url:     str = "",
    api_key: str = None,
    llm:     bool = False,
) -> dict:
    """
    Scan a web page for threats and return a structured risk report.

    Args:
        html:    Raw HTML content of the page.
        goal:    The agent's declared objective (e.g. "Login to website").
        url:     Optional page URL for logging.
        api_key: Anthropic API key for LLM analysis.
        llm:     If True, always run LLM analysis.
                 If False (default), run LLM only when heuristics flag something.
    """
    scanner = GuniScanner(goal=goal, api_key=api_key, llm=llm)
    return scanner.scan(html=html, url=url)


class GuniScanner:
    """
    Stateful scanner. Reuse across multiple pages with the same goal.

    Example (heuristics only, free):
        scanner = GuniScanner(goal="Book a flight")
        result  = scanner.scan(html=page_html)

    Example (with LLM layer):
        scanner = GuniScanner(goal="Book a flight", api_key="sk-ant-...")
        result  = scanner.scan(html=page_html)
        print(result["llm_analysis"]["summary"])
    """

    def __init__(self, goal="browse website", api_key=None, llm=False):
        self.goal    = goal
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        self.llm     = llm
        self.logger  = GuniLogger()

    def scan(self, html: str, url: str = "") -> dict:
        start = time.perf_counter()

        # ── Layer 1: Fast heuristic detection ──
        parsed = parse_dom(html)

        injection   = detect_injection(parsed)
        phishing    = detect_phishing(parsed)
        deception   = detect_ui_deception(parsed)
        scripts     = detect_dynamic_scripts(parsed)
        goal_issues = detect_goal_mismatch(parsed, self.goal)

        heuristic_latency = time.perf_counter() - start

        heuristic_evidence = {
            "injection":     injection,
            "phishing":      phishing,
            "deception":     deception,
            "scripts":       scripts,
            "goal_mismatch": goal_issues,
        }

        heuristic_risk, breakdown = calculate_risk(
            injection, phishing, deception, scripts, goal_issues
        )

        # ── Layer 2: LLM semantic reasoning ──
        llm_analysis = None
        final_risk   = heuristic_risk
        heuristic_hit = any(heuristic_evidence.values())
        should_use_llm = self.api_key and (self.llm or heuristic_hit)

        if should_use_llm:
            from guni.llm_analyzer import analyze_with_llm
            llm_analysis = analyze_with_llm(
                parsed_dom=parsed,
                goal=self.goal,
                heuristic_findings=heuristic_evidence,
                api_key=self.api_key,
            )

            if not llm_analysis.get("error"):
                llm_risk   = llm_analysis.get("overall_risk", 0)
                final_risk = min(100, max(heuristic_risk, llm_risk))

                # If LLM found threat types heuristics missed, add them to breakdown
                for threat in llm_analysis.get("threats", []):
                    t = threat.get("type", "").lower()
                    if t == "prompt_injection"  and breakdown.get("injection", 0) == 0:
                        breakdown["injection"] = 30
                    elif t == "phishing"        and breakdown.get("phishing", 0) == 0:
                        breakdown["phishing"] = 40
                    elif t == "ui_deception"    and breakdown.get("deception", 0) == 0:
                        breakdown["deception"] = 25
                    elif t == "script_attack"   and breakdown.get("scripts", 0) == 0:
                        breakdown["scripts"] = 20
                    elif t == "goal_hijacking"  and breakdown.get("goal_mismatch", 0) == 0:
                        breakdown["goal_mismatch"] = 35

        total_latency = time.perf_counter() - start
        decision      = decide_action(final_risk)

        result = {
            "risk":              final_risk,
            "decision":          decision,
            "breakdown":         breakdown,
            "evidence":          heuristic_evidence,
            "heuristic_risk":    heuristic_risk,
            "heuristic_latency": round(heuristic_latency, 6),
            "total_latency":     round(total_latency, 3),
            "goal":              self.goal,
            "url":               url,
            "llm_analysis":      llm_analysis,
        }

        self.logger.log(result)
        return result
