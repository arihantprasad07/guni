"""
Guni Demo
Shows the SDK in action against 4 test pages.
Run: python demo.py
"""

import os
import time
import sys
from playwright.sync_api import sync_playwright

from guni import scan
from guni.agent.state_machine import AgentStateMachine
from guni.agent.planner import plan_action
from guni.agent.executor import execute_action
from guni.core.dom_parser import parse_dom

RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

TEST_PAGES = [
    "safe.html",
    "visible_injection.html",
    "hidden_injection.html",
    "phishing.html",
]

AGENT_GOAL = "Login to website"


def banner():
    print("\n" + "=" * 65)
    print(f"{BOLD}{CYAN}  Guni SDK v0.1.0 — Secure Agentic Browser{RESET}")
    print("=" * 65)


def color_decision(d):
    if d == "BLOCK":   return RED + BOLD + d + RESET
    if d == "CONFIRM": return YELLOW + d + RESET
    return GREEN + d + RESET


def severity(score):
    if score >= 80: return RED + "CRITICAL" + RESET
    if score >= 60: return RED + "HIGH" + RESET
    if score >= 40: return YELLOW + "MEDIUM" + RESET
    if score > 0:   return CYAN + "LOW" + RESET
    return GREEN + "SAFE" + RESET


def loading():
    for _ in range(2):
        for dot in [" .  ", " .. ", " ..."]:
            sys.stdout.write("\r  Scanning" + dot)
            sys.stdout.flush()
            time.sleep(0.15)
    print("\r  Scan complete.     ")


def print_result(page_name, result):
    print(f"\n  {'Page':<16} {page_name}")
    print(f"  {'Risk Score':<16} {result['risk']}%  ({severity(result['risk'])})")
    print(f"  {'Decision':<16} {color_decision(result['decision'])}")
    print(f"  {'Latency':<16} {result['total_latency']:.4f}s")

    print(f"\n  {'Breakdown':}")
    for k, v in result["breakdown"].items():
        bar = "█" * (v // 5) if v else ""
        print(f"    {k:<16} {v:>3}  {bar}")

    evidence_found = any(result["evidence"].values())
    if evidence_found:
        print(f"\n  Evidence:")
        for category, findings in result["evidence"].items():
            for f in findings:
                print(f"    - [{category}] {f}")


def print_summary(results):
    print("\n" + "=" * 65)
    print(f"{BOLD}  Summary{RESET}")
    print("=" * 65)
    total   = len(results)
    blocked = sum(1 for r in results if r["decision"] == "BLOCK")
    confirm = sum(1 for r in results if r["decision"] == "CONFIRM")
    allowed = sum(1 for r in results if r["decision"] == "ALLOW")
    avg_lat = sum(r["latency"] for r in results) / total

    print(f"  Pages tested  : {total}")
    print(f"  {RED}Blocked{RESET}       : {blocked}")
    print(f"  {YELLOW}Confirm{RESET}       : {confirm}")
    print(f"  {GREEN}Allowed{RESET}       : {allowed}")
    print(f"  Avg latency   : {avg_lat:.4f}s")
    print("=" * 65 + "\n")


def main():
    banner()

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=False)
        pw_page = browser.new_page()
        results = []

        for page_name in TEST_PAGES:
            file_path = os.path.abspath(f"test_pages/{page_name}")
            print(f"\n{'─'*65}")
            print(f"{BOLD}  {page_name}{RESET}")
            print(f"{'─'*65}")

            loading()

            pw_page.goto(f"file:///{file_path}")
            html = pw_page.content()

            # ── Guni SDK — one call does everything ──
            result = scan(html=html, goal=AGENT_GOAL, url=page_name)

            print_result(page_name, result)

            # ── Agent state machine ──
            agent = AgentStateMachine(goal=AGENT_GOAL)
            parsed = parse_dom(html)
            agent.perceive(parsed)
            action_plan = agent.plan(plan_action)
            agent.validate()

            if result["decision"] != "BLOCK":
                agent.execute()
                status = execute_action(pw_page, action_plan, result["decision"])
                print(f"\n  Action: {status}")

            agent.terminate()

            print(f"\n  State trace: {' → '.join(s[1] for s in agent.history)}")

            results.append(result)
            time.sleep(1.5)

        browser.close()

    print_summary(results)


if __name__ == "__main__":
    main()
