"""
Guni Scanner v2
8-vector threat detection pipeline:
  Layer 1 — Fast heuristics (~0.001s, free)
  Layer 2 — LLM semantic reasoning (when needed)
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
from guni.detectors.clickjacking import detect_clickjacking
from guni.detectors.csrf import detect_csrf_threats
from guni.detectors.redirect import detect_open_redirects


def scan(
    html:    str,
    goal:    str  = "browse website",
    url:     str  = "",
    api_key: str  = None,
    llm_api_key: str = None,
    tracking_key: str = None,
    llm:     bool = False,
    persist: bool = True,
) -> dict:
    scanner = GuniScanner(
        goal=goal,
        api_key=api_key,
        llm_api_key=llm_api_key,
        tracking_key=tracking_key,
        llm=llm,
        persist=persist,
    )
    return scanner.scan(html=html, url=url)


class GuniScanner:
    """
    Guni 8-vector scanner.

    Example:
        scanner = GuniScanner(goal="Book a flight", api_key="sk-ant-...")
        result  = scanner.scan(html=page_html)
        print(result["decision"])    # ALLOW / CONFIRM / BLOCK
        print(result["risk"])        # 0-100
    """

    def __init__(self, goal="browse website", api_key=None, llm_api_key=None, tracking_key=None, llm=False, persist=True):
        self.goal        = goal
        self.api_key     = llm_api_key or api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        self._api_key    = tracking_key
        self.llm         = llm
        self._persist    = persist
        self.logger      = GuniLogger()

    def _load_custom_rules(self) -> list[dict]:
        if not self._api_key or self._api_key == "open":
            return []
        try:
            from api.database import db_get_rules
            return db_get_rules(self._api_key)
        except Exception:
            return []

    def _apply_custom_rules(self, parsed: dict) -> tuple[dict[str, list[str]], dict[str, int]]:
        rules = self._load_custom_rules()
        if not rules:
            return {}, {}

        searchable_parts = [parsed.get("visible_text", "")]
        searchable_parts.extend(
            el.get("text", "") for el in parsed.get("hidden_elements", [])
        )
        searchable_parts.extend(
            form.get("text", "") for form in parsed.get("forms", [])
        )
        searchable_parts.extend(parsed.get("buttons", []))
        searchable_parts.extend(parsed.get("scripts", []))
        searchable_text = "\n".join(part.lower() for part in searchable_parts if part)

        findings_by_category: dict[str, list[str]] = {}
        weight_overrides: dict[str, int] = {}
        valid_categories = {
            "injection",
            "phishing",
            "deception",
            "scripts",
            "goal_mismatch",
            "clickjacking",
            "csrf",
            "redirect",
        }

        for rule in rules:
            pattern = (rule.get("pattern") or "").strip()
            category = (rule.get("rule_type") or "injection").strip().lower()
            if not pattern or category not in valid_categories:
                continue
            if pattern.lower() not in searchable_text:
                continue

            findings_by_category.setdefault(category, []).append(
                f"Custom rule matched '{pattern}'"
            )
            try:
                weight_overrides[category] = max(
                    weight_overrides.get(category, 0),
                    int(rule.get("weight") or 0),
                )
            except Exception:
                pass

        return findings_by_category, weight_overrides

    def scan(self, html: str, url: str = "") -> dict:
        start = time.perf_counter()

        parsed = parse_dom(html)

        # ── Layer 1: 8-vector heuristics ──
        injection    = detect_injection(parsed)
        phishing     = detect_phishing(parsed)
        deception    = detect_ui_deception(parsed)
        scripts      = detect_dynamic_scripts(parsed)
        goal_issues  = detect_goal_mismatch(parsed, self.goal)
        clickjacking = detect_clickjacking(parsed)
        csrf         = detect_csrf_threats(parsed)
        redirect     = detect_open_redirects(parsed)

        heuristic_latency = time.perf_counter() - start

        evidence = {
            "injection":     injection,
            "phishing":      phishing,
            "deception":     deception,
            "scripts":       scripts,
            "goal_mismatch": goal_issues,
            "clickjacking":  clickjacking,
            "csrf":          csrf,
            "redirect":      redirect,
        }

        custom_rule_findings, custom_rule_weights = self._apply_custom_rules(parsed)
        for category, items in custom_rule_findings.items():
            evidence.setdefault(category, []).extend(items)

        heuristic_risk, breakdown = calculate_risk(
            injection, phishing, deception, scripts,
            goal_issues, clickjacking, csrf, redirect
        )

        if custom_rule_weights:
            for category, weight in custom_rule_weights.items():
                if evidence.get(category):
                    breakdown[category] = max(breakdown.get(category, 0), weight)
            heuristic_risk = min(100, sum(breakdown.values()))

        # ── Layer 2: LLM reasoning ──
        llm_analysis  = None
        final_risk    = heuristic_risk
        heuristic_hit = any(evidence.values())
        should_use_llm = self.api_key and (self.llm or heuristic_hit)

        if should_use_llm:
            from guni.llm_analyzer import analyze_with_llm
            llm_analysis = analyze_with_llm(
                parsed_dom=parsed,
                goal=self.goal,
                heuristic_findings=evidence,
                api_key=self.api_key,
            )

            if not llm_analysis.get("error"):
                llm_risk   = llm_analysis.get("overall_risk", 0)
                final_risk = min(100, max(heuristic_risk, llm_risk))

                type_map = {
                    "prompt_injection": ("injection",    30),
                    "phishing":         ("phishing",     40),
                    "ui_deception":     ("deception",    25),
                    "script_attack":    ("scripts",      20),
                    "goal_hijacking":   ("goal_mismatch",35),
                    "clickjacking":     ("clickjacking", 30),
                    "csrf_attack":      ("csrf",         35),
                    "open_redirect":    ("redirect",     20),
                }
                for threat in llm_analysis.get("threats", []):
                    t = threat.get("type", "").lower()
                    if t in type_map:
                        key, weight = type_map[t]
                        if breakdown.get(key, 0) == 0:
                            breakdown[key] = weight

        total_latency = time.perf_counter() - start
        decision      = decide_action(final_risk)

        result = {
            "risk":              final_risk,
            "decision":          decision,
            "breakdown":         breakdown,
            "evidence":          evidence,
            "heuristic_risk":    heuristic_risk,
            "heuristic_latency": round(heuristic_latency, 6),
            "total_latency":     round(total_latency, 3),
            "goal":              self.goal,
            "url":               url,
            "llm_analysis":      llm_analysis,
            "vectors_checked":   8,
        }

        self.logger.log(result)

        # Persist to database and trigger alerts (non-blocking)
        if self._persist:
            try:
                from api.database import db_log_scan, db_increment_usage
                db_log_scan(getattr(self, '_api_key', 'anonymous'), result)
                if hasattr(self, '_api_key') and self._api_key:
                    db_increment_usage(self._api_key)
            except Exception:
                pass

        try:
            from api.alerts import send_alert
            if hasattr(self, '_api_key') and self._api_key:
                send_alert(self._api_key, result)
        except Exception:
            pass

        return result
