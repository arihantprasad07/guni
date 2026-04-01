"""
Guni — AI Agent Security SDK

Quick start:
    from guni import scan

    # Heuristics only (free, ~0.001s)
    result = scan(html=page_html, goal="Login to website")

    # With LLM reasoning layer (bring your own provider + model)
    result = scan(
        html=page_html,
        goal="Login to website",
        llm_api_key="your-llm-key",
        llm_provider="openai",
        llm_model="gpt-4.1-mini",
    )

    print(result["decision"])              # ALLOW / CONFIRM / BLOCK
    print(result["risk"])                  # 0-100
    print(result["llm_analysis"]["summary"])  # human-readable explanation
"""

from guni.scanner import scan, GuniScanner

__version__ = "2.2.0"
__all__ = ["scan", "GuniScanner"]
