"""
Agent Executor
Executes validated browser actions via Playwright.
Only runs if the security decision is ALLOW or CONFIRM.
"""


def execute_action(page, action_plan: dict, decision: str) -> str:
    """
    Execute a planned action on a Playwright page.

    Returns a status string describing what happened.
    """
    action_type = action_plan.get("type", "NO_ACTION")

    if decision == "BLOCK":
        return "BLOCKED — action not executed."

    if decision == "CONFIRM":
        print("  [Guni] Action requires confirmation. Simulating approval.")

    if action_type == "CLICK_BUTTON":
        try:
            page.click("button")
            return "Button clicked."
        except Exception:
            return "No clickable button found."

    elif action_type == "SUBMIT_FORM":
        try:
            page.fill("input[type='text']", "testuser")
            page.fill("input[type='password']", "password")
            page.press("input[type='password']", "Enter")
            return "Form submitted."
        except Exception:
            return "Form submission failed."

    return "No action performed."
