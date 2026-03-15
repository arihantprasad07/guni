"""
Agent Planner
Decides the next action based on agent goal and parsed DOM.
"""


def plan_action(parsed_dom: dict, goal: str) -> dict:
    goal_lower  = goal.lower()
    buttons     = parsed_dom.get("buttons", [])
    forms       = parsed_dom.get("forms", [])

    if "login" in goal_lower or "sign in" in goal_lower:
        for form in forms:
            if "password" in form.get("fields", []):
                return {"type": "SUBMIT_FORM", "target": form, "reason": "Login form detected"}
        for btn in buttons:
            if "login" in btn or "sign in" in btn:
                return {"type": "CLICK_BUTTON", "target": btn, "reason": "Login button detected"}

    if "search" in goal_lower:
        for form in forms:
            if "search" in form.get("text", ""):
                return {"type": "SUBMIT_FORM", "target": form, "reason": "Search form detected"}

    if buttons:
        return {"type": "CLICK_BUTTON", "target": buttons[0], "reason": "Default button selected"}

    return {"type": "NO_ACTION", "target": None, "reason": "No actionable element found"}
