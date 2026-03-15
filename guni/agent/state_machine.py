"""
Agent State Machine
Tracks the lifecycle of an agent session.
States: INITIAL → PERCEIVE → PLAN → VALIDATE → EXECUTE → TERMINATE
"""


class AgentStateMachine:
    STATES = ["INITIAL", "PERCEIVE", "PLAN", "VALIDATE", "EXECUTE", "TERMINATE"]

    def __init__(self, goal: str):
        self.goal    = goal
        self.state   = "INITIAL"
        self.history = []
        self.dom     = None
        self.action_plan = None

    def transition(self, new_state: str):
        if new_state not in self.STATES:
            raise ValueError(f"Invalid state: {new_state}")
        self.history.append((self.state, new_state))
        self.state = new_state

    def perceive(self, parsed_dom: dict):
        self.transition("PERCEIVE")
        self.dom = parsed_dom

    def plan(self, planner_fn) -> dict:
        self.transition("PLAN")
        self.action_plan = planner_fn(self.dom, self.goal)
        return self.action_plan

    def validate(self):
        self.transition("VALIDATE")

    def execute(self):
        self.transition("EXECUTE")

    def terminate(self):
        self.transition("TERMINATE")

    def summary(self) -> list[str]:
        return [f"{old} → {new}" for old, new in self.history]
