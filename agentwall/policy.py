import yaml


class PolicyEngine:
    def __init__(self, policy_path: str):
        with open(policy_path, "r") as f:
            self._policy = yaml.safe_load(f)

    def evaluate(self, tool_name: str) -> str:
        rules = self._policy.get("rules", {})
        return rules.get(tool_name, self._policy.get("default", "deny"))
