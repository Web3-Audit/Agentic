from ...models.finding import Finding, Severity, Category, CodeLocation
from ...models.context import AnalysisContext, FunctionContext

class RewardSystemChecks:
    """
    Checks reward distribution, claim functions for proper access control and abuse prevention.
    """
    reward_keywords = ["claim", "reward", "harvest", "bonus", "airdrop"]

    def run(self, context: AnalysisContext) -> list:
        findings = []

        for contract_name, functions in context.functions.items():
            for func in functions:
                func_name = func.name.lower()
                if any(keyword in func_name for keyword in self.reward_keywords):
                    if not self._has_access_control(func):
                        findings.append(Finding(
                            title="Unprotected Reward Function",
                            description=f"Function '{func.name}' appears to handle rewards without access control.",
                            severity=Severity.HIGH,
                            category=Category.ACCESS_CONTROL,
                            location=CodeLocation(contract=contract_name, function=func.name, line=func.line_number),
                            recommendation="Add access checks (e.g., onlyOwner, role-based) to reward functions."
                        ))

        return findings

    def _has_access_control(self, func: FunctionContext) -> bool:
        access_indicators = ["require", "onlyowner", "hasrole", "msg.sender"]
        return any(keyword in func.body.lower() for keyword in access_indicators)
