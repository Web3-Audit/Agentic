import re
from ...models.finding import Finding, Severity, Category
from ...models.context import AnalysisContext

class YieldFarmingChecks:
    """
    Yield farming fairness, reward manipulation, and pool migration risk checks.
    """
    def __init__(self):
        self.checks = [
            self.check_reward_rate,
            self.check_migration_risk,
            self.check_pool_switch_logic
        ]

    def run(self, context: AnalysisContext) -> list:
        findings = []
        for check in self.checks:
            findings.extend(check(context))
        return findings

    def check_reward_rate(self, context: AnalysisContext) -> list:
        findings = []
        if "rewardrate" not in context.contract_code.lower() and "emissionrate" not in context.contract_code.lower():
            findings.append(Finding(
                title="No Reward Emission Rate for Farming",
                description="No reward emission rate found for pool(s).",
                severity=Severity.HIGH,
                category=Category.REWARDS,
                recommendation="Clarify and cap farming reward emission per block or sec."
            ))
        return findings

    def check_migration_risk(self, context: AnalysisContext) -> list:
        findings = []
        if "migrate" in context.contract_code.lower() and "onlyowner" not in context.contract_code.lower():
            findings.append(Finding(
                title="Unrestricted Migration Function",
                description="Pool migration is exposed without owner or governance restriction.",
                severity=Severity.CRITICAL,
                category=Category.OWNERSHIP,
                recommendation="Add strict permission for migrate/upgrade logic."
            ))
        return findings

    def check_pool_switch_logic(self, context: AnalysisContext) -> list:
        findings = []
        if "switchpool" in context.contract_code.lower() and "require" not in context.contract_code.lower():
            findings.append(Finding(
                title="Pool Switch Lacks Validation",
                description="Switching pools is allowed without any validation.",
                severity=Severity.MEDIUM,
                category=Category.POOL,
                recommendation="Require pool switches to be validated for migrators or managers only."
            ))
        return findings
