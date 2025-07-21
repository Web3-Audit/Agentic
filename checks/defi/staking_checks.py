import re
from ...models.finding import Finding, Severity, Category
from ...models.context import AnalysisContext

class StakingChecks:
    """
    Checks for staking protocol risks: reward distribution, lock-up periods, withdrawal logic.
    """
    def __init__(self):
        self.checks = [
            self.check_reward_distribution,
            self.check_withdrawal_lockup,
            self.check_early_withdraw_penalty
        ]
    
    def run(self, context: AnalysisContext) -> list:
        findings = []
        for check in self.checks:
            findings.extend(check(context))
        return findings

    def check_reward_distribution(self, context: AnalysisContext) -> list:
        findings = []
        if "rewardperblock" not in context.contract_code.lower() and "rewardrate" not in context.contract_code.lower():
            findings.append(Finding(
                title="No Reward Distribution Rate",
                description="No `rewardPerBlock` or equivalent parameter for rewards found.",
                severity=Severity.HIGH,
                category=Category.STAKING,
                recommendation="Add clearly defined reward emission logic for transparency."
            ))
        return findings

    def check_withdrawal_lockup(self, context: AnalysisContext) -> list:
        findings = []
        if "lockperiod" not in context.contract_code.lower() and "withdrawableafter" not in context.contract_code.lower():
            findings.append(Finding(
                title="No Stake Lock-up Period",
                description="Lock-up time for withdrawals is missing.",
                severity=Severity.MEDIUM,
                category=Category.STAKING,
                recommendation="Require all staked assets to set a lock-up before withdrawal."
            ))
        return findings

    def check_early_withdraw_penalty(self, context: AnalysisContext) -> list:
        findings = []
        if "penalty" not in context.contract_code.lower():
            findings.append(Finding(
                title="No Penalty on Early Withdrawal",
                description="Protocol lacks penalty logic for early un-staking.",
                severity=Severity.LOW,
                category=Category.STAKING,
                recommendation="Implement penalty or forfeit to discourage instant un-staking."
            ))
        return findings
