from ...models.finding import Finding, Severity, Category
from ...models.context import AnalysisContext

class StakingChecks:
    """
    Checks staking mechanisms such as rewards emission, lock-up periods, and early withdrawal penalties.
    """
    def run(self, context: AnalysisContext) -> list:
        findings = []
        code = context.contract_code.lower()

        if "rewardperblock" not in code and "rewardrate" not in code:
            findings.append(Finding(
                title="Missing Reward Distribution Rate",
                description="No clear reward emission rate (e.g., rewardPerBlock) found in staking contract.",
                severity=Severity.HIGH,
                category=Category.REWARDS,
                recommendation="Define and audit an explicit reward emission mechanism."
            ))

        if "lockperiod" not in code and "withdrawableafter" not in code:
            findings.append(Finding(
                title="No Stake Lock-Up Period",
                description="Staking contracts lack a lock-up period to prevent instant withdrawals.",
                severity=Severity.MEDIUM,
                category=Category.STAKING,
                recommendation="Implement locking periods to enhance staking security and avoid abuse."
            ))

        if "penalty" not in code:
            findings.append(Finding(
                title="No Early Withdrawal Penalty",
                description="No penalty mechanism for early unstaking found.",
                severity=Severity.LOW,
                category=Category.STAKING,
                recommendation="Add penalty or conditions to discourage premature withdrawal."
            ))

        return findings
