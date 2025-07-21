from ....models.finding import Finding, Severity, Category
from ....models.context import AnalysisContext

class SushiSwapChecks:
    """
    SushiSwap protocol: MasterChef, fee switch, migrator, and bonus reward.
    """
    def run(self, context: AnalysisContext) -> list:
        findings = []
        code = context.contract_code.lower()

        if "masterchef" not in code:
            findings.append(Finding(
                title="No MasterChef Contract Detected",
                description="SushiSwap farming and rewards require a MasterChef manager.",
                severity=Severity.CRITICAL,
                category=Category.REWARDS,
                recommendation="Implement MasterChef pattern per SushiSwap design."
            ))

        if "feeswitch" not in code:
            findings.append(Finding(
                title="Fee Switch Not Found",
                description="FeeSwitch toggles between protocol and liquidity provider fees; missing.",
                severity=Severity.MEDIUM,
                category=Category.ADMINISTRATION,
                recommendation="Add a configurable feeSwitch as in SushiSwap."
            ))

        if "migrator" in code and "onlyowner" not in code:
            findings.append(Finding(
                title="Unrestricted Migrator Logic",
                description="Migrator allows asset movement across contracts; require strong access control.",
                severity=Severity.HIGH,
                category=Category.OWNERSHIP,
                recommendation="Lock migrator features so that only contract owner or governance can execute."
            ))

        if "bonusendblock" not in code:
            findings.append(Finding(
                title="No Bonus Reward End Block",
                description="SushiSwap's bonus reward needs a clear end block for emissions.",
                severity=Severity.LOW,
                category=Category.REWARDS,
                recommendation="Add bonusEndBlock to stop extra reward emissions after incentive phase."
            ))

        return findings
