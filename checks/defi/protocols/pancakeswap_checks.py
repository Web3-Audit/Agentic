from ....models.finding import Finding, Severity, Category
from ....models.context import AnalysisContext

class PancakeSwapChecks:
    """
    PancakeSwap protocol: anti-flashloan, ownership transitions, fee mechanisms.
    """
    def run(self, context: AnalysisContext) -> list:
        findings = []
        code = context.contract_code.lower()

        if "masterchef" not in code:
            findings.append(Finding(
                title="No MasterChef Logic Detected",
                description="PancakeSwap pools run through a MasterChef for staking/reward; logic is missing.",
                severity=Severity.CRITICAL,
                category=Category.REWARDS,
                recommendation="Implement the MasterChef contract with appropriate emission and allocationPoint variables."
            ))

        if "antiflashloan" not in code:
            findings.append(Finding(
                title="Missing Anti-Flashloan Protections",
                description="No explicit anti-flashloan logic, e.g., holding period or contract call restrictions, detected.",
                severity=Severity.HIGH,
                category=Category.FLASH_LOAN,
                recommendation="Implement anti-flashloan restrictions such as onlyEOA or block delay[13][19]."
            ))

        if "ownership" not in code or "transferownership" not in code:
            findings.append(Finding(
                title="No Ownership Transfer/Protection Found",
                description="No mechanism for securely transferring or renouncing contract ownership.",
                severity=Severity.MEDIUM,
                category=Category.ADMINISTRATION,
                recommendation="Integrate OpenZeppelin Ownable or equivalent pattern."
            ))

        if "emit" not in code or "event" not in code:
            findings.append(Finding(
                title="No Event Logging",
                description="Event logging critically absent; transactions aren't fully auditable.",
                severity=Severity.LOW,
                category=Category.MONITORING,
                recommendation="Emit all critical events including swaps, liquidity, and ownership transfer."
            ))

        return findings
