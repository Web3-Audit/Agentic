from ....models.finding import Finding, Severity, Category
from ....models.context import AnalysisContext

class CompoundChecks:
    """
    Compound protocol security checks: governance, oracles, and liquidation features.
    """
    def run(self, context: AnalysisContext) -> list:
        findings = []
        code = context.contract_code.lower()

        if "comptroller" not in code:
            findings.append(Finding(
                title="Missing Comptroller Logic",
                description="No Comptroller contract logic detected; Compound protocol must use Comptroller for market administration.",
                severity=Severity.HIGH,
                category=Category.ADMINISTRATION,
                recommendation="Implement and integrate the Comptroller for enforcing global market rules."
            ))

        if "priceoracle" not in code:
            findings.append(Finding(
                title="Missing Price Oracle Integration",
                description="Compound depends on secure oracles. None found.",
                severity=Severity.CRITICAL,
                category=Category.ORACLE,
                recommendation="Integrate reliable oracles for up-to-date price feeds."
            ))

        if "governance" not in code:
            findings.append(Finding(
                title="No Governance Module Found",
                description="Compound-style protocols require proposal and voting mechanisms.",
                severity=Severity.MEDIUM,
                category=Category.GOVERNANCE,
                recommendation="Implement GovernorAlpha/Bravo or similar for decentralized governance."
            ))

        if "liquidateborrow" not in code:
            findings.append(Finding(
                title="No Liquidation Function",
                description="LiquidateBorrow is a fundamental part of Compound safety.",
                severity=Severity.HIGH,
                category=Category.LIQUIDITY,
                recommendation="Implement a safe and fair liquidation process."
            ))

        return findings
