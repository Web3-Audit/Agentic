import re
from ...models.finding import Finding, Severity, Category
from ...models.context import AnalysisContext

class LendingChecks:
    """
    Lending protocol security checks: collateralization, liquidation logic, interest accrual, and oracle robustness.
    """
    def __init__(self):
        self.checks = [
            self.check_overcollateralization,
            self.check_liquidation_mechanism,
            self.check_interest_calculation,
            self.check_oracle_consistency
        ]

    def run(self, context: AnalysisContext) -> list:
        findings = []
        for check in self.checks:
            findings.extend(check(context))
        return findings

    def check_overcollateralization(self, context: AnalysisContext) -> list:
        findings = []
        if ("liquidationthreshold" not in context.contract_code.lower()
            and "collateralfactor" not in context.contract_code.lower()):
            findings.append(Finding(
                title="No Overcollateralization Enforcement",
                description="Cannot find `liquidationThreshold` or `collateralFactor` in lending logic.",
                severity=Severity.CRITICAL,
                category=Category.LENDING,
                recommendation="Enforce strict overcollateralization for all borrowers."
            ))
        return findings

    def check_liquidation_mechanism(self, context: AnalysisContext) -> list:
        findings = []
        if "liquidate" not in context.contract_code.lower():
            findings.append(Finding(
                title="No Liquidation Functionality",
                description="Lending protocol does not include a `liquidate` function.",
                severity=Severity.HIGH,
                category=Category.LIQUIDITY,
                recommendation="Add safe and auditable liquidation mechanisms."
            ))
        return findings

    def check_interest_calculation(self, context: AnalysisContext) -> list:
        findings = []
        if "accrueinterest" not in context.contract_code.lower() and "interest" not in context.contract_code.lower():
            findings.append(Finding(
                title="No Interest Accrual Detected",
                description="Interest calculation or accrual logic not present.",
                severity=Severity.MEDIUM,
                category=Category.ECONOMICS,
                recommendation="Ensure protocol supplies interest logic and compounding is audited."
            ))
        return findings

    def check_oracle_consistency(self, context: AnalysisContext) -> list:
        findings = []
        if "oracle" not in context.contract_code.lower() or "pricefeed" not in context.contract_code.lower():
            findings.append(Finding(
                title="Missing Oracle/Price Feed Logic",
                description="Oracles (price feeds) not present for collateral valuation.",
                severity=Severity.CRITICAL,
                category=Category.ORACLE,
                recommendation="Integrate reliable and decentralized oracles for all asset pricing."
            ))
        return findings
