import re
from ...models.finding import Finding, Severity, Category
from ...models.context import AnalysisContext

class AMMChecks:
    """
    Audit checks for Automated Market Makers (AMMs), focusing on slippage, frontrunning, fee skimming, and price manipulation.
    """
    def __init__(self):
        self.checks = [
            self.check_slippage_protection,
            self.check_frontrunning_resistance,
            self.check_fee_skimming,
            self.check_oracle_integrity
        ]

    def run(self, context: AnalysisContext) -> list:
        findings = []
        for check in self.checks:
            findings.extend(check(context))
        return findings

    def check_slippage_protection(self, context: AnalysisContext) -> list:
        findings = []
        if "minamountout" not in context.contract_code.lower() and "slippage" not in context.contract_code.lower():
            findings.append(Finding(
                title="Missing Slippage Protection",
                description="No `minAmountOut` or equivalent slippage check found in AMM logic.",
                severity=Severity.CRITICAL,
                category=Category.ECONOMIC_ATTACK,
                recommendation="Implement slippage tolerance mechanisms in all swap functions."
            ))
        return findings

    def check_frontrunning_resistance(self, context: AnalysisContext) -> list:
        findings = []
        if "deadline" not in context.contract_code.lower():
            findings.append(Finding(
                title="No Deadline for Transactions",
                description="Swap functions lack a deadline parameter, exposing to frontrunning attacks.",
                severity=Severity.HIGH,
                category=Category.ECONOMIC_ATTACK,
                recommendation="Add a `deadline` field to all user-initiated transactions."
            ))
        return findings

    def check_fee_skimming(self, context: AnalysisContext) -> list:
        findings = []
        if "feeTo" not in context.contract_code and "skim" not in context.contract_code.lower():
            findings.append(Finding(
                title="No Fee Skimming Mechanism",
                description="AMM does not provide for protocol fee accrual or skimming.",
                severity=Severity.MEDIUM,
                category=Category.ECONOMICS,
                recommendation="Implement feeTo/skimming logic to accrue protocol revenues safely."
            ))
        return findings

    def check_oracle_integrity(self, context: AnalysisContext) -> list:
        findings = []
        if "oracle" not in context.contract_code.lower():
            findings.append(Finding(
                title="No Oracle Integration Detected",
                description="Price feeds or manipulation resistance logic are missing.",
                severity=Severity.HIGH,
                category=Category.ORACLE,
                recommendation="Integrate robust oracle checks or TWAP oracle for price integrity."
            ))
        return findings
