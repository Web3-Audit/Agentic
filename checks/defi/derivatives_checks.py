import re
from ...models.finding import Finding, Severity, Category
from ...models.context import AnalysisContext

class DerivativesChecks:
    """
    Derivatives protocol risk checks: price oracle, leverage capping, funding calculations.
    """
    def __init__(self):
        self.checks = [
            self.check_price_oracle,
            self.check_leverage_limit,
            self.check_funding_rate_mechanism
        ]

    def run(self, context: AnalysisContext) -> list:
        findings = []
        for check in self.checks:
            findings.extend(check(context))
        return findings

    def check_price_oracle(self, context: AnalysisContext) -> list:
        findings = []
        if "oracle" not in context.contract_code.lower() and "pricefeed" not in context.contract_code.lower():
            findings.append(Finding(
                title="No Price Oracle for Derivatives",
                description="No trusted oracle found in derivatives smart contract.",
                severity=Severity.CRITICAL,
                category=Category.ORACLE,
                recommendation="A reliable oracle is required for settlement and price marking."
            ))
        return findings

    def check_leverage_limit(self, context: AnalysisContext) -> list:
        findings = []
        if "maxleverage" not in context.contract_code.lower() and "leveragecap" not in context.contract_code.lower():
            findings.append(Finding(
                title="No Leverage Cap",
                description="Unbounded leverage presents tail risk.",
                severity=Severity.HIGH,
                category=Category.RISK,
                recommendation="Explicitly limit leverage, or tie it to on-chain governance."
            ))
        return findings

    def check_funding_rate_mechanism(self, context: AnalysisContext) -> list:
        findings = []
        if "fundingrate" not in context.contract_code.lower():
            findings.append(Finding(
                title="No Funding Rate Adjustment",
                description="Funding for perpetual contracts not present.",
                severity=Severity.MEDIUM,
                category=Category.ECONOMICS,
                recommendation="Implement funding rate logic for long/short position balance."
            ))
        return findings
