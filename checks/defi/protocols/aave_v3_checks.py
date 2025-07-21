from ....models.finding import Finding, Severity, Category
from ....models.context import AnalysisContext

class AaveV3Checks:
    """
    Aave V3 protocol improvements: isolation mode, efficiency mode, new oracles, and cross-chain risk.
    """
    def run(self, context: AnalysisContext) -> list:
        findings = []
        code = context.contract_code.lower()

        if "isolationmode" not in code and "emode" not in code:
            findings.append(Finding(
                title="Isolation/Efficiency Mode Not Implemented",
                description="Aave V3 introduces isolation and eMode for asset risk control; not found.",
                severity=Severity.HIGH,
                category=Category.RISK,
                recommendation="Implement IsolationMode/eMode pattern for Aave V3 compliance."
            ))

        if "priceoracle" not in code:
            findings.append(Finding(
                title="No Price Oracle Logic Detected",
                description="Aave V3 must call reliable oracles for each asset.",
                severity=Severity.CRITICAL,
                category=Category.ORACLE,
                recommendation="Connect protocol operations to decentralized oracles."
            ))

        if "flashloan" not in code or "fees" not in code:
            findings.append(Finding(
                title="Missing FlashLoan/Fee Handling",
                description="Aave V3 flash loans and fees are core to protocol operations.",
                severity=Severity.HIGH,
                category=Category.FLASH_LOAN,
                recommendation="Implement a robust and secure flashLoan interface."
            ))

        if "siloedborrowing" not in code:
            findings.append(Finding(
                title="No Siloed Borrowing Guard",
                description="Siloed (isolation) borrowing enforced per asset is not found.",
                severity=Severity.MEDIUM,
                category=Category.RISK,
                recommendation="Add and apply isolation borrower guardrails."
            ))

        return findings
