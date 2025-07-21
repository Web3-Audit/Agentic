from ....models.finding import Finding, Severity, Category
from ....models.context import AnalysisContext

class AaveV2Checks:
    """
    Audit checks for Aave V2: lending pool, price oracle, interest model, and liquidation.
    """
    def run(self, context: AnalysisContext) -> list:
        findings = []
        code = context.contract_code.lower()

        if "lendingpool" not in code:
            findings.append(Finding(
                title="Missing LendingPool Interface",
                description="Aave V2 requires LendingPool for asset market and liquidity handling.",
                severity=Severity.CRITICAL,
                category=Category.LENDING,
                recommendation="Integrate LendingPool as in canonical Aave V2 design."
            ))

        if "priceoracle" not in code:
            findings.append(Finding(
                title="No PriceOracle Found",
                description="Aave V2 must consume decentralized price oracles for collateral value.",
                severity=Severity.CRITICAL,
                category=Category.ORACLE,
                recommendation="Connect to a reliable price oracle."
            ))

        if "flashloan" not in code:
            findings.append(Finding(
                title="No FlashLoan Handler Found",
                description="Aave V2 pioneered flash loans; handler missing.",
                severity=Severity.HIGH,
                category=Category.FLASH_LOAN,
                recommendation="Add a secured flashLoan logic with all relevant access checks."
            ))

        if "reserve" not in code or ("reservefactor" not in code and "configuration" not in code):
            findings.append(Finding(
                title="No Reserve Management Detected",
                description="Reserves and configuration are core to liquidation, interest and borrow safety.",
                severity=Severity.MEDIUM,
                category=Category.LIQUIDITY,
                recommendation="Implement robust reserve and risk configuration procedures."
            ))

        return findings
