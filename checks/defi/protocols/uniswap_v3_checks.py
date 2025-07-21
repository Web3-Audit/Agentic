from ....models.finding import Finding, Severity, Category
from ....models.context import AnalysisContext

class UniswapV3Checks:
    """
    Uniswap V3-specific checks, focusing on concentrated liquidity and tick management.
    """
    def run(self, context: AnalysisContext) -> list:
        findings = []
        code = context.contract_code.lower()

        if "uniswapv3pool" not in code:
            findings.append(Finding(
                title="UniswapV3Pool Contract Missing",
                description="Uniswap V3 must use the UniswapV3Pool pattern for liquidity provision.",
                severity=Severity.CRITICAL,
                category=Category.STANDARD_COMPLIANCE,
                recommendation="Implement UniswapV3Pool logic for correct DEX functionality."
            ))

        if "ticks" not in code:
            findings.append(Finding(
                title="No Tick Management Found",
                description="Ticks are core to concentrated liquidity; none detected.",
                severity=Severity.HIGH,
                category=Category.ECONOMIC_ATTACK,
                recommendation="Ensure that ticks, tickBitmap, and their guards are correctly implemented."
            ))

        if "collect" not in code:
            findings.append(Finding(
                title="Fees Collection Missing",
                description="No collect logic to claim pool fees detected.",
                severity=Severity.MEDIUM,
                category=Category.ADMINISTRATION,
                recommendation="Add or validate the collect() handler for liquidity provider rewards."
            ))

        if "flash" not in code:
            findings.append(Finding(
                title="Flash Swap Handler Not Found",
                description="Flash swaps are a critical UniswapV3 feature.",
                severity=Severity.MEDIUM,
                category=Category.FLASH_LOAN,
                recommendation="Incorporate secure flash() logic."
            ))

        return findings
