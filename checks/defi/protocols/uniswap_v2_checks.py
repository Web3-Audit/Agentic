from ....models.finding import Finding, Severity, Category
from ....models.context import AnalysisContext

class UniswapV2Checks:
    """
    Uniswap V2 protocol-specific security checks.
    """
    def run(self, context: AnalysisContext) -> list:
        findings = []
        code = context.contract_code.lower()

        if "pair" not in code or "uniswapv2pair" not in code:
            findings.append(Finding(
                title="UniswapV2Pair Contract Not Located",
                description="Uniswap V2 deployments must implement the core Pair contract logic.",
                severity=Severity.CRITICAL,
                category=Category.STANDARD_COMPLIANCE,
                recommendation="Deploy UniswapV2Pair contracts conformantly for AMM pools."
            ))

        if "minamountout" not in code:
            findings.append(Finding(
                title="No Slippage Control Parameter",
                description="Missing `minAmountOut` for swap protection.",
                severity=Severity.HIGH,
                category=Category.ECONOMIC_ATTACK,
                recommendation="Implement or propagate minAmountOut to prevent sandwich attacks."
            ))

        if "skim" not in code:
            findings.append(Finding(
                title="Fee Skimming Not Detected",
                description="Fee skimming is vital for protocol revenue, but not found.",
                severity=Severity.MEDIUM,
                category=Category.ADMINISTRATION,
                recommendation="Incorporate fee skimming logic as per UniswapV2 design."
            ))

        if "getreserves" not in code:
            findings.append(Finding(
                title="No GetReserves Logic",
                description="UniswapV2Pair must expose getReserves for on-chain price oracles and TWAP.",
                severity=Severity.HIGH,
                category=Category.ORACLE,
                recommendation="Provide public/resolvable getReserves function."
            ))

        return findings
