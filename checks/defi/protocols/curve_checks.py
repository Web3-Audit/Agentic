from ....models.finding import Finding, Severity, Category
from ....models.context import AnalysisContext

class CurveChecks:
    """
    Curve Finance protocol checks: amplification factors, pools, biases, and admin.
    """
    def run(self, context: AnalysisContext) -> list:
        findings = []
        code = context.contract_code.lower()

        if "amplification" not in code and "a_parameter" not in code:
            findings.append(Finding(
                title="Missing Amplification Parameter",
                description="Curve pools require A (amplification) parameter.",
                severity=Severity.HIGH,
                category=Category.STABILITY,
                recommendation="Define A/Amplification or equivalent pool parameter."
            ))

        if "remove_liquidity" not in code:
            findings.append(Finding(
                title="No RemoveLiquidity Functionality",
                description="Curve pools allow safe removal of liquidity; function not found.",
                severity=Severity.MEDIUM,
                category=Category.LIQUIDITY,
                recommendation="Implement correct remove_liquidity handler with minAmounts checks."
            ))

        if "meta_pool" in code and "base_pool" not in code:
            findings.append(Finding(
                title="MetaPool Without BasePool Link",
                description="MetaPool detected but no basePool found; could affect migration/routing.",
                severity=Severity.MEDIUM,
                category=Category.POOL,
                recommendation="MetaPools should always reference a valid basePool."
            ))

        if "adminfee" not in code:
            findings.append(Finding(
                title="No AdminFee Logic",
                description="AdminFee required for Curve protocol revenue extraction.",
                severity=Severity.LOW,
                category=Category.ADMINISTRATION,
                recommendation="Implement fee parameter and event as in audited Curve pools."
            ))

        return findings
