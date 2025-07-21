from ...models.finding import Finding, Severity, Category
from ...models.context import AnalysisContext

class RoyaltyChecks:
    """
    Checks for support of ERC-2981 royalties and secure payout logic.
    """
    def run(self, context: AnalysisContext) -> list:
        findings = []
        code = context.contract_code.lower()

        if "royaltyinfo" not in code:
            findings.append(Finding(
                title="Missing ERC-2981 RoyaltyInfo Function",
                description="No `royaltyInfo()` function found, violating ERC-2981 royalty spec.",
                severity=Severity.HIGH,
                category=Category.STANDARDS_COMPLIANCE,
                recommendation="Implement `royaltyInfo` to support NFT royalties on marketplaces."
            ))

        if "fee" not in code and "percentage" not in code:
            findings.append(Finding(
                title="No Royalty Percentage Found",
                description="Royalty value or percentage not detected.",
                severity=Severity.MEDIUM,
                category=Category.ECONOMICS,
                recommendation="Use royalty fee logic (% of sales) and restrict max values."
            ))

        return findings
