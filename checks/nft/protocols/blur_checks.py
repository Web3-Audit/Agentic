from ....models.finding import Finding, Severity, Category
from ....models.context import AnalysisContext

class BlurChecks:
    """
    Checks for Blur NFT marketplace protocol patterns: batch listings, permit logic, and anti-wash-trading.
    """
    def run(self, context: AnalysisContext) -> list:
        findings = []
        code = context.contract_code.lower()

        if "bulk" not in code and "batch" not in code:
            findings.append(Finding(
                title="No Bulk/Batch Listing Detected",
                description="Blur enables bulk listing/mass actions; missing such logic may limit marketplace compatibility.",
                severity=Severity.MEDIUM,
                category=Category.FUNCTIONALITY,
                recommendation="Implement secure bulk listing and transfer logic with permission guards."
            ))

        if "permit" not in code:
            findings.append(Finding(
                title="Permit Functionality Not Detected",
                description="Permit pattern for gasless/approved listing not found, which is a UX standard on Blur.",
                severity=Severity.LOW,
                category=Category.USER_EXPERIENCE,
                recommendation="Add EIP-2612 permit or equivalent logic for seamless approvals and trading."
            ))

        if "anti-wash" not in code and "anti-manipulation" not in code:
            findings.append(Finding(
                title="No Anti-Wash Trading Protection",
                description="Blur employs anti-wash trading logic to preserve market fairness.",
                severity=Severity.MEDIUM,
                category=Category.MARKETPLACE,
                recommendation="Integrate protection or analytics to detect/prevent artificial trade volume."
            ))

        return findings
