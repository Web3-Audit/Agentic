from ....models.finding import Finding, Severity, Category
from ....models.context import AnalysisContext

class FoundationChecks:
    """
    Checks for Foundation marketplace features: Reserve auctions, creators, and primary/secondary sale splits.
    """
    def run(self, context: AnalysisContext) -> list:
        findings = []
        code = context.contract_code.lower()

        if "reserveauction" not in code:
            findings.append(Finding(
                title="Reserve Auction Logic Not Found",
                description="Reserve auction mechanism is required for Foundation-style marketplaces.",
                severity=Severity.HIGH,
                category=Category.AUCTION,
                recommendation="Implement reserve auctions for primary listing and price discovery integrity."
            ))

        if "splitpayout" not in code and "split" not in code:
            findings.append(Finding(
                title="No Sale Split Logic Detected",
                description="Marketplace must handle revenue splits between team/creator/DAO addresses.",
                severity=Severity.MEDIUM,
                category=Category.REVENUE,
                recommendation="Distribute proceeds according to marketplace and creator/DAO shares."
            ))

        if "creator" not in code:
            findings.append(Finding(
                title="Creator Attribution Not Present",
                description="Creator tracking is required for proper attribution and royalties.",
                severity=Severity.LOW,
                category=Category.METADATA,
                recommendation="Track original creator address for attribution and future reward eligibility."
            ))

        return findings
