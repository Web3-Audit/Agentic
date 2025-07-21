from ....models.finding import Finding, Severity, Category
from ....models.context import AnalysisContext

class OpenSeaChecks:
    """
    Checks for OpenSea protocol and Seaport integrations, operator filtering, and meta-transactions.
    """
    def run(self, context: AnalysisContext) -> list:
        findings = []
        code = context.contract_code.lower()

        # Seaport operator filter
        if "seaport" not in code:
            findings.append(Finding(
                title="Seaport Integration Not Detected",
                description="Recommended integration with Seaport for secure, decentralized NFT trading.",
                severity=Severity.HIGH,
                category=Category.EXTERNAL_INTEGRATION,
                recommendation="Implement and properly test Seaport protocol integration for secondary market support."
            ))

        if "operatorfilter" not in code:
            findings.append(Finding(
                title="Operator Filter Registry Not Used",
                description="Contracts should implement OpenSea's Operator Filter Registry for compliance.",
                severity=Severity.MEDIUM,
                category=Category.ACCESS_CONTROL,
                recommendation="Use operator filtering to comply with OpenSea marketplace standards."
            ))

        if "meta-transaction" not in code and "relay" not in code:
            findings.append(Finding(
                title="No Meta-Transaction Support",
                description="Meta-transactions allow gasless listings, critical on OpenSea.",
                severity=Severity.LOW,
                category=Category.USER_EXPERIENCE,
                recommendation="Implement EIP-2771 (meta-transactions) for full OpenSea compatibility."
            ))

        # Royalty info via ERC-2981
        if "royaltyinfo" not in code:
            findings.append(Finding(
                title="Missing ERC-2981 Royalty Specification",
                description="RoyaltyInfo function should be implemented for OpenSea and marketplace royalty support.",
                severity=Severity.HIGH,
                category=Category.STANDARDS_COMPLIANCE,
                recommendation="Comply with ERC-2981 to ensure royalties are enforced across marketplaces."
            ))

        return findings
