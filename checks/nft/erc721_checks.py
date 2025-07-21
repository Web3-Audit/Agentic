from ...models.finding import Finding, Severity, Category
from ...models.context import AnalysisContext

class ERC721Checks:
    """
    Ensures ERC-721 compliance and common security practices.
    """
    def run(self, context: AnalysisContext) -> list:
        findings = []
        code = context.contract_code.lower()

        required_methods = ["ownerof", "balanceof", "safeTransferFrom", "approve", "getApproved"]
        for fn in required_methods:
            if fn not in code:
                findings.append(Finding(
                    title=f"Missing ERC721 Function: {fn}",
                    description=f"Required ERC-721 method `{fn}` not found in contract.",
                    severity=Severity.HIGH,
                    category=Category.STANDARDS_COMPLIANCE,
                    recommendation=f"Implement ERC-721 `{fn}` interface as specified in the standard."
                ))

        if "onerc721received" not in code:
            findings.append(Finding(
                title="Missing onERC721Received Hook",
                description="Safe transfers should implement `onERC721Received` logic.",
                severity=Severity.MEDIUM,
                category=Category.COMPATIBILITY,
                recommendation="Implement `onERC721Received()` to prevent unsafe NFT transfers."
            ))

        return findings
