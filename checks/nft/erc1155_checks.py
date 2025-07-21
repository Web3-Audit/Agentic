from ...models.finding import Finding, Severity, Category
from ...models.context import AnalysisContext

class ERC1155Checks:
    """
    Verifies ERC-1155 interface compliance and batch handling.
    """
    def run(self, context: AnalysisContext) -> list:
        findings = []
        code = context.contract_code.lower()

        if "safetransferfrom" not in code or "safebatchtransferfrom" not in code:
            findings.append(Finding(
                title="Missing ERC1155 Transfer Functions",
                description="ERC1155 requires `safeTransferFrom` and `safeBatchTransferFrom`.",
                severity=Severity.HIGH,
                category=Category.STANDARDS_COMPLIANCE,
                recommendation="Implement all standard transfer functions for ERC-1155."
            ))

        if "onercc1155received" not in code:
            findings.append(Finding(
                title="Missing ERC1155 Receiver Logic",
                description="Receiver logic not implemented; transfers may fail.",
                severity=Severity.MEDIUM,
                category=Category.COMPATIBILITY,
                recommendation="Add `onERC1155Received()` to support receiving NFTs externally."
            ))

        return findings
