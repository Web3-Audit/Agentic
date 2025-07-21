from ...models.finding import Finding, Severity, Category
from ...models.context import AnalysisContext

class MetadataChecks:
    """
    Checks for dynamic or mutable metadata and off-chain risks.
    """
    def run(self, context: AnalysisContext) -> list:
        findings = []

        code = context.contract_code.lower()

        if "settokenuri" in code or "setbaseuri" in code:
            findings.append(Finding(
                title="Mutable Token Metadata Detected",
                description="Functionality for changing token URI exists. Risk of metadata tampering.",
                severity=Severity.MEDIUM,
                category=Category.METADATA,
                recommendation="Restrict metadata mutations to privileged roles or finalize post-mint."
            ))

        if "ipfs" not in code and "arweave" not in code and "https://" not in code:
            findings.append(Finding(
                title="Off-chain Metadata Hosting Not Detected",
                description="No reference to IPFS/Arweave/HTTPS links for metadata.",
                severity=Severity.LOW,
                category=Category.METADATA,
                recommendation="Use decentralized metadata hosting via IPFS/Arweave/secure HTTPS."
            ))

        return findings
