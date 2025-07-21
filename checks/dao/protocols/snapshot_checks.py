from ....models.finding import Finding, Severity, Category
from ....models.context import AnalysisContext

class SnapshotChecks:
    """
    Snapshot off-chain voting pattern checks.
    """
    def run(self, context: AnalysisContext) -> list:
        findings = []
        code = context.contract_code.lower()

        if "snapshot" not in code:
            findings.append(Finding(
                title="Missing Snapshot Block Consistency",
                description="DAO votes should snapshot token balances at a specific block.",
                category=Category.VOTING,
                severity=Severity.MEDIUM,
                recommendation="Enforce a consistent `snapshotBlock` to calculate voting weight."
            ))

        if "signatures" not in code and "verify" not in code:
            findings.append(Finding(
                title="No Off-Chain Signature Verification",
                description="Snapshot-based DAOs must validate user signatures off-chain.",
                category=Category.AUTHENTICATION,
                severity=Severity.HIGH,
                recommendation="Use EIP-712 or ECDSA recovery to verify off-chain votes."
            ))

        if "ipfs" not in code:
            findings.append(Finding(
                title="No IPFS Reference for Proposal",
                description="Snapshot proposals should store metadata on IPFS.",
                category=Category.CONTENT_VERIFICATION,
                severity=Severity.LOW,
                recommendation="Set an IPFS hash in each vote to ensure decentralized, verifiable content."
            ))

        return findings
