from ..base_agent import BaseAgent, AgentMetadata, AgentType
from ...models.context import AnalysisContext
from ...models.finding import Finding, Severity, Category
from typing import List

class RoyaltyAgent(BaseAgent):
    def __init__(self):
        super().__init__("RoyaltyAgent")

    @property
    def metadata(self) -> AgentMetadata:
        return AgentMetadata(
            name="RoyaltyAgent",
            version="1.0.0",
            description="Verifies royalty logic in NFT contracts and ERC-2981 compliance.",
            author="NFT Security Team",
            agent_type=AgentType.NFT,
            supported_domains=["nft"]
        )

    def analyze(self, context: AnalysisContext) -> List[Finding]:
        code = context.contract_code.lower()
        findings = []

        if "royaltyinfo" not in code and "getroyalty" not in code:
            findings.append(Finding(
                title="Missing Royalty Support",
                description="Royalty info function not found. Consider supporting ERC-2981.",
                severity=Severity.MEDIUM,
                category=Category.STANDARDS_COMPLIANCE,
                recommendation="Implement `royaltyInfo()` function to support marketplace royalties."
            ))

        if "transfer" in code and "royalty" not in code:
            findings.append(Finding(
                title="NFT Transfer Without Any Royalties Mentioned",
                description="Transfer logic found but no signs of royalty handled.",
                severity=Severity.LOW,
                category=Category.BUSINESS_LOGIC,
                recommendation="Royalty should be considered for creator earnings on transfers."
            ))

        return findings
