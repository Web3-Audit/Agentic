from ..base_agent import BaseAgent, AgentMetadata, AgentType
from ...models.context import AnalysisContext
from ...models.finding import Finding, Severity, Category
from typing import List

class MetadataAgent(BaseAgent):
    def __init__(self):
        super().__init__("MetadataAgent")

    @property
    def metadata(self) -> AgentMetadata:
        return AgentMetadata(
            name="MetadataAgent",
            version="1.0.0",
            description="Detects risks regarding mutable NFT metadata or unverified URIs.",
            author="NFT Security Team",
            agent_type=AgentType.NFT,
            supported_domains=["nft"]
        )

    def analyze(self, context: AnalysisContext) -> List[Finding]:
        findings = []
        code = context.contract_code.lower()

        if "settokenuri" in code or "setbaseuri" in code:
            findings.append(Finding(
                title="Mutable Token Metadata Detected",
                description="Functions that mutate token metadata are found.",
                severity=Severity.MEDIUM,
                category=Category.BUSINESS_LOGIC,
                recommendation="Only allow metadata changes via authorized roles or freeze after minting."
            ))

        if "ipfs://" not in code and "https://" not in code:
            findings.append(Finding(
                title="No Metadata Hosting Found",
                description="Token URI pattern shows no off-chain IPFS/HTTPS hosting.",
                severity=Severity.INFO,
                category=Category.METADATA,
                recommendation="Ensure metadata is hosted on IPFS or permanent trusted services."
            ))

        return findings
