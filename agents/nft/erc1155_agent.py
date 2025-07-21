from ..base_agent import BaseAgent, AgentMetadata, AgentType
from ...models.context import AnalysisContext
from ...models.finding import Finding, Severity, Category
from typing import List

class ERC1155Agent(BaseAgent):
    def __init__(self):
        super().__init__("ERC1155Agent")

    @property
    def metadata(self) -> AgentMetadata:
        return AgentMetadata(
            name="ERC1155Agent",
            version="1.0.0",
            description="Analyzes ERC-1155 token standard support and issues in NFT contracts.",
            author="NFT Security Team",
            agent_type=AgentType.NFT,
            supported_domains=["nft"]
        )

    def analyze(self, context: AnalysisContext) -> List[Finding]:
        code = context.contract_code.lower()
        findings = []

        if "safeTransferFrom".lower() not in code or "safeBatchTransferFrom".lower() not in code:
            findings.append(Finding(
                title="Missing ERC1155 Transfer Methods",
                description="safeTransferFrom or safeBatchTransferFrom not found. These are required in ERC1155.",
                severity=Severity.HIGH,
                category=Category.STANDARDS_COMPLIANCE,
                recommendation="Ensure ERC1155 functions are implemented with access and validation."
            ))

        if "onERC1155Received".lower() not in code:
            findings.append(Finding(
                title="Missing ERC1155 Receiver Handling",
                description="onERC1155Received not implemented, which may cause failures during token transfers.",
                severity=Severity.MEDIUM,
                category=Category.COMPATIBILITY,
                recommendation="Implement onERC1155Received in recipient contracts for compatibility."
            ))
        
        return findings
