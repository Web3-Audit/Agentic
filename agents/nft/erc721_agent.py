from ..base_agent import BaseAgent, AgentMetadata, AgentType
from ...models.context import AnalysisContext
from ...models.finding import Finding, Severity, Category, CodeLocation
from typing import List

class ERC721Agent(BaseAgent):
    def __init__(self):
        super().__init__("ERC721Agent")

    @property
    def metadata(self) -> AgentMetadata:
        return AgentMetadata(
            name="ERC721Agent",
            version="1.0.0",
            description="Checks for ERC-721 compliance and common vulnerabilities.",
            author="NFT Security Team",
            agent_type=AgentType.NFT,
            supported_domains=["nft"]
        )

    def analyze(self, context: AnalysisContext) -> List[Finding]:
        findings = []
        code = context.contract_code.lower()
        required_functions = ["ownerof", "balanceof", "getapproved", "transferfrom", "approve"]

        for func_name in required_functions:
            if func_name not in code:
                findings.append(Finding(
                    title=f"Missing ERC721 function: {func_name}",
                    description=f"Required ERC-721 function `{func_name}` is not found.",
                    severity=Severity.HIGH,
                    category=Category.STANDARDS_COMPLIANCE,
                    recommendation=f"Implement `{func_name}` to conform to ERC-721.",
                ))

        if "onerc721received" not in code:
            findings.append(Finding(
                title="Missing ERC721 Safe Transfer Hook",
                description="onERC721Received is not implemented; safe transfers could fail.",
                severity=Severity.MEDIUM,
                category=Category.COMPATIBILITY,
                recommendation="Implement onERC721Received for safe transfer compliance.",
            ))

        return findings
