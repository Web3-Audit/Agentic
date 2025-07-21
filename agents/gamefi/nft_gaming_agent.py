import re
from ..base_agent import BaseAgent, AgentMetadata, AgentType
from ...models.context import AnalysisContext, FunctionContext
from ...models.finding import Finding, Severity, Category, CodeLocation
from typing import List

class NFTGamingAgent(BaseAgent):
    def __init__(self):
        super().__init__("NFTGamingAgent")

    @property
    def metadata(self) -> AgentMetadata:
        return AgentMetadata(
            name="NFTGamingAgent",
            version="1.0.0",
            description="Looks into NFT minting, editing, and in-game usage in GameFi.",
            author="GameFi Security Team",
            agent_type=AgentType.GAMEFI,
            supported_domains=["gamefi", "nft"]
        )

    def analyze(self, context: AnalysisContext) -> List[Finding]:
        findings = []
        nft_keywords = ["_mint", "mint", "burn", "settokenuri", "setbaseuri", "updatenft"]

        for contract_name, function_list in context.functions.items():
            for func in function_list:
                if any(word in func.name.lower() or word in func.body.lower() for word in nft_keywords):
                    findings.append(Finding(
                        title="NFT Interaction Detected",
                        description=f"Function `{func.name}` in `{contract_name}` may interact with NFTs.",
                        severity=Severity.MEDIUM,
                        category=Category.BUSINESS_LOGIC,
                        location=CodeLocation(contract=contract_name, function=func.name, line=func.line_number),
                        impact="NFT functions must include access control and metadata immutability handling.",
                        recommendation="Use access modifiers and avoid mutable metadata, unless needed.",
                        affected_contracts=[contract_name],
                        affected_functions=[func.name]
                    ))

        return findings
