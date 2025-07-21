from ..base_agent import BaseAgent, AgentMetadata, AgentType
from ...models.context import AnalysisContext
from ...models.finding import Finding
from typing import List

class NFTBaseAgent(BaseAgent):
    def __init__(self):
        super().__init__("NFTBaseAgent")

    @property
    def metadata(self) -> AgentMetadata:
        return AgentMetadata(
            name="NFTBaseAgent",
            version="1.0.0",
            description="Base class for NFT-specific agents.",
            author="NFT Security Team",
            agent_type=AgentType.NFT,
            supported_domains=["nft"]
        )

    def analyze(self, context: AnalysisContext) -> List[Finding]:
        return []  # Base agent does nothing
