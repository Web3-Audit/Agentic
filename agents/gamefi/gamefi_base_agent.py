from ..base_agent import BaseAgent, AgentMetadata, AgentType
from ...models.context import AnalysisContext
from ...models.finding import Finding
from typing import List

class GameFiBaseAgent(BaseAgent):
    def __init__(self):
        super().__init__("GameFiBaseAgent")

    @property
    def metadata(self) -> AgentMetadata:
        return AgentMetadata(
            name="GameFiBaseAgent",
            version="1.0.0",
            description="Base class for GameFi-related security analysis agents.",
            author="GameFi Security Team",
            agent_type=AgentType.GAMEFI,
            supported_domains=["gamefi"]
        )

    def analyze(self, context: AnalysisContext) -> List[Finding]:
        # Base class does not implement checks, serves as foundation
        return []
