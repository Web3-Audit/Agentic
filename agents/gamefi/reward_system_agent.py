import re
from ..base_agent import BaseAgent, AgentMetadata, AgentType
from ...models.context import AnalysisContext, FunctionContext
from ...models.finding import Finding, Severity, Category, CodeLocation
from typing import List

class RewardSystemAgent(BaseAgent):
    def __init__(self):
        super().__init__("RewardSystemAgent")

    @property
    def metadata(self) -> AgentMetadata:
        return AgentMetadata(
            name="RewardSystemAgent",
            version="1.0.0",
            description="Inspects reward claiming, farming patterns or bonus logic in GameFi.",
            author="GameFi Security Team",
            agent_type=AgentType.GAMEFI,
            supported_domains=["gamefi"]
        )

    def analyze(self, context: AnalysisContext) -> List[Finding]:
        findings = []
        reward_patterns = ["claim", "reward", "harvest", "bonus", "airdrop"]

        for contract_name, function_list in context.functions.items():
            for func in function_list:
                if any(p in func.name.lower() for p in reward_patterns):
                    if not self._has_access_control(func):
                        findings.append(Finding(
                            title="Insecure Reward Function",
                            description=f"Function `{func.name}` appears to manage rewards without access control.",
                            severity=Severity.HIGH,
                            category=Category.ACCESS_CONTROL,
                            location=CodeLocation(contract=contract_name, function=func.name, line=func.line_number),
                            impact="May allow replay attacks, unauthorized reward farming.",
                            recommendation="Use roles or require statements to protect reward functions.",
                            affected_contracts=[contract_name],
                            affected_functions=[func.name]
                        ))

        return findings

    def _has_access_control(self, func: FunctionContext) -> bool:
        keywords = ["require", "onlyOwner", "hasRole", "msg.sender"]
        return any(kw in func.body for kw in keywords)
