import re
from ..base_agent import BaseAgent, AgentMetadata, AgentType
from ...models.context import AnalysisContext
from ...models.finding import Finding, Severity, Category
from typing import List

class TokenEconomicsAgent(BaseAgent):
    def __init__(self):
        super().__init__("TokenEconomicsAgent")

    @property
    def metadata(self) -> AgentMetadata:
        return AgentMetadata(
            name="TokenEconomicsAgent",
            version="1.0.0",
            description="Detects inflation, deflation, and token supply changes in GameFi projects.",
            author="GameFi Security Team",
            agent_type=AgentType.GAMEFI,
            supported_domains=["gamefi"]
        )

    def analyze(self, context: AnalysisContext) -> List[Finding]:
        findings = []
        code = context.contract_code.lower()

        inflation_keywords = ["mint", "increaseSupply", "expand"]
        burn_keywords = ["burn", "decreaseSupply"]

        for word in inflation_keywords:
            if word in code:
                findings.append(Finding(
                    title="Token Inflation Mechanism Found",
                    description=f"Keyword '{word}' implies potential token inflation in contract.",
                    severity=Severity.MEDIUM,
                    category=Category.BUSINESS_LOGIC,
                    impact="Token minting might be misused if not access-controlled.",
                    recommendation="Ensure 'mint' or inflation logic is rate-limited and owner-restricted.",
                ))

        for word in burn_keywords:
            if word in code:
                findings.append(Finding(
                    title="Token Burn Mechanism Present",
                    description=f"Keyword '{word}' implies token deflation logic.",
                    severity=Severity.INFO,
                    category=Category.BUSINESS_LOGIC,
                    impact="Burn logic should be well-documented and verified.",
                    recommendation="Review token deflation model for fairness.",
                ))

        return findings
