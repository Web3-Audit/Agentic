import re
from ..base_agent import BaseAgent, AgentMetadata, AgentType
from ...models.context import AnalysisContext, FunctionContext
from ...models.finding import Finding, Severity, Category, CodeLocation
from typing import List

class MarketplaceGamingAgent(BaseAgent):
    def __init__(self):
        super().__init__("MarketplaceGamingAgent")

    @property
    def metadata(self) -> AgentMetadata:
        return AgentMetadata(
            name="MarketplaceGamingAgent",
            version="1.0.0",
            description="Analyzes GameFi asset trading, price listings, and execution of orders.",
            author="GameFi Security Team",
            agent_type=AgentType.GAMEFI,
            supported_domains=["gamefi"]
        )

    def analyze(self, context: AnalysisContext) -> List[Finding]:
        findings = []
        keywords = ["buy", "bid", "sell", "order", "price", "list", "executeorder"]

        for contract_name, func_list in context.functions.items():
            for func in func_list:
                if any(k in func.name.lower() or k in func.body.lower() for k in keywords):
                    findings.append(Finding(
                        title="GameFi Marketplace Function Found",
                        description=f"Function `{func.name}` may be selling/buying assets on-chain.",
                        severity=Severity.MEDIUM,
                        category=Category.BUSINESS_LOGIC,
                        location=CodeLocation(contract=contract_name, function=func.name, line=func.line_number),
                        impact="Incorrect trade pricing or unauthorized access may lead to exploits.",
                        recommendation="Audit pricing logic, signature verification, and escrow mechanisms.",
                        affected_contracts=[contract_name],
                        affected_functions=[func.name]
                    ))

        return findings
