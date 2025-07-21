from ..base_agent import BaseAgent, AgentMetadata, AgentType
from ...models.context import AnalysisContext, FunctionContext
from ...models.finding import Finding, Severity, Category, CodeLocation
from typing import List

class MarketplaceAgent(BaseAgent):
    def __init__(self):
        super().__init__("MarketplaceAgent")

    @property
    def metadata(self) -> AgentMetadata:
        return AgentMetadata(
            name="MarketplaceAgent",
            version="1.0.0",
            description="Analyzes NFT marketplace logic and order execution security.",
            author="NFT Security Team",
            agent_type=AgentType.NFT,
            supported_domains=["nft"]
        )

    def analyze(self, context: AnalysisContext) -> List[Finding]:
        findings = []
        for contract, funcs in context.functions.items():
            for func in funcs:
                if "executeorder" in func.name.lower() or "buy" in func.name.lower() or "sell" in func.name.lower():
                    if "require" not in func.body.lower():
                        findings.append(Finding(
                            title="Unsafe Marketplace Execution Detected",
                            description=f"Function `{func.name}` does not include access validation.",
                            severity=Severity.HIGH,
                            category=Category.ACCESS_CONTROL,
                            location=CodeLocation(contract, func.name, func.line_number),
                            recommendation="Add necessary checks using `require()` to prevent misuse.",
                            affected_contracts=[contract],
                            affected_functions=[func.name]
                        ))

        return findings
