from ..base_agent import BaseAgent, AgentMetadata, AgentType
from ...models.context import AnalysisContext, FunctionContext
from ...models.finding import Finding, Severity, Category, CodeLocation
from typing import List

class MintingAgent(BaseAgent):
    def __init__(self):
        super().__init__("MintingAgent")

    @property
    def metadata(self) -> AgentMetadata:
        return AgentMetadata(
            name="MintingAgent",
            version="1.0.0",
            description="Checks NFT minting logic and identifies access issues.",
            author="NFT Security Team",
            agent_type=AgentType.NFT,
            supported_domains=["nft"]
        )

    def analyze(self, context: AnalysisContext) -> List[Finding]:
        findings = []

        for contract_name, functions in context.functions.items():
            for func in functions:
                if "mint" in func.name.lower():
                    if not self._has_access_control(func):
                        findings.append(Finding(
                            title="Unprotected Mint Function",
                            description=f"Function `{func.name}` might allow unrestricted minting.",
                            severity=Severity.HIGH,
                            category=Category.ACCESS_CONTROL,
                            location=CodeLocation(contract_name, func.name, func.line_number),
                            recommendation="Mint functions should be access restricted (e.g., onlyOwner).",
                            affected_contracts=[contract_name],
                            affected_functions=[func.name]
                        ))

        return findings

    def _has_access_control(self, func: FunctionContext) -> bool:
        return any(ac in func.body for ac in ["require", "onlyOwner", "hasRole"])
