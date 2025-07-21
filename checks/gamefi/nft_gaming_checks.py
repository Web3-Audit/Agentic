import re
from ...models.finding import Finding, Severity, Category, CodeLocation
from ...models.context import AnalysisContext, FunctionContext

class NFTGamingChecks:
    """
    Inspects NFT minting, burning, metadata mutation, and ownership-related GameFi logic.
    """
    nft_keywords = ["mint", "burn", "settokenuri", "updatenft", "_mint"]

    def run(self, context: AnalysisContext) -> list:
        findings = []

        for contract_name, functions in context.functions.items():
            for func in functions:
                func_body_lower = func.body.lower()
                func_name_lower = func.name.lower()
                if any(keyword in func_name_lower or keyword in func_body_lower for keyword in self.nft_keywords):
                    findings.append(Finding(
                        title="Potential NFT Interaction",
                        description=f"Function '{func.name}' involves NFT operations (mint/burn/metadata).",
                        severity=Severity.MEDIUM,
                        category=Category.BUSINESS_LOGIC,
                        location=CodeLocation(contract=contract_name, function=func.name, line=func.line_number),
                        recommendation="Verify ownership checks and protect metadata integrity."
                    ))

        return findings
