from ...models.finding import Finding, Severity, Category, CodeLocation
from ...models.context import AnalysisContext, FunctionContext

class MarketplaceGamingChecks:
    """
    Analyzes GameFi marketplace smart contracts for trade/order execution logic and security.
    """
    marketplace_keywords = ["buy", "sell", "list", "executeorder", "cancelorder", "price"]

    def run(self, context: AnalysisContext) -> list:
        findings = []

        for contract_name, functions in context.functions.items():
            for func in functions:
                func_name_lower = func.name.lower()
                func_body_lower = func.body.lower()
                if any(keyword in func_name_lower or keyword in func_body_lower for keyword in self.marketplace_keywords):
                    if "require" not in func_body_lower:
                        findings.append(Finding(
                            title="Marketplace Function Without Validation",
                            description=f"Function '{func.name}' lacks input and access validation.",
                            severity=Severity.HIGH,
                            category=Category.ACCESS_CONTROL,
                            location=CodeLocation(contract=contract_name, function=func.name, line=func.line_number),
                            recommendation="Implement strict validation and authorization in marketplace functions."
                        ))

        return findings
