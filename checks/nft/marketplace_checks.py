from ...models.finding import Finding, Severity, Category, CodeLocation
from ...models.context import AnalysisContext, FunctionContext

class MarketplaceChecks:
    """
    Analyze buy/sell/trade logic in marketplaces for pricing, access, and tamper resistance.
    """
    def run(self, context: AnalysisContext) -> list:
        findings = []
        keywords = ["buy", "sell", "order", "price", "list", "executeorder"]

        for contract_name, funcs in context.functions.items():
            for func in funcs:
                func_name = func.name.lower()
                func_body = func.body.lower()
                if any(k in func_name or k in func_body for k in keywords):
                    if "require" not in func_body:
                        findings.append(Finding(
                            title="Missing Validation in Marketplace Function",
                            description=f"Function `{func.name}` processes marketplace logic without access or input validation.",
                            severity=Severity.HIGH,
                            category=Category.BUSINESS_LOGIC,
                            location=CodeLocation(contract_name, func.name, func.line_number),
                            recommendation="Use require() or modifiers to protect marketplace logic."
                        ))

        return findings
