from ...models.finding import Finding, Severity, Category, CodeLocation
from ...models.context import AnalysisContext, FunctionContext

class MintingChecks:
    """
    Validates safe minting logic, access control, and abuse prevention.
    """
    def run(self, context: AnalysisContext) -> list:
        findings = []
        
        for contract_name, functions in context.functions.items():
            for func in functions:
                func_name = func.name.lower()
                if "mint" in func_name:
                    if not self._has_access_control(func):
                        findings.append(Finding(
                            title="Unrestricted Mint Function",
                            description=f"Function {func.name} does not include access control.",
                            severity=Severity.CRITICAL,
                            category=Category.ACCESS_CONTROL,
                            location=CodeLocation(contract=contract_name, function=func.name, line=func.line_number),
                            recommendation="Protect minting with access modifiers like onlyOwner or roles."
                        ))

        return findings

    def _has_access_control(self, func: FunctionContext) -> bool:
        access_keywords = ["require", "onlyowner", "hasrole", "msg.sender"]
        return any(keyword in func.body.lower() for keyword in access_keywords)
