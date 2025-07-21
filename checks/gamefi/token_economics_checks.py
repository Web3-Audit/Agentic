import re
from ...models.finding import Finding, Severity, Category
from ...models.context import AnalysisContext

class TokenEconomicsChecks:
    """
    Checks for token inflation, deflation, and supply management issues in GameFi tokens.
    """
    def run(self, context: AnalysisContext) -> list:
        findings = []
        code = context.contract_code.lower()

        inflation_keywords = ["mint", "increase_supply", "expand"]
        burn_keywords = ["burn", "decrease_supply"]

        for keyword in inflation_keywords:
            if re.search(rf'\b{keyword}\b', code):
                findings.append(Finding(
                    title="Token Inflation Logic Detected",
                    description=f"The contract contains '{keyword}' keyword indicating potential inflation risks.",
                    severity=Severity.MEDIUM,
                    category=Category.BUSINESS_LOGIC,
                    recommendation="Ensure minting functions are well controlled and only accessible to authorized parties."
                ))

        for keyword in burn_keywords:
            if re.search(rf'\b{keyword}\b', code):
                findings.append(Finding(
                    title="Token Burn Logic Detected",
                    description=f"Presence of '{keyword}' indicates token burning mechanisms.",
                    severity=Severity.INFO,
                    category=Category.BUSINESS_LOGIC,
                    recommendation="Confirm that burning is intentional and cannot be misused."
                ))

        return findings
