from ....models.finding import Finding, Severity, Category
from ....models.context import AnalysisContext

class STEPNChecks:
    """
    Checks for STEPN-like move-to-earn models:
    anti-bot measures, energy limits, GMT consumption.
    """
    def run(self, context: AnalysisContext) -> list:
        findings = []
        code = context.contract_code.lower()

        if "antiabot" not in code and "nobot" not in code:
            findings.append(Finding(
                title="No Anti-Bot Logic",
                description="STEPN contracts should include anti-bot mechanisms for gameplay logic.",
                severity=Severity.HIGH,
                category=Category.SECURITY,
                recommendation="Add limits or checks to prevent automated reward claiming."
            ))

        if "energy" not in code:
            findings.append(Finding(
                title="Energy Mechanism Not Detected",
                description="STEPN-like mechanics use energy caps to limit gameplay.",
                severity=Severity.MEDIUM,
                category=Category.GAME_ECONOMY,
                recommendation="Track energy usage and regenerate it over time."
            ))

        if "gmt" not in code:
            findings.append(Finding(
                title="Missing GMT Token Usage",
                description="GMT token utility is missing (e.g., upgrades, minting).",
                severity=Severity.MEDIUM,
                category=Category.TOKEN_UTILITY,
                recommendation="Incorporate GMT for in-game utility (mint caps, upgrades)."
            ))

        return findings
