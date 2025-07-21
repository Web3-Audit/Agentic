from ....models.finding import Finding, Severity, Category
from ....models.context import AnalysisContext

class AxieInfinityChecks:
    """
    Protocol-specific checks for Axie Infinity smart contracts:
    breeding, cooldowns, SLP handling.
    """
    def run(self, context: AnalysisContext) -> list:
        findings = []
        code = context.contract_code.lower()

        if "breedcount" not in code:
            findings.append(Finding(
                title="Missing Breed Count Control",
                description="Breed count should limit how many times an NFT can be used to breed.",
                severity=Severity.HIGH,
                category=Category.GAME_MECHANICS,
                recommendation="Track and restrict breeding per-generation to control minting."
            ))

        if "cooldown" not in code:
            findings.append(Finding(
                title="No Breeding Cooldown Detected",
                description="Axie breeding should include time-based restrictions.",
                severity=Severity.MEDIUM,
                category=Category.GAME_MECHANICS,
                recommendation="Add cooldowns to limit breeding frequency and exploitability."
            ))

        if "slp" not in code:
            findings.append(Finding(
                title="Missing SLP Token Interaction",
                description="Smooth Love Potion (SLP) should be required and consumed during breeding/minting.",
                severity=Severity.CRITICAL,
                category=Category.TOKEN_UTILITY,
                recommendation="Ensure SLP is burned or transferred during gameplay events like breeding."
            ))

        return findings
