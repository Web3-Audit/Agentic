from ....models.finding import Finding, Severity, Category
from ....models.context import AnalysisContext

class LooksRareChecks:
    """
    Checks for LooksRare integration patterns, custom royalty/fee logic, and reward calculation accuracy.
    """
    def run(self, context: AnalysisContext) -> list:
        findings = []
        code = context.contract_code.lower()

        if "protocolfee" not in code and "royaltyfee" not in code:
            findings.append(Finding(
                title="No Protocol Fee Detected",
                description="LooksRare requires explicit protocol fee/royalty fee logic for trades.",
                severity=Severity.MEDIUM,
                category=Category.REWARDS,
                recommendation="Implement and correctly test protocol/royalty fee calculation and disbursement."
            ))

        if "distribute" not in code and "claimreward" not in code:
            findings.append(Finding(
                title="No Marketplace Reward Distribution Detected",
                description="LooksRare encourages active trading via reward distribution.",
                severity=Severity.LOW,
                category=Category.REWARDS,
                recommendation="Integrate reward claim/distribution logic if LooksRare reward programs are used."
            ))

        if "ordervalidity" not in code and "signature" not in code:
            findings.append(Finding(
                title="Order Validation Logic Not Detected",
                description="LooksRare uses off-chain signatures for order validity and anti-fraud enforcement.",
                severity=Severity.HIGH,
                category=Category.AUTHENTICATION,
                recommendation="Add and strictly enforce ECDSA-based order signature validation."
            ))

        return findings
