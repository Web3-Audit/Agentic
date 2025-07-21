import re
from ...models.finding import Finding, Severity, Category
from ...models.context import AnalysisContext

class TreasuryChecks:
    """
    Checks related to DAO treasury operations: withdrawal restrictions, proposal-based allocation,
    multisig requirements, and transfer event logging.
    """
    def __init__(self):
        self.checks = [
            self.check_withdrawal_controls,
            self.check_proposal_based_spending,
            self.check_multisig_fund_release,
            self.check_transfer_logging,
        ]

    def run(self, context: AnalysisContext) -> list:
        findings = []
        for check in self.checks:
            findings.extend(check(context))
        return findings

    def check_withdrawal_controls(self, context: AnalysisContext) -> list:
        findings = []
        code = context.contract_code.lower()
        if "withdraw" in code and "require" not in code:
            findings.append(
                Finding(
                    title="Unrestricted Treasury Withdrawal",
                    description="Treasury withdrawal logic found without access or proposal control.",
                    severity=Severity.CRITICAL,
                    category=Category.TREASURY,
                    recommendation="Restrict withdrawals to successfully-passed proposals."
                )
            )
        return findings

    def check_proposal_based_spending(self, context: AnalysisContext) -> list:
        findings = []
        code = context.contract_code.lower()
        if "proposal" not in code or "approve" not in code or "execute" not in code:
            findings.append(
                Finding(
                    title="No Proposal-Based Treasury Spending",
                    description="Funds may be spent without full proposal and execution workflow.",
                    severity=Severity.HIGH,
                    category=Category.TREASURY,
                    recommendation="All treasury spending must occur through proposal approval and formal execution."
                )
            )
        return findings

    def check_multisig_fund_release(self, context: AnalysisContext) -> list:
        findings = []
        code = context.contract_code.lower()
        if "multisig" not in code:
            findings.append(
                Finding(
                    title="No Multisig on Treasury Funds",
                    description="Treasury release is not gated by multisig or equivalent multi-party mechanism.",
                    severity=Severity.HIGH,
                    category=Category.TREASURY,
                    recommendation="Implement multisig approvals for all large treasury disbursements."
                )
            )
        return findings

    def check_transfer_logging(self, context: AnalysisContext) -> list:
        findings = []
        code = context.contract_code
        if "event Transfer" not in code and "emit Transfer" not in code and "event TreasuryTransfer" not in code:
            findings.append(
                Finding(
                    title="No Treasury Transfer Event Logging",
                    description="Treasury transfers not logged with events.",
                    severity=Severity.MEDIUM,
                    category=Category.TREASURY,
                    recommendation="Emit events whenever DAO funds are moved for auditability."
                )
            )
        return findings
