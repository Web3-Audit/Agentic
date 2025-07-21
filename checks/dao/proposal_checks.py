import re
from ...models.finding import Finding, Severity, Category
from ...models.context import AnalysisContext

class ProposalChecks:
    """
    Checks on DAO proposal system: creation workflow, state management, execution restrictions
    and cancellation/expiration handling.
    """
    def __init__(self):
        self.checks = [
            self.check_proposal_creation,
            self.check_proposal_state,
            self.check_execution_restrictions,
            self.check_cancellation_expiration,
        ]

    def run(self, context: AnalysisContext) -> list:
        findings = []
        for check in self.checks:
            findings.extend(check(context))
        return findings

    def check_proposal_creation(self, context: AnalysisContext) -> list:
        findings = []
        code = context.contract_code.lower()
        if "createproposal" not in code and "newproposal" not in code:
            findings.append(
                Finding(
                    title="No Proposal Creation Function Detected",
                    description="No explicit function for creating proposals found.",
                    severity=Severity.CRITICAL,
                    category=Category.GOVERNANCE,
                    recommendation="Implement a proposal creation workflow in DAO logic."
                )
            )
        return findings

    def check_proposal_state(self, context: AnalysisContext) -> list:
        findings = []
        code = context.contract_code.lower()
        if "enum" not in code or "proposalstate" not in code:
            findings.append(
                Finding(
                    title="No Proposal State Tracking",
                    description="No state machine for proposals found.",
                    severity=Severity.HIGH,
                    category=Category.GOVERNANCE,
                    recommendation="Maintain explicit state for each proposal (Active, Queued, Executed, Cancelled, etc.)."
                )
            )
        return findings

    def check_execution_restrictions(self, context: AnalysisContext) -> list:
        findings = []
        code = context.contract_code.lower()
        if "execute" in code and "require" not in code and "success" not in code:
            findings.append(
                Finding(
                    title="Insufficient Restriction on Proposal Execution",
                    description="Proposal execution may not require successful vote or status check.",
                    severity=Severity.CRITICAL,
                    category=Category.GOVERNANCE,
                    recommendation="Restrict execution functions to only proposals that pass all required checks."
                )
            )
        return findings

    def check_cancellation_expiration(self, context: AnalysisContext) -> list:
        findings = []
        code = context.contract_code.lower()
        if "cancel" not in code and "expire" not in code:
            findings.append(
                Finding(
                    title="No Proposal Cancellation or Expiry",
                    description="No logic to cancel or expire dormant/failed proposals detected.",
                    severity=Severity.MEDIUM,
                    category=Category.GOVERNANCE,
                    recommendation="Implement mechanisms to cancel or expire proposals that do not pass."
                )
            )
        return findings

