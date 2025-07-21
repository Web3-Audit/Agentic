import re
from ...models.finding import Finding, Severity, Category
from ...models.context import AnalysisContext, FunctionContext

class VotingChecks:
    """
    Checks related to DAO voting: eligibility, double voting, time windows,
    and secure result tabulation.
    """
    def __init__(self):
        self.checks = [
            self.check_voting_eligibility,
            self.check_double_voting,
            self.check_voting_window,
            self.check_vote_tallying,
        ]

    def run(self, context: AnalysisContext) -> list:
        findings = []
        for check in self.checks:
            findings.extend(check(context))
        return findings

    def check_voting_eligibility(self, context: AnalysisContext) -> list:
        findings = []
        code = context.contract_code.lower()
        if "iseligible" not in code and "canvote" not in code:
            findings.append(
                Finding(
                    title="No Voting Eligibility Check Found",
                    description="Voting/participation eligibility is not explicitly enforced.",
                    severity=Severity.HIGH,
                    category=Category.VOTING,
                    recommendation="Voting functions should restrict eligibility (e.g., token holding, membership)."
                )
            )
        return findings

    def check_double_voting(self, context: AnalysisContext) -> list:
        findings = []
        code = context.contract_code.lower()
        if "hasvoted" not in code and "voted[msg.sender]" not in code:
            findings.append(
                Finding(
                    title="No Double Voting Protection",
                    description="No evidence of double-spend resistance for votes.",
                    severity=Severity.CRITICAL,
                    category=Category.VOTING,
                    recommendation="Implement state tracking to prevent multiple votes per user/proposal."
                )
            )
        return findings

    def check_voting_window(self, context: AnalysisContext) -> list:
        findings = []
        code = context.contract_code.lower()
        if "block.timestamp" not in code and "now" not in code:
            findings.append(
                Finding(
                    title="No Voting Window Enforcement Found",
                    description="Voting/approval time windows not enforced.",
                    severity=Severity.MEDIUM,
                    category=Category.VOTING,
                    recommendation="Limit all voting to well-defined start/end times."
                )
            )
        return findings

    def check_vote_tallying(self, context: AnalysisContext) -> list:
        findings = []
        code = context.contract_code
        if "tallyVotes" not in code and "countVotes" not in code:
            findings.append(
                Finding(
                    title="No Vote Tally Function Found",
                    description="Explicit vote counting/tally function not detected.",
                    severity=Severity.MEDIUM,
                    category=Category.VOTING,
                    recommendation="Implement/verify secure and auditable tally logic."
                )
            )
        return findings
