import re
from ....models.finding import Finding, Severity, Category
from ....models.context import AnalysisContext

class CompoundGovernanceChecks:
    """
    Compound Governance v2+ implementations (GovernorBravo/Alpha).
    """
    def run(self, context: AnalysisContext) -> list:
        findings = []
        code = context.contract_code.lower()

        if "proposalthreshold" not in code:
            findings.append(Finding(
                title="Missing Proposal Threshold",
                description="GovernorBravo should include a `proposalThreshold()` to prevent spam.",
                category=Category.GOVERNANCE,
                severity=Severity.MEDIUM,
                recommendation="Implement a minimum proposal threshold based on token ownership."
            ))

        if "votingperiod" not in code:
            findings.append(Finding(
                title="Missing Voting Period",
                description="Compound-style voting periods should be enforced by a votingPeriod variable.",
                category=Category.VOTING,
                severity=Severity.MEDIUM,
                recommendation="Add a constant or adjustable `votingPeriod`."
            ))

        if "queue" not in code or "timelock" not in code:
            findings.append(Finding(
                title="Missing Timelock Queue",
                description="Compound proposals must queue actions in a Timelock prior to execution.",
                category=Category.EXECUTION,
                severity=Severity.CRITICAL,
                recommendation="Ensure Timelock is used to delay proposal execution after success."
            ))

        return findings
