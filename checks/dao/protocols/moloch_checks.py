import re
from ....models.finding import Finding, Severity, Category
from ....models.context import AnalysisContext

class MolochChecks:
    """
    DAO security checks for Moloch/Moloch v2 DAOs.
    """
    def run(self, context: AnalysisContext) -> list:
        findings = []
        code = context.contract_code.lower()

        if "ragequit" not in code:
            findings.append(Finding(
                title="Missing Ragequit Functionality",
                description="Moloch contracts should allow members to ragequit (leave DAO with funds).",
                category=Category.MEMBER_RIGHTS,
                severity=Severity.CRITICAL,
                recommendation="Implement `ragequit()` for member exit with proportional refund."
            ))

        if "dilutionbound" not in code:
            findings.append(Finding(
                title="Dilution Bound Not Configured",
                description="DilutionBound prevents malicious over-proposals.",
                category=Category.ECONOMICS,
                severity=Severity.HIGH,
                recommendation="Set a `dilutionBound` to limit max inflation cost on proposal queue."
            ))

        if "processproposal" not in code:
            findings.append(Finding(
                title="Missing Proposal Processing Logic",
                description="Proposals must be explicitly processed in Moloch flows.",
                category=Category.EXECUTION,
                severity=Severity.HIGH,
                recommendation="Add `processProposal()` to finalize and execute accepted proposals."
            ))

        return findings
