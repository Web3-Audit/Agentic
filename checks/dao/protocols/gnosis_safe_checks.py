import re
from ....models.finding import Finding, Severity, Category
from ....models.context import AnalysisContext

class GnosisSafeChecks:
    """
    Gnosis Safe integration checks – ensure multi-signature wallet is secure & composable in DAO.
    """
    def run(self, context: AnalysisContext) -> list:
        findings = []
        code = context.contract_code.lower()

        if 'exectransaction' not in code and 'execute' not in code:
            findings.append(Finding(
                title="Missing Transaction Execution via Gnosis Safe",
                description="Expected function `execTransaction()` not found.",
                category=Category.EXECUTION,
                severity=Severity.CRITICAL,
                recommendation="Use `execTransaction()` from Safe contracts for secure multi-sig authorization."
            ))

        if 'owners' not in code or 'getowners' not in code:
            findings.append(Finding(
                title="No Owner Enumeration in Safe",
                description="Gnosis Safe must include ability to enumerate multisig owners.",
                category=Category.ACCESS_CONTROL,
                severity=Severity.HIGH,
                recommendation="Implement `getOwners()` and maintain owner array for SafeCoreModule."
            ))

        if 'threshold' not in code:
            findings.append(Finding(
                title="No Threshold Control in Gnosis Safe",
                description="Safe DAOs must set minimum number of signatures (threshold).",
                category=Category.CONFIGURATION,
                severity=Severity.HIGH,
                recommendation="Expose and enforce `threshold` for secure transaction approvals."
            ))

        return findings
