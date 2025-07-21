import re
from ....models.finding import Finding, Severity, Category
from ....models.context import AnalysisContext

class AragonChecks:
    """
    Checks for Aragon DAO frameworks and permissions.
    """
    def run(self, context: AnalysisContext) -> list:
        findings = []
        code = context.contract_code

        if "ACL" not in code and "createPermission" not in code:
            findings.append(Finding(
                title="Missing Aragon ACL Integration",
                description="Aragon apps must integrate with ACL to manage permissions.",
                category=Category.ACCESS_CONTROL,
                severity=Severity.CRITICAL,
                recommendation="Use `createPermission()` and `grantPermission()` through ACL for safe access."
            ))

        if "appId" not in code:
            findings.append(Finding(
                title="Missing App ID Initialization",
                description="Aragon apps should include an App ID for registration.",
                category=Category.INITIALIZATION,
                severity=Severity.MEDIUM,
                recommendation="Each installed app must register with a unique app ID."
            ))

        if "kernel" not in code.lower():
            findings.append(Finding(
                title="Missing Kernel Dependency",
                description="AragonKernel must be inherited or injected.",
                category=Category.INFRASTRUCTURE,
                severity=Severity.HIGH,
                recommendation="Import AragonKernel and extend it within app controllers."
            ))

        return findings
