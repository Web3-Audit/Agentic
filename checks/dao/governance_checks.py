import re
from ...models.finding import Finding, Severity, Category
from ...models.context import AnalysisContext, FunctionContext

class GovernanceChecks:
    """
    Checks related to DAO governance logic, including admin controls,
    multisig enforcement, quorums, and parameter change restrictions.
    """
    def __init__(self):
        self.checks = [
            self.check_multisig_enforcement,
            self.check_parameter_change_controls,
            self.check_quorum_rules,
            self.check_unauthorized_admin,
        ]

    def run(self, context: AnalysisContext) -> list:
        findings = []
        for check in self.checks:
            findings.extend(check(context))
        return findings

    def check_multisig_enforcement(self, context: AnalysisContext) -> list:
        findings = []
        code = context.contract_code.lower()
        if "multisig" not in code and "multi-sig" not in code:
            findings.append(
                Finding(
                    title="No Multisig Enforcement Detected",
                    description="Admin or governance actions may not require multisig approval.",
                    severity=Severity.HIGH,
                    category=Category.GOVERNANCE,
                    recommendation="Require multisig or time-lock for all sensitive actions."
                )
            )
        return findings

    def check_parameter_change_controls(self, context: AnalysisContext) -> list:
        findings = []
        code = context.contract_code
        param_patterns = [r'set([A-Z]\w+)\(', r'change([A-Z]\w+)\(']
        for pattern in param_patterns:
            if re.search(pattern, code):
                findings.append(
                    Finding(
                        title="Parameter Change Function Detected",
                        description="Functions allowing critical parameter changes found.",
                        severity=Severity.MEDIUM,
                        category=Category.GOVERNANCE,
                        recommendation="Require proposals and approval/quorum for all parameter updates."
                    )
                )
        return findings

    def check_quorum_rules(self, context: AnalysisContext) -> list:
        findings = []
        code = context.contract_code.lower()
        if "quorum" not in code:
            findings.append(
                Finding(
                    title="No Quorum Enforcement",
                    description="Governance actions do not require a minimum quorum.",
                    severity=Severity.HIGH,
                    category=Category.GOVERNANCE,
                    recommendation="Implement a check for minimum quorum on all votes/decisions."
                )
            )
        return findings

    def check_unauthorized_admin(self, context: AnalysisContext) -> list:
        findings = []
        code = context.contract_code.lower()
        if "onlyowner" in code or "admin" in code:
            findings.append(
                Finding(
                    title="Direct Admin Function Detected",
                    description="Admin privileges control critical logic. DAOs should not have single-owner controls.",
                    severity=Severity.MEDIUM,
                    category=Category.GOVERNANCE,
                    recommendation="Eliminate unilateral admin privileges in favor of DAO voting/quorum."
                )
            )
        return findings
