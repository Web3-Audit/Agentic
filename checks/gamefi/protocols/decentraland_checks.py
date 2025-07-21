from ....models.finding import Finding, Severity, Category
from ....models.context import AnalysisContext

class DecentralandChecks:
    """
    Protocol checks for Decentraland-like virtual environments.
    Includes LAND, estate, and permission edits.
    """
    def run(self, context: AnalysisContext) -> list:
        findings = []
        code = context.contract_code.lower()

        if "estate" not in code:
            findings.append(Finding(
                title="No Estate Functionality Detected",
                description="Decentraland contracts handle grouping parcels into estates.",
                severity=Severity.MEDIUM,
                category=Category.GAME_ECONOMY,
                recommendation="Implement estate logic for multi-LAND NFTs if required."
            ))

        if "updateoperator" not in code:
            findings.append(Finding(
                title="Missing UpdateOperator Permissions",
                description="Operators should be able to modify LAND (e.g., coordinates, permissions).",
                severity=Severity.HIGH,
                category=Category.ACCESS_CONTROL,
                recommendation="Support `setUpdateOperator` or `approveOperator` to delegate control."
            ))

        if "landregistry" not in code:
            findings.append(Finding(
                title="Missing LAND Registry Contract",
                description="Missing interaction with LANDRegistry which stores LAND data.",
                severity=Severity.CRITICAL,
                category=Category.METADATA,
                recommendation="Ensure LAND NFTs are backed/accounted via a registry contract."
            ))

        return findings
