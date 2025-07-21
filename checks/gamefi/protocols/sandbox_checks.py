from ....models.finding import Finding, Severity, Category
from ....models.context import AnalysisContext

class SandboxChecks:
    """
    Checks for Sandbox-style metaverse mechanics:
    LAND ownership, sale events, sandbox role access.
    """
    def run(self, context: AnalysisContext) -> list:
        findings = []
        code = context.contract_code.lower()

        if "land" not in code and "settokenuri" not in code:
            findings.append(Finding(
                title="LAND Token Metadata Missing",
                description="Sandbox parcels/LAND should update metadata and reference base URIs.",
                severity=Severity.MEDIUM,
                category=Category.METADATA,
                recommendation="Set `tokenURI` with coordinates or attributes for LAND NFTs."
            ))

        if "ownable" not in code or "onlyowner" not in code:
            findings.append(Finding(
                title="No Ownership Restriction",
                description="Land claiming or transfer should include ownership checks.",
                severity=Severity.HIGH,
                category=Category.ACCESS_CONTROL,
                recommendation="Use OpenZeppelin's Ownable or custom access role restriction."
            ))

        if "sale" not in code and "claim" not in code:
            findings.append(Finding(
                title="No LAND Sale Handling",
                description="Primary/secondary LAND sale functions not found.",
                severity=Severity.MEDIUM,
                category=Category.MARKETPLACE,
                recommendation="Implement LAND claim or sale mechanisms tied to off-chain events or sales."
            ))

        return findings
