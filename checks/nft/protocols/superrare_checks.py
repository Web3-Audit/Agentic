from ....models.finding import Finding, Severity, Category
from ....models.context import AnalysisContext

class SuperRareChecks:
    """
    Checks for SuperRare protocol hooks: curation, auction periods, and royalties.
    """
    def run(self, context: AnalysisContext) -> list:
        findings = []
        code = context.contract_code.lower()

        if "curator" not in code and "curation" not in code:
            findings.append(Finding(
                title="Missing Curation Logic",
                description="SuperRare uses curators for artist and content vetting.",
                severity=Severity.LOW,
                category=Category.ACCESS_CONTROL,
                recommendation="Implement artist and curation hooks per protocol guidelines."
            ))

        if "auction" not in code or "endtime" not in code:
            findings.append(Finding(
                title="Auction Period Enforcement Not Found",
                description="SuperRare auctions require clear start/end time logic.",
                severity=Severity.HIGH,
                category=Category.AUCTION,
                recommendation="Enforce minimum and maximum auction duration parameters."
            ))

        if "royalty" not in code and "superrarefee" not in code:
            findings.append(Finding(
                title="No SuperRare Royalty Logic",
                description="SuperRare requires automatic royalty disbursements on secondary trades.",
                severity=Severity.MEDIUM,
                category=Category.REVENUE,
                recommendation="Implement protocol-defined royalty fee logic for all sales."
            ))

        return findings
