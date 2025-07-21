"""
Structured report models for smart contract analysis results.

These models represent the final audit report with all findings,
analysis results, and recommendations in a structured format.
"""

import json
import logging
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, field, asdict
from enum import Enum
from datetime import datetime

from .finding import Finding, FindingCollection, Severity
from .context import AnalysisContext
from .property import Property, PropertyCollection

logger = logging.getLogger(__name__)

class ReportFormat(Enum):
    """Supported report formats."""
    JSON = "json"
    HTML = "html"
    PDF = "pdf"
    MARKDOWN = "markdown"
    CSV = "csv"

class ReportType(Enum):
    """Types of audit reports."""
    FULL_AUDIT = "full_audit"
    SECURITY_FOCUSED = "security_focused"
    BUSINESS_LOGIC = "business_logic"
    CODE_QUALITY = "code_quality"
    GAS_OPTIMIZATION = "gas_optimization"
    PRELIMINARY = "preliminary"

class RiskLevel(Enum):
    """Overall risk assessment levels."""
    VERY_HIGH = "very_high"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    VERY_LOW = "very_low"

@dataclass
class ReportMetadata:
    """Metadata for the audit report."""
    report_id: str = field(default_factory=lambda: f"report_{int(datetime.now().timestamp())}")
    generated_at: datetime = field(default_factory=datetime.now)
    report_version: str = "1.0.0"
    auditor_name: Optional[str] = None
    auditor_organization: Optional[str] = None
    
    # Analysis information
    analysis_start_time: Optional[datetime] = None
    analysis_end_time: Optional[datetime] = None
    analysis_duration_seconds: Optional[float] = None
    
    # Tool information
    analyzer_version: str = "1.0.0"
    llm_model: Optional[str] = None
    checks_performed: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        result = asdict(self)
        result['generated_at'] = self.generated_at.isoformat()
        if self.analysis_start_time:
            result['analysis_start_time'] = self.analysis_start_time.isoformat()
        if self.analysis_end_time:
            result['analysis_end_time'] = self.analysis_end_time.isoformat()
        return result

@dataclass
class ExecutiveSummary:
    """Executive summary section of the report."""
    overall_risk_assessment: RiskLevel
    total_issues_found: int
    critical_issues: int
    high_issues: int
    medium_issues: int
    low_issues: int
    
    # Key findings
    major_concerns: List[str] = field(default_factory=list)
    positive_observations: List[str] = field(default_factory=list)
    
    # Recommendations
    immediate_actions: List[str] = field(default_factory=list)
    long_term_recommendations: List[str] = field(default_factory=list)
    
    # Summary text
    summary_text: str = ""
    
    def calculate_risk_score(self) -> float:
        """Calculate overall risk score based on findings."""
        if self.total_issues_found == 0:
            return 0.0
        
        # Weight different severities
        weighted_score = (
            self.critical_issues * 1.0 +
            self.high_issues * 0.7 +
            self.medium_issues * 0.4 +
            self.low_issues * 0.2
        )
        
        # Normalize to 0-1 scale
        max_possible_score = self.total_issues_found * 1.0
        return min(weighted_score / max_possible_score, 1.0) if max_possible_score > 0 else 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        result = asdict(self)
        result['overall_risk_assessment'] = self.overall_risk_assessment.value
        result['calculated_risk_score'] = self.calculate_risk_score()
        return result

@dataclass
class ContractOverview:
    """Overview of the contracts analyzed."""
    total_contracts: int
    contract_names: List[str] = field(default_factory=list)
    total_lines_of_code: int = 0
    total_functions: int = 0
    total_state_variables: int = 0
    
    # Complexity metrics
    average_cyclomatic_complexity: float = 0.0
    most_complex_contract: Optional[str] = None
    
    # Domain information
    primary_domain: Optional[str] = None
    identified_protocols: List[str] = field(default_factory=list)
    
    # Architecture overview
    inheritance_relationships: Dict[str, List[str]] = field(default_factory=dict)
    external_dependencies: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)

@dataclass
class SecurityAssessment:
    """Security assessment section."""
    # Access control
    has_access_controls: bool = False
    access_control_mechanisms: List[str] = field(default_factory=list)
    owner_privileges: List[str] = field(default_factory=list)
    
    # External interactions
    external_call_count: int = 0
    has_delegatecalls: bool = False
    oracle_dependencies: List[str] = field(default_factory=list)
    
    # Financial operations
    handles_ether: bool = False
    token_operations: List[str] = field(default_factory=list)
    
    # Upgrade mechanisms
    is_upgradeable: bool = False
    upgrade_mechanism: Optional[str] = None
    
    # Emergency controls
    has_pause_mechanism: bool = False
    emergency_functions: List[str] = field(default_factory=list)
    
    # Risk factors
    high_risk_patterns: List[str] = field(default_factory=list)
    
    def calculate_security_score(self) -> float:
        """Calculate security score based on various factors."""
        score = 1.0
        
        # Reduce score for risky patterns
        if self.has_delegatecalls:
            score -= 0.2
        if not self.has_access_controls and self.handles_ether:
            score -= 0.3
        if len(self.high_risk_patterns) > 0:
            score -= min(len(self.high_risk_patterns) * 0.1, 0.4)
        
        # Improve score for good practices
        if self.has_access_controls:
            score += 0.1
        if self.has_pause_mechanism and self.handles_ether:
            score += 0.1
        
        return max(score, 0.0)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        result = asdict(self)
        result['calculated_security_score'] = self.calculate_security_score()
        return result

@dataclass
class BusinessLogicAssessment:
    """Business logic assessment section."""
    domain: str = "unknown"
    protocol_type: Optional[str] = None
    
    # Economic model
    has_economic_model: bool = False
    tokenomics_complexity: str = "simple"  # simple, moderate, complex
    financial_risks: List[str] = field(default_factory=list)
    
    # State management
    state_complexity: str = "simple"
    critical_state_variables: List[str] = field(default_factory=list)
    state_transition_risks: List[str] = field(default_factory=list)
    
    # Integration risks
    external_protocol_dependencies: List[str] = field(default_factory=list)
    integration_risks: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)

@dataclass
class CodeQualityAssessment:
    """Code quality assessment section."""
    # Metrics
    average_function_complexity: float = 0.0
    code_coverage_estimate: float = 0.0
    documentation_coverage: float = 0.0
    
    # Best practices
    follows_naming_conventions: bool = True
    uses_established_patterns: bool = True
    has_proper_error_handling: bool = True
    
    # Issues
    code_smells: List[str] = field(default_factory=list)
    maintainability_issues: List[str] = field(default_factory=list)
    
    # Gas optimization
    gas_optimization_opportunities: List[str] = field(default_factory=list)
    estimated_gas_savings: Optional[int] = None
    
    def calculate_quality_score(self) -> float:
        """Calculate code quality score."""
        score = 0.0
        factors = 0
        
        # Documentation
        if self.documentation_coverage > 0:
            score += min(self.documentation_coverage, 1.0)
            factors += 1
        
        # Complexity
        if self.average_function_complexity > 0:
            complexity_score = max(0, 1 - (self.average_function_complexity / 10))
            score += complexity_score
            factors += 1
        
        # Best practices
        practices_score = sum([
            self.follows_naming_conventions,
            self.uses_established_patterns,
            self.has_proper_error_handling
        ]) / 3
        score += practices_score
        factors += 1
        
        return score / factors if factors > 0 else 0.5

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        result = asdict(self)
        result['calculated_quality_score'] = self.calculate_quality_score()
        return result

@dataclass
class TestingRecommendations:
    """Testing recommendations section."""
    unit_test_recommendations: List[str] = field(default_factory=list)
    integration_test_scenarios: List[str] = field(default_factory=list)
    fuzzing_targets: List[str] = field(default_factory=list)
    formal_verification_candidates: List[str] = field(default_factory=list)
    
    # Edge cases to test
    edge_cases: List[str] = field(default_factory=list)
    boundary_conditions: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)

@dataclass
class ReportSection:
    """Generic report section."""
    title: str
    content: str
    subsections: List['ReportSection'] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'title': self.title,
            'content': self.content,
            'subsections': [section.to_dict() for section in self.subsections]
        }

@dataclass
class StructuredReport:
    """
    Complete structured audit report.
    """
    # Basic information
    metadata: ReportMetadata = field(default_factory=ReportMetadata)
    report_type: ReportType = ReportType.FULL_AUDIT
    
    # Analysis context
    analysis_context: Optional[AnalysisContext] = None
    
    # Main sections
    executive_summary: Optional[ExecutiveSummary] = None
    contract_overview: Optional[ContractOverview] = None
    security_assessment: Optional[SecurityAssessment] = None
    business_logic_assessment: Optional[BusinessLogicAssessment] = None
    code_quality_assessment: Optional[CodeQualityAssessment] = None
    testing_recommendations: Optional[TestingRecommendations] = None
    
    # Findings and properties
    findings: FindingCollection = field(default_factory=FindingCollection)
    properties: PropertyCollection = field(default_factory=PropertyCollection)
    
    # Additional sections
    custom_sections: List[ReportSection] = field(default_factory=list)
    
    # Appendices
    methodology_description: str = ""
    tools_used: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    
    def add_finding(self, finding: Finding):
        """Add a finding to the report."""
        self.findings.add(finding)
        self._update_executive_summary()

    def add_property(self, property: Property):
        """Add a property to the report."""
        self.properties.add(property)

    def add_custom_section(self, title: str, content: str, subsections: List[ReportSection] = None):
        """Add a custom section to the report."""
        section = ReportSection(title=title, content=content, subsections=subsections or [])
        self.custom_sections.append(section)

    def _update_executive_summary(self):
        """Update executive summary based on current findings."""
        if not self.executive_summary:
            self.executive_summary = ExecutiveSummary(
                overall_risk_assessment=RiskLevel.MEDIUM,
                total_issues_found=0,
                critical_issues=0,
                high_issues=0,
                medium_issues=0,
                low_issues=0
            )
        
        # Count findings by severity
        severity_dist = self.findings.get_severity_distribution()
        
        self.executive_summary.total_issues_found = len(self.findings)
        self.executive_summary.critical_issues = severity_dist.get('critical', 0)
        self.executive_summary.high_issues = severity_dist.get('high', 0)
        self.executive_summary.medium_issues = severity_dist.get('medium', 0)
        self.executive_summary.low_issues = severity_dist.get('low', 0)
        
        # Update overall risk assessment
        if self.executive_summary.critical_issues > 0:
            self.executive_summary.overall_risk_assessment = RiskLevel.VERY_HIGH
        elif self.executive_summary.high_issues > 2:
            self.executive_summary.overall_risk_assessment = RiskLevel.HIGH
        elif self.executive_summary.high_issues > 0 or self.executive_summary.medium_issues > 3:
            self.executive_summary.overall_risk_assessment = RiskLevel.MEDIUM
        elif self.executive_summary.medium_issues > 0 or self.executive_summary.low_issues > 5:
            self.executive_summary.overall_risk_assessment = RiskLevel.LOW
        else:
            self.executive_summary.overall_risk_assessment = RiskLevel.VERY_LOW

    def generate_summary_statistics(self) -> Dict[str, Any]:
        """Generate comprehensive summary statistics."""
        return {
            'report_metadata': self.metadata.to_dict(),
            'findings_statistics': self.findings.get_statistics(),
            'properties_statistics': self.properties.get_statistics(),
            'executive_summary': self.executive_summary.to_dict() if self.executive_summary else None,
            'security_score': self.security_assessment.calculate_security_score() if self.security_assessment else None,
            'quality_score': self.code_quality_assessment.calculate_quality_score() if self.code_quality_assessment else None
        }

    def to_dict(self) -> Dict[str, Any]:
        """Convert entire report to dictionary."""
        result = {
            'metadata': self.metadata.to_dict(),
            'report_type': self.report_type.value,
            'executive_summary': self.executive_summary.to_dict() if self.executive_summary else None,
            'contract_overview': self.contract_overview.to_dict() if self.contract_overview else None,
            'security_assessment': self.security_assessment.to_dict() if self.security_assessment else None,
            'business_logic_assessment': self.business_logic_assessment.to_dict() if self.business_logic_assessment else None,
            'code_quality_assessment': self.code_quality_assessment.to_dict() if self.code_quality_assessment else None,
            'testing_recommendations': self.testing_recommendations.to_dict() if self.testing_recommendations else None,
            'findings': self.findings.to_dict(),
            'properties': self.properties.to_dict(),
            'custom_sections': [section.to_dict() for section in self.custom_sections],
            'methodology_description': self.methodology_description,
            'tools_used': self.tools_used,
            'references': self.references,
            'summary_statistics': self.generate_summary_statistics()
        }
        
        if self.analysis_context:
            result['analysis_context'] = self.analysis_context.to_dict()
        
        return result

    def to_json(self) -> str:
        """Convert report to JSON string."""
        return json.dumps(self.to_dict(), indent=2, default=str)

    def export_findings_summary(self) -> str:
        """Export a summary of findings in text format."""
        lines = []
        lines.append("SECURITY FINDINGS SUMMARY")
        lines.append("=" * 50)
        
        if self.executive_summary:
            lines.append(f"Overall Risk: {self.executive_summary.overall_risk_assessment.value.upper()}")
            lines.append(f"Total Issues: {self.executive_summary.total_issues_found}")
            lines.append(f"Critical: {self.executive_summary.critical_issues}")
            lines.append(f"High: {self.executive_summary.high_issues}")
            lines.append(f"Medium: {self.executive_summary.medium_issues}")
            lines.append(f"Low: {self.executive_summary.low_issues}")
            lines.append("")
        
        # Group findings by severity
        critical_findings = self.findings.get_by_severity(Severity.CRITICAL)
        high_findings = self.findings.get_by_severity(Severity.HIGH)
        
        if critical_findings:
            lines.append("CRITICAL FINDINGS:")
            lines.append("-" * 20)
            for finding in critical_findings:
                lines.append(f"• {finding.title}")
            lines.append("")
        
        if high_findings:
            lines.append("HIGH SEVERITY FINDINGS:")
            lines.append("-" * 25)
            for finding in high_findings:
                lines.append(f"• {finding.title}")
            lines.append("")
        
        return "\n".join(lines)

    @classmethod
    def create_from_analysis(cls, analysis_context: AnalysisContext, 
                           findings: List[Finding] = None,
                           properties: List[Property] = None) -> 'StructuredReport':
        """Create a structured report from analysis results."""
        report = cls()
        report.analysis_context = analysis_context
        
        # Add findings
        if findings:
            for finding in findings:
                report.add_finding(finding)
        
        # Add properties
        if properties:
            for prop in properties:
                report.add_property(prop)
        
        # Generate contract overview
        report.contract_overview = ContractOverview(
            total_contracts=len(analysis_context.contracts),
            contract_names=list(analysis_context.contracts.keys()),
            total_functions=analysis_context.total_functions_analyzed,
            total_lines_of_code=analysis_context.total_lines_analyzed,
            primary_domain=analysis_context.domain
        )
        
        # Generate security assessment
        report.security_assessment = SecurityAssessment(
            has_access_controls=len(analysis_context.security_context.access_control_mechanisms) > 0,
            access_control_mechanisms=analysis_context.security_context.access_control_mechanisms,
            external_call_count=len(analysis_context.security_context.external_calls),
            has_delegatecalls=len(analysis_context.security_context.delegatecalls) > 0,
            handles_ether=analysis_context.security_context.handles_ether,
            is_upgradeable=analysis_context.security_context.is_upgradeable,
            has_pause_mechanism=analysis_context.security_context.has_pause_mechanism
        )
        
        # Set metadata
        report.metadata.analysis_start_time = analysis_context.timestamp
        report.metadata.analyzer_version = analysis_context.analyzer_version
        report.metadata.analysis_duration_seconds = analysis_context.analysis_duration
        
        return report

    def validate(self) -> List[str]:
        """Validate the report structure and content."""
        errors = []
        
        if not self.metadata:
            errors.append("Report metadata is missing")
        
        if not self.executive_summary:
            errors.append("Executive summary is missing")
        
        if len(self.findings) == 0:
            errors.append("No findings in report")
        
        # Validate that executive summary matches findings
        if self.executive_summary:
            actual_total = len(self.findings)
            if self.executive_summary.total_issues_found != actual_total:
                errors.append(f"Executive summary total ({self.executive_summary.total_issues_found}) "
                            f"doesn't match actual findings count ({actual_total})")
        
        return errors
