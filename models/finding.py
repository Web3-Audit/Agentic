"""
Finding models for smart contract security analysis.

These models represent security findings, vulnerabilities, and issues
discovered during smart contract analysis.
"""

import json
import logging
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, field, asdict
from enum import Enum
from datetime import datetime
import hashlib

from .context import CodeLocation

logger = logging.getLogger(__name__)

class Severity(Enum):
    """Severity levels for findings."""
    CRITICAL = "critical"
    HIGH = "high" 
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    GAS = "gas"

    def __lt__(self, other):
        """Allow sorting by severity."""
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
            Severity.GAS: 5
        }
        return severity_order[self] < severity_order[other]

class Category(Enum):
    """Categories for different types of findings."""
    # Security categories
    ACCESS_CONTROL = "access_control"
    REENTRANCY = "reentrancy"
    ARITHMETIC = "arithmetic"
    UNCHECKED_CALLS = "unchecked_calls"
    DENIAL_OF_SERVICE = "denial_of_service"
    FRONT_RUNNING = "front_running"
    TIMESTAMP_DEPENDENCE = "timestamp_dependence"
    RANDOMNESS = "randomness"
    AUTHORIZATION = "authorization"
    
    # Business logic categories
    BUSINESS_LOGIC = "business_logic"
    STATE_MANAGEMENT = "state_management"
    ECONOMIC_MODEL = "economic_model"
    INTEGRATION = "integration"
    
    # Code quality categories
    CODE_QUALITY = "code_quality"
    BEST_PRACTICES = "best_practices"
    MAINTAINABILITY = "maintainability"
    DOCUMENTATION = "documentation"
    
    # Gas optimization
    GAS_OPTIMIZATION = "gas_optimization"
    
    # Domain-specific categories
    DEFI_SPECIFIC = "defi_specific"
    DAO_SPECIFIC = "dao_specific"
    NFT_SPECIFIC = "nft_specific"
    GAMEFI_SPECIFIC = "gamefi_specific"
    
    # General
    OTHER = "other"

class ConfidenceLevel(Enum):
    """Confidence levels for automated findings."""
    VERY_HIGH = "very_high"  # 90-100%
    HIGH = "high"           # 75-90%
    MEDIUM = "medium"       # 50-75%
    LOW = "low"            # 25-50%
    VERY_LOW = "very_low"  # 0-25%

class FindingStatus(Enum):
    """Status of a finding during audit process."""
    OPEN = "open"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    FIXED = "fixed"
    ACKNOWLEDGED = "acknowledged"
    DISPUTED = "disputed"

@dataclass
class Reference:
    """External reference for a finding."""
    title: str
    url: Optional[str] = None
    description: Optional[str] = None
    reference_type: str = "general"  # swcregistry, cve, blog, documentation

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)

@dataclass
class FindingMetadata:
    """Additional metadata for a finding."""
    cwe_id: Optional[str] = None  # Common Weakness Enumeration
    swc_id: Optional[str] = None  # Smart Contract Weakness Classification
    owasp_category: Optional[str] = None
    
    # Detection metadata
    detection_method: str = "static_analysis"
    detector_name: Optional[str] = None
    detector_version: Optional[str] = None
    
    # Timing
    detected_at: datetime = field(default_factory=datetime.now)
    last_updated: datetime = field(default_factory=datetime.now)
    
    # Review information
    reviewed_by: Optional[str] = None
    review_notes: Optional[str] = None
    
    # Effort estimates
    fix_effort: Optional[str] = None  # "low", "medium", "high"
    fix_complexity: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        result = asdict(self)
        result['detected_at'] = self.detected_at.isoformat()
        result['last_updated'] = self.last_updated.isoformat()
        return result

@dataclass
class Finding:
    """
    Represents a security finding or issue in smart contract code.
    """
    # Basic information
    title: str
    description: str
    severity: Severity
    category: Category
    
    # Location information
    location: Optional[CodeLocation] = None
    affected_contracts: List[str] = field(default_factory=list)
    affected_functions: List[str] = field(default_factory=list)
    
    # Code-related
    code_snippet: str = ""
    line_numbers: List[int] = field(default_factory=list)
    
    # Impact and remediation
    impact: str = ""
    likelihood: str = ""
    recommendation: str = ""
    fix_suggestion: str = ""
    
    # References and metadata
    references: List[Reference] = field(default_factory=list)
    metadata: FindingMetadata = field(default_factory=FindingMetadata)
    
    # Analysis information
    confidence: ConfidenceLevel = ConfidenceLevel.MEDIUM
    status: FindingStatus = FindingStatus.OPEN
    
    # Identifiers
    finding_id: str = field(default="", init=False)
    
    def __post_init__(self):
        """Initialize derived fields after creation."""
        if not self.finding_id:
            self.finding_id = self._generate_finding_id()

    def _generate_finding_id(self) -> str:
        """Generate a unique finding ID based on content."""
        content = f"{self.title}_{self.category.value}_{self.location}"
        return hashlib.md5(content.encode()).hexdigest()[:12]

    def add_reference(self, title: str, url: Optional[str] = None, 
                     description: Optional[str] = None, ref_type: str = "general"):
        """Add a reference to this finding."""
        reference = Reference(
            title=title,
            url=url,
            description=description,
            reference_type=ref_type
        )
        self.references.append(reference)

    def set_cwe(self, cwe_id: str):
        """Set the CWE (Common Weakness Enumeration) ID."""
        self.metadata.cwe_id = cwe_id

    def set_swc(self, swc_id: str):
        """Set the SWC (Smart Contract Weakness Classification) ID."""
        self.metadata.swc_id = swc_id

    def update_status(self, status: FindingStatus, notes: Optional[str] = None):
        """Update finding status."""
        self.status = status
        self.metadata.last_updated = datetime.now()
        if notes:
            self.metadata.review_notes = notes

    def get_risk_score(self) -> float:
        """Calculate risk score based on severity and confidence."""
        severity_weights = {
            Severity.CRITICAL: 1.0,
            Severity.HIGH: 0.8,
            Severity.MEDIUM: 0.6,
            Severity.LOW: 0.4,
            Severity.INFO: 0.2,
            Severity.GAS: 0.1
        }
        
        confidence_weights = {
            ConfidenceLevel.VERY_HIGH: 1.0,
            ConfidenceLevel.HIGH: 0.8,
            ConfidenceLevel.MEDIUM: 0.6,
            ConfidenceLevel.LOW: 0.4,
            ConfidenceLevel.VERY_LOW: 0.2
        }
        
        severity_score = severity_weights.get(self.severity, 0.5)
        confidence_score = confidence_weights.get(self.confidence, 0.5)
        
        return severity_score * confidence_score

    def is_security_critical(self) -> bool:
        """Check if finding is security critical."""
        return (self.severity in [Severity.CRITICAL, Severity.HIGH] and 
                self.category in [
                    Category.ACCESS_CONTROL, Category.REENTRANCY, 
                    Category.ARITHMETIC, Category.AUTHORIZATION
                ])

    def is_business_logic_issue(self) -> bool:
        """Check if finding is related to business logic."""
        return self.category in [
            Category.BUSINESS_LOGIC, Category.STATE_MANAGEMENT, 
            Category.ECONOMIC_MODEL, Category.INTEGRATION
        ]

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        result = {
            'finding_id': self.finding_id,
            'title': self.title,
            'description': self.description,
            'severity': self.severity.value,
            'category': self.category.value,
            'confidence': self.confidence.value,
            'status': self.status.value,
            'affected_contracts': self.affected_contracts,
            'affected_functions': self.affected_functions,
            'code_snippet': self.code_snippet,
            'line_numbers': self.line_numbers,
            'impact': self.impact,
            'likelihood': self.likelihood,
            'recommendation': self.recommendation,
            'fix_suggestion': self.fix_suggestion,
            'references': [ref.to_dict() for ref in self.references],
            'metadata': self.metadata.to_dict(),
            'risk_score': self.get_risk_score()
        }
        
        if self.location:
            result['location'] = asdict(self.location)
        
        return result

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=2, default=str)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Finding':
        """Create Finding from dictionary."""
        # Extract location if present
        location = None
        if 'location' in data and data['location']:
            location = CodeLocation(**data['location'])
        
        # Extract metadata
        metadata_data = data.get('metadata', {})
        metadata = FindingMetadata(
            cwe_id=metadata_data.get('cwe_id'),
            swc_id=metadata_data.get('swc_id'),
            owasp_category=metadata_data.get('owasp_category'),
            detection_method=metadata_data.get('detection_method', 'static_analysis'),
            detector_name=metadata_data.get('detector_name'),
            detector_version=metadata_data.get('detector_version')
        )
        
        # Handle datetime fields
        if 'detected_at' in metadata_data:
            metadata.detected_at = datetime.fromisoformat(metadata_data['detected_at'])
        if 'last_updated' in metadata_data:
            metadata.last_updated = datetime.fromisoformat(metadata_data['last_updated'])
        
        # Extract references
        references = []
        for ref_data in data.get('references', []):
            references.append(Reference(**ref_data))
        
        finding = cls(
            title=data['title'],
            description=data['description'],
            severity=Severity(data['severity']),
            category=Category(data['category']),
            location=location,
            affected_contracts=data.get('affected_contracts', []),
            affected_functions=data.get('affected_functions', []),
            code_snippet=data.get('code_snippet', ''),
            line_numbers=data.get('line_numbers', []),
            impact=data.get('impact', ''),
            likelihood=data.get('likelihood', ''),
            recommendation=data.get('recommendation', ''),
            fix_suggestion=data.get('fix_suggestion', ''),
            references=references,
            metadata=metadata,
            confidence=ConfidenceLevel(data.get('confidence', 'medium')),
            status=FindingStatus(data.get('status', 'open'))
        )
        
        if 'finding_id' in data:
            finding.finding_id = data['finding_id']
        
        return finding

    @classmethod
    def from_json(cls, json_str: str) -> 'Finding':
        """Create Finding from JSON string."""
        data = json.loads(json_str)
        return cls.from_dict(data)

    def __str__(self) -> str:
        """String representation of the finding."""
        location_str = f" at {self.location}" if self.location else ""
        return f"[{self.severity.value.upper()}] {self.title}{location_str}"

    def __repr__(self) -> str:
        """Detailed string representation."""
        return (f"Finding(id={self.finding_id}, title='{self.title}', "
                f"severity={self.severity.value}, category={self.category.value})")

class FindingCollection:
    """Collection of findings with utility methods."""
    
    def __init__(self, findings: List[Finding] = None):
        self.findings = findings or []

    def add(self, finding: Finding):
        """Add a finding to the collection."""
        self.findings.append(finding)

    def remove(self, finding_id: str):
        """Remove a finding by ID."""
        self.findings = [f for f in self.findings if f.finding_id != finding_id]

    def get_by_id(self, finding_id: str) -> Optional[Finding]:
        """Get finding by ID."""
        for finding in self.findings:
            if finding.finding_id == finding_id:
                return finding
        return None

    def get_by_severity(self, severity: Severity) -> List[Finding]:
        """Get findings by severity level."""
        return [f for f in self.findings if f.severity == severity]

    def get_by_category(self, category: Category) -> List[Finding]:
        """Get findings by category."""
        return [f for f in self.findings if f.category == category]

    def get_by_contract(self, contract_name: str) -> List[Finding]:
        """Get findings affecting a specific contract."""
        return [f for f in self.findings if contract_name in f.affected_contracts]

    def get_security_critical(self) -> List[Finding]:
        """Get security-critical findings."""
        return [f for f in self.findings if f.is_security_critical()]

    def get_open_findings(self) -> List[Finding]:
        """Get open findings."""
        return [f for f in self.findings if f.status == FindingStatus.OPEN]

    def get_fixed_findings(self) -> List[Finding]:
        """Get fixed findings."""
        return [f for f in self.findings if f.status == FindingStatus.FIXED]

    def sort_by_severity(self) -> List[Finding]:
        """Sort findings by severity (critical first)."""
        return sorted(self.findings, key=lambda x: x.severity)

    def sort_by_risk_score(self) -> List[Finding]:
        """Sort findings by risk score (highest first)."""
        return sorted(self.findings, key=lambda x: x.get_risk_score(), reverse=True)

    def get_severity_distribution(self) -> Dict[str, int]:
        """Get distribution of findings by severity."""
        distribution = {}
        for finding in self.findings:
            severity = finding.severity.value
            distribution[severity] = distribution.get(severity, 0) + 1
        return distribution

    def get_category_distribution(self) -> Dict[str, int]:
        """Get distribution of findings by category."""
        distribution = {}
        for finding in self.findings:
            category = finding.category.value
            distribution[category] = distribution.get(category, 0) + 1
        return distribution

    def get_statistics(self) -> Dict[str, Any]:
        """Get comprehensive statistics about the findings."""
        total = len(self.findings)
        if total == 0:
            return {'total': 0}
        
        severity_dist = self.get_severity_distribution()
        category_dist = self.get_category_distribution()
        
        security_critical = len(self.get_security_critical())
        business_logic = len([f for f in self.findings if f.is_business_logic_issue()])
        
        avg_risk_score = sum(f.get_risk_score() for f in self.findings) / total
        
        return {
            'total': total,
            'severity_distribution': severity_dist,
            'category_distribution': category_dist,
            'security_critical_count': security_critical,
            'business_logic_count': business_logic,
            'average_risk_score': avg_risk_score,
            'open_findings': len(self.get_open_findings()),
            'fixed_findings': len(self.get_fixed_findings())
        }

    def to_dict(self) -> Dict[str, Any]:
        """Convert collection to dictionary."""
        return {
            'findings': [f.to_dict() for f in self.findings],
            'statistics': self.get_statistics()
        }

    def to_json(self) -> str:
        """Convert collection to JSON string."""
        return json.dumps(self.to_dict(), indent=2, default=str)

    def export_csv(self) -> str:
        """Export findings to CSV format."""
        import csv
        import io
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Header
        writer.writerow([
            'ID', 'Title', 'Severity', 'Category', 'Contract', 'Function',
            'Description', 'Impact', 'Recommendation', 'Status', 'Risk Score'
        ])
        
        # Data rows
        for finding in self.findings:
            writer.writerow([
                finding.finding_id,
                finding.title,
                finding.severity.value,
                finding.category.value,
                ', '.join(finding.affected_contracts),
                ', '.join(finding.affected_functions),
                finding.description[:200] + '...' if len(finding.description) > 200 else finding.description,
                finding.impact[:100] + '...' if len(finding.impact) > 100 else finding.impact,
                finding.recommendation[:100] + '...' if len(finding.recommendation) > 100 else finding.recommendation,
                finding.status.value,
                f"{finding.get_risk_score():.2f}"
            ])
        
        return output.getvalue()

    def __len__(self) -> int:
        """Return number of findings."""
        return len(self.findings)

    def __iter__(self):
        """Iterate over findings."""
        return iter(self.findings)

    def __getitem__(self, index) -> Finding:
        """Get finding by index."""
        return self.findings[index]
