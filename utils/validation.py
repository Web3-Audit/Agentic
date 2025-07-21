"""
Validation utilities for smart contract analysis inputs and outputs.
"""

import re
import json
import logging
from typing import Dict, List, Optional, Any, Set, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum

from ..models.context import AnalysisContext, ContractMetadata
from ..models.finding import Finding, Severity, Category
from ..models.structured_report import StructuredReport

logger = logging.getLogger(__name__)

class ValidationSeverity(Enum):
    """Severity levels for validation issues."""
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"

@dataclass
class ValidationIssue:
    """Represents a validation issue."""
    severity: ValidationSeverity
    message: str
    field: Optional[str] = None
    value: Optional[Any] = None
    suggestion: Optional[str] = None

@dataclass
class ValidationResult:
    """Result of validation process."""
    is_valid: bool
    issues: List[ValidationIssue] = field(default_factory=list)
    warnings: List[ValidationIssue] = field(default_factory=list)
    errors: List[ValidationIssue] = field(default_factory=list)
    
    def __post_init__(self):
        """Categorize issues by severity."""
        for issue in self.issues:
            if issue.severity == ValidationSeverity.ERROR:
                self.errors.append(issue)
            elif issue.severity == ValidationSeverity.WARNING:
                self.warnings.append(issue)

class InputValidator:
    """Validates input data for smart contract analysis."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def validate_source_code(self, source_code: str) -> ValidationResult:
        """
        Validate Solidity source code input.
        
        Args:
            source_code: Solidity source code to validate
            
        Returns:
            ValidationResult: Validation results
        """
        issues = []
        
        # Check if source code is provided
        if not source_code or not source_code.strip():
            issues.append(ValidationIssue(
                severity=ValidationSeverity.ERROR,
                message="Source code is empty or not provided",
                field="source_code"
            ))
            return ValidationResult(is_valid=False, issues=issues)
        
        # Check minimum length
        if len(source_code.strip()) < 50:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.WARNING,
                message="Source code seems unusually short",
                field="source_code",
                value=len(source_code)
            ))
        
        # Check for basic Solidity syntax
        if not re.search(r'\bpragma\s+solidity\b', source_code, re.IGNORECASE):
            issues.append(ValidationIssue(
                severity=ValidationSeverity.WARNING,
                message="No pragma solidity statement found",
                field="pragma",
                suggestion="Add pragma solidity version specification"
            ))
        
        # Check for contract/interface/library declaration
        if not re.search(r'\b(contract|interface|library)\s+\w+', source_code, re.IGNORECASE):
            issues.append(ValidationIssue(
                severity=ValidationSeverity.ERROR,
                message="No contract, interface, or library declaration found",
                field="contract_declaration"
            ))
        
        # Check for balanced braces
        open_braces = source_code.count('{')
        close_braces = source_code.count('}')
        if open_braces != close_braces:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.ERROR,
                message=f"Unbalanced braces: {open_braces} open, {close_braces} close",
                field="syntax"
            ))
        
        # Check for potentially dangerous patterns
        dangerous_patterns = [
            (r'\bselfdestruct\s*\(', "selfdestruct usage detected"),
            (r'\bsuicide\s*\(', "deprecated suicide function usage"),
            (r'\btx\.origin\b', "tx.origin usage detected (security risk)")
        ]
        
        for pattern, message in dangerous_patterns:
            if re.search(pattern, source_code, re.IGNORECASE):
                issues.append(ValidationIssue(
                    severity=ValidationSeverity.WARNING,
                    message=message,
                    field="security_patterns"
                ))
        
        # Check encoding
        try:
            source_code.encode('utf-8')
        except UnicodeError:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.ERROR,
                message="Source code contains invalid UTF-8 characters",
                field="encoding"
            ))
        
        is_valid = len([i for i in issues if i.severity == ValidationSeverity.ERROR]) == 0
        return ValidationResult(is_valid=is_valid, issues=issues)

    def validate_analysis_config(self, config: Dict[str, Any]) -> ValidationResult:
        """Validate analysis configuration."""
        issues = []
        
        # Check required fields
        required_fields = ['scope', 'target_networks']
        for field in required_fields:
            if field not in config:
                issues.append(ValidationIssue(
                    severity=ValidationSeverity.WARNING,
                    message=f"Missing recommended configuration field: {field}",
                    field=field
                ))
        
        # Validate scope if provided
        if 'scope' in config:
            valid_scopes = ['full', 'security_only', 'business_logic', 'code_quality']
            if config['scope'] not in valid_scopes:
                issues.append(ValidationIssue(
                    severity=ValidationSeverity.ERROR,
                    message=f"Invalid scope: {config['scope']}. Must be one of: {valid_scopes}",
                    field="scope",
                    value=config['scope']
                ))
        
        # Validate custom checks
        if 'custom_checks' in config:
            if not isinstance(config['custom_checks'], list):
                issues.append(ValidationIssue(
                    severity=ValidationSeverity.ERROR,
                    message="custom_checks must be a list",
                    field="custom_checks",
                    value=type(config['custom_checks']).__name__
                ))
        
        is_valid = len([i for i in issues if i.severity == ValidationSeverity.ERROR]) == 0
        return ValidationResult(is_valid=is_valid, issues=issues)

    def validate_file_path(self, file_path: str) -> ValidationResult:
        """Validate file path input."""
        issues = []
        
        if not file_path:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.ERROR,
                message="File path is empty",
                field="file_path"
            ))
            return ValidationResult(is_valid=False, issues=issues)
        
        # Check file extension
        valid_extensions = ['.sol', '.solidity']
        if not any(file_path.lower().endswith(ext) for ext in valid_extensions):
            issues.append(ValidationIssue(
                severity=ValidationSeverity.WARNING,
                message=f"File does not have a recognized Solidity extension: {valid_extensions}",
                field="file_extension",
                value=file_path
            ))
        
        # Check for suspicious patterns
        if '..' in file_path:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.WARNING,
                message="File path contains '..' which could indicate path traversal",
                field="file_path",
                value=file_path
            ))
        
        is_valid = len([i for i in issues if i.severity == ValidationSeverity.ERROR]) == 0
        return ValidationResult(is_valid=is_valid, issues=issues)

class ContractValidator:
    """Validates contract-specific data and metadata."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def validate_contract_metadata(self, metadata: ContractMetadata) -> ValidationResult:
        """Validate contract metadata."""
        issues = []
        
        # Check contract name
        if not metadata.name or not metadata.name.strip():
            issues.append(ValidationIssue(
                severity=ValidationSeverity.ERROR,
                message="Contract name is empty",
                field="name"
            ))
        elif not re.match(r'^[A-Za-z_][A-Za-z0-9_]*$', metadata.name):
            issues.append(ValidationIssue(
                severity=ValidationSeverity.ERROR,
                message="Contract name contains invalid characters",
                field="name",
                value=metadata.name
            ))
        
        # Check contract type
        valid_types = ['contract', 'interface', 'library']
        if metadata.contract_type.value not in valid_types:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.ERROR,
                message=f"Invalid contract type: {metadata.contract_type.value}",
                field="contract_type",
                value=metadata.contract_type.value
            ))
        
        # Check compiler version
        if metadata.compiler_version:
            if not re.match(r'^\d+\.\d+\.\d+', metadata.compiler_version):
                issues.append(ValidationIssue(
                    severity=ValidationSeverity.WARNING,
                    message="Compiler version format may be invalid",
                    field="compiler_version",
                    value=metadata.compiler_version
                ))
        
        # Check optimization runs
        if metadata.optimization_runs < 0 or metadata.optimization_runs > 10000:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.WARNING,
                message="Optimization runs value seems unusual",
                field="optimization_runs",
                value=metadata.optimization_runs
            ))
        
        # Validate addresses if provided
        if metadata.deployed_address:
            if not self._is_valid_address(metadata.deployed_address):
                issues.append(ValidationIssue(
                    severity=ValidationSeverity.ERROR,
                    message="Invalid deployed address format",
                    field="deployed_address",
                    value=metadata.deployed_address
                ))
        
        if metadata.deployer_address:
            if not self._is_valid_address(metadata.deployer_address):
                issues.append(ValidationIssue(
                    severity=ValidationSeverity.ERROR,
                    message="Invalid deployer address format",
                    field="deployer_address",
                    value=metadata.deployer_address
                ))
        
        is_valid = len([i for i in issues if i.severity == ValidationSeverity.ERROR]) == 0
        return ValidationResult(is_valid=is_valid, issues=issues)

    def validate_analysis_context(self, context: AnalysisContext) -> ValidationResult:
        """Validate analysis context."""
        issues = []
        
        # Check basic fields
        if not context.analysis_id:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.ERROR,
                message="Analysis ID is missing",
                field="analysis_id"
            ))
        
        # Check contracts
        if not context.contracts:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.WARNING,
                message="No contracts found in analysis context",
                field="contracts"
            ))
        else:
            # Validate each contract
            for contract_name, contract_metadata in context.contracts.items():
                contract_validation = self.validate_contract_metadata(contract_metadata)
                if not contract_validation.is_valid:
                    issues.extend([
                        ValidationIssue(
                            severity=issue.severity,
                            message=f"Contract '{contract_name}': {issue.message}",
                            field=f"contracts.{contract_name}.{issue.field}",
                            value=issue.value
                        )
                        for issue in contract_validation.issues
                    ])
        
        # Check function counts consistency
        declared_functions = context.total_functions_analyzed
        actual_functions = sum(len(funcs) for funcs in context.functions.values())
        if declared_functions != actual_functions:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.WARNING,
                message=f"Function count mismatch: declared {declared_functions}, actual {actual_functions}",
                field="function_count"
            ))
        
        # Check domain consistency
        if context.domain and context.domain not in ['defi', 'dao', 'nft', 'gamefi', 'utility']:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.WARNING,
                message=f"Unknown domain: {context.domain}",
                field="domain",
                value=context.domain
            ))
        
        is_valid = len([i for i in issues if i.severity == ValidationSeverity.ERROR]) == 0
        return ValidationResult(is_valid=is_valid, issues=issues)

    def _is_valid_address(self, address: str) -> bool:
        """Check if address is a valid Ethereum address."""
        if not address:
            return False
        
        # Remove 0x prefix if present
        addr = address.lower()
        if addr.startswith('0x'):
            addr = addr[2:]
        
        # Check length and hex characters
        return len(addr) == 40 and all(c in '0123456789abcdef' for c in addr)

class FindingValidator:
    """Validates finding data and quality."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def validate_finding(self, finding: Finding) -> ValidationResult:
        """Validate a single finding."""
        issues = []
        
        # Check required fields
        if not finding.title or not finding.title.strip():
            issues.append(ValidationIssue(
                severity=ValidationSeverity.ERROR,
                message="Finding title is empty",
                field="title"
            ))
        
        if not finding.description or not finding.description.strip():
            issues.append(ValidationIssue(
                severity=ValidationSeverity.ERROR,
                message="Finding description is empty",
                field="description"
            ))
        
        # Check field lengths
        if finding.title and len(finding.title) > 200:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.WARNING,
                message="Finding title is very long",
                field="title",
                value=len(finding.title)
            ))
        
        if finding.description and len(finding.description) > 5000:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.WARNING,
                message="Finding description is very long",
                field="description",
                value=len(finding.description)
            ))
        
        # Check severity and category consistency
        if finding.severity == Severity.CRITICAL and finding.category not in [
            Category.ACCESS_CONTROL, Category.REENTRANCY, Category.ARITHMETIC, Category.AUTHORIZATION
        ]:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.WARNING,
                message="Critical severity with non-critical category",
                field="severity_category_mismatch"
            ))
        
        # Check recommendation quality
        if finding.recommendation:
            if len(finding.recommendation.split()) < 5:
                issues.append(ValidationIssue(
                    severity=ValidationSeverity.WARNING,
                    message="Recommendation is very short",
                    field="recommendation"
                ))
        else:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.WARNING,
                message="No recommendation provided",
                field="recommendation"
            ))
        
        # Check code snippet
        if finding.code_snippet and len(finding.code_snippet) > 2000:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.WARNING,
                message="Code snippet is very long",
                field="code_snippet",
                value=len(finding.code_snippet)
            ))
        
        # Check finding ID format
        if finding.finding_id and not re.match(r'^[a-f0-9]{12}$', finding.finding_id):
            issues.append(ValidationIssue(
                severity=ValidationSeverity.WARNING,
                message="Finding ID format may be invalid",
                field="finding_id",
                value=finding.finding_id
            ))
        
        is_valid = len([i for i in issues if i.severity == ValidationSeverity.ERROR]) == 0
        return ValidationResult(is_valid=is_valid, issues=issues)

    def validate_findings_collection(self, findings: List[Finding]) -> ValidationResult:
        """Validate a collection of findings."""
        issues = []
        
        if not findings:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.INFO,
                message="No findings provided",
                field="findings"
            ))
            return ValidationResult(is_valid=True, issues=issues)
        
        # Check for duplicate findings
        finding_ids = [f.finding_id for f in findings if f.finding_id]
        if len(finding_ids) != len(set(finding_ids)):
            issues.append(ValidationIssue(
                severity=ValidationSeverity.WARNING,
                message="Duplicate finding IDs detected",
                field="finding_ids"
            ))
        
        # Check severity distribution
        severity_counts = {}
        for finding in findings:
            severity = finding.severity
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # Warning if too many critical findings
        if severity_counts.get(Severity.CRITICAL, 0) > 10:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.WARNING,
                message="Unusually high number of critical findings",
                field="severity_distribution",
                value=severity_counts[Severity.CRITICAL]
            ))
        
        # Validate each finding
        for i, finding in enumerate(findings):
            finding_validation = self.validate_finding(finding)
            if not finding_validation.is_valid:
                for issue in finding_validation.issues:
                    issues.append(ValidationIssue(
                        severity=issue.severity,
                        message=f"Finding {i+1}: {issue.message}",
                        field=f"findings[{i}].{issue.field}",
                        value=issue.value
                    ))
        
        is_valid = len([i for i in issues if i.severity == ValidationSeverity.ERROR]) == 0
        return ValidationResult(is_valid=is_valid, issues=issues)

class ReportValidator:
    """Validates structured report data."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.finding_validator = FindingValidator()
        self.contract_validator = ContractValidator()

    def validate_report(self, report: StructuredReport) -> ValidationResult:
        """Validate a structured report."""
        issues = []
        
        # Check metadata
        if not report.metadata:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.ERROR,
                message="Report metadata is missing",
                field="metadata"
            ))
        else:
            if not report.metadata.report_id:
                issues.append(ValidationIssue(
                    severity=ValidationSeverity.ERROR,
                    message="Report ID is missing",
                    field="metadata.report_id"
                ))
        
        # Check executive summary consistency
        if report.executive_summary and report.findings:
            declared_total = report.executive_summary.total_issues_found
            actual_total = len(report.findings)
            
            if declared_total != actual_total:
                issues.append(ValidationIssue(
                    severity=ValidationSeverity.ERROR,
                    message=f"Executive summary total ({declared_total}) doesn't match findings count ({actual_total})",
                    field="executive_summary.total_issues_found"
                ))
        
        # Validate findings
        if report.findings:
            findings_validation = self.finding_validator.validate_findings_collection(list(report.findings))
            issues.extend(findings_validation.issues)
        
        # Validate analysis context
        if report.analysis_context:
            context_validation = self.contract_validator.validate_analysis_context(report.analysis_context)
            issues.extend(context_validation.issues)
        
        # Check report completeness
        if not report.contract_overview:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.WARNING,
                message="Contract overview section is missing",
                field="contract_overview"
            ))
        
        if not report.security_assessment:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.WARNING,
                message="Security assessment section is missing",
                field="security_assessment"
            ))
        
        is_valid = len([i for i in issues if i.severity == ValidationSeverity.ERROR]) == 0
        return ValidationResult(is_valid=is_valid, issues=issues)

    def validate_report_for_export(self, report: StructuredReport) -> ValidationResult:
        """Validate report is ready for export."""
        issues = []
        
        # Basic validation first
        basic_validation = self.validate_report(report)
        issues.extend(basic_validation.issues)
        
        # Additional export-specific checks
        if not report.executive_summary:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.ERROR,
                message="Executive summary is required for export",
                field="executive_summary"
            ))
        
        if report.findings and len(report.findings) == 0:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.WARNING,
                message="Report has no findings - consider adding informational findings",
                field="findings"
            ))
        
        # Check for required sections based on findings
        if report.findings:
            has_critical_or_high = any(
                f.severity in [Severity.CRITICAL, Severity.HIGH] 
                for f in report.findings
            )
            
            if has_critical_or_high and not report.testing_recommendations:
                issues.append(ValidationIssue(
                    severity=ValidationSeverity.WARNING,
                    message="Critical/High findings present but no testing recommendations provided",
                    field="testing_recommendations"
                ))
        
        is_valid = len([i for i in issues if i.severity == ValidationSeverity.ERROR]) == 0
        return ValidationResult(is_valid=is_valid, issues=issues)

class DataSanitizer:
    """Sanitizes data for safe processing and output."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def sanitize_source_code(self, source_code: str) -> str:
        """Sanitize source code input."""
        if not source_code:
            return ""
        
        # Remove null bytes
        sanitized = source_code.replace('\x00', '')
        
        # Limit maximum length
        max_length = 1000000  # 1MB
        if len(sanitized) > max_length:
            sanitized = sanitized[:max_length]
            self.logger.warning(f"Source code truncated to {max_length} characters")
        
        return sanitized

    def sanitize_text_field(self, text: str, max_length: int = 5000) -> str:
        """Sanitize text fields."""
        if not text:
            return ""
        
        # Remove null bytes and control characters
        sanitized = ''.join(char for char in text if ord(char) >= 32 or char in '\n\t')
        
        # Truncate if too long
        if len(sanitized) > max_length:
            sanitized = sanitized[:max_length] + "..."
        
        return sanitized

    def sanitize_finding(self, finding: Finding) -> Finding:
        """Sanitize finding data."""
        finding.title = self.sanitize_text_field(finding.title, 200)
        finding.description = self.sanitize_text_field(finding.description, 5000)
        finding.impact = self.sanitize_text_field(finding.impact, 2000)
        finding.recommendation = self.sanitize_text_field(finding.recommendation, 2000)
        finding.code_snippet = self.sanitize_text_field(finding.code_snippet, 2000)
        
        return finding

    def sanitize_report(self, report: StructuredReport) -> StructuredReport:
        """Sanitize entire report."""
        # Sanitize findings
        if report.findings:
            sanitized_findings = []
            for finding in report.findings:
                sanitized_findings.append(self.sanitize_finding(finding))
            report.findings = type(report.findings)(sanitized_findings)
        
        # Sanitize other text fields
        if report.executive_summary and report.executive_summary.summary_text:
            report.executive_summary.summary_text = self.sanitize_text_field(
                report.executive_summary.summary_text, 3000
            )
        
        return report
