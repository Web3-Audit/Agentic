"""
Structured report generation utilities for smart contract audit reports.
"""

import json
import logging
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, asdict
from datetime import datetime
from abc import ABC, abstractmethod
import base64
from pathlib import Path

from ..models.structured_report import StructuredReport, ReportFormat
from ..models.finding import Finding, Severity, FindingCollection
from ..models.context import AnalysisContext

logger = logging.getLogger(__name__)

@dataclass
class ReportConfig:
    """Configuration for report generation."""
    include_code_snippets: bool = True
    include_severity_distribution: bool = True
    include_executive_summary: bool = True
    include_technical_details: bool = True
    max_snippet_length: int = 500
    template_path: Optional[str] = None
    css_style: Optional[str] = None
    logo_path: Optional[str] = None

class ReportFormatter(ABC):
    """Abstract base class for report formatters."""
    
    @abstractmethod
    def format(self, report: StructuredReport, config: ReportConfig) -> str:
        """Format a structured report."""
        pass
    
    @abstractmethod
    def get_file_extension(self) -> str:
        """Get the file extension for this format."""
        pass

class StructuredReportGenerator:
    """
    Main report generator that coordinates different output formats.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.formatters = {
            ReportFormat.JSON: JSONReportFormatter(),
            ReportFormat.HTML: HTMLReportFormatter(),
            ReportFormat.MARKDOWN: MarkdownReportFormatter(),
            ReportFormat.PDF: PDFReportFormatter(),
            ReportFormat.CSV: CSVReportFormatter()
        }

    def generate_report(self, report: StructuredReport, format: ReportFormat, 
                       config: Optional[ReportConfig] = None) -> str:
        """
        Generate a report in the specified format.
        
        Args:
            report: The structured report to format
            format: Output format
            config: Optional configuration
            
        Returns:
            str: Formatted report content
        """
        if config is None:
            config = ReportConfig()
        
        if format not in self.formatters:
            raise ValueError(f"Unsupported report format: {format}")
        
        try:
            formatter = self.formatters[format]
            formatted_report = formatter.format(report, config)
            
            self.logger.info(f"Successfully generated {format.value} report")
            return formatted_report
            
        except Exception as e:
            self.logger.error(f"Error generating {format.value} report: {str(e)}")
            raise

    def generate_multiple_formats(self, report: StructuredReport, 
                                 formats: List[ReportFormat],
                                 config: Optional[ReportConfig] = None) -> Dict[ReportFormat, str]:
        """Generate report in multiple formats."""
        results = {}
        
        for format in formats:
            try:
                results[format] = self.generate_report(report, format, config)
            except Exception as e:
                self.logger.error(f"Failed to generate {format.value} format: {str(e)}")
                results[format] = f"Error: {str(e)}"
        
        return results

    def save_report(self, report: StructuredReport, format: ReportFormat,
                   output_path: str, config: Optional[ReportConfig] = None):
        """Save report to file."""
        formatted_report = self.generate_report(report, format, config)
        
        # Ensure proper file extension
        formatter = self.formatters[format]
        if not output_path.endswith(formatter.get_file_extension()):
            output_path += formatter.get_file_extension()
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(formatted_report)
        
        self.logger.info(f"Report saved to {output_path}")

    def get_supported_formats(self) -> List[ReportFormat]:
        """Get list of supported report formats."""
        return list(self.formatters.keys())

class JSONReportFormatter(ReportFormatter):
    """JSON report formatter."""
    
    def format(self, report: StructuredReport, config: ReportConfig) -> str:
        """Format report as JSON."""
        try:
            report_dict = report.to_dict()
            
            # Remove or truncate large fields if needed
            if not config.include_code_snippets:
                self._remove_code_snippets(report_dict)
            elif config.max_snippet_length > 0:
                self._truncate_code_snippets(report_dict, config.max_snippet_length)
            
            return json.dumps(report_dict, indent=2, default=str, ensure_ascii=False)
            
        except Exception as e:
            logger.error(f"Error formatting JSON report: {str(e)}")
            raise

    def get_file_extension(self) -> str:
        return ".json"

    def _remove_code_snippets(self, report_dict: Dict[str, Any]):
        """Remove code snippets from report."""
        if 'findings' in report_dict and 'findings' in report_dict['findings']:
            for finding in report_dict['findings']['findings']:
                finding.pop('code_snippet', None)

    def _truncate_code_snippets(self, report_dict: Dict[str, Any], max_length: int):
        """Truncate code snippets to maximum length."""
        if 'findings' in report_dict and 'findings' in report_dict['findings']:
            for finding in report_dict['findings']['findings']:
                if 'code_snippet' in finding and len(finding['code_snippet']) > max_length:
                    finding['code_snippet'] = finding['code_snippet'][:max_length] + "..."

class HTMLReportFormatter(ReportFormatter):
    """HTML report formatter with professional styling."""
    
    def format(self, report: StructuredReport, config: ReportConfig) -> str:
        """Format report as HTML."""
        try:
            html_parts = []
            
            # HTML document structure
            html_parts.append(self._generate_html_header(config))
            html_parts.append(self._generate_title_section(report))
            
            if config.include_executive_summary and report.executive_summary:
                html_parts.append(self._generate_executive_summary(report))
            
            html_parts.append(self._generate_contract_overview(report))
            html_parts.append(self._generate_findings_section(report, config))
            
            if report.security_assessment:
                html_parts.append(self._generate_security_assessment(report))
            
            if report.testing_recommendations:
                html_parts.append(self._generate_testing_recommendations(report))
            
            html_parts.append(self._generate_html_footer())
            
            return ''.join(html_parts)
            
        except Exception as e:
            logger.error(f"Error formatting HTML report: {str(e)}")
            raise

    def get_file_extension(self) -> str:
        return ".html"

    def _generate_html_header(self, config: ReportConfig) -> str:
        """Generate HTML header with CSS styling."""
        css = config.css_style or self._get_default_css()
        
        return f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Smart Contract Audit Report</title>
    <style>
        {css}
    </style>
</head>
<body>
    <div class="container">
"""

    def _get_default_css(self) -> str:
        """Get default CSS styling."""
        return """
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            line-height: 1.6; 
            margin: 0; 
            padding: 0; 
            background-color: #f8f9fa;
        }
        .container { 
            max-width: 1200px; 
            margin: 0 auto; 
            padding: 20px; 
            background-color: white;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }
        .header { 
            text-align: center; 
            border-bottom: 3px solid #007bff; 
            padding-bottom: 20px; 
            margin-bottom: 30px;
        }
        .section { 
            margin: 30px 0; 
            padding: 20px;
            border: 1px solid #e9ecef;
            border-radius: 5px;
        }
        .section h2 { 
            color: #495057; 
            border-bottom: 2px solid #dee2e6; 
            padding-bottom: 10px;
        }
        .finding { 
            margin: 15px 0; 
            padding: 15px; 
            border-left: 4px solid #6c757d; 
            background-color: #f8f9fa;
            border-radius: 0 5px 5px 0;
        }
        .finding.critical { border-left-color: #dc3545; background-color: #f8d7da; }
        .finding.high { border-left-color: #fd7e14; background-color: #ffeaa7; }
        .finding.medium { border-left-color: #ffc107; background-color: #fff3cd; }
        .finding.low { border-left-color: #28a745; background-color: #d4edda; }
        .finding.info { border-left-color: #17a2b8; background-color: #d1ecf1; }
        .severity-badge { 
            display: inline-block; 
            padding: 3px 8px; 
            border-radius: 12px; 
            font-size: 0.8em; 
            font-weight: bold; 
            text-transform: uppercase;
        }
        .severity-critical { background-color: #dc3545; color: white; }
        .severity-high { background-color: #fd7e14; color: white; }
        .severity-medium { background-color: #ffc107; color: #212529; }
        .severity-low { background-color: #28a745; color: white; }
        .severity-info { background-color: #17a2b8; color: white; }
        .code-snippet { 
            background-color: #f8f9fa; 
            border: 1px solid #e9ecef; 
            border-radius: 3px; 
            padding: 10px; 
            font-family: 'Courier New', monospace; 
            font-size: 0.9em; 
            overflow-x: auto;
            margin: 10px 0;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }
        .stat-card {
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            text-align: center;
            border: 1px solid #e9ecef;
        }
        .stat-number {
            font-size: 2em;
            font-weight: bold;
            color: #007bff;
        }
        .risk-indicator {
            padding: 10px;
            border-radius: 5px;
            margin: 10px 0;
            text-align: center;
            font-weight: bold;
        }
        .risk-very-high { background-color: #dc3545; color: white; }
        .risk-high { background-color: #fd7e14; color: white; }
        .risk-medium { background-color: #ffc107; color: #212529; }
        .risk-low { background-color: #28a745; color: white; }
        .risk-very-low { background-color: #6f42c1; color: white; }
        """

    def _generate_title_section(self, report: StructuredReport) -> str:
        """Generate title section."""
        timestamp = report.metadata.generated_at.strftime("%B %d, %Y at %H:%M UTC")
        
        return f"""
        <div class="header">
            <h1>Smart Contract Security Audit Report</h1>
            <p><strong>Generated:</strong> {timestamp}</p>
            <p><strong>Report ID:</strong> {report.metadata.report_id}</p>
            <p><strong>Analyzer Version:</strong> {report.metadata.analyzer_version}</p>
        </div>
        """

    def _generate_executive_summary(self, report: StructuredReport) -> str:
        """Generate executive summary section."""
        summary = report.executive_summary
        
        risk_class = f"risk-{summary.overall_risk_assessment.value.replace('_', '-')}"
        
        html = f"""
        <div class="section">
            <h2>Executive Summary</h2>
            <div class="risk-indicator {risk_class}">
                Overall Risk Assessment: {summary.overall_risk_assessment.value.replace('_', ' ').title()}
            </div>
            
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-number">{summary.total_issues_found}</div>
                    <div>Total Issues</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number severity-critical">{summary.critical_issues}</div>
                    <div>Critical</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number severity-high">{summary.high_issues}</div>
                    <div>High</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number severity-medium">{summary.medium_issues}</div>
                    <div>Medium</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number severity-low">{summary.low_issues}</div>
                    <div>Low</div>
                </div>
            </div>
        """
        
        if summary.major_concerns:
            html += "<h3>Major Concerns</h3><ul>"
            for concern in summary.major_concerns:
                html += f"<li>{self._escape_html(concern)}</li>"
            html += "</ul>"
        
        if summary.immediate_actions:
            html += "<h3>Immediate Actions Required</h3><ul>"
            for action in summary.immediate_actions:
                html += f"<li>{self._escape_html(action)}</li>"
            html += "</ul>"
        
        if summary.summary_text:
            html += f"<h3>Summary</h3><p>{self._escape_html(summary.summary_text)}</p>"
        
        html += "</div>"
        return html

    def _generate_contract_overview(self, report: StructuredReport) -> str:
        """Generate contract overview section."""
        if not report.contract_overview:
            return ""
        
        overview = report.contract_overview
        
        html = f"""
        <div class="section">
            <h2>Contract Overview</h2>
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-number">{overview.total_contracts}</div>
                    <div>Contracts</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{overview.total_functions}</div>
                    <div>Functions</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{overview.total_lines_of_code}</div>
                    <div>Lines of Code</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{overview.total_state_variables}</div>
                    <div>State Variables</div>
                </div>
            </div>
        """
        
        if overview.contract_names:
            html += "<h3>Analyzed Contracts</h3><ul>"
            for contract_name in overview.contract_names:
                html += f"<li><code>{self._escape_html(contract_name)}</code></li>"
            html += "</ul>"
        
        if overview.primary_domain:
            html += f"<p><strong>Primary Domain:</strong> {overview.primary_domain.title()}</p>"
        
        html += "</div>"
        return html

    def _generate_findings_section(self, report: StructuredReport, config: ReportConfig) -> str:
        """Generate findings section."""
        html = ['<div class="section"><h2>Security Findings</h2>']
        
        if not report.findings or len(report.findings) == 0:
            html.append('<p class="no-findings">No security findings detected.</p>')
        else:
            # Group findings by severity
            findings_by_severity = {}
            for finding in report.findings:
                severity = finding.severity.value
                if severity not in findings_by_severity:
                    findings_by_severity[severity] = []
                findings_by_severity[severity].append(finding)
            
            # Display in severity order
            severity_order = ['critical', 'high', 'medium', 'low', 'info']
            
            for severity in severity_order:
                if severity in findings_by_severity:
                    findings = findings_by_severity[severity]
                    html.append(f'<h3>{severity.title()} Severity ({len(findings)})</h3>')
                    
                    for finding in findings:
                        html.append(self._format_finding_html(finding, config))
        
        html.append('</div>')
        return ''.join(html)

    def _format_finding_html(self, finding: Finding, config: ReportConfig) -> str:
        """Format a single finding as HTML."""
        severity_class = f"finding {finding.severity.value}"
        severity_badge = f'<span class="severity-badge severity-{finding.severity.value}">{finding.severity.value}</span>'
        
        html = f"""
        <div class="{severity_class}">
            <h4>{self._escape_html(finding.title)} {severity_badge}</h4>
            <p><strong>Description:</strong> {self._escape_html(finding.description)}</p>
        """
        
        if finding.location:
            html += f'<p><strong>Location:</strong> {self._escape_html(str(finding.location))}</p>'
        
        if finding.affected_contracts:
            html += f'<p><strong>Affected Contracts:</strong> {", ".join(finding.affected_contracts)}</p>'
        
        if finding.impact:
            html += f'<p><strong>Impact:</strong> {self._escape_html(finding.impact)}</p>'
        
        if finding.recommendation:
            html += f'<p><strong>Recommendation:</strong> {self._escape_html(finding.recommendation)}</p>'
        
        if config.include_code_snippets and finding.code_snippet:
            snippet = finding.code_snippet
            if config.max_snippet_length > 0 and len(snippet) > config.max_snippet_length:
                snippet = snippet[:config.max_snippet_length] + "..."
            
            html += f'<div class="code-snippet"><pre><code>{self._escape_html(snippet)}</code></pre></div>'
        
        html += '</div>'
        return html

    def _generate_security_assessment(self, report: StructuredReport) -> str:
        """Generate security assessment section."""
        if not report.security_assessment:
            return ""
        
        assessment = report.security_assessment
        
        html = f"""
        <div class="section">
            <h2>Security Assessment</h2>
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-number">{len(assessment.access_control_mechanisms)}</div>
                    <div>Access Control Mechanisms</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{assessment.external_call_count}</div>
                    <div>External Calls</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{'Yes' if assessment.handles_ether else 'No'}</div>
                    <div>Handles Ether</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{'Yes' if assessment.is_upgradeable else 'No'}</div>
                    <div>Upgradeable</div>
                </div>
            </div>
        """
        
        if assessment.high_risk_patterns:
            html += "<h3>High-Risk Patterns Detected</h3><ul>"
            for pattern in assessment.high_risk_patterns:
                html += f"<li>{self._escape_html(pattern)}</li>"
            html += "</ul>"
        
        html += "</div>"
        return html

    def _generate_testing_recommendations(self, report: StructuredReport) -> str:
        """Generate testing recommendations section."""
        if not report.testing_recommendations:
            return ""
        
        testing = report.testing_recommendations
        
        html = '<div class="section"><h2>Testing Recommendations</h2>'
        
        if testing.unit_test_recommendations:
            html += "<h3>Unit Testing</h3><ul>"
            for rec in testing.unit_test_recommendations:
                html += f"<li>{self._escape_html(rec)}</li>"
            html += "</ul>"
        
        if testing.integration_test_scenarios:
            html += "<h3>Integration Testing</h3><ul>"
            for scenario in testing.integration_test_scenarios:
                html += f"<li>{self._escape_html(scenario)}</li>"
            html += "</ul>"
        
        if testing.fuzzing_targets:
            html += "<h3>Fuzzing Targets</h3><ul>"
            for target in testing.fuzzing_targets:
                html += f"<li>{self._escape_html(target)}</li>"
            html += "</ul>"
        
        html += "</div>"
        return html

    def _generate_html_footer(self) -> str:
        """Generate HTML footer."""
        return """
    </div>
</body>
</html>
"""

    def _escape_html(self, text: str) -> str:
        """Escape HTML special characters."""
        if not text:
            return ""
        
        return (text.replace('&', '&amp;')
                   .replace('<', '&lt;')
                   .replace('>', '&gt;')
                   .replace('"', '&quot;')
                   .replace("'", '&#x27;'))

class MarkdownReportFormatter(ReportFormatter):
    """Markdown report formatter."""
    
    def format(self, report: StructuredReport, config: ReportConfig) -> str:
        """Format report as Markdown."""
        try:
            md_parts = []
            
            # Title and metadata
            md_parts.append(self._generate_markdown_header(report))
            
            # Executive summary
            if config.include_executive_summary and report.executive_summary:
                md_parts.append(self._generate_markdown_executive_summary(report))
            
            # Contract overview
            md_parts.append(self._generate_markdown_contract_overview(report))
            
            # Findings
            md_parts.append(self._generate_markdown_findings(report, config))
            
            # Additional sections
            if report.security_assessment:
                md_parts.append(self._generate_markdown_security_assessment(report))
            
            return '\n\n'.join(md_parts)
            
        except Exception as e:
            logger.error(f"Error formatting Markdown report: {str(e)}")
            raise

    def get_file_extension(self) -> str:
        return ".md"

    def _generate_markdown_header(self, report: StructuredReport) -> str:
        """Generate Markdown header."""
        timestamp = report.metadata.generated_at.strftime("%B %d, %Y at %H:%M UTC")
        
        return f"""# Smart Contract Security Audit Report

**Generated:** {timestamp}  
**Report ID:** {report.metadata.report_id}  
**Analyzer Version:** {report.metadata.analyzer_version}

---"""

    def _generate_markdown_executive_summary(self, report: StructuredReport) -> str:
        """Generate Markdown executive summary."""
        summary = report.executive_summary
        
        md = f"""## Executive Summary

**Overall Risk Assessment:** {summary.overall_risk_assessment.value.replace('_', ' ').title()}

### Summary Statistics

| Severity | Count |
|----------|--------|
| Critical | {summary.critical_issues} |
| High     | {summary.high_issues} |
| Medium   | {summary.medium_issues} |
| Low      | {summary.low_issues} |
| **Total** | **{summary.total_issues_found}** |
"""
        
        if summary.major_concerns:
            md += "\n### Major Concerns\n\n"
            for concern in summary.major_concerns:
                md += f"- {concern}\n"
        
        if summary.immediate_actions:
            md += "\n### Immediate Actions Required\n\n"
            for action in summary.immediate_actions:
                md += f"- {action}\n"
        
        return md

    def _generate_markdown_contract_overview(self, report: StructuredReport) -> str:
        """Generate Markdown contract overview."""
        if not report.contract_overview:
            return "## Contract Overview\n\nNo contract overview available."
        
        overview = report.contract_overview
        
        md = f"""## Contract Overview

| Metric | Count |
|--------|--------|
| Contracts | {overview.total_contracts} |
| Functions | {overview.total_functions} |
| Lines of Code | {overview.total_lines_of_code} |
| State Variables | {overview.total_state_variables} |
"""
        
        if overview.contract_names:
            md += "\n### Analyzed Contracts\n\n"
            for contract_name in overview.contract_names:
                md += f"- `{contract_name}`\n"
        
        if overview.primary_domain:
            md += f"\n**Primary Domain:** {overview.primary_domain.title()}\n"
        
        return md

    def _generate_markdown_findings(self, report: StructuredReport, config: ReportConfig) -> str:
        """Generate Markdown findings section."""
        md = ["## Security Findings"]
        
        if not report.findings or len(report.findings) == 0:
            md.append("No security findings detected.")
            return '\n\n'.join(md)
        
        # Group by severity
        findings_by_severity = {}
        for finding in report.findings:
            severity = finding.severity.value
            if severity not in findings_by_severity:
                findings_by_severity[severity] = []
            findings_by_severity[severity].append(finding)
        
        severity_order = ['critical', 'high', 'medium', 'low', 'info']
        
        for severity in severity_order:
            if severity in findings_by_severity:
                findings = findings_by_severity[severity]
                md.append(f"### {severity.title()} Severity ({len(findings)})")
                
                for i, finding in enumerate(findings, 1):
                    md.append(self._format_finding_markdown(finding, i, config))
        
        return '\n\n'.join(md)

    def _format_finding_markdown(self, finding: Finding, index: int, config: ReportConfig) -> str:
        """Format a single finding as Markdown."""
        md = f"""#### {index}. {finding.title}

**Severity:** {finding.severity.value.upper()}

**Description:** {finding.description}
"""
        
        if finding.location:
            md += f"\n**Location:** {finding.location}\n"
        
        if finding.affected_contracts:
            md += f"\n**Affected Contracts:** {', '.join(finding.affected_contracts)}\n"
        
        if finding.impact:
            md += f"\n**Impact:** {finding.impact}\n"
        
        if finding.recommendation:
            md += f"\n**Recommendation:** {finding.recommendation}\n"
        
        if config.include_code_snippets and finding.code_snippet:
            snippet = finding.code_snippet
            if config.max_snippet_length > 0 and len(snippet) > config.max_snippet_length:
                snippet = snippet[:config.max_snippet_length] + "..."
            
            md += f"\n**Code:**\n``````\n"
        
        return md

    def _generate_markdown_security_assessment(self, report: StructuredReport) -> str:
        """Generate Markdown security assessment."""
        if not report.security_assessment:
            return ""
        
        assessment = report.security_assessment
        
        md = f"""## Security Assessment

| Security Aspect | Status/Count |
|-----------------|--------------|
| Access Control Mechanisms | {len(assessment.access_control_mechanisms)} |
| External Calls | {assessment.external_call_count} |
| Handles Ether | {'Yes' if assessment.handles_ether else 'No'} |
| Upgradeable | {'Yes' if assessment.is_upgradeable else 'No'} |
| Has Pause Mechanism | {'Yes' if assessment.has_pause_mechanism else 'No'} |
"""
        
        if assessment.high_risk_patterns:
            md += "\n### High-Risk Patterns Detected\n\n"
            for pattern in assessment.high_risk_patterns:
                md += f"- {pattern}\n"
        
        return md

class CSVReportFormatter(ReportFormatter):
    """CSV report formatter for findings data."""
    
    def format(self, report: StructuredReport, config: ReportConfig) -> str:
        """Format findings as CSV."""
        try:
            import csv
            import io
            
            output = io.StringIO()
            writer = csv.writer(output)
            
            # Header
            writer.writerow([
                'Finding ID', 'Title', 'Severity', 'Category', 'Contract', 
                'Function', 'Description', 'Impact', 'Recommendation', 
                'Location', 'Risk Score'
            ])
            
            # Data rows
            if report.findings:
                for finding in report.findings:
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
                        str(finding.location) if finding.location else '',
                        f"{finding.get_risk_score():.2f}"
                    ])
            
            return output.getvalue()
            
        except Exception as e:
            logger.error(f"Error formatting CSV report: {str(e)}")
            raise

    def get_file_extension(self) -> str:
        return ".csv"

class PDFReportFormatter(ReportFormatter):
    """PDF report formatter."""
    
    def format(self, report: StructuredReport, config: ReportConfig) -> str:
        """Format report as PDF (returns base64 encoded PDF)."""
        try:
            # First generate HTML
            html_formatter = HTMLReportFormatter()
            html_content = html_formatter.format(report, config)
            
            # Convert HTML to PDF using weasyprint or similar
            # For now, return HTML content with instructions
            pdf_note = """
            <!-- PDF Generation Note -->
            <!-- To generate actual PDF, install weasyprint: pip install weasyprint -->
            <!-- Then use: weasyprint.HTML(string=html_content).write_pdf('report.pdf') -->
            """
            
            return pdf_note + html_content
            
        except Exception as e:
            logger.error(f"Error formatting PDF report: {str(e)}")
            raise

    def get_file_extension(self) -> str:
        return ".pdf"

class ReportTemplateManager:
    """Manages report templates for customization."""
    
    def __init__(self, template_dir: Optional[str] = None):
        self.template_dir = template_dir or "templates"
        self.templates = {}

    def load_template(self, template_name: str, format: ReportFormat) -> str:
        """Load a custom template."""
        template_path = Path(self.template_dir) / f"{template_name}.{format.value}"
        
        if template_path.exists():
            with open(template_path, 'r', encoding='utf-8') as f:
                return f.read()
        
        raise FileNotFoundError(f"Template not found: {template_path}")

    def save_template(self, template_name: str, format: ReportFormat, content: str):
        """Save a custom template."""
        template_path = Path(self.template_dir) / f"{template_name}.{format.value}"
        template_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(template_path, 'w', encoding='utf-8') as f:
            f.write(content)

class ReportExporter:
    """Utility class for exporting reports to various destinations."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def export_to_file(self, report_content: str, output_path: str):
        """Export report content to file."""
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(report_content)
        
        self.logger.info(f"Report exported to {output_path}")

    def export_to_multiple_files(self, reports: Dict[ReportFormat, str], base_path: str):
        """Export multiple report formats to files."""
        for format, content in reports.items():
            formatter = StructuredReportGenerator().formatters[format]
            output_path = base_path + formatter.get_file_extension()
            self.export_to_file(content, output_path)

    def compress_reports(self, reports: Dict[ReportFormat, str], output_path: str):
        """Compress multiple reports into a ZIP file."""
        import zipfile
        
        with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            generator = StructuredReportGenerator()
            
            for format, content in reports.items():
                formatter = generator.formatters[format]
                filename = f"audit_report{formatter.get_file_extension()}"
                zipf.writestr(filename, content)
        
        self.logger.info(f"Reports compressed to {output_path}")

