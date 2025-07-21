"""
Response parser for extracting structured information from LLM responses.
"""

import json
import re
import logging
from typing import Dict, List, Optional, Any, Union, Tuple
from dataclasses import dataclass, field
from enum import Enum

from ..models.finding import Finding, Severity
from ..models.structured_report import StructuredReport

logger = logging.getLogger(__name__)

class ResponseFormat(Enum):
    JSON = "json"
    MARKDOWN = "markdown"  
    TEXT = "text"
    STRUCTURED = "structured"

@dataclass
class ParsedResponse:
    """Parsed response from LLM."""
    raw_response: str
    format: ResponseFormat
    structured_data: Optional[Dict[str, Any]] = None
    findings: List[Finding] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    confidence: float = 1.0
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class ValidationResult:
    """Result of response validation."""
    is_valid: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

class ResponseParser:
    """
    Parses and validates LLM responses into structured formats.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Regex patterns for parsing
        self.patterns = {
            'json_block': r'``````',
            'code_block': r'``````', 
            'severity_pattern': r'\*\*Severity\*\*:?\s*(Critical|High|Medium|Low|Info)',
            'title_pattern': r'\*\*Title\*\*:?\s*(.+)',
            'description_pattern': r'\*\*Description\*\*:?\s*(.*?)(?=\*\*|$)',
            'location_pattern': r'\*\*Location\*\*:?\s*(.+)',
            'impact_pattern': r'\*\*Impact\*\*:?\s*(.*?)(?=\*\*|$)',
            'recommendation_pattern': r'\*\*Recommendation\*\*:?\s*(.*?)(?=\*\*|$)',
            'confidence_pattern': r'(?:confidence|score).*?([0-9]+(?:\.[0-9]+)?)',
            'finding_separator': r'(?:##\s*\d+|#{2,3}\s*Finding|#{2,3}\s*Issue)'
        }
        
        # Compile patterns for performance
        self.compiled_patterns = {
            name: re.compile(pattern, re.DOTALL | re.IGNORECASE)
            for name, pattern in self.patterns.items()
        }

    def parse_response(self, response: str, expected_format: ResponseFormat = ResponseFormat.JSON) -> ParsedResponse:
        """
        Parse LLM response into structured format.
        
        Args:
            response: Raw LLM response text
            expected_format: Expected response format
            
        Returns:
            ParsedResponse: Parsed and structured response
        """
        try:
            parsed = ParsedResponse(
                raw_response=response,
                format=expected_format
            )
            
            # Clean the response
            cleaned_response = self._clean_response(response)
            
            if expected_format == ResponseFormat.JSON:
                parsed = self._parse_json_response(cleaned_response, parsed)
            elif expected_format == ResponseFormat.MARKDOWN:
                parsed = self._parse_markdown_response(cleaned_response, parsed)
            elif expected_format == ResponseFormat.STRUCTURED:
                parsed = self._parse_structured_response(cleaned_response, parsed)
            else:
                parsed.structured_data = {'content': cleaned_response}
            
            # Extract common metadata
            parsed.metadata = self._extract_metadata(response)
            
            # Validate the parsed response
            validation = self._validate_response(parsed)
            if not validation.is_valid:
                parsed.errors.extend(validation.errors)
                self.logger.warning(f"Response validation failed: {validation.errors}")
            
            self.logger.info(f"Successfully parsed response with {len(parsed.findings)} findings")
            return parsed
            
        except Exception as e:
            self.logger.error(f"Error parsing response: {str(e)}")
            return ParsedResponse(
                raw_response=response,
                format=expected_format,
                errors=[f"Parsing error: {str(e)}"]
            )

    def _clean_response(self, response: str) -> str:
        """Clean and normalize the response text."""
        # Remove common LLM artifacts
        cleaned = response.strip()
        
        # Remove leading/trailing quotes if present
        if cleaned.startswith(('"""', "'''")):
            cleaned = cleaned[3:-3] if cleaned.endswith(('"""', "'''")) else cleaned[3:]
        elif cleaned.startswith(('"', "'")):
            cleaned = cleaned[1:-1] if cleaned.endswith(('"', "'")) else cleaned[1:]
        
        # Normalize whitespace
        cleaned = re.sub(r'\n\s*\n\s*\n', '\n\n', cleaned)
        
        return cleaned

    def _parse_json_response(self, response: str, parsed: ParsedResponse) -> ParsedResponse:
        """Parse JSON formatted response."""
        try:
            # Try to extract JSON from code blocks first
            json_match = self.compiled_patterns['json_block'].search(response)
            if json_match:
                json_str = json_match.group(1)
            else:
                json_str = response
            
            # Parse JSON
            parsed.structured_data = json.loads(json_str)
            
            # Convert to findings if it's a vulnerability analysis
            if self._is_vulnerability_response(parsed.structured_data):
                parsed.findings = self._convert_json_to_findings(parsed.structured_data)
            
            # Extract confidence if present
            if isinstance(parsed.structured_data, dict) and 'confidence' in parsed.structured_data:
                parsed.confidence = float(parsed.structured_data['confidence'])
            
        except json.JSONDecodeError as e:
            parsed.errors.append(f"JSON parsing error: {str(e)}")
            # Try to extract partial JSON or fallback to text parsing
            parsed = self._fallback_text_parsing(response, parsed)
        
        return parsed

    def _parse_markdown_response(self, response: str, parsed: ParsedResponse) -> ParsedResponse:
        """Parse markdown formatted response."""
        # Split response into sections
        sections = self._split_markdown_sections(response)
        parsed.structured_data = {'sections': sections}
        
        # Extract findings from markdown
        findings = self._extract_markdown_findings(response)
        parsed.findings = findings
        
        return parsed

    def _parse_structured_response(self, response: str, parsed: ParsedResponse) -> ParsedResponse:
        """Parse structured text response with specific patterns."""
        # Try JSON first, then markdown, then text parsing
        try:
            return self._parse_json_response(response, parsed)
        except:
            try:
                return self._parse_markdown_response(response, parsed)
            except:
                return self._parse_text_findings(response, parsed)

    def _split_markdown_sections(self, text: str) -> Dict[str, str]:
        """Split markdown text into sections by headers."""
        sections = {}
        current_section = None
        current_content = []
        
        for line in text.split('\n'):
            # Check for markdown headers
            if line.startswith('#'):
                # Save previous section
                if current_section:
                    sections[current_section] = '\n'.join(current_content).strip()
                
                # Start new section
                current_section = line.lstrip('#').strip()
                current_content = []
            else:
                current_content.append(line)
        
        # Save last section
        if current_section:
            sections[current_section] = '\n'.join(current_content).strip()
        
        return sections

    def _extract_markdown_findings(self, text: str) -> List[Finding]:
        """Extract findings from markdown formatted text."""
        findings = []
        
        # Split by finding separators
        finding_blocks = self.compiled_patterns['finding_separator'].split(text)
        
        for block in finding_blocks[1:]:  # Skip first empty block
            finding = self._parse_finding_block(block)
            if finding:
                findings.append(finding)
        
        return findings

    def _parse_finding_block(self, block: str) -> Optional[Finding]:
        """Parse a single finding block."""
        try:
            # Extract severity
            severity_match = self.compiled_patterns['severity_pattern'].search(block)
            severity = Severity.MEDIUM  # Default
            if severity_match:
                severity_str = severity_match.group(1).upper()
                severity = Severity[severity_str] if severity_str in Severity.__members__ else Severity.MEDIUM
            
            # Extract title
            title_match = self.compiled_patterns['title_pattern'].search(block)
            title = title_match.group(1).strip() if title_match else "Untitled Finding"
            
            # Extract description
            desc_match = self.compiled_patterns['description_pattern'].search(block)
            description = desc_match.group(1).strip() if desc_match else ""
            
            # Extract location
            location_match = self.compiled_patterns['location_pattern'].search(block)
            location = location_match.group(1).strip() if location_match else ""
            
            # Extract impact
            impact_match = self.compiled_patterns['impact_pattern'].search(block)
            impact = impact_match.group(1).strip() if impact_match else ""
            
            # Extract recommendation  
            rec_match = self.compiled_patterns['recommendation_pattern'].search(block)
            recommendation = rec_match.group(1).strip() if rec_match else ""
            
            # Extract code snippet
            code_match = self.compiled_patterns['code_block'].search(block)
            code_snippet = code_match.group(1).strip() if code_match else ""
            
            # Create finding
            finding = Finding(
                title=title,
                severity=severity,
                description=description,
                location=location,
                impact=impact,
                recommendation=recommendation,
                code_snippet=code_snippet,
                category="Security"  # Default category
            )
            
            return finding
            
        except Exception as e:
            self.logger.error(f"Error parsing finding block: {str(e)}")
            return None

    def _parse_text_findings(self, response: str, parsed: ParsedResponse) -> ParsedResponse:
        """Parse findings from unstructured text."""
        findings = []
        
        # Look for common vulnerability keywords and patterns
        vulnerability_patterns = [
            r'(?:reentrancy|re-entrancy)(?:\s+attack|\s+vulnerability)?',
            r'integer\s+overflow',
            r'access\s+control',
            r'unchecked\s+call',
            r'gas\s+limit',
            r'timestamp\s+dependence',
            r'tx\.origin',
            r'denial\s+of\s+service'
        ]
        
        for i, pattern in enumerate(vulnerability_patterns):
            matches = re.finditer(pattern, response, re.IGNORECASE)
            for match in matches:
                # Extract context around the match
                start = max(0, match.start() - 200)
                end = min(len(response), match.end() + 200)
                context = response[start:end]
                
                finding = Finding(
                    title=f"Potential {match.group().title()} Issue",
                    severity=Severity.MEDIUM,
                    description=context,
                    location="Unknown",
                    category="Security"
                )
                findings.append(finding)
        
        parsed.findings = findings
        parsed.structured_data = {'content': response}
        
        return parsed

    def _is_vulnerability_response(self, data: Any) -> bool:
        """Check if JSON data represents vulnerability findings."""
        if isinstance(data, list):
            return all(self._is_finding_dict(item) for item in data[:3])  # Check first 3 items
        elif isinstance(data, dict):
            return 'findings' in data or self._is_finding_dict(data)
        return False

    def _is_finding_dict(self, data: Dict) -> bool:
        """Check if dictionary represents a finding."""
        finding_keys = {'severity', 'title', 'description', 'impact', 'recommendation'}
        return isinstance(data, dict) and any(key in data for key in finding_keys)

    def _convert_json_to_findings(self, data: Any) -> List[Finding]:
        """Convert JSON data to Finding objects."""
        findings = []
        
        if isinstance(data, list):
            # Array of findings
            for item in data:
                if isinstance(item, dict):
                    finding = self._dict_to_finding(item)
                    if finding:
                        findings.append(finding)
        elif isinstance(data, dict):
            if 'findings' in data:
                # Findings are nested in 'findings' key
                return self._convert_json_to_findings(data['findings'])
            else:
                # Single finding object
                finding = self._dict_to_finding(data)
                if finding:
                    findings.append(finding)
        
        return findings

    def _dict_to_finding(self, data: Dict) -> Optional[Finding]:
        """Convert dictionary to Finding object."""
        try:
            # Map severity string to enum
            severity_str = data.get('severity', 'medium').upper()
            severity = Severity[severity_str] if severity_str in Severity.__members__ else Severity.MEDIUM
            
            finding = Finding(
                title=data.get('title', 'Untitled Finding'),
                severity=severity,
                description=data.get('description', ''),
                location=data.get('location', ''),
                impact=data.get('impact', ''),
                recommendation=data.get('recommendation', ''),
                code_snippet=data.get('code_snippet', data.get('code', '')),
                category=data.get('category', 'Security'),
                references=data.get('references', [])
            )
            
            return finding
            
        except Exception as e:
            self.logger.error(f"Error converting dict to finding: {str(e)}")
            return None

    def _extract_metadata(self, response: str) -> Dict[str, Any]:
        """Extract metadata from response."""
        metadata = {}
        
        # Extract confidence score
        confidence_match = self.compiled_patterns['confidence_pattern'].search(response)
        if confidence_match:
            try:
                metadata['confidence'] = float(confidence_match.group(1))
            except ValueError:
                pass
        
        # Extract word count and reading time
        word_count = len(response.split())
        metadata['word_count'] = word_count
        metadata['estimated_reading_time'] = max(1, word_count // 200)  # Rough estimate
        
        # Extract code blocks count
        code_blocks = self.compiled_patterns['code_block'].findall(response)
        metadata['code_blocks_count'] = len(code_blocks)
        
        # Extract JSON blocks count
        json_blocks = self.compiled_patterns['json_block'].findall(response)
        metadata['json_blocks_count'] = len(json_blocks)
        
        return metadata

    def _validate_response(self, parsed: ParsedResponse) -> ValidationResult:
        """Validate parsed response for completeness and correctness."""
        errors = []
        warnings = []
        
        # Check if response has content
        if not parsed.raw_response.strip():
            errors.append("Empty response")
        
        # Validate findings
        if parsed.findings:
            for i, finding in enumerate(parsed.findings):
                if not finding.title:
                    warnings.append(f"Finding {i+1} missing title")
                if not finding.description:
                    warnings.append(f"Finding {i+1} missing description") 
                if not finding.recommendation:
                    warnings.append(f"Finding {i+1} missing recommendation")
        
        # Validate structured data
        if parsed.format == ResponseFormat.JSON and not parsed.structured_data:
            errors.append("Expected JSON format but no structured data extracted")
        
        # Check confidence score
        if parsed.confidence < 0 or parsed.confidence > 1:
            warnings.append("Confidence score outside valid range [0,1]")
        
        return ValidationResult(
            is_valid=len(errors) == 0,
            errors=errors,
            warnings=warnings
        )

    def _fallback_text_parsing(self, response: str, parsed: ParsedResponse) -> ParsedResponse:
        """Fallback text parsing when JSON fails."""
        # Try to extract any JSON-like structures
        potential_jsons = re.findall(r'\{[^{}]*\}', response)
        
        for json_str in potential_jsons:
            try:
                data = json.loads(json_str)
                if parsed.structured_data is None:
                    parsed.structured_data = {}
                parsed.structured_data.update(data)
            except:
                continue
        
        # Extract findings using text patterns
        parsed = self._parse_text_findings(response, parsed)
        
        return parsed

    def extract_domain_classification(self, response: str) -> Optional[Dict[str, Any]]:
        """Extract domain classification from response."""
        try:
            parsed = self.parse_response(response, ResponseFormat.JSON)
            if parsed.structured_data and isinstance(parsed.structured_data, dict):
                required_keys = ['domain', 'confidence']
                if all(key in parsed.structured_data for key in required_keys):
                    return parsed.structured_data
        except:
            pass
        
        # Fallback: extract using patterns
        domain_pattern = r'domain[\'\":\s]*([\'\"]\w+[\'\"]\w+)'
        confidence_pattern = r'confidence[\'\":\s]*([0-9.]+)'
        
        domain_match = re.search(domain_pattern, response, re.IGNORECASE)
        confidence_match = re.search(confidence_pattern, response, re.IGNORECASE)
        
        if domain_match and confidence_match:
            return {
                'domain': domain_match.group(1).strip('\'"'),
                'confidence': float(confidence_match.group(1))
            }
        
        return None

    def extract_vulnerability_findings(self, response: str) -> List[Finding]:
        """Extract vulnerability findings from response."""
        parsed = self.parse_response(response, ResponseFormat.STRUCTURED)
        return parsed.findings

    def extract_business_logic_analysis(self, response: str) -> Dict[str, Any]:
        """Extract business logic analysis from response."""
        sections = self._split_markdown_sections(response)
        
        analysis = {
            'state_management': sections.get('State Management', ''),
            'access_controls': sections.get('Access Controls', ''),
            'economic_logic': sections.get('Economic Logic', ''),
            'external_interactions': sections.get('External Interactions', ''),
            'edge_cases': sections.get('Edge Cases', ''),
            'invariants': sections.get('Invariants', ''),
            'summary': sections.get('Summary', '')
        }
        
        return analysis

    def export_findings_to_json(self, findings: List[Finding]) -> str:
        """Export findings to JSON format."""
        findings_data = []
        
        for finding in findings:
            finding_dict = {
                'title': finding.title,
                'severity': finding.severity.value,
                'description': finding.description,
                'location': finding.location,
                'impact': finding.impact,
                'recommendation': finding.recommendation,
                'code_snippet': finding.code_snippet,
                'category': finding.category,
                'references': finding.references
            }
            findings_data.append(finding_dict)
        
        return json.dumps(findings_data, indent=2)

    def get_parser_statistics(self) -> Dict[str, Any]:
        """Get parser usage statistics."""
        return {
            'patterns_loaded': len(self.patterns),
            'compiled_patterns': len(self.compiled_patterns)
        }
