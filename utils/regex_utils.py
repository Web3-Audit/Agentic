"""
Regular expression utilities for smart contract pattern matching.
"""

import re
import logging
from typing import Dict, List, Optional, Any, Set, Tuple, Union, Pattern
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)

class PatternCategory(Enum):
    """Categories of regex patterns."""
    SECURITY = "security"
    ACCESS_CONTROL = "access_control"
    FINANCIAL = "financial"
    STATE_MANAGEMENT = "state_management"
    EXTERNAL_CALLS = "external_calls"
    ASSEMBLY = "assembly"
    MODIFIERS = "modifiers"
    EVENTS = "events"
    FUNCTIONS = "functions"
    VARIABLES = "variables"
    SYNTAX = "syntax"

@dataclass
class PatternMatch:
    """Represents a pattern match result."""
    pattern_name: str
    pattern_category: PatternCategory
    matched_text: str
    start_position: int
    end_position: int
    line_number: int
    severity: str = "medium"
    description: str = ""
    context: str = ""

@dataclass
class PatternResult:
    """Result of pattern analysis."""
    total_matches: int
    matches_by_category: Dict[str, int] = field(default_factory=dict)
    matches_by_pattern: Dict[str, int] = field(default_factory=dict)
    all_matches: List[PatternMatch] = field(default_factory=list)
    high_risk_matches: List[PatternMatch] = field(default_factory=list)

class SolidityPatterns:
    """
    Comprehensive collection of Solidity-specific regex patterns.
    """
    
    def __init__(self):
        self.patterns = self._initialize_patterns()
        self.compiled_patterns = self._compile_patterns()

    def _initialize_patterns(self) -> Dict[str, Dict[str, Any]]:
        """Initialize all regex patterns with metadata."""
        return {
            # Security patterns
            'delegatecall_usage': {
                'pattern': r'\.delegatecall\s*\(',
                'category': PatternCategory.SECURITY,
                'severity': 'high',
                'description': 'Usage of delegatecall which can be dangerous'
            },
            'selfdestruct_usage': {
                'pattern': r'\bselfdestruct\s*\(',
                'category': PatternCategory.SECURITY,
                'severity': 'high',
                'description': 'Usage of selfdestruct function'
            },
            'suicide_usage': {
                'pattern': r'\bsuicide\s*\(',
                'category': PatternCategory.SECURITY,
                'severity': 'high',
                'description': 'Usage of deprecated suicide function'
            },
            'tx_origin_usage': {
                'pattern': r'\btx\.origin\b',
                'category': PatternCategory.SECURITY,
                'severity': 'high',
                'description': 'Usage of tx.origin which is vulnerable to phishing attacks'
            },
            'low_level_call': {
                'pattern': r'\.call\s*\(',
                'category': PatternCategory.SECURITY,
                'severity': 'medium',
                'description': 'Low-level call usage'
            },
            'send_usage': {
                'pattern': r'\.send\s*\(',
                'category': PatternCategory.SECURITY,
                'severity': 'medium',
                'description': 'Usage of send function'
            },
            'transfer_usage': {
                'pattern': r'\.transfer\s*\(',
                'category': PatternCategory.SECURITY,
                'severity': 'low',
                'description': 'Usage of transfer function'
            },
            'inline_assembly': {
                'pattern': r'\bassembly\s*\{',
                'category': PatternCategory.ASSEMBLY,
                'severity': 'medium',
                'description': 'Usage of inline assembly'
            },
            'timestamp_dependency': {
                'pattern': r'\b(block\.timestamp|now)\b',
                'category': PatternCategory.SECURITY,
                'severity': 'medium',
                'description': 'Dependency on block timestamp'
            },
            'blockhash_usage': {
                'pattern': r'\bblockhash\s*\(',
                'category': PatternCategory.SECURITY,
                'severity': 'medium',
                'description': 'Usage of blockhash for randomness'
            },
            'block_number_dependency': {
                'pattern': r'\bblock\.number\b',
                'category': PatternCategory.SECURITY,
                'severity': 'low',
                'description': 'Dependency on block number'
            },
            
            # Access control patterns
            'only_owner_modifier': {
                'pattern': r'\bonlyOwner\b',
                'category': PatternCategory.ACCESS_CONTROL,
                'severity': 'info',
                'description': 'Usage of onlyOwner modifier'
            },
            'require_msg_sender': {
                'pattern': r'require\s*\(\s*msg\.sender\s*==',
                'category': PatternCategory.ACCESS_CONTROL,
                'severity': 'info',
                'description': 'Direct sender authorization check'
            },
            'owner_check': {
                'pattern': r'\bowner\s*==\s*msg\.sender|\bmsg\.sender\s*==\s*owner',
                'category': PatternCategory.ACCESS_CONTROL,
                'severity': 'info',
                'description': 'Owner authorization check'
            },
            'role_based_access': {
                'pattern': r'\b(hasRole|checkRole|grantRole|revokeRole)\s*\(',
                'category': PatternCategory.ACCESS_CONTROL,
                'severity': 'info',
                'description': 'Role-based access control'
            },
            
            # Financial patterns
            'balance_check': {
                'pattern': r'\b\w*\.balance\b',
                'category': PatternCategory.FINANCIAL,
                'severity': 'info',
                'description': 'Balance check'
            },
            'transfer_function': {
                'pattern': r'\btransfer\s*\(',
                'category': PatternCategory.FINANCIAL,
                'severity': 'info',
                'description': 'Token transfer function'
            },
            'approve_function': {
                'pattern': r'\bapprove\s*\(',
                'category': PatternCategory.FINANCIAL,
                'severity': 'info',
                'description': 'Token approval function'
            },
            'mint_function': {
                'pattern': r'\bmint\s*\(',
                'category': PatternCategory.FINANCIAL,
                'severity': 'info',
                'description': 'Token minting function'
            },
            'burn_function': {
                'pattern': r'\bburn\s*\(',
                'category': PatternCategory.FINANCIAL,
                'severity': 'info',
                'description': 'Token burning function'
            },
            'payable_function': {
                'pattern': r'\bpayable\b',
                'category': PatternCategory.FINANCIAL,
                'severity': 'medium',
                'description': 'Payable function that can receive Ether'
            },
            
            # State management patterns
            'state_variable_assignment': {
                'pattern': r'^\s*\w+\s*=\s*[^;]+;',
                'category': PatternCategory.STATE_MANAGEMENT,
                'severity': 'info',
                'description': 'State variable assignment'
            },
            'mapping_declaration': {
                'pattern': r'\bmapping\s*\(\s*\w+\s*=>\s*[^)]+\)',
                'category': PatternCategory.STATE_MANAGEMENT,
                'severity': 'info',
                'description': 'Mapping declaration'
            },
            'array_declaration': {
                'pattern': r'\b\w+\[\]\s+\w+',
                'category': PatternCategory.STATE_MANAGEMENT,
                'severity': 'info',
                'description': 'Array declaration'
            },
            'enum_declaration': {
                'pattern': r'\benum\s+\w+\s*\{',
                'category': PatternCategory.STATE_MANAGEMENT,
                'severity': 'info',
                'description': 'Enum declaration'
            },
            'struct_declaration': {
                'pattern': r'\bstruct\s+\w+\s*\{',
                'category': PatternCategory.STATE_MANAGEMENT,
                'severity': 'info',
                'description': 'Struct declaration'
            },
            
            # External call patterns
            'external_contract_call': {
                'pattern': r'\b\w+\.\w+\s*\(',
                'category': PatternCategory.EXTERNAL_CALLS,
                'severity': 'medium',
                'description': 'External contract call'
            },
            'interface_call': {
                'pattern': r'\b[A-Z]\w*\(\s*\w+\s*\)\.\w+',
                'category': PatternCategory.EXTERNAL_CALLS,
                'severity': 'medium',
                'description': 'Interface-based external call'
            },
            'staticcall_usage': {
                'pattern': r'\.staticcall\s*\(',
                'category': PatternCategory.EXTERNAL_CALLS,
                'severity': 'low',
                'description': 'Static call usage'
            },
            
            # Function patterns
            'function_declaration': {
                'pattern': r'\bfunction\s+\w+\s*\([^)]*\)\s*[^{]*\{',
                'category': PatternCategory.FUNCTIONS,
                'severity': 'info',
                'description': 'Function declaration'
            },
            'constructor_declaration': {
                'pattern': r'\bconstructor\s*\([^)]*\)\s*[^{]*\{',
                'category': PatternCategory.FUNCTIONS,
                'severity': 'info',
                'description': 'Constructor declaration'
            },
            'fallback_function': {
                'pattern': r'\bfallback\s*\(\s*\)\s*external\s+payable',
                'category': PatternCategory.FUNCTIONS,
                'severity': 'medium',
                'description': 'Fallback function'
            },
            'receive_function': {
                'pattern': r'\breceive\s*\(\s*\)\s*external\s+payable',
                'category': PatternCategory.FUNCTIONS,
                'severity': 'medium',
                'description': 'Receive function'
            },
            'pure_function': {
                'pattern': r'\bpure\b',
                'category': PatternCategory.FUNCTIONS,
                'severity': 'info',
                'description': 'Pure function'
            },
            'view_function': {
                'pattern': r'\bview\b',
                'category': PatternCategory.FUNCTIONS,
                'severity': 'info',
                'description': 'View function'
            },
            
            # Modifier patterns
            'modifier_declaration': {
                'pattern': r'\bmodifier\s+\w+\s*(?:\([^)]*\))?\s*\{',
                'category': PatternCategory.MODIFIERS,
                'severity': 'info',
                'description': 'Modifier declaration'
            },
            'require_statement': {
                'pattern': r'\brequire\s*\(',
                'category': PatternCategory.MODIFIERS,
                'severity': 'info',
                'description': 'Require statement'
            },
            'assert_statement': {
                'pattern': r'\bassert\s*\(',
                'category': PatternCategory.MODIFIERS,
                'severity': 'info',
                'description': 'Assert statement'
            },
            'revert_statement': {
                'pattern': r'\brevert\s*\(',
                'category': PatternCategory.MODIFIERS,
                'severity': 'info',
                'description': 'Revert statement'
            },
            
            # Event patterns
            'event_declaration': {
                'pattern': r'\bevent\s+\w+\s*\([^)]*\)\s*;',
                'category': PatternCategory.EVENTS,
                'severity': 'info',
                'description': 'Event declaration'
            },
            'emit_statement': {
                'pattern': r'\bemit\s+\w+\s*\(',
                'category': PatternCategory.EVENTS,
                'severity': 'info',
                'description': 'Event emission'
            },
            
            # Syntax patterns
            'pragma_statement': {
                'pattern': r'\bpragma\s+solidity\s+[^;]+;',
                'category': PatternCategory.SYNTAX,
                'severity': 'info',
                'description': 'Pragma statement'
            },
            'import_statement': {
                'pattern': r'\bimport\s+[^;]+;',
                'category': PatternCategory.SYNTAX,
                'severity': 'info',
                'description': 'Import statement'
            },
            'license_identifier': {
                'pattern': r'//\s*SPDX-License-Identifier:\s*[^\r\n]+',
                'category': PatternCategory.SYNTAX,
                'severity': 'info',
                'description': 'SPDX license identifier'
            },
            'contract_declaration': {
                'pattern': r'\b(contract|interface|library)\s+\w+(?:\s+is\s+[^{]+)?\s*\{',
                'category': PatternCategory.SYNTAX,
                'severity': 'info',
                'description': 'Contract/Interface/Library declaration'
            },
            
            # Additional security patterns
            'unchecked_call_return': {
                'pattern': r'\.call\s*\([^)]*\)\s*;',
                'category': PatternCategory.SECURITY,
                'severity': 'medium',
                'description': 'Unchecked low-level call return value'
            },
            'reentrancy_pattern': {
                'pattern': r'require\s*\(\s*!\s*locked\s*\)|locked\s*=\s*true',
                'category': PatternCategory.SECURITY,
                'severity': 'info',
                'description': 'Reentrancy protection pattern'
            },
            'overflow_check': {
                'pattern': r'(SafeMath|checked|unchecked)',
                'category': PatternCategory.SECURITY,
                'severity': 'info',
                'description': 'Overflow protection mechanism'
            }
        }

    def _compile_patterns(self) -> Dict[str, Pattern[str]]:
        """Compile all regex patterns for better performance."""
        compiled = {}
        for name, pattern_info in self.patterns.items():
            try:
                compiled[name] = re.compile(pattern_info['pattern'], re.MULTILINE | re.IGNORECASE)
            except re.error as e:
                logger.error(f"Error compiling pattern {name}: {str(e)}")
        return compiled

    def get_pattern_by_name(self, name: str) -> Optional[Dict[str, Any]]:
        """Get pattern information by name."""
        return self.patterns.get(name)

    def get_patterns_by_category(self, category: PatternCategory) -> Dict[str, Dict[str, Any]]:
        """Get all patterns in a specific category."""
        return {
            name: info for name, info in self.patterns.items()
            if info['category'] == category
        }

    def get_security_patterns(self) -> Dict[str, Dict[str, Any]]:
        """Get all security-related patterns."""
        return self.get_patterns_by_category(PatternCategory.SECURITY)

    def get_high_severity_patterns(self) -> Dict[str, Dict[str, Any]]:
        """Get all high-severity patterns."""
        return {
            name: info for name, info in self.patterns.items()
            if info['severity'] == 'high'
        }

class PatternMatcher:
    """
    Advanced pattern matcher with context analysis.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.patterns = SolidityPatterns()

    def analyze_code(self, source_code: str, pattern_names: Optional[List[str]] = None) -> PatternResult:
        """
        Analyze source code for pattern matches.
        
        Args:
            source_code: Solidity source code to analyze
            pattern_names: Optional list of specific patterns to check
            
        Returns:
            PatternResult: Analysis results
        """
        result = PatternResult(total_matches=0)
        lines = source_code.split('\n')
        
        patterns_to_check = pattern_names or list(self.patterns.patterns.keys())
        
        for pattern_name in patterns_to_check:
            if pattern_name not in self.patterns.compiled_patterns:
                continue
            
            pattern_info = self.patterns.patterns[pattern_name]
            compiled_pattern = self.patterns.compiled_patterns[pattern_name]
            
            matches = self._find_pattern_matches(
                source_code, lines, pattern_name, pattern_info, compiled_pattern
            )
            
            result.all_matches.extend(matches)
            result.total_matches += len(matches)
            
            # Update counters
            category = pattern_info['category'].value
            result.matches_by_category[category] = result.matches_by_category.get(category, 0) + len(matches)
            result.matches_by_pattern[pattern_name] = len(matches)
            
            # Track high-risk matches
            if pattern_info['severity'] == 'high':
                result.high_risk_matches.extend(matches)
        
        self.logger.info(f"Pattern analysis completed: {result.total_matches} total matches")
        return result

    def _find_pattern_matches(self, source_code: str, lines: List[str], 
                            pattern_name: str, pattern_info: Dict[str, Any],
                            compiled_pattern: Pattern[str]) -> List[PatternMatch]:
        """Find all matches for a specific pattern."""
        matches = []
        
        for match in compiled_pattern.finditer(source_code):
            line_number = self._get_line_number(source_code, match.start())
            context = self._get_context(lines, line_number, context_lines=2)
            
            pattern_match = PatternMatch(
                pattern_name=pattern_name,
                pattern_category=pattern_info['category'],
                matched_text=match.group(),
                start_position=match.start(),
                end_position=match.end(),
                line_number=line_number,
                severity=pattern_info['severity'],
                description=pattern_info['description'],
                context=context
            )
            
            matches.append(pattern_match)
        
        return matches

    def _get_line_number(self, source_code: str, position: int) -> int:
        """Get line number for a character position."""
        return source_code[:position].count('\n') + 1

    def _get_context(self, lines: List[str], line_number: int, context_lines: int = 2) -> str:
        """Get context around a line."""
        start = max(0, line_number - context_lines - 1)
        end = min(len(lines), line_number + context_lines)
        
        context_lines_list = []
        for i in range(start, end):
            marker = ">>> " if i == line_number - 1 else "    "
            context_lines_list.append(f"{marker}{i+1:3d}: {lines[i]}")
        
        return '\n'.join(context_lines_list)

    def find_security_issues(self, source_code: str) -> List[PatternMatch]:
        """Find security-related pattern matches."""
        security_patterns = list(self.patterns.get_security_patterns().keys())
        result = self.analyze_code(source_code, security_patterns)
        return result.all_matches

    def find_high_risk_patterns(self, source_code: str) -> List[PatternMatch]:
        """Find high-risk pattern matches."""
        high_risk_patterns = list(self.patterns.get_high_severity_patterns().keys())
        result = self.analyze_code(source_code, high_risk_patterns)
        return result.all_matches

    def check_specific_pattern(self, source_code: str, pattern_name: str) -> List[PatternMatch]:
        """Check for a specific pattern."""
        result = self.analyze_code(source_code, [pattern_name])
        return result.all_matches

    def get_pattern_statistics(self, source_code: str) -> Dict[str, Any]:
        """Get comprehensive pattern statistics."""
        result = self.analyze_code(source_code)
        
        return {
            'total_matches': result.total_matches,
            'matches_by_category': result.matches_by_category,
            'matches_by_severity': self._get_severity_distribution(result.all_matches),
            'high_risk_count': len(result.high_risk_matches),
            'most_common_patterns': self._get_most_common_patterns(result.matches_by_pattern),
            'security_score': self._calculate_security_score(result)
        }

    def _get_severity_distribution(self, matches: List[PatternMatch]) -> Dict[str, int]:
        """Get distribution of matches by severity."""
        distribution = {}
        for match in matches:
            severity = match.severity
            distribution[severity] = distribution.get(severity, 0) + 1
        return distribution

    def _get_most_common_patterns(self, matches_by_pattern: Dict[str, int], top_n: int = 10) -> List[Tuple[str, int]]:
        """Get most common patterns."""
        sorted_patterns = sorted(matches_by_pattern.items(), key=lambda x: x[1], reverse=True)
        return sorted_patterns[:top_n]

    def _calculate_security_score(self, result: PatternResult) -> float:
        """Calculate a security score based on pattern matches."""
        if result.total_matches == 0:
            return 1.0
        
        # Weight different severities
        severity_weights = {'high': 1.0, 'medium': 0.5, 'low': 0.2, 'info': 0.1}
        
        total_weighted_score = 0
        for match in result.all_matches:
            total_weighted_score += severity_weights.get(match.severity, 0.1)
        
        # Normalize to 0-1 scale (lower is better)
        max_possible_score = result.total_matches * 1.0
        normalized_score = 1.0 - min(total_weighted_score / max_possible_score, 1.0)
        
        return normalized_score

class SecurityPatternDetector:
    """
    Specialized detector for security patterns.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.matcher = PatternMatcher()

    def detect_reentrancy_vulnerabilities(self, source_code: str) -> List[Dict[str, Any]]:
        """Detect potential reentrancy vulnerabilities."""
        vulnerabilities = []
        
        # Look for external calls without proper protection
        external_calls = self.matcher.check_specific_pattern(source_code, 'low_level_call')
        external_calls.extend(self.matcher.check_specific_pattern(source_code, 'external_contract_call'))
        
        # Check for reentrancy protection patterns
        protection_patterns = self.matcher.check_specific_pattern(source_code, 'reentrancy_pattern')
        
        if external_calls and not protection_patterns:
            vulnerabilities.append({
                'type': 'potential_reentrancy',
                'description': 'External calls found without apparent reentrancy protection',
                'severity': 'high',
                'locations': [match.line_number for match in external_calls]
            })
        
        return vulnerabilities

    def detect_access_control_issues(self, source_code: str) -> List[Dict[str, Any]]:
        """Detect access control issues."""
        issues = []
        
        # Find state-changing functions
        functions = self.matcher.check_specific_pattern(source_code, 'function_declaration')
        
        # Check for access control patterns
        access_controls = []
        access_controls.extend(self.matcher.check_specific_pattern(source_code, 'only_owner_modifier'))
        access_controls.extend(self.matcher.check_specific_pattern(source_code, 'require_msg_sender'))
        access_controls.extend(self.matcher.check_specific_pattern(source_code, 'role_based_access'))
        
        # Simple heuristic: if many functions but few access controls
        if len(functions) > 5 and len(access_controls) < 3:
            issues.append({
                'type': 'insufficient_access_control',
                'description': 'Many functions found with limited access control mechanisms',
                'severity': 'medium',
                'function_count': len(functions),
                'access_control_count': len(access_controls)
            })
        
        return issues

    def detect_dangerous_functions(self, source_code: str) -> List[Dict[str, Any]]:
        """Detect usage of dangerous functions."""
        dangerous = []
        
        dangerous_patterns = [
            'delegatecall_usage',
            'selfdestruct_usage',
            'suicide_usage',
            'tx_origin_usage'
        ]
        
        for pattern_name in dangerous_patterns:
            matches = self.matcher.check_specific_pattern(source_code, pattern_name)
            if matches:
                dangerous.append({
                    'type': pattern_name,
                    'description': f'Dangerous function usage: {pattern_name}',
                    'severity': 'high',
                    'occurrences': len(matches),
                    'locations': [match.line_number for match in matches]
                })
        
        return dangerous

    def detect_timestamp_dependencies(self, source_code: str) -> List[Dict[str, Any]]:
        """Detect timestamp dependencies."""
        dependencies = []
        
        timestamp_matches = self.matcher.check_specific_pattern(source_code, 'timestamp_dependency')
        blockhash_matches = self.matcher.check_specific_pattern(source_code, 'blockhash_usage')
        
        if timestamp_matches:
            dependencies.append({
                'type': 'timestamp_dependency',
                'description': 'Contract depends on block timestamp',
                'severity': 'medium',
                'occurrences': len(timestamp_matches),
                'locations': [match.line_number for match in timestamp_matches]
            })
        
        if blockhash_matches:
            dependencies.append({
                'type': 'blockhash_randomness',
                'description': 'Contract uses blockhash for randomness',
                'severity': 'medium',
                'occurrences': len(blockhash_matches),
                'locations': [match.line_number for match in blockhash_matches]
            })
        
        return dependencies

class CodePatternAnalyzer:
    """
    Analyzes code patterns for quality and best practices.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.matcher = PatternMatcher()

    def analyze_code_quality(self, source_code: str) -> Dict[str, Any]:
        """Analyze code quality based on patterns."""
        analysis = {
            'function_analysis': self._analyze_functions(source_code),
            'state_management': self._analyze_state_management(source_code),
            'event_usage': self._analyze_events(source_code),
            'modifier_usage': self._analyze_modifiers(source_code),
            'best_practices': self._check_best_practices(source_code)
        }
        
        return analysis

    def _analyze_functions(self, source_code: str) -> Dict[str, Any]:
        """Analyze function patterns."""
        functions = self.matcher.check_specific_pattern(source_code, 'function_declaration')
        pure_functions = self.matcher.check_specific_pattern(source_code, 'pure_function')
        view_functions = self.matcher.check_specific_pattern(source_code, 'view_function')
        payable_functions = self.matcher.check_specific_pattern(source_code, 'payable_function')
        
        return {
            'total_functions': len(functions),
            'pure_functions': len(pure_functions),
            'view_functions': len(view_functions),
            'payable_functions': len(payable_functions),
            'state_changing_functions': len(functions) - len(pure_functions) - len(view_functions)
        }

    def _analyze_state_management(self, source_code: str) -> Dict[str, Any]:
        """Analyze state management patterns."""
        mappings = self.matcher.check_specific_pattern(source_code, 'mapping_declaration')
        arrays = self.matcher.check_specific_pattern(source_code, 'array_declaration')
        structs = self.matcher.check_specific_pattern(source_code, 'struct_declaration')
        enums = self.matcher.check_specific_pattern(source_code, 'enum_declaration')
        
        return {
            'mappings': len(mappings),
            'arrays': len(arrays),
            'structs': len(structs),
            'enums': len(enums),
            'complexity_score': self._calculate_state_complexity(mappings, arrays, structs)
        }

    def _analyze_events(self, source_code: str) -> Dict[str, Any]:
        """Analyze event usage patterns."""
        event_declarations = self.matcher.check_specific_pattern(source_code, 'event_declaration')
        emit_statements = self.matcher.check_specific_pattern(source_code, 'emit_statement')
        
        return {
            'declared_events': len(event_declarations),
            'emit_statements': len(emit_statements),
            'events_used': len(emit_statements) > 0,
            'event_coverage': len(emit_statements) / max(len(event_declarations), 1)
        }

    def _analyze_modifiers(self, source_code: str) -> Dict[str, Any]:
        """Analyze modifier usage."""
        modifier_declarations = self.matcher.check_specific_pattern(source_code, 'modifier_declaration')
        require_statements = self.matcher.check_specific_pattern(source_code, 'require_statement')
        assert_statements = self.matcher.check_specific_pattern(source_code, 'assert_statement')
        
        return {
            'custom_modifiers': len(modifier_declarations),
            'require_statements': len(require_statements),
            'assert_statements': len(assert_statements),
            'validation_coverage': (len(require_statements) + len(assert_statements)) / 10  # Rough metric
        }

    def _check_best_practices(self, source_code: str) -> Dict[str, Any]:
        """Check for best practice patterns."""
        license_id = self.matcher.check_specific_pattern(source_code, 'license_identifier')
        pragma_statement = self.matcher.check_specific_pattern(source_code, 'pragma_statement')
        overflow_checks = self.matcher.check_specific_pattern(source_code, 'overflow_check')
        
        return {
            'has_license_identifier': len(license_id) > 0,
            'has_pragma_statement': len(pragma_statement) > 0,
            'uses_overflow_protection': len(overflow_checks) > 0,
            'best_practices_score': self._calculate_best_practices_score(
                len(license_id), len(pragma_statement), len(overflow_checks)
            )
        }

    def _calculate_state_complexity(self, mappings: int, arrays: int, structs: int) -> float:
        """Calculate state complexity score."""
        return min((mappings * 0.3 + arrays * 0.2 + structs * 0.5) / 10, 1.0)

    def _calculate_best_practices_score(self, license: int, pragma: int, overflow: int) -> float:
        """Calculate best practices adherence score."""
        score = 0
        total = 3
        
        if license > 0:
            score += 1
        if pragma > 0:
            score += 1
        if overflow > 0:
            score += 1
        
        return score / total

    def generate_recommendations(self, source_code: str) -> List[str]:
        """Generate code quality recommendations."""
        recommendations = []
        
        quality_analysis = self.analyze_code_quality(source_code)
        security_matches = self.matcher.find_security_issues(source_code)
        
        # License and pragma recommendations
        if not quality_analysis['best_practices']['has_license_identifier']:
            recommendations.append("Add SPDX license identifier at the top of the file")
        
        if not quality_analysis['best_practices']['has_pragma_statement']:
            recommendations.append("Add pragma solidity version specification")
        
        # Security recommendations
        high_risk_patterns = [match for match in security_matches if match.severity == 'high']
        if high_risk_patterns:
            recommendations.append(f"Review {len(high_risk_patterns)} high-risk security patterns found")
        
        # Function recommendations
        func_analysis = quality_analysis['function_analysis']
        if func_analysis['payable_functions'] > 0 and func_analysis['payable_functions'] > func_analysis['total_functions'] * 0.3:
            recommendations.append("Consider reducing the number of payable functions")
        
        # Event recommendations
        event_analysis = quality_analysis['event_usage']
        if not event_analysis['events_used']:
            recommendations.append("Consider adding events for important state changes")
        
        return recommendations
