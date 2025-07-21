"""
Universal agent for mandatory checks that apply to all smart contracts.

This agent performs fundamental security checks that every contract should undergo,
regardless of domain or specific functionality.
"""

import re
import time
from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass

from .base_agent import BaseAgent, AgentMetadata, AgentType
from ..models.context import AnalysisContext, FunctionContext
from ..models.finding import Finding, Severity, Category, CodeLocation
from ..llm.client import LLMClient
from ..llm.prompts import PromptManager


@dataclass
class UniversalChecks:
    """Configuration for universal security checks."""
    
    # Access control patterns
    ACCESS_CONTROL_MODIFIERS = [
        'onlyOwner', 'onlyAdmin', 'onlyAuthorized', 'requireOwner',
        'requireAdmin', 'onlyRole', 'hasRole', 'whenNotPaused'
    ]
    
    # Dangerous functions that need protection
    DANGEROUS_FUNCTIONS = [
        'selfdestruct', 'suicide', 'delegatecall', 'callcode',
        'send', 'transfer', 'call'
    ]
    
    # State-changing patterns
    STATE_CHANGING_PATTERNS = [
        r'=\s*[^=]',  # Assignment
        r'push\s*\(',  # Array push
        r'pop\s*\(',   # Array pop
        r'delete\s+',  # Delete statement
        r'\+\+',       # Increment
        r'--'          # Decrement
    ]
    
    # External call patterns
    EXTERNAL_CALL_PATTERNS = [
        r'\.call\s*\(',
        r'\.delegatecall\s*\(',
        r'\.staticcall\s*\(',
        r'\.send\s*\(',
        r'\.transfer\s*\('
    ]
    
    # Reentrancy protection patterns
    REENTRANCY_GUARDS = [
        'nonReentrant', 'noReentrancy', 'reentrancyGuard',
        'mutex', 'locked', 'ReentrancyGuard'
    ]


class UniversalAgent(BaseAgent):
    """
    Universal agent that performs mandatory security checks for all contracts.
    
    This agent checks for fundamental security issues that apply universally,
    such as access control, reentrancy protection, integer overflow, etc.
    """
    
    def __init__(self, llm_client: Optional[LLMClient] = None,
                 prompt_manager: Optional[PromptManager] = None):
        super().__init__("UniversalAgent", llm_client, prompt_manager)
        self.checks = UniversalChecks()
    
    @property
    def metadata(self) -> AgentMetadata:
        """Get agent metadata."""
        return AgentMetadata(
            name="UniversalAgent",
            version="1.0.0",
            description="Performs mandatory security checks for all smart contracts",
            author="Smart Contract Analyzer",
            agent_type=AgentType.UNIVERSAL,
            supported_domains=["*"]  # All domains
        )
    
    def can_analyze(self, context: AnalysisContext) -> bool:
        """Universal agent can analyze any contract."""
        return self.enabled and bool(context.contract_code)
    
    def analyze(self, context: AnalysisContext) -> List[Finding]:
        """
        Perform universal security analysis.
        
        Args:
            context: Analysis context
            
        Returns:
            List[Finding]: Universal security findings
        """
        start_time = time.time()
        findings = []
        
        try:
            # Core security checks
            findings.extend(self._check_access_control(context))
            findings.extend(self._check_reentrancy_protection(context))
            findings.extend(self._check_integer_overflow(context))
            findings.extend(self._check_external_calls(context))
            findings.extend(self._check_state_mutations(context))
            findings.extend(self._check_dangerous_functions(context))
            findings.extend(self._check_visibility_issues(context))
            findings.extend(self._check_event_emissions(context))
            findings.extend(self._check_error_handling(context))
            findings.extend(self._check_gas_optimizations(context))
            findings.extend(self._check_code_quality(context))
            
            # Update metrics
            self.metrics.analysis_time = time.time() - start_time
            self.metrics.functions_analyzed = sum(len(funcs) for funcs in context.functions.values())
            
            return findings
            
        except Exception as e:
            self.logger.error(f"Error in universal analysis: {str(e)}")
            return findings
    
    def _check_access_control(self, context: AnalysisContext) -> List[Finding]:
        """Check for access control issues."""
        findings = []
        
        for contract_name, functions in context.functions.items():
            for func in functions:
                if self._is_privileged_function(func):
                    if not self._has_access_control(func):
                        finding = self.create_finding(
                            title=f"Missing Access Control in {func.name}",
                            description=f"Function '{func.name}' appears to be privileged but lacks access control",
                            severity=Severity.HIGH,
                            category=Category.ACCESS_CONTROL,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Add appropriate access control modifiers (e.g., onlyOwner, requireRole)",
                            impact="Unauthorized users could access privileged functionality"
                        )
                        findings.append(finding)
        
        return findings
    
    def _check_reentrancy_protection(self, context: AnalysisContext) -> List[Finding]:
        """Check for reentrancy vulnerabilities."""
        findings = []
        
        for contract_name, functions in context.functions.items():
            for func in functions:
                if self._has_external_calls(func) and self._modifies_state_after_call(func):
                    if not self._has_reentrancy_protection(func):
                        finding = self.create_finding(
                            title=f"Reentrancy Vulnerability in {func.name}",
                            description=f"Function '{func.name}' makes external calls and modifies state without reentrancy protection",
                            severity=Severity.CRITICAL,
                            category=Category.REENTRANCY,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Apply checks-effects-interactions pattern or use reentrancy guards",
                            impact="Attackers could drain contract funds through reentrancy attacks"
                        )
                        findings.append(finding)
        
        return findings
    
    def _check_integer_overflow(self, context: AnalysisContext) -> List[Finding]:
        """Check for integer overflow/underflow vulnerabilities."""
        findings = []
        
        # Check Solidity version first
        solidity_version = self._extract_solidity_version(context.contract_code)
        if solidity_version and self._version_less_than(solidity_version, "0.8.0"):
            
            for contract_name, functions in context.functions.items():
                for func in functions:
                    if self._has_arithmetic_operations(func):
                        if not self._uses_safe_math(func, context.contract_code):
                            finding = self.create_finding(
                                title=f"Integer Overflow Risk in {func.name}",
                                description=f"Function '{func.name}' performs arithmetic without overflow protection",
                                severity=Severity.HIGH,
                                category=Category.ARITHMETIC,
                                location=CodeLocation(
                                    contract_name=contract_name,
                                    function_name=func.name,
                                    line_number=func.line_number
                                ),
                                affected_contracts=[contract_name],
                                affected_functions=[func.name],
                                recommendation="Use SafeMath library or upgrade to Solidity 0.8.0+",
                                impact="Arithmetic operations could overflow/underflow leading to incorrect calculations"
                            )
                            findings.append(finding)
        
        return findings
    
    def _check_external_calls(self, context: AnalysisContext) -> List[Finding]:
        """Check external call security."""
        findings = []
        
        for contract_name, functions in context.functions.items():
            for func in functions:
                external_calls = self._find_external_calls(func)
                
                for call in external_calls:
                    # Check for unchecked return values
                    if not self._checks_return_value(func, call):
                        finding = self.create_finding(
                            title=f"Unchecked External Call in {func.name}",
                            description=f"External call '{call}' in function '{func.name}' doesn't check return value",
                            severity=Severity.MEDIUM,
                            category=Category.EXTERNAL_CALLS,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Check return values of external calls and handle failures appropriately",
                            impact="Failed external calls could go unnoticed"
                        )
                        findings.append(finding)
                    
                    # Check for gas griefing
                    if self._vulnerable_to_gas_griefing(func, call):
                        finding = self.create_finding(
                            title=f"Gas Griefing Risk in {func.name}",
                            description=f"External call in '{func.name}' could be vulnerable to gas griefing",
                            severity=Severity.MEDIUM,
                            category=Category.GAS_OPTIMIZATION,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Set gas limits for external calls",
                            impact="Attackers could cause DoS through gas griefing"
                        )
                        findings.append(finding)
        
        return findings
    
    def _check_state_mutations(self, context: AnalysisContext) -> List[Finding]:
        """Check state mutation patterns."""
        findings = []
        
        for contract_name, functions in context.functions.items():
            for func in functions:
                if func.visibility in ['public', 'external'] and self._modifies_state(func):
                    if func.state_mutability in ['view', 'pure']:
                        finding = self.create_finding(
                            title=f"State Mutation in View/Pure Function {func.name}",
                            description=f"Function '{func.name}' is marked as {func.state_mutability} but modifies state",
                            severity=Severity.HIGH,
                            category=Category.FUNCTION_VISIBILITY,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Remove state mutability modifier or avoid state changes",
                            impact="Function behavior doesn't match its declared interface"
                        )
                        findings.append(finding)
        
        return findings
    
    def _check_dangerous_functions(self, context: AnalysisContext) -> List[Finding]:
        """Check for usage of dangerous functions."""
        findings = []
        
        dangerous_patterns = {
            'selfdestruct': "Contract self-destruction detected",
            'suicide': "Deprecated suicide function detected",
            'delegatecall': "Dangerous delegatecall detected",
            'callcode': "Deprecated callcode function detected"
        }
        
        for pattern, message in dangerous_patterns.items():
            matches = self.find_patterns_in_code([pattern], context)
            
            for pattern_key, pattern_matches in matches.items():
                for match in pattern_matches:
                    line_number = context.contract_code[:match.start()].count('\n') + 1
                    
                    finding = self.create_finding(
                        title=f"Dangerous Function Usage: {pattern}",
                        description=message,
                        severity=Severity.HIGH if pattern in ['selfdestruct', 'delegatecall'] else Severity.MEDIUM,
                        category=Category.DANGEROUS_FUNCTIONS,
                        location=CodeLocation(
                            line_number=line_number
                        ),
                        recommendation=f"Carefully review usage of {pattern} and implement proper safeguards",
                        impact="Could lead to unexpected contract behavior or security vulnerabilities"
                    )
                    findings.append(finding)
        
        return findings
    
    def _check_visibility_issues(self, context: AnalysisContext) -> List[Finding]:
        """Check function visibility issues."""
        findings = []
        
        for contract_name, functions in context.functions.items():
            for func in functions:
                # Check for missing visibility specifiers
                if not func.visibility:
                    finding = self.create_finding(
                        title=f"Missing Visibility Specifier in {func.name}",
                        description=f"Function '{func.name}' doesn't specify visibility",
                        severity=Severity.MEDIUM,
                        category=Category.FUNCTION_VISIBILITY,
                        location=CodeLocation(
                            contract_name=contract_name,
                            function_name=func.name,
                            line_number=func.line_number
                        ),
                        affected_contracts=[contract_name],
                        affected_functions=[func.name],
                        recommendation="Explicitly specify function visibility (public, external, internal, private)",
                        impact="Unclear function accessibility could lead to security issues"
                    )
                    findings.append(finding)
                
                # Check for overly permissive visibility
                if func.visibility == 'public' and not self._needs_public_visibility(func):
                    finding = self.create_finding(
                        title=f"Overly Permissive Visibility in {func.name}",
                        description=f"Function '{func.name}' is public but could be external or internal",
                        severity=Severity.LOW,
                        category=Category.GAS_OPTIMIZATION,
                        location=CodeLocation(
                            contract_name=contract_name,
                            function_name=func.name,
                            line_number=func.line_number
                        ),
                        affected_contracts=[contract_name],
                        affected_functions=[func.name],
                        recommendation="Use external visibility for functions only called externally",
                        impact="Unnecessary gas costs and broader attack surface"
                    )
                    findings.append(finding)
        
        return findings
    
    def _check_event_emissions(self, context: AnalysisContext) -> List[Finding]:
        """Check event emission patterns."""
        findings = []
        
        for contract_name, functions in context.functions.items():
            for func in functions:
                if self._should_emit_events(func) and not self._emits_events(func):
                    finding = self.create_finding(
                        title=f"Missing Event Emission in {func.name}",
                        description=f"State-changing function '{func.name}' should emit events",
                        severity=Severity.LOW,
                        category=Category.EVENT_EMISSION,
                        location=CodeLocation(
                            contract_name=contract_name,
                            function_name=func.name,
                            line_number=func.line_number
                        ),
                        affected_contracts=[contract_name],
                        affected_functions=[func.name],
                        recommendation="Emit events for important state changes",
                        impact="Reduced transparency and monitoring capabilities"
                    )
                    findings.append(finding)
        
        return findings
    
    def _check_error_handling(self, context: AnalysisContext) -> List[Finding]:
        """Check error handling patterns."""
        findings = []
        
        for contract_name, functions in context.functions.items():
            for func in functions:
                # Check for proper require statements
                if self._has_parameter_validation_needs(func) and not self._validates_parameters(func):
                    finding = self.create_finding(
                        title=f"Missing Input Validation in {func.name}",
                        description=f"Function '{func.name}' should validate input parameters",
                        severity=Severity.MEDIUM,
                        category=Category.INPUT_VALIDATION,
                        location=CodeLocation(
                            contract_name=contract_name,
                            function_name=func.name,
                            line_number=func.line_number
                        ),
                        affected_contracts=[contract_name],
                        affected_functions=[func.name],
                        recommendation="Add require statements to validate input parameters",
                        impact="Invalid inputs could cause unexpected behavior"
                    )
                    findings.append(finding)
        
        return findings
    
    def _check_gas_optimizations(self, context: AnalysisContext) -> List[Finding]:
        """Check for gas optimization opportunities."""
        findings = []
        
        # Check for inefficient loops
        loop_patterns = [r'for\s*\(.*\)', r'while\s*\(.*\)']
        for pattern in loop_patterns:
            matches = self.find_patterns_in_code([pattern], context)
            
            for pattern_matches in matches.values():
                for match in pattern_matches:
                    if self._is_inefficient_loop(match, context.contract_code):
                        line_number = context.contract_code[:match.start()].count('\n') + 1
                        
                        finding = self.create_finding(
                            title="Inefficient Loop Pattern",
                            description="Loop pattern could be optimized for gas efficiency",
                            severity=Severity.LOW,
                            category=Category.GAS_OPTIMIZATION,
                            location=CodeLocation(line_number=line_number),
                            recommendation="Consider loop optimization techniques",
                            impact="Higher gas costs"
                        )
                        findings.append(finding)
        
        return findings
    
    def _check_code_quality(self, context: AnalysisContext) -> List[Finding]:
        """Check code quality issues."""
        findings = []
        
        # Check for magic numbers
        magic_numbers = re.findall(r'\b(?<!0x)(?<!\.)(?<!e)(?<!E)\d{4,}\b', context.contract_code)
        if magic_numbers:
            finding = self.create_finding(
                title="Magic Numbers Detected",
                description="Contract contains magic numbers that should be constants",
                severity=Severity.LOW,
                category=Category.CODE_QUALITY,
                recommendation="Replace magic numbers with named constants",
                impact="Reduced code readability and maintainability"
            )
            findings.append(finding)
        
        return findings
    
    # Helper methods for analysis
    
    def _is_privileged_function(self, func: FunctionContext) -> bool:
        """Check if function appears to be privileged."""
        privileged_keywords = [
            'withdraw', 'transfer', 'mint', 'burn', 'pause', 'unpause',
            'upgrade', 'destroy', 'admin', 'owner', 'emergency'
        ]
        return any(keyword in func.name.lower() for keyword in privileged_keywords)
    
    def _has_access_control(self, func: FunctionContext) -> bool:
        """Check if function has access control."""
        return any(
            modifier in self.checks.ACCESS_CONTROL_MODIFIERS 
            for modifier in func.modifiers
        ) or self._has_access_control_checks(func)
    
    def _has_access_control_checks(self, func: FunctionContext) -> bool:
        """Check for access control checks in function body."""
        access_patterns = [
            r'require\s*\(\s*msg\.sender\s*==\s*owner',
            r'require\s*\(\s*hasRole\s*\(',
            r'require\s*\(\s*isOwner\s*\(',
            r'onlyOwner',
            r'onlyAdmin'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) for pattern in access_patterns)
    
    def _has_external_calls(self, func: FunctionContext) -> bool:
        """Check if function has external calls."""
        return any(
            re.search(pattern, func.body, re.IGNORECASE) 
            for pattern in self.checks.EXTERNAL_CALL_PATTERNS
        )
    
    def _modifies_state_after_call(self, func: FunctionContext) -> bool:
        """Check if function modifies state after external calls."""
        # Simple heuristic: look for external calls followed by state changes
        lines = func.body.split('\n')
        found_external_call = False
        
        for line in lines:
            if any(re.search(pattern, line, re.IGNORECASE) for pattern in self.checks.EXTERNAL_CALL_PATTERNS):
                found_external_call = True
            elif found_external_call:
                if any(re.search(pattern, line) for pattern in self.checks.STATE_CHANGING_PATTERNS):
                    return True
        
        return False
    
    def _has_reentrancy_protection(self, func: FunctionContext) -> bool:
        """Check if function has reentrancy protection."""
        return any(
            guard in func.modifiers or guard in func.body 
            for guard in self.checks.REENTRANCY_GUARDS
        )
    
    def _extract_solidity_version(self, code: str) -> Optional[str]:
        """Extract Solidity version from pragma statement."""
        pragma_match = re.search(r'pragma\s+solidity\s+[^;]+;', code, re.IGNORECASE)
        if pragma_match:
            version_match = re.search(r'(\d+\.\d+\.\d+)', pragma_match.group())
            return version_match.group(1) if version_match else None
        return None
    
    def _version_less_than(self, version1: str, version2: str) -> bool:
        """Compare version strings."""
        v1_parts = [int(x) for x in version1.split('.')]
        v2_parts = [int(x) for x in version2.split('.')]
        
        for i in range(max(len(v1_parts), len(v2_parts))):
            v1_part = v1_parts[i] if i < len(v1_parts) else 0
            v2_part = v2_parts[i] if i < len(v2_parts) else 0
            
            if v1_part < v2_part:
                return True
            elif v1_part > v2_part:
                return False
        
        return False
    
    def _has_arithmetic_operations(self, func: FunctionContext) -> bool:
        """Check if function has arithmetic operations."""
        arithmetic_patterns = [r'\+', r'-', r'\*', r'/', r'%']
        return any(re.search(pattern, func.body) for pattern in arithmetic_patterns)
    
    def _uses_safe_math(self, func: FunctionContext, contract_code: str) -> bool:
        """Check if SafeMath is used."""
        safe_math_patterns = [
            'SafeMath', 'safeAdd', 'safeSub', 'safeMul', 'safeDiv',
            r'using\s+SafeMath', r'add\s*\(', r'sub\s*\(', r'mul\s*\(', r'div\s*\('
        ]
        return any(
            re.search(pattern, func.body, re.IGNORECASE) or 
            re.search(pattern, contract_code, re.IGNORECASE)
            for pattern in safe_math_patterns
        )
    
    def _find_external_calls(self, func: FunctionContext) -> List[str]:
        """Find external calls in function."""
        calls = []
        for pattern in self.checks.EXTERNAL_CALL_PATTERNS:
            matches = re.finditer(pattern, func.body, re.IGNORECASE)
            for match in matches:
                calls.append(match.group())
        return calls
    
    def _checks_return_value(self, func: FunctionContext, call: str) -> bool:
        """Check if function checks return value of external call."""
        # Look for assignment or require statements around the call
        call_context = func.body
        return (
            re.search(rf'\w+\s*=.*{re.escape(call)}', call_context, re.IGNORECASE) or
            re.search(rf'require\s*\(.*{re.escape(call)}', call_context, re.IGNORECASE) or
            re.search(rf'if\s*\(.*{re.escape(call)}', call_context, re.IGNORECASE)
        )
    
    def _vulnerable_to_gas_griefing(self, func: FunctionContext, call: str) -> bool:
        """Check if external call is vulnerable to gas griefing."""
        # Simple heuristic: calls without gas limits in loops
        has_loop = any(
            re.search(pattern, func.body, re.IGNORECASE) 
            for pattern in [r'for\s*\(', r'while\s*\(']
        )
        has_gas_limit = re.search(r'\.gas\s*\(', func.body, re.IGNORECASE)
        
        return has_loop and not has_gas_limit and '.call' in call
    
    def _modifies_state(self, func: FunctionContext) -> bool:
        """Check if function modifies contract state."""
        return any(
            re.search(pattern, func.body) 
            for pattern in self.checks.STATE_CHANGING_PATTERNS
        )
    
    def _needs_public_visibility(self, func: FunctionContext) -> bool:
        """Check if function actually needs public visibility."""
        # Heuristic: if function is called internally, it might need public
        # This is a simplified check
        return 'this.' in func.body
    
    def _should_emit_events(self, func: FunctionContext) -> bool:
        """Check if function should emit events."""
        return (
            func.visibility in ['public', 'external'] and
            self._modifies_state(func) and
            not func.name.startswith('_')  # Internal functions may not need events
        )
    
    def _emits_events(self, func: FunctionContext) -> bool:
        """Check if function emits events."""
        return re.search(r'emit\s+\w+\s*\(', func.body, re.IGNORECASE) is not None
    
    def _has_parameter_validation_needs(self, func: FunctionContext) -> bool:
        """Check if function needs parameter validation."""
        return bool(func.parameters) and func.visibility in ['public', 'external']
    
    def _validates_parameters(self, func: FunctionContext) -> bool:
        """Check if function validates parameters."""
        return re.search(r'require\s*\(', func.body, re.IGNORECASE) is not None
    
    def _is_inefficient_loop(self, match: re.Match, code: str) -> bool:
        """Check if loop is inefficient."""
        # Simple heuristic: loops with storage operations
        loop_content = self._extract_loop_content(match, code)
        storage_patterns = [r'\[\w+\]\s*=', r'\.push\s*\(', r'\.length']
        
        return any(re.search(pattern, loop_content) for pattern in storage_patterns)
    
    def _extract_loop_content(self, match: re.Match, code: str) -> str:
        """Extract loop body content."""
        # Simple extraction - find content between braces after the loop
        start = match.end()
        brace_count = 0
        content_start = -1
        
        for i, char in enumerate(code[start:], start):
            if char == '{':
                if content_start == -1:
                    content_start = i + 1
                brace_count += 1
            elif char == '}':
                brace_count -= 1
                if brace_count == 0:
                    return code[content_start:i]
        
        return ""
