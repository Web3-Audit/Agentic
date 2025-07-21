"""
External interactions agent for analyzing smart contract external calls and dependencies.
"""

import re
import logging
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum

from ..base_agent import BaseAgent
from ...models.context import AnalysisContext, FunctionContext
from ...models.finding import Finding, Severity, Category, CodeLocation
from ...llm.client import LLMClient
from ...llm.prompts import PromptManager

logger = logging.getLogger(__name__)

class CallType(Enum):
    """Types of external calls."""
    LOW_LEVEL_CALL = "low_level_call"
    DELEGATECALL = "delegatecall"
    STATICCALL = "staticcall"
    INTERFACE_CALL = "interface_call"
    LIBRARY_CALL = "library_call"
    SEND_TRANSFER = "send_transfer"

@dataclass
class ExternalCall:
    """Represents an external call."""
    call_type: CallType
    target: str
    function_name: str
    location: CodeLocation
    is_checked: bool = False
    has_reentrancy_protection: bool = False

class ExternalInteractionsAgent(BaseAgent):
    """
    Agent focused on analyzing external contract interactions and dependencies.
    """
    
    def __init__(self, llm_client: Optional[LLMClient] = None, 
                 prompt_manager: Optional[PromptManager] = None):
        super().__init__("ExternalInteractionsAgent", llm_client, prompt_manager)
        
        # External interaction patterns
        self.interaction_patterns = {
            'unchecked_low_level_call': {
                'description': 'Unchecked low-level calls',
                'severity': Severity.HIGH,
                'patterns': [
                    r'\.call\s*\([^)]*\)\s*;',
                    r'\.delegatecall\s*\([^)]*\)\s*;'
                ]
            },
            'reentrancy_vulnerable': {
                'description': 'External calls vulnerable to reentrancy',
                'severity': Severity.CRITICAL,
                'patterns': [
                    r'\.call\s*\(',
                    r'\.send\s*\(',
                    r'\.transfer\s*\('
                ]
            },
            'oracle_dependency': {
                'description': 'Oracle price feed dependencies',
                'severity': Severity.MEDIUM,
                'patterns': [
                    r'oracle\.',
                    r'getPrice\s*\(',
                    r'latestRoundData\s*\(',
                    r'chainlink'
                ]
            },
            'external_library_usage': {
                'description': 'External library dependencies',
                'severity': Severity.LOW,
                'patterns': [
                    r'using\s+\w+\s+for',
                    r'library\s+\w+'
                ]
            }
        }

    def analyze(self, context: AnalysisContext) -> List[Finding]:
        """
        Analyze external interactions in smart contracts.
        
        Args:
            context: Analysis context containing contract information
            
        Returns:
            List[Finding]: External interaction findings
        """
        self.logger.info("Starting external interactions analysis")
        findings = []
        
        try:
            # Analyze each contract
            for contract_name, functions in context.functions.items():
                contract_findings = self._analyze_contract_external_interactions(
                    contract_name, functions, context
                )
                findings.extend(contract_findings)
            
            # Analyze cross-contract dependencies
            dependency_findings = self._analyze_contract_dependencies(context)
            findings.extend(dependency_findings)
            
            # LLM-enhanced analysis if available (made synchronous)
            if self.llm_client:
                llm_findings = self._llm_external_interactions_analysis(context)
                findings.extend(llm_findings)
            
            self.logger.info(f"External interactions analysis completed with {len(findings)} findings")
            return findings
            
        except Exception as e:
            self.logger.error(f"Error in external interactions analysis: {str(e)}")
            return findings

    def _analyze_contract_external_interactions(self, contract_name: str,
                                               functions: List[FunctionContext],
                                               context: AnalysisContext) -> List[Finding]:
        """Analyze external interactions for a specific contract."""
        findings = []
        
        # Check for unchecked external calls
        findings.extend(self._check_unchecked_external_calls(contract_name, functions))
        
        # Check for reentrancy vulnerabilities
        findings.extend(self._check_reentrancy_vulnerabilities(contract_name, functions))
        
        # Check oracle dependencies
        findings.extend(self._check_oracle_dependencies(contract_name, functions))
        
        # Check external contract dependencies
        findings.extend(self._check_external_contract_dependencies(contract_name, functions))
        
        # Check for proper error handling
        findings.extend(self._check_error_handling(contract_name, functions))
        
        return findings

    def _check_unchecked_external_calls(self, contract_name: str,
                                       functions: List[FunctionContext]) -> List[Finding]:
        """Check for unchecked external calls."""
        findings = []
        
        for func in functions:
            external_calls = self._find_external_calls(func)
            
            for call in external_calls:
                if not call.is_checked:
                    severity = Severity.CRITICAL if call.call_type == CallType.DELEGATECALL else Severity.HIGH
                    
                    finding = Finding(
                        title=f"Unchecked External Call in {func.name}",
                        description=f"Function '{func.name}' makes unchecked {call.call_type.value} to {call.target}",
                        severity=severity,
                        category=Category.UNCHECKED_CALLS,
                        location=call.location,
                        affected_contracts=[contract_name],
                        affected_functions=[func.name],
                        recommendation="Check return value and handle failures appropriately",
                        impact="Failed external calls could cause unexpected behavior"
                    )
                    findings.append(finding)
        
        return findings

    def _check_reentrancy_vulnerabilities(self, contract_name: str,
                                         functions: List[FunctionContext]) -> List[Finding]:
        """Check for reentrancy vulnerabilities in external calls."""
        findings = []
        
        for func in functions:
            if self._has_reentrancy_vulnerability(func):
                finding = Finding(
                    title=f"Reentrancy Vulnerability in {func.name}",
                    description=f"Function '{func.name}' is vulnerable to reentrancy attacks",
                    severity=Severity.CRITICAL,
                    category=Category.REENTRANCY,
                    location=CodeLocation(
                        contract_name=contract_name,
                        function_name=func.name
                    ),
                    affected_contracts=[contract_name],
                    affected_functions=[func.name],
                    recommendation="Implement checks-effects-interactions pattern and reentrancy guards",
                    impact="Attacker could drain contract funds through reentrancy"
                )
                findings.append(finding)
        
        return findings

    def _check_oracle_dependencies(self, contract_name: str,
                                  functions: List[FunctionContext]) -> List[Finding]:
        """Check for oracle dependency issues."""
        findings = []
        
        for func in functions:
            if self._uses_oracle(func):
                oracle_issues = []
                
                # Check for price manipulation protection
                if not self._has_price_validation(func):
                    oracle_issues.append("No price validation")
                
                # Check for staleness protection
                if not self._has_staleness_check(func):
                    oracle_issues.append("No staleness check")
                
                # Check for circuit breaker
                if not self._has_circuit_breaker(func):
                    oracle_issues.append("No circuit breaker")
                
                if oracle_issues:
                    finding = Finding(
                        title=f"Oracle Dependency Issues in {func.name}",
                        description=f"Function '{func.name}' has oracle issues: {', '.join(oracle_issues)}",
                        severity=Severity.HIGH,
                        category=Category.EXTERNAL_INTERACTIONS,
                        location=CodeLocation(
                            contract_name=contract_name,
                            function_name=func.name
                        ),
                        affected_contracts=[contract_name],
                        affected_functions=[func.name],
                        recommendation="Implement proper oracle validation, staleness checks, and circuit breakers",
                        impact="Oracle manipulation could lead to economic exploits"
                    )
                    findings.append(finding)
        
        return findings

    def _check_external_contract_dependencies(self, contract_name: str,
                                            functions: List[FunctionContext]) -> List[Finding]:
        """Check for external contract dependency issues."""
        findings = []
        
        external_dependencies = set()
        
        for func in functions:
            deps = self._find_external_dependencies(func)
            external_dependencies.update(deps)
        
        if len(external_dependencies) > 5:
            finding = Finding(
                title="High External Dependency Count",
                description=f"Contract has {len(external_dependencies)} external dependencies",
                severity=Severity.MEDIUM,
                category=Category.EXTERNAL_INTERACTIONS,
                location=CodeLocation(contract_name=contract_name),
                affected_contracts=[contract_name],
                recommendation="Consider reducing external dependencies or implementing fallback mechanisms",
                impact="High dependency count increases systemic risk"
            )
            findings.append(finding)
        
        return findings

    def _check_error_handling(self, contract_name: str,
                             functions: List[FunctionContext]) -> List[Finding]:
        """Check for proper error handling in external interactions."""
        findings = []
        
        for func in functions:
            if func.has_external_calls and not self._has_proper_error_handling(func):
                finding = Finding(
                    title=f"Inadequate Error Handling in {func.name}",
                    description=f"Function '{func.name}' doesn't properly handle external call failures",
                    severity=Severity.MEDIUM,
                    category=Category.EXTERNAL_INTERACTIONS,
                    location=CodeLocation(
                        contract_name=contract_name,
                        function_name=func.name
                    ),
                    affected_contracts=[contract_name],
                    affected_functions=[func.name],
                    recommendation="Implement proper try-catch blocks and failure handling",
                    impact="Unhandled failures could cause function reversion"
                )
                findings.append(finding)
        
        return findings

    def _analyze_contract_dependencies(self, context: AnalysisContext) -> List[Finding]:
        """Analyze cross-contract dependencies."""
        findings = []
        
        # Check for circular dependencies
        circular_deps = self._find_circular_dependencies(context)
        if circular_deps:
            finding = Finding(
                title="Circular Contract Dependencies",
                description=f"Circular dependencies detected: {' -> '.join(circular_deps)}",
                severity=Severity.MEDIUM,
                category=Category.EXTERNAL_INTERACTIONS,
                recommendation="Refactor to remove circular dependencies",
                impact="Circular dependencies can complicate upgrades and maintenance"
            )
            findings.append(finding)
        
        return findings

    def _llm_external_interactions_analysis(self, context: AnalysisContext) -> List[Finding]:
        """Perform LLM-enhanced external interactions analysis (synchronous version)."""
        findings = []
        
        if not self.llm_client or not self.prompt_manager:
            return findings
        
        try:
            # For now, implement basic analysis without async LLM calls
            # This can be enhanced later with proper async handling
            self.logger.info("LLM analysis temporarily disabled for synchronous execution")
        except Exception as e:
            self.logger.error(f"Error in LLM external interactions analysis: {str(e)}")
        
        return findings

    # Helper methods

    def _find_external_calls(self, func: FunctionContext) -> List[ExternalCall]:
        """Find external calls in function."""
        calls = []
        
        # Low-level calls
        call_pattern = r'(\w+)\.call\s*\('
        for match in re.finditer(call_pattern, func.body):
            target = match.group(1)
            is_checked = self._is_call_checked(func.body, match.start())
            
            call = ExternalCall(
                call_type=CallType.LOW_LEVEL_CALL,
                target=target,
                function_name=func.name,
                location=CodeLocation(function_name=func.name),
                is_checked=is_checked
            )
            calls.append(call)
        
        # Delegatecalls
        delegatecall_pattern = r'(\w+)\.delegatecall\s*\('
        for match in re.finditer(delegatecall_pattern, func.body):
            target = match.group(1)
            is_checked = self._is_call_checked(func.body, match.start())
            
            call = ExternalCall(
                call_type=CallType.DELEGATECALL,
                target=target,
                function_name=func.name,
                location=CodeLocation(function_name=func.name),
                is_checked=is_checked
            )
            calls.append(call)
        
        return calls

    def _is_call_checked(self, code: str, call_position: int) -> bool:
        """Check if external call result is checked."""
        # Look for success variable or require statement after call
        after_call = code[call_position:]
        
        check_patterns = [
            r'require\s*\(',
            r'assert\s*\(',
            r'if\s*\(\s*success\s*\)',
            r'success\s*==\s*true'
        ]
        
        return any(re.search(pattern, after_call[:200]) for pattern in check_patterns)

    def _has_reentrancy_vulnerability(self, func: FunctionContext) -> bool:
        """Check if function is vulnerable to reentrancy."""
        has_external_call = any(pattern in func.body for pattern in ['.call(', '.send(', '.transfer('])
        has_state_change_after = self._has_state_change_after_external_call(func.body)
        has_protection = any(pattern in func.body for pattern in ['nonReentrant', 'mutex', 'locked'])
        
        return has_external_call and has_state_change_after and not has_protection

    def _has_state_change_after_external_call(self, code: str) -> bool:
        """Check if state is modified after external call."""
        # Simple heuristic: look for assignment after call
        call_pos = code.find('.call(')
        if call_pos == -1:
            call_pos = code.find('.send(')
        if call_pos == -1:
            call_pos = code.find('.transfer(')
        
        if call_pos != -1:
            after_call = code[call_pos:]
            return '=' in after_call and 'balance' in after_call
        
        return False

    def _uses_oracle(self, func: FunctionContext) -> bool:
        """Check if function uses oracle."""
        oracle_patterns = [
            'oracle', 'getPrice', 'latestRoundData', 'chainlink',
            'priceFeed', 'aggregator'
        ]
        return any(pattern.lower() in func.body.lower() for pattern in oracle_patterns)

    def _has_price_validation(self, func: FunctionContext) -> bool:
        """Check if function validates oracle prices."""
        validation_patterns = [
            'require.*price', 'assert.*price', 'price.*>', 'price.*<'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) for pattern in validation_patterns)

    def _has_staleness_check(self, func: FunctionContext) -> bool:
        """Check if function checks for stale oracle data."""
        staleness_patterns = [
            'timestamp', 'updatedAt', 'block.timestamp', 'stale'
        ]
        return any(pattern in func.body for pattern in staleness_patterns)

    def _has_circuit_breaker(self, func: FunctionContext) -> bool:
        """Check if function has circuit breaker for oracle failures."""
        breaker_patterns = [
            'emergency', 'pause', 'stop', 'disable', 'fallback'
        ]
        return any(pattern.lower() in func.body.lower() for pattern in breaker_patterns)

    def _find_external_dependencies(self, func: FunctionContext) -> Set[str]:
        """Find external contract dependencies."""
        dependencies = set()
        
        # Look for contract interface calls
        interface_pattern = r'(\w+)\s*\(\s*\w+\s*\)\.\w+'
        for match in re.finditer(interface_pattern, func.body):
            dependencies.add(match.group(1))
        
        return dependencies

    def _has_proper_error_handling(self, func: FunctionContext) -> bool:
        """Check if function has proper error handling."""
        error_handling_patterns = [
            'try', 'catch', 'require(', 'assert(', 'revert('
        ]
        return any(pattern in func.body for pattern in error_handling_patterns)

    def _find_circular_dependencies(self, context: AnalysisContext) -> List[str]:
        """Find circular dependencies between contracts."""
        # This would implement sophisticated dependency analysis
        # For now, return empty list
        return []
