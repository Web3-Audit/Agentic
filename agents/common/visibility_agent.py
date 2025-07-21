"""
Visibility agent for analyzing function and variable visibility issues.
"""

import re
import logging
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum

from ..base_agent import BaseAgent
from ...models.context import AnalysisContext, FunctionContext, StateVariableContext
from ...models.finding import Finding, Severity, Category, CodeLocation
from ...llm.client import LLMClient
from ...llm.prompts import PromptManager

logger = logging.getLogger(__name__)

class VisibilityIssueType(Enum):
    """Types of visibility issues."""
    OVERLY_PERMISSIVE = "overly_permissive"
    MISSING_ACCESS_CONTROL = "missing_access_control"
    UNNECESSARY_PUBLIC = "unnecessary_public"
    SENSITIVE_DATA_EXPOSED = "sensitive_data_exposed"
    INEFFICIENT_VISIBILITY = "inefficient_visibility"

@dataclass
class VisibilityIssue:
    """Represents a visibility issue."""
    issue_type: VisibilityIssueType
    element_name: str
    element_type: str  # function, variable, etc.
    current_visibility: str
    recommended_visibility: str
    severity: Severity
    reasoning: str

class VisibilityAgent(BaseAgent):
    """
    Agent focused on analyzing function and variable visibility issues.
    """
    
    def __init__(self, llm_client: Optional[LLMClient] = None, 
                 prompt_manager: Optional[PromptManager] = None):
        super().__init__("VisibilityAgent", llm_client, prompt_manager)
        
        # Patterns for sensitive data
        self.sensitive_patterns = [
            'private.*key', 'secret', 'password', 'seed', 'mnemonic',
            'admin', 'owner', 'authorized', 'permission'
        ]
        
        # Patterns for functions that should be internal/private
        self.internal_function_patterns = [
            '_.*',  # Functions starting with underscore
            '.*[Ii]nternal.*', '.*[Hh]elper.*', '.*[Uu]tility.*'
        ]

    def analyze(self, context: AnalysisContext) -> List[Finding]:
        """
        Analyze visibility issues in smart contracts.
        
        Args:
            context: Analysis context containing contract information
            
        Returns:
            List[Finding]: Visibility findings
        """
        self.logger.info("Starting visibility analysis")
        findings = []
        
        try:
            # Analyze each contract
            for contract_name, functions in context.functions.items():
                # Analyze function visibility
                function_findings = self._analyze_function_visibility(
                    contract_name, functions
                )
                findings.extend(function_findings)
                
                # Analyze state variable visibility
                if contract_name in context.state_variables:
                    variable_findings = self._analyze_variable_visibility(
                        contract_name, context.state_variables[contract_name]
                    )
                    findings.extend(variable_findings)
            
            # LLM-enhanced analysis if available (made synchronous)
            if self.llm_client:
                llm_findings = self._llm_visibility_analysis(context)
                findings.extend(llm_findings)
            
            self.logger.info(f"Visibility analysis completed with {len(findings)} findings")
            return findings
            
        except Exception as e:
            self.logger.error(f"Error in visibility analysis: {str(e)}")
            return findings

    def _analyze_function_visibility(self, contract_name: str,
                                   functions: List[FunctionContext]) -> List[Finding]:
        """Analyze function visibility issues."""
        findings = []
        
        for func in functions:
            issues = self._check_function_visibility_issues(func)
            
            for issue in issues:
                finding = Finding(
                    title=f"Function Visibility Issue: {func.name}",
                    description=f"Function '{func.name}' has {issue.issue_type.value}: {issue.reasoning}",
                    severity=issue.severity,
                    category=Category.ACCESS_CONTROL,
                    location=CodeLocation(
                        contract_name=contract_name,
                        function_name=func.name
                    ),
                    affected_contracts=[contract_name],
                    affected_functions=[func.name],
                    recommendation=f"Change visibility from '{issue.current_visibility}' to '{issue.recommended_visibility}'",
                    impact=self._get_visibility_impact(issue)
                )
                findings.append(finding)
        
        return findings

    def _analyze_variable_visibility(self, contract_name: str,
                                   variables: List[StateVariableContext]) -> List[Finding]:
        """Analyze state variable visibility issues."""
        findings = []
        
        for var in variables:
            issues = self._check_variable_visibility_issues(var)
            
            for issue in issues:
                finding = Finding(
                    title=f"State Variable Visibility Issue: {var.name}",
                    description=f"Variable '{var.name}' has {issue.issue_type.value}: {issue.reasoning}",
                    severity=issue.severity,
                    category=Category.ACCESS_CONTROL,
                    location=CodeLocation(contract_name=contract_name),
                    affected_contracts=[contract_name],
                    recommendation=f"Change visibility from '{issue.current_visibility}' to '{issue.recommended_visibility}'",
                    impact=self._get_visibility_impact(issue)
                )
                findings.append(finding)
        
        return findings

    def _check_function_visibility_issues(self, func: FunctionContext) -> List[VisibilityIssue]:
        """Check for function visibility issues."""
        issues = []
        
        # Check for overly permissive public functions
        if func.visibility == 'public' and not self._should_be_public(func):
            if self._should_be_internal(func):
                recommended = 'internal'
            elif self._should_be_private(func):
                recommended = 'private'
            else:
                recommended = 'external'
            
            issue = VisibilityIssue(
                issue_type=VisibilityIssueType.OVERLY_PERMISSIVE,
                element_name=func.name,
                element_type='function',
                current_visibility=func.visibility,
                recommended_visibility=recommended,
                severity=Severity.LOW,
                reasoning=f"Function doesn't need to be public"
            )
            issues.append(issue)
        
        # Check for missing access control on sensitive functions
        if self._is_sensitive_function(func) and not self._has_access_control(func):
            issue = VisibilityIssue(
                issue_type=VisibilityIssueType.MISSING_ACCESS_CONTROL,
                element_name=func.name,
                element_type='function',
                current_visibility=func.visibility,
                recommended_visibility=func.visibility,
                severity=Severity.HIGH,
                reasoning="Sensitive function lacks access control"
            )
            issues.append(issue)
        
        # Check for inefficient visibility (external vs public)
        if func.visibility == 'public' and not self._called_internally(func):
            issue = VisibilityIssue(
                issue_type=VisibilityIssueType.INEFFICIENT_VISIBILITY,
                element_name=func.name,
                element_type='function',
                current_visibility='public',
                recommended_visibility='external',
                severity=Severity.LOW,
                reasoning="Function only called externally, external is more gas efficient"
            )
            issues.append(issue)
        
        return issues

    def _check_variable_visibility_issues(self, var: StateVariableContext) -> List[VisibilityIssue]:
        """Check for state variable visibility issues."""
        issues = []
        
        # Check for sensitive data exposure
        if self._is_sensitive_variable(var) and var.visibility == 'public':
            issue = VisibilityIssue(
                issue_type=VisibilityIssueType.SENSITIVE_DATA_EXPOSED,
                element_name=var.name,
                element_type='state_variable',
                current_visibility='public',
                recommended_visibility='private',
                severity=Severity.MEDIUM,
                reasoning="Sensitive variable should not be public"
            )
            issues.append(issue)
        
        # Check for unnecessary public variables
        if var.visibility == 'public' and not self._needs_public_getter(var):
            issue = VisibilityIssue(
                issue_type=VisibilityIssueType.UNNECESSARY_PUBLIC,
                element_name=var.name,
                element_type='state_variable',
                current_visibility='public',
                recommended_visibility='internal',
                severity=Severity.LOW,
                reasoning="Variable doesn't need automatic public getter"
            )
            issues.append(issue)
        
        # Check for large public variables (gas inefficient)
        if var.visibility == 'public' and self._is_large_variable(var):
            issue = VisibilityIssue(
                issue_type=VisibilityIssueType.INEFFICIENT_VISIBILITY,
                element_name=var.name,
                element_type='state_variable',
                current_visibility='public',
                recommended_visibility='internal',
                severity=Severity.LOW,
                reasoning="Large variable with public getter is gas inefficient"
            )
            issues.append(issue)
        
        return issues

    def _llm_visibility_analysis(self, context: AnalysisContext) -> List[Finding]:
        """Perform LLM-enhanced visibility analysis (synchronous version)."""
        findings = []
        
        if not self.llm_client or not self.prompt_manager:
            return findings
        
        try:
            # For now, implement basic analysis without async LLM calls
            self.logger.info("LLM visibility analysis temporarily disabled for synchronous execution")
        except Exception as e:
            self.logger.error(f"Error in LLM visibility analysis: {str(e)}")
        
        return findings

    def _should_be_public(self, func: FunctionContext) -> bool:
        """Check if function should be public."""
        # Functions that should be public
        public_patterns = [
            'constructor', 'fallback', 'receive',
            # Standard interface functions
            'transfer', 'approve', 'transferFrom', 'balanceOf',
            'totalSupply', 'name', 'symbol', 'decimals'
        ]
        
        return (func.name in public_patterns or 
                func.function_type in ['constructor', 'fallback', 'receive'] or
                self._is_interface_function(func))

    def _should_be_internal(self, func: FunctionContext) -> bool:
        """Check if function should be internal."""
        return (any(re.match(pattern, func.name) for pattern in self.internal_function_patterns) or
                self._is_helper_function(func))

    def _should_be_private(self, func: FunctionContext) -> bool:
        """Check if function should be private."""
        return (func.name.startswith('__') or  # Double underscore prefix
                'private' in func.name.lower())

    def _is_sensitive_function(self, func: FunctionContext) -> bool:
        """Check if function is sensitive."""
        sensitive_keywords = [
            'admin', 'owner', 'withdraw', 'mint', 'burn', 'pause',
            'upgrade', 'selfdestruct', 'destroy', 'kill'
        ]
        
        return (any(keyword in func.name.lower() for keyword in sensitive_keywords) or
                func.is_admin_only or
                func.is_critical)

    def _has_access_control(self, func: FunctionContext) -> bool:
        """Check if function has access control."""
        access_patterns = [
            'onlyOwner', 'onlyAdmin', 'authorized', 'hasRole',
            'require(msg.sender', 'modifier'
        ]
        
        return (any(pattern in func.body for pattern in access_patterns) or
                any(mod in func.modifiers for mod in ['onlyOwner', 'onlyAdmin', 'authorized']))

    def _called_internally(self, func: FunctionContext) -> bool:
        """Check if function is called internally."""
        # This would require more sophisticated analysis of call graph
        # For now, use simple heuristics
        return (func.name.startswith('_') or
                'internal' in func.name.lower() or
                'helper' in func.name.lower())

    def _is_sensitive_variable(self, var: StateVariableContext) -> bool:
        """Check if variable contains sensitive data."""
        var_name_lower = var.name.lower()
        return any(re.search(pattern, var_name_lower) for pattern in self.sensitive_patterns)

    def _needs_public_getter(self, var: StateVariableContext) -> bool:
        """Check if variable needs public getter."""
        # Common variables that benefit from public getters
        public_getter_patterns = [
            'name', 'symbol', 'decimals', 'totalSupply', 'version',
            'owner', 'paused', 'initialized'
        ]
        
        return (var.name in public_getter_patterns or
                var.type == 'address' and 'owner' in var.name.lower())

    def _is_large_variable(self, var: StateVariableContext) -> bool:
        """Check if variable is large (inefficient public getter)."""
        large_types = ['mapping', 'struct', 'array', 'string', 'bytes']
        return any(large_type in var.type.lower() for large_type in large_types)

    def _is_interface_function(self, func: FunctionContext) -> bool:
        """Check if function is part of a standard interface."""
        # ERC20 interface functions
        erc20_functions = [
            'totalSupply', 'balanceOf', 'transfer', 'allowance',
            'approve', 'transferFrom'
        ]
        
        # ERC721 interface functions
        erc721_functions = [
            'balanceOf', 'ownerOf', 'approve', 'getApproved',
            'setApprovalForAll', 'isApprovedForAll', 'transferFrom',
            'safeTransferFrom'
        ]
        
        return func.name in erc20_functions or func.name in erc721_functions

    def _is_helper_function(self, func: FunctionContext) -> bool:
        """Check if function is a helper function."""
        helper_keywords = ['helper', 'utility', 'internal', 'calculate', 'compute']
        return any(keyword in func.name.lower() for keyword in helper_keywords)

    def _get_visibility_impact(self, issue: VisibilityIssue) -> str:
        """Get impact description for visibility issue."""
        impact_map = {
            VisibilityIssueType.OVERLY_PERMISSIVE: "Increases attack surface and gas costs",
            VisibilityIssueType.MISSING_ACCESS_CONTROL: "Unauthorized users could call sensitive functions",
            VisibilityIssueType.UNNECESSARY_PUBLIC: "Automatic getter consumes extra gas",
            VisibilityIssueType.SENSITIVE_DATA_EXPOSED: "Sensitive information visible on blockchain",
            VisibilityIssueType.INEFFICIENT_VISIBILITY: "Higher gas costs for function calls"
        }
        
        return impact_map.get(issue.issue_type, "Could affect contract security or efficiency")
