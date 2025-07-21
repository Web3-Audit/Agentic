"""
Invariant agent for analyzing smart contract invariants and formal properties.
"""

import re
import logging
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum

from ..base_agent import BaseAgent
from ...models.context import AnalysisContext, FunctionContext
from ...models.finding import Finding, Severity, Category, CodeLocation
from ...models.property import Property, PropertyType, InvariantProperty
from ...llm.client import LLMClient
from ...llm.prompts import PromptManager

logger = logging.getLogger(__name__)

class InvariantType(Enum):
    """Types of invariants."""
    BALANCE_CONSERVATION = "balance_conservation"
    SUPPLY_CONSERVATION = "supply_conservation"
    ACCESS_CONTROL = "access_control"
    STATE_CONSISTENCY = "state_consistency"
    ARITHMETIC_SAFETY = "arithmetic_safety"
    TEMPORAL = "temporal"

@dataclass
class ContractInvariant:
    """Represents a contract invariant."""
    invariant_type: InvariantType
    description: str
    expression: str
    affected_variables: List[str] = field(default_factory=list)
    affected_functions: List[str] = field(default_factory=list)
    is_violated: bool = False

class InvariantAgent(BaseAgent):
    """
    Agent focused on identifying and checking contract invariants.
    """
    
    def __init__(self, llm_client: Optional[LLMClient] = None, 
                 prompt_manager: Optional[PromptManager] = None):
        super().__init__("InvariantAgent", llm_client, prompt_manager)
        
        # Invariant patterns to detect
        self.invariant_patterns = {
            'balance_conservation': {
                'description': 'Token balance conservation',
                'variables': ['totalSupply', 'balance', 'balances'],
                'functions': ['transfer', 'mint', 'burn'],
                'expression': 'sum(balances) == totalSupply'
            },
            'supply_conservation': {
                'description': 'Total supply conservation',
                'variables': ['totalSupply', 'supply'],
                'functions': ['mint', 'burn'],
                'expression': 'totalSupply >= 0'
            },
            'access_control': {
                'description': 'Access control invariants',
                'variables': ['owner', 'admin', 'authorized'],
                'functions': ['onlyOwner', 'onlyAdmin'],
                'expression': 'msg.sender == owner'
            },
            'non_negative': {
                'description': 'Non-negative values',
                'variables': ['balance', 'amount', 'value'],
                'functions': ['transfer', 'withdraw'],
                'expression': 'value >= 0'
            }
        }

    def analyze(self, context: AnalysisContext) -> List[Finding]:
        """
        Analyze contract invariants.
        
        Args:
            context: Analysis context containing contract information
            
        Returns:
            List[Finding]: Invariant findings
        """
        self.logger.info("Starting invariant analysis")
        findings = []
        
        try:
            # Identify contract invariants
            contract_invariants = self._identify_contract_invariants(context)
            
            # Check invariant violations
            for contract_name, invariants in contract_invariants.items():
                violation_findings = self._check_invariant_violations(
                    contract_name, invariants, context
                )
                findings.extend(violation_findings)
            
            # Generate invariant properties for formal verification
            property_findings = self._generate_invariant_properties(context)
            findings.extend(property_findings)
            
            # LLM-enhanced analysis if available (made synchronous)
            if self.llm_client:
                llm_findings = self._llm_invariant_analysis(context)
                findings.extend(llm_findings)
            
            self.logger.info(f"Invariant analysis completed with {len(findings)} findings")
            return findings
            
        except Exception as e:
            self.logger.error(f"Error in invariant analysis: {str(e)}")
            return findings

    def _identify_contract_invariants(self, context: AnalysisContext) -> Dict[str, List[ContractInvariant]]:
        """Identify invariants for each contract."""
        contract_invariants = {}
        
        for contract_name, functions in context.functions.items():
            invariants = []
            
            # Check for balance conservation invariants
            if self._has_token_operations(functions):
                balance_invariant = ContractInvariant(
                    invariant_type=InvariantType.BALANCE_CONSERVATION,
                    description="Total token supply equals sum of all balances",
                    expression="sum(balances[addr] for addr in addresses) == totalSupply",
                    affected_variables=["totalSupply", "balances"],
                    affected_functions=[f.name for f in functions if self._is_balance_function(f)]
                )
                invariants.append(balance_invariant)
            
            # Check for access control invariants
            if self._has_access_control(functions):
                access_invariant = ContractInvariant(
                    invariant_type=InvariantType.ACCESS_CONTROL,
                    description="Only authorized users can call protected functions",
                    expression="hasRole(ADMIN_ROLE, msg.sender) || msg.sender == owner",
                    affected_variables=["owner", "admin", "roles"],
                    affected_functions=[f.name for f in functions if f.is_admin_only]
                )
                invariants.append(access_invariant)
            
            # Check for state consistency invariants
            state_invariants = self._identify_state_invariants(functions)
            invariants.extend(state_invariants)
            
            # Check for arithmetic safety invariants
            arithmetic_invariants = self._identify_arithmetic_invariants(functions)
            invariants.extend(arithmetic_invariants)
            
            contract_invariants[contract_name] = invariants
        
        return contract_invariants

    def _check_invariant_violations(self, contract_name: str, 
                                   invariants: List[ContractInvariant],
                                   context: AnalysisContext) -> List[Finding]:
        """Check for invariant violations."""
        findings = []
        
        functions = context.functions.get(contract_name, [])
        
        for invariant in invariants:
            violations = self._find_invariant_violations(invariant, functions)
            
            for violation in violations:
                severity = self._get_violation_severity(invariant.invariant_type)
                
                finding = Finding(
                    title=f"Invariant Violation: {invariant.description}",
                    description=f"Invariant '{invariant.expression}' may be violated in function '{violation}'",
                    severity=severity,
                    category=Category.BUSINESS_LOGIC,
                    location=CodeLocation(
                        contract_name=contract_name,
                        function_name=violation
                    ),
                    affected_contracts=[contract_name],
                    affected_functions=[violation],
                    recommendation=f"Ensure function '{violation}' maintains invariant: {invariant.expression}",
                    impact="Invariant violation could break contract correctness"
                )
                findings.append(finding)
        
        return findings

    def _generate_invariant_properties(self, context: AnalysisContext) -> List[Finding]:
        """Generate formal verification properties from invariants."""
        findings = []
        
        for contract_name, functions in context.functions.items():
            # Generate properties for critical functions
            critical_functions = [f for f in functions if f.is_critical]
            
            if critical_functions:
                finding = Finding(
                    title="Formal Verification Recommended",
                    description=f"Contract has {len(critical_functions)} critical functions that should be formally verified",
                    severity=Severity.INFO,
                    category=Category.BUSINESS_LOGIC,
                    location=CodeLocation(contract_name=contract_name),
                    affected_contracts=[contract_name],
                    affected_functions=[f.name for f in critical_functions],
                    recommendation="Consider formal verification using tools like Certora, K, or TLA+",
                    impact="Formal verification can catch subtle bugs in critical functions"
                )
                findings.append(finding)
        
        return findings

    def _llm_invariant_analysis(self, context: AnalysisContext) -> List[Finding]:
        """Perform LLM-enhanced invariant analysis (synchronous version)."""
        findings = []
        
        if not self.llm_client or not self.prompt_manager:
            return findings
        
        try:
            # For now, implement basic analysis without async LLM calls
            self.logger.info("LLM invariant analysis temporarily disabled for synchronous execution")
        except Exception as e:
            self.logger.error(f"Error in LLM invariant analysis: {str(e)}")
        
        return findings

    def _identify_state_invariants(self, functions: List[FunctionContext]) -> List[ContractInvariant]:
        """Identify state consistency invariants."""
        invariants = []
        
        # Look for state machine patterns
        state_functions = [f for f in functions if self._is_state_function(f)]
        
        if state_functions:
            state_invariant = ContractInvariant(
                invariant_type=InvariantType.STATE_CONSISTENCY,
                description="Contract state transitions are valid",
                expression="validStateTransition(oldState, newState)",
                affected_functions=[f.name for f in state_functions]
            )
            invariants.append(state_invariant)
        
        return invariants

    def _identify_arithmetic_invariants(self, functions: List[FunctionContext]) -> List[ContractInvariant]:
        """Identify arithmetic safety invariants."""
        invariants = []
        
        # Look for arithmetic operations
        arithmetic_functions = [f for f in functions if self._has_arithmetic_operations(f)]
        
        if arithmetic_functions:
            arithmetic_invariant = ContractInvariant(
                invariant_type=InvariantType.ARITHMETIC_SAFETY,
                description="Arithmetic operations don't overflow/underflow",
                expression="result >= operand1 && result >= operand2",
                affected_functions=[f.name for f in arithmetic_functions]
            )
            invariants.append(arithmetic_invariant)
        
        return invariants

    def _find_invariant_violations(self, invariant: ContractInvariant, 
                                  functions: List[FunctionContext]) -> List[str]:
        """Find functions that might violate the invariant."""
        violations = []
        
        for func in functions:
            if func.name in invariant.affected_functions:
                if self._function_violates_invariant(func, invariant):
                    violations.append(func.name)
        
        return violations

    def _function_violates_invariant(self, func: FunctionContext, 
                                   invariant: ContractInvariant) -> bool:
        """Check if function might violate invariant."""
        if invariant.invariant_type == InvariantType.BALANCE_CONSERVATION:
            return self._violates_balance_conservation(func)
        elif invariant.invariant_type == InvariantType.ACCESS_CONTROL:
            return self._violates_access_control(func)
        elif invariant.invariant_type == InvariantType.ARITHMETIC_SAFETY:
            return self._violates_arithmetic_safety(func)
        
        return False

    def _violates_balance_conservation(self, func: FunctionContext) -> bool:
        """Check if function violates balance conservation."""
        modifies_balance = any(var in func.body.lower() for var in ['balance', 'totalsupply'])
        has_conservation_check = any(pattern in func.body for pattern in ['require', 'assert'])
        
        return modifies_balance and not has_conservation_check

    def _violates_access_control(self, func: FunctionContext) -> bool:
        """Check if function violates access control."""
        is_protected = func.is_admin_only or any(mod in func.modifiers for mod in ['onlyOwner', 'onlyAdmin'])
        has_access_check = any(pattern in func.body for pattern in ['require(msg.sender', 'onlyOwner', 'hasRole'])
        
        return not is_protected and not has_access_check and func.visibility in ['public', 'external']

    def _violates_arithmetic_safety(self, func: FunctionContext) -> bool:
        """Check if function violates arithmetic safety."""
        has_arithmetic = any(op in func.body for op in ['+', '-', '*', '/'])
        has_safety_check = any(pattern in func.body.lower() for pattern in ['safemath', 'checked', 'unchecked'])
        
        return has_arithmetic and not has_safety_check

    def _get_violation_severity(self, invariant_type: InvariantType) -> Severity:
        """Get severity for invariant violation."""
        severity_map = {
            InvariantType.BALANCE_CONSERVATION: Severity.CRITICAL,
            InvariantType.SUPPLY_CONSERVATION: Severity.CRITICAL,
            InvariantType.ACCESS_CONTROL: Severity.HIGH,
            InvariantType.STATE_CONSISTENCY: Severity.HIGH,
            InvariantType.ARITHMETIC_SAFETY: Severity.MEDIUM,
            InvariantType.TEMPORAL: Severity.MEDIUM
        }
        
        return severity_map.get(invariant_type, Severity.MEDIUM)

    # Helper methods

    def _has_token_operations(self, functions: List[FunctionContext]) -> bool:
        """Check if contract has token operations."""
        token_operations = ['transfer', 'mint', 'burn', 'approve']
        return any(any(op in func.name.lower() for op in token_operations) for func in functions)

    def _is_balance_function(self, func: FunctionContext) -> bool:
        """Check if function affects balances."""
        balance_keywords = ['balance', 'transfer', 'mint', 'burn', 'supply']
        return any(keyword in func.name.lower() or keyword in func.body.lower() for keyword in balance_keywords)

    def _has_access_control(self, functions: List[FunctionContext]) -> bool:
        """Check if contract has access control."""
        return any(func.is_admin_only for func in functions)

    def _is_state_function(self, func: FunctionContext) -> bool:
        """Check if function manages state transitions."""
        state_keywords = ['state', 'phase', 'status', 'mode']
        return any(keyword in func.name.lower() for keyword in state_keywords)

    def _has_arithmetic_operations(self, func: FunctionContext) -> bool:
        """Check if function has arithmetic operations."""
        arithmetic_ops = ['+', '-', '*', '/', '%', '**']
        return any(op in func.body for op in arithmetic_ops)
