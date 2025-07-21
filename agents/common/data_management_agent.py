"""
Data management agent for analyzing smart contract data handling and storage patterns.
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

class StorageType(Enum):
    """Types of storage in Solidity."""
    STORAGE = "storage"
    MEMORY = "memory"
    CALLDATA = "calldata"
    STACK = "stack"

@dataclass
class DataPattern:
    """Represents a data management pattern."""
    pattern_type: str
    description: str
    risk_level: str
    locations: List[str] = field(default_factory=list)

class DataManagementAgent(BaseAgent):
    """
    Agent focused on data management, storage optimization, and data flow analysis.
    """
    
    def __init__(self, llm_client: Optional[LLMClient] = None, 
                 prompt_manager: Optional[PromptManager] = None):
        super().__init__("DataManagementAgent", llm_client, prompt_manager)
        
        # Data management patterns to check
        self.data_patterns = {
            'inefficient_storage': {
                'description': 'Inefficient storage usage patterns',
                'severity': Severity.LOW,
                'patterns': [
                    r'string\s+public\s+\w+',     # Public string storage
                    r'bytes\s+public\s+\w+',      # Public bytes storage
                    r'uint8\[\]\s+\w+',           # Small uint arrays
                ]
            },
            'uninitialized_storage': {
                'description': 'Uninitialized storage variables',
                'severity': Severity.MEDIUM,
                'patterns': [
                    r'mapping\s*\([^)]+\)\s+\w+\s*;',
                    r'\w+\[\]\s+\w+\s*;'
                ]
            },
            'storage_collision': {
                'description': 'Potential storage collision in upgradeable contracts',
                'severity': Severity.HIGH,
                'patterns': [
                    r'uint256\s+private\s+__gap',
                    r'initializer',
                    r'upgradeable'
                ]
            },
            'data_exposure': {
                'description': 'Sensitive data potentially exposed',
                'severity': Severity.MEDIUM,
                'patterns': [
                    r'private.*password',
                    r'private.*key',
                    r'private.*secret'
                ]
            },
            'memory_waste': {
                'description': 'Wasteful memory usage',
                'severity': Severity.LOW,
                'patterns': [
                    r'memory.*\[\].*new',
                    r'memory.*string.*concat'
                ]
            }
        }

    async def analyze(self, context: AnalysisContext) -> List[Finding]:
        logger.info("Starting data management analysis")
        findings: List[Finding] = []
        try:
            for contract_name, functions in context.functions.items():
                contract_findings = self._analyze_contract_data_management(contract_name, functions, context)
                findings.extend(contract_findings)
            for contract_name, variables in getattr(context, "state_variables", {}).items():
                variable_findings = self._analyze_state_variables(contract_name, variables)
                findings.extend(variable_findings)
            data_flow_findings = self._analyze_data_flow(context)
            findings.extend(data_flow_findings)
            # LLM-enhanced analysis if available
            if self.llm_client:
                llm_findings = await self._llm_data_management_analysis(context)
                findings.extend(llm_findings)
            logger.info(f"Data management analysis completed with {len(findings)} findings")
            return findings
        except Exception as e:
            logger.error(f"Error in data management analysis: {str(e)}")
            return findings

    def _analyze_contract_data_management(self, contract_name: str,
                                         functions: List[FunctionContext],
                                         context: AnalysisContext) -> List[Finding]:
        """Analyze data management for a specific contract."""
        findings = []
        
        # Check storage vs memory usage
        findings.extend(self._check_storage_memory_usage(contract_name, functions))
        
        # Check data initialization
        findings.extend(self._check_data_initialization(contract_name, functions))
        
        # Check data validation
        findings.extend(self._check_data_validation(contract_name, functions))
        
        # Check for data races and concurrent access
        findings.extend(self._check_data_races(contract_name, functions))
        
        # Check array and mapping usage
        findings.extend(self._check_array_mapping_usage(contract_name, functions))
        
        return findings

    def _check_storage_memory_usage(self, contract_name: str,
                                   functions: List[FunctionContext]) -> List[Finding]:
        """Check for inefficient storage vs memory usage."""
        findings = []
        
        for func in functions:
            # Check for unnecessary storage usage
            if self._has_unnecessary_storage_usage(func):
                finding = Finding(
                    title=f"Inefficient Storage Usage in {func.name}",
                    description=f"Function '{func.name}' uses storage where memory would be more efficient",
                    severity=Severity.LOW,
                    category=Category.GAS_OPTIMIZATION,
                    location=CodeLocation(
                        contract_name=contract_name,
                        function_name=func.name
                    ),
                    affected_contracts=[contract_name],
                    affected_functions=[func.name],
                    recommendation="Use memory for temporary data and calldata for read-only parameters",
                    impact="Higher gas costs due to unnecessary storage operations"
                )
                findings.append(finding)
            
            # Check for memory in loops
            if self._has_memory_allocation_in_loops(func):
                finding = Finding(
                    title=f"Memory Allocation in Loop in {func.name}",
                    description=f"Function '{func.name}' allocates memory inside loops",
                    severity=Severity.MEDIUM,
                    category=Category.GAS_OPTIMIZATION,
                    location=CodeLocation(
                        contract_name=contract_name,
                        function_name=func.name
                    ),
                    affected_contracts=[contract_name],
                    affected_functions=[func.name],
                    recommendation="Pre-allocate memory outside loops or use storage for persistent data",
                    impact="High gas costs due to repeated memory allocations"
                )
                findings.append(finding)
            
            # Check for large memory usage
            if self._has_large_memory_usage(func):
                finding = Finding(
                    title=f"Large Memory Usage in {func.name}",
                    description=f"Function '{func.name}' uses large amounts of memory",
                    severity=Severity.MEDIUM,
                    category=Category.GAS_OPTIMIZATION,
                    location=CodeLocation(
                        contract_name=contract_name,
                        function_name=func.name
                    ),
                    affected_contracts=[contract_name],
                    affected_functions=[func.name],
                    recommendation="Consider using storage or breaking down into smaller operations",
                    impact="High gas costs and potential out-of-gas errors"
                )
                findings.append(finding)
        
        return findings

    def _check_data_initialization(self, contract_name: str,
                                  functions: List[FunctionContext]) -> List[Finding]:
        """Check for proper data initialization."""
        findings = []
        
        for func in functions:
            # Check for uninitialized variables
            if self._has_uninitialized_variables(func):
                finding = Finding(
                    title=f"Uninitialized Variables in {func.name}",
                    description=f"Function '{func.name}' uses potentially uninitialized variables",
                    severity=Severity.MEDIUM,
                    category=Category.DATA_MANAGEMENT,
                    location=CodeLocation(
                        contract_name=contract_name,
                        function_name=func.name
                    ),
                    affected_contracts=[contract_name],
                    affected_functions=[func.name],
                    recommendation="Initialize all variables before use",
                    impact="Undefined behavior due to uninitialized data"
                )
                findings.append(finding)
            
            # Check for missing constructor initialization
            if func.name == 'constructor' and not self._has_proper_initialization(func):
                finding = Finding(
                    title="Incomplete Constructor Initialization",
                    description="Constructor doesn't properly initialize all state variables",
                    severity=Severity.MEDIUM,
                    category=Category.DATA_MANAGEMENT,
                    location=CodeLocation(
                        contract_name=contract_name,
                        function_name=func.name
                    ),
                    affected_contracts=[contract_name],
                    affected_functions=[func.name],
                    recommendation="Ensure all critical state variables are initialized in constructor",
                    impact="Contract may be in invalid state after deployment"
                )
                findings.append(finding)
        
        return findings

    def _check_data_validation(self, contract_name: str,
                              functions: List[FunctionContext]) -> List[Finding]:
        """Check for proper data validation."""
        findings = []
        
        for func in functions:
            if func.visibility in ['public', 'external'] and func.parameters:
                # Check for input validation
                if not self._has_input_validation(func):
                    finding = Finding(
                        title=f"Missing Input Validation in {func.name}",
                        description=f"Function '{func.name}' doesn't validate input parameters",
                        severity=Severity.MEDIUM,
                        category=Category.DATA_MANAGEMENT,
                        location=CodeLocation(
                            contract_name=contract_name,
                            function_name=func.name
                        ),
                        affected_contracts=[contract_name],
                        affected_functions=[func.name],
                        recommendation="Add require() statements to validate all input parameters",
                        impact="Invalid inputs could cause unexpected behavior"
                    )
                    findings.append(finding)
                
                # Check for boundary validation
                if not self._has_boundary_validation(func):
                    finding = Finding(
                        title=f"Missing Boundary Validation in {func.name}",
                        description=f"Function '{func.name}' doesn't validate parameter boundaries",
                        severity=Severity.MEDIUM,
                        category=Category.DATA_MANAGEMENT,
                        location=CodeLocation(
                            contract_name=contract_name,
                            function_name=func.name
                        ),
                        affected_contracts=[contract_name],
                        affected_functions=[func.name],
                        recommendation="Validate parameter ranges and array bounds",
                        impact="Out-of-bounds access could cause errors or exploits"
                    )
                    findings.append(finding)
        
        return findings

    def _check_data_races(self, contract_name: str,
                         functions: List[FunctionContext]) -> List[Finding]:
        """Check for potential data races and concurrent access issues."""
        findings = []
        
        state_modifying_functions = [f for f in functions if f.has_state_changes]
        
        if len(state_modifying_functions) > 1:
            # Check for functions that modify the same state without protection
            shared_state_groups = self._find_shared_state_functions(state_modifying_functions)
            
            for group in shared_state_groups:
                if len(group) > 1 and not self._has_reentrancy_protection(group[0]):
                    function_names = [f.name for f in group]
                    
                    finding = Finding(
                        title="Potential Data Race Condition",
                        description=f"Functions {function_names} modify shared state without protection",
                        severity=Severity.HIGH,
                        category=Category.DATA_MANAGEMENT,
                        location=CodeLocation(contract_name=contract_name),
                        affected_contracts=[contract_name],
                        affected_functions=function_names,
                        recommendation="Add reentrancy guards or mutex locks to prevent concurrent access",
                        impact="Race conditions could lead to inconsistent state"
                    )
                    findings.append(finding)
        
        return findings

    def _check_array_mapping_usage(self, contract_name: str,
                                  functions: List[FunctionContext]) -> List[Finding]:
        """Check for efficient array and mapping usage."""
        findings = []
        
        for func in functions:
            # Check for unbounded loops over arrays
            if self._has_unbounded_array_loops(func):
                finding = Finding(
                    title=f"Unbounded Array Loop in {func.name}",
                    description=f"Function '{func.name}' loops over arrays without bounds checking",
                    severity=Severity.HIGH,
                    category=Category.DENIAL_OF_SERVICE,
                    location=CodeLocation(
                        contract_name=contract_name,
                        function_name=func.name
                    ),
                    affected_contracts=[contract_name],
                    affected_functions=[func.name],
                    recommendation="Add bounds checking or pagination to prevent gas limit issues",
                    impact="Function could hit gas limit and become unusable"
                )
                findings.append(finding)
            
            # Check for inefficient array operations
            if self._has_inefficient_array_operations(func):
                finding = Finding(
                    title=f"Inefficient Array Operations in {func.name}",
                    description=f"Function '{func.name}' uses inefficient array operations",
                    severity=Severity.LOW,
                    category=Category.GAS_OPTIMIZATION,
                    location=CodeLocation(
                        contract_name=contract_name,
                        function_name=func.name
                    ),
                    affected_contracts=[contract_name],
                    affected_functions=[func.name],
                    recommendation="Use mappings for lookups and optimize array operations",
                    impact="Higher gas costs for array operations"
                )
                findings.append(finding)
        
        return findings

    def _analyze_state_variables(self, contract_name: str,
                                variables: List[StateVariableContext]) -> List[Finding]:
        """Analyze state variables for data management issues."""
        findings = []
        
        # Check for packing opportunities
        packing_findings = self._check_storage_packing(contract_name, variables)
        findings.extend(packing_findings)
        
        # Check for unnecessary public variables
        public_findings = self._check_unnecessary_public_variables(contract_name, variables)
        findings.extend(public_findings)
        
        # Check for sensitive data exposure
        exposure_findings = self._check_sensitive_data_exposure(contract_name, variables)
        findings.extend(exposure_findings)
        
        return findings

    def _check_storage_packing(self, contract_name: str,
                              variables: List[StateVariableContext]) -> List[Finding]:
        """Check for storage packing opportunities."""
        findings = []
        
        # Group variables by storage slot potential
        packable_vars = []
        for var in variables:
            if self._is_packable_type(var.type):
                packable_vars.append(var)
        
        if len(packable_vars) >= 2:
            # Check if variables could be packed together
            total_size = sum(self._get_type_size(var.type) for var in packable_vars)
            
            if total_size <= 32:  # Can fit in one storage slot
                var_names = [var.name for var in packable_vars]
                
                finding = Finding(
                    title="Storage Packing Opportunity",
                    description=f"Variables {var_names} could be packed into fewer storage slots",
                    severity=Severity.LOW,
                    category=Category.GAS_OPTIMIZATION,
                    location=CodeLocation(contract_name=contract_name),
                    affected_contracts=[contract_name],
                    recommendation="Reorder variable declarations to pack smaller types together",
                    impact="Could save gas on storage operations"
                )
                findings.append(finding)
        
        return findings

    def _check_unnecessary_public_variables(self, contract_name: str,
                                           variables: List[StateVariableContext]) -> List[Finding]:
        """Check for unnecessary public state variables."""
        findings = []
        
        unnecessary_public = []
        for var in variables:
            if (var.visibility == 'public' and 
                self._is_large_type(var.type) and 
                not self._is_commonly_accessed(var.name)):
                unnecessary_public.append(var.name)
        
        if unnecessary_public:
            finding = Finding(
                title="Unnecessary Public State Variables",
                description=f"Large state variables are public but may not need to be: {', '.join(unnecessary_public)}",
                severity=Severity.LOW,
                category=Category.GAS_OPTIMIZATION,
                location=CodeLocation(contract_name=contract_name),
                affected_contracts=[contract_name],
                recommendation="Make variables private/internal and add getter functions if needed",
                impact="Automatic getters for large types consume extra gas"
            )
            findings.append(finding)
        
        return findings

    def _check_sensitive_data_exposure(self, contract_name: str,
                                      variables: List[StateVariableContext]) -> List[Finding]:
        """Check for potential sensitive data exposure."""
        findings = []
        
        sensitive_vars = []
        sensitive_keywords = ['key', 'secret', 'password', 'private', 'seed']
        
        for var in variables:
            var_name_lower = var.name.lower()
            if any(keyword in var_name_lower for keyword in sensitive_keywords):
                sensitive_vars.append(var.name)
        
        if sensitive_vars:
            finding = Finding(
                title="Potential Sensitive Data Exposure",
                description=f"Variables may contain sensitive data: {', '.join(sensitive_vars)}",
                severity=Severity.MEDIUM,
                category=Category.DATA_MANAGEMENT,
                location=CodeLocation(contract_name=contract_name),
                affected_contracts=[contract_name],
                recommendation="Use commit-reveal schemes or external storage for sensitive data",
                impact="Sensitive information could be exposed on the blockchain"
            )
            findings.append(finding)
        
        return findings

    def _analyze_data_flow(self, context: AnalysisContext) -> List[Finding]:
        """Analyze data flow across the contract system."""
        findings = []
        
        # Check for data consistency across functions
        consistency_findings = self._check_data_consistency(context)
        findings.extend(consistency_findings)
        
        # Check for proper data encapsulation
        encapsulation_findings = self._check_data_encapsulation(context)
        findings.extend(encapsulation_findings)
        
        return findings

    def _check_data_consistency(self, context: AnalysisContext) -> List[Finding]:
        """Check for data consistency issues."""
        findings = []
        
        # This would implement more sophisticated data flow analysis
        # For now, return empty list
        
        return findings

    def _check_data_encapsulation(self, context: AnalysisContext) -> List[Finding]:
        """Check for proper data encapsulation."""
        findings = []
        
        # This would check for proper encapsulation patterns
        # For now, return empty list
        
        return findings

    async def _llm_data_management_analysis(self, context: AnalysisContext) -> List[Finding]:
        """Perform LLM-enhanced data management analysis."""
        findings = []
        
        if not self.llm_client or not self.prompt_manager:
            return findings
        
        try:
            # Generate data management analysis using LLM
            # Implementation would use structured prompts
            pass
        except Exception as e:
            self.logger.error(f"Error in LLM data management analysis: {str(e)}")
        
        return findings

    # Helper methods

    def _has_unnecessary_storage_usage(self, func: FunctionContext) -> bool:
        """Check for unnecessary storage usage."""
        storage_patterns = ['storage', 'state']
        memory_candidates = ['temp', 'tmp', 'buffer', 'cache']
        
        return (any(pattern in func.body for pattern in storage_patterns) and
                any(candidate in func.body.lower() for candidate in memory_candidates))

    def _has_memory_allocation_in_loops(self, func: FunctionContext) -> bool:
        """Check for memory allocation inside loops."""
        has_loops = any(pattern in func.body for pattern in ['for (', 'while ('])
        has_memory_alloc = any(pattern in func.body for pattern in ['new ', 'memory'])
        
        return has_loops and has_memory_alloc

    def _has_large_memory_usage(self, func: FunctionContext) -> bool:
        """Check for large memory usage."""
        large_patterns = ['bytes memory', 'string memory', 'uint256[] memory']
        return any(pattern in func.body for pattern in large_patterns)

    def _has_uninitialized_variables(self, func: FunctionContext) -> bool:
        """Check for uninitialized variables."""
        # Simple heuristic: variable declaration without assignment
        uninitialized_pattern = r'\b\w+\s+\w+\s*;'
        return bool(re.search(uninitialized_pattern, func.body))

    def _has_proper_initialization(self, func: FunctionContext) -> bool:
        """Check if constructor properly initializes variables."""
        initialization_patterns = ['=', 'initialize', 'setup']
        return any(pattern in func.body for pattern in initialization_patterns)

    def _has_input_validation(self, func: FunctionContext) -> bool:
        """Check for input validation."""
        validation_patterns = ['require(', 'assert(', 'revert(']
        return any(pattern in func.body for pattern in validation_patterns)

    def _has_boundary_validation(self, func: FunctionContext) -> bool:
        """Check for boundary validation."""
        boundary_patterns = ['>', '<', '>=', '<=', '.length']
        return any(pattern in func.body for pattern in boundary_patterns)

    def _find_shared_state_functions(self, functions: List[FunctionContext]) -> List[List[FunctionContext]]:
        """Find functions that modify shared state."""
        # This would implement sophisticated analysis to find shared state
        # For now, return empty list
        return []

    def _has_reentrancy_protection(self, func: FunctionContext) -> bool:
        """Check for reentrancy protection."""
        protection_patterns = ['nonReentrant', 'mutex', 'locked', 'guard']
        return any(pattern in func.body for pattern in protection_patterns)

    def _has_unbounded_array_loops(self, func: FunctionContext) -> bool:
        """Check for unbounded array loops."""
        has_array_loop = bool(re.search(r'for\s*\([^)]*length[^)]*\)', func.body))
        has_bounds_check = 'require(' in func.body or 'assert(' in func.body
        
        return has_array_loop and not has_bounds_check

    def _has_inefficient_array_operations(self, func: FunctionContext) -> bool:
        """Check for inefficient array operations."""
        inefficient_patterns = ['.push(', 'delete ', 'array[i]']
        return any(pattern in func.body for pattern in inefficient_patterns)

    def _is_packable_type(self, type_name: str) -> bool:
        """Check if type can be packed."""
        packable_types = ['uint8', 'uint16', 'uint32', 'uint64', 'uint128', 'bool', 'address']
        return any(ptype in type_name for ptype in packable_types)

    def _get_type_size(self, type_name: str) -> int:
        """Get size of type in bytes."""
        size_map = {
            'uint8': 1, 'uint16': 2, 'uint32': 4, 'uint64': 8, 
            'uint128': 16, 'uint256': 32, 'address': 20, 'bool': 1
        }
        
        for type_key, size in size_map.items():
            if type_key in type_name:
                return size
        
        return 32  # Default

    def _is_large_type(self, type_name: str) -> bool:
        """Check if type is large."""
        large_types = ['string', 'bytes', 'mapping', 'array']
        return any(ltype in type_name.lower() for ltype in large_types)

    def _is_commonly_accessed(self, var_name: str) -> bool:
        """Check if variable is commonly accessed."""
        common_names = ['owner', 'name', 'symbol', 'totalSupply', 'balance']
        return any(name.lower() in var_name.lower() for name in common_names)
