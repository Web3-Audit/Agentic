"""
Context classifier for understanding the business logic and operational context of smart contracts.
"""

import re
import logging
from typing import Dict, List, Set, Optional, Any
from dataclasses import dataclass, field
from enum import Enum

from .parser import ParsedContract, Contract, Function, Variable
from .domain_classifier import Domain, Protocol

logger = logging.getLogger(__name__)

class BusinessLogicType(Enum):
    FINANCIAL_OPERATIONS = "financial_operations"
    ACCESS_CONTROL = "access_control"
    STATE_MANAGEMENT = "state_management"
    EXTERNAL_INTERACTIONS = "external_interactions"
    TOKEN_OPERATIONS = "token_operations"
    GOVERNANCE_OPERATIONS = "governance_operations"
    MARKETPLACE_OPERATIONS = "marketplace_operations"
    GAMING_MECHANICS = "gaming_mechanics"

@dataclass
class SecurityContext:
    """Security-relevant context information."""
    has_payable_functions: bool = False
    has_external_calls: bool = False
    has_delegatecalls: bool = False
    has_selfdestruct: bool = False
    has_inline_assembly: bool = False
    uses_msg_sender: bool = False
    uses_tx_origin: bool = False
    has_time_dependencies: bool = False
    has_random_generation: bool = False
    access_control_patterns: List[str] = field(default_factory=list)

@dataclass
class BusinessLogicContext:
    """Business logic context information."""
    logic_types: List[BusinessLogicType] = field(default_factory=list)
    critical_functions: List[str] = field(default_factory=list)
    state_changing_functions: List[str] = field(default_factory=list)
    view_functions: List[str] = field(default_factory=list)
    admin_functions: List[str] = field(default_factory=list)
    user_functions: List[str] = field(default_factory=list)
    financial_operations: List[str] = field(default_factory=list)
    external_dependencies: List[str] = field(default_factory=list)

@dataclass
class ContextClassification:
    """Complete context classification result."""
    business_logic: BusinessLogicContext
    security_context: SecurityContext
    complexity_score: float = 0.0
    risk_score: float = 0.0
    critical_paths: List[str] = field(default_factory=list)
    invariants: List[str] = field(default_factory=list)
    assumptions: List[str] = field(default_factory=list)

class ContextClassifier:
    """
    Classifies the business logic context and security implications of smart contracts.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Pattern definitions for different contexts
        self.financial_patterns = [
            r'\b(?:transfer|send|pay|deposit|withdraw|mint|burn|swap|trade)\b',
            r'\b(?:balance|amount|value|price|fee|cost|profit|loss)\b',
            r'\b(?:token|coin|currency|money|fund|asset|collateral)\b'
        ]
        
        self.access_control_patterns = [
            r'\b(?:owner|admin|authorized|permission|role|access)\b',
            r'\b(?:onlyOwner|onlyAdmin|require|modifier|auth)\b',
            r'\b(?:public|private|internal|external)\b'
        ]
        
        self.external_interaction_patterns = [
            r'\b(?:call|delegatecall|staticcall|send|transfer)\b',
            r'\b(?:interface|external|oracle|bridge|proxy)\b',
            r'\b(?:multicall|batch|aggregate)\b'
        ]
        
        self.governance_patterns = [
            r'\b(?:vote|proposal|govern|delegate|quorum|consensus)\b',
            r'\b(?:timelock|delay|execution|veto|referendum)\b'
        ]
        
        self.gaming_patterns = [
            r'\b(?:play|game|battle|level|score|achievement|quest)\b',
            r'\b(?:character|item|weapon|skill|experience|guild)\b',
            r'\b(?:breed|pet|monster|card|deck|tournament)\b'
        ]
        
        # Compile patterns for performance
        self.compiled_patterns = {
            'financial': [re.compile(p, re.IGNORECASE) for p in self.financial_patterns],
            'access_control': [re.compile(p, re.IGNORECASE) for p in self.access_control_patterns],
            'external': [re.compile(p, re.IGNORECASE) for p in self.external_interaction_patterns],
            'governance': [re.compile(p, re.IGNORECASE) for p in self.governance_patterns],
            'gaming': [re.compile(p, re.IGNORECASE) for p in self.gaming_patterns]
        }
        
        # Critical function patterns
        self.critical_function_patterns = [
            'transfer', 'send', 'withdraw', 'deposit', 'mint', 'burn',
            'approve', 'transferFrom', 'delegatecall', 'selfdestruct',
            'changeOwner', 'upgrade', 'initialize', 'execute'
        ]
        
        # Admin function patterns
        self.admin_function_patterns = [
            'setOwner', 'changeOwner', 'transferOwnership', 'renounceOwnership',
            'pause', 'unpause', 'upgrade', 'initialize', 'configure',
            'setFee', 'setRate', 'setLimit', 'emergency', 'admin'
        ]
        
        # Risk indicators
        self.high_risk_patterns = [
            'delegatecall', 'selfdestruct', 'tx.origin', 'block.timestamp',
            'block.number', 'blockhash', 'assembly', 'inline'
        ]

    def classify(self, parsed_contract: ParsedContract, domain: Domain) -> ContextClassification:
        """
        Classify the business logic and security context of a contract.
        
        Args:
            parsed_contract: The parsed contract to analyze
            domain: The identified domain of the contract
            
        Returns:
            ContextClassification: Complete context classification
        """
        try:
            business_logic = BusinessLogicContext()
            security_context = SecurityContext()
            
            complexity_scores = []
            risk_scores = []
            all_critical_paths = []
            all_invariants = []
            all_assumptions = []
            
            # Analyze each contract
            for contract in parsed_contract.contracts:
                contract_analysis = self._analyze_contract_context(contract, domain)
                
                # Merge business logic context
                business_logic.logic_types.extend(contract_analysis['business_logic']['types'])
                business_logic.critical_functions.extend(contract_analysis['business_logic']['critical'])
                business_logic.state_changing_functions.extend(contract_analysis['business_logic']['state_changing'])
                business_logic.view_functions.extend(contract_analysis['business_logic']['view'])
                business_logic.admin_functions.extend(contract_analysis['business_logic']['admin'])
                business_logic.user_functions.extend(contract_analysis['business_logic']['user'])
                business_logic.financial_operations.extend(contract_analysis['business_logic']['financial'])
                business_logic.external_dependencies.extend(contract_analysis['business_logic']['external_deps'])
                
                # Merge security context
                security_context.has_payable_functions |= contract_analysis['security']['payable']
                security_context.has_external_calls |= contract_analysis['security']['external_calls']
                security_context.has_delegatecalls |= contract_analysis['security']['delegatecalls']
                security_context.has_selfdestruct |= contract_analysis['security']['selfdestruct']
                security_context.has_inline_assembly |= contract_analysis['security']['assembly']
                security_context.uses_msg_sender |= contract_analysis['security']['msg_sender']
                security_context.uses_tx_origin |= contract_analysis['security']['tx_origin']
                security_context.has_time_dependencies |= contract_analysis['security']['time_deps']
                security_context.has_random_generation |= contract_analysis['security']['random']
                security_context.access_control_patterns.extend(contract_analysis['security']['access_patterns'])
                
                # Collect scores and analysis
                complexity_scores.append(contract_analysis['complexity'])
                risk_scores.append(contract_analysis['risk'])
                all_critical_paths.extend(contract_analysis['critical_paths'])
                all_invariants.extend(contract_analysis['invariants'])
                all_assumptions.extend(contract_analysis['assumptions'])
            
            # Remove duplicates
            business_logic.logic_types = list(set(business_logic.logic_types))
            security_context.access_control_patterns = list(set(security_context.access_control_patterns))
            
            # Calculate overall scores
            complexity_score = sum(complexity_scores) / len(complexity_scores) if complexity_scores else 0.0
            risk_score = sum(risk_scores) / len(risk_scores) if risk_scores else 0.0
            
            result = ContextClassification(
                business_logic=business_logic,
                security_context=security_context,
                complexity_score=complexity_score,
                risk_score=risk_score,
                critical_paths=all_critical_paths,
                invariants=all_invariants,
                assumptions=all_assumptions
            )
            
            self.logger.info(f"Context classification completed. Complexity: {complexity_score:.2f}, Risk: {risk_score:.2f}")
            return result
            
        except Exception as e:
            self.logger.error(f"Error in context classification: {str(e)}")
            return ContextClassification(
                business_logic=BusinessLogicContext(),
                security_context=SecurityContext()
            )

    def _analyze_contract_context(self, contract: Contract, domain: Domain) -> Dict[str, Any]:
        """Analyze context for a single contract."""
        analysis = {
            'business_logic': {
                'types': [],
                'critical': [],
                'state_changing': [],
                'view': [],
                'admin': [],
                'user': [],
                'financial': [],
                'external_deps': []
            },
            'security': {
                'payable': False,
                'external_calls': False,
                'delegatecalls': False,
                'selfdestruct': False,
                'assembly': False,
                'msg_sender': False,
                'tx_origin': False,
                'time_deps': False,
                'random': False,
                'access_patterns': []
            },
            'complexity': 0.0,
            'risk': 0.0,
            'critical_paths': [],
            'invariants': [],
            'assumptions': []
        }
        
        # Analyze functions
        for function in contract.functions:
            func_analysis = self._analyze_function_context(function)
            
            # Categorize functions
            if self._is_critical_function(function):
                analysis['business_logic']['critical'].append(function.name)
            
            if self._is_admin_function(function):
                analysis['business_logic']['admin'].append(function.name)
            else:
                analysis['business_logic']['user'].append(function.name)
            
            if function.state_mutability.value in ['nonpayable', 'payable']:
                analysis['business_logic']['state_changing'].append(function.name)
            else:
                analysis['business_logic']['view'].append(function.name)
            
            if self._has_financial_operations(function):
                analysis['business_logic']['financial'].append(function.name)
            
            # Security analysis
            if function.state_mutability.value == 'payable':
                analysis['security']['payable'] = True
            
            if self._has_external_calls(function):
                analysis['security']['external_calls'] = True
            
            if self._has_delegatecalls(function):
                analysis['security']['delegatecalls'] = True
            
            if self._has_dangerous_patterns(function):
                analysis['security']['selfdestruct'] = True
            
            if self._uses_assembly(function):
                analysis['security']['assembly'] = True
            
            if self._uses_msg_sender(function):
                analysis['security']['msg_sender'] = True
            
            if self._uses_tx_origin(function):
                analysis['security']['tx_origin'] = True
            
            if self._has_time_dependencies(function):
                analysis['security']['time_deps'] = True
            
            if self._has_random_generation(function):
                analysis['security']['random'] = True
            
            # Merge function analysis
            analysis['complexity'] += func_analysis['complexity']
            analysis['risk'] += func_analysis['risk']
            analysis['critical_paths'].extend(func_analysis['critical_paths'])
        
        # Determine business logic types
        analysis['business_logic']['types'] = self._determine_business_logic_types(
            contract, domain, analysis
        )
        
        # Analyze state variables for additional context
        for variable in contract.state_variables:
            if self._is_financial_variable(variable):
                analysis['business_logic']['external_deps'].append(variable.name)
        
        # Calculate access control patterns
        analysis['security']['access_patterns'] = self._identify_access_patterns(contract)
        
        # Generate invariants and assumptions
        analysis['invariants'] = self._generate_invariants(contract, analysis)
        analysis['assumptions'] = self._generate_assumptions(contract, domain, analysis)
        
        # Normalize scores
        num_functions = len(contract.functions) or 1
        analysis['complexity'] /= num_functions
        analysis['risk'] /= num_functions
        
        return analysis

    def _analyze_function_context(self, function: Function) -> Dict[str, Any]:
        """Analyze context for a single function."""
        complexity = 0
        risk = 0
        critical_paths = []
        
        # Calculate complexity based on function characteristics
        complexity += len(function.parameters) * 0.1
        complexity += len(function.return_parameters) * 0.1
        complexity += len(function.modifiers) * 0.2
        
        # Estimate complexity from body length and structure
        body_complexity = self._calculate_body_complexity(function.body)
        complexity += body_complexity
        
        # Calculate risk based on dangerous patterns
        risk += self._calculate_function_risk(function)
        
        # Identify critical paths
        if self._is_critical_function(function):
            critical_paths.append(f"{function.name}: Critical function with financial impact")
        
        if function.visibility.value == 'external' and function.state_mutability.value != 'view':
            critical_paths.append(f"{function.name}: External state-changing function")
        
        return {
            'complexity': complexity,
            'risk': risk,
            'critical_paths': critical_paths
        }

    def _calculate_body_complexity(self, body: str) -> float:
        """Calculate complexity score from function body."""
        if not body:
            return 0.0
        
        complexity = 0.0
        
        # Count control structures
        control_structures = ['if', 'for', 'while', 'require', 'assert', 'revert']
        for structure in control_structures:
            complexity += body.lower().count(structure) * 0.2
        
        # Count external calls
        external_call_patterns = ['.call(', '.delegatecall(', '.send(', '.transfer(']
        for pattern in external_call_patterns:
            complexity += body.count(pattern) * 0.5
        
        # Count lines (rough measure)
        lines = len([line for line in body.split('\n') if line.strip()])
        complexity += lines * 0.05
        
        return min(complexity, 2.0)  # Cap at 2.0

    def _calculate_function_risk(self, function: Function) -> float:
        """Calculate risk score for a function."""
        risk = 0.0
        
        # Base risk from visibility and mutability
        if function.visibility.value == 'external':
            risk += 0.3
        elif function.visibility.value == 'public':
            risk += 0.2
        
        if function.state_mutability.value == 'payable':
            risk += 0.4
        elif function.state_mutability.value == 'nonpayable':
            risk += 0.2
        
        # Risk from function body patterns
        if self._has_external_calls(function):
            risk += 0.3
        
        if self._has_delegatecalls(function):
            risk += 0.5
        
        if self._has_dangerous_patterns(function):
            risk += 0.6
        
        if self._uses_assembly(function):
            risk += 0.4
        
        if self._uses_tx_origin(function):
            risk += 0.7
        
        return min(risk, 1.0)  # Cap at 1.0

    def _determine_business_logic_types(self, contract: Contract, domain: Domain, 
                                      analysis: Dict[str, Any]) -> List[BusinessLogicType]:
        """Determine the types of business logic present."""
        logic_types = []
        
        # Check for financial operations
        if (analysis['business_logic']['financial'] or 
            analysis['security']['payable'] or
            domain == Domain.DEFI):
            logic_types.append(BusinessLogicType.FINANCIAL_OPERATIONS)
        
        # Check for access control
        if (analysis['business_logic']['admin'] or
            analysis['security']['access_patterns']):
            logic_types.append(BusinessLogicType.ACCESS_CONTROL)
        
        # Check for state management
        if analysis['business_logic']['state_changing']:
            logic_types.append(BusinessLogicType.STATE_MANAGEMENT)
        
        # Check for external interactions
        if (analysis['security']['external_calls'] or
            analysis['business_logic']['external_deps']):
            logic_types.append(BusinessLogicType.EXTERNAL_INTERACTIONS)
        
        # Check for token operations
        if self._has_token_operations(contract):
            logic_types.append(BusinessLogicType.TOKEN_OPERATIONS)
        
        # Check for governance operations
        if domain == Domain.DAO or self._has_governance_operations(contract):
            logic_types.append(BusinessLogicType.GOVERNANCE_OPERATIONS)
        
        # Check for marketplace operations
        if (domain == Domain.NFT and self._has_marketplace_operations(contract)):
            logic_types.append(BusinessLogicType.MARKETPLACE_OPERATIONS)
        
        # Check for gaming mechanics
        if domain == Domain.GAMEFI or self._has_gaming_mechanics(contract):
            logic_types.append(BusinessLogicType.GAMING_MECHANICS)
        
        return logic_types

    def _is_critical_function(self, function: Function) -> bool:
        """Check if a function is critical."""
        return any(pattern in function.name.lower() 
                  for pattern in self.critical_function_patterns)

    def _is_admin_function(self, function: Function) -> bool:
        """Check if a function is an admin function."""
        return any(pattern in function.name.lower() 
                  for pattern in self.admin_function_patterns)

    def _has_financial_operations(self, function: Function) -> bool:
        """Check if function has financial operations."""
        return any(pattern.search(function.body) 
                  for pattern in self.compiled_patterns['financial'])

    def _has_external_calls(self, function: Function) -> bool:
        """Check if function has external calls."""
        return any(call in function.body.lower() 
                  for call in ['.call(', '.send(', '.transfer(', 'external'])

    def _has_delegatecalls(self, function: Function) -> bool:
        """Check if function has delegatecalls."""
        return 'delegatecall' in function.body.lower()

    def _has_dangerous_patterns(self, function: Function) -> bool:
        """Check for dangerous patterns like selfdestruct."""
        return any(pattern in function.body.lower() 
                  for pattern in ['selfdestruct', 'suicide'])

    def _uses_assembly(self, function: Function) -> bool:
        """Check if function uses inline assembly."""
        return 'assembly' in function.body.lower()

    def _uses_msg_sender(self, function: Function) -> bool:
        """Check if function uses msg.sender."""
        return 'msg.sender' in function.body

    def _uses_tx_origin(self, function: Function) -> bool:
        """Check if function uses tx.origin."""
        return 'tx.origin' in function.body

    def _has_time_dependencies(self, function: Function) -> bool:
        """Check if function has time dependencies."""
        time_patterns = ['block.timestamp', 'block.number', 'now']
        return any(pattern in function.body for pattern in time_patterns)

    def _has_random_generation(self, function: Function) -> bool:
        """Check if function generates randomness."""
        random_patterns = ['random', 'blockhash', 'keccak256(block']
        return any(pattern in function.body.lower() for pattern in random_patterns)

    def _is_financial_variable(self, variable: Variable) -> bool:
        """Check if variable is financial-related."""
        financial_keywords = ['balance', 'amount', 'price', 'fee', 'token', 'value']
        return any(keyword in variable.name.lower() or keyword in variable.type.lower() 
                  for keyword in financial_keywords)

    def _has_token_operations(self, contract: Contract) -> bool:
        """Check if contract has token operations."""
        token_functions = ['transfer', 'approve', 'transferFrom', 'mint', 'burn']
        return any(func.name in token_functions for func in contract.functions)

    def _has_governance_operations(self, contract: Contract) -> bool:
        """Check if contract has governance operations."""
        return any(pattern.search(' '.join([func.name for func in contract.functions])) 
                  for pattern in self.compiled_patterns['governance'])

    def _has_marketplace_operations(self, contract: Contract) -> bool:
        """Check if contract has marketplace operations."""
        marketplace_functions = ['buy', 'sell', 'auction', 'bid', 'offer', 'trade']
        return any(func.name.lower() in marketplace_functions for func in contract.functions)

    def _has_gaming_mechanics(self, contract: Contract) -> bool:
        """Check if contract has gaming mechanics."""
        return any(pattern.search(' '.join([func.name for func in contract.functions])) 
                  for pattern in self.compiled_patterns['gaming'])

    def _identify_access_patterns(self, contract: Contract) -> List[str]:
        """Identify access control patterns."""
        patterns = []
        
        # Check for common access control patterns
        all_function_bodies = ' '.join([func.body for func in contract.functions])
        
        if 'onlyOwner' in all_function_bodies:
            patterns.append('onlyOwner')
        if 'onlyAdmin' in all_function_bodies:
            patterns.append('onlyAdmin')
        if 'require(msg.sender ==' in all_function_bodies:
            patterns.append('direct_sender_check')
        if any(mod.name in ['onlyOwner', 'onlyAdmin', 'authorized'] for mod in contract.modifiers):
            patterns.append('modifier_based_access')
        
        return patterns

    def _generate_invariants(self, contract: Contract, analysis: Dict[str, Any]) -> List[str]:
        """Generate contract invariants based on analysis."""
        invariants = []
        
        # Financial invariants
        if BusinessLogicType.FINANCIAL_OPERATIONS in analysis['business_logic'].get('types', []):
            invariants.append("Total supply should be conserved across mint/burn operations")
            invariants.append("User balances should never be negative")
            invariants.append("Contract balance should match sum of user balances")
        
        # Access control invariants
        if BusinessLogicType.ACCESS_CONTROL in analysis['business_logic'].get('types', []):
            invariants.append("Only authorized addresses should access admin functions")
            invariants.append("Ownership transfer should be properly validated")
        
        # State consistency invariants
        if analysis['business_logic']['state_changing']:
            invariants.append("State changes should be atomic and consistent")
            invariants.append("Critical state should not be left in intermediate states")
        
        return invariants

    def _generate_assumptions(self, contract: Contract, domain: Domain, 
                            analysis: Dict[str, Any]) -> List[str]:
        """Generate contract assumptions based on context."""
        assumptions = []
        
        # Domain-specific assumptions
        if domain == Domain.DEFI:
            assumptions.extend([
                "External price oracles provide accurate data",
                "Token transfers will not revert unexpectedly",
                "Liquidity providers act rationally",
                "No front-running or MEV attacks occur"
            ])
        
        elif domain == Domain.DAO:
            assumptions.extend([
                "Voters act in good faith",
                "Quorum requirements prevent governance attacks",
                "Timelock delays are sufficient for review"
            ])
        
        elif domain == Domain.NFT:
            assumptions.extend([
                "Metadata URIs remain accessible",
                "Royalty calculations are correct",
                "Transfer hooks behave properly"
            ])
        
        # Security assumptions
        if analysis['security']['external_calls']:
            assumptions.append("External contracts behave as expected")
        
        if analysis['security']['time_deps']:
            assumptions.append("Block timestamps are not manipulated")
        
        if analysis['security']['random']:
            assumptions.append("Randomness sources are not predictable")
        
        return assumptions
