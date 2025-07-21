"""
Business logic agent for analyzing smart contract business logic correctness.
"""

import re
import logging
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field

from ..base_agent import BaseAgent
from ...models.context import AnalysisContext, FunctionContext
from ...models.finding import Finding, Severity, Category, CodeLocation
from ...utils.business_logic_utils import BusinessLogicAnalyzer
from ...llm.client import LLMClient
from ...llm.prompts import PromptManager

logger = logging.getLogger(__name__)

@dataclass
class BusinessLogicPattern:
    """Represents a business logic pattern."""
    pattern_type: str
    description: str
    risk_level: str
    affected_functions: List[str] = field(default_factory=list)

class BusinessLogicAgent(BaseAgent):
    """
    Agent focused on business logic correctness and domain-specific analysis.
    """
    
    def __init__(self, llm_client: Optional[LLMClient] = None, 
                 prompt_manager: Optional[PromptManager] = None):
        super().__init__("BusinessLogicAgent", llm_client, prompt_manager)
        self.business_logic_analyzer = BusinessLogicAnalyzer()
        
        # Business logic patterns to check
        self.logic_patterns = {
            'state_transition': {
                'description': 'Invalid state transitions',
                'severity': Severity.HIGH,
                'patterns': [
                    r'enum\s+\w*[Ss]tate\s*\{',
                    r'currentState\s*=',
                    r'setState\s*\('
                ]
            },
            'access_control': {
                'description': 'Missing or weak access controls',
                'severity': Severity.HIGH,
                'patterns': [
                    r'function\s+\w+.*public.*\{',
                    r'function\s+\w+.*external.*\{'
                ]
            },
            'economic_invariants': {
                'description': 'Economic invariant violations',
                'severity': Severity.CRITICAL,
                'patterns': [
                    r'totalSupply\s*[-+*/]',
                    r'balances?\[.*\]\s*[-+*/]',
                    r'mint\s*\(',
                    r'burn\s*\('
                ]
            },
            'input_validation': {
                'description': 'Missing input validation',
                'severity': Severity.MEDIUM,
                'patterns': [
                    r'function\s+\w+\([^)]*\)\s*public',
                    r'function\s+\w+\([^)]*\)\s*external'
                ]
            },
            'overflow_protection': {
                'description': 'Missing overflow protection',
                'severity': Severity.MEDIUM,
                'patterns': [
                    r'\b\w+\s*\+\s*\w+\b',
                    r'\b\w+\s*\*\s*\w+\b',
                    r'\b\w+\s*\-\s*\w+\b'
                ]
            }
        }

    async def analyze(self, context: AnalysisContext) -> List[Finding]:
        """
        Analyze business logic of smart contracts.
        """
        logger.info("Starting business logic analysis")
        findings: List[Finding] = []

        try:
            # Perform comprehensive business logic analysis
            bl_analysis = self.business_logic_analyzer.analyze_business_logic(context)

            # Convert analysis results to findings
            if 'logic_issues' in bl_analysis:
                for issue in bl_analysis['logic_issues']:
                    finding = self._create_finding_from_issue(issue)
                    if finding:
                        findings.append(finding)

            # Analyze each contract
            for contract_name, functions in context.functions.items():
                contract_findings = self._analyze_contract_business_logic(contract_name, functions, context)
                findings.extend(contract_findings)

            # Domain-specific business logic checks
            domain_findings = self._analyze_domain_specific_logic(context)
            findings.extend(domain_findings)

            # LLM-enhanced analysis if available
            if self.llm_client:
                llm_findings = await self._llm_business_logic_analysis(context)
                findings.extend(llm_findings)

            logger.info(f"Business logic analysis completed with {len(findings)} findings")
            return findings

        except Exception as e:
            logger.error(f"Error in business logic analysis: {str(e)}")
            return findings

    def _analyze_contract_business_logic(self, contract_name: str, 
                                       functions: List[FunctionContext],
                                       context: AnalysisContext) -> List[Finding]:
        """Analyze business logic for a specific contract."""
        findings = []
        
        # Check state management patterns
        findings.extend(self._check_state_management(contract_name, functions))
        
        # Check access control patterns
        findings.extend(self._check_access_control_logic(contract_name, functions))
        
        # Check economic logic
        findings.extend(self._check_economic_logic(contract_name, functions, context))
        
        # Check input validation
        findings.extend(self._check_input_validation(contract_name, functions))
        
        # Check function interaction patterns
        findings.extend(self._check_function_interactions(contract_name, functions))
        
        return findings

    def _check_state_management(self, contract_name: str, 
                               functions: List[FunctionContext]) -> List[Finding]:
        """Check state management business logic."""
        findings = []
        
        state_changing_functions = [f for f in functions if f.has_state_changes]
        
        for func in state_changing_functions:
            # Check for state validation
            if not self._has_state_validation(func):
                finding = Finding(
                    title=f"Missing State Validation in {func.name}",
                    description=f"Function '{func.name}' modifies state without proper validation",
                    severity=Severity.MEDIUM,
                    category=Category.BUSINESS_LOGIC,
                    location=CodeLocation(
                        contract_name=contract_name,
                        function_name=func.name
                    ),
                    affected_contracts=[contract_name],
                    affected_functions=[func.name],
                    recommendation="Add require() statements to validate state changes",
                    impact="Invalid state changes could break contract invariants"
                )
                findings.append(finding)
            
            # Check for state consistency
            if self._has_inconsistent_state_updates(func):
                finding = Finding(
                    title=f"Inconsistent State Updates in {func.name}",
                    description=f"Function '{func.name}' may leave contract in inconsistent state",
                    severity=Severity.HIGH,
                    category=Category.STATE_MANAGEMENT,
                    location=CodeLocation(
                        contract_name=contract_name,
                        function_name=func.name
                    ),
                    affected_contracts=[contract_name],
                    affected_functions=[func.name],
                    recommendation="Ensure all related state variables are updated atomically",
                    impact="Inconsistent state could lead to unexpected behavior"
                )
                findings.append(finding)
        
        return findings

    def _check_access_control_logic(self, contract_name: str,
                                   functions: List[FunctionContext]) -> List[Finding]:
        """Check access control business logic."""
        findings = []
        
        # Check for missing access controls on critical functions
        critical_functions = [f for f in functions if f.is_critical]
        
        for func in critical_functions:
            if not self._has_access_control(func):
                severity = Severity.CRITICAL if func.is_payable else Severity.HIGH
                
                finding = Finding(
                    title=f"Missing Access Control in Critical Function {func.name}",
                    description=f"Critical function '{func.name}' lacks proper access control",
                    severity=severity,
                    category=Category.ACCESS_CONTROL,
                    location=CodeLocation(
                        contract_name=contract_name,
                        function_name=func.name
                    ),
                    affected_contracts=[contract_name],
                    affected_functions=[func.name],
                    recommendation="Add onlyOwner or similar access control modifier",
                    impact="Unauthorized users could call critical functions"
                )
                findings.append(finding)
        
        # Check for privilege escalation risks
        admin_functions = [f for f in functions if f.is_admin_only]
        
        for func in admin_functions:
            if self._has_privilege_escalation_risk(func):
                finding = Finding(
                    title=f"Privilege Escalation Risk in {func.name}",
                    description=f"Admin function '{func.name}' may allow privilege escalation",
                    severity=Severity.HIGH,
                    category=Category.AUTHORIZATION,
                    location=CodeLocation(
                        contract_name=contract_name,
                        function_name=func.name
                    ),
                    affected_contracts=[contract_name],
                    affected_functions=[func.name],
                    recommendation="Review and restrict privilege modification logic",
                    impact="Could lead to unauthorized control of the contract"
                )
                findings.append(finding)
        
        return findings

    def _check_economic_logic(self, contract_name: str, functions: List[FunctionContext],
                             context: AnalysisContext) -> List[Finding]:
        """Check economic business logic."""
        findings = []
        
        # Only check for contracts that handle tokens/money
        if not self._handles_economic_operations(functions):
            return findings
        
        for func in functions:
            # Check for balance conservation issues
            if self._modifies_balances(func) and not self._conserves_balances(func):
                finding = Finding(
                    title=f"Potential Balance Conservation Violation in {func.name}",
                    description=f"Function '{func.name}' modifies balances without proper conservation",
                    severity=Severity.HIGH,
                    category=Category.ECONOMIC_MODEL,
                    location=CodeLocation(
                        contract_name=contract_name,
                        function_name=func.name
                    ),
                    affected_contracts=[contract_name],
                    affected_functions=[func.name],
                    recommendation="Ensure total supply is conserved across balance modifications",
                    impact="Could lead to token inflation or deflation bugs"
                )
                findings.append(finding)
            
            # Check for overflow in arithmetic operations
            if self._has_unsafe_arithmetic(func):
                finding = Finding(
                    title=f"Unsafe Arithmetic Operations in {func.name}",
                    description=f"Function '{func.name}' performs arithmetic without overflow protection",
                    severity=Severity.MEDIUM,
                    category=Category.ARITHMETIC,
                    location=CodeLocation(
                        contract_name=contract_name,
                        function_name=func.name
                    ),
                    affected_contracts=[contract_name],
                    affected_functions=[func.name],
                    recommendation="Use SafeMath library or Solidity ^0.8.0 for automatic overflow protection",
                    impact="Arithmetic overflow could cause unexpected behavior"
                )
                findings.append(finding)
        
        return findings

    def _check_input_validation(self, contract_name: str,
                               functions: List[FunctionContext]) -> List[Finding]:
        """Check input validation logic."""
        findings = []
        
        external_functions = [f for f in functions if f.visibility in ['public', 'external']]
        
        for func in external_functions:
            if func.parameters and not self._has_input_validation(func):
                severity = Severity.HIGH if func.is_critical else Severity.MEDIUM
                
                finding = Finding(
                    title=f"Missing Input Validation in {func.name}",
                    description=f"External function '{func.name}' lacks input parameter validation",
                    severity=severity,
                    category=Category.BUSINESS_LOGIC,
                    location=CodeLocation(
                        contract_name=contract_name,
                        function_name=func.name
                    ),
                    affected_contracts=[contract_name],
                    affected_functions=[func.name],
                    recommendation="Add require() statements to validate input parameters",
                    impact="Invalid inputs could cause unexpected behavior or exploits"
                )
                findings.append(finding)
        
        return findings

    def _check_function_interactions(self, contract_name: str,
                                   functions: List[FunctionContext]) -> List[Finding]:
        """Check function interaction patterns."""
        findings = []
        
        # Check for functions that should be called together
        related_functions = self._identify_related_functions(functions)
        
        for func_group in related_functions:
            if len(func_group) > 1:
                # Check if functions in group have proper ordering constraints
                if not self._has_proper_ordering(func_group):
                    function_names = [f.name for f in func_group]
                    
                    finding = Finding(
                        title=f"Missing Function Ordering Constraints",
                        description=f"Related functions {function_names} lack proper ordering constraints",
                        severity=Severity.MEDIUM,
                        category=Category.BUSINESS_LOGIC,
                        location=CodeLocation(contract_name=contract_name),
                        affected_contracts=[contract_name],
                        affected_functions=function_names,
                        recommendation="Add state checks to ensure proper function call ordering",
                        impact="Functions called in wrong order could lead to inconsistent state"
                    )
                    findings.append(finding)
        
        return findings

    def _analyze_domain_specific_logic(self, context: AnalysisContext) -> List[Finding]:
        """Analyze domain-specific business logic."""
        findings = []
        
        if context.domain == 'defi':
            findings.extend(self._analyze_defi_logic(context))
        elif context.domain == 'dao':
            findings.extend(self._analyze_dao_logic(context))
        elif context.domain == 'nft':
            findings.extend(self._analyze_nft_logic(context))
        elif context.domain == 'gamefi':
            findings.extend(self._analyze_gamefi_logic(context))
        
        return findings

    def _analyze_defi_logic(self, context: AnalysisContext) -> List[Finding]:
        """Analyze DeFi-specific business logic."""
        findings = []
        
        for contract_name, functions in context.functions.items():
            for func in functions:
                # Check for slippage protection
                if 'swap' in func.name.lower() and not self._has_slippage_protection(func):
                    finding = Finding(
                        title=f"Missing Slippage Protection in {func.name}",
                        description=f"Swap function '{func.name}' lacks slippage protection",
                        severity=Severity.HIGH,
                        category=Category.DEFI_SPECIFIC,
                        location=CodeLocation(
                            contract_name=contract_name,
                            function_name=func.name
                        ),
                        affected_contracts=[contract_name],
                        affected_functions=[func.name],
                        recommendation="Add minimum output amount parameter and validation",
                        impact="Users could lose funds due to sandwich attacks or high slippage"
                    )
                    findings.append(finding)
                
                # Check for oracle price manipulation
                if self._uses_price_oracle(func) and not self._has_price_validation(func):
                    finding = Finding(
                        title=f"Oracle Price Manipulation Risk in {func.name}",
                        description=f"Function '{func.name}' uses oracle prices without validation",
                        severity=Severity.HIGH,
                        category=Category.DEFI_SPECIFIC,
                        location=CodeLocation(
                            contract_name=contract_name,
                            function_name=func.name
                        ),
                        affected_contracts=[contract_name],
                        affected_functions=[func.name],
                        recommendation="Implement price validation and time-weighted average prices",
                        impact="Price manipulation could lead to economic exploits"
                    )
                    findings.append(finding)
        
        return findings

    def _analyze_dao_logic(self, context: AnalysisContext) -> List[Finding]:
        """Analyze DAO-specific business logic."""
        findings = []
        
        for contract_name, functions in context.functions.items():
            for func in functions:
                # Check voting logic
                if 'vote' in func.name.lower() and not self._has_proper_voting_validation(func):
                    finding = Finding(
                        title=f"Inadequate Voting Validation in {func.name}",
                        description=f"Voting function '{func.name}' may allow invalid votes",
                        severity=Severity.HIGH,
                        category=Category.DAO_SPECIFIC,
                        location=CodeLocation(
                            contract_name=contract_name,
                            function_name=func.name
                        ),
                        affected_contracts=[contract_name],
                        affected_functions=[func.name],
                        recommendation="Add proper voting power and eligibility validation",
                        impact="Invalid votes could compromise governance decisions"
                    )
                    findings.append(finding)
                
                # Check proposal execution
                if 'execute' in func.name.lower() and not self._has_execution_safeguards(func):
                    finding = Finding(
                        title=f"Missing Execution Safeguards in {func.name}",
                        description=f"Proposal execution function '{func.name}' lacks proper safeguards",
                        severity=Severity.HIGH,
                        category=Category.DAO_SPECIFIC,
                        location=CodeLocation(
                            contract_name=contract_name,
                            function_name=func.name
                        ),
                        affected_contracts=[contract_name],
                        affected_functions=[func.name],
                        recommendation="Add quorum checks, timelock, and execution validation",
                        impact="Malicious or invalid proposals could be executed"
                    )
                    findings.append(finding)
        
        return findings

    def _analyze_nft_logic(self, context: AnalysisContext) -> List[Finding]:
        """Analyze NFT-specific business logic."""
        findings = []
        
        for contract_name, functions in context.functions.items():
            for func in functions:
                # Check minting logic
                if 'mint' in func.name.lower() and not self._has_proper_minting_controls(func):
                    finding = Finding(
                        title=f"Inadequate Minting Controls in {func.name}",
                        description=f"Minting function '{func.name}' lacks proper access controls",
                        severity=Severity.MEDIUM,
                        category=Category.NFT_SPECIFIC,
                        location=CodeLocation(
                            contract_name=contract_name,
                            function_name=func.name
                        ),
                        affected_contracts=[contract_name],
                        affected_functions=[func.name],
                        recommendation="Add supply limits and access controls to minting",
                        impact="Unrestricted minting could devalue NFTs"
                    )
                    findings.append(finding)
        
        return findings

    def _analyze_gamefi_logic(self, context: AnalysisContext) -> List[Finding]:
        """Analyze GameFi-specific business logic."""
        findings = []
        
        for contract_name, functions in context.functions.items():
            for func in functions:
                # Check reward distribution
                if 'reward' in func.name.lower() and not self._has_fair_reward_logic(func):
                    finding = Finding(
                        title=f"Unfair Reward Logic in {func.name}",
                        description=f"Reward function '{func.name}' may have unfair distribution logic",
                        severity=Severity.MEDIUM,
                        category=Category.GAMEFI_SPECIFIC,
                        location=CodeLocation(
                            contract_name=contract_name,
                            function_name=func.name
                        ),
                        affected_contracts=[contract_name],
                        affected_functions=[func.name],
                        recommendation="Ensure reward calculations are fair and verifiable",
                        impact="Unfair rewards could lead to player dissatisfaction"
                    )
                    findings.append(finding)
        
        return findings

    async def _llm_business_logic_analysis(self, context: AnalysisContext) -> List[Finding]:
        """Perform LLM-enhanced business logic analysis."""
        findings = []
        
        if not self.llm_client or not self.prompt_manager:
            return findings
        
        try:
            for contract_name, contract_metadata in context.contracts.items():
                # Generate business logic analysis prompt
                prompt_variables = {
                    'contract_name': contract_name,
                    'domain': context.domain or 'unknown',
                    'functions': [f.name for f in context.functions.get(contract_name, [])],
                    'critical_functions': [f.name for f in context.functions.get(contract_name, []) if f.is_critical]
                }
                
                prompt = self.prompt_manager.generate_prompt(
                    'business_logic_analysis', prompt_variables
                )
                
                response = await self.llm_client.generate(prompt)
                
                # Parse LLM response into findings
                llm_findings = self._parse_llm_business_logic_response(
                    response.content, contract_name
                )
                findings.extend(llm_findings)
                
        except Exception as e:
            self.logger.error(f"Error in LLM business logic analysis: {str(e)}")
        
        return findings

    def _parse_llm_business_logic_response(self, response: str, contract_name: str) -> List[Finding]:
        """Parse LLM response into business logic findings."""
        findings = []
        
        # Implementation would parse structured LLM response
        # For now, return empty list
        
        return findings

    # Helper methods for pattern detection

    def _has_state_validation(self, func: FunctionContext) -> bool:
        """Check if function has proper state validation."""
        validation_patterns = ['require(', 'assert(', 'revert(', 'if (']
        return any(pattern in func.body for pattern in validation_patterns)

    def _has_inconsistent_state_updates(self, func: FunctionContext) -> bool:
        """Check for inconsistent state updates."""
        # Simple heuristic: if function updates balance but not totalSupply
        updates_balance = 'balance' in func.body.lower()
        updates_supply = 'totalsupply' in func.body.lower() or 'supply' in func.body.lower()
        
        return updates_balance and not updates_supply and 'mint' not in func.name.lower()

    def _has_access_control(self, func: FunctionContext) -> bool:
        """Check if function has access control."""
        access_patterns = [
            'onlyOwner', 'onlyAdmin', 'require(msg.sender', 
            'modifier', 'authorized', 'hasRole'
        ]
        
        # Check modifiers
        if any(mod.lower() in [p.lower() for p in access_patterns] for mod in func.modifiers):
            return True
        
        # Check function body
        return any(pattern.lower() in func.body.lower() for pattern in access_patterns)

    def _has_privilege_escalation_risk(self, func: FunctionContext) -> bool:
        """Check for privilege escalation risks."""
        risky_patterns = [
            'owner =', 'admin =', 'setOwner', 'addAdmin', 
            'grantRole', 'transferOwnership'
        ]
        return any(pattern.lower() in func.body.lower() for pattern in risky_patterns)

    def _handles_economic_operations(self, functions: List[FunctionContext]) -> bool:
        """Check if contract handles economic operations."""
        economic_keywords = [
            'balance', 'transfer', 'mint', 'burn', 'supply', 
            'token', 'pay', 'deposit', 'withdraw'
        ]
        
        return any(
            any(keyword in func.body.lower() for keyword in economic_keywords)
            for func in functions
        )

    def _modifies_balances(self, func: FunctionContext) -> bool:
        """Check if function modifies balances."""
        balance_patterns = ['balance[', 'balances[', 'balanceOf']
        return any(pattern.lower() in func.body.lower() for pattern in balance_patterns)

    def _conserves_balances(self, func: FunctionContext) -> bool:
        """Check if function conserves balances."""
        # Simple heuristic: look for proper balance updates
        has_subtraction = any(op in func.body for op in ['-=', '- '])
        has_addition = any(op in func.body for op in ['+=', '+ '])
        
        return has_subtraction and has_addition

    def _has_unsafe_arithmetic(self, func: FunctionContext) -> bool:
        """Check for unsafe arithmetic operations."""
        arithmetic_ops = ['+', '-', '*', '/']
        has_arithmetic = any(op in func.body for op in arithmetic_ops)
        has_safemath = 'safemath' in func.body.lower() or 'checked' in func.body.lower()
        
        return has_arithmetic and not has_safemath

    def _has_input_validation(self, func: FunctionContext) -> bool:
        """Check if function validates inputs."""
        validation_patterns = ['require(', 'assert(', 'revert(']
        return any(pattern in func.body for pattern in validation_patterns)

    def _identify_related_functions(self, functions: List[FunctionContext]) -> List[List[FunctionContext]]:
        """Identify groups of related functions."""
        # Simple heuristic: group functions with similar names
        groups = []
        processed = set()
        
        for func in functions:
            if func.name in processed:
                continue
            
            group = [func]
            base_name = func.name.lower()
            
            for other_func in functions:
                if other_func.name != func.name and other_func.name not in processed:
                    if self._are_functions_related(base_name, other_func.name.lower()):
                        group.append(other_func)
                        processed.add(other_func.name)
            
            if len(group) > 1:
                groups.append(group)
            
            processed.add(func.name)
        
        return groups

    def _are_functions_related(self, name1: str, name2: str) -> bool:
        """Check if two function names indicate related functionality."""
        # Simple heuristic: similar prefixes or related operations
        related_pairs = [
            ('deposit', 'withdraw'),
            ('mint', 'burn'),
            ('lock', 'unlock'),
            ('start', 'end'),
            ('open', 'close'),
            ('create', 'delete'),
            ('add', 'remove')
        ]
        
        for pair in related_pairs:
            if (pair[0] in name1 and pair[1] in name2) or (pair[1] in name1 and pair[0] in name2):
                return True
        
        return False

    def _has_proper_ordering(self, func_group: List[FunctionContext]) -> bool:
        """Check if function group has proper ordering constraints."""
        # Look for state checks that enforce ordering
        for func in func_group:
            if self._has_state_validation(func):
                return True
        return False

    def _has_slippage_protection(self, func: FunctionContext) -> bool:
        """Check if swap function has slippage protection."""
        slippage_patterns = ['minAmount', 'slippage', 'minimum', 'deadline']
        return any(pattern.lower() in func.body.lower() for pattern in slippage_patterns)

    def _uses_price_oracle(self, func: FunctionContext) -> bool:
        """Check if function uses price oracle."""
        oracle_patterns = ['oracle', 'price', 'getPrice', 'latestPrice']
        return any(pattern.lower() in func.body.lower() for pattern in oracle_patterns)

    def _has_price_validation(self, func: FunctionContext) -> bool:
        """Check if function validates oracle prices."""
        validation_patterns = ['require', 'assert', 'validPrice', 'checkPrice']
        return any(pattern.lower() in func.body.lower() for pattern in validation_patterns)

    def _has_proper_voting_validation(self, func: FunctionContext) -> bool:
        """Check if voting function has proper validation."""
        validation_patterns = ['votingPower', 'eligible', 'hasVoted', 'canVote']
        return any(pattern.lower() in func.body.lower() for pattern in validation_patterns)

    def _has_execution_safeguards(self, func: FunctionContext) -> bool:
        """Check if execution function has safeguards."""
        safeguard_patterns = ['quorum', 'timelock', 'delay', 'approved']
        return any(pattern.lower() in func.body.lower() for pattern in safeguard_patterns)

    def _has_proper_minting_controls(self, func: FunctionContext) -> bool:
        """Check if minting function has proper controls."""
        control_patterns = ['maxSupply', 'limit', 'onlyOwner', 'authorized']
        return any(pattern.lower() in func.body.lower() for pattern in control_patterns)

    def _has_fair_reward_logic(self, func: FunctionContext) -> bool:
        """Check if reward function has fair logic."""
        fairness_patterns = ['calculate', 'formula', 'rate', 'proportional']
        return any(pattern.lower() in func.body.lower() for pattern in fairness_patterns)

    def _create_finding_from_issue(self, issue) -> Optional[Finding]:
        """Convert business logic issue to Finding."""
        try:
            return Finding(
                title=issue.description,
                description=issue.description,
                severity=issue.severity,
                category=Category.BUSINESS_LOGIC,
                location=CodeLocation() if not issue.location else CodeLocation(contract_name=issue.location),
                affected_functions=issue.affected_functions,
                recommendation=issue.recommendation,
                impact=issue.impact_assessment
            )
        except Exception as e:
            self.logger.error(f"Error creating finding from issue: {str(e)}")
            return None
