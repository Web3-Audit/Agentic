"""
Business logic analysis utilities for smart contract auditing.
"""

import re
import logging
from typing import Dict, List, Optional, Any, Set, Tuple, Union
from dataclasses import dataclass, field
from collections import defaultdict
from enum import Enum

from ..models.context import AnalysisContext, FunctionContext
from ..models.finding import Finding, Severity, Category

logger = logging.getLogger(__name__)

class LogicPattern(Enum):
    """Types of business logic patterns."""
    ACCESS_CONTROL = "access_control"
    STATE_MACHINE = "state_machine" 
    ECONOMIC_MODEL = "economic_model"
    VOTING_MECHANISM = "voting_mechanism"
    AUCTION_MECHANISM = "auction_mechanism"
    REWARD_DISTRIBUTION = "reward_distribution"
    SUPPLY_MANAGEMENT = "supply_management"
    PRICE_CALCULATION = "price_calculation"
    LIQUIDITY_MANAGEMENT = "liquidity_management"
    RISK_MANAGEMENT = "risk_management"

@dataclass
class BusinessLogicIssue:
    """Represents a business logic issue."""
    issue_type: str
    description: str
    severity: Severity
    location: Optional[str] = None
    affected_functions: List[str] = field(default_factory=list)
    recommendation: str = ""
    impact_assessment: str = ""

@dataclass
class EconomicModel:
    """Represents an economic model analysis."""
    model_type: str
    components: List[str] = field(default_factory=list)
    invariants: List[str] = field(default_factory=list)
    risk_factors: List[str] = field(default_factory=list)
    sustainability_score: float = 0.0

class BusinessLogicAnalyzer:
    """
    Analyzes business logic correctness and security in smart contracts.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Business logic patterns
        self.patterns = {
            'access_control': [
                r'onlyOwner',
                r'require\s*\(\s*msg\.sender\s*==',
                r'modifier\s+\w*[Aa]uthorized',
                r'hasRole\s*\(',
                r'checkRole\s*\('
            ],
            'state_transitions': [
                r'enum\s+\w*[Ss]tate',
                r'currentState\s*=',
                r'setState\s*\(',
                r'phase\s*==',
                r'status\s*='
            ],
            'economic_operations': [
                r'transfer\s*\(',
                r'mint\s*\(',
                r'burn\s*\(',
                r'deposit\s*\(',
                r'withdraw\s*\(',
                r'stake\s*\(',
                r'unstake\s*\(',
                r'claim\s*\(',
                r'reward\s*\('
            ],
            'voting_patterns': [
                r'vote\s*\(',
                r'proposal\s*\[',
                r'quorum',
                r'ballot',
                r'delegate\s*\(',
                r'votingPower'
            ],
            'auction_patterns': [
                r'bid\s*\(',
                r'auction\s*\[',
                r'highestBid',
                r'winner',
                r'reserve\w*Price',
                r'endAuction'
            ],
            'price_calculations': [
                r'getPrice\s*\(',
                r'calculatePrice\s*\(',
                r'priceOracle',
                r'exchange\w*Rate',
                r'slippage',
                r'fee\s*\*',
                r'price\s*\*'
            ]
        }
        
        # Compile patterns
        self.compiled_patterns = {}
        for category, pattern_list in self.patterns.items():
            self.compiled_patterns[category] = [
                re.compile(pattern, re.IGNORECASE | re.MULTILINE)
                for pattern in pattern_list
            ]

    def analyze_business_logic(self, context: AnalysisContext) -> Dict[str, Any]:
        """
        Perform comprehensive business logic analysis.
        
        Args:
            context: Analysis context with contract information
            
        Returns:
            Dict containing business logic analysis results
        """
        try:
            analysis_result = {
                'identified_patterns': [],
                'logic_issues': [],
                'economic_model': None,
                'state_analysis': {},
                'access_control_analysis': {},
                'invariant_violations': [],
                'recommendations': [],
                'risk_assessment': {}
            }
            
            # Analyze each contract
            for contract_name, functions in context.functions.items():
                contract_source = self._get_contract_source(context, contract_name)
                
                # Identify business logic patterns
                patterns = self._identify_logic_patterns(contract_source)
                analysis_result['identified_patterns'].extend(patterns)
                
                # Analyze access control
                access_analysis = self._analyze_access_control(functions, contract_source)
                analysis_result['access_control_analysis'][contract_name] = access_analysis
                
                # Analyze state management
                state_analysis = self._analyze_state_management(functions, contract_source)
                analysis_result['state_analysis'][contract_name] = state_analysis
                
                # Check for logic issues
                issues = self._identify_logic_issues(functions, contract_source, context.domain)
                analysis_result['logic_issues'].extend(issues)
                
                # Analyze economic model if applicable
                if self._has_economic_components(contract_source):
                    economic_model = self._analyze_economic_model(functions, contract_source, context.domain)
                    analysis_result['economic_model'] = economic_model
            
            # Generate invariant checks
            analysis_result['invariant_violations'] = self._check_invariants(context, analysis_result)
            
            # Risk assessment
            analysis_result['risk_assessment'] = self._assess_business_logic_risks(analysis_result)
            
            # Generate recommendations
            analysis_result['recommendations'] = self._generate_recommendations(analysis_result)
            
            self.logger.info("Business logic analysis completed")
            return analysis_result
            
        except Exception as e:
            self.logger.error(f"Error in business logic analysis: {str(e)}")
            return {'error': str(e)}

    def _get_contract_source(self, context: AnalysisContext, contract_name: str) -> str:
        """Get source code for a specific contract."""
        # This would typically come from the parsed contract data
        # For now, return empty string as placeholder
        return ""

    def _identify_logic_patterns(self, source_code: str) -> List[Dict[str, Any]]:
        """Identify business logic patterns in source code."""
        identified_patterns = []
        
        for pattern_type, compiled_patterns in self.compiled_patterns.items():
            for pattern in compiled_patterns:
                matches = pattern.findall(source_code)
                if matches:
                    identified_patterns.append({
                        'type': pattern_type,
                        'pattern': pattern.pattern,
                        'matches': len(matches),
                        'examples': matches[:3]  # First 3 matches as examples
                    })
        
        return identified_patterns

    def _analyze_access_control(self, functions: List[FunctionContext], source_code: str) -> Dict[str, Any]:
        """Analyze access control mechanisms."""
        analysis = {
            'has_owner_pattern': False,
            'access_modifiers': [],
            'protected_functions': [],
            'public_sensitive_functions': [],
            'access_control_issues': []
        }
        
        # Check for owner pattern
        if re.search(r'owner|Owner', source_code):
            analysis['has_owner_pattern'] = True
        
        # Analyze each function's access controls
        for func in functions:
            if func.visibility == 'public' or func.visibility == 'external':
                # Check if function has access control modifiers
                has_access_control = any(
                    modifier.lower() in ['onlyowner', 'authorized', 'restricted']
                    for modifier in func.modifiers
                )
                
                if has_access_control:
                    analysis['protected_functions'].append(func.name)
                else:
                    # Check if function modifies state and lacks protection
                    if func.has_state_changes and not has_access_control:
                        analysis['public_sensitive_functions'].append(func.name)
                        analysis['access_control_issues'].append({
                            'function': func.name,
                            'issue': 'State-changing function lacks access control',
                            'severity': 'medium'
                        })
        
        return analysis

    def _analyze_state_management(self, functions: List[FunctionContext], source_code: str) -> Dict[str, Any]:
        """Analyze state management patterns."""
        analysis = {
            'has_state_machine': False,
            'state_variables': [],
            'state_transitions': [],
            'state_validation_issues': []
        }
        
        # Check for state machine patterns
        state_patterns = [
            r'enum\s+\w*[Ss]tate\s*\{',
            r'currentState',
            r'phase',
            r'status'
        ]
        
        for pattern in state_patterns:
            if re.search(pattern, source_code, re.IGNORECASE):
                analysis['has_state_machine'] = True
                break
        
        # Find state variables
        state_var_matches = re.findall(r'(\w*[Ss]tate|\w*[Pp]hase|\w*[Ss]tatus)\s+\w+', source_code)
        analysis['state_variables'] = list(set(state_var_matches))
        
        # Look for state transition functions
        for func in functions:
            if any(keyword in func.name.lower() for keyword in ['set', 'change', 'transition', 'update']):
                analysis['state_transitions'].append(func.name)
        
        # Check for validation issues
        for func in functions:
            if func.name in analysis['state_transitions']:
                # Check if state transition function validates current state
                if not any('require' in pattern or 'assert' in pattern for pattern in func.body.split('\n')):
                    analysis['state_validation_issues'].append({
                        'function': func.name,
                        'issue': 'State transition lacks validation',
                        'severity': 'medium'
                    })
        
        return analysis

    def _identify_logic_issues(self, functions: List[FunctionContext], source_code: str, domain: str) -> List[BusinessLogicIssue]:
        """Identify business logic issues."""
        issues = []
        
        # Common logic issues
        issues.extend(self._check_input_validation_issues(functions))
        issues.extend(self._check_state_consistency_issues(functions, source_code))
        issues.extend(self._check_economic_logic_issues(functions, source_code, domain))
        issues.extend(self._check_access_logic_issues(functions))
        
        return issues

    def _check_input_validation_issues(self, functions: List[FunctionContext]) -> List[BusinessLogicIssue]:
        """Check for input validation issues."""
        issues = []
        
        for func in functions:
            if func.visibility in ['public', 'external'] and func.parameters:
                # Check if function validates inputs
                has_validation = 'require(' in func.body or 'assert(' in func.body
                
                if not has_validation:
                    issues.append(BusinessLogicIssue(
                        issue_type='missing_input_validation',
                        description=f'Function {func.name} lacks input validation',
                        severity=Severity.MEDIUM,
                        location=func.name,
                        affected_functions=[func.name],
                        recommendation='Add require() statements to validate input parameters',
                        impact_assessment='Invalid inputs could cause unexpected behavior'
                    ))
        
        return issues

    def _check_state_consistency_issues(self, functions: List[FunctionContext], source_code: str) -> List[BusinessLogicIssue]:
        """Check for state consistency issues."""
        issues = []
        
        # Look for functions that change multiple related state variables
        state_changing_funcs = [f for f in functions if f.has_state_changes]
        
        for func in state_changing_funcs:
            # Check if function updates related variables atomically
            balance_updates = func.body.count('balance')
            supply_updates = func.body.count('totalSupply') + func.body.count('supply')
            
            if balance_updates > 0 and supply_updates > 0:
                # Function modifies both balance and supply - check for consistency
                if not re.search(r'require.*balance.*supply|assert.*balance.*supply', func.body):
                    issues.append(BusinessLogicIssue(
                        issue_type='state_consistency',
                        description=f'Function {func.name} modifies related state without consistency checks',
                        severity=Severity.HIGH,
                        location=func.name,
                        affected_functions=[func.name],
                        recommendation='Add checks to ensure state variables remain consistent',
                        impact_assessment='State inconsistency could break contract invariants'
                    ))
        
        return issues

    def _check_economic_logic_issues(self, functions: List[FunctionContext], source_code: str, domain: str) -> List[BusinessLogicIssue]:
        """Check for economic logic issues."""
        issues = []
        
        if domain != 'defi':
            return issues
        
        # Check for common DeFi economic issues
        for func in functions:
            func_body_lower = func.body.lower()
            
            # Check for price manipulation vulnerabilities
            if 'price' in func_body_lower and 'oracle' not in func_body_lower:
                if 'getamountout' in func_body_lower or 'swap' in func_body_lower:
                    issues.append(BusinessLogicIssue(
                        issue_type='price_manipulation',
                        description=f'Function {func.name} may be vulnerable to price manipulation',
                        severity=Severity.HIGH,
                        location=func.name,
                        affected_functions=[func.name],
                        recommendation='Use time-weighted average prices or oracle-based pricing',
                        impact_assessment='Price manipulation could lead to economic losses'
                    ))
            
            # Check for slippage protection
            if 'swap' in func_body_lower and 'slippage' not in func_body_lower and 'minamountout' not in func_body_lower:
                issues.append(BusinessLogicIssue(
                    issue_type='missing_slippage_protection',
                    description=f'Swap function {func.name} lacks slippage protection',
                    severity=Severity.MEDIUM,
                    location=func.name,
                    affected_functions=[func.name],
                    recommendation='Add minimum output amount checks for swaps',
                    impact_assessment='Users could receive less tokens than expected'
                ))
        
        return issues

    def _check_access_logic_issues(self, functions: List[FunctionContext]) -> List[BusinessLogicIssue]:
        """Check for access control logic issues."""
        issues = []
        
        # Find admin functions
        admin_functions = [f for f in functions if f.is_admin_only]
        
        for func in admin_functions:
            # Check for privilege escalation issues
            if 'owner' in func.body.lower() and func.name.lower() not in ['transferownership', 'renounceownership']:
                # Function modifies ownership but isn't a standard ownership function
                issues.append(BusinessLogicIssue(
                    issue_type='privilege_escalation_risk',
                    description=f'Admin function {func.name} modifies ownership outside standard patterns',
                    severity=Severity.HIGH,
                    location=func.name,
                    affected_functions=[func.name],
                    recommendation='Review ownership modification logic for security',
                    impact_assessment='Could lead to unauthorized privilege escalation'
                ))
        
        return issues

    def _has_economic_components(self, source_code: str) -> bool:
        """Check if contract has economic components."""
        economic_keywords = [
            'token', 'balance', 'transfer', 'mint', 'burn', 'supply',
            'price', 'fee', 'reward', 'stake', 'liquidity', 'swap'
        ]
        
        return any(keyword in source_code.lower() for keyword in economic_keywords)

    def _analyze_economic_model(self, functions: List[FunctionContext], source_code: str, domain: str) -> EconomicModel:
        """Analyze the economic model of the contract."""
        components = []
        invariants = []
        risk_factors = []
        
        # Identify economic components
        if 'mint' in source_code.lower():
            components.append('token_minting')
        if 'burn' in source_code.lower():
            components.append('token_burning')
        if 'stake' in source_code.lower():
            components.append('staking_mechanism')
        if 'reward' in source_code.lower():
            components.append('reward_distribution')
        if 'fee' in source_code.lower():
            components.append('fee_collection')
        
        # Define invariants based on components
        if 'token_minting' in components or 'token_burning' in components:
            invariants.append('Total supply conservation')
            invariants.append('Balance non-negativity')
        
        if 'staking_mechanism' in components:
            invariants.append('Staked amount <= user balance')
            invariants.append('Total staked <= total supply')
        
        if 'reward_distribution' in components:
            invariants.append('Rewards <= reward pool balance')
            invariants.append('Distributed rewards tracking')
        
        # Identify risk factors
        if not any('oracle' in func.body.lower() for func in functions):
            risk_factors.append('No price oracle (price manipulation risk)')
        
        if not any('slippage' in func.body.lower() or 'minamount' in func.body.lower() for func in functions):
            risk_factors.append('No slippage protection')
        
        if 'admin' in source_code.lower() or 'owner' in source_code.lower():
            risk_factors.append('Administrative privileges')
        
        # Calculate sustainability score
        sustainability_score = self._calculate_sustainability_score(components, invariants, risk_factors)
        
        return EconomicModel(
            model_type=domain,
            components=components,
            invariants=invariants,
            risk_factors=risk_factors,
            sustainability_score=sustainability_score
        )

    def _calculate_sustainability_score(self, components: List[str], invariants: List[str], risk_factors: List[str]) -> float:
        """Calculate economic model sustainability score."""
        base_score = 0.8
        
        # Positive factors
        if 'fee_collection' in components:
            base_score += 0.1
        if len(invariants) > 3:
            base_score += 0.1
        
        # Negative factors
        risk_penalty = len(risk_factors) * 0.15
        base_score -= risk_penalty
        
        return max(0.0, min(1.0, base_score))

    def _check_invariants(self, context: AnalysisContext, analysis_result: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for invariant violations."""
        violations = []
        
        economic_model = analysis_result.get('economic_model')
        if not economic_model:
            return violations
        
        # Check each invariant
        for invariant in economic_model.invariants:
            violation = self._check_specific_invariant(invariant, context)
            if violation:
                violations.append(violation)
        
        return violations

    def _check_specific_invariant(self, invariant: str, context: AnalysisContext) -> Optional[Dict[str, Any]]:
        """Check a specific invariant."""
        # This would be implemented with more sophisticated logic
        # For now, return None (no violations found)
        return None

    def _assess_business_logic_risks(self, analysis_result: Dict[str, Any]) -> Dict[str, Any]:
        """Assess overall business logic risks."""
        risk_assessment = {
            'overall_risk': 'medium',
            'risk_factors': [],
            'risk_score': 0.5,
            'mitigation_priorities': []
        }
        
        # Count issues by severity
        critical_issues = len([issue for issue in analysis_result['logic_issues'] if issue.severity == Severity.CRITICAL])
        high_issues = len([issue for issue in analysis_result['logic_issues'] if issue.severity == Severity.HIGH])
        medium_issues = len([issue for issue in analysis_result['logic_issues'] if issue.severity == Severity.MEDIUM])
        
        # Calculate risk score
        risk_score = (critical_issues * 0.4 + high_issues * 0.3 + medium_issues * 0.2) / max(1, len(analysis_result['logic_issues']))
        risk_assessment['risk_score'] = min(1.0, risk_score)
        
        # Determine overall risk level
        if critical_issues > 0 or high_issues > 3:
            risk_assessment['overall_risk'] = 'high'
        elif high_issues > 1 or medium_issues > 5:
            risk_assessment['overall_risk'] = 'medium'
        else:
            risk_assessment['overall_risk'] = 'low'
        
        # Identify risk factors
        if analysis_result.get('economic_model') and analysis_result['economic_model'].risk_factors:
            risk_assessment['risk_factors'].extend(analysis_result['economic_model'].risk_factors)
        
        # Set mitigation priorities
        if critical_issues > 0:
            risk_assessment['mitigation_priorities'].append('Address critical business logic issues immediately')
        if high_issues > 0:
            risk_assessment['mitigation_priorities'].append('Review and fix high-severity logic issues')
        
        return risk_assessment

    def _generate_recommendations(self, analysis_result: Dict[str, Any]) -> List[str]:
        """Generate recommendations based on analysis."""
        recommendations = []
        
        # Based on identified issues
        issue_types = set(issue.issue_type for issue in analysis_result['logic_issues'])
        
        if 'missing_input_validation' in issue_types:
            recommendations.append('Implement comprehensive input validation for all public functions')
        
        if 'state_consistency' in issue_types:
            recommendations.append('Add state consistency checks for related variables')
        
        if 'price_manipulation' in issue_types:
            recommendations.append('Implement oracle-based pricing or TWAP mechanisms')
        
        if 'missing_slippage_protection' in issue_types:
            recommendations.append('Add slippage protection for all trading functions')
        
        # Based on economic model
        economic_model = analysis_result.get('economic_model')
        if economic_model and economic_model.sustainability_score < 0.5:
            recommendations.append('Review economic model sustainability and tokenomics')
        
        # Based on access control analysis
        for contract_analysis in analysis_result.get('access_control_analysis', {}).values():
            if contract_analysis.get('public_sensitive_functions'):
                recommendations.append('Add access controls to state-changing functions')
        
        return recommendations

class EconomicModelAnalyzer:
    """Specialized analyzer for economic models in smart contracts."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def analyze_tokenomics(self, context: AnalysisContext) -> Dict[str, Any]:
        """Analyze tokenomics and economic models."""
        analysis = {
            'token_type': 'unknown',
            'supply_mechanism': {},
            'distribution_model': {},
            'incentive_structure': {},
            'economic_risks': [],
            'sustainability_assessment': {}
        }
        
        # This would implement detailed tokenomics analysis
        # Placeholder implementation
        
        return analysis

    def check_economic_invariants(self, context: AnalysisContext) -> List[Dict[str, Any]]:
        """Check economic invariants."""
        invariants = []
        
        # Common economic invariants
        invariants.extend(self._check_supply_invariants(context))
        invariants.extend(self._check_balance_invariants(context))
        invariants.extend(self._check_reward_invariants(context))
        
        return invariants

    def _check_supply_invariants(self, context: AnalysisContext) -> List[Dict[str, Any]]:
        """Check token supply invariants."""
        return []  # Placeholder

    def _check_balance_invariants(self, context: AnalysisContext) -> List[Dict[str, Any]]:
        """Check balance-related invariants."""
        return []  # Placeholder

    def _check_reward_invariants(self, context: AnalysisContext) -> List[Dict[str, Any]]:
        """Check reward distribution invariants."""
        return []  # Placeholder

class StateTransitionAnalyzer:
    """Analyzes state transitions in smart contracts."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def analyze_state_machine(self, functions: List[FunctionContext], source_code: str) -> Dict[str, Any]:
        """Analyze state machine patterns."""
        return {
            'has_state_machine': False,
            'states': [],
            'transitions': [],
            'invalid_transitions': [],
            'unreachable_states': []
        }

class InvariantExtractor:
    """Extracts and validates contract invariants."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def extract_invariants(self, context: AnalysisContext) -> List[Dict[str, Any]]:
        """Extract contract invariants."""
        return []  # Placeholder implementation
