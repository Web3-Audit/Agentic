"""
Governance agent for analyzing DAO governance mechanisms and security.
"""

import re
import logging
from typing import Dict, List, Optional, Any, Set, Tuple

from .dao_base_agent import DAOBaseAgent, DAOPattern, DAOMetrics
from ...models.context import AnalysisContext, FunctionContext
from ...models.finding import Finding, Severity, Category, CodeLocation
from ...llm.client import LLMClient
from ...llm.prompts import PromptManager

logger = logging.getLogger(__name__)

class GovernanceAgent(DAOBaseAgent):
    """
    Specialized agent for analyzing DAO governance mechanisms.
    """
    
    def __init__(self, llm_client: Optional[LLMClient] = None, 
                 prompt_manager: Optional[PromptManager] = None):
        super().__init__("GovernanceAgent", llm_client, prompt_manager)
        
        # Governance-specific patterns
        self.governance_patterns = {
            'voting_power_patterns': [
                'getVotes', 'getPastVotes', 'getCurrentVotes', 'votingPower',
                'balanceOf', 'balanceOfAt', 'delegatedPower'
            ],
            'delegation_patterns': [
                'delegate', 'delegateTo', 'delegateFrom', 'delegated',
                'delegates', 'getDelegates'
            ],
            'proposal_lifecycle': [
                'propose', 'queue', 'execute', 'cancel', 'state',
                'proposalState', 'proposalDeadline', 'proposalEta'
            ],
            'governance_attacks': [
                'flash_loan', 'vote_buying', 'bribery', 'delegation_attack',
                'proposal_spam', 'governance_extractable_value'
            ]
        }

    def analyze(self, context: AnalysisContext) -> List[Finding]:
        """
        Analyze governance mechanisms in DAO contracts.
        
        Args:
            context: Analysis context containing contract information
            
        Returns:
            List[Finding]: Governance-related findings
        """
        self.logger.info("Starting governance analysis")
        findings = []
        
        try:
            # Identify DAO pattern
            dao_pattern = self.identify_dao_pattern(context)
            
            # Calculate governance metrics
            metrics = self.calculate_dao_metrics(context)
            
            # Check governance security
            findings.extend(self.check_dao_governance_security(context))
            
            # Check voting mechanisms
            findings.extend(self._check_voting_mechanisms(context))
            
            # Check delegation security
            findings.extend(self._check_delegation_security(context))
            
            # Check proposal mechanisms
            findings.extend(self._check_proposal_mechanisms(context))
            
            # Check governance token security
            findings.extend(self._check_governance_token_security(context))
            
            # Check emergency controls
            findings.extend(self._check_emergency_controls(context))
            
            self.logger.info(f"Governance analysis completed with {len(findings)} findings")
            return findings
            
        except Exception as e:
            self.logger.error(f"Error in governance analysis: {str(e)}")
            return findings

    def _check_voting_mechanisms(self, context: AnalysisContext) -> List[Finding]:
        """Check voting mechanism security."""
        findings = []
        
        for contract_name, functions in context.functions.items():
            voting_functions = [f for f in functions if self._is_voting_function(f)]
            
            for func in voting_functions:
                # Check for double voting protection
                if not self._has_double_voting_protection(func):
                    finding = Finding(
                        title=f"Missing Double Voting Protection in {func.name}",
                        description=f"Voting function '{func.name}' doesn't prevent double voting",
                        severity=Severity.HIGH,
                        category=Category.DAO_SPECIFIC,
                        location=CodeLocation(
                            contract_name=contract_name,
                            function_name=func.name
                        ),
                        affected_contracts=[contract_name],
                        affected_functions=[func.name],
                        recommendation="Implement checks to prevent users from voting multiple times",
                        impact="Users could vote multiple times to manipulate results"
                    )
                    findings.append(finding)
                
                # Check for vote delegation validation
                if self._uses_delegation(func) and not self._validates_delegation(func):
                    finding = Finding(
                        title=f"Inadequate Delegation Validation in {func.name}",
                        description=f"Function '{func.name}' uses delegation without proper validation",
                        severity=Severity.MEDIUM,
                        category=Category.DAO_SPECIFIC,
                        location=CodeLocation(
                            contract_name=contract_name,
                            function_name=func.name
                        ),
                        affected_contracts=[contract_name],
                        affected_functions=[func.name],
                        recommendation="Add validation for delegation chains and circular delegation",
                        impact="Invalid delegation could affect voting results"
                    )
                    findings.append(finding)
                
                # Check for voting period validation
                if not self._validates_voting_period(func):
                    finding = Finding(
                        title=f"Missing Voting Period Validation in {func.name}",
                        description=f"Function '{func.name}' doesn't validate voting is within allowed period",
                        severity=Severity.MEDIUM,
                        category=Category.DAO_SPECIFIC,
                        location=CodeLocation(
                            contract_name=contract_name,
                            function_name=func.name
                        ),
                        affected_contracts=[contract_name],
                        affected_functions=[func.name],
                        recommendation="Add checks to ensure voting occurs within valid time window",
                        impact="Votes could be cast outside valid voting period"
                    )
                    findings.append(finding)
        
        return findings

    def _check_delegation_security(self, context: AnalysisContext) -> List[Finding]:
        """Check delegation mechanism security."""
        findings = []
        
        for contract_name, functions in context.functions.items():
            delegation_functions = [f for f in functions if self._is_delegation_function(f)]
            
            for func in delegation_functions:
                # Check for circular delegation protection
                if not self._prevents_circular_delegation(func):
                    finding = Finding(
                        title=f"Missing Circular Delegation Protection in {func.name}",
                        description=f"Delegation function '{func.name}' doesn't prevent circular delegation",
                        severity=Severity.MEDIUM,
                        category=Category.DAO_SPECIFIC,
                        location=CodeLocation(
                            contract_name=contract_name,
                            function_name=func.name
                        ),
                        affected_contracts=[contract_name],
                        affected_functions=[func.name],
                        recommendation="Implement checks to prevent circular delegation chains",
                        impact="Circular delegation could cause infinite loops or unexpected behavior"
                    )
                    findings.append(finding)
                
                # Check for delegation power limits
                if not self._has_delegation_limits(func):
                    finding = Finding(
                        title=f"No Delegation Power Limits in {func.name}",
                        description=f"Function '{func.name}' allows unlimited delegation power concentration",
                        severity=Severity.LOW,
                        category=Category.DAO_SPECIFIC,
                        location=CodeLocation(
                            contract_name=contract_name,
                            function_name=func.name
                        ),
                        affected_contracts=[contract_name],
                        affected_functions=[func.name],
                        recommendation="Consider implementing limits on delegation power concentration",
                        impact="Excessive delegation could lead to governance centralization"
                    )
                    findings.append(finding)
        
        return findings

    def _check_proposal_mechanisms(self, context: AnalysisContext) -> List[Finding]:
        """Check proposal mechanism security."""
        findings = []
        
        for contract_name, functions in context.functions.items():
            proposal_functions = [f for f in functions if self._is_proposal_function(f)]
            
            for func in proposal_functions:
                if 'propose' in func.name.lower():
                    # Check for proposal threshold
                    if not self._enforces_proposal_threshold(func):
                        finding = Finding(
                            title=f"Missing Proposal Threshold in {func.name}",
                            description=f"Function '{func.name}' doesn't enforce minimum voting power for proposals",
                            severity=Severity.MEDIUM,
                            category=Category.DAO_SPECIFIC,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Implement minimum voting power requirement for proposals",
                            impact="Anyone could create proposals leading to spam"
                        )
                        findings.append(finding)
                    
                    # Check for proposal cooldown
                    if not self._has_proposal_cooldown(func):
                        finding = Finding(
                            title=f"Missing Proposal Cooldown in {func.name}",
                            description=f"Function '{func.name}' doesn't implement cooldown between proposals",
                            severity=Severity.LOW,
                            category=Category.DAO_SPECIFIC,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Add cooldown period between proposals from same user",
                            impact="Users could spam proposals"
                        )
                        findings.append(finding)
                
                elif 'execute' in func.name.lower():
                    # Check for execution validation
                    if not self._validates_execution_conditions(func):
                        finding = Finding(
                            title=f"Inadequate Execution Validation in {func.name}",
                            description=f"Function '{func.name}' doesn't properly validate execution conditions",
                            severity=Severity.HIGH,
                            category=Category.DAO_SPECIFIC,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Add comprehensive validation before proposal execution",
                            impact="Invalid proposals could be executed"
                        )
                        findings.append(finding)
        
        return findings

    def _check_governance_token_security(self, context: AnalysisContext) -> List[Finding]:
        """Check governance token security."""
        findings = []
        
        for contract_name, functions in context.functions.items():
            # Check for governance token manipulation
            for func in functions:
                if self._manipulates_governance_tokens(func):
                    if not self._has_governance_protection(func):
                        finding = Finding(
                            title=f"Governance Token Manipulation Risk in {func.name}",
                            description=f"Function '{func.name}' can manipulate governance tokens without protection",
                            severity=Severity.CRITICAL,
                            category=Category.DAO_SPECIFIC,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Add strict access controls and validation for token operations",
                            impact="Manipulation could compromise entire governance system"
                        )
                        findings.append(finding)
        
        return findings

    def _check_emergency_controls(self, context: AnalysisContext) -> List[Finding]:
        """Check emergency control mechanisms."""
        findings = []
        
        has_emergency_controls = False
        emergency_functions = []
        
        for contract_name, functions in context.functions.items():
            for func in functions:
                if self._is_emergency_function(func):
                    has_emergency_controls = True
                    emergency_functions.append(func.name)
                    
                    # Check for proper emergency validation
                    if not self._has_emergency_validation(func):
                        finding = Finding(
                            title=f"Inadequate Emergency Controls in {func.name}",
                            description=f"Emergency function '{func.name}' lacks proper validation",
                            severity=Severity.HIGH,
                            category=Category.DAO_SPECIFIC,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Add strict validation and multi-sig requirements for emergency functions",
                            impact="Emergency powers could be abused"
                        )
                        findings.append(finding)
        
        # Check if governance system lacks emergency controls
        if not has_emergency_controls:
            finding = Finding(
                title="Missing Emergency Controls",
                description="DAO lacks emergency control mechanisms for critical situations",
                severity=Severity.MEDIUM,
                category=Category.DAO_SPECIFIC,
                recommendation="Implement emergency controls with proper governance oversight",
                impact="DAO may be unable to respond to critical security situations"
            )
            findings.append(finding)
        
        return findings

    # Helper methods for pattern detection

    def _is_voting_function(self, func: FunctionContext) -> bool:
        """Check if function is related to voting."""
        voting_keywords = ['vote', 'castVote', 'ballot', 'poll']
        return any(keyword.lower() in func.name.lower() for keyword in voting_keywords)

    def _is_delegation_function(self, func: FunctionContext) -> bool:
        """Check if function is related to delegation."""
        delegation_keywords = ['delegate', 'delegateTo', 'delegateFrom']
        return any(keyword.lower() in func.name.lower() for keyword in delegation_keywords)

    def _is_proposal_function(self, func: FunctionContext) -> bool:
        """Check if function is related to proposals."""
        proposal_keywords = ['propose', 'proposal', 'queue', 'execute', 'cancel']
        return any(keyword.lower() in func.name.lower() for keyword in proposal_keywords)

    def _has_double_voting_protection(self, func: FunctionContext) -> bool:
        """Check if function prevents double voting."""
        protection_patterns = [
            'hasVoted', 'voted[', 'receipt', 'require.*voted',
            'alreadyVoted', 'duplicate'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) for pattern in protection_patterns)

    def _uses_delegation(self, func: FunctionContext) -> bool:
        """Check if function uses delegation."""
        delegation_patterns = ['delegate', 'delegated', 'delegatee']
        return any(pattern.lower() in func.body.lower() for pattern in delegation_patterns)

    def _validates_delegation(self, func: FunctionContext) -> bool:
        """Check if function validates delegation."""
        validation_patterns = [
            'require.*delegate', 'valid.*delegate', 'check.*delegate'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) for pattern in validation_patterns)

    def _validates_voting_period(self, func: FunctionContext) -> bool:
        """Check if function validates voting period."""
        period_patterns = [
            'deadline', 'votingPeriod', 'endTime', 'startTime',
            'block.timestamp', 'block.number'
        ]
        return any(pattern in func.body for pattern in period_patterns)

    def _prevents_circular_delegation(self, func: FunctionContext) -> bool:
        """Check if function prevents circular delegation."""
        prevention_patterns = [
            'circular', 'cycle', 'loop', 'visited', 'path'
        ]
        return any(pattern.lower() in func.body.lower() for pattern in prevention_patterns)

    def _has_delegation_limits(self, func: FunctionContext) -> bool:
        """Check if function has delegation power limits."""
        limit_patterns = [
            'maxDelegation', 'delegationLimit', 'require.*limit',
            'maximum', 'cap'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) for pattern in limit_patterns)

    def _enforces_proposal_threshold(self, func: FunctionContext) -> bool:
        """Check if function enforces proposal threshold."""
        threshold_patterns = [
            'proposalThreshold', 'getVotes', 'votingPower',
            'require.*threshold', 'minimum.*votes'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) for pattern in threshold_patterns)

    def _has_proposal_cooldown(self, func: FunctionContext) -> bool:
        """Check if function has proposal cooldown."""
        cooldown_patterns = [
            'cooldown', 'lastProposal', 'proposalDelay',
            'timestamp', 'block.number'
        ]
        return any(pattern.lower() in func.body.lower() for pattern in cooldown_patterns)

    def _validates_execution_conditions(self, func: FunctionContext) -> bool:
        """Check if function validates execution conditions."""
        validation_patterns = [
            'require.*state', 'require.*quorum', 'require.*votes',
            'succeeded', 'passed', 'approved'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) for pattern in validation_patterns)

    def _manipulates_governance_tokens(self, func: FunctionContext) -> bool:
        """Check if function manipulates governance tokens."""
        manipulation_patterns = [
            'mint', 'burn', 'transfer.*governance', 'balanceOf',
            'totalSupply', '_mint', '_burn'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) for pattern in manipulation_patterns)

    def _has_governance_protection(self, func: FunctionContext) -> bool:
        """Check if function has governance protection."""
        protection_patterns = [
            'onlyGovernance', 'onlyOwner', 'hasRole', 'authorized',
            'require.*governance', 'modifier'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) for pattern in protection_patterns)

    def _is_emergency_function(self, func: FunctionContext) -> bool:
        """Check if function is an emergency function."""
        emergency_keywords = [
            'emergency', 'pause', 'stop', 'halt', 'freeze',
            'shutdown', 'kill', 'abort'
        ]
        return any(keyword.lower() in func.name.lower() for keyword in emergency_keywords)

    def _has_emergency_validation(self, func: FunctionContext) -> bool:
        """Check if emergency function has proper validation."""
        validation_patterns = [
            'require.*emergency', 'onlyEmergency', 'crisis',
            'guardian', 'multisig', 'timelock'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) for pattern in validation_patterns)
