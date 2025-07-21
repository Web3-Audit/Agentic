"""
Voting agent for analyzing DAO voting mechanisms and security.
"""

import re
import logging
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass

from .dao_base_agent import DAOBaseAgent
from ...models.context import AnalysisContext, FunctionContext
from ...models.finding import Finding, Severity, Category, CodeLocation
from ...llm.client import LLMClient
from ...llm.prompts import PromptManager

logger = logging.getLogger(__name__)

@dataclass
class VotingMetrics:
    """Voting-specific metrics."""
    total_voting_functions: int = 0
    delegation_functions: int = 0
    vote_casting_functions: int = 0
    vote_counting_functions: int = 0
    snapshot_functions: int = 0

class VotingAgent(DAOBaseAgent):
    """
    Specialized agent for analyzing DAO voting mechanisms.
    """
    
    def __init__(self, llm_client: Optional[LLMClient] = None, 
                 prompt_manager: Optional[PromptManager] = None):
        super().__init__("VotingAgent", llm_client, prompt_manager)
        
        # Voting-specific patterns
        self.voting_patterns = {
            'vote_types': ['for', 'against', 'abstain', 'yes', 'no'],
            'voting_power_sources': [
                'balanceOf', 'getVotes', 'getPastVotes', 'votingPower',
                'delegatedVotes', 'stakedTokens'
            ],
            'delegation_mechanisms': [
                'delegate', 'delegateTo', 'delegateFrom', 'undelegate',
                'delegatedPower', 'delegatee', 'delegator'
            ],
            'vote_security': [
                'signature', 'nonce', 'deadline', 'hash', 'merkle',
                'commit', 'reveal'
            ]
        }

    def analyze(self, context: AnalysisContext) -> List[Finding]:
        """
        Analyze voting mechanisms in DAO contracts.
        
        Args:
            context: Analysis context containing contract information
            
        Returns:
            List[Finding]: Voting-related findings
        """
        self.logger.info("Starting voting analysis")
        findings = []
        
        try:
            # Calculate voting metrics
            metrics = self._calculate_voting_metrics(context)
            
            # Check vote casting security
            findings.extend(self._check_vote_casting_security(context))
            
            # Check voting power calculation
            findings.extend(self._check_voting_power_calculation(context))
            
            # Check delegation mechanisms
            findings.extend(self._check_delegation_mechanisms(context))
            
            # Check vote counting
            findings.extend(self._check_vote_counting(context))
            
            # Check signature voting
            findings.extend(self._check_signature_voting(context))
            
            # Check snapshot mechanisms
            findings.extend(self._check_snapshot_mechanisms(context))
            
            self.logger.info(f"Voting analysis completed with {len(findings)} findings")
            return findings
            
        except Exception as e:
            self.logger.error(f"Error in voting analysis: {str(e)}")
            return findings

    def _calculate_voting_metrics(self, context: AnalysisContext) -> VotingMetrics:
        """Calculate voting-specific metrics."""
        metrics = VotingMetrics()
        
        for functions in context.functions.values():
            for func in functions:
                func_name_lower = func.name.lower()
                
                if any(pattern in func_name_lower for pattern in ['vote', 'cast', 'ballot']):
                    metrics.total_voting_functions += 1
                    
                    if 'cast' in func_name_lower:
                        metrics.vote_casting_functions += 1
                    
                if any(pattern in func_name_lower for pattern in ['delegate']):
                    metrics.delegation_functions += 1
                
                if any(pattern in func_name_lower for pattern in ['count', 'tally']):
                    metrics.vote_counting_functions += 1
                
                if any(pattern in func_name_lower for pattern in ['snapshot', 'checkpoint']):
                    metrics.snapshot_functions += 1
        
        return metrics

    def _check_vote_casting_security(self, context: AnalysisContext) -> List[Finding]:
        """Check vote casting mechanism security."""
        findings = []
        
        for contract_name, functions in context.functions.items():
            for func in functions:
                if self._is_vote_casting_function(func):
                    # Check for double voting protection
                    if not self._has_double_voting_protection(func):
                        finding = Finding(
                            title=f"Double Voting Vulnerability in {func.name}",
                            description=f"Vote casting function '{func.name}' allows double voting",
                            severity=Severity.HIGH,
                            category=Category.DAO_SPECIFIC,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Implement hasVoted mapping to prevent double voting",
                            impact="Users could vote multiple times to manipulate results"
                        )
                        findings.append(finding)
                    
                    # Check for vote type validation
                    if not self._validates_vote_type(func):
                        finding = Finding(
                            title=f"Missing Vote Type Validation in {func.name}",
                            description=f"Function '{func.name}' doesn't validate vote type (for/against/abstain)",
                            severity=Severity.MEDIUM,
                            category=Category.DAO_SPECIFIC,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Add validation for supported vote types",
                            impact="Invalid votes could be cast"
                        )
                        findings.append(finding)
                    
                    # Check for voting eligibility
                    if not self._checks_voting_eligibility(func):
                        finding = Finding(
                            title=f"Missing Voting Eligibility Check in {func.name}",
                            description=f"Function '{func.name}' doesn't verify voter eligibility",
                            severity=Severity.HIGH,
                            category=Category.DAO_SPECIFIC,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Add checks for voting power and eligibility",
                            impact="Ineligible users could participate in voting"
                        )
                        findings.append(finding)
        
        return findings

    def _check_voting_power_calculation(self, context: AnalysisContext) -> List[Finding]:
        """Check voting power calculation mechanisms."""
        findings = []
        
        for contract_name, functions in context.functions.items():
            for func in functions:
                if self._calculates_voting_power(func):
                    # Check for flash loan attack protection
                    if self._vulnerable_to_flash_loan_attack(func):
                        finding = Finding(
                            title=f"Flash Loan Voting Attack in {func.name}",
                            description=f"Voting power calculation in '{func.name}' vulnerable to flash loan attacks",
                            severity=Severity.CRITICAL,
                            category=Category.DAO_SPECIFIC,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Use historical balances or snapshots for voting power",
                            impact="Attackers could temporarily acquire large voting power"
                        )
                        findings.append(finding)
                    
                    # Check for voting power overflow
                    if self._has_voting_power_overflow_risk(func):
                        finding = Finding(
                            title=f"Voting Power Overflow Risk in {func.name}",
                            description=f"Function '{func.name}' may have voting power overflow issues",
                            severity=Severity.MEDIUM,
                            category=Category.ARITHMETIC,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Use SafeMath or built-in overflow protection",
                            impact="Voting power calculation could overflow"
                        )
                        findings.append(finding)
        
        return findings

    def _check_delegation_mechanisms(self, context: AnalysisContext) -> List[Finding]:
        """Check delegation mechanism security."""
        findings = []
        
        for contract_name, functions in context.functions.items():
            delegation_functions = [f for f in functions if self._is_delegation_function(f)]
            
            for func in delegation_functions:
                # Check for self-delegation protection
                if not self._prevents_self_delegation(func):
                    finding = Finding(
                        title=f"Self-Delegation Allowed in {func.name}",
                        description=f"Function '{func.name}' allows users to delegate to themselves",
                        severity=Severity.LOW,
                        category=Category.DAO_SPECIFIC,
                        location=CodeLocation(
                            contract_name=contract_name,
                            function_name=func.name
                        ),
                        affected_contracts=[contract_name],
                        affected_functions=[func.name],
                        recommendation="Prevent self-delegation to avoid confusion",
                        impact="Self-delegation may cause unexpected behavior"
                    )
                    findings.append(finding)
                
                # Check for delegation chain limits
                if not self._has_delegation_chain_limits(func):
                    finding = Finding(
                        title=f"Unlimited Delegation Chains in {func.name}",
                        description=f"Function '{func.name}' allows unlimited delegation chain length",
                        severity=Severity.MEDIUM,
                        category=Category.DAO_SPECIFIC,
                        location=CodeLocation(
                            contract_name=contract_name,
                            function_name=func.name
                        ),
                        affected_contracts=[contract_name],
                        affected_functions=[func.name],
                        recommendation="Implement maximum delegation chain length",
                        impact="Long delegation chains could cause gas issues"
                    )
                    findings.append(finding)
        
        return findings

    def _check_vote_counting(self, context: AnalysisContext) -> List[Finding]:
        """Check vote counting mechanisms."""
        findings = []
        
        for contract_name, functions in context.functions.items():
            for func in functions:
                if self._is_vote_counting_function(func):
                    # Check for accurate vote tallying
                    if not self._has_accurate_vote_tallying(func):
                        finding = Finding(
                            title=f"Inaccurate Vote Tallying in {func.name}",
                            description=f"Vote counting function '{func.name}' may have tallying errors",
                            severity=Severity.HIGH,
                            category=Category.DAO_SPECIFIC,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Ensure accurate vote tallying with proper arithmetic",
                            impact="Vote results could be incorrect"
                        )
                        findings.append(finding)
                    
                    # Check for quorum calculation
                    if not self._calculates_quorum_correctly(func):
                        finding = Finding(
                            title=f"Incorrect Quorum Calculation in {func.name}",
                            description=f"Function '{func.name}' may calculate quorum incorrectly",
                            severity=Severity.HIGH,
                            category=Category.DAO_SPECIFIC,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Verify quorum calculation logic",
                            impact="Proposals may pass or fail incorrectly"
                        )
                        findings.append(finding)
        
        return findings

    def _check_signature_voting(self, context: AnalysisContext) -> List[Finding]:
        """Check signature-based voting security."""
        findings = []
        
        for contract_name, functions in context.functions.items():
            for func in functions:
                if self._uses_signature_voting(func):
                    # Check for signature validation
                    if not self._validates_signatures_properly(func):
                        finding = Finding(
                            title=f"Inadequate Signature Validation in {func.name}",
                            description=f"Signature voting function '{func.name}' has weak signature validation",
                            severity=Severity.HIGH,
                            category=Category.DAO_SPECIFIC,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Implement robust signature validation including nonce and deadline checks",
                            impact="Invalid signatures could be accepted"
                        )
                        findings.append(finding)
                    
                    # Check for replay attack protection
                    if not self._has_replay_protection(func):
                        finding = Finding(
                            title=f"Signature Replay Attack in {func.name}",
                            description=f"Function '{func.name}' vulnerable to signature replay attacks",
                            severity=Severity.HIGH,
                            category=Category.DAO_SPECIFIC,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Use nonces or timestamps to prevent signature replay",
                            impact="Signatures could be replayed to cast duplicate votes"
                        )
                        findings.append(finding)
        
        return findings

    def _check_snapshot_mechanisms(self, context: AnalysisContext) -> List[Finding]:
        """Check snapshot mechanism security."""
        findings = []
        
        snapshot_functions = []
        for contract_name, functions in context.functions.items():
            for func in functions:
                if self._is_snapshot_function(func):
                    snapshot_functions.append((contract_name, func))
        
        if not snapshot_functions:
            # Check if voting uses current balances without snapshots
            uses_current_balance = False
            for contract_name, functions in context.functions.items():
                for func in functions:
                    if self._uses_current_balance_for_voting(func):
                        uses_current_balance = True
                        break
            
            if uses_current_balance:
                finding = Finding(
                    title="Missing Snapshot Mechanism",
                    description="Voting system uses current balances without snapshot protection",
                    severity=Severity.HIGH,
                    category=Category.DAO_SPECIFIC,
                    recommendation="Implement snapshot mechanism to prevent flash loan attacks",
                    impact="Voting power can be manipulated with flash loans"
                )
                findings.append(finding)
        else:
            # Check snapshot implementation
            for contract_name, func in snapshot_functions:
                if not self._implements_snapshots_correctly(func):
                    finding = Finding(
                        title=f"Incorrect Snapshot Implementation in {func.name}",
                        description=f"Snapshot function '{func.name}' may not work correctly",
                        severity=Severity.MEDIUM,
                        category=Category.DAO_SPECIFIC,
                        location=CodeLocation(
                            contract_name=contract_name,
                            function_name=func.name
                        ),
                        affected_contracts=[contract_name],
                        affected_functions=[func.name],
                        recommendation="Review snapshot implementation for correctness",
                        impact="Incorrect snapshots could affect voting results"
                    )
                    findings.append(finding)
        
        return findings

    # Helper methods for voting pattern detection

    def _is_vote_casting_function(self, func: FunctionContext) -> bool:
        """Check if function is for casting votes."""
        casting_keywords = ['castVote', 'vote', 'ballot', 'cast']
        return any(keyword.lower() in func.name.lower() for keyword in casting_keywords)

    def _is_delegation_function(self, func: FunctionContext) -> bool:
        """Check if function is for delegation."""
        delegation_keywords = ['delegate', 'delegateTo', 'delegateFrom', 'undelegate']
        return any(keyword.lower() in func.name.lower() for keyword in delegation_keywords)

    def _is_vote_counting_function(self, func: FunctionContext) -> bool:
        """Check if function counts votes."""
        counting_keywords = ['count', 'tally', 'result', 'outcome', 'quorum']
        return any(keyword.lower() in func.name.lower() for keyword in counting_keywords)

    def _is_snapshot_function(self, func: FunctionContext) -> bool:
        """Check if function implements snapshots."""
        snapshot_keywords = ['snapshot', 'checkpoint', 'capture']
        return any(keyword.lower() in func.name.lower() for keyword in snapshot_keywords)

    def _has_double_voting_protection(self, func: FunctionContext) -> bool:
        """Check if function prevents double voting."""
        protection_patterns = [
            'hasVoted', 'voted[', 'receipt', 'require.*!.*voted',
            'alreadyVoted', 'votedFor', 'votedAgainst'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) for pattern in protection_patterns)

    def _validates_vote_type(self, func: FunctionContext) -> bool:
        """Check if function validates vote type."""
        validation_patterns = [
            'require.*support', 'VoteType', 'enum.*Vote',
            'FOR.*AGAINST.*ABSTAIN', '0.*1.*2'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) for pattern in validation_patterns)

    def _checks_voting_eligibility(self, func: FunctionContext) -> bool:
        """Check if function verifies voting eligibility."""
        eligibility_patterns = [
            'getVotes', 'votingPower', 'balanceOf', 'eligible',
            'require.*votes', 'canVote'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) for pattern in eligibility_patterns)

    def _calculates_voting_power(self, func: FunctionContext) -> bool:
        """Check if function calculates voting power."""
        calculation_patterns = [
            'votingPower', 'getVotes', 'getPastVotes', 'balanceOf',
            'delegatedVotes', 'power'
        ]
        return any(pattern in func.body for pattern in calculation_patterns)

    def _vulnerable_to_flash_loan_attack(self, func: FunctionContext) -> bool:
        """Check if voting power calculation is vulnerable to flash loans."""
        uses_current_balance = any(pattern in func.body for pattern in ['balanceOf(', 'balance['])
        uses_snapshot = any(pattern in func.body for pattern in ['getPastVotes', 'balanceOfAt', 'snapshot'])
        
        return uses_current_balance and not uses_snapshot

    def _has_voting_power_overflow_risk(self, func: FunctionContext) -> bool:
        """Check for voting power overflow risks."""
        has_arithmetic = any(op in func.body for op in ['+', '*', '**'])
        has_protection = any(pattern in func.body.lower() for pattern in ['safemath', 'checked', 'unchecked'])
        
        return has_arithmetic and not has_protection

    def _prevents_self_delegation(self, func: FunctionContext) -> bool:
        """Check if function prevents self-delegation."""
        prevention_patterns = [
            'require.*!=.*msg.sender', 'require.*delegatee.*!=',
            'self.*delegation', 'msg.sender.*!=.*to'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) for pattern in prevention_patterns)

    def _has_delegation_chain_limits(self, func: FunctionContext) -> bool:
        """Check if delegation has chain length limits."""
        limit_patterns = [
            'maxDelegationDepth', 'delegationLimit', 'chainLength',
            'depth', 'recursive'
        ]
        return any(pattern.lower() in func.body.lower() for pattern in limit_patterns)

    def _has_accurate_vote_tallying(self, func: FunctionContext) -> bool:
        """Check if vote tallying is accurate."""
        tallying_patterns = [
            'forVotes', 'againstVotes', 'abstainVotes',
            'total.*votes', 'sum', 'SafeMath'
        ]
        return any(pattern in func.body for pattern in tallying_patterns)

    def _calculates_quorum_correctly(self, func: FunctionContext) -> bool:
        """Check if quorum calculation is correct."""
        quorum_patterns = [
            'quorum', 'totalSupply', 'percentage', 'threshold',
            'require.*quorum'
        ]
        return any(pattern.lower() in func.body.lower() for pattern in quorum_patterns)

    def _uses_signature_voting(self, func: FunctionContext) -> bool:
        """Check if function uses signature-based voting."""
        signature_patterns = [
            'signature', 'ecrecover', 'v,r,s', 'nonce',
            'deadline', 'hash', 'sign'
        ]
        return any(pattern.lower() in func.body.lower() for pattern in signature_patterns)

    def _validates_signatures_properly(self, func: FunctionContext) -> bool:
        """Check if signature validation is proper."""
        validation_patterns = [
            'ecrecover', 'require.*signer', 'deadline',
            'nonce', 'hash.*signature'
        ]
        return any(pattern.lower() in func.body.lower() for pattern in validation_patterns)

    def _has_replay_protection(self, func: FunctionContext) -> bool:
        """Check if function has replay attack protection."""
        protection_patterns = [
            'nonce', 'used.*signature', 'deadline',
            'timestamp', 'block.number'
        ]
        return any(pattern.lower() in func.body.lower() for pattern in protection_patterns)

    def _uses_current_balance_for_voting(self, func: FunctionContext) -> bool:
        """Check if function uses current balance for voting power."""
        current_balance_patterns = ['balanceOf(', 'balance[', 'getCurrentVotes']
        snapshot_patterns = ['getPastVotes', 'balanceOfAt', 'snapshot']
        
        uses_current = any(pattern in func.body for pattern in current_balance_patterns)
        uses_snapshot = any(pattern in func.body for pattern in snapshot_patterns)
        
        return uses_current and not uses_snapshot

    def _implements_snapshots_correctly(self, func: FunctionContext) -> bool:
        """Check if snapshot implementation is correct."""
        implementation_patterns = [
            'block.number', 'checkpoint', 'snapshot',
            'history', 'past.*balance'
        ]
        return any(pattern.lower() in func.body.lower() for pattern in implementation_patterns)
