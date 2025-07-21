"""
Base agent for DAO-specific smart contract analysis.
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

class DAOPattern(Enum):
    """Common DAO patterns."""
    GOVERNOR_ALPHA = "governor_alpha"
    GOVERNOR_BRAVO = "governor_bravo"
    COMPOUND_GOVERNOR = "compound_governor"
    ARAGON_DAO = "aragon_dao"
    MOLOCH_DAO = "moloch_dao"
    GNOSIS_SAFE = "gnosis_safe"
    CUSTOM_DAO = "custom_dao"

@dataclass
class DAOMetrics:
    """DAO-specific metrics."""
    total_governance_functions: int = 0
    voting_functions: int = 0
    proposal_functions: int = 0
    treasury_functions: int = 0
    admin_functions: int = 0
    timelock_functions: int = 0
    quorum_threshold: Optional[float] = None
    voting_period: Optional[int] = None
    proposal_threshold: Optional[float] = None

class DAOBaseAgent(BaseAgent):
    """
    Base agent for DAO-specific analysis with common functionality.
    """
    
    def __init__(self, agent_name: str, llm_client: Optional[LLMClient] = None, 
                 prompt_manager: Optional[PromptManager] = None):
        super().__init__(agent_name, llm_client, prompt_manager)
        
        # Common DAO patterns
        self.dao_patterns = {
            'governance_functions': [
                'propose', 'queue', 'execute', 'cancel', 'castVote',
                'castVoteWithReason', 'castVoteBySig'
            ],
            'voting_functions': [
                'vote', 'castVote', 'delegate', 'undelegate', 'getVotes',
                'getPastVotes', 'getCurrentVotes'
            ],
            'proposal_functions': [
                'propose', 'proposalCount', 'getProposal', 'proposalDeadline',
                'proposalSnapshot', 'proposalEta'
            ],
            'treasury_functions': [
                'withdraw', 'transfer', 'approve', 'execute', 'multicall'
            ],
            'timelock_functions': [
                'queueTransaction', 'executeTransaction', 'cancelTransaction',
                'delay', 'setDelay'
            ]
        }
        
        # Security patterns specific to DAOs
        self.security_patterns = {
            'governance_attack_vectors': [
                'flash_loan_voting',
                'vote_buying',
                'delegation_attack',
                'proposal_spam',
                'quorum_manipulation'
            ],
            'access_control_patterns': [
                'onlyGovernance',
                'onlyTimelock',
                'onlyProposer',
                'hasRole',
                'requireRole'
            ],
            'validation_patterns': [
                'require',
                'assert',
                'revert',
                'modifier'
            ]
        }

    def identify_dao_pattern(self, context: AnalysisContext) -> DAOPattern:
        """Identify the DAO pattern used."""
        for contract_name, functions in context.functions.items():
            function_names = [f.name for f in functions]
            
            # Check for Compound Governor pattern
            if any(name in function_names for name in ['propose', 'queue', 'execute', 'castVote']):
                if 'timelock' in contract_name.lower() or any('timelock' in f.name.lower() for f in functions):
                    return DAOPattern.COMPOUND_GOVERNOR
                return DAOPattern.GOVERNOR_BRAVO
            
            # Check for Aragon pattern
            if any(name in function_names for name in ['newVote', 'vote', 'executeVote']):
                return DAOPattern.ARAGON_DAO
            
            # Check for Moloch pattern
            if any(name in function_names for name in ['submitProposal', 'submitVote', 'processProposal']):
                return DAOPattern.MOLOCH_DAO
            
            # Check for Gnosis Safe pattern
            if any(name in function_names for name in ['execTransaction', 'approveHash', 'checkSignatures']):
                return DAOPattern.GNOSIS_SAFE
        
        return DAOPattern.CUSTOM_DAO

    def calculate_dao_metrics(self, context: AnalysisContext) -> DAOMetrics:
        """Calculate DAO-specific metrics."""
        metrics = DAOMetrics()
        
        for functions in context.functions.values():
            for func in functions:
                func_name_lower = func.name.lower()
                
                # Count governance functions
                if any(pattern in func_name_lower for pattern in self.dao_patterns['governance_functions']):
                    metrics.total_governance_functions += 1
                
                # Count voting functions
                if any(pattern in func_name_lower for pattern in self.dao_patterns['voting_functions']):
                    metrics.voting_functions += 1
                
                # Count proposal functions
                if any(pattern in func_name_lower for pattern in self.dao_patterns['proposal_functions']):
                    metrics.proposal_functions += 1
                
                # Count treasury functions
                if any(pattern in func_name_lower for pattern in self.dao_patterns['treasury_functions']):
                    metrics.treasury_functions += 1
                
                # Count timelock functions
                if any(pattern in func_name_lower for pattern in self.dao_patterns['timelock_functions']):
                    metrics.timelock_functions += 1
                
                # Count admin functions
                if func.is_admin_only:
                    metrics.admin_functions += 1
                
                # Extract quorum threshold
                if 'quorum' in func.body.lower():
                    quorum_match = re.search(r'quorum.*?(\d+)', func.body)
                    if quorum_match:
                        metrics.quorum_threshold = float(quorum_match.group(1))
                
                # Extract voting period
                if 'votingperiod' in func.body.lower().replace(' ', ''):
                    period_match = re.search(r'votingPeriod.*?(\d+)', func.body)
                    if period_match:
                        metrics.voting_period = int(period_match.group(1))
        
        return metrics

    def check_dao_governance_security(self, context: AnalysisContext) -> List[Finding]:
        """Check for common DAO governance security issues."""
        findings = []
        
        # Check for flash loan governance attacks
        findings.extend(self._check_flash_loan_governance_attacks(context))
        
        # Check for insufficient quorum
        findings.extend(self._check_quorum_requirements(context))
        
        # Check for timelock bypass
        findings.extend(self._check_timelock_bypass(context))
        
        # Check for proposal validation
        findings.extend(self._check_proposal_validation(context))
        
        return findings

    def _check_flash_loan_governance_attacks(self, context: AnalysisContext) -> List[Finding]:
        """Check for flash loan governance attack vectors."""
        findings = []
        
        for contract_name, functions in context.functions.items():
            for func in functions:
                if any(pattern in func.name.lower() for pattern in ['vote', 'delegate', 'propose']):
                    # Check if voting power is based on current balance
                    if self._uses_current_balance_for_voting(func) and not self._has_flash_loan_protection(func):
                        finding = Finding(
                            title=f"Flash Loan Governance Attack Vector in {func.name}",
                            description=f"Function '{func.name}' uses current balance for voting power without flash loan protection",
                            severity=Severity.HIGH,
                            category=Category.DAO_SPECIFIC,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Use snapshot-based voting power or implement flash loan protection",
                            impact="Attacker could temporarily acquire voting power via flash loans"
                        )
                        findings.append(finding)
        
        return findings

    def _check_quorum_requirements(self, context: AnalysisContext) -> List[Finding]:
        """Check for adequate quorum requirements."""
        findings = []
        
        metrics = self.calculate_dao_metrics(context)
        
        if metrics.quorum_threshold is not None and metrics.quorum_threshold < 10:  # Less than 10%
            finding = Finding(
                title="Low Quorum Threshold",
                description=f"Quorum threshold is {metrics.quorum_threshold}%, which may be too low",
                severity=Severity.MEDIUM,
                category=Category.DAO_SPECIFIC,
                recommendation="Consider increasing quorum threshold to prevent governance attacks",
                impact="Low quorum allows small groups to control governance decisions"
            )
            findings.append(finding)
        
        return findings

    def _check_timelock_bypass(self, context: AnalysisContext) -> List[Finding]:
        """Check for timelock bypass vulnerabilities."""
        findings = []
        
        for contract_name, functions in context.functions.items():
            admin_functions = [f for f in functions if f.is_admin_only]
            
            for func in admin_functions:
                if not self._has_timelock_protection(func) and self._is_critical_function(func):
                    finding = Finding(
                        title=f"Missing Timelock Protection in {func.name}",
                        description=f"Critical admin function '{func.name}' lacks timelock protection",
                        severity=Severity.HIGH,
                        category=Category.DAO_SPECIFIC,
                        location=CodeLocation(
                            contract_name=contract_name,
                            function_name=func.name
                        ),
                        affected_contracts=[contract_name],
                        affected_functions=[func.name],
                        recommendation="Add timelock mechanism for critical governance functions",
                        impact="Admins could make immediate changes without community review"
                    )
                    findings.append(finding)
        
        return findings

    def _check_proposal_validation(self, context: AnalysisContext) -> List[Finding]:
        """Check for proper proposal validation."""
        findings = []
        
        for contract_name, functions in context.functions.items():
            for func in functions:
                if 'propose' in func.name.lower():
                    validation_issues = []
                    
                    if not self._validates_proposer_eligibility(func):
                        validation_issues.append("No proposer eligibility check")
                    
                    if not self._validates_proposal_parameters(func):
                        validation_issues.append("No parameter validation")
                    
                    if not self._prevents_duplicate_proposals(func):
                        validation_issues.append("No duplicate prevention")
                    
                    if validation_issues:
                        finding = Finding(
                            title=f"Inadequate Proposal Validation in {func.name}",
                            description=f"Proposal function lacks validation: {', '.join(validation_issues)}",
                            severity=Severity.MEDIUM,
                            category=Category.DAO_SPECIFIC,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Implement comprehensive proposal validation",
                            impact="Invalid proposals could disrupt governance process"
                        )
                        findings.append(finding)
        
        return findings

    # Helper methods for pattern detection

    def _uses_current_balance_for_voting(self, func: FunctionContext) -> bool:
        """Check if function uses current balance for voting power."""
        balance_patterns = ['balanceOf', 'balance[', 'getCurrentVotes', 'getVotes()']
        snapshot_patterns = ['getPastVotes', 'balanceOfAt', 'snapshot']
        
        uses_current = any(pattern in func.body for pattern in balance_patterns)
        uses_snapshot = any(pattern in func.body for pattern in snapshot_patterns)
        
        return uses_current and not uses_snapshot

    def _has_flash_loan_protection(self, func: FunctionContext) -> bool:
        """Check if function has flash loan protection."""
        protection_patterns = [
            'getPastVotes', 'balanceOfAt', 'snapshot', 'block.number',
            'checkpoints', 'pastTotalSupply'
        ]
        return any(pattern in func.body for pattern in protection_patterns)

    def _has_timelock_protection(self, func: FunctionContext) -> bool:
        """Check if function has timelock protection."""
        timelock_patterns = ['timelock', 'delay', 'eta', 'queuedTransactions']
        return any(pattern.lower() in func.body.lower() for pattern in timelock_patterns)

    def _is_critical_function(self, func: FunctionContext) -> bool:
        """Check if function is critical for governance."""
        critical_patterns = [
            'setGovernor', 'setTimelock', 'upgrade', 'initialize',
            'setQuorum', 'setVotingPeriod', 'setProposalThreshold'
        ]
        return any(pattern.lower() in func.name.lower() for pattern in critical_patterns)

    def _validates_proposer_eligibility(self, func: FunctionContext) -> bool:
        """Check if function validates proposer eligibility."""
        validation_patterns = [
            'require.*proposer', 'require.*threshold', 'require.*balance',
            'getVotes', 'votingPower', 'canPropose'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) for pattern in validation_patterns)

    def _validates_proposal_parameters(self, func: FunctionContext) -> bool:
        """Check if function validates proposal parameters."""
        validation_patterns = [
            'require.*targets', 'require.*values', 'require.*calldatas',
            'require.*length', 'require.*description'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) for pattern in validation_patterns)

    def _prevents_duplicate_proposals(self, func: FunctionContext) -> bool:
        """Check if function prevents duplicate proposals."""
        prevention_patterns = [
            'proposalExists', 'proposalHash', 'duplicate', 'keccak256'
        ]
        return any(pattern in func.body for pattern in prevention_patterns)

    def extract_dao_parameters(self, context: AnalysisContext) -> Dict[str, Any]:
        """Extract DAO configuration parameters."""
        parameters = {}
        
        for functions in context.functions.values():
            for func in functions:
                # Extract quorum threshold
                quorum_match = re.search(r'quorum.*?(\d+)', func.body, re.IGNORECASE)
                if quorum_match:
                    parameters['quorum_threshold'] = int(quorum_match.group(1))
                
                # Extract voting period
                period_match = re.search(r'votingPeriod.*?(\d+)', func.body, re.IGNORECASE)
                if period_match:
                    parameters['voting_period'] = int(period_match.group(1))
                
                # Extract proposal threshold
                threshold_match = re.search(r'proposalThreshold.*?(\d+)', func.body, re.IGNORECASE)
                if threshold_match:
                    parameters['proposal_threshold'] = int(threshold_match.group(1))
                
                # Extract timelock delay
                delay_match = re.search(r'delay.*?(\d+)', func.body, re.IGNORECASE)
                if delay_match:
                    parameters['timelock_delay'] = int(delay_match.group(1))
        
        return parameters

    def check_dao_best_practices(self, context: AnalysisContext) -> List[Finding]:
        """Check for DAO best practices."""
        findings = []
        
        dao_params = self.extract_dao_parameters(context)
        
        # Check voting period
        if 'voting_period' in dao_params:
            if dao_params['voting_period'] < 86400:  # Less than 1 day
                finding = Finding(
                    title="Short Voting Period",
                    description=f"Voting period of {dao_params['voting_period']} seconds may be too short",
                    severity=Severity.LOW,
                    category=Category.DAO_SPECIFIC,
                    recommendation="Consider extending voting period to allow proper deliberation",
                    impact="Short voting periods may not allow adequate participation"
                )
                findings.append(finding)
        
        # Check timelock delay
        if 'timelock_delay' in dao_params:
            if dao_params['timelock_delay'] < 86400:  # Less than 1 day
                finding = Finding(
                    title="Short Timelock Delay",
                    description=f"Timelock delay of {dao_params['timelock_delay']} seconds may be too short",
                    severity=Severity.MEDIUM,
                    category=Category.DAO_SPECIFIC,
                    recommendation="Consider increasing timelock delay to allow community review",
                    impact="Short delays may not provide adequate protection against malicious proposals"
                )
                findings.append(finding)
        
        return findings
    def classify_dao_type(self, context: AnalysisContext) -> Dict[str, Any]:
        """
        Classify the specific type of DAO based on contract patterns.
        
        Returns:
            Dict containing DAO classification information
        """
        classification = {
            'primary_type': 'unknown',
            'secondary_types': [],
            'confidence': 0.0,
            'indicators': []
        }
        
        # Check for different DAO types
        dao_indicators = {
            'governance': ['governance', 'proposal', 'vote', 'delegate'],
            'investment': ['invest', 'fund', 'portfolio', 'asset'],
            'treasury': ['treasury', 'fund', 'withdraw', 'spend'],
            'protocol': ['protocol', 'upgrade', 'parameter', 'config'],
            'social': ['member', 'reputation', 'community', 'social'],
            'collector': ['nft', 'collect', 'curator', 'artwork']
        }
        
        scores = {}
        for dao_type, keywords in dao_indicators.items():
            score = 0
            found_indicators = []
            
            for contract_name, functions in context.functions.items():
                contract_code = context.contract_code.lower()
                
                # Check contract name and code
                for keyword in keywords:
                    if keyword in contract_code:
                        score += 1
                        found_indicators.append(f"keyword_{keyword}")
                
                # Check function names
                for func in functions:
                    for keyword in keywords:
                        if keyword in func.name.lower():
                            score += 2  # Function names are more indicative
                            found_indicators.append(f"function_{keyword}")
            
            if score > 0:
                scores[dao_type] = score
                classification['indicators'].extend(found_indicators)
        
        if scores:
            # Determine primary type (highest score)
            primary_type = max(scores.keys(), key=lambda k: scores[k])
            classification['primary_type'] = primary_type
            classification['confidence'] = min(scores[primary_type] / 10.0, 1.0)  # Normalize to 0-1
            
            # Determine secondary types (score > threshold)
            threshold = scores[primary_type] * 0.6
            secondary_types = [
                dao_type for dao_type, score in scores.items() 
                if dao_type != primary_type and score > threshold
            ]
            classification['secondary_types'] = secondary_types
        
        return classification
