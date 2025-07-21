"""
Proposal agent for analyzing DAO proposal mechanisms and security.
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
class ProposalMetrics:
    """Proposal-specific metrics."""
    proposal_functions: int = 0
    creation_functions: int = 0
    execution_functions: int = 0
    cancellation_functions: int = 0
    validation_functions: int = 0

class ProposalAgent(DAOBaseAgent):
    """
    Specialized agent for analyzing DAO proposal mechanisms.
    """
    
    def __init__(self, llm_client: Optional[LLMClient] = None, 
                 prompt_manager: Optional[PromptManager] = None):
        super().__init__("ProposalAgent", llm_client, prompt_manager)
        
        # Proposal-specific patterns
        self.proposal_patterns = {
            'lifecycle_functions': [
                'propose', 'queue', 'execute', 'cancel', 'expire'
            ],
            'validation_patterns': [
                'threshold', 'quorum', 'deadline', 'delay', 'eta'
            ],
            'proposal_states': [
                'Pending', 'Active', 'Canceled', 'Defeated', 
                'Succeeded', 'Queued', 'Expired', 'Executed'
            ],
            'security_patterns': [
                'proposalThreshold', 'votingDelay', 'votingPeriod',
                'timelockDelay', 'queuedTransactions'
            ]
        }

    def analyze(self, context: AnalysisContext) -> List[Finding]:
        """
        Analyze proposal mechanisms in DAO contracts.
        
        Args:
            context: Analysis context containing contract information
            
        Returns:
            List[Finding]: Proposal-related findings
        """
        self.logger.info("Starting proposal analysis")
        findings = []
        
        try:
            # Calculate proposal metrics
            metrics = self._calculate_proposal_metrics(context)
            
            # Check proposal creation security
            findings.extend(self._check_proposal_creation_security(context))
            
            # Check proposal validation
            findings.extend(self._check_proposal_validation(context))
            
            # Check proposal execution security
            findings.extend(self._check_proposal_execution_security(context))
            
            # Check proposal lifecycle
            findings.extend(self._check_proposal_lifecycle(context))
            
            # Check timelock mechanisms
            findings.extend(self._check_timelock_mechanisms(context))
            
            self.logger.info(f"Proposal analysis completed with {len(findings)} findings")
            return findings
            
        except Exception as e:
            self.logger.error(f"Error in proposal analysis: {str(e)}")
            return findings

    def _calculate_proposal_metrics(self, context: AnalysisContext) -> ProposalMetrics:
        """Calculate proposal-specific metrics."""
        metrics = ProposalMetrics()
        
        for functions in context.functions.values():
            for func in functions:
                func_name_lower = func.name.lower()
                
                if any(pattern in func_name_lower for pattern in self.proposal_patterns['lifecycle_functions']):
                    metrics.proposal_functions += 1
                    
                    if 'propose' in func_name_lower:
                        metrics.creation_functions += 1
                    elif 'execute' in func_name_lower:
                        metrics.execution_functions += 1
                    elif 'cancel' in func_name_lower:
                        metrics.cancellation_functions += 1
                
                if any(pattern in func_name_lower for pattern in self.proposal_patterns['validation_patterns']):
                    metrics.validation_functions += 1
        
        return metrics

    def _check_proposal_creation_security(self, context: AnalysisContext) -> List[Finding]:
        """Check proposal creation mechanism security."""
        findings = []
        
        for contract_name, functions in context.functions.items():
            for func in functions:
                if self._is_proposal_creation_function(func):
                    # Check for proposal threshold enforcement
                    if not self._enforces_proposal_threshold(func):
                        finding = Finding(
                            title=f"Missing Proposal Threshold in {func.name}",
                            description=f"Proposal creation function '{func.name}' doesn't enforce minimum voting power threshold",
                            severity=Severity.MEDIUM,
                            category=Category.DAO_SPECIFIC,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Implement proposal threshold to prevent spam",
                            impact="Low-stake actors could spam proposals"
                        )
                        findings.append(finding)
                    
                    # Check for duplicate proposal prevention
                    if not self._prevents_duplicate_proposals(func):
                        finding = Finding(
                            title=f"Duplicate Proposal Prevention Missing in {func.name}",
                            description=f"Function '{func.name}' doesn't prevent duplicate proposals",
                            severity=Severity.LOW,
                            category=Category.DAO_SPECIFIC,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Implement proposal hash checking to prevent duplicates",
                            impact="Identical proposals could be created multiple times"
                        )
                        findings.append(finding)
                    
                    # Check for proposal parameter validation
                    if not self._validates_proposal_parameters(func):
                        finding = Finding(
                            title=f"Inadequate Proposal Parameter Validation in {func.name}",
                            description=f"Function '{func.name}' doesn't properly validate proposal parameters",
                            severity=Severity.MEDIUM,
                            category=Category.DAO_SPECIFIC,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Add comprehensive validation for targets, values, calldatas, and description",
                            impact="Invalid proposals could be created"
                        )
                        findings.append(finding)
                    
                    # Check for proposal spam prevention
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
                            recommendation="Add cooldown period between proposals from same proposer",
                            impact="Users could spam proposals rapidly"
                        )
                        findings.append(finding)
        
        return findings

    def _check_proposal_validation(self, context: AnalysisContext) -> List[Finding]:
        """Check proposal validation mechanisms."""
        findings = []
        
        for contract_name, functions in context.functions.items():
            for func in functions:
                if self._validates_proposals(func):
                    # Check for proper state validation
                    if not self._validates_proposal_state(func):
                        finding = Finding(
                            title=f"Inadequate Proposal State Validation in {func.name}",
                            description=f"Function '{func.name}' doesn't properly validate proposal state",
                            severity=Severity.MEDIUM,
                            category=Category.DAO_SPECIFIC,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Add comprehensive proposal state validation",
                            impact="Operations could be performed on proposals in invalid states"
                        )
                        findings.append(finding)
                    
                    # Check for deadline validation
                    if not self._validates_deadlines(func):
                        finding = Finding(
                            title=f"Missing Deadline Validation in {func.name}",
                            description=f"Function '{func.name}' doesn't validate proposal deadlines",
                            severity=Severity.MEDIUM,
                            category=Category.DAO_SPECIFIC,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Add deadline checks for proposal operations",
                            impact="Operations could occur outside valid timeframes"
                        )
                        findings.append(finding)
        
        return findings

    def _check_proposal_execution_security(self, context: AnalysisContext) -> List[Finding]:
        """Check proposal execution mechanism security."""
        findings = []
        
        for contract_name, functions in context.functions.items():
            for func in functions:
                if self._is_proposal_execution_function(func):
                    # Check for execution prerequisites
                    if not self._validates_execution_prerequisites(func):
                        finding = Finding(
                            title=f"Missing Execution Prerequisites in {func.name}",
                            description=f"Execution function '{func.name}' doesn't validate all prerequisites",
                            severity=Severity.HIGH,
                            category=Category.DAO_SPECIFIC,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Validate proposal success, quorum, timelock, and other prerequisites",
                            impact="Invalid proposals could be executed"
                        )
                        findings.append(finding)
                    
                    # Check for reentrancy protection
                    if not self._has_reentrancy_protection_execution(func):
                        finding = Finding(
                            title=f"Reentrancy Risk in Proposal Execution {func.name}",
                            description=f"Execution function '{func.name}' may be vulnerable to reentrancy",
                            severity=Severity.HIGH,
                            category=Category.REENTRANCY,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Add reentrancy guards to proposal execution",
                            impact="Proposal execution could be manipulated through reentrancy"
                        )
