"""
Multisig agent for analyzing DAO multisignature wallet mechanisms and security.
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
class MultisigMetrics:
    """Multisig-specific metrics."""
    multisig_functions: int = 0
    transaction_functions: int = 0
    confirmation_functions: int = 0
    owner_management_functions: int = 0
    threshold_functions: int = 0
    required_confirmations: Optional[int] = None
    total_owners: Optional[int] = None

class MultisigAgent(DAOBaseAgent):
    """
    Specialized agent for analyzing DAO multisignature mechanisms.
    """
    
    def __init__(self, llm_client: Optional[LLMClient] = None,
                 prompt_manager: Optional[PromptManager] = None):
        super().__init__("MultisigAgent", llm_client, prompt_manager)
        
        # Multisig-specific patterns
        self.multisig_patterns = {
            'transaction_lifecycle': [
                'submitTransaction', 'confirmTransaction', 'executeTransaction',
                'revokeConfirmation', 'addTransaction'
            ],
            'owner_management': [
                'addOwner', 'removeOwner', 'replaceOwner', 'changeRequirement',
                'isOwner', 'getOwners'
            ],
            'signature_patterns': [
                'signature', 'ecrecover', 'nonce', 'hash', 'sign',
                'verify', 'validate'
            ],
            'security_patterns': [
                'threshold', 'required', 'confirmations', 'approvals',
                'owners', 'signers'
            ]
        }
    
    def analyze(self, context: AnalysisContext) -> List[Finding]:
        """
        Analyze multisig mechanisms in DAO contracts.
        
        Args:
            context: Analysis context containing contract information
            
        Returns:
            List[Finding]: Multisig-related findings
        """
        self.logger.info("Starting multisig analysis")
        findings = []
        
        try:
            # Calculate multisig metrics
            metrics = self._calculate_multisig_metrics(context)
            
            # Check multisig transaction security
            findings.extend(self._check_multisig_transaction_security(context))
            
            # Check owner management
            findings.extend(self._check_owner_management(context))
            
            # Check signature validation
            findings.extend(self._check_signature_validation(context))
            
            # Check threshold management
            findings.extend(self._check_threshold_management(context))
            
            # Check reentrancy protection
            findings.extend(self._check_multisig_reentrancy(context))
            
            # Check access controls
            findings.extend(self._check_multisig_access_controls(context))
            
            self.logger.info(f"Multisig analysis completed with {len(findings)} findings")
            return findings
            
        except Exception as e:
            self.logger.error(f"Error in multisig analysis: {str(e)}")
            return findings
    
    def _calculate_multisig_metrics(self, context: AnalysisContext) -> MultisigMetrics:
        """Calculate multisig-specific metrics."""
        metrics = MultisigMetrics()
        
        for functions in context.functions.values():
            for func in functions:
                func_name_lower = func.name.lower()
                
                if any(pattern in func_name_lower for pattern in self.multisig_patterns['transaction_lifecycle']):
                    metrics.multisig_functions += 1
                    
                    if 'submit' in func_name_lower or 'add' in func_name_lower:
                        metrics.transaction_functions += 1
                    elif 'confirm' in func_name_lower:
                        metrics.confirmation_functions += 1
                
                if any(pattern in func_name_lower for pattern in self.multisig_patterns['owner_management']):
                    metrics.owner_management_functions += 1
                
                if 'threshold' in func_name_lower or 'requirement' in func_name_lower:
                    metrics.threshold_functions += 1
                
                # Extract required confirmations
                required_match = re.search(r'required.*?(\d+)', func.body, re.IGNORECASE)
                if required_match:
                    metrics.required_confirmations = int(required_match.group(1))
                
                # Extract total owners
                owners_match = re.search(r'owners.*length.*?(\d+)', func.body, re.IGNORECASE)
                if owners_match:
                    metrics.total_owners = int(owners_match.group(1))
        
        return metrics
    
    def _check_multisig_transaction_security(self, context: AnalysisContext) -> List[Finding]:
        """Check multisig transaction mechanism security."""
        findings = []
        
        for contract_name, functions in context.functions.items():
            for func in functions:
                if self._is_multisig_transaction_function(func):
                    
                    # Check for proper confirmation tracking
                    if not self._tracks_confirmations_properly(func):
                        finding = Finding(
                            title=f"Inadequate Confirmation Tracking in {func.name}",
                            description=f"Multisig function '{func.name}' doesn't properly track confirmations",
                            severity=Severity.HIGH,
                            category=Category.DAO_SPECIFIC,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Implement proper confirmation tracking with mappings",
                            impact="Transactions could be executed without proper confirmations"
                        )
                        findings.append(finding)
                    
                    # Check for duplicate confirmation prevention
                    if not self._prevents_duplicate_confirmations(func):
                        finding = Finding(
                            title=f"Duplicate Confirmation Risk in {func.name}",
                            description=f"Function '{func.name}' allows duplicate confirmations from same owner",
                            severity=Severity.MEDIUM,
                            category=Category.DAO_SPECIFIC,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Prevent owners from confirming transactions multiple times",
                            impact="Confirmation count could be artificially inflated"
                        )
                        findings.append(finding)
                    
                    # Check for transaction execution validation
                    if 'execute' in func.name.lower() and not self._validates_execution_requirements(func):
                        finding = Finding(
                            title=f"Insufficient Execution Validation in {func.name}",
                            description=f"Transaction execution function '{func.name}' lacks proper validation",
                            severity=Severity.CRITICAL,
                            category=Category.DAO_SPECIFIC,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Validate confirmation count, transaction existence, and execution status",
                            impact="Transactions could be executed without meeting requirements"
                        )
                        findings.append(finding)
        
        return findings
    
    def _check_owner_management(self, context: AnalysisContext) -> List[Finding]:
        """Check owner management mechanisms."""
        findings = []
        
        for contract_name, functions in context.functions.items():
            for func in functions:
                if self._is_owner_management_function(func):
                    
                    # Check for proper owner validation
                    if not self._validates_owner_operations(func):
                        finding = Finding(
                            title=f"Inadequate Owner Validation in {func.name}",
                            description=f"Owner management function '{func.name}' lacks proper validation",
                            severity=Severity.HIGH,
                            category=Category.ACCESS_CONTROL,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Add comprehensive validation for owner operations",
                            impact="Invalid owner changes could break multisig functionality"
                        )
                        findings.append(finding)
                    
                    # Check for minimum owner requirements
                    if 'remove' in func.name.lower() and not self._enforces_minimum_owners(func):
                        finding = Finding(
                            title=f"Missing Minimum Owner Check in {func.name}",
                            description=f"Function '{func.name}' doesn't enforce minimum owner count",
                            severity=Severity.HIGH,
                            category=Category.DAO_SPECIFIC,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Ensure minimum number of owners is maintained",
                            impact="Multisig could become unusable with too few owners"
                        )
                        findings.append(finding)
        
        return findings
    
    def _check_signature_validation(self, context: AnalysisContext) -> List[Finding]:
        """Check signature validation mechanisms."""
        findings = []
        
        for contract_name, functions in context.functions.items():
            for func in functions:
                if self._uses_signature_validation(func):
                    
                    # Check for proper signature recovery
                    if not self._implements_secure_signature_recovery(func):
                        finding = Finding(
                            title=f"Insecure Signature Recovery in {func.name}",
                            description=f"Function '{func.name}' has insecure signature recovery implementation",
                            severity=Severity.HIGH,
                            category=Category.CRYPTOGRAPHIC,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Implement secure signature recovery with proper validation",
                            impact="Invalid signatures could be accepted"
                        )
                        findings.append(finding)
                    
                    # Check for signature replay protection
                    if not self._has_signature_replay_protection(func):
                        finding = Finding(
                            title=f"Signature Replay Vulnerability in {func.name}",
                            description=f"Function '{func.name}' vulnerable to signature replay attacks",
                            severity=Severity.HIGH,
                            category=Category.DAO_SPECIFIC,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Implement nonce or transaction hash validation",
                            impact="Signatures could be replayed to execute duplicate transactions"
                        )
                        findings.append(finding)
        
        return findings
    
    def _check_threshold_management(self, context: AnalysisContext) -> List[Finding]:
        """Check threshold management mechanisms."""
        findings = []
        
        metrics = self._calculate_multisig_metrics(context)
        
        # Check if threshold is too low
        if metrics.required_confirmations and metrics.total_owners:
            threshold_ratio = metrics.required_confirmations / metrics.total_owners
            if threshold_ratio < 0.5:  # Less than 50%
                finding = Finding(
                    title="Low Multisig Threshold",
                    description=f"Multisig threshold ({metrics.required_confirmations}/{metrics.total_owners}) may be too low",
                    severity=Severity.MEDIUM,
                    category=Category.DAO_SPECIFIC,
                    recommendation="Consider increasing threshold to at least 50% of owners",
                    impact="Low threshold reduces security benefits of multisig"
                )
                findings.append(finding)
        
        # Check threshold change functions
        for contract_name, functions in context.functions.items():
            for func in functions:
                if self._changes_threshold(func):
                    
                    # Check for threshold validation
                    if not self._validates_threshold_changes(func):
                        finding = Finding(
                            title=f"Inadequate Threshold Validation in {func.name}",
                            description=f"Function '{func.name}' doesn't properly validate threshold changes",
                            severity=Severity.HIGH,
                            category=Category.DAO_SPECIFIC,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Validate threshold is between 1 and owner count",
                            impact="Invalid threshold could break multisig functionality"
                        )
                        findings.append(finding)
        
        return findings
    
    def _check_multisig_reentrancy(self, context: AnalysisContext) -> List[Finding]:
        """Check for reentrancy vulnerabilities in multisig functions."""
        findings = []
        
        for contract_name, functions in context.functions.items():
            for func in functions:
                if self._is_multisig_execution_function(func):
                    
                    # Check for reentrancy protection
                    if not self._has_reentrancy_protection(func):
                        finding = Finding(
                            title=f"Reentrancy Vulnerability in {func.name}",
                            description=f"Multisig execution function '{func.name}' vulnerable to reentrancy",
                            severity=Severity.HIGH,
                            category=Category.REENTRANCY,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Add reentrancy guards to execution functions",
                            impact="Execution could be manipulated through reentrancy"
                        )
                        findings.append(finding)
        
        return findings
    
    def _check_multisig_access_controls(self, context: AnalysisContext) -> List[Finding]:
        """Check multisig access control mechanisms."""
        findings = []
        
        for contract_name, functions in context.functions.items():
            multisig_functions = [f for f in functions if self._is_multisig_function(f)]
            
            for func in multisig_functions:
                # Check for owner-only access
                if not self._restricts_to_owners(func):
                    finding = Finding(
                        title=f"Missing Owner Restriction in {func.name}",
                        description=f"Multisig function '{func.name}' doesn't restrict access to owners",
                        severity=Severity.HIGH,
                        category=Category.ACCESS_CONTROL,
                        location=CodeLocation(
                            contract_name=contract_name,
                            function_name=func.name
                        ),
                        affected_contracts=[contract_name],
                        affected_functions=[func.name],
                        recommendation="Add onlyOwner or equivalent modifier",
                        impact="Non-owners could access multisig functions"
                    )
                    findings.append(finding)
        
        return findings
    
    # Helper methods for multisig pattern detection
    
    def _is_multisig_transaction_function(self, func: FunctionContext) -> bool:
        """Check if function handles multisig transactions."""
        transaction_keywords = ['submitTransaction', 'confirmTransaction', 'executeTransaction', 'revokeConfirmation']
        return any(keyword.lower() in func.name.lower() for keyword in transaction_keywords)
    
    def _is_owner_management_function(self, func: FunctionContext) -> bool:
        """Check if function manages owners."""
        owner_keywords = ['addOwner', 'removeOwner', 'replaceOwner', 'changeRequirement']
        return any(keyword.lower() in func.name.lower() for keyword in owner_keywords)
    
    def _is_multisig_execution_function(self, func: FunctionContext) -> bool:
        """Check if function executes multisig transactions."""
        return 'execute' in func.name.lower() and any(
            pattern in func.body.lower() for pattern in ['multisig', 'transaction', 'confirmation']
        )
    
    def _is_multisig_function(self, func: FunctionContext) -> bool:
        """Check if function is multisig-related."""
        multisig_indicators = [
            'multisig' in func.name.lower(),
            'owners' in func.body.lower(),
            'confirmations' in func.body.lower(),
            'threshold' in func.body.lower()
        ]
        return any(multisig_indicators)
    
    def _tracks_confirmations_properly(self, func: FunctionContext) -> bool:
        """Check if function tracks confirmations properly."""
        tracking_patterns = [
            'confirmations[', 'isConfirmed', 'confirmed[',
            'mapping.*confirmations', 'confirmationCount'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) for pattern in tracking_patterns)
    
    def _prevents_duplicate_confirmations(self, func: FunctionContext) -> bool:
        """Check if function prevents duplicate confirmations."""
        prevention_patterns = [
            'require.*!.*confirmed', 'require.*!isConfirmed',
            'alreadyConfirmed', 'duplicate'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) for pattern in prevention_patterns)
    
    def _validates_execution_requirements(self, func: FunctionContext) -> bool:
        """Check if function validates execution requirements."""
        validation_patterns = [
            'require.*confirmations', 'require.*threshold',
            'isConfirmed', 'executed', 'exists'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) for pattern in validation_patterns)
    
    def _validates_owner_operations(self, func: FunctionContext) -> bool:
        """Check if function validates owner operations."""
        validation_patterns = [
            'require.*owner', 'isOwner', 'validOwner',
            'require.*!=.*address(0)', 'ownerExists'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) for pattern in validation_patterns)
    
    def _enforces_minimum_owners(self, func: FunctionContext) -> bool:
        """Check if function enforces minimum owner count."""
        enforcement_patterns = [
            'require.*owners.length', 'minimum.*owners',
            'require.*>=.*2', 'minOwners'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) for pattern in enforcement_patterns)
    
    def _uses_signature_validation(self, func: FunctionContext) -> bool:
        """Check if function uses signature validation."""
        signature_patterns = ['signature', 'ecrecover', 'sign', 'verify']
        return any(pattern.lower() in func.body.lower() for pattern in signature_patterns)
    
    def _implements_secure_signature_recovery(self, func: FunctionContext) -> bool:
        """Check if signature recovery is implemented securely."""
        secure_patterns = [
            'ecrecover', 'require.*signer', 'validSignature',
            'signatureVerification'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) for pattern in secure_patterns)
    
    def _has_signature_replay_protection(self, func: FunctionContext) -> bool:
        """Check if function has signature replay protection."""
        protection_patterns = ['nonce', 'used', 'executed', 'hash']
        return any(pattern.lower() in func.body.lower() for pattern in protection_patterns)
    
    def _changes_threshold(self, func: FunctionContext) -> bool:
        """Check if function changes threshold."""
        threshold_keywords = ['threshold', 'requirement', 'required']
        change_keywords = ['change', 'set', 'update']
        
        has_threshold = any(keyword.lower() in func.name.lower() for keyword in threshold_keywords)
        has_change = any(keyword.lower() in func.name.lower() for keyword in change_keywords)
        
        return has_threshold and has_change
    
    def _validates_threshold_changes(self, func: FunctionContext) -> bool:
        """Check if threshold changes are validated."""
        validation_patterns = [
            'require.*threshold', 'require.*>=.*1',
            'require.*<=.*owners', 'validThreshold'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) for pattern in validation_patterns)
    
    def _has_reentrancy_protection(self, func: FunctionContext) -> bool:
        """Check if function has reentrancy protection."""
        protection_patterns = [
            'nonReentrant', 'reentrancyGuard', 'locked',
            'mutex', 'ReentrancyGuard'
        ]
        return any(pattern.lower() in func.body.lower() for pattern in protection_patterns)
    
    def _restricts_to_owners(self, func: FunctionContext) -> bool:
        """Check if function restricts access to owners."""
        restriction_patterns = [
            'onlyOwner', 'require.*isOwner', 'owner.*modifier',
            'msg.sender.*owner', 'authorized'
        ]
        
        # Check modifiers
        has_owner_modifier = any(
            'owner' in mod.lower() or 'auth' in mod.lower() 
            for mod in func.modifiers
        )
        
        # Check function body
        has_owner_check = any(re.search(pattern, func.body, re.IGNORECASE) for pattern in restriction_patterns)
        
        return has_owner_modifier or has_owner_check
