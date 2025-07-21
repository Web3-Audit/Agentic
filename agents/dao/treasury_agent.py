"""
Treasury agent for analyzing DAO treasury management and security.
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
class TreasuryMetrics:
    """Treasury-specific metrics."""
    treasury_functions: int = 0
    withdrawal_functions: int = 0
    transfer_functions: int = 0
    approval_functions: int = 0
    emergency_functions: int = 0
    multisig_functions: int = 0

class TreasuryAgent(DAOBaseAgent):
    """
    Specialized agent for analyzing DAO treasury management.
    """
    
    def __init__(self, llm_client: Optional[LLMClient] = None, 
                 prompt_manager: Optional[PromptManager] = None):
        super().__init__("TreasuryAgent", llm_client, prompt_manager)
        
        # Treasury-specific patterns
        self.treasury_patterns = {
            'fund_operations': [
                'withdraw', 'transfer', 'send', 'pay', 'disburse',
                'allocate', 'approve', 'spend', 'distribute'
            ],
            'access_controls': [
                'onlyGovernance', 'onlyTreasurer', 'onlyMultisig',
                'authorized', 'hasRole', 'requireRole'
            ],
            'safety_mechanisms': [
                'timelock', 'delay', 'pause', 'emergency', 'circuit',
                'limit', 'cap', 'threshold', 'cooldown'
            ],
            'asset_management': [
                'balance', 'asset', 'token', 'reserve', 'fund',
                'portfolio', 'investment', 'yield'
            ]
        }

    def analyze(self, context: AnalysisContext) -> List[Finding]:
        """
        Analyze treasury management in DAO contracts.
        
        Args:
            context: Analysis context containing contract information
            
        Returns:
            List[Finding]: Treasury-related findings
        """
        self.logger.info("Starting treasury analysis")
        findings = []
        
        try:
            # Calculate treasury metrics
            metrics = self._calculate_treasury_metrics(context)
            
            # Check fund withdrawal security
            findings.extend(self._check_fund_withdrawal_security(context))
            
            # Check access controls
            findings.extend(self._check_treasury_access_controls(context))
            
            # Check spending limits
            findings.extend(self._check_spending_limits(context))
            
            # Check emergency controls
            findings.extend(self._check_treasury_emergency_controls(context))
            
            # Check asset management
            findings.extend(self._check_asset_management(context))
            
            # Check multisig integration
            findings.extend(self._check_multisig_integration(context))
            
            self.logger.info(f"Treasury analysis completed with {len(findings)} findings")
            return findings
            
        except Exception as e:
            self.logger.error(f"Error in treasury analysis: {str(e)}")
            return findings

    def _calculate_treasury_metrics(self, context: AnalysisContext) -> TreasuryMetrics:
        """Calculate treasury-specific metrics."""
        metrics = TreasuryMetrics()
        
        for functions in context.functions.values():
            for func in functions:
                func_name_lower = func.name.lower()
                
                if any(pattern in func_name_lower for pattern in self.treasury_patterns['fund_operations']):
                    metrics.treasury_functions += 1
                    
                    if 'withdraw' in func_name_lower:
                        metrics.withdrawal_functions += 1
                    elif 'transfer' in func_name_lower:
                        metrics.transfer_functions += 1
                    elif 'approve' in func_name_lower:
                        metrics.approval_functions += 1
                
                if any(pattern in func_name_lower for pattern in ['emergency', 'pause', 'stop']):
                    metrics.emergency_functions += 1
                
                if any(pattern in func_name_lower for pattern in ['multisig', 'multi']):
                    metrics.multisig_functions += 1
        
        return metrics

    def _check_fund_withdrawal_security(self, context: AnalysisContext) -> List[Finding]:
        """Check fund withdrawal mechanism security."""
        findings = []
        
        for contract_name, functions in context.functions.items():
            for func in functions:
                if self._is_fund_withdrawal_function(func):
                    # Check for withdrawal limits
                    if not self._has_withdrawal_limits(func):
                        finding = Finding(
                            title=f"No Withdrawal Limits in {func.name}",
                            description=f"Treasury function '{func.name}' allows unlimited withdrawals",
                            severity=Severity.HIGH,
                            category=Category.DAO_SPECIFIC,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Implement daily/monthly withdrawal limits",
                            impact="Entire treasury could be drained in single transaction"
                        )
                        findings.append(finding)
                    
                    # Check for recipient validation
                    if not self._validates_recipient(func):
                        finding = Finding(
                            title=f"Missing Recipient Validation in {func.name}",
                            description=f"Function '{func.name}' doesn't validate withdrawal recipient",
                            severity=Severity.MEDIUM,
                            category=Category.DAO_SPECIFIC,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Add recipient address validation (blacklist, whitelist)",
                            impact="Funds could be sent to invalid or malicious addresses"
                        )
                        findings.append(finding)
                    
                    # Check for zero amount protection
                    if not self._prevents_zero_amount_transfer(func):
                        finding = Finding(
                            title=f"Zero Amount Transfer Allowed in {func.name}",
                            description=f"Function '{func.name}' allows zero amount transfers",
                            severity=Severity.LOW,
                            category=Category.DAO_SPECIFIC,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Add require(amount > 0) check",
                            impact="Unnecessary gas consumption and potential confusion"
                        )
                        findings.append(finding)
        
        return findings

    def _check_treasury_access_controls(self, context: AnalysisContext) -> List[Finding]:
        """Check treasury access control mechanisms."""
        findings = []
        
        for contract_name, functions in context.functions.items():
            treasury_functions = [f for f in functions if self._is_treasury_function(f)]
            
            for func in treasury_functions:
                # Check for proper access controls
                if not self._has_proper_access_control(func):
                    severity = Severity.CRITICAL if func.is_payable else Severity.HIGH
                    
                    finding = Finding(
                        title=f"Missing Access Control in Treasury Function {func.name}",
                        description=f"Treasury function '{func.name}' lacks proper access control",
                        severity=severity,
                        category=Category.ACCESS_CONTROL,
                        location=CodeLocation(
                            contract_name=contract_name,
                            function_name=func.name
                        ),
                        affected_contracts=[contract_name],
                        affected_functions=[func.name],
                        recommendation="Add onlyGovernance or equivalent access control modifier",
                        impact="Unauthorized users could access treasury functions"
                    )
                    findings.append(finding)
                
                # Check for role-based access
                if not self._uses_role_based_access(func):
                    finding = Finding(
                        title=f"Missing Role-Based Access in {func.name}",
                        description=f"Treasury function '{func.name}' doesn't use role-based access control",
                        severity=Severity.MEDIUM,
                        category=Category.ACCESS_CONTROL,
                        location=CodeLocation(
                            contract_name=contract_name,
                            function_name=func.name
                        ),
                        affected_contracts=[contract_name],
                        affected_functions=[func.name],
                        recommendation="Implement role-based access control for different treasury operations",
                        impact="Lack of granular permissions could lead to privilege abuse"
                    )
                    findings.append(finding)
        
        return findings

    def _check_spending_limits(self, context: AnalysisContext) -> List[Finding]:
        """Check treasury spending limit mechanisms."""
        findings = []
        
        has_spending_limits = False
        
        for contract_name, functions in context.functions.items():
            for func in functions:
                if self._implements_spending_limits(func):
                    has_spending_limits = True
                    
                    # Check if limits are configurable
                    if not self._has_configurable_limits(func):
                        finding = Finding(
                            title=f"Fixed Spending Limits in {func.name}",
                            description=f"Function '{func.name}' has hardcoded spending limits",
                            severity=Severity.LOW,
                            category=Category.DAO_SPECIFIC,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Make spending limits configurable through governance",
                            impact="Inability to adjust limits as treasury grows"
                        )
                        findings.append(finding)
        
        # Check if treasury lacks spending limits entirely
        if not has_spending_limits:
            treasury_exists = any(
                self._is_treasury_function(func)
                for functions in context.functions.values()
                for func in functions
            )
            
            if treasury_exists:
                finding = Finding(
                    title="Missing Treasury Spending Limits",
                    description="Treasury functions lack spending limits or rate limiting",
                    severity=Severity.HIGH,
                    category=Category.DAO_SPECIFIC,
                    recommendation="Implement daily/monthly spending limits with governance override",
                    impact="Treasury could be rapidly depleted"
                )
                findings.append(finding)
        
        return findings

    def _check_treasury_emergency_controls(self, context: AnalysisContext) -> List[Finding]:
        """Check treasury emergency control mechanisms."""
        findings = []
        
        has_emergency_controls = False
        emergency_functions = []
        
        for contract_name, functions in context.functions.items():
            for func in functions:
                if self._is_emergency_treasury_function(func):
                    has_emergency_controls = True
                    emergency_functions.append(func.name)
                    
                    # Check for proper emergency validation
                    if not self._has_emergency_validation(func):
                        finding = Finding(
                            title=f"Weak Emergency Controls in {func.name}",
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
        
        # Check if treasury lacks emergency controls
        if not has_emergency_controls:
            finding = Finding(
                title="Missing Treasury Emergency Controls",
                description="Treasury lacks emergency pause or freeze mechanisms",
                severity=Severity.MEDIUM,
                category=Category.DAO_SPECIFIC,
                recommendation="Implement emergency controls with governance oversight",
                impact="Cannot stop treasury operations in crisis situations"
            )
            findings.append(finding)
        
        return findings

    def _check_asset_management(self, context: AnalysisContext) -> List[Finding]:
        """Check treasury asset management mechanisms."""
        findings = []
        
        for contract_name, functions in context.functions.items():
            for func in functions:
                if self._manages_assets(func):
                    # Check for asset validation
                    if not self._validates_assets(func):
                        finding = Finding(
                            title=f"Missing Asset Validation in {func.name}",
                            description=f"Asset management function '{func.name}' doesn't validate asset addresses",
                            severity=Severity.MEDIUM,
                            category=Category.DAO_SPECIFIC,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Add asset whitelist and validation checks",
                            impact="Invalid or malicious assets could be managed"
                        )
                        findings.append(finding)
                    
                    # Check for balance verification
                    if not self._verifies_balance_before_transfer(func):
                        finding = Finding(
                            title=f"Missing Balance Verification in {func.name}",
                            description=f"Function '{func.name}' doesn't verify sufficient balance before transfer",
                            severity=Severity.MEDIUM,
                            category=Category.DAO_SPECIFIC,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Add balance checks before asset transfers",
                            impact="Failed transfers could cause transaction reversion"
                        )
                        findings.append(finding)
        
        return findings

    def _check_multisig_integration(self, context: AnalysisContext) -> List[Finding]:
        """Check multisig integration for treasury operations."""
        findings = []
        
        has_multisig = False
        
        for contract_name, functions in context.functions.items():
            for func in functions:
                if self._uses_multisig(func):
                    has_multisig = True
                    
                    # Check for proper signature validation
                    if not self._validates_multisig_properly(func):
                        finding = Finding(
                            title=f"Weak Multisig Validation in {func.name}",
                            description=f"Function '{func.name}' has inadequate multisig signature validation",
                            severity=Severity.HIGH,
                            category=Category.DAO_SPECIFIC,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Implement robust multisig signature validation",
                            impact="Invalid signatures could be accepted"
                        )
                        findings.append(finding)
        
        # Check if high-value treasury operations lack multisig
        high_value_functions = [
            func for functions in context.functions.values()
            for func in functions
            if self._is_high_value_treasury_function(func)
        ]
        
        if high_value_functions and not has_multisig:
            function_names = [f.name for f in high_value_functions[:3]]  # First 3 examples
            
            finding = Finding(
                title="High-Value Operations Lack Multisig",
                description=f"High-value treasury functions lack multisig protection: {', '.join(function_names)}",
                severity=Severity.HIGH,
                category=Category.DAO_SPECIFIC,
                recommendation="Implement multisig requirements for large treasury operations",
                impact="Single party could control large treasury operations"
            )
            findings.append(finding)
        
        return findings

    # Helper methods for treasury pattern detection

    def _is_fund_withdrawal_function(self, func: FunctionContext) -> bool:
        """Check if function withdraws funds."""
        withdrawal_keywords = ['withdraw', 'transfer', 'send', 'pay', 'disburse']
        return any(keyword.lower() in func.name.lower() for keyword in withdrawal_keywords)

    def _is_treasury_function(self, func: FunctionContext) -> bool:
        """Check if function is treasury-related."""
        treasury_keywords = ['treasury', 'fund', 'withdraw', 'transfer', 'approve', 'spend']
        return any(keyword.lower() in func.name.lower() for keyword in treasury_keywords)

    def _is_emergency_treasury_function(self, func: FunctionContext) -> bool:
        """Check if function is emergency treasury function."""
        emergency_keywords = ['emergency', 'pause', 'freeze', 'stop', 'halt']
        treasury_keywords = ['treasury', 'fund', 'withdraw', 'transfer']
        
        has_emergency = any(keyword.lower() in func.name.lower() for keyword in emergency_keywords)
        has_treasury = any(keyword.lower() in func.name.lower() for keyword in treasury_keywords)
        
        return has_emergency or (has_treasury and 'emergency' in func.body.lower())

    def _has_withdrawal_limits(self, func: FunctionContext) -> bool:
        """Check if function has withdrawal limits."""
        limit_patterns = [
            'limit', 'cap', 'maximum', 'threshold', 'daily',
            'monthly', 'rate.*limit', 'withdraw.*limit'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) for pattern in limit_patterns)

    def _validates_recipient(self, func: FunctionContext) -> bool:
        """Check if function validates withdrawal recipient."""
        validation_patterns = [
            'require.*recipient', 'require.*to', 'whitelist',
            'authorized.*recipient', 'valid.*address'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) for pattern in validation_patterns)

    def _prevents_zero_amount_transfer(self, func: FunctionContext) -> bool:
        """Check if function prevents zero amount transfers."""
        prevention_patterns = [
            'require.*amount.*>', 'require.*>.*0', 'amount.*!=.*0',
            'nonzero', 'positive.*amount'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) for pattern in prevention_patterns)

    def _has_proper_access_control(self, func: FunctionContext) -> bool:
        """Check if function has proper access control."""
        access_patterns = [
            'onlyGovernance', 'onlyOwner', 'onlyTreasurer', 'hasRole',
            'authorized', 'modifier', 'require.*msg.sender'
        ]
        
        # Check modifiers
        has_modifier = any(
            any(pattern.lower() in mod.lower() for pattern in ['only', 'auth', 'role'])
            for mod in func.modifiers
        )
        
        # Check function body
        has_body_check = any(re.search(pattern, func.body, re.IGNORECASE) for pattern in access_patterns)
        
        return has_modifier or has_body_check

    def _uses_role_based_access(self, func: FunctionContext) -> bool:
        """Check if function uses role-based access control."""
        role_patterns = [
            'hasRole', 'checkRole', 'requireRole', 'onlyRole',
            'ROLE', 'role.*require'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) for pattern in role_patterns)

    def _implements_spending_limits(self, func: FunctionContext) -> bool:
        """Check if function implements spending limits."""
        limit_patterns = [
            'spendingLimit', 'dailyLimit', 'monthlyLimit',
            'rateLimited', 'withdrawal.*limit'
        ]
        return any(pattern.lower() in func.body.lower() for pattern in limit_patterns)

    def _has_configurable_limits(self, func: FunctionContext) -> bool:
        """Check if spending limits are configurable."""
        config_patterns = [
            'setLimit', 'updateLimit', 'configurable',
            'governance.*limit', 'admin.*limit'
        ]
        return any(pattern.lower() in func.body.lower() for pattern in config_patterns)

    def _manages_assets(self, func: FunctionContext) -> bool:
        """Check if function manages assets."""
        asset_patterns = [
            'asset', 'token', 'ERC20', 'balance', 'reserve'
        ]
        return any(pattern.lower() in func.body.lower() for pattern in asset_patterns)

    def _validates_assets(self, func: FunctionContext) -> bool:
        """Check if function validates assets."""
        validation_patterns = [
            'whitelist', 'approved.*asset', 'valid.*token',
            'require.*asset', 'supported.*token'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) for pattern in validation_patterns)

    def _verifies_balance_before_transfer(self, func: FunctionContext) -> bool:
        """Check if function verifies balance before transfer."""
        verification_patterns = [
            'balanceOf', 'require.*balance', 'sufficient.*balance',
            'balance.*>=', 'balance.*>'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) for pattern in verification_patterns)

    def _uses_multisig(self, func: FunctionContext) -> bool:
        """Check if function uses multisig."""
        multisig_patterns = [
            'multisig', 'multiSig', 'signature', 'threshold',
            'owners', 'confirmations'
        ]
        return any(pattern.lower() in func.body.lower() for pattern in multisig_patterns)

    def _validates_multisig_properly(self, func: FunctionContext) -> bool:
        """Check if multisig validation is proper."""
        validation_patterns = [
            'ecrecover', 'signature.*valid', 'threshold.*met',
            'confirmations.*>=', 'owners.*approve'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) for pattern in validation_patterns)

    def _is_high_value_treasury_function(self, func: FunctionContext) -> bool:
        """Check if function handles high-value treasury operations."""
        high_value_indicators = [
            func.is_payable,
            'withdraw' in func.name.lower(),
            'transfer' in func.name.lower() and 'large' in func.body.lower(),
            any(keyword in func.body.lower() for keyword in ['1000', '10000', 'million', 'bulk'])
        ]
        return any(high_value_indicators)

    def _has_emergency_validation(self, func: FunctionContext) -> bool:
        """Check if emergency function has proper validation."""
        validation_patterns = [
            'emergency.*role', 'crisis.*mode', 'guardian',
            'multisig.*emergency', 'require.*emergency'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) for pattern in validation_patterns)
