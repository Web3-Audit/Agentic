"""
Flash Loan agent for analyzing DeFi flash loan mechanisms and security.
"""

import re
import logging
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass

from .defi_base_agent import DeFiBaseAgent, DeFiProtocol, DeFiMetrics
from ...models.context import AnalysisContext, FunctionContext
from ...models.finding import Finding, Severity, Category, CodeLocation
from ...llm.client import LLMClient
from ...llm.prompts import PromptManager

logger = logging.getLogger(__name__)


@dataclass
class FlashLoanMetrics(DeFiMetrics):
    """Flash loan-specific metrics extending DeFi metrics."""
    flash_loan_functions: int = 0
    callback_functions: int = 0
    fee_calculations: int = 0
    reentrancy_guards: int = 0
    balance_checks: int = 0
    flash_mint_functions: int = 0
    arbitrage_functions: int = 0
    liquidation_flash_functions: int = 0


class FlashLoanAgent(DeFiBaseAgent):
    """
    Specialized agent for analyzing flash loan protocol contracts.
    Focuses on flash loan mechanics, callbacks, and attack prevention.
    """
    
    def __init__(self, llm_client: Optional[LLMClient] = None,
                 prompt_manager: Optional[PromptManager] = None):
        super().__init__("FlashLoanAgent", llm_client, prompt_manager)
        
        # Flash loan-specific patterns
        self.flash_loan_patterns = {
            'flash_loan_functions': [
                'flashLoan', 'flashBorrow', 'flashCredit', 'instantLoan'
            ],
            'callback_functions': [
                'executeOperation', 'onFlashLoan', 'receiveFlashLoan',
                'flashLoanCallback', 'callback'
            ],
            'fee_patterns': [
                'flashLoanFee', 'flashFee', 'instantFee', 'borrowFee',
                'FLASHLOAN_PREMIUM_TOTAL', 'FLASHLOAN_PREMIUM_TO_PROTOCOL'
            ],
            'balance_patterns': [
                'balanceBefore', 'balanceAfter', 'initialBalance', 'finalBalance'
            ],
            'security_patterns': [
                'nonReentrant', 'flashLoanLock', 'reentrancyGuard', 'mutex'
            ],
            'arbitrage_patterns': [
                'arbitrage', 'profit', 'spread', 'priceDifference'
            ]
        }
    
    def can_analyze(self, context: AnalysisContext) -> bool:
        """Check if this is a flash loan contract."""
        if not super().can_analyze(context):
            return False
        
        code_lower = context.contract_code.lower()
        
        flash_loan_indicators = [
            'flashloan', 'flash', 'instantloan', 'callback',
            'executeoperation', 'flashborrow', 'flashfee'
        ]
        
        matches = sum(1 for indicator in flash_loan_indicators if indicator in code_lower)
        return matches >= 2
    
    def analyze(self, context: AnalysisContext) -> List[Finding]:
        """
        Analyze flash loan contract for security vulnerabilities.
        
        Args:
            context: Analysis context
            
        Returns:
            List[Finding]: Flash loan-specific findings
        """
        self.logger.info("Starting flash loan analysis")
        findings = []
        
        try:
            # Calculate flash loan metrics
            metrics = self._calculate_flash_loan_metrics(context)
            
            # Core flash loan security checks
            findings.extend(self._check_flash_loan_security(context))
            findings.extend(self._check_callback_security(context))
            findings.extend(self._check_fee_calculation(context))
            findings.extend(self._check_reentrancy_protection(context))
            findings.extend(self._check_balance_validation(context))
            findings.extend(self._check_flash_mint_security(context))
            findings.extend(self._check_arbitrage_protection(context))
            findings.extend(self._check_liquidation_flash_security(context))
            findings.extend(self._check_access_control(context))
            findings.extend(self._check_flash_loan_limits(context))
            
            self.logger.info(f"Flash loan analysis completed with {len(findings)} findings")
            return findings
            
        except Exception as e:
            self.logger.error(f"Error in flash loan analysis: {str(e)}")
            return findings
    
    def _calculate_flash_loan_metrics(self, context: AnalysisContext) -> FlashLoanMetrics:
        """Calculate flash loan-specific metrics."""
        metrics = FlashLoanMetrics()
        
        for functions in context.functions.values():
            for func in functions:
                func_name_lower = func.name.lower()
                
                # Count different function types
                if any(pattern.lower() in func_name_lower 
                      for pattern in self.flash_loan_patterns['flash_loan_functions']):
                    metrics.flash_loan_functions += 1
                
                if any(pattern.lower() in func_name_lower 
                      for pattern in self.flash_loan_patterns['callback_functions']):
                    metrics.callback_functions += 1
                
                # Check for security measures
                if any(pattern in func.body.lower() 
                      for pattern in self.flash_loan_patterns['security_patterns']):
                    metrics.reentrancy_guards += 1
                
                # Check for balance validations
                if any(pattern in func.body.lower() 
                      for pattern in self.flash_loan_patterns['balance_patterns']):
                    metrics.balance_checks += 1
                
                # Check for fee calculations
                if any(pattern in func.body.lower() 
                      for pattern in self.flash_loan_patterns['fee_patterns']):
                    metrics.fee_calculations += 1
        
        return metrics
    
    def _check_flash_loan_security(self, context: AnalysisContext) -> List[Finding]:
        """Check flash loan function security."""
        findings = []
        
        for contract_name, functions in context.functions.items():
            for func in functions:
                if self._is_flash_loan_function(func):
                    
                    # Check for amount validation
                    if not self._validates_flash_loan_amount(func):
                        finding = self.create_finding(
                            title=f"Missing Flash Loan Amount Validation in {func.name}",
                            description=f"Flash loan function '{func.name}' doesn't validate loan amounts",
                            severity=Severity.MEDIUM,
                            category=Category.INPUT_VALIDATION,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Validate flash loan amounts are positive and within limits",
                            impact="Invalid amounts could cause transaction failures or exploits"
                        )
                        findings.append(finding)
                    
                    # Check for token validation
                    if not self._validates_flash_loan_token(func):
                        finding = self.create_finding(
                            title=f"Missing Token Validation in {func.name}",
                            description=f"Flash loan function '{func.name}' doesn't validate token addresses",
                            severity=Severity.MEDIUM,
                            category=Category.INPUT_VALIDATION,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Validate token addresses and supported assets",
                            impact="Invalid tokens could cause transaction failures"
                        )
                        findings.append(finding)
                    
                    # Check for liquidity validation
                    if not self._validates_available_liquidity(func):
                        finding = self.create_finding(
                            title=f"Missing Liquidity Validation in {func.name}",
                            description=f"Flash loan function '{func.name}' doesn't check available liquidity",
                            severity=Severity.HIGH,
                            category=Category.DEFI_SPECIFIC,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Validate sufficient liquidity exists before flash loan",
                            impact="Flash loans could fail or drain protocol reserves"
                        )
                        findings.append(finding)
                    
                    # Check for callback validation
                    if not self._validates_callback_target(func):
                        finding = self.create_finding(
                            title=f"Missing Callback Target Validation in {func.name}",
                            description=f"Flash loan function '{func.name}' doesn't validate callback target",
                            severity=Severity.CRITICAL,
                            category=Category.ACCESS_CONTROL,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Validate callback target implements required interface",
                            impact="Malicious contracts could receive flash loans without proper callbacks"
                        )
                        findings.append(finding)
        
        return findings
    
    def _check_callback_security(self, context: AnalysisContext) -> List[Finding]:
        """Check callback function security."""
        findings = []
        
        for contract_name, functions in context.functions.items():
            for func in functions:
                if self._is_callback_function(func):
                    
                    # Check for caller validation
                    if not self._validates_callback_caller(func):
                        finding = self.create_finding(
                            title=f"Missing Callback Caller Validation in {func.name}",
                            description=f"Callback function '{func.name}' doesn't validate caller",
                            severity=Severity.CRITICAL,
                            category=Category.ACCESS_CONTROL,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Validate callback is called by authorized flash loan provider",
                            impact="Unauthorized callers could trigger callbacks maliciously"
                        )
                        findings.append(finding)
                    
                    # Check for parameter validation
                    if not self._validates_callback_parameters(func):
                        finding = self.create_finding(
                            title=f"Missing Callback Parameter Validation in {func.name}",
                            description=f"Callback function '{func.name}' doesn't validate parameters",
                            severity=Severity.HIGH,
                            category=Category.INPUT_VALIDATION,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Validate callback parameters match expected values",
                            impact="Invalid parameters could cause incorrect callback execution"
                        )
                        findings.append(finding)
                    
                    # Check for repayment validation
                    if not self._validates_repayment_in_callback(func):
                        finding = self.create_finding(
                            title=f"Missing Repayment Validation in {func.name}",
                            description=f"Callback function '{func.name}' doesn't ensure proper repayment",
                            severity=Severity.CRITICAL,
                            category=Category.FLASH_LOAN,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Ensure flash loan is properly repaid with fees",
                            impact="Flash loan might not be repaid, causing protocol losses"
                        )
                        findings.append(finding)
        
        return findings
    
    def _check_fee_calculation(self, context: AnalysisContext) -> List[Finding]:
        """Check flash loan fee calculation security."""
        findings = []
        
        for contract_name, functions in context.functions.items():
            for func in functions:
                if self._calculates_flash_fees(func):
                    
                    # Check for fee bounds validation
                    if not self._validates_fee_bounds(func):
                        finding = self.create_finding(
                            title=f"Missing Fee Bounds Validation in {func.name}",
                            description=f"Fee calculation in '{func.name}' doesn't validate fee bounds",
                            severity=Severity.MEDIUM,
                            category=Category.DEFI_SPECIFIC,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Implement reasonable fee bounds to prevent excessive fees",
                            impact="Excessive fees could make flash loans uneconomical"
                        )
                        findings.append(finding)
                    
                    # Check for fee calculation accuracy
                    if not self._accurate_fee_calculation(func):
                        finding = self.create_finding(
                            title=f"Inaccurate Fee Calculation in {func.name}",
                            description=f"Fee calculation in '{func.name}' may be inaccurate",
                            severity=Severity.MEDIUM,
                            category=Category.ARITHMETIC,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Ensure accurate fee calculations with proper precision",
                            impact="Incorrect fees could affect protocol revenue or user costs"
                        )
                        findings.append(finding)
                    
                    # Check for overflow protection in fee calculation
                    if not self._protects_fee_overflow(func):
                        finding = self.create_finding(
                            title=f"Fee Calculation Overflow Risk in {func.name}",
                            description=f"Fee calculation in '{func.name}' may overflow",
                            severity=Severity.HIGH,
                            category=Category.ARITHMETIC,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Use safe math libraries to prevent overflow",
                            impact="Overflow could result in incorrect or zero fees"
                        )
                        findings.append(finding)
        
        return findings
    
    def _check_reentrancy_protection(self, context: AnalysisContext) -> List[Finding]:
        """Check reentrancy protection for flash loans."""
        findings = []
        
        for contract_name, functions in context.functions.items():
            for func in functions:
                if self._is_flash_loan_function(func) or self._is_callback_function(func):
                    
                    if not self._has_reentrancy_protection(func):
                        finding = self.create_finding(
                            title=f"Missing Reentrancy Protection in {func.name}",
                            description=f"Flash loan function '{func.name}' lacks reentrancy protection",
                            severity=Severity.CRITICAL,
                            category=Category.REENTRANCY,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Implement reentrancy guards for all flash loan functions",
                            impact="Reentrancy attacks could drain protocol funds"
                        )
                        findings.append(finding)
        
        return findings
    
    def _check_balance_validation(self, context: AnalysisContext) -> List[Finding]:
        """Check balance validation mechanisms."""
        findings = []
        
        for contract_name, functions in context.functions.items():
            for func in functions:
                if self._is_flash_loan_function(func):
                    
                    # Check for balance before/after checks
                    if not self._implements_balance_checks(func):
                        finding = self.create_finding(
                            title=f"Missing Balance Validation in {func.name}",
                            description=f"Flash loan function '{func.name}' doesn't implement balance checks",
                            severity=Severity.CRITICAL,
                            category=Category.FLASH_LOAN,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Implement balance before/after checks to ensure repayment",
                            impact="Flash loans might not be properly repaid"
                        )
                        findings.append(finding)
                    
                    # Check for fee inclusion in balance checks
                    if not self._validates_fee_repayment(func):
                        finding = self.create_finding(
                            title=f"Missing Fee Repayment Validation in {func.name}",
                            description=f"Flash loan function '{func.name}' doesn't validate fee repayment",
                            severity=Severity.HIGH,
                            category=Category.FLASH_LOAN,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Ensure fees are included in repayment validation",
                            impact="Fees might not be collected properly"
                        )
                        findings.append(finding)
        
        return findings
    
    def _check_flash_mint_security(self, context: AnalysisContext) -> List[Finding]:
        """Check flash mint security if implemented."""
        findings = []
        
        for contract_name, functions in context.functions.items():
            for func in functions:
                if self._is_flash_mint_function(func):
                    
                    # Check for flash mint limits
                    if not self._validates_flash_mint_limits(func):
                        finding = self.create_finding(
                            title=f"Missing Flash Mint Limits in {func.name}",
                            description=f"Flash mint function '{func.name}' doesn't enforce mint limits",
                            severity=Severity.HIGH,
                            category=Category.TOKEN_HANDLING,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Implement flash mint limits to prevent excessive inflation",
                            impact="Unlimited flash minting could destabilize token economics"
                        )
                        findings.append(finding)
                    
                    # Check for burn validation
                    if not self._validates_flash_burn(func):
                        finding = self.create_finding(
                            title=f"Missing Flash Burn Validation in {func.name}",
                            description=f"Flash mint function '{func.name}' doesn't validate token burning",
                            severity=Severity.CRITICAL,
                            category=Category.TOKEN_HANDLING,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Ensure flash minted tokens are properly burned",
                            impact="Tokens might not be burned, causing permanent inflation"
                        )
                        findings.append(finding)
        
        return findings
    
    def _check_arbitrage_protection(self, context: AnalysisContext) -> List[Finding]:
        """Check protection against arbitrage exploitation."""
        findings = []
        
        for contract_name, functions in context.functions.items():
            for func in functions:
                if self._enables_arbitrage(func):
                    
                    # Check for MEV protection
                    if not self._has_mev_protection(func):
                        finding = self.create_finding(
                            title=f"Missing MEV Protection in {func.name}",
                            description=f"Arbitrage function '{func.name}' vulnerable to MEV extraction",
                            severity=Severity.MEDIUM,
                            category=Category.MEV_PROTECTION,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Implement MEV protection mechanisms",
                            impact="MEV bots could extract value from arbitrage opportunities"
                        )
                        findings.append(finding)
        
        return findings
    
    def _check_liquidation_flash_security(self, context: AnalysisContext) -> List[Finding]:
        """Check flash loan liquidation security."""
        findings = []
        
        for contract_name, functions in context.functions.items():
            for func in functions:
                if self._uses_flash_for_liquidation(func):
                    
                    # Check for liquidation conditions
                    if not self._validates_liquidation_conditions(func):
                        finding = self.create_finding(
                            title=f"Missing Liquidation Condition Validation in {func.name}",
                            description=f"Flash liquidation function '{func.name}' doesn't validate liquidation conditions",
                            severity=Severity.HIGH,
                            category=Category.DEFI_SPECIFIC,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Validate liquidation conditions before flash loan execution",
                            impact="Healthy positions could be liquidated incorrectly"
                        )
                        findings.append(finding)
        
        return findings
    
    def _check_access_control(self, context: AnalysisContext) -> List[Finding]:
        """Check access control for flash loan functions."""
        findings = []
        
        for contract_name, functions in context.functions.items():
            for func in functions:
                if self._is_privileged_flash_function(func):
                    
                    # Check for proper access controls
                    if not self._has_proper_access_control(func):
                        finding = self.create_finding(
                            title=f"Missing Access Control in {func.name}",
                            description=f"Privileged flash loan function '{func.name}' lacks access control",
                            severity=Severity.HIGH,
                            category=Category.ACCESS_CONTROL,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Implement proper access controls for privileged functions",
                            impact="Unauthorized users could access privileged flash loan functionality"
                        )
                        findings.append(finding)
        
        return findings
    
    def _check_flash_loan_limits(self, context: AnalysisContext) -> List[Finding]:
        """Check flash loan limit mechanisms."""
        findings = []
        
        for contract_name, functions in context.functions.items():
            for func in functions:
                if self._is_flash_loan_function(func):
                    
                    # Check for maximum flash loan limits
                    if not self._validates_max_flash_loan(func):
                        finding = self.create_finding(
                            title=f"Missing Flash Loan Limits in {func.name}",
                            description=f"Flash loan function '{func.name}' doesn't enforce maximum limits",
                            severity=Severity.MEDIUM,
                            category=Category.DEFI_SPECIFIC,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Implement maximum flash loan limits to prevent liquidity drain",
                            impact="Excessive flash loans could drain protocol liquidity"
                        )
                        findings.append(finding)
        
        return findings
    
    # Helper methods for flash loan pattern detection
    
    def _is_flash_loan_function(self, func: FunctionContext) -> bool:
        """Check if function is a flash loan function."""
        return any(pattern.lower() in func.name.lower() 
                  for pattern in self.flash_loan_patterns['flash_loan_functions'])
    
    def _is_callback_function(self, func: FunctionContext) -> bool:
        """Check if function is a callback function."""
        return any(pattern.lower() in func.name.lower() 
                  for pattern in self.flash_loan_patterns['callback_functions'])
    
    def _is_flash_mint_function(self, func: FunctionContext) -> bool:
        """Check if function is a flash mint function."""
        return 'flashmint' in func.name.lower() or 'mintflash' in func.name.lower()
    
    def _calculates_flash_fees(self, func: FunctionContext) -> bool:
        """Check if function calculates flash fees."""
        return any(pattern in func.body.lower() 
                  for pattern in self.flash_loan_patterns['fee_patterns'])
    
    def _enables_arbitrage(self, func: FunctionContext) -> bool:
        """Check if function enables arbitrage."""
        return any(pattern in func.body.lower() 
                  for pattern in self.flash_loan_patterns['arbitrage_patterns'])
    
    def _uses_flash_for_liquidation(self, func: FunctionContext) -> bool:
        """Check if function uses flash loans for liquidation."""
        return ('liquidat' in func.name.lower() and 
                any(pattern.lower() in func.body.lower() 
                   for pattern in self.flash_loan_patterns['flash_loan_functions']))
    
    def _is_privileged_flash_function(self, func: FunctionContext) -> bool:
        """Check if function is a privileged flash loan function."""
        privileged_keywords = ['admin', 'owner', 'emergency', 'pause']
        return (self._is_flash_loan_function(func) and 
                any(keyword in func.name.lower() for keyword in privileged_keywords))
    
    # Validation helper methods
    
    def _validates_flash_loan_amount(self, func: FunctionContext) -> bool:
        """Check if flash loan amount is validated."""
        validation_patterns = [
            r'require\s*\(\s*.*amount\s*>\s*0',
            r'require\s*\(\s*.*amount\s*<=.*maxFlashLoan',
            r'amount\s*>\s*0',
            r'validateAmount'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) 
                  for pattern in validation_patterns)
    
    def _validates_flash_loan_token(self, func: FunctionContext) -> bool:
        """Check if flash loan token is validated."""
        validation_patterns = [
            r'require\s*\(\s*.*token\s*!=\s*address\(0\)',
            r'supportedTokens\s*\[.*\]',
            r'isSupported.*token',
            r'validToken'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) 
                  for pattern in validation_patterns)
    
    def _validates_available_liquidity(self, func: FunctionContext) -> bool:
        """Check if available liquidity is validated."""
        validation_patterns = [
            r'require\s*\(\s*.*balance\s*>=\s*.*amount',
            r'require\s*\(\s*.*liquidity\s*>=\s*.*amount',
            r'availableLiquidity',
            r'maxFlashLoan'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) 
                  for pattern in validation_patterns)
    
    def _validates_callback_target(self, func: FunctionContext) -> bool:
        """Check if callback target is validated."""
        validation_patterns = [
            r'require\s*\(\s*.*receiver\s*!=\s*address\(0\)',
            r'IERC3156FlashBorrower',
            r'onFlashLoan',
            r'supportsInterface'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) 
                  for pattern in validation_patterns)
    
    def _validates_callback_caller(self, func: FunctionContext) -> bool:
        """Check if callback caller is validated."""
        validation_patterns = [
            r'require\s*\(\s*msg\.sender\s*==.*lender',
            r'require\s*\(\s*.*authorized',
            r'onlyLender',
            r'trustedCaller'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) 
                  for pattern in validation_patterns)
    
    def _validates_callback_parameters(self, func: FunctionContext) -> bool:
        """Check if callback parameters are validated."""
        validation_patterns = [
            r'require\s*\(\s*.*amount\s*==\s*.*expectedAmount',
            r'require\s*\(\s*.*token\s*==\s*.*expectedToken',
            r'validateParams',
            r'checkCallback'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) 
                  for pattern in validation_patterns)
    
    def _validates_repayment_in_callback(self, func: FunctionContext) -> bool:
        """Check if repayment is validated in callback."""
        validation_patterns = [
            r'transfer.*amount.*fee',
            r'repay.*amount',
            r'return.*amount.*fee',
            r'payback'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) 
                  for pattern in validation_patterns)
    
    def _validates_fee_bounds(self, func: FunctionContext) -> bool:
        """Check if fee bounds are validated."""
        bounds_patterns = [
            r'require\s*\(\s*.*fee\s*<=\s*.*MAX_FEE',
            r'require\s*\(\s*.*fee\s*<\s*.*amount',
            r'maxFee',
            r'feeLimit'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) 
                  for pattern in bounds_patterns)
    
    def _accurate_fee_calculation(self, func: FunctionContext) -> bool:
        """Check if fee calculation is accurate."""
        accuracy_patterns = [
            r'fee\s*=\s*.*amount\s*\*\s*.*rate\s*/\s*10000',
            r'mulDiv',
            r'precision',
            r'BASIS_POINTS'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) 
                  for pattern in accuracy_patterns)
    
    def _protects_fee_overflow(self, func: FunctionContext) -> bool:
        """Check if fee calculation protects against overflow."""
        protection_patterns = [
            'SafeMath',
            'safeAdd',
            'safeMul',
            'safeDiv'
        ]
        return any(pattern.lower() in func.body.lower() for pattern in protection_patterns)
    
    def _has_reentrancy_protection(self, func: FunctionContext) -> bool:
        """Check if function has reentrancy protection."""
        return any(pattern in func.modifiers or pattern.lower() in func.body.lower() 
                  for pattern in self.flash_loan_patterns['security_patterns'])
    
    def _implements_balance_checks(self, func: FunctionContext) -> bool:
        """Check if function implements balance checks."""
        return any(pattern in func.body.lower() 
                  for pattern in self.flash_loan_patterns['balance_patterns'])
    
    def _validates_fee_repayment(self, func: FunctionContext) -> bool:
        """Check if fee repayment is validated."""
        validation_patterns = [
            r'require\s*\(\s*.*balance.*>=.*initialBalance.*\+.*fee',
            r'balanceAfter.*>=.*balanceBefore.*\+.*fee',
            r'repaidWithFee',
            r'totalRepayment'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) 
                  for pattern in validation_patterns)
    
    def _validates_flash_mint_limits(self, func: FunctionContext) -> bool:
        """Check if flash mint limits are validated."""
        limit_patterns = [
            r'require\s*\(\s*.*amount\s*<=\s*.*maxFlashMint',
            r'require\s*\(\s*.*totalSupply.*\+.*amount\s*<=\s*.*cap',
            r'mintLimit',
            r'flashMintCap'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) 
                  for pattern in limit_patterns)
    
    def _validates_flash_burn(self, func: FunctionContext) -> bool:
        """Check if flash burn is validated."""
        burn_patterns = [
            r'burn\s*\(\s*.*amount',
            r'_burn\s*\(\s*.*amount',
            r'require\s*\(\s*.*burned',
            r'destroyTokens'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) 
                  for pattern in burn_patterns)
    
    def _has_mev_protection(self, func: FunctionContext) -> bool:
        """Check if function has MEV protection."""
        mev_patterns = [
            'deadline',
            'minAmountOut',
            'slippageProtection',
            'private'
        ]
        return any(pattern.lower() in func.body.lower() for pattern in mev_patterns)
    
    def _validates_liquidation_conditions(self, func: FunctionContext) -> bool:
        """Check if liquidation conditions are validated."""
        condition_patterns = [
            r'require\s*\(\s*.*isLiquidatable',
            r'require\s*\(\s*.*healthFactor\s*<',
            r'canLiquidate',
            r'liquidationThreshold'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) 
                  for pattern in condition_patterns)
    
    def _has_proper_access_control(self, func: FunctionContext) -> bool:
        """Check if function has proper access control."""
        access_patterns = [
            'onlyOwner',
            'onlyAdmin',
            'onlyAuthorized',
            'hasRole'
        ]
        return any(pattern in func.modifiers or pattern.lower() in func.body.lower() 
                  for pattern in access_patterns)
    
    def _validates_max_flash_loan(self, func: FunctionContext) -> bool:
        """Check if maximum flash loan is validated."""
        max_patterns = [
            r'require\s*\(\s*.*amount\s*<=\s*.*maxFlashLoan',
            r'maxFlashAmount',
            r'flashLoanLimit',
            r'liquidityLimit'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) 
                  for pattern in max_patterns)
