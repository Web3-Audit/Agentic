"""
AMM (Automated Market Maker) agent for analyzing DEX and liquidity pool contracts.
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
class AMMMetrics(DeFiMetrics):
    """AMM-specific metrics extending DeFi metrics."""
    swap_functions: int = 0
    liquidity_functions: int = 0
    price_impact_checks: int = 0
    k_constant_validations: int = 0
    fee_calculations: int = 0
    reserve_updates: int = 0


class AMMAgent(DeFiBaseAgent):
    """
    Specialized agent for analyzing Automated Market Maker (AMM) contracts.
    Focuses on swap mechanics, liquidity management, and price calculations.
    """
    
    def __init__(self, llm_client: Optional[LLMClient] = None,
                 prompt_manager: Optional[PromptManager] = None):
        super().__init__("AMMAgent", llm_client, prompt_manager)
        
        # AMM-specific patterns
        self.amm_patterns = {
            'swap_functions': [
                'swap', 'swapExactTokensForTokens', 'swapTokensForExactTokens',
                'swapExactETHForTokens', 'swapETHForExactTokens',
                'swapExactTokensForETH', 'swapTokensForExactETH'
            ],
            'liquidity_functions': [
                'addLiquidity', 'removeLiquidity', 'mint', 'burn',
                'addLiquidityETH', 'removeLiquidityETH'
            ],
            'price_functions': [
                'getAmountsOut', 'getAmountsIn', 'getAmountOut', 'getAmountIn',
                'quote', 'getReserves', 'price0CumulativeLast', 'price1CumulativeLast'
            ],
            'fee_patterns': [
                'fee', 'feeAmount', 'protocolFee', 'lpFee', 'swapFee'
            ],
            'reserve_patterns': [
                'reserve0', 'reserve1', 'getReserves', 'sync', 'update'
            ]
        }
    
    def can_analyze(self, context: AnalysisContext) -> bool:
        """Check if this is an AMM contract."""
        if not super().can_analyze(context):
            return False
        
        # Check for AMM-specific patterns
        code_lower = context.contract_code.lower()
        
        amm_indicators = [
            'swap', 'liquidity', 'pool', 'pair', 'reserve',
            'getamountsout', 'getamountsin', 'addliquidity'
        ]
        
        matches = sum(1 for indicator in amm_indicators if indicator in code_lower)
        return matches >= 3
    
    def analyze(self, context: AnalysisContext) -> List[Finding]:
        """
        Analyze AMM contract for security vulnerabilities.
        
        Args:
            context: Analysis context
            
        Returns:
            List[Finding]: AMM-specific findings
        """
        self.logger.info("Starting AMM analysis")
        findings = []
        
        try:
            # Calculate AMM metrics
            metrics = self._calculate_amm_metrics(context)
            
            # Core AMM security checks
            findings.extend(self._check_swap_security(context))
            findings.extend(self._check_liquidity_security(context))
            findings.extend(self._check_price_calculation(context))
            findings.extend(self._check_k_constant_invariant(context))
            findings.extend(self._check_fee_calculation(context))
            findings.extend(self._check_reserve_management(context))
            findings.extend(self._check_slippage_protection(context))
            findings.extend(self._check_front_running_protection(context))
            findings.extend(self._check_sandwich_attack_protection(context))
            findings.extend(self._check_flash_swap_security(context))
            
            self.logger.info(f"AMM analysis completed with {len(findings)} findings")
            return findings
            
        except Exception as e:
            self.logger.error(f"Error in AMM analysis: {str(e)}")
            return findings
    
    def _calculate_amm_metrics(self, context: AnalysisContext) -> AMMMetrics:
        """Calculate AMM-specific metrics."""
        metrics = AMMMetrics()
        
        for functions in context.functions.values():
            for func in functions:
                func_name_lower = func.name.lower()
                
                # Count swap functions
                if any(pattern.lower() in func_name_lower 
                      for pattern in self.amm_patterns['swap_functions']):
                    metrics.swap_functions += 1
                
                # Count liquidity functions
                if any(pattern.lower() in func_name_lower 
                      for pattern in self.amm_patterns['liquidity_functions']):
                    metrics.liquidity_functions += 1
                
                # Check for price impact validations
                if 'require' in func.body and any(word in func.body.lower() 
                    for word in ['amount', 'min', 'max', 'slippage']):
                    metrics.price_impact_checks += 1
                
                # Check for K constant validations
                if 'k' in func.body and 'require' in func.body:
                    metrics.k_constant_validations += 1
                
                # Count fee calculations
                if any(pattern in func.body.lower() 
                      for pattern in self.amm_patterns['fee_patterns']):
                    metrics.fee_calculations += 1
                
                # Count reserve updates
                if any(pattern in func.body.lower() 
                      for pattern in self.amm_patterns['reserve_patterns']):
                    metrics.reserve_updates += 1
        
        return metrics
    
    def _check_swap_security(self, context: AnalysisContext) -> List[Finding]:
        """Check swap function security."""
        findings = []
        
        for contract_name, functions in context.functions.items():
            for func in functions:
                if self._is_swap_function(func):
                    
                    # Check for minimum amount validation
                    if not self._validates_minimum_amounts(func):
                        finding = self.create_finding(
                            title=f"Missing Minimum Amount Validation in {func.name}",
                            description=f"Swap function '{func.name}' doesn't validate minimum output amounts",
                            severity=Severity.HIGH,
                            category=Category.DEFI_SPECIFIC,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Add minimum amount validation to prevent excessive slippage",
                            impact="Users could lose significant value due to slippage or sandwich attacks"
                        )
                        findings.append(finding)
                    
                    # Check for deadline validation
                    if not self._validates_deadline(func):
                        finding = self.create_finding(
                            title=f"Missing Deadline Validation in {func.name}",
                            description=f"Swap function '{func.name}' doesn't validate transaction deadline",
                            severity=Severity.MEDIUM,
                            category=Category.DEFI_SPECIFIC,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Add deadline parameter and validation",
                            impact="Transactions could be executed at unfavorable times"
                        )
                        findings.append(finding)
                    
                    # Check for path validation
                    if self._has_token_path(func) and not self._validates_token_path(func):
                        finding = self.create_finding(
                            title=f"Insufficient Path Validation in {func.name}",
                            description=f"Swap function '{func.name}' doesn't properly validate token path",
                            severity=Severity.MEDIUM,
                            category=Category.INPUT_VALIDATION,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Validate token path length and addresses",
                            impact="Invalid paths could cause transaction failures or exploits"
                        )
                        findings.append(finding)
        
        return findings
    
    def _check_liquidity_security(self, context: AnalysisContext) -> List[Finding]:
        """Check liquidity management security."""
        findings = []
        
        for contract_name, functions in context.functions.items():
            for func in functions:
                if self._is_liquidity_function(func):
                    
                    # Check for minimum liquidity validation
                    if not self._validates_minimum_liquidity(func):
                        finding = self.create_finding(
                            title=f"Missing Minimum Liquidity Validation in {func.name}",
                            description=f"Liquidity function '{func.name}' doesn't validate minimum liquidity",
                            severity=Severity.MEDIUM,
                            category=Category.DEFI_SPECIFIC,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Add minimum liquidity checks to prevent dust attacks",
                            impact="Pool could be manipulated with minimal liquidity"
                        )
                        findings.append(finding)
                    
                    # Check for liquidity ratio validation
                    if 'add' in func.name.lower() and not self._validates_liquidity_ratio(func):
                        finding = self.create_finding(
                            title=f"Missing Liquidity Ratio Validation in {func.name}",
                            description=f"Add liquidity function '{func.name}' doesn't validate token ratios",
                            severity=Severity.LOW,
                            category=Category.DEFI_SPECIFIC,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Validate or adjust token ratios automatically",
                            impact="Liquidity providers might add unbalanced liquidity"
                        )
                        findings.append(finding)
        
        return findings
    
    def _check_price_calculation(self, context: AnalysisContext) -> List[Finding]:
        """Check price calculation mechanisms."""
        findings = []
        
        for contract_name, functions in context.functions.items():
            for func in functions:
                if self._calculates_prices(func):
                    
                    # Check for overflow protection in price calculations
                    if not self._has_overflow_protection(func):
                        finding = self.create_finding(
                            title=f"Price Calculation Overflow Risk in {func.name}",
                            description=f"Price calculation in '{func.name}' may be vulnerable to overflow",
                            severity=Severity.HIGH,
                            category=Category.ARITHMETIC,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Use safe math libraries or Solidity 0.8+ for price calculations",
                            impact="Overflow could result in incorrect prices and financial losses"
                        )
                        findings.append(finding)
                    
                    # Check for division by zero protection
                    if not self._protects_against_division_by_zero(func):
                        finding = self.create_finding(
                            title=f"Division by Zero Risk in {func.name}",
                            description=f"Price calculation in '{func.name}' doesn't protect against division by zero",
                            severity=Severity.HIGH,
                            category=Category.ARITHMETIC,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Add zero checks before division operations",
                            impact="Division by zero could cause transaction reverts or exploits"
                        )
                        findings.append(finding)
        
        return findings
    
    def _check_k_constant_invariant(self, context: AnalysisContext) -> List[Finding]:
        """Check K constant invariant maintenance."""
        findings = []
        
        # Look for K constant usage
        k_pattern = r'\bk\b'
        if re.search(k_pattern, context.contract_code, re.IGNORECASE):
            
            for contract_name, functions in context.functions.items():
                for func in functions:
                    if self._modifies_reserves(func):
                        
                        if not self._validates_k_invariant(func):
                            finding = self.create_finding(
                                title=f"Missing K Invariant Validation in {func.name}",
                                description=f"Function '{func.name}' modifies reserves without validating K invariant",
                                severity=Severity.CRITICAL,
                                category=Category.DEFI_SPECIFIC,
                                location=CodeLocation(
                                    contract_name=contract_name,
                                    function_name=func.name,
                                    line_number=func.line_number
                                ),
                                affected_contracts=[contract_name],
                                affected_functions=[func.name],
                                recommendation="Ensure K invariant is maintained: k_new >= k_old",
                                impact="K invariant violation could drain the pool"
                            )
                            findings.append(finding)
        
        return findings
    
    def _check_fee_calculation(self, context: AnalysisContext) -> List[Finding]:
        """Check fee calculation security."""
        findings = []
        
        for contract_name, functions in context.functions.items():
            for func in functions:
                if self._calculates_fees(func):
                    
                    # Check for fee overflow
                    if not self._validates_fee_bounds(func):
                        finding = self.create_finding(
                            title=f"Fee Calculation Issues in {func.name}",
                            description=f"Fee calculation in '{func.name}' may have overflow or bounds issues",
                            severity=Severity.MEDIUM,
                            category=Category.ARITHMETIC,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Validate fee calculations and bounds",
                            impact="Incorrect fee calculations could affect protocol revenue"
                        )
                        findings.append(finding)
        
        return findings
    
    def _check_reserve_management(self, context: AnalysisContext) -> List[Finding]:
        """Check reserve management security."""
        findings = []
        
        for contract_name, functions in context.functions.items():
            for func in functions:
                if self._manages_reserves(func):
                    
                    # Check for atomic reserve updates
                    if not self._updates_reserves_atomically(func):
                        finding = self.create_finding(
                            title=f"Non-Atomic Reserve Updates in {func.name}",
                            description=f"Function '{func.name}' doesn't update reserves atomically",
                            severity=Severity.HIGH,
                            category=Category.DEFI_SPECIFIC,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Update both reserves in a single transaction",
                            impact="Non-atomic updates could create arbitrage opportunities"
                        )
                        findings.append(finding)
        
        return findings
    
    def _check_slippage_protection(self, context: AnalysisContext) -> List[Finding]:
        """Check slippage protection mechanisms."""
        findings = []
        
        # This extends the base class check with AMM-specific validations
        base_findings = super()._check_slippage_protection(context)
        findings.extend(base_findings)
        
        # Additional AMM-specific slippage checks
        for contract_name, functions in context.functions.items():
            for func in functions:
                if self._is_swap_function(func):
                    
                    # Check for price impact limits
                    if not self._has_price_impact_limits(func):
                        finding = self.create_finding(
                            title=f"Missing Price Impact Limits in {func.name}",
                            description=f"Swap function '{func.name}' doesn't limit price impact",
                            severity=Severity.MEDIUM,
                            category=Category.DEFI_SPECIFIC,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Implement maximum price impact validation",
                            impact="Large trades could cause excessive price impact"
                        )
                        findings.append(finding)
        
        return findings
    
    def _check_front_running_protection(self, context: AnalysisContext) -> List[Finding]:
        """Check front-running protection mechanisms."""
        findings = []
        
        for contract_name, functions in context.functions.items():
            for func in functions:
                if self._is_trading_function(func):
                    
                    # Check for commit-reveal scheme or similar protection
                    if not self._has_front_running_protection(func):
                        finding = self.create_finding(
                            title=f"Front-Running Vulnerability in {func.name}",
                            description=f"Trading function '{func.name}' vulnerable to front-running attacks",
                            severity=Severity.MEDIUM,
                            category=Category.MEV_PROTECTION,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Consider implementing MEV protection mechanisms",
                            impact="Users could be front-run by MEV bots"
                        )
                        findings.append(finding)
        
        return findings
    
    def _check_sandwich_attack_protection(self, context: AnalysisContext) -> List[Finding]:
        """Check sandwich attack protection."""
        findings = []
        
        # Sandwich attacks are a specific type of MEV attack
        for contract_name, functions in context.functions.items():
            for func in functions:
                if self._is_swap_function(func):
                    
                    # Check for adequate slippage protection (helps prevent sandwich attacks)
                    if not self._has_adequate_slippage_protection(func):
                        finding = self.create_finding(
                            title=f"Sandwich Attack Risk in {func.name}",
                            description=f"Swap function '{func.name}' may be vulnerable to sandwich attacks",
                            severity=Severity.MEDIUM,
                            category=Category.MEV_PROTECTION,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Implement strict slippage limits and consider private mempools",
                            impact="Users could lose value to sandwich attacks"
                        )
                        findings.append(finding)
        
        return findings
    
    def _check_flash_swap_security(self, context: AnalysisContext) -> List[Finding]:
        """Check flash swap security if supported."""
        findings = []
        
        flash_swap_patterns = ['flashSwap', 'flash', 'callback', 'uniswapV2Call']
        
        for contract_name, functions in context.functions.items():
            for func in functions:
                if any(pattern.lower() in func.name.lower() for pattern in flash_swap_patterns):
                    
                    # Check for proper callback validation
                    if not self._validates_flash_callback(func):
                        finding = self.create_finding(
                            title=f"Insecure Flash Swap Callback in {func.name}",
                            description=f"Flash swap callback '{func.name}' lacks proper validation",
                            severity=Severity.HIGH,
                            category=Category.ACCESS_CONTROL,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Validate callback sender and implement proper access controls",
                            impact="Unauthorized flash swaps could drain pool funds"
                        )
                        findings.append(finding)
        
        return findings
    
    # Helper methods for AMM pattern detection
    
    def _is_swap_function(self, func: FunctionContext) -> bool:
        """Check if function is a swap function."""
        return any(pattern.lower() in func.name.lower() 
                  for pattern in self.amm_patterns['swap_functions'])
    
    def _is_liquidity_function(self, func: FunctionContext) -> bool:
        """Check if function manages liquidity."""
        return any(pattern.lower() in func.name.lower() 
                  for pattern in self.amm_patterns['liquidity_functions'])
    
    def _calculates_prices(self, func: FunctionContext) -> bool:
        """Check if function calculates prices."""
        return any(pattern.lower() in func.name.lower() 
                  for pattern in self.amm_patterns['price_functions'])
    
    def _validates_minimum_amounts(self, func: FunctionContext) -> bool:
        """Check if function validates minimum amounts."""
        validation_patterns = [
            r'require\s*\(\s*.*amountOut.*>=.*amountOutMin',
            r'require\s*\(\s*.*amount.*>=.*min',
            r'amountOutMin',
            r'minAmount'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) 
                  for pattern in validation_patterns)
    
    def _validates_deadline(self, func: FunctionContext) -> bool:
        """Check if function validates deadline."""
        return any(param.lower() in ['deadline', 'expiry'] for param in func.parameters) or \
               re.search(r'require\s*\(\s*.*deadline.*>=.*block\.timestamp', func.body, re.IGNORECASE)
    
    def _has_token_path(self, func: FunctionContext) -> bool:
        """Check if function uses token path."""
        return 'path' in func.body.lower() or any('path' in param.lower() for param in func.parameters)
    
    def _validates_token_path(self, func: FunctionContext) -> bool:
        """Check if function validates token path."""
        validation_patterns = [
            r'require\s*\(\s*path\.length\s*>=\s*2',
            r'require\s*\(\s*.*path.*length',
            r'path\.length\s*>\s*1'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) 
                  for pattern in validation_patterns)
    
    def _validates_minimum_liquidity(self, func: FunctionContext) -> bool:
        """Check if function validates minimum liquidity."""
        validation_patterns = [
            r'require\s*\(\s*.*liquidity.*>',
            r'MINIMUM_LIQUIDITY',
            r'minLiquidity'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) 
                  for pattern in validation_patterns)
    
    def _validates_liquidity_ratio(self, func: FunctionContext) -> bool:
        """Check if function validates liquidity ratios."""
        ratio_patterns = [
            r'amount.*Optimal',
            r'ratio',
            r'proportion'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) 
                  for pattern in ratio_patterns)
    
    def _has_overflow_protection(self, func: FunctionContext) -> bool:
        """Check if function has overflow protection."""
        protection_patterns = [
            'SafeMath',
            'safeAdd',
            'safeMul',
            'safeDiv',
            'checked'
        ]
        return any(pattern.lower() in func.body.lower() for pattern in protection_patterns)
    
    def _protects_against_division_by_zero(self, func: FunctionContext) -> bool:
        """Check if function protects against division by zero."""
        protection_patterns = [
            r'require\s*\(\s*.*\s*[>!]\s*0.*\)',
            r'require\s*\(\s*.*!=\s*0\s*\)',
            r'if\s*\(\s*.*==\s*0\s*\)'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) 
                  for pattern in protection_patterns)
    
    def _modifies_reserves(self, func: FunctionContext) -> bool:
        """Check if function modifies reserves."""
        return any(pattern in func.body.lower() 
                  for pattern in ['reserve0', 'reserve1', 'sync', 'update'])
    
    def _validates_k_invariant(self, func: FunctionContext) -> bool:
        """Check if function validates K invariant."""
        k_patterns = [
            r'require\s*\(\s*.*balance.*\*.*balance.*>=.*k',
            r'k\s*=',
            r'invariant'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) 
                  for pattern in k_patterns)
    
    def _calculates_fees(self, func: FunctionContext) -> bool:
        """Check if function calculates fees."""
        return any(pattern in func.body.lower() 
                  for pattern in self.amm_patterns['fee_patterns'])
    
    def _validates_fee_bounds(self, func: FunctionContext) -> bool:
        """Check if function validates fee bounds."""
        validation_patterns = [
            r'require\s*\(\s*fee.*<',
            r'require\s*\(\s*fee.*<=',
            r'MAX_FEE',
            r'feeRate.*<'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) 
                  for pattern in validation_patterns)
    
    def _manages_reserves(self, func: FunctionContext) -> bool:
        """Check if function manages reserves."""
        return any(pattern in func.body.lower() 
                  for pattern in self.amm_patterns['reserve_patterns'])
    
    def _updates_reserves_atomically(self, func: FunctionContext) -> bool:
        """Check if function updates reserves atomically."""
        # Look for both reserves being updated in same function
        has_reserve0 = 'reserve0' in func.body.lower()
        has_reserve1 = 'reserve1' in func.body.lower()
        return has_reserve0 and has_reserve1
    
    def _has_price_impact_limits(self, func: FunctionContext) -> bool:
        """Check if function has price impact limits."""
        impact_patterns = [
            'priceImpact',
            'maxPriceImpact',
            'impactLimit'
        ]
        return any(pattern.lower() in func.body.lower() for pattern in impact_patterns)
    
    def _has_front_running_protection(self, func: FunctionContext) -> bool:
        """Check if function has front-running protection."""
        protection_patterns = [
            'commit',
            'reveal',
            'nonce',
            'timelock',
            'private'
        ]
        return any(pattern.lower() in func.body.lower() for pattern in protection_patterns)
    
    def _has_adequate_slippage_protection(self, func: FunctionContext) -> bool:
        """Check if function has adequate slippage protection."""
        # More strict check than basic slippage protection
        strict_patterns = [
            r'require\s*\(\s*.*amount.*>=.*amount.*\*\s*\d+\s*/\s*\d+',
            r'slippageTolerance',
            r'maxSlippage'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) 
                  for pattern in strict_patterns)
    
    def _validates_flash_callback(self, func: FunctionContext) -> bool:
        """Check if flash callback is properly validated."""
        validation_patterns = [
            r'require\s*\(\s*msg\.sender\s*==',
            r'onlyFactory',
            r'onlyPair',
            r'validCallback'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) 
                  for pattern in validation_patterns)
