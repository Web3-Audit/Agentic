"""
Derivatives agent for analyzing DeFi derivatives and options protocols.
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
class DerivativesMetrics(DeFiMetrics):
    """Derivatives-specific metrics extending DeFi metrics."""
    option_functions: int = 0
    future_functions: int = 0
    perpetual_functions: int = 0
    margin_functions: int = 0
    settlement_functions: int = 0
    exercise_functions: int = 0
    liquidation_functions: int = 0
    premium_calculations: int = 0


class DerivativesAgent(DeFiBaseAgent):
    """
    Specialized agent for analyzing derivatives protocol contracts.
    Focuses on options, futures, perpetuals, and margin trading.
    """
    
    def __init__(self, llm_client: Optional[LLMClient] = None,
                 prompt_manager: Optional[PromptManager] = None):
        super().__init__("DerivativesAgent", llm_client, prompt_manager)
        
        # Derivatives-specific patterns
        self.derivatives_patterns = {
            'option_functions': [
                'option', 'call', 'put', 'exercise', 'premium', 'strike'
            ],
            'future_functions': [
                'future', 'forward', 'delivery', 'settlement', 'expiry'
            ],
            'perpetual_functions': [
                'perpetual', 'perp', 'funding', 'fundingRate', 'position'
            ],
            'margin_functions': [
                'margin', 'collateral', 'leverage', 'maintenance', 'initial'
            ],
            'settlement_patterns': [
                'settle', 'settlement', 'delivery', 'cash', 'physical'
            ],
            'pricing_patterns': [
                'premium', 'price', 'mark', 'index', 'fair', 'oracle'
            ],
            'risk_patterns': [
                'var', 'risk', 'exposure', 'hedge', 'delta', 'gamma', 'theta'
            ]
        }
    
    def can_analyze(self, context: AnalysisContext) -> bool:
        """Check if this is a derivatives contract."""
        if not super().can_analyze(context):
            return False
        
        code_lower = context.contract_code.lower()
        
        derivatives_indicators = [
            'option', 'future', 'perpetual', 'derivative', 'margin',
            'leverage', 'settlement', 'exercise', 'premium', 'strike'
        ]
        
        matches = sum(1 for indicator in derivatives_indicators if indicator in code_lower)
        return matches >= 3
    
    def analyze(self, context: AnalysisContext) -> List[Finding]:
        """
        Analyze derivatives contract for security vulnerabilities.
        
        Args:
            context: Analysis context
            
        Returns:
            List[Finding]: Derivatives-specific findings
        """
        self.logger.info("Starting derivatives protocol analysis")
        findings = []
        
        try:
            # Calculate derivatives metrics
            metrics = self._calculate_derivatives_metrics(context)
            
            # Core derivatives security checks
            findings.extend(self._check_option_security(context))
            findings.extend(self._check_margin_security(context))
            findings.extend(self._check_settlement_security(context))
            findings.extend(self._check_premium_calculation(context))
            findings.extend(self._check_exercise_security(context))
            findings.extend(self._check_liquidation_security(context))
            findings.extend(self._check_funding_rate_security(context))
            findings.extend(self._check_position_management(context))
            findings.extend(self._check_expiry_handling(context))
            findings.extend(self._check_risk_management(context))
            
            self.logger.info(f"Derivatives analysis completed with {len(findings)} findings")
            return findings
            
        except Exception as e:
            self.logger.error(f"Error in derivatives analysis: {str(e)}")
            return findings
    
    def _calculate_derivatives_metrics(self, context: AnalysisContext) -> DerivativesMetrics:
        """Calculate derivatives-specific metrics."""
        metrics = DerivativesMetrics()
        
        for functions in context.functions.values():
            for func in functions:
                func_name_lower = func.name.lower()
                
                # Count different function types
                if any(pattern.lower() in func_name_lower 
                      for pattern in self.derivatives_patterns['option_functions']):
                    metrics.option_functions += 1
                
                if any(pattern.lower() in func_name_lower 
                      for pattern in self.derivatives_patterns['future_functions']):
                    metrics.future_functions += 1
                
                if any(pattern.lower() in func_name_lower 
                      for pattern in self.derivatives_patterns['perpetual_functions']):
                    metrics.perpetual_functions += 1
                
                if any(pattern.lower() in func_name_lower 
                      for pattern in self.derivatives_patterns['margin_functions']):
                    metrics.margin_functions += 1
                
                if 'exercise' in func_name_lower:
                    metrics.exercise_functions += 1
                
                if 'settle' in func_name_lower:
                    metrics.settlement_functions += 1
                
                # Check for premium calculations
                if any(pattern in func.body.lower() 
                      for pattern in self.derivatives_patterns['pricing_patterns']):
                    metrics.premium_calculations += 1
        
        return metrics
    
    def _check_option_security(self, context: AnalysisContext) -> List[Finding]:
        """Check options contract security."""
        findings = []
        
        for contract_name, functions in context.functions.items():
            for func in functions:
                if self._is_option_function(func):
                    
                    # Check for strike price validation
                    if not self._validates_strike_price(func):
                        finding = self.create_finding(
                            title=f"Missing Strike Price Validation in {func.name}",
                            description=f"Option function '{func.name}' doesn't validate strike price",
                            severity=Severity.HIGH,
                            category=Category.INPUT_VALIDATION,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Validate strike price is reasonable and within bounds",
                            impact="Invalid strike prices could cause pricing errors"
                        )
                        findings.append(finding)
                    
                    # Check for expiry validation
                    if not self._validates_option_expiry(func):
                        finding = self.create_finding(
                            title=f"Missing Option Expiry Validation in {func.name}",
                            description=f"Option function '{func.name}' doesn't validate expiry time",
                            severity=Severity.MEDIUM,
                            category=Category.INPUT_VALIDATION,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Validate option expiry is in the future and within reasonable bounds",
                            impact="Invalid expiry times could cause settlement issues"
                        )
                        findings.append(finding)
                    
                    # Check for option type validation
                    if not self._validates_option_type(func):
                        finding = self.create_finding(
                            title=f"Missing Option Type Validation in {func.name}",
                            description=f"Option function '{func.name}' doesn't validate option type (call/put)",
                            severity=Severity.MEDIUM,
                            category=Category.INPUT_VALIDATION,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Validate option type is valid (call or put)",
                            impact="Invalid option types could cause incorrect payouts"
                        )
                        findings.append(finding)
        
        return findings
    
    def _check_margin_security(self, context: AnalysisContext) -> List[Finding]:
        """Check margin trading security."""
        findings = []
        
        for contract_name, functions in context.functions.items():
            for func in functions:
                if self._handles_margin(func):
                    
                    # Check for margin ratio validation
                    if not self._validates_margin_ratio(func):
                        finding = self.create_finding(
                            title=f"Missing Margin Ratio Validation in {func.name}",
                            description=f"Margin function '{func.name}' doesn't validate margin ratios",
                            severity=Severity.CRITICAL,
                            category=Category.DEFI_SPECIFIC,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Validate margin ratios meet minimum requirements",
                            impact="Insufficient margin could lead to protocol insolvency"
                        )
                        findings.append(finding)
                    
                    # Check for maintenance margin
                    if not self._checks_maintenance_margin(func):
                        finding = self.create_finding(
                            title=f"Missing Maintenance Margin Check in {func.name}",
                            description=f"Margin function '{func.name}' doesn't check maintenance margin",
                            severity=Severity.HIGH,
                            category=Category.DEFI_SPECIFIC,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Implement maintenance margin checks to prevent under-collateralization",
                            impact="Positions could become under-collateralized without detection"
                        )
                        findings.append(finding)
                    
                    # Check for leverage limits
                    if not self._validates_leverage_limits(func):
                        finding = self.create_finding(
                            title=f"Missing Leverage Limits in {func.name}",
                            description=f"Margin function '{func.name}' doesn't enforce leverage limits",
                            severity=Severity.MEDIUM,
                            category=Category.DEFI_SPECIFIC,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Implement maximum leverage limits to reduce risk",
                            impact="Excessive leverage could increase systemic risk"
                        )
                        findings.append(finding)
        
        return findings
    
    def _check_settlement_security(self, context: AnalysisContext) -> List[Finding]:
        """Check settlement mechanism security."""
        findings = []
        
        for contract_name, functions in context.functions.items():
            for func in functions:
                if self._handles_settlement(func):
                    
                    # Check for settlement price validation
                    if not self._validates_settlement_price(func):
                        finding = self.create_finding(
                            title=f"Missing Settlement Price Validation in {func.name}",
                            description=f"Settlement function '{func.name}' doesn't validate settlement price",
                            severity=Severity.HIGH,
                            category=Category.ORACLE_DEPENDENCY,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Validate settlement price from reliable oracle sources",
                            impact="Invalid settlement prices could cause incorrect payouts"
                        )
                        findings.append(finding)
                    
                    # Check for settlement timing
                    if not self._validates_settlement_timing(func):
                        finding = self.create_finding(
                            title=f"Missing Settlement Timing Validation in {func.name}",
                            description=f"Settlement function '{func.name}' doesn't validate settlement timing",
                            severity=Severity.MEDIUM,
                            category=Category.INPUT_VALIDATION,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Validate settlement can only occur after expiry",
                            impact="Premature settlement could affect derivative valuations"
                        )
                        findings.append(finding)
                    
                    # Check for settlement access control
                    if not self._has_settlement_access_control(func):
                        finding = self.create_finding(
                            title=f"Missing Settlement Access Control in {func.name}",
                            description=f"Settlement function '{func.name}' lacks proper access control",
                            severity=Severity.HIGH,
                            category=Category.ACCESS_CONTROL,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Implement proper access controls for settlement functions",
                            impact="Unauthorized settlement could disrupt derivative contracts"
                        )
                        findings.append(finding)
        
        return findings
    
    def _check_premium_calculation(self, context: AnalysisContext) -> List[Finding]:
        """Check premium calculation security."""
        findings = []
        
        for contract_name, functions in context.functions.items():
            for func in functions:
                if self._calculates_premium(func):
                    
                    # Check for premium calculation accuracy
                    if not self._accurate_premium_calculation(func):
                        finding = self.create_finding(
                            title=f"Inaccurate Premium Calculation in {func.name}",
                            description=f"Premium calculation in '{func.name}' may be inaccurate",
                            severity=Severity.HIGH,
                            category=Category.ARITHMETIC,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Ensure accurate premium calculations using proper mathematical models",
                            impact="Incorrect premiums could lead to mispricing and losses"
                        )
                        findings.append(finding)
                    
                    # Check for volatility input validation
                    if not self._validates_volatility_input(func):
                        finding = self.create_finding(
                            title=f"Missing Volatility Validation in {func.name}",
                            description=f"Premium calculation in '{func.name}' doesn't validate volatility inputs",
                            severity=Severity.MEDIUM,
                            category=Category.INPUT_VALIDATION,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Validate volatility inputs are within reasonable bounds",
                            impact="Invalid volatility could cause pricing errors"
                        )
                        findings.append(finding)
        
        return findings
    
    def _check_exercise_security(self, context: AnalysisContext) -> List[Finding]:
        """Check option exercise security."""
        findings = []
        
        for contract_name, functions in context.functions.items():
            for func in functions:
                if self._handles_exercise(func):
                    
                    # Check for exercise conditions
                    if not self._validates_exercise_conditions(func):
                        finding = self.create_finding(
                            title=f"Missing Exercise Condition Validation in {func.name}",
                            description=f"Exercise function '{func.name}' doesn't validate exercise conditions",
                            severity=Severity.HIGH,
                            category=Category.DEFI_SPECIFIC,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Validate exercise conditions (in-the-money, before expiry, etc.)",
                            impact="Invalid exercises could cause incorrect payouts"
                        )
                        findings.append(finding)
                    
                    # Check for exercise timing
                    if not self._validates_exercise_timing(func):
                        finding = self.create_finding(
                            title=f"Missing Exercise Timing Validation in {func.name}",
                            description=f"Exercise function '{func.name}' doesn't validate exercise timing",
                            severity=Severity.MEDIUM,
                            category=Category.INPUT_VALIDATION,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Validate exercise timing is within allowed periods",
                            impact="Exercise at wrong times could cause settlement issues"
                        )
                        findings.append(finding)
        
        return findings
    
    def _check_liquidation_security(self, context: AnalysisContext) -> List[Finding]:
        """Check liquidation mechanism security."""
        findings = []
        
        for contract_name, functions in context.functions.items():
            for func in functions:
                if self._handles_liquidation(func):
                    
                    # Check for liquidation threshold
                    if not self._validates_liquidation_threshold(func):
                        finding = self.create_finding(
                            title=f"Missing Liquidation Threshold Validation in {func.name}",
                            description=f"Liquidation function '{func.name}' doesn't validate liquidation threshold",
                            severity=Severity.CRITICAL,
                            category=Category.DEFI_SPECIFIC,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Validate position is eligible for liquidation",
                            impact="Healthy positions could be liquidated incorrectly"
                        )
                        findings.append(finding)
                    
                    # Check for liquidation penalty bounds
                    if not self._validates_liquidation_penalty(func):
                        finding = self.create_finding(
                            title=f"Missing Liquidation Penalty Validation in {func.name}",
                            description=f"Liquidation function '{func.name}' doesn't validate penalty amounts",
                            severity=Severity.MEDIUM,
                            category=Category.DEFI_SPECIFIC,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Validate liquidation penalties are within reasonable bounds",
                            impact="Excessive penalties could harm traders unfairly"
                        )
                        findings.append(finding)
        
        return findings
    
    def _check_funding_rate_security(self, context: AnalysisContext) -> List[Finding]:
        """Check funding rate mechanism security."""
        findings = []
        
        for contract_name, functions in context.functions.items():
            for func in functions:
                if self._handles_funding_rate(func):
                    
                    # Check for funding rate bounds
                    if not self._validates_funding_rate_bounds(func):
                        finding = self.create_finding(
                            title=f"Missing Funding Rate Bounds in {func.name}",
                            description=f"Funding rate function '{func.name}' doesn't validate rate bounds",
                            severity=Severity.MEDIUM,
                            category=Category.DEFI_SPECIFIC,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Implement funding rate bounds to prevent extreme rates",
                            impact="Extreme funding rates could destabilize perpetual markets"
                        )
                        findings.append(finding)
                    
                    # Check for funding calculation accuracy
                    if not self._accurate_funding_calculation(func):
                        finding = self.create_finding(
                            title=f"Inaccurate Funding Calculation in {func.name}",
                            description=f"Funding calculation in '{func.name}' may be inaccurate",
                            severity=Severity.MEDIUM,
                            category=Category.ARITHMETIC,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Ensure accurate funding rate calculations",
                            impact="Incorrect funding could affect trader positions unfairly"
                        )
                        findings.append(finding)
        
        return findings
    
    def _check_position_management(self, context: AnalysisContext) -> List[Finding]:
        """Check position management security."""
        findings = []
        
        for contract_name, functions in context.functions.items():
            for func in functions:
                if self._manages_positions(func):
                    
                    # Check for position size limits
                    if not self._validates_position_limits(func):
                        finding = self.create_finding(
                            title=f"Missing Position Size Limits in {func.name}",
                            description=f"Position function '{func.name}' doesn't enforce position size limits",
                            severity=Severity.MEDIUM,
                            category=Category.DEFI_SPECIFIC,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Implement position size limits to reduce concentration risk",
                            impact="Large positions could increase systemic risk"
                        )
                        findings.append(finding)
                    
                    # Check for position tracking accuracy
                    if not self._accurate_position_tracking(func):
                        finding = self.create_finding(
                            title=f"Inaccurate Position Tracking in {func.name}",
                            description=f"Position tracking in '{func.name}' may be inaccurate",
                            severity=Severity.HIGH,
                            category=Category.ARITHMETIC,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Ensure accurate position tracking and accounting",
                            impact="Inaccurate tracking could lead to incorrect settlements"
                        )
                        findings.append(finding)
        
        return findings
    
    def _check_expiry_handling(self, context: AnalysisContext) -> List[Finding]:
        """Check expiry handling mechanisms."""
        findings = []
        
        for contract_name, functions in context.functions.items():
            for func in functions:
                if self._handles_expiry(func):
                    
                    # Check for expiry validation
                    if not self._validates_expiry_conditions(func):
                        finding = self.create_finding(
                            title=f"Missing Expiry Validation in {func.name}",
                            description=f"Expiry function '{func.name}' doesn't validate expiry conditions",
                            severity=Severity.MEDIUM,
                            category=Category.INPUT_VALIDATION,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Validate expiry conditions before processing",
                            impact="Incorrect expiry handling could affect derivative settlements"
                        )
                        findings.append(finding)
        
        return findings
    
    def _check_risk_management(self, context: AnalysisContext) -> List[Finding]:
        """Check risk management mechanisms."""
        findings = []
        
        # Check if risk management functions exist
        has_risk_management = False
        for functions in context.functions.values():
            for func in functions:
                if self._implements_risk_management(func):
                    has_risk_management = True
                    break
        
        if not has_risk_management:
            finding = self.create_finding(
                title="Missing Risk Management Mechanisms",
                description="Derivatives contract lacks comprehensive risk management",
                severity=Severity.HIGH,
                category=Category.DEFI_SPECIFIC,
                recommendation="Implement risk management functions (VaR, exposure limits, etc.)",
                impact="Lack of risk management could lead to excessive protocol risk"
            )
            findings.append(finding)
        
        return findings
    
    # Helper methods for derivatives pattern detection
    
    def _is_option_function(self, func: FunctionContext) -> bool:
        """Check if function handles options."""
        return any(pattern.lower() in func.name.lower() 
                  for pattern in self.derivatives_patterns['option_functions'])
    
    def _handles_margin(self, func: FunctionContext) -> bool:
        """Check if function handles margin."""
        return any(pattern.lower() in func.name.lower() 
                  for pattern in self.derivatives_patterns['margin_functions'])
    
    def _handles_settlement(self, func: FunctionContext) -> bool:
        """Check if function handles settlement."""
        return any(pattern in func.body.lower() 
                  for pattern in self.derivatives_patterns['settlement_patterns'])
    
    def _calculates_premium(self, func: FunctionContext) -> bool:
        """Check if function calculates premiums."""
        return any(pattern in func.body.lower() 
                  for pattern in self.derivatives_patterns['pricing_patterns'])
    
    def _handles_exercise(self, func: FunctionContext) -> bool:
        """Check if function handles option exercise."""
        return 'exercise' in func.name.lower()
    
    def _handles_liquidation(self, func: FunctionContext) -> bool:
        """Check if function handles liquidation."""
        return 'liquidat' in func.name.lower()
    
    def _handles_funding_rate(self, func: FunctionContext) -> bool:
        """Check if function handles funding rates."""
        return any(pattern.lower() in func.name.lower() 
                  for pattern in self.derivatives_patterns['perpetual_functions'])
    
    def _manages_positions(self, func: FunctionContext) -> bool:
        """Check if function manages positions."""
        position_keywords = ['position', 'open', 'close', 'modify']
        return any(keyword in func.name.lower() for keyword in position_keywords)
    
    def _handles_expiry(self, func: FunctionContext) -> bool:
        """Check if function handles expiry."""
        expiry_keywords = ['expiry', 'expire', 'maturity', 'mature']
        return any(keyword in func.name.lower() for keyword in expiry_keywords)
    
    def _implements_risk_management(self, func: FunctionContext) -> bool:
        """Check if function implements risk management."""
        return any(pattern in func.body.lower() 
                  for pattern in self.derivatives_patterns['risk_patterns'])
    
    # Validation helper methods
    
    def _validates_strike_price(self, func: FunctionContext) -> bool:
        """Check if strike price is validated."""
        validation_patterns = [
            r'require\s*\(\s*.*strike.*>.*0',
            r'require\s*\(\s*.*strike.*<=.*maxStrike',
            r'strikePrice',
            r'validStrike'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) 
                  for pattern in validation_patterns)
    
    def _validates_option_expiry(self, func: FunctionContext) -> bool:
        """Check if option expiry is validated."""
        validation_patterns = [
            r'require\s*\(\s*.*expiry.*>.*block\.timestamp',
            r'require\s*\(\s*.*expiry.*<=.*maxExpiry',
            r'expiryTime',
            r'validExpiry'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) 
                  for pattern in validation_patterns)
    
    def _validates_option_type(self, func: FunctionContext) -> bool:
        """Check if option type is validated."""
        validation_patterns = [
            r'require\s*\(\s*.*optionType.*==.*CALL.*\|\|.*optionType.*==.*PUT',
            r'OptionType',
            r'isCall',
            r'isPut'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) 
                  for pattern in validation_patterns)
    
    def _validates_margin_ratio(self, func: FunctionContext) -> bool:
        """Check if margin ratio is validated."""
        validation_patterns = [
            r'require\s*\(\s*.*margin.*>=.*initialMargin',
            r'require\s*\(\s*.*collateral.*>=.*required',
            r'marginRatio',
            r'collateralRatio'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) 
                  for pattern in validation_patterns)
    
    def _checks_maintenance_margin(self, func: FunctionContext) -> bool:
        """Check if maintenance margin is checked."""
        maintenance_patterns = [
            'maintenanceMargin',
            'maintMargin',
            'minMargin',
            'marginCall'
        ]
        return any(pattern.lower() in func.body.lower() for pattern in maintenance_patterns)
    
    def _validates_leverage_limits(self, func: FunctionContext) -> bool:
        """Check if leverage limits are validated."""
        limit_patterns = [
            r'require\s*\(\s*.*leverage.*<=.*maxLeverage',
            r'require\s*\(\s*.*leverage.*>=.*minLeverage',
            r'leverageLimit',
            r'maxLeverage'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) 
                  for pattern in limit_patterns)
    
    def _validates_settlement_price(self, func: FunctionContext) -> bool:
        """Check if settlement price is validated."""
        validation_patterns = [
            r'require\s*\(\s*.*price.*>.*0',
            r'oraclePrice',
            r'settlementPrice',
            r'markPrice'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) 
                  for pattern in validation_patterns)
    
    def _validates_settlement_timing(self, func: FunctionContext) -> bool:
        """Check if settlement timing is validated."""
        timing_patterns = [
            r'require\s*\(\s*block\.timestamp.*>=.*expiry',
            r'require\s*\(\s*.*expired',
            r'canSettle',
            r'settlementWindow'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) 
                  for pattern in timing_patterns)
    
    def _has_settlement_access_control(self, func: FunctionContext) -> bool:
        """Check if settlement has access control."""
        access_patterns = [
            'onlySettler',
            'onlyOracle',
            'onlyKeeper',
            'canSettle'
        ]
        return any(pattern in func.modifiers or pattern.lower() in func.body.lower() 
                  for pattern in access_patterns)
    
    def _accurate_premium_calculation(self, func: FunctionContext) -> bool:
        """Check if premium calculation is accurate."""
        accuracy_patterns = [
            'blackScholes',
            'volatility',
            'timeValue',
            'intrinsicValue'
        ]
        return any(pattern.lower() in func.body.lower() for pattern in accuracy_patterns)
    
    def _validates_volatility_input(self, func: FunctionContext) -> bool:
        """Check if volatility input is validated."""
        validation_patterns = [
            r'require\s*\(\s*.*volatility.*>.*0',
            r'require\s*\(\s*.*volatility.*<=.*maxVol',
            r'impliedVolatility',
            r'vol'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) 
                  for pattern in validation_patterns)
    
    def _validates_exercise_conditions(self, func: FunctionContext) -> bool:
        """Check if exercise conditions are validated."""
        condition_patterns = [
            r'require\s*\(\s*.*inTheMoney',
            r'require\s*\(\s*.*canExercise',
            r'exerciseCondition',
            r'isExercisable'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) 
                  for pattern in condition_patterns)
    
    def _validates_exercise_timing(self, func: FunctionContext) -> bool:
        """Check if exercise timing is validated."""
        timing_patterns = [
            r'require\s*\(\s*block\.timestamp.*<.*expiry',
            r'require\s*\(\s*!.*expired',
            r'exerciseWindow',
            r'beforeExpiry'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) 
                  for pattern in timing_patterns)
    
    def _validates_liquidation_threshold(self, func: FunctionContext) -> bool:
        """Check if liquidation threshold is validated."""
        threshold_patterns = [
            r'require\s*\(\s*.*margin.*<.*maintenanceMargin',
            r'require\s*\(\s*.*underwater',
            r'liquidationThreshold',
            r'canLiquidate'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) 
                  for pattern in threshold_patterns)
    
    def _validates_liquidation_penalty(self, func: FunctionContext) -> bool:
        """Check if liquidation penalty is validated."""
        penalty_patterns = [
            r'liquidationPenalty',
            r'penalty.*<=.*maxPenalty',
            r'liquidationFee',
            r'penaltyRate'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) 
                  for pattern in penalty_patterns)
    
    def _validates_funding_rate_bounds(self, func: FunctionContext) -> bool:
        """Check if funding rate bounds are validated."""
        bounds_patterns = [
            r'require\s*\(\s*.*fundingRate.*<=.*maxFunding',
            r'require\s*\(\s*.*fundingRate.*>=.*minFunding',
            r'fundingCap',
            r'maxFundingRate'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) 
                  for pattern in bounds_patterns)
    
    def _accurate_funding_calculation(self, func: FunctionContext) -> bool:
        """Check if funding calculation is accurate."""
        accuracy_patterns = [
            'premium.*index',
            'markPrice.*indexPrice',
            'fundingInterval',
            'timeWeighted'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) 
                  for pattern in accuracy_patterns)
    
    def _validates_position_limits(self, func: FunctionContext) -> bool:
        """Check if position limits are validated."""
        limit_patterns = [
            r'require\s*\(\s*.*size.*<=.*maxPosition',
            r'require\s*\(\s*.*notional.*<=.*positionLimit',
            r'maxPositionSize',
            r'positionLimit'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) 
                  for pattern in limit_patterns)
    
    def _accurate_position_tracking(self, func: FunctionContext) -> bool:
        """Check if position tracking is accurate."""
        tracking_patterns = [
            'positionSize',
            'entryPrice',
            'unrealizedPnL',
            'realizedPnL'
        ]
        return any(pattern.lower() in func.body.lower() for pattern in tracking_patterns)
    
    def _validates_expiry_conditions(self, func: FunctionContext) -> bool:
        """Check if expiry conditions are validated."""
        condition_patterns = [
            r'require\s*\(\s*block\.timestamp.*>=.*expiry',
            r'require\s*\(\s*.*hasExpired',
            r'isExpired',
            r'afterExpiry'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) 
                  for pattern in condition_patterns)
