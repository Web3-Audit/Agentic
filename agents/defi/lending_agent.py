"""
Lending agent for analyzing DeFi lending and borrowing protocols.
"""

import re
import logging
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass
from decimal import Decimal

from .defi_base_agent import DeFiBaseAgent, DeFiProtocol, DeFiMetrics
from ...models.context import AnalysisContext, FunctionContext
from ...models.finding import Finding, Severity, Category, CodeLocation
from ...llm.client import LLMClient
from ...llm.prompts import PromptManager

logger = logging.getLogger(__name__)


@dataclass
class LendingMetrics(DeFiMetrics):
    """Lending-specific metrics extending DeFi metrics."""
    supply_functions: int = 0
    borrow_functions: int = 0
    repay_functions: int = 0
    liquidation_functions: int = 0
    collateral_functions: int = 0
    interest_rate_functions: int = 0
    health_factor_checks: int = 0
    ltv_validations: int = 0


class LendingAgent(DeFiBaseAgent):
    """
    Specialized agent for analyzing lending protocol contracts.
    Focuses on supply/borrow mechanics, collateralization, and liquidations.
    """
    
    def __init__(self, llm_client: Optional[LLMClient] = None,
                 prompt_manager: Optional[PromptManager] = None):
        super().__init__("LendingAgent", llm_client, prompt_manager)
        
        # Lending-specific patterns
        self.lending_patterns = {
            'supply_functions': [
                'supply', 'deposit', 'mint', 'lend', 'provide'
            ],
            'borrow_functions': [
                'borrow', 'loan', 'take', 'draw'
            ],
            'repay_functions': [
                'repay', 'repayBorrow', 'payback', 'return'
            ],
            'liquidation_functions': [
                'liquidate', 'liquidateBorrow', 'seize', 'liquidation'
            ],
            'collateral_functions': [
                'enterMarkets', 'exitMarket', 'collateral', 'enable', 'disable'
            ],
            'interest_patterns': [
                'interestRate', 'borrowRate', 'supplyRate', 'utilizationRate',
                'compoundRate', 'accrue', 'interest'
            ],
            'health_patterns': [
                'healthFactor', 'collateralRatio', 'borrowCapacity',
                'accountLiquidity', 'shortfall'
            ]
        }
    
    def can_analyze(self, context: AnalysisContext) -> bool:
        """Check if this is a lending protocol contract."""
        if not super().can_analyze(context):
            return False
        
        code_lower = context.contract_code.lower()
        
        lending_indicators = [
            'borrow', 'lend', 'supply', 'collateral', 'liquidate',
            'repay', 'interest', 'ctoken', 'atoken'
        ]
        
        matches = sum(1 for indicator in lending_indicators if indicator in code_lower)
        return matches >= 3
    
    def analyze(self, context: AnalysisContext) -> List[Finding]:
        """
        Analyze lending contract for security vulnerabilities.
        
        Args:
            context: Analysis context
            
        Returns:
            List[Finding]: Lending-specific findings
        """
        self.logger.info("Starting lending protocol analysis")
        findings = []
        
        try:
            # Calculate lending metrics
            metrics = self._calculate_lending_metrics(context)
            
            # Core lending security checks
            findings.extend(self._check_supply_security(context))
            findings.extend(self._check_borrow_security(context))
            findings.extend(self._check_repay_security(context))
            findings.extend(self._check_liquidation_security(context))
            findings.extend(self._check_collateral_management(context))
            findings.extend(self._check_interest_rate_security(context))
            findings.extend(self._check_health_factor_calculation(context))
            findings.extend(self._check_ltv_validation(context))
            findings.extend(self._check_price_feed_dependency(context))
            findings.extend(self._check_compound_interest_accuracy(context))
            
            self.logger.info(f"Lending analysis completed with {len(findings)} findings")
            return findings
            
        except Exception as e:
            self.logger.error(f"Error in lending analysis: {str(e)}")
            return findings
    
    def _calculate_lending_metrics(self, context: AnalysisContext) -> LendingMetrics:
        """Calculate lending-specific metrics."""
        metrics = LendingMetrics()
        
        for functions in context.functions.values():
            for func in functions:
                func_name_lower = func.name.lower()
                
                # Count different function types
                if any(pattern.lower() in func_name_lower 
                      for pattern in self.lending_patterns['supply_functions']):
                    metrics.supply_functions += 1
                
                if any(pattern.lower() in func_name_lower 
                      for pattern in self.lending_patterns['borrow_functions']):
                    metrics.borrow_functions += 1
                
                if any(pattern.lower() in func_name_lower 
                      for pattern in self.lending_patterns['repay_functions']):
                    metrics.repay_functions += 1
                
                if any(pattern.lower() in func_name_lower 
                      for pattern in self.lending_patterns['liquidation_functions']):
                    metrics.liquidation_functions += 1
                
                # Check for health factor calculations
                if any(pattern in func.body.lower() 
                      for pattern in self.lending_patterns['health_patterns']):
                    metrics.health_factor_checks += 1
                
                # Check for LTV validations
                if 'ltv' in func.body.lower() or 'loan.*value' in func.body.lower():
                    metrics.ltv_validations += 1
        
        return metrics
    
    def _check_supply_security(self, context: AnalysisContext) -> List[Finding]:
        """Check supply/deposit function security."""
        findings = []
        
        for contract_name, functions in context.functions.items():
            for func in functions:
                if self._is_supply_function(func):
                    
                    # Check for minimum supply amount
                    if not self._validates_minimum_supply(func):
                        finding = self.create_finding(
                            title=f"Missing Minimum Supply Validation in {func.name}",
                            description=f"Supply function '{func.name}' doesn't validate minimum supply amount",
                            severity=Severity.LOW,
                            category=Category.INPUT_VALIDATION,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Add minimum supply amount validation",
                            impact="Dust attacks or inefficient small supplies possible"
                        )
                        findings.append(finding)
                    
                    # Check for supply cap validation
                    if not self._validates_supply_cap(func):
                        finding = self.create_finding(
                            title=f"Missing Supply Cap Validation in {func.name}",
                            description=f"Supply function '{func.name}' doesn't check supply caps",
                            severity=Severity.MEDIUM,
                            category=Category.DEFI_SPECIFIC,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Implement supply cap checks to prevent over-supply",
                            impact="Excessive supply could destabilize the protocol"
                        )
                        findings.append(finding)
                    
                    # Check for interest accrual before supply
                    if not self._accrues_interest_before_action(func):
                        finding = self.create_finding(
                            title=f"Missing Interest Accrual in {func.name}",
                            description=f"Supply function '{func.name}' doesn't accrue interest before action",
                            severity=Severity.MEDIUM,
                            category=Category.DEFI_SPECIFIC,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Accrue interest before supply operations",
                            impact="Inaccurate interest calculations"
                        )
                        findings.append(finding)
        
        return findings
    
    def _check_borrow_security(self, context: AnalysisContext) -> List[Finding]:
        """Check borrow function security."""
        findings = []
        
        for contract_name, functions in context.functions.items():
            for func in functions:
                if self._is_borrow_function(func):
                    
                    # Check for collateral validation
                    if not self._validates_collateral_before_borrow(func):
                        finding = self.create_finding(
                            title=f"Missing Collateral Validation in {func.name}",
                            description=f"Borrow function '{func.name}' doesn't validate sufficient collateral",
                            severity=Severity.CRITICAL,
                            category=Category.DEFI_SPECIFIC,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Validate collateral ratio before allowing borrows",
                            impact="Undercollateralized loans could lead to bad debt"
                        )
                        findings.append(finding)
                    
                    # Check for borrow cap validation
                    if not self._validates_borrow_cap(func):
                        finding = self.create_finding(
                            title=f"Missing Borrow Cap Validation in {func.name}",
                            description=f"Borrow function '{func.name}' doesn't check borrow caps",
                            severity=Severity.MEDIUM,
                            category=Category.DEFI_SPECIFIC,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Implement borrow cap checks",
                            impact="Excessive borrowing could drain protocol reserves"
                        )
                        findings.append(finding)
                    
                    # Check for market participation validation
                    if not self._validates_market_membership(func):
                        finding = self.create_finding(
                            title=f"Missing Market Membership Check in {func.name}",
                            description=f"Borrow function '{func.name}' doesn't check if user entered the market",
                            severity=Severity.HIGH,
                            category=Category.ACCESS_CONTROL,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Validate market membership before borrowing",
                            impact="Users could borrow without proper market participation"
                        )
                        findings.append(finding)
        
        return findings
    
    def _check_repay_security(self, context: AnalysisContext) -> List[Finding]:
        """Check repay function security."""
        findings = []
        
        for contract_name, functions in context.functions.items():
            for func in functions:
                if self._is_repay_function(func):
                    
                    # Check for repay amount validation
                    if not self._validates_repay_amount(func):
                        finding = self.create_finding(
                            title=f"Missing Repay Amount Validation in {func.name}",
                            description=f"Repay function '{func.name}' doesn't validate repay amounts",
                            severity=Severity.MEDIUM,
                            category=Category.INPUT_VALIDATION,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Validate repay amount doesn't exceed borrow balance",
                            impact="Over-repayment could cause accounting issues"
                        )
                        findings.append(finding)
                    
                    # Check for interest update before repay
                    if not self._accrues_interest_before_action(func):
                        finding = self.create_finding(
                            title=f"Missing Interest Update in {func.name}",
                            description=f"Repay function '{func.name}' doesn't update interest before repayment",
                            severity=Severity.MEDIUM,
                            category=Category.DEFI_SPECIFIC,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Update accrued interest before repayment",
                            impact="Inaccurate repayment calculations"
                        )
                        findings.append(finding)
        
        return findings
    
    def _check_liquidation_security(self, context: AnalysisContext) -> List[Finding]:
        """Check liquidation mechanism security."""
        findings = []
        
        for contract_name, functions in context.functions.items():
            for func in functions:
                if self._is_liquidation_function(func):
                    
                    # Check for liquidation threshold validation
                    if not self._validates_liquidation_threshold(func):
                        finding = self.create_finding(
                            title=f"Missing Liquidation Threshold Check in {func.name}",
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
                            recommendation="Validate account is eligible for liquidation",
                            impact="Healthy accounts could be liquidated incorrectly"
                        )
                        findings.append(finding)
                    
                    # Check for liquidation amount limits
                    if not self._validates_liquidation_amount(func):
                        finding = self.create_finding(
                            title=f"Missing Liquidation Amount Validation in {func.name}",
                            description=f"Liquidation function '{func.name}' doesn't validate liquidation amount",
                            severity=Severity.HIGH,
                            category=Category.DEFI_SPECIFIC,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Validate liquidation amount within acceptable limits",
                            impact="Excessive liquidation amounts could harm borrowers"
                        )
                        findings.append(finding)
                    
                    # Check for liquidation incentive calculation
                    if not self._calculates_liquidation_incentive(func):
                        finding = self.create_finding(
                            title=f"Missing Liquidation Incentive in {func.name}",
                            description=f"Liquidation function '{func.name}' doesn't calculate proper liquidation incentive",
                            severity=Severity.MEDIUM,
                            category=Category.DEFI_SPECIFIC,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Implement proper liquidation incentive calculation",
                            impact="Liquidators may lack proper incentives"
                        )
                        findings.append(finding)
        
        return findings
    
    def _check_collateral_management(self, context: AnalysisContext) -> List[Finding]:
        """Check collateral management security."""
        findings = []
        
        for contract_name, functions in context.functions.items():
            for func in functions:
                if self._manages_collateral(func):
                    
                    # Check for collateral factor validation
                    if not self._validates_collateral_factor(func):
                        finding = self.create_finding(
                            title=f"Missing Collateral Factor Validation in {func.name}",
                            description=f"Collateral function '{func.name}' doesn't validate collateral factors",
                            severity=Severity.HIGH,
                            category=Category.DEFI_SPECIFIC,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Validate collateral factors are within safe ranges",
                            impact="Unsafe collateral factors could lead to protocol insolvency"
                        )
                        findings.append(finding)
        
        return findings
    
    def _check_interest_rate_security(self, context: AnalysisContext) -> List[Finding]:
        """Check interest rate calculation security."""
        findings = []
        
        for contract_name, functions in context.functions.items():
            for func in functions:
                if self._calculates_interest_rates(func):
                    
                    # Check for interest rate bounds
                    if not self._validates_interest_rate_bounds(func):
                        finding = self.create_finding(
                            title=f"Missing Interest Rate Bounds in {func.name}",
                            description=f"Interest rate function '{func.name}' doesn't validate rate bounds",
                            severity=Severity.MEDIUM,
                            category=Category.DEFI_SPECIFIC,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Implement interest rate bounds validation",
                            impact="Extreme interest rates could break protocol economics"
                        )
                        findings.append(finding)
                    
                    # Check for utilization rate validation
                    if not self._validates_utilization_rate(func):
                        finding = self.create_finding(
                            title=f"Missing Utilization Rate Validation in {func.name}",
                            description=f"Interest function '{func.name}' doesn't validate utilization rates",
                            severity=Severity.LOW,
                            category=Category.INPUT_VALIDATION,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Validate utilization rate is within expected bounds",
                            impact="Invalid utilization rates could cause calculation errors"
                        )
                        findings.append(finding)
        
        return findings
    
    def _check_health_factor_calculation(self, context: AnalysisContext) -> List[Finding]:
        """Check health factor calculation accuracy."""
        findings = []
        
        for contract_name, functions in context.functions.items():
            for func in functions:
                if self._calculates_health_factor(func):
                    
                    # Check for division by zero protection
                    if not self._protects_health_factor_division(func):
                        finding = self.create_finding(
                            title=f"Health Factor Division by Zero Risk in {func.name}",
                            description=f"Health factor calculation in '{func.name}' doesn't protect against division by zero",
                            severity=Severity.HIGH,
                            category=Category.ARITHMETIC,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Add zero checks before division in health factor calculation",
                            impact="Division by zero could cause transaction reverts"
                        )
                        findings.append(finding)
                    
                    # Check for precision in health factor calculation
                    if not self._uses_precise_health_calculation(func):
                        finding = self.create_finding(
                            title=f"Health Factor Precision Issues in {func.name}",
                            description=f"Health factor calculation in '{func.name}' may have precision issues",
                            severity=Severity.MEDIUM,
                            category=Category.ARITHMETIC,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Use high precision arithmetic for health factor calculations",
                            impact="Inaccurate health factors could lead to incorrect liquidations"
                        )
                        findings.append(finding)
        
        return findings
    
    def _check_ltv_validation(self, context: AnalysisContext) -> List[Finding]:
        """Check Loan-to-Value ratio validation."""
        findings = []
        
        for contract_name, functions in context.functions.items():
            for func in functions:
                if self._uses_ltv_ratio(func):
                    
                    # Check for LTV bounds validation
                    if not self._validates_ltv_bounds(func):
                        finding = self.create_finding(
                            title=f"Missing LTV Bounds Validation in {func.name}",
                            description=f"Function '{func.name}' doesn't validate LTV ratio bounds",
                            severity=Severity.HIGH,
                            category=Category.DEFI_SPECIFIC,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Validate LTV ratios are within safe bounds (typically < 80%)",
                            impact="Unsafe LTV ratios could lead to protocol insolvency"
                        )
                        findings.append(finding)
        
        return findings
    
    def _check_price_feed_dependency(self, context: AnalysisContext) -> List[Finding]:
        """Check price feed dependencies specific to lending."""
        findings = []
        
        # Extend base oracle checks with lending-specific validations
        base_findings = super()._check_oracle_dependencies(context)
        findings.extend(base_findings)
        
        # Additional lending-specific price feed checks
        for contract_name, functions in context.functions.items():
            for func in functions:
                if self._uses_price_feeds_for_collateral(func):
                    
                    # Check for price feed heartbeat validation
                    if not self._validates_price_feed_heartbeat(func):
                        finding = self.create_finding(
                            title=f"Missing Price Feed Heartbeat Check in {func.name}",
                            description=f"Function '{func.name}' doesn't validate price feed heartbeat",
                            severity=Severity.MEDIUM,
                            category=Category.ORACLE_DEPENDENCY,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Validate price feed updates are within expected heartbeat",
                            impact="Stale prices could lead to incorrect liquidations"
                        )
                        findings.append(finding)
        
        return findings
    
    def _check_compound_interest_accuracy(self, context: AnalysisContext) -> List[Finding]:
        """Check compound interest calculation accuracy."""
        findings = []
        
        for contract_name, functions in context.functions.items():
            for func in functions:
                if self._compounds_interest(func):
                    
                    # Check for interest compounding frequency
                    if not self._has_appropriate_compounding_frequency(func):
                        finding = self.create_finding(
                            title=f"Interest Compounding Frequency Issues in {func.name}",
                            description=f"Interest compounding in '{func.name}' may have frequency issues",
                            severity=Severity.LOW,
                            category=Category.DEFI_SPECIFIC,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Ensure appropriate interest compounding frequency",
                            impact="Inaccurate interest accrual could affect protocol economics"
                        )
                        findings.append(finding)
        
        return findings
    
    # Helper methods for lending pattern detection
    
    def _is_supply_function(self, func: FunctionContext) -> bool:
        """Check if function is a supply/deposit function."""
        return any(pattern.lower() in func.name.lower() 
                  for pattern in self.lending_patterns['supply_functions'])
    
    def _is_borrow_function(self, func: FunctionContext) -> bool:
        """Check if function is a borrow function."""
        return any(pattern.lower() in func.name.lower() 
                  for pattern in self.lending_patterns['borrow_functions'])
    
    def _is_repay_function(self, func: FunctionContext) -> bool:
        """Check if function is a repay function."""
        return any(pattern.lower() in func.name.lower() 
                  for pattern in self.lending_patterns['repay_functions'])
    
    def _is_liquidation_function(self, func: FunctionContext) -> bool:
        """Check if function is a liquidation function."""
        return any(pattern.lower() in func.name.lower() 
                  for pattern in self.lending_patterns['liquidation_functions'])
    
    def _validates_minimum_supply(self, func: FunctionContext) -> bool:
        """Check if function validates minimum supply amounts."""
        validation_patterns = [
            r'require\s*\(\s*.*amount.*>\s*0',
            r'require\s*\(\s*.*amount.*>=.*MIN',
            r'minSupply',
            r'minimumAmount'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) 
                  for pattern in validation_patterns)
    
    def _validates_supply_cap(self, func: FunctionContext) -> bool:
        """Check if function validates supply caps."""
        cap_patterns = [
            r'supplyCap',
            r'maxSupply',
            r'require\s*\(\s*.*totalSupply.*<',
            r'supply.*limit'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) 
                  for pattern in cap_patterns)
    
    def _accrues_interest_before_action(self, func: FunctionContext) -> bool:
        """Check if function accrues interest before action."""
        accrual_patterns = [
            'accrueInterest',
            'updateInterest',
            'compound',
            'accrue'
        ]
        return any(pattern.lower() in func.body.lower() for pattern in accrual_patterns)
    
    def _validates_collateral_before_borrow(self, func: FunctionContext) -> bool:
        """Check if borrow function validates collateral."""
        validation_patterns = [
            r'require\s*\(\s*.*collateral',
            r'require\s*\(\s*.*healthFactor',
            r'accountLiquidity',
            r'borrowAllowed',
            r'checkCollateral'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) 
                  for pattern in validation_patterns)
    
    def _validates_borrow_cap(self, func: FunctionContext) -> bool:
        """Check if function validates borrow caps."""
        cap_patterns = [
            r'borrowCap',
            r'maxBorrow',
            r'require\s*\(\s*.*totalBorrows.*<',
            r'borrow.*limit'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) 
                  for pattern in cap_patterns)
    
    def _validates_market_membership(self, func: FunctionContext) -> bool:
        """Check if function validates market membership."""
        membership_patterns = [
            r'markets\s*\[.*\]\s*\.isListed',
            r'checkMembership',
            r'enterMarkets',
            r'accountAssets'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) 
                  for pattern in membership_patterns)
    
    def _validates_repay_amount(self, func: FunctionContext) -> bool:
        """Check if repay function validates amounts."""
        validation_patterns = [
            r'require\s*\(\s*.*repayAmount.*<=.*borrowBalance',
            r'require\s*\(\s*.*amount.*<=.*borrowed',
            r'maxRepay',
            r'borrowBalance'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) 
                  for pattern in validation_patterns)
    
    def _validates_liquidation_threshold(self, func: FunctionContext) -> bool:
        """Check if liquidation validates threshold."""
        threshold_patterns = [
            r'require\s*\(\s*.*healthFactor.*<',
            r'require\s*\(\s*.*shortfall.*>',
            r'liquidationThreshold',
            r'isLiquidatable'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) 
                  for pattern in threshold_patterns)
    
    def _validates_liquidation_amount(self, func: FunctionContext) -> bool:
        """Check if liquidation validates amount limits."""
        amount_patterns = [
            r'maxLiquidation',
            r'closeFactor',
            r'require\s*\(\s*.*repayAmount.*<=.*maxClose'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) 
                  for pattern in amount_patterns)
    
    def _calculates_liquidation_incentive(self, func: FunctionContext) -> bool:
        """Check if liquidation calculates incentive."""
        incentive_patterns = [
            'liquidationIncentive',
            'liquidatorReward',
            'bonus',
            'incentive'
        ]
        return any(pattern.lower() in func.body.lower() for pattern in incentive_patterns)
    
    def _manages_collateral(self, func: FunctionContext) -> bool:
        """Check if function manages collateral."""
        return any(pattern.lower() in func.name.lower() 
                  for pattern in self.lending_patterns['collateral_functions'])
    
    def _validates_collateral_factor(self, func: FunctionContext) -> bool:
        """Check if function validates collateral factors."""
        factor_patterns = [
            r'collateralFactor',
            r'require\s*\(\s*.*factor.*<=',
            r'ltv',
            r'loanToValue'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) 
                  for pattern in factor_patterns)
    
    def _calculates_interest_rates(self, func: FunctionContext) -> bool:
        """Check if function calculates interest rates."""
        return any(pattern in func.body.lower() 
                  for pattern in self.lending_patterns['interest_patterns'])
    
    def _validates_interest_rate_bounds(self, func: FunctionContext) -> bool:
        """Check if function validates interest rate bounds."""
        bounds_patterns = [
            r'require\s*\(\s*.*rate.*<=.*MAX',
            r'require\s*\(\s*.*rate.*<.*\d+',
            r'maxRate',
            r'rateLimit'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) 
                  for pattern in bounds_patterns)
    
    def _validates_utilization_rate(self, func: FunctionContext) -> bool:
        """Check if function validates utilization rates."""
        utilization_patterns = [
            r'require\s*\(\s*.*utilization.*<=',
            r'utilizationRate',
            r'utilization.*<=.*1e18'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) 
                  for pattern in utilization_patterns)
    
    def _calculates_health_factor(self, func: FunctionContext) -> bool:
        """Check if function calculates health factor."""
        return any(pattern in func.body.lower() 
                  for pattern in self.lending_patterns['health_patterns'])
    
    def _protects_health_factor_division(self, func: FunctionContext) -> bool:
        """Check if health factor calculation protects against division by zero."""
        protection_patterns = [
            r'require\s*\(\s*.*totalBorrow.*>.*0',
            r'require\s*\(\s*.*debt.*!=.*0',
            r'if\s*\(\s*.*borrow.*==.*0'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) 
                  for pattern in protection_patterns)
    
    def _uses_precise_health_calculation(self, func: FunctionContext) -> bool:
        """Check if health factor uses precise calculation."""
        precision_patterns = [
            r'1e18',
            r'PRECISION',
            r'WAD',
            r'RAY'
        ]
        return any(re.search(pattern, func.body) for pattern in precision_patterns)
    
    def _uses_ltv_ratio(self, func: FunctionContext) -> bool:
        """Check if function uses LTV ratio."""
        ltv_patterns = ['ltv', 'loanToValue', 'loan.*value']
        return any(re.search(pattern, func.body, re.IGNORECASE) 
                  for pattern in ltv_patterns)
    
    def _validates_ltv_bounds(self, func: FunctionContext) -> bool:
        """Check if function validates LTV bounds."""
        bounds_patterns = [
            r'require\s*\(\s*.*ltv.*<',
            r'require\s*\(\s*.*ltv.*<=.*80',
            r'MAX_LTV',
            r'ltvLimit'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) 
                  for pattern in bounds_patterns)
    
    def _uses_price_feeds_for_collateral(self, func: FunctionContext) -> bool:
        """Check if function uses price feeds for collateral valuation."""
        return (self._manages_collateral(func) or self._calculates_health_factor(func)) and \
               any(re.search(pattern, func.body, re.IGNORECASE) 
                   for pattern in self.patterns.ORACLE_PATTERNS)
    
    def _validates_price_feed_heartbeat(self, func: FunctionContext) -> bool:
        """Check if function validates price feed heartbeat."""
        heartbeat_patterns = [
            r'heartbeat',
            r'staleAfter',
            r'maxDelay',
            r'block\.timestamp.*-.*updatedAt.*<'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) 
                  for pattern in heartbeat_patterns)
    
    def _compounds_interest(self, func: FunctionContext) -> bool:
        """Check if function compounds interest."""
        compound_patterns = [
            'compound',
            'accrue',
            'interestIndex',
            'cumulativeInterest'
        ]
        return any(pattern.lower() in func.body.lower() for pattern in compound_patterns)
    
    def _has_appropriate_compounding_frequency(self, func: FunctionContext) -> bool:
        """Check if interest compounding has appropriate frequency."""
        frequency_patterns = [
            r'block\.timestamp.*-.*lastAccrual',
            r'timeElapsed',
            r'deltaTime',
            r'secondsElapsed'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) 
                  for pattern in frequency_patterns)
