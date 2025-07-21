"""
Yield Farming agent for analyzing DeFi yield farming and vault strategies.
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
class YieldFarmingMetrics(DeFiMetrics):
    """Yield farming-specific metrics extending DeFi metrics."""
    vault_functions: int = 0
    strategy_functions: int = 0
    harvest_functions: int = 0
    compound_functions: int = 0
    fee_functions: int = 0
    emergency_functions: int = 0
    rebalance_functions: int = 0
    auto_compound_checks: int = 0


class YieldFarmingAgent(DeFiBaseAgent):
    """
    Specialized agent for analyzing yield farming and vault strategy contracts.
    Focuses on vault mechanics, strategy execution, and yield optimization.
    """
    
    def __init__(self, llm_client: Optional[LLMClient] = None,
                 prompt_manager: Optional[PromptManager] = None):
        super().__init__("YieldFarmingAgent", llm_client, prompt_manager)
        
        # Yield farming-specific patterns
        self.farming_patterns = {
            'vault_functions': [
                'deposit', 'withdraw', 'mint', 'redeem', 'totalAssets',
                'previewDeposit', 'previewWithdraw'
            ],
            'strategy_functions': [
                'harvest', 'compound', 'rebalance', 'execute', 'allocate'
            ],
            'yield_patterns': [
                'apy', 'yield', 'earn', 'profit', 'return', 'performance'
            ],
            'fee_patterns': [
                'managementFee', 'performanceFee', 'withdrawalFee',
                'depositFee', 'harvestFee'
            ],
            'emergency_patterns': [
                'emergency', 'pause', 'panic', 'rescue', 'recover'
            ],
            'auto_compound_patterns': [
                'autoCompound', 'reinvest', 'compound', 'rebalance'
            ]
        }
    
    def can_analyze(self, context: AnalysisContext) -> bool:
        """Check if this is a yield farming contract."""
        if not super().can_analyze(context):
            return False
        
        code_lower = context.contract_code.lower()
        
        farming_indicators = [
            'vault', 'strategy', 'harvest', 'yield', 'farm',
            'compound', 'reinvest', 'apy', 'performance'
        ]
        
        matches = sum(1 for indicator in farming_indicators if indicator in code_lower)
        return matches >= 3
    
    def analyze(self, context: AnalysisContext) -> List[Finding]:
        """
        Analyze yield farming contract for security vulnerabilities.
        
        Args:
            context: Analysis context
            
        Returns:
            List[Finding]: Yield farming-specific findings
        """
        self.logger.info("Starting yield farming analysis")
        findings = []
        
        try:
            # Calculate yield farming metrics
            metrics = self._calculate_farming_metrics(context)
            
            # Core yield farming security checks
            findings.extend(self._check_vault_security(context))
            findings.extend(self._check_strategy_security(context))
            findings.extend(self._check_harvest_security(context))
            findings.extend(self._check_fee_calculation(context))
            findings.extend(self._check_emergency_mechanisms(context))
            findings.extend(self._check_auto_compound_security(context))
            findings.extend(self._check_slippage_protection(context))
            findings.extend(self._check_yield_calculation(context))
            findings.extend(self._check_rebalancing_security(context))
            findings.extend(self._check_share_price_manipulation(context))
            
            self.logger.info(f"Yield farming analysis completed with {len(findings)} findings")
            return findings
            
        except Exception as e:
            self.logger.error(f"Error in yield farming analysis: {str(e)}")
            return findings
    
    def _calculate_farming_metrics(self, context: AnalysisContext) -> YieldFarmingMetrics:
        """Calculate yield farming-specific metrics."""
        metrics = YieldFarmingMetrics()
        
        for functions in context.functions.values():
            for func in functions:
                func_name_lower = func.name.lower()
                
                # Count different function types
                if any(pattern.lower() in func_name_lower 
                      for pattern in self.farming_patterns['vault_functions']):
                    metrics.vault_functions += 1
                
                if any(pattern.lower() in func_name_lower 
                      for pattern in self.farming_patterns['strategy_functions']):
                    metrics.strategy_functions += 1
                
                if 'harvest' in func_name_lower:
                    metrics.harvest_functions += 1
                
                if 'compound' in func_name_lower:
                    metrics.compound_functions += 1
                
                # Check for emergency mechanisms
                if any(pattern in func.body.lower() 
                      for pattern in self.farming_patterns['emergency_patterns']):
                    metrics.emergency_functions += 1
                
                # Check for auto-compound features
                if any(pattern in func.body.lower() 
                      for pattern in self.farming_patterns['auto_compound_patterns']):
                    metrics.auto_compound_checks += 1
        
        return metrics
    
    def _check_vault_security(self, context: AnalysisContext) -> List[Finding]:
        """Check vault function security."""
        findings = []
        
        for contract_name, functions in context.functions.items():
            for func in functions:
                if self._is_vault_function(func):
                    
                    # Check for deposit limit validation
                    if 'deposit' in func.name.lower() and not self._validates_deposit_limits(func):
                        finding = self.create_finding(
                            title=f"Missing Deposit Limit Validation in {func.name}",
                            description=f"Vault deposit function '{func.name}' doesn't validate deposit limits",
                            severity=Severity.MEDIUM,
                            category=Category.DEFI_SPECIFIC,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Implement deposit limits to prevent excessive concentration",
                            impact="Large deposits could destabilize vault strategy"
                        )
                        findings.append(finding)
                    
                    # Check for share calculation accuracy
                    if self._calculates_shares(func) and not self._accurate_share_calculation(func):
                        finding = self.create_finding(
                            title=f"Inaccurate Share Calculation in {func.name}",
                            description=f"Share calculation in '{func.name}' may be inaccurate",
                            severity=Severity.HIGH,
                            category=Category.ARITHMETIC,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Ensure accurate share-to-asset ratio calculations",
                            impact="Incorrect shares could lead to unfair value distribution"
                        )
                        findings.append(finding)
                    
                    # Check for withdrawal queue management
                    if 'withdraw' in func.name.lower() and not self._manages_withdrawal_queue(func):
                        finding = self.create_finding(
                            title=f"Missing Withdrawal Queue Management in {func.name}",
                            description=f"Withdrawal function '{func.name}' doesn't manage withdrawal queues properly",
                            severity=Severity.MEDIUM,
                            category=Category.DEFI_SPECIFIC,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Implement proper withdrawal queue management",
                            impact="Large withdrawals could cause liquidity issues"
                        )
                        findings.append(finding)
        
        return findings
    
    def _check_strategy_security(self, context: AnalysisContext) -> List[Finding]:
        """Check strategy execution security."""
        findings = []
        
        for contract_name, functions in context.functions.items():
            for func in functions:
                if self._is_strategy_function(func):
                    
                    # Check for strategy validation
                    if not self._validates_strategy_parameters(func):
                        finding = self.create_finding(
                            title=f"Missing Strategy Parameter Validation in {func.name}",
                            description=f"Strategy function '{func.name}' doesn't validate strategy parameters",
                            severity=Severity.HIGH,
                            category=Category.INPUT_VALIDATION,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Validate all strategy parameters before execution",
                            impact="Invalid strategy parameters could cause losses"
                        )
                        findings.append(finding)
                    
                    # Check for strategy access control
                    if not self._has_strategy_access_control(func):
                        finding = self.create_finding(
                            title=f"Missing Strategy Access Control in {func.name}",
                            description=f"Strategy function '{func.name}' lacks proper access control",
                            severity=Severity.CRITICAL,
                            category=Category.ACCESS_CONTROL,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Implement strict access controls for strategy functions",
                            impact="Unauthorized strategy execution could drain vault funds"
                        )
                        findings.append(finding)
                    
                    # Check for strategy failure handling
                    if not self._handles_strategy_failures(func):
                        finding = self.create_finding(
                            title=f"Missing Strategy Failure Handling in {func.name}",
                            description=f"Strategy function '{func.name}' doesn't handle execution failures",
                            severity=Severity.MEDIUM,
                            category=Category.ERROR_HANDLING,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Implement proper error handling for strategy failures",
                            impact="Strategy failures could lock funds or cause unexpected behavior"
                        )
                        findings.append(finding)
        
        return findings
    
    def _check_harvest_security(self, context: AnalysisContext) -> List[Finding]:
        """Check harvest function security."""
        findings = []
        
        for contract_name, functions in context.functions.items():
            for func in functions:
                if self._is_harvest_function(func):
                    
                    # Check for harvest timing validation
                    if not self._validates_harvest_timing(func):
                        finding = self.create_finding(
                            title=f"Missing Harvest Timing Validation in {func.name}",
                            description=f"Harvest function '{func.name}' doesn't validate harvest timing",
                            severity=Severity.LOW,
                            category=Category.DEFI_SPECIFIC,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Implement harvest timing validation to prevent excessive calls",
                            impact="Frequent harvesting could reduce yield efficiency"
                        )
                        findings.append(finding)
                    
                    # Check for harvest reward validation
                    if not self._validates_harvest_rewards(func):
                        finding = self.create_finding(
                            title=f"Missing Harvest Reward Validation in {func.name}",
                            description=f"Harvest function '{func.name}' doesn't validate reward amounts",
                            severity=Severity.MEDIUM,
                            category=Category.INPUT_VALIDATION,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Validate harvest reward amounts before processing",
                            impact="Invalid reward amounts could affect yield calculations"
                        )
                        findings.append(finding)
                    
                    # Check for MEV protection in harvest
                    if not self._has_harvest_mev_protection(func):
                        finding = self.create_finding(
                            title=f"Missing MEV Protection in {func.name}",
                            description=f"Harvest function '{func.name}' vulnerable to MEV extraction",
                            severity=Severity.MEDIUM,
                            category=Category.MEV_PROTECTION,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Implement MEV protection mechanisms for harvest operations",
                            impact="MEV bots could extract value from harvest operations"
                        )
                        findings.append(finding)
        
        return findings
    
    def _check_fee_calculation(self, context: AnalysisContext) -> List[Finding]:
        """Check fee calculation security."""
        findings = []
        
        for contract_name, functions in context.functions.items():
            for func in functions:
                if self._calculates_fees(func):
                    
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
                            recommendation="Implement maximum fee limits to protect users",
                            impact="Excessive fees could harm vault participants"
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
                            recommendation="Ensure accurate fee calculations using proper precision",
                            impact="Incorrect fees could affect vault economics"
                        )
                        findings.append(finding)
        
        return findings
    
    def _check_emergency_mechanisms(self, context: AnalysisContext) -> List[Finding]:
        """Check emergency mechanism security."""
        findings = []
        
        has_emergency_functions = False
        for functions in context.functions.values():
            for func in functions:
                if self._is_emergency_function(func):
                    has_emergency_functions = True
                    break
        
        if not has_emergency_functions:
            finding = self.create_finding(
                title="Missing Emergency Mechanisms",
                description="Vault contract lacks emergency pause/recovery mechanisms",
                severity=Severity.MEDIUM,
                category=Category.ACCESS_CONTROL,
                recommendation="Implement emergency pause and recovery functions",
                impact="No way to handle emergency situations or contract issues"
            )
            findings.append(finding)
        else:
            for contract_name, functions in context.functions.items():
                for func in functions:
                    if self._is_emergency_function(func):
                        
                        # Check for emergency access control
                        if not self._has_emergency_access_control(func):
                            finding = self.create_finding(
                                title=f"Missing Emergency Access Control in {func.name}",
                                description=f"Emergency function '{func.name}' lacks proper access control",
                                severity=Severity.HIGH,
                                category=Category.ACCESS_CONTROL,
                                location=CodeLocation(
                                    contract_name=contract_name,
                                    function_name=func.name,
                                    line_number=func.line_number
                                ),
                                affected_contracts=[contract_name],
                                affected_functions=[func.name],
                                recommendation="Implement strict access controls for emergency functions",
                                impact="Unauthorized emergency actions could disrupt vault operations"
                            )
                            findings.append(finding)
        
        return findings
    
    def _check_auto_compound_security(self, context: AnalysisContext) -> List[Finding]:
        """Check auto-compound mechanism security."""
        findings = []
        
        for contract_name, functions in context.functions.items():
            for func in functions:
                if self._implements_auto_compound(func):
                    
                    # Check for compound frequency limits
                    if not self._validates_compound_frequency(func):
                        finding = self.create_finding(
                            title=f"Missing Compound Frequency Validation in {func.name}",
                            description=f"Auto-compound function '{func.name}' doesn't validate compound frequency",
                            severity=Severity.LOW,
                            category=Category.DEFI_SPECIFIC,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Implement compound frequency limits to optimize gas efficiency",
                            impact="Excessive compounding could waste gas and reduce yields"
                        )
                        findings.append(finding)
                    
                    # Check for compound slippage protection
                    if not self._has_compound_slippage_protection(func):
                        finding = self.create_finding(
                            title=f"Missing Compound Slippage Protection in {func.name}",
                            description=f"Auto-compound function '{func.name}' lacks slippage protection",
                            severity=Severity.MEDIUM,
                            category=Category.DEFI_SPECIFIC,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Implement slippage protection for compound operations",
                            impact="High slippage during compounding could reduce yields"
                        )
                        findings.append(finding)
        
        return findings
    
    def _check_yield_calculation(self, context: AnalysisContext) -> List[Finding]:
        """Check yield calculation accuracy."""
        findings = []
        
        for contract_name, functions in context.functions.items():
            for func in functions:
                if self._calculates_yield(func):
                    
                    # Check for yield calculation precision
                    if not self._uses_precise_yield_calculation(func):
                        finding = self.create_finding(
                            title=f"Yield Calculation Precision Issues in {func.name}",
                            description=f"Yield calculation in '{func.name}' may have precision issues",
                            severity=Severity.MEDIUM,
                            category=Category.ARITHMETIC,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Use high precision arithmetic for yield calculations",
                            impact="Precision errors could lead to incorrect yield reporting"
                        )
                        findings.append(finding)
                    
                    # Check for time-weighted yield calculations
                    if not self._uses_time_weighted_calculations(func):
                        finding = self.create_finding(
                            title=f"Missing Time-Weighted Yield Calculation in {func.name}",
                            description=f"Yield calculation in '{func.name}' doesn't account for time weighting",
                            severity=Severity.LOW,
                            category=Category.DEFI_SPECIFIC,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Implement time-weighted yield calculations for accuracy",
                            impact="Yield calculations may not reflect actual performance over time"
                        )
                        findings.append(finding)
        
        return findings
    
    def _check_rebalancing_security(self, context: AnalysisContext) -> List[Finding]:
        """Check rebalancing mechanism security."""
        findings = []
        
        for contract_name, functions in context.functions.items():
            for func in functions:
                if self._implements_rebalancing(func):
                    
                    # Check for rebalance triggers
                    if not self._validates_rebalance_triggers(func):
                        finding = self.create_finding(
                            title=f"Missing Rebalance Trigger Validation in {func.name}",
                            description=f"Rebalance function '{func.name}' doesn't validate rebalance triggers",
                            severity=Severity.MEDIUM,
                            category=Category.DEFI_SPECIFIC,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Implement proper rebalance trigger validation",
                            impact="Unnecessary rebalancing could increase costs and reduce yields"
                        )
                        findings.append(finding)
                    
                    # Check for rebalance slippage protection
                    if not self._has_rebalance_slippage_protection(func):
                        finding = self.create_finding(
                            title=f"Missing Rebalance Slippage Protection in {func.name}",
                            description=f"Rebalance function '{func.name}' lacks slippage protection",
                            severity=Severity.MEDIUM,
                            category=Category.DEFI_SPECIFIC,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Implement slippage protection for rebalancing operations",
                            impact="High slippage during rebalancing could reduce vault performance"
                        )
                        findings.append(finding)
        
        return findings
    
    def _check_share_price_manipulation(self, context: AnalysisContext) -> List[Finding]:
        """Check for share price manipulation vulnerabilities."""
        findings = []
        
        for contract_name, functions in context.functions.items():
            for func in functions:
                if self._affects_share_price(func):
                    
                    # Check for first depositor attack protection
                    if 'deposit' in func.name.lower() and not self._protects_against_first_depositor_attack(func):
                        finding = self.create_finding(
                            title=f"First Depositor Attack Vulnerability in {func.name}",
                            description=f"Deposit function '{func.name}' vulnerable to first depositor attack",
                            severity=Severity.HIGH,
                            category=Category.DEFI_SPECIFIC,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Implement minimum share price or virtual shares protection",
                            impact="First depositor could manipulate share price to steal funds"
                        )
                        findings.append(finding)
                    
                    # Check for share inflation attacks
                    if not self._protects_against_share_inflation(func):
                        finding = self.create_finding(
                            title=f"Share Inflation Attack Risk in {func.name}",
                            description=f"Function '{func.name}' may be vulnerable to share inflation attacks",
                            severity=Severity.MEDIUM,
                            category=Category.DEFI_SPECIFIC,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Implement protection against share inflation attacks",
                            impact="Attackers could manipulate share prices to steal value"
                        )
                        findings.append(finding)
        
        return findings
    
    # Helper methods for yield farming pattern detection
    
    def _is_vault_function(self, func: FunctionContext) -> bool:
        """Check if function is a vault function."""
        return any(pattern.lower() in func.name.lower() 
                  for pattern in self.farming_patterns['vault_functions'])
    
    def _is_strategy_function(self, func: FunctionContext) -> bool:
        """Check if function is a strategy function."""
        return any(pattern.lower() in func.name.lower() 
                  for pattern in self.farming_patterns['strategy_functions'])
    
    def _is_harvest_function(self, func: FunctionContext) -> bool:
        """Check if function is a harvest function."""
        return 'harvest' in func.name.lower()
    
    def _is_emergency_function(self, func: FunctionContext) -> bool:
        """Check if function is an emergency function."""
        return any(pattern in func.name.lower() 
                  for pattern in self.farming_patterns['emergency_patterns'])
    
    def _validates_deposit_limits(self, func: FunctionContext) -> bool:
        """Check if function validates deposit limits."""
        limit_patterns = [
            r'require\s*\(\s*.*amount.*<=.*maxDeposit',
            r'require\s*\(\s*.*totalAssets.*<=.*depositCap',
            r'depositLimit',
            r'maxDeposit'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) 
                  for pattern in limit_patterns)
    
    def _calculates_shares(self, func: FunctionContext) -> bool:
        """Check if function calculates shares."""
        share_patterns = ['shares', 'mint', 'convertTo', 'previewDeposit']
        return any(pattern.lower() in func.body.lower() for pattern in share_patterns)
    
    def _accurate_share_calculation(self, func: FunctionContext) -> bool:
        """Check if share calculation is accurate."""
        accuracy_patterns = [
            r'shares\s*=\s*.*assets.*\*.*totalSupply.*\/.*totalAssets',
            r'convertToShares',
            r'previewDeposit'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) 
                  for pattern in accuracy_patterns)
    
    def _manages_withdrawal_queue(self, func: FunctionContext) -> bool:
        """Check if function manages withdrawal queues."""
        queue_patterns = [
            'withdrawalQueue',
            'queue',
            'requestWithdrawal',
            'claimWithdrawal'
        ]
        return any(pattern.lower() in func.body.lower() for pattern in queue_patterns)
    
    def _validates_strategy_parameters(self, func: FunctionContext) -> bool:
        """Check if strategy parameters are validated."""
        validation_patterns = [
            r'require\s*\(\s*.*strategy.*!=.*address\(0\)',
            r'require\s*\(\s*.*allocation.*<=.*100',
            r'validateStrategy',
            r'strategyParams'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) 
                  for pattern in validation_patterns)
    
    def _has_strategy_access_control(self, func: FunctionContext) -> bool:
        """Check if strategy has access control."""
        access_patterns = [
            'onlyManager',
            'onlyKeeper',
            'onlyStrategist',
            'onlyGovernance'
        ]
        return any(pattern in func.modifiers or pattern.lower() in func.body.lower() 
                  for pattern in access_patterns)
    
    def _handles_strategy_failures(self, func: FunctionContext) -> bool:
        """Check if strategy failures are handled."""
        error_patterns = [
            'try',
            'catch',
            'revert',
            r'require\s*\(\s*success'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) 
                  for pattern in error_patterns)
    
    def _validates_harvest_timing(self, func: FunctionContext) -> bool:
        """Check if harvest timing is validated."""
        timing_patterns = [
            r'require\s*\(\s*.*lastHarvest.*\+.*harvestDelay',
            r'require\s*\(\s*block\.timestamp.*>.*lastHarvest',
            r'harvestCooldown',
            r'minHarvestDelay'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) 
                  for pattern in timing_patterns)
    
    def _validates_harvest_rewards(self, func: FunctionContext) -> bool:
        """Check if harvest rewards are validated."""
        validation_patterns = [
            r'require\s*\(\s*.*rewards.*>.*0',
            r'require\s*\(\s*.*profit.*>=.*minProfit',
            r'minHarvestAmount',
            r'profitThreshold'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) 
                  for pattern in validation_patterns)
    
    def _has_harvest_mev_protection(self, func: FunctionContext) -> bool:
        """Check if harvest has MEV protection."""
        mev_patterns = [
            'deadline',
            'minAmountOut',
            'slippageProtection',
            'private'
        ]
        return any(pattern.lower() in func.body.lower() for pattern in mev_patterns)
    
    def _calculates_fees(self, func: FunctionContext) -> bool:
        """Check if function calculates fees."""
        return any(pattern in func.body.lower() 
                  for pattern in self.farming_patterns['fee_patterns'])
    
    def _validates_fee_bounds(self, func: FunctionContext) -> bool:
        """Check if fee bounds are validated."""
        bounds_patterns = [
            r'require\s*\(\s*.*fee.*<=.*MAX_FEE',
            r'require\s*\(\s*.*fee.*<.*10000',
            r'maxFee',
            r'FEE_MAX'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) 
                  for pattern in bounds_patterns)
    
    def _accurate_fee_calculation(self, func: FunctionContext) -> bool:
        """Check if fee calculation is accurate."""
        accuracy_patterns = [
            r'fee.*=.*amount.*\*.*feeRate.*\/.*10000',
            r'mulDiv',
            r'precision',
            r'BASIS_POINTS'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) 
                  for pattern in accuracy_patterns)
    
    def _has_emergency_access_control(self, func: FunctionContext) -> bool:
        """Check if emergency functions have access control."""
        access_patterns = [
            'onlyEmergency',
            'onlyGovernance',
            'onlyGuardian',
            'emergencyRole'
        ]
        return any(pattern in func.modifiers or pattern.lower() in func.body.lower() 
                  for pattern in access_patterns)
    
    def _implements_auto_compound(self, func: FunctionContext) -> bool:
        """Check if function implements auto-compound."""
        return any(pattern in func.body.lower() 
                  for pattern in self.farming_patterns['auto_compound_patterns'])
    
    def _validates_compound_frequency(self, func: FunctionContext) -> bool:
        """Check if compound frequency is validated."""
        frequency_patterns = [
            r'require\s*\(\s*.*lastCompound.*\+.*compoundDelay',
            r'compoundCooldown',
            r'minCompoundDelay'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) 
                  for pattern in frequency_patterns)
    
    def _has_compound_slippage_protection(self, func: FunctionContext) -> bool:
        """Check if compound has slippage protection."""
        slippage_patterns = [
            'minAmountOut',
            'slippageTolerance',
            'maxSlippage'
        ]
        return any(pattern.lower() in func.body.lower() for pattern in slippage_patterns)
    
    def _calculates_yield(self, func: FunctionContext) -> bool:
        """Check if function calculates yield."""
        return any(pattern in func.body.lower() 
                  for pattern in self.farming_patterns['yield_patterns'])
    
    def _uses_precise_yield_calculation(self, func: FunctionContext) -> bool:
        """Check if yield calculation uses high precision."""
        precision_patterns = [
            r'1e18',
            r'PRECISION',
            r'WAD',
            r'RAY'
        ]
        return any(re.search(pattern, func.body) for pattern in precision_patterns)
    
    def _uses_time_weighted_calculations(self, func: FunctionContext) -> bool:
        """Check if yield calculations are time-weighted."""
        time_patterns = [
            'timeWeighted',
            'duration',
            'elapsed',
            'block.timestamp'
        ]
        return any(pattern.lower() in func.body.lower() for pattern in time_patterns)
    
    def _implements_rebalancing(self, func: FunctionContext) -> bool:
        """Check if function implements rebalancing."""
        return 'rebalance' in func.name.lower()
    
    def _validates_rebalance_triggers(self, func: FunctionContext) -> bool:
        """Check if rebalance triggers are validated."""
        trigger_patterns = [
            r'require\s*\(\s*.*deviation.*>.*threshold',
            r'rebalanceThreshold',
            r'needsRebalance'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) 
                  for pattern in trigger_patterns)
    
    def _has_rebalance_slippage_protection(self, func: FunctionContext) -> bool:
        """Check if rebalance has slippage protection."""
        slippage_patterns = [
            'minAmountOut',
            'maxSlippage',
            'slippageProtection'
        ]
        return any(pattern.lower() in func.body.lower() for pattern in slippage_patterns)
    
    def _affects_share_price(self, func: FunctionContext) -> bool:
        """Check if function affects share price."""
        price_affecting = ['deposit', 'withdraw', 'mint', 'redeem', 'harvest']
        return any(keyword in func.name.lower() for keyword in price_affecting)
    
    def _protects_against_first_depositor_attack(self, func: FunctionContext) -> bool:
        """Check if protected against first depositor attack."""
        protection_patterns = [
            r'require\s*\(\s*.*totalSupply.*>.*0',
            r'MINIMUM_SHARES',
            r'virtualShares',
            r'DEAD_SHARES'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) 
                  for pattern in protection_patterns)
    
    def _protects_against_share_inflation(self, func: FunctionContext) -> bool:
        """Check if protected against share inflation attacks."""
        protection_patterns = [
            'virtualShares',
            'MINIMUM_LIQUIDITY',
            'inflationProtection'
        ]
        return any(pattern.lower() in func.body.lower() for pattern in protection_patterns)
