"""
Oracle agent for analyzing DeFi oracle mechanisms and price feed security.
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
class OracleMetrics(DeFiMetrics):
    """Oracle-specific metrics extending DeFi metrics."""
    price_feed_functions: int = 0
    aggregator_functions: int = 0
    update_functions: int = 0
    validation_functions: int = 0
    fallback_mechanisms: int = 0
    heartbeat_checks: int = 0
    price_deviation_checks: int = 0
    multi_source_validations: int = 0


class OracleAgent(DeFiBaseAgent):
    """
    Specialized agent for analyzing oracle and price feed contracts.
    Focuses on price feeds, data validation, and oracle security.
    """
    
    def __init__(self, llm_client: Optional[LLMClient] = None,
                 prompt_manager: Optional[PromptManager] = None):
        super().__init__("OracleAgent", llm_client, prompt_manager)
        
        # Oracle-specific patterns
        self.oracle_patterns = {
            'price_functions': [
                'getPrice', 'latestAnswer', 'latestRoundData', 'getRoundData',
                'price', 'quote', 'rate', 'exchangeRate'
            ],
            'aggregator_functions': [
                'aggregator', 'feed', 'priceFeed', 'dataFeed'
            ],
            'update_functions': [
                'updatePrice', 'setPrice', 'submit', 'transmit', 'report'
            ],
            'validation_patterns': [
                'validate', 'check', 'verify', 'confirm', 'ensure'
            ],
            'staleness_patterns': [
                'stale', 'outdated', 'expired', 'heartbeat', 'updatedAt',
                'timestamp', 'lastUpdate'
            ],
            'deviation_patterns': [
                'deviation', 'threshold', 'bounds', 'min', 'max',
                'circuit', 'breaker'
            ],
            'fallback_patterns': [
                'fallback', 'backup', 'secondary', 'emergency', 'alternative'
            ]
        }
    
    def can_analyze(self, context: AnalysisContext) -> bool:
        """Check if this is an oracle contract."""
        if not super().can_analyze(context):
            return False
        
        code_lower = context.contract_code.lower()
        
        oracle_indicators = [
            'oracle', 'price', 'feed', 'aggregator', 'chainlink',
            'getprice', 'latestanswer', 'rounddata', 'pricefeed'
        ]
        
        matches = sum(1 for indicator in oracle_indicators if indicator in code_lower)
        return matches >= 3
    
    def analyze(self, context: AnalysisContext) -> List[Finding]:
        """
        Analyze oracle contract for security vulnerabilities.
        
        Args:
            context: Analysis context
            
        Returns:
            List[Finding]: Oracle-specific findings
        """
        self.logger.info("Starting oracle analysis")
        findings = []
        
        try:
            # Calculate oracle metrics
            metrics = self._calculate_oracle_metrics(context)
            
            # Core oracle security checks
            findings.extend(self._check_price_feed_security(context))
            findings.extend(self._check_staleness_protection(context))
            findings.extend(self._check_price_deviation_protection(context))
            findings.extend(self._check_oracle_manipulation_protection(context))
            findings.extend(self._check_fallback_mechanisms(context))
            findings.extend(self._check_multi_oracle_validation(context))
            findings.extend(self._check_oracle_access_control(context))
            findings.extend(self._check_price_update_security(context))
            findings.extend(self._check_circuit_breaker_mechanisms(context))
            findings.extend(self._check_oracle_governance(context))
            
            self.logger.info(f"Oracle analysis completed with {len(findings)} findings")
            return findings
            
        except Exception as e:
            self.logger.error(f"Error in oracle analysis: {str(e)}")
            return findings
    
    def _calculate_oracle_metrics(self, context: AnalysisContext) -> OracleMetrics:
        """Calculate oracle-specific metrics."""
        metrics = OracleMetrics()
        
        for functions in context.functions.values():
            for func in functions:
                func_name_lower = func.name.lower()
                
                # Count different function types
                if any(pattern.lower() in func_name_lower 
                      for pattern in self.oracle_patterns['price_functions']):
                    metrics.price_feed_functions += 1
                
                if any(pattern.lower() in func_name_lower 
                      for pattern in self.oracle_patterns['aggregator_functions']):
                    metrics.aggregator_functions += 1
                
                if any(pattern.lower() in func_name_lower 
                      for pattern in self.oracle_patterns['update_functions']):
                    metrics.update_functions += 1
                
                # Check for validation mechanisms
                if any(pattern in func.body.lower() 
                      for pattern in self.oracle_patterns['staleness_patterns']):
                    metrics.heartbeat_checks += 1
                
                if any(pattern in func.body.lower() 
                      for pattern in self.oracle_patterns['deviation_patterns']):
                    metrics.price_deviation_checks += 1
                
                if any(pattern in func.body.lower() 
                      for pattern in self.oracle_patterns['fallback_patterns']):
                    metrics.fallback_mechanisms += 1
        
        return metrics
    
    def _check_price_feed_security(self, context: AnalysisContext) -> List[Finding]:
        """Check price feed function security."""
        findings = []
        
        for contract_name, functions in context.functions.items():
            for func in functions:
                if self._is_price_feed_function(func):
                    
                    # Check for price validation
                    if not self._validates_price_data(func):
                        finding = self.create_finding(
                            title=f"Missing Price Validation in {func.name}",
                            description=f"Price feed function '{func.name}' doesn't validate price data",
                            severity=Severity.HIGH,
                            category=Category.ORACLE_DEPENDENCY,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Validate price data is positive and within reasonable bounds",
                            impact="Invalid price data could cause incorrect valuations"
                        )
                        findings.append(finding)
                    
                    # Check for round data validation
                    if self._returns_round_data(func) and not self._validates_round_data(func):
                        finding = self.create_finding(
                            title=f"Missing Round Data Validation in {func.name}",
                            description=f"Round data function '{func.name}' doesn't validate round information",
                            severity=Severity.MEDIUM,
                            category=Category.ORACLE_DEPENDENCY,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Validate round ID and timestamp data",
                            impact="Invalid round data could cause incorrect price interpretations"
                        )
                        findings.append(finding)
                    
                    # Check for decimals consistency
                    if not self._handles_decimals_properly(func):
                        finding = self.create_finding(
                            title=f"Missing Decimals Handling in {func.name}",
                            description=f"Price function '{func.name}' doesn't properly handle decimal places",
                            severity=Severity.MEDIUM,
                            category=Category.ARITHMETIC,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Ensure consistent decimal handling across price feeds",
                            impact="Decimal inconsistencies could cause pricing errors"
                        )
                        findings.append(finding)
        
        return findings
    
    def _check_staleness_protection(self, context: AnalysisContext) -> List[Finding]:
        """Check staleness protection mechanisms."""
        findings = []
        
        for contract_name, functions in context.functions.items():
            for func in functions:
                if self._consumes_price_data(func):
                    
                    # Check for staleness validation
                    if not self._validates_data_freshness(func):
                        finding = self.create_finding(
                            title=f"Missing Staleness Protection in {func.name}",
                            description=f"Function '{func.name}' doesn't validate data freshness",
                            severity=Severity.HIGH,
                            category=Category.ORACLE_DEPENDENCY,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Implement staleness checks with appropriate heartbeat validation",
                            impact="Stale price data could cause incorrect financial operations"
                        )
                        findings.append(finding)
                    
                    # Check for heartbeat configuration
                    if not self._has_heartbeat_configuration(func):
                        finding = self.create_finding(
                            title=f"Missing Heartbeat Configuration in {func.name}",
                            description=f"Function '{func.name}' doesn't configure appropriate heartbeat intervals",
                            severity=Severity.MEDIUM,
                            category=Category.ORACLE_DEPENDENCY,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Configure appropriate heartbeat intervals for each price feed",
                            impact="Inappropriate heartbeat settings could allow stale data usage"
                        )
                        findings.append(finding)
        
        return findings
    
    def _check_price_deviation_protection(self, context: AnalysisContext) -> List[Finding]:
        """Check price deviation protection mechanisms."""
        findings = []
        
        for contract_name, functions in context.functions.items():
            for func in functions:
                if self._consumes_price_data(func):
                    
                    # Check for price deviation limits
                    if not self._validates_price_deviation(func):
                        finding = self.create_finding(
                            title=f"Missing Price Deviation Protection in {func.name}",
                            description=f"Function '{func.name}' doesn't validate price deviations",
                            severity=Severity.MEDIUM,
                            category=Category.ORACLE_DEPENDENCY,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Implement price deviation checks to detect manipulation",
                            impact="Price manipulation could go undetected"
                        )
                        findings.append(finding)
                    
                    # Check for circuit breaker mechanisms
                    if not self._has_circuit_breaker(func):
                        finding = self.create_finding(
                            title=f"Missing Circuit Breaker in {func.name}",
                            description=f"Function '{func.name}' lacks circuit breaker for extreme price movements",
                            severity=Severity.MEDIUM,
                            category=Category.ORACLE_DEPENDENCY,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Implement circuit breakers for extreme price movements",
                            impact="Extreme price movements could cause system instability"
                        )
                        findings.append(finding)
        
        return findings
    
    def _check_oracle_manipulation_protection(self, context: AnalysisContext) -> List[Finding]:
        """Check oracle manipulation protection."""
        findings = []
        
        for contract_name, functions in context.functions.items():
            for func in functions:
                if self._vulnerable_to_manipulation(func):
                    
                    # Check for single oracle dependency
                    if self._relies_on_single_oracle(func):
                        finding = self.create_finding(
                            title=f"Single Oracle Dependency in {func.name}",
                            description=f"Function '{func.name}' relies on a single oracle source",
                            severity=Severity.HIGH,
                            category=Category.ORACLE_DEPENDENCY,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Use multiple oracle sources or implement fallback mechanisms",
                            impact="Single point of failure could be exploited for manipulation"
                        )
                        findings.append(finding)
                    
                    # Check for time-weighted average price (TWAP)
                    if not self._uses_twap_protection(func):
                        finding = self.create_finding(
                            title=f"Missing TWAP Protection in {func.name}",
                            description=f"Function '{func.name}' doesn't use time-weighted average prices",
                            severity=Severity.MEDIUM,
                            category=Category.ORACLE_DEPENDENCY,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Consider implementing TWAP to reduce manipulation risk",
                            impact="Spot price manipulation could affect protocol operations"
                        )
                        findings.append(finding)
        
        return findings
    
    def _check_fallback_mechanisms(self, context: AnalysisContext) -> List[Finding]:
        """Check fallback mechanism implementation."""
        findings = []
        
        # Check if fallback mechanisms exist
        has_fallback = False
        for functions in context.functions.values():
            for func in functions:
                if self._implements_fallback(func):
                    has_fallback = True
                    break
        
        if not has_fallback:
            finding = self.create_finding(
                title="Missing Oracle Fallback Mechanisms",
                description="Oracle contract lacks fallback mechanisms for oracle failures",
                severity=Severity.HIGH,
                category=Category.ORACLE_DEPENDENCY,
                recommendation="Implement fallback mechanisms for oracle failures",
                impact="Oracle failures could cause system breakdown"
            )
            findings.append(finding)
        else:
            for contract_name, functions in context.functions.items():
                for func in functions:
                    if self._implements_fallback(func):
                        
                        # Check fallback validation
                        if not self._validates_fallback_data(func):
                            finding = self.create_finding(
                                title=f"Missing Fallback Validation in {func.name}",
                                description=f"Fallback function '{func.name}' doesn't validate fallback data",
                                severity=Severity.MEDIUM,
                                category=Category.ORACLE_DEPENDENCY,
                                location=CodeLocation(
                                    contract_name=contract_name,
                                    function_name=func.name,
                                    line_number=func.line_number
                                ),
                                affected_contracts=[contract_name],
                                affected_functions=[func.name],
                                recommendation="Validate fallback data quality and freshness",
                                impact="Invalid fallback data could cause incorrect operations"
                            )
                            findings.append(finding)
        
        return findings
    
    def _check_multi_oracle_validation(self, context: AnalysisContext) -> List[Finding]:
        """Check multi-oracle validation mechanisms."""
        findings = []
        
        for contract_name, functions in context.functions.items():
            for func in functions:
                if self._uses_multiple_oracles(func):
                    
                    # Check for consensus mechanism
                    if not self._implements_consensus_mechanism(func):
                        finding = self.create_finding(
                            title=f"Missing Consensus Mechanism in {func.name}",
                            description=f"Multi-oracle function '{func.name}' lacks proper consensus mechanism",
                            severity=Severity.MEDIUM,
                            category=Category.ORACLE_DEPENDENCY,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Implement consensus mechanism for multiple oracle sources",
                            impact="Conflicting oracle data could cause inconsistent results"
                        )
                        findings.append(finding)
                    
                    # Check for outlier detection
                    if not self._detects_outliers(func):
                        finding = self.create_finding(
                            title=f"Missing Outlier Detection in {func.name}",
                            description=f"Multi-oracle function '{func.name}' doesn't detect outliers",
                            severity=Severity.LOW,
                            category=Category.ORACLE_DEPENDENCY,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Implement outlier detection for oracle aggregation",
                            impact="Outlier data could skew aggregated price results"
                        )
                        findings.append(finding)
        
        return findings
    
    def _check_oracle_access_control(self, context: AnalysisContext) -> List[Finding]:
        """Check oracle access control mechanisms."""
        findings = []
        
        for contract_name, functions in context.functions.items():
            for func in functions:
                if self._updates_oracle_data(func):
                    
                    # Check for update access control
                    if not self._has_update_access_control(func):
                        finding = self.create_finding(
                            title=f"Missing Update Access Control in {func.name}",
                            description=f"Oracle update function '{func.name}' lacks proper access control",
                            severity=Severity.CRITICAL,
                            category=Category.ACCESS_CONTROL,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Implement strict access controls for oracle updates",
                            impact="Unauthorized oracle updates could manipulate prices"
                        )
                        findings.append(finding)
        
        return findings
    
    def _check_price_update_security(self, context: AnalysisContext) -> List[Finding]:
        """Check price update mechanism security."""
        findings = []
        
        for contract_name, functions in context.functions.items():
            for func in functions:
                if self._updates_prices(func):
                    
                    # Check for update frequency limits
                    if not self._limits_update_frequency(func):
                        finding = self.create_finding(
                            title=f"Missing Update Frequency Limits in {func.name}",
                            description=f"Price update function '{func.name}' doesn't limit update frequency",
                            severity=Severity.LOW,
                            category=Category.ORACLE_DEPENDENCY,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Implement reasonable update frequency limits",
                            impact="Excessive updates could cause gas issues or manipulation"
                        )
                        findings.append(finding)
                    
                    # Check for price change validation
                    if not self._validates_price_changes(func):
                        finding = self.create_finding(
                            title=f"Missing Price Change Validation in {func.name}",
                            description=f"Price update function '{func.name}' doesn't validate price changes",
                            severity=Severity.MEDIUM,
                            category=Category.ORACLE_DEPENDENCY,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Validate price changes are within reasonable bounds",
                            impact="Extreme price changes could indicate manipulation"
                        )
                        findings.append(finding)
        
        return findings
    
    def _check_circuit_breaker_mechanisms(self, context: AnalysisContext) -> List[Finding]:
        """Check circuit breaker implementation."""
        findings = []
        
        has_circuit_breaker = False
        for functions in context.functions.values():
            for func in functions:
                if self._implements_circuit_breaker(func):
                    has_circuit_breaker = True
                    break
        
        if not has_circuit_breaker:
            finding = self.create_finding(
                title="Missing Circuit Breaker Mechanisms",
                description="Oracle system lacks circuit breaker mechanisms for extreme conditions",
                severity=Severity.MEDIUM,
                category=Category.ORACLE_DEPENDENCY,
                recommendation="Implement circuit breakers for extreme market conditions",
                impact="Extreme market conditions could cause system instability"
            )
            findings.append(finding)
        
        return findings
    
    def _check_oracle_governance(self, context: AnalysisContext) -> List[Finding]:
        """Check oracle governance mechanisms."""
        findings = []
        
        for contract_name, functions in context.functions.items():
            for func in functions:
                if self._manages_oracle_config(func):
                    
                    # Check for governance controls
                    if not self._has_governance_controls(func):
                        finding = self.create_finding(
                            title=f"Missing Governance Controls in {func.name}",
                            description=f"Oracle configuration function '{func.name}' lacks governance controls",
                            severity=Severity.HIGH,
                            category=Category.ACCESS_CONTROL,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Implement proper governance controls for oracle management",
                            impact="Unauthorized configuration changes could compromise oracle security"
                        )
                        findings.append(finding)
        
        return findings
    
    # Helper methods for oracle pattern detection
    
    def _is_price_feed_function(self, func: FunctionContext) -> bool:
        """Check if function provides price feeds."""
        return any(pattern.lower() in func.name.lower() 
                  for pattern in self.oracle_patterns['price_functions'])
    
    def _consumes_price_data(self, func: FunctionContext) -> bool:
        """Check if function consumes price data."""
        price_consumption_patterns = [
            'getPrice', 'latestAnswer', 'price', 'quote', 'rate'
        ]
        return any(pattern.lower() in func.body.lower() for pattern in price_consumption_patterns)
    
    def _updates_oracle_data(self, func: FunctionContext) -> bool:
        """Check if function updates oracle data."""
        return any(pattern.lower() in func.name.lower() 
                  for pattern in self.oracle_patterns['update_functions'])
    
    def _updates_prices(self, func: FunctionContext) -> bool:
        """Check if function updates prices."""
        return 'price' in func.name.lower() and any(
            update_pattern.lower() in func.name.lower() 
            for update_pattern in self.oracle_patterns['update_functions']
        )
    
    def _manages_oracle_config(self, func: FunctionContext) -> bool:
        """Check if function manages oracle configuration."""
        config_keywords = ['config', 'set', 'update', 'change', 'modify']
        oracle_keywords = ['oracle', 'feed', 'aggregator', 'source']
        
        return (any(config_kw in func.name.lower() for config_kw in config_keywords) and
                any(oracle_kw in func.name.lower() for oracle_kw in oracle_keywords))
    
    def _returns_round_data(self, func: FunctionContext) -> bool:
        """Check if function returns round data."""
        return 'round' in func.name.lower() and 'data' in func.name.lower()
    
    def _vulnerable_to_manipulation(self, func: FunctionContext) -> bool:
        """Check if function is vulnerable to manipulation."""
        return self._consumes_price_data(func) and 'price' in func.body.lower()
    
    def _uses_multiple_oracles(self, func: FunctionContext) -> bool:
        """Check if function uses multiple oracles."""
        multi_oracle_patterns = [
            'oracles', 'feeds', 'sources', 'aggregator', 'consensus'
        ]
        return any(pattern.lower() in func.body.lower() for pattern in multi_oracle_patterns)
    
    def _implements_fallback(self, func: FunctionContext) -> bool:
        """Check if function implements fallback."""
        return any(pattern in func.body.lower() 
                  for pattern in self.oracle_patterns['fallback_patterns'])
    
    def _implements_circuit_breaker(self, func: FunctionContext) -> bool:
        """Check if function implements circuit breaker."""
        circuit_patterns = ['circuit', 'breaker', 'emergency', 'halt', 'pause']
        return any(pattern.lower() in func.name.lower() or pattern.lower() in func.body.lower() 
                  for pattern in circuit_patterns)
    
    # Validation helper methods
    
    def _validates_price_data(self, func: FunctionContext) -> bool:
        """Check if price data is validated."""
        validation_patterns = [
            r'require\s*\(\s*.*price\s*>\s*0',
            r'require\s*\(\s*.*answer\s*>\s*0',
            r'validatePrice',
            r'checkPrice'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) 
                  for pattern in validation_patterns)
    
    def _validates_round_data(self, func: FunctionContext) -> bool:
        """Check if round data is validated."""
        validation_patterns = [
            r'require\s*\(\s*.*roundId\s*>\s*0',
            r'require\s*\(\s*.*updatedAt\s*>\s*0',
            r'validateRound',
            r'checkRound'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) 
                  for pattern in validation_patterns)
    
    def _handles_decimals_properly(self, func: FunctionContext) -> bool:
        """Check if decimals are handled properly."""
        decimal_patterns = [
            'decimals',
            '10**decimals',
            'scaleTo',
            'normalize'
        ]
        return any(pattern.lower() in func.body.lower() for pattern in decimal_patterns)
    
    def _validates_data_freshness(self, func: FunctionContext) -> bool:
        """Check if data freshness is validated."""
        freshness_patterns = [
            r'require\s*\(\s*block\.timestamp\s*-\s*.*updatedAt\s*<=\s*.*heartbeat',
            r'require\s*\(\s*.*timestamp\s*>\s*.*lastUpdate',
            r'checkFreshness',
            r'validateStaleness'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) 
                  for pattern in freshness_patterns)
    
    def _has_heartbeat_configuration(self, func: FunctionContext) -> bool:
        """Check if heartbeat is configured."""
        heartbeat_patterns = [
            'heartbeat',
            'maxStaleness',
            'stalenessThreshold',
            'updateInterval'
        ]
        return any(pattern.lower() in func.body.lower() for pattern in heartbeat_patterns)
    
    def _validates_price_deviation(self, func: FunctionContext) -> bool:
        """Check if price deviation is validated."""
        deviation_patterns = [
            r'require\s*\(\s*.*deviation\s*<=\s*.*threshold',
            r'require\s*\(\s*.*price\s*>=\s*.*minPrice',
            r'require\s*\(\s*.*price\s*<=\s*.*maxPrice',
            r'checkDeviation'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) 
                  for pattern in deviation_patterns)
    
    def _has_circuit_breaker(self, func: FunctionContext) -> bool:
        """Check if circuit breaker exists."""
        return any(pattern in func.body.lower() 
                  for pattern in self.oracle_patterns['deviation_patterns'])
    
    def _relies_on_single_oracle(self, func: FunctionContext) -> bool:
        """Check if function relies on single oracle."""
        # Simple heuristic: if only one oracle call and no fallback
        oracle_calls = len(re.findall(r'\.latestAnswer\(\)|\.getPrice\(\)', func.body))
        has_fallback = any(pattern in func.body.lower() 
                          for pattern in self.oracle_patterns['fallback_patterns'])
        
        return oracle_calls == 1 and not has_fallback
    
    def _uses_twap_protection(self, func: FunctionContext) -> bool:
        """Check if TWAP protection is used."""
        twap_patterns = [
            'twap',
            'timeWeighted',
            'average',
            'window',
            'period'
        ]
        return any(pattern.lower() in func.body.lower() for pattern in twap_patterns)
    
    def _validates_fallback_data(self, func: FunctionContext) -> bool:
        """Check if fallback data is validated."""
        validation_patterns = [
            r'require\s*\(\s*.*fallback.*>\s*0',
            r'validateFallback',
            r'checkBackup',
            r'verifySecondary'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) 
                  for pattern in validation_patterns)
    
    def _implements_consensus_mechanism(self, func: FunctionContext) -> bool:
        """Check if consensus mechanism is implemented."""
        consensus_patterns = [
            'consensus',
            'median',
            'majority',
            'aggregate',
            'combine'
        ]
        return any(pattern.lower() in func.body.lower() for pattern in consensus_patterns)
    
    def _detects_outliers(self, func: FunctionContext) -> bool:
        """Check if outlier detection is implemented."""
        outlier_patterns = [
            'outlier',
            'deviation',
            'threshold',
            'filter',
            'exclude'
        ]
        return any(pattern.lower() in func.body.lower() for pattern in outlier_patterns)
    
    def _has_update_access_control(self, func: FunctionContext) -> bool:
        """Check if update has access control."""
        access_patterns = [
            'onlyOracle',
            'onlyUpdater',
            'onlyTransmitter',
            'hasRole'
        ]
        return any(pattern in func.modifiers or pattern.lower() in func.body.lower() 
                  for pattern in access_patterns)
    
    def _limits_update_frequency(self, func: FunctionContext) -> bool:
        """Check if update frequency is limited."""
        frequency_patterns = [
            r'require\s*\(\s*block\.timestamp\s*-\s*.*lastUpdate\s*>=\s*.*minInterval',
            r'updateDelay',
            r'cooldown',
            r'minUpdateTime'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) 
                  for pattern in frequency_patterns)
    
    def _validates_price_changes(self, func: FunctionContext) -> bool:
        """Check if price changes are validated."""
        change_patterns = [
            r'require\s*\(\s*.*newPrice\s*<=\s*.*oldPrice\s*\*\s*.*maxIncrease',
            r'require\s*\(\s*.*change\s*<=\s*.*threshold',
            r'validateChange',
            r'checkPriceChange'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) 
                  for pattern in change_patterns)
    
    def _has_governance_controls(self, func: FunctionContext) -> bool:
        """Check if governance controls exist."""
        governance_patterns = [
            'onlyGovernance',
            'onlyOwner',
            'onlyAdmin',
            'requireGovernance'
        ]
        return any(pattern in func.modifiers or pattern.lower() in func.body.lower() 
                  for pattern in governance_patterns)
