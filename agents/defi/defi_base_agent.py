"""
Base agent for DeFi (Decentralized Finance) smart contract analysis.
Provides common functionality for all DeFi-specific agents.
"""

import re
import logging
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass
from enum import Enum

from ..base_agent import BaseAgent, AgentMetadata, AgentType
from ...models.context import AnalysisContext, FunctionContext
from ...models.finding import Finding, Severity, Category, CodeLocation
from ...llm.client import LLMClient
from ...llm.prompts import PromptManager

logger = logging.getLogger(__name__)


class DeFiProtocol(Enum):
    """Supported DeFi protocols."""
    UNISWAP_V2 = "uniswap_v2"
    UNISWAP_V3 = "uniswap_v3"
    SUSHISWAP = "sushiswap"
    PANCAKESWAP = "pancakeswap"
    CURVE = "curve"
    BALANCER = "balancer"
    AAVE_V2 = "aave_v2"
    AAVE_V3 = "aave_v3"
    COMPOUND = "compound"
    MAKERDAO = "makerdao"
    YEARN = "yearn"
    CONVEX = "convex"
    SYNTHETIX = "synthetix"
    CHAINLINK = "chainlink"
    UNKNOWN = "unknown"


@dataclass
class DeFiMetrics:
    """DeFi-specific metrics."""
    total_value_locked_functions: int = 0
    price_manipulation_risks: int = 0
    flash_loan_vulnerabilities: int = 0
    oracle_dependencies: int = 0
    liquidity_risks: int = 0
    slippage_protections: int = 0
    reentrancy_risks: int = 0
    
    def to_dict(self) -> Dict[str, int]:
        """Convert metrics to dictionary."""
        return {
            'total_value_locked_functions': self.total_value_locked_functions,
            'price_manipulation_risks': self.price_manipulation_risks,
            'flash_loan_vulnerabilities': self.flash_loan_vulnerabilities,
            'oracle_dependencies': self.oracle_dependencies,
            'liquidity_risks': self.liquidity_risks,
            'slippage_protections': self.slippage_protections,
            'reentrancy_risks': self.reentrancy_risks
        }


@dataclass
class DeFiPatterns:
    """Common DeFi patterns for detection and analysis."""
    
    # Price and value patterns
    PRICE_PATTERNS = [
        r'price\s*\(',
        r'getPrice\s*\(',
        r'latestAnswer\s*\(',
        r'latestRoundData\s*\(',
        r'exchangeRate\s*\(',
        r'getAmountsOut\s*\(',
        r'getAmountsIn\s*\(',
        r'quote\s*\('
    ]
    
    # Liquidity patterns
    LIQUIDITY_PATTERNS = [
        r'addLiquidity\s*\(',
        r'removeLiquidity\s*\(',
        r'mint\s*\(',
        r'burn\s*\(',
        r'totalSupply\s*\(',
        r'balanceOf\s*\(',
        r'reserve\w*\s*\('
    ]
    
    # Token transfer patterns
    TRANSFER_PATTERNS = [
        r'transfer\s*\(',
        r'transferFrom\s*\(',
        r'safeTransfer\s*\(',
        r'safeTransferFrom\s*\(',
        r'_transfer\s*\('
    ]
    
    # Mathematical operations
    MATH_PATTERNS = [
        r'mul\s*\(',
        r'div\s*\(',
        r'add\s*\(',
        r'sub\s*\(',
        r'sqrt\s*\(',
        r'pow\s*\('
    ]
    
    # Oracle patterns
    ORACLE_PATTERNS = [
        r'oracle\s*\.',
        r'priceFeed\s*\.',
        r'aggregator\s*\.',
        r'chainlink\s*\.',
        r'getRoundData\s*\(',
        r'decimals\s*\('
    ]
    
    # Flash loan patterns
    FLASH_LOAN_PATTERNS = [
        r'flashLoan\s*\(',
        r'flashBorrow\s*\(',
        r'executeOperation\s*\(',
        r'onFlashLoan\s*\(',
        r'flashFee\s*\(',
        r'maxFlashLoan\s*\('
    ]


class DeFiBaseAgent(BaseAgent):
    """
    Base agent for DeFi smart contract analysis.
    Provides common functionality and patterns for all DeFi agents.
    """
    
    def __init__(self, agent_name: str = "DeFiBaseAgent",
                 llm_client: Optional[LLMClient] = None,
                 prompt_manager: Optional[PromptManager] = None):
        super().__init__(agent_name, llm_client, prompt_manager)
        self.patterns = DeFiPatterns()
        self.defi_metrics = DeFiMetrics()
        
    @property
    def metadata(self) -> AgentMetadata:
        """Get agent metadata."""
        return AgentMetadata(
            name=self.agent_name,
            version="1.0.0",
            description="Base agent for DeFi smart contract analysis",
            author="Smart Contract Analyzer",
            agent_type=AgentType.DEFI,
            supported_domains=["defi"]
        )
    
    def can_analyze(self, context: AnalysisContext) -> bool:
        """Check if this agent can analyze the given context."""
        return self.enabled and self.is_defi_contract(context)
    
    def is_defi_contract(self, context: AnalysisContext) -> bool:
        """Check if the contract appears to be a DeFi contract."""
        code_lower = context.contract_code.lower()
        
        # Check for DeFi keywords
        defi_keywords = [
            'swap', 'liquidity', 'pool', 'reserve', 'token', 'price',
            'oracle', 'lending', 'borrow', 'stake', 'yield', 'farm',
            'vault', 'strategy', 'compound', 'flashloan'
        ]
        
        keyword_matches = sum(1 for keyword in defi_keywords if keyword in code_lower)
        
        # Check for DeFi function patterns
        pattern_matches = 0
        all_patterns = (
            self.patterns.PRICE_PATTERNS + 
            self.patterns.LIQUIDITY_PATTERNS + 
            self.patterns.TRANSFER_PATTERNS
        )
        
        for pattern in all_patterns:
            if re.search(pattern, context.contract_code, re.IGNORECASE):
                pattern_matches += 1
        
        # Require significant presence of DeFi elements
        return keyword_matches >= 3 or pattern_matches >= 5
    
    def detect_defi_protocol(self, context: AnalysisContext) -> DeFiProtocol:
        """Detect the specific DeFi protocol based on contract patterns."""
        code = context.contract_code
        
        # Protocol-specific signatures
        protocol_signatures = {
            DeFiProtocol.UNISWAP_V2: [
                'IUniswapV2', 'UniswapV2', 'WETH', 'factory', 'getReserves',
                'swapExactTokensForTokens', 'addLiquidity'
            ],
            DeFiProtocol.UNISWAP_V3: [
                'IUniswapV3', 'UniswapV3', 'tick', 'sqrtPrice', 'liquidity',
                'positions', 'mint', 'collect'
            ],
            DeFiProtocol.SUSHISWAP: [
                'SushiSwap', 'SUSHI', 'MasterChef', 'SLP', 'pendingSushi'
            ],
            DeFiProtocol.AAVE_V2: [
                'IAave', 'AaveV2', 'lendingPool', 'aToken', 'stableDebtToken',
                'variableDebtToken'
            ],
            DeFiProtocol.AAVE_V3: [
                'IAaveV3', 'AaveV3', 'Pool', 'supply', 'borrow', 'repay'
            ],
            DeFiProtocol.COMPOUND: [
                'Compound', 'cToken', 'Comptroller', 'exchangeRate',
                'supplyRate', 'borrowRate'
            ],
            DeFiProtocol.CURVE: [
                'Curve', 'CurvePool', 'get_dy', 'exchange', 'add_liquidity',
                'remove_liquidity'
            ],
            DeFiProtocol.YEARN: [
                'Yearn', 'Vault', 'Strategy', 'harvest', 'earn', 'want'
            ],
            DeFiProtocol.CHAINLINK: [
                'Chainlink', 'AggregatorV3', 'latestRoundData', 'getRoundData',
                'priceFeed'
            ]
        }
        
        best_match = DeFiProtocol.UNKNOWN
        best_score = 0
        
        for protocol, signatures in protocol_signatures.items():
            score = sum(1 for sig in signatures if sig in code)
            if score > best_score:
                best_score = score
                best_match = protocol
        
        return best_match if best_score >= 2 else DeFiProtocol.UNKNOWN
    
    def analyze(self, context: AnalysisContext) -> List[Finding]:
        """
        Perform base DeFi analysis.
        
        Args:
            context: Analysis context
            
        Returns:
            List[Finding]: DeFi-related findings
        """
        findings = []
        
        try:
            # Calculate DeFi metrics
            self.defi_metrics = self._calculate_defi_metrics(context)
            
            # Core DeFi security checks
            findings.extend(self._check_price_manipulation(context))
            findings.extend(self._check_slippage_protection(context))
            findings.extend(self._check_oracle_dependencies(context))
            findings.extend(self._check_liquidity_risks(context))
            findings.extend(self._check_token_transfers(context))
            findings.extend(self._check_mathematical_operations(context))
            findings.extend(self._check_defi_reentrancy(context))
            findings.extend(self._check_flash_loan_protection(context))
            
            return findings
            
        except Exception as e:
            self.logger.error(f"Error in DeFi base analysis: {str(e)}")
            return findings
    
    def _calculate_defi_metrics(self, context: AnalysisContext) -> DeFiMetrics:
        """Calculate DeFi-specific metrics."""
        metrics = DeFiMetrics()
        
        for functions in context.functions.values():
            for func in functions:
                # Count TVL-related functions
                tvl_keywords = ['balance', 'totalSupply', 'reserve', 'locked']
                if any(keyword in func.name.lower() for keyword in tvl_keywords):
                    metrics.total_value_locked_functions += 1
                
                # Count oracle dependencies
                if any(re.search(pattern, func.body, re.IGNORECASE) 
                       for pattern in self.patterns.ORACLE_PATTERNS):
                    metrics.oracle_dependencies += 1
                
                # Count flash loan usage
                if any(re.search(pattern, func.body, re.IGNORECASE) 
                       for pattern in self.patterns.FLASH_LOAN_PATTERNS):
                    metrics.flash_loan_vulnerabilities += 1
        
        return metrics
    
    def _check_price_manipulation(self, context: AnalysisContext) -> List[Finding]:
        """Check for price manipulation vulnerabilities."""
        findings = []
        
        for contract_name, functions in context.functions.items():
            for func in functions:
                # Check for price-dependent operations
                if self._uses_price_data(func):
                    if not self._has_price_validation(func):
                        finding = self.create_finding(
                            title=f"Price Manipulation Risk in {func.name}",
                            description=f"Function '{func.name}' uses price data without proper validation",
                            severity=Severity.HIGH,
                            category=Category.DEFI_SPECIFIC,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Implement price validation, use time-weighted averages, or multiple oracle sources",
                            impact="Attackers could manipulate prices to gain unfair advantage"
                        )
                        findings.append(finding)
                        self.defi_metrics.price_manipulation_risks += 1
        
        return findings
    
    def _check_slippage_protection(self, context: AnalysisContext) -> List[Finding]:
        """Check for slippage protection in trading functions."""
        findings = []
        
        for contract_name, functions in context.functions.items():
            for func in functions:
                if self._is_trading_function(func):
                    if not self._has_slippage_protection(func):
                        finding = self.create_finding(
                            title=f"Missing Slippage Protection in {func.name}",
                            description=f"Trading function '{func.name}' lacks slippage protection",
                            severity=Severity.MEDIUM,
                            category=Category.DEFI_SPECIFIC,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Add minimum amount parameters and validation",
                            impact="Users could experience unexpected losses due to slippage"
                        )
                        findings.append(finding)
                    else:
                        self.defi_metrics.slippage_protections += 1
        
        return findings
    
    def _check_oracle_dependencies(self, context: AnalysisContext) -> List[Finding]:
        """Check oracle dependency risks."""
        findings = []
        
        oracle_functions = []
        for functions in context.functions.values():
            for func in functions:
                if any(re.search(pattern, func.body, re.IGNORECASE) 
                       for pattern in self.patterns.ORACLE_PATTERNS):
                    oracle_functions.append(func)
        
        if oracle_functions:
            # Check for single point of failure
            if len(oracle_functions) == 1:
                func = oracle_functions[0]
                finding = self.create_finding(
                    title="Single Oracle Dependency",
                    description="Contract relies on a single oracle source",
                    severity=Severity.MEDIUM,
                    category=Category.ORACLE_DEPENDENCY,
                    location=CodeLocation(
                        function_name=func.name,
                        line_number=func.line_number
                    ),
                    recommendation="Use multiple oracle sources or implement fallback mechanisms",
                    impact="Oracle failure or manipulation could break contract functionality"
                )
                findings.append(finding)
            
            # Check for stale data protection
            for func in oracle_functions:
                if not self._has_stale_data_protection(func):
                    finding = self.create_finding(
                        title=f"Missing Stale Data Protection in {func.name}",
                        description=f"Oracle function '{func.name}' doesn't check for stale data",
                        severity=Severity.MEDIUM,
                        category=Category.ORACLE_DEPENDENCY,
                        location=CodeLocation(
                            function_name=func.name,
                            line_number=func.line_number
                        ),
                        recommendation="Check timestamp or round ID to ensure data freshness",
                        impact="Stale oracle data could lead to incorrect pricing"
                    )
                    findings.append(finding)
        
        return findings
    
    def _check_liquidity_risks(self, context: AnalysisContext) -> List[Finding]:
        """Check for liquidity-related risks."""
        findings = []
        
        for contract_name, functions in context.functions.items():
            for func in functions:
                if self._handles_liquidity(func):
                    # Check for liquidity validation
                    if not self._validates_liquidity(func):
                        finding = self.create_finding(
                            title=f"Insufficient Liquidity Validation in {func.name}",
                            description=f"Function '{func.name}' doesn't properly validate liquidity",
                            severity=Severity.MEDIUM,
                            category=Category.DEFI_SPECIFIC,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Add liquidity checks before operations",
                            impact="Operations could fail or be exploited with insufficient liquidity"
                        )
                        findings.append(finding)
                        self.defi_metrics.liquidity_risks += 1
        
        return findings
    
    def _check_token_transfers(self, context: AnalysisContext) -> List[Finding]:
        """Check token transfer security."""
        findings = []
        
        for contract_name, functions in context.functions.items():
            for func in functions:
                if self._has_token_transfers(func):
                    # Check for safe transfer usage
                    if not self._uses_safe_transfers(func):
                        finding = self.create_finding(
                            title=f"Unsafe Token Transfer in {func.name}",
                            description=f"Function '{func.name}' uses unsafe token transfers",
                            severity=Severity.MEDIUM,
                            category=Category.TOKEN_HANDLING,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Use SafeERC20 library for token transfers",
                            impact="Token transfers could fail silently"
                        )
                        findings.append(finding)
        
        return findings
    
    def _check_mathematical_operations(self, context: AnalysisContext) -> List[Finding]:
        """Check mathematical operations in DeFi context."""
        findings = []
        
        for contract_name, functions in context.functions.items():
            for func in functions:
                if self._has_complex_math(func):
                    # Check for precision issues
                    if self._has_precision_issues(func):
                        finding = self.create_finding(
                            title=f"Precision Issues in {func.name}",
                            description=f"Function '{func.name}' may have mathematical precision issues",
                            severity=Severity.MEDIUM,
                            category=Category.ARITHMETIC,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Use fixed-point arithmetic or safe math libraries",
                            impact="Precision errors could lead to incorrect calculations"
                        )
                        findings.append(finding)
        
        return findings
    
    def _check_defi_reentrancy(self, context: AnalysisContext) -> List[Finding]:
        """Check for DeFi-specific reentrancy vulnerabilities."""
        findings = []
        
        for contract_name, functions in context.functions.items():
            for func in functions:
                if self._is_defi_critical_function(func):
                    if self._has_external_calls(func) and not self._has_reentrancy_protection(func):
                        finding = self.create_finding(
                            title=f"DeFi Reentrancy Risk in {func.name}",
                            description=f"Critical DeFi function '{func.name}' vulnerable to reentrancy",
                            severity=Severity.HIGH,
                            category=Category.REENTRANCY,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Implement reentrancy guards for critical DeFi operations",
                            impact="Reentrancy attacks could drain protocol funds"
                        )
                        findings.append(finding)
                        self.defi_metrics.reentrancy_risks += 1
        
        return findings
    
    def _check_flash_loan_protection(self, context: AnalysisContext) -> List[Finding]:
        """Check for flash loan protection mechanisms."""
        findings = []
        
        has_flash_loans = any(
            any(re.search(pattern, func.body, re.IGNORECASE) 
                for pattern in self.patterns.FLASH_LOAN_PATTERNS)
            for functions in context.functions.values()
            for func in functions
        )
        
        if has_flash_loans:
            for contract_name, functions in context.functions.items():
                for func in functions:
                    if self._uses_flash_loans(func):
                        if not self._has_flash_loan_protection(func):
                            finding = self.create_finding(
                                title=f"Insufficient Flash Loan Protection in {func.name}",
                                description=f"Function '{func.name}' uses flash loans without adequate protection",
                                severity=Severity.HIGH,
                                category=Category.FLASH_LOAN,
                                location=CodeLocation(
                                    contract_name=contract_name,
                                    function_name=func.name,
                                    line_number=func.line_number
                                ),
                                affected_contracts=[contract_name],
                                affected_functions=[func.name],
                                recommendation="Implement flash loan protection mechanisms",
                                impact="Flash loan attacks could manipulate protocol state"
                            )
                            findings.append(finding)
        
        return findings
    
    # Helper methods for pattern detection
    
    def _uses_price_data(self, func: FunctionContext) -> bool:
        """Check if function uses price data."""
        return any(re.search(pattern, func.body, re.IGNORECASE) 
                  for pattern in self.patterns.PRICE_PATTERNS)
    
    def _has_price_validation(self, func: FunctionContext) -> bool:
        """Check if function validates price data."""
        validation_patterns = [
            r'require\s*\(\s*price\s*[><!]=',
            r'require\s*\(\s*.*price.*\s*[><!]=',
            r'if\s*\(\s*price\s*[><!]=',
            r'timestamp\s*[><!]=',
            r'updatedAt\s*[><!]='
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) 
                  for pattern in validation_patterns)
    
    def _is_trading_function(self, func: FunctionContext) -> bool:
        """Check if function is a trading function."""
        trading_keywords = ['swap', 'trade', 'exchange', 'buy', 'sell']
        return any(keyword in func.name.lower() for keyword in trading_keywords)
    
    def _has_slippage_protection(self, func: FunctionContext) -> bool:
        """Check if function has slippage protection."""
        slippage_patterns = [
            r'minAmount',
            r'minimumAmount',
            r'amountOutMin',
            r'amountInMax',
            r'slippage',
            r'require\s*\(\s*.*amount.*>=.*min'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) 
                  for pattern in slippage_patterns)
    
    def _has_stale_data_protection(self, func: FunctionContext) -> bool:
        """Check if function protects against stale oracle data."""
        stale_protection_patterns = [
            r'updatedAt',
            r'timestamp',
            r'roundId',
            r'block\.timestamp\s*-\s*.*<',
            r'require\s*\(\s*.*updatedAt'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) 
                  for pattern in stale_protection_patterns)
    
    def _handles_liquidity(self, func: FunctionContext) -> bool:
        """Check if function handles liquidity."""
        return any(re.search(pattern, func.body, re.IGNORECASE) 
                  for pattern in self.patterns.LIQUIDITY_PATTERNS)
    
    def _validates_liquidity(self, func: FunctionContext) -> bool:
        """Check if function validates liquidity."""
        validation_patterns = [
            r'require\s*\(\s*.*liquidity.*>',
            r'require\s*\(\s*.*reserve.*>',
            r'require\s*\(\s*.*balance.*>',
            r'if\s*\(\s*.*liquidity.*=='
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) 
                  for pattern in validation_patterns)
    
    def _has_token_transfers(self, func: FunctionContext) -> bool:
        """Check if function has token transfers."""
        return any(re.search(pattern, func.body, re.IGNORECASE) 
                  for pattern in self.patterns.TRANSFER_PATTERNS)
    
    def _uses_safe_transfers(self, func: FunctionContext) -> bool:
        """Check if function uses safe token transfers."""
        safe_patterns = [
            r'safeTransfer',
            r'safeTransferFrom',
            r'SafeERC20',
            r'IERC20.*\.transfer.*require'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) 
                  for pattern in safe_patterns)
    
    def _has_complex_math(self, func: FunctionContext) -> bool:
        """Check if function has complex mathematical operations."""
        return any(re.search(pattern, func.body, re.IGNORECASE) 
                  for pattern in self.patterns.MATH_PATTERNS)
    
    def _has_precision_issues(self, func: FunctionContext) -> bool:
        """Check for potential precision issues."""
        # Look for division before multiplication (precision loss)
        lines = func.body.split('\n')
        for line in lines:
            if '/' in line and '*' in line:
                div_pos = line.find('/')
                mul_pos = line.find('*')
                if div_pos < mul_pos:
                    return True
        return False
    
    def _is_defi_critical_function(self, func: FunctionContext) -> bool:
        """Check if function is critical in DeFi context."""
        critical_keywords = [
            'swap', 'trade', 'deposit', 'withdraw', 'mint', 'burn',
            'borrow', 'repay', 'liquidate', 'harvest', 'claim'
        ]
        return any(keyword in func.name.lower() for keyword in critical_keywords)
    
    def _has_external_calls(self, func: FunctionContext) -> bool:
        """Check if function has external calls."""
        external_patterns = [
            r'\.call\s*\(',
            r'\.delegatecall\s*\(',
            r'\.transfer\s*\(',
            r'\.send\s*\(',
            r'\w+\.\w+\s*\('  # General external call pattern
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) 
                  for pattern in external_patterns)
    
    def _has_reentrancy_protection(self, func: FunctionContext) -> bool:
        """Check if function has reentrancy protection."""
        protection_patterns = [
            'nonReentrant',
            'ReentrancyGuard',
            'mutex',
            'locked'
        ]
        return any(
            pattern in func.modifiers or pattern in func.body 
            for pattern in protection_patterns
        )
    
    def _uses_flash_loans(self, func: FunctionContext) -> bool:
        """Check if function uses flash loans."""
        return any(re.search(pattern, func.body, re.IGNORECASE) 
                  for pattern in self.patterns.FLASH_LOAN_PATTERNS)
    
    def _has_flash_loan_protection(self, func: FunctionContext) -> bool:
        """Check if function has flash loan protection."""
        protection_patterns = [
            r'onlyWhitelisted',
            r'flashLoanFee',
            r'require\s*\(\s*.*fee.*>',
            r'balanceBefore',
            r'balanceAfter'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) 
                  for pattern in protection_patterns)
