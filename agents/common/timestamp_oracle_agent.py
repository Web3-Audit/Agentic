"""
Timestamp and oracle agent for analyzing time dependencies and oracle usage.
"""

import re
import logging
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum

from ..base_agent import BaseAgent
from ...models.context import AnalysisContext, FunctionContext
from ...models.finding import Finding, Severity, Category, CodeLocation
from ...llm.client import LLMClient
from ...llm.prompts import PromptManager

logger = logging.getLogger(__name__)

class TimeDependencyType(Enum):
    """Types of time dependencies."""
    BLOCK_TIMESTAMP = "block_timestamp"
    BLOCK_NUMBER = "block_number"
    BLOCKHASH = "blockhash"
    NOW = "now"

class OracleType(Enum):
    """Types of oracles."""
    PRICE_FEED = "price_feed"
    RANDOM_ORACLE = "random_oracle"
    DATA_FEED = "data_feed"
    CHAINLINK = "chainlink"

@dataclass
class TimeDependency:
    """Represents a time dependency."""
    dependency_type: TimeDependencyType
    function_name: str
    location: CodeLocation
    usage_context: str
    is_safe: bool = False

@dataclass
class OracleUsage:
    """Represents oracle usage."""
    oracle_type: OracleType
    function_name: str
    location: CodeLocation
    has_validation: bool = False
    has_fallback: bool = False

class TimestampOracleAgent(BaseAgent):
    """
    Agent focused on analyzing timestamp dependencies and oracle usage.
    """
    
    def __init__(self, llm_client: Optional[LLMClient] = None, 
                 prompt_manager: Optional[PromptManager] = None):
        super().__init__("TimestampOracleAgent", llm_client, prompt_manager)
        
        # Time dependency patterns
        self.time_patterns = {
            'block_timestamp': {
                'patterns': [r'\bblock\.timestamp\b', r'\bnow\b'],
                'severity': Severity.MEDIUM,
                'description': 'Block timestamp dependency'
            },
            'block_number': {
                'patterns': [r'\bblock\.number\b'],
                'severity': Severity.LOW,
                'description': 'Block number dependency'
            },
            'blockhash': {
                'patterns': [r'\bblockhash\s*\(', r'\bblock\.blockhash\s*\('],
                'severity': Severity.HIGH,
                'description': 'Blockhash usage for randomness'
            }
        }
        
        # Oracle patterns
        self.oracle_patterns = {
            'chainlink': {
                'patterns': [r'chainlink', r'AggregatorV3Interface', r'latestRoundData'],
                'severity': Severity.MEDIUM,
                'description': 'Chainlink oracle usage'
            },
            'price_feed': {
                'patterns': [r'getPrice', r'priceFeed', r'oracle\.price'],
                'severity': Severity.MEDIUM,
                'description': 'Price oracle usage'
            },
            'random_oracle': {
                'patterns': [r'random', r'entropy', r'VRF'],
                'severity': Severity.HIGH,
                'description': 'Random oracle usage'
            }
        }

    def analyze(self, context: AnalysisContext) -> List[Finding]:
        """
        Analyze timestamp dependencies and oracle usage.
        
        Args:
            context: Analysis context containing contract information
            
        Returns:
            List[Finding]: Timestamp and oracle findings
        """
        self.logger.info("Starting timestamp and oracle analysis")
        findings = []
        
        try:
            # Analyze each contract
            for contract_name, functions in context.functions.items():
                contract_findings = self._analyze_contract_time_oracle(
                    contract_name, functions, context
                )
                findings.extend(contract_findings)
            
            # LLM-enhanced analysis if available (made synchronous)
            if self.llm_client:
                llm_findings = self._llm_timestamp_oracle_analysis(context)
                findings.extend(llm_findings)
            
            self.logger.info(f"Timestamp and oracle analysis completed with {len(findings)} findings")
            return findings
            
        except Exception as e:
            self.logger.error(f"Error in timestamp and oracle analysis: {str(e)}")
            return findings

    def _analyze_contract_time_oracle(self, contract_name: str,
                                     functions: List[FunctionContext],
                                     context: AnalysisContext) -> List[Finding]:
        """Analyze timestamp and oracle usage for a specific contract."""
        findings = []
        
        # Check timestamp dependencies
        findings.extend(self._check_timestamp_dependencies(contract_name, functions))
        
        # Check oracle usage
        findings.extend(self._check_oracle_usage(contract_name, functions))
        
        # Check randomness sources
        findings.extend(self._check_randomness_sources(contract_name, functions))
        
        return findings

    def _check_timestamp_dependencies(self, contract_name: str,
                                     functions: List[FunctionContext]) -> List[Finding]:
        """Check for timestamp dependencies."""
        findings = []
        
        for func in functions:
            time_deps = self._find_time_dependencies(func)
            
            for dep in time_deps:
                if not dep.is_safe:
                    severity = self._get_time_dependency_severity(dep, func)
                    
                    finding = Finding(
                        title=f"Time Dependency in {func.name}",
                        description=f"Function '{func.name}' depends on {dep.dependency_type.value}",
                        severity=severity,
                        category=Category.TIMESTAMP_DEPENDENCE,
                        location=dep.location,
                        affected_contracts=[contract_name],
                        affected_functions=[func.name],
                        recommendation=self._get_time_dependency_recommendation(dep),
                        impact="Time manipulation could affect contract behavior"
                    )
                    findings.append(finding)
        
        return findings

    def _check_oracle_usage(self, contract_name: str,
                           functions: List[FunctionContext]) -> List[Finding]:
        """Check for oracle usage issues."""
        findings = []
        
        for func in functions:
            oracle_usages = self._find_oracle_usage(func)
            
            for usage in oracle_usages:
                oracle_issues = []
                
                if not usage.has_validation:
                    oracle_issues.append("No price validation")
                
                if not usage.has_fallback:
                    oracle_issues.append("No fallback mechanism")
                
                if not self._has_staleness_check(func):
                    oracle_issues.append("No staleness check")
                
                if oracle_issues:
                    finding = Finding(
                        title=f"Oracle Usage Issues in {func.name}",
                        description=f"Oracle usage has issues: {', '.join(oracle_issues)}",
                        severity=Severity.HIGH,
                        category=Category.EXTERNAL_INTERACTIONS,
                        location=usage.location,
                        affected_contracts=[contract_name],
                        affected_functions=[func.name],
                        recommendation="Implement proper oracle validation, fallback, and staleness checks",
                        impact="Oracle manipulation or failure could cause incorrect behavior"
                    )
                    findings.append(finding)
        
        return findings

    def _check_randomness_sources(self, contract_name: str,
                                 functions: List[FunctionContext]) -> List[Finding]:
        """Check for weak randomness sources."""
        findings = []
        
        for func in functions:
            if self._uses_weak_randomness(func):
                finding = Finding(
                    title=f"Weak Randomness Source in {func.name}",
                    description=f"Function '{func.name}' uses predictable randomness sources",
                    severity=Severity.HIGH,
                    category=Category.RANDOMNESS,
                    location=CodeLocation(
                        contract_name=contract_name,
                        function_name=func.name
                    ),
                    affected_contracts=[contract_name],
                    affected_functions=[func.name],
                    recommendation="Use verifiable random functions (VRF) or commit-reveal schemes",
                    impact="Predictable randomness can be exploited by miners or attackers"
                )
                findings.append(finding)
        
        return findings

    def _llm_timestamp_oracle_analysis(self, context: AnalysisContext) -> List[Finding]:
        """Perform LLM-enhanced timestamp and oracle analysis (synchronous version)."""
        findings = []
        
        if not self.llm_client or not self.prompt_manager:
            return findings
        
        try:
            # For now, implement basic analysis without async LLM calls
            self.logger.info("LLM timestamp/oracle analysis temporarily disabled for synchronous execution")
        except Exception as e:
            self.logger.error(f"Error in LLM timestamp/oracle analysis: {str(e)}")
        
        return findings

    def _find_time_dependencies(self, func: FunctionContext) -> List[TimeDependency]:
        """Find time dependencies in function."""
        dependencies = []
        
        # Check for block.timestamp
        if re.search(r'\bblock\.timestamp\b', func.body):
            dep = TimeDependency(
                dependency_type=TimeDependencyType.BLOCK_TIMESTAMP,
                function_name=func.name,
                location=CodeLocation(function_name=func.name),
                usage_context="block.timestamp",
                is_safe=self._is_timestamp_usage_safe(func)
            )
            dependencies.append(dep)
        
        # Check for now
        if re.search(r'\bnow\b', func.body):
            dep = TimeDependency(
                dependency_type=TimeDependencyType.NOW,
                function_name=func.name,
                location=CodeLocation(function_name=func.name),
                usage_context="now",
                is_safe=self._is_timestamp_usage_safe(func)
            )
            dependencies.append(dep)
        
        # Check for block.number
        if re.search(r'\bblock\.number\b', func.body):
            dep = TimeDependency(
                dependency_type=TimeDependencyType.BLOCK_NUMBER,
                function_name=func.name,
                location=CodeLocation(function_name=func.name),
                usage_context="block.number",
                is_safe=True  # Generally safer than timestamp
            )
            dependencies.append(dep)
        
        # Check for blockhash
        if re.search(r'\bblockhash\s*\(', func.body):
            dep = TimeDependency(
                dependency_type=TimeDependencyType.BLOCKHASH,
                function_name=func.name,
                location=CodeLocation(function_name=func.name),
                usage_context="blockhash",
                is_safe=False  # Generally unsafe for randomness
            )
            dependencies.append(dep)
        
        return dependencies

    def _find_oracle_usage(self, func: FunctionContext) -> List[OracleUsage]:
        """Find oracle usage in function."""
        usages = []
        
        # Check for Chainlink oracle
        if re.search(r'chainlink|AggregatorV3Interface|latestRoundData', func.body, re.IGNORECASE):
            usage = OracleUsage(
                oracle_type=OracleType.CHAINLINK,
                function_name=func.name,
                location=CodeLocation(function_name=func.name),
                has_validation=self._has_oracle_validation(func),
                has_fallback=self._has_oracle_fallback(func)
            )
            usages.append(usage)
        
        # Check for price feed oracle
        if re.search(r'getPrice|priceFeed|oracle\.price', func.body, re.IGNORECASE):
            usage = OracleUsage(
                oracle_type=OracleType.PRICE_FEED,
                function_name=func.name,
                location=CodeLocation(function_name=func.name),
                has_validation=self._has_oracle_validation(func),
                has_fallback=self._has_oracle_fallback(func)
            )
            usages.append(usage)
        
        return usages

    def _get_time_dependency_severity(self, dep: TimeDependency, func: FunctionContext) -> Severity:
        """Get severity for time dependency."""
        if dep.dependency_type == TimeDependencyType.BLOCKHASH:
            return Severity.HIGH
        elif dep.dependency_type in [TimeDependencyType.BLOCK_TIMESTAMP, TimeDependencyType.NOW]:
            if func.is_critical or func.is_payable:
                return Severity.HIGH
            else:
                return Severity.MEDIUM
        else:
            return Severity.LOW

    def _get_time_dependency_recommendation(self, dep: TimeDependency) -> str:
        """Get recommendation for time dependency."""
        recommendations = {
            TimeDependencyType.BLOCK_TIMESTAMP: "Use block.timestamp only for non-critical time checks with sufficient tolerance",
            TimeDependencyType.NOW: "Replace 'now' with block.timestamp and ensure proper time tolerance",
            TimeDependencyType.BLOCK_NUMBER: "Block number dependency is generally safe but consider miner influence",
            TimeDependencyType.BLOCKHASH: "Don't use blockhash for randomness - use VRF or commit-reveal instead"
        }
        return recommendations.get(dep.dependency_type, "Review time dependency usage")

    def _is_timestamp_usage_safe(self, func: FunctionContext) -> bool:
        """Check if timestamp usage is safe."""
        # Check for time tolerance
        has_tolerance = any(op in func.body for op in ['>', '<', '>=', '<=', '+', '-'])
        
        # Check for critical operations
        is_critical_context = any(keyword in func.body.lower() for keyword in [
            'transfer', 'withdraw', 'deposit', 'mint', 'burn', 'approve'
        ])
        
        return has_tolerance and not is_critical_context

    def _has_oracle_validation(self, func: FunctionContext) -> bool:
        """Check if function validates oracle data."""
        validation_patterns = [
            'require.*price', 'assert.*price', 'price.*>', 'price.*<',
            'validate', 'check.*price'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) for pattern in validation_patterns)

    def _has_oracle_fallback(self, func: FunctionContext) -> bool:
        """Check if function has oracle fallback."""
        fallback_patterns = [
            'fallback', 'backup', 'alternative', 'try.*catch',
            'if.*fail', 'emergency'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) for pattern in fallback_patterns)

    def _has_staleness_check(self, func: FunctionContext) -> bool:
        """Check if function checks for stale oracle data."""
        staleness_patterns = [
            'timestamp', 'updatedAt', 'lastUpdate', 'stale',
            'block.timestamp.*-.*updatedAt'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) for pattern in staleness_patterns)

    def _uses_weak_randomness(self, func: FunctionContext) -> bool:
        """Check if function uses weak randomness sources."""
        weak_patterns = [
            r'blockhash\s*\(',
            r'block\.timestamp.*%',
            r'block\.number.*%',
            r'keccak256\s*\(\s*abi\.encodePacked\s*\(\s*block\.',
            r'now.*%'
        ]
        return any(re.search(pattern, func.body) for pattern in weak_patterns)
