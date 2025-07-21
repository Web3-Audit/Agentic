"""
Base agent class for all smart contract analysis agents.

This module provides the fundamental structure and common functionality
that all specialized agents inherit from.
"""

import logging
import re
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass
from enum import Enum

from ..models.context import AnalysisContext, FunctionContext
from ..models.finding import Finding, Severity, Category, CodeLocation
from ..llm.client import LLMClient
from ..llm.prompts import PromptManager


class AgentType(Enum):
    """Types of agents available in the system."""
    UNIVERSAL = "universal"
    COMMON = "common"
    DEFI = "defi"
    DAO = "dao"
    NFT = "nft"
    GAMEFI = "gamefi"


@dataclass
class AgentMetadata:
    """Metadata for an agent."""
    name: str
    version: str
    description: str
    author: str
    agent_type: AgentType
    supported_domains: List[str]
    dependencies: List[str] = None


@dataclass
class AnalysisMetrics:
    """Metrics collected during analysis."""
    functions_analyzed: int = 0
    patterns_matched: int = 0
    findings_generated: int = 0
    analysis_time: float = 0.0
    llm_calls_made: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert metrics to dictionary."""
        return {
            'functions_analyzed': self.functions_analyzed,
            'patterns_matched': self.patterns_matched,
            'findings_generated': self.findings_generated,
            'analysis_time': self.analysis_time,
            'llm_calls_made': self.llm_calls_made
        }


class BaseAgent(ABC):
    """
    Abstract base class for all smart contract analysis agents.
    
    This class provides common functionality and enforces the interface
    that all specialized agents must implement.
    """
    
    def __init__(self, agent_name: str, 
                 llm_client: Optional[LLMClient] = None,
                 prompt_manager: Optional[PromptManager] = None):
        """
        Initialize the base agent.
        
        Args:
            agent_name: Name of the agent
            llm_client: Optional LLM client for AI-powered analysis
            prompt_manager: Optional prompt manager for LLM interactions
        """
        self.agent_name = agent_name
        self.llm_client = llm_client
        self.prompt_manager = prompt_manager
        self.logger = logging.getLogger(f"{__name__}.{agent_name}")
        
        # Analysis state
        self.current_context: Optional[AnalysisContext] = None
        self.metrics = AnalysisMetrics()
        self.findings_cache: List[Finding] = []
        
        # Configuration
        self.enabled = True
        self.debug_mode = False
        self.config = {}
        
        # Initialize agent-specific data
        self._initialize_agent()
    
    def _initialize_agent(self):
        """Initialize agent-specific data. Override in subclasses."""
        pass
    
    @property
    @abstractmethod
    def metadata(self) -> AgentMetadata:
        """Get agent metadata. Must be implemented by subclasses."""
        pass
    
    @abstractmethod
    def analyze(self, context: AnalysisContext) -> List[Finding]:
        """
        Perform analysis on the given context.
        
        Args:
            context: Analysis context containing contract information
            
        Returns:
            List[Finding]: List of security findings
        """
        pass
    
    def can_analyze(self, context: AnalysisContext) -> bool:
        """
        Check if this agent can analyze the given context.
        
        Args:
            context: Analysis context
            
        Returns:
            bool: True if agent can analyze this context
        """
        return self.enabled
    
    def pre_analyze(self, context: AnalysisContext) -> bool:
        """
        Pre-analysis hook. Called before main analysis.
        
        Args:
            context: Analysis context
            
        Returns:
            bool: True to continue with analysis, False to skip
        """
        self.current_context = context
        self.metrics = AnalysisMetrics()  # Reset metrics
        self.findings_cache = []  # Reset findings cache
        
        self.logger.info(f"Starting {self.agent_name} analysis")
        return True
    
    def post_analyze(self, findings: List[Finding]) -> List[Finding]:
        """
        Post-analysis hook. Called after main analysis.
        
        Args:
            findings: Initial findings from analysis
            
        Returns:
            List[Finding]: Processed findings
        """
        self.metrics.findings_generated = len(findings)
        self.logger.info(f"Completed {self.agent_name} analysis with {len(findings)} findings")
        
        # Apply post-processing filters
        processed_findings = self._post_process_findings(findings)
        return processed_findings
    
    def get_metrics(self) -> AnalysisMetrics:
        """Get analysis metrics."""
        return self.metrics
    
    def configure(self, config: Dict[str, Any]):
        """
        Configure the agent with custom settings.
        
        Args:
            config: Configuration dictionary
        """
        self.config.update(config)
        
        # Handle common configuration options
        if 'enabled' in config:
            self.enabled = config['enabled']
        if 'debug_mode' in config:
            self.debug_mode = config['debug_mode']
    
    # Helper methods for common analysis patterns
    
    def find_functions_by_pattern(self, pattern: str, 
                                 context: Optional[AnalysisContext] = None) -> List[FunctionContext]:
        """
        Find functions matching a regex pattern.
        
        Args:
            pattern: Regex pattern to match
            context: Optional context, uses current_context if None
            
        Returns:
            List[FunctionContext]: Matching functions
        """
        if context is None:
            context = self.current_context
        
        if not context:
            return []
        
        matching_functions = []
        for functions in context.functions.values():
            for func in functions:
                if re.search(pattern, func.name, re.IGNORECASE):
                    matching_functions.append(func)
        
        return matching_functions
    
    def find_patterns_in_code(self, patterns: List[str], 
                            context: Optional[AnalysisContext] = None) -> Dict[str, List[re.Match]]:
        """
        Find multiple patterns in contract code.
        
        Args:
            patterns: List of regex patterns
            context: Optional context, uses current_context if None
            
        Returns:
            Dict[str, List[re.Match]]: Pattern matches grouped by pattern
        """
        if context is None:
            context = self.current_context
        
        if not context:
            return {}
        
        results = {}
        for pattern in patterns:
            matches = list(re.finditer(pattern, context.contract_code, re.IGNORECASE | re.MULTILINE))
            if matches:
                results[pattern] = matches
                self.metrics.patterns_matched += len(matches)
        
        return results
    
    def check_function_modifiers(self, func: FunctionContext, 
                                required_modifiers: List[str]) -> bool:
        """
        Check if function has required modifiers.
        
        Args:
            func: Function to check
            required_modifiers: List of required modifier names
            
        Returns:
            bool: True if all required modifiers are present
        """
        func_modifiers_lower = [mod.lower() for mod in func.modifiers]
        return all(
            any(req_mod.lower() in mod for mod in func_modifiers_lower)
            for req_mod in required_modifiers
        )
    
    def extract_numeric_values(self, text: str) -> List[int]:
        """
        Extract numeric values from text.
        
        Args:
            text: Text to search
            
        Returns:
            List[int]: Found numeric values
        """
        numbers = re.findall(r'\d+', text)
        return [int(num) for num in numbers]
    
    def find_line_number(self, search_text: str, 
                        context: Optional[AnalysisContext] = None) -> int:
        """
        Find line number of text in contract code.
        
        Args:
            search_text: Text to search for
            context: Optional context, uses current_context if None
            
        Returns:
            int: Line number (1-based), 0 if not found
        """
        if context is None:
            context = self.current_context
        
        if not context:
            return 0
        
        lines = context.contract_code.split('\n')
        for i, line in enumerate(lines, 1):
            if search_text in line:
                return i
        return 0
    
    def create_finding(self, title: str, description: str, severity: Severity,
                      category: Category, **kwargs) -> Finding:
        """
        Helper method to create findings with common attributes.
        
        Args:
            title: Finding title
            description: Finding description
            severity: Finding severity
            category: Finding category
            **kwargs: Additional finding attributes
            
        Returns:
            Finding: Created finding
        """
        # Set default values based on current context
        if self.current_context and 'location' not in kwargs:
            kwargs['location'] = CodeLocation(
                contract_name=list(self.current_context.functions.keys())[0] if self.current_context.functions else "Unknown"
            )
        
        kwargs.setdefault('agent_name', self.agent_name)
        kwargs.setdefault('confidence', 0.8)
        
        return Finding(
            title=title,
            description=description,
            severity=severity,
            category=category,
            **kwargs
        )
    
    def _post_process_findings(self, findings: List[Finding]) -> List[Finding]:
        """
        Post-process findings (deduplication, filtering, etc.).
        
        Args:
            findings: Raw findings
            
        Returns:
            List[Finding]: Processed findings
        """
        # Remove duplicates based on title and description
        seen = set()
        unique_findings = []
        
        for finding in findings:
            key = (finding.title, finding.description)
            if key not in seen:
                seen.add(key)
                unique_findings.append(finding)
        
        # Sort by severity (Critical first)
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4
        }
        
        unique_findings.sort(key=lambda f: severity_order.get(f.severity, 5))
        
        return unique_findings
    
    def call_llm(self, prompt: str, **kwargs) -> Optional[str]:
        """
        Make a call to the LLM service.
        
        Args:
            prompt: Prompt to send
            **kwargs: Additional parameters for LLM call
            
        Returns:
            Optional[str]: LLM response, None if LLM not available
        """
        if not self.llm_client:
            return None
        
        try:
            self.metrics.llm_calls_made += 1
            return self.llm_client.generate(prompt, **kwargs)
        except Exception as e:
            self.logger.error(f"LLM call failed: {str(e)}")
            return None
    
    def validate_finding(self, finding: Finding) -> bool:
        """
        Validate a finding before including it in results.
        
        Args:
            finding: Finding to validate
            
        Returns:
            bool: True if finding is valid
        """
        # Basic validation
        if not finding.title or not finding.description:
            return False
        
        # Agent-specific validation can be overridden
        return True
    
    def __str__(self) -> str:
        """String representation of the agent."""
        return f"{self.agent_name} (enabled: {self.enabled})"
    
    def __repr__(self) -> str:
        """Detailed string representation of the agent."""
        return f"<{self.__class__.__name__}: {self.agent_name}, enabled: {self.enabled}>"
