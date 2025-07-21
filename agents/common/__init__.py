"""
Common agents package for smart contract analysis.

This package contains agents that are used across all domains and provide
fundamental analysis capabilities for smart contracts.
"""

from .business_logic_agent import BusinessLogicAgent
from .code_quality_agent import CodeQualityAgent
from .data_management_agent import DataManagementAgent
from .external_interactions_agent import ExternalInteractionsAgent
from .invariant_agent import InvariantAgent
from .timestamp_oracle_agent import TimestampOracleAgent
from .visibility_agent import VisibilityAgent

__all__ = [
    'BusinessLogicAgent',
    'CodeQualityAgent',
    'DataManagementAgent',
    'ExternalInteractionsAgent',
    'InvariantAgent',
    'TimestampOracleAgent',
    'VisibilityAgent'
]

# Version info
__version__ = "1.0.0"

# Common agent configuration
DEFAULT_AGENT_CONFIG = {
    'enable_llm_analysis': True,
    'max_findings_per_agent': 50,
    'severity_threshold': 'low',
    'include_code_snippets': True,
    'detailed_analysis': True
}
