"""
Core module for smart contract analysis.

This module contains the core functionality for parsing, analyzing, and classifying
smart contracts for automated security auditing.
"""

from .parser import SolidityParser
from .analyzer import ContractAnalyzer
from .context_classifier import ContextClassifier
from .domain_classifier import DomainClassifier
from .protocol_classifier import ProtocolClassifier

__all__ = [
    'SolidityParser',
    'ContractAnalyzer', 
    'ContextClassifier',
    'DomainClassifier',
    'ProtocolClassifier'
]

# Version info
__version__ = "1.0.0"
