"""
LLM module for smart contract analysis.

This module provides LLM client functionality, prompt management, and response parsing
for automated smart contract security analysis.
"""

from .client import LLMClient
from .prompts import PromptManager, PromptTemplates
from .response_parser import ResponseParser, ParsedResponse

__all__ = [
    'LLMClient',
    'PromptManager',
    'PromptTemplates', 
    'ResponseParser',
    'ParsedResponse'
]

# Version info
__version__ = "1.0.0"

# Default configuration
DEFAULT_MODEL = "gpt-4"
DEFAULT_TEMPERATURE = 0.1
DEFAULT_MAX_TOKENS = 4000
