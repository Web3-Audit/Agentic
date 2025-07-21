"""
Utilities package for smart contract analysis system.

This package contains utility functions, helper classes, and common tools
used throughout the smart contract security analysis system.
"""

from .ast_utils import (
    ASTAnalyzer,
    FunctionExtractor,
    VariableExtractor,
    CallGraphBuilder,
    ComplexityCalculator
)
from .business_logic_utils import (
    BusinessLogicAnalyzer,
    EconomicModelAnalyzer,
    StateTransitionAnalyzer,
    InvariantExtractor
)
from .code_snippet_utils import (
    CodeSnippetExtractor,
    ContextualSnippet,
    SnippetHighlighter,
    CodeLocationResolver
)
from .fuzzing_template_generator import (
    FuzzingTemplateGenerator,
    PropertyBasedGenerator,
    BoundaryValueGenerator,
    StateTransitionGenerator
)
from .regex_utils import (
    SolidityPatterns,
    PatternMatcher,
    SecurityPatternDetector,
    CodePatternAnalyzer
)
from .structured_report_generator import (
    StructuredReportGenerator,
    ReportFormatter,
    HTMLReportFormatter,
    MarkdownReportFormatter
)
from .validation import (
    InputValidator,
    ContractValidator,
    FindingValidator,
    ReportValidator
)

__all__ = [
    # AST utilities
    'ASTAnalyzer',
    'FunctionExtractor',
    'VariableExtractor', 
    'CallGraphBuilder',
    'ComplexityCalculator',
    
    # Business logic utilities
    'BusinessLogicAnalyzer',
    'EconomicModelAnalyzer',
    'StateTransitionAnalyzer',
    'InvariantExtractor',
    
    # Code snippet utilities
    'CodeSnippetExtractor',
    'ContextualSnippet',
    'SnippetHighlighter',
    'CodeLocationResolver',
    
    # Fuzzing utilities
    'FuzzingTemplateGenerator',
    'PropertyBasedGenerator',
    'BoundaryValueGenerator',
    'StateTransitionGenerator',
    
    # Regex utilities
    'SolidityPatterns',
    'PatternMatcher',
    'SecurityPatternDetector',
    'CodePatternAnalyzer',
    
    # Report generation utilities
    'StructuredReportGenerator',
    'ReportFormatter',
    'HTMLReportFormatter', 
    'MarkdownReportFormatter',
    
    # Validation utilities
    'InputValidator',
    'ContractValidator',
    'FindingValidator',
    'ReportValidator'
]

# Version info
__version__ = "1.0.0"

# Common constants
DEFAULT_MAX_LINE_LENGTH = 100
DEFAULT_CONTEXT_LINES = 5
DEFAULT_SNIPPET_MAX_LENGTH = 500
