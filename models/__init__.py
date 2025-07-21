"""
Models package for smart contract analysis system.

This package contains all the data models, structures, and schemas used
throughout the smart contract security analysis system.
"""

from .context import (
    AnalysisContext,
    ContractMetadata,
    FunctionContext,
    StateVariableContext,
    SecurityContext
)
from .finding import (
    Finding,
    Severity,
    Category,
    FindingMetadata,
    Reference,
    CodeLocation
)
from .property import (
    Property,
    PropertyType,
    PropertyStatus,
    InvariantProperty,
    SecurityProperty,
    BusinessLogicProperty
)
from .structured_report import (
    StructuredReport,
    ReportSection,
    ExecutiveSummary,
    ContractOverview,
    SecurityAssessment,
    ReportMetadata
)

__all__ = [
    # Context models
    'AnalysisContext',
    'ContractMetadata', 
    'FunctionContext',
    'StateVariableContext',
    'SecurityContext',
    
    # Finding models
    'Finding',
    'Severity',
    'Category',
    'FindingMetadata',
    'Reference',
    'CodeLocation',
    
    # Property models
    'Property',
    'PropertyType',
    'PropertyStatus',
    'InvariantProperty',
    'SecurityProperty',
    'BusinessLogicProperty',
    
    # Report models
    'StructuredReport',
    'ReportSection',
    'ExecutiveSummary',
    'ContractOverview',
    'SecurityAssessment',
    'ReportMetadata'
]

# Version info
__version__ = "1.0.0"

# Model validation settings
ENABLE_STRICT_VALIDATION = True
MAX_DESCRIPTION_LENGTH = 5000
MAX_CODE_SNIPPET_LENGTH = 2000
