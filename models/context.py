"""
Context models for smart contract analysis.

These models capture the context and metadata needed for comprehensive
smart contract security analysis.
"""

import json
import logging
from typing import Dict, List, Optional, Any, Set, Union
from dataclasses import dataclass, field, asdict
from enum import Enum
from datetime import datetime

logger = logging.getLogger(__name__)

class ContractType(Enum):
    CONTRACT = "contract"
    INTERFACE = "interface"
    LIBRARY = "library"
    ABSTRACT = "abstract"

class NetworkType(Enum):
    MAINNET = "mainnet"
    TESTNET = "testnet"
    POLYGON = "polygon"
    BSC = "bsc"
    ARBITRUM = "arbitrum"
    OPTIMISM = "optimism"
    AVALANCHE = "avalanche"
    FANTOM = "fantom"
    LOCAL = "local"
    UNKNOWN = "unknown"

class AnalysisScope(Enum):
    FULL = "full"
    SECURITY_ONLY = "security_only"
    BUSINESS_LOGIC = "business_logic"
    CODE_QUALITY = "code_quality"
    GAS_OPTIMIZATION = "gas_optimization"
    CUSTOM = "custom"

@dataclass
class CodeLocation:
    """Represents a location in the source code."""
    file_path: Optional[str] = None
    contract_name: Optional[str] = None
    function_name: Optional[str] = None
    line_number: Optional[int] = None
    column_number: Optional[int] = None
    start_line: Optional[int] = None
    end_line: Optional[int] = None
    code_snippet: Optional[str] = None

    def __str__(self) -> str:
        parts = []
        if self.contract_name:
            parts.append(self.contract_name)
        if self.function_name:
            parts.append(f"{self.function_name}()")
        if self.line_number:
            parts.append(f"L{self.line_number}")
        
        return " - ".join(parts) if parts else "Unknown location"

@dataclass
class FunctionContext:
    """Context information for a function."""
    name: str
    signature: str
    visibility: str
    state_mutability: str
    function_type: str
    modifiers: List[str] = field(default_factory=list)
    parameters: List[Dict[str, str]] = field(default_factory=list)
    return_parameters: List[Dict[str, str]] = field(default_factory=list)
    body: str = ""
    location: Optional[CodeLocation] = None
    
    # Analysis metadata
    is_critical: bool = False
    is_admin_only: bool = False
    has_external_calls: bool = False
    has_state_changes: bool = False
    complexity_score: float = 0.0
    gas_estimate: Optional[int] = None
    
    # Security flags
    is_payable: bool = False
    has_delegatecall: bool = False
    has_assembly: bool = False
    uses_tx_origin: bool = False
    has_time_dependency: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        result = asdict(self)
        if self.location:
            result['location'] = asdict(self.location)
        return result

@dataclass
class StateVariableContext:
    """Context information for a state variable."""
    name: str
    type: str
    visibility: str
    is_constant: bool = False
    is_immutable: bool = False
    initial_value: Optional[str] = None
    location: Optional[CodeLocation] = None
    
    # Analysis metadata
    is_critical: bool = False
    affects_security: bool = False
    is_user_controlled: bool = False
    storage_slot: Optional[int] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        result = asdict(self)
        if self.location:
            result['location'] = asdict(self.location)
        return result

@dataclass
class EventContext:
    """Context information for an event."""
    name: str
    parameters: List[Dict[str, Any]] = field(default_factory=list)
    location: Optional[CodeLocation] = None
    
    # Analysis metadata
    is_security_relevant: bool = False
    emission_count: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        result = asdict(self)
        if self.location:
            result['location'] = asdict(self.location)
        return result

@dataclass
class ModifierContext:
    """Context information for a modifier."""
    name: str
    parameters: List[Dict[str, str]] = field(default_factory=list)
    body: str = ""
    location: Optional[CodeLocation] = None
    
    # Analysis metadata
    is_access_control: bool = False
    is_security_critical: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        result = asdict(self)
        if self.location:
            result['location'] = asdict(self.location)
        return result

@dataclass
class ContractMetadata:
    """Comprehensive metadata for a smart contract."""
    name: str
    contract_type: ContractType
    source_file: Optional[str] = None
    compiler_version: Optional[str] = None
    optimization_enabled: bool = False
    optimization_runs: int = 200
    
    # Inheritance
    inherits: List[str] = field(default_factory=list)
    inherited_by: List[str] = field(default_factory=list)
    
    # Dependencies
    imports: List[str] = field(default_factory=list)
    libraries: List[str] = field(default_factory=list)
    interfaces: List[str] = field(default_factory=list)
    
    # License and documentation
    license: Optional[str] = None
    natspec_title: Optional[str] = None
    natspec_notice: Optional[str] = None
    natspec_dev: Optional[str] = None
    
    # Deployment information
    network: Optional[NetworkType] = None
    deployed_address: Optional[str] = None
    deployment_block: Optional[int] = None
    deployer_address: Optional[str] = None
    creation_code_hash: Optional[str] = None
    runtime_code_hash: Optional[str] = None
    
    # Code metrics
    lines_of_code: int = 0
    complexity_score: float = 0.0
    cyclomatic_complexity: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        result = asdict(self)
        result['contract_type'] = self.contract_type.value
        if self.network:
            result['network'] = self.network.value
        return result

@dataclass
class SecurityContext:
    """Security-specific context information."""
    # Access control
    has_owner: bool = False
    owner_functions: List[str] = field(default_factory=list)
    access_control_mechanisms: List[str] = field(default_factory=list)
    
    # External interactions
    external_calls: List[str] = field(default_factory=list)
    delegatecalls: List[str] = field(default_factory=list)
    interface_interactions: List[str] = field(default_factory=list)
    
    # Financial operations
    handles_ether: bool = False
    token_operations: List[str] = field(default_factory=list)
    financial_functions: List[str] = field(default_factory=list)
    
    # Dangerous patterns
    uses_assembly: bool = False
    has_selfdestruct: bool = False
    uses_tx_origin: bool = False
    has_timestamp_dependency: bool = False
    has_blockhash_dependency: bool = False
    
    # Upgrade patterns
    is_upgradeable: bool = False
    proxy_pattern: Optional[str] = None
    upgrade_functions: List[str] = field(default_factory=list)
    
    # Emergency controls
    has_pause_mechanism: bool = False
    emergency_functions: List[str] = field(default_factory=list)
    circuit_breakers: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)

@dataclass
class AnalysisContext:
    """Complete analysis context for a smart contract or project."""
    
    # Basic information
    project_name: Optional[str] = None
    analysis_id: str = field(default_factory=lambda: f"analysis_{int(datetime.now().timestamp())}")
    timestamp: datetime = field(default_factory=datetime.now)
    
    # Analysis configuration
    scope: AnalysisScope = AnalysisScope.FULL
    target_networks: List[NetworkType] = field(default_factory=list)
    custom_checks: List[str] = field(default_factory=list)
    excluded_checks: List[str] = field(default_factory=list)
    
    # Contract information
    contracts: Dict[str, ContractMetadata] = field(default_factory=dict)
    functions: Dict[str, List[FunctionContext]] = field(default_factory=dict)  # contract_name -> functions
    state_variables: Dict[str, List[StateVariableContext]] = field(default_factory=dict)
    events: Dict[str, List[EventContext]] = field(default_factory=dict)
    modifiers: Dict[str, List[ModifierContext]] = field(default_factory=dict)
    
    # Security context
    security_context: SecurityContext = field(default_factory=SecurityContext)
    
    # Domain and protocol information
    domain: Optional[str] = None
    domains: List[str] = field(default_factory=list)
    protocol: Optional[str] = None
    protocol_version: Optional[str] = None
    
    # Business logic context
    business_logic_types: List[str] = field(default_factory=list)
    critical_paths: List[str] = field(default_factory=list)
    economic_model: Optional[str] = None
    
    # Analysis metadata
    analyzer_version: str = "1.0.0"
    analysis_duration: Optional[float] = None
    total_functions_analyzed: int = 0
    total_lines_analyzed: int = 0
    
    # External dependencies
    oracle_dependencies: List[str] = field(default_factory=list)
    external_contract_dependencies: List[str] = field(default_factory=list)
    library_dependencies: List[str] = field(default_factory=list)
    
    # Invariants and assumptions
    invariants: List[str] = field(default_factory=list)
    assumptions: List[str] = field(default_factory=list)
    
    def add_contract(self, name: str, metadata: ContractMetadata):
        """Add a contract to the analysis context."""
        self.contracts[name] = metadata
        self.functions[name] = []
        self.state_variables[name] = []
        self.events[name] = []
        self.modifiers[name] = []

    def add_function(self, contract_name: str, function: FunctionContext):
        """Add a function to a contract's context."""
        if contract_name not in self.functions:
            self.functions[contract_name] = []
        self.functions[contract_name].append(function)
        self.total_functions_analyzed += 1

    def add_state_variable(self, contract_name: str, variable: StateVariableContext):
        """Add a state variable to a contract's context."""
        if contract_name not in self.state_variables:
            self.state_variables[contract_name] = []
        self.state_variables[contract_name].append(variable)

    def get_all_functions(self) -> List[FunctionContext]:
        """Get all functions across all contracts."""
        all_functions = []
        for functions in self.functions.values():
            all_functions.extend(functions)
        return all_functions

    def get_critical_functions(self) -> List[FunctionContext]:
        """Get all functions marked as critical."""
        return [func for func in self.get_all_functions() if func.is_critical]

    def get_payable_functions(self) -> List[FunctionContext]:
        """Get all payable functions."""
        return [func for func in self.get_all_functions() if func.is_payable]

    def get_external_functions(self) -> List[FunctionContext]:
        """Get all external functions."""
        return [func for func in self.get_all_functions() 
                if func.visibility == 'external']

    def get_admin_functions(self) -> List[FunctionContext]:
        """Get all admin-only functions."""
        return [func for func in self.get_all_functions() if func.is_admin_only]

    def get_functions_with_external_calls(self) -> List[FunctionContext]:
        """Get all functions that make external calls."""
        return [func for func in self.get_all_functions() if func.has_external_calls]

    def get_complexity_score(self) -> float:
        """Calculate overall complexity score."""
        if not self.contracts:
            return 0.0
        
        total_complexity = sum(contract.complexity_score 
                             for contract in self.contracts.values())
        return total_complexity / len(self.contracts)

    def get_security_risk_score(self) -> float:
        """Calculate overall security risk score."""
        risk_factors = 0
        total_factors = 10
        
        # Check various risk factors
        if self.security_context.uses_assembly:
            risk_factors += 1
        if self.security_context.has_selfdestruct:
            risk_factors += 2
        if self.security_context.uses_tx_origin:
            risk_factors += 2
        if self.security_context.has_timestamp_dependency:
            risk_factors += 1
        if self.security_context.delegatecalls:
            risk_factors += 2
        if len(self.security_context.external_calls) > 5:
            risk_factors += 1
        if self.security_context.handles_ether and not self.security_context.has_pause_mechanism:
            risk_factors += 1
        
        return min(risk_factors / total_factors, 1.0)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        result = {
            'project_name': self.project_name,
            'analysis_id': self.analysis_id,
            'timestamp': self.timestamp.isoformat(),
            'scope': self.scope.value,
            'target_networks': [network.value for network in self.target_networks],
            'custom_checks': self.custom_checks,
            'excluded_checks': self.excluded_checks,
            'contracts': {name: contract.to_dict() 
                         for name, contract in self.contracts.items()},
            'functions': {contract_name: [func.to_dict() for func in functions]
                         for contract_name, functions in self.functions.items()},
            'state_variables': {contract_name: [var.to_dict() for var in variables]
                               for contract_name, variables in self.state_variables.items()},
            'events': {contract_name: [event.to_dict() for event in events]
                      for contract_name, events in self.events.items()},
            'modifiers': {contract_name: [mod.to_dict() for mod in mods]
                         for contract_name, mods in self.modifiers.items()},
            'security_context': self.security_context.to_dict(),
            'domain': self.domain,
            'domains': self.domains,
            'protocol': self.protocol,
            'protocol_version': self.protocol_version,
            'business_logic_types': self.business_logic_types,
            'critical_paths': self.critical_paths,
            'economic_model': self.economic_model,
            'analyzer_version': self.analyzer_version,
            'analysis_duration': self.analysis_duration,
            'total_functions_analyzed': self.total_functions_analyzed,
            'total_lines_analyzed': self.total_lines_analyzed,
            'oracle_dependencies': self.oracle_dependencies,
            'external_contract_dependencies': self.external_contract_dependencies,
            'library_dependencies': self.library_dependencies,
            'invariants': self.invariants,
            'assumptions': self.assumptions
        }
        
        return result

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=2, default=str)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'AnalysisContext':
        """Create AnalysisContext from dictionary."""
        context = cls()
        
        # Basic fields
        context.project_name = data.get('project_name')
        context.analysis_id = data.get('analysis_id', context.analysis_id)
        
        if 'timestamp' in data:
            context.timestamp = datetime.fromisoformat(data['timestamp'])
        
        if 'scope' in data:
            context.scope = AnalysisScope(data['scope'])
        
        context.target_networks = [NetworkType(net) for net in data.get('target_networks', [])]
        context.custom_checks = data.get('custom_checks', [])
        context.excluded_checks = data.get('excluded_checks', [])
        
        # Contracts
        for name, contract_data in data.get('contracts', {}).items():
            contract_metadata = ContractMetadata(
                name=contract_data['name'],
                contract_type=ContractType(contract_data['contract_type'])
            )
            # Set other fields...
            context.contracts[name] = contract_metadata
        
        # Other fields
        context.domain = data.get('domain')
        context.domains = data.get('domains', [])
        context.protocol = data.get('protocol')
        context.business_logic_types = data.get('business_logic_types', [])
        context.invariants = data.get('invariants', [])
        context.assumptions = data.get('assumptions', [])
        
        return context

    @classmethod
    def from_json(cls, json_str: str) -> 'AnalysisContext':
        """Create AnalysisContext from JSON string."""
        data = json.loads(json_str)
        return cls.from_dict(data)

    def validate(self) -> List[str]:
        """Validate the context and return any validation errors."""
        errors = []
        
        if not self.contracts:
            errors.append("No contracts found in analysis context")
        
        for contract_name, contract in self.contracts.items():
            if not contract.name:
                errors.append(f"Contract {contract_name} missing name")
            
            # Check for functions without contracts
            if contract_name in self.functions and not self.functions[contract_name]:
                errors.append(f"Contract {contract_name} has no functions")
        
        # Validate security context
        if self.security_context.has_selfdestruct and not self.security_context.has_owner:
            errors.append("Contract has selfdestruct but no owner mechanism")
        
        return errors

    def get_summary(self) -> Dict[str, Any]:
        """Get a summary of the analysis context."""
        return {
            'project_name': self.project_name,
            'analysis_id': self.analysis_id,
            'scope': self.scope.value,
            'total_contracts': len(self.contracts),
            'total_functions': sum(len(funcs) for funcs in self.functions.values()),
            'total_state_variables': sum(len(vars) for vars in self.state_variables.values()),
            'domain': self.domain,
            'domains': self.domains,
            'protocol': self.protocol,
            'complexity_score': self.get_complexity_score(),
            'security_risk_score': self.get_security_risk_score(),
            'has_external_calls': len(self.security_context.external_calls) > 0,
            'handles_ether': self.security_context.handles_ether,
            'is_upgradeable': self.security_context.is_upgradeable
        }
