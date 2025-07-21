"""
Solidity parser for converting smart contracts to AST and extracting structured information.
"""

import re
import json
import logging
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)

class FunctionType(Enum):
    CONSTRUCTOR = "constructor"
    FUNCTION = "function"
    MODIFIER = "modifier"
    FALLBACK = "fallback"
    RECEIVE = "receive"

class Visibility(Enum):
    PUBLIC = "public"
    PRIVATE = "private"
    INTERNAL = "internal"
    EXTERNAL = "external"

class StateMutability(Enum):
    PURE = "pure"
    VIEW = "view"
    PAYABLE = "payable"
    NONPAYABLE = "nonpayable"

@dataclass
class Variable:
    name: str
    type: str
    visibility: Optional[str] = None
    is_constant: bool = False
    is_immutable: bool = False
    initial_value: Optional[str] = None
    location: Optional[Tuple[int, int]] = None

@dataclass
class Function:
    name: str
    function_type: FunctionType
    visibility: Visibility
    state_mutability: StateMutability
    parameters: List[Dict[str, str]] = field(default_factory=list)
    return_parameters: List[Dict[str, str]] = field(default_factory=list)
    modifiers: List[str] = field(default_factory=list)
    body: str = ""
    location: Optional[Tuple[int, int]] = None
    is_virtual: bool = False
    is_override: bool = False

@dataclass
class Event:
    name: str
    parameters: List[Dict[str, Any]] = field(default_factory=list)
    location: Optional[Tuple[int, int]] = None

@dataclass
class Modifier:
    name: str
    parameters: List[Dict[str, str]] = field(default_factory=list)
    body: str = ""
    location: Optional[Tuple[int, int]] = None

@dataclass
class Contract:
    name: str
    contract_type: str  # "contract", "interface", "library"
    inherits: List[str] = field(default_factory=list)
    state_variables: List[Variable] = field(default_factory=list)
    functions: List[Function] = field(default_factory=list)
    events: List[Event] = field(default_factory=list)
    modifiers: List[Modifier] = field(default_factory=list)
    using_statements: List[str] = field(default_factory=list)
    imports: List[str] = field(default_factory=list)
    location: Optional[Tuple[int, int]] = None

@dataclass
class ParsedContract:
    source_code: str
    contracts: List[Contract] = field(default_factory=list)
    pragma_statements: List[str] = field(default_factory=list)
    license: Optional[str] = None
    imports: List[str] = field(default_factory=list)
    parse_errors: List[str] = field(default_factory=list)

class SolidityParser:
    """
    Advanced Solidity parser that converts smart contract source code into structured AST.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Regex patterns for parsing
        self.patterns = {
            'pragma': r'pragma\s+solidity\s+([^;]+);',
            'license': r'//\s*SPDX-License-Identifier:\s*(.+)',
            'import': r'import\s+(?:(?:"([^"]+)"|\'([^\']+)\')|(?:\{([^}]+)\}\s+from\s+(?:"([^"]+)"|\'([^\']+)\')))',
            'contract': r'(contract|interface|library)\s+(\w+)(?:\s+is\s+([^{]+))?\s*\{',
            'function': r'function\s+(\w+)?\s*\(([^)]*)\)\s*(external|public|internal|private)?\s*(pure|view|payable)?\s*(virtual|override)?\s*(returns\s*\([^)]*\))?\s*(?:(\w+(?:\([^)]*\))?(?:\s*,\s*\w+(?:\([^)]*\))?)*))?\s*\{',
            'constructor': r'constructor\s*\(([^)]*)\)\s*(public|internal)?\s*(payable)?\s*(?:(\w+(?:\([^)]*\))?(?:\s*,\s*\w+(?:\([^)]*\))?)*))?\s*\{',
            'modifier': r'modifier\s+(\w+)\s*(?:\(([^)]*)\))?\s*\{',
            'event': r'event\s+(\w+)\s*\(([^)]*)\)\s*;',
            'state_variable': r'((?:public|private|internal)\s+)?(?:(constant|immutable)\s+)?(\w+(?:\[\])*)\s+(?:(public|private|internal)\s+)?(\w+)(?:\s*=\s*([^;]+))?\s*;',
            'using': r'using\s+(\w+)\s+for\s+([^;]+);',
        }
        
        # Compile patterns for performance
        self.compiled_patterns = {
            name: re.compile(pattern, re.MULTILINE | re.DOTALL)
            for name, pattern in self.patterns.items()
        }

    def parse(self, source_code: str) -> ParsedContract:
        """
        Parse Solidity source code and return structured representation.
        
        Args:
            source_code: The Solidity source code to parse
            
        Returns:
            ParsedContract: Structured representation of the contract
        """
        try:
            parsed_contract = ParsedContract(source_code=source_code)
            
            # Remove comments for easier parsing
            cleaned_code = self._remove_comments(source_code)
            
            # Extract top-level elements
            parsed_contract.pragma_statements = self._extract_pragma_statements(source_code)
            parsed_contract.license = self._extract_license(source_code)
            parsed_contract.imports = self._extract_imports(source_code)
            
            # Extract contracts
            contracts = self._extract_contracts(cleaned_code)
            parsed_contract.contracts = contracts
            
            self.logger.info(f"Successfully parsed {len(contracts)} contracts")
            return parsed_contract
            
        except Exception as e:
            self.logger.error(f"Error parsing contract: {str(e)}")
            parsed_contract.parse_errors.append(str(e))
            return parsed_contract

    def _remove_comments(self, code: str) -> str:
        """Remove single-line and multi-line comments."""
        # Remove single-line comments
        code = re.sub(r'//.*?$', '', code, flags=re.MULTILINE)
        # Remove multi-line comments
        code = re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)
        return code

    def _extract_pragma_statements(self, code: str) -> List[str]:
        """Extract pragma statements."""
        matches = self.compiled_patterns['pragma'].findall(code)
        return matches

    def _extract_license(self, code: str) -> Optional[str]:
        """Extract SPDX license identifier."""
        match = self.compiled_patterns['license'].search(code)
        return match.group(1).strip() if match else None

    def _extract_imports(self, code: str) -> List[str]:
        """Extract import statements."""
        imports = []
        for match in self.compiled_patterns['import'].finditer(code):
            if match.group(1):  # Simple import
                imports.append(match.group(1))
            elif match.group(2):
                imports.append(match.group(2))
            elif match.group(4):  # Named import
                imports.append(match.group(4))
            elif match.group(5):
                imports.append(match.group(5))
        return imports

    def _extract_contracts(self, code: str) -> List[Contract]:
        """Extract contract definitions."""
        contracts = []
        
        for match in self.compiled_patterns['contract'].finditer(code):
            contract_type = match.group(1)  # contract, interface, library
            contract_name = match.group(2)
            inheritance = match.group(3)
            
            # Find contract body
            start_pos = match.end()
            contract_body = self._extract_contract_body(code, start_pos)
            
            # Parse inheritance
            inherits = []
            if inheritance:
                inherits = [name.strip() for name in inheritance.split(',')]
            
            contract = Contract(
                name=contract_name,
                contract_type=contract_type,
                inherits=inherits,
                location=(match.start(), match.end())
            )
            
            # Parse contract contents
            self._parse_contract_contents(contract, contract_body)
            contracts.append(contract)
            
        return contracts

    def _extract_contract_body(self, code: str, start_pos: int) -> str:
        """Extract the body of a contract by matching braces."""
        brace_count = 0
        body_start = -1
        
        for i in range(start_pos, len(code)):
            if code[i] == '{':
                if brace_count == 0:
                    body_start = i + 1
                brace_count += 1
            elif code[i] == '}':
                brace_count -= 1
                if brace_count == 0:
                    return code[body_start:i]
        
        return code[body_start:] if body_start != -1 else ""

    def _parse_contract_contents(self, contract: Contract, body: str):
        """Parse the contents of a contract body."""
        # Parse state variables
        contract.state_variables = self._extract_state_variables(body)
        
        # Parse functions
        contract.functions = self._extract_functions(body)
        
        # Parse events
        contract.events = self._extract_events(body)
        
        # Parse modifiers
        contract.modifiers = self._extract_modifiers(body)
        
        # Parse using statements
        contract.using_statements = self._extract_using_statements(body)

    def _extract_state_variables(self, body: str) -> List[Variable]:
        """Extract state variable declarations."""
        variables = []
        
        # More comprehensive regex for state variables
        pattern = r'(?:^|\n)\s*(?:(public|private|internal)\s+)?(?:(constant|immutable)\s+)?(\w+(?:\s*\[\s*\d*\s*\])*)\s+(?:(public|private|internal)\s+)?(\w+)(?:\s*=\s*([^;]+))?\s*;'
        
        for match in re.finditer(pattern, body, re.MULTILINE):
            visibility1 = match.group(1)
            modifier = match.group(2)
            var_type = match.group(3)
            visibility2 = match.group(4)
            var_name = match.group(5)
            initial_value = match.group(6)
            
            # Determine final visibility
            visibility = visibility2 or visibility1 or "internal"
            
            variable = Variable(
                name=var_name,
                type=var_type,
                visibility=visibility,
                is_constant=modifier == "constant",
                is_immutable=modifier == "immutable",
                initial_value=initial_value.strip() if initial_value else None,
                location=(match.start(), match.end())
            )
            
            variables.append(variable)
            
        return variables

    def _extract_functions(self, body: str) -> List[Function]:
        """Extract function declarations."""
        functions = []
        
        # Function pattern
        func_pattern = r'function\s+(\w+)?\s*\(([^)]*)\)\s*(external|public|internal|private)?\s*(pure|view|payable|nonpayable)?\s*(virtual|override)?\s*(?:returns\s*\(([^)]*)\))?\s*(?:(\w+(?:\([^)]*\))?(?:\s*,\s*\w+(?:\([^)]*\))?)*))?\s*\{'
        
        for match in re.finditer(func_pattern, body):
            func_name = match.group(1) or "fallback"
            parameters_str = match.group(2)
            visibility_str = match.group(3) or "internal"
            mutability_str = match.group(4) or "nonpayable"
            virtual_override = match.group(5)
            returns_str = match.group(6)
            modifiers_str = match.group(7)
            
            # Parse parameters
            parameters = self._parse_parameters(parameters_str)
            return_parameters = self._parse_parameters(returns_str) if returns_str else []
            modifiers = modifiers_str.split(',') if modifiers_str else []
            
            # Extract function body
            func_body = self._extract_function_body(body, match.end())
            
            function = Function(
                name=func_name,
                function_type=FunctionType.FUNCTION,
                visibility=Visibility(visibility_str.lower()),
                state_mutability=StateMutability(mutability_str.lower()),
                parameters=parameters,
                return_parameters=return_parameters,
                modifiers=[mod.strip() for mod in modifiers],
                body=func_body,
                location=(match.start(), match.end()),
                is_virtual="virtual" in (virtual_override or ""),
                is_override="override" in (virtual_override or "")
            )
            
            functions.append(function)
        
        # Extract constructors
        constructor_pattern = r'constructor\s*\(([^)]*)\)\s*(public|internal)?\s*(payable)?\s*(?:(\w+(?:\([^)]*\))?(?:\s*,\s*\w+(?:\([^)]*\))?)*))?\s*\{'
        
        for match in re.finditer(constructor_pattern, body):
            parameters_str = match.group(1)
            visibility_str = match.group(2) or "internal"
            is_payable = match.group(3) == "payable"
            modifiers_str = match.group(4)
            
            parameters = self._parse_parameters(parameters_str)
            modifiers = modifiers_str.split(',') if modifiers_str else []
            func_body = self._extract_function_body(body, match.end())
            
            constructor = Function(
                name="constructor",
                function_type=FunctionType.CONSTRUCTOR,
                visibility=Visibility(visibility_str.lower()),
                state_mutability=StateMutability.PAYABLE if is_payable else StateMutability.NONPAYABLE,
                parameters=parameters,
                modifiers=[mod.strip() for mod in modifiers],
                body=func_body,
                location=(match.start(), match.end())
            )
            
            functions.append(constructor)
            
        return functions

    def _extract_function_body(self, code: str, start_pos: int) -> str:
        """Extract function body by matching braces."""
        brace_count = 1  # We start after the opening brace
        body_start = start_pos
        
        for i in range(start_pos, len(code)):
            if code[i] == '{':
                brace_count += 1
            elif code[i] == '}':
                brace_count -= 1
                if brace_count == 0:
                    return code[body_start:i]
        
        return code[body_start:]

    def _parse_parameters(self, params_str: str) -> List[Dict[str, str]]:
        """Parse function parameters."""
        if not params_str or not params_str.strip():
            return []
        
        parameters = []
        param_parts = params_str.split(',')
        
        for param in param_parts:
            param = param.strip()
            if param:
                # Simple parsing - can be enhanced
                parts = param.split()
                if len(parts) >= 2:
                    param_type = parts[0]
                    param_name = parts[-1]
                    parameters.append({
                        'type': param_type,
                        'name': param_name
                    })
                elif len(parts) == 1:
                    parameters.append({
                        'type': parts[0],
                        'name': ''
                    })
        
        return parameters

    def _extract_events(self, body: str) -> List[Event]:
        """Extract event declarations."""
        events = []
        
        for match in self.compiled_patterns['event'].finditer(body):
            event_name = match.group(1)
            parameters_str = match.group(2)
            
            # Parse event parameters
            parameters = []
            if parameters_str:
                param_parts = parameters_str.split(',')
                for param in param_parts:
                    param = param.strip()
                    if param:
                        # Check for indexed keyword
                        is_indexed = 'indexed' in param
                        param_clean = param.replace('indexed', '').strip()
                        
                        parts = param_clean.split()
                        if len(parts) >= 2:
                            parameters.append({
                                'type': parts[0],
                                'name': parts[1],
                                'indexed': is_indexed
                            })
            
            event = Event(
                name=event_name,
                parameters=parameters,
                location=(match.start(), match.end())
            )
            
            events.append(event)
            
        return events

    def _extract_modifiers(self, body: str) -> List[Modifier]:
        """Extract modifier declarations."""
        modifiers = []
        
        for match in self.compiled_patterns['modifier'].finditer(body):
            modifier_name = match.group(1)
            parameters_str = match.group(2)
            
            parameters = self._parse_parameters(parameters_str) if parameters_str else []
            modifier_body = self._extract_function_body(body, match.end())
            
            modifier = Modifier(
                name=modifier_name,
                parameters=parameters,
                body=modifier_body,
                location=(match.start(), match.end())
            )
            
            modifiers.append(modifier)
            
        return modifiers

    def _extract_using_statements(self, body: str) -> List[str]:
        """Extract using statements."""
        using_statements = []
        
        for match in self.compiled_patterns['using'].finditer(body):
            library = match.group(1)
            target_type = match.group(2)
            using_statements.append(f"{library} for {target_type}")
            
        return using_statements

    def to_dict(self, parsed_contract: ParsedContract) -> Dict[str, Any]:
        """Convert parsed contract to dictionary for JSON serialization."""
        def contract_to_dict(contract: Contract) -> Dict[str, Any]:
            return {
                'name': contract.name,
                'contract_type': contract.contract_type,
                'inherits': contract.inherits,
                'state_variables': [
                    {
                        'name': var.name,
                        'type': var.type,
                        'visibility': var.visibility,
                        'is_constant': var.is_constant,
                        'is_immutable': var.is_immutable,
                        'initial_value': var.initial_value,
                        'location': var.location
                    }
                    for var in contract.state_variables
                ],
                'functions': [
                    {
                        'name': func.name,
                        'function_type': func.function_type.value,
                        'visibility': func.visibility.value,
                        'state_mutability': func.state_mutability.value,
                        'parameters': func.parameters,
                        'return_parameters': func.return_parameters,
                        'modifiers': func.modifiers,
                        'body': func.body,
                        'location': func.location,
                        'is_virtual': func.is_virtual,
                        'is_override': func.is_override
                    }
                    for func in contract.functions
                ],
                'events': [
                    {
                        'name': event.name,
                        'parameters': event.parameters,
                        'location': event.location
                    }
                    for event in contract.events
                ],
                'modifiers': [
                    {
                        'name': mod.name,
                        'parameters': mod.parameters,
                        'body': mod.body,
                        'location': mod.location
                    }
                    for mod in contract.modifiers
                ],
                'using_statements': contract.using_statements,
                'location': contract.location
            }
        
        return {
            'source_code': parsed_contract.source_code,
            'contracts': [contract_to_dict(contract) for contract in parsed_contract.contracts],
            'pragma_statements': parsed_contract.pragma_statements,
            'license': parsed_contract.license,
            'imports': parsed_contract.imports,
            'parse_errors': parsed_contract.parse_errors
        }

    def get_contract_summary(self, parsed_contract: ParsedContract) -> Dict[str, Any]:
        """Get a high-level summary of the parsed contract."""
        summary = {
            'total_contracts': len(parsed_contract.contracts),
            'contract_names': [contract.name for contract in parsed_contract.contracts],
            'contract_types': {},
            'total_functions': 0,
            'total_state_variables': 0,
            'total_events': 0,
            'total_modifiers': 0,
            'imports': len(parsed_contract.imports),
            'pragma_versions': parsed_contract.pragma_statements,
            'license': parsed_contract.license,
            'has_errors': len(parsed_contract.parse_errors) > 0,
            'errors': parsed_contract.parse_errors
        }
        
        for contract in parsed_contract.contracts:
            # Count contract types
            if contract.contract_type in summary['contract_types']:
                summary['contract_types'][contract.contract_type] += 1
            else:
                summary['contract_types'][contract.contract_type] = 1
            
            # Count functions, variables, events, modifiers
            summary['total_functions'] += len(contract.functions)
            summary['total_state_variables'] += len(contract.state_variables)
            summary['total_events'] += len(contract.events)
            summary['total_modifiers'] += len(contract.modifiers)
        
        return summary


def parse_contract_code(source_code: str, file_path: str) -> 'AnalysisContext':
    """
    Parse contract code and return an AnalysisContext.
    
    Args:
        source_code: The Solidity source code
        file_path: Path to the contract file
        
    Returns:
        AnalysisContext: Context object containing parsed contract data
    """
    from ..models.context import AnalysisContext, ContractMetadata, ContractType, FunctionContext, StateVariableContext
    
    parser = SolidityParser()
    parsed_contract = parser.parse(source_code)
    
    # Create analysis context
    context = AnalysisContext()
    context.project_name = file_path.split('/')[-1].split('.')[0]
    
    # Store the parsed contract for domain classification
    context._parsed_contract = parsed_contract
    
    # Convert parsed contracts to context format
    for contract in parsed_contract.contracts:
        metadata = ContractMetadata(
            name=contract.name,
            contract_type=ContractType(contract.contract_type.lower()),
            source_file=file_path,
            inherits=contract.inherits,
            lines_of_code=source_code.count('\n')
        )
        context.add_contract(contract.name, metadata)
        
        # Add functions to context
        for func in contract.functions:
            func_context = FunctionContext(
                name=func.name,
                signature=f"{func.name}({','.join([p['type'] for p in func.parameters])})",
                visibility=func.visibility.value,
                state_mutability=func.state_mutability.value,
                function_type=func.function_type.value,
                modifiers=func.modifiers,
                parameters=func.parameters,
                return_parameters=func.return_parameters,
                body=func.body
            )
            context.add_function(contract.name, func_context)
            
        # Add state variables to context
        for var in contract.state_variables:
            var_context = StateVariableContext(
                name=var.name,
                type=var.type,
                visibility=var.visibility or 'internal',
                is_constant=var.is_constant,
                is_immutable=var.is_immutable,
                initial_value=var.initial_value
            )
            context.add_state_variable(contract.name, var_context)
    
    return context
