"""
AST (Abstract Syntax Tree) utilities for Solidity smart contract analysis.
"""

import re
import logging
from typing import Dict, List, Optional, Any, Set, Tuple, Union
from dataclasses import dataclass, field
from collections import defaultdict, deque

from ..models.context import FunctionContext, StateVariableContext, CodeLocation

logger = logging.getLogger(__name__)

@dataclass
class CallInfo:
    """Information about a function call."""
    caller: str
    callee: str
    call_type: str  # internal, external, delegate
    location: Optional[CodeLocation] = None
    arguments: List[str] = field(default_factory=list)

@dataclass
class DependencyInfo:
    """Information about dependencies between functions/contracts."""
    source: str
    target: str
    dependency_type: str  # calls, inherits, imports, uses
    strength: float = 1.0  # dependency strength 0-1

class ASTAnalyzer:
    """
    Advanced AST analyzer for Solidity smart contracts.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Solidity syntax patterns
        self.patterns = {
            'function_declaration': r'function\s+(\w+)\s*\([^)]*\)\s*([^{]*)\s*\{',
            'modifier_declaration': r'modifier\s+(\w+)\s*(?:\([^)]*\))?\s*\{',
            'event_declaration': r'event\s+(\w+)\s*\([^)]*\)\s*;',
            'struct_declaration': r'struct\s+(\w+)\s*\{',
            'enum_declaration': r'enum\s+(\w+)\s*\{',
            'function_call': r'(\w+)\s*\(',
            'external_call': r'(\w+)\.(\w+)\s*\(',
            'state_variable': r'^\s*(?:public|private|internal)\s+(\w+)\s+(\w+)',
            'mapping_declaration': r'mapping\s*\(\s*(\w+)\s*=>\s*([^)]+)\)\s+(\w+)',
            'array_declaration': r'(\w+)\[\]\s+(\w+)',
            'require_statement': r'require\s*\(',
            'assert_statement': r'assert\s*\(',
            'revert_statement': r'revert\s*\(',
            'if_statement': r'\bif\s*\(',
            'for_loop': r'\bfor\s*\(',
            'while_loop': r'\bwhile\s*\(',
            'assembly_block': r'assembly\s*\{',
            'inline_assembly': r'assembly\s*\{[^}]*\}',
            'delegatecall': r'\.delegatecall\s*\(',
            'call_function': r'\.call\s*\(',
            'send_function': r'\.send\s*\(',
            'transfer_function': r'\.transfer\s*\(',
            'selfdestruct': r'selfdestruct\s*\(',
            'suicide': r'suicide\s*\('
        }
        
        # Compile patterns for performance
        self.compiled_patterns = {
            name: re.compile(pattern, re.MULTILINE | re.IGNORECASE)
            for name, pattern in self.patterns.items()
        }

    def analyze_contract_ast(self, source_code: str, contract_name: str) -> Dict[str, Any]:
        """
        Perform comprehensive AST analysis of a contract.
        
        Args:
            source_code: Solidity source code
            contract_name: Name of the contract to analyze
            
        Returns:
            Dict containing AST analysis results
        """
        try:
            analysis_result = {
                'contract_name': contract_name,
                'functions': [],
                'state_variables': [],
                'modifiers': [],
                'events': [],
                'structs': [],
                'enums': [],
                'call_graph': {},
                'complexity_metrics': {},
                'security_patterns': [],
                'control_flow': {},
                'data_flow': {}
            }
            
            # Extract contract body
            contract_body = self._extract_contract_body(source_code, contract_name)
            if not contract_body:
                self.logger.warning(f"Could not extract body for contract {contract_name}")
                return analysis_result
            
            # Analyze different components
            analysis_result['functions'] = self._analyze_functions(contract_body)
            analysis_result['state_variables'] = self._analyze_state_variables(contract_body)
            analysis_result['modifiers'] = self._analyze_modifiers(contract_body)
            analysis_result['events'] = self._analyze_events(contract_body)
            analysis_result['structs'] = self._analyze_structs(contract_body)
            analysis_result['enums'] = self._analyze_enums(contract_body)
            
            # Build call graph
            analysis_result['call_graph'] = self._build_call_graph(contract_body, analysis_result['functions'])
            
            # Calculate complexity metrics
            analysis_result['complexity_metrics'] = self._calculate_complexity_metrics(contract_body, analysis_result)
            
            # Detect security patterns
            analysis_result['security_patterns'] = self._detect_security_patterns(contract_body)
            
            # Analyze control flow
            analysis_result['control_flow'] = self._analyze_control_flow(contract_body, analysis_result['functions'])
            
            # Analyze data flow
            analysis_result['data_flow'] = self._analyze_data_flow(contract_body, analysis_result)
            
            self.logger.info(f"AST analysis completed for contract {contract_name}")
            return analysis_result
            
        except Exception as e:
            self.logger.error(f"Error in AST analysis for {contract_name}: {str(e)}")
            return analysis_result

    def _extract_contract_body(self, source_code: str, contract_name: str) -> str:
        """Extract the body of a specific contract."""
        pattern = rf'\b(?:contract|library|interface)\s+{contract_name}\b[^{{]*\{{'
        match = re.search(pattern, source_code)
        
        if not match:
            return ""
        
        start = match.end() - 1  # Include opening brace
        brace_count = 1
        current_pos = start + 1
        
        while current_pos < len(source_code) and brace_count > 0:
            char = source_code[current_pos]
            if char == '{':
                brace_count += 1
            elif char == '}':
                brace_count -= 1
            current_pos += 1
        
        return source_code[start:current_pos-1] if brace_count == 0 else ""

    def _analyze_functions(self, contract_body: str) -> List[Dict[str, Any]]:
        """Analyze all functions in the contract."""
        functions = []
        
        for match in self.compiled_patterns['function_declaration'].finditer(contract_body):
            func_name = match.group(1)
            func_signature = match.group(2).strip()
            func_start = match.start()
            
            # Extract function body
            func_body = self._extract_function_body(contract_body, match.end())
            
            # Parse function signature
            visibility, mutability, modifiers = self._parse_function_signature(func_signature)
            
            # Analyze function complexity
            complexity = self._calculate_function_complexity(func_body)
            
            # Detect function patterns
            patterns = self._detect_function_patterns(func_body)
            
            function_info = {
                'name': func_name,
                'signature': func_signature,
                'visibility': visibility,
                'state_mutability': mutability,
                'modifiers': modifiers,
                'body': func_body,
                'start_position': func_start,
                'complexity': complexity,
                'patterns': patterns,
                'calls_made': self._extract_function_calls(func_body),
                'state_changes': self._detect_state_changes(func_body),
                'external_interactions': self._detect_external_interactions(func_body)
            }
            
            functions.append(function_info)
        
        return functions

    def _extract_function_body(self, contract_body: str, start_pos: int) -> str:
        """Extract function body starting from given position."""
        brace_count = 1
        current_pos = start_pos
        
        while current_pos < len(contract_body) and brace_count > 0:
            char = contract_body[current_pos]
            if char == '{':
                brace_count += 1
            elif char == '}':
                brace_count -= 1
            current_pos += 1
        
        return contract_body[start_pos:current_pos-1] if brace_count == 0 else ""

    def _parse_function_signature(self, signature: str) -> Tuple[str, str, List[str]]:
        """Parse function signature to extract visibility, mutability, and modifiers."""
        visibility = "internal"  # default
        mutability = "nonpayable"  # default
        modifiers = []
        
        tokens = signature.split()
        
        for token in tokens:
            if token in ['public', 'private', 'internal', 'external']:
                visibility = token
            elif token in ['pure', 'view', 'payable', 'nonpayable']:
                mutability = token
            elif token not in ['returns', 'virtual', 'override'] and not token.startswith('('):
                # Likely a modifier
                modifiers.append(token)
        
        return visibility, mutability, modifiers

    def _analyze_state_variables(self, contract_body: str) -> List[Dict[str, Any]]:
        """Analyze state variables in the contract."""
        variables = []
        
        # Regular state variables
        for match in self.compiled_patterns['state_variable'].finditer(contract_body):
            var_type = match.group(1)
            var_name = match.group(2)
            
            variables.append({
                'name': var_name,
                'type': var_type,
                'visibility': 'internal',  # Default, would need more parsing
                'is_constant': 'constant' in match.group(0),
                'is_immutable': 'immutable' in match.group(0),
                'position': match.start()
            })
        
        # Mapping declarations
        for match in self.compiled_patterns['mapping_declaration'].finditer(contract_body):
            key_type = match.group(1)
            value_type = match.group(2)
            var_name = match.group(3)
            
            variables.append({
                'name': var_name,
                'type': f'mapping({key_type} => {value_type})',
                'visibility': 'internal',
                'is_mapping': True,
                'key_type': key_type,
                'value_type': value_type,
                'position': match.start()
            })
        
        # Array declarations
        for match in self.compiled_patterns['array_declaration'].finditer(contract_body):
            element_type = match.group(1)
            var_name = match.group(2)
            
            variables.append({
                'name': var_name,
                'type': f'{element_type}[]',
                'visibility': 'internal',
                'is_array': True,
                'element_type': element_type,
                'position': match.start()
            })
        
        return variables

    def _analyze_modifiers(self, contract_body: str) -> List[Dict[str, Any]]:
        """Analyze modifiers in the contract."""
        modifiers = []
        
        for match in self.compiled_patterns['modifier_declaration'].finditer(contract_body):
            modifier_name = match.group(1)
            modifier_body = self._extract_function_body(contract_body, match.end())
            
            modifiers.append({
                'name': modifier_name,
                'body': modifier_body,
                'position': match.start(),
                'complexity': self._calculate_function_complexity(modifier_body)
            })
        
        return modifiers

    def _analyze_events(self, contract_body: str) -> List[Dict[str, Any]]:
        """Analyze events in the contract."""
        events = []
        
        for match in self.compiled_patterns['event_declaration'].finditer(contract_body):
            event_name = match.group(1)
            
            events.append({
                'name': event_name,
                'position': match.start(),
                'declaration': match.group(0)
            })
        
        return events

    def _analyze_structs(self, contract_body: str) -> List[Dict[str, Any]]:
        """Analyze struct declarations in the contract."""
        structs = []
        
        for match in self.compiled_patterns['struct_declaration'].finditer(contract_body):
            struct_name = match.group(1)
            struct_body = self._extract_function_body(contract_body, match.end())
            
            structs.append({
                'name': struct_name,
                'body': struct_body,
                'position': match.start()
            })
        
        return structs

    def _analyze_enums(self, contract_body: str) -> List[Dict[str, Any]]:
        """Analyze enum declarations in the contract."""
        enums = []
        
        for match in self.compiled_patterns['enum_declaration'].finditer(contract_body):
            enum_name = match.group(1)
            enum_body = self._extract_function_body(contract_body, match.end())
            
            enums.append({
                'name': enum_name,
                'body': enum_body,
                'position': match.start()
            })
        
        return enums

    def _build_call_graph(self, contract_body: str, functions: List[Dict[str, Any]]) -> Dict[str, List[str]]:
        """Build call graph showing function call relationships."""
        call_graph = defaultdict(list)
        
        for func in functions:
            func_name = func['name']
            func_body = func['body']
            
            # Find function calls within this function
            calls = self._extract_function_calls(func_body)
            call_graph[func_name] = calls
        
        return dict(call_graph)

    def _extract_function_calls(self, function_body: str) -> List[str]:
        """Extract function calls from function body."""
        calls = []
        
        # Internal function calls
        for match in self.compiled_patterns['function_call'].finditer(function_body):
            function_name = match.group(1)
            # Filter out keywords and common patterns
            if function_name not in ['require', 'assert', 'revert', 'if', 'for', 'while']:
                calls.append(function_name)
        
        # External calls
        for match in self.compiled_patterns['external_call'].finditer(function_body):
            contract_name = match.group(1)
            function_name = match.group(2)
            calls.append(f"{contract_name}.{function_name}")
        
        return list(set(calls))  # Remove duplicates

    def _calculate_function_complexity(self, function_body: str) -> Dict[str, int]:
        """Calculate complexity metrics for a function."""
        complexity = {
            'cyclomatic': 1,  # Base complexity
            'lines_of_code': len([line for line in function_body.split('\n') if line.strip()]),
            'control_structures': 0,
            'function_calls': 0,
            'state_changes': 0
        }
        
        # Count control structures (each adds to cyclomatic complexity)
        control_patterns = ['if_statement', 'for_loop', 'while_loop']
        for pattern_name in control_patterns:
            matches = self.compiled_patterns[pattern_name].findall(function_body)
            count = len(matches)
            complexity['control_structures'] += count
            complexity['cyclomatic'] += count
        
        # Count function calls
        complexity['function_calls'] = len(self._extract_function_calls(function_body))
        
        # Count potential state changes
        state_change_patterns = ['require_statement', 'assert_statement']
        for pattern_name in state_change_patterns:
            complexity['state_changes'] += len(self.compiled_patterns[pattern_name].findall(function_body))
        
        return complexity

    def _calculate_complexity_metrics(self, contract_body: str, analysis_result: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate overall complexity metrics for the contract."""
        metrics = {
            'total_functions': len(analysis_result['functions']),
            'total_state_variables': len(analysis_result['state_variables']),
            'total_modifiers': len(analysis_result['modifiers']),
            'average_function_complexity': 0.0,
            'max_function_complexity': 0,
            'total_lines_of_code': len([line for line in contract_body.split('\n') if line.strip()]),
            'complexity_distribution': defaultdict(int)
        }
        
        if metrics['total_functions'] > 0:
            complexities = [func['complexity']['cyclomatic'] for func in analysis_result['functions']]
            metrics['average_function_complexity'] = sum(complexities) / len(complexities)
            metrics['max_function_complexity'] = max(complexities)
            
            # Distribution of complexity
            for complexity in complexities:
                if complexity <= 5:
                    metrics['complexity_distribution']['low'] += 1
                elif complexity <= 10:
                    metrics['complexity_distribution']['medium'] += 1
                else:
                    metrics['complexity_distribution']['high'] += 1
        
        return dict(metrics)

    def _detect_security_patterns(self, contract_body: str) -> List[Dict[str, Any]]:
        """Detect security-relevant patterns in the contract."""
        patterns = []
        
        security_checks = {
            'delegatecall': 'Potential delegatecall usage',
            'call_function': 'Low-level call usage',
            'send_function': 'Send function usage',
            'transfer_function': 'Transfer function usage',
            'selfdestruct': 'Selfdestruct usage',
            'suicide': 'Suicide function usage (deprecated)',
            'assembly_block': 'Inline assembly usage'
        }
        
        for pattern_name, description in security_checks.items():
            matches = list(self.compiled_patterns[pattern_name].finditer(contract_body))
            for match in matches:
                patterns.append({
                    'type': pattern_name,
                    'description': description,
                    'location': match.start(),
                    'code_snippet': match.group(0)
                })
        
        return patterns

    def _detect_state_changes(self, function_body: str) -> List[str]:
        """Detect potential state changes in function body."""
        state_changes = []
        
        # Look for assignment patterns (simplified)
        assignment_pattern = r'(\w+)\s*=\s*'
        for match in re.finditer(assignment_pattern, function_body):
            var_name = match.group(1)
            if not var_name in ['i', 'j', 'k', 'temp', 'tmp']:  # Skip common loop variables
                state_changes.append(var_name)
        
        return list(set(state_changes))

    def _detect_external_interactions(self, function_body: str) -> List[Dict[str, Any]]:
        """Detect external interactions in function body."""
        interactions = []
        
        external_patterns = {
            'external_call': 'External contract call',
            'delegatecall': 'Delegatecall interaction',
            'call_function': 'Low-level call',
            'send_function': 'Ether send',
            'transfer_function': 'Ether transfer'
        }
        
        for pattern_name, description in external_patterns.items():
            for match in self.compiled_patterns[pattern_name].finditer(function_body):
                interactions.append({
                    'type': pattern_name,
                    'description': description,
                    'location': match.start(),
                    'code': match.group(0)
                })
        
        return interactions

    def _detect_function_patterns(self, function_body: str) -> List[str]:
        """Detect common patterns in function."""
        patterns = []
        
        # Check for common security patterns
        if self.compiled_patterns['require_statement'].search(function_body):
            patterns.append('input_validation')
        
        if self.compiled_patterns['assembly_block'].search(function_body):
            patterns.append('inline_assembly')
        
        if re.search(r'msg\.sender', function_body):
            patterns.append('sender_check')
        
        if re.search(r'msg\.value', function_body):
            patterns.append('value_handling')
        
        if re.search(r'block\.timestamp', function_body):
            patterns.append('timestamp_dependency')
        
        return patterns

    def _analyze_control_flow(self, contract_body: str, functions: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze control flow patterns."""
        control_flow = {
            'total_branches': 0,
            'max_nesting_depth': 0,
            'loop_count': 0,
            'conditional_count': 0,
            'function_flows': {}
        }
        
        for func in functions:
            func_name = func['name']
            func_body = func['body']
            
            # Count control structures
            if_count = len(self.compiled_patterns['if_statement'].findall(func_body))
            for_count = len(self.compiled_patterns['for_loop'].findall(func_body))
            while_count = len(self.compiled_patterns['while_loop'].findall(func_body))
            
            control_flow['conditional_count'] += if_count
            control_flow['loop_count'] += for_count + while_count
            control_flow['total_branches'] += if_count
            
            control_flow['function_flows'][func_name] = {
                'conditionals': if_count,
                'loops': for_count + while_count,
                'nesting_estimate': self._estimate_nesting_depth(func_body)
            }
            
            # Update max nesting depth
            nesting = control_flow['function_flows'][func_name]['nesting_estimate']
            if nesting > control_flow['max_nesting_depth']:
                control_flow['max_nesting_depth'] = nesting
        
        return control_flow

    def _estimate_nesting_depth(self, code: str) -> int:
        """Estimate maximum nesting depth in code."""
        depth = 0
        max_depth = 0
        
        for char in code:
            if char == '{':
                depth += 1
                max_depth = max(max_depth, depth)
            elif char == '}':
                depth = max(0, depth - 1)
        
        return max_depth

    def _analyze_data_flow(self, contract_body: str, analysis_result: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze data flow patterns."""
        data_flow = {
            'state_variable_usage': defaultdict(list),
            'parameter_flow': {},
            'return_value_flow': {},
            'global_access_patterns': []
        }
        
        state_vars = [var['name'] for var in analysis_result['state_variables']]
        
        for func in analysis_result['functions']:
            func_name = func['name']
            func_body = func['body']
            
            # Check which state variables are accessed
            for var_name in state_vars:
                if re.search(rf'\b{var_name}\b', func_body):
                    data_flow['state_variable_usage'][var_name].append(func_name)
            
            # Check for global variable access
            global_vars = ['msg.sender', 'msg.value', 'block.timestamp', 'block.number', 'tx.origin']
            for global_var in global_vars:
                if global_var in func_body:
                    data_flow['global_access_patterns'].append({
                        'function': func_name,
                        'global_var': global_var
                    })
        
        return dict(data_flow)

class FunctionExtractor:
    """Specialized extractor for function information."""
    
    def __init__(self):
        self.ast_analyzer = ASTAnalyzer()

    def extract_functions(self, source_code: str, contract_name: str) -> List[FunctionContext]:
        """Extract function contexts from source code."""
        ast_result = self.ast_analyzer.analyze_contract_ast(source_code, contract_name)
        function_contexts = []
        
        for func_data in ast_result['functions']:
            location = CodeLocation(
                contract_name=contract_name,
                function_name=func_data['name'],
                line_number=self._calculate_line_number(source_code, func_data['start_position'])
            )
            
            context = FunctionContext(
                name=func_data['name'],
                signature=func_data['signature'],
                visibility=func_data['visibility'],
                state_mutability=func_data['state_mutability'],
                function_type='function',
                modifiers=func_data['modifiers'],
                body=func_data['body'],
                location=location,
                complexity_score=func_data['complexity']['cyclomatic'],
                has_external_calls=len(func_data['external_interactions']) > 0,
                has_state_changes=len(func_data['state_changes']) > 0,
                is_payable=func_data['state_mutability'] == 'payable'
            )
            
            function_contexts.append(context)
        
        return function_contexts

    def _calculate_line_number(self, source_code: str, position: int) -> int:
        """Calculate line number from character position."""
        return source_code[:position].count('\n') + 1

class VariableExtractor:
    """Specialized extractor for state variable information."""
    
    def __init__(self):
        self.ast_analyzer = ASTAnalyzer()

    def extract_state_variables(self, source_code: str, contract_name: str) -> List[StateVariableContext]:
        """Extract state variable contexts from source code."""
        ast_result = self.ast_analyzer.analyze_contract_ast(source_code, contract_name)
        variable_contexts = []
        
        for var_data in ast_result['state_variables']:
            location = CodeLocation(
                contract_name=contract_name,
                line_number=self._calculate_line_number(source_code, var_data['position'])
            )
            
            context = StateVariableContext(
                name=var_data['name'],
                type=var_data['type'],
                visibility=var_data['visibility'],
                is_constant=var_data.get('is_constant', False),
                is_immutable=var_data.get('is_immutable', False),
                location=location
            )
            
            variable_contexts.append(context)
        
        return variable_contexts

    def _calculate_line_number(self, source_code: str, position: int) -> int:
        """Calculate line number from character position."""
        return source_code[:position].count('\n') + 1

class CallGraphBuilder:
    """Builds call graphs for smart contracts."""
    
    def __init__(self):
        self.ast_analyzer = ASTAnalyzer()

    def build_call_graph(self, source_code: str, contract_name: str) -> Dict[str, Any]:
        """Build comprehensive call graph."""
        ast_result = self.ast_analyzer.analyze_contract_ast(source_code, contract_name)
        
        call_graph = {
            'nodes': [],
            'edges': [],
            'metrics': {},
            'critical_paths': [],
            'dependency_analysis': {}
        }
        
        # Create nodes for each function
        for func in ast_result['functions']:
            call_graph['nodes'].append({
                'id': func['name'],
                'type': 'function',
                'visibility': func['visibility'],
                'complexity': func['complexity']['cyclomatic'],
                'external_interactions': len(func['external_interactions'])
            })
        
        # Create edges for function calls
        for caller, callees in ast_result['call_graph'].items():
            for callee in callees:
                call_graph['edges'].append({
                    'source': caller,
                    'target': callee,
                    'type': 'calls'
                })
        
        # Calculate metrics
        call_graph['metrics'] = self._calculate_graph_metrics(call_graph)
        
        # Identify critical paths
        call_graph['critical_paths'] = self._identify_critical_paths(call_graph)
        
        return call_graph

    def _calculate_graph_metrics(self, call_graph: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate call graph metrics."""
        nodes = call_graph['nodes']
        edges = call_graph['edges']
        
        metrics = {
            'total_functions': len(nodes),
            'total_calls': len(edges),
            'average_calls_per_function': len(edges) / len(nodes) if nodes else 0,
            'max_function_complexity': max((node['complexity'] for node in nodes), default=0),
            'functions_with_external_calls': len([node for node in nodes if node['external_interactions'] > 0])
        }
        
        return metrics

    def _identify_critical_paths(self, call_graph: Dict[str, Any]) -> List[str]:
        """Identify critical execution paths."""
        # Simplified implementation - would need more sophisticated analysis
        critical_paths = []
        
        # Find high-complexity functions
        high_complexity_funcs = [
            node['id'] for node in call_graph['nodes'] 
            if node['complexity'] > 10
        ]
        
        # Find functions with external interactions
        external_funcs = [
            node['id'] for node in call_graph['nodes']
            if node['external_interactions'] > 0
        ]
        
        critical_paths.extend([f"High complexity: {func}" for func in high_complexity_funcs])
        critical_paths.extend([f"External interactions: {func}" for func in external_funcs])
        
        return critical_paths

class ComplexityCalculator:
    """Calculates various complexity metrics for smart contracts."""
    
    def __init__(self):
        self.ast_analyzer = ASTAnalyzer()

    def calculate_complexity(self, source_code: str, contract_name: str) -> Dict[str, Any]:
        """Calculate comprehensive complexity metrics."""
        ast_result = self.ast_analyzer.analyze_contract_ast(source_code, contract_name)
        
        complexity = {
            'cyclomatic_complexity': self._calculate_cyclomatic_complexity(ast_result),
            'cognitive_complexity': self._calculate_cognitive_complexity(ast_result),
            'halstead_metrics': self._calculate_halstead_metrics(source_code),
            'maintainability_index': 0.0,
            'function_complexities': {},
            'overall_rating': 'medium'
        }
        
        # Calculate per-function complexity
        for func in ast_result['functions']:
            complexity['function_complexities'][func['name']] = {
                'cyclomatic': func['complexity']['cyclomatic'],
                'lines_of_code': func['complexity']['lines_of_code'],
                'control_structures': func['complexity']['control_structures']
            }
        
        # Calculate maintainability index
        complexity['maintainability_index'] = self._calculate_maintainability_index(complexity)
        
        # Determine overall rating
        complexity['overall_rating'] = self._determine_complexity_rating(complexity)
        
        return complexity

    def _calculate_cyclomatic_complexity(self, ast_result: Dict[str, Any]) -> int:
        """Calculate total cyclomatic complexity."""
        total = sum(func['complexity']['cyclomatic'] for func in ast_result['functions'])
        return total

    def _calculate_cognitive_complexity(self, ast_result: Dict[str, Any]) -> int:
        """Calculate cognitive complexity (simplified)."""
        # Cognitive complexity considers nesting and other factors
        # This is a simplified implementation
        total = 0
        for func in ast_result['functions']:
            # Base complexity plus nesting penalty
            base = func['complexity']['cyclomatic']
            nesting_penalty = func['complexity']['control_structures'] * 2
            total += base + nesting_penalty
        return total

    def _calculate_halstead_metrics(self, source_code: str) -> Dict[str, Any]:
        """Calculate Halstead complexity metrics."""
        # Simplified Halstead metrics calculation
        operators = len(re.findall(r'[+\-*/=<>!&|]', source_code))
        operands = len(re.findall(r'\b\w+\b', source_code))
        
        unique_operators = len(set(re.findall(r'[+\-*/=<>!&|]', source_code)))
        unique_operands = len(set(re.findall(r'\b\w+\b', source_code)))
        
        vocabulary = unique_operators + unique_operands
        length = operators + operands
        
        volume = length * (vocabulary.bit_length() if vocabulary > 0 else 0)
        
        return {
            'vocabulary': vocabulary,
            'length': length,
            'volume': volume,
            'difficulty': (unique_operators / 2) * (operands / unique_operands) if unique_operands > 0 else 0,
            'effort': volume * ((unique_operators / 2) * (operands / unique_operands)) if unique_operands > 0 else 0
        }

    def _calculate_maintainability_index(self, complexity: Dict[str, Any]) -> float:
        """Calculate maintainability index."""
        # Simplified maintainability index
        cyclomatic = complexity['cyclomatic_complexity']
        halstead_volume = complexity['halstead_metrics']['volume']
        
        # MI = 171 - 5.2 * ln(V) - 0.23 * G - 16.2 * ln(LOC)
        # Simplified version
        if halstead_volume > 0 and cyclomatic > 0:
            import math
            mi = 171 - 5.2 * math.log(halstead_volume) - 0.23 * cyclomatic
            return max(0, min(100, mi))
        
        return 50.0  # Default value

    def _determine_complexity_rating(self, complexity: Dict[str, Any]) -> str:
        """Determine overall complexity rating."""
        cyclomatic = complexity['cyclomatic_complexity']
        maintainability = complexity['maintainability_index']
        
        if cyclomatic > 50 or maintainability < 30:
            return 'very_high'
        elif cyclomatic > 30 or maintainability < 50:
            return 'high'
        elif cyclomatic > 15 or maintainability < 70:
            return 'medium'
        elif cyclomatic > 5 or maintainability < 85:
            return 'low'
        else:
            return 'very_low'
