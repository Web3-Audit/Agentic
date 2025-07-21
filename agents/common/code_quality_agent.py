"""
Code quality agent for analyzing smart contract code quality and best practices.
"""

import re
import logging
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass

from ..base_agent import BaseAgent
from ...models.context import AnalysisContext, FunctionContext
from ...models.finding import Finding, Severity, Category, CodeLocation
from ...utils.regex_utils import CodePatternAnalyzer
from ...llm.client import LLMClient
from ...llm.prompts import PromptManager

logger = logging.getLogger(__name__)

@dataclass
class CodeQualityMetrics:
    """Code quality metrics."""
    complexity_score: float = 0.0
    maintainability_index: float = 0.0
    documentation_coverage: float = 0.0
    naming_consistency: float = 0.0
    function_length_avg: float = 0.0
    cyclomatic_complexity: int = 0

class CodeQualityAgent(BaseAgent):
    """
    Agent focused on code quality, best practices, and maintainability.
    """
    
    def __init__(self, llm_client: Optional[LLMClient] = None, 
                 prompt_manager: Optional[PromptManager] = None):
        super().__init__("CodeQualityAgent", llm_client, prompt_manager)
        self.pattern_analyzer = CodePatternAnalyzer()
        
        # Code quality patterns
        self.quality_patterns = {
            'long_functions': {
                'description': 'Functions that are too long',
                'severity': Severity.LOW,
                'threshold': 50  # lines
            },
            'complex_functions': {
                'description': 'Functions with high cyclomatic complexity',
                'severity': Severity.MEDIUM,
                'threshold': 10
            },
            'missing_natspec': {
                'description': 'Missing NatSpec documentation',
                'severity': Severity.INFO,
                'patterns': [r'function\s+\w+.*\{', r'contract\s+\w+.*\{']
            },
            'inconsistent_naming': {
                'description': 'Inconsistent naming conventions',
                'severity': Severity.LOW,
                'patterns': [r'[a-z][A-Z]', r'[A-Z][a-z]']
            },
            'magic_numbers': {
                'description': 'Magic numbers in code',
                'severity': Severity.LOW,
                'patterns': [r'\b\d{2,}\b']
            },
            'duplicate_code': {
                'description': 'Potential code duplication',
                'severity': Severity.LOW
            },
            'unused_variables': {
                'description': 'Unused variables',
                'severity': Severity.INFO,
                'patterns': [r'\b\w+\s+\w+\s*;']
            },
            'gas_inefficient_patterns': {
                'description': 'Gas-inefficient code patterns',
                'severity': Severity.LOW,
                'patterns': [
                    r'for\s*\([^)]*\)\s*\{[^}]*\.push',  # Push in loop
                    r'string\s+memory',                    # String in memory
                    r'bytes\s+memory'                     # Bytes in memory
                ]
            }
        }

    async def analyze(self, context: AnalysisContext) -> List[Finding]:
        logger.info("Starting code quality analysis")
        findings: List[Finding] = []
        try:
            metrics = self._calculate_quality_metrics(context)
            for contract_name, functions in context.functions.items():
                contract_findings = self._analyze_contract_quality(contract_name, functions, context)
                findings.extend(contract_findings)
            metric_findings = self._generate_metric_findings(metrics, context)
            findings.extend(metric_findings)
            if self.llm_client:
                llm_findings = await self._llm_code_quality_analysis(context)
                findings.extend(llm_findings)
            logger.info(f"Code quality analysis completed with {len(findings)} findings")
            return findings
        except Exception as e:
            logger.error(f"Error in code quality analysis: {str(e)}")
            return findings

    def _calculate_quality_metrics(self, context: AnalysisContext) -> CodeQualityMetrics:
        """Calculate overall code quality metrics."""
        metrics = CodeQualityMetrics()
        
        total_functions = 0
        total_complexity = 0
        total_length = 0
        documented_functions = 0
        
        for functions in context.functions.values():
            for func in functions:
                total_functions += 1
                total_complexity += func.complexity_score
                
                # Estimate function length
                func_lines = len(func.body.split('\n')) if func.body else 0
                total_length += func_lines
                
                # Check for documentation
                if self._has_documentation(func):
                    documented_functions += 1
        
        if total_functions > 0:
            metrics.complexity_score = total_complexity / total_functions
            metrics.function_length_avg = total_length / total_functions
            metrics.documentation_coverage = documented_functions / total_functions
            metrics.cyclomatic_complexity = int(total_complexity)
        
        # Calculate maintainability index (simplified)
        metrics.maintainability_index = max(0, 100 - (
            metrics.complexity_score * 2 + 
            (100 - metrics.documentation_coverage * 100) * 0.5
        ))
        
        return metrics

    def _analyze_contract_quality(self, contract_name: str, 
                                 functions: List[FunctionContext],
                                 context: AnalysisContext) -> List[Finding]:
        """Analyze code quality for a specific contract."""
        findings = []
        
        # Check function complexity
        findings.extend(self._check_function_complexity(contract_name, functions))
        
        # Check function length
        findings.extend(self._check_function_length(contract_name, functions))
        
        # Check documentation
        findings.extend(self._check_documentation(contract_name, functions))
        
        # Check naming conventions
        findings.extend(self._check_naming_conventions(contract_name, functions))
        
        # Check for code smells
        findings.extend(self._check_code_smells(contract_name, functions))
        
        # Check gas efficiency
        findings.extend(self._check_gas_efficiency(contract_name, functions))
        
        return findings

    def _check_function_complexity(self, contract_name: str,
                                  functions: List[FunctionContext]) -> List[Finding]:
        """Check for overly complex functions."""
        findings = []
        complexity_threshold = self.quality_patterns['complex_functions']['threshold']
        
        for func in functions:
            if func.complexity_score > complexity_threshold:
                finding = Finding(
                    title=f"High Complexity Function: {func.name}",
                    description=f"Function '{func.name}' has cyclomatic complexity of {func.complexity_score}, which exceeds the threshold of {complexity_threshold}",
                    severity=Severity.MEDIUM,
                    category=Category.CODE_QUALITY,
                    location=CodeLocation(
                        contract_name=contract_name,
                        function_name=func.name
                    ),
                    affected_contracts=[contract_name],
                    affected_functions=[func.name],
                    recommendation="Consider breaking down this function into smaller, more focused functions",
                    impact="High complexity makes code harder to understand, test, and maintain"
                )
                findings.append(finding)
        
        return findings

    def _check_function_length(self, contract_name: str,
                              functions: List[FunctionContext]) -> List[Finding]:
        """Check for overly long functions."""
        findings = []
        length_threshold = self.quality_patterns['long_functions']['threshold']
        
        for func in functions:
            func_lines = len(func.body.split('\n')) if func.body else 0
            
            if func_lines > length_threshold:
                finding = Finding(
                    title=f"Long Function: {func.name}",
                    description=f"Function '{func.name}' has {func_lines} lines, which exceeds the threshold of {length_threshold}",
                    severity=Severity.LOW,
                    category=Category.CODE_QUALITY,
                    location=CodeLocation(
                        contract_name=contract_name,
                        function_name=func.name
                    ),
                    affected_contracts=[contract_name],
                    affected_functions=[func.name],
                    recommendation="Consider breaking down this function into smaller functions",
                    impact="Long functions are harder to understand and maintain"
                )
                findings.append(finding)
        
        return findings

    def _check_documentation(self, contract_name: str,
                           functions: List[FunctionContext]) -> List[Finding]:
        """Check for missing documentation."""
        findings = []
        
        undocumented_functions = []
        
        for func in functions:
            if not self._has_documentation(func):
                undocumented_functions.append(func.name)
        
        if undocumented_functions:
            finding = Finding(
                title="Missing Function Documentation",
                description=f"Functions lack NatSpec documentation: {', '.join(undocumented_functions)}",
                severity=Severity.INFO,
                category=Category.DOCUMENTATION,
                location=CodeLocation(contract_name=contract_name),
                affected_contracts=[contract_name],
                affected_functions=undocumented_functions,
                recommendation="Add NatSpec comments (@dev, @notice, @param, @return) to improve code documentation",
                impact="Poor documentation makes code harder to understand and maintain"
            )
            findings.append(finding)
        
        return findings

    def _check_naming_conventions(self, contract_name: str,
                                 functions: List[FunctionContext]) -> List[Finding]:
        """Check naming convention consistency."""
        findings = []
        
        # Check function naming
        camel_case_functions = []
        snake_case_functions = []
        inconsistent_functions = []
        
        for func in functions:
            if re.match(r'^[a-z][a-zA-Z0-9]*$', func.name):
                camel_case_functions.append(func.name)
            elif re.match(r'^[a-z][a-z0-9_]*$', func.name):
                snake_case_functions.append(func.name)
            else:
                inconsistent_functions.append(func.name)
        
        # If both camelCase and snake_case are used, flag as inconsistent
        if camel_case_functions and snake_case_functions:
            finding = Finding(
                title="Inconsistent Function Naming Convention",
                description=f"Contract mixes camelCase ({len(camel_case_functions)}) and snake_case ({len(snake_case_functions)}) function names",
                severity=Severity.LOW,
                category=Category.CODE_QUALITY,
                location=CodeLocation(contract_name=contract_name),
                affected_contracts=[contract_name],
                recommendation="Choose one naming convention (camelCase is recommended for Solidity) and apply consistently",
                impact="Inconsistent naming makes code less professional and harder to read"
            )
            findings.append(finding)
        
        # Flag functions with completely inconsistent names
        if inconsistent_functions:
            finding = Finding(
                title="Non-Standard Function Names",
                description=f"Functions don't follow standard naming conventions: {', '.join(inconsistent_functions)}",
                severity=Severity.LOW,
                category=Category.CODE_QUALITY,
                location=CodeLocation(contract_name=contract_name),
                affected_contracts=[contract_name],
                affected_functions=inconsistent_functions,
                recommendation="Use camelCase for function names (e.g., 'getUserBalance' not 'get_user_balance')",
                impact="Non-standard naming reduces code readability"
            )
            findings.append(finding)
        
        return findings

    def _check_code_smells(self, contract_name: str,
                          functions: List[FunctionContext]) -> List[Finding]:
        """Check for code smells."""
        findings = []
        
        for func in functions:
            # Check for magic numbers
            magic_numbers = self._find_magic_numbers(func.body)
            if magic_numbers:
                finding = Finding(
                    title=f"Magic Numbers in {func.name}",
                    description=f"Function contains magic numbers: {', '.join(magic_numbers)}",
                    severity=Severity.LOW,
                    category=Category.CODE_QUALITY,
                    location=CodeLocation(
                        contract_name=contract_name,
                        function_name=func.name
                    ),
                    affected_contracts=[contract_name],
                    affected_functions=[func.name],
                    recommendation="Replace magic numbers with named constants",
                    impact="Magic numbers make code harder to understand and maintain"
                )
                findings.append(finding)
            
            # Check for deeply nested code
            if self._has_deep_nesting(func.body):
                finding = Finding(
                    title=f"Deep Nesting in {func.name}",
                    description=f"Function has deeply nested control structures",
                    severity=Severity.MEDIUM,
                    category=Category.CODE_QUALITY,
                    location=CodeLocation(
                        contract_name=contract_name,
                        function_name=func.name
                    ),
                    affected_contracts=[contract_name],
                    affected_functions=[func.name],
                    recommendation="Refactor to reduce nesting levels (early returns, guard clauses)",
                    impact="Deep nesting makes code harder to read and understand"
                )
                findings.append(finding)
            
            # Check for long parameter lists
            if len(func.parameters) > 5:
                finding = Finding(
                    title=f"Too Many Parameters in {func.name}",
                    description=f"Function has {len(func.parameters)} parameters, which is more than recommended",
                    severity=Severity.LOW,
                    category=Category.CODE_QUALITY,
                    location=CodeLocation(
                        contract_name=contract_name,
                        function_name=func.name
                    ),
                    affected_contracts=[contract_name],
                    affected_functions=[func.name],
                    recommendation="Consider using a struct to group related parameters",
                    impact="Too many parameters make functions harder to use and understand"
                )
                findings.append(finding)
        
        return findings

    def _check_gas_efficiency(self, contract_name: str,
                             functions: List[FunctionContext]) -> List[Finding]:
        """Check for gas inefficiency patterns."""
        findings = []
        
        for func in functions:
            # Check for loops with expensive operations
            if self._has_expensive_loop_operations(func.body):
                finding = Finding(
                    title=f"Gas-Inefficient Loop in {func.name}",
                    description="Function contains loops with expensive operations like storage writes or external calls",
                    severity=Severity.MEDIUM,
                    category=Category.GAS_OPTIMIZATION,
                    location=CodeLocation(
                        contract_name=contract_name,
                        function_name=func.name
                    ),
                    affected_contracts=[contract_name],
                    affected_functions=[func.name],
                    recommendation="Consider batching operations or using more efficient patterns",
                    impact="High gas costs for function execution"
                )
                findings.append(finding)
            
            # Check for string concatenation
            if self._has_string_concatenation(func.body):
                finding = Finding(
                    title=f"Inefficient String Operations in {func.name}",
                    description="Function uses string concatenation which is gas-expensive",
                    severity=Severity.LOW,
                    category=Category.GAS_OPTIMIZATION,
                    location=CodeLocation(
                        contract_name=contract_name,
                        function_name=func.name
                    ),
                    affected_contracts=[contract_name],
                    affected_functions=[func.name],
                    recommendation="Use bytes for string manipulation or consider alternative approaches",
                    impact="Higher gas costs for string operations"
                )
                findings.append(finding)
            
            # Check for redundant storage reads
            if self._has_redundant_storage_reads(func.body):
                finding = Finding(
                    title=f"Redundant Storage Reads in {func.name}",
                    description="Function repeatedly reads from storage instead of using local variables",
                    severity=Severity.LOW,
                    category=Category.GAS_OPTIMIZATION,
                    location=CodeLocation(
                        contract_name=contract_name,
                        function_name=func.name
                    ),
                    affected_contracts=[contract_name],
                    affected_functions=[func.name],
                    recommendation="Cache storage values in local variables when accessed multiple times",
                    impact="Unnecessary gas consumption from repeated storage reads"
                )
                findings.append(finding)
        
        return findings

    def _generate_metric_findings(self, metrics: CodeQualityMetrics, 
                                 context: AnalysisContext) -> List[Finding]:
        """Generate findings based on overall metrics."""
        findings = []
        
        # Overall complexity finding
        if metrics.complexity_score > 15:
            finding = Finding(
                title="High Overall Complexity",
                description=f"Project has high average complexity score of {metrics.complexity_score:.2f}",
                severity=Severity.MEDIUM,
                category=Category.CODE_QUALITY,
                recommendation="Review and refactor complex functions to improve maintainability",
                impact="High complexity makes the codebase harder to maintain and test"
            )
            findings.append(finding)
        
        # Documentation coverage finding
        if metrics.documentation_coverage < 0.5:
            finding = Finding(
                title="Low Documentation Coverage",
                description=f"Only {metrics.documentation_coverage*100:.1f}% of functions are documented",
                severity=Severity.INFO,
                category=Category.DOCUMENTATION,
                recommendation="Add NatSpec documentation to improve code documentation coverage",
                impact="Poor documentation makes code harder to understand and maintain"
            )
            findings.append(finding)
        
        # Maintainability finding
        if metrics.maintainability_index < 50:
            finding = Finding(
                title="Low Maintainability Index",
                description=f"Project maintainability index is {metrics.maintainability_index:.1f} (below 50 indicates poor maintainability)",
                severity=Severity.MEDIUM,
                category=Category.MAINTAINABILITY,
                recommendation="Improve code quality through refactoring, documentation, and complexity reduction",
                impact="Poor maintainability leads to higher development and maintenance costs"
            )
            findings.append(finding)
        
        return findings

    async def _llm_code_quality_analysis(self, context: AnalysisContext) -> List[Finding]:
        """Perform LLM-enhanced code quality analysis."""
        findings = []
        
        if not self.llm_client or not self.prompt_manager:
            return findings
        
        try:
            for contract_name in context.contracts.keys():
                # Generate code quality analysis prompt
                prompt_variables = {
                    'contract_name': contract_name,
                    'function_count': len(context.functions.get(contract_name, [])),
                    'average_complexity': sum(f.complexity_score for f in context.functions.get(contract_name, [])) / max(len(context.functions.get(contract_name, [])), 1)
                }
                
                prompt = self.prompt_manager.generate_prompt(
                    'code_quality_analysis', prompt_variables
                )
                
                response = await self.llm_client.generate(prompt)
                
                # Parse LLM response into findings
                llm_findings = self._parse_llm_quality_response(
                    response.content, contract_name
                )
                findings.extend(llm_findings)
                
        except Exception as e:
            self.logger.error(f"Error in LLM code quality analysis: {str(e)}")
        
        return findings

    def _parse_llm_quality_response(self, response: str, contract_name: str) -> List[Finding]:
        """Parse LLM response into code quality findings."""
        findings = []
        
        # Implementation would parse structured LLM response
        # For now, return empty list
        
        return findings

    # Helper methods

    def _has_documentation(self, func: FunctionContext) -> bool:
        """Check if function has documentation."""
        doc_patterns = ['///', '/**', '@dev', '@notice', '@param', '@return']
        return any(pattern in func.body for pattern in doc_patterns)

    def _find_magic_numbers(self, code: str) -> List[str]:
        """Find magic numbers in code."""
        # Look for numbers that are not 0, 1, or common constants
        magic_numbers = []
        number_pattern = r'\b(\d{2,})\b'
        
        for match in re.finditer(number_pattern, code):
            number = match.group(1)
            if number not in ['10', '100', '1000'] and int(number) not in [0, 1]:
                magic_numbers.append(number)
        
        return list(set(magic_numbers))

    def _has_deep_nesting(self, code: str) -> bool:
        """Check for deep nesting in code."""
        max_depth = 0
        current_depth = 0
        
        for char in code:
            if char == '{':
                current_depth += 1
                max_depth = max(max_depth, current_depth)
            elif char == '}':
                current_depth = max(0, current_depth - 1)
        
        return max_depth > 4

    def _has_expensive_loop_operations(self, code: str) -> bool:
        """Check for expensive operations in loops."""
        loop_patterns = [r'for\s*\([^)]*\)\s*\{', r'while\s*\([^)]*\)\s*\{']
        expensive_patterns = ['.push(', '.call(', '.delegatecall(', '.send(', 'storage']
        
        for loop_pattern in loop_patterns:
            for match in re.finditer(loop_pattern, code):
                loop_start = match.end()
                # Find the end of the loop (simplified)
                brace_count = 1
                loop_end = loop_start
                
                for i in range(loop_start, len(code)):
                    if code[i] == '{':
                        brace_count += 1
                    elif code[i] == '}':
                        brace_count -= 1
                        if brace_count == 0:
                            loop_end = i
                            break
                
                loop_body = code[loop_start:loop_end]
                if any(pattern in loop_body for pattern in expensive_patterns):
                    return True
        
        return False

    def _has_string_concatenation(self, code: str) -> bool:
        """Check for string concatenation."""
        concat_patterns = [
            r'string\s*\(\s*abi\.encodePacked',
            r'abi\.encodePacked',
            r'bytes\.concat'
        ]
        return any(re.search(pattern, code) for pattern in concat_patterns)

    def _has_redundant_storage_reads(self, code: str) -> bool:
        """Check for redundant storage reads."""
        # Simple heuristic: same storage variable accessed multiple times
        storage_vars = re.findall(r'\b(\w+)\[', code)  # array access
        storage_vars.extend(re.findall(r'\b(\w+)\.', code))  # struct access
        
        var_counts = {}
        for var in storage_vars:
            var_counts[var] = var_counts.get(var, 0) + 1
        
        return any(count > 2 for count in var_counts.values())
    
    async def _llm_code_quality_analysis(self, context: AnalysisContext) -> List[Finding]:
        findings: List[Finding] = []
        if not self.llm_client or not self.prompt_manager:
            return findings
        try:
            for contract_name in context.contracts.keys():
                prompt_variables = {
                    'contract_name': contract_name,
                    'function_count': len(context.functions.get(contract_name, [])),
                    'average_complexity': sum(f.complexity_score for f in context.functions.get(contract_name, [])) / max(len(context.functions.get(contract_name, [])), 1)
                }
                prompt = self.prompt_manager.generate_prompt('code_quality_analysis', prompt_variables)
                response = await self.llm_client.generate(prompt)
                llm_findings = self._parse_llm_quality_response(response.content, contract_name)
                findings.extend(llm_findings)
        except Exception as e:
            logger.error(f"Error in LLM code quality analysis: {str(e)}")
        return findings
