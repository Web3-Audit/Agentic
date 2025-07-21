"""
Code snippet utilities for extracting and formatting code snippets with context.
"""

import re
import logging
from typing import Dict, List, Optional, Any, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum

from ..models.context import CodeLocation

logger = logging.getLogger(__name__)

class HighlightStyle(Enum):
    """Code highlighting styles."""
    SOLIDITY = "solidity"
    PLAIN = "plain"
    ANSI = "ansi"
    HTML = "html"
    MARKDOWN = "markdown"

@dataclass
class ContextualSnippet:
    """Represents a code snippet with context."""
    snippet: str
    start_line: int
    end_line: int
    highlighted_lines: List[int] = field(default_factory=list)
    context_lines_before: int = 3
    context_lines_after: int = 3
    file_path: Optional[str] = None
    function_name: Optional[str] = None
    contract_name: Optional[str] = None
    
    def get_line_numbers(self) -> List[int]:
        """Get all line numbers in the snippet."""
        return list(range(self.start_line, self.end_line + 1))
    
    def get_highlighted_snippet(self, style: HighlightStyle = HighlightStyle.PLAIN) -> str:
        """Get snippet with highlighting applied."""
        highlighter = SnippetHighlighter()
        return highlighter.highlight(self, style)

class CodeSnippetExtractor:
    """
    Extracts contextual code snippets from source code.
    """
    
    def __init__(self, default_context_lines: int = 3):
        self.logger = logging.getLogger(__name__)
        self.default_context_lines = default_context_lines

    def extract_snippet(self, source_code: str, location: CodeLocation, 
                       context_lines: Optional[int] = None) -> ContextualSnippet:
        """
        Extract a code snippet around a specific location.
        
        Args:
            source_code: The full source code
            location: Location to extract snippet around
            context_lines: Number of context lines before/after
            
        Returns:
            ContextualSnippet: Extracted snippet with context
        """
        if context_lines is None:
            context_lines = self.default_context_lines
        
        lines = source_code.split('\n')
        total_lines = len(lines)
        
        # Determine line numbers
        if location.line_number:
            target_line = location.line_number - 1  # Convert to 0-based
        elif location.start_line:
            target_line = location.start_line - 1
        else:
            # If no line number, try to find by function name
            target_line = self._find_line_by_function(lines, location.function_name)
        
        if target_line < 0:
            target_line = 0
        
        # Calculate snippet boundaries
        start_line = max(0, target_line - context_lines)
        end_line = min(total_lines - 1, target_line + context_lines)
        
        # Handle range-based locations
        if location.start_line and location.end_line:
            range_start = location.start_line - 1
            range_end = location.end_line - 1
            
            # Expand to include context
            start_line = max(0, range_start - context_lines)
            end_line = min(total_lines - 1, range_end + context_lines)
            
            # All lines in the original range should be highlighted
            highlighted_lines = list(range(range_start + 1, range_end + 2))  # Convert back to 1-based
        else:
            highlighted_lines = [target_line + 1] if target_line >= 0 else []
        
        # Extract snippet
        snippet_lines = lines[start_line:end_line + 1]
        snippet = '\n'.join(snippet_lines)
        
        return ContextualSnippet(
            snippet=snippet,
            start_line=start_line + 1,  # Convert back to 1-based
            end_line=end_line + 1,
            highlighted_lines=highlighted_lines,
            context_lines_before=context_lines,
            context_lines_after=context_lines,
            contract_name=location.contract_name,
            function_name=location.function_name
        )

    def extract_function_snippet(self, source_code: str, function_name: str, 
                                contract_name: Optional[str] = None) -> Optional[ContextualSnippet]:
        """
        Extract a complete function as a snippet.
        
        Args:
            source_code: The full source code
            function_name: Name of the function to extract
            contract_name: Optional contract name for context
            
        Returns:
            ContextualSnippet: Function snippet or None if not found
        """
        lines = source_code.split('\n')
        
        # Find function start
        function_start = None
        function_pattern = rf'function\s+{re.escape(function_name)}\s*\('
        
        for i, line in enumerate(lines):
            if re.search(function_pattern, line, re.IGNORECASE):
                function_start = i
                break
        
        if function_start is None:
            return None
        
        # Find function end by matching braces
        brace_count = 0
        function_end = None
        in_function = False
        
        for i in range(function_start, len(lines)):
            line = lines[i]
            
            for char in line:
                if char == '{':
                    brace_count += 1
                    in_function = True
                elif char == '}':
                    brace_count -= 1
                    if in_function and brace_count == 0:
                        function_end = i
                        break
            
            if function_end is not None:
                break
        
        if function_end is None:
            function_end = len(lines) - 1
        
        # Extract function with minimal context
        start_line = max(0, function_start - 1)
        end_line = min(len(lines) - 1, function_end + 1)
        
        snippet_lines = lines[start_line:end_line + 1]
        snippet = '\n'.join(snippet_lines)
        
        # Highlight the actual function lines
        highlighted_lines = list(range(function_start + 1, function_end + 2))
        
        return ContextualSnippet(
            snippet=snippet,
            start_line=start_line + 1,
            end_line=end_line + 1,
            highlighted_lines=highlighted_lines,
            context_lines_before=1,
            context_lines_after=1,
            function_name=function_name,
            contract_name=contract_name
        )

    def extract_multiple_snippets(self, source_code: str, locations: List[CodeLocation]) -> List[ContextualSnippet]:
        """
        Extract multiple code snippets.
        
        Args:
            source_code: The full source code
            locations: List of locations to extract
            
        Returns:
            List[ContextualSnippet]: List of extracted snippets
        """
        snippets = []
        
        for location in locations:
            try:
                snippet = self.extract_snippet(source_code, location)
                snippets.append(snippet)
            except Exception as e:
                self.logger.error(f"Error extracting snippet for location {location}: {str(e)}")
        
        return snippets

    def extract_contract_overview(self, source_code: str, contract_name: str) -> ContextualSnippet:
        """
        Extract contract overview including declaration and key components.
        
        Args:
            source_code: The full source code
            contract_name: Name of the contract
            
        Returns:
            ContextualSnippet: Contract overview snippet
        """
        lines = source_code.split('\n')
        
        # Find contract declaration
        contract_start = None
        contract_pattern = rf'(contract|interface|library)\s+{re.escape(contract_name)}\b'
        
        for i, line in enumerate(lines):
            if re.search(contract_pattern, line, re.IGNORECASE):
                contract_start = i
                break
        
        if contract_start is None:
            # Return empty snippet if contract not found
            return ContextualSnippet(
                snippet="// Contract not found",
                start_line=1,
                end_line=1,
                contract_name=contract_name
            )
        
        # Extract overview (first ~20 lines of contract or until first function)
        overview_lines = 20
        end_line = min(len(lines) - 1, contract_start + overview_lines)
        
        # Stop at first function declaration
        for i in range(contract_start + 1, end_line + 1):
            if re.search(r'function\s+\w+', lines[i]):
                end_line = i - 1
                break
        
        snippet_lines = lines[contract_start:end_line + 1]
        snippet = '\n'.join(snippet_lines)
        
        return ContextualSnippet(
            snippet=snippet,
            start_line=contract_start + 1,
            end_line=end_line + 1,
            highlighted_lines=[contract_start + 1],
            contract_name=contract_name
        )

    def _find_line_by_function(self, lines: List[str], function_name: Optional[str]) -> int:
        """Find line number by function name."""
        if not function_name:
            return 0
        
        pattern = rf'function\s+{re.escape(function_name)}\s*\('
        for i, line in enumerate(lines):
            if re.search(pattern, line, re.IGNORECASE):
                return i
        
        return 0

    def optimize_snippet_for_display(self, snippet: ContextualSnippet, max_lines: int = 20) -> ContextualSnippet:
        """
        Optimize snippet for display by limiting lines and focusing on important parts.
        
        Args:
            snippet: Original snippet
            max_lines: Maximum number of lines to display
            
        Returns:
            ContextualSnippet: Optimized snippet
        """
        lines = snippet.snippet.split('\n')
        
        if len(lines) <= max_lines:
            return snippet
        
        # If we have highlighted lines, focus around them
        if snippet.highlighted_lines:
            # Find the middle of highlighted lines
            highlighted_range = (min(snippet.highlighted_lines), max(snippet.highlighted_lines))
            middle_line = (highlighted_range[0] + highlighted_range[1]) // 2
            
            # Convert to snippet-relative line numbers
            relative_middle = middle_line - snippet.start_line
            
            # Calculate new boundaries
            half_max = max_lines // 2
            new_start = max(0, relative_middle - half_max)
            new_end = min(len(lines), relative_middle + half_max)
            
            # Adjust if we hit boundaries
            if new_end - new_start < max_lines and new_end < len(lines):
                new_end = min(len(lines), new_start + max_lines)
            if new_end - new_start < max_lines and new_start > 0:
                new_start = max(0, new_end - max_lines)
            
            optimized_lines = lines[new_start:new_end]
            
            return ContextualSnippet(
                snippet='\n'.join(optimized_lines),
                start_line=snippet.start_line + new_start,
                end_line=snippet.start_line + new_end - 1,
                highlighted_lines=snippet.highlighted_lines,
                context_lines_before=snippet.context_lines_before,
                context_lines_after=snippet.context_lines_after,
                function_name=snippet.function_name,
                contract_name=snippet.contract_name
            )
        else:
            # Just take the first max_lines
            optimized_lines = lines[:max_lines]
            return ContextualSnippet(
                snippet='\n'.join(optimized_lines),
                start_line=snippet.start_line,
                end_line=snippet.start_line + len(optimized_lines) - 1,
                highlighted_lines=[],
                context_lines_before=snippet.context_lines_before,
                context_lines_after=snippet.context_lines_after,
                function_name=snippet.function_name,
                contract_name=snippet.contract_name
            )

class SnippetHighlighter:
    """
    Applies syntax highlighting to code snippets.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Solidity keywords for highlighting
        self.solidity_keywords = {
            'keywords': [
                'contract', 'function', 'modifier', 'event', 'struct', 'enum',
                'public', 'private', 'internal', 'external', 'pure', 'view', 'payable',
                'if', 'else', 'for', 'while', 'do', 'break', 'continue', 'return',
                'require', 'assert', 'revert', 'throw', 'emit',
                'mapping', 'address', 'uint', 'int', 'bool', 'bytes', 'string',
                'memory', 'storage', 'calldata', 'constant', 'immutable'
            ],
            'built_ins': [
                'msg', 'block', 'tx', 'now', 'this', 'super',
                'sender', 'value', 'data', 'gas', 'origin',
                'timestamp', 'number', 'difficulty', 'gaslimit', 'coinbase'
            ]
        }

    def highlight(self, snippet: ContextualSnippet, style: HighlightStyle) -> str:
        """
        Apply highlighting to a code snippet.
        
        Args:
            snippet: The snippet to highlight
            style: Highlighting style to apply
            
        Returns:
            str: Highlighted snippet
        """
        if style == HighlightStyle.PLAIN:
            return self._add_line_numbers(snippet)
        elif style == HighlightStyle.ANSI:
            return self._highlight_ansi(snippet)
        elif style == HighlightStyle.HTML:
            return self._highlight_html(snippet)
        elif style == HighlightStyle.MARKDOWN:
            return self._highlight_markdown(snippet)
        elif style == HighlightStyle.SOLIDITY:
            return self._highlight_solidity(snippet)
        else:
            return snippet.snippet

    def _add_line_numbers(self, snippet: ContextualSnippet) -> str:
        """Add line numbers to snippet."""
        lines = snippet.snippet.split('\n')
        highlighted_set = set(snippet.highlighted_lines)
        
        result_lines = []
        for i, line in enumerate(lines):
            line_num = snippet.start_line + i
            marker = ">>>" if line_num in highlighted_set else "   "
            result_lines.append(f"{marker} {line_num:3d} | {line}")
        
        return '\n'.join(result_lines)

    def _highlight_ansi(self, snippet: ContextualSnippet) -> str:
        """Apply ANSI color highlighting."""
        # ANSI color codes
        RESET = '\033[0m'
        BOLD = '\033[1m'
        RED = '\033[91m'
        GREEN = '\033[92m'
        YELLOW = '\033[93m'
        BLUE = '\033[94m'
        MAGENTA = '\033[95m'
        CYAN = '\033[96m'
        
        lines = snippet.snippet.split('\n')
        highlighted_set = set(snippet.highlighted_lines)
        
        result_lines = []
        for i, line in enumerate(lines):
            line_num = snippet.start_line + i
            
            # Highlight keywords
            highlighted_line = line
            for keyword in self.solidity_keywords['keywords']:
                pattern = rf'\b{re.escape(keyword)}\b'
                highlighted_line = re.sub(pattern, f'{BLUE}{keyword}{RESET}', highlighted_line)
            
            # Highlight comments
            highlighted_line = re.sub(r'//.*$', f'{GREEN}\\g<0>{RESET}', highlighted_line)
            highlighted_line = re.sub(r'/\*.*?\*/', f'{GREEN}\\g<0>{RESET}', highlighted_line)
            
            # Highlight strings
            highlighted_line = re.sub(r'"[^"]*"', f'{YELLOW}\\g<0>{RESET}', highlighted_line)
            highlighted_line = re.sub(r"'[^']*'", f'{YELLOW}\\g<0>{RESET}', highlighted_line)
            
            # Add line number with highlighting for important lines
            if line_num in highlighted_set:
                marker = f"{RED}>>>{RESET}"
                line_prefix = f"{marker} {BOLD}{line_num:3d}{RESET} | "
            else:
                line_prefix = f"    {line_num:3d} | "
            
            result_lines.append(line_prefix + highlighted_line)
        
        return '\n'.join(result_lines)

    def _highlight_html(self, snippet: ContextualSnippet) -> str:
        """Apply HTML highlighting."""
        lines = snippet.snippet.split('\n')
        highlighted_set = set(snippet.highlighted_lines)
        
        html_lines = ['<div class="code-snippet">']
        
        for i, line in enumerate(lines):
            line_num = snippet.start_line + i
            
            # Escape HTML
            escaped_line = (line.replace('&', '&amp;')
                              .replace('<', '&lt;')
                              .replace('>', '&gt;'))
            
            # Apply syntax highlighting
            highlighted_line = escaped_line
            
            # Keywords
            for keyword in self.solidity_keywords['keywords']:
                pattern = rf'\b{re.escape(keyword)}\b'
                highlighted_line = re.sub(pattern, f'<span class="keyword">{keyword}</span>', highlighted_line)
            
            # Comments
            highlighted_line = re.sub(r'//.*$', '<span class="comment">\\g<0></span>', highlighted_line)
            
            # Strings
            highlighted_line = re.sub(r'"[^"]*"', '<span class="string">\\g<0></span>', highlighted_line)
            
            # Line container with highlighting
            css_class = "highlighted-line" if line_num in highlighted_set else "normal-line"
            
            html_lines.append(f'  <div class="line {css_class}">')
            html_lines.append(f'    <span class="line-number">{line_num:3d}</span>')
            html_lines.append(f'    <span class="line-content">{highlighted_line}</span>')
            html_lines.append(f'  </div>')
        
        html_lines.append('</div>')
        return '\n'.join(html_lines)

    def _highlight_markdown(self, snippet: ContextualSnippet) -> str:
        """Apply Markdown highlighting."""
        lines = snippet.snippet.split('\n')
        highlighted_set = set(snippet.highlighted_lines)
        
        # Add language identifier for syntax highlighting
        result = ['```solidity']
        
        for i, line in enumerate(lines):
            line_num = snippet.start_line + i
            marker = "// >>> " if line_num in highlighted_set else "// "
            
            # Add line number as comment
            result.append(f"{marker}{line_num:3d} | {line}")
        
        result.append('```')
        
        # Add context information
        if snippet.function_name:
            result.insert(1, f"// Function: {snippet.function_name}")
        if snippet.contract_name:
            result.insert(1, f"// Contract: {snippet.contract_name}")
        
        return '\n'.join(result)



    def _highlight_solidity(self, snippet: ContextualSnippet) -> str:
        """Apply Solidity-specific highlighting."""
        # This combines line numbers with basic syntax highlighting
        return self._add_line_numbers(snippet)

class CodeLocationResolver:
    """
    Resolves code locations from various inputs.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def resolve_location_from_error(self, error_message: str, source_code: str) -> Optional[CodeLocation]:
        """
        Resolve code location from compiler error message.
        
        Args:
            error_message: Compiler error message
            source_code: Source code
            
        Returns:
            CodeLocation: Resolved location or None
        """
        # Try to extract line number from error message
        line_match = re.search(r'line (\d+)', error_message, re.IGNORECASE)
        if line_match:
            line_number = int(line_match.group(1))
            return CodeLocation(line_number=line_number)
        
        # Try to extract function name
        func_match = re.search(r'function (\w+)', error_message, re.IGNORECASE)
        if func_match:
            function_name = func_match.group(1)
            return CodeLocation(function_name=function_name)
        
        return None

    def resolve_location_from_pattern(self, pattern: str, source_code: str, 
                                    contract_name: Optional[str] = None) -> List[CodeLocation]:
        """
        Find all locations matching a pattern.
        
        Args:
            pattern: Regex pattern to search for
            source_code: Source code to search in
            contract_name: Optional contract name
            
        Returns:
            List[CodeLocation]: All matching locations
        """
        locations = []
        lines = source_code.split('\n')
        
        try:
            compiled_pattern = re.compile(pattern, re.IGNORECASE)
        except re.error as e:
            self.logger.error(f"Invalid regex pattern: {pattern}, error: {str(e)}")
            return locations
        
        for i, line in enumerate(lines):
            if compiled_pattern.search(line):
                locations.append(CodeLocation(
                    line_number=i + 1,
                    contract_name=contract_name,
                    code_snippet=line.strip()
                ))
        
        return locations

    def resolve_function_location(self, function_name: str, source_code: str,
                                contract_name: Optional[str] = None) -> Optional[CodeLocation]:
        """
        Resolve location of a specific function.
        
        Args:
            function_name: Name of the function
            source_code: Source code
            contract_name: Optional contract name
            
        Returns:
            CodeLocation: Function location or None
        """
        lines = source_code.split('\n')
        pattern = rf'function\s+{re.escape(function_name)}\s*\('
        
        for i, line in enumerate(lines):
            if re.search(pattern, line, re.IGNORECASE):
                # Find function end
                brace_count = 0
                start_line = i + 1
                end_line = start_line
                
                for j in range(i, len(lines)):
                    for char in lines[j]:
                        if char == '{':
                            brace_count += 1
                        elif char == '}':
                            brace_count -= 1
                            if brace_count == 0:
                                end_line = j + 1
                                break
                    if brace_count == 0:
                        break
                
                return CodeLocation(
                    function_name=function_name,
                    contract_name=contract_name,
                    line_number=start_line,
                    start_line=start_line,
                    end_line=end_line
                )
        
        return None

    def get_surrounding_context(self, location: CodeLocation, source_code: str, 
                               context_lines: int = 5) -> Dict[str, Any]:
        """
        Get surrounding context for a code location.
        
        Args:
            location: The code location
            source_code: Source code
            context_lines: Number of context lines
            
        Returns:
            Dict with context information
        """
        lines = source_code.split('\n')
        
        if location.line_number:
            target_line = location.line_number - 1
        else:
            return {'error': 'No line number in location'}
        
        start_line = max(0, target_line - context_lines)
        end_line = min(len(lines) - 1, target_line + context_lines)
        
        context = {
            'before_lines': lines[start_line:target_line],
            'target_line': lines[target_line] if target_line < len(lines) else '',
            'after_lines': lines[target_line + 1:end_line + 1],
            'start_line_number': start_line + 1,
            'end_line_number': end_line + 1,
            'target_line_number': target_line + 1
        }
        
        return context
