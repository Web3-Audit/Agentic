
"""
Prompt management and templates for smart contract analysis.
"""

import os
import json
import logging
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass
from enum import Enum
from string import Template

from ..core.domain_classifier import Domain, Protocol
from ..core.context_classifier import BusinessLogicType

logger = logging.getLogger(__name__)

class PromptType(Enum):
    ANALYSIS = "analysis"
    CLASSIFICATION = "classification"
    VULNERABILITY_DETECTION = "vulnerability_detection"
    BUSINESS_LOGIC = "business_logic"
    CODE_QUALITY = "code_quality"
    FUZZING_GENERATION = "fuzzing_generation"
    REPORT_GENERATION = "report_generation"

@dataclass
class PromptTemplate:
    """Template for LLM prompts."""
    name: str
    template: str
    variables: List[str]
    description: str
    domain: Optional[Domain] = None
    prompt_type: Optional[PromptType] = None
    examples: List[str] = None

class PromptTemplates:
    """Collection of all prompt templates."""
    
    # Base system prompts
    SYSTEM_PROMPT_BASE = """You are an expert smart contract security auditor with deep knowledge of:
- Solidity programming language and EVM mechanics
- Common vulnerability patterns and attack vectors
- DeFi, DAO, NFT, and GameFi protocol security
- Smart contract best practices and design patterns
- Formal verification and invariant analysis

Your responses should be:
- Technically accurate and detailed
- Focused on security implications
- Structured and well-organized
- Backed by specific code analysis
- Actionable for developers

Always provide specific line references and code snippets when identifying issues."""

    SYSTEM_PROMPT_DEFI = SYSTEM_PROMPT_BASE + """

You specialize in DeFi protocol security including:
- AMM mechanics and slippage protection
- Lending/borrowing protocols and liquidation
- Yield farming and staking mechanisms
- Oracle manipulation and price feed security
- Flash loan attacks and MEV protection
- Economic models and tokenomics analysis"""

    SYSTEM_PROMPT_DAO = SYSTEM_PROMPT_BASE + """

You specialize in DAO governance security including:
- Voting mechanisms and vote manipulation
- Proposal systems and execution timeouts
- Treasury management and fund protection
- Delegation patterns and power concentration
- Governance attacks and defense mechanisms"""

    SYSTEM_PROMPT_NFT = SYSTEM_PROMPT_BASE + """

You specialize in NFT and marketplace security including:
- ERC-721 and ERC-1155 implementation correctness
- Metadata handling and IPFS integration
- Royalty mechanisms and marketplace interactions
- Minting controls and supply management
- Trading and auction security"""

    SYSTEM_PROMPT_GAMEFI = SYSTEM_PROMPT_BASE + """

You specialize in GameFi and gaming protocol security including:
- Token economics and reward mechanisms
- In-game asset management and trading
- Battle and competition fairness
- Random number generation security
- Cross-game interoperability"""

    # Domain classification prompts
    DOMAIN_CLASSIFICATION_PROMPT = """Analyze the following Solidity smart contract and classify its domain and protocol type.

Contract Code:
$contract_code

text

Contract Name: $contract_name
Functions: $function_names
State Variables: $state_variables
Imports: $imports

Please analyze the contract and provide:

1. **Primary Domain** (choose one):
   - DeFi (Decentralized Finance)
   - DAO (Decentralized Autonomous Organization) 
   - NFT (Non-Fungible Tokens)
   - GameFi (Gaming Finance)
   - Utility (General utility contracts)
   - Unknown

2. **Protocol Type** (if identifiable):
   - For DeFi: Uniswap, Aave, Compound, Curve, SushiSwap, etc.
   - For DAO: Compound Governance, Aragon, Moloch, etc.
   - For NFT: OpenSea, Foundation, SuperRare, etc.
   - For GameFi: Axie Infinity, StepN, Sandbox, etc.

3. **Subtype** (specific functionality):
   - For DeFi: AMM, Lending, Staking, Oracle, etc.
   - For DAO: Governance, Voting, Treasury, etc.
   - For NFT: Marketplace, Collection, Gaming, etc.
   - For GameFi: Battle, Breeding, Rewards, etc.

4. **Confidence Score** (0.0-1.0): How confident are you in this classification?

5. **Key Indicators**: List the specific patterns, function names, or features that led to this classification.

6. **Reasoning**: Explain your classification logic.

Format your response as structured JSON:
{
"domain": "domain_name",
"protocol": "protocol_name_or_null",
"subtype": "subtype_or_null",
"confidence": 0.95,
"key_indicators": ["indicator1", "indicator2"],
"reasoning": "Detailed explanation..."
}

"""

    # Vulnerability detection prompts
    VULNERABILITY_ANALYSIS_PROMPT = """Perform a comprehensive security analysis of the following smart contract code.

Contract Information:
- Name: $contract_name
- Domain: $domain
- Protocol: $protocol

Contract Code:
$contract_code

text

Analyze for the following vulnerability categories:

## 1. Common Vulnerabilities
- Reentrancy attacks
- Integer overflow/underflow
- Access control issues
- Gas limit problems
- Timestamp dependencies
- tx.origin usage
- Unchecked external calls
- Denial of Service vulnerabilities

## 2. Domain-Specific Issues
$domain_specific_checks

## 3. Business Logic Flaws
- Economic model vulnerabilities  
- Incorrect state transitions
- Missing validation checks
- Logic contradictions
- Edge case handling

## 4. Code Quality Issues
- Uninitialized variables
- Dead code
- Complex functions
- Poor error handling
- Gas optimization opportunities

For each finding, provide:
- **Severity**: Critical/High/Medium/Low/Info
- **Title**: Brief description
- **Description**: Detailed explanation
- **Location**: Function name and line numbers
- **Code Snippet**: Relevant code
- **Impact**: Potential consequences
- **Recommendation**: How to fix
- **References**: Related CVEs or documentation

Format as structured JSON array of findings."""

    # Business logic analysis
    BUSINESS_LOGIC_ANALYSIS_PROMPT = """Analyze the business logic of this smart contract for correctness and security.

Contract Code:
$contract_code

text

Contract Context:
- Domain: $domain
- Critical Functions: $critical_functions
- State Variables: $state_variables
- External Dependencies: $external_dependencies

Focus on:

## 1. State Management
- Are state transitions valid and complete?
- Can the contract reach invalid states?
- Are state variables properly initialized?
- Is state consistency maintained across functions?

## 2. Access Controls
- Who can call critical functions?
- Are permissions properly enforced?
- Can unauthorized users bypass restrictions?
- Is ownership transfer secure?

## 3. Economic Logic (if applicable)
- Are mathematical operations correct?
- Can economic invariants be broken?
- Are there arbitrage or manipulation opportunities?
- Is fee calculation accurate?

## 4. External Interactions  
- Are external calls handled safely?
- What happens if external contracts fail?
- Are oracle dependencies secure?
- Is integration with other protocols correct?

## 5. Edge Cases
- How does the contract handle zero values?
- What about maximum values?
- Are array bounds checked?
- How are failures handled?

## 6. Invariants
- What properties should always be true?
- Can these invariants be violated?
- Are there implicit assumptions?

Provide detailed analysis with specific examples and recommendations."""

    # Code quality analysis
    CODE_QUALITY_ANALYSIS_PROMPT = """Analyze the code quality, gas efficiency, and best practices of this smart contract.

Contract Code:
$contract_code

text

Evaluate:

## 1. Code Structure & Readability
- Function organization and naming
- Variable naming conventions  
- Comment quality and documentation
- Code complexity and maintainability

## 2. Gas Optimization
- Expensive operations
- Storage vs memory usage
- Loop optimizations
- Redundant operations
- Pack struct variables

## 3. Best Practices
- Use of established patterns
- Error handling approaches
- Event emission practices
- Modifier usage
- Library utilization

## 4. Security Patterns
- Checks-Effects-Interactions pattern
- Pull payment pattern
- Circuit breaker implementation
- Upgrade patterns

## 5. Testing Considerations
- Edge cases to test
- Invariants to verify
- Integration test scenarios
- Fuzzing targets

Provide specific recommendations for improvement with code examples where helpful."""

    # Fuzzing generation
    FUZZING_GENERATION_PROMPT = """Generate a comprehensive fuzzing test suite for this smart contract.

Contract Code:
$contract_code

text

Contract Analysis:
- Domain: $domain
- Critical Functions: $critical_functions  
- State Variables: $state_variables
- Access Controls: $access_patterns

Generate:

## 1. Property-Based Tests
Create invariant properties that should always hold:
- Balance conservation
- State consistency  
- Access control enforcement
- Mathematical correctness

## 2. Boundary Value Testing
- Maximum and minimum values
- Zero values and edge cases
- Array bounds and limits
- Time-based boundaries

## 3. State Transition Testing
- Valid state transitions
- Invalid transition attempts
- State corruption scenarios
- Rollback scenarios

## 4. Integration Testing
- Multi-contract interactions
- External dependency failures
- Oracle manipulation scenarios
- Front-running simulations

## 5. Chaos Testing
- Random function call sequences
- Random parameter combinations
- Resource exhaustion tests
- Timing attack simulations

Provide the fuzzing suite as executable Python code using appropriate testing frameworks."""

    # Report generation
    REPORT_GENERATION_PROMPT = """Generate a comprehensive security audit report for this smart contract analysis.

Analysis Results:
$analysis_results

Contract Information:
- Name: $contract_name
- Domain: $domain
- Protocol: $protocol
- Complexity Score: $complexity_score
- Risk Score: $risk_score

Format the report with:

## Executive Summary
Brief overview of findings and overall security assessment.

## Contract Overview
- Purpose and functionality
- Architecture and design
- Key components and interactions

## Security Analysis
### Critical Findings
[List critical severity issues]

### High Severity Findings  
[List high severity issues]

### Medium Severity Findings
[List medium severity issues]

### Low Severity Findings
[List low severity issues]

### Informational Findings
[List informational issues]

## Business Logic Analysis
Evaluation of contract logic and economic model.

## Code Quality Assessment
Analysis of code structure, gas efficiency, and best practices.

## Recommendations
- Immediate actions required
- Best practice improvements
- Long-term considerations

## Testing Recommendations
Suggested testing approaches and scenarios.

## Conclusion
Overall assessment and risk rating.

Make the report professional, detailed, and actionable for developers."""

class PromptManager:
    """Manages prompt templates and dynamic prompt generation."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.templates = {}
        self._initialize_templates()

    def _initialize_templates(self):
        """Initialize all prompt templates."""
        
        # Domain classification template
        self.templates['domain_classification'] = PromptTemplate(
            name="domain_classification",
            template=PromptTemplates.DOMAIN_CLASSIFICATION_PROMPT,
            variables=['contract_code', 'contract_name', 'function_names', 
                      'state_variables', 'imports'],
            description="Classify contract domain and protocol type",
            prompt_type=PromptType.CLASSIFICATION
        )
        
        # Vulnerability analysis template
        self.templates['vulnerability_analysis'] = PromptTemplate(
            name="vulnerability_analysis", 
            template=PromptTemplates.VULNERABILITY_ANALYSIS_PROMPT,
            variables=['contract_code', 'contract_name', 'domain', 'protocol',
                      'domain_specific_checks'],
            description="Comprehensive vulnerability analysis",
            prompt_type=PromptType.VULNERABILITY_DETECTION
        )
        
        # Business logic analysis template
        self.templates['business_logic_analysis'] = PromptTemplate(
            name="business_logic_analysis",
            template=PromptTemplates.BUSINESS_LOGIC_ANALYSIS_PROMPT, 
            variables=['contract_code', 'domain', 'critical_functions',
                      'state_variables', 'external_dependencies'],
            description="Business logic and correctness analysis",
            prompt_type=PromptType.BUSINESS_LOGIC
        )
        
        # Code quality analysis template
        self.templates['code_quality_analysis'] = PromptTemplate(
            name="code_quality_analysis",
            template=PromptTemplates.CODE_QUALITY_ANALYSIS_PROMPT,
            variables=['contract_code'],
            description="Code quality and best practices analysis", 
            prompt_type=PromptType.CODE_QUALITY
        )
        
        # Fuzzing generation template
        self.templates['fuzzing_generation'] = PromptTemplate(
            name="fuzzing_generation",
            template=PromptTemplates.FUZZING_GENERATION_PROMPT,
            variables=['contract_code', 'domain', 'critical_functions',
                      'state_variables', 'access_patterns'],
            description="Generate comprehensive fuzzing test suite",
            prompt_type=PromptType.FUZZING_GENERATION
        )
        
        # Report generation template  
        self.templates['report_generation'] = PromptTemplate(
            name="report_generation",
            template=PromptTemplates.REPORT_GENERATION_PROMPT,
            variables=['analysis_results', 'contract_name', 'domain', 'protocol',
                      'complexity_score', 'risk_score'], 
            description="Generate comprehensive audit report",
            prompt_type=PromptType.REPORT_GENERATION
        )

    def get_template(self, template_name: str) -> PromptTemplate:
        """Get a prompt template by name."""
        if template_name not in self.templates:
            raise ValueError(f"Template '{template_name}' not found")
        
        return self.templates[template_name]

    def get_system_prompt(self, domain: Optional[Domain] = None) -> str:
        """Get appropriate system prompt based on domain."""
        if domain == Domain.DEFI:
            return PromptTemplates.SYSTEM_PROMPT_DEFI
        elif domain == Domain.DAO:
            return PromptTemplates.SYSTEM_PROMPT_DAO  
        elif domain == Domain.NFT:
            return PromptTemplates.SYSTEM_PROMPT_NFT
        elif domain == Domain.GAMEFI:
            return PromptTemplates.SYSTEM_PROMPT_GAMEFI
        else:
            return PromptTemplates.SYSTEM_PROMPT_BASE

    def generate_prompt(self, template_name: str, variables: Dict[str, Any]) -> str:
        """
        Generate a prompt from template with variable substitution.
        
        Args:
            template_name: Name of the template to use
            variables: Dictionary of variables to substitute
            
        Returns:
            str: Generated prompt with variables substituted
        """
        template = self.get_template(template_name)
        
        # Validate all required variables are provided
        missing_vars = set(template.variables) - set(variables.keys())
        if missing_vars:
            raise ValueError(f"Missing required variables: {missing_vars}")
        
        # Use Template for safe substitution
        prompt_template = Template(template.template)
        
        try:
            return prompt_template.substitute(variables)
        except KeyError as e:
            raise ValueError(f"Variable substitution failed: {str(e)}")

    def get_domain_specific_checks(self, domain: Domain) -> str:
        """Get domain-specific vulnerability checks."""
        
        checks = {
            Domain.DEFI: """
            - Slippage protection and MEV resistance
            - Oracle manipulation and price feed security  
            - Flash loan attack vectors
            - Liquidity pool security and invariants
            - Yield farming and reward calculation correctness
            - Economic model vulnerabilities and arbitrage
            - Cross-protocol integration risks
            """,
            
            Domain.DAO: """
            - Vote manipulation and governance attacks
            - Proposal system security and validation
            - Timelock bypass vulnerabilities
            - Delegation security and vote buying
            - Treasury fund protection
            - Quorum manipulation
            - Execution privilege escalation
            """,
            
            Domain.NFT: """
            - Metadata manipulation and IPFS security
            - Royalty calculation and enforcement
            - Minting control and supply management  
            - Marketplace integration vulnerabilities
            - Transfer hook security
            - Token enumeration attacks
            - Cross-contract NFT interactions
            """,
            
            Domain.GAMEFI: """
            - Random number generation predictability
            - In-game economy manipulation
            - Battle outcome fairness
            - Asset duplication vulnerabilities  
            - Cross-game interoperability risks
            - Reward distribution correctness
            - Player collusion prevention
            """
        }
        
        return checks.get(domain, "- General smart contract vulnerabilities")

    def create_custom_template(self, name: str, template: str, variables: List[str],
                              description: str, domain: Optional[Domain] = None,
                              prompt_type: Optional[PromptType] = None) -> PromptTemplate:
        """Create a custom prompt template."""
        
        custom_template = PromptTemplate(
            name=name,
            template=template,
            variables=variables,
            description=description,
            domain=domain,
            prompt_type=prompt_type
        )
        
        self.templates[name] = custom_template
        self.logger.info(f"Created custom template: {name}")
        
        return custom_template

    def list_templates(self) -> List[str]:
        """List all available template names."""
        return list(self.templates.keys())

    def get_templates_by_type(self, prompt_type: PromptType) -> List[PromptTemplate]:
        """Get all templates of a specific type."""
        return [
            template for template in self.templates.values()
            if template.prompt_type == prompt_type
        ]

    def get_templates_by_domain(self, domain: Domain) -> List[PromptTemplate]:
        """Get all templates for a specific domain."""
        return [
            template for template in self.templates.values()
            if template.domain == domain or template.domain is None
        ]

    def validate_template(self, template_name: str) -> bool:
        """Validate that a template is properly formatted."""
        try:
            template = self.get_template(template_name)
            
            # Check if all variables in template string are declared
            template_obj = Template(template.template)
            test_vars = {var: f"test_{var}" for var in template.variables}
            template_obj.substitute(test_vars)
            
            return True
            
        except Exception as e:
            self.logger.error(f"Template validation failed for {template_name}: {str(e)}")
            return False

    def export_templates(self, file_path: str):
        """Export all templates to a JSON file."""
        export_data = {}
        
        for name, template in self.templates.items():
            export_data[name] = {
                'template': template.template,
                'variables': template.variables,
                'description': template.description,
                'domain': template.domain.value if template.domain else None,
                'prompt_type': template.prompt_type.value if template.prompt_type else None
            }
        
        with open(file_path, 'w') as f:
            json.dump(export_data, f, indent=2)
        
        self.logger.info(f"Exported {len(self.templates)} templates to {file_path}")

    def import_templates(self, file_path: str):
        """Import templates from a JSON file."""
        with open(file_path, 'r') as f:
            import_data = json.load(f)
        
        imported_count = 0
        for name, template_data in import_data.items():
            try:
                domain = Domain(template_data['domain']) if template_data.get('domain') else None
                prompt_type = PromptType(template_data['prompt_type']) if template_data.get('prompt_type') else None
                
                self.templates[name] = PromptTemplate(
                    name=name,
                    template=template_data['template'],
                    variables=template_data['variables'],
                    description=template_data['description'],
                    domain=domain,
                    prompt_type=prompt_type
                )
                imported_count += 1
                
            except Exception as e:
                self.logger.error(f"Failed to import template {name}: {str(e)}")
        
        self.logger.info(f"Imported {imported_count} templates from {file_path}")