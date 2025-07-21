"""
Main contract analyzer that orchestrates parsing, cross-domain classification, and analysis.
"""

import logging
import json
import time
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict

from .parser import SolidityParser, ParsedContract
from .domain_classifier import DomainClassifier, Domain, ClassificationResult
from .context_classifier import ContextClassifier, ContextClassification
from ..models.structured_report import StructuredReport, Finding, Severity

logger = logging.getLogger(__name__)

@dataclass
class AnalysisResult:
    parsed_contract: ParsedContract
    domain_classifications: List[ClassificationResult]
    context_classifications: List[ContextClassification]
    findings: List[Finding]
    applicable_agents: List[str]
    applicable_checks: List[str]
    analysis_metadata: Dict[str, Any]
    structured_report: Optional[StructuredReport] = None

class ContractAnalyzer:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.parser = SolidityParser()
        self.domain_classifier = DomainClassifier()
        self.context_classifier = ContextClassifier()
        self.analysis_start_time = None
        self.analysis_stats = {
            'contracts_analyzed': 0,
            'total_functions': 0,
            'total_findings': 0,
            'analysis_time': 0.0,
        }

    def analyze(self, source_code: str, contract_name: Optional[str] = None) -> AnalysisResult:
        self.analysis_start_time = time.time()
        try:
            self.logger.info("Starting contract analysis...")
            parsed_contract = self.parser.parse(source_code)
            if parsed_contract.parse_errors:
                self.logger.warning(f"Parse errors found: {parsed_contract.parse_errors}")
            if not parsed_contract.contracts:
                raise ValueError("No contracts found in source code")

            # === Multi-domain & protocol classification ===
            self.logger.info("Step 2: Classifying domain(s) and protocol(s)...")
            # For each contract, classify separately (if multiple contracts in file)
            contract_results = []
            for contract in parsed_contract.contracts:
                contract_results.append(
                    self.domain_classifier.classify(ParsedContract(
                        source_code=parsed_contract.source_code,
                        contracts=[contract],  # Only this contract
                        pragma_statements=parsed_contract.pragma_statements,
                        license=parsed_contract.license,
                        imports=parsed_contract.imports,
                    ))
                )
            # Aggregate by domains
            all_domains = set()
            all_protocols = set()
            all_reasonings = []
            all_patterns = []
            for cr in contract_results:
                if cr.domain != Domain.UNKNOWN:
                    all_domains.add(cr.domain)
                if cr.protocol:
                    all_protocols.add(cr.protocol)
                all_reasonings.extend(cr.reasoning)
                all_patterns.extend(cr.matched_patterns)
            # Build list of ClassificationResults, de-duplicated
            unique_classifications = []
            for domain in all_domains:
                protos = [cr.protocol for cr in contract_results if cr.domain == domain and cr.protocol]
                subtype = next((cr.subtype for cr in contract_results if cr.domain == domain), None)
                unique_classifications.append(ClassificationResult(
                    domain=domain,
                    protocol=protos[0] if protos else None,
                    confidence=1.0,  # If it's in the set, we have high confidence
                    subtype=subtype,
                    reasoning=[r for r in all_reasonings if r],
                    matched_patterns=[p for p in all_patterns if p]
                ))

            self.logger.info("Domains classified as: %s" % ", ".join(d.domain.value for d in unique_classifications))

            # === Context classification for each domain ===
            context_classifications = []
            for cl in unique_classifications:
                ctx_type = self.context_classifier.classify(parsed_contract, cl.domain)
                context_classifications.append(ctx_type)

            # === Find and run all applicable agents and checks from all domains ===
            all_applicable_agents = set()
            all_applicable_checks = set()
            for cl in unique_classifications:
                all_applicable_agents.update(self.domain_classifier.get_applicable_agents(cl))
                all_applicable_checks.update(self.domain_classifier.get_applicable_checks(cl))

            findings = []
            for agent_name in all_applicable_agents:
                agent_instance = self._instantiate_agent(agent_name)
                if agent_instance:
                    findings.extend(agent_instance.analyze(parsed_contract))

            # === Metadata and report ===
            analysis_metadata = {
                'timestamp': time.time(),
                'domains_detected': [cl.domain.value for cl in unique_classifications],
                'protocols_detected': [cl.protocol.value for cl in unique_classifications if cl.protocol],
                'applicable_agents': list(all_applicable_agents),
                'applicable_checks': list(all_applicable_checks),
            }

            result = AnalysisResult(
                parsed_contract=parsed_contract,
                domain_classifications=unique_classifications,
                context_classifications=context_classifications,
                findings=findings,
                applicable_agents=list(all_applicable_agents),
                applicable_checks=list(all_applicable_checks),
                analysis_metadata=analysis_metadata,
            )

            self._update_analysis_stats(result)
            self.logger.info("Contract analysis completed successfully")
            return result

        except Exception as e:
            self.logger.error(f"Error during contract analysis: {str(e)}")
            raise

    def _instantiate_agent(self, agent_name: str):
        try:
            # Example: dynamic import by name, more robust with full routing
            from ..agents import (
                universal_agent, visibility_agent, business_logic_agent, code_quality_agent,
                # ... import all domain/protocol agents you support here
            )
            AGENT_MAP = {
                'universal_agent': universal_agent.UniversalAgent(),
                'visibility_agent': universal_agent.VisibilityAgent(),
                'business_logic_agent': business_logic_agent.BusinessLogicAgent(),
                'code_quality_agent': code_quality_agent.CodeQualityAgent(),
                # Add mapping for all your domain/protocol agents
            }
            return AGENT_MAP.get(agent_name)
        except Exception as e:
            self.logger.warning(f"Could not instantiate agent {agent_name}: {e}")
            return None

    def _create_analysis_metadata(self, parsed_contract: ParsedContract,
                                 domain_classification: ClassificationResult,
                                 context_classification: ContextClassification) -> Dict[str, Any]:
        """Create comprehensive analysis metadata."""
        metadata = {
            'analysis_timestamp': time.time(),
            'analysis_version': '1.0.0',
            'parser_info': {
                'total_contracts': len(parsed_contract.contracts),
                'contract_names': [contract.name for contract in parsed_contract.contracts],
                'pragma_statements': parsed_contract.pragma_statements,
                'license': parsed_contract.license,
                'imports_count': len(parsed_contract.imports),
                'parse_errors': parsed_contract.parse_errors
            },
            'classification_info': {
                'domain': domain_classification.domain.value,
                'protocol': domain_classification.protocol.value if domain_classification.protocol else None,
                'confidence': domain_classification.confidence,
                'subtype': domain_classification.subtype,
                'reasoning': domain_classification.reasoning,
                'matched_patterns': domain_classification.matched_patterns
            },
            'context_info': {
                'business_logic_types': [bl.value for bl in context_classification.business_logic.logic_types],
                'complexity_score': context_classification.complexity_score,
                'risk_score': context_classification.risk_score,
                'critical_functions_count': len(context_classification.business_logic.critical_functions),
                'admin_functions_count': len(context_classification.business_logic.admin_functions),
                'financial_operations_count': len(context_classification.business_logic.financial_operations),
                'security_flags': {
                    'has_payable_functions': context_classification.security_context.has_payable_functions,
                    'has_external_calls': context_classification.security_context.has_external_calls,
                    'has_delegatecalls': context_classification.security_context.has_delegatecalls,
                    'has_selfdestruct': context_classification.security_context.has_selfdestruct,
                    'has_inline_assembly': context_classification.security_context.has_inline_assembly,
                    'uses_tx_origin': context_classification.security_context.uses_tx_origin,
                    'has_time_dependencies': context_classification.security_context.has_time_dependencies
                }
            },
            'contract_statistics': self._calculate_contract_statistics(parsed_contract),
            'analysis_summary': {
                'total_lines': len(parsed_contract.source_code.split('\n')),
                'total_functions': sum(len(contract.functions) for contract in parsed_contract.contracts),
                'total_state_variables': sum(len(contract.state_variables) for contract in parsed_contract.contracts),
                'total_events': sum(len(contract.events) for contract in parsed_contract.contracts),
                'total_modifiers': sum(len(contract.modifiers) for contract in parsed_contract.contracts)
            }
        }
        
        return metadata

    def _calculate_contract_statistics(self, parsed_contract: ParsedContract) -> Dict[str, Any]:
        """Calculate detailed statistics for the contracts."""
        stats = {
            'contracts': [],
            'overall': {
                'total_contracts': len(parsed_contract.contracts),
                'total_functions': 0,
                'total_state_variables': 0,
                'total_events': 0,
                'total_modifiers': 0,
                'visibility_distribution': {'public': 0, 'private': 0, 'internal': 0, 'external': 0},
                'mutability_distribution': {'view': 0, 'pure': 0, 'payable': 0, 'nonpayable': 0},
                'function_types': {'function': 0, 'constructor': 0, 'modifier': 0, 'fallback': 0}
            }
        }
        
        for contract in parsed_contract.contracts:
            contract_stats = {
                'name': contract.name,
                'type': contract.contract_type,
                'inherits': contract.inherits,
                'functions_count': len(contract.functions),
                'state_variables_count': len(contract.state_variables),
                'events_count': len(contract.events),
                'modifiers_count': len(contract.modifiers),
                'function_details': []
            }
            
            # Analyze functions
            for function in contract.functions:
                func_detail = {
                    'name': function.name,
                    'type': function.function_type.value,
                    'visibility': function.visibility.value,
                    'mutability': function.state_mutability.value,
                    'parameters_count': len(function.parameters),
                    'return_parameters_count': len(function.return_parameters),
                    'modifiers_count': len(function.modifiers),
                    'body_length': len(function.body)
                }
                contract_stats['function_details'].append(func_detail)
                
                # Update overall statistics
                stats['overall']['visibility_distribution'][function.visibility.value] += 1
                stats['overall']['mutability_distribution'][function.state_mutability.value] += 1
                stats['overall']['function_types'][function.function_type.value] += 1
            
            stats['contracts'].append(contract_stats)
            
            # Update overall totals
            stats['overall']['total_functions'] += len(contract.functions)
            stats['overall']['total_state_variables'] += len(contract.state_variables)
            stats['overall']['total_events'] += len(contract.events)
            stats['overall']['total_modifiers'] += len(contract.modifiers)
        
        return stats

    def _update_analysis_stats(self, result: AnalysisResult):
        """Update internal analysis statistics."""
        self.analysis_stats['contracts_analyzed'] += len(result.parsed_contract.contracts)
        self.analysis_stats['total_functions'] += result.analysis_metadata['analysis_summary']['total_functions']
        self.analysis_stats['total_findings'] += len(result.findings)
        
        if self.analysis_start_time:
            self.analysis_stats['analysis_time'] = time.time() - self.analysis_start_time

    def get_analysis_summary(self, result: AnalysisResult) -> Dict[str, Any]:
        """Get a high-level summary of the analysis result."""
        summary = {
            'contract_info': {
                'total_contracts': len(result.parsed_contract.contracts),
                'contract_names': [contract.name for contract in result.parsed_contract.contracts],
                'domain': result.domain_classification.domain.value,
                'protocol': result.domain_classification.protocol.value if result.domain_classification.protocol else 'Unknown',
                'confidence': result.domain_classification.confidence
            },
            'complexity_assessment': {
                'complexity_score': result.context_classification.complexity_score,
                'risk_score': result.context_classification.risk_score,
                'business_logic_types': len(result.context_classification.business_logic.logic_types),
                'critical_functions': len(result.context_classification.business_logic.critical_functions)
            },
            'security_overview': {
                'has_high_risk_patterns': (
                    result.context_classification.security_context.has_delegatecalls or
                    result.context_classification.security_context.has_selfdestruct or
                    result.context_classification.security_context.uses_tx_origin
                ),
                'external_interactions': result.context_classification.security_context.has_external_calls,
                'financial_operations': len(result.context_classification.business_logic.financial_operations) > 0,
                'access_control_patterns': len(result.context_classification.security_context.access_control_patterns)
            },
            'analysis_scope': {
                'applicable_agents': len(result.applicable_agents),
                'applicable_checks': len(result.applicable_checks),
                'agent_types': result.applicable_agents,
                'check_types': result.applicable_checks
            },
            'findings_summary': {
                'total_findings': len(result.findings),
                'severity_distribution': self._get_severity_distribution(result.findings)
            },
            'recommendations': self._generate_recommendations(result)
        }
        
        return summary

    def _get_severity_distribution(self, findings: List[Finding]) -> Dict[str, int]:
        """Get distribution of findings by severity."""
        distribution = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        
        for finding in findings:
            if hasattr(finding, 'severity') and finding.severity:
                severity_key = finding.severity.value.lower()
                if severity_key in distribution:
                    distribution[severity_key] += 1
        
        return distribution

    def _generate_recommendations(self, result: AnalysisResult) -> List[str]:
        """Generate high-level recommendations based on analysis."""
        recommendations = []
        
        # Risk-based recommendations
        if result.context_classification.risk_score > 0.7:
            recommendations.append("High risk score detected - conduct thorough security review")
        
        if result.context_classification.security_context.has_delegatecalls:
            recommendations.append("Contract uses delegatecall - verify proxy implementation security")
        
        if result.context_classification.security_context.uses_tx_origin:
            recommendations.append("Contract uses tx.origin - replace with msg.sender for better security")
        
        if result.context_classification.security_context.has_external_calls:
            recommendations.append("Contract makes external calls - implement reentrancy protection")
        
        # Complexity-based recommendations
        if result.context_classification.complexity_score > 0.8:
            recommendations.append("High complexity detected - consider code refactoring and modularization")
        
        # Domain-specific recommendations
        if result.domain_classification.domain.value == 'defi':
            recommendations.extend([
                "Implement comprehensive slippage protection",
                "Add oracle price manipulation safeguards",
                "Verify economic models and tokenomics"
            ])
        elif result.domain_classification.domain.value == 'dao':
            recommendations.extend([
                "Verify governance attack vectors",
                "Implement proper timelock mechanisms",
                "Check voting power concentration"
            ])
        elif result.domain_classification.domain.value == 'nft':
            recommendations.extend([
                "Verify metadata immutability",
                "Check royalty implementation correctness",
                "Implement proper access controls for minting"
            ])
        
        # General recommendations
        if len(result.context_classification.business_logic.critical_functions) > 5:
            recommendations.append("Multiple critical functions identified - implement comprehensive testing")
        
        if not result.context_classification.security_context.access_control_patterns:
            recommendations.append("No access control patterns detected - implement proper authorization")
        
        return recommendations

    def export_analysis_result(self, result: AnalysisResult, format: str = 'json') -> str:
        """Export analysis result in specified format."""
        if format.lower() == 'json':
            return self._export_as_json(result)
        elif format.lower() == 'text':
            return self._export_as_text(result)
        else:
            raise ValueError(f"Unsupported export format: {format}")

    def _export_as_json(self, result: AnalysisResult) -> str:
        """Export analysis result as JSON."""
        export_data = {
            'analysis_metadata': result.analysis_metadata,
            'domain_classification': {
                'domain': result.domain_classification.domain.value,
                'protocol': result.domain_classification.protocol.value if result.domain_classification.protocol else None,
                'confidence': result.domain_classification.confidence,
                'subtype': result.domain_classification.subtype,
                'reasoning': result.domain_classification.reasoning,
                'matched_patterns': result.domain_classification.matched_patterns
            },
            'context_classification': {
                'business_logic_types': [bl.value for bl in result.context_classification.business_logic.logic_types],
                'complexity_score': result.context_classification.complexity_score,
                'risk_score': result.context_classification.risk_score,
                'critical_functions': result.context_classification.business_logic.critical_functions,
                'admin_functions': result.context_classification.business_logic.admin_functions,
                'security_context': {
                    'has_payable_functions': result.context_classification.security_context.has_payable_functions,
                    'has_external_calls': result.context_classification.security_context.has_external_calls,
                    'has_delegatecalls': result.context_classification.security_context.has_delegatecalls,
                    'has_selfdestruct': result.context_classification.security_context.has_selfdestruct,
                    'access_control_patterns': result.context_classification.security_context.access_control_patterns
                }
            },
            'applicable_agents': result.applicable_agents,
            'applicable_checks': result.applicable_checks,
            'findings': [asdict(finding) for finding in result.findings] if result.findings else [],
            'analysis_summary': self.get_analysis_summary(result)
        }
        
        return json.dumps(export_data, indent=2, default=str)

    def _export_as_text(self, result: AnalysisResult) -> str:
        """Export analysis result as formatted text."""
        lines = []
        lines.append("=" * 80)
        lines.append("SMART CONTRACT ANALYSIS REPORT")
        lines.append("=" * 80)
        lines.append("")
        
        # Contract information
        lines.append("CONTRACT INFORMATION:")
        lines.append("-" * 40)
        for contract in result.parsed_contract.contracts:
            lines.append(f"Contract Name: {contract.name}")
            lines.append(f"Contract Type: {contract.contract_type}")
            lines.append(f"Functions: {len(contract.functions)}")
            lines.append(f"State Variables: {len(contract.state_variables)}")
            lines.append("")
        
        # Classification results
        lines.append("CLASSIFICATION RESULTS:")
        lines.append("-" * 40)
        lines.append(f"Domain: {result.domain_classification.domain.value}")
        if result.domain_classification.protocol:
            lines.append(f"Protocol: {result.domain_classification.protocol.value}")
        lines.append(f"Confidence: {result.domain_classification.confidence:.2f}")
        if result.domain_classification.subtype:
            lines.append(f"Subtype: {result.domain_classification.subtype}")
        lines.append("")
        
        # Context analysis
        lines.append("CONTEXT ANALYSIS:")
        lines.append("-" * 40)
        lines.append(f"Complexity Score: {result.context_classification.complexity_score:.2f}")
        lines.append(f"Risk Score: {result.context_classification.risk_score:.2f}")
        lines.append(f"Business Logic Types: {len(result.context_classification.business_logic.logic_types)}")
        lines.append(f"Critical Functions: {len(result.context_classification.business_logic.critical_functions)}")
        lines.append("")
        
        # Security overview
        lines.append("SECURITY OVERVIEW:")
        lines.append("-" * 40)
        sec_ctx = result.context_classification.security_context
        lines.append(f"Has Payable Functions: {sec_ctx.has_payable_functions}")
        lines.append(f"Has External Calls: {sec_ctx.has_external_calls}")
        lines.append(f"Has Delegatecalls: {sec_ctx.has_delegatecalls}")
        lines.append(f"Uses tx.origin: {sec_ctx.uses_tx_origin}")
        lines.append("")
        
        # Applicable checks and agents
        lines.append("ANALYSIS SCOPE:")
        lines.append("-" * 40)
        lines.append(f"Applicable Agents: {len(result.applicable_agents)}")
        for agent in result.applicable_agents:
            lines.append(f"  - {agent}")
        lines.append(f"Applicable Checks: {len(result.applicable_checks)}")
        for check in result.applicable_checks:
            lines.append(f"  - {check}")
        lines.append("")
        
        # Findings summary
        lines.append("FINDINGS SUMMARY:")
        lines.append("-" * 40)
        lines.append(f"Total Findings: {len(result.findings)}")
        
        if result.findings:
            severity_dist = self._get_severity_distribution(result.findings)
            for severity, count in severity_dist.items():
                if count > 0:
                    lines.append(f"  {severity.capitalize()}: {count}")
        lines.append("")
        
        # Recommendations
        recommendations = self._generate_recommendations(result)
        if recommendations:
            lines.append("RECOMMENDATIONS:")
            lines.append("-" * 40)
            for rec in recommendations:
                lines.append(f"• {rec}")
            lines.append("")
        
        lines.append("=" * 80)
        lines.append("End of Report")
        lines.append("=" * 80)
        
        return "\n".join(lines)

    def get_statistics(self) -> Dict[str, Any]:
        """Get analyzer statistics."""
        return {
            'analysis_stats': self.analysis_stats.copy(),
            'parser_stats': {
                'patterns_loaded': len(self.parser.patterns),
                'compiled_patterns': len(self.parser.compiled_patterns)
            },
            'classifier_stats': {
                'domains_supported': len(self.domain_classifier.domain_patterns),
                'protocols_supported': len(self.domain_classifier.protocol_patterns)
            }
        }
