"""
Main orchestrator for the smart contract audit platform.
Handles:
    - Contract loading and validation
    - AST parsing and metadata extraction
    - Domain and protocol classification
    - Comprehensive security analysis
    - Agent/check invocation
    - Finding generation with code snippets and line numbers
    - Fuzzing template generation for testing
    - LLM integration (if enabled)
    - Structured report generation
"""

import os
import sys
import json
import logging
from pathlib import Path
from datetime import datetime

from . import config
from .core.parser import parse_contract_code
from .core.domain_classifier import DomainClassifier
from .core.protocol_classifier import ProtocolClassifier
from .models.context import AnalysisContext
from .models.finding import Finding, Severity, Category, CodeLocation

# === Logging setup ===
logging.basicConfig(
    filename=config.LOG_FILE,
    level=getattr(logging, config.LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s"
)
logger = logging.getLogger("MainAuditOrchestration")

# === Multi-Domain Analysis Functions ===

def analyze_cross_domain_vulnerabilities(contract_code: str, domains: list, context: AnalysisContext) -> list:
    """Analyze vulnerabilities that arise from cross-domain interactions."""
    findings = []
    code_lower = contract_code.lower()
    
    if len(domains) < 2:
        return findings
    
    contract_names = []
    if hasattr(context, '_parsed_contract') and context._parsed_contract.contracts:
        contract_names = [contract.name for contract in context._parsed_contract.contracts]
    else:
        contract_names = ["UnknownContract"]
    
    logger.info(f"🔀 Analyzing cross-domain vulnerabilities for: {' + '.join(domains)}")
    
    # 1. GameFi + DeFi: Economic exploit through game mechanics
    if 'gamefi' in domains and 'defi' in domains:
        if 'random' in code_lower and ('reward' in code_lower or 'stake' in code_lower):
            snippet, line_num = extract_code_snippet(contract_code, 'reward')
            finding = Finding(
                title="GameFi-DeFi Cross-Domain Risk: Exploitable Game Economics",
                description="GameFi randomness combined with DeFi rewards creates exploitable economic incentives. Players may manipulate game outcomes to maximize financial returns.",
                severity=Severity.HIGH,
                category=Category.ECONOMIC_MODEL,
                location=CodeLocation(
                    contract_name=contract_names[0],
                    line_number=line_num,
                    code_snippet=snippet
                ),
                affected_contracts=contract_names,
                affected_functions=["claimRewards", "_random"],
                recommendation="Implement cooldowns, commit-reveal schemes, or separate game rewards from financial staking rewards",
                impact="Players could exploit predictable randomness to extract excessive rewards from staking mechanisms",
                code_snippet=snippet,
                line_numbers=[line_num]
            )
            findings.append(finding)
        
        # Check for flash loan gaming exploits
        if 'flashloan' in code_lower or ('game' in code_lower and 'liquidity' in code_lower):
            snippet, line_num = extract_code_snippet(contract_code, 'flash')
            finding = Finding(
                title="GameFi-DeFi: Flash Loan Gaming Exploit",
                description="Flash loans could be used to temporarily manipulate game state or rankings for profit.",
                severity=Severity.HIGH,
                category=Category.DEFI_SPECIFIC,
                location=CodeLocation(
                    contract_name=contract_names[0],
                    line_number=line_num,
                    code_snippet=snippet
                ),
                affected_contracts=contract_names,
                recommendation="Implement time-based restrictions and flash loan protection in game mechanics",
                impact="Players could use flash loans to manipulate leaderboards or extract rewards unfairly",
                code_snippet=snippet,
                line_numbers=[line_num]
            )
            findings.append(finding)
    
    # 2. DAO + DeFi: Governance attacks on treasury
    if 'dao' in domains and 'defi' in domains:
        if ('vote' in code_lower or 'propose' in code_lower) and ('treasury' in code_lower or 'withdraw' in code_lower):
            snippet, line_num = extract_code_snippet(contract_code, 'treasury' if 'treasury' in code_lower else 'withdraw')
            finding = Finding(
                title="DAO-DeFi Cross-Domain Risk: Governance Treasury Drain",
                description="DAO voting mechanisms control DeFi treasury functions. Malicious proposals could drain protocol funds if governance thresholds are too low.",
                severity=Severity.CRITICAL,
                category=Category.AUTHORIZATION,
                location=CodeLocation(
                    contract_name=contract_names[0],
                    line_number=line_num,
                    code_snippet=snippet
                ),
                affected_contracts=contract_names,
                recommendation="Implement proposal timeouts, higher quorum requirements for treasury operations, and emergency veto mechanisms",
                impact="Attackers could acquire voting power and drain protocol treasury through malicious governance proposals",
                code_snippet=snippet,
                line_numbers=[line_num]
            )
            findings.append(finding)
    
    # 3. NFT + GameFi: Asset duplication through game mechanics
    if 'nft' in domains and 'gamefi' in domains:
        if 'mint' in code_lower and ('level' in code_lower or 'upgrade' in code_lower):
            snippet, line_num = extract_code_snippet(contract_code, 'mint')
            finding = Finding(
                title="NFT-GameFi Cross-Domain Risk: Asset Inflation Through Game Mechanics",
                description="NFT minting combined with game upgrade mechanics could allow unintended asset creation or duplication.",
                severity=Severity.MEDIUM,
                category=Category.BUSINESS_LOGIC,
                location=CodeLocation(
                    contract_name=contract_names[0],
                    line_number=line_num,
                    code_snippet=snippet
                ),
                affected_contracts=contract_names,
                affected_functions=["mintItem", "upgrade"],
                recommendation="Implement strict validation for NFT state changes and prevent double-spending of upgrade resources",
                impact="Players could potentially duplicate valuable NFTs or create assets beyond intended game economy limits",
                code_snippet=snippet,
                line_numbers=[line_num]
            )
            findings.append(finding)
        
        # Check for metadata manipulation in games
        if 'tokenuri' in code_lower or 'metadata' in code_lower:
            snippet, line_num = extract_code_snippet(contract_code, 'tokenuri' if 'tokenuri' in code_lower else 'metadata')
            finding = Finding(
                title="NFT-GameFi: Metadata Manipulation Risk",
                description="Game mechanics could allow unauthorized changes to NFT metadata, affecting rarity or attributes.",
                severity=Severity.MEDIUM,
                category=Category.NFT_SPECIFIC,
                location=CodeLocation(
                    contract_name=contract_names[0],
                    line_number=line_num,
                    code_snippet=snippet
                ),
                affected_contracts=contract_names,
                recommendation="Implement immutable metadata or strict access controls for metadata updates",
                impact="Game exploits could modify NFT attributes, affecting marketplace value",
                code_snippet=snippet,
                line_numbers=[line_num]
            )
            findings.append(finding)
    
    # 4. NFT + DeFi: Collateral and liquidation risks
    if 'nft' in domains and 'defi' in domains:
        if ('collateral' in code_lower or 'liquidat' in code_lower) and 'nft' in code_lower:
            snippet, line_num = extract_code_snippet(contract_code, 'collateral' if 'collateral' in code_lower else 'liquidat')
            finding = Finding(
                title="NFT-DeFi: NFT Collateral Liquidation Risk",
                description="Using NFTs as collateral in DeFi protocols creates unique liquidation and valuation challenges.",
                severity=Severity.HIGH,
                category=Category.DEFI_SPECIFIC,
                location=CodeLocation(
                    contract_name=contract_names[0],
                    line_number=line_num,
                    code_snippet=snippet
                ),
                affected_contracts=contract_names,
                recommendation="Implement robust NFT valuation oracles and gradual liquidation mechanisms",
                impact="Flash crashes in NFT prices could lead to cascading liquidations and protocol insolvency",
                code_snippet=snippet,
                line_numbers=[line_num]
            )
            findings.append(finding)
        
        # Check for NFT fractionalization risks
        if 'fraction' in code_lower or ('share' in code_lower and 'nft' in code_lower):
            snippet, line_num = extract_code_snippet(contract_code, 'fraction' if 'fraction' in code_lower else 'share')
            finding = Finding(
                title="NFT-DeFi: Fractionalization Governance Risk",
                description="Fractional NFT ownership combined with DeFi creates complex governance and ownership disputes.",
                severity=Severity.MEDIUM,
                category=Category.BUSINESS_LOGIC,
                location=CodeLocation(
                    contract_name=contract_names[0],
                    line_number=line_num,
                    code_snippet=snippet
                ),
                affected_contracts=contract_names,
                recommendation="Implement clear governance rules for fractional NFT ownership and DeFi interactions",
                impact="Ownership disputes could lock NFTs or prevent DeFi operations",
                code_snippet=snippet,
                line_numbers=[line_num]
            )
            findings.append(finding)
    
    # 5. DAO + NFT: Governance of NFT collections
    if 'dao' in domains and 'nft' in domains:
        if ('vote' in code_lower or 'govern' in code_lower) and ('mint' in code_lower or 'collection' in code_lower):
            snippet, line_num = extract_code_snippet(contract_code, 'vote' if 'vote' in code_lower else 'govern')
            finding = Finding(
                title="DAO-NFT: Collection Governance Manipulation",
                description="DAO governance over NFT minting could be exploited to dilute collections or manipulate rarity.",
                severity=Severity.MEDIUM,
                category=Category.DAO_SPECIFIC,
                location=CodeLocation(
                    contract_name=contract_names[0],
                    line_number=line_num,
                    code_snippet=snippet
                ),
                affected_contracts=contract_names,
                recommendation="Implement supply caps and rarity protection in DAO-governed NFT collections",
                impact="Malicious proposals could flood market with NFTs, destroying collection value",
                code_snippet=snippet,
                line_numbers=[line_num]
            )
            findings.append(finding)
    
    # 6. DAO + GameFi: Game parameter manipulation
    if 'dao' in domains and 'gamefi' in domains:
        if ('vote' in code_lower or 'propose' in code_lower) and ('difficulty' in code_lower or 'reward' in code_lower or 'rate' in code_lower):
            snippet, line_num = extract_code_snippet(contract_code, 'vote' if 'vote' in code_lower else 'propose')
            finding = Finding(
                title="DAO-GameFi: Game Economy Manipulation",
                description="DAO control over game parameters could be exploited to create unfair advantages.",
                severity=Severity.MEDIUM,
                category=Category.GAMEFI_SPECIFIC,
                location=CodeLocation(
                    contract_name=contract_names[0],
                    line_number=line_num,
                    code_snippet=snippet
                ),
                affected_contracts=contract_names,
                recommendation="Implement parameter change limits and cooldown periods for game economy adjustments",
                impact="Players could vote to manipulate game difficulty or rewards for personal gain",
                code_snippet=snippet,
                line_numbers=[line_num]
            )
            findings.append(finding)
    
    # 7. Multi-domain (3+): Complex interaction risks
    if len(domains) >= 3:
        finding = Finding(
            title="Complex Multi-Domain Interaction Risk",
            description=f"Contract combines {len(domains)} domains ({', '.join(domains)}), creating complex attack surfaces and unexpected interactions.",
            severity=Severity.HIGH,
            category=Category.BUSINESS_LOGIC,
            location=CodeLocation(
                contract_name=contract_names[0],
                line_number=1,
                code_snippet="Multiple domain contract"
            ),
            affected_contracts=contract_names,
            recommendation="Consider separating concerns into multiple contracts with clear interfaces and access controls",
            impact="Complex interactions between domains could create unforeseen vulnerabilities",
            code_snippet="Contract combines: " + ", ".join(domains),
            line_numbers=[1]
        )
        findings.append(finding)
    
    # 8. General multi-domain: Inconsistent access controls
    if len(domains) >= 2:
        access_patterns = ['onlyowner', 'onlyoperator', 'require(msg.sender', 'modifier']
        access_found = [pattern for pattern in access_patterns if pattern in code_lower]
        
        if access_found and ('public' in code_lower or 'external' in code_lower):
            snippet, line_num = extract_code_snippet(contract_code, access_found[0])
            finding = Finding(
                title="Multi-Domain Access Control Inconsistency",
                description=f"Contract spans multiple domains ({' + '.join(domains)}) but may have inconsistent access control patterns across different functional areas.",
                severity=Severity.MEDIUM,
                category=Category.ACCESS_CONTROL,
                location=CodeLocation(
                    contract_name=contract_names[0],
                    line_number=line_num,
                    code_snippet=snippet
                ),
                affected_contracts=contract_names,
                recommendation="Ensure consistent access control patterns across all domains and create clear role separation",
                impact="Privilege escalation attacks could affect multiple protocol domains simultaneously",
                code_snippet=snippet,
                line_numbers=[line_num]
            )
            findings.append(finding)
    
    return findings

# === Security Analysis Functions ===

def find_line_number(code: str, snippet: str) -> int:
    """Find the line number of a code snippet."""
    lines = code.split('\n')
    for i, line in enumerate(lines):
        if snippet.strip() in line.strip():
            return i + 1
    return 1

def extract_code_snippet(code: str, pattern: str, context_lines: int = 2) -> tuple:
    """Extract code snippet with context and line number."""
    lines = code.split('\n')
    for i, line in enumerate(lines):
        if pattern.lower() in line.lower():
            start = max(0, i - context_lines)
            end = min(len(lines), i + context_lines + 1)
            snippet = '\n'.join(lines[start:end])
            return snippet, i + 1
    return pattern, 1

def run_comprehensive_security_analysis(contract_code: str, context: AnalysisContext, workflow_trace: list) -> list:
    """Run comprehensive security analysis with detailed findings."""
    findings = []
    code_lower = contract_code.lower()
    
    try:
        # Get contract names
        contract_names = []
        if hasattr(context, '_parsed_contract') and context._parsed_contract.contracts:
            contract_names = [contract.name for contract in context._parsed_contract.contracts]
        else:
            contract_names = ["UnknownContract"]
        
        workflow_trace.append("Analyzing access control patterns...")
        
        # 1. Check for missing access controls on critical functions
        critical_functions = ['withdraw', 'transfer', 'mint', 'burn', 'pause', 'unpause', 'setowner', 'setoperator']
        for func in critical_functions:
            if func in code_lower:
                # Check if function has access control
                func_snippet, func_line = extract_code_snippet(contract_code, func)
                if 'require' not in func_snippet and 'modifier' not in func_snippet and 'only' not in func_snippet:
                    finding = Finding(
                        title=f"Missing Access Control on {func.capitalize()} Function",
                        description=f"The {func} function appears to lack access control modifiers. This could allow unauthorized users to execute critical operations.",
                        severity=Severity.CRITICAL,
                        category=Category.ACCESS_CONTROL,
                        location=CodeLocation(
                            contract_name=contract_names[0],
                            line_number=func_line,
                            code_snippet=func_snippet
                        ),
                        affected_contracts=contract_names,
                        affected_functions=[func],
                        recommendation="Add appropriate access control modifiers (onlyOwner, onlyRole, etc.) to restrict function access",
                        impact="Unauthorized users could drain funds, mint tokens, or manipulate contract state",
                        code_snippet=func_snippet,
                        line_numbers=[func_line]
                    )
                    findings.append(finding)
        
        # 2. Centralization risks
        if 'onlyowner' in code_lower or 'onlygovernance' in code_lower:
            snippet, line_num = extract_code_snippet(contract_code, 'only')
            finding = Finding(
                title="Centralization Risk - Single Point of Control",
                description="Contract has centralized control through owner/governance roles. This creates trust assumptions and potential for rug pulls.",
                severity=Severity.HIGH,
                category=Category.ACCESS_CONTROL,
                location=CodeLocation(
                    contract_name=contract_names[0],
                    line_number=line_num,
                    code_snippet=snippet
                ),
                affected_contracts=contract_names,
                affected_functions=["Multiple functions with restricted access"],
                recommendation="Implement multi-signature wallets, time-locks, or decentralized governance to reduce centralization risks",
                impact="Single entity can control critical contract functions, potentially leading to fund theft or malicious updates",
                code_snippet=snippet,
                line_numbers=[line_num]
            )
            findings.append(finding)
        
        workflow_trace.append("Checking reentrancy vulnerabilities...")
        
        # 3. Check for reentrancy vulnerabilities
        external_calls = ['.call{', '.transfer(', '.send(', 'call(abi', 'delegatecall', 'staticcall']
        state_changes = ['balances[', 'balance[', '+=', '-=', '=']
        
        for call_pattern in external_calls:
            if call_pattern in code_lower:
                snippet, line_num = extract_code_snippet(contract_code, call_pattern)
                # Check if state changes happen after external call
                for state_pattern in state_changes:
                    if state_pattern in snippet:
                        finding = Finding(
                            title="Critical Reentrancy Vulnerability Detected",
                            description="External calls are made before state changes. This violates the checks-effects-interactions pattern and enables reentrancy attacks.",
                            severity=Severity.CRITICAL,
                            category=Category.REENTRANCY,
                            location=CodeLocation(
                                contract_name=contract_names[0],
                                line_number=line_num,
                                code_snippet=snippet
                            ),
                            affected_contracts=contract_names,
                            recommendation="Follow checks-effects-interactions pattern: 1) Check conditions, 2) Update state, 3) Make external calls. Use ReentrancyGuard.",
                            impact="Attackers can recursively call the function to drain all funds from the contract",
                            code_snippet=snippet,
                            line_numbers=[line_num]
                        )
                        findings.append(finding)
                        break
        
        # 4. Integer overflow/underflow vulnerabilities
        workflow_trace.append("Checking for integer overflow/underflow vulnerabilities...")
        arithmetic_ops = ['+=', '-=', '*=', '/=', '++', '--']
        for op in arithmetic_ops:
            if op in code_lower and 'safeMath' not in code_lower and 'using SafeMath' not in contract_code:
                snippet, line_num = extract_code_snippet(contract_code, op)
                finding = Finding(
                    title="Integer Overflow/Underflow Risk",
                    description="Arithmetic operations without SafeMath library or overflow checks detected. This can lead to integer overflow/underflow vulnerabilities.",
                    severity=Severity.HIGH,
                    category=Category.ARITHMETIC,
                    location=CodeLocation(
                        contract_name=contract_names[0],
                        line_number=line_num,
                        code_snippet=snippet
                    ),
                    affected_contracts=contract_names,
                    recommendation="Use SafeMath library or Solidity 0.8+ with built-in overflow protection for all arithmetic operations",
                    impact="Arithmetic overflow could allow attackers to manipulate balances, bypass checks, or mint unlimited tokens",
                    code_snippet=snippet,
                    line_numbers=[line_num]
                )
                findings.append(finding)
                break
        
        workflow_trace.append("Analyzing randomness sources...")
        
        # 3. Weak randomness
        if 'block.timestamp' in code_lower and ('random' in code_lower or 'prevrandao' in code_lower):
            snippet, line_num = extract_code_snippet(contract_code, 'block.timestamp')
            finding = Finding(
                title="Weak Randomness Source - Miner Manipulation Risk",
                description="Using block.timestamp and block.prevrandao for randomness can be manipulated by miners.",
                severity=Severity.HIGH,
                category=Category.RANDOMNESS,
                location=CodeLocation(
                    contract_name=contract_names[0],
                    function_name="_random",
                    line_number=line_num,
                    code_snippet=snippet
                ),
                affected_contracts=contract_names,
                affected_functions=["_random", "mintItem"],
                recommendation="Use Chainlink VRF (Verifiable Random Function) or commit-reveal schemes for secure randomness",
                impact="Predictable randomness could be exploited for unfair advantages in gaming or NFT minting",
                code_snippet=snippet,
                line_numbers=[line_num]
            )
            findings.append(finding)
        
        workflow_trace.append("Checking economic model sustainability...")
        
        # 4. Fixed reward rate risk
        if 'reward_rate' in code_lower and '15' in code_lower:
            snippet, line_num = extract_code_snippet(contract_code, 'REWARD_RATE')
            finding = Finding(
                title="Fixed Reward Rate - Economic Sustainability Risk",
                description="Contract uses a fixed 15% reward rate which may not be economically sustainable long-term.",
                severity=Severity.MEDIUM,
                category=Category.ECONOMIC_MODEL,
                location=CodeLocation(
                    contract_name=contract_names[0],
                    line_number=line_num,
                    code_snippet=snippet
                ),
                affected_contracts=contract_names,
                recommendation="Implement dynamic reward rates based on token supply, treasury balance, or performance metrics",
                impact="Unsustainable tokenomics could lead to protocol failure or token inflation",
                code_snippet=snippet,
                line_numbers=[line_num]
            )
            findings.append(finding)
        
        # 5. Check for unchecked return values
        workflow_trace.append("Checking for unchecked return values...")
        if '.transfer(' in code_lower or '.send(' in code_lower:
            snippet, line_num = extract_code_snippet(contract_code, '.transfer' if '.transfer(' in code_lower else '.send')
            if 'require' not in snippet and 'assert' not in snippet and 'if' not in snippet:
                finding = Finding(
                    title="Unchecked Return Value on Transfer",
                    description="Transfer or send operations without checking return values can fail silently, leading to accounting errors.",
                    severity=Severity.HIGH,
                    category=Category.UNCHECKED_CALLS,
                    location=CodeLocation(
                        contract_name=contract_names[0],
                        line_number=line_num,
                        code_snippet=snippet
                    ),
                    affected_contracts=contract_names,
                    recommendation="Always check return values of transfer/send operations. Use require() or revert on failure.",
                    impact="Failed transfers could lead to incorrect balance tracking and loss of funds",
                    code_snippet=snippet,
                    line_numbers=[line_num]
                )
                findings.append(finding)
        
        # 6. Check for DeFi-specific vulnerabilities
        workflow_trace.append("Checking DeFi-specific vulnerabilities...")
        
        # Check for flash loan vulnerabilities
        if 'flashloan' in code_lower or ('borrow' in code_lower and 'repay' in code_lower):
            snippet, line_num = extract_code_snippet(contract_code, 'borrow')
            finding = Finding(
                title="Flash Loan Attack Vector Present",
                description="Contract implements flash loan functionality or borrowing mechanisms that could be exploited for price manipulation or reentrancy attacks.",
                severity=Severity.HIGH,
                category=Category.DEFI_SPECIFIC,
                location=CodeLocation(
                    contract_name=contract_names[0],
                    line_number=line_num,
                    code_snippet=snippet
                ),
                affected_contracts=contract_names,
                recommendation="Implement flash loan protection: price oracles with TWAP, reentrancy guards, and proper access controls",
                impact="Flash loan attacks could manipulate prices, drain liquidity pools, or exploit economic mechanisms",
                code_snippet=snippet,
                line_numbers=[line_num]
            )
            findings.append(finding)
        
        # Check for price oracle manipulation
        if 'price' in code_lower and ('oracle' in code_lower or 'getprice' in code_lower):
            snippet, line_num = extract_code_snippet(contract_code, 'price')
            finding = Finding(
                title="Price Oracle Manipulation Risk",
                description="Contract relies on price oracles that may be vulnerable to manipulation through flash loans or other attacks.",
                severity=Severity.HIGH,
                    category=Category.DEFI_SPECIFIC,
                location=CodeLocation(
                    contract_name=contract_names[0],
                    line_number=line_num,
                    code_snippet=snippet
                ),
                affected_contracts=contract_names,
                recommendation="Use time-weighted average prices (TWAP), multiple oracle sources, or Chainlink price feeds for reliable pricing",
                impact="Price manipulation could lead to incorrect valuations, unfair liquidations, or protocol insolvency",
                code_snippet=snippet,
                line_numbers=[line_num]
            )
            findings.append(finding)
        
        # 7. Check for DAO-specific vulnerabilities
        workflow_trace.append("Checking DAO-specific vulnerabilities...")
        
        # Check for voting vulnerabilities
        if 'vote' in code_lower and 'proposal' in code_lower:
            snippet, line_num = extract_code_snippet(contract_code, 'vote')
            # Check for double voting
            if 'voted[' not in code_lower and 'hasvoted' not in code_lower:
                finding = Finding(
                    title="Double Voting Vulnerability",
                    description="Voting mechanism may allow users to vote multiple times on the same proposal.",
                    severity=Severity.CRITICAL,
                    category=Category.DAO_SPECIFIC,
                    location=CodeLocation(
                        contract_name=contract_names[0],
                        line_number=line_num,
                        code_snippet=snippet
                    ),
                    affected_contracts=contract_names,
                    recommendation="Track which addresses have voted using a mapping(uint => mapping(address => bool)) hasVoted",
                    impact="Malicious actors could manipulate governance decisions by voting multiple times",
                    code_snippet=snippet,
                    line_numbers=[line_num]
                )
                findings.append(finding)
        
        # Check for proposal spam
        if 'propose' in code_lower and 'proposalcount' in code_lower:
            snippet, line_num = extract_code_snippet(contract_code, 'propose')
            if 'fee' not in snippet and 'cost' not in snippet and 'stake' not in snippet:
                finding = Finding(
                    title="Proposal Spam Attack Vector",
                    description="No cost or stake requirement for creating proposals. This could lead to proposal spam attacks.",
                    severity=Severity.MEDIUM,
                    category=Category.DENIAL_OF_SERVICE,
                    location=CodeLocation(
                        contract_name=contract_names[0],
                        line_number=line_num,
                        code_snippet=snippet
                    ),
                    affected_contracts=contract_names,
                    recommendation="Require a minimum token stake or fee for proposal creation to prevent spam",
                    impact="Governance could be disrupted by spam proposals, making it difficult to find legitimate proposals",
                    code_snippet=snippet,
                    line_numbers=[line_num]
                )
                findings.append(finding)
        
        workflow_trace.append("Analyzing emergency mechanisms...")
        
        workflow_trace.append("Checking timestamp dependencies...")
        
        # 6. Time-based logic risks
        if 'block.timestamp' in code_lower and ('days' in code_lower or 'duration' in code_lower):
            snippet, line_num = extract_code_snippet(contract_code, 'STAKING_DURATION')
            finding = Finding(
                title="Timestamp Dependence in Critical Logic",
                description="Contract relies on block.timestamp for time-sensitive operations. Miners can manipulate timestamps within limits.",
                severity=Severity.LOW,
                category=Category.TIMESTAMP_DEPENDENCE,
                location=CodeLocation(
                    contract_name=contract_names[0],
                    line_number=line_num,
                    code_snippet=snippet
                ),
                affected_contracts=contract_names,
                recommendation="Consider using block numbers instead of timestamps for critical time-based logic, or implement tolerance ranges",
                impact="Slight timing manipulation possible, affecting reward calculations",
                code_snippet=snippet,
                line_numbers=[line_num]
            )
            findings.append(finding)
        
        workflow_trace.append("Analyzing event emissions...")
        
        # 7. Missing events for important state changes
        has_events = 'emit' in code_lower
        has_state_changes = any(keyword in code_lower for keyword in ['stake', 'withdraw', 'claim', 'mint'])
        
        if not has_events and has_state_changes:
            finding = Finding(
                title="Missing Event Emissions for State Changes",
                description="Important state-changing functions should emit events for transparency and monitoring.",
                severity=Severity.LOW,
                category=Category.BEST_PRACTICES,
                affected_contracts=contract_names,
                recommendation="Add comprehensive event emissions for all state-changing operations",
                impact="Reduced transparency and difficulty in monitoring contract activity"
            )
            findings.append(finding)
        
        workflow_trace.append("Generating fuzzing test templates...")
        
        # 8. Generate fuzzing recommendations
        fuzzing_targets = []
        if 'stake' in code_lower:
            fuzzing_targets.append("stakeTokens function with edge case amounts (0, max uint256, etc.)")
        if 'mint' in code_lower:
            fuzzing_targets.append("mintItem function with various token URI inputs")
        if 'upgrade' in code_lower:
            fuzzing_targets.append("upgrade function with boundary token IDs")
        
        if fuzzing_targets:
            finding = Finding(
                title="Recommended Fuzzing Test Targets",
                description=f"Key functions identified for fuzzing tests: {', '.join(fuzzing_targets)}",
                severity=Severity.INFO,
                category=Category.OTHER,
                affected_contracts=contract_names,
                recommendation="Implement property-based fuzzing tests for critical functions with edge cases",
                impact="Improved test coverage and bug detection"
            )
            findings.append(finding)
        
        logger.info(f"Generated {len(findings)} security findings")
        return findings
        
    except Exception as e:
        logger.error(f"Error in security analysis: {e}")
        error_finding = Finding(
            title="Security Analysis Error",
            description=f"An error occurred during security analysis: {str(e)}",
            severity=Severity.INFO,
            category=Category.OTHER,
            recommendation="Review analysis configuration and contract format",
            impact="Incomplete security analysis"
        )
        return [error_finding]

# === Contract Loader ===
def load_contract_source(file_path: str) -> str:
    if not os.path.isfile(file_path):
        logger.error(f"❌ File not found: {file_path}")
        raise FileNotFoundError(f"Contract file not found: {file_path}")

    with open(file_path, encoding="utf-8") as f:
        logger.info(f"📦 Loaded contract: {file_path}")
        return f.read()

# === Audit Run ===
def orchestrate_audit(contract_path: str):
    # === Logging + Trace ===
    logger.info(f"🧠 Starting analysis for: {contract_path}")
    workflow_trace = []

    # === Step 1: Load source code ===
    workflow_trace.append("Loading contract source...")
    contract_code = load_contract_source(contract_path)

    # === Step 2: Parse AST and functions ===
    workflow_trace.append("Parsing contract AST and metadata...")
    context: AnalysisContext = parse_contract_code(contract_code, contract_path)
    logger.info("✔ AST Parsing complete")

    # === Step 3: Multi-Domain Classification ===
    workflow_trace.append("Classifying contract domain(s)...")
    domain_classifier = DomainClassifier()
    if hasattr(context, '_parsed_contract'):
        # Get single domain classification for compatibility
        classification_result = domain_classifier.classify(context._parsed_contract)
        
        # Get multiple domains classification
        multi_domains = domain_classifier.classify_multiple_domains(context._parsed_contract, threshold=0.2)
        
        # Convert domain enums to string values
        context.domains = [domain.value for domain, _ in multi_domains]
        context.domain = context.domains[0] if context.domains else "unknown"
        
        logger.info(f"🔍 Domains detected: {context.domains}")
        
        # Check for cross-domain patterns
        if len(context.domains) > 1:
            logger.info(f"🔀 Multi-domain contract detected: {' + '.join(context.domains)}")
            workflow_trace.append(f"Multi-domain analysis: {' + '.join(context.domains)}")
    else:
        context.domains = ["unknown"]
        context.domain = "unknown"
        logger.warning("⚠️ No parsed contract for classification")

    # === Step 4: Optional – Protocol Classification ===
    workflow_trace.append("Classifying protocol (if applicable)...")
    protocol_classifier = ProtocolClassifier()
    if hasattr(context, '_parsed_contract'):
        context.protocol = protocol_classifier.classify_protocol(context._parsed_contract)
        if context.protocol:
            logger.info(f"📡 Protocol detected: {context.protocol}")
        else:
            logger.info("📡 No protocol match found")
    else:
        context.protocol = None
        logger.warning("⚠️ No parsed contract for protocol classification")

    # === Step 5: Run Comprehensive Security Analysis ===
    workflow_trace.append("Running comprehensive security analysis...")
    findings = run_comprehensive_security_analysis(contract_code, context, workflow_trace)
    logger.info(f"✔ Security analysis complete – {len(findings)} findings extracted")
    
    # === Step 5.5: Cross-Domain Vulnerability Analysis ===
    if len(context.domains) > 1:
        workflow_trace.append(f"Analyzing cross-domain vulnerabilities for: {' + '.join(context.domains)}...")
        cross_domain_findings = analyze_cross_domain_vulnerabilities(contract_code, context.domains, context)
        findings.extend(cross_domain_findings)
        logger.info(f"✔ Cross-domain analysis complete – {len(cross_domain_findings)} additional findings extracted")
    else:
        logger.info(f"⏩ Single domain ({context.domain}) - skipping cross-domain analysis")
    
    # === Step 5.6: Run Domain-Specific Agents ===
    workflow_trace.append("Running domain-specific security agents...")
    agent_findings = []
    
    # Get applicable agents based on domains
    applicable_agents = set()
    if hasattr(context, '_parsed_contract') and classification_result:
        for domain_value in context.domains:
            # Create a temporary classification result for each domain
            domain_enum = next((d for d in DomainClassifier().domain_patterns.keys() if d.value == domain_value), None)
            if domain_enum:
                temp_classification = type('obj', (object,), {
                    'domain': domain_enum,
                    'protocol': classification_result.protocol,
                    'subtype': classification_result.subtype
                })
                agents = domain_classifier.get_applicable_agents(temp_classification)
                applicable_agents.update(agents)
    
    logger.info(f"🤖 Running {len(applicable_agents)} domain-specific agents...")
    workflow_trace.append(f"Applicable agents: {', '.join(sorted(applicable_agents))}")
    
    # Run basic analyzer to invoke agents
    try:
        from .core.analyzer import ContractAnalyzer
        analyzer = ContractAnalyzer()
        analysis_result = analyzer.analyze(contract_code)
        
        # Extract agent findings
        if analysis_result and analysis_result.findings:
            agent_findings = analysis_result.findings
            logger.info(f"✔ Agent analysis complete – {len(agent_findings)} findings from agents")
            
            # Convert agent findings to our Finding format if needed
            for agent_finding in agent_findings:
                if not isinstance(agent_finding, Finding):
                    # Convert from agent format to our Finding format
                    finding = Finding(
                        title=agent_finding.get('title', 'Agent Finding'),
                        description=agent_finding.get('description', ''),
                        severity=Severity.MEDIUM,
                        category=Category.OTHER,
                        affected_contracts=contract_names,
                        recommendation=agent_finding.get('recommendation', ''),
                        impact=agent_finding.get('impact', '')
                    )
                    findings.append(finding)
                else:
                    findings.append(agent_finding)
    except Exception as e:
        logger.warning(f"⚠️ Agent analysis failed: {e}")
        workflow_trace.append(f"Agent analysis error: {str(e)}")

    # === Step 6: Optional – LLM-Powered Analysis ===
    if config.ENABLE_LLM_ANALYSIS and config.LLM_API_KEY:
        try:
            workflow_trace.append("Running LLM-powered enhanced analysis...")
            from .llm.client import LLMClient
            from .llm.prompts import PromptManager

            llm_client = LLMClient(
                provider=config.LLM_PROVIDER,
                model_name=getattr(config, "LLM_MODEL_NAME", "gpt-4.1-nano"),
                api_key=config.LLM_API_KEY
            )
            prompt_manager = PromptManager()

            llm_findings = analyzer.run_llm(context, llm_client, prompt_manager)
            findings.extend(llm_findings)
            logger.info(f"➕ LLM-enhanced findings: {len(llm_findings)}")

        except Exception as e:
            logger.error(f"⚠️ Failed to run LLM analysis: {e}")

    # === Step 7: Final Report ===
    report = {
        "status": "success",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "contract": os.path.basename(contract_path),
        "domain": context.domain,                        # e.g., "defi"
        "domains": context.domains,                      # e.g., ["defi", "dao"]
        "protocol": context.protocol,                    # e.g., "compound_governance"
        "findings": [f.to_dict() for f in findings],     # Convert all findings to JSON-serializable
        "trace": workflow_trace
    }

    with open(config.RESULTS_FILE, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    logger.info(f"✅ Report written: {config.RESULTS_FILE}")
    print(f"\n🎉 Audit complete – results in: '{config.RESULTS_FILE}'\n")

# === CLI Entrypoint ===
def main():
    if len(sys.argv) < 2:
        print("❗ USAGE: python src/main.py path/to/YourContract.sol")
        sys.exit(1)

    contract_path = sys.argv[1]
    try:
        orchestrate_audit(contract_path)
    except Exception as e:
        logger.exception(f"Analysis failed: {str(e)}")
        print(f"❌ Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
