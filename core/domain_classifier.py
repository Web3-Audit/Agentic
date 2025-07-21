"""
Domain classifier for identifying the domain and type of smart contracts.
"""

import re
import logging
from typing import Dict, List, Set, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

from .parser import ParsedContract, Contract, Function

logger = logging.getLogger(__name__)

class Domain(Enum):
    DEFI = "defi"
    DAO = "dao"
    NFT = "nft"
    GAMEFI = "gamefi"
    UTILITY = "utility"
    SECURITY = "security"
    UNKNOWN = "unknown"

class Protocol(Enum):
    # DeFi Protocols
    UNISWAP_V2 = "uniswap_v2"
    UNISWAP_V3 = "uniswap_v3"
    AAVE_V2 = "aave_v2"
    AAVE_V3 = "aave_v3"
    COMPOUND = "compound"
    CURVE = "curve"
    SUSHISWAP = "sushiswap"
    PANCAKESWAP = "pancakeswap"
    
    # DAO Protocols
    COMPOUND_GOVERNANCE = "compound_governance"
    ARAGON = "aragon"
    MOLOCH = "moloch"
    GNOSIS_SAFE = "gnosis_safe"
    SNAPSHOT = "snapshot"
    
    # NFT Protocols
    OPENSEA = "opensea"
    BLUR = "blur"
    LOOKSRARE = "looksrare"
    FOUNDATION = "foundation"
    SUPERRARE = "superrare"
    
    # GameFi Protocols
    AXIE_INFINITY = "axie_infinity"
    STEPN = "stepn"
    SANDBOX = "sandbox"
    DECENTRALAND = "decentraland"
    
    UNKNOWN = "unknown"

@dataclass
class ClassificationResult:
    domain: Domain
    protocol: Optional[Protocol] = None
    confidence: float = 0.0
    subtype: Optional[str] = None
    reasoning: List[str] = None
    matched_patterns: List[str] = None
    
    def __post_init__(self):
        if self.reasoning is None:
            self.reasoning = []
        if self.matched_patterns is None:
            self.matched_patterns = []

class DomainClassifier:
    """
    Classifies smart contracts by domain (DeFi, DAO, NFT, GameFi, etc.)
    and identifies specific protocols when possible.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Domain classification patterns
        self.domain_patterns = {
            Domain.DEFI: {
                'function_names': [
                    'swap', 'addLiquidity', 'removeLiquidity', 'mint', 'burn',
                    'deposit', 'withdraw', 'borrow', 'repay', 'liquidate',
                    'stake', 'unstake', 'claim', 'harvest', 'compound',
                    'flashLoan', 'getAmountOut', 'getAmountIn', 'getReserves',
                    'price', 'oracle', 'pool', 'pair', 'reserve'
                ],
                'contract_names': [
                    'Router', 'Factory', 'Pair', 'Pool', 'Vault', 'Strategy',
                    'LendingPool', 'AaveProtocol', 'CompoundProtocol',
                    'UniswapV2', 'UniswapV3', 'SushiSwap', 'PancakeSwap',
                    'Curve', 'Balancer', 'Yearn'
                ],
                'keywords': [
                    'liquidity', 'swap', 'amm', 'dex', 'lending', 'borrowing',
                    'yield', 'farming', 'staking', 'defi', 'protocol',
                    'flashloan', 'oracle', 'price', 'slippage', 'fee'
                ],
                'interfaces': [
                    'IERC20', 'IUniswapV2Router', 'IUniswapV3Pool', 
                    'IAaveProtocol', 'ICompound', 'ICurve'
                ]
            },
            
            Domain.DAO: {
                'function_names': [
                    'propose', 'vote', 'execute', 'delegate', 'veto',
                    'govVote', 'govPropose', 'govExecute', 'timelock',
                    'quorum', 'threshold', 'ballot', 'referendum'
                ],
                'contract_names': [
                    'Governor', 'Governance', 'DAO', 'Voting', 'Proposal',
                    'Treasury', 'Timelock', 'Multisig', 'Council', 'Parliament'
                ],
                'keywords': [
                    'governance', 'voting', 'proposal', 'dao', 'delegate',
                    'quorum', 'threshold', 'timelock', 'treasury', 'multisig',
                    'council', 'parliament', 'referendum', 'ballot'
                ],
                'interfaces': [
                    'IGovernor', 'IERC20Votes', 'ITimelock', 'IMultisig'
                ]
            },
            
            Domain.NFT: {
                'function_names': [
                    'mint', 'burn', 'tokenURI', 'setApprovalForAll',
                    'safeTransferFrom', 'transferFrom', 'approve',
                    'ownerOf', 'balanceOf', 'totalSupply', 'royaltyInfo',
                    'setRoyalty', 'marketplace', 'auction', 'bid'
                ],
                'contract_names': [
                    'NFT', 'ERC721', 'ERC1155', 'Marketplace', 'Auction',
                    'Collection', 'Token', 'Art', 'Collectible', 'Avatar'
                ],
                'keywords': [
                    'nft', 'token', 'collectible', 'art', 'metadata',
                    'royalty', 'marketplace', 'auction', 'mint', 'collection',
                    'avatar', 'pfp', 'generative', 'rarity'
                ],
                'interfaces': [
                    'IERC721', 'IERC1155', 'IERC721Metadata', 'IERC2981',
                    'IERC721Enumerable', 'IERC1155MetadataURI'
                ]
            },
            
            Domain.GAMEFI: {
                'function_names': [
                    'play', 'battle', 'breed', 'level', 'upgrade', 'craft',
                    'reward', 'earn', 'quest', 'achievement', 'experience',
                    'item', 'weapon', 'character', 'guild', 'tournament'
                ],
                'contract_names': [
                    'Game', 'Gaming', 'Battle', 'Character', 'Item', 'Weapon',
                    'Quest', 'Achievement', 'Guild', 'Tournament', 'Arena',
                    'Pet', 'Monster', 'Hero', 'Card'
                ],
                'keywords': [
                    'game', 'gaming', 'play', 'player', 'battle', 'quest',
                    'achievement', 'level', 'experience', 'item', 'weapon',
                    'character', 'guild', 'tournament', 'arena', 'pet',
                    'monster', 'hero', 'card', 'breed'
                ],
                'interfaces': [
                    'IERC721', 'IERC1155', 'IGame', 'IBattle', 'IQuest'
                ]
            }
        }
        
        # Protocol-specific patterns
        self.protocol_patterns = {
            # DeFi Protocols
            Protocol.UNISWAP_V2: {
                'signatures': ['swapExactTokensForTokens', 'addLiquidity', 'WETH'],
                'contract_names': ['UniswapV2Router', 'UniswapV2Factory', 'UniswapV2Pair'],
                'keywords': ['uniswap', 'v2', '0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D']
            },
            Protocol.UNISWAP_V3: {
                'signatures': ['exactInputSingle', 'mint', 'collect', 'increaseLiquidity'],
                'contract_names': ['SwapRouter', 'NonfungiblePositionManager', 'UniswapV3Pool'],
                'keywords': ['uniswap', 'v3', 'tick', 'sqrt', 'position']
            },
            Protocol.AAVE_V2: {
                'signatures': ['deposit', 'withdraw', 'borrow', 'repay', 'liquidationCall'],
                'contract_names': ['LendingPool', 'AaveProtocolDataProvider'],
                'keywords': ['aave', 'atoken', 'debttoken', 'lending', 'pool']
            },
            Protocol.COMPOUND: {
                'signatures': ['mint', 'redeem', 'borrow', 'repayBorrow', 'liquidateBorrow'],
                'contract_names': ['Comptroller', 'CToken', 'CompoundLens'],
                'keywords': ['compound', 'ctoken', 'comptroller', 'comp']
            },
            
            # DAO Protocols
            Protocol.COMPOUND_GOVERNANCE: {
                'signatures': ['propose', 'castVote', 'execute', 'queue'],
                'contract_names': ['GovernorBravo', 'Timelock', 'Comp'],
                'keywords': ['governor', 'bravo', 'timelock', 'comp']
            },
            Protocol.GNOSIS_SAFE: {
                'signatures': ['execTransaction', 'addOwner', 'removeOwner', 'changeThreshold'],
                'contract_names': ['GnosisSafe', 'MultiSig'],
                'keywords': ['gnosis', 'safe', 'multisig', 'threshold']
            },
            
            # NFT Protocols
            Protocol.OPENSEA: {
                'signatures': ['atomicMatch_', 'ordersCanMatch', 'validateOrder'],
                'contract_names': ['WyvernExchange', 'OpenSeaMarket'],
                'keywords': ['opensea', 'wyvern', 'seaport']
            }
        }

    def classify(self, parsed_contract: ParsedContract) -> ClassificationResult:
        """
        Classify the domain and protocol of a parsed contract.
        
        Args:
            parsed_contract: The parsed contract to classify
            
        Returns:
            ClassificationResult: Classification results with confidence scores
        """
        try:
            # Initialize scores for each domain
            domain_scores = {domain: 0.0 for domain in Domain}
            protocol_scores = {protocol: 0.0 for protocol in Protocol}
            
            reasoning = []
            matched_patterns = []
            
            # Analyze all contracts in the file
            for contract in parsed_contract.contracts:
                contract_scores, contract_reasoning, contract_patterns = self._analyze_contract(contract)
                
                # Combine scores
                for domain, score in contract_scores['domains'].items():
                    domain_scores[domain] += score
                
                for protocol, score in contract_scores['protocols'].items():
                    protocol_scores[protocol] += score
                
                reasoning.extend(contract_reasoning)
                matched_patterns.extend(contract_patterns)
            
            # Normalize scores
            total_contracts = len(parsed_contract.contracts)
            if total_contracts > 0:
                for domain in domain_scores:
                    domain_scores[domain] /= total_contracts
                for protocol in protocol_scores:
                    protocol_scores[protocol] /= total_contracts
            
            # Determine best domain
            best_domain = max(domain_scores.items(), key=lambda x: x[1])
            best_protocol = max(protocol_scores.items(), key=lambda x: x[1])
            
            # Apply minimum confidence threshold
            final_domain = best_domain[0] if best_domain[1] > 0.3 else Domain.UNKNOWN
            final_protocol = best_protocol[0] if best_protocol[1] > 0.5 else None
            
            # Determine subtype based on patterns
            subtype = self._determine_subtype(final_domain, matched_patterns)
            
            result = ClassificationResult(
                domain=final_domain,
                protocol=final_protocol if final_protocol != Protocol.UNKNOWN else None,
                confidence=best_domain[1],
                subtype=subtype,
                reasoning=reasoning,
                matched_patterns=matched_patterns
            )
            
            self.logger.info(f"Classified contract as {final_domain.value} with confidence {best_domain[1]:.2f}")
            if final_protocol:
                self.logger.info(f"Detected protocol: {final_protocol.value}")
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error classifying contract: {str(e)}")
            return ClassificationResult(
                domain=Domain.UNKNOWN,
                confidence=0.0,
                reasoning=[f"Classification error: {str(e)}"]
            )
    
    def classify_multiple_domains(self, parsed_contract: ParsedContract, threshold: float = 0.3) -> List[Tuple[Domain, float]]:
        """
        Classify multiple domains for a parsed contract.
        
        Args:
            parsed_contract: The parsed contract to classify
            threshold: Minimum confidence score to include a domain
            
        Returns:
            List of tuples containing (Domain, confidence_score) sorted by confidence
        """
        try:
            # Initialize scores for each domain
            domain_scores = {domain: 0.0 for domain in Domain}
            
            # Analyze all contracts in the file
            for contract in parsed_contract.contracts:
                contract_scores, _, _ = self._analyze_contract(contract)
                
                # Combine scores
                for domain, score in contract_scores['domains'].items():
                    domain_scores[domain] += score
            
            # Normalize scores
            total_contracts = len(parsed_contract.contracts)
            if total_contracts > 0:
                for domain in domain_scores:
                    domain_scores[domain] /= total_contracts
            
            # Filter domains above threshold and exclude UNKNOWN
            valid_domains = [
                (domain, score) for domain, score in domain_scores.items()
                if score >= threshold and domain != Domain.UNKNOWN
            ]
            
            # Sort by confidence score
            valid_domains.sort(key=lambda x: x[1], reverse=True)
            
            # If no domains meet threshold, return UNKNOWN
            if not valid_domains:
                return [(Domain.UNKNOWN, 0.0)]
            
            return valid_domains
            
        except Exception as e:
            self.logger.error(f"Error classifying multiple domains: {str(e)}")
            return [(Domain.UNKNOWN, 0.0)]

    def _analyze_contract(self, contract: Contract) -> Tuple[Dict, List[str], List[str]]:
        """Analyze a single contract for classification."""
        scores = {
            'domains': {domain: 0.0 for domain in Domain},
            'protocols': {protocol: 0.0 for protocol in Protocol}
        }
        reasoning = []
        matched_patterns = []
        
        # Analyze contract name
        contract_name_scores = self._analyze_contract_name(contract.name)
        for domain, score in contract_name_scores.items():
            scores['domains'][domain] += score * 0.3  # Weight: 30%
            if score > 0:
                reasoning.append(f"Contract name '{contract.name}' suggests {domain.value}")
                matched_patterns.append(f"contract_name:{contract.name}")
        
        # Analyze inheritance
        inheritance_scores = self._analyze_inheritance(contract.inherits)
        for domain, score in inheritance_scores.items():
            scores['domains'][domain] += score * 0.2  # Weight: 20%
            if score > 0:
                reasoning.append(f"Inheritance pattern suggests {domain.value}")
                matched_patterns.extend([f"inherits:{base}" for base in contract.inherits])
        
        # Analyze functions
        function_scores = self._analyze_functions(contract.functions)
        for domain, score in function_scores.items():
            scores['domains'][domain] += score * 0.4  # Weight: 40%
            if score > 0:
                reasoning.append(f"Function patterns suggest {domain.value}")
        
        # Analyze state variables
        variable_scores = self._analyze_state_variables(contract.state_variables)
        for domain, score in variable_scores.items():
            scores['domains'][domain] += score * 0.1  # Weight: 10%
        
        # Analyze protocol-specific patterns
        protocol_scores = self._analyze_protocol_patterns(contract)
        scores['protocols'].update(protocol_scores)
        
        return scores, reasoning, matched_patterns

    def _analyze_contract_name(self, name: str) -> Dict[Domain, float]:
        """Analyze contract name for domain classification."""
        scores = {domain: 0.0 for domain in Domain}
        name_lower = name.lower()
        
        # Check for domain keywords in contract name
        if 'defi' in name_lower:
            scores[Domain.DEFI] += 1.0
        if 'dao' in name_lower:
            scores[Domain.DAO] += 1.0
        if 'nft' in name_lower:
            scores[Domain.NFT] += 1.0
        if 'game' in name_lower or 'gamefi' in name_lower:
            scores[Domain.GAMEFI] += 1.0
        
        # Also check against pattern contract names
        for domain, patterns in self.domain_patterns.items():
            for contract_name in patterns['contract_names']:
                if contract_name.lower() in name_lower:
                    scores[domain] += 0.5
                    break
        
        return scores

    def _analyze_inheritance(self, inherits: List[str]) -> Dict[Domain, float]:
        """Analyze inheritance for domain classification."""
        scores = {domain: 0.0 for domain in Domain}
        
        for base_contract in inherits:
            base_lower = base_contract.lower()
            
            for domain, patterns in self.domain_patterns.items():
                for interface in patterns['interfaces']:
                    if interface.lower() in base_lower:
                        scores[domain] += 0.8
                
                for keyword in patterns['keywords']:
                    if keyword in base_lower:
                        scores[domain] += 0.5
        
        return scores

    def _analyze_functions(self, functions: List[Function]) -> Dict[Domain, float]:
        """Analyze function signatures for domain classification."""
        scores = {domain: 0.0 for domain in Domain}
        function_names = [func.name.lower() for func in functions]
        
        for domain, patterns in self.domain_patterns.items():
            matched_functions = 0
            for func_pattern in patterns['function_names']:
                if func_pattern.lower() in function_names:
                    matched_functions += 1
            
            # Score based on percentage of matched patterns
            if matched_functions > 0:
                scores[domain] = min(matched_functions / len(patterns['function_names']), 1.0)
        
        return scores

    def _analyze_state_variables(self, variables) -> Dict[Domain, float]:
        """Analyze state variables for domain classification."""
        scores = {domain: 0.0 for domain in Domain}
        
        variable_names = [var.name.lower() for var in variables]
        variable_types = [var.type.lower() for var in variables]
        all_variables = variable_names + variable_types
        
        for domain, patterns in self.domain_patterns.items():
            matched_keywords = 0
            for keyword in patterns['keywords']:
                if any(keyword in var for var in all_variables):
                    matched_keywords += 1
            
            if matched_keywords > 0:
                scores[domain] = min(matched_keywords / len(patterns['keywords']), 0.5)
        
        return scores

    def _analyze_protocol_patterns(self, contract: Contract) -> Dict[Protocol, float]:
        """Analyze contract for specific protocol patterns."""
        scores = {protocol: 0.0 for protocol in Protocol}
        
        # Get all contract elements for analysis
        contract_elements = {
            'name': contract.name.lower(),
            'functions': [func.name for func in contract.functions],
            'inherits': [base.lower() for base in contract.inherits],
            'all_text': ' '.join([
                contract.name.lower(),
                ' '.join([func.name for func in contract.functions]),
                ' '.join(contract.inherits).lower()
            ])
        }
        
        for protocol, patterns in self.protocol_patterns.items():
            score = 0.0
            
            # Check function signatures
            for signature in patterns.get('signatures', []):
                if signature in contract_elements['functions']:
                    score += 0.4
            
            # Check contract names
            for name_pattern in patterns.get('contract_names', []):
                if name_pattern.lower() in contract_elements['name']:
                    score += 0.3
            
            # Check keywords
            for keyword in patterns.get('keywords', []):
                if keyword in contract_elements['all_text']:
                    score += 0.1
            
            scores[protocol] = min(score, 1.0)
        
        return scores

    def _determine_subtype(self, domain: Domain, patterns: List[str]) -> Optional[str]:
        """Determine contract subtype based on domain and patterns."""
        subtype_mappings = {
            Domain.DEFI: {
                'amm': ['swap', 'liquidity', 'pair', 'router'],
                'lending': ['borrow', 'lend', 'deposit', 'withdraw'],
                'staking': ['stake', 'unstake', 'reward', 'yield'],
                'derivatives': ['option', 'future', 'synthetic'],
                'oracle': ['price', 'feed', 'oracle'],
                'flash_loan': ['flashloan', 'flash']
            },
            Domain.DAO: {
                'governance': ['govern', 'vote', 'propose'],
                'treasury': ['treasury', 'fund'],
                'multisig': ['multisig', 'safe', 'threshold'],
                'voting': ['vote', 'ballot', 'referendum']
            },
            Domain.NFT: {
                'marketplace': ['market', 'auction', 'trade'],
                'collection': ['mint', 'collection', 'token'],
                'gaming': ['game', 'character', 'item'],
                'art': ['art', 'creative', 'generative']
            },
            Domain.GAMEFI: {
                'battle': ['battle', 'fight', 'combat'],
                'breeding': ['breed', 'genetics', 'offspring'],
                'marketplace': ['market', 'trade', 'auction'],
                'rewards': ['reward', 'earn', 'income']
            }
        }
        
        if domain not in subtype_mappings:
            return None
        
        pattern_text = ' '.join(patterns).lower()
        
        for subtype, keywords in subtype_mappings[domain].items():
            if any(keyword in pattern_text for keyword in keywords):
                return subtype
        
        return None

    def get_applicable_agents(self, classification: ClassificationResult) -> List[str]:
        """
        Get list of applicable agent classes based on classification.
        
        Args:
            classification: The classification result
            
        Returns:
            List of agent class names to apply
        """
        agents = []
        
        # Universal agents (applied to all contracts)
        agents.extend([
            'universal_agent',
            'visibility_agent',
            'business_logic_agent',
            'code_quality_agent'
        ])
        
        # Domain-specific agents
        if classification.domain == Domain.DEFI:
            agents.extend([
                'amm_agent',
                'lending_agent', 
                'staking_agent',
                'oracle_agent',
                'flash_loan_agent'
            ])
            
            if classification.subtype == 'amm':
                agents.append('amm_agent')
            elif classification.subtype == 'lending':
                agents.append('lending_agent')
            elif classification.subtype == 'staking':
                agents.append('staking_agent')
                
        elif classification.domain == Domain.DAO:
            agents.extend([
                'governance_agent',
                'voting_agent',
                'treasury_agent',
                'multisig_agent'
            ])
            
        elif classification.domain == Domain.NFT:
            agents.extend([
                'erc721_agent',
                'erc1155_agent',
                'marketplace_agent',
                'royalty_agent',
                'metadata_agent',
                'minting_agent'
            ])
            
        elif classification.domain == Domain.GAMEFI:
            agents.extend([
                'token_economics_agent',
                'reward_system_agent',
                'nft_gaming_agent',
                'marketplace_gaming_agent'
            ])
        
        # Protocol-specific agents
        if classification.protocol:
            protocol_agents = {
                Protocol.UNISWAP_V2: ['uniswap_v2_agent'],
                Protocol.UNISWAP_V3: ['uniswap_v3_agent'],
                Protocol.AAVE_V2: ['aave_v2_agent'],
                Protocol.AAVE_V3: ['aave_v3_agent'],
                Protocol.COMPOUND: ['compound_agent'],
                Protocol.GNOSIS_SAFE: ['gnosis_safe_agent']
            }
            
            if classification.protocol in protocol_agents:
                agents.extend(protocol_agents[classification.protocol])
        
        return agents

    def get_applicable_checks(self, classification: ClassificationResult) -> List[str]:
        """
        Get list of applicable check modules based on classification.
        
        Args:
            classification: The classification result
            
        Returns:
            List of check module names to apply
        """
        checks = []
        
        # Base checks (applied to all contracts)
        checks.append('base_checks')
        
        # Domain-specific checks
        domain_check_mapping = {
            Domain.DEFI: [
                'amm_checks',
                'lending_checks', 
                'staking_checks',
                'yield_farming_checks',
                'derivatives_checks'
            ],
            Domain.DAO: [
                'governance_checks',
                'voting_checks',
                'treasury_checks',
                'proposal_checks'
            ],
            Domain.NFT: [
                'erc721_checks',
                'erc1155_checks',
                'marketplace_checks',
                'royalty_checks',
                'metadata_checks'
            ],
            Domain.GAMEFI: [
                'token_economics_checks',
                'reward_system_checks',
                'marketplace_checks',
                'nft_gaming_checks'
            ]
        }
        
        if classification.domain in domain_check_mapping:
            checks.extend(domain_check_mapping[classification.domain])
        
        # Protocol-specific checks
        protocol_check_mapping = {
            Protocol.UNISWAP_V2: ['uniswap_v2_checks'],
            Protocol.UNISWAP_V3: ['uniswap_v3_checks'],
            Protocol.AAVE_V2: ['aave_v2_checks'],
            Protocol.AAVE_V3: ['aave_v3_checks'],
            Protocol.COMPOUND: ['compound_checks'],
            Protocol.CURVE: ['curve_checks'],
            Protocol.GNOSIS_SAFE: ['gnosis_safe_checks']
        }
        
        if classification.protocol and classification.protocol in protocol_check_mapping:
            checks.extend(protocol_check_mapping[classification.protocol])
        
        return checks
