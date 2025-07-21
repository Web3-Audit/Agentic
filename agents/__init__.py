"""
Agents package for smart contract analysis.

This package contains all the specialized agents for analyzing different types of smart contracts.
Each agent focuses on specific domain expertise and security patterns.
"""

from .base_agent import BaseAgent
from .universal_agent import UniversalAgent

# Import common agents
from .common.business_logic_agent import BusinessLogicAgent
from .common.code_quality_agent import CodeQualityAgent
from .common.data_management_agent import DataManagementAgent
from .common.external_interactions_agent import ExternalInteractionsAgent
from .common.invariant_agent import InvariantAgent
from .common.timestamp_oracle_agent import TimestampOracleAgent
from .common.visibility_agent import VisibilityAgent

# Import domain-specific agents
from .defi.defi_base_agent import DeFiBaseAgent
from .defi.amm_agent import AMMAgent
from .defi.lending_agent import LendingAgent
from .defi.staking_agent import StakingAgent
from .defi.yield_farming_agent import YieldFarmingAgent
from .defi.derivatives_agent import DerivativesAgent
from .defi.flash_loan_agent import FlashLoanAgent
from .defi.oracle_agent import OracleAgent

from .dao.dao_base_agent import DAOBaseAgent
from .dao.governance_agent import GovernanceAgent
from .dao.voting_agent import VotingAgent
from .dao.treasury_agent import TreasuryAgent
from .dao.proposal_agent import ProposalAgent
from .dao.multisig_agent import MultisigAgent

from .nft.nft_base_agent import NFTBaseAgent
from .nft.erc721_agent import ERC721Agent
from .nft.erc1155_agent import ERC1155Agent
from .nft.marketplace_agent import MarketplaceAgent
from .nft.royalty_agent import RoyaltyAgent
from .nft.metadata_agent import MetadataAgent
from .nft.minting_agent import MintingAgent

from .gamefi.gamefi_base_agent import GameFiBaseAgent
from .gamefi.token_economics_agent import TokenEconomicsAgent
from .gamefi.reward_system_agent import RewardSystemAgent
from .gamefi.nft_gaming_agent import NFTGamingAgent
from .gamefi.marketplace_gaming_agent import MarketplaceGamingAgent

# Agent registry for dynamic loading
AGENT_REGISTRY = {
    # Universal agents (always loaded)
    'universal': UniversalAgent,
    
    # Common agents
    'business_logic': BusinessLogicAgent,
    'code_quality': CodeQualityAgent,
    'data_management': DataManagementAgent,
    'external_interactions': ExternalInteractionsAgent,
    'invariant': InvariantAgent,
    'timestamp_oracle': TimestampOracleAgent,
    'visibility': VisibilityAgent,
    
    # DeFi agents
    'defi_base': DeFiBaseAgent,
    'amm': AMMAgent,
    'lending': LendingAgent,
    'staking': StakingAgent,
    'yield_farming': YieldFarmingAgent,
    'derivatives': DerivativesAgent,
    'flash_loan': FlashLoanAgent,
    'oracle': OracleAgent,
    
    # DAO agents
    'dao_base': DAOBaseAgent,
    'governance': GovernanceAgent,
    'voting': VotingAgent,
    'treasury': TreasuryAgent,
    'proposal': ProposalAgent,
    'multisig': MultisigAgent,
    
    # NFT agents
    'nft_base': NFTBaseAgent,
    'erc721': ERC721Agent,
    'erc1155': ERC1155Agent,
    'marketplace': MarketplaceAgent,
    'royalty': RoyaltyAgent,
    'metadata': MetadataAgent,
    'minting': MintingAgent,
    
    # GameFi agents
    'gamefi_base': GameFiBaseAgent,
    'token_economics': TokenEconomicsAgent,
    'reward_system': RewardSystemAgent,
    'nft_gaming': NFTGamingAgent,
    'marketplace_gaming': MarketplaceGamingAgent,
}

# Domain to agent mapping
DOMAIN_AGENT_MAPPING = {
    'defi': [
        'defi_base', 'amm', 'lending', 'staking', 'yield_farming',
        'derivatives', 'flash_loan', 'oracle'
    ],
    'dao': [
        'dao_base', 'governance', 'voting', 'treasury', 'proposal', 'multisig'
    ],
    'nft': [
        'nft_base', 'erc721', 'erc1155', 'marketplace', 'royalty', 'metadata', 'minting'
    ],
    'gamefi': [
        'gamefi_base', 'token_economics', 'reward_system', 'nft_gaming', 'marketplace_gaming'
    ],
    'generic': [
        'business_logic', 'code_quality', 'data_management', 
        'external_interactions', 'invariant', 'timestamp_oracle', 'visibility'
    ]
}

def get_agent(agent_name: str) -> type:
    """
    Get agent class by name.
    
    Args:
        agent_name: Name of the agent
        
    Returns:
        Agent class
        
    Raises:
        ValueError: If agent not found
    """
    if agent_name not in AGENT_REGISTRY:
        raise ValueError(f"Agent '{agent_name}' not found in registry")
    
    return AGENT_REGISTRY[agent_name]

def get_agents_for_domain(domain: str) -> list:
    """
    Get all agents for a specific domain.
    
    Args:
        domain: Domain name (defi, dao, nft, gamefi, generic)
        
    Returns:
        List of agent classes
    """
    if domain not in DOMAIN_AGENT_MAPPING:
        return []
    
    agents = []
    for agent_name in DOMAIN_AGENT_MAPPING[domain]:
        try:
            agents.append(get_agent(agent_name))
        except ValueError:
            continue  # Skip agents that aren't available
    
    return agents

def get_all_agents():
    """Get all available agents."""
    return list(AGENT_REGISTRY.values())

__all__ = [
    'BaseAgent',
    'UniversalAgent',
    
    # Common agents
    'BusinessLogicAgent',
    'CodeQualityAgent',
    'DataManagementAgent',
    'ExternalInteractionsAgent',
    'InvariantAgent',
    'TimestampOracleAgent',
    'VisibilityAgent',
    
    # DeFi agents
    'DeFiBaseAgent',
    'AMMAgent',
    'LendingAgent',
    'StakingAgent',
    'YieldFarmingAgent',
    'DerivativesAgent',
    'FlashLoanAgent',
    'OracleAgent',
    
    # DAO agents
    'DAOBaseAgent',
    'GovernanceAgent',
    'VotingAgent',
    'TreasuryAgent',
    'ProposalAgent',
    'MultisigAgent',
    
    # NFT agents
    'NFTBaseAgent',
    'ERC721Agent',
    'ERC1155Agent',
    'MarketplaceAgent',
    'RoyaltyAgent',
    'MetadataAgent',
    'MintingAgent',
    
    # GameFi agents
    'GameFiBaseAgent',
    'TokenEconomicsAgent',
    'RewardSystemAgent',
    'NFTGamingAgent',
    'MarketplaceGamingAgent',
    
    # Helper functions
    'get_agent',
    'get_agents_for_domain',
    'get_all_agents',
    'AGENT_REGISTRY',
    'DOMAIN_AGENT_MAPPING'
]
