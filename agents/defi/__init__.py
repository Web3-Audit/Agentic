"""
DeFi (Decentralized Finance) agents package.

This package contains specialized agents for analyzing DeFi smart contracts including
AMMs, lending protocols, staking mechanisms, yield farming, derivatives, flash loans,
and oracle integrations.
"""

from .defi_base_agent import DeFiBaseAgent
from .amm_agent import AMMAgent
from .lending_agent import LendingAgent
from .staking_agent import StakingAgent
from .yield_farming_agent import YieldFarmingAgent
from .derivatives_agent import DerivativesAgent
from .flash_loan_agent import FlashLoanAgent
from .oracle_agent import OracleAgent

# DeFi agent registry
DEFI_AGENTS = {
    'defi_base': DeFiBaseAgent,
    'amm': AMMAgent,
    'lending': LendingAgent,
    'staking': StakingAgent,
    'yield_farming': YieldFarmingAgent,
    'derivatives': DerivativesAgent,
    'flash_loan': FlashLoanAgent,
    'oracle': OracleAgent
}

# Protocol-specific agent mappings
PROTOCOL_AGENTS = {
    'uniswap': ['amm', 'oracle'],
    'sushiswap': ['amm', 'yield_farming'],
    'pancakeswap': ['amm', 'yield_farming', 'staking'],
    'curve': ['amm', 'staking'],
    'balancer': ['amm'],
    'aave': ['lending', 'flash_loan', 'oracle'],
    'compound': ['lending', 'oracle'],
    'makerdao': ['lending', 'oracle'],
    'yearn': ['yield_farming', 'staking'],
    'convex': ['yield_farming', 'staking'],
    'synthetix': ['derivatives', 'oracle', 'staking'],
    'dydx': ['derivatives', 'flash_loan'],
    'chainlink': ['oracle']
}

# DeFi patterns for contract detection
DEFI_PATTERNS = {
    'amm': [
        'swap', 'addLiquidity', 'removeLiquidity', 'pair', 'pool',
        'reserve', 'getAmountsOut', 'getAmountsIn'
    ],
    'lending': [
        'supply', 'borrow', 'repay', 'liquidate', 'collateral',
        'cToken', 'underlying', 'exchangeRate'
    ],
    'staking': [
        'stake', 'unstake', 'reward', 'withdraw', 'claim',
        'stakingToken', 'rewardToken', 'rewardRate'
    ],
    'yield_farming': [
        'deposit', 'withdraw', 'harvest', 'farm', 'vault',
        'strategy', 'yield', 'compound'
    ],
    'derivatives': [
        'option', 'future', 'perpetual', 'margin', 'leverage',
        'position', 'settlement', 'premium'
    ],
    'flash_loan': [
        'flashLoan', 'flashBorrow', 'executeOperation',
        'flashLoanFee', 'FLASHLOAN_PREMIUM'
    ],
    'oracle': [
        'oracle', 'price', 'aggregator', 'feed', 'roundData',
        'latestAnswer', 'getPrice', 'updatePrice'
    ]
}

def get_defi_agent(agent_name: str):
    """Get DeFi agent by name."""
    if agent_name not in DEFI_AGENTS:
        raise ValueError(f"DeFi agent '{agent_name}' not found")
    return DEFI_AGENTS[agent_name]

def get_agents_for_protocol(protocol: str) -> list:
    """Get agents suitable for a specific DeFi protocol."""
    if protocol.lower() not in PROTOCOL_AGENTS:
        return [DeFiBaseAgent]  # Return base agent if protocol not recognized
    
    agents = []
    for agent_name in PROTOCOL_AGENTS[protocol.lower()]:
        agents.append(DEFI_AGENTS[agent_name])
    
    return agents

def detect_defi_type(contract_code: str) -> list:
    """Detect DeFi types present in contract code."""
    detected_types = []
    code_lower = contract_code.lower()
    
    for defi_type, patterns in DEFI_PATTERNS.items():
        matches = sum(1 for pattern in patterns if pattern in code_lower)
        if matches >= 2:  # Require at least 2 pattern matches
            detected_types.append(defi_type)
    
    return detected_types

__all__ = [
    'DeFiBaseAgent',
    'AMMAgent', 
    'LendingAgent',
    'StakingAgent',
    'YieldFarmingAgent',
    'DerivativesAgent',
    'FlashLoanAgent',
    'OracleAgent',
    'DEFI_AGENTS',
    'PROTOCOL_AGENTS',
    'DEFI_PATTERNS',
    'get_defi_agent',
    'get_agents_for_protocol',
    'detect_defi_type'
]
