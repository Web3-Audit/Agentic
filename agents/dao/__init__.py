"""
DAO agents package for smart contract analysis.

This package contains specialized agents for analyzing DAO (Decentralized Autonomous Organization)
smart contracts including governance, voting, treasury, and proposal mechanisms.
"""

from .dao_base_agent import DAOBaseAgent
from .governance_agent import GovernanceAgent
from .voting_agent import VotingAgent
from .treasury_agent import TreasuryAgent
from .proposal_agent import ProposalAgent
from .multisig_agent import MultisigAgent

__all__ = [
    'DAOBaseAgent',
    'GovernanceAgent',
    'VotingAgent',
    'TreasuryAgent',
    'ProposalAgent',
    'MultisigAgent'
]

# Version info
__version__ = "1.0.0"

# DAO-specific configuration
DAO_AGENT_CONFIG = {
    'check_governance_attacks': True,
    'validate_voting_mechanisms': True,
    'analyze_treasury_security': True,
    'check_proposal_validation': True,
    'verify_multisig_security': True,
    'min_quorum_threshold': 0.1,  # 10%
    'max_voting_period': 86400 * 7,  # 7 days in seconds
    'min_timelock_delay': 86400,  # 24 hours
}
