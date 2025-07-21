"""
Staking agent for analyzing DeFi staking and rewards mechanisms.
"""

import re
import logging
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass

from .defi_base_agent import DeFiBaseAgent, DeFiProtocol, DeFiMetrics
from ...models.context import AnalysisContext, FunctionContext
from ...models.finding import Finding, Severity, Category, CodeLocation
from ...llm.client import LLMClient
from ...llm.prompts import PromptManager

logger = logging.getLogger(__name__)


@dataclass
class StakingMetrics(DeFiMetrics):
    """Staking-specific metrics extending DeFi metrics."""
    stake_functions: int = 0
    unstake_functions: int = 0
    reward_functions: int = 0
    claim_functions: int = 0
    penalty_functions: int = 0
    lock_period_checks: int = 0
    reward_calculations: int = 0
    slash_mechanisms: int = 0


class StakingAgent(DeFiBaseAgent):
    """
    Specialized agent for analyzing staking protocol contracts.
    Focuses on staking mechanics, reward distribution, and penalties.
    """
    
    def __init__(self, llm_client: Optional[LLMClient] = None,
                 prompt_manager: Optional[PromptManager] = None):
        super().__init__("StakingAgent", llm_client, prompt_manager)
        
        # Staking-specific patterns
        self.staking_patterns = {
            'stake_functions': [
                'stake', 'deposit', 'lock', 'bond', 'delegate'
            ],
            'unstake_functions': [
                'unstake', 'withdraw', 'unlock', 'unbond', 'undelegate'
            ],
            'reward_functions': [
                'reward', 'earn', 'yield', 'distribute', 'accrue'
            ],
            'claim_functions': [
                'claim', 'harvest', 'collect', 'withdraw.*reward'
            ],
            'penalty_patterns': [
                'slash', 'penalty', 'forfeit', 'burn', 'fine'
            ],
            'time_patterns': [
                'lockPeriod', 'stakingPeriod', 'cooldown', 'vestingPeriod',
                'timelock', 'duration', 'epoch'
            ],
            'validator_patterns': [
                'validator', 'node', 'operator', 'delegate', 'nominee'
            ]
        }
    
    def can_analyze(self, context: AnalysisContext) -> bool:
        """Check if this is a staking protocol contract."""
        if not super().can_analyze(context):
            return False
        
        code_lower = context.contract_code.lower()
        
        staking_indicators = [
            'stake', 'reward', 'claim', 'harvest', 'delegate',
            'validator', 'slash', 'penalty', 'lock'
        ]
        
        matches = sum(1 for indicator in staking_indicators if indicator in code_lower)
        return matches >= 3
    
    def analyze(self, context: AnalysisContext) -> List[Finding]:
        """
        Analyze staking contract for security vulnerabilities.
        
        Args:
            context: Analysis context
            
        Returns:
            List[Finding]: Staking-specific findings
        """
        self.logger.info("Starting staking protocol analysis")
        findings = []
        
        try:
            # Calculate staking metrics
            metrics = self._calculate_staking_metrics(context)
            
            # Core staking security checks
            findings.extend(self._check_staking_security(context))
            findings.extend(self._check_unstaking_security(context))
            findings.extend(self._check_reward_distribution(context))
            findings.extend(self._check_claim_security(context))
            findings.extend(self._check_penalty_mechanisms(context))
            findings.extend(self._check_time_lock_security(context))
            findings.extend(self._check_validator_security(context))
            findings.extend(self._check_reward_calculation_accuracy(context))
            findings.extend(self._check_slashing_mechanisms(context))
            findings.extend(self._check_delegation_security(context))
            
            self.logger.info(f"Staking analysis completed with {len(findings)} findings")
            return findings
            
        except Exception as e:
            self.logger.error(f"Error in staking analysis: {str(e)}")
            return findings
    
    def _calculate_staking_metrics(self, context: AnalysisContext) -> StakingMetrics:
        """Calculate staking-specific metrics."""
        metrics = StakingMetrics()
        
        for functions in context.functions.values():
            for func in functions:
                func_name_lower = func.name.lower()
                
                # Count different function types
                if any(pattern.lower() in func_name_lower 
                      for pattern in self.staking_patterns['stake_functions']):
                    metrics.stake_functions += 1
                
                if any(pattern.lower() in func_name_lower 
                      for pattern in self.staking_patterns['unstake_functions']):
                    metrics.unstake_functions += 1
                
                if any(pattern.lower() in func_name_lower 
                      for pattern in self.staking_patterns['reward_functions']):
                    metrics.reward_functions += 1
                
                if any(pattern.lower() in func_name_lower 
                      for pattern in self.staking_patterns['claim_functions']):
                    metrics.claim_functions += 1
                
                # Check for time-based mechanics
                if any(pattern in func.body.lower() 
                      for pattern in self.staking_patterns['time_patterns']):
                    metrics.lock_period_checks += 1
                
                # Check for penalty mechanisms
                if any(pattern in func.body.lower() 
                      for pattern in self.staking_patterns['penalty_patterns']):
                    metrics.penalty_functions += 1
        
        return metrics
    
    def _check_staking_security(self, context: AnalysisContext) -> List[Finding]:
        """Check staking function security."""
        findings = []
        
        for contract_name, functions in context.functions.items():
            for func in functions:
                if self._is_stake_function(func):
                    
                    # Check for minimum stake amount
                    if not self._validates_minimum_stake(func):
                        finding = self.create_finding(
                            title=f"Missing Minimum Stake Validation in {func.name}",
                            description=f"Stake function '{func.name}' doesn't validate minimum stake amount",
                            severity=Severity.LOW,
                            category=Category.INPUT_VALIDATION,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Add minimum stake amount validation",
                            impact="Dust staking could affect reward calculations"
                        )
                        findings.append(finding)
                    
                    # Check for stake cap validation
                    if not self._validates_stake_cap(func):
                        finding = self.create_finding(
                            title=f"Missing Stake Cap Validation in {func.name}",
                            description=f"Stake function '{func.name}' doesn't check maximum stake limits",
                            severity=Severity.MEDIUM,
                            category=Category.DEFI_SPECIFIC,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Implement maximum stake limits to prevent centralization",
                            impact="Excessive staking could lead to centralization risks"
                        )
                        findings.append(finding)
                    
                    # Check for lock period validation
                    if self._has_lock_period(func) and not self._validates_lock_period(func):
                        finding = self.create_finding(
                            title=f"Missing Lock Period Validation in {func.name}",
                            description=f"Stake function '{func.name}' doesn't properly validate lock periods",
                            severity=Severity.MEDIUM,
                            category=Category.INPUT_VALIDATION,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Validate lock period parameters within acceptable bounds",
                            impact="Invalid lock periods could affect reward calculations"
                        )
                        findings.append(finding)
                    
                    # Check for reward rate updates
                    if not self._updates_reward_tracking(func):
                        finding = self.create_finding(
                            title=f"Missing Reward Tracking Update in {func.name}",
                            description=f"Stake function '{func.name}' doesn't update reward tracking",
                            severity=Severity.MEDIUM,
                            category=Category.DEFI_SPECIFIC,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Update reward tracking when staking occurs",
                            impact="Inaccurate reward calculations for stakers"
                        )
                        findings.append(finding)
        
        return findings
    
    def _check_unstaking_security(self, context: AnalysisContext) -> List[Finding]:
        """Check unstaking function security."""
        findings = []
        
        for contract_name, functions in context.functions.items():
            for func in functions:
                if self._is_unstake_function(func):
                    
                    # Check for cooldown period validation
                    if not self._validates_cooldown_period(func):
                        finding = self.create_finding(
                            title=f"Missing Cooldown Period Validation in {func.name}",
                            description=f"Unstake function '{func.name}' doesn't validate cooldown periods",
                            severity=Severity.MEDIUM,
                            category=Category.DEFI_SPECIFIC,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Validate cooldown period before allowing unstaking",
                            impact="Premature unstaking could disrupt protocol mechanics"
                        )
                        findings.append(finding)
                    
                    # Check for penalty calculation
                    if self._applies_penalties(func) and not self._calculates_penalties_correctly(func):
                        finding = self.create_finding(
                            title=f"Incorrect Penalty Calculation in {func.name}",
                            description=f"Unstake function '{func.name}' may calculate penalties incorrectly",
                            severity=Severity.HIGH,
                            category=Category.ARITHMETIC,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Ensure penalty calculations are accurate and fair",
                            impact="Incorrect penalties could harm stakers unfairly"
                        )
                        findings.append(finding)
                    
                    # Check for stake amount validation
                    if not self._validates_unstake_amount(func):
                        finding = self.create_finding(
                            title=f"Missing Unstake Amount Validation in {func.name}",
                            description=f"Unstake function '{func.name}' doesn't validate unstake amounts",
                            severity=Severity.MEDIUM,
                            category=Category.INPUT_VALIDATION,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Validate unstake amount doesn't exceed staked balance",
                            impact="Over-unstaking could cause accounting errors"
                        )
                        findings.append(finding)
        
        return findings
    
    def _check_reward_distribution(self, context: AnalysisContext) -> List[Finding]:
        """Check reward distribution mechanisms."""
        findings = []
        
        for contract_name, functions in context.functions.items():
            for func in functions:
                if self._distributes_rewards(func):
                    
                    # Check for reward pool validation
                    if not self._validates_reward_pool(func):
                        finding = self.create_finding(
                            title=f"Missing Reward Pool Validation in {func.name}",
                            description=f"Reward function '{func.name}' doesn't validate reward pool sufficiency",
                            severity=Severity.HIGH,
                            category=Category.DEFI_SPECIFIC,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Validate sufficient rewards exist before distribution",
                            impact="Reward distribution could fail or drain unexpected funds"
                        )
                        findings.append(finding)
                    
                    # Check for fair reward distribution
                    if not self._ensures_fair_distribution(func):
                        finding = self.create_finding(
                            title=f"Unfair Reward Distribution in {func.name}",
                            description=f"Reward distribution in '{func.name}' may not be fair or proportional",
                            severity=Severity.MEDIUM,
                            category=Category.DEFI_SPECIFIC,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Ensure rewards are distributed proportionally to stakes",
                            impact="Unfair distribution could favor certain stakers"
                        )
                        findings.append(finding)
        
        return findings
    
    def _check_claim_security(self, context: AnalysisContext) -> List[Finding]:
        """Check reward claiming security."""
        findings = []
        
        for contract_name, functions in context.functions.items():
            for func in functions:
                if self._is_claim_function(func):
                    
                    # Check for double claiming protection
                    if not self._prevents_double_claiming(func):
                        finding = self.create_finding(
                            title=f"Double Claiming Risk in {func.name}",
                            description=f"Claim function '{func.name}' vulnerable to double claiming",
                            severity=Severity.HIGH,
                            category=Category.DEFI_SPECIFIC,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Implement double claiming prevention mechanisms",
                            impact="Users could claim rewards multiple times"
                        )
                        findings.append(finding)
                    
                    # Check for claim amount validation
                    if not self._validates_claim_amount(func):
                        finding = self.create_finding(
                            title=f"Missing Claim Amount Validation in {func.name}",
                            description=f"Claim function '{func.name}' doesn't validate claim amounts",
                            severity=Severity.MEDIUM,
                            category=Category.INPUT_VALIDATION,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Validate claim amounts against earned rewards",
                            impact="Over-claiming could drain reward pools"
                        )
                        findings.append(finding)
        
        return findings
    
    def _check_penalty_mechanisms(self, context: AnalysisContext) -> List[Finding]:
        """Check penalty and slashing mechanisms."""
        findings = []
        
        for contract_name, functions in context.functions.items():
            for func in functions:
                if self._applies_penalties(func):
                    
                    # Check for penalty bounds
                    if not self._validates_penalty_bounds(func):
                        finding = self.create_finding(
                            title=f"Missing Penalty Bounds in {func.name}",
                            description=f"Penalty function '{func.name}' doesn't validate penalty bounds",
                            severity=Severity.HIGH,
                            category=Category.DEFI_SPECIFIC,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Implement maximum penalty limits to prevent excessive penalties",
                            impact="Excessive penalties could harm stakers unfairly"
                        )
                        findings.append(finding)
                    
                    # Check for penalty justification
                    if not self._validates_penalty_conditions(func):
                        finding = self.create_finding(
                            title=f"Missing Penalty Condition Validation in {func.name}",
                            description=f"Penalty function '{func.name}' doesn't validate penalty conditions",
                            severity=Severity.MEDIUM,
                            category=Category.ACCESS_CONTROL,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Validate conditions that justify penalty application",
                            impact="Unjustified penalties could be applied to stakers"
                        )
                        findings.append(finding)
        
        return findings
    
    def _check_time_lock_security(self, context: AnalysisContext) -> List[Finding]:
        """Check time lock mechanisms."""
        findings = []
        
        for contract_name, functions in context.functions.items():
            for func in functions:
                if self._uses_time_locks(func):
                    
                    # Check for time manipulation resistance
                    if not self._resistant_to_time_manipulation(func):
                        finding = self.create_finding(
                            title=f"Time Manipulation Risk in {func.name}",
                            description=f"Time lock function '{func.name}' may be vulnerable to time manipulation",
                            severity=Severity.MEDIUM,
                            category=Category.TIMESTAMP_DEPENDENCY,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Use block numbers instead of timestamps or implement additional safeguards",
                            impact="Miners could manipulate timestamps to bypass time locks"
                        )
                        findings.append(finding)
        
        return findings
    
    def _check_validator_security(self, context: AnalysisContext) -> List[Finding]:
        """Check validator-related security."""
        findings = []
        
        for contract_name, functions in context.functions.items():
            for func in functions:
                if self._manages_validators(func):
                    
                    # Check for validator registration validation
                    if not self._validates_validator_registration(func):
                        finding = self.create_finding(
                            title=f"Missing Validator Registration Validation in {func.name}",
                            description=f"Validator function '{func.name}' doesn't properly validate registration",
                            severity=Severity.MEDIUM,
                            category=Category.ACCESS_CONTROL,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Implement proper validator registration validation",
                            impact="Invalid validators could participate in consensus"
                        )
                        findings.append(finding)
        
        return findings
    
    def _check_reward_calculation_accuracy(self, context: AnalysisContext) -> List[Finding]:
        """Check reward calculation accuracy."""
        findings = []
        
        for contract_name, functions in context.functions.items():
            for func in functions:
                if self._calculates_rewards(func):
                    
                    # Check for precision in reward calculations
                    if not self._uses_precise_reward_calculation(func):
                        finding = self.create_finding(
                            title=f"Reward Calculation Precision Issues in {func.name}",
                            description=f"Reward calculation in '{func.name}' may have precision issues",
                            severity=Severity.MEDIUM,
                            category=Category.ARITHMETIC,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Use high precision arithmetic for reward calculations",
                            impact="Precision errors could lead to incorrect reward distributions"
                        )
                        findings.append(finding)
                    
                    # Check for reward calculation overflow
                    if not self._protects_reward_overflow(func):
                        finding = self.create_finding(
                            title=f"Reward Calculation Overflow Risk in {func.name}",
                            description=f"Reward calculation in '{func.name}' may overflow",
                            severity=Severity.HIGH,
                            category=Category.ARITHMETIC,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Use safe math libraries to prevent overflow",
                            impact="Overflow could result in incorrect or no rewards"
                        )
                        findings.append(finding)
        
        return findings
    
    def _check_slashing_mechanisms(self, context: AnalysisContext) -> List[Finding]:
        """Check slashing mechanism security."""
        findings = []
        
        for contract_name, functions in context.functions.items():
            for func in functions:
                if self._implements_slashing(func):
                    
                    # Check for slashing protection
                    if not self._has_slashing_protection(func):
                        finding = self.create_finding(
                            title=f"Missing Slashing Protection in {func.name}",
                            description=f"Slashing function '{func.name}' lacks adequate protection mechanisms",
                            severity=Severity.HIGH,
                            category=Category.ACCESS_CONTROL,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Implement proper access controls and validation for slashing",
                            impact="Unauthorized or excessive slashing could harm validators"
                        )
                        findings.append(finding)
        
        return findings
    
    def _check_delegation_security(self, context: AnalysisContext) -> List[Finding]:
        """Check delegation mechanism security."""
        findings = []
        
        for contract_name, functions in context.functions.items():
            for func in functions:
                if self._handles_delegation(func):
                    
                    # Check for delegation validation
                    if not self._validates_delegation(func):
                        finding = self.create_finding(
                            title=f"Missing Delegation Validation in {func.name}",
                            description=f"Delegation function '{func.name}' doesn't properly validate delegation",
                            severity=Severity.MEDIUM,
                            category=Category.INPUT_VALIDATION,
                            location=CodeLocation(
                                contract_name=contract_name,
                                function_name=func.name,
                                line_number=func.line_number
                            ),
                            affected_contracts=[contract_name],
                            affected_functions=[func.name],
                            recommendation="Validate delegation parameters and conditions",
                            impact="Invalid delegations could disrupt staking mechanics"
                        )
                        findings.append(finding)
        
        return findings
    
    # Helper methods for staking pattern detection
    
    def _is_stake_function(self, func: FunctionContext) -> bool:
        """Check if function is a stake function."""
        return any(pattern.lower() in func.name.lower() 
                  for pattern in self.staking_patterns['stake_functions'])
    
    def _is_unstake_function(self, func: FunctionContext) -> bool:
        """Check if function is an unstake function."""
        return any(pattern.lower() in func.name.lower() 
                  for pattern in self.staking_patterns['unstake_functions'])
    
    def _is_claim_function(self, func: FunctionContext) -> bool:
        """Check if function is a claim function."""
        return any(re.search(pattern, func.name, re.IGNORECASE) 
                  for pattern in self.staking_patterns['claim_functions'])
    
    def _distributes_rewards(self, func: FunctionContext) -> bool:
        """Check if function distributes rewards."""
        return any(pattern.lower() in func.name.lower() 
                  for pattern in self.staking_patterns['reward_functions'])
    
    def _validates_minimum_stake(self, func: FunctionContext) -> bool:
        """Check if function validates minimum stake amounts."""
        validation_patterns = [
            r'require\s*\(\s*.*amount.*>\s*0',
            r'require\s*\(\s*.*amount.*>=.*MIN',
            r'minStake',
            r'minimumStake'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) 
                  for pattern in validation_patterns)
    
    def _validates_stake_cap(self, func: FunctionContext) -> bool:
        """Check if function validates stake caps."""
        cap_patterns = [
            r'maxStake',
            r'stakeCap',
            r'require\s*\(\s*.*totalStaked.*<',
            r'stake.*limit'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) 
                  for pattern in cap_patterns)
    
    def _has_lock_period(self, func: FunctionContext) -> bool:
        """Check if function uses lock periods."""
        return any(pattern in func.body.lower() 
                  for pattern in self.staking_patterns['time_patterns'])
    
    def _validates_lock_period(self, func: FunctionContext) -> bool:
        """Check if function validates lock periods."""
        validation_patterns = [
            r'require\s*\(\s*.*lockPeriod.*>',
            r'require\s*\(\s*.*duration.*>=',
            r'minLockPeriod',
            r'maxLockPeriod'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) 
                  for pattern in validation_patterns)
    
    def _updates_reward_tracking(self, func: FunctionContext) -> bool:
        """Check if function updates reward tracking."""
        tracking_patterns = [
            'updateReward',
            'accruedRewards',
            'rewardIndex',
            'lastUpdate'
        ]
        return any(pattern.lower() in func.body.lower() for pattern in tracking_patterns)
    
    def _validates_cooldown_period(self, func: FunctionContext) -> bool:
        """Check if function validates cooldown periods."""
        cooldown_patterns = [
            r'require\s*\(\s*.*cooldown.*<.*block\.timestamp',
            r'require\s*\(\s*.*lastStake.*\+.*period.*<',
            r'cooldownPeriod',
            r'unstakeDelay'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) 
                  for pattern in cooldown_patterns)
    
    def _applies_penalties(self, func: FunctionContext) -> bool:
        """Check if function applies penalties."""
        return any(pattern in func.body.lower() 
                  for pattern in self.staking_patterns['penalty_patterns'])
    
    def _calculates_penalties_correctly(self, func: FunctionContext) -> bool:
        """Check if penalties are calculated correctly."""
        calculation_patterns = [
            r'penalty.*=.*stake.*\*.*rate',
            r'penaltyAmount',
            r'calculatePenalty',
            r'penaltyRate'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) 
                  for pattern in calculation_patterns)
    
    def _validates_unstake_amount(self, func: FunctionContext) -> bool:
        """Check if unstake amount is validated."""
        validation_patterns = [
            r'require\s*\(\s*.*amount.*<=.*stakedBalance',
            r'require\s*\(\s*.*amount.*<=.*staked',
            r'stakedAmount',
            r'stakingBalance'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) 
                  for pattern in validation_patterns)
    
    def _validates_reward_pool(self, func: FunctionContext) -> bool:
        """Check if reward pool is validated."""
        validation_patterns = [
            r'require\s*\(\s*.*rewardPool.*>=',
            r'require\s*\(\s*.*rewardBalance.*>=',
            r'availableRewards',
            r'rewardBalance'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) 
                  for pattern in validation_patterns)
    
    def _ensures_fair_distribution(self, func: FunctionContext) -> bool:
        """Check if reward distribution is fair."""
        fairness_patterns = [
            r'reward.*proportional',
            r'stake.*ratio',
            r'weight',
            r'share'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) 
                  for pattern in fairness_patterns)
    
    def _prevents_double_claiming(self, func: FunctionContext) -> bool:
        """Check if double claiming is prevented."""
        prevention_patterns = [
            r'claimed\s*\[\s*.*\]\s*=\s*true',
            r'lastClaim',
            r'require\s*\(\s*!.*claimed',
            r'alreadyClaimed'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) 
                  for pattern in prevention_patterns)
    
    def _validates_claim_amount(self, func: FunctionContext) -> bool:
        """Check if claim amount is validated."""
        validation_patterns = [
            r'require\s*\(\s*.*claimAmount.*<=.*earned',
            r'require\s*\(\s*.*amount.*<=.*pending',
            r'earnedRewards',
            r'pendingRewards'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) 
                  for pattern in validation_patterns)
    
    def _validates_penalty_bounds(self, func: FunctionContext) -> bool:
        """Check if penalty bounds are validated."""
        bounds_patterns = [
            r'require\s*\(\s*.*penalty.*<=.*MAX',
            r'require\s*\(\s*.*penalty.*<.*stake',
            r'maxPenalty',
            r'penaltyLimit'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) 
                  for pattern in bounds_patterns)
    
    def _validates_penalty_conditions(self, func: FunctionContext) -> bool:
        """Check if penalty conditions are validated."""
        condition_patterns = [
            r'require\s*\(\s*.*violation',
            r'require\s*\(\s*.*misbehavior',
            r'slashingCondition',
            r'penaltyReason'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) 
                  for pattern in condition_patterns)
    
    def _uses_time_locks(self, func: FunctionContext) -> bool:
        """Check if function uses time locks."""
        return any(pattern in func.body.lower() 
                  for pattern in self.staking_patterns['time_patterns'])
    
    def _resistant_to_time_manipulation(self, func: FunctionContext) -> bool:
        """Check if time locks are resistant to manipulation."""
        resistance_patterns = [
            r'block\.number',
            r'blockNumber',
            r'require\s*\(\s*block\.timestamp.*>.*lastUpdate.*\+.*MIN_DELAY'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) 
                  for pattern in resistance_patterns)
    
    def _manages_validators(self, func: FunctionContext) -> bool:
        """Check if function manages validators."""
        return any(pattern in func.body.lower() 
                  for pattern in self.staking_patterns['validator_patterns'])
    
    def _validates_validator_registration(self, func: FunctionContext) -> bool:
        """Check if validator registration is validated."""
        validation_patterns = [
            r'require\s*\(\s*.*validator.*!=.*address\(0\)',
            r'require\s*\(\s*!.*isValidator',
            r'validatorRequirement',
            r'registerValidator'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) 
                  for pattern in validation_patterns)
    
    def _calculates_rewards(self, func: FunctionContext) -> bool:
        """Check if function calculates rewards."""
        calculation_patterns = [
            'calculateReward',
            'rewardAmount',
            'earnedReward',
            'rewardCalculation'
        ]
        return any(pattern.lower() in func.body.lower() for pattern in calculation_patterns)
    
    def _uses_precise_reward_calculation(self, func: FunctionContext) -> bool:
        """Check if reward calculation uses high precision."""
        precision_patterns = [
            r'1e18',
            r'PRECISION',
            r'WAD',
            r'RAY'
        ]
        return any(re.search(pattern, func.body) for pattern in precision_patterns)
    
    def _protects_reward_overflow(self, func: FunctionContext) -> bool:
        """Check if reward calculation protects against overflow."""
        protection_patterns = [
            'SafeMath',
            'safeAdd',
            'safeMul',
            'safeDiv'
        ]
        return any(pattern.lower() in func.body.lower() for pattern in protection_patterns)
    
    def _implements_slashing(self, func: FunctionContext) -> bool:
        """Check if function implements slashing."""
        slashing_patterns = ['slash', 'slashing', 'penalize', 'cut']
        return any(pattern.lower() in func.name.lower() or pattern.lower() in func.body.lower() 
                  for pattern in slashing_patterns)
    
    def _has_slashing_protection(self, func: FunctionContext) -> bool:
        """Check if slashing has adequate protection."""
        protection_patterns = [
            r'require\s*\(\s*.*authorized',
            r'onlySlasher',
            r'slashingCommittee',
            r'governance'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) 
                  for pattern in protection_patterns)
    
    def _handles_delegation(self, func: FunctionContext) -> bool:
        """Check if function handles delegation."""
        delegation_patterns = ['delegate', 'delegation', 'delegated', 'delegator']
        return any(pattern.lower() in func.name.lower() or pattern.lower() in func.body.lower() 
                  for pattern in delegation_patterns)
    
    def _validates_delegation(self, func: FunctionContext) -> bool:
        """Check if delegation is properly validated."""
        validation_patterns = [
            r'require\s*\(\s*.*delegatee.*!=.*address\(0\)',
            r'require\s*\(\s*.*amount.*>.*0',
            r'validDelegatee',
            r'delegationLimit'
        ]
        return any(re.search(pattern, func.body, re.IGNORECASE) 
                  for pattern in validation_patterns)
