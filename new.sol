// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title DeFiDAOExample
/// @notice A minimal DeFi lending pool with DAO-style governance for parameter changes.

contract DeFiDAOExample {

    // ---- DeFi PART: Minimal lending pool logic ---- //
    mapping(address => uint256) public balances;
    uint256 public totalDeposits;
    uint256 public interestRate; // controlled by DAO proposals

    address public governance; // DAO's multisig or contract

    event Deposited(address indexed user, uint256 amount);
    event Withdrawn(address indexed user, uint256 amount);
    event InterestRateChanged(uint256 newRate);

    modifier onlyGovernance() {
        require(msg.sender == governance, "Only governance");
        _;
    }

    constructor(address _governance) {
        governance = _governance;
        interestRate = 5; // e.g., 5%
    }

    function deposit() external payable {
        require(msg.value > 0, "No Ether sent");
        balances[msg.sender] += msg.value;
        totalDeposits += msg.value;
        emit Deposited(msg.sender, msg.value);
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient");
        balances[msg.sender] -= amount;
        totalDeposits -= amount;
        (bool sent, ) = msg.sender.call{value: amount}("");
        require(sent, "Withdraw failed");
        emit Withdrawn(msg.sender, amount);
    }

    // --- Simulate simple interest accrued, omitted for brevity ---

    // ---- DAO PART: Proposal for interest rate ---- //

    struct Proposal {
        address proposer;
        uint256 newRate;
        uint256 votesFor;
        uint256 votesAgainst;
        uint256 deadline;
        bool executed;
    }

    uint256 public proposalCount;
    mapping(uint256 => Proposal) public proposals;
    mapping(address => uint256) public votingPower; // For simplicity, 1 address = 1 vote

    // Simulate governance voting power assignment
    function setVotingPower(address user, uint256 power) external onlyGovernance {
        votingPower[user] = power;
    }

    function proposeInterestRate(uint256 newRate) external returns (uint256) {
        require(votingPower[msg.sender] > 0, "No voting power");
        proposalCount++;
        proposals[proposalCount] = Proposal({
            proposer: msg.sender,
            newRate: newRate,
            votesFor: 0,
            votesAgainst: 0,
            deadline: block.timestamp + 2 days,
            executed: false
        });
        return proposalCount;
    }

    function vote(uint256 proposalId, bool support) external {
        Proposal storage prop = proposals[proposalId];
        require(block.timestamp < prop.deadline, "Proposal ended");
        require(votingPower[msg.sender] > 0, "No voting power");

        if (support) {
            prop.votesFor += votingPower[msg.sender];
        } else {
            prop.votesAgainst += votingPower[msg.sender];
        }
        // One address can vote many times for demo, normally you'd prevent double voting!
    }

    function executeProposal(uint256 proposalId) external onlyGovernance {
        Proposal storage prop = proposals[proposalId];
        require(!prop.executed, "Already executed");
        require(block.timestamp >= prop.deadline, "Voting not ended");
        require(prop.votesFor > prop.votesAgainst, "Not enough support");

        interestRate = prop.newRate;
        prop.executed = true;
        emit InterestRateChanged(prop.newRate);
    }

    receive() external payable {}
}
