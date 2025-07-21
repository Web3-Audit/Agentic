// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC721/extensions/ERC721URIStorage.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/Counters.sol";

/// @title GameFiBattle - Token + NFT + staking + game logic
contract GameFiBattle is Ownable, ERC721URIStorage {
    using Counters for Counters.Counter;
    Counters.Counter private _tokenIds;

    // ERC20 game token
    IERC20 public immutable gameToken;

    // Constants
    uint256 public constant MIN_STAKE_AMOUNT = 100 ether;
    uint256 public constant STAKING_DURATION = 7 days;
    uint256 public constant REWARD_RATE = 15; // 15%

    // Role management
    mapping(address => bool) public isOperator;

    // NFT staked, user => list of tokens
    mapping(address => uint256[]) public stakedItems;

    // NFT metadata
    struct Item {
        uint8 level;
        uint256 power;
        uint256 cooldownUntil;
    }
    mapping(uint256 => Item) public itemAttributes;

    // Token staking data
    struct Stake {
        uint256 amount;
        uint256 startTime;
        bool claimed;
    }
    mapping(address => Stake) public stakes;

    // Events
    event ItemMinted(address indexed user, uint256 tokenId, uint256 power);
    event Upgraded(address user, uint256 tokenId, uint8 newLevel);
    event TokensStaked(address indexed user, uint256 amount);
    event RewardsClaimed(address indexed user, uint256 reward);

    constructor(address _erc20Token) ERC721("Game Item", "GITEM") {
        require(_erc20Token != address(0), "Invalid token");
        gameToken = IERC20(_erc20Token);
        isOperator[msg.sender] = true; // owner is operator by default
    }

    // --- ADMINISTRATION ---

    function setOperator(address user, bool status) external onlyOwner {
        require(user != address(0), "Zero address");
        isOperator[user] = status;
    }

    modifier onlyOperator() {
        require(isOperator[msg.sender], "Must be operator");
        _;
    }

    // --- MINTING NFT (with ERC20 fee) ---

    function mintItem(string memory tokenURI) external {
        uint256 mintFee = 20 ether;
        require(gameToken.transferFrom(msg.sender, address(this), mintFee), "Payment failed");

        _tokenIds.increment();
        uint256 newId = _tokenIds.current();
        _mint(msg.sender, newId);
        _setTokenURI(newId, tokenURI);

        uint256 basePower = 50 + _random(newId) % 50;

        itemAttributes[newId] = Item({
            level: 1,
            power: basePower,
            cooldownUntil: 0
        });

        emit ItemMinted(msg.sender, newId, basePower);
    }

    // --- UPGRADE NFT ITEM (cooldown + fee) ---

    function upgrade(uint256 tokenId) external {
        require(ownerOf(tokenId) == msg.sender, "Not the owner");
        Item storage item = itemAttributes[tokenId];
        require(block.timestamp > item.cooldownUntil, "In cooldown");

        uint256 upgradeFee = item.level * 10 ether;
        require(gameToken.transferFrom(msg.sender, address(this), upgradeFee), "Payment failed");

        item.level += 1;
        item.power += 10 + (item.level * 2);
        item.cooldownUntil = block.timestamp + 1 days;

        emit Upgraded(msg.sender, tokenId, item.level);
    }

    // --- STAKING ERC20 TOKENS ---

    function stakeTokens(uint256 amount) external {
        require(amount >= MIN_STAKE_AMOUNT, "Too little");
        require(stakes[msg.sender].amount == 0, "Already staking");

        require(gameToken.transferFrom(msg.sender, address(this), amount), "Stake failed");
        stakes[msg.sender] = Stake({
            amount: amount,
            startTime: block.timestamp,
            claimed: false
        });

        emit TokensStaked(msg.sender, amount);
    }

    function claimRewards() external {
        Stake storage s = stakes[msg.sender];
        require(s.amount > 0, "No stake");
        require(!s.claimed, "Already claimed");
        require(block.timestamp >= s.startTime + STAKING_DURATION, "Too early");

        uint256 reward = (s.amount * REWARD_RATE) / 100;
        s.claimed = true;

        require(gameToken.transfer(msg.sender, reward), "Reward failed");

        emit RewardsClaimed(msg.sender, reward);
    }

    // --- INTERNALS ---

    function _random(uint256 salt) internal view returns (uint256) {
        return uint256(keccak256(abi.encodePacked(
            block.timestamp,
            msg.sender,
            salt,
            block.prevrandao
        )));
    }

    // Emergency withdrawal for owner (only for trapped funds)
    function emergencyWithdraw(address to) external onlyOwner {
        payable(to).transfer(address(this).balance);
    }

    // Fallback-capable
    receive() external payable {}
}
