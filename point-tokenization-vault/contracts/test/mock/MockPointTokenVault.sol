// SPDX-License-Identifier: UNLICENSED
pragma solidity =0.8.24;

import {console} from "forge-std/Test.sol";

import {MerkleProof} from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

import {UUPSUpgradeable} from "openzeppelin-contracts-upgradeable/contracts/proxy/utils/UUPSUpgradeable.sol";
import {AccessControlUpgradeable} from
    "openzeppelin-contracts-upgradeable/contracts/access/AccessControlUpgradeable.sol";
import {MulticallUpgradeable} from "openzeppelin-contracts-upgradeable/contracts/utils/MulticallUpgradeable.sol";

import {ERC20} from "solmate/tokens/ERC20.sol";
import {SafeTransferLib} from "solmate/utils/SafeTransferLib.sol";

import {LibString} from "solady/utils/LibString.sol";
import {FixedPointMathLib} from "solmate/utils/FixedPointMathLib.sol";

import {PToken} from "../../PToken.sol";

/// @title Point Token Vault
/// @notice Manages deposits and withdrawals for points-earning assets, point token claims, and reward redemptions.
contract MockPointTokenVault is UUPSUpgradeable, AccessControlUpgradeable, MulticallUpgradeable {
    using SafeTransferLib for ERC20;
    using MerkleProof for bytes32[];

    bytes32 public constant REDEMPTION_RIGHTS_PREFIX = keccak256("REDEMPTION_RIGHTS");
    bytes32 public constant MERKLE_UPDATER_ROLE = keccak256("MERKLE_UPDATER_ROLE");
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");

    // Deposit asset balancess.
    mapping(address => mapping(ERC20 => uint256)) public balances; // user => point-earning token => balance

    // Merkle root distribution.
    bytes32 public currRoot;
    bytes32 public prevRoot;
    mapping(address => mapping(bytes32 => uint256)) public claimedPTokens; // user => pointsId => claimed
    mapping(address => mapping(bytes32 => uint256)) public claimedRedemptionRights; // user => pointsId => claimed

    mapping(bytes32 => PToken) public pTokens; // pointsId => pTokens

    mapping(bytes32 => RedemptionParams) public redemptions; // pointsId => redemptionParams

    mapping(address => uint256) public caps; // asset => deposit cap
    bool public isCapped;

    struct Claim {
        bytes32 pointsId;
        uint256 totalClaimable;
        uint256 amountToClaim;
        bytes32[] proof;
    }

    struct RedemptionParams {
        ERC20 rewardToken;
        uint256 rewardsPerPToken; // Assume 18 decimals.
        bool isMerkleBased;
    }

    event Deposit(address indexed receiver, address indexed token, uint256 amount);
    event Withdraw(address indexed user, address indexed token, uint256 amount);
    event RootUpdated(bytes32 prevRoot, bytes32 newRoot);
    event PTokensClaimed(address indexed account, bytes32 indexed pointsId, uint256 amount);
    event RewardsClaimed(address indexed owner, address indexed receiver, bytes32 indexed pointsId, uint256 amount);
    event RewardRedemptionSet(
        bytes32 indexed pointsId, ERC20 rewardToken, uint256 rewardsPerPToken, bool isMerkleBased
    );
    event PTokenDeployed(bytes32 indexed pointsId, address indexed pToken);
    event CapSet(address indexed token, uint256 cap);

    error ProofInvalidOrExpired();
    error ClaimTooLarge();
    error RewardsNotReleased();
    error PTokenAlreadyDeployed();
    error DepositExceedsCap();
    error PTokenNotDeployed();

    constructor() {
        _disableInitializers();
    }

    function initialize(address _admin) public initializer {
        __UUPSUpgradeable_init();
        __AccessControl_init();
        __Multicall_init();
        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        isCapped = true;
    }

    // Rebasing and fee-on-transfer tokens must be wrapped before depositing.
    function deposit(ERC20 _token, uint256 _amount, address _receiver) public {
        if (isCapped && (_amount + _token.balanceOf(address(this)) > caps[address(_token)])) {
            revert DepositExceedsCap();
        }

        _token.safeTransferFrom(msg.sender, address(this), _amount);

        balances[_receiver][_token] += _amount;

        emit Deposit(_receiver, address(_token), _amount);
    }

    function withdraw(ERC20 _token, uint256 _amount, address _receiver) public {
        balances[msg.sender][_token] -= _amount;

        _token.safeTransfer(_receiver, _amount);

        emit Withdraw(_receiver, address(_token), _amount);
    }

    /// @notice Claims point tokens after verifying the merkle proof
    /// @param _claim The claim details including the merkle proof
    /// @param _account The account to claim for
    // Adapted from Morpho's RewardsDistributor.sol (https://github.com/morpho-org/morpho-optimizers/blob/ffd702f045d24b911d6c8c6c2194dd15cf9387ff/src/common/rewards-distribution/RewardsDistributor.sol)
    function claimPTokens(Claim calldata _claim, address _account) public {
        bytes32 pointsId = _claim.pointsId;

        bytes32 claimHash = keccak256(abi.encodePacked(_account, pointsId, _claim.totalClaimable));
        _verifyClaimAndUpdateClaimed(_claim, claimHash, _account, claimedPTokens);

        if (address(pTokens[pointsId]) == address(0)) {
            revert PTokenNotDeployed();
        }

        pTokens[pointsId].mint(_account, _claim.amountToClaim);

        emit PTokensClaimed(_account, pointsId, _claim.amountToClaim);
    }

    /// @notice Redeems rewards for point tokens
    /// @param _claim Details of the claim including the amount and merkle proof
    /// @param _receiver The account that will receive the msg.sender redeemed rewards
    function redeemRewards(Claim calldata _claim, address _receiver) public {
        (bytes32 pointsId, uint256 amountToClaim) = (_claim.pointsId, _claim.amountToClaim);

        RedemptionParams memory params = redemptions[pointsId];
        (ERC20 rewardToken, uint256 rewardsPerPToken, bool isMerkleBased) =
            (params.rewardToken, params.rewardsPerPToken, params.isMerkleBased);

        if (address(rewardToken) == address(0)) {
            revert RewardsNotReleased();
        }

        if (isMerkleBased) {
            // If it's merkle-based, only those callers with redemption rights can redeem their point token for rewards.

            bytes32 claimHash =
                keccak256(abi.encodePacked(REDEMPTION_RIGHTS_PREFIX, msg.sender, pointsId, _claim.totalClaimable));
            _verifyClaimAndUpdateClaimed(_claim, claimHash, msg.sender, claimedRedemptionRights);
        }

        // Will fail if the user doesn't also have enough point tokens. Assume rewardsPerPToken is 18 decimals.
        pTokens[pointsId].burn(msg.sender, FixedPointMathLib.divWadUp(amountToClaim, rewardsPerPToken)); // Round up for burn.
        rewardToken.safeTransfer(_receiver, amountToClaim);
        emit RewardsClaimed(msg.sender, _receiver, pointsId, amountToClaim);
    }

    /// @notice Mints point tokens for rewards after redemption has been enabled
    function convertRewardsToPTokens(address _receiver, bytes32 _pointsId, uint256 _amountToConvert) public {
        RedemptionParams memory params = redemptions[_pointsId];
        (ERC20 rewardToken, uint256 rewardsPerPToken) = (params.rewardToken, params.rewardsPerPToken);

        if (address(rewardToken) == address(0)) {
            revert RewardsNotReleased();
        }

        rewardToken.safeTransferFrom(msg.sender, address(this), _amountToConvert);
        pTokens[_pointsId].mint(_receiver, FixedPointMathLib.divWadDown(_amountToConvert, rewardsPerPToken)); // Round down for mint.
    }

    function deployPToken(bytes32 _pointsId) public {
        if (address(pTokens[_pointsId]) != address(0)) {
            revert PTokenAlreadyDeployed();
        }

        (string memory name, string memory symbol) = LibString.unpackTwo(_pointsId); // Assume the points id was created using LibString.packTwo.
        pTokens[_pointsId] = new PToken{salt: _pointsId}(name, symbol, 18);
        emit PTokenDeployed(_pointsId, address(pTokens[_pointsId]));
    }

    // Internal ---

    function _verifyClaimAndUpdateClaimed(
        Claim calldata _claim,
        bytes32 _claimHash,
        address _account,
        mapping(address => mapping(bytes32 => uint256)) storage _claimed
    ) internal {
        // bytes32 candidateRoot = _claim.proof.processProof(_claimHash);
        // The following line exists only here in the mock, just to silence the warning about _claimHash being unused
        _claimHash;
        bytes32 pointsId = _claim.pointsId;
        uint256 amountToClaim = _claim.amountToClaim;

        // Check if the root is valid.
        // if (candidateRoot != currRoot && candidateRoot != prevRoot) {
        //     revert ProofInvalidOrExpired();
        // }

        uint256 alreadyClaimed = _claimed[_account][pointsId];

        // Can claim up to the total claimable amount from the hash.
        // IMPORTANT: totalClaimable must be in the claim hash passed into this function.
        if (_claim.totalClaimable < alreadyClaimed + amountToClaim) revert ClaimTooLarge();

        // Update the total claimed amount.
        unchecked {
            _claimed[_account][pointsId] = alreadyClaimed + amountToClaim;
        }
    }

    // Admin ---

    function updateRoot(bytes32 _newRoot) external onlyRole(MERKLE_UPDATER_ROLE) {
        prevRoot = currRoot;
        currRoot = _newRoot;
        emit RootUpdated(prevRoot, currRoot);
    }

    function setCap(address _token, uint256 _cap) external onlyRole(OPERATOR_ROLE) {
        caps[_token] = _cap;
        emit CapSet(_token, _cap);
    }

    function setIsCapped(bool _isCapped) external onlyRole(OPERATOR_ROLE) {
        isCapped = _isCapped;
    }

    // Can be used to unlock reward token redemption (can also modify a live redemption, so use with care).
    function setRedemption(bytes32 _pointsId, ERC20 _rewardToken, uint256 _rewardsPerPToken, bool _isMerkleBased)
        external
        onlyRole(OPERATOR_ROLE)
    {
        redemptions[_pointsId] = RedemptionParams(_rewardToken, _rewardsPerPToken, _isMerkleBased);
        emit RewardRedemptionSet(_pointsId, _rewardToken, _rewardsPerPToken, _isMerkleBased);
    }

    // To handle arbitrary reward claiming logic.
    function execute(address _to, bytes memory _data, uint256 _txGas)
        external
        onlyRole(DEFAULT_ADMIN_ROLE)
        returns (bool success)
    {
        assembly {
            success := delegatecall(_txGas, _to, add(_data, 0x20), mload(_data), 0, 0)
        }
    }

    function _authorizeUpgrade(address _newImplementation) internal override onlyRole(DEFAULT_ADMIN_ROLE) {}

    receive() external payable {}
}
