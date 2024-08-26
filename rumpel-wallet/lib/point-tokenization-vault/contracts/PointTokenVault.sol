// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {MerkleProof} from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

import {UUPSUpgradeable} from "openzeppelin-contracts-upgradeable/contracts/proxy/utils/UUPSUpgradeable.sol";
import {AccessControlUpgradeable} from
    "openzeppelin-contracts-upgradeable/contracts/access/AccessControlUpgradeable.sol";
import {MulticallUpgradeable} from "openzeppelin-contracts-upgradeable/contracts/utils/MulticallUpgradeable.sol";

import {ERC20} from "solmate/tokens/ERC20.sol";
import {SafeTransferLib} from "solmate/utils/SafeTransferLib.sol";

import {LibString} from "solady/utils/LibString.sol";
import {FixedPointMathLib} from "solmate/utils/FixedPointMathLib.sol";

import {PToken} from "./PToken.sol";

/// @title Point Token Vault
/// @notice Manages deposits and withdrawals for points-earning assets, point token claims, and reward redemptions.
contract PointTokenVault is UUPSUpgradeable, AccessControlUpgradeable, MulticallUpgradeable {
    using SafeTransferLib for ERC20;
    using MerkleProof for bytes32[];

    bytes32 public constant REDEMPTION_RIGHTS_PREFIX = keccak256("REDEMPTION_RIGHTS");
    bytes32 public constant MERKLE_UPDATER_ROLE = keccak256("MERKLE_UPDATER_ROLE");
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");

    // Deposit asset balances.
    mapping(address => mapping(ERC20 => uint256)) public balances; // user => point-earning token => balance

    // Merkle root distribution.
    bytes32 public currRoot;
    bytes32 public prevRoot;
    mapping(address => mapping(bytes32 => uint256)) public claimedPTokens; // user => pointsId => claimed
    mapping(address => mapping(bytes32 => uint256)) public claimedRedemptionRights; // user => pointsId => claimed

    mapping(bytes32 => PToken) public pTokens; // pointsId => pTokens

    mapping(bytes32 => RedemptionParams) public redemptions; // pointsId => redemptionParams

    mapping(address => uint256) public caps; // asset => deposit cap

    mapping(address => mapping(address => bool)) public trustedClaimers; // owner => delegate => trustedClaimers

    // Fees
    uint256 public mintFee;
    uint256 public redemptionFee;
    mapping(bytes32 => uint256) public pTokenFeeAcc; // pTokenFeeAccumulator
    mapping(bytes32 => uint256) public rewardTokenFeeAcc; // rewardTokenFeeAccumulator
    mapping(address => mapping(bytes32 => uint256)) public feelesslyRedeemedPTokens; // user => pointsId => feelesslyRedeemedPTokens
    address public feeCollector;

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

    event Deposit(address indexed depositor, address indexed receiver, address indexed token, uint256 amount);
    event Withdraw(address indexed withdrawer, address indexed receiver, address indexed token, uint256 amount);
    event TrustClaimer(address indexed owner, address indexed delegate, bool isTrusted);
    event RootUpdated(bytes32 prevRoot, bytes32 newRoot);
    event PTokensClaimed(
        address indexed account, address indexed receiver, bytes32 indexed pointsId, uint256 amount, uint256 fee
    );
    event RewardsClaimed(
        address indexed owner, address indexed receiver, bytes32 indexed pointsId, uint256 amount, uint256 fee
    );
    event RewardsConverted(address indexed owner, address indexed receiver, bytes32 indexed pointsId, uint256 amount);
    event RewardRedemptionSet(
        bytes32 indexed pointsId, ERC20 rewardToken, uint256 rewardsPerPToken, bool isMerkleBased
    );
    event PTokenDeployed(bytes32 indexed pointsId, address indexed pToken);
    event CapSet(address indexed token, uint256 prevCap, uint256 cap);
    event FeesCollected(
        bytes32 indexed pointsId, address indexed feeCollector, uint256 pTokenFee, uint256 rewardTokenFee
    );
    event FeeCollectorSet(address feeCollector);
    event MintFeeSet(uint256 mintFee);
    event RedemptionFeeSet(uint256 redemptionFee);

    error ProofInvalidOrExpired();
    error ClaimTooLarge();
    error RewardsNotReleased();
    error CantConvertMerkleRedemption();
    error PTokenAlreadyDeployed();
    error DepositExceedsCap();
    error PTokenNotDeployed();
    error AmountTooSmall();
    error NotTrustedClaimer();

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address _admin, address _feeCollector) public initializer {
        __UUPSUpgradeable_init();
        __AccessControl_init();
        __Multicall_init();
        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _setFeeCollector(_feeCollector);
    }

    // Rebasing and fee-on-transfer tokens must be wrapped before depositing.
    function deposit(ERC20 _token, uint256 _amount, address _receiver) public {
        uint256 cap = caps[address(_token)];

        if (cap != type(uint256).max) {
            if (_amount + _token.balanceOf(address(this)) > cap) {
                revert DepositExceedsCap();
            }
        }

        _token.safeTransferFrom(msg.sender, address(this), _amount);

        balances[_receiver][_token] += _amount;

        emit Deposit(msg.sender, _receiver, address(_token), _amount);
    }

    function withdraw(ERC20 _token, uint256 _amount, address _receiver) public {
        balances[msg.sender][_token] -= _amount;

        _token.safeTransfer(_receiver, _amount);

        emit Withdraw(msg.sender, _receiver, address(_token), _amount);
    }

    /// @notice Claims point tokens after verifying the merkle proof
    /// @param _claim The claim details including the merkle proof
    /// @param _account The account to claim for
    // Adapted from Morpho's RewardsDistributor.sol (https://github.com/morpho-org/morpho-optimizers/blob/ffd702f045d24b911d6c8c6c2194dd15cf9387ff/src/common/rewards-distribution/RewardsDistributor.sol)
    function claimPTokens(Claim calldata _claim, address _account, address _receiver) public {
        bytes32 pointsId = _claim.pointsId;

        bytes32 claimHash = keccak256(abi.encodePacked(_account, pointsId, _claim.totalClaimable));
        _verifyClaimAndUpdateClaimed(_claim, claimHash, _account, claimedPTokens);

        if (address(pTokens[pointsId]) == address(0)) {
            revert PTokenNotDeployed();
        }

        if (_account != _receiver && !trustedClaimers[_account][_receiver]) {
            revert NotTrustedClaimer();
        }

        uint256 pTokenFee = FixedPointMathLib.mulWadUp(_claim.amountToClaim, mintFee);
        pTokenFeeAcc[pointsId] += pTokenFee;

        pTokens[pointsId].mint(_receiver, _claim.amountToClaim - pTokenFee); // Subtract mint fee.

        emit PTokensClaimed(_account, _receiver, pointsId, _claim.amountToClaim, pTokenFee);
    }

    function trustClaimer(address _account, bool _isTrusted) public {
        trustedClaimers[msg.sender][_account] = _isTrusted;
        emit TrustClaimer(msg.sender, _account, _isTrusted);
    }

    /// @notice Redeems point tokens for rewards
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

        uint256 pTokensToBurn = FixedPointMathLib.divWadUp(amountToClaim, rewardsPerPToken);
        pTokens[pointsId].burn(msg.sender, pTokensToBurn);

        uint256 claimed = claimedPTokens[msg.sender][pointsId];
        uint256 feelesslyRedeemed = feelesslyRedeemedPTokens[msg.sender][pointsId];

        // The amount of pTokens that are free to redeem without fee.
        uint256 feelesslyRedeemable = claimed - feelesslyRedeemed;

        uint256 rewardsToTransfer;
        uint256 fee;

        if (feelesslyRedeemable >= pTokensToBurn) {
            // If all of the pTokens are free to redeem without fee.
            rewardsToTransfer = amountToClaim;
            feelesslyRedeemedPTokens[msg.sender][pointsId] += pTokensToBurn;
        } else {
            // If some or all of the pTokens need to be charged a fee.
            uint256 redeemableWithFee = pTokensToBurn - feelesslyRedeemable;
            // fee = amount of pTokens that are not feeless * rewardsPerPToken * redemptionFee
            fee = FixedPointMathLib.mulWadUp(
                FixedPointMathLib.mulWadUp(redeemableWithFee, rewardsPerPToken), redemptionFee
            );

            rewardTokenFeeAcc[pointsId] += fee;
            rewardsToTransfer = amountToClaim - fee;

            if (feelesslyRedeemed != claimed) {
                feelesslyRedeemedPTokens[msg.sender][pointsId] = claimed;
            }
        }

        params.rewardToken.safeTransfer(_receiver, rewardsToTransfer);

        emit RewardsClaimed(msg.sender, _receiver, pointsId, rewardsToTransfer, fee);
    }

    /// @notice Mints point tokens for rewards after redemption has been enabled
    function convertRewardsToPTokens(address _receiver, bytes32 _pointsId, uint256 _amountToConvert) public {
        RedemptionParams memory params = redemptions[_pointsId];
        (ERC20 rewardToken, uint256 rewardsPerPToken, bool isMerkleBased) =
            (params.rewardToken, params.rewardsPerPToken, params.isMerkleBased);

        if (address(rewardToken) == address(0)) {
            revert RewardsNotReleased();
        }

        if (isMerkleBased) {
            revert CantConvertMerkleRedemption();
        }

        rewardToken.safeTransferFrom(msg.sender, address(this), _amountToConvert);

        uint256 pTokensToMint = FixedPointMathLib.divWadDown(_amountToConvert, rewardsPerPToken); // Round down for mint.

        // Dust guard.
        if (pTokensToMint == 0) {
            revert AmountTooSmall();
        }

        pTokens[_pointsId].mint(_receiver, pTokensToMint);

        emit RewardsConverted(msg.sender, _receiver, _pointsId, _amountToConvert);
    }

    function deployPToken(bytes32 _pointsId) public returns (PToken pToken) {
        if (address(pTokens[_pointsId]) != address(0)) {
            revert PTokenAlreadyDeployed();
        }

        (string memory name, string memory symbol) = LibString.unpackTwo(_pointsId); // Assume the points id was created using LibString.packTwo.
        pToken = new PToken{salt: _pointsId}(name, symbol, 18);

        pTokens[_pointsId] = pToken;

        emit PTokenDeployed(_pointsId, address(pToken));
    }

    // Internal ---

    function _verifyClaimAndUpdateClaimed(
        Claim calldata _claim,
        bytes32 _claimHash,
        address _account,
        mapping(address => mapping(bytes32 => uint256)) storage _claimed
    ) internal {
        bytes32 candidateRoot = _claim.proof.processProof(_claimHash);
        bytes32 pointsId = _claim.pointsId;
        uint256 amountToClaim = _claim.amountToClaim;

        // Check if the root is valid.
        if (candidateRoot != currRoot && candidateRoot != prevRoot) {
            revert ProofInvalidOrExpired();
        }

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
        uint256 prevCap = caps[_token];
        caps[_token] = _cap;
        emit CapSet(_token, prevCap, _cap);
    }

    // Can be used to unlock reward token redemption (can also modify a live redemption, so use with care).
    function setRedemption(bytes32 _pointsId, ERC20 _rewardToken, uint256 _rewardsPerPToken, bool _isMerkleBased)
        external
        onlyRole(OPERATOR_ROLE)
    {
        redemptions[_pointsId] = RedemptionParams(_rewardToken, _rewardsPerPToken, _isMerkleBased);
        emit RewardRedemptionSet(_pointsId, _rewardToken, _rewardsPerPToken, _isMerkleBased);
    }

    function setMintFee(uint256 _mintFee) external onlyRole(OPERATOR_ROLE) {
        mintFee = _mintFee;
        emit MintFeeSet(_mintFee);
    }

    function setRedemptionFee(uint256 _redemptionFee) external onlyRole(OPERATOR_ROLE) {
        redemptionFee = _redemptionFee;
        emit RedemptionFeeSet(_redemptionFee);
    }

    function pausePToken(bytes32 _pointsId) external onlyRole(OPERATOR_ROLE) {
        pTokens[_pointsId].pause();
    }

    function unpausePToken(bytes32 _pointsId) external onlyRole(OPERATOR_ROLE) {
        pTokens[_pointsId].unpause();
    }

    function renouncePauseRole(bytes32 _pointsId) external onlyRole(OPERATOR_ROLE) {
        pTokens[_pointsId].renounceRole(pTokens[_pointsId].PAUSE_ROLE(), address(this));
    }

    function collectFees(bytes32 _pointsId) external {
        (uint256 pTokenFee, uint256 rewardTokenFee) = (pTokenFeeAcc[_pointsId], rewardTokenFeeAcc[_pointsId]);

        if (pTokenFee > 0) {
            pTokens[_pointsId].mint(feeCollector, pTokenFee);
            pTokenFeeAcc[_pointsId] = 0;
        }

        if (rewardTokenFee > 0) {
            // There will only be a positive rewardTokenFee if there are reward tokens in this contract available for transfer.
            redemptions[_pointsId].rewardToken.safeTransfer(feeCollector, rewardTokenFee);
            rewardTokenFeeAcc[_pointsId] = 0;
        }

        emit FeesCollected(_pointsId, feeCollector, pTokenFee, rewardTokenFee);
    }

    function setFeeCollector(address _feeCollector) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _setFeeCollector(_feeCollector);
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

    function _setFeeCollector(address _feeCollector) internal {
        feeCollector = _feeCollector;
        emit FeeCollectorSet(_feeCollector);
    }

    receive() external payable {}
}
