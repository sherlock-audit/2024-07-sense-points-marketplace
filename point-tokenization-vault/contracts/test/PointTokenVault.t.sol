// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity =0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {PointTokenVault} from "../PointTokenVault.sol";
import {PToken} from "../PToken.sol";

import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";

import {MockERC20, ERC20} from "solmate/test/utils/mocks/MockERC20.sol";

import {LibString} from "solady/utils/LibString.sol";

import {PointTokenVaultScripts} from "../script/PointTokenVault.s.sol";

contract PointTokenVaultTest is Test {
    PointTokenVault pointTokenVault;

    MockERC20 pointEarningToken;
    MockERC20 rewardToken;

    address vitalik = makeAddr("vitalik");
    address toly = makeAddr("toly");
    address illia = makeAddr("illia");
    address admin = makeAddr("admin");
    address operator = makeAddr("operator");
    address merkleUpdater = makeAddr("merkleUpdater");

    bytes32 eigenPointsId = LibString.packTwo("Eigen Layer Point", "pEL");

    function setUp() public {
        PointTokenVaultScripts scripts = new PointTokenVaultScripts();

        // Deploy the PointTokenVault
        pointTokenVault = scripts.run("0.0.1");

        pointTokenVault.grantRole(pointTokenVault.DEFAULT_ADMIN_ROLE(), admin);
        pointTokenVault.grantRole(pointTokenVault.MERKLE_UPDATER_ROLE(), merkleUpdater);
        pointTokenVault.grantRole(pointTokenVault.OPERATOR_ROLE(), operator);
        pointTokenVault.revokeRole(pointTokenVault.DEFAULT_ADMIN_ROLE(), address(this));

        // Deploy a mock token
        pointEarningToken = new MockERC20("Test Token", "TST", 18);
        rewardToken = new MockERC20("Reward Token", "RWT", 18);

        pointTokenVault.deployPToken(eigenPointsId);
        vm.prank(operator);
        pointTokenVault.setCap(address(pointEarningToken), type(uint256).max);
    }

    event Deposit(address indexed depositor, address indexed receiver, address indexed token, uint256 amount);

    function test_Deposit() public {
        pointEarningToken.mint(vitalik, 1.123e18);

        // Can deposit for yourself
        vm.startPrank(vitalik);
        pointEarningToken.approve(address(pointTokenVault), 1.123e18);
        pointTokenVault.deposit(pointEarningToken, 0.5e18, vitalik);
        vm.stopPrank();

        assertEq(pointEarningToken.balanceOf(vitalik), 0.623e18);
        assertEq(pointTokenVault.balances(vitalik, pointEarningToken), 0.5e18);

        // Can deposit for someone else
        vm.prank(vitalik);
        vm.expectEmit(true, true, true, true);
        emit Deposit(vitalik, toly, address(pointEarningToken), 0.623e18);
        pointTokenVault.deposit(pointEarningToken, 0.623e18, toly);

        assertEq(pointEarningToken.balanceOf(vitalik), 0);
        assertEq(pointTokenVault.balances(toly, pointEarningToken), 0.623e18);
        assertEq(pointTokenVault.balances(vitalik, pointEarningToken), 0.5e18);
    }

    event Withdraw(address indexed withdrawer, address indexed receiver, address indexed token, uint256 amount);

    function test_Withdraw() public {
        pointEarningToken.mint(vitalik, 1.123e18);

        // Can withdraw for yourself
        vm.startPrank(vitalik);
        pointEarningToken.approve(address(pointTokenVault), 1.123e18);
        pointTokenVault.deposit(pointEarningToken, 1.123e18, vitalik);
        pointTokenVault.withdraw(pointEarningToken, 0.623e18, vitalik);
        vm.stopPrank();

        assertEq(pointEarningToken.balanceOf(vitalik), 0.623e18);
        assertEq(pointTokenVault.balances(vitalik, pointEarningToken), 0.5e18);

        // Can withdraw with a different receiver
        vm.prank(vitalik);
        vm.expectEmit(true, true, true, true);
        emit Withdraw(vitalik, toly, address(pointEarningToken), 0.5e18);
        pointTokenVault.withdraw(pointEarningToken, 0.5e18, toly);

        assertEq(pointEarningToken.balanceOf(vitalik), 0.623e18);
        assertEq(pointEarningToken.balanceOf(toly), 0.5e18);

        assertEq(pointTokenVault.balances(toly, pointEarningToken), 0);
        assertEq(pointTokenVault.balances(vitalik, pointEarningToken), 0);
    }

    event CapSet(address indexed token, uint256 prevCap, uint256 cap);

    function test_DepositCaps() public {
        // Deploy a new mock token
        MockERC20 newMockToken = new MockERC20("New Test Token", "NTT", 18);

        // Set a cap for the new token
        uint256 capAmount = 1e18; // 1 token cap
        vm.prank(operator);
        vm.expectEmit(true, true, true, true);
        emit CapSet(address(newMockToken), 0, capAmount);
        pointTokenVault.setCap(address(newMockToken), capAmount);

        // Mint tokens to vitalik
        newMockToken.mint(vitalik, 2e18); // 2 tokens

        // Approve and try to deposit more than the cap
        vm.startPrank(vitalik);
        newMockToken.approve(address(pointTokenVault), 2e18);
        vm.expectRevert(PointTokenVault.DepositExceedsCap.selector);
        pointTokenVault.deposit(newMockToken, 1.5e18, vitalik); // Try to deposit 1.5 tokens
        vm.stopPrank();

        // Approve and deposit exactly at the cap
        vm.startPrank(vitalik);
        newMockToken.approve(address(pointTokenVault), 1e18);
        pointTokenVault.deposit(newMockToken, 1e18, vitalik); // Deposit exactly 1 token
        vm.stopPrank();

        assertEq(pointTokenVault.balances(vitalik, newMockToken), 1e18);

        // Set deposit cap to max
        vm.prank(operator);
        pointTokenVault.setCap(address(newMockToken), 2 ** 256 - 1);

        // Approve and deposit more than the previous cap
        vm.startPrank(vitalik);
        newMockToken.approve(address(pointTokenVault), 1e18);
        pointTokenVault.deposit(newMockToken, 1e18, vitalik); // Deposit another 1 token
        vm.stopPrank();

        assertEq(pointTokenVault.balances(vitalik, newMockToken), 2e18); // Total 2 tokens deposited
    }

    function test_DepositCapRewardSameAsDeposit() public {
        // Set up an 18 decimal token as both deposit and reward token
        MockERC20 token = new MockERC20("Example Token", "EX", 18);

        vm.startPrank(operator);
        // Set deposit cap for token to 5000
        pointTokenVault.setCap(address(token), 5000e18);

        // Set token as reward token with 1:1 ratio
        pointTokenVault.setRedemption(eigenPointsId, token, 1e18, false);
        vm.stopPrank();

        // Mint tokens to users
        token.mint(vitalik, 5000e18);
        token.mint(toly, 2000e18);

        // Vitalik deposits 4000 tokens
        vm.startPrank(vitalik);
        token.approve(address(pointTokenVault), 4000e18);
        pointTokenVault.deposit(token, 4000e18, vitalik);
        vm.stopPrank();

        // Toly converts 2000 tokens to pTokens
        vm.startPrank(toly);
        token.approve(address(pointTokenVault), 2000e18);
        pointTokenVault.convertRewardsToPTokens(toly, eigenPointsId, 2000e18);
        vm.stopPrank();

        // Assert current token balance in vault
        assertEq(token.balanceOf(address(pointTokenVault)), 6000e18);

        // Try to deposit 1000 tokens, which should succeed
        vm.startPrank(vitalik);
        token.approve(address(pointTokenVault), 1000e18);
        pointTokenVault.deposit(token, 1000e18, vitalik);
        vm.stopPrank();

        // Assert that 5000 tokens have been deposited
        assertEq(pointTokenVault.balances(vitalik, token), 5000e18);
    }

    function test_DeployPToken() public {
        // Can't deploy the same token twice
        vm.expectRevert(PointTokenVault.PTokenAlreadyDeployed.selector);
        pointTokenVault.deployPToken(eigenPointsId);

        // Name and symbol are set correctly
        assertEq(pointTokenVault.pTokens(eigenPointsId).name(), "Eigen Layer Point");
        assertEq(pointTokenVault.pTokens(eigenPointsId).symbol(), "pEL");
    }

    function test_ProxyUpgrade() public {
        PointTokenVault newPointTokenVault = new PointTokenVault();
        address eigenPointTokenPre = address(pointTokenVault.pTokens(eigenPointsId));

        // Only admin role can upgrade
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector, vitalik, pointTokenVault.DEFAULT_ADMIN_ROLE()
            )
        );
        vm.prank(vitalik);
        pointTokenVault.upgradeToAndCall(address(newPointTokenVault), bytes(""));

        vm.prank(admin);
        pointTokenVault.upgradeToAndCall(address(newPointTokenVault), bytes(""));

        // Check that the state is still there.
        assertEq(address(pointTokenVault.pTokens(eigenPointsId)), eigenPointTokenPre);
        // Check that the implementation has been updated.
        address implementation = address(
            uint160(
                uint256(
                    vm.load(
                        address(pointTokenVault),
                        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc // eip1967 implementation slot
                    )
                )
            )
        );

        assertEq(address(newPointTokenVault), implementation);
    }

    function test_UpdateRoot() public {
        bytes32 root = 0x5842148bc6ebeb52af882a317c765fccd3ae80589b21a9b8cbf21abb630e46a7;

        // Only merkle root updater role can update root
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector, vitalik, pointTokenVault.MERKLE_UPDATER_ROLE()
            )
        );
        vm.prank(vitalik);
        pointTokenVault.updateRoot(root);

        // Update the root
        vm.prank(merkleUpdater);
        pointTokenVault.updateRoot(root);
    }

    function test_ExecuteAuth(address lad) public {
        vm.assume(lad != admin);
        // Only admin can exec
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector, lad, pointTokenVault.DEFAULT_ADMIN_ROLE()
            )
        );
        vm.prank(lad);
        pointTokenVault.execute(vitalik, bytes(""), 0);
    }

    event EchoEvent(string message, address caller);

    function test_Execute() public {
        Echo echo = new Echo();
        CallEcho callEcho = new CallEcho();

        uint256 GAS_LIMIT = 1e9;

        // Execute a simple call
        vm.prank(admin);

        vm.expectEmit(true, true, true, true);
        emit EchoEvent("Hello", address(pointTokenVault));
        pointTokenVault.execute(
            address(callEcho), abi.encodeWithSelector(CallEcho.callEcho.selector, echo, "Hello"), GAS_LIMIT
        );

        // Test that failed calls revert with ExecutionFailed error
        vm.prank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(
                PointTokenVault.ExecutionFailed.selector,
                address(callEcho),
                abi.encodeWithSelector(CallEcho.fail.selector)
            )
        );
        pointTokenVault.execute(address(callEcho), abi.encodeWithSelector(CallEcho.fail.selector), GAS_LIMIT);
    }

    event PTokensClaimed(
        address indexed account, address indexed receiver, bytes32 indexed pointsId, uint256 amount, uint256 fee
    );

    function test_Distribution() public {
        // Merkle tree created from leaves [keccack(vitalik, pointsId, 1e18), keccack(toly, pointsId, 0.5e18)].
        bytes32[] memory goodProof = new bytes32[](1);
        goodProof[0] = 0x6d0fcb8de12b1f57f81e49fa18b641487b932cdba4f064409fde3b05d3824ca2;
        bytes32 root = 0x4e40a10ce33f33a4786960a8bb843fe0e170b651acd83da27abc97176c4bed3c;

        bytes32[] memory badProof = new bytes32[](1);
        badProof[0] = 0x6d06cb8de12b1f57f81e49fa18b641487b932cdba4f064409fde3b05d3824ca2;

        vm.prank(merkleUpdater);
        pointTokenVault.updateRoot(root);

        // Can't claim with the wrong proof
        vm.prank(vitalik);
        vm.expectRevert(PointTokenVault.ProofInvalidOrExpired.selector);
        pointTokenVault.claimPTokens(PointTokenVault.Claim(eigenPointsId, 1e18, 1e18, badProof), vitalik, vitalik);

        // Can't claim with the wrong claimable amount
        vm.prank(vitalik);
        vm.expectRevert(PointTokenVault.ProofInvalidOrExpired.selector);
        pointTokenVault.claimPTokens(PointTokenVault.Claim(eigenPointsId, 0.9e18, 0.9e18, goodProof), vitalik, vitalik);

        // Can't claim with the wrong pointsId
        vm.prank(vitalik);
        vm.expectRevert(PointTokenVault.ProofInvalidOrExpired.selector);
        pointTokenVault.claimPTokens(PointTokenVault.Claim(bytes32("123"), 1e18, 1e18, goodProof), vitalik, vitalik);

        // Can claim with the right proof
        vm.prank(vitalik);
        vm.expectEmit(true, true, true, true);
        emit PTokensClaimed(vitalik, vitalik, eigenPointsId, 1e18, 0);
        pointTokenVault.claimPTokens(PointTokenVault.Claim(eigenPointsId, 1e18, 1e18, goodProof), vitalik, vitalik);

        assertEq(pointTokenVault.pTokens(eigenPointsId).balanceOf(vitalik), 1e18);

        // Can't use the same proof twice
        vm.expectRevert(PointTokenVault.ClaimTooLarge.selector);
        pointTokenVault.claimPTokens(PointTokenVault.Claim(eigenPointsId, 1e18, 1e18, goodProof), vitalik, vitalik);
    }

    function test_DistributionTwoRecipients() public {
        // Merkle tree created from leaves [keccack(vitalik, pointsId, 1e18), keccack(toly, pointsId, 0.5e18)].
        bytes32 root = 0x4e40a10ce33f33a4786960a8bb843fe0e170b651acd83da27abc97176c4bed3c;

        vm.prank(merkleUpdater);
        pointTokenVault.updateRoot(root);

        bytes32[] memory vitalikProof = new bytes32[](1);
        vitalikProof[0] = 0x6d0fcb8de12b1f57f81e49fa18b641487b932cdba4f064409fde3b05d3824ca2;

        // Vitalik can claim
        vm.prank(vitalik);
        pointTokenVault.claimPTokens(PointTokenVault.Claim(eigenPointsId, 1e18, 1e18, vitalikProof), vitalik, vitalik);

        assertEq(pointTokenVault.pTokens(eigenPointsId).balanceOf(vitalik), 1e18);

        bytes32[] memory tolyProof = new bytes32[](1);
        tolyProof[0] = 0x77ec2184ee10de8d8164b15f7f9e734a985dbe8a49e28feb2793ab17c9ed215c;

        // Illia can execute toly's claim, but can only send the tokens to toly
        vm.prank(illia);
        vm.expectRevert(PointTokenVault.ProofInvalidOrExpired.selector);
        pointTokenVault.claimPTokens(PointTokenVault.Claim(eigenPointsId, 0.5e18, 0.5e18, tolyProof), illia, illia);

        pointTokenVault.claimPTokens(PointTokenVault.Claim(eigenPointsId, 0.5e18, 0.5e18, tolyProof), toly, toly);

        assertEq(pointTokenVault.pTokens(eigenPointsId).balanceOf(toly), 0.5e18);
    }

    function test_MultiClaim() public {
        // Merkle tree created from leaves [keccack(vitalik, pointsId, 1e18), keccack(toly, pointsId, 0.5e18)].
        bytes32 root = 0x4e40a10ce33f33a4786960a8bb843fe0e170b651acd83da27abc97176c4bed3c;

        bytes32[] memory vitalikProof = new bytes32[](1);
        vitalikProof[0] = 0x6d0fcb8de12b1f57f81e49fa18b641487b932cdba4f064409fde3b05d3824ca2;

        bytes32[] memory tolyProof = new bytes32[](1);
        tolyProof[0] = 0x77ec2184ee10de8d8164b15f7f9e734a985dbe8a49e28feb2793ab17c9ed215c;

        vm.prank(merkleUpdater);
        pointTokenVault.updateRoot(root);

        bytes[] memory calls = new bytes[](2);
        calls[0] = abi.encodeCall(
            pointTokenVault.claimPTokens,
            (PointTokenVault.Claim(eigenPointsId, 1e18, 1e18, vitalikProof), vitalik, vitalik)
        );
        calls[1] = abi.encodeCall(
            pointTokenVault.claimPTokens, (PointTokenVault.Claim(eigenPointsId, 0.5e18, 0.5e18, tolyProof), toly, toly)
        );

        pointTokenVault.multicall(calls);

        // Claimed for both vitalik and toly at once.
        assertEq(pointTokenVault.pTokens(eigenPointsId).balanceOf(vitalik), 1e18);
        assertEq(pointTokenVault.pTokens(eigenPointsId).balanceOf(toly), 0.5e18);
    }

    function test_MulticallAuth(address lad) public {
        vm.assume(lad != admin);
        // Only admin can exec
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector, lad, pointTokenVault.MERKLE_UPDATER_ROLE()
            )
        );
        vm.prank(lad);
        bytes[] memory calls = new bytes[](1);
        calls[0] = abi.encodeCall(pointTokenVault.updateRoot, (bytes32("123")));
        pointTokenVault.multicall(calls);

        vm.prank(merkleUpdater);
        pointTokenVault.multicall(calls);
    }

    function test_SimpleRedemption() public {
        bytes32 root = 0x4e40a10ce33f33a4786960a8bb843fe0e170b651acd83da27abc97176c4bed3c;

        bytes32[] memory proof = new bytes32[](1);
        proof[0] = 0x6d0fcb8de12b1f57f81e49fa18b641487b932cdba4f064409fde3b05d3824ca2;

        vm.prank(merkleUpdater);
        pointTokenVault.updateRoot(root);

        vm.prank(vitalik);
        pointTokenVault.claimPTokens(PointTokenVault.Claim(eigenPointsId, 1e18, 1e18, proof), vitalik, vitalik);

        rewardToken.mint(address(pointTokenVault), 3e18);

        vm.prank(operator);
        pointTokenVault.setRedemption(eigenPointsId, rewardToken, 2e18, false);

        bytes32[] memory empty = new bytes32[](0);
        vm.prank(vitalik);
        pointTokenVault.redeemRewards(PointTokenVault.Claim(eigenPointsId, 2e18, 2e18, empty), vitalik);

        assertEq(rewardToken.balanceOf(vitalik), 2e18);
    }

    function test_RedeemRounding() public {
        bytes32 root = 0x4e40a10ce33f33a4786960a8bb843fe0e170b651acd83da27abc97176c4bed3c;

        bytes32[] memory proof = new bytes32[](1);
        proof[0] = 0x6d0fcb8de12b1f57f81e49fa18b641487b932cdba4f064409fde3b05d3824ca2;

        vm.prank(merkleUpdater);
        pointTokenVault.updateRoot(root);

        vm.prank(vitalik);
        pointTokenVault.claimPTokens(PointTokenVault.Claim(eigenPointsId, 1e18, 1e18, proof), vitalik, vitalik);

        rewardToken.mint(address(pointTokenVault), 3e18);

        vm.prank(operator);
        pointTokenVault.setRedemption(eigenPointsId, rewardToken, 2e18, false);

        bytes32[] memory empty = new bytes32[](0);
        vm.prank(vitalik);
        pointTokenVault.redeemRewards(PointTokenVault.Claim(eigenPointsId, 2e18, 1, empty), vitalik);

        assertEq(rewardToken.balanceOf(vitalik), 1);
        // Even the smallest redemption results in a burn.
        assertEq(pointTokenVault.pTokens(eigenPointsId).balanceOf(vitalik), 1e18 - 1);
    }

    function test_RedeemRewardsWith6DecimalToken() public {
        // Setup a mock 6-decimal token (like USDC)
        MockERC20 usdcReward = new MockERC20("USDC Reward", "USDC", 6);

        // Mint 1,000,000 USDC to the vault
        usdcReward.mint(address(pointTokenVault), 1_000_000 * 1e6);

        // Set redemption parameters (1 pToken = 1 USDC)
        vm.prank(operator);
        pointTokenVault.setRedemption(eigenPointsId, usdcReward, 1e18, false);

        // Mint 1 pToken to vitalik
        vm.startPrank(address(pointTokenVault));
        pointTokenVault.pTokens(eigenPointsId).mint(vitalik, 1e18);
        vm.stopPrank();

        // Vitalik redeems 1 pToken for 1 USDC
        vm.prank(vitalik);
        pointTokenVault.redeemRewards(PointTokenVault.Claim(eigenPointsId, 1e6, 1e6, new bytes32[](0)), vitalik);

        // Check balances
        assertEq(usdcReward.balanceOf(vitalik), 1e6, "Vitalik should receive 1 USDC");
        assertEq(pointTokenVault.pTokens(eigenPointsId).balanceOf(vitalik), 0, "Vitalik should have 0 pTokens left");
    }

    event RewardsClaimed(
        address indexed owner, address indexed receiver, bytes32 indexed pointsId, uint256 amount, uint256 tax
    );

    function test_MerkleBasedRedemption() public {
        bytes32 root = 0x409fd0e46d8453765fb513ae35a1899d667478c40233b67360023c86927eb802;

        bytes32[] memory validProofVitalikPToken = new bytes32[](2);
        validProofVitalikPToken[0] = 0x6d0fcb8de12b1f57f81e49fa18b641487b932cdba4f064409fde3b05d3824ca2;
        validProofVitalikPToken[1] = 0xae126f1299213c869259b52ab24f7270f3cce1de54c187271c52373d8947c2fe;

        // Set up the Merkle root and redemption parameters
        vm.prank(merkleUpdater);
        pointTokenVault.updateRoot(root);
        vm.prank(operator);
        pointTokenVault.setRedemption(eigenPointsId, rewardToken, 2e18, true); // Set isMerkleBased true

        // Mint tokens and distribute
        vm.prank(admin);
        rewardToken.mint(address(pointTokenVault), 5e18); // Ensure enough rewards are in the vault

        // Vitalik redeems with a valid proof
        vm.prank(vitalik);
        pointTokenVault.claimPTokens(
            PointTokenVault.Claim(eigenPointsId, 1e18, 1e18, validProofVitalikPToken), vitalik, vitalik
        );

        // Redeem the tokens for rewards with the wrong proof should fail
        bytes32[] memory empty = new bytes32[](0);
        vm.prank(vitalik);
        vm.expectRevert(PointTokenVault.ProofInvalidOrExpired.selector);
        pointTokenVault.redeemRewards(PointTokenVault.Claim(eigenPointsId, 2e18, 2e18, empty), vitalik);

        bytes32[] memory validProofVitalikRedemption = new bytes32[](1);
        validProofVitalikRedemption[0] = 0x4e40a10ce33f33a4786960a8bb843fe0e170b651acd83da27abc97176c4bed3c;

        // Redeem the tokens for rewards with the right proof should succeed
        vm.prank(vitalik);
        vm.expectEmit(true, true, true, true);
        emit RewardsClaimed(vitalik, vitalik, eigenPointsId, 2e18, 0);
        pointTokenVault.redeemRewards(
            PointTokenVault.Claim(eigenPointsId, 2e18, 2e18, validProofVitalikRedemption), vitalik
        );

        assertEq(rewardToken.balanceOf(vitalik), 2e18);
    }

    function test_PartialClaim() public {
        bytes32[] memory proof = new bytes32[](1);
        proof[0] = 0x6d0fcb8de12b1f57f81e49fa18b641487b932cdba4f064409fde3b05d3824ca2;
        bytes32 root = 0x4e40a10ce33f33a4786960a8bb843fe0e170b651acd83da27abc97176c4bed3c;

        vm.prank(merkleUpdater);
        pointTokenVault.updateRoot(root);

        // Can do a partial claim
        vm.prank(vitalik);
        pointTokenVault.claimPTokens(PointTokenVault.Claim(eigenPointsId, 1e18, 0.5e18, proof), vitalik, vitalik);

        assertEq(pointTokenVault.pTokens(eigenPointsId).balanceOf(vitalik), 0.5e18);

        // Can only claim the remainder, no more
        vm.prank(vitalik);
        vm.expectRevert(PointTokenVault.ClaimTooLarge.selector);
        pointTokenVault.claimPTokens(PointTokenVault.Claim(eigenPointsId, 1e18, 0.75e18, proof), vitalik, vitalik);

        // Can claim the rest
        vm.prank(vitalik);
        pointTokenVault.claimPTokens(PointTokenVault.Claim(eigenPointsId, 1e18, 0.5e18, proof), vitalik, vitalik);

        assertEq(pointTokenVault.pTokens(eigenPointsId).balanceOf(vitalik), 1e18);
    }

    function test_TrustedReceiver() public {
        bytes32 root = 0x4e40a10ce33f33a4786960a8bb843fe0e170b651acd83da27abc97176c4bed3c;

        bytes32[] memory proof = new bytes32[](1);
        proof[0] = 0x6d0fcb8de12b1f57f81e49fa18b641487b932cdba4f064409fde3b05d3824ca2;

        vm.prank(merkleUpdater);
        pointTokenVault.updateRoot(root);

        // Toly tries to claim vitalik's pTokens (should fail)
        vm.prank(toly);
        vm.expectRevert(PointTokenVault.NotTrustedReceiver.selector);
        pointTokenVault.claimPTokens(PointTokenVault.Claim(eigenPointsId, 1e18, 0.6e18, proof), vitalik, toly);

        // Vitalik delegates claiming rights to Toly
        vm.prank(vitalik);
        pointTokenVault.trustReceiver(toly, true);

        // Toly claims the half of Vitalik's pTokens
        vm.prank(toly);
        pointTokenVault.claimPTokens(PointTokenVault.Claim(eigenPointsId, 1e18, 0.5e18, proof), vitalik, toly);

        // Check balances
        assertEq(pointTokenVault.pTokens(eigenPointsId).balanceOf(toly), 0.5e18);
        assertEq(pointTokenVault.pTokens(eigenPointsId).balanceOf(vitalik), 0);

        // Vitalik claims the remaining amount for himself
        vm.prank(vitalik);
        pointTokenVault.claimPTokens(PointTokenVault.Claim(eigenPointsId, 1e18, 0.5e18, proof), vitalik, vitalik);

        // Check final balances
        assertEq(pointTokenVault.pTokens(eigenPointsId).balanceOf(toly), 0.5e18);
        assertEq(pointTokenVault.pTokens(eigenPointsId).balanceOf(vitalik), 0.5e18);
    }

    event RewardsConverted(address indexed owner, address indexed receiver, bytes32 indexed pointsId, uint256 amount);

    function test_ConvertRewardsToPTokens() public {
        bytes32 root = 0x4e40a10ce33f33a4786960a8bb843fe0e170b651acd83da27abc97176c4bed3c;

        bytes32[] memory proof = new bytes32[](1);
        proof[0] = 0x6d0fcb8de12b1f57f81e49fa18b641487b932cdba4f064409fde3b05d3824ca2;

        vm.prank(merkleUpdater);
        pointTokenVault.updateRoot(root);

        vm.prank(vitalik);
        pointTokenVault.claimPTokens(PointTokenVault.Claim(eigenPointsId, 1e18, 1e18, proof), vitalik, vitalik);

        rewardToken.mint(address(pointTokenVault), 3e18);

        // Cannot redeem pTokens or convert rewards before redemption data is set
        bytes32[] memory empty = new bytes32[](0);
        vm.expectRevert(PointTokenVault.RewardsNotLive.selector);
        pointTokenVault.redeemRewards(PointTokenVault.Claim(eigenPointsId, 2e18, 2e18, empty), vitalik);
        vm.expectRevert(PointTokenVault.RewardsNotLive.selector);
        pointTokenVault.convertRewardsToPTokens(vitalik, eigenPointsId, 1e18);

        vm.prank(operator);
        pointTokenVault.setRedemption(eigenPointsId, rewardToken, 2e18, false);

        vm.prank(vitalik);
        pointTokenVault.redeemRewards(PointTokenVault.Claim(eigenPointsId, 2e18, 2e18, empty), vitalik);

        assertEq(rewardToken.balanceOf(vitalik), 2e18);
        assertEq(pointTokenVault.pTokens(eigenPointsId).balanceOf(vitalik), 0);

        // Mint pTokens with reward tokens
        vm.prank(vitalik);
        rewardToken.approve(address(pointTokenVault), 1e18);
        vm.prank(vitalik);
        vm.expectEmit(true, true, true, true);
        emit RewardsConverted(vitalik, vitalik, eigenPointsId, 1e18);
        pointTokenVault.convertRewardsToPTokens(vitalik, eigenPointsId, 1e18);

        assertEq(rewardToken.balanceOf(vitalik), 1e18);
        assertEq(pointTokenVault.pTokens(eigenPointsId).balanceOf(vitalik), 0.5e18);

        // Can go the other way again
        vm.prank(vitalik);
        pointTokenVault.redeemRewards(PointTokenVault.Claim(eigenPointsId, 1e18, 1e18, empty), vitalik);

        assertEq(rewardToken.balanceOf(vitalik), 2e18);
        assertEq(pointTokenVault.pTokens(eigenPointsId).balanceOf(vitalik), 0);
    }

    function test_ConvertRewardsToPTokensWith6DecimalToken() public {
        // Setup a mock 6-decimal token (like USDC)
        MockERC20 usdcReward = new MockERC20("USDC Reward", "USDC", 6);

        // Mint 1,000,000 USDC to vitalik
        usdcReward.mint(vitalik, 1_000_000 * 1e6);

        // Set redemption parameters (1 pToken = 1 USDC)
        vm.prank(operator);
        pointTokenVault.setRedemption(eigenPointsId, usdcReward, 1e18, false);

        // Approve USDC spend
        vm.prank(vitalik);
        usdcReward.approve(address(pointTokenVault), type(uint256).max);

        // Vitalik converts 1 USDC to 1 pToken
        vm.prank(vitalik);
        pointTokenVault.convertRewardsToPTokens(vitalik, eigenPointsId, 1e6);

        // Check balances
        assertEq(usdcReward.balanceOf(vitalik), 999_999 * 1e6, "Vitalik should have 999,999 USDC left");
        assertEq(pointTokenVault.pTokens(eigenPointsId).balanceOf(vitalik), 1e18, "Vitalik should receive 1 pToken");
    }

    event FeeCollectorSet(address feeCollector);

    function test_setFeeCollector() public {
        vm.prank(admin);
        vm.expectEmit(true, true, true, true);
        emit FeeCollectorSet(toly);
        pointTokenVault.setFeeCollector(toly);

        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector,
                address(vitalik),
                pointTokenVault.DEFAULT_ADMIN_ROLE()
            )
        );
        vm.prank(vitalik);
        pointTokenVault.setFeeCollector(vitalik);
    }

    event FeesCollected(
        bytes32 indexed pointsId, address indexed feeCollector, uint256 pTokenFee, uint256 rewardTokenFee
    );

    function test_FeeCollectionNoRedemptionFee() public {
        bytes32 root = 0x4e40a10ce33f33a4786960a8bb843fe0e170b651acd83da27abc97176c4bed3c;

        bytes32[] memory proof = new bytes32[](1);
        proof[0] = 0x6d0fcb8de12b1f57f81e49fa18b641487b932cdba4f064409fde3b05d3824ca2;

        vm.prank(merkleUpdater);
        pointTokenVault.updateRoot(root);

        // Set mint fee to 10%
        vm.prank(operator);
        pointTokenVault.setMintFee(0.1e18); // 10% in WAD

        // Claim pTokens
        vm.prank(vitalik);
        pointTokenVault.claimPTokens(PointTokenVault.Claim(eigenPointsId, 1e18, 1e18, proof), vitalik, vitalik);

        assertEq(pointTokenVault.pTokenFeeAcc(eigenPointsId), 0.1e18);
        assertEq(pointTokenVault.pTokens(eigenPointsId).balanceOf(vitalik), 0.9e18);

        // Set up redemption
        rewardToken.mint(address(pointTokenVault), 3e18);
        vm.prank(operator);
        pointTokenVault.setRedemption(eigenPointsId, rewardToken, 2e18, false);

        // Set redemption fee to 5%
        vm.prank(operator);
        pointTokenVault.setRedemptionFee(0.05e18); // 5% in WAD

        // Redeem rewards
        bytes32[] memory empty = new bytes32[](0);
        vm.prank(vitalik);
        pointTokenVault.redeemRewards(PointTokenVault.Claim(eigenPointsId, 1.8e18, 1.8e18, empty), vitalik);

        // Collect fees
        vm.expectEmit(true, true, true, true);
        emit FeesCollected(eigenPointsId, pointTokenVault.feeCollector(), 0.1e18, 0e18); // No redemption fees
        pointTokenVault.collectFees(eigenPointsId);

        // Check balances after fee collection
        assertEq(pointTokenVault.pTokens(eigenPointsId).balanceOf(pointTokenVault.feeCollector()), 0.1e18);
        assertEq(rewardToken.balanceOf(pointTokenVault.feeCollector()), 0);

        // Check that fee accumulators are reset
        assertEq(pointTokenVault.pTokenFeeAcc(eigenPointsId), 0);
        assertEq(pointTokenVault.rewardTokenFeeAcc(eigenPointsId), 0);
    }

    function test_FeeCollectionRedemptionFee() public {
        bytes32 root = 0x4e40a10ce33f33a4786960a8bb843fe0e170b651acd83da27abc97176c4bed3c;

        bytes32[] memory proof = new bytes32[](1);
        proof[0] = 0x6d0fcb8de12b1f57f81e49fa18b641487b932cdba4f064409fde3b05d3824ca2;

        vm.prank(merkleUpdater);
        pointTokenVault.updateRoot(root);

        // Set mint fee to 10%
        vm.prank(operator);
        pointTokenVault.setMintFee(0.1e18); // 10% in WAD

        // Claim pTokens
        vm.prank(vitalik);
        pointTokenVault.claimPTokens(PointTokenVault.Claim(eigenPointsId, 1e18, 1e18, proof), vitalik, vitalik);

        vm.startPrank(vitalik);
        pointTokenVault.pTokens(eigenPointsId).transfer(toly, 0.9e18);
        vm.stopPrank();

        assertEq(pointTokenVault.pTokenFeeAcc(eigenPointsId), 0.1e18);
        assertEq(pointTokenVault.pTokens(eigenPointsId).balanceOf(toly), 0.9e18);

        // Set up redemption
        rewardToken.mint(address(pointTokenVault), 3e18);
        vm.prank(operator);
        pointTokenVault.setRedemption(eigenPointsId, rewardToken, 2e18, false);

        // Set redemption fee to 5%
        vm.prank(operator);
        pointTokenVault.setRedemptionFee(0.05e18); // 5% in WAD

        // Redeem rewards
        bytes32[] memory empty = new bytes32[](0);
        vm.prank(toly);
        pointTokenVault.redeemRewards(PointTokenVault.Claim(eigenPointsId, 1.8e18, 1.8e18, empty), toly);

        // Unset redemption
        vm.prank(operator);
        pointTokenVault.setRedemption(eigenPointsId, ERC20(address(0)), 0, false);

        // No reward token fees are collected.
        vm.expectEmit(true, true, true, true);
        emit FeesCollected(eigenPointsId, pointTokenVault.feeCollector(), 0.1e18, 0);
        pointTokenVault.collectFees(eigenPointsId);
        assertEq(rewardToken.balanceOf(pointTokenVault.feeCollector()), 0);

        // Set redemption again
        vm.prank(operator);
        pointTokenVault.setRedemption(eigenPointsId, rewardToken, 2e18, false);

        // Collect fees
        vm.expectEmit(true, true, true, true);
        emit FeesCollected(eigenPointsId, pointTokenVault.feeCollector(), 0, 0.09e18);
        pointTokenVault.collectFees(eigenPointsId);

        // Check balances after fee collection
        assertEq(pointTokenVault.pTokens(eigenPointsId).balanceOf(pointTokenVault.feeCollector()), 0.1e18);
        assertEq(rewardToken.balanceOf(pointTokenVault.feeCollector()), 0.09e18);

        // Check that fee accumulators are reset
        assertEq(pointTokenVault.pTokenFeeAcc(eigenPointsId), 0);
        assertEq(pointTokenVault.rewardTokenFeeAcc(eigenPointsId), 0);
    }

    function test_CantMintPTokensForRewardsMerkleBased() public {
        bool IS_MERKLE_BASED = true;

        bytes32 root = 0x409fd0e46d8453765fb513ae35a1899d667478c40233b67360023c86927eb802;

        bytes32[] memory proof = new bytes32[](2);
        proof[0] = 0x6d0fcb8de12b1f57f81e49fa18b641487b932cdba4f064409fde3b05d3824ca2;
        proof[1] = 0xae126f1299213c869259b52ab24f7270f3cce1de54c187271c52373d8947c2fe;

        vm.prank(merkleUpdater);
        pointTokenVault.updateRoot(root);

        vm.prank(vitalik);
        pointTokenVault.claimPTokens(PointTokenVault.Claim(eigenPointsId, 1e18, 1e18, proof), vitalik, vitalik);

        rewardToken.mint(address(pointTokenVault), 3e18);

        vm.prank(operator);
        pointTokenVault.setRedemption(eigenPointsId, rewardToken, 2e18, IS_MERKLE_BASED);

        bytes32[] memory redemptionProof = new bytes32[](1);
        redemptionProof[0] = 0x4e40a10ce33f33a4786960a8bb843fe0e170b651acd83da27abc97176c4bed3c;
        vm.prank(vitalik);
        pointTokenVault.redeemRewards(PointTokenVault.Claim(eigenPointsId, 2e18, 2e18, redemptionProof), vitalik);

        assertEq(rewardToken.balanceOf(vitalik), 2e18);
        assertEq(pointTokenVault.pTokens(eigenPointsId).balanceOf(vitalik), 0);

        // Can't mint ptokens if it's a merkle-based redemption
        vm.prank(vitalik);
        rewardToken.approve(address(pointTokenVault), 1e18);
        vm.prank(vitalik);
        vm.expectRevert(PointTokenVault.CantConvertMerkleRedemption.selector);
        pointTokenVault.convertRewardsToPTokens(vitalik, eigenPointsId, 1e18);
    }

    function test_CantMintPTokensForRewardsAmountTooSmall() public {
        bytes32 root = 0x4e40a10ce33f33a4786960a8bb843fe0e170b651acd83da27abc97176c4bed3c;

        bytes32[] memory proof = new bytes32[](1);
        proof[0] = 0x6d0fcb8de12b1f57f81e49fa18b641487b932cdba4f064409fde3b05d3824ca2;

        vm.prank(merkleUpdater);
        pointTokenVault.updateRoot(root);

        vm.prank(vitalik);
        pointTokenVault.claimPTokens(PointTokenVault.Claim(eigenPointsId, 1e18, 1e18, proof), vitalik, vitalik);

        rewardToken.mint(address(pointTokenVault), 3e18);

        vm.prank(operator);
        pointTokenVault.setRedemption(eigenPointsId, rewardToken, 2e18, false);

        bytes32[] memory empty = new bytes32[](0);
        vm.prank(vitalik);
        pointTokenVault.redeemRewards(PointTokenVault.Claim(eigenPointsId, 2e18, 2e18, empty), vitalik);

        assertEq(rewardToken.balanceOf(vitalik), 2e18);
        assertEq(pointTokenVault.pTokens(eigenPointsId).balanceOf(vitalik), 0);

        // Can't mint ptokens if the amount is too small
        vm.prank(vitalik);
        rewardToken.approve(address(pointTokenVault), 1);
        vm.prank(vitalik);
        vm.expectRevert(PointTokenVault.AmountTooSmall.selector);
        pointTokenVault.convertRewardsToPTokens(vitalik, eigenPointsId, 1);

        // Can mint anything above the absolute minimum
        vm.prank(vitalik);
        rewardToken.approve(address(pointTokenVault), 2);
        vm.prank(vitalik);
        pointTokenVault.convertRewardsToPTokens(vitalik, eigenPointsId, 2);
    }

    function test_ReceiveETH() public payable {
        // Amount of ETH to send
        uint256 amountToSend = 1 ether;

        // Record the initial balance of the PointTokenVault
        uint256 initialBalance = address(pointTokenVault).balance;

        // Send ETH to the PointTokenVault
        (bool sent,) = address(pointTokenVault).call{value: 1 ether}("");
        require(sent, "Failed to send Ether");

        // Check the new balance of the PointTokenVault
        uint256 newBalance = address(pointTokenVault).balance;
        assertEq(newBalance, initialBalance + amountToSend);
    }

    function test_PTokenNotDeployed() public {
        // Deploy new instance of vault (without pToken deployed)
        PointTokenVault mockVault = _deployAdditionalVault();

        bytes32 root = 0x4e40a10ce33f33a4786960a8bb843fe0e170b651acd83da27abc97176c4bed3c;
        bytes32[] memory proof = new bytes32[](1);
        proof[0] = 0x6d0fcb8de12b1f57f81e49fa18b641487b932cdba4f064409fde3b05d3824ca2;

        vm.prank(merkleUpdater);
        mockVault.updateRoot(root);

        // Cannot claim if pToken hasn't been deployed yet
        vm.prank(vitalik);
        vm.expectRevert(PointTokenVault.PTokenNotDeployed.selector);
        mockVault.claimPTokens(PointTokenVault.Claim(eigenPointsId, 1e18, 1e18, proof), vitalik, vitalik);
    }

    function test_PTokenPause() public {
        bytes32 root = 0x4e40a10ce33f33a4786960a8bb843fe0e170b651acd83da27abc97176c4bed3c;

        bytes32[] memory proof = new bytes32[](1);
        proof[0] = 0x6d0fcb8de12b1f57f81e49fa18b641487b932cdba4f064409fde3b05d3824ca2;

        vm.prank(merkleUpdater);
        pointTokenVault.updateRoot(root);

        vm.prank(vitalik);
        pointTokenVault.claimPTokens(PointTokenVault.Claim(eigenPointsId, 1e18, 1e18, proof), vitalik, vitalik);

        PToken pToken = pointTokenVault.pTokens(eigenPointsId);

        // Pause the pToken
        vm.prank(operator);
        pointTokenVault.pausePToken(eigenPointsId);

        // Cannot transfer pTokens
        vm.prank(vitalik);
        vm.expectRevert(Pausable.EnforcedPause.selector);
        pToken.transfer(toly, 1e18);

        // Unpause the pToken
        vm.prank(operator);
        pointTokenVault.unpausePToken(eigenPointsId);

        // Can transfer pTokens
        vm.prank(vitalik);
        pToken.transfer(toly, 1e18);
    }

    function test_RenouncePauseRole() public {
        bytes32 root = 0x4e40a10ce33f33a4786960a8bb843fe0e170b651acd83da27abc97176c4bed3c;

        bytes32[] memory proof = new bytes32[](1);
        proof[0] = 0x6d0fcb8de12b1f57f81e49fa18b641487b932cdba4f064409fde3b05d3824ca2;

        vm.prank(merkleUpdater);
        pointTokenVault.updateRoot(root);

        // Deploy pToken
        vm.prank(vitalik);
        pointTokenVault.claimPTokens(PointTokenVault.Claim(eigenPointsId, 1e18, 1e18, proof), vitalik, vitalik);

        PToken pToken = pointTokenVault.pTokens(eigenPointsId);

        // Check that the operator has the PAUSE_ROLE
        assertTrue(pToken.hasRole(pToken.PAUSE_ROLE(), address(pointTokenVault)));

        // Renounce the PAUSE_ROLE
        vm.prank(operator);
        pointTokenVault.renouncePauseRole(eigenPointsId);

        // Check that the operator no longer has the PAUSE_ROLE
        assertFalse(pToken.hasRole(pToken.PAUSE_ROLE(), address(pointTokenVault)));

        // Try to pause the pToken (should fail)
        vm.startPrank(operator);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector, address(pointTokenVault), pToken.PAUSE_ROLE()
            )
        );
        pointTokenVault.pausePToken(eigenPointsId);
        vm.stopPrank();
    }

    // Internal
    function _deployAdditionalVault() internal returns (PointTokenVault mockVault) {
        PointTokenVaultScripts scripts = new PointTokenVaultScripts();

        mockVault = scripts.run("0.0.1");

        mockVault.grantRole(pointTokenVault.DEFAULT_ADMIN_ROLE(), admin);
        mockVault.grantRole(pointTokenVault.MERKLE_UPDATER_ROLE(), merkleUpdater);
        mockVault.grantRole(pointTokenVault.OPERATOR_ROLE(), operator);
        mockVault.revokeRole(pointTokenVault.DEFAULT_ADMIN_ROLE(), address(this));
    }
}

contract Echo {
    event EchoEvent(string message, address caller);

    function echo(string calldata message) public {
        emit EchoEvent(message, msg.sender);
    }
}

contract CallEcho {
    function callEcho(Echo echo, string calldata message) public {
        echo.echo(message);
    }

    function fail() public pure {
        revert("Failed");
    }
}
