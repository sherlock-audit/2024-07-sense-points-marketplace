pragma solidity ^0.8.13;

import {Test, console, console2} from "forge-std/Test.sol";

import {MockPointTokenVault} from "../mock/MockPointTokenVault.sol";
import {MockPointTokenVaultScripts} from "../mock/script/MockPointTokenVault.s.sol";

import {PointTokenVaultHandler} from "./handlers/PointTokenVaultHandler.sol";

import {MockERC20} from "solmate/test/utils/mocks/MockERC20.sol";

contract PointTokenVaultInvariants is Test {
    PointTokenVaultHandler handler;
    
    MockPointTokenVault pointTokenVault;

    function setUp() public {
        // Mock vault bypasses merkle validation to allow for fuzzing.
        // Merkle validation is tested in PointTokenVault.t.sol
        MockPointTokenVaultScripts scripts = new MockPointTokenVaultScripts();

        // Deploy the PointTokenVault
        pointTokenVault = scripts.run("0.0.1");
        address[3] memory admins = [
            makeAddr("admin"),
            makeAddr("operator"),
            makeAddr("merkleUpdater")
        ];

        pointTokenVault.grantRole(pointTokenVault.DEFAULT_ADMIN_ROLE(), admins[0]);
        pointTokenVault.grantRole(pointTokenVault.MERKLE_UPDATER_ROLE(), admins[2]);
        pointTokenVault.grantRole(pointTokenVault.OPERATOR_ROLE(), admins[1]);
        pointTokenVault.revokeRole(pointTokenVault.DEFAULT_ADMIN_ROLE(), address(this));

        handler = new PointTokenVaultHandler(
            pointTokenVault,
            admins
        );

        bytes4[] memory selectors = new bytes4[](5);
        selectors[0] = handler.deposit.selector;
        selectors[1] = handler.withdraw.selector;
        selectors[2] = handler.claimPTokens.selector;
        selectors[3] = handler.redeem.selector;
        selectors[4] = handler.convertRewardsToPTokens.selector;

        targetSelector(
            FuzzSelector({
                addr: address(handler),
                selectors: selectors
            })
        );

        targetContract(address(handler));
    }

    function invariant_point_earning_token_balances_remain_accurate_over_time() public view {
        require(handler.checkPointEarningTokenGhosts(), "local pointsEarningTokens balances do not match balances stored in contract");
    }

    function invariant_claimed_ptoken_balances_remain_accurate_over_time() public view {
        require(handler.checkClaimedPTokensGhosts(), "local claimed pTokens balances do not match balances stored in contract");
    }

    function invariant_ptoken_total_supplies_equal_sum_of_balances() public view {
        require(handler.checkSumOfPTokenBalances(), "sum of a pToken's balances does not equal its total supply");
    }
}