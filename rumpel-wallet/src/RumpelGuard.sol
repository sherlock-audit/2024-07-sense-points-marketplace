// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity =0.8.24;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

import {Enum} from "./interfaces/external/ISafe.sol";
import {IGuard} from "./interfaces/external/IGuard.sol";

/// @notice Rumpel Safe Guard with a blocklist for the Rumpel Wallet.
/// @dev Compatible with Safe v1.3.0-libs.0, the last Safe Ethereum mainnet release, so it can't use module execution hooks.
contract RumpelGuard is Ownable, IGuard {
    mapping(address => mapping(bytes4 => AllowListState)) public allowedCalls; // target => functionSelector => allowListState

    address public immutable signMessageLib;

    enum AllowListState {
        OFF,
        ON,
        PERMANENTLY_ON
    }

    event SetCallAllowed(address indexed target, bytes4 indexed functionSelector, AllowListState allowListState);

    error CallNotAllowed(address target, bytes4 functionSelector);
    error PermanentlyOn();

    constructor(address _signMessageLib) Ownable(msg.sender) {
        signMessageLib = _signMessageLib;
    }

    /// @notice Called by the Safe contract before a transaction is executed.
    /// @dev Safe user execution hook that blocks all calls by default, including delegatecalls, unless explicitly added to the allowlist.
    function checkTransaction(
        address to,
        uint256,
        bytes memory data,
        Enum.Operation operation,
        uint256,
        uint256,
        uint256,
        address,
        address payable,
        bytes memory,
        address
    ) external view {
        // Disallow calls with function selectors that will be padded with 0s.
        // Allow calls with data length 0 for ETH transfers.
        if (data.length > 0 && data.length < 4) {
            revert CallNotAllowed(to, bytes4(data));
        }

        bytes4 functionSelector = bytes4(data);

        // Only allow delegatecalls to the signMessageLib.
        if (operation == Enum.Operation.DelegateCall) {
            if (to == signMessageLib) {
                return;
            } else {
                revert CallNotAllowed(to, functionSelector);
            }
        }

        bool toSafe = msg.sender == to;

        if (toSafe) {
            // If this transaction is to a Safe itself, to e.g. update config, we check the zero address for allowed calls.
            if (allowedCalls[address(0)][functionSelector] == AllowListState.OFF) {
                revert CallNotAllowed(to, functionSelector);
            }
        } else if (data.length == 0) {
            // If this transaction is a simple ETH transfer, we check the zero address with the zero function selector to see if it's allowed.
            if (allowedCalls[address(0)][bytes4(0)] == AllowListState.OFF) {
                revert CallNotAllowed(address(0), bytes4(0));
            }
        } else {
            // For all other calls, we check the allowedCalls mapping normally.
            if (allowedCalls[to][functionSelector] == AllowListState.OFF) {
                revert CallNotAllowed(to, functionSelector);
            }
        }
    }

    /// @notice Called by the Safe contract after a transaction is executed.
    /// @dev No-op.
    function checkAfterExecution(bytes32, bool) external view {}

    function supportsInterface(bytes4 interfaceId) public view returns (bool) {
        return interfaceId == type(IGuard).interfaceId;
    }

    // Admin ----

    /// @notice Enable or disable Safes from calling a function.
    /// @dev Scoped to <address>.<selector>, so all calls to added address <> selector pairs are allowed.
    /// @dev Function arguments aren't checked, so any arguments are allowed for the enabled functions.
    /// @dev Calls can be enabled, disabled, or permanently enabled, that last of which guarantees the call can't be rugged.
    function setCallAllowed(address target, bytes4 functionSelector, AllowListState allowListState)
        external
        onlyOwner
    {
        if (allowedCalls[target][functionSelector] == AllowListState.PERMANENTLY_ON) {
            revert PermanentlyOn();
        }

        allowedCalls[target][functionSelector] = allowListState;
        emit SetCallAllowed(target, functionSelector, allowListState);
    }
}
