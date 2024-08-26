// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

import {Enum} from "./interfaces/external/ISafe.sol";
import {ISafe} from "./interfaces/external/ISafe.sol";

/// @notice Rumpel Safe Module allowing an admin to execute calls on behalf of the Safe.
contract RumpelModule is Ownable {
    mapping(address => mapping(bytes4 => bool)) public blockedModuleCalls; // target => functionSelector => blocked
    address public immutable signMessageLib;

    struct Call {
        ISafe safe;
        address to;
        uint256 value;
        bytes data;
        Enum.Operation operation;
    }

    event ExecutionFromModule(ISafe indexed safe, address indexed target, uint256 value, bytes data);
    event SetModuleCallBlocked(address indexed target, bytes4 indexed functionSelector);

    error ExecFailed(ISafe safe, address target, bytes data);
    error CallBlocked(address target, bytes4 functionSelector);

    constructor(address _signMessageLib) Ownable(msg.sender) {
        signMessageLib = _signMessageLib;
    }

    /// @notice Execute a series of calls through Safe contracts.
    /// @param calls An array of Call structs containing the details of each call to be executed.
    function exec(Call[] calldata calls) external onlyOwner {
        for (uint256 i = 0; i < calls.length;) {
            Call calldata call = calls[i];
            bool blockedCall = blockedModuleCalls[call.to][bytes4(call.data)];
            bool toSafe = address(call.safe) == call.to;

            // If this transaction is to a Safe itself, to e.g. update config, we check the zero address for blocked calls.
            if (blockedCall || (toSafe && blockedModuleCalls[address(0)][bytes4(call.data)])) {
                revert CallBlocked(call.to, bytes4(call.data));
            }

            // Only allow delegatecalls to the signMessageLib.
            if (call.operation == Enum.Operation.DelegateCall) {
                if (call.to != signMessageLib) {
                    revert CallBlocked(call.to, bytes4(call.data));
                }
            }

            bool success = call.safe.execTransactionFromModule(call.to, call.value, call.data, call.operation);

            if (!success) {
                revert ExecFailed(call.safe, call.to, call.data);
            }

            emit ExecutionFromModule(call.safe, call.to, call.value, call.data);

            unchecked {
                ++i;
            }
        }
    }

    /// @notice Prevent call from being executed via the module permanently. Useful as an assurance that e.g. an admin will never transfer a user's USDC.
    /// @dev Scoped to <address>.<selector>, so all calls to added address <> selector pairs are blocked.
    /// @dev To block calls to arbitrary Safes, to prevent an admin from updating config, the Zero address is used for the target.
    function addBlockedModuleCall(address target, bytes4 functionSelector) external onlyOwner {
        blockedModuleCalls[target][functionSelector] = true;
        emit SetModuleCallBlocked(target, functionSelector);
    }
}
