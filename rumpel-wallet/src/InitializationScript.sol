// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity =0.8.24;

import {ISafe} from "./interfaces/external/ISafe.sol";
import {Enum} from "./interfaces/external/ISafe.sol";
import {RumpelGuard} from "./RumpelGuard.sol";

/// @notice Delegatecall script to initialize Safes.
contract InitializationScript {
    error InitializationFailed();

    event InitialCall(address to, bytes data);

    struct InitCall {
        address to;
        bytes data;
    }

    /// @notice This function is called via delegatecall by newly created Safes.
    function initialize(address module, address guard, InitCall[] memory initCalls) external {
        ISafe safe = ISafe(address(this));
        safe.enableModule(module);
        safe.setGuard(guard);

        // Arbitrary initial calls.
        for (uint256 i = 0; i < initCalls.length; i++) {
            address to = initCalls[i].to;
            bytes memory data = initCalls[i].data;

            // Check each tx with the guard.
            RumpelGuard(guard).checkTransaction(
                to, 0, data, Enum.Operation.Call, 0, 0, 0, address(0), payable(address(0)), bytes(""), address(0)
            );

            bool success;
            assembly {
                success := call(sub(gas(), 500), to, 0, add(data, 0x20), mload(data), 0, 0)
            }

            if (!success) revert InitializationFailed();

            emit InitialCall(to, data);
        }
    }
}
