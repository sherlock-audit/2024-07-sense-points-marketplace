// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity =0.8.24;

interface ISignMessageLib {
    function signMessage(bytes calldata digest) external;
}
