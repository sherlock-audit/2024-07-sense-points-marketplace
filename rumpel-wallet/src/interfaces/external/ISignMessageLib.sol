// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

interface ISignMessageLib {
    function signMessage(bytes calldata digest) external;
}
