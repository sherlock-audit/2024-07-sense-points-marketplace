// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

interface ISafeProxyFactory {
    function createProxyWithNonce(address _singleton, bytes memory _initializer, uint256 _saltNonce)
        external
        returns (address);
    function proxyCreationCode() external pure returns (bytes memory);
}
