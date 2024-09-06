// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity =0.8.24;

interface ISafeProxyFactory {
    function createProxyWithNonce(address _singleton, bytes memory _initializer, uint256 _saltNonce)
        external
        returns (address);
    function proxyCreationCode() external pure returns (bytes memory);
}
