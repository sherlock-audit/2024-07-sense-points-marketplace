// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity =0.8.24;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {ISafe} from "./interfaces/external/ISafe.sol";
import {ISafeProxyFactory} from "./interfaces/external/ISafeProxyFactory.sol";
import {InitializationScript} from "./InitializationScript.sol";

/// @notice Factory to create Rumpel Wallets; Safes with the Rumpel Guard and Rumpel Module added on.
contract RumpelWalletFactory is Ownable, Pausable {
    mapping(address => uint256) public saltNonce;

    ISafeProxyFactory public proxyFactory;
    address public compatibilityFallback;
    address public safeSingleton;
    address public rumpelModule;
    address public rumpelGuard;
    address public initializationScript;

    event SafeCreated(address indexed safe, address[] indexed owners, uint256 threshold);
    event ParamChanged(bytes32 what, address data);

    error UnrecognizedParam(bytes32 what);

    constructor(
        ISafeProxyFactory _proxyFactory,
        address _compatibilityFallback,
        address _safeSingleton,
        address _rumpelModule,
        address _rumpelGuard,
        address _initializationScript
    ) Ownable(msg.sender) {
        proxyFactory = _proxyFactory;
        compatibilityFallback = _compatibilityFallback;
        safeSingleton = _safeSingleton;
        rumpelModule = _rumpelModule;
        rumpelGuard = _rumpelGuard;
        initializationScript = _initializationScript;
    }

    /// @notice Create a Safe with the Rumpel Module and Rumpel Guard added.
    function createWallet(
        address[] calldata owners,
        uint256 threshold,
        InitializationScript.InitCall[] calldata initCalls
    ) external whenNotPaused returns (address) {
        // Calculate a unique salt based on the sender's address and nonce.
        uint256 salt = uint256(keccak256(abi.encodePacked(msg.sender, saltNonce[msg.sender]++)));

        address safe = proxyFactory.createProxyWithNonce(
            safeSingleton,
            abi.encodeWithSelector(
                ISafe.setup.selector,
                owners,
                threshold,
                initializationScript, // Contract with initialization logic
                abi.encodeWithSelector(InitializationScript.initialize.selector, rumpelModule, rumpelGuard, initCalls), // Add module and guard + initial calls
                compatibilityFallback, // fallbackHandler
                address(0), // paymentToken
                0, // payment
                address(0) // paymentReceiver
            ),
            salt // For deterministic address generation
        );

        emit SafeCreated(safe, owners, threshold);

        return safe;
    }

    function precomputeAddress(bytes memory _initializer, address _sender, uint256 _saltNonce)
        external
        view
        returns (address)
    {
        bytes32 salt = keccak256(
            abi.encodePacked(keccak256(_initializer), uint256(keccak256(abi.encodePacked(_sender, _saltNonce))))
        );

        bytes memory deploymentData =
            abi.encodePacked(proxyFactory.proxyCreationCode(), uint256(uint160(safeSingleton)));

        bytes32 deploymentHash =
            keccak256(abi.encodePacked(bytes1(0xff), address(proxyFactory), salt, keccak256(deploymentData)));

        return address(uint160(uint256(deploymentHash)));
    }

    // Admin ----

    /// @notice Set admin params, only callable by the owner.
    /// @dev These changes will only apply to future Safes deployed with this factory.
    function setParam(bytes32 what, address data) external onlyOwner {
        if (what == "PROXY_FACTORY") proxyFactory = ISafeProxyFactory(data);
        else if (what == "SAFE_SINGLETON") safeSingleton = data;
        else if (what == "RUMPEL_MODULE") rumpelModule = data;
        else if (what == "RUMPEL_GUARD") rumpelGuard = data;
        else if (what == "INITIALIZATION_SCRIPT") initializationScript = data;
        else if (what == "COMPATIBILITY_FALLBACK") compatibilityFallback = data;
        else revert UnrecognizedParam(what);
        emit ParamChanged(what, data);
    }

    function pauseWalletCreation() external onlyOwner {
        _pause();
    }

    function unpauseWalletCreation() external onlyOwner {
        _unpause();
    }
}
