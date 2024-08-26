// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import {Test, console} from "forge-std/Test.sol";
import {MockERC20} from "solmate/test/utils/mocks/MockERC20.sol";
import {ERC20} from "solmate/tokens/ERC20.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {PointTokenVault, LibString} from "point-tokenization-vault/PointTokenVault.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {RumpelWalletFactory} from "../src/RumpelWalletFactory.sol";
import {RumpelGuard} from "../src/RumpelGuard.sol";
import {InitializationScript} from "../src/InitializationScript.sol";
import {RumpelModule} from "../src/RumpelModule.sol";

import {ISafe, Enum} from "../src/interfaces/external/ISafe.sol";
import {ISafeProxyFactory} from "../src/interfaces/external/ISafeProxyFactory.sol";
import {ISignMessageLib} from "../src/interfaces/external/ISignMessageLib.sol";
import {RumpelWalletFactoryScripts} from "../script/RumpelWalletFactory.s.sol";

contract RumpelWalletTest is Test {
    RumpelWalletFactory public rumpelWalletFactory;
    RumpelModule public rumpelModule;
    InitializationScript public initializationScript;
    RumpelGuard public rumpelGuard;
    Counter public counter;
    MockERC20 public mockToken;

    // Mainnet addresses
    ISafeProxyFactory public PROXY_FACTORY = ISafeProxyFactory(0xa6B71E26C5e0845f74c812102Ca7114b6a896AB2);
    address public SAFE_SINGLETON = 0xd9Db270c1B5E3Bd161E8c8503c55cEABeE709552;
    address public RUMPEL_VAULT = 0x1EeEBa76f211C4Dce994b9c5A74BDF25DB649Fa1;
    address public POINT_TOKENIZATION_VAULT = 0x1EeEBa76f211C4Dce994b9c5A74BDF25DB649Fa1;

    address alice;
    uint256 alicePk;

    address admin = makeAddr("admin");

    struct SafeTX {
        address to;
        uint256 value;
        bytes data;
        Enum.Operation operation;
    }

    function setUp() public {
        (alice, alicePk) = makeAddrAndKey("alice");

        RumpelWalletFactoryScripts scripts = new RumpelWalletFactoryScripts();

        (rumpelModule, rumpelGuard, rumpelWalletFactory) = scripts.run(admin);

        counter = new Counter();
        mockToken = new MockERC20("Mock Token", "MTKN", 18);

        string memory MAINNET_RPC_URL = vm.envString("MAINNET_RPC_URL");
        uint256 mainnetFork = vm.createFork(MAINNET_RPC_URL);
        vm.selectFork(mainnetFork);
    }

    // Factory ----

    function test_FactoryPauseUnpause() public {
        address[] memory owners = new address[](1);
        owners[0] = address(alice);

        // Pause wallet creation
        vm.prank(admin);
        rumpelWalletFactory.pauseWalletCreation();

        // Attempt to create a wallet while paused
        InitializationScript.InitCall[] memory initCalls = new InitializationScript.InitCall[](0);
        vm.expectRevert(Pausable.EnforcedPause.selector);
        rumpelWalletFactory.createWallet(owners, 1, initCalls);

        // Unpause wallet creation
        vm.prank(admin);
        rumpelWalletFactory.unpauseWalletCreation();

        // Create a wallet after unpausing
        address safe = rumpelWalletFactory.createWallet(owners, 1, initCalls);
        assertTrue(safe != address(0));
    }

    function test_FactoryUpdateComponents() public {
        address newGuard = makeAddr("newGuard");
        address newModule = makeAddr("newModule");
        address newScript = makeAddr("newScript");
        address newSingleton = makeAddr("newSingleton");
        address newProxyFactory = makeAddr("newProxyFactory");

        vm.startPrank(admin);
        rumpelWalletFactory.setParam("RUMPEL_GUARD", newGuard);
        rumpelWalletFactory.setParam("RUMPEL_MODULE", newModule);
        rumpelWalletFactory.setParam("INITIALIZATION_SCRIPT", newScript);
        rumpelWalletFactory.setParam("SAFE_SINGLETON", newSingleton);
        rumpelWalletFactory.setParam("PROXY_FACTORY", newProxyFactory);
        vm.stopPrank();

        assertEq(rumpelWalletFactory.rumpelGuard(), newGuard);
        assertEq(rumpelWalletFactory.rumpelModule(), newModule);
        assertEq(rumpelWalletFactory.initializationScript(), newScript);
        assertEq(rumpelWalletFactory.safeSingleton(), newSingleton);
        assertEq(address(rumpelWalletFactory.proxyFactory()), newProxyFactory);
    }

    function testFuzz_createWalletOwners(uint256 ownersLength, uint256 threshold) public {
        ownersLength = ownersLength % 255;
        threshold = threshold % 255;

        vm.assume(ownersLength > 0);
        vm.assume(threshold > 0 && threshold <= ownersLength);
        address[] memory owners = new address[](ownersLength);
        for (uint256 i = 0; i < ownersLength; i++) {
            owners[i] = address(uint160(uint256(keccak256(abi.encodePacked(i)))));
        }

        InitializationScript.InitCall[] memory initCalls = new InitializationScript.InitCall[](0);
        ISafe safe = ISafe(rumpelWalletFactory.createWallet(owners, uint256(threshold), initCalls));

        assertEq(safe.getOwners(), owners);
    }

    function test_CreateWalletRumpelModuleEnabled() public {
        address[] memory owners = new address[](1);
        owners[0] = address(alice);

        InitializationScript.InitCall[] memory initCalls = new InitializationScript.InitCall[](0);

        ISafe safe = ISafe(rumpelWalletFactory.createWallet(owners, 1, initCalls));

        assertEq(safe.isModuleEnabled(address(rumpelModule)), true);
    }

    function test_CreateWalletDeterministicAddress() public {
        address[] memory owners = new address[](1);
        owners[0] = address(alice);

        // Prepare the initializer data
        InitializationScript.InitCall[] memory initCalls = new InitializationScript.InitCall[](0);
        bytes memory initializer = abi.encodeWithSelector(
            ISafe.setup.selector,
            owners,
            1,
            rumpelWalletFactory.initializationScript(),
            abi.encodeWithSelector(
                InitializationScript.initialize.selector,
                rumpelWalletFactory.rumpelModule(),
                rumpelWalletFactory.rumpelGuard(),
                initCalls
            ),
            rumpelWalletFactory.compatibilityFallback(),
            address(0),
            0,
            address(0)
        );

        uint256 saltNonce = 0; // First wallet for this sender
        address expectedAddress = rumpelWalletFactory.precomputeAddress(initializer, saltNonce);

        // Create the wallet
        address actualAddress = rumpelWalletFactory.createWallet(owners, 1, initCalls);

        // Check if the actual address matches the expected address
        assertEq(actualAddress, expectedAddress, "Actual address does not match expected address");

        // Verify that the contract is actually deployed at this address
        uint256 codeSize;
        assembly {
            codeSize := extcodesize(actualAddress)
        }
        assertTrue(codeSize > 0, "No contract deployed at the expected address");

        // Verify that it's a Safe by calling a Safe-specific function
        assertEq(ISafe(actualAddress).getThreshold(), 1, "Deployed contract is not a Safe or not initialized correctly");
    }

    function test_CreateWalletRumpelGuardSet() public {
        address[] memory owners = new address[](1);
        owners[0] = address(alice);

        InitializationScript.InitCall[] memory initCalls = new InitializationScript.InitCall[](0);
        ISafe safe = ISafe(rumpelWalletFactory.createWallet(owners, 1, initCalls));

        assertEq(
            address(uint160(uint256(vm.load(address(safe), keccak256("guard_manager.guard.address"))))),
            address(rumpelGuard)
        );
    }

    function test_CreateWalletCallOnDeploy() public {
        address[] memory owners = new address[](1);
        owners[0] = address(alice);

        // Call reverts if the call isn't allowed by the guard
        InitializationScript.InitCall[] memory initCalls = new InitializationScript.InitCall[](1);
        initCalls[0] =
            InitializationScript.InitCall({to: address(counter), data: abi.encodeCall(Counter.addToCount, (4337))});
        vm.expectRevert();
        rumpelWalletFactory.createWallet(owners, 1, initCalls);

        assertEq(counter.count(), 0);

        // Call reverts if the first call itself fails
        initCalls[0] = InitializationScript.InitCall({to: address(counter), data: abi.encodeCall(Counter.fail, ())});
        vm.prank(admin);
        rumpelGuard.setCallAllowed(address(counter), Counter.fail.selector, RumpelGuard.AllowListState.ON);
        vm.expectRevert();
        rumpelWalletFactory.createWallet(owners, 1, initCalls);

        vm.prank(admin);
        rumpelGuard.setCallAllowed(address(counter), Counter.addToCount.selector, RumpelGuard.AllowListState.ON);
        initCalls[0] =
            InitializationScript.InitCall({to: address(counter), data: abi.encodeCall(Counter.addToCount, (4337))});
        rumpelWalletFactory.createWallet(owners, 1, initCalls);

        assertEq(counter.count(), 4337);
    }

    function test_CreateWalletCallTrustOnDeploy() public {
        address[] memory owners = new address[](1);
        owners[0] = address(alice);

        // Deploy point token vault
        PointTokenVault pointTokenVaultImplementation = new PointTokenVault();
        PointTokenVault vault = PointTokenVault(
            payable(
                address(
                    new ERC1967Proxy(
                        address(pointTokenVaultImplementation),
                        abi.encodeCall(PointTokenVault.initialize, (admin, address(this)))
                    )
                )
            )
        );

        vm.prank(admin);
        rumpelGuard.setCallAllowed(address(vault), PointTokenVault.trustClaimer.selector, RumpelGuard.AllowListState.ON);

        InitializationScript.InitCall[] memory initCalls = new InitializationScript.InitCall[](1);
        initCalls[0] = InitializationScript.InitCall({
            to: address(vault),
            data: abi.encodeCall(PointTokenVault.trustClaimer, (alice, true))
        });

        ISafe safe = ISafe(rumpelWalletFactory.createWallet(owners, 1, initCalls));

        assertEq(vault.trustedClaimers(address(safe), alice), true);
    }

    function test_SafeSignMessage() public {
        // Setup
        address[] memory owners = new address[](1);
        owners[0] = alice;
        InitializationScript.InitCall[] memory initCalls = new InitializationScript.InitCall[](0);
        ISafe safe = ISafe(rumpelWalletFactory.createWallet(owners, 1, initCalls));

        // Create the message
        bytes memory message = "Hello Safe";

        // Sign the message using the Safe
        _execSafeTx(
            safe,
            address(rumpelGuard.signMessageLib()),
            0,
            abi.encodeCall(ISignMessageLib.signMessage, (abi.encode(keccak256(message)))),
            Enum.Operation.DelegateCall
        );

        // Verify the signature
        bytes memory emptySignature = "";
        // bytes4(keccak256("isValidSignature(bytes32,bytes)")
        bytes4 EIP1271_MAGIC_VALUE = 0x1626ba7e;
        assertEq(safe.isValidSignature(keccak256(message), emptySignature), EIP1271_MAGIC_VALUE);

        // Demonstrate that an incorrect message hash fails
        vm.expectRevert("Invalid signature");
        bytes memory incorrectMessage = "Hello Safe bad";
        safe.isValidSignature(incorrectMessage, emptySignature);
    }

    // Helper function to get the correct message hash
    function getMessageHash(ISafe safe, bytes memory message) internal view returns (bytes32) {
        bytes32 SAFE_MSG_TYPEHASH = keccak256("SafeMessage(bytes message)");
        bytes32 safeMessageHash = keccak256(abi.encode(SAFE_MSG_TYPEHASH, keccak256(message)));
        return keccak256(abi.encodePacked(bytes1(0x19), bytes1(0x01), safe.domainSeparator(), safeMessageHash));
    }

    // Guard ----

    function test_GuardAuth(address lad) public {
        vm.assume(lad != admin);

        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, lad));
        vm.prank(lad);
        rumpelGuard.setCallAllowed(address(counter), Counter.increment.selector, RumpelGuard.AllowListState.ON);
    }

    function testFuzz_GuardAllowAndDisallowCalls(address target, bytes4 functionSelector) public {
        vm.prank(admin);
        rumpelGuard.setCallAllowed(target, functionSelector, RumpelGuard.AllowListState.ON);
        assertEq(uint256(rumpelGuard.allowedCalls(target, functionSelector)), uint256(RumpelGuard.AllowListState.ON));

        vm.prank(admin);
        rumpelGuard.setCallAllowed(target, functionSelector, RumpelGuard.AllowListState.OFF);
        assertEq(uint256(rumpelGuard.allowedCalls(target, functionSelector)), uint256(RumpelGuard.AllowListState.OFF));
    }

    function test_RumpelWalletIsGuarded() public {
        address[] memory owners = new address[](1);
        owners[0] = address(alice);

        InitializationScript.InitCall[] memory initCalls = new InitializationScript.InitCall[](0);
        ISafe safe = ISafe(rumpelWalletFactory.createWallet(owners, 1, initCalls));

        // Will revert if the address.func has not been allowed
        vm.expectRevert(
            abi.encodeWithSelector(
                RumpelGuard.CallNotAllowed.selector, address(counter), bytes4(abi.encodeCall(Counter.increment, ()))
            )
        );
        this._execSafeTx(safe, address(counter), 0, abi.encodeCall(Counter.increment, ()), Enum.Operation.Call);

        vm.prank(admin);
        rumpelGuard.setCallAllowed(address(counter), Counter.increment.selector, RumpelGuard.AllowListState.ON);

        // Will succeed if the address.func has been allowed
        this._execSafeTx(safe, address(counter), 0, abi.encodeCall(Counter.increment, ()), Enum.Operation.Call);

        assertEq(counter.count(), 1);
    }

    function test_GuardDisallowDelegateCall() public {
        DelegateCallTestScript delegateCallTestScript = new DelegateCallTestScript();

        address[] memory owners = new address[](1);
        owners[0] = address(alice);

        InitializationScript.InitCall[] memory initCalls = new InitializationScript.InitCall[](0);
        ISafe safe = ISafe(rumpelWalletFactory.createWallet(owners, 1, initCalls));

        // Enable call to the delegate call script
        vm.prank(admin);
        rumpelGuard.setCallAllowed(
            address(delegateCallTestScript), DelegateCallTestScript.echo.selector, RumpelGuard.AllowListState.ON
        );

        // Build a delegate call transaction
        SafeTX memory safeTX = SafeTX({
            to: address(delegateCallTestScript),
            value: 0,
            data: abi.encodeCall(DelegateCallTestScript.echo, (123)),
            operation: Enum.Operation.DelegateCall
        });

        uint256 nonce = safe.nonce();

        bytes32 txHash = safe.getTransactionHash(
            safeTX.to, safeTX.value, safeTX.data, safeTX.operation, 0, 0, 0, address(0), payable(address(0)), nonce
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alicePk, txHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.expectRevert(
            abi.encodeWithSelector(
                RumpelGuard.CallNotAllowed.selector,
                address(delegateCallTestScript),
                bytes4(abi.encodeCall(DelegateCallTestScript.echo, (123)))
            )
        );
        safe.execTransaction(
            safeTX.to, safeTX.value, safeTX.data, safeTX.operation, 0, 0, 0, address(0), payable(address(0)), signature
        );
    }

    function test_RumpelWalletDisallowSmallData() public {
        address[] memory owners = new address[](1);
        owners[0] = address(alice);

        InitializationScript.InitCall[] memory initCalls = new InitializationScript.InitCall[](0);
        ISafe safe = ISafe(rumpelWalletFactory.createWallet(owners, 1, initCalls));

        // 3 bytes. Will be padded out with two 0s when cast to bytes4
        bytes memory smallData = new bytes(3);
        smallData[0] = bytes1(uint8(1));
        smallData[1] = bytes1(uint8(2));
        smallData[2] = bytes1(uint8(3));

        vm.prank(admin);
        rumpelGuard.setCallAllowed(address(counter), bytes4(smallData), RumpelGuard.AllowListState.ON);

        // Will revert even though the data has been allowed, because the data is too small
        vm.expectRevert(
            abi.encodeWithSelector(RumpelGuard.CallNotAllowed.selector, address(counter), bytes4(smallData))
        );
        this._execSafeTx(safe, address(counter), 0, smallData, Enum.Operation.Call);
    }

    function test_RumpelWalletAllowETHTransfers() public {
        address[] memory owners = new address[](1);
        owners[0] = address(alice);

        InitializationScript.InitCall[] memory initCalls = new InitializationScript.InitCall[](0);
        ISafe safe = ISafe(rumpelWalletFactory.createWallet(owners, 1, initCalls));

        bytes memory zeroData = new bytes(0);

        // Enable ETH transfers
        vm.prank(admin);
        rumpelGuard.setCallAllowed(address(0), bytes4(0), RumpelGuard.AllowListState.ON);

        // Mint 1 ETH to the safe
        vm.deal(address(safe), 1 ether);

        assertEq(address(safe).balance, 1 ether);
        assertEq(address(counter).balance, 0);

        // Transfer to contract
        this._execSafeTx(safe, address(counter), 0.1 ether, zeroData, Enum.Operation.Call);

        assertEq(address(safe).balance, 0.9 ether);
        assertEq(address(counter).balance, 0.1 ether);

        // Transfer to address
        this._execSafeTx(safe, address(alice), 0.1 ether, zeroData, Enum.Operation.Call);

        assertEq(address(safe).balance, 0.8 ether);
        assertEq(address(alice).balance, 0.1 ether);
    }

    function test_RumpelWalletConfigUpdateAuth() public {
        address[] memory owners = new address[](1);
        owners[0] = address(alice);

        InitializationScript.InitCall[] memory initCalls = new InitializationScript.InitCall[](0);
        ISafe safe = ISafe(rumpelWalletFactory.createWallet(owners, 1, initCalls));

        bytes memory addOwnerData = abi.encodeCall(ISafe.addOwnerWithThreshold, (makeAddr("bob"), 1));

        // Try to add an owner to the safe wallet
        vm.expectRevert(
            abi.encodeWithSelector(RumpelGuard.CallNotAllowed.selector, address(safe), bytes4(addOwnerData))
        );
        this._execSafeTx(safe, address(safe), 0, addOwnerData, Enum.Operation.Call);

        vm.prank(admin);
        rumpelGuard.setCallAllowed(address(0), bytes4(addOwnerData), RumpelGuard.AllowListState.ON);
        this._execSafeTx(safe, address(safe), 0, addOwnerData, Enum.Operation.Call);

        assertEq(safe.getOwners().length, 2);
    }

    function test_RumpelWalletAllowZeroData() public {
        address[] memory owners = new address[](1);
        owners[0] = address(alice);

        InitializationScript.InitCall[] memory initCalls = new InitializationScript.InitCall[](0);
        ISafe safe = ISafe(rumpelWalletFactory.createWallet(owners, 1, initCalls));

        // 3 bytes. Will be padded out with two 0s when cast to bytes4
        bytes memory smallData = new bytes(3);
        smallData[0] = bytes1(uint8(1));
        smallData[1] = bytes1(uint8(2));
        smallData[2] = bytes1(uint8(3));

        vm.prank(admin);
        rumpelGuard.setCallAllowed(address(counter), bytes4(smallData), RumpelGuard.AllowListState.ON);

        // Will revert even though the data has been allowed, because the data is too small
        vm.expectRevert(
            abi.encodeWithSelector(RumpelGuard.CallNotAllowed.selector, address(counter), bytes4(smallData))
        );
        this._execSafeTx(safe, address(counter), 0, smallData, Enum.Operation.Call);
    }

    function test_GuardPermanentlyAllowedCall() public {
        address[] memory owners = new address[](1);
        owners[0] = address(alice);

        InitializationScript.InitCall[] memory initCalls = new InitializationScript.InitCall[](0);
        ISafe safe = ISafe(rumpelWalletFactory.createWallet(owners, 1, initCalls));

        // Set the call as permanently allowed
        vm.prank(admin);
        rumpelGuard.setCallAllowed(
            address(counter), Counter.increment.selector, RumpelGuard.AllowListState.PERMANENTLY_ON
        );

        // Sign and execute the transaction
        this._execSafeTx(safe, address(counter), 0, abi.encodeCall(Counter.increment, ()), Enum.Operation.Call);

        assertEq(counter.count(), 1);

        // Try to disallow the call (should revert)
        vm.prank(admin);
        vm.expectRevert(RumpelGuard.PermanentlyOn.selector);
        rumpelGuard.setCallAllowed(address(counter), Counter.increment.selector, RumpelGuard.AllowListState.OFF);

        // Execute the transaction again (should still work)
        this._execSafeTx(safe, address(counter), 0, abi.encodeCall(Counter.increment, ()), Enum.Operation.Call);

        assertEq(counter.count(), 2);
    }

    // Module ----

    function test_ModuleAuth(address lad) public {
        vm.assume(lad != admin);

        address[] memory owners = new address[](1);
        owners[0] = address(makeAddr("random 111")); // random owner

        InitializationScript.InitCall[] memory initCalls = new InitializationScript.InitCall[](0);
        ISafe safe = ISafe(rumpelWalletFactory.createWallet(owners, 1, initCalls));

        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, lad));
        vm.prank(lad);
        RumpelModule.Call[] memory calls = new RumpelModule.Call[](1);
        calls[0] = RumpelModule.Call({
            safe: safe,
            to: address(mockToken),
            data: abi.encodeCall(ERC20.transfer, (RUMPEL_VAULT, 1.1e18)),
            value: 0,
            operation: Enum.Operation.Call
        });

        rumpelModule.exec(calls);
    }

    function test_RumpelModuleCanExecute() public {
        address[] memory owners = new address[](1);
        owners[0] = address(makeAddr("random 111")); // random owner

        InitializationScript.InitCall[] memory initCalls = new InitializationScript.InitCall[](0);
        ISafe safe = ISafe(rumpelWalletFactory.createWallet(owners, 1, initCalls));

        mockToken.mint(address(this), 1.1e18);
        mockToken.transfer(address(safe), 1.1e18);

        assertEq(mockToken.balanceOf(address(safe)), 1.1e18);
        assertEq(mockToken.balanceOf(address(RUMPEL_VAULT)), 0);

        vm.prank(admin);
        RumpelModule.Call[] memory calls = new RumpelModule.Call[](1);
        calls[0] = RumpelModule.Call({
            safe: safe,
            to: address(mockToken),
            data: abi.encodeCall(ERC20.transfer, (RUMPEL_VAULT, 1.1e18)),
            value: 0,
            operation: Enum.Operation.Call
        });
        rumpelModule.exec(calls);

        assertEq(mockToken.balanceOf(address(safe)), 0);
        assertEq(mockToken.balanceOf(address(RUMPEL_VAULT)), 1.1e18);
    }

    function test_RumpelModuleCanSignMessage() public {
        // Setup
        address[] memory owners = new address[](1);
        owners[0] = alice;
        InitializationScript.InitCall[] memory initCalls = new InitializationScript.InitCall[](0);
        ISafe safe = ISafe(rumpelWalletFactory.createWallet(owners, 1, initCalls));

        // Create the message
        bytes memory message = "Hello Safe";

        // Sign the message via the Rumpel Module
        vm.startPrank(admin);
        RumpelModule.Call[] memory calls = new RumpelModule.Call[](1);
        calls[0] = RumpelModule.Call({
            safe: safe,
            to: address(rumpelModule.signMessageLib()),
            data: abi.encodeCall(ISignMessageLib.signMessage, (abi.encode(keccak256(message)))),
            value: 0,
            operation: Enum.Operation.DelegateCall
        });
        rumpelModule.exec(calls);
        vm.stopPrank();

        // Verify the signature
        bytes memory emptySignature = "";
        // bytes4(keccak256("isValidSignature(bytes32,bytes)")
        bytes4 EIP1271_MAGIC_VALUE = 0x1626ba7e;
        assertEq(safe.isValidSignature(keccak256(message), emptySignature), EIP1271_MAGIC_VALUE);

        // Still verifies the signature, even if a non-empty signature is provided
        assertEq(safe.isValidSignature(keccak256(message), "0x1234"), EIP1271_MAGIC_VALUE);

        // Demonstrate that an incorrect message hash fails
        vm.expectRevert("Invalid signature");
        bytes memory incorrectMessage = "Hello Safe bad";
        safe.isValidSignature(incorrectMessage, emptySignature);
    }

    function test_ModuleExecGuardedCall() public {
        address[] memory owners = new address[](1);
        owners[0] = address(makeAddr("random 111"));

        InitializationScript.InitCall[] memory initCalls = new InitializationScript.InitCall[](0);
        ISafe safe = ISafe(rumpelWalletFactory.createWallet(owners, 1, initCalls));

        mockToken.mint(address(safe), 1e18);

        // Guard the transfer call
        vm.prank(admin);
        rumpelModule.addBlockedModuleCall(address(mockToken), ERC20.transfer.selector);

        // Attempt to execute the guarded call
        vm.prank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(RumpelModule.CallBlocked.selector, address(mockToken), ERC20.transfer.selector)
        );
        RumpelModule.Call[] memory calls = new RumpelModule.Call[](1);
        calls[0] = RumpelModule.Call({
            safe: safe,
            to: address(mockToken),
            data: abi.encodeCall(ERC20.transfer, (RUMPEL_VAULT, 1e18)),
            value: 0,
            operation: Enum.Operation.Call
        });
        rumpelModule.exec(calls);

        assertEq(mockToken.balanceOf(address(safe)), 1e18);
        assertEq(mockToken.balanceOf(RUMPEL_VAULT), 0);
    }

    function test_ModuleExecGuardedSelfCall() public {
        address[] memory owners = new address[](1);
        owners[0] = address(makeAddr("random 111"));

        InitializationScript.InitCall[] memory initCalls = new InitializationScript.InitCall[](0);
        ISafe safe = ISafe(rumpelWalletFactory.createWallet(owners, 1, initCalls));

        RumpelModule newRumpelModule = new RumpelModule(rumpelModule.signMessageLib());

        // Attempt to execute "enableModule" on the safe itself, a function disabled by the deployment script
        vm.expectRevert(
            abi.encodeWithSelector(RumpelModule.CallBlocked.selector, address(safe), ISafe.enableModule.selector)
        );
        vm.prank(admin);
        RumpelModule.Call[] memory calls = new RumpelModule.Call[](1);
        calls[0] = RumpelModule.Call({
            safe: safe,
            to: address(safe),
            data: abi.encodeCall(ISafe.enableModule, (address(newRumpelModule))),
            value: 0,
            operation: Enum.Operation.Call
        });
        rumpelModule.exec(calls);
    }

    // e2e ---

    // function test_e2e_earnClaimRedeemPTokens() public {
    //     // Setup
    //     address[] memory owners = new address[](1);
    //     owners[0] = alice;
    //     ISafe safe = ISafe(rumpelWalletFactory.createWallet(owners, 1));

    //     address bob = makeAddr("bob");

    //     // Deploy a mock external protocol that earns points
    //     MockExternalProtocol externalProtocol = new MockExternalProtocol();
    //     MockERC20 externalToken = new MockERC20("External Token", "EXT", 18);
    //     externalToken.mint(address(safe), 100e18);

    //     // Deploy a mock reward token
    //     MockERC20 rewardToken = new MockERC20("Reward Token", "RWT", 18);

    //     // Deploy the PointTokenVault
    // PointTokenVault pointTokenVaultImplementation = new PointTokenVault();
    // PointTokenVault vault = PointTokenVault(
    //     payable(
    //         address(
    //             new ERC1967Proxy(
    //                 address(pointTokenVaultImplementation), abi.encodeCall(PointTokenVault.initialize, (admin))
    //             )
    //         )
    //     )
    // );
    //     vm.startPrank(admin);
    //     vault.grantRole(vault.MERKLE_UPDATER_ROLE(), admin);
    //     vm.stopPrank();

    //     // Setup the Point Token
    //     bytes32 pointsId = LibString.packTwo("Test Points", "TP");
    //     vault.deployPToken(pointsId);

    //     // Allow safe to interact with external protocol and vault
    //     vm.startPrank(admin);
    //     rumpelGuard.setCallAllowed(address(externalToken), ERC20.approve.selector, RumpelGuard.AllowListState.ON);
    //     rumpelGuard.setCallAllowed(
    //         address(externalProtocol), MockExternalProtocol.stake.selector, RumpelGuard.AllowListState.ON
    //     );
    //     rumpelGuard.setCallAllowed(address(vault), PointTokenVault.claimPTokens.selector, RumpelGuard.AllowListState.ON);
    //     rumpelGuard.setCallAllowed(
    //         address(vault.pTokens(pointsId)), ERC20.transfer.selector, RumpelGuard.AllowListState.ON
    //     );
    //     vm.stopPrank();

    //     // 1. Stake in external protocol to earn points
    //     uint256 stakeAmount = 50e18;
    //     bytes memory approveData = abi.encodeCall(ERC20.approve, (address(externalProtocol), stakeAmount));
    //     _execSafeTx(safe, address(externalToken), 0, approveData);
    //     bytes memory stakeData = abi.encodeCall(MockExternalProtocol.stake, (externalToken, stakeAmount));
    //     _execSafeTx(safe, address(externalProtocol), 0, stakeData);
    //     assertEq(externalProtocol.stakedBalance(address(safe)), stakeAmount);

    //     // 2. Simulate point accrual and update merkle root
    //     vm.prank(admin);
    //     vault.updateRoot(_simulatePointAccrual(address(safe), pointsId, 10e18));

    //     // 3. Claim pTokens
    //     bytes32[] memory proof = new bytes32[](1);
    //     proof[0] = keccak256(abi.encodePacked(address(safe), pointsId, uint256(10e18)));
    //     bytes memory claimData = abi.encodeCall(
    //         PointTokenVault.claimPTokens, (PointTokenVault.Claim(pointsId, 10e18, 10e18, proof), address(safe))
    //     );
    //     _execSafeTx(safe, address(vault), 0, claimData);
    //     assertEq(vault.pTokens(pointsId).balanceOf(address(safe)), 10e18);
    //     return;

    // 4. Transfer some pTokens to Bob
    // bytes memory transferData = abi.encodeCall(ERC20.transfer, (bob, 3e18));
    // _execSafeTx(safe, address(vault.pTokens(pointsId)), 0, transferData);
    // assertEq(vault.pTokens(pointsId).balanceOf(address(safe)), 7e18);
    // assertEq(vault.pTokens(pointsId).balanceOf(bob), 3e18);

    // // 5. Setup redemption
    // rewardToken.mint(address(vault), 20e18);
    // vm.prank(admin);
    // vault.setRedemption(pointsId, rewardToken, 2e18, false);

    // 6. Sweep rewards to Rumpel vault (simulating rewards claimed by the protocol)
    // rewardToken.mint(address(safe), 14e18);
    // vm.prank(admin);
    // RumpelModule.Sweep[] memory sweeps = new RumpelModule.Sweep[](1);
    // sweeps[0] = RumpelModule.Sweep({safe: safe, token: ERC20(address(rewardToken)), amount: 14e18});
    // rumpelModule.sweep(sweeps);
    // assertEq(rewardToken.balanceOf(RUMPEL_VAULT), 14e18);
    // assertEq(rewardToken.balanceOf(address(safe)), 0);

    // // 7. Bob redeems his pTokens for rewards
    // vm.startPrank(bob);
    // vault.pTokens(pointsId).approve(address(vault), 3e18);
    // vault.redeemRewards(PointTokenVault.Claim(pointsId, 6e18, 6e18, new bytes32[](0)), bob);
    // vm.stopPrank();

    // assertEq(rewardToken.balanceOf(bob), 6e18);
    // assertEq(vault.pTokens(pointsId).balanceOf(bob), 0);

    // // 8. Safe redeems remaining pTokens for rewards
    // bytes memory redeemData = abi.encodeCall(
    //     PointTokenVault.redeemRewards,
    //     (PointTokenVault.Claim(pointsId, 14e18, 14e18, new bytes32[](0)), address(safe))
    // );
    // _execSafeTx(safe, address(vault), 0, redeemData);
    // assertEq(rewardToken.balanceOf(address(safe)), 14e18);
    // assertEq(vault.pTokens(pointsId).balanceOf(address(safe)), 0);
    // }

    function _execSafeTx(ISafe safe, address to, uint256 value, bytes memory data, Enum.Operation operation) public {
        SafeTX memory safeTX = SafeTX({to: to, value: value, data: data, operation: operation});

        uint256 nonce = safe.nonce();

        bytes32 txHash = safe.getTransactionHash(
            safeTX.to, safeTX.value, safeTX.data, safeTX.operation, 0, 0, 0, address(0), payable(address(0)), nonce
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alicePk, txHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        safe.execTransaction(
            safeTX.to, safeTX.value, safeTX.data, safeTX.operation, 0, 0, 0, address(0), payable(address(0)), signature
        );
    }

    function _simulatePointAccrual(address user, bytes32 pointsId, uint256 amount) internal pure returns (bytes32) {
        bytes32[] memory leaves = new bytes32[](1);
        leaves[0] = keccak256(abi.encodePacked(user, pointsId, amount));
        return leaves[0]; // For simplicity, we're just using a single leaf as the root
    }

    // test owner is blocked for actions not on the whitelist
    // - cant disable module
    // - cant change guard
    // - cant change owners
    // - cant withdraw funds
    // test migrations
}

contract MockExternalProtocol {
    mapping(address => uint256) public stakedBalance;

    function stake(ERC20 token, uint256 amount) external {
        token.transferFrom(msg.sender, address(this), amount);
        stakedBalance[msg.sender] += amount;
    }
}

contract DelegateCallTestScript {
    event Echo(uint256);

    function echo(uint256 num) external {
        emit Echo(num);
    }
}

contract Counter {
    uint256 public count;

    function increment() public {
        count += 1;
    }

    function addToCount(uint256 num) external {
        count += num;
    }

    function fail() external {
        revert("fail");
    }

    fallback() external payable {}
}
