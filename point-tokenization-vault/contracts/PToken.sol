// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {ERC20} from "solmate/tokens/ERC20.sol";

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";

contract PToken is ERC20, AccessControl, Pausable {
    bytes32 public constant PAUSE_ROLE = keccak256("PAUSE_ROLE");
    bytes32 public constant SUPPLY_ADMIN_ROLE = keccak256("SUPPLY_ADMIN_ROLE");

    constructor(string memory _name, string memory _symbol, uint8 _decimals)
        ERC20(_name, _symbol, _decimals)
        AccessControl()
    {
        _grantRole(PAUSE_ROLE, msg.sender);
        _grantRole(SUPPLY_ADMIN_ROLE, msg.sender);
    }

    function mint(address to, uint256 value) public virtual whenNotPaused onlyRole(SUPPLY_ADMIN_ROLE) {
        _mint(to, value);
    }

    function burn(address from, uint256 value) public virtual whenNotPaused onlyRole(SUPPLY_ADMIN_ROLE) {
        _burn(from, value);
    }

    function transferFrom(address from, address to, uint256 amount) public override whenNotPaused returns (bool) {
        return super.transferFrom(from, to, amount);
    }

    function transfer(address to, uint256 amount) public override whenNotPaused returns (bool) {
        return super.transfer(to, amount);
    }

    function pause() public onlyRole(PAUSE_ROLE) {
        _pause();
    }

    function unpause() public onlyRole(PAUSE_ROLE) {
        _unpause();
    }
}
