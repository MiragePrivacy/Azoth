// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
contract DemoToken is ERC20 {
    constructor() ERC20("Demo", "DMO") {
        _mint(msg.sender, 1_000_000 ether);
    }
}
