// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

contract Escrow {
    // The following variables are set up in the contructor.
    address immutable deployerAddress;
    address immutable tokenContract; // The tokens used in the escrow
    // address immutable paymentTokenContract; // The tokens used in the payment to the recipient
    uint256 public currentRewardAmount;
    uint256 public currentPaymentAmount;
    uint256 public originalRewardAmount;

    // The following variables are dynamically adjusted by the contract when a bond or cancellation request is submitted.
    address public bondedExecutor;
    uint256 public executionDeadline;
    uint256 public bondAmount;
    uint256 public totalBondsDeposited;
    bool public cancellationRequest;
    bool public funded; // marks if the contract ahs funds to pay out the executors or not (if it doesn't have funds, no executor should be accepted)

    constructor(address _tokenContract) {
        tokenContract = _tokenContract;
        deployerAddress = msg.sender;
    }

    // takes currentRewardAmount + currentPaymentAmount from the deployer's balance from the tokenContract.
    function fund(uint256 _currentRewardAmount, uint256 _currentPaymentAmount) public {
        require(msg.sender == deployerAddress, "Only callable by the deployer");
        require(!funded, "Contract already funded");

        currentRewardAmount = _currentRewardAmount;
        originalRewardAmount = _currentRewardAmount;
        currentPaymentAmount = _currentPaymentAmount;
        IERC20(tokenContract).transferFrom(msg.sender, address(this), originalRewardAmount + currentPaymentAmount);
        funded = true;
    }

    // takes _bondAmount from the caller's balance of the tokenContract. The bondstatus is now bonded, execution deadline is current block timestam + 5 minutes. Sets bondedexecutor to the caller. Will only accept a bond if the cancellationrequest is set to false, and no one is bonded.
    function bond(uint256 _bondAmount) public {
        require(funded, "Contract not funded");
        require(!cancellationRequest, "Cancellation requested");
        require(_bondAmount >= currentRewardAmount / 2, "Bond must be at least half of reward amount");

        // If deadline passed and someone is bonded, add their bond to reward
        if (executionDeadline > 0 && block.timestamp > executionDeadline) {
            currentRewardAmount += bondAmount;
            totalBondsDeposited += bondAmount;
            tryResetBondData();
        }

        IERC20(tokenContract).transferFrom(msg.sender, address(this), _bondAmount);

        bondedExecutor = msg.sender;
        executionDeadline = block.timestamp + 5 minutes;
        bondAmount = _bondAmount;
    }

    // only deployer can call this. will set the cancellation request to true.
    // when the cancellation is requested, the bonded executor may still finish their job and collect, but no new executor is accepted after the current bonded one.
    function requestCancellation() public {
        require(msg.sender == deployerAddress, "Only callable by the deployer");
        cancellationRequest = true;
    }

    // sets cancellation request to false, if the caller is deployer.
    // starts accepting new executors
    function resume() public {
        require(msg.sender == deployerAddress, "Only callable by the deployer");
        cancellationRequest = false;
    }

    // ignore the proof for now, it's a placeholder, mark it as such. releases the bondAmount + currentRewardAmount + pyamnetAmount to the caller only and only if the caller is bondedExecutor
    function collect() public {
        require(funded, "Contract not funded");
        require(msg.sender == bondedExecutor && is_bonded(), "Only bonded executor can collect");

        uint256 payout = bondAmount + currentRewardAmount + currentPaymentAmount;
        address executor = bondedExecutor;

        bondedExecutor = address(0);
        bondAmount = 0;
        executionDeadline = 0;
        funded = false;
        currentPaymentAmount = 0;
        currentRewardAmount = 0;
        IERC20(tokenContract).transfer(executor, payout);
    }

    // checks if contract is currently bonded by verifying deadline
    function is_bonded() public view returns (bool) {
        return executionDeadline > 0 && block.timestamp <= executionDeadline;
    }

    // allows deployer to withdraw all assets except the seized bonds (so the deployer can withdraw only and only what was deposited by deployer in the start function)
    // only if the contract is not currently bonded (or the execution deadline has passed)
    function withdraw() public {
        require(funded, "Contract not funded");
        require(msg.sender == deployerAddress, "Only callable by the deployer");
        require(funded == true, "The contract was not funded or has been drained already");
        tryResetBondData();

        uint256 withdrawableAmount = currentPaymentAmount + originalRewardAmount;

        funded = false;
        currentPaymentAmount = 0;
        currentRewardAmount = 0;

        require(withdrawableAmount > 0, "No withdrawable funds");

        IERC20(tokenContract).transfer(msg.sender, withdrawableAmount);
    }

    function tryResetBondData() internal {
        require(!is_bonded(), "Cannot reset while bond is active");

        bondedExecutor = address(0);
        bondAmount = 0;
        executionDeadline = 0;
    }
}
