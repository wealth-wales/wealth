// SPDX-License-Identifier: MIT
pragma solidity ^0.8.9;

import "@openzeppelin/contracts/access/Ownable.sol";

contract Subscription is Ownable {
    BorrowInfo[] public borrowInfos;

    address[] public partner;

    bytes4 private constant SELECTOR =
        bytes4(keccak256(bytes("transfer(address,uint256)")));

    // An event sent when funds are received.
    event Funded(address from, uint256 value);

    // An event sent when a spend is triggered to the given address.
    event Spent(address to, uint256 transfer);

    // An event sent when a spendERC20 is triggered to the given address.
    event SpentERC20(address erc20contract, address to, uint256 transfer);

    // An event sent when an spendAny is executed.
    event SpentAny(address to, uint256 transfer);

    event BorrowInfoUpdated(BorrowInfo newInfo);

    struct BorrowInfo {
        string orderId;
        uint256 borrowAmount;
        address tokenAddress;
    }

    constructor() {
        _transferOwnership(_msgSender());
    }

    // The receive function for this contract.
    receive() external payable {
        if (msg.value > 0) {
            emit Funded(msg.sender, msg.value);
        }
    }

    /**
     * @param destination: the ether receiver address.
     * @param value: the ether value, in wei.
     */
    function spend(address destination, uint256 value) external onlyOwner {
        require(destination != address(this), "Not allow sending to yourself");
        require(
            address(this).balance >= value && value > 0,
            "balance or spend value invalid"
        );

        //transfer will throw if fails
        (bool success, ) = destination.call{value: value}("");
        require(success, "transfer fail");
        emit Spent(destination, value);
    }

    /**
     * @param erc20contract: the erc20 contract address.
     * @param destination: the token receiver address.
     * @param value: the token value, in token minimum unit.
     */
    function spendERC20(
        address destination,
        address erc20contract,
        uint256 value
    ) external onlyOwner {
        require(destination != address(this), "Not allow sending to yourself");
        //transfer erc20 token
        require(value > 0, "Erc20 spend value invalid");

        // transfer tokens from this contract to the destination address
        _safeTransfer(erc20contract, destination, value);
        emit SpentERC20(erc20contract, destination, value);
    }

    function _safeTransfer(address token, address to, uint256 value) private {
        (bool success, bytes memory data) = token.call(
            abi.encodeWithSelector(SELECTOR, to, value)
        );
        require(
            success && (data.length == 0 || abi.decode(data, (bool))),
            "Subscription: TRANSFER_FAILED"
        );
    }

    //This is usually for some emergent recovery, for example, recovery of NTFs, etc.
    function spendAny(
        address destination,
        uint256 value,
        bytes calldata data
    ) external onlyOwner {
        require(destination != address(this), "Not allow sending to yourself");
        //transfer tokens from this contract to the destination address
        (bool success, ) = destination.call{value: value}(data);
        require(success, "call fail");
        emit SpentAny(destination, value);
    }

    function setBorrowInfo(
        bytes calldata borrowInfoBytes,
        address _partner
    ) external onlyOwner {
        partner.push(_partner);
        (
            string memory orderId,
            uint256 borrowAmount,
            address tokenAddress
        ) = abi.decode(borrowInfoBytes, (string, uint256, address));

        BorrowInfo memory borrowInfo = BorrowInfo({
            orderId: orderId,
            borrowAmount: borrowAmount,
            tokenAddress: tokenAddress
        });
        borrowInfos.push(borrowInfo);
        emit BorrowInfoUpdated(borrowInfo);
    }
}
