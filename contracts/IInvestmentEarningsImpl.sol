// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.9;

import "./IInvestmentEarnings.sol";

contract IInvestmentEarningsImpl is IInvestmentEarnings {
    // event NotedCancelReinvest(string orderId);
    // event NotedWithdraw(uint64[] recordIds);
    // event Liquidated(string orderId);
    // event Processed(string orderId);

    function noteCancelReinvest(string calldata orderId) external {
        emit NotedCancelReinvest(orderId);
    }

    function noteWithdrawal(uint64[] calldata recordIds) external {
        emit NotedWithdraw(recordIds);
    }

    function liquidatedAssets(string calldata orderId) external {
        emit Liquidated(orderId);
    }

    function processBorrowing(string calldata orderId) external {
        emit Processed(orderId);
    }
}
