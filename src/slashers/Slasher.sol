// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.12;

import {IStrategy} from "eigenlayer-contracts/src/contracts/interfaces/IStrategy.sol";
import {SlasherBase} from "./SlasherBase.sol";

contract Slasher is SlasherBase {
    uint256 public nextRequestId;

    function initialize(address _serviceManager) public initializer {
        __SlasherBase_init(_serviceManager);
    }

    function fulfillSlashingRequest(
        address operator,
        uint32 operatorSetId,
        IStrategy[] memory strategies,
        uint256 wadToSlash,
        string memory description
    ) external virtual {
        uint256 requestId = nextRequestId++;
        _fulfillSlashingRequest(
            operator,
            operatorSetId,
            strategies,
            wadToSlash,
            description
        );
        emit OperatorSlashed(requestId, operator, operatorSetId, strategies, wadToSlash, description);
    }
}