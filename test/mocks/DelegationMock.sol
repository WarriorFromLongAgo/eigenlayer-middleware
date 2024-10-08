// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.12;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import {IDelegationManager} from "eigenlayer-contracts/src/contracts/interfaces/IDelegationManager.sol";
import {IStrategyManager} from "eigenlayer-contracts/src/contracts/interfaces/IStrategyManager.sol";
import {StrategyManager} from "eigenlayer-contracts/src/contracts/core/StrategyManager.sol";
import {IStrategy} from "eigenlayer-contracts/src/contracts/interfaces/IStrategy.sol";
import {ISignatureUtils} from "eigenlayer-contracts/src/contracts/interfaces/ISignatureUtils.sol";
import {SlashingLib} from "eigenlayer-contracts/src/contracts/libraries/SlashingLib.sol";

contract DelegationMock is IDelegationManager {
  using SlashingLib for uint256;

  mapping(address => bool) public isOperator;
  mapping(address => mapping(IStrategy => uint256)) public operatorShares;

  function setIsOperator(
    address operator,
    bool _isOperatorReturnValue
  ) external {
    isOperator[operator] = _isOperatorReturnValue;
  }

  /// @notice returns the total number of shares in `strategy` that are delegated to `operator`.
  function setOperatorShares(
    address operator,
    IStrategy strategy,
    uint256 shares
  ) external {
    operatorShares[operator][strategy] = shares;
  }

  mapping(address => address) public delegatedTo;

  function registerAsOperator(
    OperatorDetails calldata /*registeringOperatorDetails*/,
    string calldata /*metadataURI*/
  ) external pure {}

  function updateOperatorMetadataURI(
    string calldata /*metadataURI*/
  ) external pure {}

  function updateAVSMetadataURI(
    string calldata /*metadataURI*/
  ) external pure {}

  function delegateTo(
    address operator,
    SignatureWithExpiry memory /*approverSignatureAndExpiry*/,
    bytes32 /*approverSalt*/
  ) external {
    delegatedTo[msg.sender] = operator;
  }

  function modifyOperatorDetails(
    OperatorDetails calldata /*newOperatorDetails*/
  ) external pure {}

  function delegateToBySignature(
    address /*staker*/,
    address /*operator*/,
    SignatureWithExpiry memory /*stakerSignatureAndExpiry*/,
    SignatureWithExpiry memory /*approverSignatureAndExpiry*/,
    bytes32 /*approverSalt*/
  ) external pure {}

  function undelegate(
    address staker
  ) external returns (bytes32[] memory withdrawalRoot) {
    delegatedTo[staker] = address(0);
    return withdrawalRoot;
  }

  function increaseDelegatedShares(
    address /*staker*/,
    IStrategy /*strategy*/,
    uint256 /*shares*/
  ) external pure {}

  function operatorDetails(
    address operator
  ) external pure returns (OperatorDetails memory) {
    OperatorDetails memory returnValue = OperatorDetails({
      __deprecated_earningsReceiver: operator,
      delegationApprover: operator,
      stakerOptOutWindowBlocks: 0
    });
    return returnValue;
  }

  function beaconChainETHStrategy() external pure returns (IStrategy) {}

  function earningsReceiver(address operator) external pure returns (address) {
    return operator;
  }

  function delegationApprover(
    address operator
  ) external pure returns (address) {
    return operator;
  }

  function stakerOptOutWindowBlocks(
    address /*operator*/
  ) external pure returns (uint256) {
    return 0;
  }

  function minWithdrawalDelayBlocks() external view returns (uint256) {
    return 50400;
  }

  /**
   * @notice Minimum delay enforced by this contract per Strategy for completing queued withdrawals. Measured in blocks, and adjustable by this contract's owner,
   * up to a maximum of `MAX_WITHDRAWAL_DELAY_BLOCKS`. Minimum value is 0 (i.e. no delay enforced).
   */
  function strategyWithdrawalDelayBlocks(
    IStrategy /*strategy*/
  ) external view returns (uint256) {
    return 0;
  }

  function getOperatorShares(
    address operator,
    IStrategy[] memory strategies
  ) external view returns (uint256[] memory) {
    uint256[] memory shares = new uint256[](strategies.length);
    for (uint256 i = 0; i < strategies.length; ++i) {
      shares[i] = operatorShares[operator][strategies[i]];
    }
    return shares;
  }

  function getWithdrawalDelay(
    IStrategy[] calldata /*strategies*/
  ) public view returns (uint256) {
    return 0;
  }

  function isDelegated(address staker) external view returns (bool) {
    return (delegatedTo[staker] != address(0));
  }

  function isNotDelegated(address /*staker*/) external pure returns (bool) {}

  // function isOperator(address /*operator*/) external pure returns (bool) {}

  function stakerNonce(address /*staker*/) external pure returns (uint256) {}

  function delegationApproverSaltIsSpent(
    address /*delegationApprover*/,
    bytes32 /*salt*/
  ) external pure returns (bool) {}

  function calculateCurrentStakerDelegationDigestHash(
    address /*staker*/,
    address /*operator*/,
    uint256 /*expiry*/
  ) external view returns (bytes32) {}

  function calculateStakerDelegationDigestHash(
    address /*staker*/,
    uint256 /*stakerNonce*/,
    address /*operator*/,
    uint256 /*expiry*/
  ) external view returns (bytes32) {}

  function calculateDelegationApprovalDigestHash(
    address /*staker*/,
    address /*operator*/,
    address /*_delegationApprover*/,
    bytes32 /*approverSalt*/,
    uint256 /*expiry*/
  ) external view returns (bytes32) {}

  function calculateStakerDigestHash(
    address /*staker*/,
    address /*operator*/,
    uint256 /*expiry*/
  ) external pure returns (bytes32 stakerDigestHash) {}

  function calculateApproverDigestHash(
    address /*staker*/,
    address /*operator*/,
    uint256 /*expiry*/
  ) external pure returns (bytes32 approverDigestHash) {}

  function calculateOperatorAVSRegistrationDigestHash(
    address /*operator*/,
    address /*avs*/,
    bytes32 /*salt*/,
    uint256 /*expiry*/
  ) external pure returns (bytes32 digestHash) {}

  function DOMAIN_TYPEHASH() external view returns (bytes32) {}

  function STAKER_DELEGATION_TYPEHASH() external view returns (bytes32) {}

  function DELEGATION_APPROVAL_TYPEHASH() external view returns (bytes32) {}

  function domainSeparator() external view returns (bytes32) {}

  function cumulativeWithdrawalsQueued(
    address staker
  ) external view returns (uint256) {}

  function calculateWithdrawalRoot(
    Withdrawal memory withdrawal
  ) external pure returns (bytes32) {}

  function operatorSaltIsSpent(
    address avs,
    bytes32 salt
  ) external view returns (bool) {}

  function queueWithdrawals(
    QueuedWithdrawalParams[] calldata queuedWithdrawalParams
  ) external returns (bytes32[] memory) {}

  function completeQueuedWithdrawal(
    Withdrawal calldata withdrawal,
    IERC20[] calldata tokens,
    uint256 middlewareTimesIndex,
    bool receiveAsTokens
  ) external {}

  function completeQueuedWithdrawals(
    Withdrawal[] calldata withdrawals,
    IERC20[][] calldata tokens,
    uint256[] calldata middlewareTimesIndexes,
    bool[] calldata receiveAsTokens
  ) external {}

  // onlyDelegationManager functions in StrategyManager
  function addShares(
    IStrategyManager strategyManager,
    address staker,
    IERC20 token,
    IStrategy strategy,
    uint256 shares
  ) external {
    strategyManager.addShares(staker, strategy, token, shares);
  }

  function removeShares(
    IStrategyManager strategyManager,
    address staker,
    IStrategy strategy,
    uint256 shares
  ) external {
    strategyManager.removeDepositShares(staker, strategy, shares);
  }

  function withdrawSharesAsTokens(
    IStrategyManager strategyManager,
    address recipient,
    IStrategy strategy,
    uint256 shares,
    IERC20 token
  ) external {
    strategyManager.withdrawSharesAsTokens(
      recipient,
      strategy,
      token,
      shares
    );
  }

  function registerAsOperator(
    OperatorDetails calldata registeringOperatorDetails,
    uint32 allocationDelay,
    string calldata metadataURI
  ) external override {}

  function completeQueuedWithdrawal(
    Withdrawal calldata withdrawal,
    IERC20[] calldata tokens,
    bool receiveAsTokens
  ) external override {}

  function completeQueuedWithdrawals(
    Withdrawal[] calldata withdrawals,
    IERC20[][] calldata tokens,
    bool[] calldata receiveAsTokens
  ) external override {}

  function decreaseBeaconChainScalingFactor(
    address staker,
    uint256 existingDepositShares,
    uint64 proportionOfOldBalance
  ) external override {}

  function decreaseOperatorShares(
    address operator,
    IStrategy strategy,
    uint64 previousTotalMagnitude,
    uint64 newTotalMagnitude
  ) external override {}

  function increaseDelegatedShares(
    address staker,
    IStrategy strategy,
    uint256 existingDepositShares,
    uint256 addedShares
  ) external override {}

}
