// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.12;

import {IBLSApkRegistry} from "./interfaces/IBLSApkRegistry.sol";
import {IStakeRegistry} from "./interfaces/IStakeRegistry.sol";
import {IIndexRegistry} from "./interfaces/IIndexRegistry.sol";
import {IServiceManager} from "./interfaces/IServiceManager.sol";
import {IRegistryCoordinator} from "./interfaces/IRegistryCoordinator.sol";

abstract contract RegistryCoordinatorStorage is IRegistryCoordinator {

    /*******************************************************************************
                               CONSTANTS AND IMMUTABLES 
    *******************************************************************************/

    /// @notice The EIP-712 typehash for the `DelegationApproval` struct used by the contract
    bytes32 public constant OPERATOR_CHURN_APPROVAL_TYPEHASH =
        keccak256("OperatorChurnApproval(address registeringOperator,bytes32 registeringOperatorId,OperatorKickParam[] operatorKickParams,bytes32 salt,uint256 expiry)OperatorKickParam(uint8 quorumNumber,address operator)");
    /// @notice The EIP-712 typehash used for registering BLS public keys
    bytes32 public constant PUBKEY_REGISTRATION_TYPEHASH = keccak256("BN254PubkeyRegistration(address operator)");
    /// @notice The maximum value of a quorum bitmap
    uint256 internal constant MAX_QUORUM_BITMAP = type(uint192).max;
    /// @notice The basis point denominator
    uint16 internal constant BIPS_DENOMINATOR = 10000;
    /// @notice Index for flag that pauses operator registration
    uint8 internal constant PAUSED_REGISTER_OPERATOR = 0;
    /// @notice Index for flag that pauses operator deregistration
    uint8 internal constant PAUSED_DEREGISTER_OPERATOR = 1;
    /// @notice Index for flag pausing operator stake updates
    uint8 internal constant PAUSED_UPDATE_OPERATOR = 2;
    /// @notice The maximum number of quorums this contract supports
    uint8 internal constant MAX_QUORUM_COUNT = 192;

    /// @notice the ServiceManager for this AVS, which forwards calls onto EigenLayer's core contracts
    /// 此 AVS 的 ServiceManager，它将调用转发到 EigenLayer 的核心合约
    /// 服务管理器合约,用于转发调用到 EigenLayer 的核心合约。
    IServiceManager public immutable serviceManager;
    /// @notice the BLS Aggregate Pubkey Registry contract that will keep track of operators' aggregate BLS public keys per quorum
    /// BLS 聚合公钥注册合约将跟踪每个法定人数的运营商的聚合 BLS 公钥
    /// BLS 聚合公钥注册表合约,用于跟踪每个仲裁的操作员聚合 BLS 公钥。
    IBLSApkRegistry public immutable blsApkRegistry;
    /// @notice the Stake Registry contract that will keep track of operators' stakes
    /// 质押注册表合约,用于跟踪操作员的质押。
    /// 权益登记合约将跟踪运营商的权益
    IStakeRegistry public immutable stakeRegistry;
    /// 索引注册表合约,用于跟踪操作员的索引。
    /// @notice the Index Registry contract that will keep track of operators' indexes
    /// 跟踪运营商指数的 Index Registry 合约
    IIndexRegistry public immutable indexRegistry;

    /*******************************************************************************
                                       STATE 
    *******************************************************************************/

    /// @notice the current number of quorums supported by the registry coordinator
    uint8 public quorumCount;
    /// @notice maps quorum number => operator cap and kick params
    mapping(uint8 => OperatorSetParam) internal _quorumParams;
    /// @notice maps operator id => historical quorums they registered for
    mapping(bytes32 => QuorumBitmapUpdate[]) internal _operatorBitmapHistory;
    /// @notice maps operator address => operator id and status
    mapping(address => OperatorInfo) internal _operatorInfo;
    /// @notice whether the salt has been used for an operator churn approval
    mapping(bytes32 => bool) public isChurnApproverSaltUsed;
    /// @notice mapping from quorum number to the latest block that all quorums were updated all at once
    mapping(uint8 => uint256) public quorumUpdateBlockNumber;

    /// @notice the dynamic-length array of the registries this coordinator is coordinating
    /// 这是一个动态数组,存储了该协调器正在协调的所有注册表的地址。
    /// 这些注册表可能包括之前定义的 IBLSApkRegistry, IStakeRegistry 和 IIndexRegistry。这允许协调器管理多个相关的注册表。
    address[] public registries;
    /// @notice the address of the entity allowed to sign off on operators getting kicked out of the AVS during registration
    /// 这是一个允许签署操作员在注册过程中被踢出 AVS (Actively Validated Service) 的实体地址。它的作用是控制和批准操作员的更替过程,确保系统的稳定性和安全性。
    address public churnApprover;
    /// @notice the address of the entity allowed to eject operators from the AVS
    /// 这是一个允许将操作员从 AVS 中驱逐的实体地址。它可能具有紧急移除不良或有问题操作员的权力,以保护系统的完整性。
    address public ejector;

    constructor(
        IServiceManager _serviceManager,
        IStakeRegistry _stakeRegistry,
        IBLSApkRegistry _blsApkRegistry,
        IIndexRegistry _indexRegistry
    ) {
        serviceManager = _serviceManager;
        stakeRegistry = _stakeRegistry;
        blsApkRegistry = _blsApkRegistry;
        indexRegistry = _indexRegistry;
    }

    // storage gap for upgradeability
    // slither-disable-next-line shadowing-state
    uint256[41] private __GAP;
}
