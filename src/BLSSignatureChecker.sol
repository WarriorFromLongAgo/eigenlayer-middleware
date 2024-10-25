// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.12;

import {IBLSSignatureChecker} from "./interfaces/IBLSSignatureChecker.sol";
import {IRegistryCoordinator} from "./interfaces/IRegistryCoordinator.sol";
import {IBLSApkRegistry} from "./interfaces/IBLSApkRegistry.sol";
import {IStakeRegistry, IDelegationManager} from "./interfaces/IStakeRegistry.sol";

import {BitmapUtils} from "./libraries/BitmapUtils.sol";
import {BN254} from "./libraries/BN254.sol";

/**
 * @title Used for checking BLS aggregate signatures from the operators of a `BLSRegistry`.
 * @author Layr Labs, Inc.
 * @notice Terms of Service: https://docs.eigenlayer.xyz/overview/terms-of-service
 * @notice This is the contract for checking the validity of aggregate operator signatures.
 */
contract BLSSignatureChecker is IBLSSignatureChecker {
    using BN254 for BN254.G1Point;

    // CONSTANTS & IMMUTABLES

    // gas cost of multiplying 2 pairings
    uint256 internal constant PAIRING_EQUALITY_CHECK_GAS = 120000;

    IRegistryCoordinator public immutable registryCoordinator;
    IStakeRegistry public immutable stakeRegistry;
    IBLSApkRegistry public immutable blsApkRegistry;
    IDelegationManager public immutable delegation;
    /// @notice If true, check the staleness of the operator stakes and that its within the delegation withdrawalDelayBlocks window.
    bool public staleStakesForbidden;

    modifier onlyCoordinatorOwner() {
        require(msg.sender == registryCoordinator.owner(), "BLSSignatureChecker.onlyCoordinatorOwner: caller is not the owner of the registryCoordinator");
        _;
    }

    constructor(IRegistryCoordinator _registryCoordinator) {
        registryCoordinator = _registryCoordinator;
        stakeRegistry = _registryCoordinator.stakeRegistry();
        blsApkRegistry = _registryCoordinator.blsApkRegistry();
        delegation = stakeRegistry.delegation();

        staleStakesForbidden = true;
    }

    /**
     * RegistryCoordinator owner can either enforce or not that operator stakes are staler
     * than the delegation.minWithdrawalDelayBlocks() window.
     * @param value to toggle staleStakesForbidden
     */
    function setStaleStakesForbidden(bool value) external onlyCoordinatorOwner {
        staleStakesForbidden = value;
        emit StaleStakesForbiddenUpdate(value);
    }

    struct NonSignerInfo {
        uint256[] quorumBitmaps;
        bytes32[] pubkeyHashes;
    }

    /**
     * @notice This function is called by disperser when it has aggregated all the signatures of the operators
     * that are part of the quorum for a particular taskNumber and is asserting them into onchain. The function
     * checks that the claim for aggregated signatures are valid.
     *
     * The thesis of this procedure entails:
     * - getting the aggregated pubkey of all registered nodes at the time of pre-commit by the
     * disperser (represented by apk in the parameters),
     * - subtracting the pubkeys of all the signers not in the quorum (nonSignerPubkeys) and storing 
     * the output in apk to get aggregated pubkey of all operators that are part of quorum.
     * - use this aggregated pubkey to verify the aggregated signature under BLS scheme.
     * 
     * @dev Before signature verification, the function verifies operator stake information.  This includes ensuring that the provided `referenceBlockNumber`
     * is correct, i.e., ensure that the stake returned from the specified block number is recent enough and that the stake is either the most recent update
     * for the total stake (of the operator) or latest before the referenceBlockNumber.
     * @param msgHash is the hash being signed
     * @dev NOTE: Be careful to ensure `msgHash` is collision-resistant! This method does not hash 
     * `msgHash` in any way, so if an attacker is able to pass in an arbitrary value, they may be able
     * to tamper with signature verification.
     * @param quorumNumbers is the bytes array of quorum numbers that are being signed for
     * @param referenceBlockNumber is the block number at which the stake information is being verified
     * @param params is the struct containing information on nonsigners, stakes, quorum apks, and the aggregate signature
     * @return quorumStakeTotals is the struct containing the total and signed stake for each quorum
     * @return signatoryRecordHash is the hash of the signatory record, which is used for fraud proofs
     */
    //  @notice 当分散器已汇总特定 taskNumber 的法定人数的所有操作员的签名并将其声明到链上时，分散器将调用此函数。该函数检查聚合签名的声明是否有效。
    //  此过程的论点包括：
    //  - 在分散器预提交时获取所有注册节点的聚合公钥（在参数中用 apk 表示），
    //  - 减去所有不在法定人数中的签名者（nonSignerPubkeys）的公钥并将输出存储在 apk 中以获取法定人数中所有操作员的聚合公钥。
    //  - 使用此聚合公钥在 BLS 方案下验证聚合签名。
    //  @dev 在签名验证之前，该函数会验证操作员权益信息。这包括确保提供的 `referenceBlockNumber`
    //  是正确的，即确保从指定区块号返回的权益足够新，并且权益是总权益（运营商的）的最新更新，或 referenceBlockNumber 之前的最新权益。
    //  @param msgHash 是正在签名的哈希值
    //  @dev 注意：请务必确保 `msgHash` 具有抗碰撞性！此方法不会以任何方式对 `msgHash` 进行哈希处理，因此如果攻击者能够传入任意值，他们可能能够
    //  篡改签名验证。
    //  @param quorumNumbers 是正在签名的仲裁号码的字节数组
    //  @param referenceBlockNumber 是正在验证权益信息的区块编号
    //  @param params 是包含非签名者、权益、仲裁 apk 和聚合签名信息的结构
    //  @return quorumStakeTotals 是包含每个仲裁的总权益和已签名权益的结构
    //  @return signatoryRecordHash 是签名者记录的哈希值，用于欺诈证明
    function checkSignatures(
        bytes32 msgHash,
        bytes calldata quorumNumbers,
        uint32 referenceBlockNumber,
        NonSignerStakesAndSignature memory params
    )
    public
    view
    returns (
        QuorumStakeTotals memory,
        bytes32
    )
    {
        // 验证输入参数的有效性
        require(quorumNumbers.length != 0, "BLSSignatureChecker.checkSignatures: empty quorum input");

        require(
            (quorumNumbers.length == params.quorumApks.length) &&
            (quorumNumbers.length == params.quorumApkIndices.length) &&
            (quorumNumbers.length == params.totalStakeIndices.length) &&
            (quorumNumbers.length == params.nonSignerStakeIndices.length),
            "BLSSignatureChecker.checkSignatures: input quorum length mismatch"
        );

        require(
            params.nonSignerPubkeys.length == params.nonSignerQuorumBitmapIndices.length,
            "BLSSignatureChecker.checkSignatures: input nonsigner length mismatch"
        );

        require(referenceBlockNumber < uint32(block.number), "BLSSignatureChecker.checkSignatures: invalid reference block");

        // This method needs to calculate the aggregate pubkey for all signing operators across
        // all signing quorums. To do that, we can query the aggregate pubkey for each quorum
        // and subtract out the pubkey for each nonsigning operator registered to that quorum.
        //
        // In practice, we do this in reverse - calculating an aggregate pubkey for all nonsigners,
        // negating that pubkey, then adding the aggregate pubkey for each quorum.
        // 初始化聚合公钥和stake总量
        BN254.G1Point memory apk = BN254.G1Point(0, 0);

        // For each quorum, we're also going to query the total stake for all registered operators
        // at the referenceBlockNumber, and derive the stake held by signers by subtracting out
        // stakes held by nonsigners.
        // 对于每个法定人数，我们还将查询 referenceBlockNumber 中所有注册运营商的总股份
        // ，并通过减去非签名者持有的股份来得出签名者持有的股份
        QuorumStakeTotals memory stakeTotals;
        stakeTotals.totalStakeForQuorum = new uint96[](quorumNumbers.length);
        stakeTotals.signedStakeForQuorum = new uint96[](quorumNumbers.length);
        // 处理非签名者信息
        NonSignerInfo memory nonSigners;
        nonSigners.quorumBitmaps = new uint256[](params.nonSignerPubkeys.length);
        nonSigners.pubkeyHashes = new bytes32[](params.nonSignerPubkeys.length);

        {
            // Get a bitmap of the quorums signing the message, and validate that
            // quorumNumbers contains only unique, valid quorum numbers
            // 获取签名quorum的位图
            uint256 signingQuorumBitmap = BitmapUtils.orderedBytesArrayToBitmap(quorumNumbers, registryCoordinator.quorumCount());
            // 处理每个非签名者
            for (uint256 j = 0; j < params.nonSignerPubkeys.length; j++) {
                // The nonsigner's pubkey hash doubles as their operatorId
                // The check below validates that these operatorIds are sorted (and therefore
                // free of duplicates)
                // 计算非签名者的公钥哈希（作为operatorId）
                nonSigners.pubkeyHashes[j] = params.nonSignerPubkeys[j].hashG1Point();
                if (j != 0) {
                    require(
                        uint256(nonSigners.pubkeyHashes[j]) > uint256(nonSigners.pubkeyHashes[j - 1]),
                        "BLSSignatureChecker.checkSignatures: nonSignerPubkeys not sorted"
                    );
                }

                // Get the quorums the nonsigner was registered for at referenceBlockNumber
                // 获取非签名者在referenceBlockNumber时注册的quorums
                nonSigners.quorumBitmaps[j] =
                                    registryCoordinator.getQuorumBitmapAtBlockNumberByIndex({
                        operatorId: nonSigners.pubkeyHashes[j],
                        blockNumber: referenceBlockNumber,
                        index: params.nonSignerQuorumBitmapIndices[j]
                    });

                // Add the nonsigner's pubkey to the total apk, multiplied by the number
                // of quorums they have in common with the signing quorums, because their
                // public key will be a part of each signing quorum's aggregate pubkey
                // 将非签名者的公钥添加到总apk中
                apk = apk.plus(
                    params.nonSignerPubkeys[j]
                    .scalar_mul_tiny(
                        BitmapUtils.countNumOnes(nonSigners.quorumBitmaps[j] & signingQuorumBitmap)
                    )
                );
            }
        }
        // 对非签名者的聚合公钥进行取反
        // Negate the sum of the nonsigner aggregate pubkeys - from here, we'll add the
        // total aggregate pubkey from each quorum. Because the nonsigners' pubkeys are
        // in these quorums, this initial negation ensures they're cancelled out
        apk = apk.negate();

        /**
         * For each quorum (at referenceBlockNumber):
         * - add the apk for all registered operators
         * - query the total stake for each quorum
         * - subtract the stake for each nonsigner to calculate the stake belonging to signers
         */
        {
            bool _staleStakesForbidden = staleStakesForbidden;
            uint256 withdrawalDelayBlocks = _staleStakesForbidden ? delegation.minWithdrawalDelayBlocks() : 0;

            for (uint256 i = 0; i < quorumNumbers.length; i++) {
                // If we're disallowing stale stake updates, check that each quorum's last update block
                // is within withdrawalDelayBlocks
                if (_staleStakesForbidden) {
                    require(
                        registryCoordinator.quorumUpdateBlockNumber(uint8(quorumNumbers[i])) + withdrawalDelayBlocks > referenceBlockNumber,
                        "BLSSignatureChecker.checkSignatures: StakeRegistry updates must be within withdrawalDelayBlocks window"
                    );
                }

                // Validate params.quorumApks is correct for this quorum at the referenceBlockNumber,
                // then add it to the total apk
                require(
                    bytes24(params.quorumApks[i].hashG1Point()) ==
                    blsApkRegistry.getApkHashAtBlockNumberAndIndex({
                        quorumNumber: uint8(quorumNumbers[i]),
                        blockNumber: referenceBlockNumber,
                        index: params.quorumApkIndices[i]
                    }),
                    "BLSSignatureChecker.checkSignatures: quorumApk hash in storage does not match provided quorum apk"
                );
                apk = apk.plus(params.quorumApks[i]);

                // Get the total and starting signed stake for the quorum at referenceBlockNumber
                stakeTotals.totalStakeForQuorum[i] =
                                    stakeRegistry.getTotalStakeAtBlockNumberFromIndex({
                        quorumNumber: uint8(quorumNumbers[i]),
                        blockNumber: referenceBlockNumber,
                        index: params.totalStakeIndices[i]
                    });
                stakeTotals.signedStakeForQuorum[i] = stakeTotals.totalStakeForQuorum[i];

                // Keep track of the nonSigners index in the quorum
                uint256 nonSignerForQuorumIndex = 0;

                // loop through all nonSigners, checking that they are a part of the quorum via their quorumBitmap
                // if so, load their stake at referenceBlockNumber and subtract it from running stake signed
                for (uint256 j = 0; j < params.nonSignerPubkeys.length; j++) {
                    // if the nonSigner is a part of the quorum, subtract their stake from the running total
                    if (BitmapUtils.isSet(nonSigners.quorumBitmaps[j], uint8(quorumNumbers[i]))) {
                        stakeTotals.signedStakeForQuorum[i] -=
                                            stakeRegistry.getStakeAtBlockNumberAndIndex({
                                quorumNumber: uint8(quorumNumbers[i]),
                                blockNumber: referenceBlockNumber,
                                operatorId: nonSigners.pubkeyHashes[j],
                                index: params.nonSignerStakeIndices[i][nonSignerForQuorumIndex]
                            });
                        unchecked {
                            ++nonSignerForQuorumIndex;
                        }
                    }
                }
            }
        }
        {
            // verify the signature
            (bool pairingSuccessful, bool signatureIsValid) = trySignatureAndApkVerification(
                msgHash,
                apk,
                params.apkG2,
                params.sigma
            );
            require(pairingSuccessful, "BLSSignatureChecker.checkSignatures: pairing precompile call failed");
            require(signatureIsValid, "BLSSignatureChecker.checkSignatures: signature is invalid");
        }
        // set signatoryRecordHash variable used for fraudproofs
        bytes32 signatoryRecordHash = keccak256(abi.encodePacked(referenceBlockNumber, nonSigners.pubkeyHashes));

        // return the total stakes that signed for each quorum, and a hash of the information required to prove the exact signers and stake
        return (stakeTotals, signatoryRecordHash);
    }

    /**
     * trySignatureAndApkVerification verifies a BLS aggregate signature and the veracity of a calculated G1 Public key
     * @param msgHash is the hash being signed
     * @param apk is the claimed G1 public key
     * @param apkG2 is provided G2 public key
     * @param sigma is the G1 point signature
     * @return pairingSuccessful is true if the pairing precompile call was successful
     * @return siganatureIsValid is true if the signature is valid
     */
    function trySignatureAndApkVerification(
        bytes32 msgHash,
        BN254.G1Point memory apk,
        BN254.G2Point memory apkG2,
        BN254.G1Point memory sigma
    ) public view returns (bool pairingSuccessful, bool siganatureIsValid) {
        // gamma = keccak256(abi.encodePacked(msgHash, apk, apkG2, sigma))
        uint256 gamma = uint256(keccak256(abi.encodePacked(msgHash, apk.X, apk.Y, apkG2.X[0], apkG2.X[1], apkG2.Y[0], apkG2.Y[1], sigma.X, sigma.Y))) % BN254.FR_MODULUS;
        // verify the signature
        (pairingSuccessful, siganatureIsValid) = BN254.safePairing(
            sigma.plus(apk.scalar_mul(gamma)),
            BN254.negGeneratorG2(),
            BN254.hashToG1(msgHash).plus(BN254.generatorG1().scalar_mul(gamma)),
            apkG2,
            PAIRING_EQUALITY_CHECK_GAS
        );
    }

    // storage gap for upgradeability
    // slither-disable-next-line shadowing-state
    uint256[49] private __GAP;
}
