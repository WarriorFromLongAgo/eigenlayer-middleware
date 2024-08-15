// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.12;

import {EIP1271SignatureUtils} from
    "eigenlayer-contracts/src/contracts/libraries/EIP1271SignatureUtils.sol";

/**
 * @title SignatureCheckerLib
 * @dev This library wraps the EIP1271SignatureUtils library to provide an external function for signature validation.
 * This approach helps in reducing the code size of the RegistryCoordinator contract by offloading the signature
 * validation logic to this external library.
 */
library SignatureCheckerLib {
    /**
     * @notice Validates a signature using EIP-1271 standard.
     * @param signer The address of the signer.
     * @param digestHash The hash of the data that was signed.
     * @param signature The signature to be validated.
     */
    function isValidSignature(
        address signer,
        bytes32 digestHash,
        bytes memory signature
    ) external view {
        EIP1271SignatureUtils.checkSignature_EIP1271(signer, digestHash, signature);
    }
}
