// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.20;

import {ISP1Verifier} from "./sp1/ISP1Verifier.sol";
import {ZylemClaim} from "./ZylemClaim.sol";

/// @notice An example consumer: accepts Zylem history proofs (Groth16-wrapped SP1 proofs)
/// and records the Zcash block hash at the top of each proven range. It trusts SP1's
/// verifier, the aggregation program whose key it pins, and the Groth16 setup. It has no
/// freshness rule and no link between submitted ranges; a production client needs both.
contract ZcashHeaderOracle {
    ISP1Verifier public immutable verifier;
    bytes32 public immutable programVKey;

    /// Zcash block hash (internal byte order) by height, for proven range tops.
    mapping(uint64 => bytes32) public blockHash;

    event RangeProven(uint64 firstHeight, uint64 lastHeight, bytes32 lastHash, uint32 leaves);

    error EquihashNotChecked();

    constructor(ISP1Verifier verifier_, bytes32 programVKey_) {
        verifier = verifier_;
        programVKey = programVKey_;
    }

    function submit(bytes calldata publicValues, bytes calldata proofBytes) external {
        verifier.verifyProof(programVKey, publicValues, proofBytes);
        ZylemClaim.Claim memory c = ZylemClaim.parse(publicValues);
        if (!c.equihashChecked) revert EquihashNotChecked();
        blockHash[c.lastHeight] = c.lastHash;
        emit RangeProven(c.firstHeight, c.lastHeight, c.lastHash, c.leaves);
    }
}
