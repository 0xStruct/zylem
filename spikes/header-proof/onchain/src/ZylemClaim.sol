// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.20;

/// @notice Reads a Zylem history claim (generation 0, claim v1): the public values of a
/// history proof. Integers are little-endian; hashes are in Zcash's internal byte order.
library ZylemClaim {
    struct Claim {
        uint64 firstHeight;
        bytes32 anchorHash;
        uint64 lastHeight;
        bytes32 lastHash;
        bytes32 work;
        uint32 leaves;
        bool equihashChecked;
    }

    error ClaimTooShort();

    function le64(bytes calldata b, uint256 at) private pure returns (uint64 v) {
        for (uint256 i = 0; i < 8; i++) v |= uint64(uint8(b[at + i])) << uint64(8 * i);
    }

    function le32(bytes calldata b, uint256 at) private pure returns (uint32 v) {
        for (uint256 i = 0; i < 4; i++) v |= uint32(uint8(b[at + i])) << uint32(8 * i);
    }

    /// Layout: leaf key (32), aggregation key (32), first height (8), anchor hash (32),
    /// start context (32), last height (8), last hash (32), end context (32), work (32,
    /// big-endian), leaves (4), Equihash flag (1), then the records commitment.
    function parse(bytes calldata pv) internal pure returns (Claim memory c) {
        if (pv.length <= 245) revert ClaimTooShort();
        c.firstHeight = le64(pv, 64);
        c.anchorHash = bytes32(pv[72:104]);
        c.lastHeight = le64(pv, 136);
        c.lastHash = bytes32(pv[144:176]);
        c.work = bytes32(pv[208:240]);
        c.leaves = le32(pv, 240);
        c.equihashChecked = pv[244] == 0x01;
    }
}
