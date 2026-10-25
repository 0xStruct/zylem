// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.20;

import {ISP1Verifier} from "../src/sp1/ISP1Verifier.sol";
import {SP1Verifier} from "../src/sp1/v6.1.0/SP1VerifierGroth16.sol";
import {ZylemClaim} from "../src/ZylemClaim.sol";
import {ZcashHeaderOracle} from "../src/ZcashHeaderOracle.sol";

/// The few Foundry cheatcodes these tests use, declared here instead of pulling in forge-std.
interface Vm {
    function readFileBinary(string calldata path) external view returns (bytes memory);
    function expectRevert() external;
}

contract ClaimReader {
    function parse(bytes calldata pv) external pure returns (ZylemClaim.Claim memory) {
        return ZylemClaim.parse(pv);
    }
}

/// Zylem's real history proof for testnet blocks 4,527,490 to 4,529,025, proved on an
/// RTX 5090 with Equihash and wrapped in Groth16 (356 bytes), checked by SP1's v6.1.0
/// verifier contract in a local EVM.
contract ZylemOnchainTest {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    event log_named_uint(string key, uint256 val);
    event log_named_bytes32(string key, bytes32 val);

    // Zylem's aggregation program (generation 0), as pinned by the demo page.
    bytes32 constant PROGRAM = 0x007d30f107c4bc577316a24437873fdcd918cbc9319ed6307a19584f876f34cb;
    // Block 4,529,025, internal byte order (displayed reversed: 000023ec5e9b…2f7a06).
    bytes32 constant TOP_HASH = 0x067a2fd9e461da4eb23755ec9a9d4bd9aa5d79cf84d192fa48729b5eec230000;

    ISP1Verifier verifier;
    bytes proof;
    bytes pv;

    function setUp() public {
        verifier = ISP1Verifier(address(new SP1Verifier()));
        proof = vm.readFileBinary("fixtures/history-4527490-4529025.groth16");
        pv = vm.readFileBinary("fixtures/history-4527490-4529025.pv");
    }

    function test_AcceptsZylemHistoryProof() public {
        // Copied to memory first, so the measured call does not include reading storage.
        (bytes memory v, bytes memory g) = (pv, proof);
        uint256 before = gasleft();
        verifier.verifyProof(PROGRAM, v, g);
        emit log_named_uint("verifyProof gas", before - gasleft());
        emit log_named_uint("proof bytes", proof.length);
        emit log_named_uint("public value bytes", pv.length);
    }

    function test_RefusesAlteredClaim() public {
        bytes memory bad = pv;
        bad[136] = bytes1(uint8(bad[136]) ^ 1); // claim a different last height
        vm.expectRevert();
        verifier.verifyProof(PROGRAM, bad, proof);
    }

    function test_RefusesAnotherProgram() public {
        vm.expectRevert();
        verifier.verifyProof(bytes32(uint256(PROGRAM) ^ 1), pv, proof);
    }

    function test_RefusesAlteredProof() public {
        bytes memory bad = proof;
        bad[200] = bytes1(uint8(bad[200]) ^ 1); // inside the Groth16 proof points
        vm.expectRevert();
        verifier.verifyProof(PROGRAM, pv, bad);
    }

    function test_ClaimSaysWhatWasProven() public {
        ZylemClaim.Claim memory c = new ClaimReader().parse(pv);
        require(c.firstHeight == 4_527_490, "first height");
        require(c.lastHeight == 4_529_025, "last height");
        require(c.lastHash == TOP_HASH, "top block hash");
        require(c.leaves == 3, "leaves");
        require(c.equihashChecked, "Equihash");
        emit log_named_uint("last height", c.lastHeight);
        emit log_named_bytes32("last hash (internal order)", c.lastHash);
    }

    /// The two whole-Ring proofs the demo's light Rings are checked against, each 8 leaves
    /// of 512 headers: verified, read and recorded by the example oracle.
    function test_AcceptsWholeRingProofs() public {
        string[2] memory names = ["fixtures/history-4518274-4522369", "fixtures/history-4526466-4530561"];
        uint64[2] memory firsts = [uint64(4_518_274), 4_526_466];
        bytes32[2] memory tops = [
            bytes32(0x5339bbe62b48a5142ccdf223011b114edf332d0f715da49d9f709ea5b8040000),
            bytes32(0x7e6beb25ea7ad1b195c8a14a0ae734da49e140a98c84657725563a6b96250000)
        ];
        ZcashHeaderOracle oracle = new ZcashHeaderOracle(verifier, PROGRAM);
        for (uint256 i = 0; i < 2; i++) {
            bytes memory g = vm.readFileBinary(string.concat(names[i], ".groth16"));
            bytes memory v = vm.readFileBinary(string.concat(names[i], ".pv"));
            uint256 before = gasleft();
            verifier.verifyProof(PROGRAM, v, g);
            emit log_named_uint("verifyProof gas", before - gasleft());
            ZylemClaim.Claim memory c = new ClaimReader().parse(v);
            require(c.firstHeight == firsts[i] && c.lastHeight == firsts[i] + 4_095, "a whole Ring");
            require(c.leaves == 8 && c.equihashChecked, "8 leaves with Equihash");
            require(c.lastHash == tops[i], "top block hash");
            before = gasleft();
            oracle.submit(v, g);
            emit log_named_uint("submit gas (verify + parse + store)", before - gasleft());
            require(oracle.blockHash(c.lastHeight) == tops[i], "stored hash");
        }
    }

    function test_OracleRecordsTheProvenBlockHash() public {
        ZcashHeaderOracle oracle = new ZcashHeaderOracle(verifier, PROGRAM);
        (bytes memory v, bytes memory g) = (pv, proof);
        uint256 before = gasleft();
        oracle.submit(v, g);
        emit log_named_uint("submit gas (verify + parse + store)", before - gasleft());
        require(oracle.blockHash(4_529_025) == TOP_HASH, "stored hash");
    }
}
