# Zylem history proof on an EVM

Checks Zylem's real history proof with SP1's own Groth16 verifier contract in a local EVM
(Foundry), and shows what a contract learns from it.

- `fixtures/`: the history proof for testnet blocks 4,527,490 to 4,529,025, proved on an
  RTX 5090 with Equihash and wrapped in Groth16 (356 bytes), and its public values (the
  697-byte claim). Copied from `data/publish/smoke`.
- `src/sp1/`: `ISP1Verifier.sol` and the v6.1.0 `SP1VerifierGroth16.sol` and
  `Groth16Verifier.sol`, copied unchanged (MIT) from
  [succinctlabs/sp1-contracts](https://github.com/succinctlabs/sp1-contracts) at commit
  `d362972`. v6.1.0 is the circuit version of SP1 6.9.0, which made the proof.
- `src/ZylemClaim.sol`: reads the claim (heights, top block hash, work, leaves, Equihash).
- `src/ZcashHeaderOracle.sol`: an example consumer that pins Zylem's aggregation program,
  accepts a proof and records the Zcash block hash at the top of the proven range.

```
forge test -vv
```

Results, 2026-10-27, Foundry 1.1.0, solc 0.8.28 with the optimizer:

| Test | Result |
|---|---|
| The proof verifies under Zylem's aggregation program key | passes, 303,762 gas for `verifyProof` |
| The claim reads blocks 4,527,490 to 4,529,025, top hash `000023ec…2f7a06`, 3 leaves, Equihash checked | passes |
| The example oracle verifies, parses and stores the top block hash | passes, 334,361 gas for `submit` |
| A claim with one byte changed (the last height) | refused |
| Another program's key | refused |
| A proof with one byte changed | refused, after consuming the call's gas |

The gas figures are for the calls inside the EVM; a transaction also pays its base cost
and about 17,000 gas for the 1 KB of calldata. A bad proof fails in the pairing check by
using up its gas, so a submitter should simulate before sending.

Not covered: a freshness rule (accept only ranges a set depth below a proven tip with
enough work), linking submitted ranges to each other, transaction inclusion paths, and any
deployment to a real chain.
