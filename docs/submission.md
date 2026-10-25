Zylem: verify every block your Zcash light wallet receives

WHAT IT DOES
A Zcash light wallet trusts its server. The server can show a payment that never happened, hide one that did, or hand out a wrong note commitment tree, and the wallet cannot tell. Zylem removes that trust. The wallet checks everything it receives against block headers it verifies itself:
- every header from a checkpoint: Equihash, its target, the difficulty and time rules, chain work;
- every transaction ID rebuilt from the compact data wallets already get plus a few hundred bytes of digests, and matched to the header's Merkle root;
- the ZIP 221 history tree replayed to authenticate every block's note commitment roots.

Blocks travel as Rings: one file per 4,096 blocks, named by its hash. Any static host or CDN can serve them, because the client re-checks every block inside. SP1 proofs compress the header checks: one 1.27 MB proof covers any number of headers, Equihash included, so a phone checks a whole range in about 60 ms. A 356-byte Groth16 wrap of the same proof takes Zcash block facts to smart contracts.

Three ways in:
- zylem-proxy: a drop-in light-wallet server. An unmodified wallet changes one URL.
- A 1.8 MB WebAssembly client that verifies Rings and proofs in a browser. The live demo runs it, with no node and no server.
- SP1's own Groth16 verifier contract, for other chains.

Trusted: a checkpoint, the cryptography and honest-majority hashpower (plus SP1 when using proofs). Not trusted: Ring hosts, mirrors and upstream servers.

WHY IT DOES NOT LEAK
- Every wallet downloads whole Rings, the same files for everyone. The host learns which height range was fetched, not which notes, addresses or transactions the wallet cares about. Trial decryption and payment lookup stay on the device.
- Verification uses no keys and sends nothing: Rings, proofs and block records are public data, checked locally.
- Rings are named by their hash, so a host cannot hand one user a tailored file without it failing the checks.
- Zylem adds no new queries. What still reaches an upstream server, exactly as today: broadcasting a transaction, fetching a full transaction, transparent-address lookups and the mempool. Hiding those (OHTTP, PIR) is planned, not built. The proxy is meant to run on the user's own machine.

WHAT IS REAL
- Zcash testnet after NU7 (Ironwood): 10 sealed Rings, 40,960 blocks (4,493,698 to 4,534,657), built from a pruned Zakura node. Two independent builds are byte-identical.
- An unmodified zcash-devtool wallet syncs through zylem-proxy. A fake note, a hidden payment and a wrong tree state are each rejected with a typed error.
- The header rules pass on 1.55M real testnet headers and agree with Zakura on 400,000 random contexts.
- Real GPU proofs (SP1 6.9.0, one RTX 5090, Equihash proven): blocks 4,465,026 to 4,481,409 (32 leaves of 512 headers), and 4,527,490 to 4,529,025 with its 356-byte Groth16 wrap. About 5 minutes and $0.09 per 512-header leaf.
- In a browser: a full Ring check takes about 2.5 s, a history proof about 60 ms, the Groth16 wrap about 0.3 s.
- SP1's Groth16 verifier contract (v6.1.0) accepts the wrap in a local EVM for 303,762 gas, and refuses an altered claim, another program's key and an altered proof.
- Light Rings: proven blocks carry 104-byte records instead of 1,487-byte headers, checked against the proof natively and in the browser.

WHAT IS A MOCK OR NOT DONE
- The demo's attacks are simulated: the page edits a real Ring the way a malicious server would, then runs the real checks on it.
- Testnet only. The proofs cover two ranges, not all of NU7; about 90 more leaves close the gap. The generation 1 program registry is tested with mock and small CPU proofs only.
- Nothing is deployed on a chain. The oracle contract is an example, without a freshness rule.
- Light Rings work, but no proof covers a whole Ring yet: the one light Ring, with 1,536 of its 4,096 blocks proven, is 5.10 MB instead of 7.19 MB (about 2 MB once fully proven). zylem-proxy reads only full Rings.
- The mempool and the completeness of transparent-address lookups are not verified.

Live demo: https://zylem.cash/demo/


---- SHORT VERSION (under 2,000 characters) ----

Zylem lets a Zcash light wallet verify every block it receives instead of trusting its server, which today can fake a payment, hide one, or serve a wrong note tree undetected.

WHAT IT DOES
From a checkpoint, the wallet checks each header (Equihash, difficulty, chain work), rebuilds every transaction ID and matches the Merkle root, and replays the ZIP 221 history tree to authenticate note commitment roots. Blocks ship as Rings: hash-named files of 4,096 blocks that any CDN can host. SP1 proofs compress header checks: one 1.27 MB proof covers a whole range (a phone verifies it in ~60 ms); a 356-byte Groth16 wrap brings it on-chain. Use it via zylem-proxy (drop-in server, wallet changes one URL), a WebAssembly client, or SP1's verifier contract.

WHY IT DOES NOT LEAK
Every wallet downloads whole Rings, the same files for everyone: the host sees a height range, not your notes or addresses. Verification is local, uses no keys and sends nothing. Hash-named Rings can't be tailored to one user. Zylem adds no queries; sending a transaction, full-transaction and transparent lookups still go upstream as today (OHTTP/PIR planned).

REAL (testnet, NU7)
- 10 Rings, 40,960 blocks, byte-identical across builds
- Unmodified zcash-devtool wallet syncs via zylem-proxy; fake note, hidden payment, wrong tree state all rejected
- Header rules pass on 1.55M real headers
- Real SP1 GPU proofs with Equihash: 32 leaves (16,384 blocks) and a 3-leaf range with its Groth16 wrap
- Browser: Ring check ~2.5 s, proof ~60 ms
- SP1's Groth16 contract accepts the wrap in a local EVM: 303,762 gas
- Light Rings: proven blocks carry 104-byte records, not headers (7.19 → 5.10 MB with 1,536 blocks proven)

MOCK / NOT DONE
- Demo attacks are simulated: the page tampers a real Ring, real checks reject it
- Testnet only; proofs cover two ranges, not all of NU7
- No on-chain deployment
- Mempool not verified

Live demo: https://zylem.cash/demo/
