# Tip policy

Valid proof of work does not make a chain the real one. Zcash adjusts difficulty every
block (each block's target can be up to 1.32 times the window's mean), so a private fork
from the checkpoint lowers its difficulty fast:

| Difficulty reduction | Before NU7 (17-block window) | NU7 (102-block window) |
|---|---|---|
| ×2 | 17 blocks | 90 blocks |
| ×1,000 | 210 blocks | 1,187 blocks |
| ×10 million | about 500 blocks | about 2,800 blocks |

An endless fake chain costs about 26 honest blocks of work before NU7 and about 145
with NU7, and its timestamps are invented, so an attacker with 1% of the hashrate can
prepare one in about two days. The header rules alone stop nothing a patient attacker
who controls every source wants to show. The tip policy closes that.

## Rules

1. **Minimum chain work.** A checkpoint is `HEIGHT:HASH:MINWORK`: the work the honest
   chain carried from the checkpoint to a release height. `zylem-proxy` refuses to start,
   and strict mode refuses to present a tip, while the verified work after the
   checkpoint is below it. A fork made after the release height still has to beat the
   real chain's work, which the next rules enforce.
2. **Heaviest tail across Ring hosts.** `--rings` repeats. Sealed Rings are
   content-addressed, so honest hosts list the same ones; a host listing a different one
   is reported. Every host's open tail is verified and the one with the most work is
   served.
3. **Confirmation by independent sources.** A source confirms the tip when its chain
   contains it: a Ring host whose newest block is the tip, a header witness
   (`--headers-rpc`, a Zakura or zcashd JSON-RPC endpoint), or the upstream light-wallet
   server reporting the same block at that height. Strict mode needs `--min-sources`
   (default 2).
4. **Not outworked.** A header witness's blocks are verified header by header (Equihash,
   target, difficulty, time) from the served chain before they count. The tip fails if a
   witness shows more than `--max-behind` (default 12, five minutes at 25 s) verified
   blocks after it, a fork from a recent block with more verified work, or no shared
   block in the last 200. A light-wallet server serves no difficulty, so its height
   claims and disagreements only raise alarms: a lying upstream cannot stop every
   wallet.
5. **No headers from the future.** A header dated more than two hours after the
   verifier's clock is rejected, as nodes reject it.
6. **Stale-tip alarm.** If the newest block is older than `--stale-after` (default: the
   time in which no block arrives with probability 1 in 10,000, plus two minutes for
   miners' clocks: 350 s at 25-second blocks, 810 s at 75), the proxy raises an alarm.
   Silence that long means a source is withholding.

When the tip fails, strict mode answers `GetLatestBlock`, the call every wallet sync
starts with, with `UNAVAILABLE` and the reason; the wallet shows an error instead of a
weak chain. `GetLightdInfo`'s vendor string carries the verdict, and
`zylem-build probe --lwd URL` prints it. Alarms are logged.

## Checkpoints

```bash
zylem-build --network test checkpoint --rpc http://user:pass@127.0.0.1:18232/ \
    --height 4500000 --release 4526500 --out checkpoints/testnet.json
```

The command replays every header from the checkpoint to the release height through the
header rules and sums their work. `checkpoints/testnet.json` records the block, the
minimum work, the release block and the command that reproduces it, so anyone with a
node can check it.

## Tested on testnet (2026-10-22)

Sources: a Ring host following the node, a frozen copy of the same Rings (stale since
4,523,268), the testnet node as a header witness, and testnet.zec.rocks upstream.

| Setup | Verdict | Wallet's `GetLatestBlock` |
|---|---|---|
| Live host, frozen host, witness, upstream | tip ok, confirmed by 3 sources; alarm: frozen host lags at 4,523,268 | 4,526,662 |
| Frozen host only, with minimum work | proxy refuses to start: work after the checkpoint below the minimum | no proxy |
| Frozen host only, without minimum work | fails: the witness has 2,000 verified blocks after the tip; alarms: upstream reports 3,405 more, stale tip (84,833 s old) | refused with the reason |
| Live host and upstream, three sources required | fails: confirmed by 2 sources, 3 required | refused with the reason |

Unit tests cover heavier, lighter and deep forks, unverified height claims, the
minimum-work boundary, the stale-tip bound, headers two hours ahead, and 64-byte
transactions.

## Also rejected now

A v4 transaction of exactly 64 bytes. Its ID is SHA-256d of its bytes, like a Merkle
node of two 32-byte children, so it could stand in for a subtree and hide the
transactions under it (CVE-2017-12842). No valid v4 transaction is 64 bytes. v5 and v6
IDs are ZIP 244 BLAKE2b digests and cannot collide with a node.

## Limits

- A header witness is only as independent as its peers: two nodes eclipsed together
  confirm the same fake chain. Witnesses on different networks and operators help.
- The minimum work dates from the release height; between releases, protection comes
  from rules 2 to 4.
- `scripts/demo.sh` runs one Ring host per proxy and passes `--min-sources 1`, to show
  the content checks on their own.
