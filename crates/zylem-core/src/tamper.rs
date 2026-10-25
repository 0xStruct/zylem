//! What a dishonest Ring host would do, for demonstrations and tests: each attack alters a
//! decoded Ring in place, the way a server would before re-encoding and re-hashing it, so
//! only verification can catch it.

use zylem_proto::ring::Ring;

use crate::tree::Trees;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Attack {
    /// Add a fake Ironwood action to a transaction (a fake incoming note).
    Inject,
    /// Leave a whole transaction out of a block (a hidden payment).
    Hide,
    /// Replace the Ring's starting Ironwood frontier with a different one of the same size
    /// (wrong tree states, so a wallet builds bad anchors).
    Tree,
}

/// The first block at or after `height` with a transaction that has Ironwood actions.
fn target(ring: &Ring, height: u64) -> Option<(usize, usize)> {
    for (bi, rb) in ring.blocks.iter().enumerate() {
        let cb = rb.block.as_ref()?;
        if cb.height < height {
            continue;
        }
        if let Some(ti) = cb.vtx.iter().position(|t| !t.ironwood_actions.is_empty()) {
            return Some((bi, ti));
        }
    }
    None
}

/// Applies `attack` at `height` (to transaction `tx_index` of that block if given, else to
/// the first Ironwood transaction at or after it) and says what changed. A fake note added
/// to a transaction with no Ironwood actions is copied from elsewhere in the Ring.
pub fn apply(ring: &mut Ring, attack: Attack, height: u64, tx_index: Option<usize>) -> Result<String, String> {
    match attack {
        Attack::Inject | Attack::Hide => {
            // Any real Ironwood action in the Ring, for a target transaction that has none.
            let any_action = ring
                .blocks
                .iter()
                .filter_map(|b| b.block.as_ref())
                .flat_map(|cb| cb.vtx.iter())
                .find_map(|t| t.ironwood_actions.first().cloned());
            let (bi, ti) = match tx_index {
                Some(ti) => (height.checked_sub(ring.start_height).ok_or("height before this Ring")? as usize, ti),
                None => target(ring, height).ok_or("no Ironwood transaction at or after that height")?,
            };
            let rb = ring.blocks.get_mut(bi).ok_or("height after this Ring")?;
            let cb = rb.block.as_mut().ok_or("no compact block")?;
            let h = cb.height;
            if ti >= cb.vtx.len() {
                return Err(format!("block {h} has {} transactions", cb.vtx.len()));
            }
            if attack == Attack::Inject {
                let mut fake = cb.vtx[ti].ironwood_actions.first().cloned().or(any_action).ok_or("no Ironwood action in this Ring to copy")?;
                fake.nullifier[0] ^= 0x5a;
                fake.ciphertext[0] ^= 0x5a;
                cb.vtx[ti].ironwood_actions.push(fake);
                Ok(format!("added a fake Ironwood action to transaction {ti} of block {h}"))
            } else {
                cb.vtx.remove(ti);
                rb.aux.remove(ti);
                for (i, t) in cb.vtx.iter_mut().enumerate() {
                    t.index = i as u64;
                }
                Ok(format!("removed transaction {ti} from block {h}"))
            }
        }
        Attack::Tree => {
            let start = ring.start.as_mut().ok_or("no start state")?;
            let mut t = Trees::decode(&start.sapling_frontier, &start.orchard_frontier, &start.ironwood_frontier).map_err(|e| e.to_string())?;
            let nf = t.ironwood.value().ok_or("empty Ironwood frontier")?;
            // Same position and size, different leaf: the root changes, the sizes don't.
            let leaf = <orchard::tree::MerkleHashOrchard as incrementalmerkletree::Hashable>::empty_leaf();
            t.ironwood = incrementalmerkletree::frontier::Frontier::from_parts(nf.position(), leaf, nf.ommers().to_vec())
                .map_err(|e| format!("{e:?}"))?;
            start.ironwood_frontier = t.encode()[2].clone();
            Ok(format!("replaced the Ironwood frontier before block {}", ring.start_height))
        }
    }
}
