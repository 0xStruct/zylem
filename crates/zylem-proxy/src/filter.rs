//! Shaping verified compact blocks the way the light-wallet protocol asks for them.

use zylem_proto::rpc::{CompactBlock, CompactOrchardAction, PoolType};

#[derive(Clone, Copy, Default)]
pub struct Pools {
    pub transparent: bool,
    pub sapling: bool,
    pub orchard: bool,
    pub ironwood: bool,
}

impl Pools {
    /// No pool types means the legacy behaviour: the shielded pools only.
    pub fn from_request(types: &[i32]) -> Self {
        if types.is_empty() {
            return Pools { transparent: false, sapling: true, orchard: true, ironwood: true };
        }
        let has = |p: PoolType| types.contains(&(p as i32));
        Pools {
            transparent: has(PoolType::Transparent),
            sapling: has(PoolType::Sapling),
            orchard: has(PoolType::Orchard),
            ironwood: has(PoolType::Ironwood),
        }
    }
}

fn nullifier_only(a: &CompactOrchardAction) -> CompactOrchardAction {
    CompactOrchardAction { nullifier: a.nullifier.clone(), ..Default::default() }
}

/// Keeps only the requested pools' data and drops transactions left with none.
pub fn filter(cb: &CompactBlock, pools: Pools, nullifiers_only: bool) -> CompactBlock {
    let mut out = cb.clone();
    out.vtx = cb
        .vtx
        .iter()
        .filter_map(|tx| {
            let mut t = tx.clone();
            if !pools.transparent || nullifiers_only {
                t.vin.clear();
                t.vout.clear();
            }
            if !pools.sapling {
                t.spends.clear();
                t.outputs.clear();
            }
            if !pools.orchard {
                t.actions.clear();
            }
            if !pools.ironwood {
                t.ironwood_actions.clear();
            }
            if nullifiers_only {
                t.outputs.clear();
                t.actions = t.actions.iter().map(nullifier_only).collect();
                t.ironwood_actions = t.ironwood_actions.iter().map(nullifier_only).collect();
            }
            let empty = t.vin.is_empty()
                && t.vout.is_empty()
                && t.spends.is_empty()
                && t.outputs.is_empty()
                && t.actions.is_empty()
                && t.ironwood_actions.is_empty();
            (!empty).then_some(t)
        })
        .collect();
    if nullifiers_only {
        out.chain_metadata = None;
    }
    out
}
