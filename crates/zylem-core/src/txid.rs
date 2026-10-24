//! Rebuilding transaction IDs from compact data plus auxiliary digests.
//!
//! ZIP 244 (v5) and ZIP 229 (v6) split each shielded component into a compact part,
//! which light wallets already receive, and parts they don't. Given the digests of the
//! parts they don't receive, a client can recompute the full transaction ID from the
//! compact part alone. A v4 transaction ID is a double SHA-256 of the whole
//! transaction, so v4 transactions travel in full.

use std::io::Write;

use blake2b_simd::{Hash as Blake2bHash, Params, State};
use zcash_primitives::transaction::{Transaction, TxVersion};
use zcash_protocol::consensus::BranchId;
use zylem_proto::{
    ring::{ActionsAux, SaplingAux, TxAux},
    rpc::{CompactOrchardAction, CompactSaplingOutput, CompactSaplingSpend, CompactTx, CompactTxIn, TxOut},
};

use crate::Reject;

const TX_PREFIX: &[u8; 12] = b"ZcashTxHash_";
const HEADERS: &[u8; 16] = b"ZTxIdHeadersHash";
const TRANSPARENT: &[u8; 16] = b"ZTxIdTranspaHash";
const PREVOUTS: &[u8; 16] = b"ZTxIdPrevoutHash";
const SEQUENCE: &[u8; 16] = b"ZTxIdSequencHash";
const OUTPUTS: &[u8; 16] = b"ZTxIdOutputsHash";
const SAPLING: &[u8; 16] = b"ZTxIdSaplingHash";
const S_SPENDS: &[u8; 16] = b"ZTxIdSSpendsHash";
const S_SPENDS_C: &[u8; 16] = b"ZTxIdSSpendCHash";
const S_SPENDS_N_V5: &[u8; 16] = b"ZTxIdSSpendNHash";
const S_SPENDS_N_V6: &[u8; 16] = b"ZTxIdSSpendNH_v6";
const S_OUTPUTS: &[u8; 16] = b"ZTxIdSOutputHash";
const S_OUTPUTS_C: &[u8; 16] = b"ZTxIdSOutC__Hash";
const S_OUTPUTS_M: &[u8; 16] = b"ZTxIdSOutM__Hash";
const S_OUTPUTS_N: &[u8; 16] = b"ZTxIdSOutN__Hash";

/// Personalization strings of an Orchard-shaped bundle (Orchard or Ironwood).
struct ActionsFormat {
    bundle: &'static [u8; 16],
    compact: &'static [u8; 16],
    memos: &'static [u8; 16],
    noncompact: &'static [u8; 16],
    anchor_in_txid: bool,
}

const ORCHARD_V5: ActionsFormat = ActionsFormat {
    bundle: b"ZTxIdOrchardHash",
    compact: b"ZTxIdOrcActCHash",
    memos: b"ZTxIdOrcActMHash",
    noncompact: b"ZTxIdOrcActNHash",
    anchor_in_txid: true,
};
const ORCHARD_V6: ActionsFormat = ActionsFormat {
    bundle: b"ZTxIdOrchardH_v6",
    compact: b"ZTxIdOrcActCHash",
    memos: b"ZTxIdOrcActMHash",
    noncompact: b"ZTxIdOrcActNHash",
    anchor_in_txid: false,
};
const IRONWOOD_V6: ActionsFormat = ActionsFormat {
    bundle: b"ZTxIdIronwd_H_v6",
    compact: b"ZTxIdIrnActCH_v6",
    memos: b"ZTxIdIrnActMH_v6",
    noncompact: b"ZTxIdIrnActNH_v6",
    anchor_in_txid: false,
};

fn hasher(personal: &[u8; 16]) -> State {
    Params::new().hash_length(32).personal(personal).to_state()
}

fn bytes32(h: Blake2bHash) -> Vec<u8> {
    h.as_bytes().to_vec()
}

fn arr32(bytes: &[u8], what: &'static str) -> Result<[u8; 32], Reject> {
    bytes
        .try_into()
        .map_err(|_| Reject::malformed(what, format!("{} bytes, expected 32", bytes.len())))
}

fn write_compact_size(out: &mut Vec<u8>, n: usize) {
    match n {
        0..=0xfc => out.push(n as u8),
        0xfd..=0xffff => {
            out.push(0xfd);
            out.extend_from_slice(&(n as u16).to_le_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(0xfe);
            out.extend_from_slice(&(n as u32).to_le_bytes());
        }
        _ => {
            out.push(0xff);
            out.extend_from_slice(&(n as u64).to_le_bytes());
        }
    }
}

// ---------------------------------------------------------------------------------
// Builder side: split a full transaction into its compact part and its aux digests.
// ---------------------------------------------------------------------------------

/// The compact form of a transaction, with every pool and its transparent data, in the
/// light-wallet protocol encoding. The coinbase input is omitted, as the protocol
/// specifies.
pub fn compact_from_tx(index: usize, tx: &Transaction) -> CompactTx {
    let mut ctx = CompactTx {
        index: index as u64,
        txid: tx.txid().as_ref().to_vec(),
        ..Default::default()
    };
    if let Some(t) = tx.transparent_bundle() {
        if !t.is_coinbase() {
            ctx.vin = t
                .vin
                .iter()
                .map(|i| CompactTxIn {
                    prevout_txid: i.prevout().hash().to_vec(),
                    prevout_index: i.prevout().n(),
                })
                .collect();
        }
        ctx.vout = t
            .vout
            .iter()
            .map(|o| TxOut {
                value: o.value().into_u64(),
                script_pub_key: o.script_pubkey().0 .0.clone(),
            })
            .collect();
    }
    if let Some(s) = tx.sapling_bundle() {
        ctx.spends = s
            .shielded_spends()
            .iter()
            .map(|sp| CompactSaplingSpend { nf: sp.nullifier().0.to_vec() })
            .collect();
        ctx.outputs = s
            .shielded_outputs()
            .iter()
            .map(|o| CompactSaplingOutput {
                cmu: o.cmu().to_bytes().to_vec(),
                ephemeral_key: o.ephemeral_key().as_ref().to_vec(),
                ciphertext: o.enc_ciphertext()[..52].to_vec(),
            })
            .collect();
    }
    let actions = |b: &orchard::Bundle<orchard::bundle::Authorized, _>| {
        b.actions()
            .iter()
            .map(|a| CompactOrchardAction {
                nullifier: a.nullifier().to_bytes().to_vec(),
                cmx: a.cmx().to_bytes().to_vec(),
                ephemeral_key: a.encrypted_note().epk_bytes.to_vec(),
                ciphertext: a.encrypted_note().enc_ciphertext.0[..52].to_vec(),
            })
            .collect()
    };
    if let Some(b) = tx.orchard_bundle() {
        ctx.actions = actions(b);
    }
    if let Some(b) = tx.ironwood_bundle() {
        ctx.ironwood_actions = actions(b);
    }
    ctx
}

fn version_number(v: TxVersion) -> u32 {
    match v {
        TxVersion::V4 => 4,
        TxVersion::V5 => 5,
        TxVersion::V6 => 6,
        _ => 0,
    }
}

fn actions_aux(
    b: &orchard::Bundle<orchard::bundle::Authorized, zcash_protocol::value::ZatBalance>,
    format: &ActionsFormat,
) -> ActionsAux {
    let mut mh = hasher(format.memos);
    let mut nh = hasher(format.noncompact);
    for a in b.actions().iter() {
        mh.update(&a.encrypted_note().enc_ciphertext.0[52..564]);
        nh.update(&a.cv_net().to_bytes());
        nh.update(&<[u8; 32]>::from(a.rk()));
        nh.update(&a.encrypted_note().enc_ciphertext.0[564..]);
        nh.update(&a.encrypted_note().out_ciphertext);
    }
    ActionsAux {
        memos_digest: bytes32(mh.finalize()),
        noncompact_digest: bytes32(nh.finalize()),
        flags: b.flag_byte() as u32,
        value_balance: i64::from(*b.value_balance()),
        anchor: if format.anchor_in_txid {
            b.anchor().to_bytes().to_vec()
        } else {
            vec![]
        },
    }
}

/// The digests of everything the compact form leaves out. For v4 it is the full
/// transaction.
pub fn aux_from_tx(tx: &Transaction) -> Result<TxAux, Reject> {
    let version = tx.version();
    if !matches!(version, TxVersion::V5 | TxVersion::V6) {
        let mut full = vec![];
        tx.write(&mut full).map_err(|e| Reject::malformed("transaction", e))?;
        return Ok(TxAux {
            version: version_number(version),
            full_tx: full,
            ..Default::default()
        });
    }
    let v6 = version == TxVersion::V6;
    let branch_id = u32::from(tx.consensus_branch_id());

    let mut hh = hasher(HEADERS);
    hh.update(&version.header().to_le_bytes());
    hh.update(&version.version_group_id().to_le_bytes());
    hh.update(&branch_id.to_le_bytes());
    hh.update(&tx.lock_time().to_le_bytes());
    hh.update(&u32::from(tx.expiry_height()).to_le_bytes());

    let mut aux = TxAux {
        version: version_number(version),
        branch_id,
        header_digest: bytes32(hh.finalize()),
        ..Default::default()
    };

    if let Some(t) = tx.transparent_bundle() {
        let mut sh = hasher(SEQUENCE);
        for i in &t.vin {
            sh.update(&i.sequence().to_le_bytes());
        }
        aux.has_transparent = true;
        aux.transparent_sequence_digest = bytes32(sh.finalize());
    }

    if let Some(s) = tx.sapling_bundle() {
        let mut sa = SaplingAux {
            value_balance: i64::from(*s.value_balance()),
            ..Default::default()
        };
        if !s.shielded_spends().is_empty() {
            let mut nh = hasher(if v6 { S_SPENDS_N_V6 } else { S_SPENDS_N_V5 });
            for sp in s.shielded_spends() {
                nh.update(&sp.cv().to_bytes());
                if !v6 {
                    nh.update(&sp.anchor().to_bytes());
                }
                nh.update(&<[u8; 32]>::from(*sp.rk()));
            }
            sa.spends_noncompact_digest = bytes32(nh.finalize());
        }
        if !s.shielded_outputs().is_empty() {
            let mut mh = hasher(S_OUTPUTS_M);
            let mut nh = hasher(S_OUTPUTS_N);
            for o in s.shielded_outputs() {
                mh.update(&o.enc_ciphertext()[52..564]);
                nh.update(&o.cv().to_bytes());
                nh.update(&o.enc_ciphertext()[564..]);
                nh.update(&o.out_ciphertext()[..]);
            }
            sa.outputs_memos_digest = bytes32(mh.finalize());
            sa.outputs_noncompact_digest = bytes32(nh.finalize());
        }
        aux.sapling = Some(sa);
    }

    if let Some(b) = tx.orchard_bundle() {
        aux.orchard = Some(actions_aux(b, if v6 { &ORCHARD_V6 } else { &ORCHARD_V5 }));
    }
    if let Some(b) = tx.ironwood_bundle() {
        aux.ironwood = Some(actions_aux(b, &IRONWOOD_V6));
    }
    Ok(aux)
}

// ---------------------------------------------------------------------------------
// Verifier side: rebuild the ID from what the client received.
// ---------------------------------------------------------------------------------

fn actions_digest(
    actions: &[CompactOrchardAction],
    aux: Option<&ActionsAux>,
    format: &ActionsFormat,
) -> Result<[u8; 32], Reject> {
    let mut h = hasher(format.bundle);
    let Some(aux) = aux else {
        if !actions.is_empty() {
            return Err(Reject::malformed("aux", "actions without a bundle"));
        }
        return Ok(h.finalize().as_bytes().try_into().unwrap());
    };
    if actions.is_empty() {
        return Err(Reject::malformed("aux", "bundle without actions"));
    }
    let mut ch = hasher(format.compact);
    for a in actions {
        ch.update(&arr32(&a.nullifier, "nullifier")?);
        ch.update(&arr32(&a.cmx, "cmx")?);
        ch.update(&arr32(&a.ephemeral_key, "ephemeral key")?);
        if a.ciphertext.len() != 52 {
            return Err(Reject::malformed("ciphertext", a.ciphertext.len()));
        }
        ch.update(&a.ciphertext);
    }
    h.update(ch.finalize().as_bytes());
    h.update(&arr32(&aux.memos_digest, "memos digest")?);
    h.update(&arr32(&aux.noncompact_digest, "noncompact digest")?);
    let flags = u8::try_from(aux.flags).map_err(|_| Reject::malformed("flags", aux.flags))?;
    h.update(&[flags]);
    h.update(&aux.value_balance.to_le_bytes());
    if format.anchor_in_txid {
        h.update(&arr32(&aux.anchor, "anchor")?);
    }
    Ok(h.finalize().as_bytes().try_into().unwrap())
}

fn sapling_digest(ctx: &CompactTx, aux: Option<&SaplingAux>) -> Result<[u8; 32], Reject> {
    let mut h = hasher(SAPLING);
    let Some(aux) = aux else {
        if !ctx.spends.is_empty() || !ctx.outputs.is_empty() {
            return Err(Reject::malformed("aux", "Sapling data without a bundle"));
        }
        return Ok(h.finalize().as_bytes().try_into().unwrap());
    };
    if ctx.spends.is_empty() && ctx.outputs.is_empty() {
        return Ok(h.finalize().as_bytes().try_into().unwrap());
    }

    let mut spends = hasher(S_SPENDS);
    if !ctx.spends.is_empty() {
        let mut ch = hasher(S_SPENDS_C);
        for s in &ctx.spends {
            ch.update(&arr32(&s.nf, "nullifier")?);
        }
        spends.update(ch.finalize().as_bytes());
        spends.update(&arr32(&aux.spends_noncompact_digest, "spends digest")?);
    }
    let mut outputs = hasher(S_OUTPUTS);
    if !ctx.outputs.is_empty() {
        let mut ch = hasher(S_OUTPUTS_C);
        for o in &ctx.outputs {
            ch.update(&arr32(&o.cmu, "cmu")?);
            ch.update(&arr32(&o.ephemeral_key, "ephemeral key")?);
            if o.ciphertext.len() != 52 {
                return Err(Reject::malformed("ciphertext", o.ciphertext.len()));
            }
            ch.update(&o.ciphertext);
        }
        outputs.update(ch.finalize().as_bytes());
        outputs.update(&arr32(&aux.outputs_memos_digest, "memos digest")?);
        outputs.update(&arr32(&aux.outputs_noncompact_digest, "outputs digest")?);
    }
    h.update(spends.finalize().as_bytes());
    h.update(outputs.finalize().as_bytes());
    h.update(&aux.value_balance.to_le_bytes());
    Ok(h.finalize().as_bytes().try_into().unwrap())
}

fn transparent_digest(index: usize, ctx: &CompactTx, aux: &TxAux) -> Result<[u8; 32], Reject> {
    let mut h = hasher(TRANSPARENT);
    if !aux.has_transparent {
        if !ctx.vin.is_empty() || !ctx.vout.is_empty() {
            return Err(Reject::malformed("aux", "transparent data without a bundle"));
        }
        return Ok(h.finalize().as_bytes().try_into().unwrap());
    }
    let mut prevouts = hasher(PREVOUTS);
    if index == 0 {
        // The coinbase input is omitted from compact data; its outpoint is null.
        prevouts.update(&[0; 32]);
        prevouts.update(&u32::MAX.to_le_bytes());
    }
    for i in &ctx.vin {
        prevouts.update(&arr32(&i.prevout_txid, "prevout")?);
        prevouts.update(&i.prevout_index.to_le_bytes());
    }
    let mut outputs = hasher(OUTPUTS);
    for o in &ctx.vout {
        let mut ser = Vec::with_capacity(9 + o.script_pub_key.len());
        ser.extend_from_slice(&o.value.to_le_bytes());
        write_compact_size(&mut ser, o.script_pub_key.len());
        ser.write_all(&o.script_pub_key).unwrap();
        outputs.update(&ser);
    }
    h.update(prevouts.finalize().as_bytes());
    h.update(&arr32(&aux.transparent_sequence_digest, "sequence digest")?);
    h.update(outputs.finalize().as_bytes());
    Ok(h.finalize().as_bytes().try_into().unwrap())
}

/// Rebuilds the ID of transaction `index` from its compact form and aux digests.
///
/// For v4, the full transaction is parsed and hashed, and its compact form must equal
/// the one supplied, so a server cannot pair honest full bytes with altered compact data.
pub fn rebuild_txid(
    height: u64,
    index: usize,
    ctx: &CompactTx,
    aux: &TxAux,
    branch_for_height: BranchId,
) -> Result<[u8; 32], Reject> {
    match aux.version {
        5 | 6 => {}
        4 => {
            // A v4 ID is SHA-256d of the bytes, like a Merkle node of two 32-byte children,
            // so a 64-byte "transaction" could stand in for a subtree (CVE-2017-12842) and
            // hide the transactions under it. No valid v4 transaction is 64 bytes: it needs
            // an input, and any input makes it longer. (v5 and v6 IDs are ZIP 244 BLAKE2b
            // digests, which cannot equal a node.)
            if aux.full_tx.len() == 64 {
                return Err(Reject::SixtyFourByteTransaction { height, index });
            }
            let tx = Transaction::read(&aux.full_tx[..], branch_for_height)
                .map_err(|e| Reject::malformed("v4 transaction", e))?;
            if tx.version() != TxVersion::V4 {
                return Err(Reject::malformed("v4 transaction", "not v4"));
            }
            let mut derived = compact_from_tx(index, &tx);
            derived.txid.clear();
            let mut given = ctx.clone();
            given.txid.clear();
            if derived != given {
                return Err(Reject::V4CompactMismatch { height, index });
            }
            return Ok(*tx.txid().as_ref());
        }
        v => return Err(Reject::Unsupported(format!("transaction version {v}"))),
    }
    let v6 = aux.version == 6;
    let header = arr32(&aux.header_digest, "header digest")?;
    let transparent = transparent_digest(index, ctx, aux)?;
    let sapling = sapling_digest(ctx, aux.sapling.as_ref())?;
    let orchard = actions_digest(
        &ctx.actions,
        aux.orchard.as_ref(),
        if v6 { &ORCHARD_V6 } else { &ORCHARD_V5 },
    )?;

    let mut personal = [0; 16];
    personal[..12].copy_from_slice(TX_PREFIX);
    personal[12..].copy_from_slice(&aux.branch_id.to_le_bytes());
    let mut h = hasher(&personal);
    h.update(&header);
    h.update(&transparent);
    h.update(&sapling);
    h.update(&orchard);
    if v6 {
        h.update(&actions_digest(&ctx.ironwood_actions, aux.ironwood.as_ref(), &IRONWOOD_V6)?);
    } else if !ctx.ironwood_actions.is_empty() || aux.ironwood.is_some() {
        return Err(Reject::malformed("aux", "Ironwood data in a v5 transaction"));
    }
    Ok(h.finalize().as_bytes().try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sixty_four_byte_v4_transactions_are_rejected() {
        let aux = TxAux { version: 4, full_tx: vec![0x04; 64], ..Default::default() };
        let r = rebuild_txid(500_000, 3, &CompactTx::default(), &aux, BranchId::Sapling);
        assert_eq!(r, Err(Reject::SixtyFourByteTransaction { height: 500_000, index: 3 }));
    }
}
