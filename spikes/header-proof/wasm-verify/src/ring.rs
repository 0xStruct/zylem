//! A Ring file opened in the browser: what is inside, the full client check, and the
//! block records that bind it to a history proof. The same `zylem-core` code a native
//! client runs.

use std::cell::RefCell;

use serde_json::{json, Value};
use wasm_bindgen::prelude::*;
use zcash_protocol::consensus::Network;
use zylem_core::{block, header::Header, ring, tamper};
use zylem_header::{record_of, RECORD_SIZE};
use zylem_proto::{ring::Ring, Message};

fn err(e: impl core::fmt::Display) -> JsError {
    JsError::new(&e.to_string())
}

/// Hashes are stored in internal byte order; explorers show them reversed.
fn display(b: &[u8]) -> String {
    let mut v = b.to_vec();
    v.reverse();
    hex::encode(v)
}

#[wasm_bindgen]
pub struct RingFile {
    ring: Ring,
    network: Network,
    file_bytes: usize,
    raw_bytes: usize,
    /// Rebuilt transaction IDs per block, filled in by `verify`.
    txids: RefCell<Option<Vec<Vec<[u8; 32]>>>>,
    /// For a copy made by `attacked`: what the attack changed.
    altered: Option<String>,
}

#[wasm_bindgen]
impl RingFile {
    /// Decodes a Ring file (zstd over protobuf). Nothing is trusted yet.
    #[wasm_bindgen(constructor)]
    pub fn new(bytes: &[u8]) -> Result<RingFile, JsError> {
        let ring = ring::decode_file(bytes).map_err(err)?;
        let network = match ring.network.as_str() {
            "main" | "mainnet" => Network::MainNetwork,
            _ => Network::TestNetwork,
        };
        let raw_bytes = ring.encoded_len();
        Ok(RingFile { ring, network, file_bytes: bytes.len(), raw_bytes, txids: RefCell::new(None), altered: None })
    }

    /// What the Ring holds, by pool, and how big each part is.
    pub fn summary(&self) -> String {
        let r = &self.ring;
        let (mut txs, mut vin, mut vout, mut spends, mut outputs, mut orchard, mut ironwood) = (0, 0, 0, 0, 0, 0, 0);
        let (mut header_bytes, mut compact_bytes, mut aux_bytes, mut v4_full) = (0, 0, 0, 0);
        for b in &r.blocks {
            header_bytes += b.header.len();
            aux_bytes += b.aux.iter().map(|a| a.encoded_len()).sum::<usize>();
            v4_full += b.aux.iter().filter(|a| !a.full_tx.is_empty()).count();
            if let Some(cb) = &b.block {
                compact_bytes += cb.encoded_len();
                txs += cb.vtx.len();
                for t in &cb.vtx {
                    vin += t.vin.len();
                    vout += t.vout.len();
                    spends += t.spends.len();
                    outputs += t.outputs.len();
                    orchard += t.actions.len();
                    ironwood += t.ironwood_actions.len();
                }
            }
        }
        let start = r.start.as_ref();
        json!({
            "network": r.network,
            "format": r.format,
            "start_height": r.start_height,
            "end_height": r.end_height,
            "blocks": r.blocks.len(),
            "sealed": !r.next_header.is_empty(),
            "transactions": txs,
            "v4_with_full_bytes": v4_full,
            "transparent": {"inputs": vin, "outputs": vout},
            "sapling": {"spends": spends, "outputs": outputs},
            "orchard_actions": orchard,
            "ironwood_actions": ironwood,
            "bytes": {
                "file": self.file_bytes,
                "decompressed": self.raw_bytes,
                "headers": header_bytes,
                "compact_blocks": compact_bytes,
                "aux": aux_bytes,
            },
            "start_state": start.map(|s| json!({
                "sapling_frontier_bytes": s.sapling_frontier.len(),
                "orchard_frontier_bytes": s.orchard_frontier.len(),
                "ironwood_frontier_bytes": s.ironwood_frontier.len(),
                "history_nodes": s.history_length,
                "history_peaks": s.history_peaks.len(),
            })),
        })
        .to_string()
    }

    /// One line per block: height, hash, time, transactions, shielded actions.
    pub fn blocks(&self) -> String {
        let rows: Vec<Value> = self
            .ring
            .blocks
            .iter()
            .enumerate()
            .map(|(i, b)| {
                let cb = b.block.as_ref();
                let shielded: usize = cb.map_or(0, |c| c.vtx.iter().map(|t| t.spends.len() + t.outputs.len() + t.actions.len() + t.ironwood_actions.len()).sum());
                json!([
                    self.ring.start_height + i as u64,
                    cb.map(|c| display(&c.hash)).unwrap_or_default(),
                    cb.map_or(0, |c| c.time),
                    cb.map_or(0, |c| c.vtx.len()),
                    shielded,
                ])
            })
            .collect();
        Value::Array(rows).to_string()
    }

    /// One block in detail: its header fields and every transaction with the ID rebuilt
    /// from compact data plus aux (and matched to the header's Merkle root).
    pub fn block(&self, height: u32) -> Result<String, JsError> {
        let h = height as u64;
        if h < self.ring.start_height || h > self.ring.end_height {
            return Err(JsError::new("height outside this Ring"));
        }
        let rb = &self.ring.blocks[(h - self.ring.start_height) as usize];
        let header = Header::parse_unchecked(h, &rb.header).map_err(err)?;
        let vb = block::verify(&header, rb, &self.network).map_err(err)?;
        let cb = rb.block.as_ref().ok_or_else(|| JsError::new("no compact block"))?;
        let txs: Vec<Value> = cb
            .vtx
            .iter()
            .zip(&rb.aux)
            .zip(&vb.txids)
            .map(|((t, a), id)| {
                let actions = |x: &Option<zylem_proto::ring::ActionsAux>| x.as_ref().map(|y| y.value_balance);
                json!({
                    "index": t.index,
                    "txid": display(id),
                    "version": a.version,
                    "transparent": {"inputs": t.vin.len(), "outputs": t.vout.len(),
                                     "output_values": t.vout.iter().map(|o| o.value).collect::<Vec<_>>()},
                    "sapling": {"spends": t.spends.len(), "outputs": t.outputs.len(), "value_balance": a.sapling.as_ref().map(|s| s.value_balance)},
                    "orchard": {"actions": t.actions.len(), "value_balance": actions(&a.orchard)},
                    "ironwood": {"actions": t.ironwood_actions.len(), "value_balance": actions(&a.ironwood)},
                    "aux_bytes": a.encoded_len(),
                    "compact_bytes": t.encoded_len(),
                })
            })
            .collect();
        Ok(json!({
            "height": h,
            "hash": display(&header.hash),
            "prev_hash": display(&header.prev_hash),
            "merkle_root": display(&header.merkle_root),
            "block_commitments": display(&header.commitments),
            "time": header.time,
            "bits": format!("{:08x}", header.bits),
            "header_bytes": rb.header.len(),
            "roots_after": {
                "sapling": display(&rb.sapling_root),
                "orchard": display(&rb.orchard_root),
                "ironwood": display(&rb.ironwood_root),
            },
            "transactions": txs,
            "merkle_root_matches": true,
        })
        .to_string())
    }

    /// The whole client check, as `zylem-core` runs it natively: Equihash, targets and
    /// links for every header (difficulty and time rules once enough predecessors are in
    /// the Ring), every transaction ID rebuilt and matched to its Merkle root, the history
    /// tree against every following header, and the note commitment trees against the
    /// authenticated roots. Throws with the typed reason on the first failure.
    pub fn verify(&self) -> Result<String, JsError> {
        let v = ring::verify(&self.network, &self.ring, None).map_err(err)?;
        let txs: usize = v.blocks.iter().map(|b| b.txids.len()).sum();
        *self.txids.borrow_mut() = Some(v.blocks.iter().map(|b| b.txids.clone()).collect());
        let mut work = [0u8; 32];
        v.work.to_big_endian(&mut work);
        Ok(json!({
            "start_height": v.start_height,
            "end_height": v.end_height(),
            "blocks": v.blocks.len(),
            "transactions": txs,
            "authenticated_to": v.authenticated_to,
            "difficulty_checked_from": v.context_checked_from,
            "work": hex::encode(work),
            "last_hash": display(&v.last_header().hash),
        })
        .to_string())
    }

    /// Finds a transaction by its ID among the IDs rebuilt by `verify`.
    pub fn find_tx(&self, txid_display: &str) -> Result<String, JsError> {
        let mut want = hex::decode(txid_display.trim()).map_err(err)?;
        want.reverse();
        let ids = self.txids.borrow();
        let ids = ids.as_ref().ok_or_else(|| JsError::new("verify the Ring first"))?;
        for (i, block_ids) in ids.iter().enumerate() {
            if let Some(index) = block_ids.iter().position(|id| id[..] == want[..]) {
                return Ok(json!({"height": self.ring.start_height + i as u64, "index": index, "of": block_ids.len()}).to_string());
            }
        }
        Err(JsError::new("not in this Ring"))
    }

    /// The 104-byte record of every block in `from..=to` (hash, Merkle root, block
    /// commitments, time, bits): what a history proof commits to.
    pub fn records(&self, from: u32, to: u32) -> Result<Vec<u8>, JsError> {
        let (from, to) = (from as u64, to as u64);
        if from < self.ring.start_height || to > self.ring.end_height || from > to {
            return Err(JsError::new("range outside this Ring"));
        }
        let mut out = Vec::with_capacity((to - from + 1) as usize * RECORD_SIZE);
        for h in from..=to {
            let rb = &self.ring.blocks[(h - self.ring.start_height) as usize];
            let header = Header::parse_unchecked(h, &rb.header).map_err(err)?;
            out.extend_from_slice(&record_of(&rb.header, &header.hash));
        }
        Ok(out)
    }

    /// Checks only the headers of `from..=to` (Equihash, own target, links): the part a
    /// history proof covering them replaces.
    pub fn check_headers(&self, from: u32, to: u32) -> Result<u32, JsError> {
        let (from, to) = (from as u64, to as u64);
        if from < self.ring.start_height || to > self.ring.end_height || from > to {
            return Err(JsError::new("range outside this Ring"));
        }
        let mut prev: Option<[u8; 32]> = None;
        for h in from..=to {
            let rb = &self.ring.blocks[(h - self.ring.start_height) as usize];
            let header = Header::parse_and_check(h, &rb.header).map_err(err)?;
            if prev.is_some_and(|p| p != header.prev_hash) {
                return Err(JsError::new(&format!("header {h} does not link to its predecessor")));
            }
            prev = Some(header.hash);
        }
        Ok((to - from + 1) as u32)
    }

    /// A copy of this Ring altered the way a dishonest host would: `inject` a fake
    /// Ironwood note, `hide` a transaction, or `tree` (a wrong starting tree state). The
    /// copy has not been checked; `verify` on it shows what a client does.
    pub fn attacked(&self, attack: &str, height: u32, tx_index: Option<u32>) -> Result<RingFile, JsError> {
        let a = match attack {
            "inject" => tamper::Attack::Inject,
            "hide" => tamper::Attack::Hide,
            "tree" => tamper::Attack::Tree,
            _ => return Err(JsError::new("attack is inject, hide or tree")),
        };
        let mut ring = self.ring.clone();
        let what = tamper::apply(&mut ring, a, height as u64, tx_index.map(|i| i as usize)).map_err(|e| JsError::new(&e))?;
        let raw_bytes = ring.encoded_len();
        Ok(RingFile { ring, network: self.network, file_bytes: self.file_bytes, raw_bytes, txids: RefCell::new(None), altered: Some(what) })
    }

    /// What `attacked` changed, if this is an altered copy.
    #[wasm_bindgen(getter)]
    pub fn altered(&self) -> Option<String> {
        self.altered.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn start_height(&self) -> u32 {
        self.ring.start_height as u32
    }

    #[wasm_bindgen(getter)]
    pub fn end_height(&self) -> u32 {
        self.ring.end_height as u32
    }
}
