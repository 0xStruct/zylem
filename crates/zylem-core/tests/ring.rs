//! A real 7-block testnet Ring (heights 4,521,976 to 4,521,982, around a zdlc contract's
//! settlement) verifies, and every way a server could alter it is rejected with its
//! typed error.

use zcash_protocol::consensus::Network;
use zylem_core::{ring, tree::Trees, Reject};
use zylem_proto::ring::Ring;

const FIXTURE: &[u8] = include_bytes!("data/ring-4521976-4521982.zst");
const NET: Network = Network::TestNetwork;
/// Block 4,521,980 holds the contract's cooperative close, an Ironwood payment, at index 4.
const PAYMENT_BLOCK: usize = 4;
const PAYMENT_TX: usize = 4;

fn fixture() -> Ring {
    ring::decode_file(FIXTURE).unwrap()
}

fn verify(r: &Ring) -> Result<(), Reject> {
    ring::verify(&NET, r, None).map(|_| ())
}

#[test]
fn honest_ring_verifies_and_authenticates_every_block() {
    let r = fixture();
    let v = ring::verify(&NET, &r, None).unwrap();
    assert_eq!(v.start_height, 4_521_976);
    assert_eq!(v.end_height(), 4_521_982);
    assert_eq!(v.authenticated_to, 4_521_982);
    let payment = &r.blocks[PAYMENT_BLOCK].block.as_ref().unwrap().vtx[PAYMENT_TX];
    assert!(!payment.ironwood_actions.is_empty(), "the fixture's payment is an Ironwood payment");
}

#[test]
fn encoding_is_deterministic() {
    assert_eq!(ring::encode_file(&fixture()), FIXTURE);
}

#[test]
fn fake_incoming_note_is_rejected() {
    let mut r = fixture();
    let tx = &mut r.blocks[PAYMENT_BLOCK].block.as_mut().unwrap().vtx[PAYMENT_TX];
    let mut fake = tx.ironwood_actions[0].clone();
    fake.nullifier[0] ^= 1;
    tx.ironwood_actions.push(fake);
    assert_eq!(verify(&r), Err(Reject::TxIdMismatch { height: 4_521_980, index: PAYMENT_TX }));
}

#[test]
fn altered_ciphertext_is_rejected() {
    // Garbling the compact ciphertext would hide the note from trial decryption.
    let mut r = fixture();
    let tx = &mut r.blocks[PAYMENT_BLOCK].block.as_mut().unwrap().vtx[PAYMENT_TX];
    tx.ironwood_actions[0].ciphertext[0] ^= 1;
    assert_eq!(verify(&r), Err(Reject::TxIdMismatch { height: 4_521_980, index: PAYMENT_TX }));
}

#[test]
fn dropped_action_is_rejected() {
    let mut r = fixture();
    let tx = &mut r.blocks[PAYMENT_BLOCK].block.as_mut().unwrap().vtx[PAYMENT_TX];
    tx.ironwood_actions.pop();
    assert!(matches!(verify(&r), Err(Reject::Malformed { .. }) | Err(Reject::TxIdMismatch { .. })));
}

#[test]
fn hidden_transaction_is_rejected() {
    let mut r = fixture();
    let rb = &mut r.blocks[PAYMENT_BLOCK];
    let cb = rb.block.as_mut().unwrap();
    cb.vtx.remove(PAYMENT_TX);
    rb.aux.remove(PAYMENT_TX);
    for (i, t) in cb.vtx.iter_mut().enumerate() {
        t.index = i as u64;
    }
    assert_eq!(verify(&r), Err(Reject::MerkleMismatch { height: 4_521_980 }));
}

#[test]
fn duplicated_transaction_is_rejected() {
    // Repeating the last transaction keeps the Merkle root (CVE-2012-2459).
    let mut r = fixture();
    let rb = &mut r.blocks[PAYMENT_BLOCK];
    let cb = rb.block.as_mut().unwrap();
    let mut last = cb.vtx.last().unwrap().clone();
    last.index = cb.vtx.len() as u64;
    cb.vtx.push(last);
    rb.aux.push(rb.aux.last().unwrap().clone());
    let res = verify(&r);
    assert!(
        matches!(res, Err(Reject::DuplicateTxId { height: 4_521_980 }) | Err(Reject::MerkleMismatch { height: 4_521_980 })),
        "{res:?}"
    );
}

#[test]
fn wrong_start_frontier_is_rejected() {
    let mut r = fixture();
    let start = r.start.as_mut().unwrap();
    let mut t = Trees::decode(&start.sapling_frontier, &start.orchard_frontier, &start.ironwood_frontier).unwrap();
    let nf = t.ironwood.value().unwrap().clone();
    let leaf = <orchard::tree::MerkleHashOrchard as incrementalmerkletree::Hashable>::empty_leaf();
    t.ironwood = incrementalmerkletree::frontier::Frontier::from_parts(nf.position(), leaf, nf.ommers().to_vec()).unwrap();
    start.ironwood_frontier = t.encode()[2].clone();
    assert_eq!(verify(&r), Err(Reject::TreeRootMismatch { height: 4_521_982, pool: "Ironwood" }));
}

#[test]
fn forged_tree_root_claim_is_rejected() {
    // A claimed per-block root feeds the history tree, which the next header commits to.
    let mut r = fixture();
    r.blocks[2].ironwood_root[0] ^= 1;
    assert_eq!(verify(&r), Err(Reject::HistoryMismatch { height: 4_521_979 }));
}

#[test]
fn bad_proof_of_work_is_rejected() {
    let mut r = fixture();
    let h = &mut r.blocks[3].header;
    let n = h.len();
    h[n - 1] ^= 1; // last byte of the Equihash solution
    assert_eq!(verify(&r), Err(Reject::PowInvalid { height: 4_521_979 }));
}

#[test]
fn reordered_blocks_break_the_chain() {
    let mut r = fixture();
    r.blocks.swap(1, 2);
    let res = verify(&r);
    assert!(matches!(res, Err(Reject::BrokenChain { .. }) | Err(Reject::HistoryMismatch { .. })), "{res:?}");
}

#[test]
fn missing_next_header_leaves_last_block_unauthenticated() {
    let mut r = fixture();
    r.next_header.clear();
    r.next_auth_data_root.clear();
    let v = ring::verify(&NET, &r, None).unwrap();
    assert_eq!(v.authenticated_to, 4_521_981);
}
