//! Light Rings: blocks a history proof covers carry their 104-byte records instead of
//! headers. The fixture Ring is checked against a records commitment built here, which
//! stands in for a verified proof's claim.

use zcash_protocol::consensus::Network;
use zylem_core::{
    header::Header,
    ring::{self, Proven},
    Reject,
};
use zylem_header::{range_paths, Peaks, RECORD_SIZE};
use zylem_proto::ring::Ring;

const FIXTURE: &[u8] = include_bytes!("data/ring-4521976-4521982.zst");
const NET: Network = Network::TestNetwork;
const FIRST: u64 = 4_521_976;
const PAYMENT_BLOCK: usize = 4;
const PAYMENT_TX: usize = 4;

fn fixture() -> Ring {
    ring::decode_file(FIXTURE).unwrap()
}

fn record(r: &Ring, height: u64) -> [u8; RECORD_SIZE] {
    Header::parse_unchecked(height, &r.blocks[(height - FIRST) as usize].header).unwrap().record()
}

/// A proof's commitment to `first..=FIRST + 6`, with `before` as the records of any
/// blocks it covers before the fixture.
struct Proof {
    first: u64,
    anchor: [u8; 32],
    records: Vec<[u8; RECORD_SIZE]>,
    peaks: Peaks,
}

impl Proof {
    fn new(first: u64, before: &[[u8; RECORD_SIZE]]) -> Self {
        let r = fixture();
        let mut records = before.to_vec();
        records.extend((first.max(FIRST)..=FIRST + 6).map(|h| record(&r, h)));
        let anchor = if first > FIRST {
            record(&r, first - 1)[..32].try_into().unwrap()
        } else if first == FIRST {
            Header::parse_unchecked(FIRST, &r.blocks[0].header).unwrap().prev_hash
        } else {
            [7; 32]
        };
        let peaks = Peaks::of_records(first, &records);
        Proof { first, anchor, records, peaks }
    }

    fn paths(&self, light_first: u64, light_last: u64) -> Vec<Vec<[u8; 32]>> {
        let (from, to) = Proven::binding_range(self.first, light_first, light_last);
        range_paths(self.first, &self.records, from, to)
    }

    fn check(&self, r: &Ring, paths: &[Vec<[u8; 32]>]) -> Result<ring::VerifiedRing, Reject> {
        let p = Proven {
            first_height: self.first,
            last_height: FIRST + 6,
            anchor_hash: self.anchor,
            equihash_checked: true,
            records: &self.peaks,
            paths,
        };
        ring::verify_light(&NET, r, None, &p)
    }
}

fn light(from: u64, to: u64, prev_record: Option<[u8; RECORD_SIZE]>) -> Ring {
    let mut r = fixture();
    ring::lighten(&mut r, from, to, prev_record).unwrap();
    r
}

#[test]
fn header_record_matches_the_proof_programs_record() {
    let r = fixture();
    for (i, b) in r.blocks.iter().enumerate() {
        let h = Header::parse_unchecked(FIRST + i as u64, &b.header).unwrap();
        assert_eq!(h.record(), zylem_header::record_of(&b.header, &h.hash));
    }
}

#[test]
fn light_blocks_inside_the_proof_verify_like_the_full_ring() {
    let proof = Proof::new(FIRST + 1, &[]);
    let r = light(FIRST + 2, FIRST + 5, None);
    let v = proof.check(&r, &proof.paths(FIRST + 2, FIRST + 5)).unwrap();
    let full = ring::verify(&NET, &fixture(), None).unwrap();
    assert_eq!(v.light, Some((FIRST + 2, FIRST + 5)));
    assert_eq!(v.authenticated_to, full.authenticated_to);
    assert_eq!(v.work, full.work);
    let ids = |v: &ring::VerifiedRing| v.blocks.iter().map(|b| b.txids.clone()).collect::<Vec<_>>();
    assert_eq!(ids(&v), ids(&full));
    assert!(ring::encode_file(&r).len() < FIXTURE.len());
}

#[test]
fn a_light_run_at_the_proofs_start_links_to_its_anchor() {
    let proof = Proof::new(FIRST + 1, &[]);
    let r = light(FIRST + 1, FIRST + 6, None);
    assert!(proof.check(&r, &proof.paths(FIRST + 1, FIRST + 6)).is_ok());

    let mut wrong = proof;
    wrong.anchor = [9; 32];
    assert_eq!(wrong.check(&r, &wrong.paths(FIRST + 1, FIRST + 6)).err(), Some(Reject::BrokenChain { height: FIRST + 1 }));
}

#[test]
fn a_ring_starting_inside_the_proof_carries_its_predecessors_record() {
    // The proof starts one block before the fixture; that block's record carries the hash
    // the fixture's first header links to.
    let mut before = [[3u8; RECORD_SIZE]];
    before[0][..32].copy_from_slice(&Header::parse_unchecked(FIRST, &fixture().blocks[0].header).unwrap().prev_hash);
    let proof = Proof::new(FIRST - 1, &before);
    let r = light(FIRST, FIRST + 6, Some(before[0]));
    assert!(proof.check(&r, &proof.paths(FIRST, FIRST + 6)).is_ok());

    let mut missing = r.clone();
    missing.prev_record.clear();
    assert!(matches!(proof.check(&missing, &proof.paths(FIRST, FIRST + 6)), Err(Reject::Malformed { .. })));

    let mut forged = r;
    forged.prev_record[96] ^= 1;
    assert_eq!(proof.check(&forged, &proof.paths(FIRST, FIRST + 6)).err(), Some(Reject::RecordNotProven { height: FIRST }));
}

#[test]
fn a_light_ring_needs_a_proof() {
    let r = light(FIRST + 2, FIRST + 5, None);
    assert_eq!(ring::verify(&NET, &r, None).err(), Some(Reject::RecordNotProven { height: FIRST + 2 }));
}

#[test]
fn records_outside_the_proof_are_refused() {
    let proof = Proof::new(FIRST + 3, &[]);
    let r = light(FIRST + 2, FIRST + 5, None);
    assert_eq!(proof.check(&r, &proof.paths(FIRST + 3, FIRST + 5)).err(), Some(Reject::RecordNotProven { height: FIRST + 2 }));
}

#[test]
fn a_record_the_proof_does_not_commit_to_is_refused() {
    // The newest block of an open tail has no later header to commit to it. A host shifts
    // its time in the record and the compact block alike, so every check inside the Ring
    // agrees; only the proof can tell.
    let proof = Proof::new(FIRST + 1, &[]);
    let mut r = light(FIRST + 2, FIRST + 6, None);
    r.next_header.clear();
    assert!(proof.check(&r, &proof.paths(FIRST + 2, FIRST + 6)).is_ok());
    let rb = &mut r.blocks[6];
    let t = u32::from_le_bytes(rb.record[96..100].try_into().unwrap()) + 1;
    rb.record[96..100].copy_from_slice(&t.to_le_bytes());
    rb.block.as_mut().unwrap().time = t;
    assert_eq!(proof.check(&r, &proof.paths(FIRST + 2, FIRST + 6)).err(), Some(Reject::RecordNotProven { height: FIRST + 2 }));
}

#[test]
fn a_binding_for_other_heights_is_refused() {
    let proof = Proof::new(FIRST + 1, &[]);
    let r = light(FIRST + 2, FIRST + 5, None);
    assert_eq!(proof.check(&r, &proof.paths(FIRST + 1, FIRST + 4)).err(), Some(Reject::RecordNotProven { height: FIRST + 2 }));
}

#[test]
fn a_fake_note_in_a_light_block_is_still_caught() {
    let proof = Proof::new(FIRST + 1, &[]);
    let mut r = light(FIRST + 2, FIRST + 5, None);
    let tx = &mut r.blocks[PAYMENT_BLOCK].block.as_mut().unwrap().vtx[PAYMENT_TX];
    let mut fake = tx.ironwood_actions[0].clone();
    fake.nullifier[0] ^= 1;
    tx.ironwood_actions.push(fake);
    assert_eq!(
        proof.check(&r, &proof.paths(FIRST + 2, FIRST + 5)).err(),
        Some(Reject::TxIdMismatch { height: FIRST + PAYMENT_BLOCK as u64, index: PAYMENT_TX })
    );
}

#[test]
fn a_full_ring_passes_verify_light() {
    let proof = Proof::new(FIRST + 1, &[]);
    let v = proof.check(&fixture(), &[]).unwrap();
    assert_eq!(v.light, None);
}
