//! Claim v2 and the program registry.
//!
//! Proving programs are frozen as compiled files and registered: an append-only list of
//! entries says which program key may prove which kind of claim for which network, era
//! and heights, and which keys are revoked from which height on. The aggregation program
//! holds no Zcash rules; it checks each child's key against the registry, joins the two
//! ranges, and states the registry root it checked against. A client pins registry roots
//! instead of program keys, so adding an era or replacing a program needs no new client.

use alloc::{string::String, vec::Vec};
use primitive_types::U256;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{Input, Join, Net, Output, Peaks, PEAK_SIZE};

pub const CLAIM_MAGIC: [u8; 4] = *b"ZYLC";
pub const CLAIM_VERSION: u8 = 2;
/// The era of a claim or entry that is not tied to one era: aggregates.
pub const ANY_ERA: u8 = 0xff;
const REGISTRY_DOMAIN: &[u8] = b"zylem program registry v1";
/// The `last` height of an entry with no end yet. It is the largest integer JSON readers
/// in JavaScript keep exact, so `registry.json` survives a browser unchanged.
pub const OPEN_END: u64 = (1 << 53) - 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Kind {
    /// Proves up to `LEAF_SIZE` headers of one era.
    HeaderLeaf,
    /// Joins two adjacent claims.
    Aggregate,
}

impl Kind {
    fn byte(self) -> u8 {
        match self {
            Kind::HeaderLeaf => 1,
            Kind::Aggregate => 2,
        }
    }
    fn from_byte(b: u8) -> Option<Self> {
        match b {
            1 => Some(Kind::HeaderLeaf),
            2 => Some(Kind::Aggregate),
            _ => None,
        }
    }
}

fn net_byte(n: Net) -> u8 {
    match n {
        Net::Main => 0,
        Net::Test => 1,
    }
}

fn net_from(b: u8) -> Option<Net> {
    match b {
        0 => Some(Net::Main),
        1 => Some(Net::Test),
        _ => None,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Action {
    /// `key` may prove `kind` claims for `net`, `era` and heights `first..=last`.
    Allow,
    /// `key` may no longer prove any claim that reaches height `first` or above. From 0
    /// it is revoked outright; from a later height it is retired, as when an era's end is
    /// set after its program was registered with an open end.
    Revoke,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub action: Action,
    pub kind: Kind,
    pub net: Net,
    pub era: u8,
    pub first: u64,
    pub last: u64,
    /// The program key as the zkVM sees it (`hash_u32`); the same eight words are the
    /// STARK verifier's key.
    pub key: [u32; 8],
    pub sp1_version: String,
}

impl Entry {
    fn encode(&self, out: &mut Vec<u8>) {
        out.push(match self.action {
            Action::Allow => 1,
            Action::Revoke => 2,
        });
        out.push(self.kind.byte());
        out.push(net_byte(self.net));
        out.push(self.era);
        out.extend_from_slice(&self.first.to_le_bytes());
        out.extend_from_slice(&self.last.to_le_bytes());
        key_bytes(&self.key, out);
        out.push(self.sp1_version.len() as u8);
        out.extend_from_slice(self.sp1_version.as_bytes());
    }

    fn decode(b: &[u8]) -> Option<(Entry, usize)> {
        const FIXED: usize = 4 + 8 + 8 + 32 + 1;
        if b.len() < FIXED {
            return None;
        }
        let n = b[FIXED - 1] as usize;
        let version = core::str::from_utf8(b.get(FIXED..FIXED + n)?).ok()?;
        let entry = Entry {
            action: match b[0] {
                1 => Action::Allow,
                2 => Action::Revoke,
                _ => return None,
            },
            kind: Kind::from_byte(b[1])?,
            net: net_from(b[2])?,
            era: b[3],
            first: u64::from_le_bytes(b[4..12].try_into().unwrap()),
            last: u64::from_le_bytes(b[12..20].try_into().unwrap()),
            key: key_from(&b[20..52]),
            sp1_version: String::from(version),
        };
        let mut check = Vec::new();
        entry.encode(&mut check);
        (check == b[..FIXED + n]).then_some((entry, FIXED + n))
    }
}

/// Why a child claim cannot be joined under a registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refused {
    Range(Join),
    OtherNetwork,
    /// A leaf claim with aggregate fields set, or the reverse.
    Malformed,
    /// The leaf's key is not allowed for its era and heights, or is revoked for them.
    LeafNotAllowed,
    AggregateNotAllowed,
    /// An aggregate child states a key other than the one its proof was checked with.
    KeyMismatch,
    /// An aggregate child was made under a registry that is not a prefix of this one.
    UnknownRegistry,
    /// A revocation added after the child's registry reaches the child's heights, so it
    /// may contain a revoked leaf and must be joined again from its leaves.
    StaleRegistry,
    OwnKeyNotAllowed,
}

/// The append-only list of program entries.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Registry {
    pub entries: Vec<Entry>,
}

impl Registry {
    /// The root after each prefix of the entries, from the empty registry to all of them:
    /// `r0 = H(domain)`, `r(i+1) = H(r(i) || entry i)`.
    pub fn prefix_roots(&self) -> Vec<[u8; 32]> {
        let mut roots = Vec::with_capacity(self.entries.len() + 1);
        let mut r: [u8; 32] = Sha256::digest(REGISTRY_DOMAIN).into();
        roots.push(r);
        let mut buf = Vec::new();
        for e in &self.entries {
            buf.clear();
            e.encode(&mut buf);
            let mut h = Sha256::new();
            h.update(r);
            h.update(&buf);
            r = h.finalize().into();
            roots.push(r);
        }
        roots
    }

    pub fn root(&self) -> [u8; 32] {
        *self.prefix_roots().last().unwrap()
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(self.entries.len() as u32).to_le_bytes());
        for e in &self.entries {
            e.encode(&mut out);
        }
        out
    }

    pub fn decode(b: &[u8]) -> Option<Self> {
        let n = u32::from_le_bytes(b.get(..4)?.try_into().unwrap()) as usize;
        let mut at = 4;
        let mut entries = Vec::with_capacity(n.min(1024));
        for _ in 0..n {
            let (e, used) = Entry::decode(&b[at..])?;
            entries.push(e);
            at += used;
        }
        (at == b.len()).then_some(Registry { entries })
    }

    fn revoked_in(entries: &[Entry], key: &[u32; 8], last_height: u64) -> bool {
        entries.iter().any(|e| e.action == Action::Revoke && e.key == *key && e.first <= last_height)
    }

    /// Whether `key` may prove a `kind` claim for `net`, `era` (ignored for aggregates)
    /// and `first..=last`.
    pub fn allows(&self, kind: Kind, net: Net, era: u8, first: u64, last: u64, key: &[u32; 8]) -> bool {
        let allowed = self.entries.iter().any(|e| {
            e.action == Action::Allow
                && e.kind == kind
                && e.net == net
                && (kind == Kind::Aggregate || e.era == era)
                && e.first <= first
                && last <= e.last
                && e.key == *key
        });
        allowed && !Self::revoked_in(&self.entries, key, last)
    }

    /// Whether a claim made under the prefix with root `root` is still sound under the
    /// whole registry: no revocation added since reaches `last_height`.
    pub fn current_for(&self, root: &[u8; 32], last_height: u64) -> Result<(), Refused> {
        let at = self.prefix_roots().iter().position(|r| r == root).ok_or(Refused::UnknownRegistry)?;
        if self.entries[at..].iter().any(|e| e.action == Action::Revoke && e.first <= last_height) {
            return Err(Refused::StaleRegistry);
        }
        Ok(())
    }
}

/// What a v2 proof publishes, for leaves and aggregates alike.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Claim {
    pub kind: Kind,
    pub net: Net,
    /// A leaf's era; `ANY_ERA` for an aggregate.
    pub era: u8,
    /// An aggregate's registry root, the one it checked its children against. Zero in a
    /// leaf.
    pub registry_root: [u8; 32],
    /// An aggregate's own program key. Zero in a leaf: a program cannot know its own key,
    /// and the aggregate above it checks the leaf's key instead.
    pub program: [u32; 8],
    pub first_height: u64,
    /// Hash of the block before `first_height`.
    pub anchor_hash: [u8; 32],
    pub start_context_hash: [u8; 32],
    pub last_height: u64,
    pub last_hash: [u8; 32],
    pub end_context_hash: [u8; 32],
    /// Total work, big-endian.
    pub work: [u8; 32],
    pub leaves: u32,
    pub equihash_checked: bool,
    pub records: Peaks,
}

/// Size of a v2 claim before its records commitment.
pub const CLAIM_FIXED: usize = 4 + 1 + 1 + 1 + 1 + 32 + 32 + 8 + 32 + 32 + 8 + 32 + 32 + 32 + 4 + 1;

fn key_bytes(key: &[u32; 8], out: &mut Vec<u8>) {
    for w in key {
        out.extend_from_slice(&w.to_le_bytes());
    }
}

fn key_from(b: &[u8]) -> [u32; 8] {
    let mut key = [0u32; 8];
    for (i, w) in key.iter_mut().enumerate() {
        *w = u32::from_le_bytes(b[i * 4..i * 4 + 4].try_into().unwrap());
    }
    key
}

impl Claim {
    /// A leaf's claim about the segment it proved.
    pub fn leaf(input: &Input, out: &Output) -> Self {
        Claim {
            kind: Kind::HeaderLeaf,
            net: input.net,
            era: input.net.era(input.first_height),
            registry_root: [0; 32],
            program: [0; 8],
            first_height: input.first_height,
            anchor_hash: input.anchor_hash,
            start_context_hash: out.context_hash,
            last_height: out.last_height,
            last_hash: out.last_hash,
            end_context_hash: out.end_context_hash,
            work: out.work,
            leaves: 1,
            equihash_checked: out.equihash_checked,
            records: out.records.clone(),
        }
    }

    /// Checks a child proved with `key` may be joined under `registry`.
    fn admit(&self, key: &[u32; 8], registry: &Registry) -> Result<(), Refused> {
        if !self.records.is_canonical(self.first_height, self.last_height) {
            return Err(Refused::Range(Join::BadRecords));
        }
        match self.kind {
            Kind::HeaderLeaf => {
                if self.leaves != 1 || self.registry_root != [0; 32] || self.program != [0; 8] {
                    return Err(Refused::Malformed);
                }
                if !registry.allows(Kind::HeaderLeaf, self.net, self.era, self.first_height, self.last_height, key) {
                    return Err(Refused::LeafNotAllowed);
                }
            }
            Kind::Aggregate => {
                if self.era != ANY_ERA || self.leaves < 2 {
                    return Err(Refused::Malformed);
                }
                if self.program != *key {
                    return Err(Refused::KeyMismatch);
                }
                if !registry.allows(Kind::Aggregate, self.net, ANY_ERA, self.first_height, self.last_height, key) {
                    return Err(Refused::AggregateNotAllowed);
                }
                registry.current_for(&self.registry_root, self.last_height)?;
            }
        }
        Ok(())
    }

    /// The aggregate claim covering `left` followed directly by `right`, each proved with
    /// the key beside it, made by the aggregation program with key `own` under `registry`.
    pub fn join(
        left: (&Self, &[u32; 8]),
        right: (&Self, &[u32; 8]),
        registry: &Registry,
        own: &[u32; 8],
    ) -> Result<Self, Refused> {
        let ((l, lk), (r, rk)) = (left, right);
        if l.net != r.net {
            return Err(Refused::OtherNetwork);
        }
        if r.anchor_hash != l.last_hash {
            return Err(Refused::Range(Join::NotAdjacent));
        }
        if r.first_height != l.last_height + 1 {
            return Err(Refused::Range(Join::HeightGap));
        }
        if r.start_context_hash != l.end_context_hash {
            return Err(Refused::Range(Join::ContextMismatch));
        }
        l.admit(lk, registry)?;
        r.admit(rk, registry)?;
        if !registry.allows(Kind::Aggregate, l.net, ANY_ERA, l.first_height, r.last_height, own) {
            return Err(Refused::OwnKeyNotAllowed);
        }
        let mut work = [0u8; 32];
        (U256::from_big_endian(&l.work) + U256::from_big_endian(&r.work)).to_big_endian(&mut work);
        Ok(Claim {
            kind: Kind::Aggregate,
            net: l.net,
            era: ANY_ERA,
            registry_root: registry.root(),
            program: *own,
            first_height: l.first_height,
            anchor_hash: l.anchor_hash,
            start_context_hash: l.start_context_hash,
            last_height: r.last_height,
            last_hash: r.last_hash,
            end_context_hash: r.end_context_hash,
            work,
            leaves: l.leaves + r.leaves,
            equihash_checked: l.equihash_checked && r.equihash_checked,
            records: Peaks::join(&l.records, &r.records),
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(CLAIM_FIXED + 1 + self.records.0.len() * PEAK_SIZE);
        out.extend_from_slice(&CLAIM_MAGIC);
        out.push(CLAIM_VERSION);
        out.push(self.kind.byte());
        out.push(net_byte(self.net));
        out.push(self.era);
        out.extend_from_slice(&self.registry_root);
        key_bytes(&self.program, &mut out);
        out.extend_from_slice(&self.first_height.to_le_bytes());
        out.extend_from_slice(&self.anchor_hash);
        out.extend_from_slice(&self.start_context_hash);
        out.extend_from_slice(&self.last_height.to_le_bytes());
        out.extend_from_slice(&self.last_hash);
        out.extend_from_slice(&self.end_context_hash);
        out.extend_from_slice(&self.work);
        out.extend_from_slice(&self.leaves.to_le_bytes());
        out.push(self.equihash_checked as u8);
        self.records.encode(&mut out);
        out
    }

    /// Decodes a v2 claim. Version 1 claims (generation 0) have no magic and decode with
    /// `RangeClaim::decode`.
    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.len() <= CLAIM_FIXED || b[..4] != CLAIM_MAGIC || b[4] != CLAIM_VERSION {
            return None;
        }
        let (records, used) = Peaks::decode(&b[CLAIM_FIXED..])?;
        if CLAIM_FIXED + used != b.len() {
            return None;
        }
        let a32 = |at: usize| -> [u8; 32] { b[at..at + 32].try_into().unwrap() };
        let u64_at = |at: usize| u64::from_le_bytes(b[at..at + 8].try_into().unwrap());
        Some(Claim {
            kind: Kind::from_byte(b[5])?,
            net: net_from(b[6])?,
            era: b[7],
            registry_root: a32(8),
            program: key_from(&b[40..72]),
            first_height: u64_at(72),
            anchor_hash: a32(80),
            start_context_hash: a32(112),
            last_height: u64_at(144),
            last_hash: a32(152),
            end_context_hash: a32(184),
            work: a32(216),
            leaves: u32::from_le_bytes(b[248..252].try_into().unwrap()),
            equihash_checked: b[252] == 1,
            records,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RECORD_SIZE;
    use alloc::vec;

    const LEAF_A: [u32; 8] = [1; 8];
    const LEAF_B: [u32; 8] = [2; 8];
    const AGG: [u32; 8] = [9; 8];
    const AGG2: [u32; 8] = [10; 8];
    const ERA2: u64 = 4_465_026;

    fn allow(kind: Kind, era: u8, first: u64, last: u64, key: [u32; 8]) -> Entry {
        Entry { action: Action::Allow, kind, net: Net::Test, era, first, last, key, sp1_version: "v6.0.0".into() }
    }

    fn revoke(key: [u32; 8], from: u64) -> Entry {
        Entry { action: Action::Revoke, kind: Kind::HeaderLeaf, net: Net::Test, era: ANY_ERA, first: from, last: OPEN_END, key, sp1_version: "v6.0.0".into() }
    }

    fn base() -> Registry {
        Registry { entries: vec![allow(Kind::HeaderLeaf, 2, ERA2, OPEN_END, LEAF_A), allow(Kind::Aggregate, ANY_ERA, 0, OPEN_END, AGG)] }
    }

    /// A leaf claim over `first..first+n` whose hashes chain by height.
    fn leaf(first: u64, n: u64) -> Claim {
        let h = |x: u64| {
            let mut a = [0u8; 32];
            a[..8].copy_from_slice(&x.to_le_bytes());
            a
        };
        let records: Vec<[u8; RECORD_SIZE]> = (first..first + n).map(|x| [x as u8; RECORD_SIZE]).collect();
        let mut work = [0u8; 32];
        work[31] = n as u8;
        Claim {
            kind: Kind::HeaderLeaf,
            net: Net::Test,
            era: Net::Test.era(first),
            registry_root: [0; 32],
            program: [0; 8],
            first_height: first,
            anchor_hash: h(first - 1),
            start_context_hash: h(first + 1_000_000),
            last_height: first + n - 1,
            last_hash: h(first + n - 1),
            end_context_hash: h(first + n + 1_000_000),
            work,
            leaves: 1,
            equihash_checked: true,
            records: Peaks::of_records(first, &records),
        }
    }

    #[test]
    fn claims_and_registries_round_trip() {
        let reg = base();
        assert_eq!(Registry::decode(&reg.encode()), Some(reg.clone()));
        let c = Claim::join((&leaf(ERA2, 512), &LEAF_A), (&leaf(ERA2 + 512, 512), &LEAF_A), &reg, &AGG).unwrap();
        assert_eq!(Claim::decode(&c.encode()), Some(c.clone()));
        assert_eq!(c.registry_root, reg.root());
        assert_eq!(c.program, AGG);
        assert_eq!(c.leaves, 2);
        // A version 1 claim is not mistaken for a v2 one.
        assert_eq!(Claim::decode(&crate::RangeClaim::decode(&v1_claim()).unwrap().encode()), None);
    }

    fn v1_claim() -> Vec<u8> {
        let c = leaf(ERA2, 4);
        crate::RangeClaim {
            leaf_vk: [0; 8],
            agg_vk: [0; 8],
            first_height: c.first_height,
            anchor_hash: c.anchor_hash,
            start_context_hash: c.start_context_hash,
            last_height: c.last_height,
            last_hash: c.last_hash,
            end_context_hash: c.end_context_hash,
            work: c.work,
            leaves: 1,
            equihash_checked: true,
            records: c.records,
        }
        .encode()
    }

    #[test]
    fn prefix_roots_chain() {
        let mut reg = base();
        let before = reg.root();
        reg.entries.push(allow(Kind::HeaderLeaf, 2, ERA2, OPEN_END, LEAF_B));
        let roots = reg.prefix_roots();
        assert_eq!(roots.len(), 4);
        assert_eq!(roots[2], before);
        assert_ne!(reg.root(), before);
    }

    #[test]
    fn a_leaf_needs_an_allowed_key_for_its_era_and_heights() {
        let reg = base();
        let (l, r) = (leaf(ERA2, 512), leaf(ERA2 + 512, 512));
        assert_eq!(Claim::join((&l, &LEAF_B), (&r, &LEAF_A), &reg, &AGG), Err(Refused::LeafNotAllowed));
        // Allowed for era 1 only: an era-2 leaf is refused.
        let era1 = Registry { entries: vec![allow(Kind::HeaderLeaf, 1, 584_000, ERA2 - 1, LEAF_A), allow(Kind::Aggregate, ANY_ERA, 0, OPEN_END, AGG)] };
        assert_eq!(Claim::join((&l, &LEAF_A), (&r, &LEAF_A), &era1, &AGG), Err(Refused::LeafNotAllowed));
        // Allowed for era 2 but only up to a height inside the right leaf.
        let short = Registry { entries: vec![allow(Kind::HeaderLeaf, 2, ERA2, ERA2 + 600, LEAF_A), allow(Kind::Aggregate, ANY_ERA, 0, OPEN_END, AGG)] };
        assert_eq!(Claim::join((&l, &LEAF_A), (&r, &LEAF_A), &short, &AGG), Err(Refused::LeafNotAllowed));
    }

    #[test]
    fn two_leaf_programs_of_one_era_mix() {
        let mut reg = base();
        reg.entries.push(allow(Kind::HeaderLeaf, 2, ERA2, OPEN_END, LEAF_B));
        assert!(Claim::join((&leaf(ERA2, 512), &LEAF_A), (&leaf(ERA2 + 512, 512), &LEAF_B), &reg, &AGG).is_ok());
    }

    #[test]
    fn a_revoked_leaf_key_is_refused() {
        let mut reg = base();
        reg.entries.push(revoke(LEAF_A, 0));
        assert_eq!(
            Claim::join((&leaf(ERA2, 512), &LEAF_A), (&leaf(ERA2 + 512, 512), &LEAF_A), &reg, &AGG),
            Err(Refused::LeafNotAllowed)
        );
    }

    #[test]
    fn a_retired_key_still_proves_below_its_cutoff() {
        let mut reg = base();
        reg.entries.push(revoke(LEAF_A, ERA2 + 1024));
        let ok = Claim::join((&leaf(ERA2, 512), &LEAF_A), (&leaf(ERA2 + 512, 512), &LEAF_A), &reg, &AGG);
        assert!(ok.is_ok());
        let late = Claim::join((&leaf(ERA2 + 512, 512), &LEAF_A), (&leaf(ERA2 + 1024, 512), &LEAF_A), &reg, &AGG);
        assert_eq!(late, Err(Refused::LeafNotAllowed));
    }

    #[test]
    fn an_aggregate_child_must_be_current() {
        let mut reg = base();
        let a = Claim::join((&leaf(ERA2, 512), &LEAF_A), (&leaf(ERA2 + 512, 512), &LEAF_A), &reg, &AGG).unwrap();
        let next = leaf(ERA2 + 1024, 512);
        // Registry grew by an allow: the old aggregate still joins.
        reg.entries.push(allow(Kind::HeaderLeaf, 2, ERA2, OPEN_END, LEAF_B));
        assert!(Claim::join((&a, &AGG), (&next, &LEAF_B), &reg, &AGG).is_ok());
        // A retirement above the aggregate's range does not touch it.
        reg.entries.push(revoke(LEAF_B, ERA2 + 2048));
        assert!(Claim::join((&a, &AGG), (&next, &LEAF_A), &reg, &AGG).is_ok());
        // A revocation reaching its range does, even of a key it may not contain.
        reg.entries.push(revoke(LEAF_B, 0));
        assert_eq!(Claim::join((&a, &AGG), (&next, &LEAF_A), &reg, &AGG), Err(Refused::StaleRegistry));
        // Joined again under the current registry, it is accepted.
        let a2 = Claim::join((&leaf(ERA2, 512), &LEAF_A), (&leaf(ERA2 + 512, 512), &LEAF_A), &reg, &AGG).unwrap();
        assert!(Claim::join((&a2, &AGG), (&next, &LEAF_A), &reg, &AGG).is_ok());
    }

    #[test]
    fn an_aggregate_child_from_another_registry_is_refused() {
        let reg = base();
        let a = Claim::join((&leaf(ERA2, 512), &LEAF_A), (&leaf(ERA2 + 512, 512), &LEAF_A), &reg, &AGG).unwrap();
        let mut forked = base();
        forked.entries.insert(0, allow(Kind::HeaderLeaf, 2, ERA2, OPEN_END, LEAF_B));
        assert_eq!(Claim::join((&a, &AGG), (&leaf(ERA2 + 1024, 512), &LEAF_A), &forked, &AGG), Err(Refused::UnknownRegistry));
    }

    #[test]
    fn aggregation_keys_are_checked() {
        let mut reg = base();
        let (l, r) = (leaf(ERA2, 512), leaf(ERA2 + 512, 512));
        assert_eq!(Claim::join((&l, &LEAF_A), (&r, &LEAF_A), &reg, &AGG2), Err(Refused::OwnKeyNotAllowed));
        let a = Claim::join((&l, &LEAF_A), (&r, &LEAF_A), &reg, &AGG).unwrap();
        let next = leaf(ERA2 + 1024, 512);
        assert_eq!(Claim::join((&a, &AGG2), (&next, &LEAF_A), &reg, &AGG), Err(Refused::KeyMismatch));
        // A new aggregation program takes old aggregates as children.
        reg.entries.push(allow(Kind::Aggregate, ANY_ERA, 0, OPEN_END, AGG2));
        let b = Claim::join((&a, &AGG), (&next, &LEAF_A), &reg, &AGG2).unwrap();
        assert_eq!(b.program, AGG2);
        assert_eq!(b.leaves, 3);
    }

    #[test]
    fn malformed_children_are_refused() {
        let reg = base();
        let (mut l, r) = (leaf(ERA2, 512), leaf(ERA2 + 512, 512));
        l.program = AGG;
        assert_eq!(Claim::join((&l, &LEAF_A), (&r, &LEAF_A), &reg, &AGG), Err(Refused::Malformed));
        let (l, mut r) = (leaf(ERA2, 512), leaf(ERA2 + 512, 512));
        r.net = Net::Main;
        assert_eq!(Claim::join((&l, &LEAF_A), (&r, &LEAF_A), &reg, &AGG), Err(Refused::OtherNetwork));
        let (l, mut r) = (leaf(ERA2, 512), leaf(ERA2 + 512, 512));
        r.records = l.records.clone();
        assert_eq!(Claim::join((&l, &LEAF_A), (&r, &LEAF_A), &reg, &AGG), Err(Refused::Range(Join::BadRecords)));
        let (l, r) = (leaf(ERA2, 512), leaf(ERA2 + 513, 512));
        assert!(matches!(Claim::join((&l, &LEAF_A), (&r, &LEAF_A), &reg, &AGG), Err(Refused::Range(_))));
    }

    #[test]
    fn one_leaf_without_equihash_marks_every_aggregate_above_it() {
        let reg = base();
        let mut skipped = leaf(ERA2 + 512, 512);
        skipped.equihash_checked = false;
        let a = Claim::join((&leaf(ERA2, 512), &LEAF_A), (&skipped, &LEAF_A), &reg, &AGG).unwrap();
        assert!(!a.equihash_checked);
        let b = Claim::join((&a, &AGG), (&leaf(ERA2 + 1024, 512), &LEAF_A), &reg, &AGG).unwrap();
        assert!(!b.equihash_checked);
    }

    #[test]
    fn allowing_a_revoked_key_again_does_not_restore_it() {
        let mut reg = base();
        reg.entries.push(revoke(LEAF_A, 0));
        reg.entries.push(allow(Kind::HeaderLeaf, 2, ERA2, OPEN_END, LEAF_A));
        assert_eq!(
            Claim::join((&leaf(ERA2, 512), &LEAF_A), (&leaf(ERA2 + 512, 512), &LEAF_A), &reg, &AGG),
            Err(Refused::LeafNotAllowed)
        );
        // The same holds for an aggregation key.
        let mut reg = base();
        reg.entries.push(revoke(AGG, 0));
        reg.entries.push(allow(Kind::Aggregate, ANY_ERA, 0, OPEN_END, AGG));
        assert_eq!(
            Claim::join((&leaf(ERA2, 512), &LEAF_A), (&leaf(ERA2 + 512, 512), &LEAF_A), &reg, &AGG),
            Err(Refused::OwnKeyNotAllowed)
        );
    }

}
