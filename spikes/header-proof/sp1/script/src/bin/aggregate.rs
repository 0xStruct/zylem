//! Two leaf segments proved independently, joined by the aggregation program, checked by
//! a client, bound to the Ring headers they cover, and a set of negative tests.
//!
//! Usage: aggregate [RING_DIR] [--headers N] [--equihash] [--reuse] [--prove-negatives]
//!
//! Leaves skip Equihash unless `--equihash` is given, so the client rejects the honest
//! aggregate with `EquihashNotChecked` after every other check passes. Proving Equihash
//! needs about 27 GB of memory on a CPU; `SP1_PROVER=mock aggregate --equihash` runs the
//! whole flow with Equihash through execution only (mock proofs, so proof validity itself
//! is not checked, only the claim rules), and a GPU proves it for real.

use std::{path::PathBuf, time::Instant};

use anyhow::{bail, Context, Result};
use sp1_sdk::{
    blocking::{ProveRequest, Prover, ProverClient},
    include_elf, Elf, HashableKey, ProvingKey, SP1Proof, SP1ProofWithPublicValues, SP1PublicValues, SP1Stdin,
    SP1VerifyingKey,
};
use zylem_hdr::{context_hash, range_paths, record_of, sha256d, Input, Net, Peaks, RangeClaim, MAX_CONTEXT, RECORD_SIZE};

const LEAF_ELF: Elf = include_elf!("header-chain-leaf");
const AGG_ELF: Elf = include_elf!("header-chain-agg");

/// What a wallet trusts before it sees any proof: the two programs and a checkpoint.
pub struct Trusted {
    pub leaf_vk: [u32; 8],
    pub agg_vk: SP1VerifyingKey,
    pub checkpoint_height: u64,
    pub checkpoint_hash: [u8; 32],
    pub checkpoint_context_hash: [u8; 32],
}

#[derive(Debug)]
pub enum Rejected {
    /// The proof does not verify against the trusted aggregation program, or its guest
    /// exited non-zero.
    ProofInvalid(String),
    /// The claim does not decode, or its records commitment does not have the canonical
    /// shape for its height range.
    Malformed,
    NotAnAggregate,
    WrongAggregationProgram,
    WrongLeafProgram,
    WrongCheckpoint,
    /// Some header in the range was proved without its Equihash solution being checked.
    EquihashNotChecked,
}

/// The client's whole acceptance rule for a history proof.
pub fn accept(client: &impl Prover, proof: &SP1ProofWithPublicValues, t: &Trusted) -> Result<RangeClaim, Rejected> {
    // `verify` also requires exit code 0.
    client.verify(proof, &t.agg_vk, None).map_err(|e| Rejected::ProofInvalid(e.to_string()))?;
    let claim = RangeClaim::decode(proof.public_values.as_slice()).ok_or(Rejected::Malformed)?;
    if !claim.records.is_canonical(claim.first_height, claim.last_height) {
        return Err(Rejected::Malformed);
    }
    if claim.is_leaf() {
        return Err(Rejected::NotAnAggregate);
    }
    if claim.agg_vk != t.agg_vk.hash_u32() {
        return Err(Rejected::WrongAggregationProgram);
    }
    if claim.leaf_vk != t.leaf_vk {
        return Err(Rejected::WrongLeafProgram);
    }
    if claim.first_height != t.checkpoint_height + 1
        || claim.anchor_hash != t.checkpoint_hash
        || claim.start_context_hash != t.checkpoint_context_hash
    {
        return Err(Rejected::WrongCheckpoint);
    }
    // Last, so a proof that fails only this check says so.
    if !claim.equihash_checked {
        return Err(Rejected::EquihashNotChecked);
    }
    Ok(claim)
}

fn segment(all: &[(u64, Vec<u8>)], start: usize, count: usize, equihash: bool) -> (Input, Vec<u8>) {
    let context = all[start - MAX_CONTEXT..start]
        .iter()
        .map(|(_, h)| {
            (
                u32::from_le_bytes(h[104..108].try_into().unwrap()),
                u32::from_le_bytes(h[100..104].try_into().unwrap()),
            )
        })
        .collect();
    let headers = all[start..start + count].iter().flat_map(|(_, h)| h.clone()).collect();
    let input = Input {
        net: Net::Test,
        first_height: all[start].0,
        anchor_hash: zylem_hdr::sha256d(&all[start - 1].1),
        context,
        count: count as u32,
        check_equihash: equihash,
    };
    (input, headers)
}

fn leaf_stdin(input: &Input, headers: &[u8]) -> SP1Stdin {
    let mut s = SP1Stdin::new();
    s.write(input);
    s.write_vec(headers.to_vec());
    s
}

/// Aggregation stdin. `proofs` are the children's proofs with their keys, in the order the
/// guest verifies them; execution-only runs may pass none, and mock runs ignore them.
fn agg_stdin(agg_vk: [u32; 8], leaf_vk: [u32; 8], left: &[u8], right: &[u8], proofs: &[(&SP1ProofWithPublicValues, &SP1VerifyingKey)]) -> Result<SP1Stdin> {
    let mut s = SP1Stdin::new();
    s.write(&agg_vk);
    s.write(&leaf_vk);
    s.write_vec(left.to_vec());
    s.write_vec(right.to_vec());
    // A mock prover only executes, and rejects mock children as deferred proofs.
    if std::env::var("SP1_PROVER").is_ok_and(|p| p == "mock") {
        return Ok(s);
    }
    for (p, vk) in proofs {
        let SP1Proof::Compressed(inner) = &p.proof else { bail!("child proof is not compressed") };
        s.write_proof((**inner).clone(), vk.vk.clone());
    }
    Ok(s)
}

/// A leaf's claim computed natively, for execution-only negative tests.
fn native_claim(input: &Input, headers: &[u8]) -> Result<RangeClaim> {
    let out = zylem_hdr::run(input, headers).map_err(|e| anyhow::anyhow!("native: {e:?}"))?;
    Ok(RangeClaim::leaf(input, &out))
}

fn saved(p: &SP1ProofWithPublicValues, name: &str) -> Result<u64> {
    let path = std::env::temp_dir().join(name);
    p.save(&path)?;
    Ok(std::fs::metadata(&path)?.len())
}

fn arg(name: &str) -> Option<usize> {
    let args: Vec<String> = std::env::args().collect();
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).and_then(|v| v.parse().ok())
}

fn flag(name: &str) -> bool {
    std::env::args().any(|a| a == name)
}

fn main() -> Result<()> {
    let dir = std::env::args()
        .nth(1)
        .filter(|a| !a.starts_with("--"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("../../../data/testnet"));
    let n = arg("--headers").unwrap_or(100);
    let all = zylem_hdr_validate::load_headers(&dir)?;
    let start = MAX_CONTEXT + 1_000;
    let client = ProverClient::from_env();
    let leaf_pk = client.setup(LEAF_ELF)?;
    let agg_pk = client.setup(AGG_ELF)?;
    let leaf_vk = leaf_pk.verifying_key().clone();
    let agg_vk = agg_pk.verifying_key().clone();
    let (lv, av) = (leaf_vk.hash_u32(), agg_vk.hash_u32());
    println!("leaf program {}\naggregation program {}", leaf_vk.bytes32(), agg_vk.bytes32());
    let equihash = flag("--equihash");
    let mock = std::env::var("SP1_PROVER").is_ok_and(|p| p == "mock");

    let (in_a, h_a) = segment(&all, start, n, equihash);
    let (in_b, h_b) = segment(&all, start + n, n, equihash);
    let (in_c, h_c) = segment(&all, start + 2 * n, n, equihash);
    println!(
        "leaf A: {}..={}, leaf B: {}..={}",
        in_a.first_height,
        in_a.first_height + n as u64 - 1,
        in_b.first_height,
        in_b.first_height + n as u64 - 1
    );

    // Leaves: independent, so a prover farm would run them at the same time.
    let (pa, pb) = if flag("--reuse") {
        (
            SP1ProofWithPublicValues::load(std::env::temp_dir().join("zylem-leafA.bin"))?,
            SP1ProofWithPublicValues::load(std::env::temp_dir().join("zylem-leafB.bin"))?,
        )
    } else {
        let mut proofs = vec![];
        for (name, input, headers) in [("A", &in_a, &h_a), ("B", &in_b, &h_b)] {
            let t = Instant::now();
            let p = client.prove(&leaf_pk, leaf_stdin(input, headers)).compressed().run()?;
            let secs = t.elapsed().as_secs_f64();
            client.verify(&p, &leaf_vk, None)?;
            let size = saved(&p, &format!("zylem-leaf{name}.bin"))?;
            println!("leaf {name} proved in {secs:.1} s, saved proof {size} B");
            proofs.push(p);
        }
        let pb = proofs.pop().unwrap();
        (proofs.pop().unwrap(), pb)
    };
    let (ca, cb) = (pa.public_values.to_vec(), pb.public_values.to_vec());

    // Aggregation: verifies both leaves and joins them.
    let (_, r) = client.execute(AGG_ELF, agg_stdin(av, lv, &ca, &cb, &[])?).run()?;
    println!("aggregation executes in {} instructions (exit code {})", r.total_instruction_count(), r.exit_code);
    let t = Instant::now();
    let agg = client
        .prove(&agg_pk, agg_stdin(av, lv, &ca, &cb, &[(&pa, &leaf_vk), (&pb, &leaf_vk)])?)
        .compressed()
        .run()?;
    let secs = t.elapsed().as_secs_f64();
    println!("aggregation proved in {secs:.1} s, saved proof {} B", saved(&agg, "zylem-agg.bin")?);

    // The client's view.
    let trusted = Trusted {
        leaf_vk: lv,
        agg_vk: agg_vk.clone(),
        checkpoint_height: in_a.first_height - 1,
        checkpoint_hash: in_a.anchor_hash,
        checkpoint_context_hash: context_hash(&in_a.context),
    };
    let claim = match accept(&client, &agg, &trusted) {
        Ok(claim) => claim,
        // Leaves without Equihash: every other check passed.
        Err(Rejected::EquihashNotChecked) if !equihash => {
            println!("client: rejected only because the leaves skipped Equihash (EquihashNotChecked), as it must");
            RangeClaim::decode(agg.public_values.as_slice()).unwrap()
        }
        Err(e) => bail!("honest proof rejected: {e:?}"),
    };
    println!(
        "{}: heights {}..={}, {} leaves, Equihash {}, last hash {}, records commitment {} peaks",
        if claim.equihash_checked { "accepted" } else { "claim" },
        claim.first_height,
        claim.last_height,
        claim.leaves,
        if claim.equihash_checked { "checked" } else { "not checked" },
        hex::encode(claim.last_hash),
        claim.records.0.len()
    );

    // ---- Binding to Rings ----
    // A client recomputes records from the headers it downloaded; it never needs the
    // proof's leaf boundaries.
    let headers = &all[start..start + 2 * n];
    let records: Vec<[u8; RECORD_SIZE]> = headers.iter().map(|(_, h)| record_of(h, &sha256d(h))).collect();
    let first = claim.first_height;
    println!("\nbinding to Ring headers:");
    println!(
        "  records recomputed from the headers equal the proven commitment: {}",
        Peaks::of_records(first, &records) == claim.records
    );
    // Same range, split into three uneven leaves and joined the other way round, by
    // executing the same programs.
    let thirds = [(0, n / 3), (n / 3, n + n / 2), (n + n / 2, 2 * n)];
    let mut parts = vec![];
    for (from, to) in thirds {
        let (i, h) = segment(&all, start + from, to - from, false);
        let (pv, rep) = client.execute(LEAF_ELF, leaf_stdin(&i, &h)).run()?;
        anyhow::ensure!(rep.exit_code == 0, "leaf {from}..{to} failed");
        parts.push(pv.to_vec());
    }
    let (pv, _) = client.execute(AGG_ELF, agg_stdin(av, lv, &parts[1], &parts[2], &[])?).run()?;
    let (pv, _) = client.execute(AGG_ELF, agg_stdin(av, lv, &parts[0], pv.as_slice(), &[])?).run()?;
    let other = RangeClaim::decode(pv.as_slice()).context("re-split claim")?;
    println!(
        "  leaves of {}, {} and {} headers joined right-first give the same commitment: {}",
        n / 3,
        n + n / 2 - n / 3,
        2 * n - n - n / 2,
        other.records == claim.records
    );
    // A Ring-sized piece that crosses the leaf boundary, and one block.
    let (lo, hi) = (first + n as u64 / 4, first + n as u64 + n as u64 / 2);
    let piece = &records[(lo - first) as usize..=(hi - first) as usize];
    let paths = range_paths(first, &records, lo, hi);
    let path_hashes: usize = paths.iter().map(Vec::len).sum();
    println!(
        "  headers {lo}..={hi} with {path_hashes} sibling hashes: {:?}",
        claim.records.verify_range(lo, piece, &paths)
    );
    let one = (lo + 3 - first) as usize;
    println!(
        "  block {}: {:?}",
        lo + 3,
        claim.records.verify_range(lo + 3, &records[one..=one], &range_paths(first, &records, lo + 3, lo + 3))
    );
    let mut swapped = piece.to_vec();
    swapped.swap(5, 6);
    println!("  two neighbouring headers swapped: {:?}", claim.records.verify_range(lo, &swapped, &paths));
    let shifted = &records[(lo + 1 - first) as usize..=(hi + 1 - first) as usize];
    println!(
        "  every header one height off (paths for the claimed heights): {:?}",
        claim.records.verify_range(lo, shifted, &paths)
    );
    let past_end = &records[records.len() - 2..];
    println!(
        "  headers after the proven range: {:?}",
        claim.records.verify_range(claim.last_height, past_end, &range_paths(first, &records, lo, hi))
    );

    // ---- Negative tests ----
    println!("\nguest rejects (execution; the join checks run before any proof is needed):");
    let verdict = |code: u64| if code == 0 { "ACCEPTED".to_string() } else { format!("rejected (exit code {code})") };
    let nc = native_claim(&in_c, &h_c)?.encode();
    let cases: Vec<(&str, Vec<u8>, Vec<u8>)> = vec![
        ("leaves not adjacent (A then C)", ca.clone(), nc.clone()),
        ("leaves in the wrong order (B then A)", cb.clone(), ca.clone()),
        ("right leaf starts from another difficulty context", ca.clone(), {
            let mut c = RangeClaim::decode(&cb).unwrap();
            c.start_context_hash[0] ^= 1;
            c.encode()
        }),
        ("child aggregate made with other programs", ca.clone(), {
            let mut c = RangeClaim::decode(&cb).unwrap();
            c.leaves = 2;
            c.leaf_vk = [7; 8];
            c.agg_vk = [7; 8];
            c.encode()
        }),
        ("right leaf's records committed one height off", ca.clone(), {
            let mut c = RangeClaim::decode(&cb).unwrap();
            let recs: Vec<_> = h_b.chunks(zylem_hdr::HEADER_SIZE).map(|h| record_of(h, &sha256d(h))).collect();
            c.records = Peaks::of_records(c.first_height + 1, &recs);
            c.encode()
        }),
        ("right leaf's records not merged into the canonical blocks", ca.clone(), {
            let mut c = RangeClaim::decode(&cb).unwrap();
            c.records = Peaks(
                (c.first_height..=c.last_height)
                    .map(|h| zylem_hdr::Peak { start: h, level: 0, root: [0; 32] })
                    .collect(),
            );
            c.encode()
        }),
    ];
    for (name, l, r) in cases {
        let (_, rep) = client.execute(AGG_ELF, agg_stdin(av, lv, &l, &r, &[])?).run()?;
        println!("  {name}: {}", verdict(rep.exit_code));
    }

    println!("\nclient rejects:");
    let show = |r: Result<RangeClaim, Rejected>| match r {
        Ok(_) => "ACCEPTED".to_string(),
        Err(Rejected::ProofInvalid(e)) => format!("rejected: proof invalid ({})", e.lines().next().unwrap_or("")),
        Err(e) => format!("rejected: {e:?}"),
    };
    let wrong_cp = Trusted { checkpoint_height: trusted.checkpoint_height + 1, ..clone_trusted(&trusted) };
    println!("  checkpoint the client does not trust: {}", show(accept(&client, &agg, &wrong_cp)));
    let other_program = Trusted { agg_vk: leaf_vk.clone(), ..clone_trusted(&trusted) };
    println!("  proof checked against a different program key: {}", show(accept(&client, &agg, &other_program)));
    println!("  a single leaf presented as the history proof: {}", show(accept(&client, &pa, &trusted)));
    if mock {
        println!("  (mock proofs: claims altered after proving are not caught here; a real prover's verify catches them)");
    } else {
        let mut tampered = agg.clone();
        let mut pv = tampered.public_values.to_vec();
        pv[208 + 31] ^= 1; // work
        tampered.public_values = SP1PublicValues::from(&pv[..]);
        println!("  published claim altered after proving (work): {}", show(accept(&client, &tampered, &trusted)));
        let mut tampered = agg.clone();
        let mut pv = tampered.public_values.to_vec();
        let at = pv.len() - 1;
        pv[at] ^= 1; // last byte of the last peak's root
        tampered.public_values = SP1PublicValues::from(&pv[..]);
        println!("  published records commitment altered after proving: {}", show(accept(&client, &tampered, &trusted)));
    }
    if equihash {
        // One leaf without Equihash next to one with it: the aggregate must say "not checked".
        let (i, h) = segment(&all, start + n, n, false);
        let pb_off = client.prove(&leaf_pk, leaf_stdin(&i, &h)).compressed().run()?;
        let mixed = client
            .prove(&agg_pk, agg_stdin(av, lv, &ca, pb_off.public_values.as_slice(), &[(&pa, &leaf_vk), (&pb_off, &leaf_vk)])?)
            .compressed()
            .run()?;
        println!("  one leaf proved without Equihash: {}", show(accept(&client, &mixed, &trusted)));
    } else {
        println!("  leaves proved without Equihash: {}", show(accept(&client, &agg, &trusted)));
    }
    let other_leaf = Trusted { leaf_vk: [9; 8], ..clone_trusted(&trusted) };
    println!("  client trusts a different leaf program: {}", show(accept(&client, &agg, &other_leaf)));

    if flag("--prove-negatives") {
        println!("\nproving rejects:");
        let mut forged = RangeClaim::decode(&ca).unwrap();
        forged.work[31] ^= 1;
        let res = client
            .prove(&agg_pk, agg_stdin(av, lv, &forged.encode(), &cb, &[(&pa, &leaf_vk), (&pb, &leaf_vk)])?)
            .compressed()
            .run();
        println!("  leaf A's claim altered (work) with A's real proof: {}", match res {
            Err(e) => format!("no proof produced ({})", e.to_string().lines().next().unwrap_or("")),
            Ok(p) => show(accept(&client, &p, &trusted)),
        });
        let res = client
            .prove(&agg_pk, agg_stdin(av, lv, &cb, &ca, &[(&pb, &leaf_vk), (&pa, &leaf_vk)])?)
            .compressed()
            .run();
        println!("  wrong order, proved anyway: {}", match res {
            Err(e) => format!("no proof produced ({})", e.to_string().lines().next().unwrap_or("")),
            Ok(p) => show(accept(&client, &p, &trusted)),
        });
    }
    Ok(())
}

fn clone_trusted(t: &Trusted) -> Trusted {
    Trusted {
        leaf_vk: t.leaf_vk,
        agg_vk: t.agg_vk.clone(),
        checkpoint_height: t.checkpoint_height,
        checkpoint_hash: t.checkpoint_hash,
        checkpoint_context_hash: t.checkpoint_context_hash,
    }
}
