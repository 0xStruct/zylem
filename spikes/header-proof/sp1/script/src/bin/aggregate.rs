//! Two leaf segments proved independently, joined by the aggregation program, accepted by
//! a client, and a set of negative tests.
//!
//! Usage: aggregate [RING_DIR] [--headers N] [--reuse] [--prove-negatives]

use std::{path::PathBuf, time::Instant};

use anyhow::{bail, Context, Result};
use sp1_sdk::{
    blocking::{ProveRequest, Prover, ProverClient},
    include_elf, Elf, HashableKey, ProvingKey, SP1Proof, SP1ProofWithPublicValues, SP1PublicValues, SP1Stdin,
    SP1VerifyingKey,
};
use zylem_hdr::{context_hash, Input, Net, RangeClaim, MAX_CONTEXT};

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
    Malformed,
    NotAnAggregate,
    WrongAggregationProgram,
    WrongLeafProgram,
    WrongCheckpoint,
}

/// The client's whole acceptance rule for a history proof.
pub fn accept(client: &impl Prover, proof: &SP1ProofWithPublicValues, t: &Trusted) -> Result<RangeClaim, Rejected> {
    // `verify` also requires exit code 0.
    client.verify(proof, &t.agg_vk, None).map_err(|e| Rejected::ProofInvalid(e.to_string()))?;
    let claim = RangeClaim::decode(proof.public_values.as_slice()).ok_or(Rejected::Malformed)?;
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
    Ok(claim)
}

fn segment(all: &[(u64, Vec<u8>)], start: usize, count: usize) -> (Input, Vec<u8>) {
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
        check_equihash: false,
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
/// guest verifies them; execution-only runs may pass none.
fn agg_stdin(agg_vk: [u32; 8], leaf_vk: [u32; 8], left: &[u8], right: &[u8], proofs: &[(&SP1ProofWithPublicValues, &SP1VerifyingKey)]) -> Result<SP1Stdin> {
    let mut s = SP1Stdin::new();
    s.write(&agg_vk);
    s.write(&leaf_vk);
    s.write_vec(left.to_vec());
    s.write_vec(right.to_vec());
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

    let (in_a, h_a) = segment(&all, start, n);
    let (in_b, h_b) = segment(&all, start + n, n);
    let (in_c, h_c) = segment(&all, start + 2 * n, n);
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
    let claim = accept(&client, &agg, &trusted).map_err(|e| anyhow::anyhow!("honest proof rejected: {e:?}"))?;
    println!(
        "accepted: heights {}..={}, {} leaves, last hash {}, records root {}",
        claim.first_height,
        claim.last_height,
        claim.leaves,
        hex::encode(claim.last_hash),
        hex::encode(claim.records_root)
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
    let mut tampered = agg.clone();
    let mut pv = tampered.public_values.to_vec();
    pv[208 + 31] ^= 1; // work
    tampered.public_values = SP1PublicValues::from(&pv[..]);
    println!("  published claim altered after proving (work): {}", show(accept(&client, &tampered, &trusted)));
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
