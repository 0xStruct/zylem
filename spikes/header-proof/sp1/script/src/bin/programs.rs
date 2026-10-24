//! Freezes and registers generation 1 programs.
//!
//!   programs freeze DIR --kind leaf --net test --era 2 --first H [--last H] [--note TEXT]
//!   programs freeze DIR --kind aggregate --net test [--note TEXT]
//!   programs revoke DIR --key HEX [--from H] [--note TEXT]
//!   programs show DIR
//!
//! `freeze` copies the program this tool was built with (or `--elf PATH`) to
//! `DIR/<kind>-<key>.elf`, computes its key, and appends an allow entry to
//! `DIR/registry.json`. `revoke` appends a revocation of a key from height `--from`
//! (default 0: outright). Entries are only ever appended.

use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use sp1_sdk::{
    blocking::{Prover, ProverClient},
    include_elf, Elf, HashableKey, ProvingKey,
};
use zylem_hdr::{Action, Entry, Kind, Net, ANY_ERA, OPEN_END};
use zylem_hdr_sp1::{arg, key_hex, positional, InRuntime, Listed, RegistryFile, REGISTRY_FILE};

const LEAF_ELF: Elf = include_elf!("zylem-header-leaf");
const AGG_ELF: Elf = include_elf!("zylem-aggregate");
const VALUE_FLAGS: &[&str] = &["--kind", "--net", "--era", "--first", "--last", "--note", "--elf", "--key", "--from"];

fn open(dir: &PathBuf) -> Result<RegistryFile> {
    if dir.join(REGISTRY_FILE).exists() {
        let f = RegistryFile::load(dir)?;
        if let Some(n) = arg("--net") {
            if net(&n)? != f.network {
                bail!("{} is a {:?} registry", dir.display(), f.network);
            }
        }
        Ok(f)
    } else {
        Ok(RegistryFile::new(dir, net(&arg("--net").context("--net for a new registry")?)?))
    }
}

fn net(s: &str) -> Result<Net> {
    match s {
        "main" | "mainnet" => Ok(Net::Main),
        "test" | "testnet" => Ok(Net::Test),
        _ => bail!("network is main or test"),
    }
}

fn height(name: &str) -> Result<Option<u64>> {
    arg(name).map(|h| h.replace([',', '_'], "").parse().with_context(|| name.to_string())).transpose()
}

fn main() -> Result<()> {
    let mode = std::env::args().nth(1).context("mode: freeze | revoke | show")?;
    let dir = PathBuf::from(positional(VALUE_FLAGS).first().context("DIR")?);
    let note = arg("--note").unwrap_or_default();
    match mode.as_str() {
        "freeze" => {
            let mut f = open(&dir)?;
            let kind = match arg("--kind").as_deref() {
                Some("leaf") => Kind::HeaderLeaf,
                Some("aggregate") => Kind::Aggregate,
                _ => bail!("--kind leaf | aggregate"),
            };
            let elf: Vec<u8> = match arg("--elf") {
                Some(p) => std::fs::read(&p).with_context(|| p.clone())?,
                None => match kind {
                    Kind::HeaderLeaf => LEAF_ELF.to_vec(),
                    Kind::Aggregate => AGG_ELF.to_vec(),
                },
            };
            let (era, first, last) = match kind {
                Kind::HeaderLeaf => {
                    let era: u8 = arg("--era").context("--era")?.parse()?;
                    let first = height("--first")?.context("--first")?;
                    let last = height("--last")?.unwrap_or(OPEN_END);
                    if f.network.era(first) != era || (last != OPEN_END && f.network.era(last) != era) {
                        bail!("heights {first}..={last} are not all in era {era}");
                    }
                    (era, first, last)
                }
                Kind::Aggregate => (ANY_ERA, height("--first")?.unwrap_or(0), height("--last")?.unwrap_or(OPEN_END)),
            };
            // A mock client computes the same key as a proving one, without a GPU.
            let client = InRuntime::new(ProverClient::builder().mock().build());
            let pk = InRuntime::new(client.setup(Elf::from(elf.clone()))?);
            let vk = pk.verifying_key();
            let key = vk.hash_u32();
            let stem = match kind {
                Kind::HeaderLeaf => format!("header-leaf-era{era}"),
                Kind::Aggregate => "aggregate".into(),
            };
            let name = format!("{stem}-{}.elf", &key_hex(&key)[..16]);
            if f.entries.iter().any(|l| l.entry.action == Action::Allow && l.entry.key == key && l.entry.kind == kind && l.entry.era == era) {
                bail!("{name} is already registered for this");
            }
            std::fs::create_dir_all(&dir)?;
            std::fs::write(dir.join(&name), &elf)?;
            f.entries.push(Listed {
                entry: Entry { action: Action::Allow, kind, net: f.network, era, first, last, key, sp1_version: sp1_sdk::SP1_CIRCUIT_VERSION.into() },
                artifact: Some(name.clone()),
                artifact_sha256: Some(hex::encode(Sha256::digest(&elf))),
                note,
            });
            f.save()?;
            println!("froze {name}: key {} (bytes32 {}), registry root {}", key_hex(&key), vk.bytes32(), f.root);
        }
        "revoke" => {
            let mut f = RegistryFile::load(&dir)?;
            let key_hex_in = arg("--key").context("--key")?;
            let l = f.entries.iter().find(|l| key_hex(&l.entry.key) == key_hex_in || l.artifact.as_deref() == Some(key_hex_in.as_str())).context("no such program")?.clone();
            let from = height("--from")?.unwrap_or(0);
            f.entries.push(Listed {
                entry: Entry { action: Action::Revoke, era: ANY_ERA, first: from, last: OPEN_END, ..l.entry.clone() },
                artifact: None,
                artifact_sha256: None,
                note,
            });
            f.save()?;
            println!("revoked {} from height {from}, registry root {}", key_hex(&l.entry.key), f.root);
        }
        "show" => {
            let f = RegistryFile::load(&dir)?;
            println!("{:?} registry, root {}", f.network, f.root);
            for (i, l) in f.entries.iter().enumerate() {
                let e = &l.entry;
                println!(
                    "{i:>3} {:?} {:?} era {} {}..={} {} {}",
                    e.action,
                    e.kind,
                    if e.era == ANY_ERA { "any".into() } else { e.era.to_string() },
                    e.first,
                    if e.last == OPEN_END { "open".into() } else { e.last.to_string() },
                    &key_hex(&e.key)[..16],
                    l.note
                );
            }
        }
        m => bail!("unknown mode {m}"),
    }
    Ok(())
}
