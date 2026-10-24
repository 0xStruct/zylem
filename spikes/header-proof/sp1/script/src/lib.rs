//! Generation 1 programs on disk: `programs/<network>/registry.json` lists every registry
//! entry in order, with the file each allowed program was frozen to. Tools load programs
//! from these files, never from what they were compiled with, so every prover uses
//! exactly the registered bytes.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use zylem_hdr::{Action, Entry, Kind, Net, Registry};

pub const REGISTRY_FILE: &str = "registry.json";

/// A registry entry and, for an allow, the frozen program file beside `registry.json`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Listed {
    #[serde(flatten)]
    pub entry: Entry,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_sha256: Option<String>,
    /// Why the entry was added.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub note: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegistryFile {
    pub network: Net,
    /// The root of `entries`, hex; recomputed and checked on load.
    pub root: String,
    pub entries: Vec<Listed>,
    #[serde(skip)]
    pub dir: PathBuf,
}

pub fn key_hex(key: &[u32; 8]) -> String {
    hex::encode(key.iter().flat_map(|w| w.to_le_bytes()).collect::<Vec<u8>>())
}

impl RegistryFile {
    pub fn new(dir: &Path, network: Net) -> Self {
        let mut f = RegistryFile { network, root: String::new(), entries: vec![], dir: dir.to_path_buf() };
        f.root = hex::encode(f.registry().root());
        f
    }

    pub fn load(dir: &Path) -> Result<Self> {
        let path = dir.join(REGISTRY_FILE);
        let mut f: RegistryFile = serde_json::from_slice(&std::fs::read(&path).with_context(|| path.display().to_string())?)?;
        f.dir = dir.to_path_buf();
        let root = hex::encode(f.registry().root());
        if root != f.root {
            bail!("{}: entries hash to {root}, the file states {}", path.display(), f.root);
        }
        Ok(f)
    }

    pub fn save(&mut self) -> Result<()> {
        self.root = hex::encode(self.registry().root());
        std::fs::create_dir_all(&self.dir)?;
        std::fs::write(self.dir.join(REGISTRY_FILE), serde_json::to_string_pretty(self)? + "\n")?;
        Ok(())
    }

    pub fn registry(&self) -> Registry {
        Registry { entries: self.entries.iter().map(|l| l.entry.clone()).collect() }
    }

    /// The newest program allowed for a `kind` claim over `first..=last`.
    pub fn program_for(&self, kind: Kind, era: u8, first: u64, last: u64) -> Result<&Listed> {
        let reg = self.registry();
        self.entries
            .iter()
            .rev()
            .find(|l| l.entry.action == Action::Allow && l.entry.kind == kind && reg.allows(kind, self.network, era, first, last, &l.entry.key))
            .with_context(|| format!("no {kind:?} program registered for era {era}, heights {first}..={last}"))
    }

    pub fn by_key(&self, key: &[u32; 8]) -> Result<&Listed> {
        self.entries
            .iter()
            .find(|l| l.entry.action == Action::Allow && l.entry.key == *key)
            .with_context(|| format!("program {} is not registered", key_hex(key)))
    }

    /// The program file's bytes, checked against the hash registered with it.
    pub fn elf(&self, l: &Listed) -> Result<Vec<u8>> {
        let name = l.artifact.as_ref().context("entry has no program file")?;
        let bytes = std::fs::read(self.dir.join(name)).with_context(|| name.clone())?;
        use sha2::Digest;
        let h = hex::encode(sha2::Sha256::digest(&bytes));
        if Some(&h) != l.artifact_sha256.as_ref() {
            bail!("{name} does not match its registered hash");
        }
        Ok(bytes)
    }
}

/// Keeps an SP1 client or proving key, which must be dropped inside a tokio runtime (see
/// gpu-bench).
pub struct InRuntime<T>(Option<T>);

impl<T> InRuntime<T> {
    pub fn new(value: T) -> Self {
        InRuntime(Some(value))
    }
}

impl<T> std::ops::Deref for InRuntime<T> {
    type Target = T;
    fn deref(&self) -> &T {
        self.0.as_ref().unwrap()
    }
}

impl<T> Drop for InRuntime<T> {
    fn drop(&mut self) {
        match tokio::runtime::Runtime::new() {
            Ok(rt) => {
                let _guard = rt.enter();
                drop(self.0.take());
            }
            Err(_) => std::mem::forget(self.0.take()),
        }
    }
}

pub fn arg(name: &str) -> Option<String> {
    let args: Vec<String> = std::env::args().collect();
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned()
}

pub fn flag(name: &str) -> bool {
    std::env::args().any(|a| a == name)
}

/// Positional arguments after the mode, skipping `--name value` pairs and bare flags.
pub fn positional(flags_with_values: &[&str]) -> Vec<String> {
    let args: Vec<String> = std::env::args().skip(2).collect();
    let mut out = vec![];
    let mut i = 0;
    while i < args.len() {
        if flags_with_values.contains(&args[i].as_str()) {
            i += 2;
        } else {
            if !args[i].starts_with("--") {
                out.push(args[i].clone());
            }
            i += 1;
        }
    }
    out
}
