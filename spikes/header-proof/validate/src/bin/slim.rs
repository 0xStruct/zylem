//! Measures a Ring file with each 1,487-byte header replaced by its 104-byte record.

use zylem_core::{manifest::Manifest, ring};

fn main() -> anyhow::Result<()> {
    let dir = std::path::PathBuf::from(std::env::args().nth(1).unwrap_or_else(|| "../../data/testnet".into()));
    let m: Manifest = serde_json::from_slice(&std::fs::read(dir.join("manifest.json"))?)?;
    for e in m.rings.iter().take(3) {
        let bytes = std::fs::read(dir.join(&e.file))?;
        let mut r = ring::decode_file(&bytes)?;
        for b in &mut r.blocks {
            let h = &b.header;
            let mut rec = zylem_hdr::sha256d(h).to_vec();
            rec.extend_from_slice(&h[36..108]);
            b.header = rec;
        }
        let slim = ring::encode_file(&r).len();
        println!("{}: {} B -> {} B with records (+ ~222,668 B receipt = {} B, {:.1}x smaller)",
            e.file, bytes.len(), slim, slim + 222_668, bytes.len() as f64 / (slim + 222_668) as f64);
    }
    Ok(())
}
